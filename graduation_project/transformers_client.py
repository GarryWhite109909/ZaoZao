"""
Transformers 进程内推理客户端 —— Q4 基座（bitsandbytes NF4）+ FP16 LoRA。

背景：Ollama 发布版是把 base+LoRA 合并后整体压进 GGUF Q4_K_M，训练得到的
LoRA 信号被一并重量化，导致 20 真实召回从 95%（全精度 LoRA）跌到 79%。
本客户端复现 evaluate.py 95% 那套加载方式：
    AutoModelForCausalLM + BitsAndBytesConfig(load_in_4bit, nf4) + PeftModel(FP16 LoRA)
保证 LoRA 增量保持 FP16 精度，只压基座。

接口与 OllamaClient / VLLMClient 对齐（generate / generate_structured /
check_connection / list_models / unload_model / model），便于 Scanner 无缝切换。

使用约定（环境变量）：
    VULN_SCANNER_MODEL_ID   基座模型（默认项目本地 models/transformers/Qwen3-8B，缺失回退 Qwen/Qwen3-8B）
    VULN_SCANNER_ADAPTER    LoRA adapter 目录（必填，含 adapter_model.safetensors）
    VULN_SCANNER_NUM_CTX    上下文长度（默认 6144，用户指定）
    VULN_SCANNER_QUANTIZE   是否 NF4 4bit 量化基座（默认 1）
    VULN_SCANNER_FLASH_ATTN 是否优先 flash_attention_2（默认 1；不可用时自动回退 sdpa）
    VULN_SCANNER_COMPUTE_DTYPE 基座计算精度：fp16 / bf16（默认按平台自动：ROCm→bf16，NVIDIA→fp16）
    VULN_SCANNER_COMPILE    是否 torch.compile 加速 decode（默认 auto：NVIDIA 开、ROCm 关；设 0/1 强制覆盖）

性能说明：单条自回归解码是显存带宽瓶颈（GPU 计算单元等权重读取，故功耗上不去）。
要真正吃满功耗，用 generate_batch 把多个 chunk 拼成 batch 一次解码（见本文件与 scanner）。

注意：模型进程内常驻、显存占用高（Q4 基座 ~4.5GB + KV cache@6144 + 激活 ≈ 6-7GB）。
本客户端只负责推理；模型管理（拉取/删除/切换）仍走 Ollama，见 app/backend/main.py。
"""

from __future__ import annotations

import json
import os
import shutil
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Union

# 延迟导入重型依赖（torch/transformers/peft/bitsandbytes），仅在真正加载模型时才 import，
# 避免未安装 transformers 的环境 import 本模块即报错。
_TORCH = None
_TF = None
_PEFT = None


def _lazy_import_torch():
    global _TORCH
    if _TORCH is None:
        import torch
        _TORCH = torch
    return _TORCH


def _lazy_import_transformers():
    global _TF
    if _TF is None:
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            BitsAndBytesConfig,
        )
        _TF = {
            "AutoModelForCausalLM": AutoModelForCausalLM,
            "AutoTokenizer": AutoTokenizer,
            "BitsAndBytesConfig": BitsAndBytesConfig,
        }
    return _TF


def _lazy_import_peft():
    global _PEFT
    if _PEFT is None:
        from peft import PeftModel
        _PEFT = {"PeftModel": PeftModel}
    return _PEFT


# 统一输出 schema 的约束描述（与 scanner 的 CoT+JSON 模式一致；transformers 无 guided
# decoding，结构化兜底靠模型训练时学会的 JSON 输出 + 解析层 parse_verdict 容错）。
# 复用 graduation_project.prompts 的 build_user_prompt 组装 user prompt。
from graduation_project.prompts import build_user_prompt
from graduation_project.schema import parse_verdict, normalize_has_vulnerability
from graduation_project.paths import (
    resolve_adapter_path,
    resolve_base_model_path,
    local_hf_model_dir,
    hf_home_dir,
)


def is_transformers_runtime_compatible() -> tuple[bool, str]:
    """检查当前环境能否运行 transformers 进程内后端（NF4 4bit + LoRA）。

    主要排查两类会把协作者/新机器带崩的问题：
    1. torch 内核不包含当前显卡架构（NVIDIA 典型报错 'no kernel image'）；
    2. bitsandbytes 缺失（NF4 量化必需）。

    Returns:
        (ok, reason)；ok=False 时 reason 给出原因与改用 Ollama 的建议。
    """
    try:
        torch = _lazy_import_torch()
    except Exception as e:  # noqa: BLE001
        return False, f"torch 未安装或无法导入: {e}"
    try:
        has_cuda = torch.cuda.is_available()
    except Exception:  # noqa: BLE001
        has_cuda = False
    is_rocm = bool(getattr(torch.version, "hip", None))
    if not has_cuda:
        return False, "未检测到可用的 CUDA/ROCm 设备（CPU 上 4bit 推理不实用）"

    # NVIDIA：核对当前显卡 compute capability 是否被 torch 内核覆盖
    if not is_rocm:
        try:
            cap = torch.cuda.get_device_capability(0)
            arch = f"sm_{cap[0]}{cap[1]}"
            compute = f"compute_{cap[0]}{cap[1]}"
            arch_list = torch.cuda.get_arch_list() or []
            covered = any(arch in a for a in arch_list) or any(compute in a for a in arch_list)
            if not covered:
                return False, (
                    f"当前 torch {torch.__version__} 的内核不支持此显卡 "
                    f"(compute capability {cap[0]}.{cap[1]}，torch 支持: {arch_list or '未知'})；"
                    "典型报错为 'no kernel image'。请安装匹配显卡的 torch，"
                    "或改用 Ollama 后端（VULN_SCANNER_BACKEND=ollama）。"
                )
        except Exception:  # noqa: BLE001
            pass  # 查询失败时不阻断，交由加载阶段给出具体报错

    try:
        import bitsandbytes  # noqa: F401
    except ImportError:
        return False, (
            "未安装 bitsandbytes（NF4 量化必需）；请安装，"
            "或改用 Ollama 后端（VULN_SCANNER_BACKEND=ollama）。"
        )
    return True, "ok"


def _local_dir_state(local_dir: Path) -> tuple[bool | None, str]:
    """检查本地基座目录是否完整（config + 权重分片）。"""
    if not (local_dir / "config.json").is_file():
        return False, f"本地基座目录缺少 config.json：{local_dir}"
    if (local_dir / "model.safetensors").is_file():
        return True, "已就绪（本地基座模型）"
    index = local_dir / "model.safetensors.index.json"
    if index.is_file():
        try:
            shards = set(json.loads(index.read_text(encoding="utf-8")).get("weight_map", {}).values())
            present = {p.name for p in local_dir.glob("*.safetensors")}
            if shards.issubset(present):
                return True, "已就绪（本地基座模型）"
            return False, f"本地基座不完整（{len(present & shards)}/{len(shards)} 个权重分片）"
        except Exception as e:  # noqa: BLE001
            return None, f"本地基座检测异常：{e}"
    if any(local_dir.glob("pytorch_model*.bin")) or any(local_dir.glob("*.bin")):
        return True, "已就绪（本地基座模型）"
    return False, "本地基座缺少权重文件"


def _ensure_hf_home() -> None:
    """把 HF_HOME 锁到项目目录，保证 HuggingFace 相关文件（含模型权重）不落 C 盘。"""
    if os.environ.get("HF_HOME") or os.environ.get("HF_HUB_CACHE"):
        return
    home = hf_home_dir()
    home.mkdir(parents=True, exist_ok=True)
    os.environ["HF_HOME"] = str(home)


def _hf_cache_repo_candidates(model_id: str) -> list[Path]:
    """HF cache 中对应仓库的候选目录（默认 C 盘 + HF_HOME 指向的位置）。"""
    name = f"models--{model_id.replace('/', '--')}"
    roots: list[Path] = []
    try:
        from huggingface_hub.constants import HUGGINGFACE_HUB_CACHE
        roots.append(Path(HUGGINGFACE_HUB_CACHE))
    except Exception:  # noqa: BLE001
        pass
    roots.append(Path.home() / ".cache" / "huggingface" / "hub")
    seen: set[str] = set()
    out: list[Path] = []
    for root in roots:
        p = root / name
        key = str(p).lower()
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def _migrate_completed_hf_cache(model_id: str, local_dir: Path) -> bool:
    """把 HF 默认 cache 里**已完整**的基座迁移到项目目录（剪切 + 清理缓存）。

    适用场景：学妹等老用户之前把 16GB 基座下到了 C 盘 HF cache，
    项目切换到本地目录后应直接搬过来，避免重新下载。

    安全规则：
    - 只在本地目录缺失/不完整、且 cache 快照**权重完整**时执行；
    - 缓存不完整（下载中）或不存在时不动，继续走 snapshot_download；
    - 先迁移/复制，校验本地完整后才删除缓存仓库，避免误删。
    """
    if (local_dir / "config.json").is_file() and _local_dir_state(local_dir)[0] is True:
        return False  # 本地已完整，无需迁移
    for repo in _hf_cache_repo_candidates(model_id):
        snapshots = repo / "snapshots"
        if not snapshots.is_dir():
            continue
        candidates = sorted(
            (p for p in snapshots.iterdir() if p.is_dir()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for snap in candidates:
            ok, _ = _local_dir_state(snap)
            if ok is not True:
                continue
            local_dir.mkdir(parents=True, exist_ok=True)
            try:
                for item in snap.iterdir():
                    dest = local_dir / item.name
                    if dest.exists():
                        continue
                    if item.is_symlink():
                        # Linux 缓存里是符号链接：复制内容，随后整体删除仓库
                        shutil.copy2(item, dest)
                    else:
                        shutil.move(str(item), str(dest))
            except Exception as e:  # noqa: BLE001
                print(f"[TransformersClient] HF cache 迁移失败: {e}")
                return False
            if _local_dir_state(local_dir)[0] is True:
                try:
                    shutil.rmtree(repo, ignore_errors=True)
                    print(
                        f"[TransformersClient] 已从 HF cache 迁移基座到 {local_dir}，"
                        "并清理了 C 盘缓存"
                    )
                except Exception as e:  # noqa: BLE001
                    print(f"[TransformersClient] 缓存清理失败（不影响使用）: {e}")
                return True
            return False
    return False


class TransformersClient:
    """transformers 进程内推理客户端（NF4 基座 + FP16 LoRA）。

    模型在首次调用时懒加载并常驻显存（进程内全局单例由调用方 Scanner 持有）。
    线程安全：用 _gen_lock 串行化 generate，避免并发 generate 竞争 CUDA。

    Args:
        model_id:   基座模型（HuggingFace 名或本地路径）
        adapter:    LoRA adapter 目录（含 adapter_model.safetensors / adapter_config.json）
        num_ctx:    上下文长度（用于截断输入，保证不超过 max_model_len）
        quantize:   是否用 bitsandbytes NF4 4bit 量化基座
        flash_attn: 是否优先 flash_attention_2（不可用自动回退 sdpa）
        compile:    是否 torch.compile 加速 decode
    """

    def __init__(
        self,
        model_id: str = "",
        adapter: str = "",
        num_ctx: int = 6144,
        quantize: bool = True,
        flash_attn: bool = True,
        compile_: bool = False,
        merge: bool = True,
    ):
        self.model_id = resolve_base_model_path(model_id)
        self.adapter = resolve_adapter_path(adapter)
        self.num_ctx = int(os.environ.get("VULN_SCANNER_NUM_CTX", str(num_ctx)))
        self.quantize = quantize if not os.environ.get("VULN_SCANNER_QUANTIZE") else (
            os.environ.get("VULN_SCANNER_QUANTIZE", "1") != "0"
        )
        # merge 开关：默认合并 LoRA 进基座（快、但 LoRA 增量会被折回 NF4 存储）。
        # 设 VULN_SCANNER_MERGE=0 时不合并，LoRA 保持 FP16 精度、运行时叠加（更保精度）。
        # ⚠ 不合并时推理会变慢（每层多一次 LoRA 矩阵乘，且单条 decode 本就带宽受限）。
        self.merge = bool(
            os.environ.get("VULN_SCANNER_MERGE", "1" if merge else "0") != "0"
        )
        self.flash_attn = flash_attn if not os.environ.get("VULN_SCANNER_FLASH_ATTN") else (
            os.environ.get("VULN_SCANNER_FLASH_ATTN", "1") != "0"
        )
        # 计算精度：fp16 / bf16。默认按平台在 load_model 里自动决定（ROCm→bf16，NVIDIA→fp16）。
        self.compute_dtype = os.environ.get("VULN_SCANNER_COMPUTE_DTYPE", "").strip().lower()
        # compile 请求：None=auto（NVIDIA 开、ROCm 关）；显式 "0"/"1" 强制覆盖。
        _compile_env = os.environ.get("VULN_SCANNER_COMPILE")
        self.compile_requested = None
        if _compile_env is not None:
            self.compile_requested = _compile_env.strip() != "0"
        elif compile_:
            self.compile_requested = True
        # 与 OllamaClient/VLLMClient 的 model 字段语义对齐（供 Scanner/model_registry 读取）
        self.model = self.model_id
        self._model = None  # 懒加载
        self._tokenizer = None
        self._gen_lock = threading.Lock()
        # 加载锁：防止"后台预热"与"首次扫描"并发同时进入 load_model 重复加载
        self._load_lock = threading.Lock()
        self._load_error: Optional[str] = None

    # ------------------------------------------------------------------
    # 加载与生命周期
    # ------------------------------------------------------------------
    def _check_adapter(self) -> Optional[str]:
        """校验 adapter 路径存在且含权重。返回错误信息或 None。"""
        if not self.adapter:
            return "未找到 LoRA adapter：请设置 VULN_SCANNER_ADAPTER，或将 adapter 放到项目根目录 models/"
        p = Path(self.adapter)
        if not p.is_dir():
            return f"LoRA adapter 路径不存在: {self.adapter}"
        # 兼容不同权重文件名（adapter_model.safetensors / adapter_model.bin / adapter_model.gguf）
        has_weights = any(
            (p / name).exists()
            for name in ("adapter_model.safetensors", "adapter_model.bin", "adapter_model.gguf")
        )
        if not has_weights:
            return f"LoRA adapter 目录缺少权重文件: {self.adapter}"
        return None

    def load_model(self) -> bool:
        """加载模型 + tokenizer（幂等，仅首次真正加载）。

        Returns:
            True 加载成功；False 失败（错误信息存 self._load_error）。
        """
        if self._model is not None:
            return True
        if self._load_error:
            return False

        # 串行化加载：后台预热线程与首次扫描线程可能同时调用，避免重复加载
        with self._load_lock:
            if self._model is not None:
                return True
            if self._load_error:
                return False
            return self._do_load()

    def _do_load(self) -> bool:
        err = self._check_adapter()
        if err:
            self._load_error = err
            print(f"[TransformersClient] 加载失败: {err}")
            return False

        torch = _lazy_import_torch()
        tf = _lazy_import_transformers()
        peft = _lazy_import_peft()

        try:
            # HuggingFace 缓存锁定到项目目录（models/transformers/.hf_home），
            # 保证模型权重/元数据完全不落 C 盘
            _ensure_hf_home()

            # 基座统一下载到项目目录 models/transformers/<名称>（与设置页按钮、就绪检测一致）。
            # 本地已有则直接使用；VULN_SCANNER_HF_LOCAL_DIR=0 可关闭本地化（走 HF 默认 cache）。
            load_model_id = self.model_id
            local_dir = self._resolved_local_dir()
            if local_dir is not None and not Path(self.model_id).expanduser().is_dir():
                if not (local_dir / "config.json").is_file():
                    # 老用户可能已把基座下到 HF 默认 cache（C 盘）：先尝试剪切迁移，
                    # 迁移失败/缓存不完整才重新下载到项目目录。
                    if not _migrate_completed_hf_cache(self.model_id, local_dir):
                        print(
                            f"[TransformersClient] 首次下载基座到 {local_dir}"
                            "（约 16GB，支持断点续传；可在设置页查看进度）..."
                        )
                        from huggingface_hub import snapshot_download
                        snapshot_download(repo_id=self.model_id, local_dir=str(local_dir))
                if (local_dir / "config.json").is_file():
                    load_model_id = str(local_dir)

            has_cuda = torch.cuda.is_available()
            is_rocm = bool(getattr(torch.version, "hip", None))

            # 计算精度：
            #   - ROCm→bf16（fp16 在部分 CDNA 卡上慢）
            #   - NVIDIA→fp16（消费级 2x 速率）
            #   - CPU→fp32（ safest，部分 CPU 不支持 bf16/fp16 高效向量指令）
            compute_dtype_str = self.compute_dtype or (
                "bf16" if is_rocm else "fp16" if has_cuda else "fp32"
            )
            if compute_dtype_str == "bf16":
                dtype = torch.bfloat16
            elif compute_dtype_str == "fp32":
                dtype = torch.float32
            else:
                dtype = torch.float16

            # 设备映射：无 GPU 时走 CPU（bitsandbytes CPU 4bit 已支持）
            device_map: Union[str, dict] = {"": 0} if has_cuda else "cpu"

            print("[TransformersClient] 首次加载：需加载基座并合并 LoRA 权重，耗时较长（数分钟级），请耐心等待……")
            print("[TransformersClient] 加载完成后模型将常驻显存/内存，直到关闭后端服务；如需释放请退出本程序。")
            print(f"[TransformersClient] 加载 tokenizer: {load_model_id}")
            tokenizer = tf["AutoTokenizer"].from_pretrained(
                load_model_id, trust_remote_code=True
            )
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token

            # 注意力后端：flash_attn 仅 NVIDIA CUDA；ROCm/CPU 用 sdpa
            attn_impl = "sdpa"
            if self.flash_attn and has_cuda and not is_rocm:
                try:
                    from transformers.utils import is_flash_attn_2_available
                    if is_flash_attn_2_available():
                        attn_impl = "flash_attention_2"
                except Exception:
                    attn_impl = "sdpa"

            kwargs: dict = {
                "device_map": device_map,
                "trust_remote_code": True,
                "torch_dtype": dtype,
                "attn_implementation": attn_impl,
            }
            if self.quantize:
                kwargs["quantization_config"] = tf["BitsAndBytesConfig"](
                    load_in_4bit=True,
                    bnb_4bit_quant_type="nf4",
                    bnb_4bit_compute_dtype=dtype,
                    bnb_4bit_use_double_quant=True,
                )

            device_label = "ROCm" if is_rocm else "CUDA" if has_cuda else "CPU"
            print(f"[TransformersClient] 加载基座 {load_model_id} "
                  f"(device={device_label}, quantize={self.quantize}, dtype={compute_dtype_str}, attn={attn_impl})")
            model = tf["AutoModelForCausalLM"].from_pretrained(load_model_id, **kwargs)

            print(f"[TransformersClient] 加载 LoRA adapter: {self.adapter}")
            model = peft["PeftModel"].from_pretrained(model, self.adapter)
            if self.merge:
                # 合并 LoRA 权重加速推理（保留 FP16 精度，仅量化基座）。
                # 注意：合并后归一化权重会折回 NF4 存储，LoRA 增量精度有损。
                model = model.merge_and_unload()
                print("[TransformersClient] LoRA 已合并（VULN_SCANNER_MERGE=1 默认）")
            else:
                # ⚠ 不合并模式：LoRA 保持 FP16 精度、运行时叠加，推理会变慢。
                # 设 VULN_SCANNER_MERGE=0 开启；仅在需要极致 LoRA 精度时建议使用。
                print("[TransformersClient] 不合并 LoRA，运行时叠加（VULN_SCANNER_MERGE=0）")
                print("       ⚠ 推理会比合并模式更慢（每层多一次 LoRA 矩阵乘）")

            # torch.compile：默认仅 NVIDIA CUDA 开启（reduce-overhead + CUDA graph）。
            # ROCm/CPU 默认关闭：ROCm 稳定性差，CPU 无收益。
            do_compile = self.compile_requested
            if do_compile is None:
                do_compile = has_cuda and not is_rocm
            if do_compile:
                try:
                    model = torch.compile(model, mode="reduce-overhead")
                    print("[TransformersClient] 已启用 torch.compile (reduce-overhead)")
                except Exception as e:
                    print(f"[TransformersClient] torch.compile 失败，跳过: {e}")

            model.eval()
            self._model = model
            self._tokenizer = tokenizer
            self._load_error = None
            return True
        except Exception as e:
            msg = f"{type(e).__name__}: {e}"
            low = msg.lower()
            if "no kernel image" in low or "kernel image" in low or "bnb4bitquantize" in low:
                msg += (
                    " | 提示: 显卡与当前 torch/bitsandbytes 内核不匹配，"
                    "建议设置 VULN_SCANNER_BACKEND=ollama 改用 Ollama 后端，"
                    "或安装匹配显卡的 torch"
                )
            self._load_error = msg
            print(f"[TransformersClient] 模型加载失败: {self._load_error}")
            return False

    # ------------------------------------------------------------------
    # OllamaClient/VLLMClient 兼容接口
    # ------------------------------------------------------------------
    def check_connection(self) -> bool:
        """模型是否已加载（进程内，无需网络探测）。"""
        return self._model is not None

    def _base_resolvable(self) -> bool:
        """基座是否可加载：本地目录或 HF cache 已**完整下载**权重。"""
        ok, _ = self.model_availability()
        return ok is True

    def _resolved_local_dir(self) -> Optional[Path]:
        """基座下载/检测目录：本地路径 > VULN_SCANNER_HF_LOCAL_DIR > 项目约定目录。

        项目约定目录为 models/transformers/<repo 名>（与设置页下载按钮、paths.local_hf_model_dir
        一致）；设 VULN_SCANNER_HF_LOCAL_DIR=0/none/off 可禁用本地目录下载。
        """
        p = Path(self.model_id).expanduser()
        if p.is_dir():
            return p
        env_dir = os.environ.get("VULN_SCANNER_HF_LOCAL_DIR", "").strip()
        if env_dir.lower() in ("0", "none", "off"):
            return None
        if env_dir:
            return Path(env_dir).expanduser()
        try:
            return local_hf_model_dir(self.model_id)
        except Exception:  # noqa: BLE001
            return None

    def model_availability(self) -> tuple[bool | None, str]:
        """查询基座模型下载状态（只检查项目本地目录，不再看 HF 默认 cache）。

        返回 (是否完整可用, 状态描述)。

        与 is_ready() 不同：is_ready 只给布尔值，这里给出可展示的原因，
        供健康检查/设置页区分「未下载」「下载中」「已完整」。
        """
        if self._model is not None:
            return True, "已加载到内存"
        if self._load_error:
            return False, f"加载失败：{self._load_error}"
        local_dir = self._resolved_local_dir()
        if local_dir is None:
            return False, "未配置本地基座下载目录（VULN_SCANNER_HF_LOCAL_DIR=0）"
        if not local_dir.exists():
            return False, f"未下载（首次分析/设置页将自动下载到 {local_dir}）"
        return _local_dir_state(local_dir)

    def is_ready(self) -> bool:
        """进程内后端是否就绪：已加载，或本地基座 + adapter 资源齐全。

        与 check_connection() 不同：check_connection() 仅表示模型是否已读入显存；
        is_ready() 表示“引擎可用”——资源已就绪、首次扫描时才懒加载（8B NF4 约 6GB，
        若每次健康检查都强制加载会占用显存且拖慢启动）。

        注意：基座权重未完整下载（HF cache 只有 config / 部分分片）时返回 False，
        避免健康检查/前端把“正在下载”误报成“就绪”。
        """
        if self._model is not None:
            return True
        if self._check_adapter():
            return False
        ok, _ = self.model_availability()
        return ok is True

    def list_models(self) -> List[str]:
        """返回当前模型名（进程内仅一个模型）。"""
        return [self.model] if self._model is not None else []

    def unload_model(self, timeout: int = 60) -> bool:
        """释放模型占用的显存。"""
        torch = _lazy_import_torch()
        if self._model is not None:
            try:
                del self._model
                self._model = None
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                return True
            except Exception:
                return False
        return True

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = 2048,
        keep_alive=0,
        timeout: int = 300,
        num_ctx: Optional[int] = None,
        num_gpu: Optional[int] = None,
        num_thread: Optional[int] = None,
        think: Optional[bool] = None,
        format: Optional[Union[str, dict]] = None,
    ) -> Dict:
        """生成文本（确定性贪心解码，Qwen3 禁用 thinking）。

        返回结构与 OllamaClient/VLLMClient 一致：
            {"text", "duration", "tokens", "meta", "error"}
        """
        start_time = time.time()
        if not self.load_model():
            return {
                "text": "", "duration": 0.0,
                "tokens": {"prompt": 0, "completion": 0, "total": 0},
                "meta": {}, "error": self._load_error,
            }

        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        with self._gen_lock:
            try:
                text = tokenizer_apply_chat_template(
                    self._tokenizer, messages, enable_thinking=False
                )
                inputs = self._tokenizer(text, return_tensors="pt")
                # 上下文截断：总长度不超过 num_ctx，并给 max_tokens 预留空间
                ctx = num_ctx or self.num_ctx
                max_new = max_tokens if max_tokens is not None else 2048
                max_input = max(1, ctx - max_new)
                if inputs["input_ids"].shape[1] > max_input:
                    inputs["input_ids"] = inputs["input_ids"][:, -max_input:]
                    inputs["attention_mask"] = inputs["attention_mask"][:, -max_input:]

                # 贪心解码为默认；temperature>0 时才启用采样（与 evaluate.py 一致）
                gen_kwargs = {
                    "max_new_tokens": max_new,
                    "do_sample": False,
                    "pad_token_id": self._tokenizer.pad_token_id,
                }
                if temperature and temperature > 0:
                    gen_kwargs["do_sample"] = True
                    gen_kwargs["temperature"] = temperature
                    gen_kwargs["top_p"] = 0.9

                torch = _lazy_import_torch()
                inputs = {k: v.to(self._model.device) for k, v in inputs.items()}
                with torch.no_grad():
                    outputs = self._model.generate(**inputs, **gen_kwargs)

                input_len = inputs["input_ids"].shape[1]
                generated = outputs[0][input_len:]
                response = self._tokenizer.decode(generated, skip_special_tokens=True)
                duration = time.time() - start_time

                return {
                    "text": response,
                    "duration": duration,
                    "tokens": {
                        "prompt": input_len,
                        "completion": int(generated.shape[0]),
                        "total": input_len + int(generated.shape[0]),
                    },
                    "meta": {"backend": "transformers", "model": self.model_id},
                    "error": None,
                }
            except Exception as e:
                return {
                    "text": "",
                    "duration": time.time() - start_time,
                    "tokens": {"prompt": 0, "completion": 0, "total": 0},
                    "meta": {},
                    "error": f"{type(e).__name__}: {e}",
                }

    def generate_batch(
        self,
        prompts: List[str],
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = 2048,
        num_ctx: Optional[int] = None,
    ) -> List[Dict]:
        """批量解码多条 prompt（一次 generate 走完整 batch）。

        核心优化：单条自回归解码是显存带宽瓶颈（GPU 计算单元等权重读取，功耗上不去）。
        把多条 prompt 拼成一个 batch 后，prefill 与 decode 的权重读取被 batch 摊薄，
        算术强度上升 → 真正吃满 GPU。适合 Scanner 一次分析多个 chunk 的场景。

        Args:
            prompts: 多条 user prompt 文本
            system_prompt: 共享 system prompt（None 则只发 user）
            temperature: 采样温度（>0 才启用采样，否则贪心解码）
            max_tokens: 每条最大生成 token 数
            num_ctx: 上下文长度（截断输入，默认 self.num_ctx）

        Returns:
            长度与 prompts 相同的列表，每项结构与 generate 一致
            {"text", "duration", "tokens", "meta", "error"}
        """
        n = len(prompts)
        start_time = time.time()

        def _err_result(msg: str) -> List[Dict]:
            return [
                {
                    "text": "", "duration": time.time() - start_time,
                    "tokens": {"prompt": 0, "completion": 0, "total": 0},
                    "meta": {}, "error": msg,
                }
                for _ in range(n)
            ]

        if n == 0:
            return []
        if not self.load_model():
            return _err_result(self._load_error)

        torch = _lazy_import_torch()
        ctx = num_ctx or self.num_ctx
        max_new = max_tokens if max_tokens is not None else 2048
        max_input = max(1, ctx - max_new)

        # 逐条应用 ChatML 模板（Qwen3 禁用 thinking）
        texts = []
        for p in prompts:
            messages: List[Dict[str, str]] = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": p})
            texts.append(tokenizer_apply_chat_template(
                self._tokenizer, messages, enable_thinking=False
            ))

        batch_error: Optional[str] = None
        with self._gen_lock:
            # decoder-only 批量解码必须左 padding：右 padding 时短序列的"最后
            # 一个 token"是 pad，生成从 pad 位置继续会产生不可靠输出
            old_padding_side = getattr(self._tokenizer, "padding_side", "right")
            if hasattr(self._tokenizer, "padding_side"):
                self._tokenizer.padding_side = "left"
            try:
                # 批量 tokenize：padding 到 batch 内最长，truncation 到 max_input
                enc = self._tokenizer(
                    texts, return_tensors="pt", padding=True,
                    truncation=True, max_length=max_input,
                )
                enc = {k: v.to(self._model.device) for k, v in enc.items()}

                gen_kwargs = {
                    "max_new_tokens": max_new,
                    "do_sample": False,
                    "pad_token_id": self._tokenizer.pad_token_id,
                }
                if temperature and temperature > 0:
                    gen_kwargs["do_sample"] = True
                    gen_kwargs["temperature"] = temperature
                    gen_kwargs["top_p"] = 0.9

                with torch.no_grad():
                    outputs = self._model.generate(**enc, **gen_kwargs)

                padded_len = enc["input_ids"].shape[1]  # batch 内最长输入长度
                eos_id = self._tokenizer.eos_token_id
                results: List[Dict] = []
                for i in range(n):
                    # 每条的真实输入长度（不含 padding）
                    actual_len = int(enc["attention_mask"][i].sum().item())
                    # 从 padded_len 之后取生成区（避开 padding），再按首个 eos 截断
                    row = outputs[i][padded_len:]
                    if eos_id is not None:
                        eos_pos = (row == eos_id).nonzero(as_tuple=True)[0]
                        if len(eos_pos) > 0:
                            row = row[:eos_pos[0]]
                    response = self._tokenizer.decode(row, skip_special_tokens=True)
                    results.append({
                        "text": response,
                        "duration": time.time() - start_time,
                        "tokens": {
                            "prompt": actual_len,
                            "completion": int(row.shape[0]),
                            "total": actual_len + int(row.shape[0]),
                        },
                        "meta": {"backend": "transformers", "model": self.model_id},
                        "error": None,
                    })
                return results
            except Exception as e:
                batch_error = f"{type(e).__name__}: {e}"
            finally:
                if hasattr(self._tokenizer, "padding_side"):
                    self._tokenizer.padding_side = old_padding_side

        if batch_error is not None:
            # 批量失败（如 OOM）逐条回退（锁外执行，self.generate 会重新取锁），
            # 避免整批因单条超长/显存峰值全部报废
            print(f"[TransformersClient] 批量解码失败（{batch_error}），逐条回退")
            return [
                self.generate(
                    prompt=p, system_prompt=system_prompt,
                    temperature=temperature, max_tokens=max_tokens,
                    num_ctx=num_ctx,
                )
                for p in prompts
            ]

    def generate_structured(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = 1024,
        keep_alive=0,
        timeout: int = 300,
        num_ctx: Optional[int] = None,
        num_gpu: Optional[int] = None,
        num_thread: Optional[int] = None,
        think: Optional[bool] = None,
    ) -> Dict:
        """结构化输出兜底。

        transformers 无 guided decoding，此方法退化为普通 generate（模型训练时已学会
        输出 schema 要求的 JSON），由上层 parse_verdict 容错解析。接口与其余 client 对齐。
        注意：与 Ollama format=json 的"数学上保证可解析"不同，本路径不保证——
        首次调用时打印一次警告，监控侧应关注 parse_fail 率。
        """
        if not getattr(self, "_structured_warned", False):
            print("[TransformersClient] 警告: 本后端无约束解码，generate_structured "
                  "退化为普通 generate，解析成功率依赖模型格式遵循")
            self._structured_warned = True
        return self.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            keep_alive=keep_alive,
            timeout=timeout,
            num_ctx=num_ctx,
        )

    def analyze_vulnerability(
        self,
        code: str,
        language: str = "python",
        rag_context: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> Dict:
        """分析代码漏洞（接口与其余 client 对齐，供 standalone 使用）。"""
        prompt = build_user_prompt(
            code=code, language=language, filename=filename, rag_context=rag_context
        )
        return self.generate(prompt, system_prompt=os.environ.get("VULN_SCANNER_SYSTEM_PROMPT"))


def tokenizer_apply_chat_template(tokenizer, messages, enable_thinking=False) -> str:
    """对 messages 应用 ChatML 模板（Qwen3 默认 disable thinking）。"""
    apply = getattr(tokenizer, "apply_chat_template", None)
    if apply is not None:
        try:
            return apply(
                messages, tokenize=False, add_generation_prompt=True,
                enable_thinking=enable_thinking,
            )
        except TypeError:
            return apply(messages, tokenize=False, add_generation_prompt=True)
    # 兜底：手动拼接（无模板时）
    parts = []
    for m in messages:
        role = m["role"]
        content = m["content"]
        if role == "system":
            parts.append(f"<|im_start|>system\n{content}<|im_end|>")
        elif role == "user":
            parts.append(f"<|im_start|>user\n{content}<|im_end|>")
        elif role == "assistant":
            parts.append(f"<|im_start|>assistant\n{content}<|im_end|>")
    parts.append("<|im_start|>assistant\n")
    return "\n".join(parts)


# 兼容工厂：与 create_llm_client 对齐，便于按 backend 名创建
def create_llm_client(backend: str = "transformers", **kwargs):
    """按 backend 名创建客户端。'transformers' 返回 TransformersClient；其余转发。"""
    backend_lower = backend.strip().lower()
    if backend_lower in ("transformers", "hf", "peft"):
        return TransformersClient(**kwargs)
    if backend_lower == "ollama":
        from graduation_project.llm_client import OllamaClient
        return OllamaClient(**kwargs)
    if backend_lower == "vllm":
        from graduation_project.vllm_client import VLLMClient
        return VLLMClient(**kwargs)
    if backend_lower in ("llamacpp", "llama-cpp", "llama_cpp", "gguf"):
        from graduation_project.llamacpp_client import LlamaCppClient
        return LlamaCppClient(**kwargs)
    raise ValueError(f"未知 backend: {backend}，支持 'transformers'/'ollama'/'vllm'/'llamacpp'")


if __name__ == "__main__":
    # 自检：加载 + 推理一条注入漏洞
    client = TransformersClient()
    ok = client.load_model()
    print(f"[自检] 加载成功: {ok}")
    if not ok:
        print(f"[自检] 错误: {client._load_error}")
    else:
        test_code = (
            "import sqlite3\n"
            "def get_user(username):\n"
            "    cur = sqlite3.connect('users.db').cursor()\n"
            "    cur.execute(\"SELECT * FROM users WHERE name='\" + username + \"'\")\n"
        )
        result = client.analyze_vulnerability(test_code, "python")
        print(f"[自检] 耗时: {result['duration']:.2f}s")
        print(f"[自检] error: {result['error']}")
        if not result["error"]:
            verdict = parse_verdict(result["text"])
            print(f"[自检] has_vuln = {normalize_has_vulnerability(verdict.get('has_vulnerability'))}")
