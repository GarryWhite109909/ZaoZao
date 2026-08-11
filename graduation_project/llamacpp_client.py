"""
llama-cpp-python 推理客户端 —— Q4 GGUF 基座 + 运行时加载独立 FP16 LoRA adapter。

背景：Ollama 发布版是把 base+LoRA 合并后整体压进 GGUF Q4_K_M，LoRA 信号被一并重量化，
导致 20 真实召回从 95%（全精度 LoRA）跌到 79%。TransformersClient 用
AutoModelForCausalLM + bitsandbytes NF4 + PeftModel 保住了 LoRA 精度，但 bitsandbytes
的 NF4 反量化 kernel 不如 llama.cpp 紧凑，单条解码比 Ollama 慢、GPU 吃不满。

本客户端的思路：用 llama.cpp（llama-cpp-python）加载 Q4 GGUF 基座，同时把 FP16 LoRA
adapter 作为独立权重在运行时叠加（lora_path 参数），既拿到 llama.cpp 的高速内核，
又保留 LoRA 的 FP16 精度（避免合并量化损失）。是「Ollama 速度 + Transformers 精度」的折中。

注意：
- 依赖 llama-cpp-python：ROCm 需自行编译（CMAKE_ARGS="-DGGML_HIP=ON"），见项目文档。
- 通过 VULN_SCANNER_BACKEND=llamacpp 切换。
- 模型管理（拉取/删除/切换）仍走 Ollama，本客户端只负责推理。

接口与 OllamaClient / VLLMClient / TransformersClient 对齐（generate / generate_structured /
check_connection / list_models / unload_model / analyze_vulnerability / model）。

使用约定（环境变量）：
    VULN_SCANNER_GGUF       Q4 基座 GGUF 文件路径（必填）
    VULN_SCANNER_ADAPTER    FP16 LoRA adapter 目录（必填，含 adapter_model.safetensors）
    VULN_SCANNER_NUM_CTX    上下文长度（默认 6144）
    VULN_SCANNER_GPU_LAYERS 卸载到 GPU 的层数（默认 -1=全部，CPU+GPU 混合可设小值）
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Union

from graduation_project.prompts import V3_PROMPT, build_user_prompt
from graduation_project.schema import parse_verdict, normalize_has_vulnerability
from graduation_project.paths import resolve_adapter_path, llamacpp_dir

_LLAMA = None  # 延迟导入 llama_cpp


def _ensure_cuda_runtime_on_path() -> None:
    """把 pip 安装的 NVIDIA CUDA 运行时 DLL 目录加进 PATH。

    背景：llama-cpp-python 的 CUDA 预编译 wheel（cu125 等）编译时链接
    cudart64_12.dll / cublas64_12.dll，但 wheel 本身不打包这两个运行时，
    需要系统有 CUDA Toolkit 或 pip 装 nvidia-cuda-runtime-cu12 / nvidia-cublas-cu12。
    而 pip 是把这些 DLL 装到 site-packages/nvidia/*/bin/，不在 PATH 里；
    若不加入 PATH，llama.dll 加载时会报 "Could not find module ... llama.dll
    (or one of its dependencies)"，进而 llama_supports_gpu_offload() 返回 False、
    回退 CPU。这里在 import llama_cpp 前把相关 bin 目录前置到 PATH 解决。
    """
    import site

    nvidia_root = None
    for sp in site.getsitepackages():
        cand = Path(sp) / "nvidia"
        if cand.is_dir():
            nvidia_root = cand
            break
    if nvidia_root is None:
        # 备选：用户级 site-packages（--user 安装）
        user_dir = Path(site.getusersitepackages()) / "nvidia"
        if user_dir.is_dir():
            nvidia_root = user_dir
    if nvidia_root is None:
        return

    bin_dirs = sorted(
        (nvidia_root / pkg / "bin" for pkg in ("cuda_runtime", "cublas", "cuda_nvrtc", "cuda_cudart")),
        key=lambda p: p.exists(),
        reverse=True,  # 存在的排前面
    )
    existing = set(
        p.rstrip("/\\").lower()
        for p in os.environ.get("PATH", "").split(os.pathsep)
        if p
    )
    new_bits = [str(b) for b in bin_dirs if b.is_dir() and str(b).rstrip("/\\").lower() not in existing]
    if new_bits:
        os.environ["PATH"] = os.pathsep.join(new_bits) + os.pathsep + os.environ.get("PATH", "")


def _lazy_import_llama_cpp():
    """延迟导入 llama_cpp，避免未安装的环境 import 本模块即报错。"""
    global _LLAMA
    if _LLAMA is None:
        _ensure_cuda_runtime_on_path()  # 先补 CUDA 运行时后再加载 llama.dll
        from llama_cpp import Llama
        _LLAMA = {"Llama": Llama}
    return _LLAMA


def _build_chatml(system_prompt: Optional[str], user_prompt: str) -> str:
    """构造 Qwen3 ChatML 文本（enable_thinking=False，与 TransformersClient 一致）。

    复用 transformers_client.tokenizer_apply_chat_template 的兜底格式，保证两种后端
    收到的 prompt 完全一致，输出行为可复现。
    """
    parts = []
    if system_prompt:
        parts.append(f"<|im_start|>system\n{system_prompt}<|im_end|>")
    parts.append(f"<|im_start|>user\n{user_prompt}<|im_end|>")
    parts.append("<|im_start|>assistant\n")
    return "\n".join(parts)


class LlamaCppClient:
    """llama-cpp-python 推理客户端（Q4 GGUF 基座 + 运行时 FP16 LoRA）。

    模型首次调用时懒加载并常驻显存。线程安全：用 _gen_lock 串行化 generate。
    """

    def __init__(
        self,
        base_gguf: str = "",
        adapter: str = "",
        num_ctx: int = 6144,
        gpu_layers: int = -1,
        verbose: bool = False,
    ):
        self.base_gguf = base_gguf or os.environ.get("VULN_SCANNER_GGUF", "") or self._discover_gguf()
        self.adapter = resolve_adapter_path(adapter)
        self.num_ctx = int(os.environ.get("VULN_SCANNER_NUM_CTX", str(num_ctx)))
        self.gpu_layers = int(os.environ.get("VULN_SCANNER_GPU_LAYERS", str(gpu_layers)))
        self.verbose = verbose
        self.model = self.base_gguf  # 接口对齐
        self._llm = None
        self._gen_lock = threading.Lock()
        self._load_error: Optional[str] = None
        # 运行时叠加的 LoRA 权重文件（从 adapter 目录内定位，llama.cpp 的
        # lora_path 需要单个文件路径，而非目录；由 _check_paths 解析）
        self._adapter_file: Optional[str] = None
        self._adapter_file_mtime = 0.0

    @staticmethod
    def _discover_gguf() -> str:
        """自动探测项目 models/llamacpp/ 下的 GGUF 基座文件（未设置 VULN_SCANNER_GGUF 时）。

        与 transformers 的 models/transformers、vLLM 的 models/vllm 对齐，
        GGUF 统一放 models/llamacpp/。多个文件时优先 Q4 量化。
        """
        d = llamacpp_dir()
        if not d.is_dir():
            return ""
        gguFs = sorted(d.glob("*.gguf"))
        if not gguFs:
            return ""
        # 优先 Q4，其次 Q5/Q6/Q8（量化层次越深，越接近发布模型的 Q4 口径）
        def _prio(p: Path) -> int:
            low = p.name.lower()
            for i, q in enumerate(("q4", "q5", "q6", "q8")):
                if q in low:
                    return i
            return len(("q4", "q5", "q6", "q8"))
        return str(sorted(gguFs, key=_prio)[0])

    # ------------------------------------------------------------------
    # 加载与生命周期
    # ------------------------------------------------------------------
    def _check_paths(self) -> Optional[str]:
        """校验基座 GGUF 与 LoRA adapter 路径，并把 adapter 目录内的权重文件定位到
        self._adapter_file（llama.cpp 的 lora_path 需要单个文件路径）。返回错误信息或 None。"""
        if not self.base_gguf:
            return "VULN_SCANNER_GGUF 未设置：需要 Q4 基座 GGUF 文件路径"
        if not Path(self.base_gguf).is_file():
            return f"GGUF 基座文件不存在: {self.base_gguf}"
        if not self.adapter:
            return "未找到 LoRA adapter：请设置 VULN_SCANNER_ADAPTER，或将 adapter 放到项目根目录 models/"
        p = Path(self.adapter)
        if not p.is_dir():
            return f"LoRA adapter 路径不存在: {self.adapter}"
        # 与 paths.is_valid_adapter_dir 口径一致：safetensors/bin/gguf 任一即可。
        # 注意：llama-cpp-python 0.3.34 加载 safetensors LoRA 推理会卡死(hang)，
        # GGUF LoRA 是 llama.cpp 原生格式、推理正常，故优先选 GGUF。
        for name in ("adapter_model.gguf", "adapter_model.safetensors", "adapter_model.bin"):
            f = p / name
            if f.is_file():
                self._adapter_file = str(f)
                break
        else:
            return f"LoRA adapter 目录缺少权重文件: {self.adapter}"
        return None

    def load_model(self) -> bool:
        """加载 Q4 GGUF 基座 + FP16 LoRA adapter（幂等）。"""
        if self._llm is not None:
            return True
        if self._load_error:
            return False

        err = self._check_paths()
        if err:
            self._load_error = err
            print(f"[LlamaCppClient] 加载失败: {err}")
            return False

        try:
            llama = _lazy_import_llama_cpp()
            gpu_layers = self.gpu_layers
            # n_gpu_layers：-1 表示"尽量卸载到 GPU"，正整数表示卸载前 N 层到 GPU、其余跑 CPU。
            # 无论哪种 GPU 模式，若当前 llama-cpp-python 编译时未开启任何 GPU 后端
            # （CPU-only，如 AMD 回退、预编译 CPU wheel），传非 0 都会报错，
            # 统一自动降级为 0（纯 CPU），避免加载失败。
            if gpu_layers != 0:
                try:
                    import llama_cpp
                    supports_gpu = getattr(llama_cpp, "llama_supports_gpu_offload", lambda: True)()
                    if not supports_gpu:
                        gpu_layers = 0
                except Exception:
                    pass

            print(f"[LlamaCppClient] 加载 GGUF 基座 {self.base_gguf} "
                  f"(LoRA={self._adapter_file}, n_ctx={self.num_ctx}, gpu_layers={gpu_layers})")
            self._llm = llama["Llama"](
                model_path=self.base_gguf,
                lora_path=self._adapter_file,  # 运行时叠加 FP16 LoRA，保留精度
                n_ctx=self.num_ctx,
                n_gpu_layers=gpu_layers,
                verbose=self.verbose,
            )
            self._load_error = None
            return True
        except Exception as e:
            self._load_error = f"{type(e).__name__}: {e}"
            print(f"[LlamaCppClient] 模型加载失败: {self._load_error}")
            return False

    # ------------------------------------------------------------------
    # OllamaClient/VLLMClient/TransformersClient 兼容接口
    # ------------------------------------------------------------------
    def check_connection(self) -> bool:
        return self._llm is not None

    def is_ready(self) -> bool:
        """进程内后端是否就绪：已加载，或基座 GGUF + LoRA adapter 资源齐全。

        与 check_connection() 不同：check_connection() 仅表示模型是否已读入显存；
        is_ready() 表示"引擎可用"——资源已就绪、首次扫描时才懒加载（8B Q4 GGUF
        约 5GB），避免健康检查/前端每次强制加载拖慢启动。
        """
        if self._llm is not None:
            return True
        # 资源齐全：GGUF 基座存在 + adapter 目录含权重文件
        if not self.base_gguf or not Path(self.base_gguf).is_file():
            return False
        if not self.adapter or not Path(self.adapter).is_dir():
            return False
        for name in ("adapter_model.gguf", "adapter_model.safetensors", "adapter_model.bin"):
            if (Path(self.adapter) / name).is_file():
                return True
        return False

    def list_models(self) -> List[str]:
        return [self.model] if self._llm is not None else []

    def unload_model(self, timeout: int = 60) -> bool:
        if self._llm is not None:
            try:
                del self._llm
                self._llm = None
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
        """生成文本（ChatML 手工拼接，禁用 Qwen3 thinking，贪心解码）。"""
        start_time = time.time()
        if not self.load_model():
            return {
                "text": "", "duration": 0.0,
                "tokens": {"prompt": 0, "completion": 0, "total": 0},
                "meta": {}, "error": self._load_error,
            }

        text = _build_chatml(system_prompt, prompt)
        max_new = max_tokens if max_tokens is not None else 2048

        # num_ctx 生效：prompt 超预算时截断（保留尾部，代码与结论在 prompt 末尾），
        # 否则 create_completion 会直接抛异常
        ctx = num_ctx or self.num_ctx
        budget = max(1, ctx - max_new)
        tokens = self._llm.tokenize(text.encode("utf-8"))
        if len(tokens) > budget:
            tokens = tokens[-budget:]
            text = self._llm.detokenize(tokens).decode("utf-8", errors="replace")
        n_prompt_tokens = len(tokens)

        with self._gen_lock:
            try:
                resp = self._llm.create_completion(
                    prompt=text,
                    max_tokens=max_new,
                    temperature=temperature,
                    top_p=0.9 if temperature > 0 else 1.0,
                    stream=False,
                )
                choices = resp.get("choices", [])
                response = choices[0].get("text", "") if choices else ""
                usage = resp.get("usage", {})
                n_completion = usage.get("completion_tokens", 0)
                if not n_completion:
                    n_completion = len(self._llm.tokenize(response.encode("utf-8")))
                return {
                    "text": response,
                    "duration": time.time() - start_time,
                    "tokens": {
                        "prompt": n_prompt_tokens,
                        "completion": n_completion,
                        "total": n_prompt_tokens + n_completion,
                    },
                    "meta": {"backend": "llamacpp", "model": self.base_gguf},
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
        """结构化输出兜底：退化为普通 generate（模型训练时已学会 JSON 输出）。

        注意：llama.cpp 支持 GBNF 语法约束，但本客户端未启用——与 Ollama
        format=json 的"保证可解析"不同，本路径不保证，首次调用打印一次警告。
        """
        if not getattr(self, "_structured_warned", False):
            print("[LlamaCppClient] 警告: 本后端未启用语法约束解码，generate_structured "
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

    def generate_batch(
        self,
        prompts: List[str],
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = 2048,
        num_ctx: Optional[int] = None,
    ) -> List[Dict]:
        """批量生成（实验性）：逐条走 llama.cpp（内核快，但未做真正的并发 batch）。

        llama-cpp-python 高层 API 未暴露并发序列 batch，这里顺序循环。尽管如此，
        每条仍走 llama.cpp 的高速内核 + FP16 LoRA，已比 bitsandbytes 单条快。
        """
        results = []
        for p in prompts:
            results.append(self.generate(
                prompt=p,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
                num_ctx=num_ctx,
            ))
        return results

    def analyze_vulnerability(
        self,
        code: str,
        language: str = "python",
        rag_context: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> Dict:
        """分析代码漏洞（接口对齐，供 standalone 使用）。"""
        prompt = build_user_prompt(
            code=code, language=language, filename=filename, rag_context=rag_context
        )
        # 优先允许环境变量覆盖（供消融实验/调试），否则默认对齐 v3 训练 prompt。
        system_prompt = os.environ.get("VULN_SCANNER_SYSTEM_PROMPT") or V3_PROMPT
        return self.generate(prompt, system_prompt=system_prompt)


# 兼容工厂：与 create_llm_client 对齐
def create_llm_client(backend: str = "llamacpp", **kwargs):
    """按 backend 名创建客户端。'llamacpp' 返回 LlamaCppClient；其余转发。"""
    backend_lower = backend.strip().lower()
    if backend_lower in ("llamacpp", "llama-cpp", "llama_cpp", "gguf"):
        return LlamaCppClient(**kwargs)
    if backend_lower == "transformers":
        from graduation_project.transformers_client import TransformersClient
        return TransformersClient(**kwargs)
    if backend_lower == "ollama":
        from graduation_project.llm_client import OllamaClient
        return OllamaClient(**kwargs)
    if backend_lower == "vllm":
        from graduation_project.vllm_client import VLLMClient
        return VLLMClient(**kwargs)
    raise ValueError(f"未知 backend: {backend}")


if __name__ == "__main__":
    # 自检：加载 + 推理一条注入漏洞
    client = LlamaCppClient()
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