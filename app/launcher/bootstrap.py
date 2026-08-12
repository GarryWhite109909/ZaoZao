"""
启动器 —— 首次使用检测推理后端与模型，后续直接启动后端 + 打开浏览器。

推理后端（与 app/backend/services/scanner.py 的解析规则一致）：
    - transformers：配置了 VULN_SCANNER_ADAPTER 时启用（Q4 基座 + FP16 LoRA 进程内推理，
      复现 95% 召回管道），需要 transformers/peft/bitsandbytes，不依赖 Ollama
    - ollama：默认一键启动形态（GGUF Q4_K_M 发布模型），自动安装/启动 Ollama 并拉取模型
    - llamacpp：Q4 GGUF 基座 + 运行时 FP16 LoRA，需要 llama-cpp-python
    - vllm：实验性（暂无现成测试机器），AWQ/GPTQ 基座 + FP16 LoRA，仅 Linux/WSL2
    可用 VULN_SCANNER_BACKEND 显式覆盖。

跨平台入口：
    python -m app.launcher.bootstrap

启动脚本：
    Windows: 双击 start_windows.bat
    Linux/macOS: bash start_linux_macos.sh
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

import requests

from app.launcher import dependency_installer
from graduation_project.paths import (
    resolve_adapter_path,
    find_project_root,
    ollama_models_dir,
    hf_home_dir,
    local_vllm_model_dir,
    llamacpp_dir,
)
from graduation_project.transformers_client import (
    is_transformers_runtime_compatible,
    migrate_hf_cache_to_project,
    resolve_default_backend,
)

# 项目根目录（Graduation-Project/）
PROJECT_ROOT = Path(__file__).resolve().parents[2]
# 默认模型（从模型注册表读取当前默认版本，如 v9max；导入失败时回退到 v9max 全名）
try:
    from app.backend.services.model_registry import (
        get_default_model as _get_default_model,
        normalize_ollama_name as _normalize_ollama_name,
    )
    DEFAULT_MODEL = os.environ.get("VULN_SCANNER_MODEL", _get_default_model())
except Exception:
    _normalize_ollama_name = lambda name: name  # noqa: E731
    DEFAULT_MODEL = os.environ.get("VULN_SCANNER_MODEL", "garrywhite109909/graduation-vuln-scanner:v9max")
# 回退模型（官方 Qwen3-8B，未微调）
FALLBACK_MODEL = os.environ.get("VULN_SCANNER_FALLBACK_MODEL", "qwen3:8b")
# 后端端口
PORT = 8765


def resolve_backend() -> str:
    """解析推理后端（委托 transformers_client.resolve_default_backend，与 scanner 共用）。"""
    return resolve_default_backend()


def migrate_ollama_models_to_project() -> Optional[str]:
    """把 C 盘/外部的 Ollama 模型存储剪切到项目 models/ollama（现行分类标准）。

    规则：
    - 候选源：OLLAMA_MODELS 指向的位置 + ~/.ollama/models（兼容默认 C 盘）；
    - 源目录有内容（含未下载完的 partial）就整体迁移，C 盘不留任何模型文件；
    - Ollama 服务正在运行时跳过并提示先退出（Windows 文件锁会失败/损坏运行中的服务）。
    OLLAMA_MODELS 由调用方在启动前锁定到项目目录，保证后续 pull 不写 C 盘。
    """
    dst = ollama_models_dir()
    candidates: list[Path] = []
    env_val = os.environ.get("OLLAMA_MODELS", "").strip()
    if env_val:
        candidates.append(Path(env_val).expanduser())
    candidates.append(Path.home() / ".ollama" / "models")

    for src in candidates:
        if not src.is_dir():
            continue
        try:
            if src.resolve() == dst.resolve():
                continue
        except Exception:  # noqa: BLE001
            pass
        # C 盘不允许出现任何模型文件：有真实模型文件（含未下完的 partial）就整体迁移；
        # 只有空目录残留（blobs/manifests 空壳）不算内容，顺手清掉即可
        if not _has_model_files(src):
            _remove_empty_model_dirs(src)
            continue
        # 源目录只剩“项目里已有完整版”的过期 partial / 重复文件时，不提示、不迁移，
        # 直接清理干净（例如：alpha0 已在项目下完，C 盘只剩它的 partial 残留）
        if not _needs_migration(src, dst):
            print(f"[启动器] {src} 只剩项目里已存在的过期/重复文件，正在清理...")
            _cleanup_redundant_src_files(src, dst)
            _remove_empty_model_dirs(src)
            continue

        # Ollama 正在运行：Windows 上文件被占用，剪切会失败或破坏运行中的服务
        try:
            resp = requests.get(
                "http://localhost:11434/api/tags", timeout=2,
                proxies={"http": None, "https": None},
            )
            running = resp.status_code == 200
        except Exception:  # noqa: BLE001
            running = False
        if running:
            print(f"[启动器] 检测到 Ollama 正在运行且模型存储仍在 {src}：")
            try:
                ans = input("  是否自动退出 Ollama 完成迁移？[Y/n]: ").strip().lower()
            except EOFError:
                # 非交互环境（无 stdin）无法等待用户确认：默认执行迁移，
                # 与交互默认 [Y] 一致，避免模型文件继续落回 C 盘。
                ans = "y"
            if ans in ("y", "yes", ""):
                _stop_ollama()
                try:
                    resp2 = requests.get(
                        "http://localhost:11434/api/tags", timeout=2,
                        proxies={"http": None, "https": None},
                    )
                    still_running = resp2.status_code == 200
                except Exception:  # noqa: BLE001
                    still_running = False
                if still_running:
                    hint = (
                        "托盘 → Quit 后重试" if sys.platform == "win32"
                        else "关闭 Ollama 或 `pkill -f ollama` 后重试"
                    )
                    print(f"  Ollama 仍在运行，请手动退出（{hint}）。")
                    return None
                print(f"[启动器] Ollama 已退出，开始迁移到 {dst} ...")
            else:
                print("  已取消迁移；请先退出 Ollama 再运行本启动器，否则本次拉取仍会写入旧位置。")
                return None

        dst.mkdir(parents=True, exist_ok=True)
        # 迁移前先清掉过期残留（项目已有完整版的 partial），避免无谓跨盘搬运
        _cleanup_redundant_src_files(src, dst)
        print(f"[启动器] 检测到 Ollama 模型存储 {src}，正在剪切到 {dst} ...")
        try:
            # 逐文件按相对路径镜像搬移（blobs/、manifests/ 子目录结构保持），
            # 避免“目标已有 blobs 目录就整包跳过”导致 C 盘文件永远搬不走
            for item in sorted(src.rglob("*")):
                if not item.is_file() or not item.exists():
                    continue
                rel = item.relative_to(src)
                target = dst / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    # 同名文件：内容相同（同大小）视为重复副本，删源；不同则保留源并跳过
                    try:
                        same = item.stat().st_size == target.stat().st_size
                    except OSError:
                        same = False
                    if same:
                        print(f"[启动器] {item.name} 与项目内容相同，删除源副本")
                        item.unlink()
                    else:
                        print(f"[启动器] {item.name} 已存在于目标目录且内容不同，跳过")
                    continue
                shutil.move(str(item), str(target))
        except Exception as e:  # noqa: BLE001
            print(f"[启动器] Ollama 模型迁移失败: {e}")
            print("  请确认 Ollama 已完全退出后重试。")
            return None
        _remove_empty_model_dirs(src)  # 内容已全部搬走，清理源目录空壳
        os.environ["OLLAMA_MODELS"] = str(dst)  # 迁移后锁定到项目目录
        print(f"[启动器] ✅ 已剪切 Ollama 模型到 {dst}")
        return str(dst)
    return None


def _has_model_files(path: Path) -> bool:
    """判断目录里是否有真正的模型文件（递归找文件；纯空目录不算内容）。"""
    try:
        for p in path.rglob("*"):
            if p.is_file():
                return True
    except Exception:
        return True  # 无法读取时保守视为有内容，避免误删
    return False


def _needs_migration(src: Path, dst: Path) -> bool:
    """判断源目录是否还有**真正需要迁移**的内容。

    不需要迁移的情况：
        - 只有过期 partial（sha256-xxx-partial），而项目里已有完整 sha256-xxx；
        - 只有与项目内容完全相同（同名且同大小）的重复文件；
        - 只有空目录。
    其余情况（未完成的 partial、项目里没有的模型等）都需要迁移。
    """
    try:
        for p in src.rglob("*"):
            if not p.is_file():
                continue
            name = p.name
            # 源文件在 src 下的相对子目录（如 blobs/...）要镜像到 dst 的相同子目录
            rel_dir = p.relative_to(src).parent
            mirrored = dst / rel_dir / name
            if name.endswith("-partial"):
                # 项目里已有同名 partial（正在下载/续传）或完整文件时，源文件是冗余残留
                if mirrored.exists() or (dst / rel_dir / name[: -len("-partial")]).exists():
                    continue
                return True
            if "-partial-" in name:
                # 分块标记：跟随主 partial 处理；项目里已有完整版则忽略
                base = name.split("-partial-")[0]
                if (dst / rel_dir / base).exists() or (dst / rel_dir / (base + "-partial")).exists():
                    continue
                return True
            if mirrored.exists():
                # 同名完整文件：大小一致视为内容重复，不需要迁移
                try:
                    if p.stat().st_size == mirrored.stat().st_size:
                        continue
                except OSError:
                    pass
            return True
    except Exception:
        return True  # 无法读取时保守视为需要迁移
    return False


def _cleanup_redundant_src_files(src: Path, dst: Path) -> None:
    """清理源目录里项目已存在对应完整版的冗余文件（过期 partial / 重复文件）。"""
    for item in list(src.rglob("*")):
        if not item.is_file() or not item.exists():
            continue
        name = item.name
        rel_dir = item.relative_to(src).parent
        mirrored = dst / rel_dir / name
        try:
            if name.endswith("-partial") and (
                mirrored.exists() or (dst / rel_dir / name[: -len("-partial")]).exists()
            ):
                item.unlink()
                for sibling in (src / rel_dir).glob(name[: -len("-partial")] + "-partial-*"):
                    try:
                        sibling.unlink()
                    except OSError:
                        pass
                print(f"[启动器] 已删除过期下载残留 {name}")
            elif "-partial-" in name and item.is_file():
                base = name.split("-partial-")[0]
                if (dst / rel_dir / base).exists() or (dst / rel_dir / (base + "-partial")).exists():
                    item.unlink()
                    print(f"[启动器] 已删除过期分块标记 {name}")
            elif item.is_file() and mirrored.exists():
                if item.stat().st_size == mirrored.stat().st_size:
                    item.unlink()
                    print(f"[启动器] 已删除与项目重复的文件 {name}")
        except OSError as e:
            print(f"[启动器] 清理残留失败: {e}（不影响使用，可稍后手动清理）")


def _remove_empty_model_dirs(path: Path) -> None:
    """自底向上删除 path 下的空目录残留（不含任何文件的目录），最后删 path 本身。"""
    try:
        for p in sorted(path.rglob("*"), key=lambda x: len(x.parts), reverse=True):
            if p.is_dir() and not _has_model_files(p):
                p.rmdir()
        if path.is_dir() and not _has_model_files(path):
            path.rmdir()
    except OSError:
        pass


def _stop_ollama() -> bool:
    """尝试停止 Ollama（供迁移/接管前使用），并轮询确认其真正退出。

    Windows 必须先结束托盘应用（ollama app.exe）：它会在 serve 被杀后立即
    重新拉起一个默认存储（~/.ollama/models）的服务并抢占 11434，导致模型
    下载落到 C 盘。结束 app 后再结束 serve 才能真正接管。
    """
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/IM", "ollama app.exe", "/T", "/F"],
                capture_output=True, text=True, timeout=30,
            )
            subprocess.run(
                ["taskkill", "/IM", "ollama.exe", "/T", "/F"],
                capture_output=True, text=True, timeout=30,
            )
        else:
            # 先尝试停 systemd 服务（sudo -n 免密时生效；无权限失败也无害），
            # 再 pkill 兜底。轮询 /api/tags 确认真正停止。
            subprocess.run(
                ["systemctl", "stop", "ollama"],
                capture_output=True, text=True, timeout=30,
            )
            # 兜底：仅匹配 ollama serve 进程，避免 `pkill -f ollama` 误杀
            # 命令行里恰好包含 "ollama" 字样的无关进程。
            subprocess.run(["pkill", "-f", "ollama serve"], capture_output=True, text=True, timeout=15)
            subprocess.run(["pkill", "-9", "-f", "ollama serve"], capture_output=True, text=True, timeout=15)
        # 等待服务真正退出（最多 ~5s）
        for _ in range(10):
            try:
                r = requests.get(
                    "http://localhost:11434/api/tags", timeout=1,
                    proxies={"http": None, "https": None},
                )
                if r.status_code != 200:
                    return True
            except Exception:
                return True
            time.sleep(0.5)
        return False
    except Exception:  # noqa: BLE001
        return False


def _listening_pid_on(port: int = 11434) -> Optional[str]:
    """返回占用指定端口的进程 PID（跨平台）。"""
    try:
        if sys.platform == "win32":
            out = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True, text=True, timeout=5,
                encoding="utf-8", errors="replace",
            ).stdout
            for line in out.splitlines():
                if f":{port}" in line and "LISTENING" in line:
                    parts = line.split()
                    if parts:
                        return parts[-1]
        else:
            out = subprocess.run(
                ["lsof", "-ti", f"tcp:{port}"],
                capture_output=True, text=True, timeout=5,
            ).stdout.split()
            return out[0] if out else None
    except Exception:
        pass
    return None


def _recommend_backend_by_vram() -> tuple[str, str]:
    """根据显存推荐推理后端。

    规则：
        - ≥8GB 显存：推荐 transformers（NF4 基座 + FP16 LoRA，精度最高）
        - 无独显或 <8GB 显存：推荐 ollama（CPU/GPU 皆可，兼容性最好）
    返回 (推荐后端, 推荐理由)。
    """
    try:
        hardware = detect_hardware()
    except Exception:
        hardware = {}
    vram_mb = hardware.get("vram_mb")
    gpu_name = hardware.get("gpu_name")
    has_gpu = hardware.get("has_nvidia_gpu") or hardware.get("has_amd_gpu")

    if vram_mb and vram_mb >= 8192:
        g = gpu_name or "GPU"
        ok, reason = is_transformers_runtime_compatible()
        if not ok:
            return "ollama", (
                f"检测到 {g} 显存约 {vram_mb // 1024}GB，但当前 torch 环境不兼容"
                f"（{reason[:80]}），推荐 Ollama（兼容性最好）"
            )
        return "transformers", f"检测到 {g} 显存约 {vram_mb // 1024}GB，可跑 NF4 基座 + FP16 LoRA（精度最高）"
    if has_gpu and vram_mb:
        g = gpu_name or "GPU"
        return "ollama", f"检测到 {g} 显存约 {vram_mb // 1024}GB，不足以全 GPU 跑 8B 模型，Ollama 可 CPU/GPU 混合，兼容最好"
    return "ollama", "未检测到独立显存/显存不足，Ollama 纯 CPU 也能跑，兼容性最好"


def select_backend() -> str:
    """交互式选择推理后端，允许用户覆盖自动解析结果。

    自动解析规则：
        - 已设置 VULN_SCANNER_BACKEND 时直接使用
        - 已设置 VULN_SCANNER_ADAPTER 时自动选 transformers
        - 项目根目录 models/ 下探测到合法 adapter 时自动选 transformers
        - 否则默认 ollama

    交互式环境：额外根据显存给出推荐（≥8GB→transformers，否则→ollama），
    仅在显式设置 VULN_SCANNER_BACKEND 时强制采用，否则用户可回车跟推荐或手动选择。

    非交互式环境（如 CI）直接返回自动解析结果，避免 input 挂起。
    """
    default_backend = resolve_backend()
    if not sys.stdin.isatty():
        return default_backend

    label_map = {
        "ollama": "Ollama",
        "transformers": "Transformers",
        "llamacpp": "LlamaCPP",
        "vllm": "vLLM",
    }
    default_label = label_map.get(default_backend, default_backend)

    desc = {
        "ollama": "一键启动（兼容性最好，CPU/GPU 皆可）",
        "transformers": "进程内 NF4 基座 + FP16 LoRA（需 8GB+ 显存，精度最高）",
        "llamacpp": "Q4 GGUF + 运行时 LoRA（需适配 CMAKE）",
        "vllm": "实验性（暂无现成测试机器），AWQ/GPTQ 基座 + FP16 LoRA（高吞吐，需 NVIDIA GPU）",
    }

    # 显存推荐：只有未显式锁定后端时才用于覆盖默认值
    recommended, reason = _recommend_backend_by_vram()
    if not os.environ.get("VULN_SCANNER_BACKEND", "").strip():
        # 推荐 transformers 但没有任何 adapter 时它跑不起来，退回 ollama
        if recommended == "transformers" and (
            not resolve_adapter_path() or not is_transformers_runtime_compatible()[0]
        ):
            recommended = "ollama"
            reason = "显存充足但当前环境无法运行 transformers 后端（缺 adapter 或 torch 内核不匹配），退回 Ollama"
        default_backend = recommended
        default_label = label_map.get(default_backend, default_backend)

    print()
    print("=" * 60)
    print("  推理后端选择")
    print("=" * 60)
    print(f"  [{reason}]")
    print(f"  推荐: {label_map.get(recommended, recommended)}（按回车直接使用）")
    print("-" * 60)
    # vLLM 官方仅支持 Linux/WSL2：Windows/macOS 上不提供该选项
    is_linux = dependency_installer.detect_platform().os_name == "linux"
    backend_order = ("ollama", "transformers", "llamacpp", "vllm") if is_linux else ("ollama", "transformers", "llamacpp")
    if not is_linux:
        print("  [说明] vLLM 仅支持 Linux/WSL2，当前平台已隐藏该选项")
    for idx, bid in enumerate(backend_order, start=1):
        mark = "  ← 当前" if bid == default_backend else ""
        tag = label_map.get(bid, bid)
        print(f"  [{idx}] {tag:<13}—— {desc[bid]}{mark}")
    print("-" * 60)
    while True:
        choice = input(f"请选择推理后端（回车=使用 {default_label}，1-{len(backend_order)}=切换）: ").strip()
        if choice == "":
            return default_backend
        try:
            idx = int(choice)
            if 1 <= idx <= len(backend_order):
                return backend_order[idx - 1]
        except ValueError:
            pass
        print("[启动器] 无效输入，请重新选择。")


def resolve_transformers_merge() -> str:
    """选定 transformers 后端后，追加 LoRA 合并 / 不合并子选择。

    返回 "1"=合并（默认，推理快） / "0"=不合并（LoRA 保持 FP16 精度、精度更高，但更慢）。
    选择写入环境变量传给后端进程，后端启动后即固定，重启后端前无法更改。

    非交互环境（stdin 非 tty）或已显式设置 VULN_SCANNER_MERGE 时直接沿用现有值，不重复询问。
    """
    existing = os.environ.get("VULN_SCANNER_MERGE", "").strip()
    if existing in ("0", "1") or not sys.stdin.isatty():
        return existing or "1"
    print()
    print("  Transformers 后端 · LoRA 合并方式")
    print("-" * 60)
    print("  [1] 合并 LoRA 进基座（默认，推理更快）")
    print("  [2] 不合并，运行时叠加（LoRA 保持 FP16 精度，精度更高，但推理更慢）")
    print("  ⚠ 该选择会写入后端配置；后端启动后固定，重启后端前无法更改。")
    while True:
        choice = input("请选择（回车=合并，1=合并，2=不合并）: ").strip()
        if choice == "" or choice == "1":
            return "1"
        if choice == "2":
            return "0"
        print("[启动器] 无效输入，请输入 1 或 2。")


def check_inprocess_backend_ready(backend: str) -> bool:
    """校验进程内 / 独立服务的推理后端（transformers/llamacpp/vllm）的依赖与模型配置。

    依赖检查已前置由 dependency_installer 完成；本函数主要验证：
        - transformers: LoRA adapter 目录是否存在（支持 models/ 自动探测）
        - llamacpp: VULN_SCANNER_GGUF 与 LoRA adapter 是否存在
        - vllm: VULN_SCANNER_VLLM_MODEL 指向的基座模型目录/id 是否合法

    返回 True 表示就绪；False 时已打印具体缺失项与修复命令。
    """
    ok = True
    project_root = find_project_root()
    models_dir = project_root / "models"

    if backend == "transformers":
        ok_runtime, reason_runtime = is_transformers_runtime_compatible()
        if not ok_runtime:
            # CPU torch（无 CUDA/ROCm）是低显存机器上 transformers 的预期路径：
            # 保留 CPU 版走 4bit CPU 推理，不当作错误拦截。
            cpu_mode = "CUDA/ROCm" in reason_runtime or "未检测到" in reason_runtime
            if cpu_mode:
                print(f"[启动器] ⚠ transformers 后端将使用 CPU 推理（{reason_runtime}）；"
                      "4bit 仍可用但速度慢，建议改用 Ollama")
            else:
                print(f"[错误] 当前环境无法运行 transformers 后端: {reason_runtime}")
                print("  建议：设置 VULN_SCANNER_BACKEND=ollama 改用 Ollama 后端，")
                print("  或安装与显卡匹配的 torch/bitsandbytes 后再试。")
                ok = False
        adapter = resolve_adapter_path()
        if not adapter:
            print("[错误] transformers 后端需要 LoRA adapter 目录")
            print("  （目录内需含 adapter_model.safetensors / adapter_model.bin）")
            print(f"  推荐做法：将 adapter 放到 {models_dir / 'adapter'}")
            print("  示例: set VULN_SCANNER_ADAPTER=D:\\code\\Graduation-Project\\models\\adapter")
            ok = False
        elif not Path(adapter).is_dir():
            print(f"[错误] LoRA adapter 路径不存在: {adapter}")
            ok = False
        else:
            # 把最终解析到的路径写回环境变量，供后端进程读取
            os.environ["VULN_SCANNER_ADAPTER"] = adapter
    elif backend == "llamacpp":
        gguf = os.environ.get("VULN_SCANNER_GGUF", "").strip()
        adapter = resolve_adapter_path()
        if not gguf:
            # 自动探测 models/llamacpp/ 下的 GGUF。为保证与 llamacpp_client 的量化
            # 优先级（Q4 优先）完全一致，直接复用其 _discover_gguf，避免 bootstrap 用
            # 文件名首字母排序导致多 .gguf 时选到不同文件。
            try:
                from graduation_project.llamacpp_client import LlamaCppClient
                discovered = LlamaCppClient._discover_gguf()
            except Exception:
                discovered = ""
            if discovered and Path(discovered).is_file():
                gguf = discovered
                os.environ["VULN_SCANNER_GGUF"] = gguf
        if not gguf:
            # GGUF 未配置：不拦截启动。与 transformers 后端一致——允许先进应用，
            # 在「设置 → 模型管理」下载 GGUF 到 models/llamacpp/（下载完成自动绑定），
            # 首次扫描时再懒加载。真正扫描前若仍未就绪，LlamaCppClient 会在生成时报错。
            print("[启动器] ⚠ llamacpp 后端未配置 GGUF 基座，可先进应用下载：")
            print(f"  「设置 → 模型管理 → llamacpp」下载到 {llamacpp_dir()}")
            print(f"  或设置 VULN_SCANNER_GGUF 后重启后端（示例: VULN_SCANNER_GGUF="
                  f"{llamacpp_dir()}\\Qwen3-8B-Q4_K_M.gguf）")
        elif not Path(gguf).is_file():
            print(f"[错误] GGUF 文件不存在: {gguf}")
            ok = False
        if not adapter:
            print("[错误] llamacpp 后端需要 FP16 LoRA adapter 目录")
            print(f"  推荐做法：将 adapter 放到 {models_dir / 'adapter'}")
            ok = False
        elif not Path(adapter).is_dir():
            print(f"[错误] LoRA adapter 路径不存在: {adapter}")
            ok = False
        else:
            os.environ["VULN_SCANNER_ADAPTER"] = adapter
    elif backend == "vllm":
        # vLLM 是独立服务，基座模型由 VULN_SCANNER_VLLM_MODEL 指定（HF id 或本地 AWQ/GPTQ 目录）。
        # 优先自动探测项目 models/vllm/ 下的量化目录（与 transformers 的 models/transformers 对齐）；
        # 未探测到时要求显式配置。
        model = os.environ.get("VULN_SCANNER_VLLM_MODEL", "").strip()
        if not model:
            for repo_name in ("Qwen3-8B-AWQ", "Qwen3-8B-GPTQ"):
                d = local_vllm_model_dir(repo_name)
                if (d / "config.json").is_file():
                    model = str(d)
                    os.environ["VULN_SCANNER_VLLM_MODEL"] = model
                    break
        if not model:
            # 兼容旧布局：models/ 根下的量化目录
            candidates = ["vllm", "awq", "gptq", "Qwen3-8B-AWQ", "Qwen3-8B-GPTQ"]
            for cand in candidates:
                d = models_dir / cand
                if (d / "config.json").is_file():
                    model = str(d)
                    os.environ["VULN_SCANNER_VLLM_MODEL"] = model
                    break
        if not model:
            print("[错误] vllm 后端需要 VULN_SCANNER_VLLM_MODEL 指向基座模型")
            print("  （HF id 或本地 AWQ/GPTQ 量化目录，需含 config.json）")
            print(f"  示例: set VULN_SCANNER_VLLM_MODEL=D:\\code\\Graduation-Project\\models\\vllm\\Qwen3-8B-AWQ")
            print(f"  或将量化目录放到 {models_dir}\\vllm（设置页可下载 Qwen/Qwen3-8B-AWQ）")
            ok = False
        elif not (model.startswith("/") or ":" in model or "\\" in model or "." in model):
            # 看起来很可能是 HF id（如 Qwen/Qwen3-8B-AWQ），无需本地校验
            pass
        elif Path(model).expanduser().is_dir():
            local = Path(model).expanduser()
            if not (local / "config.json").is_file():
                print(f"[错误] vLLM 模型目录缺少 config.json: {local}")
                ok = False
        else:
            print(f"[错误] vLLM 模型路径不存在（既不是 HF id 也不是本地目录）: {model}")
            ok = False
        # 为 vllm_server.py 固化对外模型名（与 scanner.py 的 model 一致）
        os.environ.setdefault("VULN_SCANNER_MODEL", DEFAULT_MODEL)
    return ok


def is_port_in_use(port: int) -> bool:
    """检测本机指定端口是否已被占用（仅判断 127.0.0.1）。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        try:
            s.bind(("127.0.0.1", port))
            return False
        except OSError:
            return True


def kill_process_on_port(port: int) -> bool:
    """尝试终止占用指定端口的进程。Windows 用 netstat+taskkill；其他平台用 lsof/fuser。

    仅在能确认 PID 时执行，且结束前需用户确认，避免误杀无关服务。
    """
    try:
        if sys.platform == "win32":
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True, text=True, timeout=5,
            )
            target_pid = None
            for line in result.stdout.splitlines():
                parts = line.split()
                # 期望格式：Proto  Local Address  Foreign Address  State  PID
                if (
                    len(parts) >= 5
                    and f":{port}" in parts[1]
                    and parts[3] == "LISTENING"
                ):
                    target_pid = parts[-1]
                    break
            if target_pid and target_pid.isdigit():
                print(f"[启动器] 端口 {port} 被 PID {target_pid} 占用。")
                answer = input("该进程可能不是本程序（例如其他服务），是否强制结束？[y/N]: ").strip().lower()
                if answer not in ("y", "yes"):
                    print("[启动器] 已取消释放端口，请手动关闭占用程序后重试。")
                    return False
                print(f"[启动器] 尝试结束 PID {target_pid} ...")
                stop = subprocess.run(
                    ["taskkill", "/F", "/PID", target_pid],
                    capture_output=True, text=True, timeout=10,
                )
                return stop.returncode == 0
        else:
            # macOS/Linux：收集占用端口的**全部** PID（lsof 优先，fuser 兜底）。
            # 端口可能同时被主进程 + worker 多个进程持有，必须全部结束才能释放。
            pids: list[str] = []
            try:
                result = subprocess.run(
                    ["lsof", "-ti", f"tcp:{port}"],
                    capture_output=True, text=True, timeout=5,
                )
                pids = [p for p in result.stdout.split() if p.isdigit()]
            except Exception:
                pids = []
            if not pids:
                try:
                    result = subprocess.run(
                        ["fuser", f"{port}/tcp"],
                        capture_output=True, text=True, timeout=5,
                    )
                    pids = [p for p in result.stdout.split() if p.isdigit()]
                except Exception:
                    pids = []
            if pids:
                print(f"[启动器] 端口 {port} 被 PID {', '.join(pids)} 占用。")
                # 非交互式环境（CI/后台）无法确认，视为允许释放（通常就是本程序残留后端）
                if sys.stdin.isatty():
                    answer = input("该进程可能不是本程序（例如其他服务），是否强制结束？[y/N]: ").strip().lower()
                    if answer not in ("y", "yes"):
                        print("[启动器] 已取消释放端口，请手动关闭占用程序后重试。")
                        return False
                print(f"[启动器] 尝试结束 PID {', '.join(pids)} ...")
                for pid in pids:
                    subprocess.run(["kill", "-9", pid], capture_output=True, text=True, timeout=5)
                # 兜底：fuser -k 清除端口上剩余持有进程（含进程组/worker）
                try:
                    subprocess.run(
                        ["fuser", "-k", f"{port}/tcp"],
                        capture_output=True, text=True, timeout=5,
                    )
                except Exception:
                    pass
                return True
    except Exception as e:
        print(f"[启动器] 释放端口 {port} 失败: {e}")
    return False


def check_ollama_installed() -> bool:
    """检测系统是否安装 Ollama。"""
    return shutil.which("ollama") is not None


def _ollama_version() -> Optional[str]:
    """读取 Ollama 版本号（如 '0.5.7'）；读取失败返回 None。"""
    try:
        r = subprocess.run(
            ["ollama", "--version"],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace",
        )
        if r.returncode != 0:
            return None
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", r.stdout + r.stderr)
        return m.group(1) if m else None
    except Exception:
        return None


def _maybe_upgrade_ollama() -> None:
    """检测 Ollama 版本是否过旧，过旧时提示并（交互式确认后）自动升级。

    Ollama 0.30+ 才支持 Qwen3/QwQ 等模型的 think 参数；过旧版本会导致
    这类模型的 response 为空或行为异常，因此启动时做一次版本检查。
    """
    ver = _ollama_version()
    if not ver:
        print("[启动器] 无法读取 Ollama 版本号（跳过版本检查）")
        return
    print(f"[启动器] Ollama 版本: {ver}")
    if not dependency_installer._version_lt(ver, "0.30"):
        return
    print(f"[启动器] ⚠ Ollama {ver} 版本过旧：0.30+ 才支持 Qwen3 等模型的 think 参数。")
    if not sys.stdin.isatty():
        print("[启动器] 非交互环境，跳过自动升级；可手动执行 winget upgrade Ollama.Ollama")
        return
    try:
        ans = input("[启动器] 是否自动升级 Ollama？[Y/n]: ").strip().lower()
    except EOFError:
        return
    if ans in ("n", "no"):
        print("[启动器] 跳过升级，继续启动（旧版可能影响 Qwen3 系列模型）")
        return
    print("[启动器] 正在升级 Ollama...")
    try:
        if sys.platform == "win32" and shutil.which("winget"):
            subprocess.run(
                ["winget", "upgrade", "Ollama.Ollama",
                 "--accept-source-agreements", "--accept-package-agreements"],
                timeout=1800,
            )
        elif sys.platform == "darwin" and shutil.which("brew"):
            subprocess.run(["brew", "upgrade", "ollama"], timeout=1800)
        else:
            print("[启动器] 当前平台暂不支持自动升级，请手动升级：https://ollama.com/download")
            return
        print("[启动器] Ollama 升级完成，请重新运行本启动器以让新版本生效")
    except subprocess.TimeoutExpired:
        print("[启动器] Ollama 升级超时，请稍后重试或手动升级")
    except Exception as e:
        print(f"[启动器] Ollama 升级失败: {e}")


def try_install_ollama() -> bool:
    """尝试自动安装 Ollama。成功返回 True，失败回退到打开下载页。"""
    print("[启动器] 未检测到 Ollama，尝试自动安装...")

    if sys.platform == "win32":
        # Windows: 优先 winget
        if shutil.which("winget"):
            print("[启动器] 使用 winget 安装 Ollama（下载约 1.5GB，含安装过程）...")
            try:
                result = subprocess.run(
                    ["winget", "install", "Ollama.Ollama",
                     "--accept-source-agreements", "--accept-package-agreements"],
                    timeout=1800,  # 30 分钟：覆盖慢速下载 + 安装
                )
                if result.returncode == 0 and check_ollama_installed():
                    print("[启动器] Ollama 安装完成。")
                    return True
                print(f"[启动器] winget 退出码 {result.returncode}。")
            except subprocess.TimeoutExpired:
                print("[启动器] winget 安装超时（30 分钟未完成）。")
                print("[启动器] 可能是网络较慢，建议：")
                print("  1. 直接重试本启动器（winget 会续传已下载的部分）")
                print("  2. 或手动下载安装：https://ollama.com/download")
        else:
            print("[启动器] 未检测到 winget，无法自动安装。")
        webbrowser.open("https://ollama.com/download")
        return False

    elif sys.platform == "darwin":
        # macOS: 优先 Homebrew
        if shutil.which("brew"):
            print("[启动器] 使用 Homebrew 安装 Ollama...")
            try:
                result = subprocess.run(
                    ["brew", "install", "ollama"],
                    timeout=1800,  # 30 分钟
                )
                if result.returncode == 0 and check_ollama_installed():
                    print("[启动器] Ollama 安装完成。")
                    return True
                print(f"[启动器] brew 退出码 {result.returncode}。")
            except subprocess.TimeoutExpired:
                print("[启动器] brew 安装超时（30 分钟未完成）。")
                print("[启动器] 可能是网络较慢，建议手动安装：https://ollama.com/download")
        else:
            print("[启动器] 未检测到 brew，无法自动安装。")
        webbrowser.open("https://ollama.com/download")
        return False

    else:
        # Linux: 官方一键脚本（可能需要 sudo 密码）
        print("[启动器] 使用官方脚本安装 Ollama（如提示请输入 sudo 密码）...")
        try:
            result = subprocess.run(
                ["bash", "-c", "curl -fsSL https://ollama.com/install.sh | sh"],
                timeout=1800,  # 30 分钟
            )
            if result.returncode == 0 and check_ollama_installed():
                print("[启动器] Ollama 安装完成。")
                return True
            print(f"[启动器] 安装脚本退出码 {result.returncode}。")
        except subprocess.TimeoutExpired:
            print("[启动器] 安装超时（30 分钟未完成）。")
            print("[启动器] 可能是网络较慢，建议手动安装：https://ollama.com/download")
        webbrowser.open("https://ollama.com/download")
        return False


def _running_ollama_store() -> Optional[str]:
    """尽力读取占用 11434 的 ollama 进程的 OLLAMA_MODELS 存储路径。

    仅当运行用户与 ollama 进程同一用户（或 /proc 可读）时能读到；否则返回 None。
    """
    try:
        pids = subprocess.run(
            ["lsof", "-ti", "tcp:11434"],
            capture_output=True, text=True, timeout=5,
        ).stdout.split()
    except Exception:  # noqa: BLE001
        return None
    for pid in pids:
        if not pid.isdigit():
            continue
        try:
            env = Path(f"/proc/{pid}/environ").read_bytes().decode("utf-8", "ignore")
            for kv in env.split("\x00"):
                if kv.startswith("OLLAMA_MODELS="):
                    return kv.split("=", 1)[1]
        except Exception:  # noqa: BLE001
            continue
    return None


def ensure_ollama_running() -> bool:
    """确保 Ollama 服务运行，且使用**项目目录** models/ollama 作为存储。

    若检测到 11434 上已有 Ollama 服务但其存储不在项目目录（例如系统级 / 别的
    用户起的 systemd ollama），则停掉它并用项目目录重启，保证后续 pull 落到
    models/ollama。可用 VULN_SCANNER_KEEP_EXTERNAL_OLLAMA=1 关闭此强制接管。
    """
    want = str(ollama_models_dir())
    # 探测当前 11434 上是否已有 ollama 在服务
    try:
        resp = requests.get(
            "http://localhost:11434/api/tags",
            timeout=3,
            proxies={"http": None, "https": None},
        )
        up = resp.status_code == 200
    except Exception:  # noqa: BLE001
        up = False

    if up:
        store = _running_ollama_store()
        same_store = (
            store is not None
            and os.path.realpath(os.path.expanduser(store)) == os.path.realpath(want)
        )
        if same_store:
            return True  # 已是项目存储，直接复用
        if os.environ.get("VULN_SCANNER_KEEP_EXTERNAL_OLLAMA", "0").strip() == "1":
            print("[启动器] 检测到已运行的 Ollama（存储无法确认为项目目录），")
            print("         因 VULN_SCANNER_KEEP_EXTERNAL_OLLAMA=1，直接复用，不强制接管。")
            return True
        print(
            f"[启动器] 检测到 Ollama 已在运行，但其存储不在项目目录"
            f"（{'未知' if store is None else store}）。"
        )
        print(f"[启动器] 需要停掉它并用项目目录 {want} 重启，以保证模型落在 models/ollama。")
        if not _stop_ollama():
            print("[启动器] 无法自动停止现有 Ollama 服务（可能无权限）。")
            print("         请手动执行后重试：sudo systemctl stop ollama   （或 pkill -f ollama）")
            print("         或设置 VULN_SCANNER_KEEP_EXTERNAL_OLLAMA=1 直接复用现有服务。")
            return False

    # 启动我们自己的 serve（继承本进程 OLLAMA_MODELS=项目目录）。
    # Windows 上必须确认 11434 由我们启动的进程监听：Ollama 桌面版（ollama app.exe）
    # 会在 serve 被杀后立即重启默认存储的服务抢占端口，导致 pull 写到 C 盘。
    for attempt in range(2):
        print(f"[启动器] 启动 Ollama（模型存储: {want}）...")
        try:
            if sys.platform == "win32":
                proc = subprocess.Popen(
                    ["ollama", "serve"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                proc = subprocess.Popen(
                    ["ollama", "serve"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        except Exception as e:  # noqa: BLE001
            print(f"[启动器] 启动 Ollama 失败: {e}")
            return False

        ok = False
        for _ in range(12):
            time.sleep(0.5)
            try:
                r = requests.get(
                    "http://localhost:11434/api/tags",
                    timeout=1,
                    proxies={"http": None, "https": None},
                )
                if r.status_code == 200:
                    pid = _listening_pid_on()
                    if proc.poll() is None and pid is not None and str(proc.pid) == str(pid):
                        ok = True
                    break
            except Exception:  # noqa: BLE001
                pass
        if ok:
            return True
        # 端口被桌面版抢占：结束 app + serve 后重试一次
        print("[启动器] 检测到 Ollama 桌面版抢占 11434（会导致模型落到 C 盘），正在结束桌面版后重试...")
        _stop_ollama()

    print("[启动器] 无法接管 Ollama：桌面版会自动重启并占用 11434。")
    print("         请退出托盘中的 Ollama（右击图标 → Quit）后重新运行本启动器；")
    print("         或设置 VULN_SCANNER_KEEP_EXTERNAL_OLLAMA=1 复用外部服务（模型会存到 C 盘）。")
    return False


def list_ollama_models() -> list[str]:
    """列出已 pull 的模型。"""
    try:
        resp = requests.get(
            "http://localhost:11434/api/tags",
            timeout=5,
            proxies={"http": None, "https": None},
        )
        data = resp.json()
        # 统一去掉 :latest，与注册表 full_name（无标签）对齐，避免误判“未安装”重复拉取
        return [_normalize_ollama_name(m["name"]) for m in data.get("models", [])]
    except Exception:
        return []


def ensure_model_available(model: str) -> bool:
    """确保模型已 pull。未 pull 则自动从 Ollama Registry 下载。"""
    models = list_ollama_models()
    # 精确匹配（Ollama 模型名含 tag，不需要模糊匹配）
    if model in models:
        return True

    print(f"[启动器] 首次使用，正在下载模型 {model}（约 5GB，请耐心等待）...")
    print(f"[启动器] 下载过程中可以关闭此窗口，下次启动会继续。")
    try:
        result = subprocess.run(
            ["ollama", "pull", model],
            timeout=5400,  # 90 分钟：5GB 模型 + 慢速网络
        )
        if result.returncode == 0:
            print(f"[启动器] 模型 {model} 下载完成。")
            return True
        print(f"[启动器] 模型下载失败（退出码 {result.returncode}）。")
        print(f"[启动器] 请检查网络后重试，或手动运行：ollama pull {model}")
        return False
    except subprocess.TimeoutExpired:
        print("[启动器] 模型下载超时（90 分钟未完成）。")
        print("[启动器] 可能是网络较慢，下次启动会断点续传，请重试。")
        print(f"[启动器] 或手动运行：ollama pull {model}")
        return False


def enable_ansi_on_windows() -> None:
    """在 Windows 控制台开启 ANSI 虚拟终端处理，使 uvicorn 的日志颜色码能被渲染。

    transformers 的后端窗口能正常显示 INFO/200 OK 的颜色，是因为它跑在支持
    ANSI 的终端里；ollama 若跑在旧式 cmd 控制台则不渲染转义码，直接显示 [32m 乱码。
    开启本模式后，两者都会显示成有颜色的干净文字。
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        h = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(h, ctypes.byref(mode)):
            kernel32.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


def start_vllm_service() -> subprocess.Popen | None:
    """启动 vLLM 独立推理服务（vllm_server.py）。

    vLLM 是常驻服务进程：加载 AWQ/GPTQ 基座 + FP16 LoRA 到显存，
    通过 OpenAI 兼容 API 对外提供。若 VULN_SCANNER_VLLM_PORT（默认 8000）
    上已有可用的 vLLM 服务，则直接复用，不再重复拉起。

    返回服务子进程（复用已有服务时返回 None）；启动失败返回 None。
    """
    port = int(os.environ.get("VULN_SCANNER_VLLM_PORT", "8000") or "8000")
    # 已存在可用服务则直接复用
    try:
        resp = requests.get(
            f"http://127.0.0.1:{port}/v1/models",
            timeout=3, proxies={"http": None, "https": None},
        )
        if resp.status_code == 200:
            print(f"[启动器] 检测到已运行的 vLLM 服务（http://127.0.0.1:{port}），直接复用。")
            return None
    except Exception:
        pass

    print(f"[启动器] 启动 vLLM 独立服务（端口 {port}，首次加载模型到显存可能需要数十秒到数分钟）...")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    cmd = [sys.executable, "-m", "app.launcher.vllm_server"]
    try:
        proc = subprocess.Popen(cmd, env=env, cwd=str(PROJECT_ROOT))
    except Exception as e:
        print(f"[启动器] 拉起 vLLM 服务失败: {e}")
        return None
    return proc


def wait_for_vllm_ready(port: int, timeout: int = 600, proc: subprocess.Popen | None = None) -> bool:
    """等待 vLLM 服务就绪（/v1/models 可访问）。"""
    url = f"http://127.0.0.1:{port}/v1/models"
    for i in range(timeout):
        if proc is not None and proc.poll() is not None:
            print(f"[启动器] vLLM 服务进程已退出（退出码 {proc.returncode}）。")
            return False
        try:
            resp = requests.get(
                url, timeout=3, proxies={"http": None, "https": None},
            )
            if resp.status_code == 200:
                print(f"[启动器] vLLM 服务就绪（第 {i + 1}/{timeout} 次尝试）。")
                return True
        except Exception:
            pass
        if i % 10 == 0:
            print(f"[启动器] 等待 vLLM 服务就绪（已等待 {i} 秒）...")
        time.sleep(1)
    print(f"[启动器] 等待 vLLM 服务就绪超时（{timeout} 秒）。")
    return False


def start_backend(port: int = PORT) -> subprocess.Popen:
    """启动 FastAPI 后端。"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    # 防止 OOM：限制 Ollama 并发请求数和常驻模型数
    env.setdefault("OLLAMA_NUM_PARALLEL", "1")
    env.setdefault("OLLAMA_MAX_LOADED_MODELS", "1")

    # 让 uvicorn 输出颜色（与 transformers 一致），并确保当前控制台能渲染 ANSI 颜色码
    enable_ansi_on_windows()
    cmd = [
        sys.executable, "-m", "uvicorn",
        "app.backend.main:app",
        "--host", "127.0.0.1",
        "--port", str(port),
    ]
    print(f"[启动器] 启动后端：http://127.0.0.1:{port}")
    proc = subprocess.Popen(cmd, env=env, cwd=str(PROJECT_ROOT))
    return proc


def wait_for_backend(port: int, timeout: int = 60, proc: subprocess.Popen | None = None) -> bool:
    """等待后端就绪。

    参数:
        port: 后端监听端口。
        timeout: 最大等待秒数（默认 60 秒）。
        proc: 后端子进程对象；如果进程提前退出，立即返回失败。
    """
    for i in range(timeout):
        # 若后端子进程已退出，不必等到超时
        if proc is not None and proc.poll() is not None:
            print(f"[启动器] 后端进程已退出（退出码 {proc.returncode}）。")
            return False

        try:
            # 禁用代理访问本地回环地址，避免系统代理导致 localhost 请求失败
            # 使用轻量级存活探针 /api/health/live（即时返回，不调 Ollama/外部工具），
            # 避免 /api/health 因 Ollama 预热耗时导致客户端超时
            resp = requests.get(
                f"http://127.0.0.1:{port}/api/health/live",
                timeout=3,
                proxies={"http": None, "https": None},
            )
            if resp.status_code == 200:
                print(f"[启动器] 后端健康检查通过（第 {i + 1}/{timeout} 次尝试）。")
                return True
            print(f"[启动器] 后端健康检查返回 HTTP {resp.status_code}，继续等待...")
        except Exception as e:
            # 仅在前几次打印详细错误，避免刷屏
            if i < 5 or i % 10 == 0:
                print(f"[启动器] 后端健康检查第 {i + 1}/{timeout} 次失败: {e}")
        time.sleep(1)
    return False


def detect_hardware() -> dict:
    """检测本机硬件（GPU/CPU/RAM）。跨平台、无额外依赖。

    返回字典结构：
        {
            "has_nvidia_gpu": bool,
            "has_amd_gpu": bool,
            "gpu_name": str | None,
            "vram_mb": int | None,
            "cpu_cores": int,
            "ram_gb": float,
            "platform": str,
        }
    """
    hardware: dict = {
        "has_nvidia_gpu": False,
        "has_amd_gpu": False,
        "gpu_name": None,
        "vram_mb": None,
        "cpu_cores": os.cpu_count() or 4,
        "ram_gb": 0.0,
        "platform": sys.platform,
    }

    # 1) NVIDIA GPU 检测：优先 nvidia-smi（跨平台，Windows/Linux 都可用）
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            line = result.stdout.strip().splitlines()[0]
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2 and parts[0]:
                hardware["has_nvidia_gpu"] = True
                hardware["gpu_name"] = parts[0]
                try:
                    hardware["vram_mb"] = int(parts[1])
                except ValueError:
                    hardware["vram_mb"] = None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # 2) nvidia-smi 失败则尝试 torch.cuda（torch 是 sentence-transformers 的间接依赖）
    #    注意：ROCm 版 torch 会让 torch.cuda.is_available() 返回 True（复用 CUDA 命名空间），
    #    但那是 AMD GPU 而非 NVIDIA。必须排除 hip 构建，否则 AMD/ROCm 机器会被误判成
    #    NVIDIA 而套用错误的 NVIDIA 推理参数，且会跳过后续步骤 4 的 AMD 检测。
    if not hardware["has_nvidia_gpu"]:
        try:
            import torch  # type: ignore
            if torch.version.hip:
                # ROCm 构建：属于 AMD GPU，交给步骤 4 检测
                pass
            elif torch.cuda.is_available():
                hardware["has_nvidia_gpu"] = True
                hardware["gpu_name"] = torch.cuda.get_device_name(0)
                props = torch.cuda.get_device_properties(0)
                hardware["vram_mb"] = int(props.total_memory // 1024 // 1024)
        except Exception:
            pass

    # 3) macOS Apple Silicon 检测（统一内存架构，无独立显存统计）
    if sys.platform == "darwin" and not hardware["has_nvidia_gpu"]:
        try:
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=3,
            )
            brand = result.stdout.strip()
            if "Apple M" in brand:
                hardware["gpu_name"] = brand
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    # 4) AMD/ROCm GPU 检测（Linux 优先 rocm-smi，再读 sysfs；Windows 用 wmic）
    if not hardware["has_nvidia_gpu"] and not hardware["gpu_name"]:
        if sys.platform.startswith("linux"):
            # 4a) rocm-smi 是 ROCm 驱动自带的工具，最可靠
            try:
                result = subprocess.run(
                    ["rocm-smi", "--showproductname"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip():
                    for line in result.stdout.strip().splitlines():
                        line = line.strip()
                        # 典型输出: "GPU[0]          : Card Series:          AMD Radeon RX 9060 XT"
                        if "Card Series" in line:
                            parts = line.split(":", 2)
                            if len(parts) >= 3 and parts[2].strip():
                                hardware["has_amd_gpu"] = True
                                hardware["gpu_name"] = parts[2].strip()
                                break
                # 显存：rocm-smi --showmeminfo vram 输出为字节
                if hardware["has_amd_gpu"]:
                    try:
                        mem_result = subprocess.run(
                            ["rocm-smi", "--showmeminfo", "vram"],
                            capture_output=True, text=True, timeout=5,
                        )
                        if mem_result.returncode == 0 and mem_result.stdout.strip():
                            for line in mem_result.stdout.strip().splitlines():
                                if "Total Memory" in line:
                                    parts = line.split(":", 2)
                                    if len(parts) >= 3:
                                        try:
                                            hardware["vram_mb"] = int(parts[2].strip()) // 1024 // 1024
                                        except ValueError:
                                            pass
                                    break
                    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                        pass
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass

            # 4b) rocm-smi 不存在时，读 sysfs 中的 AMD GPU 拓扑信息
            if not hardware["has_amd_gpu"]:
                try:
                    kfd_nodes = Path("/sys/class/kfd/kfd/topology/nodes")
                    if kfd_nodes.is_dir():
                        for node_dir in sorted(kfd_nodes.iterdir()):
                            props_path = node_dir / "properties"
                            if not props_path.is_file():
                                continue
                            props = props_path.read_text(encoding="utf-8", errors="ignore")
                            # vendor_id 0x1002 / 4098 为 AMD；跳过 vendor_id 0 的 CPU 节点
                            if ("vendor_id 0x1002" in props or "vendor_id 4098" in props):
                                # 显存大小在 mem_banks/0/properties 的 size_in_bytes 行
                                vram_mb = None
                                mem_props_path = node_dir / "mem_banks" / "0" / "properties"
                                if mem_props_path.is_file():
                                    try:
                                        mem_props = mem_props_path.read_text(encoding="utf-8", errors="ignore")
                                        for p in mem_props.splitlines():
                                            if p.startswith("size_in_bytes "):
                                                vram_mb = int(p.split(" ", 1)[1].strip()) // 1024 // 1024
                                                break
                                    except (ValueError, OSError):
                                        pass
                                hardware["has_amd_gpu"] = True
                                hardware["gpu_name"] = "AMD GPU"
                                hardware["vram_mb"] = vram_mb
                                break
                except (OSError, PermissionError):
                    pass

            # 4c) 若 sysfs 只给出通用名称，尝试用 lspci 获取具体型号
            if hardware["has_amd_gpu"] and hardware["gpu_name"] == "AMD GPU":
                try:
                    result = subprocess.run(
                        ["lspci", "-nn"],
                        capture_output=True, text=True, timeout=5,
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        for line in result.stdout.strip().splitlines():
                            if "VGA" in line and ("AMD" in line or "Radeon" in line or "ATI" in line):
                                # 提取方括号后的描述文本
                                desc = line.split(":", 2)[-1].strip()
                                # 去掉尾部的 [1002:xxxx] 设备 ID
                                desc = desc.split(" [1002:")[0].strip()
                                if desc:
                                    hardware["gpu_name"] = desc
                                    break
                except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                    pass

        elif sys.platform == "win32":
            # Windows 下通过 wmic 查找 AMD 显卡
            try:
                result = subprocess.run(
                    ["wmic", "path", "win32_VideoController",
                     "get", "Name,AdapterRAM", "/format:csv"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip():
                    for line in result.stdout.strip().splitlines()[1:]:
                        if "AMD" in line or "Radeon" in line:
                            parts = line.split(",")
                            if len(parts) >= 3:
                                hardware["has_amd_gpu"] = True
                                hardware["gpu_name"] = parts[-2].strip().strip('"')
                                try:
                                    hardware["vram_mb"] = int(parts[-1].strip().strip('"')) // 1024 // 1024
                                except ValueError:
                                    pass
                            break
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass

    # 5) RAM 检测：优先 psutil，否则平台特定回退
    try:
        import psutil  # type: ignore
        hardware["ram_gb"] = round(psutil.virtual_memory().total / 1024 ** 3, 1)
    except Exception:
        if sys.platform.startswith("linux"):
            try:
                ram_bytes = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
                hardware["ram_gb"] = round(ram_bytes / 1024 ** 3, 1)
            except (ValueError, OSError):
                pass
        elif sys.platform == "win32":
            try:
                result = subprocess.run(
                    ["wmic", "ComputerSystem", "get", "TotalPhysicalMemory"],
                    capture_output=True, text=True, timeout=3,
                )
                lines = [l.strip() for l in result.stdout.splitlines()
                         if l.strip().isdigit()]
                if lines:
                    hardware["ram_gb"] = round(int(lines[0]) / 1024 ** 3, 1)
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass
        # 兜底估算：8GB
        if hardware["ram_gb"] == 0.0:
            hardware["ram_gb"] = 8.0

    return hardware


def recommend_config(hardware: dict) -> dict:
    """根据硬件信息返回推荐的 Ollama 推理参数。

    返回字典结构：
        {
            "num_ctx": int,
            "num_gpu": int,
            "num_thread": int,
            "quantization": str,
            "warning": str | None,
            "mode": str,   # "gpu" / "cpu" / "apple_silicon"
        }
    """
    cpu_cores = hardware.get("cpu_cores") or 4
    num_thread = min(cpu_cores, 8)

    is_apple_silicon = (
        sys.platform == "darwin"
        and not hardware.get("has_nvidia_gpu")
        and hardware.get("gpu_name")
        and "Apple M" in hardware["gpu_name"]
    )

    # NVIDIA GPU 分支：按显存分档
    # q4_k_m 量化的 8B 模型权重约 4.7GB，加上 num_ctx 的 KV cache。
    # 注意：GPU 可用显存通常低于标称容量（RTX 5050 标 8G 实际报 8151MB；12G/16G 类似），
    # 因此分档阈值按 名义容量×~0.95 取整，避免 8G/12G/16G 卡因不足标称而错档：
    #   ≥15.5G(15872MB) → 全 GPU，num_ctx=16384（16K）
    #   11.5-15.5G      → 全 GPU，num_ctx=12288（12K）
    #   7.5-11.5G       → 全 GPU，num_ctx=9216（9K，覆盖 8G/10G/12G 档）
    #   6-7.5G          → 全 GPU，num_ctx=6144（6K，6GB 勉强够 4.7GB 权重 + KV cache）
    #   <6G             → 显存装不下，降级 CPU（避免 Ollama 反复试错 offload 导致启动卡住）
    if hardware.get("has_nvidia_gpu") and hardware.get("vram_mb"):
        vram = hardware["vram_mb"]
        if vram >= 15872:
            return {
                "num_ctx": 16384, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "gpu",
            }
        elif vram >= 11776:
            return {
                "num_ctx": 12288, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "gpu",
            }
        elif vram >= 7680:
            return {
                "num_ctx": 9216, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "gpu",
            }
        elif vram >= 6144:
            return {
                "num_ctx": 6144, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "gpu",
            }
        else:
            return {
                "num_ctx": 2048, "num_gpu": 0, "num_thread": num_thread,
                "quantization": "q4_k_m",
                "warning": (f"显存 {vram}MB 不足以全 GPU 加载 q4_k_m 8B 模型"
                            f"（权重约 4.7GB + KV cache），降级 CPU 推理。"
                            f"GPU 仍可用于其他任务，模型推理走 CPU（速度较慢但稳定）。"),
                "mode": "cpu",
            }

    # AMD/ROCm GPU 分支：Ollama 在 Linux 上支持 ROCm 后端，num_gpu=-1 表示尽量 offload
    # 阈值同样按 名义容量×~0.95 取整（与 NVIDIA 一致）
    if hardware.get("has_amd_gpu") and hardware.get("vram_mb"):
        vram = hardware["vram_mb"]
        if vram >= 15872:
            return {
                "num_ctx": 16384, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "rocm",
            }
        elif vram >= 11776:
            return {
                "num_ctx": 12288, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "rocm",
            }
        elif vram >= 7680:
            return {
                "num_ctx": 9216, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "rocm",
            }
        elif vram >= 6144:
            return {
                "num_ctx": 6144, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "rocm",
            }
        else:
            return {
                "num_ctx": 2048, "num_gpu": 0, "num_thread": num_thread,
                "quantization": "q4_k_m",
                "warning": "AMD 显存较小，将使用 CPU 推理（速度较慢）",
                "mode": "cpu",
            }

    # Apple Silicon 分支：Metal 加速
    if is_apple_silicon:
        return {
            "num_ctx": 4096, "num_gpu": 1, "num_thread": num_thread,
            "quantization": "q4_k_m", "warning": None, "mode": "apple_silicon",
        }

    # 纯 CPU 分支
    return {
        "num_ctx": 2048, "num_gpu": 0, "num_thread": num_thread,
        "quantization": "q4_k_m",
        "warning": "未检测到 GPU，将使用 CPU 推理（速度约为 GPU 的 1/10）",
        "mode": "cpu",
    }


def print_hardware_summary(hardware: dict, config: dict) -> None:
    """将硬件检测结果打印到控制台。"""
    if hardware.get("has_nvidia_gpu") and hardware.get("gpu_name"):
        fam = dependency_installer.classify_gpu(dependency_installer.GPUInfo(
            vendor="nvidia", name=hardware.get("gpu_name"), vram_mb=hardware.get("vram_mb"),
        ))
        print(f"[硬件检测] GPU: {hardware['gpu_name']} ({hardware['vram_mb']}MB) [{fam.label}]")
    elif hardware.get("has_amd_gpu") and hardware.get("gpu_name"):
        fam = dependency_installer.classify_gpu(dependency_installer.GPUInfo(
            vendor="amd", name=hardware.get("gpu_name"), vram_mb=hardware.get("vram_mb"),
        ))
        print(f"[硬件检测] GPU: {hardware['gpu_name']} ({hardware['vram_mb']}MB) [AMD/ROCm · {fam.label}]")
    elif hardware.get("gpu_name") and "Apple M" in hardware["gpu_name"]:
        print(f"[硬件检测] GPU: {hardware['gpu_name']} (Apple Silicon)")
    else:
        print("[硬件检测] GPU: 未检测到 NVIDIA/AMD GPU")
    print(f"[硬件检测] CPU: {hardware['cpu_cores']} 核")
    print(f"[硬件检测] 推理模式: {config['mode'].upper()} "
          f"(num_ctx={config['num_ctx']}, {config['quantization']})")
    if config["warning"]:
        print(f"[硬件检测] ⚠️ {config['warning']}")


def select_mode() -> str:
    """交互式选择启动模式。

    后端进程始终启动（Web 与插件共用同一后端），区别仅在于：
        web    —— 启动后端 + 自动打开浏览器（仅用 Web 应用）
        plugin —— 启动后端，不开浏览器（供 VSCode/IntelliJ 插件连接）
        all    —— 启动后端 + 打开浏览器 + 打印插件连接说明（同时用 Web 与插件）

    Returns:
        "web" / "plugin" / "all"
    """
    print("=" * 60)
    print("  AI 漏洞扫描器 —— 启动模式选择")
    print("=" * 60)
    print("  后端服务始终启动（Web 与插件共用同一后端）")
    print("  [1] Web 模式    —— 后端 + 浏览器（仅用 Web 应用）")
    print("  [2] 插件模式    —— 仅后端，不开浏览器（供编辑器插件连接）")
    print("  [3] 全部        —— 后端 + 浏览器 + 插件提示（Web 与插件同时用）")
    print("  [0] 退出")
    print("-" * 60)
    while True:
        choice = input("请选择 [1/2/3/0]（默认 3）: ").strip()
        if choice in ("", "3"):
            return "all"
        if choice == "1":
            return "web"
        if choice == "2":
            return "plugin"
        if choice == "0":
            print("已取消启动。")
            sys.exit(0)
        print("[启动器] 无效输入，请重新选择。")


def print_plugin_hint(port: int) -> None:
    """打印编辑器插件连接说明（插件模式 / 全部模式使用）。"""
    print()
    print("-" * 60)
    print("  编辑器插件连接说明")
    print("-" * 60)
    print(f"  后端地址：http://localhost:{port}")
    print()
    print("  ▸ VSCode 插件")
    print("    1. 在 VSCode 中打开 app/vscode-extension/ 目录，按 F5 调试")
    print("       （或用 vsce package 打包成 vsix 后安装）")
    print("    2. 设置 vulnScanner.backendUrl = http://localhost:%d" % port)
    print("    3. 右键编辑器 → “AI 漏洞扫描: 分析当前文件”")
    print()
    print("  ▸ IntelliJ 插件")
    print("    1. 在 IntelliJ IDEA 中打开 app/intellij-extension/ 目录")
    print("    2. 执行 Gradle 任务 runIde 启动沙盒 IDE")
    print("    3. 选中代码 → 右键 → “AI 漏洞扫描”（Ctrl+Shift+V）")
    print()
    print("  ▸ 队列状态查询：GET  http://localhost:%d/api/queue/status" % port)
    print("-" * 60)


def main():
    mode = select_mode()
    print()
    print("=" * 60)
    print("  AI 漏洞扫描器 —— 启动中（模式: %s）" % mode)
    print("=" * 60)

    # 0. 选择并锁定推理后端
    backend = select_backend()
    os.environ["VULN_SCANNER_BACKEND"] = backend
    # transformers 后端追加 LoRA 合并 / 不合并子选择（写入环境变量，后端启动后固定）
    if backend == "transformers":
        os.environ["VULN_SCANNER_MERGE"] = resolve_transformers_merge()
    use_ollama = backend == "ollama"
    print(f"[启动器] 推理后端: {backend}")

    # 模型存储锁定：后端已写死读取项目 models/ 下的模型，因此**任何平台**都把
    # Ollama 存储锁到项目 models/ollama、并把旧位置（默认 ~/.ollama/models）已有
    # 模型迁移过来，保证后端可访问。
    ollama_models_dir().mkdir(parents=True, exist_ok=True)
    os.environ["OLLAMA_MODELS"] = str(ollama_models_dir())
    # HuggingFace 缓存：仅 Windows 需要强制迁离 C 盘；Linux/macOS 保持系统默认
    # （~/.cache/huggingface），后端基座走本地 models/transformers，无需搬动。
    if sys.platform == "win32":
        hf_home = hf_home_dir()
        hf_home.mkdir(parents=True, exist_ok=True)
        os.environ.setdefault("HF_HOME", str(hf_home))
        try:
            migrate_hf_cache_to_project()
        except Exception as e:  # noqa: BLE001
            print(f"[启动器] HF 缓存迁移异常: {e}")
    # 把旧位置（默认 ~/.ollama/models）已有 Ollama 模型剪切到项目 models/ollama
    migrate_ollama_models_to_project()

    if use_ollama:
        # 1. 检测 Ollama
        if not check_ollama_installed():
            # 尝试自动安装
            if not try_install_ollama():
                print("\n[错误] Ollama 自动安装失败。请手动安装：")
                print("  下载地址：https://ollama.com/download")
                print("  安装后重新运行本启动器。")
                input("\n按回车键退出...")
                return
            # 安装后重新检查 PATH
            if not check_ollama_installed():
                print("\n[错误] Ollama 已安装但不在 PATH 中。")
                print("  请重启终端后重新运行本启动器，或手动将 ollama 加入 PATH。")
                input("\n按回车键退出...")
                return

        print("[1/5] Ollama 已安装")

        # 2. 确保 Ollama 服务运行
        if not ensure_ollama_running():
            print("\n[错误] Ollama 服务无法启动。请手动运行 `ollama serve` 后重试。")
            input("\n按回车键退出...")
            return

        print("[2/5] Ollama 服务已运行")
        _maybe_upgrade_ollama()
    else:
        # 进程内后端（transformers/llamacpp）与独立服务后端（vllm）：不依赖 Ollama，
        # 自动安装依赖并校验配置。依赖一律装进「当前解释器」（sys.executable）——
        # 不再跨 conda 环境扫描 torch 构建并 re-exec 切换，避免"环境换来换去"造成
        # 依赖分裂（torch 对了却缺 tree_sitter_python / 工具装到别的环境）。
        # 当前环境缺 torch 时由 install_backend_dependencies 现场安装。

        deps_ok = dependency_installer.install_backend_dependencies(
            backend,
            python_executable=sys.executable,
            dry_run=False,
            auto_confirm=None,  # 按 VULN_SCANNER_AUTO_INSTALL_DEPS 环境变量，默认自动安装
        )
        if not deps_ok:
            print(f"\n[错误] {backend} 后端依赖未就绪。")
            dependency_installer.print_manual_install_commands(backend, sys.executable)
            print("\n  或设置 VULN_SCANNER_BACKEND=ollama 改用 Ollama 后端。")
            input("\n按回车键退出...")
            return

        if not check_inprocess_backend_ready(backend):
            print("\n[错误] 推理后端配置未就绪，请按上方提示修复后重试。")
            input("\n按回车键退出...")
            return
        print(f"[1/5] {backend} 后端依赖就绪")
        if backend == "vllm":
            print("[2/5] 跳过 Ollama（vllm 为独立服务，下一步单独启动）")
        else:
            print("[2/5] 跳过 Ollama（进程内推理后端不需要）")

    # 3. 安全工具：新框架（两阶段/外部扫描）所需传统工具的启动前自动下载
    print("[3/6] 检查安全工具（bandit/semgrep/gitleaks/trivy/pip-audit/detect-secrets）...")
    dependency_installer.install_security_tools(
        python_executable=sys.executable,
        dry_run=False,
        auto_confirm=None,  # 按 VULN_SCANNER_AUTO_INSTALL_DEPS 环境变量，默认自动安装
    )

    # 3.5 Semgrep registry 规则本地化（models/semgrep_rules/，离线可用）
    # 在线 registry 包（p/xxx）每次运行都重新下载、离线不可用，且包名不存在时
    # 会导致每次扫描联网降级拖慢。这里拉取到项目目录（幂等，缺失才拉取），
    # external_scanner 随后用 --config <本地 yaml> 完全离线运行。
    # 需联网/代理：优先读 HTTPS_PROXY/HTTP_PROXY 环境变量。
    print("[3.5/6] 检查 Semgrep registry 规则本地化...")
    try:
        import subprocess as _sp
        _rules_script = PROJECT_ROOT / "tools" / "fetch_semgrep_rules.py"
        _r = _sp.run([sys.executable, _rules_script, "--check"],
                     capture_output=True, text=True, encoding="utf-8", errors="replace",
                     timeout=120, cwd=os.getcwd())
        if _r.returncode != 0:
            print("  Semgrep registry 规则未本地化，尝试拉取（需联网；可设置 HTTPS_PROXY）...")
            _sp.run([sys.executable, _rules_script],
                    timeout=300, cwd=os.getcwd())
        else:
            print("  Semgrep registry 规则已本地化（models/semgrep_rules/）")
    except Exception as e:
        print(f"  Semgrep 规则本地化跳过: {type(e).__name__}: {e}")

    # 4. 硬件检测 + 自适应推理参数（在拉取/加载模型前完成，便于后续 scanner.py 读取）
    hardware = detect_hardware()
    config = recommend_config(hardware)
    print_hardware_summary(hardware, config)
    # 写入环境变量，供 scanner.py / 后端进程读取
    os.environ["VULN_SCANNER_NUM_CTX"] = str(config["num_ctx"])
    os.environ["VULN_SCANNER_NUM_GPU"] = str(config["num_gpu"])
    os.environ["VULN_SCANNER_NUM_THREAD"] = str(config["num_thread"])
    # LlamaCPP 后端：把硬件自适应映射到 n_gpu_layers（GPU/CPU 混合推理）。
    # Ollama 用 VULN_SCANNER_NUM_GPU；llama-cpp-python 用 VULN_SCANNER_GPU_LAYERS，
    # 两者语义不同，必须为 llamacpp 单独推导，否则落后于 Ollama 的自适应逻辑：
    #   -1=全部层卸载到 GPU，0=纯 CPU，正整数=卸载前 N 层到 GPU、剩余层跑 CPU。
    # 显存不足时用部分卸载（GPU 放得下几层就放几层，其余走 CPU），实现 GPU+CPU 合作，
    # 而不是要么全 GPU（4G 卡 OOM）要么纯 CPU（浪费 GPU）。
    if backend == "llamacpp":
        gpu_layers = -1  # 默认全部卸载到 GPU
        vram = hardware.get("vram_mb")
        if config.get("mode") == "cpu":
            # 显存装不下全量权重（<6G 走 CPU 档）：有独显则部分卸载做 GPU+CPU 混合。
            # Q4 8B 权重约 4.7GB / ~40 层 ≈ 每层约 120MB，留 KV cache 余量按 150MB/层估。
            if (hardware.get("has_nvidia_gpu") or hardware.get("has_amd_gpu")) and vram:
                gpu_layers = max(1, vram // 150)
            else:
                gpu_layers = 0  # 纯 CPU，无 GPU 可用
        os.environ["VULN_SCANNER_GPU_LAYERS"] = str(gpu_layers)

    # Ollama 后端：与上面 llamacpp 的 GPU+CPU 混合卸载对齐。
    # recommend_config 在 <6G 档返回 num_gpu=0（纯 CPU，GPU 闲置），
    # 这里在检测到独显时按同样估算把前 N 层卸载到 GPU、其余层走 CPU，
    # 让 4G 等低显存卡也能用上 GPU 分担，而不是一刀切纯 CPU。
    if backend == "ollama" and config.get("mode") == "cpu":
        vram = hardware.get("vram_mb")
        if (hardware.get("has_nvidia_gpu") or hardware.get("has_amd_gpu")) and vram:
            num_gpu = max(1, vram // 150)  # GPU 部分卸载 + CPU 分担
        else:
            num_gpu = 0  # 无 GPU 可用，纯 CPU
        os.environ["VULN_SCANNER_NUM_GPU"] = str(num_gpu)
        print(f"[硬件检测] Ollama 低显存(<6G)有独显：GPU 卸载前 {num_gpu} 层，其余层走 CPU")

    print("[4/6] 硬件检测完成")

    # 5. 确保模型可用（仅 Ollama 后端需要拉取；进程内后端在首次推理时懒加载）
    if use_ollama:
        model = os.environ.get("VULN_SCANNER_MODEL", DEFAULT_MODEL)
        if not ensure_model_available(model):
            # 回退到官方 Qwen3-8B
            print(f"[启动器] {model} 不可用，尝试回退模型 {FALLBACK_MODEL}")
            if not ensure_model_available(FALLBACK_MODEL):
                print(f"\n[错误] 无法获取任何可用模型。请手动运行：")
                print(f"  ollama pull {model}")
                input("\n按回车键退出...")
                return
            os.environ["VULN_SCANNER_MODEL"] = FALLBACK_MODEL
    elif backend == "vllm":
        # vLLM 是独立服务：此刻拉起 vllm_server.py 并等待其把基座 + LoRA 加载到显存
        vllm_port = int(os.environ.get("VULN_SCANNER_VLLM_PORT", "8000") or "8000")
        vllm_proc = start_vllm_service()
        if not wait_for_vllm_ready(vllm_port, proc=vllm_proc):
            print("\n[错误] vLLM 服务启动失败或超时，请参考上方日志排查。")
            print("  常见原因：模型路径错误、显存不足、量化类型与权重不匹配。")
            print("  可手动运行 `python -m app.launcher.vllm_server --dry-run` 查看将要执行的命令。")
            input("\n按回车键退出...")
            return

    print(f"[5/6] 模型就绪")

    # 6. 启动后端
    # 5.1 端口占用检测：若被占用，先尝试释放残留进程
    if is_port_in_use(PORT):
        print(f"[启动器] 端口 {PORT} 已被占用，尝试释放残留进程...")
        if not kill_process_on_port(PORT):
            print(f"\n[错误] 端口 {PORT} 被占用且无法自动释放。")
            print("  请手动关闭占用该端口的程序后重试。")
            input("\n按回车键退出...")
            return
        # 等待端口释放（最长 ~15s，SIGKILL 后 socket 一般立即释放）
        for _ in range(30):
            if not is_port_in_use(PORT):
                break
            time.sleep(0.5)
        if is_port_in_use(PORT):
            print(f"\n[错误] 端口 {PORT} 释放后仍被占用，请手动检查。")
            print("  可执行：lsof -i tcp:%d 或 fuser %d/tcp 查看占用进程后手动结束。" % (PORT, PORT))
            input("\n按回车键退出...")
            return
        print(f"[启动器] 端口 {PORT} 已释放。")

    backend_proc = start_backend(PORT)
    if not wait_for_backend(PORT, proc=backend_proc):
        print(f"\n[错误] 后端启动超时。请检查端口 {PORT} 是否被占用，或查看上方日志中的具体错误。")
        try:
            backend_proc.terminate()
            backend_proc.wait(timeout=5)
        except Exception:
            pass
        input("\n按回车键退出...")
        return

    # 6. 根据启动模式决定后续动作（后端已就绪，Web 与插件共用）
    if mode in ("web", "all"):
        print(f"[5/5] 后端就绪，正在打开浏览器...")
        webbrowser.open(f"http://localhost:{PORT}")
    else:
        print(f"[5/5] 后端就绪（插件模式，不打开浏览器）")

    if mode in ("plugin", "all"):
        print_plugin_hint(PORT)

    print(f"\n{'=' * 60}")
    print(f"  AI 漏洞扫描器已启动（模式: {mode}）")
    print(f"  访问地址：http://localhost:{PORT}")
    print(f"  API 文档：http://localhost:{PORT}/docs")
    print(f"  队列状态：http://localhost:{PORT}/api/queue/status")
    print(f"  按 Ctrl+C 停止服务")
    print(f"{'=' * 60}\n")

    # 保持运行
    try:
        backend_proc.wait()
    except KeyboardInterrupt:
        print("\n[启动器] 正在停止服务...")
        backend_proc.terminate()
        backend_proc.wait()


if __name__ == "__main__":
    main()
