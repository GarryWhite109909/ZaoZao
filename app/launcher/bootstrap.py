"""
启动器 —— 首次使用检测推理后端与模型，后续直接启动后端 + 打开浏览器。

推理后端（与 app/backend/services/scanner.py 的解析规则一致）：
    - transformers：配置了 VULN_SCANNER_ADAPTER 时启用（Q4 基座 + FP16 LoRA 进程内推理，
      复现 95% 召回管道），需要 transformers/peft/bitsandbytes，不依赖 Ollama
    - ollama：默认一键启动形态（GGUF Q4_K_M 发布模型），自动安装/启动 Ollama 并拉取模型
    - llamacpp：实验性（Q4 GGUF 基座 + 运行时 FP16 LoRA），需要 llama-cpp-python
    可用 VULN_SCANNER_BACKEND 显式覆盖。

跨平台入口：
    python -m app.launcher.bootstrap

启动脚本：
    Windows: 双击 start_windows.bat
    Linux/macOS: bash start_linux_macos.sh
"""

from __future__ import annotations

import os
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
)
from graduation_project.transformers_client import is_transformers_runtime_compatible

# 项目根目录（Graduation-Project/）
PROJECT_ROOT = Path(__file__).resolve().parents[2]
# 默认模型（从模型注册表读取当前默认版本，如 v9max；导入失败时回退到 v9max 全名）
try:
    from app.backend.services.model_registry import get_default_model as _get_default_model
    DEFAULT_MODEL = os.environ.get("VULN_SCANNER_MODEL", _get_default_model())
except Exception:
    DEFAULT_MODEL = os.environ.get("VULN_SCANNER_MODEL", "garrywhite109909/graduation-vuln-scanner:v9max")
# 回退模型（官方 Qwen3-8B，未微调）
FALLBACK_MODEL = os.environ.get("VULN_SCANNER_FALLBACK_MODEL", "qwen3:8b")
# 后端端口
PORT = 8765


def resolve_backend() -> str:
    """解析推理后端（规则与 scanner.py._resolve_default_backend 保持一致）。"""
    backend = os.environ.get("VULN_SCANNER_BACKEND", "").strip().lower()
    if backend:
        return backend
    if os.environ.get("VULN_SCANNER_ADAPTER", "").strip():
        return "transformers"
    if resolve_adapter_path():
        ok, reason = is_transformers_runtime_compatible()
        if ok:
            return "transformers"
        print(f"[启动器] 检测到 models/ LoRA adapter，但当前环境不适合 transformers 后端: {reason}")
        print("[启动器] 已自动回退 ollama（如确要用 transformers，请显式设置 VULN_SCANNER_BACKEND=transformers）")
    return "ollama"


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
        # C 盘不允许出现任何模型文件：有内容（含未下完的 partial）就整体迁移
        if not any(src.iterdir()):
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
            print(f"[启动器] 检测到 Ollama 正在运行且模型存储仍在 {src}（可能在 C 盘）：")
            print(f"  请先退出 Ollama，再运行本启动器，会自动剪切到 {dst} 并锁定 OLLAMA_MODELS；")
            print("  否则本次拉取仍会写入 C 盘。")
            return None

        dst.mkdir(parents=True, exist_ok=True)
        print(f"[启动器] 检测到 Ollama 模型存储 {src}，正在剪切到 {dst} ...")
        try:
            for item in sorted(src.iterdir()):
                target = dst / item.name
                if target.exists():
                    print(f"[启动器] {item.name} 已存在于目标目录，跳过")
                    continue
                shutil.move(str(item), str(target))
        except Exception as e:  # noqa: BLE001
            print(f"[启动器] Ollama 模型迁移失败: {e}")
            print("  请确认 Ollama 已完全退出后重试。")
            return None
        try:
            src.rmdir()  # 内容已全部搬走，移除源目录空壳
        except OSError:
            pass
        os.environ["OLLAMA_MODELS"] = str(dst)  # 迁移后锁定到项目目录
        print(f"[启动器] ✅ 已剪切 Ollama 模型到 {dst}")
        return str(dst)
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
        "llamacpp": "实验性，Q4 GGUF + 运行时 LoRA（需适配 CMAKE）",
        "vllm": "独立服务，AWQ/GPTQ 基座 + FP16 LoRA（高吞吐，需 NVIDIA GPU）",
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
    for idx, bid in enumerate(("ollama", "transformers", "llamacpp", "vllm"), start=1):
        mark = "  ← 当前" if bid == default_backend else ""
        tag = label_map.get(bid, bid)
        print(f"  [{idx}] {tag:<13}—— {desc[bid]}{mark}")
    print("-" * 60)
    while True:
        choice = input(f"请选择推理后端（回车=使用 {default_label}，1/2/3/4=切换）: ").strip()
        if choice == "":
            return default_backend
        if choice == "1":
            return "ollama"
        if choice == "2":
            return "transformers"
        if choice == "3":
            return "llamacpp"
        if choice == "4":
            return "vllm"
        print("[启动器] 无效输入，请重新选择。")


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
            print("[错误] llamacpp 后端需要 VULN_SCANNER_GGUF 指向 Q4 GGUF 文件")
            print("  示例: set VULN_SCANNER_GGUF=D:\\code\\Graduation-Project\\models\\ollama\\qwen3-8b-q4_k_m.gguf")
            ok = False
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
        # 优先自动探测 models/ 下的量化目录；未探测到时要求显式配置。
        model = os.environ.get("VULN_SCANNER_VLLM_MODEL", "").strip()
        if not model:
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
            print(f"  示例: set VULN_SCANNER_VLLM_MODEL=D:\\models\\qwen3-8b-awq")
            print(f"  或将量化目录放到 {models_dir}\\vllm")
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
            # macOS/Linux：先尝试 lsof
            result = subprocess.run(
                ["lsof", "-ti", f"tcp:{port}"],
                capture_output=True, text=True, timeout=5,
            )
            pid = result.stdout.strip().splitlines()[0] if result.stdout.strip() else None
            if pid:
                print(f"[启动器] 端口 {port} 被 PID {pid} 占用。")
                answer = input("该进程可能不是本程序（例如其他服务），是否强制结束？[y/N]: ").strip().lower()
                if answer not in ("y", "yes"):
                    print("[启动器] 已取消释放端口，请手动关闭占用程序后重试。")
                    return False
                print(f"[启动器] 尝试结束 PID {pid} ...")
                stop = subprocess.run(["kill", "-9", pid], capture_output=True, text=True, timeout=5)
                return stop.returncode == 0
    except Exception as e:
        print(f"[启动器] 释放端口 {port} 失败: {e}")
    return False


def check_ollama_installed() -> bool:
    """检测系统是否安装 Ollama。"""
    return shutil.which("ollama") is not None


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


def ensure_ollama_running() -> bool:
    """确保 Ollama 服务在运行。未运行则尝试启动。"""
    try:
        resp = requests.get(
            "http://localhost:11434/api/tags",
            timeout=3,
            proxies={"http": None, "https": None},
        )
        return resp.status_code == 200
    except Exception:
        # 尝试后台启动 ollama serve
        print("[启动器] Ollama 服务未运行，尝试启动...")
        try:
            if sys.platform == "win32":
                subprocess.Popen(
                    ["ollama", "serve"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.Popen(
                    ["ollama", "serve"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            time.sleep(3)
            resp = requests.get(
                "http://localhost:11434/api/tags",
                timeout=5,
                proxies={"http": None, "https": None},
            )
            return resp.status_code == 200
        except Exception as e:
            print(f"[启动器] 启动 Ollama 失败: {e}")
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
        return [m["name"] for m in data.get("models", [])]
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
    # q4_k_m 量化的 8B 模型权重约 4.7GB，加上 num_ctx 的 KV cache：
    #   ≥10GB → 全 GPU，num_ctx=8192
    #   8-10GB→ 全 GPU，num_ctx=6144（8G 卡贴显存，6144 比 8192 稳）
    #   6-8GB → 全 GPU，num_ctx=4096（6GB 勉强够 4.7GB 权重 + KV cache）
    #   4-6GB → 显存装不下，降级 CPU（避免 Ollama 反复试错 offload 导致启动卡住）
    #   <4GB  → CPU
    if hardware.get("has_nvidia_gpu") and hardware.get("vram_mb"):
        vram = hardware["vram_mb"]
        if vram >= 10240:
            return {
                "num_ctx": 8192, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "gpu",
            }
        elif vram >= 8192:
            return {
                "num_ctx": 6144, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "gpu",
            }
        elif vram >= 6144:
            return {
                "num_ctx": 4096, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "gpu",
            }
        elif vram >= 4096:
            return {
                "num_ctx": 2048, "num_gpu": 0, "num_thread": num_thread,
                "quantization": "q4_k_m",
                "warning": (f"显存 {vram}MB 不足以全 GPU 加载 q4_k_m 8B 模型"
                            f"（权重约 4.7GB + KV cache），降级 CPU 推理。"
                            f"GPU 仍可用于其他任务，模型推理走 CPU（速度较慢但稳定）。"),
                "mode": "cpu",
            }
        else:
            return {
                "num_ctx": 2048, "num_gpu": 0, "num_thread": num_thread,
                "quantization": "q4_k_m",
                "warning": "显存不足，将使用 CPU 推理（速度较慢）",
                "mode": "cpu",
            }

    # AMD/ROCm GPU 分支：Ollama 在 Linux 上支持 ROCm 后端，num_gpu=-1 表示尽量 offload
    if hardware.get("has_amd_gpu") and hardware.get("vram_mb"):
        vram = hardware["vram_mb"]
        if vram >= 10240:
            return {
                "num_ctx": 8192, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "rocm",
            }
        elif vram >= 8192:
            return {
                "num_ctx": 6144, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "rocm",
            }
        elif vram >= 4096:
            return {
                "num_ctx": 4096, "num_gpu": -1, "num_thread": num_thread,
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
    use_ollama = backend == "ollama"
    print(f"[启动器] 推理后端: {backend}")

    # 模型文件绝不落 C 盘：
    #  - Ollama 存储锁定到项目 models/ollama（模型文件绝不落 C 盘）
    #  - HuggingFace 缓存锁定到项目 models/transformers/.hf_home
    ollama_models_dir().mkdir(parents=True, exist_ok=True)
    # 强制锁定：模型文件绝不落 C 盘（若确需自定义位置，请另行设置环境变量后改回 setdefault）
    os.environ["OLLAMA_MODELS"] = str(ollama_models_dir())
    hf_home = hf_home_dir()
    hf_home.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("HF_HOME", str(hf_home))

    if use_ollama:
        # C 盘/旧位置已有模型则剪切到项目 models/ollama
        migrate_ollama_models_to_project()

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
    else:
        # 进程内后端（transformers/llamacpp）与独立服务后端（vllm）：不依赖 Ollama，
        # 自动安装依赖并校验配置。自动识别匹配当前硬件（CUDA/ROCm）的 python 环境并
        # 切换到它，避免 base/graproj 装的是 CUDA 版 torch 导致 AMD/ROCm 机器上落到 CPU。
        # VULN_SCANNER_REEXEC 守卫：只允许切换一次，防止环境间来回切换形成死循环。
        best_python = dependency_installer.discover_best_python()
        already_reexec = os.environ.get("VULN_SCANNER_REEXEC", "0") == "1"
        if (
            not already_reexec
            and best_python
            and os.path.realpath(best_python) != os.path.realpath(sys.executable)
            and os.environ.get("VULN_SCANNER_FORCE_ENV", "1").strip() != "0"
        ):
            print(f"[启动器] 当前 Python ({sys.executable}) 的 torch 与硬件不匹配，")
            print(f"          自动切换到已匹配的环境: {best_python}")
            print(f"[启动器] 正在用该环境重新启动...\n")
            # 用匹配的解释器重新执行本启动器（交互流程在子进程里再次进行）
            env = os.environ.copy()
            env["VULN_SCANNER_REEXEC"] = "1"
            code = subprocess.call([best_python, "-m", "app.launcher.bootstrap", *sys.argv[1:]], env=env)
            sys.exit(code)

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

    # 4. 硬件检测 + 自适应推理参数（在拉取/加载模型前完成，便于后续 scanner.py 读取）
    hardware = detect_hardware()
    config = recommend_config(hardware)
    print_hardware_summary(hardware, config)
    # 写入环境变量，供 scanner.py / 后端进程读取
    os.environ["VULN_SCANNER_NUM_CTX"] = str(config["num_ctx"])
    os.environ["VULN_SCANNER_NUM_GPU"] = str(config["num_gpu"])
    os.environ["VULN_SCANNER_NUM_THREAD"] = str(config["num_thread"])

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
        # 等待端口释放
        for _ in range(10):
            if not is_port_in_use(PORT):
                break
            time.sleep(0.5)
        if is_port_in_use(PORT):
            print(f"\n[错误] 端口 {PORT} 释放后仍被占用，请手动检查。")
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
