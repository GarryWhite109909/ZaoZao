"""
vLLM 独立服务启动脚本 —— 为 vllm 推理后端拉起一个 OpenAI 兼容 API 服务进程。

背景：vLLM 与 Ollama / Transformers / llama.cpp 不同，它是一个"常驻服务进程"：
    1. 需要先加载量化基座（AWQ/GPTQ 4bit 或 FP16）到显存，常驻不释放；
    2. 通过 OpenAI 兼容 API（/v1/chat/completions）对外提供调用；
    3. 由 graduation_project/vllm_client.py 作为客户端消费该 API。

因此"前后端打通"需要三个环节：
    - 本脚本：把模型 + 量化 + LoRA 参数组装成 vllm serve 命令并拉起进程；
    - bootstrap.py：选择 vllm 后端时安装依赖并调用本脚本启动服务；
    - scanner.py / main.py：用 VLLMClient 指向 VULN_SCANNER_VLLM_URL。

用量化策略：vLLM 用 AWQ/GPTQ 4bit 量化基座以适配 8GB 显存，
LoRA 通过 --enable-lora 在运行时以 FP16 叠加（避免合并量化损失精度）。
若用户已有合并好的模型（如 Ollama 发布版），也可直接加载合并后的权重。

配置（环境变量，也可用 CLI 参数覆盖）：
    VULN_SCANNER_VLLM_MODEL        基座模型：HF id 或本地目录（AWQ/GPTQ 量化目录）（必填）
    VULN_SCANNER_VLLM_PORT         API 端口（默认 8000）
    VULN_SCANNER_VLLM_QUANTIZATION 量化方式：auto / awq / gptq（默认 auto）
    VULN_SCANNER_VLLM_ADAPTER      LoRA adapter 目录（可选，启用 --enable-lora）
    VULN_SCANNER_VLLM_GPU_MEMORY_UTIL  GPU 显存利用率（默认 0.85）
    VULN_SCANNER_VLLM_MAX_MODEL_LEN 最大上下文长度（默认 16384）
    VULN_SCANNER_MODEL              served-model-name（默认取模型名尾段）

用法：
    python -m app.launcher.vllm_server --model Qwen/Qwen3-8B-AWQ
    python -m app.launcher.vllm_server --model D:/models/qwen3-8b-awq --quantization awq
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import requests

# 默认 served-model-name：与 vllm_client.py / scanner.py 使用的模型名对齐
DEFAULT_MODEL = os.environ.get(
    "VULN_SCANNER_MODEL", "garrywhite109909/graduation-vuln-scanner:v9max"
)


def _host() -> str:
    return os.environ.get("VULN_SCANNER_VLLM_HOST", "127.0.0.1")


def _port() -> int:
    return int(os.environ.get("VULN_SCANNER_VLLM_PORT", "8000"))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析 CLI 参数（环境变量为默认值）。"""
    p = argparse.ArgumentParser(description="vLLM 独立推理服务启动器")
    p.add_argument(
        "--model",
        default=os.environ.get("VULN_SCANNER_VLLM_MODEL", "").strip(),
        help="基座模型：HF id 或本地目录（AWQ/GPTQ 量化目录）。可用 VULN_SCANNER_VLLM_MODEL 设置",
    )
    p.add_argument(
        "--served-model-name",
        default=os.environ.get("VULN_SCANNER_MODEL", DEFAULT_MODEL),
        help="对外暴露的模型名（与 vllm_client 的 model 参数一致）",
    )
    p.add_argument(
        "--port",
        type=int,
        default=_port(),
        help=f"API 端口（默认 {_port()}）",
    )
    p.add_argument(
        "--quantization",
        default=os.environ.get("VULN_SCANNER_VLLM_QUANTIZATION", "auto").strip(),
        choices=["auto", "awq", "gptq", "fp16", "bf16"],
        help="量化方式：auto 自动识别权重文件中的量化类型；awq/gptq 显式指定",
    )
    p.add_argument(
        "--lora",
        default=os.environ.get("VULN_SCANNER_VLLM_ADAPTER", "").strip(),
        help="LoRA adapter 目录（可选，启用 --enable-lora 运行时叠加 FP16）",
    )
    p.add_argument(
        "--gpu-memory-utilization",
        type=float,
        default=float(os.environ.get("VULN_SCANNER_VLLM_GPU_MEMORY_UTIL", "0.85")),
        help="GPU 显存利用率（默认 0.85）",
    )
    p.add_argument(
        "--max-model-len",
        type=int,
        default=int(os.environ.get("VULN_SCANNER_VLLM_MAX_MODEL_LEN", "16384")),
        help="最大上下文长度（默认 16384）",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="仅打印将要执行的 vllm serve 命令，不真正启动",
    )
    return p.parse_args(argv)


def _resolve_model(args: argparse.Namespace) -> str:
    """解析基座模型：优先本地目录，其次 HF id。"""
    model = args.model.strip()
    if not model:
        # 尝试自动探测项目 models/vllm/ 下的量化目录（与 transformers 的 models/transformers 对齐）
        from graduation_project.paths import find_project_root, local_vllm_model_dir

        # 主位置：models/vllm/Qwen3-8B-AWQ（现行标准，与本地下载目录一致）
        for repo_name in ("Qwen3-8B-AWQ", "Qwen3-8B-GPTQ"):
            d = local_vllm_model_dir(repo_name)
            if (d / "config.json").is_file():
                return str(d)
        # 兼容旧布局：models/ 根下的量化目录
        models_dir = find_project_root() / "models"
        candidates = ["vllm", "awq", "gptq", "Qwen3-8B-AWQ", "Qwen3-8B-GPTQ"]
        for cand in candidates:
            d = models_dir / cand
            if (d / "config.json").is_file():
                return str(d)
        raise SystemExit(
            "[vllm_server] 未指定模型。请设置 VULN_SCANNER_VLLM_MODEL 或 --model "
            "（HF id 或本地 AWQ/GPTQ 量化目录，可先用设置页下载到 models/vllm/）。"
        )

    # 本地目录：校验存在且含 config.json
    local = Path(model).expanduser()
    if local.is_dir():
        if not (local / "config.json").is_file():
            raise SystemExit(f"[vllm_server] 本地模型目录缺少 config.json: {model}")
        return str(local.resolve())
    return model  # HF id


def _check_vllm_installed() -> tuple[bool, str]:
    """检查 vllm 是否已安装。"""
    code, out = -1, ""
    try:
        r = subprocess.run(
            [sys.executable, "-c", "import vllm; print(vllm.__version__)"],
            capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace",
        )
        code, out = r.returncode, r.stdout.strip()
    except Exception as e:
        out = str(e)
    if code == 0 and out:
        return True, out
    return False, out or "vllm 未安装"


def lora_module_name(served_model_name: str) -> str:
    """从对外模型名派生 LoRA 模块名（去命名空间和 tag），保证服务端与客户端一致。"""
    name = served_model_name.split("/")[-1]
    name = name.split(":")[0]
    return name or "lora"


def build_serve_cmd(args: argparse.Namespace, model: str) -> list[str]:
    """组装 `python -m vllm serve ...` 命令。"""
    cmd = [sys.executable, "-m", "vllm", "serve", model]

    # 量化：auto 时不显式传，让 vLLM 自动识别权重文件中的量化类型
    if args.quantization not in ("auto", "fp16", "bf16"):
        cmd += ["--quantization", args.quantization]

    # 对外暴露的模型名（与 vllm_client 的 model 参数一致）
    cmd += ["--served-model-name", args.served_model_name]

    cmd += [
        "--host", _host(),
        "--port", str(args.port),
        "--gpu-memory-utilization", str(args.gpu_memory_utilization),
        "--max-model-len", str(args.max_model_len),
    ]

    # LoRA 运行时叠加（FP16，不改动基座权重，保留精度）
    if args.lora:
        lora_path = Path(args.lora).expanduser()
        if not lora_path.is_dir():
            raise SystemExit(f"[vllm_server] LoRA adapter 目录不存在: {args.lora}")
        lora_name = lora_module_name(args.served_model_name)
        cmd += ["--enable-lora", "--lora-modules", f"{lora_name}={lora_path}"]

    return cmd


def wait_for_ready(port: int, timeout: int = 300, proc: subprocess.Popen | None = None) -> bool:
    """等待 vLLM 服务就绪（/v1/models 可访问）。"""
    url = f"http://{_host()}:{port}/v1/models"
    start = time.time()
    while time.time() - start < timeout:
        if proc is not None and proc.poll() is not None:
            print(f"[vllm_server] vLLM 进程提前退出（退出码 {proc.returncode}）。")
            return False
        try:
            resp = requests.get(
                url, timeout=3,
                proxies={"http": None, "https": None},
            )
            if resp.status_code == 200:
                print(f"[vllm_server] 服务就绪（第 {int(time.time() - start)}s）：{url}")
                return True
        except Exception:
            pass
        time.sleep(2)
    print(f"[vllm_server] 等待服务就绪超时（{timeout}s）。")
    return False


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    # vLLM 官方仅支持 Linux/WSL2；原生 Windows 直接拒绝启动，避免误导
    if sys.platform == "win32":
        print("[vllm_server] vLLM 官方不支持原生 Windows（仅支持 Linux / WSL2）。")
        print("[vllm_server] 建议改用 Ollama / LlamaCPP 后端，或在 WSL2 / Linux 中运行本项目。")
        return 1
    model = _resolve_model(args)

    # 1. vllm 依赖检查
    ok, ver = _check_vllm_installed()
    if not ok:
        print("[vllm_server] 未检测到 vllm，请先安装：")
        print("  通过启动器选择 vllm 后端自动安装，或手动执行：")
        print("  pip install vllm")
        print("  提示：vLLM 依赖 torch，安装体积较大（数 GB），请耐心等待。")
        return 1
    print(f"[vllm_server] vLLM 版本: {ver}")
    print(f"[vllm_server] 基座模型: {model}")
    print(f"[vllm_server] 对外模型名: {args.served_model_name}")
    if args.lora:
        print(f"[vllm_server] LoRA: {args.lora}（--enable-lora 运行时叠加）")
    print(f"[vllm_server] 端口: {args.port} | 量化: {args.quantization} | "
          f"显存利用率: {args.gpu_memory_utilization} | 上下文: {args.max_model_len}")

    cmd = build_serve_cmd(args, model)
    if args.dry_run:
        print("\n[DRY-RUN] 将执行：\n  " + " ".join(cmd))
        return 0

    print("\n[vllm_server] 启动 vLLM 服务（模型加载到显存，可能需要数十秒到数分钟）...")
    print(f"[vllm_server] 命令: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd)

    # 中断信号转发，让 Ctrl+C 能同时停掉 vLLM 子进程
    def _forward(signum, frame):
        try:
            proc.terminate()
        except Exception:
            pass
    signal.signal(signal.SIGINT, _forward)
    signal.signal(signal.SIGTERM, _forward)

    if not wait_for_ready(args.port, proc=proc):
        proc.terminate()
        return 1

    print(f"\n[vllm_server] vLLM 服务已启动：http://{_host()}:{args.port}/v1")
    print("[vllm_server] 按 Ctrl+C 停止服务。")
    try:
        proc.wait()
    except KeyboardInterrupt:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
