#!/usr/bin/env python3
"""
模型下载脚本 —— 支持两种获取方式，并自动适配本机硬件：

1. Ollama Registry（默认，最简单）
   python tools/download_model.py --source ollama --model graduation-vuln-scanner:v9max

2. 直接下载 GGUF（适合无法访问 Ollama Registry 的环境）
   python tools/download_model.py \
       --source gguf \
       --url https://github.com/GarryWhite109909/ZaoZao/releases/download/v1.0/merged_v5-q4_k_m.gguf \
       --model graduation-vuln-scanner:v9max

国内网络加速：source=gguf 时，若 URL 指向 github.com，默认自动加 ghproxy 前缀
（https://mirror.ghproxy.com/）加速下载。可用 --no-mirror 关闭。

硬件自适应：脚本会自动检测 GPU 显存 / CPU 核数，动态生成 Modelfile 中的
num_ctx / num_gpu / num_thread 参数。≥8GB 显存使用 num_ctx=8192，6-8GB 使用
4096，4-6GB 或无 GPU 时回退到 2048 并启用 CPU 推理（q4_k_m 8B 模型权重约
4.7GB，4GB 显存装不下）。
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.request import urlopen

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# 复用 bootstrap 中的硬件检测逻辑，避免代码漂移
sys.path.insert(0, str(PROJECT_ROOT))
try:
    from app.launcher.bootstrap import detect_hardware, recommend_config
except Exception:  # pragma: no cover - 兜底，避免独立运行时 import 失败
    detect_hardware = None  # type: ignore
    recommend_config = None  # type: ignore


def run(cmd: list[str], **kwargs) -> int:
    print("$ " + " ".join(cmd))
    return subprocess.run(cmd, **kwargs).returncode


def apply_ghproxy(url: str) -> str:
    """对 GitHub URL 自动加 ghproxy 前缀以加速国内下载。

    仅对 github.com 的下载链接生效（release assets / raw 文件）。
    非 GitHub URL 原样返回。
    """
    if url.startswith("https://github.com/"):
        mirrored = "https://mirror.ghproxy.com/" + url
        print(f"[镜像] 检测到 GitHub URL，已自动加 ghproxy 前缀加速下载")
        print(f"[镜像] 原址: {url}")
        print(f"[镜像] 加速: {mirrored}")
        print(f"[镜像] 若加速地址不可用，加 --no-mirror 关闭")
        return mirrored
    return url


def download_gguf(url: str, out_path: Path) -> None:
    print(f"[下载] {url} -> {out_path}")
    with urlopen(url, timeout=60) as resp, open(out_path, "wb") as f:
        total = int(resp.headers.get("content-length", 0))
        downloaded = 0
        chunk_size = 1024 * 1024
        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            f.write(chunk)
            downloaded += len(chunk)
            if total:
                pct = downloaded / total * 100
                print(f"  {downloaded / 1e6:.1f}MB / {total / 1e6:.1f}MB ({pct:.1f}%)", end="\r")
    print()


def create_modelfile(gguf_path: Path, model_name: str) -> Path:
    """根据本机硬件自适应生成 Modelfile。

    - ≥8GB 显存：num_ctx=8192，全 GPU 层
    - 6-8GB 显存：num_ctx=4096，全 GPU 层
    - 4-6GB 显存：显存不足以装下 q4_k_m 8B 模型（4.7GB），降级 CPU（num_gpu=0）
    - <4GB 或无 GPU：num_ctx=2048，CPU 推理（num_gpu=0）
    - Apple Silicon：num_ctx=4096，Metal 加速（num_gpu=1）
    """
    modelfile = PROJECT_ROOT / f"outputs/Modelfile_{model_name.replace(':', '_')}"
    modelfile.parent.mkdir(parents=True, exist_ok=True)

    # 硬件检测 + 推荐参数
    if detect_hardware is not None and recommend_config is not None:
        hardware = detect_hardware()
        config = recommend_config(hardware)
    else:
        # 兜底：保守配置（与历史行为一致）
        hardware = {"has_nvidia_gpu": False, "gpu_name": None,
                    "vram_mb": None, "cpu_cores": os.cpu_count() or 4,
                    "ram_gb": 8.0, "platform": sys.platform}
        config = {
            "num_ctx": 8192, "num_gpu": -1,
            "num_thread": min(os.cpu_count() or 4, 8),
            "quantization": "q4_k_m", "warning": None, "mode": "gpu",
        }

    # 打印硬件摘要
    print("[硬件检测] 生成 Modelfile 前的硬件检测结果：")
    if hardware.get("has_nvidia_gpu") and hardware.get("gpu_name"):
        print(f"  GPU: {hardware['gpu_name']} ({hardware['vram_mb']}MB)")
    elif hardware.get("gpu_name") and "Apple M" in hardware["gpu_name"]:
        print(f"  GPU: {hardware['gpu_name']} (Apple Silicon)")
    else:
        print("  GPU: 未检测到 NVIDIA GPU")
    print(f"  CPU: {hardware['cpu_cores']} 核")
    print(f"  推理模式: {config['mode'].upper()} "
          f"(num_ctx={config['num_ctx']}, num_gpu={config['num_gpu']}, "
          f"num_thread={config['num_thread']}, {config['quantization']})")
    if config["warning"]:
        print(f"  ⚠️ {config['warning']}")

    # 根据模式组织 Modelfile 注释
    if config["mode"] == "gpu":
        if config["num_ctx"] == 8192:
            hw_comment = "# 硬件适配：≥8GB 显存，Q4_K_M 约 4.7GB，num_ctx 8192 留足 activations 余量\n"
        else:
            hw_comment = "# 硬件适配：6-8GB 显存，num_ctx 4096 平衡显存与上下文长度\n"
    elif config["mode"] == "apple_silicon":
        hw_comment = "# 硬件适配：Apple Silicon，Metal 加速（num_gpu=1），统一内存架构\n"
    else:
        hw_comment = "# 硬件适配：显存不足或无 GPU，启用 CPU 推理（num_gpu=0），速度较慢\n"

    # num_gpu 仅在非默认时显式写出（-1 全 GPU / 0 纯 CPU / 1 Metal）
    num_gpu_line = f"PARAMETER num_gpu {config['num_gpu']}\n"
    num_thread_line = f"PARAMETER num_thread {config['num_thread']}\n"

    content = (
        f"FROM {gguf_path}\n\n"
        "# Qwen3 chat template（与训练时一致）\n"
        'TEMPLATE """{{- if .System }}<|im_start|>system\n'
        "{{ .System }}<|im_end|>\n"
        "{{- end }}<|im_start|>user\n"
        "{{ .Prompt }}<|im_end|>\n"
        "<|im_start|>assistant\n"
        '"""\n\n'
        'SYSTEM """你是一名资深的代码安全审计专家。请对给出的代码片段进行安全分析，判断其中是否存在安全漏洞。"""\n\n'
        f"{hw_comment}"
        "PARAMETER temperature 0.1\n"
        f"PARAMETER num_ctx {config['num_ctx']}\n"
        f"{num_gpu_line}"
        f"{num_thread_line}"
        "PARAMETER num_predict 2048\n"
        'PARAMETER stop "<|im_end|>"\n'
        'PARAMETER stop "<|endoftext|>"\n'
    )
    modelfile.write_text(content, encoding="utf-8")
    print(f"[硬件检测] Modelfile 已写入：{modelfile}")
    return modelfile


def pull_ollama(model: str) -> int:
    if shutil.which("ollama") is None:
        print("[ERROR] 未找到 ollama 命令。请先安装：https://ollama.com/download")
        return 1
    return run(["ollama", "pull", model])


def create_from_gguf(url: str, model: str, use_mirror: bool = True) -> int:
    if shutil.which("ollama") is None:
        print("[ERROR] 未找到 ollama 命令。请先安装：https://ollama.com/download")
        return 1

    if use_mirror:
        url = apply_ghproxy(url)

    with tempfile.TemporaryDirectory() as tmp:
        gguf_path = Path(tmp) / "model.gguf"
        download_gguf(url, gguf_path)
        modelfile = create_modelfile(gguf_path, model)
        print(f"[创建] ollama create {model} -f {modelfile}")
        return run(["ollama", "create", model, "-f", str(modelfile)])


def main() -> int:
    parser = argparse.ArgumentParser(description="下载并安装漏洞扫描模型")
    parser.add_argument(
        "--source",
        choices=["ollama", "gguf"],
        default="ollama",
        help="模型来源：ollama registry 或直接下载 GGUF",
    )
    parser.add_argument("--model", default="graduation-vuln-scanner:v9max", help="本地 Ollama 模型名")
    parser.add_argument("--url", help="GGUF 下载地址（source=gguf 时必填）")
    parser.add_argument(
        "--no-mirror",
        action="store_true",
        default=False,
        help="关闭 ghproxy 加速，直接从原始 URL 下载（海外网络环境适用）",
    )
    args = parser.parse_args()

    if args.source == "ollama":
        return pull_ollama(args.model)
    else:
        if not args.url:
            print("[ERROR] source=gguf 时必须指定 --url")
            return 1
        return create_from_gguf(args.url, args.model, use_mirror=not args.no_mirror)


if __name__ == "__main__":
    sys.exit(main())
