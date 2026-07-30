#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/../.." || exit 1
echo "Starting AI Vulnerability Scanner..."

# 首次运行自动安装依赖：检测核心 Web 层 + 分析引擎层 + tree-sitter 语言包 + 启动器硬件检测
python3 -c "import fastapi, uvicorn, pydantic, requests, tree_sitter, tree_sitter_python, tree_sitter_javascript, tree_sitter_java, tree_sitter_php, tree_sitter_typescript, chromadb, sentence_transformers, psutil" 2>/dev/null || {
    echo "[Setup] First run: installing dependencies..."

    # 根据 GPU 类型预装 torch，避免 AMD 机器误装 NVIDIA CUDA 包。
    # 大模型推理由 Ollama 负责，Python 侧 torch 仅用于 sentence-transformers embedding。
    # AMD ROCm 环境准备可参考 tools/install_rocm_7.2.4.sh。
    if [ "$(uname -s)" = "Linux" ]; then
        if command -v rocm-smi >/dev/null 2>&1 || lspci -nn 2>/dev/null | grep -qiE '(vga|3d|display).*(amd|radeon|ati)'; then
            echo "[Setup] 检测到 AMD GPU，安装 ROCm 7.2 版 torch..."
            pip3 install torch torchvision --index-url https://download.pytorch.org/whl/rocm7.2 || true
        elif lspci -nn 2>/dev/null | grep -qiE '(vga|3d|display).*nvidia'; then
            echo "[Setup] 检测到 NVIDIA GPU，使用 PyPI 默认 CUDA 版 torch..."
            # 不预装，让 requirements.txt 自动解析合适的 CUDA 版本
            :
        else
            echo "[Setup] 未检测到 AMD/NVIDIA GPU，安装 CPU 版 torch..."
            pip3 install --index-url https://download.pytorch.org/whl/cpu torch || true
        fi
    else
        # macOS 默认 torch 无 NVIDIA 依赖，装 CPU 版保底
        pip3 install --index-url https://download.pytorch.org/whl/cpu torch || true
    fi

    # 使用清华 TUNA 镜像加速国内 pip 下载
    pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
    pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
    echo "[Setup] Dependencies installed."
}

python3 -m app.launcher.bootstrap
