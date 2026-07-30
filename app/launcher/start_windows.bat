@echo off
chcp 65001 >nul
cd /d "%~dp0\..\.."
echo Starting AI Vulnerability Scanner...

REM 首次运行自动安装依赖：检测核心 Web 层 + 分析引擎层 + tree-sitter 语言包 + 启动器硬件检测
python -c "import fastapi, uvicorn, pydantic, requests, tree_sitter, tree_sitter_python, tree_sitter_javascript, tree_sitter_java, tree_sitter_php, tree_sitter_typescript, chromadb, sentence_transformers, psutil" 2>nul
if errorlevel 1 (
    echo [Setup] First run: installing dependencies...
    REM 先安装 CPU 版 torch，避免 sentence-transformers 间接拖下 NVIDIA CUDA 包。
    REM 本应用的大模型推理由 Ollama 负责，Python 侧仅需 torch 运行 embedding，CPU 版足够。
    pip install --index-url https://download.pytorch.org/whl/cpu torch
    REM 使用清华 TUNA 镜像加速国内 pip 下载
    pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
    pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
    echo [Setup] Dependencies installed.
)

python -m app.launcher.bootstrap
pause
