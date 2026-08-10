#!/usr/bin/env bash
set -e
# 项目根目录：始终以脚本所在位置推导，不依赖用户调用时的 $PWD，
# 保证 OLLAMA_MODELS/HF_HOME 与软件内 find_project_root() 解析一致。
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"
echo "Starting AI Vulnerability Scanner..."

# 模型存储统一到项目相对目录（与软件 ollama_models_dir()/hf_home_dir() 一致）：
#   - Ollama 模型 → <项目>/models/ollama
#   - HuggingFace 缓存 → <项目>/models/transformers/.hf_home
export OLLAMA_MODELS="$PROJECT_ROOT/models/ollama"
export HF_HOME="$PROJECT_ROOT/models/transformers/.hf_home"
mkdir -p "$OLLAMA_MODELS" "$HF_HOME"

# 依赖一律装进「当前解释器」python3（sys.executable），并在同环境下跑启动器。
# 不再跨 conda 环境扫描 torch 构建并 re-exec 切换，避免"环境换来换去"导致依赖分裂
# （torch 对了却缺 tree_sitter_python / 安全工具装到别的环境）。缺 torch 时后续
# dependency_installer 会现场安装。
PY="${PYTHON:-python3}"
echo "[Setup] 使用解释器: $PY"

# 首次运行自动安装核心依赖（Web 层 + 分析引擎 + tree-sitter + 启动器硬件检测）
if ! "$PY" -c "import fastapi, uvicorn, pydantic, requests, tree_sitter, tree_sitter_python, tree_sitter_javascript, tree_sitter_java, tree_sitter_php, tree_sitter_typescript, chromadb, sentence_transformers, psutil" 2>/dev/null; then
    echo "[Setup] First run: installing core dependencies..."

    # 若该解释器完全没有 torch，先装 CPU 版保底（用于 sentence-transformers embedding）。
    # 已有 torch（如 ROCm/CUDA 匹配环境）则跳过，避免用 CPU 版覆盖掉硬件匹配版。
    if ! "$PY" -c "import torch" 2>/dev/null; then
        "$PY" -m pip install --upgrade --index-url https://download.pytorch.org/whl/cpu torch || true
    fi

    # 使用清华 TUNA 镜像加速国内 pip 下载
    "$PY" -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
    "$PY" -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
    echo "[Setup] Core dependencies installed."
fi

# 新框架所需传统安全工具（bandit/semgrep/pip-audit/detect-secrets/gitleaks/trivy）：
# 缺失自动安装；已存在但损坏（冒烟测试 --version 失败，如 Traceback 的 semgrep）
# 自动强制重装修复。版本下限见 dependency_installer.py 的 SECURITY_TOOLS_PIP_SPEC。
if [ "${VULN_SCANNER_SKIP_TOOLS:-0}" != "1" ]; then
    echo "[Setup] Checking/installing security tools (latest stable)..."
    "$PY" -m app.launcher.dependency_installer tools || true
fi

# 若用户已显式指定 transformers/llamacpp 后端，提前预热安装对应依赖（可选，自动指向最新稳定版）
if [ -n "${VULN_SCANNER_BACKEND:-}" ]; then
    if [ "$VULN_SCANNER_BACKEND" = "transformers" ]; then
        "$PY" -m app.launcher.dependency_installer transformers || true
    elif [ "$VULN_SCANNER_BACKEND" = "llamacpp" ]; then
        "$PY" -m app.launcher.dependency_installer llamacpp || true
    fi
fi

"$PY" -m app.launcher.bootstrap
