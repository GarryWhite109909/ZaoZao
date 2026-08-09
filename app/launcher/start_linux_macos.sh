#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/../.." || exit 1
echo "Starting AI Vulnerability Scanner..."

# 模型文件绝不落 C 盘/用户目录：Ollama 存储与 HuggingFace 缓存全部锁到项目 models/
export OLLAMA_MODELS="$PWD/models/ollama"
export HF_HOME="$PWD/models/transformers/.hf_home"
mkdir -p "$OLLAMA_MODELS" "$HF_HOME"

# 关键：先决定用哪个 python 解释器，再装依赖、跑启动器。
# 这样 torch 匹配硬件（CUDA/ROCm）的环境会承载「全部」依赖（Web 层 + 分析引擎 +
# tree-sitter + 推理），避免出现"torch 对了但缺 tree_sitter_python"这类环境分裂问题。
# 找不到匹配环境时回退到当前 python3（如纯 CPU 机器）。
PY="$(python3 - <<'PYEOF' 2>/dev/null || true
import sys
try:
    sys.path.insert(0, '.')
    from app.launcher.dependency_installer import discover_best_python
    best = discover_best_python()
    print(best or sys.executable)
except Exception:
    print(sys.executable)
PYEOF
)"
PY="${PY:-python3}"
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
# 缺失即自动安装，并自动指向最新稳定版（版本下限见 dependency_installer.py 的
# SECURITY_TOOLS_PIP_SPEC / SECURITY_TOOLS_BIN）。重复执行仅补齐缺失项，不强制升级。
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
