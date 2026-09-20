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
# 用户原本自定义的 OLLAMA_MODELS 先暂存到 VULN_LEGACY_OLLAMA_MODELS：
# bootstrap.py 会把旧位置的已有模型迁移进项目目录，避免"模型消失"重新下载
if [ -n "${OLLAMA_MODELS:-}" ]; then
    export VULN_LEGACY_OLLAMA_MODELS="$OLLAMA_MODELS"
fi
export OLLAMA_MODELS="$PROJECT_ROOT/models/ollama"
export HF_HOME="$PROJECT_ROOT/models/transformers/.hf_home"
mkdir -p "$OLLAMA_MODELS" "$HF_HOME"

# ---------------------------------------------------------------------------
# 2026-09-20 修复：Ubuntu 23.04+ / Debian 12 起系统 Python 受 PEP 668
# （externally-managed）保护，直接 `pip3 install` 会硬失败；此前脚本在 set -e
# 下首个 pip 报错即整段退出，双击用户只见窗口闪退。现改为解释器回退链：
#   (a) 已存在可用 venv（.venv/bin/python 且带 pip）→ 直接复用；
#   (b) 尝试 `python3 -m venv .venv`，成功 → 后续 pip 与启动全部走 .venv；
#   (c) venv 创建失败（多因缺 python3-venv）→ pip3 install --user；
#   (d) 仍失败（PEP 668 拒绝 --user）→ pip3 install --break-system-packages
#       （打印明确警告：会写进系统 site-packages，建议改装 python3-venv）。
# 每级失败都先打印原因再降级，不再静默崩掉。
# bootstrap.py 内部一律用 sys.executable 装 pip 包，venv 模式下天然继承 .venv。
# ---------------------------------------------------------------------------
die() {
    # 失败退出：打印醒目原因；仅交互终端（[ -t 0 ]）才等待回车，避免 CI/管道挂住，
    # 也避免双击运行时窗口一闪而过看不到错误。
    echo "" >&2
    echo "============================================================" >&2
    echo "  [ERROR] $1" >&2
    echo "============================================================" >&2
    if [ -t 0 ]; then
        read -r -p "按回车退出..." _
    fi
    exit "${2:-1}"
}

SRC_PY="${PYTHON:-python3}"
PY=""
PIP_FLAGS=""

# (a) 已存在可用 venv：直接用（含 pip 可用性校验，防半成品 venv）
if [ -x ".venv/bin/python" ] && ".venv/bin/python" -m pip --version >/dev/null 2>&1; then
    PY="$PROJECT_ROOT/.venv/bin/python"
    echo "[Setup] 复用已存在的虚拟环境: $PROJECT_ROOT/.venv"
else
    # (b) 尝试创建 venv
    if "$SRC_PY" -m venv .venv 2>/dev/null && [ -x ".venv/bin/python" ] && ".venv/bin/python" -m pip --version >/dev/null 2>&1; then
        PY="$PROJECT_ROOT/.venv/bin/python"
        echo "[Setup] 已创建并使用虚拟环境: $PROJECT_ROOT/.venv"
    else
        echo "[Setup] ⚠ 虚拟环境创建失败（常见原因：Debian/Ubuntu 缺 python3-venv，"
        echo "[Setup] ⚠ 可执行: sudo apt install python3-venv python3-pip 后重试），降级到 --user 安装"
        rm -rf "$PROJECT_ROOT/.venv" 2>/dev/null || true  # 清掉半成品，避免下次被 (a) 误认
        # (c)/(d) 按 PEP 668 标记(EXTERNALLY-MANAGED)预判：无标记走 --user；有标记
        # 则 --user 也必被拒，直接进入 --break-system-packages 并给出明确警告
        _STD="$("$SRC_PY" -c 'import sysconfig; print(sysconfig.get_path("stdlib"))' 2>/dev/null || true)"
        if [ -n "$_STD" ] && [ -f "$_STD/EXTERNALLY-MANAGED" ]; then
            echo "[Setup] ⚠ 检测到 PEP 668 (externally-managed) 系统解释器：--user 安装也会被拒绝。"
            echo "[Setup] ⚠ 降级为 pip --break-system-packages（写入系统 site-packages，"
            echo "[Setup] ⚠ 与 apt 包存在理论冲突风险；强烈建议 sudo apt install python3-venv 后重跑本脚本）。"
            PY="$SRC_PY"
            PIP_FLAGS="--break-system-packages"
        else
            PY="$SRC_PY"
            PIP_FLAGS="--user"
            echo "[Setup] 降级为 pip --user 安装（装进 ~/.local，不污染系统 Python）"
        fi
    fi
fi

# 统一 pip 安装入口：--user 模式下若运行期仍被拒（如 pip 过旧/策略变化），
# 自动再降级一次到 --break-system-packages（PEP 668），并打印原因。
pip_install() {
    local rc=0
    "$PY" -m pip install $PIP_FLAGS "$@" || rc=$?
    if [ "$rc" -eq 0 ]; then
        return 0
    fi
    if [ "$PIP_FLAGS" = "--user" ]; then
        echo "[Setup] ⚠ pip --user 安装失败（退出码 $rc），降级为 --break-system-packages 重试..."
        PIP_FLAGS="--break-system-packages"
        "$PY" -m pip install $PIP_FLAGS "$@"
    else
        return 1
    fi
}

echo "[Setup] 使用解释器: $PY${PIP_FLAGS:+（pip 附加参数: $PIP_FLAGS）}"

# 首次运行自动安装核心依赖（Web 层 + 分析引擎 + tree-sitter + 启动器硬件检测）
if ! "$PY" -c "import fastapi, uvicorn, pydantic, requests, tree_sitter, tree_sitter_python, tree_sitter_javascript, tree_sitter_java, tree_sitter_php, tree_sitter_typescript, chromadb, sentence_transformers, psutil" 2>/dev/null; then
    echo "[Setup] First run: installing core dependencies..."

    # 若该解释器完全没有 torch，先装 CPU 版保底（用于 sentence-transformers embedding）。
    # 已有 torch（如 ROCm/CUDA 匹配环境）则跳过，避免用 CPU 版覆盖掉硬件匹配版。
    if ! "$PY" -c "import torch" 2>/dev/null; then
        "$PY" -m pip install $PIP_FLAGS --upgrade --index-url https://download.pytorch.org/whl/cpu torch || true
    fi

    # 使用清华 TUNA 镜像加速国内 pip 下载
    pip_install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt \
        || die "核心依赖安装失败（requirements.txt）。请检查网络后重试，或手动执行：\"$PY\" -m pip install $PIP_FLAGS -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt"
    pip_install -i https://pypi.tuna.tsinghua.edu.cn/simple -e . \
        || die "项目包安装失败（pip install -e .）。可手动执行：\"$PY\" -m pip install $PIP_FLAGS -i https://pypi.tuna.tsinghua.edu.cn/simple -e ."
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

# 2026-09-20 修复：启动失败时打印醒目原因并等待回车（仅交互终端），
# 不再让 set -e 下窗口一闪而过。
if ! "$PY" -m app.launcher.bootstrap; then
    echo ""
    echo "============================================================"  >&2
    echo "  [ERROR] 启动器异常退出（具体错误见上方日志）。"              >&2
    echo "  常见原因："                                                     >&2
    echo "    1. 网络/代理问题导致依赖或模型下载失败 → 重试或配置代理"        >&2
    echo "    2. 推理后端配置缺失（adapter/GGUF/模型路径）→ 按上方提示修复"   >&2
    echo "    3. venv 相关 → sudo apt install python3-venv python3-pip"     >&2
    echo "  手动重跑: cd \"$PROJECT_ROOT\" && \"$PY\" -m app.launcher.bootstrap" >&2
    echo "============================================================"     >&2
    if [ -t 0 ]; then
        read -r -p "按回车退出..." _
    fi
    exit 1
fi
