@echo off
chcp 65001 >nul
cd /d "%~dp0\..\.."
for %%I in ("%~dp0..\..") do set "VULN_PROJECT_ROOT=%%~fI"
set "OLLAMA_MODELS=%VULN_PROJECT_ROOT%\models\ollama"
set "HF_HOME=%VULN_PROJECT_ROOT%\models\transformers\.hf_home"
if not exist "%OLLAMA_MODELS%" mkdir "%OLLAMA_MODELS%"
if not exist "%HF_HOME%" mkdir "%HF_HOME%"
echo Starting AI Vulnerability Scanner...

REM =====================================================================
REM 依赖一律装进「当前解释器」python（sys.executable），并在同环境下跑启动器。
REM 不再跨 conda 环境扫描 torch 构建并 re-exec 切换，避免"环境换来换去"导致依赖分裂
REM （torch 对了却缺 tree_sitter_python / 安全工具装到别的环境）。缺 torch 时后续
REM dependency_installer 会现场安装。
REM =====================================================================
set "PY=%PYTHON%"
if "%PY%"=="" set "PY=python"
echo [Setup] Using interpreter: %PY%

REM ---------------------------------------------------------------------
REM First-run auto-install: web layer + analysis engine + tree-sitter + launcher detection
REM ---------------------------------------------------------------------
"%PY%" -c "import fastapi, uvicorn, pydantic, requests, tree_sitter, tree_sitter_python, tree_sitter_javascript, tree_sitter_java, tree_sitter_php, tree_sitter_typescript, chromadb, sentence_transformers, psutil" 2>nul
if errorlevel 1 (
    echo [Setup] First run: installing core dependencies...

    REM Install CPU torch for embeddings ONLY if this interpreter has no torch at all;
    REM skip when it already has a hardware-matched torch (CUDA/ROCm), to avoid
    REM overwriting the matching build with the CPU one.
    "%PY%" -c "import torch" 2>nul
    if errorlevel 1 (
        "%PY%" -m pip install --index-url https://download.pytorch.org/whl/cpu torch
    )

    REM Use Tsinghua TUNA mirror to speed up pip downloads in China
    "%PY%" -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
    "%PY%" -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
    echo [Setup] Core dependencies installed.
)

REM New-framework legacy security tools (auto-install, latest stable)
if not "%VULN_SCANNER_SKIP_TOOLS%"=="1" (
    echo [Setup] Checking/installing security tools ^(latest stable^)...
    "%PY%" -m app.launcher.dependency_installer tools
)

REM If the user explicitly picked transformers/llamacpp backend, pre-install its deps (optional)
if not "%VULN_SCANNER_BACKEND%"=="" (
    if "%VULN_SCANNER_BACKEND%"=="transformers" "%PY%" -m app.launcher.dependency_installer transformers
    if "%VULN_SCANNER_BACKEND%"=="llamacpp" "%PY%" -m app.launcher.dependency_installer llamacpp
)

"%PY%" -m app.launcher.bootstrap
pause
