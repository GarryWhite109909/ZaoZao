@echo off
REM NOTE: Do NOT use `chcp 65001` here. This batch file may live under a path
REM containing non-ASCII characters (e.g. a Chinese folder name). Switching
REM the code page to UTF-8 while cmd still parses the script (and the
REM expanded %~dp0 path) with the system ANSI code page causes the parser to
REM misread multi-byte characters and "eat" the tail of a command, producing
REM errors like "'ec' is not recognized" or "'cy_installer' is not recognized".
REM Keeping the default code page keeps the non-ASCII path self-consistent.
REM All echo'd text in this file is ASCII, so no mojibake.
cd /d "%~dp0\..\.."
for %%I in ("%~dp0..\..") do set "VULN_PROJECT_ROOT=%%~fI"
set "OLLAMA_MODELS=%VULN_PROJECT_ROOT%\models\ollama"
set "HF_HOME=%VULN_PROJECT_ROOT%\models\transformers\.hf_home"
if not exist "%OLLAMA_MODELS%" mkdir "%OLLAMA_MODELS%"
if not exist "%HF_HOME%" mkdir "%HF_HOME%"
echo Starting AI Vulnerability Scanner...

REM =====================================================================
REM Install ALL deps into the current interpreter (sys.executable) and run
REM the launcher in that same environment. Do NOT scan conda envs for a torch
REM build and re-exec across envs, to avoid dependency fragmentation (torch
REM OK but missing tree_sitter / security tools installed elsewhere).
REM dependency_installer will install missing torch on the fly.
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
