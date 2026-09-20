@echo off
REM NOTE: Keep EVERY byte of this file ASCII-only. No Chinese comments/echo.
REM cmd.exe parses this file with the system ANSI code page (GBK on zh-CN
REM Windows). Multi-byte text - even inside REM lines - desyncs the parser
REM and the tail of the line gets executed as a command, producing errors
REM like "'<mojibake>' is not recognized as an internal or external command".
REM Repro 2026-09-19: Chinese REM lines added on 2026-08-20 broke this rule
REM and shipped exactly such errors on default zh-CN consoles.
REM Do NOT add `chcp 65001` either: it has the same tail-eating effect when
REM the path (expanded %~dp0) contains non-ASCII characters.
REM Chinese guidance is printed by the Python launcher (bootstrap), which
REM writes to the console through Unicode APIs and is immune to code pages.
cd /d "%~dp0\..\.."
for %%I in ("%~dp0..\..") do set "VULN_PROJECT_ROOT=%%~fI"
REM Preserve the user's original Ollama model store (if set) before we take
REM over OLLAMA_MODELS below: bootstrap.py migrates existing models from that
REM legacy location into the project dir so they are not silently orphaned.
if defined OLLAMA_MODELS set "VULN_LEGACY_OLLAMA_MODELS=%OLLAMA_MODELS%"
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
REM
REM 2026-08-20: check errorlevel after every critical step and pause with a
REM clear message, so a fake python / failed pip is no longer swallowed by
REM 2^>nul and a double-click no longer exits silently. Stop on first
REM failure: the user must see exactly which step broke.
REM =====================================================================
set "PY=%PYTHON%"
if "%PY%"=="" set "PY=python"
echo [Setup] Using interpreter: %PY%

REM ---- 0) Sanity check: is python really runnable (anti fake python) ----
"%PY%" --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] No usable Python interpreter: "%PY%"
    echo   Install Python 3.10+ and check "Add Python to PATH",
    echo   or set the PYTHON env var to a real python.exe and retry.
    echo   Download: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

REM ---- 1) First-run dependency installation ----
"%PY%" -c "import fastapi, uvicorn, pydantic, requests, tree_sitter, tree_sitter_python, tree_sitter_javascript, tree_sitter_java, tree_sitter_php, tree_sitter_typescript, chromadb, sentence_transformers, psutil" >nul 2>&1
if errorlevel 1 (
    echo [Setup] First run: installing core dependencies...

    REM Install CPU torch for embeddings ONLY if this interpreter has no torch
    REM at all; skip when it already has a hardware-matched torch build
    REM (CUDA/ROCm), to avoid overwriting the matching build with the CPU one.
    "%PY%" -c "import torch" >nul 2>&1
    if errorlevel 1 (
        echo [Setup] Installing CPU torch...
        "%PY%" -m pip install --index-url https://download.pytorch.org/whl/cpu torch
        if errorlevel 1 (
            echo.
            echo [ERROR] CPU torch installation failed. Check the network and retry,
            echo   or run manually:
            echo   "%PY%" -m pip install --index-url https://download.pytorch.org/whl/cpu torch
            echo.
            pause
            exit /b 1
        )
    )

    REM Use Tsinghua TUNA mirror to speed up pip downloads in China
    echo [Setup] Installing requirements.txt...
    "%PY%" -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
    if errorlevel 1 (
        echo.
        echo [ERROR] Core dependency installation failed: requirements.txt.
        echo   Check the network connection, or run manually:
        echo   "%PY%" -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
        echo.
        pause
        exit /b 1
    )
    echo [Setup] Installing project package...
    "%PY%" -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
    if errorlevel 1 (
        echo.
        echo [ERROR] Project package installation failed: pip install -e .
        echo   Run manually:
        echo   "%PY%" -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
        echo.
        pause
        exit /b 1
    )
    echo [Setup] Core dependencies installed.
)

REM ---- 2) Security tools - optionally skip: set VULN_SCANNER_SKIP_TOOLS=1 ----
if not "%VULN_SCANNER_SKIP_TOOLS%"=="1" (
    echo [Setup] Checking/installing security tools ^(latest stable^)...
    "%PY%" -m app.launcher.dependency_installer tools
    if errorlevel 1 (
        echo.
        echo [WARN] Security tool installation did not fully succeed.
        echo   This does not affect the core two-stage scanning; fix it later.
        echo   Set VULN_SCANNER_SKIP_TOOLS=1 to skip this step on next start.
        echo.
    )
)

REM ---- 3) Explicit backend dependencies - optional ----
if not "%VULN_SCANNER_BACKEND%"=="" (
    if "%VULN_SCANNER_BACKEND%"=="transformers" (
        echo [Setup] Pre-installing transformers backend deps...
        "%PY%" -m app.launcher.dependency_installer transformers
        if errorlevel 1 (
            echo.
            echo [WARN] transformers backend deps not fully installed; launcher will keep trying.
            echo.
        )
    )
    if "%VULN_SCANNER_BACKEND%"=="llamacpp" (
        echo [Setup] Pre-installing llamacpp backend deps...
        "%PY%" -m app.launcher.dependency_installer llamacpp
        if errorlevel 1 (
            echo.
            echo [WARN] llamacpp backend deps not fully installed; launcher will keep trying.
            echo.
        )
    )
)

REM ---- 4) Launcher ----
"%PY%" -m app.launcher.bootstrap
if errorlevel 1 (
    echo.
    echo [ERROR] Launcher exited with an error. Details should be above.
    echo   If nothing is shown, run this manually to see the full output:
    echo   "%PY%" -m app.launcher.bootstrap
    echo.
    pause
    exit /b 1
)

pause
