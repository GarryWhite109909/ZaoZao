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
REM Decide the interpreter FIRST, then use it for the whole flow.
REM This way the torch-matched env (CUDA/ROCm) carries ALL deps
REM (web + analysis + tree-sitter + inference), avoiding split-env issues
REM (torch is right but tree_sitter_python is missing).
REM Falls back to plain "python" when no matching env is found.
REM
REM NOTE: never inline this probe into a `( ... )` parenthesized block with `echo`.
REM cmd treats the `(`/`)` inside e.g. `print(best or sys.executable)` as block
REM delimiters and aborts the whole batch instantly (flash-close,
REM "was unexpected at this time"). We write a temp .py line-by-line instead,
REM mirroring the heredoc in start_linux_macos.sh.
REM =====================================================================
set "PY="
set "PROBE=%TEMP%\nivis_discover_python.py"
REM Write the probe line-by-line with '>' then '>>' (NOT a parenthesized block).
REM Inside a `( ... )` block, cmd treats the `(`/`)` inside e.g. `print(best or sys.executable)`
REM as block delimiters and aborts the whole batch with "was unexpected at this time".
REM Writing each line separately avoids that and mirrors the heredoc in start_linux_macos.sh.
>  "%PROBE%" echo import sys
>> "%PROBE%" echo import os
>> "%PROBE%" echo sys.path.insert(0, os.getcwd())
>> "%PROBE%" echo try:
>> "%PROBE%" echo     from app.launcher.dependency_installer import discover_best_python
>> "%PROBE%" echo     best = discover_best_python()
>> "%PROBE%" echo except Exception:
>> "%PROBE%" echo     best = None
>> "%PROBE%" echo print(best or sys.executable)
for /f "delims=" %%i in ('python "%PROBE%" 2^>nul') do set "PY=%%i"
del "%PROBE%" 2>nul
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
