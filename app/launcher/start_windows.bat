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
REM
REM 2026-08-20: 每个关键步骤都检查 errorlevel 并显示明确错误再暂停，
REM 避免"假 python / pip 失败"被 2>nul 吞掉导致双击后静默退出、
REM 用户看不到任何报错。失败即停，用户能立即看到问题出在哪一步。
REM =====================================================================
set "PY=%PYTHON%"
if "%PY%"=="" set "PY=python"
echo [Setup] Using interpreter: %PY%

REM ---- 0) 前置校验：python 真的能跑吗（防 Microsoft Store 假 python / 未安装）----
"%PY%" --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo [错误] 找不到可用的 Python 解释器: "%PY%"
    echo   请先安装 Python 3.10+（勾选 "Add Python to PATH"），
    echo   或设置 PYTHON 环境变量指向真实 python.exe 后重试。
    echo   下载: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

REM ---- 1) 首次运行依赖安装 ----
"%PY%" -c "import fastapi, uvicorn, pydantic, requests, tree_sitter, tree_sitter_python, tree_sitter_javascript, tree_sitter_java, tree_sitter_php, tree_sitter_typescript, chromadb, sentence_transformers, psutil" >nul 2>&1
if errorlevel 1 (
    echo [Setup] First run: installing core dependencies...

    REM Install CPU torch for embeddings ONLY if this interpreter has no torch at all;
    REM skip when it already has a hardware-matched torch (CUDA/ROCm), to avoid
    REM overwriting the matching build with the CPU one.
    "%PY%" -c "import torch" >nul 2>&1
    if errorlevel 1 (
        echo [Setup] Installing CPU torch...
        "%PY%" -m pip install --index-url https://download.pytorch.org/whl/cpu torch
        if errorlevel 1 (
            echo.
            echo [错误] CPU torch 安装失败。请检查网络后重试，
            echo   或手动执行: "%PY%" -m pip install --index-url https://download.pytorch.org/whl/cpu torch
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
        echo [错误] 核心依赖安装失败（requirements.txt）。
        echo   请检查网络连接，或手动执行:
        echo   "%PY%" -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
        echo.
        pause
        exit /b 1
    )
    echo [Setup] Installing project package...
    "%PY%" -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
    if errorlevel 1 (
        echo.
        echo [错误] 项目包安装失败（pip install -e .）。
        echo   请手动执行: "%PY%" -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
        echo.
        pause
        exit /b 1
    )
    echo [Setup] Core dependencies installed.
)

REM ---- 2) 安全工具（可选跳过：set VULN_SCANNER_SKIP_TOOLS=1）----
if not "%VULN_SCANNER_SKIP_TOOLS%"=="1" (
    echo [Setup] Checking/installing security tools ^(latest stable^)...
    "%PY%" -m app.launcher.dependency_installer tools
    if errorlevel 1 (
        echo.
        echo [警告] 安全工具安装未完全成功（不影响核心两阶段扫描，可稍后手动修复）。
        echo   可设置 VULN_SCANNER_SKIP_TOOLS=1 跳过本步骤后重新启动。
        echo.
    )
)

REM ---- 3) 显式指定的后端依赖（可选）----
if not "%VULN_SCANNER_BACKEND%"=="" (
    if "%VULN_SCANNER_BACKEND%"=="transformers" (
        echo [Setup] Pre-installing transformers backend deps...
        "%PY%" -m app.launcher.dependency_installer transformers
        if errorlevel 1 (
            echo.
            echo [警告] transformers 后端依赖安装未完全成功，启动器将继续尝试。
            echo.
        )
    )
    if "%VULN_SCANNER_BACKEND%"=="llamacpp" (
        echo [Setup] Pre-installing llamacpp backend deps...
        "%PY%" -m app.launcher.dependency_installer llamacpp
        if errorlevel 1 (
            echo.
            echo [警告] llamacpp 后端依赖安装未完全成功，启动器将继续尝试。
            echo.
        )
    )
)

REM ---- 4) 启动器 ----
"%PY%" -m app.launcher.bootstrap
if errorlevel 1 (
    echo.
    echo [错误] 启动器退出（错误码 %errorlevel%）。
    echo   上方应有具体错误信息；若没有，请手动执行下面命令查看完整输出:
    echo   "%PY%" -m app.launcher.bootstrap
    echo.
    pause
    exit /b 1
)

pause
