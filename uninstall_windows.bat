@echo off
REM AI Vulnerability Scanner - Uninstaller (Windows)
REM Double-click for interactive mode, or pass args:
REM   --yes / --dry-run / --keep-project / --keep-ollama / --keep-accel
REM   --purge-deps : ALSO uninstall 40+ generic indirect packages (numpy,
REM     pandas, transformers, ...). Default: they are KEPT, even with --yes.
REM IMPORTANT: run this script in the SAME Python environment used to install
REM dependencies (conda/venv/system Python). It only cleans the environment
REM that runs it. Do NOT run it in training/experiment envs (graproj, AI).
REM 2026-09-20: removed `chcp 65001 >nul`. Per app/launcher/start_windows.bat
REM (lines 9-10), chcp 65001 has a tail-eating effect on cmd.exe when the
REM expanded %~dp0 path contains non-ASCII characters, producing parse errors.
REM This file stays ASCII-only and runs under the system ANSI code page.
cd /d "%~dp0"

echo ============================================================
echo   AI Vulnerability Scanner - Uninstaller (Windows)
echo   Will clean: backend processes, Python packages, Ollama and models,
echo   ROCm system parts (NVIDIA drivers are never touched), local data,
echo   editor plugins, project folder.
echo ============================================================
echo.
echo   IMPORTANT: activate the SAME conda/venv environment used for
echo   installation before running this script.
echo.
echo   [1] Interactive (default, ask before each step)
echo   [2] Automatic (--yes, no confirmation)
echo   [3] Dry run (--dry-run, only list actions)
echo   [0] Exit
echo.
echo   Note: generic indirect packages (numpy/pandas/...) are kept unless
echo   you run with --purge-deps.
echo.
set /p MODE=Please select [1/2/3/0]: 

if "%MODE%"=="2" set EXTRA=--yes
if "%MODE%"=="3" set EXTRA=--dry-run
if "%MODE%"=="0" exit /b 0

set "PYCMD=python"
where python >nul 2>nul
if errorlevel 1 (
    set "PYCMD=py -3"
    where py >nul 2>nul
    if errorlevel 1 set "PYCMD=python3"
)

%PYCMD% uninstall.py %EXTRA%
echo.
pause
