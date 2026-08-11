#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 漏洞扫描器 —— 一键卸载程序（跨平台，适配各种硬件）

设计目标：面向所有用户，无论其硬件是 NVIDIA / AMD(ROCm) / Apple Silicon / 纯 CPU，
脚本会先探测本机实际安装了哪些组件，再按需清理，不会误删不存在的依赖。

清理范围（按检测结果动态执行）：
  [1] 停进程        —— 后端(端口8765) + Ollama 服务
  [2] Python 依赖   —— 卸载运行脚本时所在环境的项目相关包（装到哪个环境就用哪个环境卸）
  [3] 安全工具      —— pip 工具(bandit/semgrep/pip-audit/detect-secrets) + 系统二进制(gitleaks/trivy)
  [4] Ollama 模型   —— 删除 ~/.ollama（含 OLLAMA_MODELS 指定目录）
  [5] Ollama 本体   —— Windows(winget/uninstaller) / macOS(brew/官方App) / Linux(apt/官方脚本)
  [6] 推理加速栈    —— NVIDIA CUDA / AMD ROCm（Linux 系统级 apt 包 + /opt/rocm，需 sudo）
  [7] 本地运行数据  —— data/chroma_db、outputs/、logs/、models/、__pycache__、egg-info、HF/torch 缓存
  [8] 编辑器插件    —— VS Code / IntelliJ 中已安装的本项目插件（尽力而为）
  [9] 项目文件夹    —— 删除整个 Graduation-Project/（自动切换工作目录后删除，Windows 可用）

安全机制：
  - 默认交互式确认，每一步列出将删除的内容与预估占用
  - --yes 一键全自动（CI/无人值守）
  - --dry-run 只打印将执行的动作，不实际删除
  - 删除前逐项 try/except，单项失败不中断整体
"""

from __future__ import annotations

import argparse
import glob
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ===========================================================================
# 常量
# ===========================================================================
PROJECT_DIR_HINT = "Graduation-Project"          # 项目文件夹名
BACKEND_PORTS = [8765]                            # 后端监听端口
# 本项目直接/间接依赖的顶层包名（pip uninstall 用）
PIP_PACKAGES = [
    "graduation-project",
    "sentence-transformers",
    "chromadb",
    "tree-sitter",
    "tree-sitter-python",
    "tree-sitter-javascript",
    "tree-sitter-java",
    "tree-sitter-php",
    "tree-sitter-typescript",
    "fastapi",
    "pydantic",
    "uvicorn",
    "python-multipart",
    "psutil",
    "requests",
    "torch",
    "torchvision",
]
# 常见间接依赖（可选清理，检测到才卸）
PIP_OPTIONAL = [
    "onnxruntime",
    "transformers",
    "peft",
    "accelerate",
    "bitsandbytes",
    "datasets",
    "tokenizers",
    "safetensors",
    "huggingface-hub",
    "numpy",
    "scipy",
    "scikit-learn",
    "pandas",
    "onnx",
    "ollama",
    # llamacpp 后端
    "llama-cpp-python",
    # 新框架（两阶段/外部扫描）pip 可安装的安全工具
    "bandit",
    "semgrep",
    "pip-audit",
    "detect-secrets",
    # Web 层 extras / 常见间接依赖（检测到才卸载）
    "uvloop",
    "httptools",
    "websockets",
    "watchfiles",
    "python-dotenv",
    "click",
    "h11",
    "starlette",
    "anyio",
    "pydantic-core",
    "annotated-types",
    "posthog",
    "tenacity",
    "pypika",
]
# 新框架（两阶段/外部扫描）经系统包管理器安装的二进制工具：
# 键=命令名，值=(winget 包ID, brew 包名, Linux 包名)。卸载时按平台探测后清理。
SECURITY_TOOLS_BIN = {
    "gitleaks": ("Gitleaks.Gitleaks", "gitleaks", "gitleaks"),
    "trivy": ("AquaSecurity.Trivy", "trivy", "trivy"),
}


class UI:
    """交互 / 日志工具。"""
    N = "\033[0m"; R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"

    def __init__(self, yes: bool, dry: bool):
        self.yes = yes
        self.dry = dry

    def _c(self, s, color):
        if sys.platform == "win32" or not sys.stdout.isatty():
            return s
        return f"{color}{s}{self.N}"

    def info(self, s): print(self._c(s, self.B))
    def ok(self, s):   print(self._c("  ✓ " + s, self.G))
    def warn(self, s): print(self._c("  ⚠ " + s, self.Y))
    def err(self, s):  print(self._c("  ✗ " + s, self.R))

    def confirm(self, what: str, size_hint: str = "") -> bool:
        """确认某项删除。返回 True=执行, False=跳过。"""
        if self.dry:
            print(f"  [模拟] 将删除: {what} {size_hint}")
            return False
        if self.yes:
            return True
        try:
            ans = input(f"  删除 {what} {size_hint}？[y/N]: ").strip().lower()
            return ans in ("y", "yes")
        except EOFError:
            return False


def run(cmd: list[str], timeout: int = 300, check: bool = False) -> subprocess.CompletedProcess:
    """执行命令，静默捕获输出。"""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            shell=(sys.platform == "win32"),
        )
    except Exception:
        return subprocess.CompletedProcess(cmd, -1, "", "")


def which(name: str) -> str | None:
    return shutil.which(name)


def dir_size_gb(path: Path) -> str:
    """估算目录占用（GB）。"""
    total = 0
    try:
        for p in path.rglob("*"):
            if p.is_file():
                total += p.stat().st_size
    except Exception:
        pass
    return f"(~{total / 1024**3:.1f} GB)" if total > 0 else ""


def _sudo_cmd(cmd: list[str]) -> list[str]:
    """Linux 下普通用户自动加 sudo；已是 root 或非 Linux 平台原样返回。"""
    if sys.platform.startswith("linux") and os.geteuid() != 0 and which("sudo"):
        return ["sudo"] + cmd
    return cmd


def _remove_paths(ui: UI, paths: list, sudo: bool = False) -> None:
    """逐个确认并删除路径（仅 POSIX），检查实际删除结果。"""
    for p in paths:
        p = Path(p)
        if not (p.exists() or p.is_symlink()):
            continue
        if ui.confirm(str(p), dir_size_gb(p)):
            r = run(_sudo_cmd(["rm", "-rf", str(p)]) if sudo else ["rm", "-rf", str(p)], timeout=120)
            if r.returncode == 0 and not (p.exists() or p.is_symlink()):
                ui.ok(f"已删除 {p}")
            else:
                ui.err(f"删除 {p} 失败（可能需要权限）")


# ===========================================================================
# 1. 停进程
# ===========================================================================
def stop_processes(ui: UI):
    ui.info("\n[1/9] 停止相关进程（后端 + Ollama）...")
    if ui.dry:
        ui.warn("模拟模式：跳过进程终止")
        return

    backend_procs = []
    for port in BACKEND_PORTS:
        if sys.platform == "win32":
            r = run(["netstat", "-ano"], timeout=10)
            for line in r.stdout.splitlines():
                if f":{port}" in line and "LISTENING" in line:
                    pid = line.split()[-1] if line.split() else None
                    if pid and pid.isdigit():
                        backend_procs.append(pid)
        else:
            r = run(["lsof", "-ti", f"tcp:{port}"], timeout=10)
            if r.returncode == 0 and r.stdout.strip():
                backend_procs += [p for p in r.stdout.split() if p.isdigit()]
            else:
                # lsof 未安装时用 fuser 兜底
                f = run(["fuser", "-k", f"{port}/tcp"], timeout=10)
                if f.returncode == 0:
                    ui.warn(f"已通过 fuser 结束端口 {port} 上的进程")

    for pid in set(backend_procs):
        ui.warn(f"停止后端进程 PID {pid}")
        if sys.platform == "win32":
            run(["taskkill", "/F", "/PID", pid])
        else:
            run(["kill", "-9", pid])
    if backend_procs:
        ui.ok(f"已停止 {len(set(backend_procs))} 个后端进程")
    else:
        ui.ok("未发现后端进程（端口未被占用）")

    if which("ollama"):
        ui.warn("停止 Ollama 服务")
        if sys.platform == "win32":
            run(["taskkill", "/F", "/IM", "ollama.exe"])
            run(["taskkill", "/F", "/IM", "ollama_runners.exe"])
        else:
            r = run(["pkill", "-9", "-x", "ollama"], timeout=10)
            if r.returncode != 0:
                run(["pkill", "-9", "-f", "ollama"], timeout=10)
        ui.ok("已停止 Ollama")
    else:
        ui.ok("未安装 Ollama，跳过")
    time.sleep(2)


# ===========================================================================
# 3. 卸载 Ollama 模型（~/.ollama）——先于本体，探测靠文件路径
# ===========================================================================
def remove_ollama_model(ui: UI):
    ui.info("\n[4/9] 删除 Ollama 拉取的模型...")
    candidates = ["~/.ollama"]
    env_models = os.environ.get("OLLAMA_MODELS")
    if env_models:
        p = Path(env_models).expanduser()
        if str(p) not in [str(Path(x).expanduser()) for x in candidates]:
            candidates.append(str(p))
    found = False
    for d in candidates:
        p = Path(d).expanduser()
        if p.exists():
            found = True
            if ui.confirm(f"Ollama 模型目录 {p}", dir_size_gb(p)):
                try:
                    shutil.rmtree(p, ignore_errors=True)
                    if p.exists():
                        ui.err(f"删除 {p} 失败（可能被占用或权限不足）")
                    else:
                        ui.ok(f"已删除 {p}")
                except Exception as e:
                    ui.err(f"删除 {p} 失败: {e}")
    if not found:
        ui.ok("未发现 Ollama 模型目录 (~/.ollama)，跳过")


# ===========================================================================
# 4. 卸载 Ollama 本体（平台自适应）
# ===========================================================================
def uninstall_ollama(ui: UI):
    ui.info("\n[5/9] 卸载 Ollama 本体...")
    if not which("ollama"):
        ui.ok("未检测到 ollama 命令，跳过")
        return
    if ui.dry:
        ui.warn("模拟模式：跳过 Ollama 卸载")
        return

    if sys.platform == "win32":
        # 尝试 winget 卸载，否则定位卸载器
        r = run(["winget", "uninstall", "--id", "Ollama.Ollama", "--silent",
                 "--accept-source-agreements", "--accept-package-agreements"],
                timeout=300)
        if r.returncode == 0:
            ui.ok("已通过 winget 卸载 Ollama")
        else:
            # 找 uninstall.exe
            uni = None
            for base in [Path.home() / "AppData/Local/Programs/Ollama",
                         Path("C:/Program Files/Ollama")]:
                cand = base / "unins000.exe"
                if cand.exists():
                    uni = cand
                    break
            if uni:
                ui.warn("运行 Ollama 卸载器（静默）")
                run([str(uni), "/SILENT", "/NORESTART"], timeout=300)
                ui.ok("已运行 Ollama 卸载器")
            else:
                ui.warn("未找到 Ollama 卸载器，请手动从「设置→应用」卸载")
        # 尽力清理残留目录与自启动任务
        for p in [Path.home() / "AppData/Local/Ollama",
                  Path.home() / "AppData/Roaming/Ollama"]:
            if p.exists() and ui.confirm(f"删除 Ollama 残留目录 {p}", dir_size_gb(p)):
                shutil.rmtree(p, ignore_errors=True)
                if not p.exists():
                    ui.ok(f"已删除 {p}")
                else:
                    ui.err(f"删除 {p} 失败（可能被占用）")
        run(["schtasks", "/Delete", "/TN", "Ollama", "/F"], timeout=30)

    elif sys.platform == "darwin":
        r = run(["brew", "uninstall", "ollama"])
        if r.returncode != 0:
            run(["brew", "uninstall", "--cask", "ollama"])
        # 无论 brew 是否成功，都清理官方 App / CLI / 用户数据
        _remove_paths(ui, [
            "/Applications/Ollama.app",
            "/usr/local/bin/ollama",
            "/opt/homebrew/bin/ollama",
            str(Path.home() / "Library/Application Support/Ollama"),
        ])
        for f in glob.glob(str(Path.home() / "Library/LaunchAgents/*ollama*.plist")) + \
                 glob.glob(str(Path.home() / "Library/Preferences/com.ollama*.plist")):
            _remove_paths(ui, [f])
        ui.ok("macOS 卸载处理完成（brew 失败时已尽力删除 App 与 CLI）")

    else:
        # Linux: 按发行版包管理器卸载；失败则手动删除官方脚本安装的文件
        pm_cmds = [
            (["apt-get", "purge", "-y", "ollama"], ["apt-get", "autoremove", "--purge", "-y"]),
            (["dnf", "remove", "-y", "ollama"], None),
            (["pacman", "-Rns", "--noconfirm", "ollama"], None),
            (["zypper", "remove", "-y", "ollama"], None),
            (["apk", "del", "ollama"], None),
        ]
        uninstalled = False
        for purge_cmd, clean_cmd in pm_cmds:
            if not which(purge_cmd[0]):
                continue
            r = run(_sudo_cmd(purge_cmd), timeout=300)
            if r.returncode == 0:
                ui.ok(f"已通过 {purge_cmd[0]} 卸载 Ollama")
                if clean_cmd:
                    run(_sudo_cmd(clean_cmd), timeout=300)
                uninstalled = True
                break
        if not uninstalled:
            ui.warn("包管理器卸载未成功（可能不是包管理器安装），尝试手动删除...")
            _remove_paths(ui, [
                "/usr/local/bin/ollama",
                "/usr/bin/ollama",
                "/usr/local/lib/ollama",
                "/usr/lib/ollama",
                "/usr/share/ollama",
            ], sudo=True)
            _remove_paths(ui, [
                str(Path.home() / ".local/bin/ollama"),
                str(Path.home() / ".local/share/ollama"),
            ], sudo=False)
        # 清理 systemd 服务
        for svc, is_user in [
            (Path("/etc/systemd/system/ollama.service"), False),
            (Path.home() / ".config/systemd/user/ollama.service", True),
        ]:
            if svc.exists() and ui.confirm(f"删除 {svc}"):
                if is_user:
                    run(["systemctl", "--user", "disable", "ollama"], timeout=30)
                    rc = run(["rm", "-rf", str(svc)], timeout=30)
                else:
                    run(_sudo_cmd(["systemctl", "disable", "ollama"]), timeout=30)
                    rc = run(_sudo_cmd(["rm", "-rf", str(svc)]), timeout=30)
                if rc.returncode == 0:
                    ui.ok(f"已删除 {svc}")
                else:
                    ui.err(f"删除 {svc} 失败")


# ===========================================================================
# 5. 卸载推理加速栈（NVIDIA CUDA / AMD ROCm）
# ===========================================================================
def uninstall_accel_stack(ui: UI):
    ui.info("\n[6/9] 卸载 GPU 推理加速栈（CUDA / ROCm / Apple）...")

    # 5a. Python 侧 torch 已在本脚本 [2] 卸载，这里处理系统级
    if sys.platform.startswith("linux"):
        # --- AMD ROCm ---
        rocm_dirs = [str(p) for p in Path("/opt").glob("rocm*")]
        for extra in ["/opt/rocm", "/opt/rocm-install"]:
            if Path(extra).exists() and extra not in rocm_dirs:
                rocm_dirs.append(extra)
        has_rocm = bool(rocm_dirs) or which("rocm-smi") or which("hipcc")
        if has_rocm:
            ui.warn("检测到 AMD ROCm 安装")
            if ui.confirm("卸载 ROCm 系统包（rocm 元包 + 运行时）(需要 sudo)"):
                _remove_paths(ui, rocm_dirs, sudo=True)
                # 移除 apt 源
                for f in ["/etc/apt/sources.list.d/rocm.list",
                          "/etc/apt/sources.list.d/amdgpu.list",
                          "/etc/apt/preferences.d/99-rocm",
                          "/etc/apt/keyrings/rocm.gpg"]:
                    if Path(f).exists():
                        if ui.confirm(f"删除 {f}"):
                            r = run(_sudo_cmd(["rm", "-f", f]), timeout=60)
                            if r.returncode == 0:
                                ui.ok(f"已删除 {f}")
                            else:
                                ui.err(f"删除 {f} 失败")
                if not which("apt-get"):
                    ui.warn("未检测到 apt-get（非 Debian/Ubuntu 系）：系统包请用 dnf/pacman/zypper 等手动清理")
                else:
                    r = run(_sudo_cmd(["apt-get", "purge", "-y", "rocm", "rocm-core",
                                       "rocm-hip-sdk", "rocm-smi", "rocm-libs",
                                       "amdgpu-dkms"]), timeout=300)
                    r2 = run(_sudo_cmd(["apt-get", "autoremove", "--purge", "-y"]), timeout=300)
                    if r.returncode == 0 and r2.returncode == 0:
                        ui.ok("已清理 ROCm 系统组件")
                    else:
                        ui.warn("ROCm 部分组件可能未完全卸载，建议检查包管理器输出")
            else:
                ui.warn("跳过 ROCm 系统组件卸载")
        else:
            ui.ok("未检测到 ROCm，跳过")

        # --- NVIDIA CUDA ---
        has_cuda = which("nvidia-smi") or which("nvcc") or which("nvidia-settings")
        if has_cuda:
            ui.warn("检测到 NVIDIA 驱动 / CUDA")
            if ui.confirm("卸载 NVIDIA 驱动与 CUDA 包 (需要 sudo；将移除显卡驱动)"):
                cuda_files = [str(p) for p in glob.glob("/etc/apt/sources.list.d/cuda*.list")] + \
                             [str(p) for p in glob.glob("/etc/apt/sources.list.d/nvidia-ml.list")]
                for f in cuda_files:
                    if ui.confirm(f"删除 {f}"):
                        r = run(_sudo_cmd(["rm", "-f", f]), timeout=60)
                        if r.returncode == 0:
                            ui.ok(f"已删除 {f}")
                        else:
                            ui.err(f"删除 {f} 失败")
                if not which("apt-get"):
                    ui.warn("未检测到 apt-get（非 Debian/Ubuntu 系）：驱动/CUDA 系统包请用 dnf/pacman/zypper 等手动清理")
                else:
                    # apt 支持 * 通配包名（不需要 shell 引号）
                    r = run(_sudo_cmd(["apt-get", "purge", "-y",
                                       "*cuda*", "*cudnn*", "*nvidia*",
                                       "nvidia-driver-*"]), timeout=600)
                    r2 = run(_sudo_cmd(["apt-get", "autoremove", "--purge", "-y"]), timeout=600)
                    if r.returncode == 0 and r2.returncode == 0:
                        ui.ok("已卸载 NVIDIA 驱动/CUDA 包")
                    else:
                        ui.warn("NVIDIA 部分包可能未完全卸载，建议检查包管理器输出")
            else:
                ui.warn("跳过 NVIDIA 驱动/CUDA 卸载")
        else:
            ui.ok("未检测到 NVIDIA CUDA，跳过")
    else:
        ui.ok("非 Linux 平台：CUDA/ROCm 系统级组件通常经 pip/安装器处理，跳过")


# ===========================================================================
# 2. 卸载 Python 依赖
# ===========================================================================
def uninstall_python_deps(ui: UI):
    ui.info("\n[2/9] 卸载 Python 依赖...")
    # 始终使用当前解释器的 pip，保证“在哪个环境装就在哪个环境卸”
    r = run([sys.executable, "-m", "pip", "--version"])
    if r.returncode != 0:
        ui.warn("当前 Python 环境没有可用的 pip（python -m pip），跳过 Python 依赖卸载")
        return

    # 先查已装哪些，只卸存在的
    installed = set()
    r = run([sys.executable, "-m", "pip", "list", "--format=freeze"])
    for line in r.stdout.splitlines():
        name = line.split("==")[0].strip().replace("_", "-").lower()
        installed.add(name)
    # 老版本 pip 对本地可编辑安装（pip install -e .）可能只输出 "-e file:///..."，
    # 这里用 pip show 兜底，确保本项目包本身能被识别并卸载
    r2 = run([sys.executable, "-m", "pip", "show", "graduation-project"], timeout=30)
    if r2.returncode == 0:
        installed.add("graduation-project")

    to_remove = []
    for pkg in PIP_PACKAGES + PIP_OPTIONAL:
        key = pkg.replace("_", "-").lower()
        if key in installed:
            to_remove.append(pkg)
    if not to_remove:
        ui.ok("当前环境未发现本项目相关 Python 包，跳过")
        return
    ui.warn(f"将卸载 {len(to_remove)} 个 Python 包: {', '.join(to_remove[:12])}...")
    if ui.dry:
        ui.warn("模拟模式：以上包不会实际卸载")
        return
    if ui.yes or ui.confirm(f"{len(to_remove)} 个 Python 包"):
        r = run([sys.executable, "-m", "pip", "uninstall", "-y"] + to_remove, timeout=600)
        if getattr(r, "returncode", -1) == 0:
            ui.ok("已卸载 Python 依赖")
        else:
            ui.warn("pip 卸载可能未完全成功，可手动执行 pip uninstall -y "
                    + " ".join(to_remove))


# ===========================================================================
# 3. 卸载安全工具（系统级二进制：gitleaks / trivy）
# ===========================================================================
def uninstall_security_tools(ui: UI):
    """卸载新框架经系统包管理器安装的二进制安全工具（gitleaks / trivy）。

    pip 可安装的安全工具（bandit/semgrep/pip-audit/detect-secrets）随 [2] Python
    依赖统一清理，本步骤只处理 winget / brew / apt 等系统级二进制工具。
    """
    ui.info("\n[3/9] 卸载系统级安全工具（gitleaks / trivy）...")
    if ui.dry:
        ui.warn("模拟模式：跳过系统级安全工具卸载")
        return

    removed_any = False
    for tool, (winget_id, brew_pkg, linux_pkg) in SECURITY_TOOLS_BIN.items():
        if not which(tool):
            ui.ok(f"未检测到 {tool}，跳过")
            continue
        if not ui.confirm(f"卸载安全工具 {tool}"):
            continue
        ok = False
        if sys.platform == "win32":
            if which("winget"):
                r = run(["winget", "uninstall", "--id", winget_id, "--silent",
                         "--accept-source-agreements", "--accept-package-agreements"],
                        timeout=300)
                ok = r.returncode == 0
            if not ok:
                ui.warn(f"winget 卸载 {tool} 未成功，请在「设置→应用」手动卸载")
        elif sys.platform == "darwin":
            if which("brew"):
                # trivy 是 brew cask，gitleaks 是 brew formula；先试 cask 再试 formula
                r = run(["brew", "uninstall", "--cask", brew_pkg], timeout=300)
                if r.returncode != 0:
                    r = run(["brew", "uninstall", brew_pkg], timeout=300)
                ok = r.returncode == 0
            if not ok:
                ui.warn(f"brew 卸载 {tool} 未成功，可手动清理")
        else:
            # Linux：按包管理器卸载
            pm_cmds = [
                ["apt-get", "remove", "-y", linux_pkg],
                ["dnf", "remove", "-y", linux_pkg],
                ["pacman", "-R", "--noconfirm", linux_pkg],
                ["zypper", "remove", "-y", linux_pkg],
            ]
            for pkg_cmd in pm_cmds:
                if not which(pkg_cmd[0]):
                    continue
                r = run(_sudo_cmd(pkg_cmd), timeout=300)
                if r.returncode == 0:
                    ok = True
                    break
            if not ok:
                ui.warn(f"包管理器卸载 {tool} 未成功，可手动清理")
        if ok:
            ui.ok(f"已卸载 {tool}")
            removed_any = True
    if not removed_any:
        # 上面每个工具都单独打印了状态，这里仅在确实卸载过时无需额外输出；
        # 若全部跳过，提示用户。
        remaining = [t for t in SECURITY_TOOLS_BIN if which(t)]
        if remaining:
            ui.warn(f"以下工具仍存在，请手动清理: {', '.join(remaining)}")


# ===========================================================================
# 6. 删除本地运行数据
# ===========================================================================
def remove_local_data(ui: UI, project_root: Path):
    ui.info("\n[7/9] 删除本地运行数据（向量库 / 模型产物 / 缓存 / 构建残留）...")
    targets: list[Path] = []
    if project_root.exists():
        # 项目内已知数据目录
        for rel in ["data/chroma_db", "outputs", "logs",
                    "models",   # 下载的 HF 基座 / GGUF / LoRA adapter
                    "experiments/exp_06_finetune/data",
                    "experiments/exp_06_finetune/outputs",
                    ".cache"]:
            p = project_root / rel
            if p.exists():
                targets.append(p)
        # 递归清理缓存 / 构建残留（真正的 rglob 实现）
        for pattern in ["__pycache__", "*.egg-info", ".pytest_cache",
                        ".mypy_cache", ".ruff_cache", "chroma_db", ".cache"]:
            for p in project_root.rglob(pattern):
                if p.is_dir() and p not in targets:
                    targets.append(p)
    # 用户级共享缓存（跨环境共享，README 已提示会同时影响其他项目）
    for p in ["~/.cache/huggingface", "~/.cache/chroma", "~/.cache/torch",
              "~/Library/Caches/huggingface", "~/Library/Caches/chroma",
              "~/Library/Caches/torch"]:
        pp = Path(p).expanduser()
        if pp.exists() and pp not in targets:
            targets.append(pp)
    # 注意：~/.ollama 由 [4/9] remove_ollama_model 负责，此处不重复处理

    if not targets:
        ui.ok("未发现本地运行数据，跳过")
        return
    for p in targets:
        if ui.confirm(str(p), dir_size_gb(p)):
            try:
                shutil.rmtree(p, ignore_errors=True)
                if p.exists():
                    ui.err(f"删除 {p} 失败（可能被占用或权限不足）")
                else:
                    ui.ok(f"已删除 {p}")
            except Exception as e:
                ui.err(f"删除 {p} 失败: {e}")


# ===========================================================================
# 7. 清理编辑器插件（安装位置在项目目录之外）
# ===========================================================================
def remove_editor_plugins(ui: UI):
    """尽力卸载已安装的 VS Code / IntelliJ 插件。"""
    ui.info("\n[8/9] 清理已安装的编辑器插件（VS Code / IntelliJ）...")
    if ui.dry:
        ui.warn("模拟模式：跳过编辑器插件清理")
        return

    # VS Code：优先用 code CLI 卸载（插件 ID: graduation-project.vuln-scanner）
    ext_id = "graduation-project.vuln-scanner"
    code_cli = None
    for c in ["code", "code-insiders", "codium", "cursor"]:
        if which(c):
            code_cli = c
            break
    if code_cli:
        if ui.confirm(f"通过 {code_cli} CLI 卸载 VS Code 扩展 {ext_id}"):
            r = run([code_cli, "--uninstall-extension", ext_id], timeout=120)
            if r.returncode == 0:
                ui.ok(f"已卸载 VS Code 扩展 {ext_id}")
            else:
                ui.warn("VS Code 扩展卸载命令未成功，可手动在扩展面板卸载")
    else:
        ui.ok("未检测到 code CLI，跳过 VS Code 扩展卸载（可在扩展面板手动卸载）")

    # IntelliJ：扫描各产品版本的 plugins 目录
    jetbrains_bases = []
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            jetbrains_bases.append(Path(appdata) / "JetBrains")
    elif sys.platform == "darwin":
        jetbrains_bases.append(Path.home() / "Library/Application Support/JetBrains")
    else:
        jetbrains_bases.append(Path.home() / ".local/share/JetBrains")
        jetbrains_bases.append(Path.home() / ".config/JetBrains")

    found = False
    for base in jetbrains_bases:
        if not base.exists():
            continue
        for product in base.iterdir():
            plugins = product / "plugins"
            if not plugins.is_dir():
                continue
            for cand in plugins.iterdir():
                name = cand.name.lower()
                if "vuln" in name and ("scanner" in name or "scan" in name):
                    found = True
                    if ui.confirm(f"删除 IntelliJ 插件 {cand}"):
                        try:
                            shutil.rmtree(cand, ignore_errors=True)
                            if cand.exists():
                                ui.err(f"删除 {cand} 失败")
                            else:
                                ui.ok(f"已删除 {cand}")
                        except Exception as e:
                            ui.err(f"删除 {cand} 失败: {e}")
    if not found:
        ui.ok("未发现已安装的 IntelliJ 插件，跳过")


# ===========================================================================
# 8. 删除项目文件夹
# ===========================================================================
def remove_project_folder(ui: UI, project_root: Path):
    ui.info("\n[9/9] 删除项目文件夹...")
    if not project_root.exists():
        ui.ok("项目文件夹不存在，跳过")
        return
    if ui.confirm(f"项目文件夹 {project_root}", dir_size_gb(project_root)):
        # Windows 不允许删除“当前进程的工作目录”，先切到临时目录再删
        tmp = Path(tempfile.mkdtemp(prefix="gp_uninstall_"))
        ok = False
        try:
            os.chdir(tmp)
            ok = _rmtree(project_root)
        except Exception as e:
            ui.err(f"删除项目文件夹异常: {e}")
        finally:
            try:
                os.chdir(tempfile.gettempdir())
            except Exception:
                pass
            shutil.rmtree(tmp, ignore_errors=True)
        if ok and not project_root.exists():
            ui.ok("项目文件夹已删除")
            ui.info("\n全部完成。相关依赖与项目已清理。")
        else:
            ui.err(f"项目文件夹删除失败，请手动删除: {project_root}")


def _rmtree(path: Path) -> bool:
    """跨平台递归删除，返回是否真正删除成功。"""
    if sys.platform == "win32":
        r = run(["cmd", "/c", "rmdir", "/s", "/q", str(path)], timeout=300)
    else:
        r = run(["rm", "-rf", str(path)], timeout=300)
    return r.returncode == 0 and not Path(path).exists()


def _fix_console_encoding():
    """中文 Windows（GBK 控制台）下保证 ✓/⚠ 等符号可正常输出。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main():
    _fix_console_encoding()
    ap = argparse.ArgumentParser(description="AI 漏洞扫描器一键卸载程序")
    ap.add_argument("--yes", action="store_true", help="全自动，跳过所有确认")
    ap.add_argument("--dry-run", action="store_true", help="只打印将执行的动作，不删除")
    ap.add_argument("--keep-project", action="store_true", help="保留项目文件夹")
    ap.add_argument("--keep-ollama", action="store_true", help="保留 Ollama 本体与模型")
    ap.add_argument("--keep-accel", action="store_true", help="保留 CUDA/ROCm 系统组件")
    ap.add_argument("--stage2", help="内部参数：删除项目文件夹阶段")
    ap.add_argument("--project", default=None, help="项目根目录（默认自动探测）")
    args = ap.parse_args()

    ui = UI(yes=args.yes, dry=args.dry_run)

    # 定位项目根
    if args.stage2:
        project_root = Path(args.stage2).resolve()
        ui.info(f"[stage2] 删除项目文件夹: {project_root}")
        if not args.keep_project:
            remove_project_folder(ui, project_root)
        return
    elif args.project:
        project_root = Path(args.project).resolve()
    else:
        # 自动探测：向上找 Graduation-Project
        cand = Path(__file__).resolve()
        project_root = None
        for p in [cand, cand.parent, cand.parent.parent, cand.parent.parent.parent,
                  cand.parent.parent.parent.parent]:
            if p.name == PROJECT_DIR_HINT:
                project_root = p
                break
        if project_root is None:
            # 最后手段：当前目录
            project_root = Path.cwd()

    print("=" * 60)
    print("  AI 漏洞扫描器 —— 一键卸载")
    print("  硬件自适应：探测到才清理，未安装的组件自动跳过")
    print("=" * 60)
    print(f"  目标项目: {project_root}")
    print(f"  模式: {'模拟(dry-run)' if args.dry_run else '全自动(--yes)' if args.yes else '交互确认'}")

    # 按顺序清理（编号与各函数内部 [n/9] 一致）
    stop_processes(ui)                # [1/9]
    uninstall_python_deps(ui)         # [2/9]
    uninstall_security_tools(ui)      # [3/9]
    if args.keep_ollama:
        ui.info("[4/9] 已按 --keep-ollama 保留 Ollama 本体与模型")
    else:
        # 先删模型（探测基于 ~/.ollama 文件路径，不依赖 ollama 二进制），再卸本体
        remove_ollama_model(ui)       # [4/9]
        uninstall_ollama(ui)          # [5/9]
    if args.keep_accel:
        ui.info("[6/9] 已按 --keep-accel 保留 CUDA/ROCm 系统组件")
    else:
        uninstall_accel_stack(ui)     # [6/9]
    remove_local_data(ui, project_root)  # [7/9]
    remove_editor_plugins(ui)         # [8/9]
    if args.keep_project:
        ui.info("[9/9] 已按 --keep-project 保留项目文件夹")
    else:
        remove_project_folder(ui, project_root)  # [9/9]


if __name__ == "__main__":
    main()
