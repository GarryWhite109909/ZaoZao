#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""llama-cpp-python 自动编译脚本（跨平台 GPU 版）。

背景
----
llama-cpp-python 在 PyPI 上的预编译 wheel 是 CPU-only。直接 pip install 时，
pip 会用现成 wheel 而**忽略** CMAKE_ARGS，导致 GPU offload 静默失效（装了却没吃到显卡）。
本脚本强制从源码编译，并按 OS/GPU 生成正确的 CMAKE_ARGS：

    NVIDIA        -DGGML_CUDA=on（兼容旧参数 -DLLAMA_CUDA=on；需 CUDA Toolkit(nvcc) + C++ 编译器）
    AMD + Linux   -DGGML_HIP=ON       （需 /opt/rocm 的 hipcc + rocm-cmake）
    AMD + Windows -DGGML_HIP=ON       （ROCm-On-Windows，较折腾，尽力而为）
    Apple Silicon -DGGML_METAL=on（兼容旧参数 -DLLAMA_METAL=on；clang 自带 Metal，最省事）
    CPU           （直接装预编译 wheel，无需编译）

注意：Windows 源码编译会解压超长路径文件，必须开启 Windows 长路径支持
（LongPathsEnabled=1），否则报 "No such file or directory"。

用法
----
    python -m app.launcher.install_llamacpp_gpu --dry-run   # 只打印编译计划，不执行
    python -m app.launcher.install_llamacpp_gpu             # 自动编译安装
    python -m app.launcher.install_llamacpp_gpu --verify    # 只校验 GPU offload 是否生效
    python -m app.launcher.install_llamacpp_gpu --python /path/to/python

设计原则
--------
- 复用 dependency_installer 的底层检测（detect_platform / detect_gpu），保证与
  启动器的平台判断口径完全一致。
- 编译工具链（cmake/编译器）缺失时按平台自动安装（winget / brew / apt/dnf/pacman），
  尽力而为；nvcc / hipcc 这类大型 SDK 无法一键装，缺失时明确告警并给出指引。
- 编译后二次校验 llama_supports_gpu_offload()，确保 GPU 真的可用。
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

# Windows 默认 GBK 控制台：任何会 print 非 GBK 字符的脚本必须重新配置 stdout/stderr
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 复用启动器的平台/GPU 检测，保证口径一致
from app.launcher.dependency_installer import detect_gpu, detect_platform


# ---------------------------------------------------------------------------
# 编译计划
# ---------------------------------------------------------------------------

def build_plan() -> Dict:
    """根据当前 OS + GPU 生成 llama-cpp-python 编译计划。

    Returns key:
        backend:      "nvidia" / "amd" / "apple" / "cpu"
        needs_build:  bool，是否需要从源码编译（GPU 才需要；CPU 装 wheel 即可）
        cmake_args:   str，源码编译时注入的 CMAKE_ARGS（CPU 为空）
        label:        str，人类可读描述
        warnings:     list[str]，编译前置条件缺失的提示
    """
    platform_info = detect_platform()
    gpu = detect_gpu(platform_info)

    plan: Dict = {
        "backend": "cpu",
        "needs_build": False,
        "cmake_args": "",
        "label": "CPU",
        "warnings": [],
        "platform": platform_info,
        "gpu": gpu,
    }

    vendor = gpu.vendor
    if vendor == "nvidia":
        plan.update(backend="nvidia", needs_build=True,
                    cmake_args="-DGGML_CUDA=on -DLLAMA_CUDA=on",
                    label=f"CUDA ({gpu.name})")
    elif vendor == "apple":
        plan.update(backend="apple", needs_build=True,
                    cmake_args="-DGGML_METAL=on -DLLAMA_METAL=on",
                    label=f"Metal ({gpu.name})")
    elif vendor == "amd":
        # AMD 全程走 HIP；Linux 是官方支持，Windows/macOS 是尽力而为
        plan.update(backend="amd", needs_build=True,
                    cmake_args="-DGGML_HIP=ON",
                    label=f"ROCm/HIP ({gpu.name})")
        if platform_info.os_name in ("windows", "darwin"):
            plan["warnings"].append(
                "AMD 在 Windows/macOS 上的 ROCm 支持有限，HIP 编译可能失败；"
                "失败时请改用 transformers 或 ollama 后端。"
            )
    else:
        plan["label"] = "CPU（无 GPU 或未检测到，安装预编译 wheel）"

    # ---- 编译前置条件探测 ----
    if plan["needs_build"]:
        _probe_build_toolchain(plan)

    return plan


def _probe_build_toolchain(plan: Dict) -> None:
    """探测编译所需工具链，缺失时写入 warnings（能自动装的在 ensure 阶段处理）。"""
    platform_info = plan["platform"]
    backend = plan["backend"]

    # cmake：各平台通用，缺失时 ensure 阶段安装
    if not shutil.which("cmake"):
        plan["warnings"].append("未找到 cmake，脚本将尝试自动安装（见 ensure 阶段）。")

    # C++ 编译器
    if platform_info.os_name == "windows":
        if not (shutil.which("cl") or shutil.which("g++")):
            plan["warnings"].append(
                "未检测到 MSVC(cl) 或 MinGW(g++)，CUDA/HIP 编译需要 C++ 编译器；"
                "请安装 Visual Studio Build Tools 或 MinGW。"
            )
    elif platform_info.os_name == "darwin":
        if not shutil.which("clang"):
            plan["warnings"].append("未找到 clang（macOS 应自带，需安装命令行工具）。")
    else:  # linux
        if not (shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")):
            plan["warnings"].append("未找到 C 编译器（gcc/clang），脚本将尝试自动安装。")

    # 厂商 SDK
    if backend == "nvidia" and not shutil.which("nvcc"):
        plan["warnings"].append(
            "未找到 nvcc（CUDA Toolkit）。llama.cpp CUDA 编译需要 nvcc；"
            "请安装 CUDA Toolkit 后重试（https://developer.nvidia.com/cuda-downloads）。"
        )
    if backend == "amd":
        rocm_hipcc = shutil.which("hipcc") or (
            Path("/opt/rocm/bin/hipcc").is_file()
        )
        if not rocm_hipcc:
            plan["warnings"].append(
                "未找到 hipcc（ROCm）。llama.cpp HIP 编译需要 ROCm 工具链；"
                "请安装 ROCm 后重试（Linux 推荐 apt 装 rocm-cmake rocm-hip-sdk）。"
            )


# ---------------------------------------------------------------------------
# 编译工具链安装（尽力而为）
# ---------------------------------------------------------------------------

def _run(cmd, dry_run: bool, env: Optional[Dict] = None, timeout: int = 3600) -> None:
    """执行命令并打印结果；dry_run 时只打印。"""
    print(f"  $ {' '.join(cmd)}")
    if dry_run:
        return
    e = os.environ.copy()
    if env:
        e.update(env)
    try:
        r = subprocess.run(cmd, env=e, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        print("    ❌ 超时")
        return
    except Exception as ex:
        print(f"    ❌ 异常: {ex}")
        return
    if r.returncode != 0:
        print(f"    ⚠ 退出码 {r.returncode}")
    else:
        print("    ✅ 完成")


def ensure_build_toolchain(plan: Dict, dry_run: bool) -> None:
    """按平台安装缺失的 cmake / 编译器（尽力而为，失败不阻断）。"""
    platform_info = plan["platform"]
    if not plan["needs_build"]:
        return

    print("\n[编译工具链] 检查并补齐 cmake / 编译器 ...")

    # cmake
    if not shutil.which("cmake"):
        print(f"\n[cmake] 缺失，尝试安装 ...")
        if platform_info.os_name == "windows":
            if shutil.which("winget"):
                _run(["winget", "install", "Kitware.CMake", "--silent",
                      "--accept-source-agreements", "--accept-package-agreements",
                      "--disable-interactivity"], dry_run)
            elif shutil.which("choco"):
                _run(["choco", "install", "cmake", "-y"], dry_run)
            else:
                print("  ⚠ 未找到 winget/choco，请手动安装 cmake")
        elif platform_info.os_name == "darwin":
            if shutil.which("brew"):
                _run(["brew", "install", "cmake"], dry_run)
            else:
                print("  ⚠ 未找到 brew，请手动安装 cmake")
        else:  # linux
            for pm in (["apt-get", "install", "-y", "cmake", "gcc", "g++"],
                       ["dnf", "install", "-y", "cmake", "gcc", "g++"],
                       ["pacman", "-S", "--noconfirm", "cmake", "gcc"]):
                if shutil.which(pm[0]):
                    _run([pm[0]] + pm[1:], dry_run)
                    break
            else:
                print("  ⚠ 未找到 apt/dnf/pacman，请手动安装 cmake + gcc")

    # AMD Linux 缺 rocm 头文件时提示（不自动装，太大）
    if plan["backend"] == "amd" and platform_info.os_name == "linux":
        if not (shutil.which("hipcc") or Path("/opt/rocm/bin/hipcc").is_file()):
            print("\n[ROCm] 缺少 hipcc，请手动安装（示例）：")
            print("    sudo apt-get install rocm-cmake rocm-hip-sdk rocm-dev")
            print("    或设置 HIPCC 环境变量指向你的 hipcc。")


# ---------------------------------------------------------------------------
# 源码编译安装
# ---------------------------------------------------------------------------

def compile_install(plan: Dict, python_executable: str, dry_run: bool) -> bool:
    """强制从源码编译并安装 llama-cpp-python。

    --no-binary llama-cpp-python 强制走 sdist 源码编译，CMAKE_ARGS 才会真正生效；
    --force-reinstall 覆盖可能的 CPU wheel 缓存；FORCE_CMAKE=1 让 llama.cpp 一定重新 cmake。
    """
    if not plan["needs_build"]:
        # CPU：直接装官方预编译 wheel，无需编译
        print("\n[安装] CPU 平台，直接安装官方预编译 wheel ...")
        cmd = [python_executable, "-m", "pip", "install", "--upgrade",
               "--no-cache-dir", "llama-cpp-python"]
        print(f"  $ {' '.join(cmd)}")
        if not dry_run:
            _run(cmd, dry_run)
            return _is_gpu_supported()
        return True

    print(f"\n[安装] 从源码编译 llama-cpp-python（{plan['label']}）...")
    print(f"  CMAKE_ARGS = {plan['cmake_args']}")

    env = {"CMAKE_ARGS": plan["cmake_args"], "FORCE_CMAKE": "1"}
    cmd = [python_executable, "-m", "pip", "install", "--upgrade",
           "--no-cache-dir",
           "--no-binary", "llama-cpp-python",
           "--force-reinstall",
           "llama-cpp-python"]
    print(f"  $ {' '.join(cmd)}")

    if dry_run:
        return True

    e = os.environ.copy()
    e.update(env)
    try:
        r = subprocess.run(cmd, env=e, text=True, encoding="utf-8",
                           errors="replace", timeout=3600)
    except subprocess.TimeoutExpired:
        print("    ❌ 编译超时（60 分钟）")
        return False
    except Exception as ex:
        print(f"    ❌ 编译异常: {ex}")
        return False

    if r.returncode != 0:
        print("    ❌ 编译安装失败（见上方日志尾部）。")
        print("       常见原因与解决：")
        print("       - 缺 nvcc/hipcc  → 见前置警告，装对应 SDK")
        print("       - 缺 C++ 编译器  → Windows 装 VS Build Tools/MinGW，Linux 装 gcc")
        print("       - Windows AMD    → ROCm 支持差，建议改用 transformers/ollama")
        return False
    print("    ✅ 编译安装完成")
    return _is_gpu_supported()


def _is_gpu_supported() -> bool:
    """校验当前已装的 llama_cpp 是否支持 GPU offload。"""
    try:
        import llama_cpp
    except Exception:
        print("    ⚠ 无法 import llama_cpp，校验失败")
        return False
    try:
        ok = bool(llama_cpp.llama_supports_gpu_offload())
    except Exception:
        ok = False
    if ok:
        print("    ✅ GPU offload 可用（llama_supports_gpu_offload() = True）")
    else:
        print("    ⚠ 当前 llama_cpp 编译为 CPU-only，GPU offload 不可用")
    return ok


def verify(plan: Dict) -> bool:
    """校验已安装的 llama_cpp 是否支持 GPU（供 --verify 单独使用）。"""
    print("\n[校验] llama-cpp-python GPU offload ...")
    ok = _is_gpu_supported()
    if not ok:
        print("  GPU offload 不可用。若你是 GPU 机器，请重新运行本脚本编译安装：")
        print("    python -m app.launcher.install_llamacpp_gpu")
    return ok


# ---------------------------------------------------------------------------
# 打印计划
# ---------------------------------------------------------------------------

def print_plan(plan: Dict) -> None:
    print("=" * 66)
    print("[llama-cpp-python 自动编译计划]")
    print(f"  平台        : {plan['platform'].os_name}/{plan['platform'].arch}")
    print(f"  GPU         : {plan['gpu'].vendor or '无'} {plan['gpu'].name or ''}")
    print(f"  后端        : {plan['label']}")
    print(f"  需要源码编译 : {'是（CMAKE_ARGS=' + plan['cmake_args'] + '）' if plan['needs_build'] else '否（装预编译 wheel）'}")
    if plan["warnings"]:
        print("  前置提示    :")
        for w in plan["warnings"]:
            print(f"    ⚠ {w}")
    print("=" * 66)


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="llama-cpp-python 跨平台自动编译（GPU）")
    parser.add_argument("--dry-run", action="store_true", help="只打印编译计划与命令，不执行")
    parser.add_argument("--verify", action="store_true", help="只校验已装 llama_cpp 是否支持 GPU，不安装")
    parser.add_argument("--python", default=sys.executable, help="目标 Python 解释器（默认当前）")
    args = parser.parse_args()

    plan = build_plan()
    print_plan(plan)

    if args.verify:
        return 0 if verify(plan) else 1

    # CPU 平台无需编译，但若指定 --verify 之外仍走安装
    ensure_build_toolchain(plan, args.dry_run)

    ok = compile_install(plan, args.python, args.dry_run)

    if args.dry_run:
        print("\n[dry-run] 以上为将要执行的操作，未真正安装。")
        return 0

    if ok:
        print("\n✅ llama-cpp-python GPU 就绪。")
        print("   在启动器里启用：VULN_SCANNER_BACKEND=llamacpp")
        return 0
    print("\n❌ GPU 编译/校验未通过。可回退：VULN_SCANNER_BACKEND=transformers 或 ollama")
    return 1


if __name__ == "__main__":
    sys.exit(main())
