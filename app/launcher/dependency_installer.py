"""
跨平台推理后端依赖自动安装器。

职责：
    1. 检测操作系统、CPU 架构、GPU 厂商（NVIDIA / AMD / Apple Silicon / CPU）。
    2. 根据所选推理后端（transformers / llamacpp）和硬件组合，生成正确的 pip 安装命令。
    3. 检查依赖是否已安装；缺失时自动下载安装（支持 dry-run、超时、进度回调）。
    4. 对预览/慢速组合（如 ROCm / Apple Silicon / CPU-only + bitsandbytes）给出明确警告。

使用方式（由 bootstrap.py 调用）：
    from app.launcher.dependency_installer import install_backend_dependencies
    ok = install_backend_dependencies("transformers", dry_run=False)

环境变量：
    VULN_SCANNER_AUTO_INSTALL_DEPS
        0 — 禁用自动安装（仅检测并打印手动命令）
        1 — 强制自动安装（即使依赖已存在也重新检查/升级）
        未设置 — 缺省时对缺失依赖自动安装
    VULN_SCANNER_PIP_INDEX
        覆盖 pip 镜像源，例如 https://pypi.tuna.tsinghua.edu.cn/simple
    VULN_SCANNER_TORCH_INDEX
        覆盖 PyTorch 专用 index-url（高级用户）
    VULN_SCANNER_PIP_TIMEOUT
        整条 pip install 的墙钟上限（秒），0=不限制；默认 7200（2 小时）。
        网络慢、torch 这类大 wheel 下载慢时建议调大或设 0。
    VULN_SCANNER_PIP_SOCKET_TIMEOUT
        pip 单次网络请求超时（秒），默认 60；网络差时 pip 会重试而不是直接失败。
    VULN_SCANNER_PIP_RETRIES
        pip 请求重试次数，默认 5。
    VULN_SCANNER_PIP_PROGRESS
        pip 进度条模式（on/off/raw），默认 raw（管道输出下仍显示进度）。
    VULN_SCANNER_FORCE_GPU_TORCH
        设为 1 时，即使显存不足也强制安装 CUDA/ROCm 版 torch（高级用户，可能 OOM）。
"""

from __future__ import annotations

import os
import re
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional
from urllib.parse import urlparse
from urllib.request import ProxyHandler, build_opener, urlopen

# Windows 默认 GBK 控制台：任何会 print 非 GBK 字符的脚本必须重新配置 stdout/stderr
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# pip 安装的网络韧性参数（详见模块 docstring）
PIP_TOTAL_TIMEOUT = int(os.environ.get("VULN_SCANNER_PIP_TIMEOUT", "7200"))
PIP_SOCKET_TIMEOUT = int(os.environ.get("VULN_SCANNER_PIP_SOCKET_TIMEOUT", "60"))
PIP_RETRIES = int(os.environ.get("VULN_SCANNER_PIP_RETRIES", "5"))
PIP_PROGRESS_BAR = os.environ.get("VULN_SCANNER_PIP_PROGRESS", "raw").strip().lower()
# 8B NF4 基座约 4.7GB + KV/激活，低于 6GB 显存装不下，transformers 应走 CPU
TORCH_GPU_VRAM_MIN_MB = 6144


def _force_gpu_torch() -> bool:
    """高级用户强制在低显存机器上安装 GPU 版 torch。"""
    return os.environ.get("VULN_SCANNER_FORCE_GPU_TORCH", "").strip() == "1"


def _low_vram_cpu_mode(gpu: GPUInfo) -> bool:
    """显存不足时 transformers 后端应使用 CPU torch（避免误卸 CPU 版）。"""
    return (
        gpu.vendor in ("nvidia", "amd")
        and gpu.vram_mb is not None
        and gpu.vram_mb < TORCH_GPU_VRAM_MIN_MB
        and not _force_gpu_torch()
    )


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class PlatformInfo:
    """操作系统与架构信息。"""

    os_name: str  # windows / linux / darwin
    arch: str     # amd64 / arm64 / x86 / etc.
    is_64bit: bool


@dataclass
class GPUInfo:
    """GPU 信息。"""

    vendor: Optional[str]  # nvidia / amd / apple / None
    name: Optional[str]
    vram_mb: Optional[int]


@dataclass
class InstallSpec:
    """一条 pip 安装指令。"""

    description: str
    packages: List[str]
    index_url: Optional[str] = None
    extra_index_url: Optional[str] = None
    env: dict = field(default_factory=dict)
    required: bool = True
    warning: Optional[str] = None
    # 安装成功后需要能 import 的模块名（用于二次校验）
    check_modules: List[str] = field(default_factory=list)
    # 额外的 pip 参数（如 --no-binary xx，用于强制源码编译）
    pip_extra_args: List[str] = field(default_factory=list)
    # 当前平台/硬件组合不支持该后端时置为 True，安装前直接拦截并给出指引
    blocked: bool = False
    blocked_message: str = ""
    # 安装后校验版本号必须包含的标记（如 CUDA 预编译 wheel 的 "+cu125"/"cu125"），
    # 用于防止 pip 静默回退到 CPU wheel
    version_marker: Optional[str] = None
    # 安装后运行 GPU 能力探测代码（目标解释器执行，stdout 输出 TRUE/FALSE）。
    # 用于验证预编译 GPU wheel 真的带 GPU 后端，而不是仅能 import
    gpu_probe: Optional[str] = None
    # 已安装的依赖与目标版本/构建不匹配时，先卸载再安装（同版本 CPU→GPU 替换
    # 必须卸载，否则 pip 认为已满足而不覆盖）
    cleanup_on_mismatch: bool = True
    # 为 True 时，--index-url 强制使用 spec.index_url，忽略 VULN_SCANNER_PIP_INDEX。
    # 用于 llama-cpp-python 的 CUDA/Metal 预编译 wheel：这类 wheel 必须从 abetlen 官方
    # 索引取，若被全局镜像覆盖会静默回退到 PyPI 的 CPU wheel，导致 GPU offload 失效。
    prefer_index_url: bool = False
    # llama-cpp-python 预编译 wheel 实际托管在 GitHub Releases（abetlen 索引只有链接）。
    # 国内直连 GitHub 大文件极易被掐断（ConnectionResetError 10054）。设置此项后，
    # 安装前先经 ghproxy 镜像把该 wheel 下载到本地，再用本地文件安装，绕开 GitHub 直连。
    mirror_wheel_url: Optional[str] = None


# ---------------------------------------------------------------------------
# 平台 / 硬件检测
# ---------------------------------------------------------------------------

def detect_platform() -> PlatformInfo:
    """检测操作系统与架构。"""
    system = platform.system().lower()
    if system == "windows":
        os_name = "windows"
    elif system == "linux":
        os_name = "linux"
    elif system == "darwin":
        os_name = "darwin"
    else:
        os_name = system

    machine = platform.machine().lower()
    # 统一常见架构名
    if machine in ("amd64", "x86_64", "x64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        arch = machine

    return PlatformInfo(os_name=os_name, arch=arch, is_64bit=platform.architecture()[0] == "64bit")


def _run_quiet(cmd: List[str], timeout: float = 5.0) -> tuple[int, str]:
    """运行命令并返回 (returncode, stdout)。忽略异常。"""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return result.returncode, result.stdout
    except Exception:
        return -1, ""


def _detect_nvidia() -> tuple[Optional[str], Optional[int]]:
    """优先 nvidia-smi，再尝试 torch.cuda。"""
    try:
        code, out = _run_quiet(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
            timeout=5.0,
        )
        if code == 0 and out.strip():
            line = out.strip().splitlines()[0]
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2 and parts[0]:
                name = parts[0]
                try:
                    vram = int(parts[1])
                except ValueError:
                    vram = None
                return name, vram
    except Exception:
        pass

    try:
        import torch  # type: ignore
        # ROCm 版 torch 也会让 torch.cuda.is_available() 返回 True（复用 CUDA 命名空间），
        # 但那是 AMD GPU 而非 NVIDIA。必须排除 hip 构建，否则 AMD+ROCm 会被误判成 NVIDIA
        # 而错误地要求安装 CUDA 版 torch。
        if torch.version.hip:
            # ROCm 构建：不是 NVIDIA
            return None, None
        if torch.cuda.is_available():
            name = torch.cuda.get_device_name(0)
            props = torch.cuda.get_device_properties(0)
            vram = int(props.total_memory // 1024 // 1024)
            return name, vram
    except Exception:
        pass
    return None, None


def _detect_amd_windows() -> tuple[Optional[str], Optional[int]]:
    try:
        code, out = _run_quiet(
            ["wmic", "path", "win32_VideoController", "get", "Name,AdapterRAM", "/format:csv"],
            timeout=5.0,
        )
        if code == 0 and out.strip():
            for line in out.strip().splitlines()[1:]:
                if "AMD" in line or "Radeon" in line:
                    parts = line.split(",")
                    if len(parts) >= 3:
                        name = parts[-2].strip().strip('"')
                        try:
                            vram = int(parts[-1].strip().strip('"')) // 1024 // 1024
                        except ValueError:
                            vram = None
                        return name, vram
    except Exception:
        pass
    return None, None


def _detect_amd_linux() -> tuple[Optional[str], Optional[int]]:
    # 1) rocm-smi
    try:
        code, out = _run_quiet(["rocm-smi", "--showproductname"], timeout=5.0)
        if code == 0 and out.strip():
            name = None
            for line in out.strip().splitlines():
                line = line.strip()
                if "Card Series" in line:
                    parts = line.split(":", 2)
                    if len(parts) >= 3 and parts[2].strip():
                        name = parts[2].strip()
                        break
            vram = None
            if name:
                try:
                    _, mem_out = _run_quiet(["rocm-smi", "--showmeminfo", "vram"], timeout=5.0)
                    if mem_out:
                        for line in mem_out.strip().splitlines():
                            if "Total Memory" in line:
                                parts = line.split(":", 2)
                                if len(parts) >= 3:
                                    vram = int(parts[2].strip()) // 1024 // 1024
                                break
                except Exception:
                    pass
            return name, vram
    except Exception:
        pass

    # 2) sysfs kfd
    try:
        kfd_nodes = Path("/sys/class/kfd/kfd/topology/nodes")
        if kfd_nodes.is_dir():
            for node_dir in sorted(kfd_nodes.iterdir()):
                props_path = node_dir / "properties"
                if not props_path.is_file():
                    continue
                props = props_path.read_text(encoding="utf-8", errors="ignore")
                if "vendor_id 0x1002" in props or "vendor_id 4098" in props:
                    vram = None
                    mem_props_path = node_dir / "mem_banks" / "0" / "properties"
                    if mem_props_path.is_file():
                        try:
                            mem_props = mem_props_path.read_text(encoding="utf-8", errors="ignore")
                            for p in mem_props.splitlines():
                                if p.startswith("size_in_bytes "):
                                    vram = int(p.split(" ", 1)[1].strip()) // 1024 // 1024
                                    break
                        except Exception:
                            pass
                    return "AMD GPU", vram
    except Exception:
        pass

    # 3) lspci fallback
    try:
        code, out = _run_quiet(["lspci", "-nn"], timeout=5.0)
        if code == 0 and out.strip():
            for line in out.strip().splitlines():
                if "VGA" in line and ("AMD" in line or "Radeon" in line or "ATI" in line):
                    desc = line.split(":", 2)[-1].strip()
                    desc = desc.split(" [1002:")[0].strip()
                    return desc, None
    except Exception:
        pass
    return None, None


def _detect_amd(platform_info: PlatformInfo) -> tuple[Optional[str], Optional[int]]:
    if platform_info.os_name == "windows":
        return _detect_amd_windows()
    if platform_info.os_name == "linux":
        return _detect_amd_linux()
    return None, None


def _detect_apple() -> Optional[str]:
    try:
        code, out = _run_quiet(["sysctl", "-n", "machdep.cpu.brand_string"], timeout=3.0)
        if code == 0 and out.strip():
            brand = out.strip()
            if "Apple M" in brand:
                return brand
    except Exception:
        pass
    return None


def detect_gpu(platform_info: Optional[PlatformInfo] = None) -> GPUInfo:
    """检测 GPU 厂商与显存。"""
    if platform_info is None:
        platform_info = detect_platform()

    # NVIDIA
    nvidia_name, nvidia_vram = _detect_nvidia()
    if nvidia_name:
        return GPUInfo(vendor="nvidia", name=nvidia_name, vram_mb=nvidia_vram)

    # Apple Silicon
    if platform_info.os_name == "darwin":
        apple_name = _detect_apple()
        if apple_name:
            return GPUInfo(vendor="apple", name=apple_name, vram_mb=None)

    # AMD
    amd_name, amd_vram = _detect_amd(platform_info)
    if amd_name:
        return GPUInfo(vendor="amd", name=amd_name, vram_mb=amd_vram)

    return GPUInfo(vendor=None, name=None, vram_mb=None)


@dataclass
class GPUFamilyInfo:
    """GPU 系别（用于选择匹配的 torch/bitsandbytes 构建）。"""

    family: str      # nvidia_50 / nvidia_40 / ... / amd_rdna4 / ... / unknown
    label: str       # 用户可读描述


def _query_nvidia_compute_cap() -> Optional[str]:
    """查询 NVIDIA 显卡 compute capability（如 '12.0' / '8.9'）。"""
    try:
        code, out = _run_quiet(
            ["nvidia-smi", "--query-gpu=compute_cap", "--format=csv,noheader,nounits"],
            timeout=5.0,
        )
        if code == 0 and out.strip():
            return out.strip().splitlines()[0].strip()
    except Exception:
        pass
    return None


def classify_gpu(gpu: GPUInfo) -> GPUFamilyInfo:
    """把 GPU 归入系别，决定装哪个 torch 构建。

    NVIDIA 优先用 compute capability（nvidia-smi 查询），失败时按型号名推断；
    AMD 按 Radeon 型号前缀推断 RDNA 代数（决定 ROCm 版本）。
    """
    if gpu.vendor == "nvidia":
        cap = _query_nvidia_compute_cap()
        if cap:
            major = cap.split(".", 1)[0]
            if major == "12":
                return GPUFamilyInfo("nvidia_50", "NVIDIA RTX 50 系（Blackwell, sm_120）")
            if major == "9":
                return GPUFamilyInfo("nvidia_dc", "NVIDIA 数据中心卡（Hopper/Blackwell, sm_90+）")
            if cap.startswith("8.9"):
                return GPUFamilyInfo("nvidia_40", "NVIDIA RTX 40 系（Ada, sm_89）")
            if cap.startswith(("8.6", "8.0")):
                return GPUFamilyInfo("nvidia_30", "NVIDIA RTX 30 系（Ampere, sm_86/80）")
            if cap.startswith("7.5"):
                return GPUFamilyInfo("nvidia_20", "NVIDIA RTX 20 / GTX 16 系（Turing, sm_75）")
            if cap.startswith(("6.1", "6.0")):
                return GPUFamilyInfo("nvidia_10", "NVIDIA GTX 10 系（Pascal, sm_61）")
            return GPUFamilyInfo("nvidia_unknown", "NVIDIA（未知系别）")

        name = (gpu.name or "").lower()
        if re.search(r"(rtx\s*50\d{2}|rtx\s*50\b|b100|b200|gb10)", name):
            return GPUFamilyInfo("nvidia_50", "NVIDIA RTX 50 系（Blackwell, sm_120）")
        if re.search(r"rtx\s*40\d{2}", name):
            return GPUFamilyInfo("nvidia_40", "NVIDIA RTX 40 系（Ada, sm_89）")
        if re.search(r"(rtx\s*30\d{2}|rtx\s*a\d{4}|a100|a800)", name):
            return GPUFamilyInfo("nvidia_30", "NVIDIA RTX 30 系（Ampere, sm_86/80）")
        if re.search(r"(rtx\s*20\d{2}|gtx\s*16\d{2})", name):
            return GPUFamilyInfo("nvidia_20", "NVIDIA RTX 20 / GTX 16 系（Turing, sm_75）")
        if re.search(r"gtx\s*10\d{2}", name):
            return GPUFamilyInfo("nvidia_10", "NVIDIA GTX 10 系（Pascal, sm_61）")
        if re.search(r"(h100|h200|h800|a100|a800|b100|b200)", name):
            return GPUFamilyInfo("nvidia_dc", "NVIDIA 数据中心卡（A/H/B 系列）")
        return GPUFamilyInfo("nvidia_unknown", "NVIDIA（未知系别）")

    if gpu.vendor == "amd":
        name = (gpu.name or "").lower()
        if re.search(r"(rx\s*9\d{3}|9000|9060|9070|9080|9090)", name):
            return GPUFamilyInfo("amd_rdna4", "AMD Radeon RX 9000 系（RDNA4, gfx1200/1201）")
        if re.search(r"rx\s*7\d{3}", name):
            return GPUFamilyInfo("amd_rdna3", "AMD Radeon RX 7000 系（RDNA3, gfx1100）")
        if re.search(r"rx\s*6\d{3}", name):
            return GPUFamilyInfo("amd_rdna2", "AMD Radeon RX 6000 系（RDNA2, gfx1030）")
        if re.search(r"rx\s*5(700|600|500|900)", name):
            return GPUFamilyInfo("amd_rdna1", "AMD Radeon RX 5000 系（RDNA1, gfx1010）")
        if re.search(r"(vega|radeon vii|rx\s*5\d{2}\b|rx\s*4\d{2}|r9\s)", name):
            return GPUFamilyInfo("amd_gcn", "AMD Vega/Polaris（gfx900/gfx803）")
        if re.search(r"(mi100|mi200|mi210|mi250|mi300|mi350)", name):
            return GPUFamilyInfo("amd_dc", "AMD Instinct（CDNA）")
        return GPUFamilyInfo("amd_unknown", "AMD（未知系别）")

    if gpu.vendor == "apple":
        return GPUFamilyInfo("apple", "Apple Silicon")
    return GPUFamilyInfo("cpu", "无独立 GPU / CPU")


# NVIDIA 系别 → torch CUDA 分支。RTX 50 系（sm_120）必须 cu128+，其余 cu126 通用。
_NVIDIA_TORCH_INDEX: dict[str, tuple[str, str, Optional[str]]] = {
    "nvidia_50": (
        "https://download.pytorch.org/whl/cu128",
        "PyTorch (CUDA 12.8, Blackwell sm_120)",
        "RTX 50 系需要 CUDA 12.8+ 驱动（NVIDIA 驱动 ≥570）；"
        "bitsandbytes 需 ≥0.45.5（含 Blackwell 内核），Windows 缺 "
        "libbitsandbytes_cuda128.dll 时请升级到最新版。",
    ),
    "nvidia_40": (
        "https://download.pytorch.org/whl/cu126",
        "PyTorch (CUDA 12.6, Ada sm_89)",
        None,
    ),
    "nvidia_30": (
        "https://download.pytorch.org/whl/cu126",
        "PyTorch (CUDA 12.6, Ampere sm_86/80)",
        None,
    ),
    "nvidia_20": (
        "https://download.pytorch.org/whl/cu121",
        "PyTorch (CUDA 12.1, Turing sm_75)",
        "Turing（RTX 20/GTX 16）用 cu121；若该索引没有可用轮子可手动改 cu118。",
    ),
    "nvidia_10": (
        "https://download.pytorch.org/whl/cu118",
        "PyTorch (CUDA 11.8, Pascal sm_61)",
        "Pascal（GTX 10 系）太老，4bit 量化支持有限，强烈建议改用 Ollama 后端。",
    ),
    "nvidia_dc": (
        "https://download.pytorch.org/whl/cu126",
        "PyTorch (CUDA 12.6, A/H 系列)",
        None,
    ),
    "nvidia_unknown": (
        "https://download.pytorch.org/whl/cu126",
        "PyTorch (CUDA 12.6, 通用)",
        "未能识别 NVIDIA 具体系别，按 CUDA 12.6 安装；若报 no kernel image，"
        "可设 VULN_SCANNER_TORCH_INDEX=https://download.pytorch.org/whl/cu128 覆盖。",
    ),
}

# AMD 系别 → torch ROCm 分支（仅 Linux 有官方轮子）。
_AMD_TORCH_INDEX: dict[str, tuple[str, str, Optional[str]]] = {
    "amd_rdna4": (
        "https://download.pytorch.org/whl/rocm7.2",
        "PyTorch (ROCm 7.2, RDNA4 gfx1200/1201)",
        "RDNA4 需要较新的 Linux 内核 + ROCm 驱动；装不上可回退 rocm6.3 或改用 Ollama。",
    ),
    "amd_rdna3": (
        "https://download.pytorch.org/whl/rocm6.3",
        "PyTorch (ROCm 6.3, RDNA3 gfx1100)",
        None,
    ),
    "amd_rdna2": (
        "https://download.pytorch.org/whl/rocm6.2",
        "PyTorch (ROCm 6.2, RDNA2 gfx1030)",
        "RDNA2 若在 ROCm 6.2 上驱动异常，可回退 rocm5.7。",
    ),
    "amd_rdna1": (
        "https://download.pytorch.org/whl/rocm5.7",
        "PyTorch (ROCm 5.7, RDNA1 gfx1010)",
        "RDNA1 较老，ROCm 支持有限，建议优先 Ollama。",
    ),
    "amd_gcn": (
        "https://download.pytorch.org/whl/rocm5.7",
        "PyTorch (ROCm 5.7, Vega/Polaris)",
        "Vega/Polaris 太老，ROCm 支持有限，强烈建议改用 Ollama 后端。",
    ),
    "amd_dc": (
        "https://download.pytorch.org/whl/rocm6.3",
        "PyTorch (ROCm 6.3, Instinct CDNA)",
        None,
    ),
    "amd_unknown": (
        "https://download.pytorch.org/whl/rocm6.3",
        "PyTorch (ROCm 6.3, 通用)",
        "未能识别 AMD 具体系别，按 ROCm 6.3 安装；可设 VULN_SCANNER_TORCH_INDEX 覆盖。",
    ),
}


# ---------------------------------------------------------------------------
# 依赖规格生成
# ---------------------------------------------------------------------------

def _pip_base_cmd(python_executable: str) -> List[str]:
    return [python_executable, "-m", "pip", "install", "--upgrade"]


def _pip_index_args(spec: InstallSpec) -> List[str]:
    args: List[str] = []
    # 允许用户通过环境变量覆盖镜像源
    global_index = os.environ.get("VULN_SCANNER_PIP_INDEX", "").strip()
    torch_index = os.environ.get("VULN_SCANNER_TORCH_INDEX", "").strip()

    # torch 专用 index 优先级：显式 TORCH_INDEX > spec.index_url > 全局 PIP_INDEX
    if spec.index_url and "pytorch.org" in spec.index_url:
        if torch_index:
            args.extend(["--index-url", torch_index])
        else:
            args.extend(["--index-url", spec.index_url])
        if spec.extra_index_url:
            args.extend(["--extra-index-url", spec.extra_index_url])
    else:
        if spec.prefer_index_url and spec.index_url:
            # 强制以 spec.index_url 为主索引（忽略全局镜像），保证 CUDA/Metal 预编译
            # wheel 从 abetlen 官方索引取，避免回退到 PyPI 的 CPU wheel
            args.extend(["--index-url", spec.index_url])
        elif global_index:
            args.extend(["--index-url", global_index])
        elif spec.index_url:
            args.extend(["--index-url", spec.index_url])
        if spec.extra_index_url:
            args.extend(["--extra-index-url", spec.extra_index_url])
    return args


def _torch_spec(platform_info: PlatformInfo, gpu: GPUInfo, python_executable: str) -> InstallSpec:
    """生成 PyTorch 安装规格（按平台 + GPU 系别选择构建）。"""
    # 项目只需要 torch；不安装 torchvision/torchaudio，避免与 torch 版本/index 不匹配。
    base_pkgs = ["torch"]
    family = classify_gpu(gpu)

    # 显存不足（如 4G 卡）强制选 transformers 时：保留 CPU torch 走 CPU 推理，
    # 不卸载现有 CPU 版、不下载数 GB 的 CUDA/ROCm wheel（GPU 也装不下 8B 模型）。
    if _low_vram_cpu_mode(gpu):
        return InstallSpec(
            description=f"PyTorch (CPU-only，{family.label} 显存不足无法 GPU 跑 8B NF4)",
            packages=base_pkgs,
            index_url="https://download.pytorch.org/whl/cpu",
            check_modules=["torch"],
            warning=(
                f"检测到显存 {gpu.vram_mb}MB < {TORCH_GPU_VRAM_MIN_MB}MB，"
                "transformers 后端将使用 CPU 推理（4bit 可用但速度慢）；"
                "要 GPU 加速请改用 Ollama 后端。"
                "如确要强装 GPU 版 torch，可设 VULN_SCANNER_FORCE_GPU_TORCH=1（可能 OOM）。"
            ),
        )

    if gpu.vendor == "nvidia":
        index_url, description, warning = _NVIDIA_TORCH_INDEX[family.family]
        return InstallSpec(
            description=description,
            packages=base_pkgs,
            index_url=index_url,
            check_modules=["torch"],
            warning=warning,
        )

    if gpu.vendor == "amd":
        if platform_info.os_name == "linux":
            index_url, description, warning = _AMD_TORCH_INDEX[family.family]
            return InstallSpec(
                description=description,
                packages=base_pkgs,
                index_url=index_url,
                check_modules=["torch"],
                warning=warning or "ROCm 需要兼容的 Linux 内核与驱动；安装失败时请改回 Ollama 后端。",
            )
        # AMD on Windows/macOS：PyTorch 无官方 ROCm  wheel，只能走 CPU
        return InstallSpec(
            description="PyTorch (CPU-only，Windows/macOS AMD GPU 无官方 ROCm 支持)",
            packages=base_pkgs,
            index_url="https://download.pytorch.org/whl/cpu",
            check_modules=["torch"],
            warning=f"{family.label}：Windows/macOS 上的 AMD GPU 无官方 ROCm 轮子，PyTorch 将使用 CPU；"
                    "要 GPU 加速请用 Ollama 后端，或改用 Linux + ROCm。",
        )

    if gpu.vendor == "apple":
        # 默认 PyPI wheel 在 Apple Silicon 上启用 Metal Performance Shaders
        return InstallSpec(
            description="PyTorch (Apple Metal)",
            packages=base_pkgs,
            check_modules=["torch"],
        )

    # CPU-only
    return InstallSpec(
        description="PyTorch (CPU-only)",
        packages=base_pkgs,
        index_url="https://download.pytorch.org/whl/cpu",
        check_modules=["torch"],
    )


def _bitsandbytes_spec(platform_info: PlatformInfo, gpu: GPUInfo) -> InstallSpec:
    """生成 bitsandbytes 安装规格。

    bitsandbytes 官方当前支持：
      - NVIDIA CUDA（Windows/Linux）
      - AMD ROCm（Linux 预览轮；Windows 预览需 ROCm SDK，见官方文档）
      - CPU-only（Windows/Linux/macOS，慢但可用）
      - Apple Silicon（macOS arm64，通过 CPU 路径慢速运行）

    因此除明确禁用的场景外，一律安装 bitsandbytes，让用户在对应平台获得
    4bit/8bit 量化能力；不支持的组合会在运行时由 transformers_client 回退到
    CPU 或非量化路径。
    """
    platform_label = {
        "windows": "Windows", "linux": "Linux", "darwin": "macOS"
    }.get(platform_info.os_name, platform_info.os_name)
    gpu_label = gpu.vendor.upper() if gpu.vendor else "CPU"

    family = classify_gpu(gpu)
    warning: Optional[str] = None
    if gpu.vendor == "nvidia" and family.family == "nvidia_50":
        warning = (
            "RTX 50 系需要 bitsandbytes ≥0.45.5（含 Blackwell/sm_120 内核）；"
            "Windows 若报缺 libbitsandbytes_cuda128.dll，请升级到最新版。"
        )
    elif gpu.vendor == "nvidia" and family.family == "nvidia_10":
        warning = "Pascal（GTX 10 系）的 4bit 支持有限，建议改用 Ollama 后端。"
    if gpu.vendor == "amd":
        warning = (
            f"{platform_label} + ROCm 的 bitsandbytes 支持仍处于预览阶段，"
            "需兼容的 ROCm PyTorch 环境；安装失败时可设置 VULN_SCANNER_QUANTIZE=0 关闭量化。"
        )
    elif gpu.vendor == "apple":
        warning = (
            "Apple Silicon 上的 bitsandbytes 走 CPU 路径，4bit 推理速度较慢；"
            "追求速度请改用 Ollama 后端。"
        )
    elif gpu.vendor is None:
        warning = (
            "CPU-only 模式下 bitsandbytes 4bit 可用但速度显著慢于 GPU；"
            "大模型建议改用 Ollama 后端。"
        )

    return InstallSpec(
        description=f"bitsandbytes ({platform_label} {gpu_label})",
        packages=["bitsandbytes>=0.50.0"],
        check_modules=["bitsandbytes"],
        warning=warning,
    )


def _transformers_specs(platform_info: PlatformInfo, gpu: GPUInfo, python_executable: str) -> List[InstallSpec]:
    """transformers 后端：torch + transformers + peft + accelerate + bitsandbytes。"""
    specs: List[InstallSpec] = []

    specs.append(_torch_spec(platform_info, gpu, python_executable))
    specs.append(InstallSpec(
        description="Transformers / PEFT / Accelerate",
        packages=["transformers>=4.46.0", "peft>=0.20.0", "accelerate>=1.14.0"],
        check_modules=["transformers", "peft", "accelerate"],
    ))
    specs.append(_bitsandbytes_spec(platform_info, gpu))
    return specs


def _llamacpp_specs(platform_info: PlatformInfo, gpu: GPUInfo, python_executable: str) -> List[InstallSpec]:
    """llamacpp 后端：llama-cpp-python（按平台 + GPU 系别选预编译 wheel 或源码编译）。

    设计原则：能用官方预编译 GPU wheel 就不源码编译——
    - Windows + NVIDIA：abetlen 官方 cuXXX 预编译 CUDA wheel（避免源码解压长路径问题）
    - macOS + Apple：官方 metal 预编译 wheel
    - Linux + NVIDIA / AMD：源码编译（Linux 无 Windows 长路径问题）
    - Windows + AMD / 纯 CPU：PyPI 预编译 CPU wheel
    - 高级用户可 VULN_SCANNER_LLAMACPP_SOURCE_BUILD=1 强制源码编译，
      或用 VULN_SCANNER_LLAMACPP_CMAKE_ARGS 完全自定义编译参数
    """
    env: dict = {}
    index_url: Optional[str] = None
    extra_index_url: Optional[str] = None
    prefer_index_url = False
    description = "llama-cpp-python"
    warning: Optional[str] = None
    gpu_probe: Optional[str] = None
    packages = ["llama-cpp-python"]
    mirror_wheel_url: Optional[str] = None
    # GPU 平台若走源码编译，必须用 --no-binary 强制 sdist（PyPI wheel 是 CPU-only），
    # 否则 pip 会用 wheel 而忽略 CMAKE_ARGS，导致 GPU offload 静默失效。
    pip_extra_args: List[str] = []

    # 用户显式覆盖编译参数（高级用户：如 Vulkan / OpenBLAS / 自定义 arch）
    override_cmake = os.environ.get("VULN_SCANNER_LLAMACPP_CMAKE_ARGS", "").strip()
    force_source = os.environ.get("VULN_SCANNER_LLAMACPP_SOURCE_BUILD", "").strip() == "1"

    if override_cmake:
        env = {"CMAKE_ARGS": override_cmake}
        description = "llama-cpp-python (自定义 CMAKE_ARGS)"
        pip_extra_args = ["--no-binary", "llama-cpp-python"]
    elif force_source:
        # 强制源码编译：按 GPU 系别给出默认参数
        if gpu.vendor == "nvidia":
            env = {"CMAKE_ARGS": "-DGGML_CUDA=on -DLLAMA_CUDA=on"}
            description = "llama-cpp-python (CUDA 源码编译)"
        elif gpu.vendor == "apple":
            env = {"CMAKE_ARGS": "-DGGML_METAL=on -DLLAMA_METAL=on"}
            description = "llama-cpp-python (Metal 源码编译)"
        elif gpu.vendor == "amd":
            env = {"CMAKE_ARGS": "-DGGML_HIP=ON"}
            description = "llama-cpp-python (ROCm 源码编译)"
        pip_extra_args = ["--no-binary", "llama-cpp-python"]
        if platform_info.os_name == "windows":
            warning = (
                "Windows 源码编译 llama-cpp-python 需要启用 Windows 长路径支持，"
                "否则解压源码时会报 'No such file or directory'（即刚才遇到的错误）；"
                "并需安装匹配的 CUDA/ROCm/Vulkan 工具链。如非必要请改用预编译 wheel 或 Ollama。"
            )
    elif gpu.vendor == "nvidia" and platform_info.os_name == "windows":
        # Windows + NVIDIA：官方预编译 CUDA wheel，免源码编译 / 免长路径问题。
        # 默认 CUDA 分支按 GPU 系别自动选择，确保不同显卡拿到匹配的 wheel：
        #   RTX 50（Blackwell sm_120）→ cu128（必须 CUDA 12.8+/驱动≥570）
        #   RTX 20/GTX 16（Turing）→ cu121
        #   GTX 10（Pascal）→ cu118
        #   其余 Ampere/Ada/数据中心/未知 → cu125（官方 wheel 覆盖最全，兼容性最好）
        # 高级用户可用 VULN_SCANNER_LLAMACPP_CUDA_VERSION 显式覆盖。
        family = classify_gpu(gpu).family
        _default_cuda = {
            "nvidia_50": "cu128",
            "nvidia_40": "cu125",
            "nvidia_30": "cu125",
            "nvidia_20": "cu121",
            "nvidia_10": "cu118",
            "nvidia_dc": "cu125",
            "nvidia_unknown": "cu125",
        }.get(family, "cu125")
        cuda_ver = os.environ.get(
            "VULN_SCANNER_LLAMACPP_CUDA_VERSION", _default_cuda
        ).strip().lower()
        if not cuda_ver.startswith("cu"):
            cuda_ver = "cu" + cuda_ver
        ver = os.environ.get("VULN_SCANNER_LLAMACPP_VERSION", "0.3.34").strip()
        # 主索引指向 abetlen 官方 CUDA wheel，依赖（如 numpy 等）经 extra Pypi 拉取。
        # 用 --index-url 而非 --extra-index-url，避免同版本 CPU wheel 被 pip 误选。
        index_url = f"https://abetlen.github.io/llama-cpp-python/whl/{cuda_ver}"
        extra_index_url = "https://pypi.org/simple"
        prefer_index_url = True
        description = f"llama-cpp-python {ver} (CUDA 预编译 {cuda_ver})"
        packages = [f"llama-cpp-python=={ver}"]
        # 预编译 wheel 实际在 GitHub Releases，标记镜像 URL：安装前经 ghproxy 下载到本地，
        # 绕开国内 GitHub 大文件被掐断（ConnectionResetError 10054）的问题。
        mirror_wheel_url = (
            f"https://github.com/abetlen/llama-cpp-python/releases/download/"
            f"v{ver}-{cuda_ver}/llama_cpp_python-{ver}-py3-none-win_amd64.whl"
        )
        gpu_probe = (
            "import llama_cpp; "
            "print('TRUE' if llama_cpp.llama_supports_gpu_offload() else 'FALSE')"
        )
        if cuda_ver in ("cu128", "cu129", "cu130"):
            warning = (
                f"预编译索引 {cuda_ver} 需要较新的 NVIDIA 驱动（cu128 需 ≥570）；"
                f"若机器为 RTX 50 系，这是自动选择的最匹配版本。若该索引无匹配 wheel，"
                "可设置 VULN_SCANNER_LLAMACPP_CUDA_VERSION 改用其它版本，"
                "或 VULN_SCANNER_LLAMACPP_SOURCE_BUILD=1 源码编译（需启用 Windows 长路径支持）。"
            )
    elif gpu.vendor == "nvidia":
        # Linux + NVIDIA：源码编译 CUDA（Linux 无 Windows 长路径问题）
        # 新版 llama.cpp 使用 GGML_CUDA；LLAMA_CUDA 为旧版兼容参数，同时传不冲突
        env = {"CMAKE_ARGS": "-DGGML_CUDA=on -DLLAMA_CUDA=on"}
        description = "llama-cpp-python (CUDA)"
        pip_extra_args = ["--no-binary", "llama-cpp-python"]
    elif gpu.vendor == "apple":
        # macOS + Apple Silicon：官方预编译 Metal wheel，免 Xcode/CMake 编译
        ver = os.environ.get("VULN_SCANNER_LLAMACPP_VERSION", "0.3.34").strip()
        index_url = "https://abetlen.github.io/llama-cpp-python/whl/metal"
        extra_index_url = "https://pypi.org/simple"
        prefer_index_url = True
        description = f"llama-cpp-python {ver} (Metal 预编译)"
        packages = [f"llama-cpp-python=={ver}"]
        gpu_probe = (
            "import llama_cpp; "
            "print('TRUE' if llama_cpp.llama_supports_gpu_offload() else 'FALSE')"
        )
        warning = (
            "Metal 预编译 wheel 目前提供 cp311/cp312；若当前 Python 版本无对应 wheel，"
            "安装会失败或回退 CPU 版（安装器会探测并报错）。建议使用 Python 3.11/3.12，"
            "或设置 VULN_SCANNER_LLAMACPP_SOURCE_BUILD=1 源码编译（需 Xcode Command Line Tools）。"
        )
    elif gpu.vendor == "amd" and platform_info.os_name == "linux":
        env = {"CMAKE_ARGS": "-DGGML_HIP=ON"}
        description = "llama-cpp-python (ROCm)"
        pip_extra_args = ["--no-binary", "llama-cpp-python"]
    elif gpu.vendor == "amd":
        warning = (
            "Windows + AMD GPU：llama-cpp-python 的 PyPI 预编译包是 CPU 版，将按 CPU 安装。"
            "如需 GPU 加速：优先用 Ollama（原生支持 ROCm）；或设置 "
            "VULN_SCANNER_LLAMACPP_CMAKE_ARGS=\"-DGGML_VULKAN=on\" 并设 "
            "VULN_SCANNER_LLAMACPP_SOURCE_BUILD=1 源码编译（需安装 Vulkan SDK 与长路径支持）。"
        )

    return [InstallSpec(
        description=description,
        packages=packages,
        index_url=index_url,
        extra_index_url=extra_index_url,
        prefer_index_url=prefer_index_url,
        mirror_wheel_url=mirror_wheel_url,
        env=env,
        pip_extra_args=pip_extra_args,
        check_modules=["llama_cpp"],
        warning=warning,
        gpu_probe=gpu_probe,
    )]


def _vllm_specs(platform_info: PlatformInfo, gpu: GPUInfo, python_executable: str) -> List[InstallSpec]:
    """vllm 后端：按平台 + GPU 系别选择最合适的安装方式。

    vLLM 官方只完整支持 Linux（Windows 需 WSL2）；GPU 支持 NVIDIA CUDA、
    AMD ROCm（实验性）与 Intel XPU。Windows 原生 / macOS / 纯 CPU 均无法
    直接安装使用，默认拦截并给出替代方案，用户可设置 VULN_SCANNER_FORCE_VLLM=1 强制尝试。
    """
    platform_label = {
        "windows": "Windows", "linux": "Linux", "darwin": "macOS"
    }.get(platform_info.os_name, platform_info.os_name)
    gpu_label = gpu.vendor.upper() if gpu.vendor else "CPU"
    force = os.environ.get("VULN_SCANNER_FORCE_VLLM", "").strip() == "1"

    warning: Optional[str] = None
    blocked = False
    blocked_message = ""

    # 1) 原生 Windows：vLLM 官方不支持，直接拦截（避免下载数 GB 后安装失败）
    if platform_info.os_name == "windows":
        blocked = not force
        blocked_message = (
            "vLLM 官方不支持原生 Windows（仅支持 Linux / WSL2），"
            "在 Windows 上直接 pip install vllm 会安装失败或无法运行。"
            "建议改用 Ollama / LlamaCPP 后端，或在 WSL2 / Linux 中运行本项目。"
        )
        warning = "如仍要强制尝试（不保证可用），请设置 VULN_SCANNER_FORCE_VLLM=1。"

    # 2) Apple Silicon / macOS：官方不完整支持，默认拦截
    elif gpu.vendor == "apple":
        blocked = not force
        blocked_message = (
            "vLLM 官方仅完整支持 Linux；macOS 上即使安装也无法运行预编译内核"
            "（MPS 属实验性，另有社区 vllm-metal 插件）。"
            "建议 Apple Silicon 用户改用 LlamaCPP（Metal）或 Ollama 后端。"
        )
        warning = "如仍要强制尝试（不保证可用），请设置 VULN_SCANNER_FORCE_VLLM=1。"

    # 3) 纯 CPU / 未识别 GPU（含 Intel 常规核显）：vLLM 无法高效运行，默认拦截
    elif gpu.vendor is None:
        blocked = not force
        blocked_message = (
            "未检测到受 vLLM 支持的 GPU（需要 Linux + NVIDIA CUDA / AMD ROCm / Intel XPU）。"
            "纯 CPU 上 vLLM 无法高效运行，建议改用 Ollama 或 LlamaCPP 后端。"
        )
        warning = "如仍要强制尝试（不保证可用），请设置 VULN_SCANNER_FORCE_VLLM=1。"

    # 4) NVIDIA + Linux：官方 PyPI CUDA 轮子
    elif gpu.vendor == "nvidia":
        warning = (
            "vLLM 官方 Linux 轮子基于 CUDA 12.8+，要求 NVIDIA 驱动支持对应 CUDA 版本；"
            "如需其它 CUDA 版本可从源码构建。"
        )

    # 5) AMD + Linux：使用官方 ROCm 专用 wheel 索引
    elif gpu.vendor == "amd":
        rocm_version = os.environ.get("VULN_SCANNER_VLLM_VERSION", "").strip()
        rocm_index = os.environ.get("VULN_SCANNER_VLLM_ROCM_INDEX", "").strip()
        if not (rocm_version and rocm_index):
            # 默认取官方文档中已验证的 ROCm 7.0 wheel；高级用户可用环境变量覆盖
            rocm_version = "0.18.0+rocm700"
            rocm_index = "https://wheels.vllm.ai/rocm/0.18.0/rocm700"
        return [InstallSpec(
            description=f"vLLM (ROCm {rocm_version}, Linux)",
            packages=[f"vllm=={rocm_version}"],
            extra_index_url=rocm_index,
            check_modules=["vllm"],
            warning=(
                "AMD ROCm 版 vLLM 需 ROCm 6.3+/7.0 驱动（MI200/MI300/RX7900/RX9000 等），"
                "安装与运行属实验性。若版本不匹配，可设置 VULN_SCANNER_VLLM_VERSION 与 "
                "VULN_SCANNER_VLLM_ROCM_INDEX 指定官方 wheel；或改用 Ollama（ROCm 支持更成熟）。"
            ),
        )]

    else:
        warning = (
            f"{platform_label} + {gpu_label} 的 vLLM 支持不明确，安装可能失败；"
            "建议改用 Ollama / LlamaCPP。"
        )

    return [InstallSpec(
        description=f"vLLM ({platform_label} {gpu_label})",
        packages=["vllm"] if not blocked else [],
        check_modules=["vllm"],
        warning=warning,
        blocked=blocked,
        blocked_message=blocked_message,
    )]


def get_backend_requirements(
    backend: str,
    platform_info: Optional[PlatformInfo] = None,
    gpu: Optional[GPUInfo] = None,
    python_executable: Optional[str] = None,
) -> List[InstallSpec]:
    """获取指定后端在当【前平台的全部安装规格。"""
    if platform_info is None:
        platform_info = detect_platform()
    if gpu is None:
        gpu = detect_gpu(platform_info)
    python_executable = python_executable or sys.executable

    backend = backend.strip().lower()
    if backend == "transformers":
        return _transformers_specs(platform_info, gpu, python_executable)
    if backend in ("llamacpp", "llama-cpp", "llama_cpp", "gguf"):
        return _llamacpp_specs(platform_info, gpu, python_executable)
    if backend == "vllm":
        return _vllm_specs(platform_info, gpu, python_executable)
    raise ValueError(f"不支持自动安装的后端: {backend}")


# ---------------------------------------------------------------------------
# 安装 / 检测
# ---------------------------------------------------------------------------

def _module_import_name(package: str) -> str:
    """pip 包名 -> import 时模块名。"""
    mapping = {
        "llama-cpp-python": "llama_cpp",
    }
    return mapping.get(package, package.replace("-", "_"))


def check_module_installed(module: str) -> bool:
    """检查模块是否已安装（通过 import）。安装新包后调用会刷新 importlib 缓存。"""
    try:
        import importlib
        importlib.invalidate_caches()
        __import__(module)
        return True
    except Exception:
        return False


def _installed_package_version(python_executable: str, package: str) -> str:
    """在目标解释器中读取已安装包的版本号（用于校验预编译 GPU wheel 是否真的装上）。"""
    try:
        code = (
            "import importlib.metadata as m; "
            f"print(m.version({package!r}))"
        )
        r = subprocess.run(
            [python_executable, "-c", code],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace",
        )
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def _nvidia_runtime_dirs() -> list[str]:
    """返回 pip 安装的 NVIDIA CUDA 运行时 DLL 所在目录（需加入 PATH 才能加载 llama.dll）。

    llama_cpp 的 CUDA wheel 只自带 llama.dll，其依赖的 cudart64_12.dll / cublas64_12.dll
    由 nvidia-cuda-runtime-cu12 / nvidia-cublas-cu12 等 pip 包提供。这些 DLL 不在系统 PATH
    上，若探测子进程环境里没把它们加进去，import llama_cpp 会报
    "Could not find module ... llama.dll (or one of its dependencies)"，导致
    llama_supports_gpu_offload() 探测失败（误判为 CPU-only 版本）。
    """
    dirs: list[str] = []
    try:
        import site
        roots = []
        for sp in site.getsitepackages():
            cand = Path(sp) / "nvidia"
            if cand.is_dir():
                roots.append(cand)
        user_dir = Path(site.getusersitepackages()) / "nvidia"
        if user_dir.is_dir():
            roots.append(user_dir)
        for root in roots:
            for pkg in ("cuda_runtime", "cublas", "cuda_nvrtc", "cuda_cudart"):
                bin_dir = root / pkg / "bin"
                if bin_dir.is_dir():
                    dirs.append(str(bin_dir))
    except Exception:
        pass
    return dirs


def _probe_gpu_support(python_executable: str, code: str) -> bool:
    """在目标解释器中运行 GPU 能力探测代码，stdout 为 TRUE 表示 GPU 后端可用。

    探测前把 pip 安装的 NVIDIA 运行时 DLL 目录注入子进程 PATH，否则 llama.dll 加载
    依赖失败会误判为 CPU-only 版本。
    """
    try:
        env = os.environ.copy()
        nvidia_dirs = _nvidia_runtime_dirs()
        if nvidia_dirs:
            env["PATH"] = os.pathsep.join(nvidia_dirs) + os.pathsep + env.get("PATH", "")
        r = subprocess.run(
            [python_executable, "-c", code],
            capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace", env=env,
        )
        return r.returncode == 0 and "TRUE" in r.stdout.upper()
    except Exception:
        return False


def _spec_package_name(spec: InstallSpec) -> str:
    """从安装包描述中提取 pip 包名（去掉 ==/>= 等版本约束）。"""
    name = spec.packages[0].split("==")[0].split(">=")[0].split("<")[0].strip()
    return name


def _parse_requirement(req: str) -> tuple[str, Optional[str], Optional[str]]:
    """解析 pip 包要求："pkg" / "pkg>=1.2" / "pkg==1.2" → (包名, 最低版本, 精确版本)。"""
    name = req.strip()
    min_version: Optional[str] = None
    exact_version: Optional[str] = None
    for op in (">=", "=="):
        if op in name:
            parts = name.split(op, 1)
            name = parts[0].strip()
            ver = parts[1].strip()
            if op == "==":
                exact_version = ver
            else:
                min_version = ver
            break
    return name, min_version, exact_version


def _spec_status(
    spec: InstallSpec,
    python_executable: str,
    torch_mismatch: bool,
) -> tuple[str, str]:
    """判断一条依赖规格的当前状态。

    Returns:
        (status, reason)，status 取值：
            - "ok"       已安装且版本/构建匹配
            - "missing"  未安装
            - "outdated" 已安装但版本低于要求（pip --upgrade 即可）
            - "mismatch" 已安装但版本/GPU 构建不匹配（需先卸载再重装）
    """
    if torch_mismatch and spec.check_modules == ["torch"]:
        return "mismatch", "torch 构建与当前硬件不匹配"

    for req in spec.packages:
        name, min_version, exact_version = _parse_requirement(req)
        ver = _package_version(python_executable, name)
        if ver is None:
            return "missing", f"{name} 未安装"
        if exact_version and ver != exact_version:
            return "mismatch", f"{name} 已装 {ver}，目标版本 {exact_version}"
        if min_version and _version_lt(ver, min_version):
            return "outdated", f"{name} 已装 {ver}，低于要求 {min_version}"

    if spec.version_marker:
        ver = _installed_package_version(python_executable, _spec_package_name(spec))
        if spec.version_marker not in ver:
            return "mismatch", f"版本 {ver or '未知'} 不含 GPU 标记 '{spec.version_marker}'"

    if spec.gpu_probe:
        if not _probe_gpu_support(python_executable, spec.gpu_probe):
            return "mismatch", "GPU 探测失败（疑似 CPU-only 版本）"

    return "ok", ""


def get_missing_modules(backend: str) -> List[str]:
    """获取某后端缺失的必须模块。"""
    backend = backend.strip().lower()
    if backend == "transformers":
        required = ["torch", "transformers", "peft", "accelerate", "bitsandbytes"]
    elif backend in ("llamacpp", "llama-cpp", "llama_cpp", "gguf"):
        required = ["llama_cpp"]
    elif backend == "vllm":
        required = ["vllm"]
    else:
        return []
    return [m for m in required if not check_module_installed(m)]


def _is_auto_install_enabled() -> bool:
    val = os.environ.get("VULN_SCANNER_AUTO_INSTALL_DEPS", "").strip().lower()
    return val not in ("0", "false", "no", "off")


def _force_reinstall() -> bool:
    val = os.environ.get("VULN_SCANNER_AUTO_INSTALL_DEPS", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def _build_pip_cmd(spec: InstallSpec, python_executable: str) -> List[str]:
    cmd = _pip_base_cmd(python_executable)
    cmd.extend(_pip_index_args(spec))
    cmd.extend(spec.pip_extra_args)
    cmd.extend(spec.packages)
    _add_pip_network_flags(cmd)
    return cmd


def _add_pip_network_flags(cmd: List[str]) -> None:
    """给 pip install 追加网络韧性参数：慢网请求超时放宽 + 失败自动重试。"""
    if PIP_SOCKET_TIMEOUT > 0:
        cmd.extend(["--timeout", str(PIP_SOCKET_TIMEOUT)])
    if PIP_RETRIES > 0:
        cmd.extend(["--retries", str(PIP_RETRIES)])
    if PIP_PROGRESS_BAR in ("on", "raw"):
        cmd.extend(["--progress-bar", PIP_PROGRESS_BAR])


# llama-cpp-python 预编译 wheel 的 ghproxy 镜像前缀（避免国内直连 GitHub Releases 被掐断）。
# 注意：各 ghproxy 公共镜像节点经常失效/宕机（如 mirror.ghproxy.com 已不可用），
# 因此维护一个候选列表，下载时逐个探测直到成功，避免写死单一节点导致必挂。
# 用户可用 VULN_SCANNER_GH_PROXY 显式指定首个候选。
_GH_PROXY_CANDIDATES = [
    os.environ.get("VULN_SCANNER_GH_PROXY", "").strip(),
    "https://ghproxy.net/",
    "https://gh-proxy.com/",
    "https://ghproxy.link/",
    "https://ghfast.top/",
]
# 去掉空项、去重、统一以 "/" 结尾；探测失败时会继续尝试下一个候选。
_GH_PROXY_PREFIXES = [
    p.rstrip("/") + "/"
    for p in dict.fromkeys(c for c in _GH_PROXY_CANDIDATES if c and c.strip())
]


class _SlowMirrorError(Exception):
    """镜像下载速度过低时抛出，用于中断当前镜像换下一个。"""


# 镜像下载最低速度（B/s）：低于此值视为"慢镜像"并立即放弃。
# 公共 ghproxy 回源 536MB 大文件经常只有 ~20KB/s，等 read 超时太久；
# 这里以 8 秒窗口计速，低于 50KB/s 就换下一个。可用环境变量覆盖。
WHEEL_MIN_SPEED = int(
    os.environ.get("VULN_SCANNER_WHEEL_MIN_SPEED", "").strip() or (50 * 1024)
)


def _detect_system_proxy() -> str:
    """探测可用的系统代理（优先环境变量，回退 Windows 注册表系统代理）。

    返回形如 "http://127.0.0.1:7897" 的代理地址；未检测到时返回空字符串。
    """
    # 1) 环境变量（http_proxy / https_proxy / all_proxy），大小写都认
    for var in ("https_proxy", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        val = os.environ.get(var, "").strip()
        if val:
            if not val.lower().startswith(("http://", "https://")):
                val = "http://" + val
            return val
    # 2) Windows 注册表系统代理（仅当开启了系统代理才读取）
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                if enabled:
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")
                else:
                    server = ""
            if server:
                if not server.lower().startswith(("http://", "https://")):
                    server = "http://" + server
                return server
        except Exception:  # noqa: BLE001
            pass
    return ""


def _download_wheel_via_mirror(spec: InstallSpec, callback: Optional[Callable[[str], None]] = None) -> Optional[Path]:
    """把 spec.mirror_wheel_url 指定的 GitHub wheel 下载到本地。

    下载策略（按优先级）：
        1. 若检测到系统代理 → 直接走代理连 GitHub（快，一次性，避免在慢镜像上死等）
        2. 否则 → 逐个试 ghproxy 镜像（直连，不吃代理流量），配最低速度监控，
           速度过慢立即放弃换下一个，不等 read 超时
    返回本地 wheel 路径；全部失败返回 None，调用方回退 pip 直连。
    """
    url = (spec.mirror_wheel_url or "").strip()
    if not url:
        return None
    filename = url.rsplit("/", 1)[-1].split("?", 1)[0].split("#", 1)[0]
    if not filename:
        return None
    # 缓存到项目 D 盘目录（cache/wheels），避免 500MB+ wheel 占用系统盘 C 盘；
    # 重复运行/重试时直接复用，避免反复下载。项目根通过依赖安装器所在
    # app/launcher 向上两级定位（与 graduation_project.paths.find_project_root 一致）。
    _proj_root = Path(__file__).resolve().parents[2]
    cache_dir = _proj_root / "cache" / "wheels"
    cache_dir.mkdir(parents=True, exist_ok=True)
    dest = cache_dir / filename
    marker = cache_dir / (filename + ".ok")
    # 缓存完整性用 sidecar 标记校验：只有上次下载完整成功写出 .ok 的 wheel 才可复用，
    # 避免下载中断留下的残片（>0 字节但远小于完整大小）被误当有效缓存。
    if marker.is_file():
        try:
            expected = int(marker.read_text(encoding="utf-8").strip())
        except Exception:  # noqa: BLE001
            expected = 0
        if dest.is_file() and dest.stat().st_size == expected and expected > 0:
            _emit(f"[依赖安装] 复用已缓存 wheel: {dest}", callback)
            return dest
        # 标记存在但文件缺失/不完整 → 视为损坏缓存，删除后重新下载
        _emit(f"[依赖安装] ⚠️ 缓存损坏（残片 {dest}），删除并重新下载", callback)
        dest.unlink(missing_ok=True)
        marker.unlink(missing_ok=True)

    # —— 1) 优先走系统代理直连 GitHub（快且一次性，避免在慢镜像上死等）——
    proxy_url = _detect_system_proxy()
    if proxy_url:
        _emit(f"[依赖安装] 检测到系统代理，直连 GitHub 下载（不经镜像）: {proxy_url}", callback)
        try:
            opener = build_opener(ProxyHandler({"http": proxy_url, "https": proxy_url}))
            with opener.open(url, timeout=60) as resp, open(dest, "wb") as f:
                total = int(resp.headers.get("content-length", 0))
                downloaded = 0
                last_report = time.time()
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    # 进度上报：每 2 秒输出一次（下载 536MB 大文件时让用户看到实时进度）
                    now = time.time()
                    if now - last_report >= 2:
                        _emit(
                            f"[依赖安装] 代理下载中: {downloaded/1024/1024:.1f}MB / {total/1024/1024:.1f}MB"
                            f" ({downloaded*100/total:.0f}%)"
                            if total > 0
                            else f"[依赖安装] 代理下载中: {downloaded/1024/1024:.1f}MB",
                            callback,
                        )
                        last_report = now
            if total > 0 and downloaded != total:
                _emit(
                    f"[依赖安装] ⚠️ 代理下载不完整 {downloaded}/{total} 字节，删缓存并回退 pip 直连",
                    callback,
                )
                dest.unlink(missing_ok=True)
                marker.unlink(missing_ok=True)
                return None
            marker.write_text(str(downloaded), encoding="utf-8")
            _emit(f"[依赖安装] ✅ 代理直连 GitHub 下载完成: {dest}", callback)
            return dest
        except Exception as e:
            _emit(
                f"[依赖安装] ⚠️ 代理直连 GitHub 失败（{type(e).__name__}: {e}），回退走镜像",
                callback,
            )
            dest.unlink(missing_ok=True)
            marker.unlink(missing_ok=True)
            # 代理失败不立即返回，落到下方镜像逻辑再试

    # —— 2) 无代理 / 代理失败时，逐个试 ghproxy 镜像（直连，不吃代理流量）——
    # 每个候选都设 NO_PROXY 直连。加速：最低速度监控，速度过低马上放弃换下一个，
    # 避免在 20KB/s 的慢镜像上死等 read 超时（慢速但它不报超时）。
    reflected_hosts = set()
    for prefix in _GH_PROXY_PREFIXES:
        mirror_url = prefix + url
        mirror_host = urlparse(mirror_url).hostname or ""
        if mirror_host:
            reflected_hosts.add(mirror_host)
        _no_proxy = set(
            h.strip()
            for h in os.environ.get("NO_PROXY", "").replace(";", ",").split(",")
            if h.strip()
        )
        _no_proxy |= reflected_hosts
        _no_proxy_val = ",".join(sorted(_no_proxy))
        os.environ["NO_PROXY"] = _no_proxy_val
        os.environ["no_proxy"] = _no_proxy_val

        _emit(f"[依赖安装] 经镜像下载 llama-cpp-python wheel（避免 GitHub 断连）: {mirror_url}", callback)
        try:
            with urlopen(mirror_url, timeout=60) as resp, open(dest, "wb") as f:
                total = int(resp.headers.get("content-length", 0))
                downloaded = 0
                window_started = time.time()
                window_bytes = 0
                last_report = time.time()
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    # 最低速度监控：以最近的 8 秒窗口计速，低于 50KB/s 视为"慢镜像"，
                    # 立即中断换下一个（公共 ghproxy 回源大文件经常只有 20KB/s）。
                    window_bytes += len(chunk)
                    now = time.time()
                    if now - window_started >= 8:
                        speed = window_bytes / (now - window_started)
                        if speed < WHEEL_MIN_SPEED:
                            raise _SlowMirrorError(
                                f"镜像下载过慢（{speed:.0f} B/s < {WHEEL_MIN_SPEED // 1024}KB/s），换下一个"
                            )
                        window_started = now
                        window_bytes = 0
                    # 进度上报：每 2 秒输出一次
                    if now - last_report >= 2:
                        _emit(
                            f"[依赖安装] 镜像下载中: {downloaded/1024/1024:.1f}MB / {total/1024/1024:.1f}MB"
                            f" ({downloaded*100/total:.0f}%)"
                            if total > 0
                            else f"[依赖安装] 镜像下载中: {downloaded/1024/1024:.1f}MB",
                            callback,
                        )
                        last_report = now
            if total > 0 and downloaded != total:
                _emit(
                    f"[依赖安装] ⚠️ 镜像下载不完整 {downloaded}/{total} 字节，换下一个镜像重试",
                    callback,
                )
                dest.unlink(missing_ok=True)
                marker.unlink(missing_ok=True)
                continue
            marker.write_text(str(downloaded), encoding="utf-8")
            _emit(f"[依赖安装] ✅ 镜像下载完成: {dest}", callback)
            return dest
        except Exception as e:
            _emit(
                f"[依赖安装] ⚠️ 镜像 {prefix} 下载失败（{type(e).__name__}: {e}），换下一个镜像",
                callback,
            )
            dest.unlink(missing_ok=True)
            marker.unlink(missing_ok=True)
            continue

    _emit(f"[依赖安装] ⚠️ 没有可用镜像，回退 pip 直连下载", callback)
    return None


def _run_pip_install(
    cmd: List[str],
    env: dict,
    description: str,
    callback: Optional[Callable[[str], None]] = None,
) -> tuple[int, str]:
    """流式执行 pip install：实时转发输出，只有超过墙钟上限才终止进程。

    网络慢时用户能实时看到下载进度；pip 自身有 socket 超时 + 重试（见
    _add_pip_network_flags），不会因为单个请求慢就被掐断。

    Returns:
        (returncode, 完整输出文本)
    """
    # Windows 下 pip 子进程默认按系统代码页（GBK/cp936）输出中文报错，
    # 若按 utf-8 解读会变成乱码。这里强制子进程以 UTF-8 输出（Python 解释器
    # 统一走 PYTHONUTF8/PYTHONIOENCODING），保证不同硬件/不同控制台编码下
    # 中文错误消息都能被下面 encoding="utf-8" 正确解码。
    env = dict(env)
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")

    lines: list[str] = []
    proc = subprocess.Popen(
        cmd, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", bufsize=1,
    )
    assert proc.stdout is not None
    deadline = time.time() + PIP_TOTAL_TIMEOUT if PIP_TOTAL_TIMEOUT > 0 else None
    for line in proc.stdout:
        lines.append(line)
        stripped = line.strip()
        if stripped:
            _emit(f"  {stripped}", callback)
        if deadline is not None and time.time() > deadline:
            _emit(
                f"[依赖安装] {description} 总时长超过 {PIP_TOTAL_TIMEOUT // 60} 分钟，"
                "已终止下载进程；网络慢可设 VULN_SCANNER_PIP_TIMEOUT 调大（0=不限制）",
                callback,
            )
            proc.kill()
            break
    proc.wait(timeout=10)
    return proc.returncode, "".join(lines)


def _query_torch_build(python_executable: str) -> Optional[str]:
    """查询目标解释器里已装 torch 的构建标识（如 'cu130' / 'rocm7.2' / 'cpu'）。

    返回：
        - '+后缀' 的小写形式（如 'cu130'）：torch.__version__ 形如 2.12.1+cu130
        - '' ：torch 已装但无构建后缀（旧版 / 官方 pypi 版）
        - None：torch 未安装或查询失败
    """
    try:
        r = subprocess.run(
            [python_executable, "-c", "import torch; print(torch.__version__)"],
            capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace",
        )
        if r.returncode != 0:
            return None
        ver = r.stdout.strip()
        if "+" in ver:
            return ver.split("+", 1)[1].lower()
        return ""
    except Exception:
        return None


def _required_torch_family(platform_info: PlatformInfo, gpu: GPUInfo) -> str:
    """根据硬件确定当前应安装的 torch 构建后缀。

    返回形如 'cu128' / 'cu126' / 'rocm7.2' / 'cpu'，用于判断已装 torch 是否匹配。
    """
    # 显存不足时 transformers 走 CPU：已装的 CPU torch 视为匹配，不触发重装/卸载
    if _low_vram_cpu_mode(gpu):
        return "cpu"
    family = classify_gpu(gpu)
    if gpu.vendor == "nvidia":
        index_url, _, _ = _NVIDIA_TORCH_INDEX[family.family]
        return index_url.rstrip("/").rsplit("/", 1)[-1]
    if gpu.vendor == "amd" and platform_info.os_name == "linux":
        index_url, _, _ = _AMD_TORCH_INDEX[family.family]
        return index_url.rstrip("/").rsplit("/", 1)[-1]
    return "cpu"


def _build_satisfies(installed: str, required: str) -> bool:
    """判断已装 torch 构建是否满足要求。

    - cu 系列：数字 ≥ 要求即可（如 RTX 50 要求 cu128，已装 cu130 也满足）；
    - rocm 系列：主版本号 ≥ 要求即可（如要求 rocm6.2，已装 rocm7.2 也满足）；
    - cpu / 无构建后缀：彼此视为等价（官方 PyPI 版无 +cpu 后缀，但功能上是 CPU 版）。
    """
    if installed == required:
        return True
    # 无构建后缀的官方 PyPI 版：CPU 场景下视为满足；GPU 场景下因 required 为 cu/rocm，不满足
    if not installed:
        return required == "cpu"
    if installed.startswith("cu") and required.startswith("cu"):
        try:
            return int(installed[2:]) >= int(required[2:])
        except ValueError:
            return False
    if installed.startswith("rocm") and required.startswith("rocm"):
        try:
            def _ver(s: str) -> tuple[int, int]:
                parts = s[4:].split(".")
                return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
            return _ver(installed) >= _ver(required)
        except ValueError:
            return False
    return False


def _build_eq(a: Optional[str], b: Optional[str]) -> bool:
    """判断两个构建后缀是否等价（空字符串与 'cpu' 视为等价）。"""
    if a == b:
        return True
    cpu_like = {"", "cpu"}
    return a in cpu_like and b in cpu_like


# 与 torch 共用 C++ ABI 的 PyTorch 官方生态包：从 PyTorch index 安装时版本号
# 带 +cuXXX/+cpu 构建后缀，必须与 torch 一致，否则可能触发 Windows DLL 入口点错误。
# 本项目不依赖它们，发现不一致时直接卸载。
_TORCH_ABI_PACKAGES = ("torchvision", "torchaudio", "torchtext", "torchdata")


def torch_needs_reinstall(
    platform_info: PlatformInfo,
    gpu: GPUInfo,
    python_executable: str,
) -> bool:
    """判断已装 torch 是否与当前硬件匹配，不匹配则需要重装。

    规则：
        - 当前硬件需要的构建族 = NVIDIA→cu / AMD+Linux→rocm / 其余→cpu
        - torch 未安装 → 需要装
        - 需要 cu/rocm 但已装构建不匹配 → 需要重装（例如 AMD 机器上装了 CUDA 版 torch，
          或 ROCm 机器上被误判成 NVIDIA 而要求 cu）
        - CPU 族 → 任何已装构建都能跑，不重装

    使用 pip 元数据（_query_package_build）而非直接 import torch，避免在清理前
    触发 ABI 不匹配的 .pyd 加载，导致 Windows 弹出 "无法定位程序输入点" 错误窗口。
    """
    required = _required_torch_family(platform_info, gpu)
    installed = _query_package_build(python_executable, "torch")

    if installed is None:
        return True
    if required == "cpu":
        return False
    return not _build_satisfies(installed, required)


def _conda_envs_dir() -> Optional[Path]:
    """定位 conda 的 envs 目录（尽可能不依赖特定调用方式）。

    优先级：
        1. sys.executable 路径中出现的 envs 目录（env python 形如 .../envs/<名>/bin/python3）
        2. 从 sys.executable 向上找到 conda 根目录（含 conda-meta）下的 envs/
        3. conda 可执行文件在 PATH 时，从它推导根目录下的 envs/
    """
    p = Path(sys.executable).resolve()
    # 1) env python：路径里含 /envs/<名>/bin/python3
    for parent in p.parents:
        if parent.name == "envs" and parent.is_dir():
            return parent
    # 2) base / 根目录：找到含 conda-meta 的目录，取其 envs 子目录
    for parent in p.parents:
        if (parent / "conda-meta").is_dir():
            envs = parent / "envs"
            if envs.is_dir():
                return envs
    # 3) conda 在 PATH（即使当前解释器不是 conda python）：从 conda 可执行文件推导
    conda_exe = shutil.which("conda")
    if conda_exe:
        root = Path(conda_exe).resolve().parent.parent  # <root>/bin/conda -> <root>
        envs = root / "envs"
        if envs.is_dir():
            return envs
    return None


def _env_python(env: Path) -> Optional[str]:
    """返回某个 conda 环境内的 python 可执行文件（按平台区分路径）。"""
    if sys.platform == "win32":
        candidates = [env / "python.exe"]
    else:
        candidates = [env / "bin" / "python3", env / "bin" / "python"]
    for c in candidates:
        if c.is_file():
            return str(c)
    return None


def _list_conda_env_pythons() -> List[str]:
    """列出所有 conda 环境里的 python 解释器（平台感知）。

    优先用 `conda env list --json`；conda 不在 PATH 时回退到直接扫描 envs 目录。
    Windows 环境解释器为 <env>/python.exe，linux/macOS 为 <env>/bin/python3。
    """
    pythons: List[str] = []

    def _collect(env_path: str) -> None:
        p = _env_python(Path(env_path))
        if p:
            pythons.append(p)

    # 1) conda 命令方式（最准确）
    try:
        r = subprocess.run(
            ["conda", "env", "list", "--json"],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace",
        )
        if r.returncode == 0:
            import json
            data = json.loads(r.stdout)
            for env_path in data.get("envs", []):
                _collect(env_path)
            if pythons:
                return pythons
    except Exception:
        pass
    # 2) 回退：扫描 envs 目录
    envs_dir = _conda_envs_dir()
    if envs_dir is not None:
        try:
            for env in sorted(envs_dir.iterdir()):
                if env.is_dir():
                    _collect(str(env))
        except Exception:
            pass
    return pythons


def _query_package_build(python_executable: str, package: str) -> Optional[str]:
    """查询指定包的构建后缀（如 torchvision 2.7.0+cu128 -> cu128）。

    不 import 包，避免 ABI 不匹配的 .pyd 在 import 时弹出 DLL 入口点错误窗口。
    直接从 pip 元数据读取版本号（包含 +cu128 等 local version）。
    """
    try:
        r = subprocess.run(
            [python_executable, "-m", "pip", "show", package],
            capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace",
        )
        if r.returncode != 0:
            return None
        for line in r.stdout.splitlines():
            if line.startswith("Version:"):
                ver = line.split(":", 1)[1].strip()
                if "+" in ver:
                    return ver.split("+", 1)[1].lower()
                return "" if ver else None
        return None
    except Exception:
        return None


def _package_version(python_executable: str, package: str) -> Optional[str]:
    """查询目标解释器里指定包的版本；未安装返回 None。"""
    try:
        r = subprocess.run(
            [
                python_executable, "-c",
                f"import importlib.metadata as m; print(m.version('{package}'))",
            ],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace",
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    return None


def _version_lt(installed: str, minimum: str) -> bool:
    """比较版本号（x.y.z），installed < minimum 返回 True。"""
    try:
        def _parts(v: str):
            return tuple(int(x) for x in re.split(r"[^\d]+", v)[:3] if x)
        return _parts(installed) < _parts(minimum)
    except Exception:
        return False


def build_cleanup_plan(
    platform_info: PlatformInfo,
    gpu: GPUInfo,
    python_executable: str,
) -> List[str]:
    """找出与当前硬件不匹配、需要先卸载的旧依赖。

    原则：只在明确不匹配时才动，平时不卸载任何包。
    - torch 构建不满足当前显卡要求（如旧版本装了 cu126，RTX 50 需要 cu128，
      或 AMD 机器上装了 CUDA 版 torch）→ 卸载 torch + bitsandbytes；
      若环境中还残留 torchvision/torchaudio/torchtext/torchdata 等旧构建
      （ABI 与新 torch 不匹配），也一并卸载，避免启动时弹
      "无法定位程序输入点" DLL 错误；
    - RTX 50 系且 bitsandbytes 版本过旧（<0.45.5，无 Blackwell 内核）→ 卸载 bnb；
    可用 VULN_SCANNER_SKIP_CLEAN=1 完全关闭自动卸载。

    全程使用 pip 元数据查询构建后缀，避免在主进程 import torch/torchvision，
    防止 Windows 在清理前就弹出 DLL 入口点错误窗口。
    """
    if os.environ.get("VULN_SCANNER_SKIP_CLEAN", "").strip() == "1":
        return []

    plan: List[str] = []
    required = _required_torch_family(platform_info, gpu)
    # 子进程 / pip 元数据查询：不在主进程 import torch
    installed = _query_package_build(python_executable, "torch")

    # 1) torch 构建不匹配：卸载 torch + bnb + 所有 torch C++ 生态包
    if required != "cpu" and installed is not None and not _build_satisfies(installed, required):
        plan.append("torch")
        # torch 构建变了，bitsandbytes 的内核与 torch 绑定，必须一起重装
        if _package_version(python_executable, "bitsandbytes") is not None:
            plan.append("bitsandbytes")
        # 环境里若存在 torchvision/torchaudio 等的旧构建（如 cu126/cu121），与新 torch
        # ABI 不匹配会导致启动时弹 "无法定位程序输入点" 错误；一并卸载让它们随新 torch
        # 重新解析或不再加载（本项目实际不需要它们）。
        for pkg in _TORCH_ABI_PACKAGES:
            if _package_version(python_executable, pkg) is not None:
                plan.append(pkg)

    # 2) RTX 50 系且 bitsandbytes 版本过旧（<0.45.5，无 Blackwell 内核）
    if gpu.vendor == "nvidia" and classify_gpu(gpu).family == "nvidia_50":
        bnb_ver = _package_version(python_executable, "bitsandbytes")
        if bnb_ver is not None and _version_lt(bnb_ver, "0.45.5"):
            plan.append("bitsandbytes")

    # 3) 即使 torch 本身已匹配当前硬件，若环境中残留的 torch C++ 生态包构建与 torch
    # 不一致（例如 torch 已升级到 cu128，但 torchvision 还是 cu126），import 时会触发
    # DLL 入口点错误。这里把构建不一致的也清理掉。
    # 若 torch 未装或查询失败，用 required 作为参考构建继续检测。
    reference_build = installed if installed is not None else required
    if reference_build:
        for pkg in _TORCH_ABI_PACKAGES:
            if _package_version(python_executable, pkg) is None:
                continue
            pkg_build = _query_package_build(python_executable, pkg)
            if pkg_build is None:
                continue
            # 构建后缀必须与 torch 一致；空字符串与 "cpu" 视为等价
            if not _build_eq(pkg_build, reference_build):
                plan.append(pkg)

    return sorted(set(plan))


def _uninstall_packages(
    python_executable: str,
    packages: List[str],
    callback: Optional[Callable[[str], None]] = None,
) -> None:
    """卸载指定包；失败不阻断后续安装（pip install 仍会覆盖）。"""
    if not packages:
        return
    try:
        r = subprocess.run(
            [python_executable, "-m", "pip", "uninstall", "-y", *packages],
            capture_output=True, text=True, timeout=300,
            encoding="utf-8", errors="replace",
        )
        if r.returncode == 0:
            _emit(f"[依赖安装] 已卸载: {', '.join(packages)}", callback)
        else:
            _emit(
                f"[依赖安装] 卸载 {', '.join(packages)} 未完全成功"
                f"（pip 退出码 {r.returncode}），继续安装会覆盖，一般不影响",
                callback,
            )
    except Exception as e:  # noqa: BLE001
        _emit(f"[依赖安装] 卸载 {', '.join(packages)} 异常: {e}（继续安装）", callback)


def discover_best_python(
    platform_info: Optional[PlatformInfo] = None,
    gpu: Optional[GPUInfo] = None,
) -> Optional[str]:
    """为当前硬件寻找一个 torch 构建匹配的 python 解释器。

    解决"不同用户必须分配到合适依赖"：不同机器/环境可能装了不同 torch 构建，
    本函数优先返回当前解释器（若其 torch 已匹配硬件），否则在 conda 环境里
    寻找一个 torch 构建匹配的解释器。找不到或非 GPU 场景返回 None。

    返回的路径可交给启动器重新执行（re-exec），从而自动用对的环境跑推理后端，
    避免"装了 CUDA 版 torch 的 base/graproj 在 AMD 机器上落到 CPU"。
    """
    if platform_info is None:
        platform_info = detect_platform()
    if gpu is None:
        gpu = detect_gpu(platform_info)

    required = _required_torch_family(platform_info, gpu)
    # CPU 族不需要特定 torch 构建，无需切换环境
    if not required.startswith(("cu", "rocm")):
        return None

    # 当前解释器已匹配 → 无需切换（用 pip 元数据查询，避免 import 触发 DLL 错误）
    cur = _query_package_build(sys.executable, "torch")
    if cur is not None and cur.startswith(required):
        return sys.executable

    # 扫描 conda 环境，找一个 torch 匹配的（同样用 pip 元数据，避免子进程 import 出窗）
    for env_py in _list_conda_env_pythons():
        build = _query_package_build(env_py, "torch")
        if build is not None and build.startswith(required):
            return env_py
    return None


def install_backend_dependencies(
    backend: str,
    python_executable: Optional[str] = None,
    dry_run: bool = False,
    auto_confirm: Optional[bool] = None,
    callback: Optional[Callable[[str], None]] = None,
) -> bool:
    """自动安装指定后端的依赖。

    Args:
        backend: "transformers" 或 "llamacpp"
        python_executable: 目标 Python 解释器（默认 sys.executable）
        dry_run: 为 True 时只打印安装命令，不执行
        auto_confirm: True 不询问；False 只检测不安装；None 按环境变量/默认自动安装
        callback: 进度回调函数，接收字符串消息

    Returns:
        True 表示依赖已就绪；False 表示有缺失且安装失败/被取消。
    """
    if auto_confirm is False:
        # 仅检测模式：报告缺失 / 过旧 / 不匹配的完整状态
        python_executable = python_executable or sys.executable
        platform_info = detect_platform()
        gpu = detect_gpu(platform_info)
        specs = get_backend_requirements(backend, platform_info, gpu, python_executable)
        torch_spec_idx = next(
            (i for i, s in enumerate(specs) if s.check_modules == ["torch"]), None
        )
        torch_mismatch = (
            torch_spec_idx is not None
            and torch_needs_reinstall(platform_info, gpu, python_executable)
        )
        for spec in specs:
            if not spec.required:
                continue
            if getattr(spec, "blocked", False):
                _emit(f"[检测] ⛔ {spec.description}：{spec.blocked_message}", callback)
                return False
            status, reason = _spec_status(spec, python_executable, torch_mismatch)
            if status != "ok":
                _emit(f"[检测] {spec.description} -> {reason}", callback)
                return False
        _emit(f"[检测] {backend} 后端依赖已就绪（版本与硬件匹配）", callback)
        return True

    python_executable = python_executable or sys.executable
    platform_info = detect_platform()
    gpu = detect_gpu(platform_info)

    _emit(f"[依赖安装] 后端: {backend} | 系统: {platform_info.os_name}/{platform_info.arch} | GPU: {gpu.vendor or '无'}", callback)

    specs = get_backend_requirements(backend, platform_info, gpu, python_executable)

    # 当前平台/硬件不支持的后端（如 Windows 上的 vLLM）：直接拦截，不触发 pip
    blocked_specs = [s for s in specs if getattr(s, "blocked", False)]
    if blocked_specs:
        for s in blocked_specs:
            _emit(f"[依赖安装] ⛔ {s.description}", callback)
            if s.blocked_message:
                _emit(f"  {s.blocked_message}", callback)
            if s.warning:
                _emit(f"  {s.warning}", callback)
        _emit("[依赖安装] 已取消安装。请更换后端（推荐 ollama / llamacpp），"
              "或到支持该后端的平台上运行。", callback)
        return False

    # torch 构建必须匹配当前硬件（CUDA/ROCm/CPU）。
    # 之前只检查"torch 是否已 import"，导致 CUDA 版 torch 在 AMD/ROCm 机器上被误判
    # 为已就绪而跳过，模型最终加载到 CPU。这里识别出"torch 存在但构建不匹配"，
    # 强制重装为正确版本。
    torch_spec_idx = next(
        (i for i, s in enumerate(specs) if s.check_modules == ["torch"]), None
    )
    current_torch_build = _query_package_build(python_executable, "torch")
    torch_mismatch = (
        torch_spec_idx is not None
        and torch_needs_reinstall(platform_info, gpu, python_executable)
    )
    if torch_mismatch:
        _emit(
            f"[依赖安装] 检测到 torch 构建不匹配（本机需要 "
            f"{_required_torch_family(platform_info, gpu)}，当前 "
            f"{current_torch_build or '未安装'}），将重装为匹配本机硬件的版本",
            callback,
        )
    # 旧版本留下的不兼容依赖：先卸载再装
    # 即使 torch 本身已匹配，也可能残留 torchvision/torchaudio 旧构建导致 DLL 入口点错误
    cleanup_plan = build_cleanup_plan(platform_info, gpu, python_executable)
    if cleanup_plan:
        _emit(
            f"[依赖安装] 检测到需清理的旧依赖: {', '.join(cleanup_plan)}"
            "（将先卸载再安装匹配版本）",
            callback,
        )

    # 先检查必须 spec 是否已全部就绪（含版本过旧 / GPU 构建不匹配）
    if not _force_reinstall():
        all_ready = True
        for spec in specs:
            if not spec.required:
                continue
            status, reason = _spec_status(spec, python_executable, torch_mismatch)
            if status != "ok":
                all_ready = False
                _emit(f"[依赖安装] 检测: {spec.description} -> {reason}", callback)
                break
        # 即使所有 required spec 都已就绪，若检测到有需清理的不兼容旧依赖
        # （如 torchvision/torchaudio 构建与 torch 不匹配），仍要先卸载它们，
        # 否则 import 时会触发 DLL 入口点错误。
        if all_ready and cleanup_plan:
            all_ready = False
            _emit(
                f"[依赖安装] 当前 torch 已匹配，但仍需先清理旧依赖: {', '.join(cleanup_plan)}",
                callback,
            )
        if all_ready:
            _emit(f"[依赖安装] {backend} 后端依赖已就绪（版本与硬件匹配），跳过安装", callback)
            return True

    if dry_run:
        _emit("[依赖安装] DRY-RUN 模式，仅展示命令：", callback)
        if cleanup_plan:
            _emit("  先卸载旧依赖：", callback)
            _emit(
                f"    {python_executable} -m pip uninstall -y {' '.join(cleanup_plan)}",
                callback,
            )
        for spec in specs:
            if spec.warning:
                _emit(f"  ⚠️ {spec.warning}", callback)
            if not spec.packages:
                continue
            cmd = _build_pip_cmd(spec, python_executable)
            env_repr = " ".join(f'{k}="{v}"' for k, v in spec.env.items()) if spec.env else ""
            _emit(f"  [{spec.description}]", callback)
            _emit(f"    {env_repr + ' ' if env_repr else ''}{' '.join(cmd)}", callback)
        return True

    # 实际安装
    if not _is_auto_install_enabled():
        _emit("[依赖安装] 已禁用自动安装（VULN_SCANNER_AUTO_INSTALL_DEPS=0）", callback)
        _emit("[依赖安装] 请手动执行以下命令：", callback)
        if cleanup_plan:
            _emit(f"  先卸载旧依赖: {python_executable} -m pip uninstall -y {' '.join(cleanup_plan)}", callback)
        for spec in specs:
            if not spec.packages:
                continue
            cmd = _build_pip_cmd(spec, python_executable)
            env_repr = " ".join(f'{k}="{v}"' for k, v in spec.env.items()) if spec.env else ""
            _emit(f"  {env_repr + ' ' if env_repr else ''}{' '.join(cmd)}", callback)
        return False

    auto = auto_confirm if auto_confirm is not None else True
    if not auto:
        answer = input(f"[依赖安装] 将为 {backend} 后端安装依赖（可能下载数 GB），是否继续？[Y/n]: ").strip().lower()
        if answer and answer not in ("y", "yes"):
            _emit("[依赖安装] 用户取消安装", callback)
            return False

    if cleanup_plan:
        _uninstall_packages(python_executable, cleanup_plan, callback)

    overall_ok = True
    for spec in specs:
        if spec.warning:
            _emit(f"[依赖安装] ⚠️ {spec.warning}", callback)
        if not spec.packages:
            continue

        # 统一检测：缺失 / 版本过旧 / 版本或 GPU 构建不匹配
        status, reason = _spec_status(spec, python_executable, torch_mismatch)
        if status == "ok" and not _force_reinstall():
            _emit(f"[依赖安装] {spec.description} 已就绪且匹配，跳过", callback)
            continue
        if status != "ok":
            _emit(f"[依赖安装] 检测: {spec.description} -> {reason}", callback)

        # 已安装但版本/构建不匹配（或强制重装）时，先卸载旧包再安装。
        # 同版本 CPU→GPU 替换必须卸载，否则 pip 认为已满足而不覆盖。
        primary = _spec_package_name(spec)
        primary_installed = _package_version(python_executable, primary) is not None
        torch_handled = torch_mismatch and spec.check_modules == ["torch"]
        skip_clean = os.environ.get("VULN_SCANNER_SKIP_CLEAN", "").strip() == "1"
        if (
            primary_installed
            and spec.cleanup_on_mismatch
            and not torch_handled
            and not skip_clean
            and (status == "mismatch" or _force_reinstall())
        ):
            _uninstall_packages(python_executable, [primary], callback)

        # llama-cpp-python CUDA/Metal wheel 在 GitHub Releases，国内直连易被掐断。
        # 若配置了 mirror_wheel_url，先经 ghproxy 镜像下载到本地，再用本地文件安装；
        # 镜像失败时回退正常 pip（abetlen 索引），不阻断安装流程。
        local_wheel = _download_wheel_via_mirror(spec, callback)
        if local_wheel is not None:
            spec.packages = [str(local_wheel)]
            spec.index_url = None
            spec.extra_index_url = None
            spec.prefer_index_url = False

        cmd = _build_pip_cmd(spec, python_executable)
        env = os.environ.copy()
        env.update(spec.env)

        _emit(f"[依赖安装] 正在安装: {spec.description}...", callback)
        _emit(f"[依赖安装] 命令: {' '.join(cmd)}", callback)

        try:
            # 流式执行：实时显示下载进度；总时长上限可配（默认 2 小时，0=不限）
            returncode, output = _run_pip_install(cmd, env, spec.description, callback)
            if returncode != 0:
                _emit(f"[依赖安装] ❌ {spec.description} 安装失败（退出码 {returncode}）", callback)
                # 打印最后 800 字符帮助诊断
                tail = output.strip()[-800:] if output else ""
                if tail:
                    _emit(f"[依赖安装] 日志尾部:\n{tail}", callback)
                overall_ok = False
                if spec.required:
                    break
            else:
                _emit(f"[依赖安装] ✅ {spec.description} 安装完成", callback)
                if spec.version_marker:
                    ver = _installed_package_version(python_executable, _spec_package_name(spec))
                    if spec.version_marker not in ver:
                        _emit(
                            f"[依赖安装] ❌ {spec.description} 安装后版本为 {ver or '未知'}，"
                            f"未包含 GPU 标记 '{spec.version_marker}'，可能回退到了 CPU wheel",
                            callback,
                        )
                        overall_ok = False
                        if spec.required:
                            break
                if spec.gpu_probe:
                    if not _probe_gpu_support(python_executable, spec.gpu_probe):
                        _emit(
                            f"[依赖安装] ❌ {spec.description} 安装后 GPU 探测失败"
                            "（llama_supports_gpu_offload()=False），可能回退到了 CPU-only 版本",
                            callback,
                        )
                        overall_ok = False
                        if spec.required:
                            break
        except Exception as e:
            _emit(f"[依赖安装] ❌ {spec.description} 安装异常: {e}", callback)
            overall_ok = False
            if spec.required:
                break

    # 二次校验
    if overall_ok:
        for spec in specs:
            if not spec.required:
                continue
            status, reason = _spec_status(spec, python_executable, torch_mismatch)
            if status != "ok":
                _emit(f"[依赖安装] ❌ 安装后校验失败: {spec.description} -> {reason}", callback)
                overall_ok = False
                break
        if overall_ok:
            _emit(f"[依赖安装] ✅ {backend} 后端依赖全部就绪（版本与硬件匹配）", callback)
    else:
        _emit(f"[依赖安装] 部分依赖安装失败，可尝试：", callback)
        _emit(f"  1. 设置 VULN_SCANNER_AUTO_INSTALL_DEPS=0 后手动安装", callback)
        _emit(f"  2. 或设置 VULN_SCANNER_BACKEND=ollama 改用 Ollama 后端", callback)

    return overall_ok


# ---------------------------------------------------------------------------
# 安全工具安装（新框架：两阶段/外部扫描所需的传统 SAST/SCA/Secret 工具）
# ---------------------------------------------------------------------------

# pip 可安装的 CLI 工具（跨平台可靠，用于 external_scanner / two_stage Stage 1）。
# 键为可执行名（用于 PATH 探测），值为安装时的版本下限（自动装到最新稳定版）。
SECURITY_TOOLS_PIP: list[str] = ["bandit", "semgrep", "pip-audit", "detect-secrets"]
# 各 pip 工具的“最新稳定版本”下限（2026-08 核实的最新发布版本）：
#   bandit          1.9.4
#   semgrep         1.172.0
#   pip-audit       2.10.1
#   detect-secrets  1.5.0
SECURITY_TOOLS_PIP_SPEC: dict[str, str] = {
    "bandit": "bandit>=1.9.4",
    "semgrep": "semgrep>=1.172.0",
    "pip-audit": "pip-audit>=2.10.1",
    "detect-secrets": "detect-secrets>=1.5.0",
}
# 独立二进制工具（经系统包管理器安装，最佳努力：失败仅告警不阻断）
SECURITY_TOOLS_BIN: dict[str, str] = {
    "gitleaks": "Gitleaks.Gitleaks",   # winget 包 ID（最新稳定：8.30.1）
    "trivy": "AquaSecurity.Trivy",     # winget 包 ID（最新稳定：0.73.0）
}
# 全部安全工具（供安装/卸载/状态汇总共用）
SECURITY_TOOLS_ALL: list[str] = SECURITY_TOOLS_PIP + list(SECURITY_TOOLS_BIN.keys())


def _tool_installed(name: str) -> bool:
    """判断命令行工具是否已安装（在 PATH 中）。"""
    return shutil.which(name) is not None


def _find_winget_install(tool: str) -> bool:
    """Windows 下在 winget 常见安装目录探测工具可执行文件。

    winget 安装的便携工具通常落在：
      %LOCALAPPDATA%\\Microsoft\\WinGet\\Packages\\<Publisher>\\<Pkg>\\<ver>\\
    gitleaks/trivy 的可执行文件位于其中某个子目录。此函数在用户级与系统级
    WinGet 目录里递归查找 <tool>.exe，命中即返回 True（不依赖 PATH）。
    """
    if sys.platform != "win32":
        return False
    exe_name = f"{tool}.exe"
    bases = []
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        bases.append(Path(local_app_data) / "Microsoft" / "WinGet" / "Packages")
    program_data = os.environ.get("ProgramData")
    if program_data:
        bases.append(Path(program_data) / "Microsoft" / "WinGet" / "Packages")
    for base in bases:
        if not base.is_dir():
            continue
        try:
            for candidate in base.rglob(exe_name):
                if candidate.is_file():
                    return True
        except Exception:
            continue
    return False


def _refresh_process_path() -> None:
    """Windows 下从注册表重新读取 PATH，刷新生效到当前进程。

    winget / 安装器写完系统/用户 PATH 后，当前进程的 os.environ["PATH"] 不会自动
    更新，导致 shutil.which() 找不到刚装好的工具。此函数把注册表中的 PATH 合并回
    当前进程，使安装结果立即可见（无需重启终端）。
    """
    if sys.platform != "win32":
        return
    try:
        import winreg
    except Exception:
        return

    new_paths: list[str] = []
    # 系统级 + 用户级 PATH，按序读取（系统在前、用户在后，与 Windows 解析顺序一致）
    for root, subkey in (
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
        (winreg.HKEY_CURRENT_USER, r"Environment"),
    ):
        try:
            with winreg.OpenKey(root, subkey) as key:
                value, _ = winreg.QueryValueEx(key, "Path")
                new_paths.append(value or "")
        except Exception:
            continue

    registry_path = os.pathsep.join(p for p in new_paths if p)
    if not registry_path:
        return
    # 保留当前进程已有的、注册表里没有的条目（如虚拟环境），避免丢失
    current = os.environ.get("PATH", "")
    merged = registry_path
    for item in current.split(os.pathsep):
        if item and item not in merged.split(os.pathsep):
            merged += os.pathsep + item
    os.environ["PATH"] = merged
    # 让 shutil 重新解析
    try:
        import importlib
        importlib.reload(shutil)
    except Exception:
        pass


def _try_install_binary_tool(
    tool: str,
    platform_info: PlatformInfo,
    dry_run: bool,
    callback: Optional[Callable[[str], None]] = None,
) -> None:
    """最佳努力安装独立二进制工具（gitleaks / trivy），失败仅告警。
    经系统包管理器安装；无法自动安装时给出手动指引。
    """
    if dry_run:
        _emit(f"[安全工具] DRY-RUN: 将安装二进制工具 {tool}", callback)
        return

    if platform_info.os_name == "windows":
        if shutil.which("winget"):
            pkg = SECURITY_TOOLS_BIN[tool]
            _emit(f"[安全工具] 使用 winget 安装 {tool}...", callback)
            cmd = ["winget", "install", pkg, "--silent",
                   "--accept-source-agreements", "--accept-package-agreements",
                   "--disable-interactivity"]
            try:
                r = _run_quiet(cmd, timeout=1800)
                # winget 退出码 0 = 安装成功，但新目录可能不在当前进程 PATH：
                # 先刷新注册表 PATH，再探测常见 winget Links / Packages 目录
                _refresh_process_path()
                found = _tool_installed(tool) or _find_winget_install(tool)
                if r[0] == 0 and found:
                    _emit(f"[安全工具] ✅ {tool} 安装完成", callback)
                elif r[0] == 0 and not found:
                    _emit(f"[安全工具] ✓ {tool} 已安装（退出码 0），但未加入 PATH，"
                          f"请重启终端后再使用", callback)
                else:
                    _emit(f"[安全工具] ⚠ {tool} winget 安装未成功（退出码 {r[0]}），可手动安装", callback)
            except Exception as e:
                _emit(f"[安全工具] ⚠ {tool} 安装异常: {e}", callback)
        else:
            _emit(f"[安全工具] 未检测到 winget，请手动安装 {tool}（GitHub Releases）", callback)

    elif platform_info.os_name == "darwin":
        if shutil.which("brew"):
            _emit(f"[安全工具] 使用 Homebrew 安装 {tool}...", callback)
            cmd = ["brew", "install", tool]
            try:
                r = _run_quiet(cmd, timeout=1800)
                if r[0] == 0 and _tool_installed(tool):
                    _emit(f"[安全工具] ✅ {tool} 安装完成", callback)
                else:
                    _emit(f"[安全工具] ⚠ {tool} brew 安装未成功，可手动安装", callback)
            except Exception as e:
                _emit(f"[安全工具] ⚠ {tool} 安装异常: {e}", callback)
        else:
            _emit(f"[安全工具] 未检测到 brew，请手动安装 {tool}（GitHub Releases）", callback)

    else:
        # Linux：尝试常见包管理器，否则提示手动安装
        pm_cmds = [
            ["apt-get", "install", "-y", tool],
            ["dnf", "install", "-y", tool],
            ["pacman", "-S", "--noconfirm", tool],
            ["zypper", "install", "-y", tool],
        ]
        installed = False
        for cmd in pm_cmds:
            if shutil.which(cmd[0]):
                _emit(f"[安全工具] 使用 {cmd[0]} 安装 {tool}...", callback)
                try:
                    r = _run_quiet([c for c in cmd], timeout=1800)
                    if r[0] == 0 and _tool_installed(tool):
                        _emit(f"[安全工具] ✅ {tool} 安装完成", callback)
                        installed = True
                        break
                except Exception:
                    pass
        if not installed:
            _emit(f"[安全工具] 请手动安装 {tool}（GitHub Releases / 系统包管理器）", callback)


def install_security_tools(
    python_executable: Optional[str] = None,
    dry_run: bool = False,
    auto_confirm: Optional[bool] = None,
    callback: Optional[Callable[[str], None]] = None,
) -> bool:
    """启动前自动下载新框架所需的传统安全工具。

    - pip 工具（bandit / semgrep / pip-audit / detect-secrets）：缺失即 pip 安装
    - 二进制工具（gitleaks / trivy）：经系统包管理器最佳努力安装，失败不阻断

    返回 True 表示核心 pip 工具已就绪（二进制工具缺失仅告警，不影响核心两阶段扫描）。
    """
    python_executable = python_executable or sys.executable
    platform_info = detect_platform()

    _emit("[安全工具] 检查新框架所需传统工具 "
          f"({', '.join(SECURITY_TOOLS_ALL)})...", callback)

    # 1) pip 可安装工具
    missing_pip = [t for t in SECURITY_TOOLS_PIP if not _tool_installed(t)]
    missing_pip_spec = [SECURITY_TOOLS_PIP_SPEC.get(t, t) for t in missing_pip]
    if missing_pip:
        _emit(f"[安全工具] 缺失 pip 工具: {', '.join(missing_pip_spec)}", callback)
        if dry_run:
            _emit(f"[安全工具] DRY-RUN: pip install {' '.join(missing_pip_spec)}", callback)
        elif _is_auto_install_enabled():
            cmd = _pip_base_cmd(python_executable) + missing_pip_spec
            global_index = os.environ.get("VULN_SCANNER_PIP_INDEX", "").strip()
            if global_index:
                cmd.extend(["--index-url", global_index])
            _add_pip_network_flags(cmd)
            _emit(f"[安全工具] 正在安装: {' '.join(cmd)}", callback)
            returncode, output = _run_pip_install(
                cmd, os.environ.copy(), "安全工具", callback,
            )
            if returncode == 0:
                _emit("[安全工具] ✅ pip 工具安装完成", callback)
            else:
                _emit(f"[安全工具] ❌ pip 工具安装失败（退出码 {returncode}）", callback)
                tail = output.strip()[-800:] if output else ""
                if tail:
                    _emit(f"[安全工具] 日志尾部:\n{tail}", callback)
        else:
            _emit("[安全工具] 自动安装已禁用，请手动: "
                  f"pip install {' '.join(missing_pip_spec)}", callback)
    else:
        _emit("[安全工具] pip 工具已就绪", callback)

    # 2) 独立二进制工具（最佳努力）
    for tool in SECURITY_TOOLS_BIN:
        if _tool_installed(tool):
            _emit(f"[安全工具] {tool} 已就绪", callback)
        else:
            _try_install_binary_tool(tool, platform_info, dry_run, callback)

    # 汇总：核心（pip）工具必须就绪；二进制缺失仅告警
    missing_pip = [t for t in SECURITY_TOOLS_PIP if not _tool_installed(t)]
    if missing_pip:
        _emit(f"[安全工具] ⚠ 核心工具仍缺失: {', '.join(missing_pip)}（外部工具扫描会静默跳过）", callback)
        return False
    _emit("[安全工具] ✅ 核心安全工具就绪", callback)
    return True


def _emit(message: str, callback: Optional[Callable[[str], None]] = None) -> None:
    """输出消息，同时调用回调。"""
    print(message)
    if callback is not None:
        try:
            callback(message)
        except Exception:
            pass


def print_manual_install_commands(backend: str, python_executable: Optional[str] = None) -> None:
    """打印手动安装命令（用于失败后的回退提示）。"""
    python_executable = python_executable or sys.executable
    platform_info = detect_platform()
    gpu = detect_gpu(platform_info)
    specs = get_backend_requirements(backend, platform_info, gpu, python_executable)
    print(f"# 手动安装 {backend} 后端依赖（{platform_info.os_name}/{platform_info.arch}, GPU={gpu.vendor or '无'}）")
    for spec in specs:
        if spec.warning:
            print(f"# ⚠️ {spec.warning}")
        if not spec.packages:
            continue
        cmd = _build_pip_cmd(spec, python_executable)
        env_repr = " ".join(f'{k}="{v}"' for k, v in spec.env.items()) if spec.env else ""
        print(f"{env_repr + ' ' if env_repr else ''}{' '.join(cmd)}")


if __name__ == "__main__":
    # 命令行入口：python -m app.launcher.dependency_installer [transformers|llamacpp|tools] [--dry-run]
    import argparse

    parser = argparse.ArgumentParser(description="推理后端 / 安全工具依赖自动安装器")
    parser.add_argument("target", choices=["transformers", "llamacpp", "vllm", "tools"], help="安装目标：推理后端或安全工具")
    parser.add_argument("--dry-run", action="store_true", help="仅打印安装命令")
    parser.add_argument("--python", default=sys.executable, help="目标 Python 解释器")
    args = parser.parse_args()

    if args.target == "tools":
        ok = install_security_tools(python_executable=args.python, dry_run=args.dry_run)
    else:
        ok = install_backend_dependencies(args.target, python_executable=args.python, dry_run=args.dry_run)
    sys.exit(0 if ok else 1)
