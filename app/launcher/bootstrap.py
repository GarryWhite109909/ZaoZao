"""
启动器 —— 首次使用检测 Ollama + 模型，后续直接启动后端 + 打开浏览器。

跨平台入口：
    python -m app.launcher.bootstrap

启动脚本：
    Windows: 双击 start_windows.bat
    Linux/macOS: bash start_linux_macos.sh
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

import requests

# 项目根目录（Graduation-Project/）
PROJECT_ROOT = Path(__file__).resolve().parents[2]
# 默认模型（发布到 Ollama Registry 的 SFT，可通过环境变量切换版本）
DEFAULT_MODEL = os.environ.get("VULN_SCANNER_MODEL", "garrywhite109909/graduation-vuln-scanner:v5")
# 回退模型（官方 Qwen3-8B，未微调）
FALLBACK_MODEL = os.environ.get("VULN_SCANNER_FALLBACK_MODEL", "qwen3:8b")
# 后端端口
PORT = 8765


def check_ollama_installed() -> bool:
    """检测系统是否安装 Ollama。"""
    return shutil.which("ollama") is not None


def try_install_ollama() -> bool:
    """尝试自动安装 Ollama。成功返回 True，失败回退到打开下载页。"""
    print("[启动器] 未检测到 Ollama，尝试自动安装...")

    if sys.platform == "win32":
        # Windows: 优先 winget
        if shutil.which("winget"):
            print("[启动器] 使用 winget 安装 Ollama...")
            try:
                result = subprocess.run(
                    ["winget", "install", "Ollama.Ollama",
                     "--accept-source-agreements", "--accept-package-agreements"],
                    timeout=600,
                )
                if result.returncode == 0 and check_ollama_installed():
                    print("[启动器] Ollama 安装完成。")
                    return True
                print(f"[启动器] winget 退出码 {result.returncode}。")
            except subprocess.TimeoutExpired:
                print("[启动器] winget 安装超时。")
        else:
            print("[启动器] 未检测到 winget，无法自动安装。")
        webbrowser.open("https://ollama.com/download")
        return False

    elif sys.platform == "darwin":
        # macOS: 优先 Homebrew
        if shutil.which("brew"):
            print("[启动器] 使用 Homebrew 安装 Ollama...")
            try:
                result = subprocess.run(
                    ["brew", "install", "ollama"],
                    timeout=600,
                )
                if result.returncode == 0 and check_ollama_installed():
                    print("[启动器] Ollama 安装完成。")
                    return True
                print(f"[启动器] brew 退出码 {result.returncode}。")
            except subprocess.TimeoutExpired:
                print("[启动器] brew 安装超时。")
        else:
            print("[启动器] 未检测到 brew，无法自动安装。")
        webbrowser.open("https://ollama.com/download")
        return False

    else:
        # Linux: 官方一键脚本（可能需要 sudo 密码）
        print("[启动器] 使用官方脚本安装 Ollama（如提示请输入 sudo 密码）...")
        try:
            result = subprocess.run(
                ["bash", "-c", "curl -fsSL https://ollama.com/install.sh | sh"],
                timeout=600,
            )
            if result.returncode == 0 and check_ollama_installed():
                print("[启动器] Ollama 安装完成。")
                return True
            print(f"[启动器] 安装脚本退出码 {result.returncode}。")
        except subprocess.TimeoutExpired:
            print("[启动器] 安装超时。")
        webbrowser.open("https://ollama.com/download")
        return False


def ensure_ollama_running() -> bool:
    """确保 Ollama 服务在运行。未运行则尝试启动。"""
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=3)
        return resp.status_code == 200
    except Exception:
        # 尝试后台启动 ollama serve
        print("[启动器] Ollama 服务未运行，尝试启动...")
        try:
            if sys.platform == "win32":
                subprocess.Popen(
                    ["ollama", "serve"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.Popen(
                    ["ollama", "serve"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            time.sleep(3)
            resp = requests.get("http://localhost:11434/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception as e:
            print(f"[启动器] 启动 Ollama 失败: {e}")
            return False


def list_ollama_models() -> list[str]:
    """列出已 pull 的模型。"""
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=5)
        data = resp.json()
        return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


def ensure_model_available(model: str) -> bool:
    """确保模型已 pull。未 pull 则自动从 Ollama Registry 下载。"""
    models = list_ollama_models()
    # 精确匹配（Ollama 模型名含 tag，不需要模糊匹配）
    if model in models:
        return True

    print(f"[启动器] 首次使用，正在下载模型 {model}（约 5GB，请耐心等待）...")
    print(f"[启动器] 下载过程中可以关闭此窗口，下次启动会继续。")
    try:
        result = subprocess.run(
            ["ollama", "pull", model],
            timeout=1800,  # 30 分钟超时
        )
        if result.returncode == 0:
            print(f"[启动器] 模型 {model} 下载完成。")
            return True
        print(f"[启动器] 模型下载失败（退出码 {result.returncode}）。")
        print(f"[启动器] 请检查网络后重试，或手动运行：ollama pull {model}")
        return False
    except subprocess.TimeoutExpired:
        print("[启动器] 模型下载超时（30 分钟未完成）。")
        print(f"[启动器] 请检查网络后重试，或手动运行：ollama pull {model}")
        return False


def start_backend(port: int = PORT) -> subprocess.Popen:
    """启动 FastAPI 后端。"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    # 防止 OOM：限制 Ollama 并发请求数和常驻模型数
    env.setdefault("OLLAMA_NUM_PARALLEL", "1")
    env.setdefault("OLLAMA_MAX_LOADED_MODELS", "1")

    cmd = [
        sys.executable, "-m", "uvicorn",
        "app.backend.main:app",
        "--host", "127.0.0.1",
        "--port", str(port),
    ]
    print(f"[启动器] 启动后端：http://127.0.0.1:{port}")
    proc = subprocess.Popen(cmd, env=env, cwd=str(PROJECT_ROOT))
    return proc


def wait_for_backend(port: int, timeout: int = 30) -> bool:
    """等待后端就绪。"""
    for _ in range(timeout):
        try:
            resp = requests.get(f"http://127.0.0.1:{port}/api/health", timeout=2)
            if resp.status_code == 200:
                return True
        except Exception:
            time.sleep(1)
    return False


def detect_hardware() -> dict:
    """检测本机硬件（GPU/CPU/RAM）。跨平台、无额外依赖。

    返回字典结构：
        {
            "has_nvidia_gpu": bool,
            "has_amd_gpu": bool,
            "gpu_name": str | None,
            "vram_mb": int | None,
            "cpu_cores": int,
            "ram_gb": float,
            "platform": str,
        }
    """
    hardware: dict = {
        "has_nvidia_gpu": False,
        "has_amd_gpu": False,
        "gpu_name": None,
        "vram_mb": None,
        "cpu_cores": os.cpu_count() or 4,
        "ram_gb": 0.0,
        "platform": sys.platform,
    }

    # 1) NVIDIA GPU 检测：优先 nvidia-smi（跨平台，Windows/Linux 都可用）
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            line = result.stdout.strip().splitlines()[0]
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2 and parts[0]:
                hardware["has_nvidia_gpu"] = True
                hardware["gpu_name"] = parts[0]
                try:
                    hardware["vram_mb"] = int(parts[1])
                except ValueError:
                    hardware["vram_mb"] = None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # 2) nvidia-smi 失败则尝试 torch.cuda（torch 是 sentence-transformers 的间接依赖）
    if not hardware["has_nvidia_gpu"]:
        try:
            import torch  # type: ignore
            if torch.cuda.is_available():
                hardware["has_nvidia_gpu"] = True
                hardware["gpu_name"] = torch.cuda.get_device_name(0)
                props = torch.cuda.get_device_properties(0)
                hardware["vram_mb"] = int(props.total_memory // 1024 // 1024)
        except Exception:
            pass

    # 3) macOS Apple Silicon 检测（统一内存架构，无独立显存统计）
    if sys.platform == "darwin" and not hardware["has_nvidia_gpu"]:
        try:
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=3,
            )
            brand = result.stdout.strip()
            if "Apple M" in brand:
                hardware["gpu_name"] = brand
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    # 4) AMD/ROCm GPU 检测（Linux 优先 rocm-smi，再读 sysfs；Windows 用 wmic）
    if not hardware["has_nvidia_gpu"] and not hardware["gpu_name"]:
        if sys.platform.startswith("linux"):
            # 4a) rocm-smi 是 ROCm 驱动自带的工具，最可靠
            try:
                result = subprocess.run(
                    ["rocm-smi", "--showproductname"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip():
                    for line in result.stdout.strip().splitlines():
                        line = line.strip()
                        # 典型输出: "GPU[0]          : Card Series:          AMD Radeon RX 9060 XT"
                        if "Card Series" in line:
                            parts = line.split(":", 2)
                            if len(parts) >= 3 and parts[2].strip():
                                hardware["has_amd_gpu"] = True
                                hardware["gpu_name"] = parts[2].strip()
                                break
                # 显存：rocm-smi --showmeminfo vram 输出为字节
                if hardware["has_amd_gpu"]:
                    try:
                        mem_result = subprocess.run(
                            ["rocm-smi", "--showmeminfo", "vram"],
                            capture_output=True, text=True, timeout=5,
                        )
                        if mem_result.returncode == 0 and mem_result.stdout.strip():
                            for line in mem_result.stdout.strip().splitlines():
                                if "Total Memory" in line:
                                    parts = line.split(":", 2)
                                    if len(parts) >= 3:
                                        try:
                                            hardware["vram_mb"] = int(parts[2].strip()) // 1024 // 1024
                                        except ValueError:
                                            pass
                                    break
                    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                        pass
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass

            # 4b) rocm-smi 不存在时，读 sysfs 中的 AMD GPU 拓扑信息
            if not hardware["has_amd_gpu"]:
                try:
                    kfd_nodes = Path("/sys/class/kfd/kfd/topology/nodes")
                    if kfd_nodes.is_dir():
                        for node_dir in sorted(kfd_nodes.iterdir()):
                            props_path = node_dir / "properties"
                            if not props_path.is_file():
                                continue
                            props = props_path.read_text(encoding="utf-8", errors="ignore")
                            # vendor_id 0x1002 / 4098 为 AMD；跳过 vendor_id 0 的 CPU 节点
                            if ("vendor_id 0x1002" in props or "vendor_id 4098" in props):
                                # 显存大小在 mem_banks/0/properties 的 size_in_bytes 行
                                vram_mb = None
                                mem_props_path = node_dir / "mem_banks" / "0" / "properties"
                                if mem_props_path.is_file():
                                    try:
                                        mem_props = mem_props_path.read_text(encoding="utf-8", errors="ignore")
                                        for p in mem_props.splitlines():
                                            if p.startswith("size_in_bytes "):
                                                vram_mb = int(p.split(" ", 1)[1].strip()) // 1024 // 1024
                                                break
                                    except (ValueError, OSError):
                                        pass
                                hardware["has_amd_gpu"] = True
                                hardware["gpu_name"] = "AMD GPU"
                                hardware["vram_mb"] = vram_mb
                                break
                except (OSError, PermissionError):
                    pass

            # 4c) 若 sysfs 只给出通用名称，尝试用 lspci 获取具体型号
            if hardware["has_amd_gpu"] and hardware["gpu_name"] == "AMD GPU":
                try:
                    result = subprocess.run(
                        ["lspci", "-nn"],
                        capture_output=True, text=True, timeout=5,
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        for line in result.stdout.strip().splitlines():
                            if "VGA" in line and ("AMD" in line or "Radeon" in line or "ATI" in line):
                                # 提取方括号后的描述文本
                                desc = line.split(":", 2)[-1].strip()
                                # 去掉尾部的 [1002:xxxx] 设备 ID
                                desc = desc.split(" [1002:")[0].strip()
                                if desc:
                                    hardware["gpu_name"] = desc
                                    break
                except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                    pass

        elif sys.platform == "win32":
            # Windows 下通过 wmic 查找 AMD 显卡
            try:
                result = subprocess.run(
                    ["wmic", "path", "win32_VideoController",
                     "get", "Name,AdapterRAM", "/format:csv"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip():
                    for line in result.stdout.strip().splitlines()[1:]:
                        if "AMD" in line or "Radeon" in line:
                            parts = line.split(",")
                            if len(parts) >= 3:
                                hardware["has_amd_gpu"] = True
                                hardware["gpu_name"] = parts[-2].strip().strip('"')
                                try:
                                    hardware["vram_mb"] = int(parts[-1].strip().strip('"')) // 1024 // 1024
                                except ValueError:
                                    pass
                            break
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass

    # 5) RAM 检测：优先 psutil，否则平台特定回退
    try:
        import psutil  # type: ignore
        hardware["ram_gb"] = round(psutil.virtual_memory().total / 1024 ** 3, 1)
    except Exception:
        if sys.platform.startswith("linux"):
            try:
                ram_bytes = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
                hardware["ram_gb"] = round(ram_bytes / 1024 ** 3, 1)
            except (ValueError, OSError):
                pass
        elif sys.platform == "win32":
            try:
                result = subprocess.run(
                    ["wmic", "ComputerSystem", "get", "TotalPhysicalMemory"],
                    capture_output=True, text=True, timeout=3,
                )
                lines = [l.strip() for l in result.stdout.splitlines()
                         if l.strip().isdigit()]
                if lines:
                    hardware["ram_gb"] = round(int(lines[0]) / 1024 ** 3, 1)
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass
        # 兜底估算：8GB
        if hardware["ram_gb"] == 0.0:
            hardware["ram_gb"] = 8.0

    return hardware


def recommend_config(hardware: dict) -> dict:
    """根据硬件信息返回推荐的 Ollama 推理参数。

    返回字典结构：
        {
            "num_ctx": int,
            "num_gpu": int,
            "num_thread": int,
            "quantization": str,
            "warning": str | None,
            "mode": str,   # "gpu" / "cpu" / "apple_silicon"
        }
    """
    cpu_cores = hardware.get("cpu_cores") or 4
    num_thread = min(cpu_cores, 8)

    is_apple_silicon = (
        sys.platform == "darwin"
        and not hardware.get("has_nvidia_gpu")
        and hardware.get("gpu_name")
        and "Apple M" in hardware["gpu_name"]
    )

    # NVIDIA GPU 分支：按显存分档
    if hardware.get("has_nvidia_gpu") and hardware.get("vram_mb"):
        vram = hardware["vram_mb"]
        if vram >= 8192:
            return {
                "num_ctx": 8192, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "gpu",
            }
        elif vram >= 4096:
            return {
                "num_ctx": 4096, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "gpu",
            }
        else:
            return {
                "num_ctx": 2048, "num_gpu": 0, "num_thread": num_thread,
                "quantization": "q4_k_m",
                "warning": "显存不足，将使用 CPU 推理（速度较慢）",
                "mode": "cpu",
            }

    # AMD/ROCm GPU 分支：Ollama 在 Linux 上支持 ROCm 后端，num_gpu=-1 表示尽量 offload
    if hardware.get("has_amd_gpu") and hardware.get("vram_mb"):
        vram = hardware["vram_mb"]
        if vram >= 8192:
            return {
                "num_ctx": 8192, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "rocm",
            }
        elif vram >= 4096:
            return {
                "num_ctx": 4096, "num_gpu": -1, "num_thread": num_thread,
                "quantization": "q4_k_m", "warning": None, "mode": "rocm",
            }
        else:
            return {
                "num_ctx": 2048, "num_gpu": 0, "num_thread": num_thread,
                "quantization": "q4_k_m",
                "warning": "AMD 显存较小，将使用 CPU 推理（速度较慢）",
                "mode": "cpu",
            }

    # Apple Silicon 分支：Metal 加速
    if is_apple_silicon:
        return {
            "num_ctx": 4096, "num_gpu": 1, "num_thread": num_thread,
            "quantization": "q4_k_m", "warning": None, "mode": "apple_silicon",
        }

    # 纯 CPU 分支
    return {
        "num_ctx": 2048, "num_gpu": 0, "num_thread": num_thread,
        "quantization": "q4_k_m",
        "warning": "未检测到 GPU，将使用 CPU 推理（速度约为 GPU 的 1/10）",
        "mode": "cpu",
    }


def print_hardware_summary(hardware: dict, config: dict) -> None:
    """将硬件检测结果打印到控制台。"""
    if hardware.get("has_nvidia_gpu") and hardware.get("gpu_name"):
        print(f"[硬件检测] GPU: {hardware['gpu_name']} ({hardware['vram_mb']}MB)")
    elif hardware.get("has_amd_gpu") and hardware.get("gpu_name"):
        print(f"[硬件检测] GPU: {hardware['gpu_name']} ({hardware['vram_mb']}MB) [AMD/ROCm]")
    elif hardware.get("gpu_name") and "Apple M" in hardware["gpu_name"]:
        print(f"[硬件检测] GPU: {hardware['gpu_name']} (Apple Silicon)")
    else:
        print("[硬件检测] GPU: 未检测到 NVIDIA/AMD GPU")
    print(f"[硬件检测] CPU: {hardware['cpu_cores']} 核")
    print(f"[硬件检测] 推理模式: {config['mode'].upper()} "
          f"(num_ctx={config['num_ctx']}, {config['quantization']})")
    if config["warning"]:
        print(f"[硬件检测] ⚠️ {config['warning']}")


def main():
    print("=" * 60)
    print("  AI 漏洞扫描器 —— 启动中")
    print("=" * 60)

    # 1. 检测 Ollama
    if not check_ollama_installed():
        # 尝试自动安装
        if not try_install_ollama():
            print("\n[错误] Ollama 自动安装失败。请手动安装：")
            print("  下载地址：https://ollama.com/download")
            print("  安装后重新运行本启动器。")
            input("\n按回车键退出...")
            return
        # 安装后重新检查 PATH
        if not check_ollama_installed():
            print("\n[错误] Ollama 已安装但不在 PATH 中。")
            print("  请重启终端后重新运行本启动器，或手动将 ollama 加入 PATH。")
            input("\n按回车键退出...")
            return

    print("[1/5] Ollama 已安装")

    # 2. 确保 Ollama 服务运行
    if not ensure_ollama_running():
        print("\n[错误] Ollama 服务无法启动。请手动运行 `ollama serve` 后重试。")
        input("\n按回车键退出...")
        return

    print("[2/5] Ollama 服务已运行")

    # 3. 硬件检测 + 自适应推理参数（在拉取模型前完成，便于后续 scanner.py 读取）
    hardware = detect_hardware()
    config = recommend_config(hardware)
    print_hardware_summary(hardware, config)
    # 写入环境变量，供 scanner.py / 后端进程读取
    os.environ["VULN_SCANNER_NUM_CTX"] = str(config["num_ctx"])
    os.environ["VULN_SCANNER_NUM_GPU"] = str(config["num_gpu"])
    os.environ["VULN_SCANNER_NUM_THREAD"] = str(config["num_thread"])

    print("[3/5] 硬件检测完成")

    # 4. 确保模型可用
    model = os.environ.get("VULN_SCANNER_MODEL", DEFAULT_MODEL)
    if not ensure_model_available(model):
        # 回退到官方 Qwen3-8B
        print(f"[启动器] {model} 不可用，尝试回退模型 {FALLBACK_MODEL}")
        if not ensure_model_available(FALLBACK_MODEL):
            print(f"\n[错误] 无法获取任何可用模型。请手动运行：")
            print(f"  ollama pull {model}")
            input("\n按回车键退出...")
            return
        os.environ["VULN_SCANNER_MODEL"] = FALLBACK_MODEL

    print(f"[4/5] 模型就绪")

    # 5. 启动后端
    backend_proc = start_backend(PORT)
    if not wait_for_backend(PORT):
        print(f"\n[错误] 后端启动超时。请检查端口 {PORT} 是否被占用。")
        backend_proc.terminate()
        input("\n按回车键退出...")
        return

    print(f"[5/5] 后端就绪，正在打开浏览器...")

    # 6. 打开浏览器
    webbrowser.open(f"http://localhost:{PORT}")

    print(f"\n{'=' * 60}")
    print(f"  AI 漏洞扫描器已启动")
    print(f"  访问地址：http://localhost:{PORT}")
    print(f"  API 文档：http://localhost:{PORT}/docs")
    print(f"  按 Ctrl+C 停止服务")
    print(f"{'=' * 60}\n")

    # 保持运行
    try:
        backend_proc.wait()
    except KeyboardInterrupt:
        print("\n[启动器] 正在停止服务...")
        backend_proc.terminate()
        backend_proc.wait()


if __name__ == "__main__":
    main()
