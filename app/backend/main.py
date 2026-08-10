"""
FastAPI 后端入口 —— 漏洞扫描器 API。

路由：
  GET  /api/health            健康检查（Ollama + vLLM 连接、外部工具、各层开关）
  GET  /api/stats             仪表盘统计（扫描历史汇总 + 最近动态 + 健康状态）
  POST /api/analyze           单文件分析（JSON body: code/language/filename）
  POST /api/batch             批量扫描（multipart 文件上传，NDJSON 流式进度）
  POST /api/url-scan          URL 抓取扫描
  POST /api/github-scan       GitHub 仓库扫描
  POST /api/external-scan     外部工具扫描（Bandit/Semgrep/Gitleaks/Trivy）
  POST /api/verify-fix        修复建议验证（语法校验 + 危险模式移除）
  POST /api/multi-model-scan  多模型投票扫描
  POST /api/vllm-analyze      vLLM 推理后端单文件分析
  GET  /api/report            下载最近一次批量扫描的 Markdown 报告
  POST /api/report/single     分析并下载单文件 Markdown 报告

启动：
  uvicorn app.backend.main:app --host 127.0.0.1 --port 8765 --reload
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

# huggingface_hub 的 endpoint 在「模块首次 import」时按 HF_ENDPOINT 固定，之后改环境变量无效。
# 必须在进程内任何 huggingface_hub import（transformers 库内部懒加载）之前设置，否则模型下载
# 实际仍指向被墙的 huggingface.co，list_repo_files 会秒失败。这里在 main.py 最顶部、任何
# app/graduation_project 模块 import 之前设置，走国内镜像 hf-mirror.com（可用变量覆盖）。
os.environ.setdefault("HF_ENDPOINT", os.environ.get("VULN_SCANNER_HF_MIRROR", "https://hf-mirror.com").strip() or "https://hf-mirror.com")

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.backend.services.fetcher import fetch_url, validate_target_url
from app.backend.services.reporter import render_batch_markdown, render_single_markdown
from app.backend.services.scanner import DEFAULT_MODEL, Scanner
from graduation_project.result_types import SingleResult, BatchResult
from app.backend.services.model_registry import (
    list_registry,
    get_model_info,
    get_default_model,
    is_allowed,
    normalize_ollama_name,
)
from app.backend.services.scheduler import (
    PRIORITY_HIGH,
    PRIORITY_LOW,
    ScanScheduler,
    resolve_client_id,
    resolve_priority,
)

# 核心层能力（两阶段扫描 / 外部工具 / 修复验证 / vLLM；多模型投票在业务服务层）
from graduation_project.external_scanner import ExternalScanner
from graduation_project.two_stage_scanner import TwoStageScanner, tool_recall_monitor_snapshot
from graduation_project.fix_verifier import FixVerifier, validate_fix_suggestion
from app.backend.services.multi_model_scanner import MultiModelScanner
from graduation_project.vllm_client import VLLMClient
from graduation_project.schema import parse_verdict, normalize_has_vulnerability
from graduation_project.prompts import build_user_prompt
from graduation_project.paths import (
    resolve_adapter_path,
    resolve_base_model_path,
    find_project_root,
    local_hf_model_dir,
    local_vllm_model_dir,
    llamacpp_dir,
    ollama_models_dir,
)

# ---------------------------------------------------------------------------
# 全局 Scanner 实例（单例，避免重复初始化 Chroma/OllamaClient）
# ---------------------------------------------------------------------------
scanner = Scanner(
    model=os.environ.get("VULN_SCANNER_MODEL", DEFAULT_MODEL),
    use_rag=os.environ.get("VULN_SCANNER_RAG", "0") == "1",
    use_prefilter=os.environ.get("VULN_SCANNER_PREFILTER", "1") != "0",  # 默认启用预筛
)

# ---------------------------------------------------------------------------
# transformers 后端后台预热（让首次分析立即可用）
# ---------------------------------------------------------------------------
# 进程内 transformers 后端默认是"首次扫描才懒加载"（8B NF4 约 6GB、加载约数十秒）。
# 为免用户等第一次扫描干等，这里在「选完 transformers 且模型资源就绪」后、以及
# 「基座模型下载完成」后，都主动在后台线程加载基座并合并 LoRA。
# 用 VULN_SCANNER_PRELOAD=0 可关闭预加载。
_warmup_lock = threading.Lock()
_warmup_started = False


def _trigger_transformers_warmup() -> None:
    """后台加载 transformers 模型（基座 + 合并 LoRA），幂等、仅触发一次。"""
    global _warmup_started
    if os.environ.get("VULN_SCANNER_PRELOAD", "1") == "0":
        return
    client = scanner.client
    if type(client).__name__ != "TransformersClient":
        return
    with _warmup_lock:
        if _warmup_started:
            return
        if client._model is not None:
            _warmup_started = True
            return
        _warmup_started = True

    def _warm():
        try:
            # 启动即迁移 C 盘 HF 缓存（完整/未下完都搬），保证模型文件不落 C 盘
            if hasattr(client, "migrate_cache_to_project"):
                client.migrate_cache_to_project()
            # 基座权重未完整下载时跳过预热：避免启动即触发 16GB 下载。
            # 下载完成后（设置页下载端点）会再次触发预热。
            if not client.is_ready():
                _, base_status = client.model_availability()
                print(f"[Warmup] 基座未就绪，跳过预热（{base_status}）")
                return
            if not client.load_model():
                print(f"[Warmup] transformers 模型加载失败: {client._load_error}")
        except Exception as e:
            print(f"[Warmup] transformers 模型加载异常: {type(e).__name__}: {e}")

    threading.Thread(target=_warm, daemon=True, name="transformers-warmup").start()

# ---------------------------------------------------------------------------
# 扫描请求调度器（单例）
# ---------------------------------------------------------------------------
# 在 FastAPI 与 Ollama 之间引入优先级队列：交互式扫描（HIGH）优先于批量扫描
# （LOW），单工作线程与 Ollama 串行推理对齐。详见 services/scheduler.py。
scheduler = ScanScheduler(
    max_queue=int(os.environ.get("VULN_SCANNER_MAX_QUEUE", "50")),
    max_per_client=int(os.environ.get("VULN_SCANNER_MAX_PER_CLIENT", "8")),
    queue_timeout=float(os.environ.get("VULN_SCANNER_QUEUE_TIMEOUT", "600")),
)

# ---------------------------------------------------------------------------
# 文件扩展名 → 语言映射
# ---------------------------------------------------------------------------
EXT_TO_LANG = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript",
    ".java": "java", ".php": "php", ".go": "go",
    ".html": "html", ".htm": "html",
    ".vue": "javascript", ".svelte": "javascript",
}

# ---------------------------------------------------------------------------
# 输入大小限制（本地服务也要防误操作/恶意大请求拖垮内存）
# ---------------------------------------------------------------------------
MAX_CODE_CHARS = 2_000_000                      # 单段代码/修复建议字符上限
MAX_BATCH_FILES = 200                           # 单次批量上传文件数上限
MAX_SINGLE_FILE_BYTES = 2 * 1024 * 1024         # 单文件大小上限（2MB）
MAX_BATCH_TOTAL_BYTES = 10 * 1024 * 1024        # 批量总大小上限（10MB）

# ---------------------------------------------------------------------------
# Pydantic 请求模型
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    code: str = Field(..., max_length=MAX_CODE_CHARS)
    language: str = "python"
    filename: str = "pasted_code.py"
    use_rag: Optional[bool] = None


class UrlScanRequest(BaseModel):
    url: str = Field(..., max_length=2048)
    use_rag: Optional[bool] = None


class GithubScanRequest(BaseModel):
    repo_url: str = Field(..., max_length=2048)
    use_rag: Optional[bool] = None
    max_files: int = Field(50, ge=1, le=500)  # 限制扫描文件数，避免大仓库超时


class ExternalScanRequest(BaseModel):
    """外部工具扫描请求（Bandit/Semgrep/Gitleaks/Trivy）。"""
    code: str = Field(..., max_length=MAX_CODE_CHARS)
    language: str = "python"
    filename: str = "pasted_code.py"


class VerifyFixRequest(BaseModel):
    """修复建议验证请求。"""
    original_code: str = Field(..., max_length=MAX_CODE_CHARS)
    fix_suggestion: str = Field(..., max_length=MAX_CODE_CHARS)
    language: str = "python"


class MultiModelRequest(BaseModel):
    """多模型投票扫描请求。"""
    code: str = Field(..., max_length=MAX_CODE_CHARS)
    language: str = "python"
    filename: str = "pasted_code.py"
    models: list[str] = Field(default_factory=list, max_length=8)
    use_rag: Optional[bool] = None


class VllmAnalyzeRequest(BaseModel):
    """vLLM 后端单文件分析请求。"""
    code: str = Field(..., max_length=MAX_CODE_CHARS)
    language: str = "python"
    filename: str = "pasted_code.py"
    use_rag: Optional[bool] = None


class TwoStageRequest(BaseModel):
    """两阶段扫描请求（工具召回 + LLM 裁决）。"""
    code: str = Field(..., max_length=MAX_CODE_CHARS)
    language: str = "python"
    filename: str = "pasted_code.py"
    n_samples: int = Field(5, ge=1, le=10)   # 自一致率采样次数
    use_rag: Optional[bool] = None


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AI 漏洞扫描器",
    description="基于 LLM 的代码安全审计系统 API",
    version="1.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def _bind_scheduler_loop() -> None:
    """启动时把事件循环绑定到调度器，使其能回填 asyncio.Future 结果。"""
    import asyncio
    scheduler.bind_loop(asyncio.get_running_loop())
    # transformers 后端：若模型资源已就绪，后台预热加载基座并合并 LoRA，使首次分析立即可用
    _trigger_transformers_warmup()


@app.on_event("shutdown")
async def _shutdown_scheduler() -> None:
    """关闭时停止调度器工作线程。"""
    scheduler.shutdown()

# 最近一次批量扫描结果（供 /api/report 下载）
_last_batch: Optional[BatchResult] = None

# 扫描历史统计（进程内，重启后清零）
_scan_stats: dict = {
    "total_scans": 0,
    "total_files": 0,
    "total_vulnerable": 0,
    "total_safe": 0,
    "total_errors": 0,
    "recent_scans": [],  # 最近 20 条扫描记录
}

# _scan_stats / _last_batch 的读写防护锁：
# 写入发生在 async handler（事件循环线程），而 get_stats 是普通 def（线程池线程）、
# download_report 是 async，故存在跨线程读写，需加锁避免统计丢失/读撕。
_stats_lock = threading.Lock()


# ---------------------------------------------------------------------------
# 健康检查
# ---------------------------------------------------------------------------
@app.get("/api/health/live")
async def health_live():
    """轻量级存活探针：仅确认 uvicorn 进程已就绪，不调用任何外部服务。

    用于启动器 wait_for_backend 的就绪检测，避免 /api/health 因 Ollama 预热 /
    外部工具探测耗时导致客户端超时。
    """
    return {"status": "alive"}


@app.get("/api/health")
def health():
    """深度健康检查：Ollama + vLLM 连接、模型可用性、外部工具安装情况、各层开关状态。

    供前端仪表盘使用（可能较慢，调用方需设置较长超时）。
    注意：必须用普通 def（非 async def），否则同步阻塞调用会卡死 uvicorn 事件循环，
    导致并发的 /api/health/live、静态资源等请求全部排队等待。
    FastAPI 会自动把 def 端点放到线程池执行，不阻塞事件循环。
    """
    base = scanner.check_health()

    # vLLM 推理后端探测
    try:
        vllm = VLLMClient()
        base["vllm_connected"] = vllm.check_connection()
        base["vllm_models"] = vllm.list_models() if base["vllm_connected"] else []
    except Exception as e:
        base["vllm_connected"] = False
        base["vllm_models"] = []
        base["vllm_error"] = str(e)

    # 外部安全工具探测（Bandit/Semgrep/Gitleaks/Trivy）
    try:
        ext = ExternalScanner()
        base["external_tools"] = ext.available_tools()
    except Exception as e:
        base["external_tools"] = []
        base["external_error"] = str(e)

    return base


def _detect_model_available(backend: str, client) -> tuple[bool | None, str]:
    """检测模型是否已下载/可用。返回 (是否可用, 状态描述)。

    - transformers: 检测 HuggingFace 本地 cache 是否已下载基座模型
    - ollama: 检测模型是否已 pull
    - llamacpp: 检测 GGUF 文件是否存在
    - vllm: 检测 vLLM 服务是否运行且模型已加载
    - 其他: 返回 (None, "未实现检测")
    """
    if backend == "transformers":
        # 客户端自带完整性检测（区分未下载/下载中/已完整），优先复用
        if hasattr(client, "model_availability"):
            try:
                return client.model_availability()
            except Exception as e:  # noqa: BLE001
                return None, f"检测异常：{e}"
        model_id = getattr(client, "model_id", "") or resolve_base_model_path()
        # 若已加载到内存，肯定可用
        if getattr(client, "_model", None) is not None:
            return True, "已加载到内存"
        # 若有加载错误，检查是否与下载相关
        load_err = getattr(client, "_load_error", None)
        if load_err:
            return False, f"加载失败：{load_err}"
        # 本地目录路径（models/transformers/...）→ 直接检查目录内 config.json
        local_dir = Path(model_id).expanduser()
        if local_dir.is_dir():
            if (local_dir / "config.json").is_file():
                return True, "已就绪（本地基座模型）"
            return False, f"本地基座目录缺少 config.json：{model_id}"
        # 否则用 huggingface_hub 检测本地 cache
        try:
            from huggingface_hub import try_to_load_from_cache
            # 检测 config.json 是否在本地 cache（模型下载的标志文件）
            result = try_to_load_from_cache(model_id, "config.json")
            # 返回值：_CACHED_NO_EXIST=文件不存在但仓库已缓存, 本地路径=已下载, None=未缓存
            if result is None:
                return False, f"未从 HuggingFace 下载，首次推理将自动拉取（约 15GB）"
            return True, "已下载到本地 cache"
        except ImportError:
            # huggingface_hub 未安装，无法检测
            return None, "未安装 huggingface_hub，无法检测"
        except Exception as e:
            return None, f"检测异常：{e}"

    elif backend == "ollama":
        model = getattr(client, "model", os.environ.get("VULN_SCANNER_MODEL", ""))
        try:
            import requests
            resp = requests.get("http://localhost:11434/api/tags", timeout=3)
            if resp.status_code != 200:
                return False, "Ollama 服务未运行"
            models = [normalize_ollama_name(m.get("name", "")) for m in resp.json().get("models", [])]
            if model in models:
                return True, "已 pull 到本地"
            return False, f"未 pull，需运行 ollama pull {model}"
        except Exception as e:
            return False, f"Ollama 未运行：{e}"

    elif backend == "llamacpp":
        base_gguf = getattr(client, "base_gguf", "") or os.environ.get("VULN_SCANNER_GGUF", "")
        if base_gguf and Path(base_gguf).exists():
            return True, "GGUF 文件存在"
        return False, f"GGUF 文件不存在：{base_gguf or '未配置'}"

    elif backend == "vllm":
        model = getattr(client, "model", os.environ.get("VULN_SCANNER_MODEL", ""))
        try:
            if not client.check_connection():
                return False, "vLLM 服务未运行（请先启动 app/launcher/vllm_server.py）"
            models = client.list_models()
            if not models:
                return False, "vLLM 服务已连接但未暴露任何模型"
            if model and model in models:
                return True, "vLLM 服务运行中，模型已加载"
            # 模型名未精确匹配时，只要服务有模型即视为可用（served-model-name 可能不同）
            return True, f"vLLM 服务运行中（已加载: {', '.join(models)}）"
        except Exception as e:
            return False, f"vLLM 检测异常：{e}"

    return None, "未实现检测"


def _build_backend_info() -> dict:
    """构造当前推理后端的精度/流程信息，供前端展示（检测报告式）。"""
    client = scanner.client
    cls_name = type(client).__name__
    backend = {
        "OllamaClient": "ollama",
        "TransformersClient": "transformers",
        "LlamaCppClient": "llamacpp",
        "VLLMClient": "vllm",
    }.get(cls_name, cls_name)

    # 通用环境变量
    num_ctx = int(os.environ.get("VULN_SCANNER_NUM_CTX", "0") or "0")
    num_gpu = int(os.environ.get("VULN_SCANNER_NUM_GPU", "-1") or "-1")

    # 模型下载状态检测
    model_available, model_status = _detect_model_available(backend, client)

    info: dict = {
        "backend": backend,
        "backend_class": cls_name,
        "num_ctx": num_ctx if num_ctx > 0 else None,
        "num_gpu": num_gpu if num_gpu >= 0 else None,
        "model_available": model_available,
        "model_status": model_status,
    }

    if backend == "ollama":
        model = getattr(client, "model", os.environ.get("VULN_SCANNER_MODEL", ""))
        q_label = "GGUF Q4_K_M"
        if "q6" in model.lower() or "q6_k" in model.lower():
            q_label = "GGUF Q6_K"
        elif "q5" in model.lower():
            q_label = "GGUF Q5_K_M"
        elif "q4" in model.lower() or "v9max" in model.lower():
            q_label = "GGUF Q4_K_M"
        info.update({
            "model": model,
            "base_quantization": f"推理时将采用 {q_label} 量化",
            "lora_quantized": True,
            "lora_precision": "Base + LoRA 合并后整体量化为 Q4_K_M（LoRA 被二次量化）",
            "compute_dtype": None,
            "device_type": "Ollama 托管",
            "num_gpu_layers": None,
            "precision_note": (
                "Ollama 发布版把微调后的 Base + LoRA 先合并，再整体压成 GGUF Q4_K_M。"
                "这会把原本 FP16 的 LoRA 增量再次量化，导致真实 CVE-fix 召回从 HF 管道的 0.95 掉到约 0.75~0.79。"
            ),
        })
        info["detection_method"] = (
            "请求 Ollama 服务 /api/tags 获取已安装模型列表，并与注册表 full_name 精确比对"
            "（自动去掉 :latest）；服务不可达或列表中无当前模型即判为未就绪。"
        )
        info["download_method"] = (
            "点击「拉取」调用 Ollama /api/pull 下载到 OLLAMA_MODELS 目录（当前 "
            f"{ollama_models_dir()}），支持断点续传；已安装模型可切换或删除。"
        )
        info["model_store"] = str(ollama_models_dir())

    elif backend == "transformers":
        adapter = resolve_adapter_path(getattr(client, "adapter", ""))
        model_id = getattr(client, "model_id", "") or os.environ.get("VULN_SCANNER_MODEL_ID", "Qwen/Qwen3-8B")
        quantize = bool(getattr(client, "quantize", True))
        compute_dtype = (getattr(client, "compute_dtype", "") or "").lower()
        if not compute_dtype:
            # 与 transformers_client 默认保持一致
            compute_dtype = "bf16" if "rocm" in os.environ.get("VULN_SCANNER_COMPUTE_DTYPE", "").lower() else "fp16"

        # 探测实际运行设备（torch 已安装才走此分支）
        device_type = "未知"
        try:
            import torch
            if torch.cuda.is_available():
                device_type = "ROCm" if getattr(torch.version, "hip", None) else "CUDA"
            else:
                device_type = "CPU"
        except Exception:
            device_type = "未知（未加载）"

        q_desc = "推理时将采用 bitsandbytes NF4 4bit 量化基座" if quantize else "推理时基座不量化（FP16/FP32 全精度）"
        info.update({
            "model": model_id,
            "adapter_path": adapter,
            "base_quantization": q_desc,
            "lora_quantized": False,
            "lora_precision": "FP16（运行时叠加并合并，保持 LoRA 精度）",
            "compute_dtype": compute_dtype,
            "device_type": device_type,
            "num_gpu_layers": num_gpu if num_gpu >= 0 else None,
            "precision_note": (
                "Transformers 管道：Base 用 bitsandbytes NF4 4bit 量化，LoRA 以 FP16 精度在运行时叠加并合并。"
                "只压缩基座，不压缩 LoRA，复现了 G0 冻结集 95% CVE-fix recall 的管道。"
            ),
        })
        info["detection_method"] = (
            "检查本地基座目录 "
            f"{local_hf_model_dir(model_id)} "
            "是否含 config.json 且权重分片齐全，并校验 LoRA adapter 目录；"
            "模型已加载进内存则直接视为就绪。"
        )
        info["download_method"] = (
            f"点击「下载」经 {HF_MIRROR} 镜像逐文件下载到 "
            f"{local_hf_model_dir(model_id)}（约 16GB，支持断点续传）；"
            "下载完成自动后台加载，首次扫描即可用。"
        )
        info["model_store"] = str(local_hf_model_dir(model_id))
        # 模型未下载时给出下载提示
        if model_available is False:
            info["download_hint"] = (
                f"基座模型 {model_id} 未下载。"
                f"首次分析或设置页下载时会自动拉取到项目基座目录 "
                f"{local_hf_model_dir(model_id)}（约 16GB，支持断点续传）。"
            )

    elif backend == "llamacpp":
        base_gguf = getattr(client, "base_gguf", "") or os.environ.get("VULN_SCANNER_GGUF", "")
        adapter = resolve_adapter_path(getattr(client, "adapter", ""))
        gguf_name = Path(base_gguf).name if base_gguf else ""
        q_label = "GGUF Q4（常见）"
        if gguf_name:
            lowered = gguf_name.lower()
            if "q6" in lowered:
                q_label = "GGUF Q6"
            elif "q5" in lowered:
                q_label = "GGUF Q5"
            elif "q4" in lowered:
                q_label = "GGUF Q4"
            elif "q8" in lowered:
                q_label = "GGUF Q8"
        gpu_layers = getattr(client, "gpu_layers", -1)
        info.update({
            "model": gguf_name or "未配置 GGUF",
            "gguf_path": base_gguf,
            "adapter_path": adapter,
            "base_quantization": f"推理时将采用 {q_label} 量化基座",
            "lora_quantized": False,
            "lora_precision": "FP16（运行时通过 lora_path 叠加）",
            "compute_dtype": "FP16",
            "device_type": "GPU" if gpu_layers != 0 else "CPU",
            "num_gpu_layers": gpu_layers if gpu_layers >= 0 else None,
            "precision_note": (
                "llama.cpp 加载 Q4 GGUF 基座，同时把 FP16 LoRA 作为独立权重在运行时叠加。"
                "速度优于 transformers，但量化/反量化细节与 transformers 不同，召回需单独验证。"
            ),
        })
        info["detection_method"] = (
            "检查 VULN_SCANNER_GGUF 指定路径，或自动探测 "
            f"{llamacpp_dir()} 下是否存在 *.gguf 文件；文件存在即就绪。"
        )
        info["download_method"] = (
            f"点击「下载」输入 GGUF URL（GitHub 链接自动加 ghproxy 镜像）下载到 "
            f"{llamacpp_dir()}；下载完成自动绑定当前后端，首次扫描即可加载。"
        )
        info["model_store"] = str(llamacpp_dir())
        if model_available is False:
            info["download_hint"] = (
                f"GGUF 文件不存在：{base_gguf or '未配置'}。"
                "可在「设置 → 模型管理」输入 GGUF URL 下载到 "
                f"{llamacpp_dir()}，下载完成自动绑定；或设置 VULN_SCANNER_GGUF 后重启后端。"
            )

    elif backend == "vllm":
        model = getattr(client, "model", os.environ.get("VULN_SCANNER_MODEL", ""))
        base_url = os.environ.get("VULN_SCANNER_VLLM_URL", "http://localhost:8000")
        vllm_model_id = os.environ.get("VULN_SCANNER_VLLM_MODEL_ID", "Qwen/Qwen3-8B-AWQ")
        # 由 GGUF / AWQ / GPTQ 权重文件名推断量化位宽（仅供参考，实际由 vLLM 服务加载决定）
        q_label = "AWQ/GPTQ 4bit（常见）"
        info.update({
            "model": model or "未配置模型",
            "server_url": base_url,
            "base_quantization": f"vLLM 服务加载量化基座（{q_label}）",
            "lora_quantized": False,
            "lora_precision": "FP16（vLLM --enable-lora 运行时叠加）",
            "compute_dtype": "FP16（vLLM 托管）",
            "device_type": "vLLM 服务（GPU 高吞吐）",
            "num_gpu_layers": None,
            "precision_note": (
                "vLLM 通过 OpenAI 兼容 API 提供高吞吐推理（PagedAttention + continuous batching）。"
                "基座可用 AWQ/GPTQ 4bit 量化以适配 8GB 显存，LoRA 通过 --enable-lora 在运行时以 FP16 叠加。"
                "需先用 app/launcher/vllm_server.py 启动服务（vLLM 仅支持 Linux/WSL2，Windows 原生不可用）。"
            ),
        })
        info["detection_method"] = (
            f"探测 {base_url}/v1/models 是否可访问，并检查服务已加载的模型列表；"
            "服务不可达或未加载任何模型即判为未就绪。"
        )
        info["download_method"] = (
            f"点击「下载基座」经 {HF_MIRROR} 镜像下载 AWQ/GPTQ 量化基座到 "
            f"{local_vllm_model_dir(vllm_model_id)}；"
            "之后用 app/launcher/vllm_server.py 启动服务加载。"
        )
        info["model_store"] = str(local_vllm_model_dir(vllm_model_id))
        if model_available is False:
            info["download_hint"] = (
                f"vLLM 服务未运行或未加载模型。可在「设置 → 模型管理」先下载 AWQ 基座到 "
                f"{local_vllm_model_dir(vllm_model_id)}，再用 app/launcher/vllm_server.py "
                f"启动服务（默认 {base_url}，--served-model-name 需与当前模型 "
                f"{model or '设置 VULN_SCANNER_MODEL'} 一致）。"
            )

    else:
        info.update({
            "model": getattr(client, "model", ""),
            "base_quantization": "未知",
            "lora_quantized": None,
            "lora_precision": "未知",
            "compute_dtype": None,
            "device_type": "未知",
            "num_gpu_layers": None,
            "precision_note": "未知后端，无法判断精度信息。",
        })

    return info


@app.get("/api/backend/info")
def backend_info():
    """当前推理后端与模型精度信息。

    供前端显式展示：用的哪个后端、基座量化位宽、LoRA 是否被量化、运行设备等。
    """
    return _build_backend_info()


@app.get("/api/backend/options")
def backend_options():
    """列出所有可选推理后端及其简要精度特征，供前端切换时提示。"""
    return {
        "current": _build_backend_info(),
        "available": [
            {
                "id": "ollama",
                "name": "Ollama",
                "recommended": True,
                "precision_summary": "GGUF Q4_K_M（Base+LoRA 合并后再量化）",
                "pros": "一键启动、兼容性好、CPU 也能跑",
                "cons": "LoRA 被二次量化，真实召回最低（约 75~79%）",
            },
            {
                "id": "transformers",
                "name": "Transformers",
                "recommended": False,
                "precision_summary": "NF4 Base + FP16 LoRA（LoRA 不量化）",
                "pros": "精度最高，复现 95% CVE-fix recall",
                "cons": "依赖大、显存/内存占用高、速度较慢",
            },
            {
                "id": "llamacpp",
                "name": "LlamaCPP",
                "recommended": False,
                "precision_summary": "Q4 GGUF + 运行时 FP16 LoRA",
                "pros": "llama.cpp 内核快，LoRA 精度保留",
                "cons": "GPU 需源码编译（CUDA/Metal/ROCm）；Windows AMD 默认 CPU 预编译包",
            },
            {
                "id": "vllm",
                "name": "vLLM",
                "recommended": False,
                "precision_summary": "AWQ/GPTQ 4bit 基座 + FP16 LoRA",
                "pros": "PagedAttention/continuous batching，高吞吐批量推理",
                "cons": "仅 Linux/WSL2 可用；Windows/macOS 原生不可用；需 NVIDIA/AMD(ROCm)/Intel GPU",
            },
        ],
    }


def _record_scan(batch: BatchResult, source: str = "batch") -> None:
    """记录一次扫描到统计中（进程内，重启后清零）。

    Args:
        batch: 扫描批次结果。
        source: 扫描来源标记（"github" / "url" / "batch"），供前端按来源过滤
                （如安全态势页只统计 GitHub 仓库扫描）。
    """
    with _stats_lock:
        _scan_stats["total_scans"] += 1
        _scan_stats["total_files"] += batch.total_files
        _scan_stats["total_vulnerable"] += batch.vulnerable
        _scan_stats["total_safe"] += batch.safe
        _scan_stats["total_errors"] += batch.errors
        # 记录最近 20 条
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "source": source,
            "total_files": batch.total_files,
            "vulnerable": batch.vulnerable,
            "safe": batch.safe,
            "errors": batch.errors,
            "duration": round(batch.total_duration, 2),
            "results": [
                {
                    "filename": r.filename,
                    "has_vulnerability": r.has_vulnerability,
                    "vulnerability_type": r.vulnerability_type,
                    "risk_level": r.risk_level,
                }
                for r in batch.results[:20]  # 最多保留 20 条文件结果
            ],
        }
        _scan_stats["recent_scans"].insert(0, entry)
        if len(_scan_stats["recent_scans"]) > 20:
            _scan_stats["recent_scans"] = _scan_stats["recent_scans"][:20]


@app.get("/api/stats")
def get_stats():
    """仪表盘统计数据：扫描历史汇总 + 最近动态。

    前端 index.html 调用此端点获取真实数据，替换静态占位。
    进程重启后统计清零，前端可用 localStorage 做历史持久化。
    注意：此端点不调用 check_health（会阻塞等待 Ollama），健康状态由前端
    单独请求 /api/health/live 获取，避免拖慢仪表盘数据加载。
    """
    with _stats_lock:
        recent = _scan_stats["recent_scans"]

        # 从最近扫描中提取漏洞列表（用于"最近动态"）
        recent_findings = []
        for scan in recent[:5]:
            for r in scan.get("results", []):
                if r.get("has_vulnerability") is True:
                    recent_findings.append({
                        "filename": r["filename"],
                        "vulnerability_type": r["vulnerability_type"],
                        "risk_level": r["risk_level"],
                        "timestamp": scan["timestamp"],
                    })

        return {
            "total_scans": _scan_stats["total_scans"],
            "total_files": _scan_stats["total_files"],
            "total_vulnerable": _scan_stats["total_vulnerable"],
            "total_safe": _scan_stats["total_safe"],
            "total_errors": _scan_stats["total_errors"],
            "recent_scans": recent,
            "recent_findings": recent_findings[:10],
        }


# ---------------------------------------------------------------------------
# 单文件分析（代码粘贴）
# ---------------------------------------------------------------------------
async def _await_scan(future):
    """等待调度器 future 完成。

    Returns:
        (result, None) 成功；或 (None, JSONResponse) 失败（队列满/超时/取消）。
    """
    try:
        return await future, None
    except Exception as e:
        return None, JSONResponse({"error": str(e)}, status_code=503)


@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest, request: Request):
    # 交互式单文件扫描：默认 HIGH 优先级；批量客户端可通过 X-Scan-Scope: batch 降级
    client_id = resolve_client_id(request.headers.get("x-client-type"))
    priority = resolve_priority(request.headers.get("x-scan-scope"), PRIORITY_HIGH)

    _, future = scheduler.submit(
        priority, client_id,
        lambda: scanner.scan_code(
            code=req.code, language=req.language,
            filename=req.filename, use_rag=req.use_rag,
        ),
        description=f"analyze:{req.filename}",
    )
    result, err = await _await_scan(future)
    if err is not None:
        return err
    return result.to_dict()


# ---------------------------------------------------------------------------
# 两阶段扫描（工具召回 + LLM 裁决）
# ---------------------------------------------------------------------------
@app.post("/api/analyze/two-stage")
async def analyze_two_stage(req: TwoStageRequest, request: Request):
    """两阶段架构扫描：Stage 1 工具召回候选 + Stage 2 LLM 裁决（自一致率）。

    与旧 /api/analyze 的"LLM 为主、工具为辅"不同，本端点反转为"工具召回 +
    LLM 裁决"：只有有候选的少数文件才触发 LLM，且 LLM 只做封闭二分类（判定
    某 source→sink 证据链真伪），以 N 次采样自一致率作为置信度。

    复用全局 scanner 的 client 与 system_prompt（同一推理后端，避免重复加载
    模型），走调度器 HIGH 优先级（与旧 analyze 一致，避免抢占串行 Ollama）。
    """
    client_id = resolve_client_id(request.headers.get("x-client-type"))
    priority = resolve_priority(request.headers.get("x-scan-scope"), PRIORITY_HIGH)

    def _run():
        # 与 scan_code 互斥：N 次采样裁决期间不允许 switch_model，
        # 否则中途切模型会出现"旧 system prompt + 新模型"的撕裂结果
        with scanner._model_lock:
            ts = TwoStageScanner(
                client=scanner.client,
                system_prompt=scanner.system_prompt,
                n_samples=req.n_samples,
                keep_alive=scanner.keep_alive,
                num_ctx=scanner._num_ctx,
                use_rag=False,      # 默认关闭；req.use_rag=True 时经 scan_code 参数启用（Chroma 不可用时自动降级）
            )
            return ts.scan_code(
                code=req.code, language=req.language,
                filename=req.filename, use_rag=req.use_rag,
            )

    _, future = scheduler.submit(
        priority, client_id, _run,
        description=f"two-stage:{req.filename}",
    )
    result, err = await _await_scan(future)
    if err is not None:
        return err
    # ?format=sarif → 返回 SARIF 2.1.0（GitHub Code Scanning / IDE 原生可消费）
    if request.query_params.get("format") == "sarif":
        from graduation_project.sarif_report import to_sarif
        return to_sarif([result], tool_version=scanner.model)
    out = result.to_dict()
    # 附带工具层召回监控（抽样复核计数），供前端/论文追踪 Stage 1 漏报率
    out["tool_recall_monitor"] = tool_recall_monitor_snapshot()
    return out


# ---------------------------------------------------------------------------
# 批量扫描（文件上传）+ SSE 进度推送
# ---------------------------------------------------------------------------
@app.post("/api/batch")
async def batch_scan(
    request: Request,
    files: list[UploadFile] = File(...),
    use_rag: str = Form("0"),
):
    """批量扫描上传的文件。

    返回 NDJSON 流（每行一个文件的结果），前端可逐行解析显示进度。
    每个文件作为 LOW 优先级任务入队，自动让路于交互式扫描（HIGH）。
    """
    rag = use_rag == "1"
    client_id = resolve_client_id(request.headers.get("x-client-type"), fallback="web")
    if not files:
        return JSONResponse({"error": "未接收到文件"}, status_code=400)
    if len(files) > MAX_BATCH_FILES:
        return JSONResponse(
            {"error": f"单次批量扫描最多 {MAX_BATCH_FILES} 个文件"},
            status_code=413,
        )
    file_list = []
    total_bytes = 0
    for f in files:
        raw = await f.read(MAX_SINGLE_FILE_BYTES + 1)
        if len(raw) > MAX_SINGLE_FILE_BYTES:
            return JSONResponse(
                {"error": f"文件 {f.filename} 超过单文件上限 2MB"},
                status_code=413,
            )
        total_bytes += len(raw)
        if total_bytes > MAX_BATCH_TOTAL_BYTES:
            return JSONResponse(
                {"error": "批量文件总大小超过上限 10MB"},
                status_code=413,
            )
        ext = Path(f.filename).suffix.lower()
        lang = EXT_TO_LANG.get(ext, "text")
        content = raw.decode("utf-8", errors="replace")
        file_list.append((f.filename, lang, content))

    async def generate():
        global _last_batch
        batch = BatchResult(total_files=len(file_list))
        batch_start = time.time()

        for filename, lang, code in file_list:
            # 每个文件单独入队（LOW），交互式扫描可插队
            _, future = scheduler.submit(
                PRIORITY_LOW, client_id,
                lambda fn=filename, lg=lang, cd=code: scanner.scan_code(
                    cd, lg, fn, use_rag=rag,
                ),
                description=f"batch:{filename}",
            )
            try:
                r = await future
            except Exception as e:
                r = SingleResult(
                    filename=filename, language=lang,
                    has_vulnerability=None, error=str(e),
                )

            batch.results.append(r)
            batch.scanned += 1
            if r.has_vulnerability is True:
                batch.vulnerable += 1
            elif r.has_vulnerability is False:
                batch.safe += 1
            else:
                batch.errors += 1

            # 推送单文件结果（NDJSON）
            yield json.dumps({
                "type": "progress",
                "scanned": batch.scanned,
                "total": batch.total_files,
                "result": r.to_dict(),
            }, ensure_ascii=False) + "\n"

        batch.total_duration = time.time() - batch_start
        with _stats_lock:
            _last_batch = batch
        _record_scan(batch, source="batch")
        yield json.dumps({
            "type": "done",
            "summary": batch.to_dict(),
        }, ensure_ascii=False) + "\n"

    return StreamingResponse(generate(), media_type="application/x-ndjson")


# ---------------------------------------------------------------------------
# 逐文件调度扫描（替代 Scanner.scan_files，支持优先级让路）
# ---------------------------------------------------------------------------
async def _scan_files_scheduled(
    files: list[tuple[str, str, str]],
    use_rag: Optional[bool],
    client_id: str,
    priority: int = PRIORITY_LOW,
) -> BatchResult:
    """逐文件提交到调度器，等待结果汇总。

    批量场景（URL / GitHub / 工作区）每个文件以 LOW 优先级入队，
    交互式扫描（HIGH）可随时插队，避免批量任务饿死单文件请求。
    """
    batch = BatchResult(total_files=len(files))
    batch_start = time.time()
    for filename, language, code in files:
        _, future = scheduler.submit(
            priority, client_id,
            lambda fn=filename, lg=language, cd=code: scanner.scan_code(
                cd, lg, fn, use_rag=use_rag,
            ),
            description=f"scan:{filename}",
        )
        try:
            r = await future
        except Exception as e:
            r = SingleResult(
                filename=filename, language=language,
                has_vulnerability=None, error=str(e),
            )
        batch.results.append(r)
        batch.scanned += 1
        if r.has_vulnerability is True:
            batch.vulnerable += 1
        elif r.has_vulnerability is False:
            batch.safe += 1
        else:
            batch.errors += 1
    batch.total_duration = time.time() - batch_start
    return batch


# ---------------------------------------------------------------------------
# URL 抓取扫描
# ---------------------------------------------------------------------------
@app.post("/api/url-scan")
async def url_scan(req: UrlScanRequest, request: Request):
    """抓取目标 URL 的所有脚本，逐个扫描（LOW 优先级，让路交互式）。"""
    client_id = resolve_client_id(request.headers.get("x-client-type"), fallback="web")
    # SSRF 防护：仅允许公网 http/https，重定向前同样校验目标地址
    url_err = validate_target_url(req.url)
    if url_err:
        return JSONResponse({"error": url_err, "url": req.url}, status_code=400)
    # fetch_url 是同步阻塞（requests），放线程池避免卡事件循环
    fetch_result = await asyncio.to_thread(fetch_url, req.url)

    if fetch_result.error:
        return JSONResponse(
            {"error": fetch_result.error, "url": req.url},
            status_code=502,
        )

    if not fetch_result.scripts:
        return {"url": req.url, "title": fetch_result.title, "results": [], "message": "未找到可分析的脚本"}

    files = [
        (s.source if s.source != "inline" else "inline_script",
         s.language, s.content)
        for s in fetch_result.scripts
    ]
    batch = await _scan_files_scheduled(files, req.use_rag, client_id)
    global _last_batch
    with _stats_lock:
        _last_batch = batch
    _record_scan(batch, source="url")

    return {
        "url": req.url,
        "title": fetch_result.title,
        "total_scripts": fetch_result.total_scripts,
        "summary": batch.to_dict(),
    }


# ---------------------------------------------------------------------------
# GitHub 仓库扫描
# ---------------------------------------------------------------------------
def _clone_and_collect(req: GithubScanRequest) -> tuple[Optional[str], Optional[list], Optional[JSONResponse]]:
    """同步：克隆仓库 + 遍历代码文件。放线程池执行，避免阻塞事件循环。

    Returns:
        (error_response, None, None) 失败；
        (None, code_files, tmp_dir) 成功（tmp_dir 需调用方清理）。
    """
    # SSRF 防护：仓库地址仅允许公网 http/https（内网/回环地址在此拦截）
    url_err = validate_target_url(req.repo_url)
    if url_err:
        return None, None, JSONResponse({"error": url_err}, status_code=400)

    tmp_dir = tempfile.mkdtemp(prefix="vuln_scan_")
    repo_name = req.repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    repo_name = re.sub(r"[^A-Za-z0-9_.-]", "_", repo_name) or "repo"
    if repo_name in (".", ".."):
        repo_name = "repo"
    clone_target = os.path.join(tmp_dir, repo_name)

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--", req.repo_url, clone_target],
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        if result.returncode != 0:
            return tmp_dir, None, JSONResponse(
                {"error": f"git clone 失败: {result.stderr[:500]}"},
                status_code=502,
            )
    except subprocess.TimeoutExpired:
        return tmp_dir, None, JSONResponse({"error": "git clone 超时（120s）"}, status_code=504)
    except FileNotFoundError:
        return tmp_dir, None, JSONResponse({"error": "系统未安装 git"}, status_code=500)

    code_files = []
    for root, _dirs, fnames in os.walk(clone_target):
        # 按路径段精确匹配跳过依赖/版本目录（子串匹配会误伤 x.gitlab 等合法目录名）
        if set(Path(root).parts) & {".git", "node_modules", "vendor", "__pycache__"}:
            continue
        for fname in fnames:
            ext = Path(fname).suffix.lower()
            if ext not in EXT_TO_LANG:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fp:
                    content = fp.read()
                rel_path = os.path.relpath(fpath, clone_target)
                code_files.append((rel_path, EXT_TO_LANG[ext], content))
            except Exception:
                continue
            if len(code_files) >= req.max_files:
                break
        if len(code_files) >= req.max_files:
            break

    return tmp_dir, code_files, None


@app.post("/api/github-scan")
async def github_scan(req: GithubScanRequest, request: Request):
    """clone GitHub 仓库 → 遍历代码文件 → 批量扫描（LOW 优先级）。"""
    client_id = resolve_client_id(request.headers.get("x-client-type"), fallback="web")
    tmp_dir, code_files, err = await asyncio.to_thread(_clone_and_collect, req)

    try:
        if err is not None:
            return err

        if not code_files:
            return {"repo": req.repo_url, "message": "仓库中未找到支持的代码文件"}

        batch = await _scan_files_scheduled(code_files, req.use_rag, client_id)
        global _last_batch
        with _stats_lock:
            _last_batch = batch
        _record_scan(batch, source="github")

        return {
            "repo": req.repo_url,
            "scanned_files": len(code_files),
            "summary": batch.to_dict(),
        }
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 报告下载
# ---------------------------------------------------------------------------
@app.get("/api/report")
async def download_report():
    """下载最近一次批量扫描的 Markdown 报告。"""
    with _stats_lock:
        last_batch = _last_batch
    if last_batch is None:
        return JSONResponse({"error": "暂无扫描结果，请先扫描"}, status_code=404)
    md = render_batch_markdown(last_batch)
    return StreamingResponse(
        iter([md.encode("utf-8")]),
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=vuln_scan_report.md"},
    )


@app.post("/api/report/single")
async def download_single_report(req: AnalyzeRequest, request: Request):
    """分析并返回单文件 Markdown 报告（与 /api/analyze 一样走调度器，避免插队）。"""
    client_id = resolve_client_id(request.headers.get("x-client-type"))
    priority = resolve_priority(request.headers.get("x-scan-scope"), PRIORITY_HIGH)

    _, future = scheduler.submit(
        priority, client_id,
        lambda: scanner.scan_code(
            code=req.code, language=req.language,
            filename=req.filename, use_rag=req.use_rag,
        ),
        description=f"report/single:{req.filename}",
    )
    result, err = await _await_scan(future)
    if err is not None:
        return err
    md = render_single_markdown(result)
    return StreamingResponse(
        iter([md.encode("utf-8")]),
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=single_report.md"},
    )


# ---------------------------------------------------------------------------
# 外部工具扫描（Bandit / Semgrep / Gitleaks / Trivy）
# ---------------------------------------------------------------------------
@app.post("/api/external-scan")
def external_scan(req: ExternalScanRequest):
    """调用传统安全工具对代码做 SAST/SCA/Secret/IaC 扫描。

    将粘贴代码写入临时文件后运行 ExternalScanner，未安装的工具静默跳过。
    返回 ExternalFinding 列表，供前端与 LLM 结果融合展示。
    """
    ext = ExternalScanner()
    suffix = Path(req.filename).suffix.lower() or ".py"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(req.code)
        tmp_path = tmp.name
    try:
        findings = ext.scan(tmp_path, req.language)
        return {
            "available_tools": ext.available_tools(),
            "total": len(findings),
            "findings": [
                {
                    "tool": f.tool,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "message": f.message,
                    "filename": f.filename,
                    "line": f.line,
                    "category": f.category,
                }
                for f in findings
            ],
        }
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# 修复建议验证
# ---------------------------------------------------------------------------
@app.post("/api/verify-fix")
def verify_fix(req: VerifyFixRequest):
    """校验修复建议：行号锚定合法性 + 旧式代码块语法/危险模式检查。

    schema 已改为"行号锚定的局部修复建议"（单行、不含完整代码），因此主校验是
    提取建议中的 line N / 第 N 行 引用并核对是否落在原始代码真实行数内。
    若建议仍包含代码围栏（旧格式），顺带跑 FixVerifier 的语法 + 危险模式移除检查。
    """
    verifier = FixVerifier()
    anchor = validate_fix_suggestion(req.fix_suggestion, req.original_code)
    result = verifier.verify_fix(
        original_code=req.original_code,
        fix_suggestion=req.fix_suggestion,
        language=req.language,
    ) if anchor["code_block"] else None
    return {
        "mode": "code_block" if anchor["code_block"] else "localized",
        "line_refs": anchor["line_refs"],
        "total_lines": anchor["total_lines"],
        "all_refs_valid": anchor["all_refs_valid"],
        "code_block": anchor["code_block"],
        "syntax_valid": result.syntax_valid if result else None,
        "tests_passed": result.tests_passed if result else None,
        "fixed_code": result.fixed_code if result else None,
        "error_message": result.error_message if result else (
            None if anchor["all_refs_valid"] else "建议未引用代码中真实存在的行号"
        ),
        "duration": round(result.duration, 2) if result else 0.0,
    }


# ---------------------------------------------------------------------------
# 多模型投票扫描
# ---------------------------------------------------------------------------
@app.post("/api/multi-model-scan")
async def multi_model_scan(req: MultiModelRequest, request: Request):
    """多模型交叉验证扫描：顺序加载各模型 → 投票聚合 → 返回 VoteResult。

    前端需传入 ≥2 个模型名；任一时刻显存只驻留单模型（keep_alive=0）。
    走 Ollama，纳入调度器（交互式 HIGH 优先级）。
    """
    if len(req.models) < 2:
        return JSONResponse(
            {"error": "多模型投票至少需要 2 个模型，当前仅 " + str(len(req.models)) + " 个"},
            status_code=400,
        )
    client_id = resolve_client_id(request.headers.get("x-client-type"))
    priority = resolve_priority(request.headers.get("x-scan-scope"), PRIORITY_HIGH)

    def _run():
        mms = MultiModelScanner(
            models=req.models,
            use_prefilter=True,
            keep_alive=0,
        )
        return mms.scan_code(
            code=req.code,
            language=req.language,
            filename=req.filename,
            use_rag=req.use_rag,
        )

    _, future = scheduler.submit(
        priority, client_id, _run,
        description=f"multi-model:{req.filename}",
    )
    result, err = await _await_scan(future)
    if err is not None:
        return err
    return result.to_dict()


# ---------------------------------------------------------------------------
# vLLM 推理后端单文件分析
# ---------------------------------------------------------------------------
@app.post("/api/vllm-analyze")
def vllm_analyze(req: VllmAnalyzeRequest):
    """使用 vLLM（OpenAI 兼容 API）后端分析单段代码。

    vLLM 通过 PagedAttention + continuous batching 提供高吞吐推理，
    适合批量评测场景；接口与 /api/analyze 对齐，便于前端无缝切换后端。
    """
    vllm_client = VLLMClient()
    if not vllm_client.check_connection():
        return JSONResponse(
            {"error": "vLLM 服务未启动（默认 http://localhost:8000）"},
            status_code=503,
        )

    # 与 /api/analyze 走同一套扫描流水线（预筛/切片/RAG/污点/约束解码兜底），
    # 仅替换推理后端为 vLLM，避免绕过 Scanner 导致能力不一致。
    # 注意：此处有意绕过优先级调度器——调度器是为 Ollama OLLAMA_NUM_PARALLEL=1 的
    # 单并发显存约束设计；vLLM 自带 PagedAttention + continuous batching 高吞吐并发，
    # 直接同步推理即可，不占用 Ollama 队列（避免 vLLM 任务被误排 LOW 拖慢）。
    vllm_scanner = Scanner(
        model=vllm_client.model,
        client=vllm_client,
        use_rag=os.environ.get("VULN_SCANNER_RAG", "0") == "1",
        use_prefilter=os.environ.get("VULN_SCANNER_PREFILTER", "1") != "0",
    )
    return vllm_scanner.scan_code(
        code=req.code, language=req.language, filename=req.filename,
        use_rag=req.use_rag,
    ).to_dict()


# ---------------------------------------------------------------------------
# 模型管理（拉取 / 删除 / 切换 / 查询）—— 仅限 garrywhite109909 命名空间
# ---------------------------------------------------------------------------
class ModelActionRequest(BaseModel):
    model: str = Field(..., description="模型全名，如 garrywhite109909/graduation-vuln-scanner:v9max")


class HfDownloadRequest(BaseModel):
    """HuggingFace 基座模型下载请求（transformers / vllm 后端）。

    backend: "transformers" → models/transformers/<名称>；"vllm" → models/vllm/<名称>。
    """
    model_id: str = Field(..., description="HuggingFace 模型 ID，如 Qwen/Qwen3-8B")
    backend: str = Field("transformers", description="目标后端：transformers / vllm")


class GgufDownloadRequest(BaseModel):
    """GGUF 文件下载请求（llama.cpp 后端）。"""
    url: str = Field(..., max_length=2048, description="GGUF 下载 URL")
    filename: str = Field(..., max_length=256, description="保存文件名，如 v9max-q4_k_m.gguf")


@app.get("/api/models/registry")
def models_registry():
    """返回已登记的模型清单（前端模型管理 UI 数据源）。

    每个模型包含 display_name / description / prompt_variant / deprecated 等元数据。
    前端只允许拉取/删除/切换此处登记的模型。
    """
    return {"models": list_registry()}


def _model_mgmt_gate(capability: str):
    """非 Ollama 后端（transformers/llamacpp 等进程内推理）无模型管理接口，
    对应路由返回 501 而非 500/误报。"""
    caps = scanner.model_management_capabilities()
    if not caps.get(capability):
        return JSONResponse(
            {"error": f"当前推理后端（{type(scanner.client).__name__}）不支持模型{capability}操作，"
                      "模型管理仅 Ollama 后端可用",
             "backend": type(scanner.client).__name__,
             "model_management": caps},
            status_code=501,
        )
    return None


@app.get("/api/models/installed")
def models_installed():
    """返回已安装的模型列表（从 Ollama /api/tags 过滤 garrywhite109909 命名空间）。

    每个模型附带注册表中的元数据（display_name / deprecated 等）和磁盘占用。
    非 Ollama 后端无模型列表能力：返回空列表 + management_supported=false。
    """
    caps = scanner.model_management_capabilities()
    if not caps["list"]:
        return {
            "installed": [],
            "active_model": scanner.model,
            "management_supported": False,
            "backend": type(scanner.client).__name__,
        }
    registry = {m["full_name"]: m for m in list_registry()}
    installed = []
    for name in scanner.client.list_models():
        name = normalize_ollama_name(name)  # :latest → 无标签，与注册表 full_name 对齐
        if name in registry:
            info = dict(registry[name])
            info["installed"] = True
            info["size_bytes"] = scanner.client.get_model_size(name)
            installed.append(info)
    return {
        "installed": installed,
        "active_model": scanner.model,
        "management_supported": True,
    }


@app.post("/api/models/pull")
async def models_pull(req: ModelActionRequest):
    """流式拉取模型（NDJSON 流，每行含 status / completed / total / digest）。

    拉取完成后模型即可使用（Modelfile 已内置 SYSTEM prompt 和推理参数）。
    仅允许拉取注册表中的模型。
    """
    if not is_allowed(req.model):
        return JSONResponse(
            {"error": f"模型 {req.model} 不在允许列表中"}, status_code=403,
        )
    gate = _model_mgmt_gate("pull")
    if gate is not None:
        return gate

    async def stream():
        import queue as _q
        import threading

        chunk_queue: _q.Queue = _q.Queue()
        done_flag = {"done": False, "result": None}

        def callback(chunk):
            chunk_queue.put(chunk)

        def run_pull():
            result = scanner.client.pull_model(req.model, stream_callback=callback)
            done_flag["result"] = result
            done_flag["done"] = True
            chunk_queue.put(None)  # 哨兵，唤醒流式迭代

        thread = threading.Thread(target=run_pull, daemon=True)
        thread.start()

        while True:
            try:
                chunk = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: chunk_queue.get(timeout=1),
                )
            except Exception:
                if done_flag["done"]:
                    break
                continue
            if chunk is None:
                break
            yield json.dumps(chunk, ensure_ascii=False) + "\n"
            if chunk.get("error"):
                break

        result = done_flag["result"] or {}
        if result.get("success"):
            yield json.dumps({"status": "success", "completed": True}, ensure_ascii=False) + "\n"
        elif not result.get("error"):
            yield json.dumps({"status": result.get("final_status", "unknown"),
                              "error": "拉取未完成"}, ensure_ascii=False) + "\n"

    return StreamingResponse(stream(), media_type="application/x-ndjson")


@app.delete("/api/models/{model_name:path}")
def models_delete(model_name: str):
    """删除模型（从 ~/.ollama 目录彻底删除 blob 文件，释放磁盘空间）。

    模型全名含 / 与 :（如 garrywhite109909/graduation-vuln-scanner:v9max），
    故使用 :path 转换器匹配整段路径。前端需对模型名做 encodeURIComponent。
    仅允许删除注册表中的模型。
    """
    # URL 解码后的模型名可能含 / :，FastAPI path 参数已自动解码
    if not is_allowed(model_name):
        return JSONResponse(
            {"error": f"模型 {model_name} 不在允许列表中"}, status_code=403,
        )
    gate = _model_mgmt_gate("delete")
    if gate is not None:
        return gate
    # 如果删除的是当前活动模型，先切回默认模型
    if scanner.model == model_name:
        default = get_default_model()
        if default != model_name:
            scanner.switch_model(default)
    result = scanner.client.delete_model(model_name)
    if result["success"]:
        return {"deleted": True, "model": model_name}
    return JSONResponse(
        {"deleted": False, "model": model_name, "error": result["error"]},
        status_code=500,
    )


@app.post("/api/models/activate")
def models_activate(req: ModelActionRequest):
    """切换当前活动模型。队列中的待执行任务也会用新模型。

    根据模型注册表自动切换 system prompt：
    - v9max → BASE_PROMPT
    - v5    → SYSTEM_PROMPT_LITE
    """
    if not is_allowed(req.model):
        return JSONResponse(
            {"error": f"模型 {req.model} 不在允许列表中"}, status_code=403,
        )
    gate = _model_mgmt_gate("activate")
    if gate is not None:
        return gate
    # 检查模型是否已安装
    installed = scanner.client.list_models()
    if req.model not in installed:
        return JSONResponse(
            {"error": f"模型 {req.model} 未安装，请先拉取"}, status_code=409,
        )
    scanner.switch_model(req.model)
    return {"activated": True, "model": req.model}


# ---------------------------------------------------------------------------
# 进程内后端模型下载（transformers / llamacpp）—— 下载到 models/ 分类目录
# ---------------------------------------------------------------------------

# HuggingFace 镜像（国内加速），可通过环境变量覆盖
# （HF_ENDPOINT 已在文件顶部、任何 huggingface_hub import 之前设置，这里仅保留常量供界面展示）
HF_MIRROR = os.environ.get("VULN_SCANNER_HF_MIRROR", "https://hf-mirror.com").strip() or "https://hf-mirror.com"

# llamacpp 后端所需的"未合并基座" GGUF —— 官方 Qwen3-8B-GGUF 的 Q4_K_M（与 LoRA adapter 同源）。
# 下载按钮固定指向它，与 transformers 后端"只能下载所需模型"对齐：基座 + models/adapter 的
# LoRA 在运行时叠加（lora_path），绝不能下成已合并 LoRA 的发布 GGUF（否则二次叠加，结果错误）。
LLAMACPP_BASE_GGUF_URL = (
    os.environ.get(
        "VULN_SCANNER_GGUF_URL",
        "https://huggingface.co/Qwen/Qwen3-8B-GGUF/resolve/main/Qwen3-8B-Q4_K_M.gguf",
    ).strip()
    or "https://huggingface.co/Qwen/Qwen3-8B-GGUF/resolve/main/Qwen3-8B-Q4_K_M.gguf"
)


def _no_proxy_for_mirrors(*hosts: str) -> None:
    """让指定的国内镜像域名直连、不走代理（写入并合并 NO_PROXY/no_proxy）。

    用户机器常配置 HTTP_PROXY/HTTPS_PROXY（科学上网）。若 hf-mirror.com / ghproxy 等
    镜像下载也走代理，既会秒断（代理对国内域名路由不佳），又会白白消耗代理流量
    （几个 GB 的模型流量瞬间用光）。这里把镜像域名追加进 NO_PROXY，强制直连镜像。
    """
    no_proxy = set(
        h.strip()
        for h in os.environ.get("NO_PROXY", "").replace(";", ",").split(",")
        if h.strip()
    )
    no_proxy |= {h for h in hosts if h and h.strip()}
    val = ",".join(sorted(no_proxy))
    os.environ["NO_PROXY"] = val
    os.environ["no_proxy"] = val


def _models_dir() -> Path:
    """返回项目 models/ 目录（不存在则创建）。"""
    d = find_project_root() / "models"
    d.mkdir(parents=True, exist_ok=True)
    return d


@app.get("/api/models/local-resources")
def models_local_resources():
    """返回进程内后端（transformers/llamacpp）需要的本地资源及下载状态。

    Ollama 后端返回空资源列表（模型管理走 /api/models/* 端点）。
    """
    caps = scanner.model_management_capabilities()
    if caps["list"]:
        return {"backend": "ollama", "management_supported": True, "resources": []}

    client = scanner.client
    cls_name = type(client).__name__
    resources: list[dict] = []

    if cls_name == "TransformersClient":
        model_id = getattr(client, "model_id", "") or resolve_base_model_path()
        available, status = _detect_model_available("transformers", client)
        # 下载/检测唯一位置：项目扁平基座目录 models/transformers/<名称>
        # （自动下载、设置页下载按钮、迁移、就绪检测、加载全部落这里，与调用路径一致）
        cache_dir = local_hf_model_dir(model_id)
        resources.append({
            "type": "huggingface",
            "id": model_id,
            "name": model_id,
            "description": "基座模型（HuggingFace，约 16GB）",
            "available": available,
            "status": status,
            "download_endpoint": "/api/models/download-hf",
            "download_path": str(cache_dir),
            "mirror": HF_MIRROR,
        })
        adapter = resolve_adapter_path(getattr(client, "adapter", ""))
        resources.append({
            "type": "adapter",
            "path": str(adapter) if adapter else "",
            "available": bool(adapter) and Path(adapter).is_dir(),
            "description": "LoRA adapter（训练产物，自动探测 models/adapter/ 目录）",
        })

    elif cls_name == "LlamaCppClient":
        base_gguf = getattr(client, "base_gguf", "") or os.environ.get("VULN_SCANNER_GGUF", "")
        available, status = _detect_model_available("llamacpp", client)
        # GGUF 固定基座：官方 Qwen3-8B-GGUF Q4_K_M（未合并基座，与 LoRA adapter 同源）。
        # 与 transformers 后端固定 model_id 对齐，下载按钮只能拉取该基座，避免误下合并发布 GGUF。
        resources.append({
            "type": "gguf",
            "path": base_gguf,
            "available": available,
            "status": status,
            "description": "Q4 GGUF 未合并基座（官方 Qwen3-8B-GGUF）",
            "download_endpoint": "/api/models/download-gguf",
            "download_path": str(llamacpp_dir()),
            "default_url": LLAMACPP_BASE_GGUF_URL,
        })
        adapter = resolve_adapter_path(getattr(client, "adapter", ""))
        resources.append({
            "type": "adapter",
            "path": str(adapter) if adapter else "",
            "available": bool(adapter) and Path(adapter).is_dir(),
            "description": "LoRA adapter（训练产物，自动探测 models/adapter/ 目录）",
        })

    elif cls_name == "VLLMClient":
        # vLLM 是独立服务进程，模型在服务端加载。这里报告服务连接状态，并
        # 提供 AWQ/GPTQ 基座下载到项目 models/vllm/（与 transformers 对齐）。
        public = getattr(client, "base_url", "") or os.environ.get("VULN_SCANNER_VLLM_URL", "http://localhost:8000")
        available, status = _detect_model_available("vllm", client)
        # 默认基座（AWQ 量化版，与 transformers 的 Qwen3-8B 同源、不同量化策略）
        vllm_model_id = os.environ.get("VULN_SCANNER_VLLM_MODEL_ID", "Qwen/Qwen3-8B-AWQ")
        vllm_dir = local_vllm_model_dir(vllm_model_id)
        resources.append({
            "type": "vllm_server",
            "id": vllm_model_id,
            "path": public,
            "available": available,
            "status": status,
            "description": "vLLM 服务（AWQ/GPTQ 4bit 基座 + FP16 LoRA）",
            "download_endpoint": "/api/models/download-hf",
            "download_path": str(vllm_dir),
            "default_model_id": vllm_model_id,
            "mirror": HF_MIRROR,
            "hint": "用 app/launcher/vllm_server.py 启动服务；--model 指向 models/vllm/ 下的量化目录，--served-model-name 需与当前模型一致",
        })

    return {
        "backend": cls_name,
        "management_supported": False,
        "resources": resources,
    }


@app.post("/api/models/download-hf")
async def models_download_hf(req: HfDownloadRequest):
    """流式下载 HuggingFace 基座模型到项目 models/ 目录（NDJSON 进度）。

    目标：models/transformers/<名称>（与自动下载/检测/迁移同一位置）。
    使用 hf-mirror.com 镜像加速国内下载；下载支持断点续传。
    """
    import queue as _q
    import threading
    import traceback

    model_id = req.model_id.strip()
    if not model_id:
        return JSONResponse({"error": "model_id 不能为空"}, status_code=400)

    # 下载目标：按后端落到项目 models/ 分类目录（与加载/检测/迁移同一位置，调用路径一致）
    #   - transformers → models/transformers/<名称>（扁平基座目录，可续传）
    #   - vllm        → models/vllm/<名称>（AWQ/GPTQ 量化目录，与 transformers 对齐）
    if (req.backend or "transformers").strip().lower() == "vllm":
        cache_dir = local_vllm_model_dir(model_id)
    else:
        cache_dir = local_hf_model_dir(model_id)

    chunk_queue: _q.Queue = _q.Queue()
    done_flag = {"done": False, "result": None, "error": None}

    # 网络操作超时（秒）：列表/单文件元数据请求不宜过长，大文件传输由 hf_hub_download 内部管理
    HF_NETWORK_TIMEOUT = 60

    def _friendly_error(e: Exception, phase: str) -> str:
        """把 huggingface_hub 异常转换成用户可操作的提示。"""
        name = type(e).__name__
        msg = str(e)
        lower = (name + " " + msg).lower()
        if "import" in lower and "huggingface_hub" in lower:
            return "huggingface_hub 未安装，请运行启动器让依赖安装完成"
        if any(k in lower for k in ("timeout", "timed out", "connecttimeout")):
            return (
                f"连接镜像超时（{phase}）：请检查能否访问 {HF_MIRROR}，"
                "或尝试设置系统代理/HTTP_PROXY 后重试"
            )
        if any(k in lower for k in ("connection", "refused", "reset", "name or service not known", "getaddrinfo")):
            return (
                f"无法连接到镜像（{phase}）：请检查网络、代理设置，"
                f"或尝试浏览器直接打开 {HF_MIRROR}/Qwen/Qwen3-8B"
            )
        if "401" in lower or "unauthorized" in lower or "access" in lower:
            return f"访问仓库被拒绝（{phase}）：请检查 HuggingFace Token/权限"
        if "404" in lower or "not found" in lower:
            return f"仓库或文件不存在（{phase}）：{model_id}"
        return f"{phase}失败 ({name}): {msg}"

    def run_download():
        try:
            os.environ["HF_ENDPOINT"] = HF_MIRROR
            # 国内镜像直连、不走代理：避免代理秒断 + 白白消耗代理流量
            _hf_host = urlparse(HF_MIRROR).hostname or "hf-mirror.com"
            _no_proxy_for_mirrors(_hf_host)
            try:
                from huggingface_hub import list_repo_files, hf_hub_download
            except Exception as e:
                raise RuntimeError(_friendly_error(e, "导入 huggingface_hub")) from e

            # 立即报告开始连接镜像，让用户知道按钮已生效
            chunk_queue.put({"status": "downloading", "message": f"正在连接镜像 {HF_MIRROR}…", "pct": 0})

            # 获取仓库文件列表（进度估算用）
            # 注意：list_repo_files 不接受 timeout 参数（huggingface_hub 1.x 传入会抛
            # TypeError 并被误判为"连接超时"），这里不带该参数；实际大文件传输由
            # hf_hub_download 的 timeout 负责。
            files: list[str] = []
            total_files = 0
            try:
                files = list_repo_files(model_id)
                total_files = len(files)
            except Exception as e:
                err = _friendly_error(e, "获取文件列表")
                print(f"[download-hf] list_repo_files 失败: {err}", flush=True)
                traceback.print_exc()
                raise RuntimeError(err) from e

            chunk_queue.put({"status": "downloading", "total_files": total_files, "completed": 0, "pct": 0})

            # 逐文件下载，每完成一个文件报告进度（显式 endpoint 指向镜像；
            # huggingface_hub 1.x 的 hf_hub_download 不接受 timeout 参数，元数据用 etag_timeout 兜底）
            completed_files = 0
            for fname in files:
                try:
                    hf_hub_download(
                        repo_id=model_id,
                        filename=fname,
                        local_dir=str(cache_dir),
                        local_dir_use_symlinks=False,
                        resume_download=True,
                        endpoint=HF_MIRROR,
                        etag_timeout=HF_NETWORK_TIMEOUT,
                    )
                except Exception as e:
                    err = _friendly_error(e, f"下载 {fname}")
                    print(f"[download-hf] hf_hub_download 失败: {err}", flush=True)
                    traceback.print_exc()
                    raise RuntimeError(err) from e
                completed_files += 1
                pct = int(completed_files / total_files * 100) if total_files else 0
                chunk_queue.put({
                    "status": "downloading",
                    "completed": completed_files,
                    "total": total_files,
                    "pct": pct,
                    "current_file": fname,
                })

            done_flag["result"] = {"dest": str(cache_dir), "model_id": model_id}
        except Exception as e:
            done_flag["error"] = str(e)
        finally:
            done_flag["done"] = True
            chunk_queue.put(None)

    thread = threading.Thread(target=run_download, daemon=True)
    thread.start()

    async def stream():
        while True:
            try:
                chunk = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: chunk_queue.get(timeout=2),
                )
            except Exception:
                if done_flag["done"]:
                    break
                # 超时但未完成，发送心跳保持连接
                yield json.dumps({"status": "downloading", "heartbeat": True}, ensure_ascii=False) + "\n"
                continue
            if chunk is None:
                break
            yield json.dumps(chunk, ensure_ascii=False) + "\n"

        if done_flag["error"]:
            yield json.dumps({"status": "error", "error": done_flag["error"]}, ensure_ascii=False) + "\n"
        elif done_flag["result"]:
            r = done_flag["result"]
            # 下载完成后：若下载的正是当前 transformers 后端预期的基座（按仓库名匹配），
            # 直接把客户端指向本地路径并后台加载，避免"需重启"的空窗期，首次分析立即可用。
            auto_loaded = False
            try:
                client = scanner.client
                if type(client).__name__ == "TransformersClient":
                    if Path(r["dest"]).name == (client.model_id or "").split("/")[-1]:
                        if (Path(r["dest"]) / "config.json").is_file():
                            client.model_id = str(Path(r["dest"]))
                            client.model = client.model_id
                            _trigger_transformers_warmup()
                            auto_loaded = True
            except Exception:
                auto_loaded = False
            msg = (
                f"基座模型已下载到 {r['dest']}，已开始后台加载（首次分析立即可用）"
                if auto_loaded else
                f"基座模型已下载到 {r['dest']}，请重启后端以加载（设置 VULN_SCANNER_MODEL_ID={r['model_id']} 或指向本地路径）"
            )
            yield json.dumps({
                "status": "success", "completed": True,
                "dest": r["dest"],
                "message": msg,
            }, ensure_ascii=False) + "\n"

    return StreamingResponse(
        stream(),
        media_type="application/x-ndjson",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control": "no-cache",
        },
    )


@app.post("/api/models/download-gguf")
async def models_download_gguf(req: GgufDownloadRequest):
    """流式下载 GGUF 文件到项目 models/llamacpp/ 目录（NDJSON 进度）。

    对 GitHub URL 自动加 ghproxy 镜像加速。下载完成后需重启后端使配置生效。
    """
    import queue as _q
    import threading
    from urllib.request import urlopen

    url = req.url.strip()
    filename = req.filename.strip()
    if not url or not filename:
        return JSONResponse({"error": "url 和 filename 不能为空"}, status_code=400)
    # 防路径穿越
    if "/" in filename or "\\" in filename or ".." in filename:
        return JSONResponse({"error": "filename 含非法字符"}, status_code=400)

    # 只允许下载"未合并基座" GGUF：拒绝指向已合并 LoRA 的发布模型（URL/文件名含其标记）。
    # 否则基座本身已带 LoRA，运行时再经 lora_path 叠加会二次叠加，结果错误。
    _merged_markers = ("merged", "graduation-vuln-scanner", "graduation_vuln_scanner", "v9max")
    _low_url = url.lower()
    _low_name = filename.lower()
    if any(m in _low_url for m in _merged_markers) or any(m in _low_name for m in _merged_markers):
        return JSONResponse({
            "error": "拒绝下载已合并 LoRA 的发布 GGUF。llamacpp 需要【未合并基座】（官方 Qwen3-8B-GGUF），"
                     "基座 + models/adapter 的 LoRA 在运行时叠加；请下载官方基座。",
        }, status_code=400)

    # 国内加速：GitHub 加 ghproxy；HuggingFace 走 HF_MIRROR（与 transformers 下载口径一致）
    if url.startswith("https://github.com/"):
        url = "https://mirror.ghproxy.com/" + url
    elif url.startswith("https://huggingface.co/"):
        url = HF_MIRROR + url[len("https://huggingface.co"):]

    dest_dir = llamacpp_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / filename
    chunk_queue: _q.Queue = _q.Queue()
    done_flag = {"done": False, "result": None, "error": None}

    # HuggingFace resolve 链接：/repo_id/resolve/<revision>/<file>
    _HF_RESOLVE_RE = re.compile(r"^/(?P<repo>.+?)/resolve/(?P<rev>[^/]+)/(?P<file>.+)$")

    def run_download():
        try:
            # HuggingFace resolve URL → 复用 huggingface_hub 的 hf_hub_download
            # （断点续传 + 重试 + 走 HF_MIRROR 镜像），与 transformers 下载同栈，
            # 避免裸 urlopen 直连 hf-mirror.com 大文件连接超时（WinError 10060）。
            _hf_match = _HF_RESOLVE_RE.match(urlparse(url).path)
            if _hf_match:
                def _hf_download(_bypass_proxy: bool) -> str:
                    # 直连回退时把镜像域名塞进 NO_PROXY，强制不走系统代理；
                    # 首次（代理优先）保持环境原样，让 hf_hub_download 按
                    # HTTP_PROXY/HTTPS_PROXY 走代理，失败再回退直连。
                    if _bypass_proxy:
                        _no_proxy_for_mirrors(urlparse(url).hostname or "")
                    os.environ["HF_ENDPOINT"] = HF_MIRROR
                    from huggingface_hub import hf_hub_download
                    return hf_hub_download(
                        repo_id=_hf_match.group("repo"),
                        filename=_hf_match.group("file"),
                        local_dir=str(dest_dir),
                        local_dir_use_symlinks=False,
                        resume_download=True,
                        endpoint=HF_MIRROR,
                        etag_timeout=60,
                    )

                chunk_queue.put({
                    "status": "downloading",
                    "message": f"正在连接镜像 {HF_MIRROR}…",
                    "pct": 0,
                })
                try:
                    # 1) 代理优先：不注入 NO_PROXY，走系统代理（无代理则直连）
                    local = _hf_download(_bypass_proxy=False)
                except Exception as _e:
                    # 2) 直连回退：强制镜像直连再试一次
                    print(f"[download-gguf] 走代理下载失败({type(_e).__name__}: {_e})，回退镜像直连", flush=True)
                    local = _hf_download(_bypass_proxy=True)
                actual = Path(local)
                total = actual.stat().st_size
                chunk_queue.put({
                    "status": "downloading",
                    "completed": total,
                    "total": total,
                    "pct": 100,
                })
                done_flag["result"] = {"dest": str(actual), "filename": actual.name}
                return

            # 非 HuggingFace URL（如 GitHub 大文件）：回退 urlopen，带重试避免偶发断连
            with urlopen(url, timeout=60) as resp, open(dest_path, "wb") as f:
                total = int(resp.headers.get("content-length", 0))
                downloaded = 0
                chunk_size = 1024 * 1024  # 1MB
                last_report = 0
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    pct = int(downloaded / total * 100) if total else 0
                    # 每 2% 报告一次，避免队列爆炸
                    if pct - last_report >= 2 or pct == 100:
                        chunk_queue.put({
                            "status": "downloading",
                            "completed": downloaded,
                            "total": total,
                            "pct": pct,
                        })
                        last_report = pct
            # 完整性校验：content-length 与实际字节数不符视为下载失败，避免残缺文件被当作就绪模型
            if total > 0 and downloaded != total:
                raise ValueError(f"下载不完整: {downloaded}/{total} 字节")
            done_flag["result"] = {"dest": str(dest_path), "filename": filename}
        except Exception as e:
            done_flag["error"] = f"{type(e).__name__}: {e}"
        finally:
            done_flag["done"] = True
            chunk_queue.put(None)

    thread = threading.Thread(target=run_download, daemon=True)
    thread.start()

    async def stream():
        while True:
            try:
                chunk = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: chunk_queue.get(timeout=2),
                )
            except Exception:
                if done_flag["done"]:
                    break
                yield json.dumps({"status": "downloading", "heartbeat": True}, ensure_ascii=False) + "\n"
                continue
            if chunk is None:
                break
            yield json.dumps(chunk, ensure_ascii=False) + "\n"

        if done_flag["error"]:
            yield json.dumps({"status": "error", "error": done_flag["error"]}, ensure_ascii=False) + "\n"
        elif done_flag["result"]:
            r = done_flag["result"]
            # 与 transformers 下载后自动加载对齐：llamacpp 下载完成直接绑定到当前客户端，
            # 首次扫描即自动加载，无需重启后端
            auto_bound = False
            try:
                client = scanner.client
                if type(client).__name__ == "LlamaCppClient":
                    client.base_gguf = r["dest"]
                    client.model = r["dest"]
                    auto_bound = True
            except Exception:
                auto_bound = False
            msg = (
                f"GGUF 已下载到 {r['dest']} 并已绑定到当前 llamacpp 后端，首次扫描将自动加载"
                if auto_bound else
                f"GGUF 已下载到 {r['dest']}，请重启后端以加载（设置 VULN_SCANNER_GGUF={r['dest']}）"
            )
            yield json.dumps({
                "status": "success", "completed": True,
                "dest": r["dest"],
                "message": msg,
            }, ensure_ascii=False) + "\n"

    return StreamingResponse(
        stream(),
        media_type="application/x-ndjson",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control": "no-cache",
        },
    )


# ---------------------------------------------------------------------------
# 调度器队列管理（供 Web/插件查询排队状态、取消排队任务）
# ---------------------------------------------------------------------------
@app.get("/api/queue/status")
def queue_status():
    """返回当前调度队列状态：排队数、各优先级计数、当前执行任务、统计。

    客户端可轮询此端点展示“前面还有 N 个任务”的提示。
    """
    return scheduler.status()


@app.post("/api/queue/cancel/{task_id}")
def queue_cancel(task_id: str):
    """取消排队中的任务。正在执行的任务不可取消。

    Returns:
        {"canceled": true} 成功标记取消；
        {"canceled": false, "reason": "..."} 任务不存在或正在执行。
    """
    ok = scheduler.cancel(task_id)
    if ok:
        return {"canceled": True, "task_id": task_id}
    return JSONResponse(
        {"canceled": False, "task_id": task_id,
         "reason": "任务不存在或正在执行，无法取消"},
        status_code=409,
    )


# ---------------------------------------------------------------------------
# 静态资源托管（Vue 构建产物，开发时不存在则跳过）
# ---------------------------------------------------------------------------
_static_dir = Path(__file__).resolve().parent / "static"
if _static_dir.is_dir():
    # 根路径返回欢迎页，其余静态资源由 StaticFiles 托管
    @app.get("/", response_class=HTMLResponse)
    async def welcome():
        welcome_file = _static_dir / "welcome.html"
        if welcome_file.is_file():
            return FileResponse(str(welcome_file))
        return FileResponse(str(_static_dir / "index.html"))

    app.mount("/", StaticFiles(directory=str(_static_dir), html=True), name="static")
else:
    @app.get("/", response_class=HTMLResponse)
    async def index():
        return """
        <html><body>
        <h1>AI 漏洞扫描器 API</h1>
        <p>后端已启动。前端静态资源未构建（app/backend/static/ 不存在）。</p>
        <p>API 文档：<a href="/docs">/docs</a></p>
        </body></html>
        """


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.backend.main:app",
        host="127.0.0.1",
        port=8765,
        reload=False,
    )
