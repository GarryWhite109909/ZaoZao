"""
扫描编排服务 —— 复用 graduation_project 核心包，统一调度
LLM 推理 + 代码切片 + RAG 检索 + 传统规则预筛。

关键设计：
- system prompt 由 model_registry 统一选择（当前全部为 V3_PROMPT，
  训练/推理一致，不再按模型区分 lite/base 变体）
- RAG 可开关（Web 端默认开，插件端默认关）
- 预筛层（prefilter）可开关：开启后对明显漏洞/安全样本直接短路，跳过 LLM
"""

from __future__ import annotations

import os
import threading
import time
from typing import Optional

from graduation_project.llm_client import OllamaClient
from graduation_project.prompts import build_user_prompt
from graduation_project.schema import parse_verdict, normalize_has_vulnerability
from graduation_project.cwe_normalizer import normalize_cwe_label
from graduation_project.code_slicer import CodeSlicer, SliceResult
from graduation_project.prefilter import Prefilter, PrefilterResult, PREFILTER_RULE_INFO
from app.backend.services.model_registry import get_default_model, get_prompt_for_model
from graduation_project.paths import resolve_adapter_path, resolve_base_model_path
from graduation_project.result_types import SingleResult
from graduation_project.transformers_client import resolve_default_backend

# 默认模型：从环境变量读取，缺省为注册表中的默认模型（当前 α0，已训练未评估；
# 论文口径当前已发布最佳仍为 v9max，二者区分见素材库「写作口径须知」）
DEFAULT_MODEL = os.environ.get("VULN_SCANNER_MODEL", get_default_model())
# 回退模型：官方 Qwen3-8B（未微调，用户首次未 pull 自定义模型时可用）
FALLBACK_MODEL = os.environ.get("VULN_SCANNER_FALLBACK_MODEL", "qwen3:8b")

def _resolve_default_backend() -> str:
    """解析默认推理后端（委托 transformes_client.resolve_default_backend，与启动器共用）。"""
    return resolve_default_backend()


DEFAULT_BACKEND = _resolve_default_backend()
# transformers 后端加载参数（Q4 基座 + FP16 LoRA）
DEFAULT_TRANSFORMERS_MODEL_ID = os.environ.get("VULN_SCANNER_MODEL_ID", "") or resolve_base_model_path()
# LoRA adapter 路径：优先 VULN_SCANNER_ADAPTER，其次自动探测项目根目录 models/
DEFAULT_TRANSFORMERS_ADAPTER = resolve_adapter_path()
DEFAULT_TRANSFORMERS_NUM_CTX = int(os.environ.get("VULN_SCANNER_NUM_CTX", "6144"))
# Chroma 知识库集合名
KNOWLEDGE_COLLECTION = "vuln_knowledge"

# 预筛规则名 → (CWE 标签, 风险等级)：预筛短路时给出与 LLM 一致的信息格式。
# 元数据统一来自 prefilter.PREFILTER_RULE_INFO，避免与两阶段扫描器两份映射漂移。
_PREFILTER_VULN_INFO = {
    name: (meta["cwe"], meta["risk"])
    for name, meta in PREFILTER_RULE_INFO.items()
}


class Scanner:
    """漏洞扫描编排器。

    Args:
        model: Ollama 模型名（默认注册表中的默认模型，当前 α0）
        base_url: Ollama 服务地址
        use_rag: 是否启用 RAG 知识库增强
        use_lite_prompt: 已废弃（保留参数兼容旧调用），prompt 现由 model_registry 自动选择，
            全部登记模型统一为 V3_PROMPT
        use_prefilter: 是否启用传统规则预筛层（True 时对明显样本短路跳过 LLM）
        use_structured_fallback: 是否在 CoT+JSON 解析失败时用 Ollama format=json 约束解码兜底
        use_taint_tracking: 是否启用轻量污点分析（source→sink 路径注入 LLM 上下文）
        keep_alive: 模型卸载策略（0=用完即卸，-1=常驻）
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = "http://localhost:11434",
        use_rag: bool = False,
        use_lite_prompt: bool = True,
        use_prefilter: bool = False,
        use_structured_fallback: bool = True,
        use_taint_tracking: bool = False,
        keep_alive=0,
        client: Optional[OllamaClient] = None,
        backend: Optional[str] = None,
    ):
        # 允许注入外部客户端（如 vLLM 后端），默认按 backend 选择推理后端
        if client is not None:
            self.client = client
        else:
            self.client = self._build_default_client(model, backend, base_url)
        self.model = model
        self.use_rag = use_rag
        self.use_prefilter = use_prefilter
        self.use_structured_fallback = use_structured_fallback
        self.use_taint_tracking = use_taint_tracking
        self.keep_alive = keep_alive
        # 从环境变量读取硬件适配配置（bootstrap.py 设置）；默认值与模块级常量统一
        self._num_ctx = int(os.environ.get("VULN_SCANNER_NUM_CTX", str(DEFAULT_TRANSFORMERS_NUM_CTX)))
        self._num_gpu = int(os.environ.get("VULN_SCANNER_NUM_GPU", "-1"))
        self._num_thread = int(os.environ.get("VULN_SCANNER_NUM_THREAD", "0"))
        # system prompt 由 model_registry 自动选择（当前全部登记模型统一为 V3_PROMPT）
        self.system_prompt = get_prompt_for_model(model)
        self.slicer = CodeSlicer(min_lines=150)
        self.prefilter = Prefilter() if use_prefilter else None
        self._taint_tracker = None
        self._chroma = None  # 延迟初始化（首次用 RAG 时才连 Chroma）
        # 模型切换锁：switch_model 与 scan_code 互斥，避免多 chunk 扫描中途切模型撕裂结果
        self._model_lock = threading.RLock()

    @staticmethod
    def _build_default_client(model: str, backend: Optional[str], base_url: str = "http://localhost:11434"):
        """按后端类型构建默认推理客户端。

        backend 取值：
            - "transformers"：TransformersClient（NF4 基座 + FP16 LoRA 进程内推理，
              自动探测到 models/adapter 且运行时兼容时作为默认）
            - "ollama"：OllamaClient（GGUF Q4_K_M 发布模型）
            - "llamacpp"：LlamaCppClient（Q4 GGUF 基座 + 运行时 FP16 LoRA，
              llama.cpp 内核快 + LoRA 保精度，需 llama-cpp-python 且 VULN_SCANNER_GGUF 指向基座）
            - "vllm"（实验性）：VLLMClient（OpenAI 兼容 API，PagedAttention + continuous batching 高吞吐，
              需先用 app/launcher/vllm_server.py 启动 vLLM 服务，VULN_SCANNER_VLLM_URL 指向其地址）

        base_url 仅对 ollama / vllm 后端生效（transformers / llamacpp 为进程内推理，
        无远端地址概念）。
        """
        backend = backend or DEFAULT_BACKEND
        if backend == "transformers":
            from graduation_project.transformers_client import TransformersClient
            return TransformersClient(
                model_id=DEFAULT_TRANSFORMERS_MODEL_ID,
                adapter=DEFAULT_TRANSFORMERS_ADAPTER,
                num_ctx=DEFAULT_TRANSFORMERS_NUM_CTX,
            )
        if backend == "llamacpp":
            from graduation_project.llamacpp_client import LlamaCppClient
            return LlamaCppClient(
                base_gguf=os.environ.get("VULN_SCANNER_GGUF", ""),
                adapter=DEFAULT_TRANSFORMERS_ADAPTER,
                num_ctx=DEFAULT_TRANSFORMERS_NUM_CTX,
            )
        if backend == "vllm":
            from graduation_project.vllm_client import VLLMClient
            vllm_url = base_url or os.environ.get("VULN_SCANNER_VLLM_URL", "http://localhost:8000")
            return VLLMClient(base_url=vllm_url, model=model)
        # 默认回退 Ollama
        return OllamaClient(base_url=base_url or "http://localhost:11434", model=model)

    def switch_model(self, model: str) -> None:
        """运行时切换活动模型。队列中的待执行任务也会用新模型。

        根据模型注册表自动选择对应的 system prompt（当前全部登记模型统一为
        V3_PROMPT，训练/推理一致；未登记模型回退 BASE_PROMPT）。

        与 scan_code 互斥：正在执行的扫描不会在 chunk 中途切换模型，
        避免同一文件的前后切片使用不同模型/提示词导致结果撕裂。
        """
        with self._model_lock:
            self.model = model
            self.client.model = model
            self.system_prompt = get_prompt_for_model(model)

    @property
    def chroma(self):
        """延迟加载 ChromaManager，避免未安装 chromadb 时报错。"""
        if self._chroma is None and self.use_rag:
            try:
                from graduation_project.chroma_manager import ChromaManager
                self._chroma = ChromaManager()
            except Exception as e:
                print(f"[Scanner] RAG 初始化失败，回退纯 LLM: {e}")
                self.use_rag = False
        return self._chroma

    @property
    def taint_tracker(self):
        """延迟加载 TaintTracker，避免未安装依赖时报错。"""
        if self._taint_tracker is None and self.use_taint_tracking:
            try:
                from graduation_project.taint_tracker import TaintTracker
                self._taint_tracker = TaintTracker()
            except Exception as e:
                print(f"[Scanner] 污点分析初始化失败，跳过: {e}")
                self.use_taint_tracking = False
        return self._taint_tracker

    def check_health(self) -> dict:
        """健康检查：后端连接 + 模型可用性 + 各层开关状态。

        兼容非 Ollama 后端（transformers/llamacpp 无 list_models 等管理接口）：
        管理类能力缺失时对应字段返回空/None，不抛异常。
        """
        try:
            connected = self.client.check_connection()
        except Exception:
            connected = False
        models = []
        if connected and hasattr(self.client, "list_models"):
            try:
                models = self.client.list_models()
            except Exception:
                models = []
        caps = self.model_management_capabilities()
        # 进程内后端（transformers/llamacpp/vllm）默认懒加载，模型未读入显存不代表引擎不可用。
        # 用 is_ready()（资源就绪即可）判定"引擎就绪"，避免健康检查强制加载 8B 模型。
        ready = connected
        if not caps["list"] and hasattr(self.client, "is_ready"):
            try:
                ready = self.client.is_ready()
            except Exception:
                ready = connected
        return {
            "backend": type(self.client).__name__,
            "ollama_connected": ready,  # 字段名保留兼容前端；非 Ollama 后端表示"推理后端就绪"
            "model": self.model,
            # 实际基座模型：transformers=model_id、llamacpp=GGUF 路径、ollama=模型名
            "base_model": (
                getattr(self.client, "model_id", None)
                or getattr(self.client, "base_gguf", None)
                or self.model
            ),
            # 无模型列表能力的后端（进程内推理）视为引擎随资源就绪
            "model_available": (self.model in models) if caps["list"] else ready,
            "available_models": models,
            "model_management": caps,
            "rag_enabled": self.use_rag,
            "prefilter_enabled": self.use_prefilter,
            "structured_fallback_enabled": self.use_structured_fallback,
            "taint_tracking_enabled": self.use_taint_tracking,
        }

    def model_management_capabilities(self) -> dict:
        """当前推理客户端支持的运行时模型管理能力（仅 Ollama 全支持）。

        进程内后端（transformers/llamacpp/vllm）虽也有 list_models/model 属性，
        但语义是"返回当前已加载模型"，不支持运行时拉取/删除/切换，
        故 list/activate 也以"具备 pull+delete 能力"为前置条件。
        """
        c = self.client
        runtime = hasattr(c, "pull_model") and hasattr(c, "delete_model")
        return {
            "list": runtime,
            "pull": hasattr(c, "pull_model"),
            "delete": hasattr(c, "delete_model"),
            "activate": runtime,
        }

    def _retrieve_rag_context(self, code: str) -> Optional[str]:
        """从知识库检索相关漏洞知识。"""
        if not self.use_rag or not self.chroma:
            return None
        try:
            results = self.chroma.query(
                collection_name=KNOWLEDGE_COLLECTION,
                query_text=code[:2000],  # 限制查询长度
                n_results=3,
            )
            docs = results.get("documents", [])
            if not docs:
                return None
            return "\n---\n".join(docs)
        except Exception as e:
            print(f"[Scanner] RAG 检索失败: {e}")
            return None

    def _retrieve_taint_context(self, code: str, language: str, filename: str) -> Optional[str]:
        """轻量污点分析：提取 source→sink 数据流路径，作为 LLM 上下文。

        与 RAG 上下文互补：RAG 提供领域知识，污点分析提供代码内真实调用链。
        """
        if not self.use_taint_tracking or not self.taint_tracker:
            return None
        try:
            paths = self.taint_tracker.trace(code, language=language, filename=filename)
            if not paths:
                return None
            lines = ["[污点分析] 检测到以下 source→sink 数据流路径（行号为源码行号）："]
            for p in paths:
                chain = " → ".join(p.propagation) if p.propagation else "(直接表达式)"
                line = f"  L{p.source_line}:{p.source} → L{p.sink_line}:{p.sink} ({p.taint_type})"
                if p.propagation:
                    line += f" [传播链: {chain}]"
                lines.append(line)
            return "\n".join(lines)
        except Exception as e:
            print(f"[Scanner] 污点分析失败: {e}")
            return None

    def scan_code(
        self,
        code: str,
        language: str = "python",
        filename: str = "",
        use_rag: Optional[bool] = None,
    ) -> SingleResult:
        """扫描单段代码（与 switch_model 互斥，保证切片使用同一模型）。"""
        with self._model_lock:
            return self._scan_code_impl(
                code, language=language, filename=filename, use_rag=use_rag,
            )

    def _scan_code_impl(
        self,
        code: str,
        language: str = "python",
        filename: str = "",
        use_rag: Optional[bool] = None,
    ) -> SingleResult:
        """扫描单段代码（实际实现，调用方需持有 _model_lock）。

        长文件（>150 行）自动切片，逐 chunk 分析，
        若任一 chunk 发现漏洞则整文件判漏洞。

        Args:
            code: 代码文本
            language: 代码语言
            filename: 文件名（给模型作上下文）
            use_rag: 是否启用 RAG（None 表示用 Scanner 默认值）
        """
        if not code or not code.strip():
            return SingleResult(
                filename=filename, language=language,
                has_vulnerability=None, error="empty code",
            )

        # 记录整文件分析的起始时刻，返回给前端的 duration 覆盖切片/预筛/RAG/污点/多 chunk 等全部耗时，
        # 而非仅单次 LLM generate 的耗时（否则长文件/排队会导致前端显示时间远小于实际等待时间）
        _scan_start = time.time()

        rag_enabled = self.use_rag if use_rag is None else use_rag
        rag_context = self._retrieve_rag_context(code) if rag_enabled else None

        # 污点分析：提取 source→sink 数据流路径，作为 LLM 上下文
        taint_context = self._retrieve_taint_context(code, language, filename) if self.use_taint_tracking else None

        # 预筛层：对明显漏洞/安全样本直接短路，跳过 LLM 调用
        prefilter_result: Optional[PrefilterResult] = None
        if self.prefilter:
            prefilter_result = self.prefilter.scan(code, language)
            if prefilter_result.preliminary_verdict is not None:
                # 预筛给出高置信判定，直接返回，不调 LLM
                has_vuln = prefilter_result.preliminary_verdict
                if has_vuln:
                    rule_name = prefilter_result.matched_rules[0] if prefilter_result.matched_rules else "detected"
                    vuln_type, risk_level = _PREFILTER_VULN_INFO.get(rule_name, ("detected", "High"))
                    return SingleResult(
                        filename=filename, language=language,
                        has_vulnerability=True,
                        vulnerability_type=vuln_type,
                        risk_level=risk_level,
                        explanation=f"预筛层检测到明显漏洞特征：{', '.join(prefilter_result.matched_rules)}",
                        fix_suggestion="请参考 LLM 详细分析或相关 CWE 修复指南",
                        duration=0.0,
                        prefilter_verdict=True,
                        prefilter_rules=prefilter_result.matched_rules,
                    )
                else:
                    return SingleResult(
                        filename=filename, language=language,
                        has_vulnerability=False,
                        vulnerability_type="none",
                        risk_level="None",
                        explanation=f"预筛层检测到安全模式：{', '.join(prefilter_result.matched_rules)}",
                        prefilter_verdict=False,
                        prefilter_rules=prefilter_result.matched_rules,
                    )

        # 切片
        slice_result: SliceResult = self.slicer.slice(
            code, language=language, filename=filename,
        )

        # 逐 chunk 分析
        # 批量解码优化：多 chunk 且后端支持 generate_batch 时，一次 generate 走完整 batch。
        # 单条自回归解码是显存带宽瓶颈（GPU 等权重读取，功耗上不去），batch 摊薄权重读取
        # → 算术强度上升、真正吃满 GPU。TransformersClient 支持；Ollama/VLLM 不支持则顺序执行。
        chunk_results: list[SingleResult] = []
        chunks = slice_result.chunks
        if len(chunks) > 1 and hasattr(self.client, "generate_batch"):
            # 构建所有 chunk 的 prompt（上下文与 _analyze_chunk 一致）
            prompts = []
            for chunk in chunks:
                display_name = f"{filename}::{chunk.name}" if chunk.name else filename
                combined_context = None
                if rag_context and taint_context:
                    combined_context = rag_context + "\n\n" + taint_context
                elif rag_context:
                    combined_context = rag_context
                elif taint_context:
                    combined_context = taint_context
                prompts.append(build_user_prompt(
                    code=chunk.code, language=language,
                    filename=display_name, rag_context=combined_context,
                ))
            gen_results = self.client.generate_batch(
                prompts,
                system_prompt=self.system_prompt,
                max_tokens=2048,
                num_ctx=self._num_ctx,
            )
            for chunk, res in zip(chunks, gen_results):
                r = self._analyze_chunk(
                    chunk.code, language, filename, rag_context,
                    chunk_name=chunk.name,
                    taint_context=taint_context,
                    result=res,
                )
                r.sliced = slice_result.sliced
                r.chunk_count = slice_result.chunk_count
                chunk_results.append(r)
        else:
            for chunk in chunks:
                r = self._analyze_chunk(
                    chunk.code, language, filename, rag_context,
                    chunk_name=chunk.name,
                    taint_context=taint_context,
                )
                r.sliced = slice_result.sliced
                r.chunk_count = slice_result.chunk_count
                chunk_results.append(r)

        # 合并：任一 chunk 有漏洞 → 整文件有漏洞；任一 chunk 报错且无漏洞 → 整文件报错
        if len(chunk_results) == 1:
            chunk_results[0].duration = time.time() - _scan_start
            return chunk_results[0]

        # 多 chunk：取风险最高的；但若有 error 且无漏洞，整文件判 error（避免部分失败被误判为安全）
        risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        merged = chunk_results[0]
        merged.filename = filename
        for cr in chunk_results[1:]:
            cr_risk = risk_order.get((cr.risk_level or "none").lower(), 0)
            merged_risk = risk_order.get((merged.risk_level or "none").lower(), 0)
            if cr.has_vulnerability and (
                not merged.has_vulnerability or cr_risk > merged_risk
            ):
                merged = cr
                merged.filename = filename

        # 合并后修正：若整体无漏洞但存在报错 chunk，标记为 error（None）而非安全（False）
        if not merged.has_vulnerability:
            has_error_chunk = any(
                cr.has_vulnerability is None or cr.error
                for cr in chunk_results
            )
            if has_error_chunk:
                err_msgs = [
                    (cr.error or cr.chunk_name or "unknown")
                    for cr in chunk_results
                    if (cr.has_vulnerability is None or cr.error)
                ]
                merged.has_vulnerability = None
                merged.error = "部分 chunk 分析失败: " + "; ".join(err_msgs)
        # 设置为整文件分析总耗时（覆盖所有 chunk 的 LLM 调用）
        merged.duration = time.time() - _scan_start
        return merged

    def _analyze_chunk(
        self,
        code: str,
        language: str,
        filename: str,
        rag_context: Optional[str],
        chunk_name: str = "",
        taint_context: Optional[str] = None,
        result: Optional[dict] = None,
    ) -> SingleResult:
        """分析单个代码 chunk。

        流程：
        1. 第一轮：正常 CoT + JSON 输出（保留分析过程）
        2. 若 parse 失败且 use_structured_fallback=True：
           用 Ollama format=json 约束解码重试，数学上保证输出可解析
        3. 污点分析上下文（如有）与 RAG 上下文一并注入 prompt

        Args:
            result: 若传入预生成的 generate 结果 dict，则跳过本轮 LLM 调用，
                直接进入解析与兜底（供批量解码路径复用；None 时自行调用 generate）。
        """
        display_name = f"{filename}::{chunk_name}" if chunk_name else filename
        # 合并 RAG + 污点上下文
        combined_context = None
        if rag_context and taint_context:
            combined_context = rag_context + "\n\n" + taint_context
        elif rag_context:
            combined_context = rag_context
        elif taint_context:
            combined_context = taint_context

        prompt = build_user_prompt(
            code=code, language=language,
            filename=display_name, rag_context=combined_context,
        )

        if result is None:
            start = time.time()
            result = self.client.generate(
                prompt=prompt,
                system_prompt=self.system_prompt,
                keep_alive=self.keep_alive,
                num_ctx=self._num_ctx,
                num_gpu=self._num_gpu,
                num_thread=self._num_thread,
            )
            duration = time.time() - start
        else:
            duration = result.get("duration", 0.0)

        if result["error"]:
            return SingleResult(
                filename=filename, language=language,
                has_vulnerability=None, error=result["error"],
                duration=duration,
            )

        verdict = parse_verdict(result["text"])
        has_vuln = normalize_has_vulnerability(verdict.get("has_vulnerability"))
        # 模型原始输出的漏洞类型（纠正前），供界面展示 CWE Normalizer 的纠正过程
        raw_vuln_type = str(verdict.get("vulnerability_type", "")).strip()

        # 约束解码兜底：CoT+JSON 解析失败时，用 Ollama format=json 重试
        if has_vuln is None and self.use_structured_fallback:
            structured_result = self.client.generate_structured(
                prompt=prompt,
                system_prompt=self.system_prompt,
                keep_alive=self.keep_alive,
                num_ctx=self._num_ctx,
                num_gpu=self._num_gpu,
                num_thread=self._num_thread,
            )
            if not structured_result["error"]:
                verdict = parse_verdict(structured_result["text"])
                has_vuln = normalize_has_vulnerability(verdict.get("has_vulnerability"))
                if has_vuln is not None:
                    # 约束解码成功，用结构化输出替换
                    result = structured_result
                    duration += structured_result["duration"]

        return SingleResult(
            filename=filename,
            language=language,
            chunk_name=chunk_name,
            has_vulnerability=has_vuln,
            vulnerability_type=normalize_cwe_label(
                verdict.get("vulnerability_type", "none")),
            raw_vulnerability_type=raw_vuln_type,
            risk_level=verdict.get("risk_level", "None"),
            source=verdict.get("source", "N/A"),
            sink=verdict.get("sink", "N/A"),
            explanation=verdict.get("explanation", ""),
            fix_suggestion=verdict.get("fix_suggestion", "no fix needed"),
            raw_output=result["text"],
            duration=duration,
        )

    def unload(self):
        """卸载模型释放显存。"""
        self.client.unload_model()
