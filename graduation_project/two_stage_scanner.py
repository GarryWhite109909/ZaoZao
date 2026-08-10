"""
两阶段扫描器 —— 工具召回 + LLM 裁决的核心编排模块。

架构（详见 docs/方法论_工具召回与LLM裁决.md §二、docs/设计草稿_P1_两阶段架构.md）：

    Stage 1 静态工具层（并行，近零成本）
      ├─ Semgrep taint（整文件，含污点路径）    ← external_scanner.scan_taint()
      ├─ TaintTracker（AST 轻量污点，交叉验证）  ← taint_tracker.trace()
      └─ Prefilter（正则，高置信命中作为候选）   ← prefilter.scan()
            │
            ▼
      候选 Finding 列表（合并去重 + 归一化）
            │
     ┌──────┴───────┐
  无候选          有候选（少数文件）
    │                │
    ▼                ▼
 直接判安全       Stage 2 LLM 裁决层
 记录召回监控      逐 finding 判真伪
                  上下文：切片 + 污点
                  N 次采样 → 自一致率置信度
                    │
                    ▼
            结构化结果（verdict + 置信度 + 证据链 + 修复）

关键反转：LLM 的任务从"在全文中发现漏洞"（开放生成）变为"对具体 finding
判定真伪"（封闭判别）。LLM 只介入有候选的少数文件。

置信度：自一致率 = 判真票数 / N（N 次 temperature>0 采样），度量输出稳定性
而非真实正确率，文档/前端须用"一致性置信度"表述。

本模块不直接调用 Ollama，而是复用调用方注入的 client（通常为
app.backend.services.scanner.Scanner 的 client），保证与主扫描共享同一推理
后端与 system_prompt（由 model_registry 选择，统一为 v3 训练数据的 V3_PROMPT）。
"""

from __future__ import annotations

import json
import os
import random
import re
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from graduation_project.external_scanner import ExternalScanner
from graduation_project.prefilter import Prefilter
from graduation_project.prompts import build_triage_prompt, build_user_prompt
from graduation_project.schema import normalize_has_vulnerability, parse_verdict
from graduation_project.cwe_normalizer import normalize_cwe_label
from graduation_project.code_slicer import CodeSlicer


# ---------------------------------------------------------------------------
# 工具层召回监控（模块级计数器，供 /api 健康检查与论文召回漂移分析使用）
# ---------------------------------------------------------------------------
_MONITOR = {
    "no_candidate_total": 0,    # 无候选直判安全的文件数
    "recheck_sampled": 0,       # 其中被抽样复核的次数
    "recheck_vuln_found": 0,    # 抽样复核发现工具层漏报的次数
}
_MONITOR_LOCK = threading.Lock()


def tool_recall_monitor_snapshot() -> dict:
    """返回工具召回监控快照（含估算漏报率）。"""
    with _MONITOR_LOCK:
        snap = dict(_MONITOR)
    snap["estimated_miss_rate"] = (
        round(snap["recheck_vuln_found"] / snap["recheck_sampled"], 4)
        if snap["recheck_sampled"] else None
    )
    return snap


def _monitor_incr(key: str) -> None:
    with _MONITOR_LOCK:
        _MONITOR[key] += 1


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------
@dataclass
class ToolFinding:
    """Stage 1 产出的候选 finding（统一结构）。"""
    rule_id: str            # semgrep check_id / taint_tracker 类型 / prefilter 规则名
    category: str           # "sast" / "taint" / "prefilter"
    source: str             # 污染源（如 request.args.get('uid')）
    sink: str               # 危险点（如 cursor.execute(query)）
    taint_type: str         # SQL Injection / Command Injection / ...
    source_line: int
    sink_line: int
    path: list[str] = field(default_factory=list)  # 传播链（source→...→sink）
    severity: str = "medium"
    tool: str = "semgrep"   # semgrep / taint_tracker / prefilter
    evidence: str = ""      # 原始证据文本（供 LLM 参考）

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "source": self.source,
            "sink": self.sink,
            "taint_type": self.taint_type,
            # 统一显示逻辑：规范 CWE 标签由后端一次性计算，前端不再维护映射表
            "cwe_label": normalize_cwe_label(self.taint_type),
            "source_line": self.source_line,
            "sink_line": self.sink_line,
            "path": self.path,
            "severity": self.severity,
            "tool": self.tool,
            "evidence": self.evidence,
        }


@dataclass
class AdjudicationVerdict:
    """单个 finding 的裁决结果。"""
    confirmed: bool                 # 是否判为真漏洞（多数票）
    confidence: float               # 一致性置信度 = 多数方票数 / N（非正确概率）
    votes_true: int
    votes_false: int
    votes_invalid: int
    reasoning: str = ""             # 首个判真模型的分析
    fix_suggestion: str = ""        # 修复建议
    raw_outputs: list[str] = field(default_factory=list)  # N 次采样原始输出
    finding: Optional[dict] = None  # 关联的候选 finding（含 taint_type/severity/source/sink）

    def to_dict(self) -> dict:
        return {
            "confirmed": self.confirmed,
            "confidence": round(self.confidence, 3),
            "votes_true": self.votes_true,
            "votes_false": self.votes_false,
            "votes_invalid": self.votes_invalid,
            "reasoning": self.reasoning,
            "fix_suggestion": self.fix_suggestion,
            "raw_outputs": self.raw_outputs,
            "finding": self.finding,
        }


@dataclass
class TwoStageResult:
    """两阶段扫描的文件级结果。"""
    filename: str
    language: str
    has_vulnerability: Optional[bool]
    stage1: dict = field(default_factory=dict)                    # 工具层统计
    findings: list[ToolFinding] = field(default_factory=list)     # 全部候选
    adjudications: list[AdjudicationVerdict] = field(default_factory=list)
    reviewer_findings: list[dict] = field(default_factory=list)   # 低置信需人工复核
    vulnerability_type: str = ""      # 文件级漏洞类型（取已确认裁决中最高严重度 finding）
    risk_level: str = "None"          # 文件级风险等级（同样取最高严重度）
    explanation: str = ""             # 文件级分析说明（取已确认裁决的 reason）
    fix_suggestion: str = ""          # 文件级修复建议（取已确认裁决的 fix_suggestion）
    source: str = ""                  # 文件级 source（取已确认裁决 finding 的 source）
    sink: str = ""                    # 文件级 sink（取已确认裁决 finding 的 sink）
    total_duration: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "language": self.language,
            "has_vulnerability": self.has_vulnerability,
            "stage1": self.stage1,
            "findings": [f.to_dict() for f in self.findings],
            "adjudications": [a.to_dict() for a in self.adjudications],
            "reviewer_findings": self.reviewer_findings,
            "vulnerability_type": self.vulnerability_type,
            "risk_level": self.risk_level,
            "explanation": self.explanation,
            "fix_suggestion": self.fix_suggestion,
            "source": self.source,
            "sink": self.sink,
            "total_duration": round(self.total_duration, 2),
            "error": self.error,
        }


# 置信度阈值：≥0.8 自动结论；0.5~0.8 结论但标记复核；<0.5 或平票→reviewer
_CONF_AUTO = 0.8
_CONF_MANUAL = 0.5

# 严重度排序（用于文件级取最高风险 finding）
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "none": 0}


# ---------------------------------------------------------------------------
# 裁决结果解析
# ---------------------------------------------------------------------------
def _extract_json_object(text: str) -> Optional[str]:
    """从文本中提取第一个完整 JSON 对象（花括号平衡匹配）。

    非贪婪 `\{.*?\}` 在 reason 等字段含 `}` 时会提前截断导致 JSON 解析失败，
    这里从每个 `{` 起做括号深度匹配，取第一个能完整闭合的对象。
    """
    start = -1
    depth = 0
    in_str = False
    escape = False
    for i, ch in enumerate(text):
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if start < 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
    return None


def parse_triage_verdict(raw_output: str) -> Optional[dict]:
    """从裁决模型输出中解析 is_confirmed JSON。

    兼容 ```json ... ``` 围栏与裸 JSON。返回含 is_confirmed 的 dict；
    解析失败返回 None。
    """
    if not raw_output:
        return None
    # 提取 ```json ... ``` 围栏
    fences = re.findall(r"```(?:json)?\s*(.*?)\s*```", raw_output, re.DOTALL)
    candidates = fences + [raw_output]
    for text in candidates:
        obj = _extract_json_object(text)
        if not obj:
            continue
        try:
            parsed = json.loads(obj)
            if isinstance(parsed, dict) and "is_confirmed" in parsed:
                return parsed
        except json.JSONDecodeError:
            continue
    # 字段级兜底
    m = re.search(r'"is_confirmed"\s*:\s*(true|false)', raw_output, re.IGNORECASE)
    if m:
        return {"is_confirmed": m.group(1).lower() == "true"}
    return None


def _normalize_confirmed(value) -> Optional[bool]:
    """把 is_confirmed 归一化为 bool；无法识别返回 None。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "yes", "1"):
            return True
        if v in ("false", "no", "0"):
            return False
    return None


# ---------------------------------------------------------------------------
# 两阶段扫描器
# ---------------------------------------------------------------------------
class TwoStageScanner:
    """两阶段扫描器：Stage 1 工具召回 + Stage 2 LLM 裁决（自一致率）。

    Args:
        client: 推理客户端（复用 Scanner.client，须有 generate(text,
                system_prompt=..., temperature=...) 接口）。
        system_prompt: 裁决层 system prompt（通常为 Scanner.system_prompt）。
        n_samples: 自一致率采样次数 N（默认 5）。
        temperature: 采样温度（>0 保证投票多样性，默认 0.7）。
        keep_alive: 模型卸载策略（透传给 client.generate）。
        num_ctx: 上下文长度（透传）。
        use_rag: 是否对裁决注入 RAG 上下文（默认 False）。
        use_semgrep: 是否启用 Semgrep taint 召回（默认 True；未安装自动降级）。
        use_taint_tracker: 是否启用 TaintTracker 召回（默认 True）。
        use_prefilter: 是否启用 Prefilter 召回（默认 True）。
    """

    def __init__(
        self,
        client,
        system_prompt: str,
        n_samples: int = 5,
        temperature: float = 0.7,
        keep_alive=0,
        num_ctx: Optional[int] = None,
        use_rag: bool = False,
        use_semgrep: bool = True,
        use_taint_tracker: bool = True,
        use_prefilter: bool = True,
        sampling_rate: Optional[float] = None,
    ):
        self.client = client
        self.system_prompt = system_prompt
        self.n_samples = max(1, min(int(n_samples), 10))
        self.temperature = temperature
        self.keep_alive = keep_alive
        self.num_ctx = num_ctx or int(os.environ.get("VULN_SCANNER_NUM_CTX", "8192"))
        self.use_rag = use_rag
        self.use_semgrep = use_semgrep
        self.use_taint_tracker = use_taint_tracker
        self.use_prefilter = use_prefilter

        self._external = ExternalScanner() if use_semgrep else None
        self._taint_tracker = None
        self._prefilter = Prefilter() if use_prefilter else None
        self._slicer = CodeSlicer(min_lines=150)
        self._chroma = None  # 延迟初始化（首次用 RAG 时才连 Chroma）
        # 无候选直判安全路径的抽样复核比例（默认 10%，VULN_SCANNER_RECHECK_RATE 可调）
        self.sampling_rate = float(
            sampling_rate if sampling_rate is not None
            else os.environ.get("VULN_SCANNER_RECHECK_RATE", "0.1")
        )

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------
    def scan_code(
        self,
        code: str,
        language: str = "python",
        filename: str = "",
        n_samples: Optional[int] = None,
        use_rag: Optional[bool] = None,
    ) -> TwoStageResult:
        """对单文件执行两阶段扫描。

        Args:
            code: 源代码文本
            language: 语言标签
            filename: 文件名
            n_samples: 采样次数（None 用默认值）
            use_rag: 是否启用 RAG（None 用默认值）

        Returns:
            TwoStageResult。
        """
        if n_samples is not None:
            self.n_samples = max(1, min(int(n_samples), 10))
        rag_enabled = self.use_rag if use_rag is None else use_rag
        start = time.time()

        result = TwoStageResult(
            filename=filename, language=language, has_vulnerability=None,
        )

        if not code or not code.strip():
            result.error = "empty code"
            result.total_duration = time.time() - start
            return result

        # Stage 1：工具召回
        findings = self._stage1_recall(code, language, filename)
        result.findings = findings
        result.stage1 = self._stage1_stats(findings)
        result.stage1["recall_duration"] = round(time.time() - start, 2)

        # 无候选 → 直接判安全，但按比例抽样复核（监控工具层召回漂移）
        if not findings:
            recheck = self._maybe_recheck(code, language)
            result.has_vulnerability = False
            result.stage1["decision"] = "no_candidate_safe"
            if recheck is not None:
                result.stage1["recheck"] = recheck
                if recheck.get("has_vulnerability") is True:
                    # 抽样复核命中：工具层漏报，不直接采信 LLM 也不放行，转人工复核
                    result.has_vulnerability = None
                    result.stage1["decision"] = "recheck_hit_review"
                    result.error = "抽样复核发现疑似漏洞（Stage 1 未召回），需人工复核"
            result.total_duration = time.time() - start
            return result

        # 有候选 → Stage 2：LLM 裁决
        result.stage1["decision"] = "has_candidate_adjudicate"
        rag_context = self._retrieve_rag_context(code) if rag_enabled else None
        adjudications, reviewer = self._adjudicate_all(
            findings, code, language, filename, rag_context,
        )
        result.adjudications = adjudications
        result.reviewer_findings = reviewer

        # 聚合最终结论
        self._aggregate(result)
        result.total_duration = time.time() - start
        return result

    # ------------------------------------------------------------------
    # Stage 1：工具召回（并行：semgrep taint / taint_tracker / prefilter）
    # ------------------------------------------------------------------
    def _stage1_recall(self, code: str, language: str, filename: str) -> list[ToolFinding]:
        """并行调用三种工具召回候选 finding，合并去重 + 归一化。"""
        findings: list[ToolFinding] = []

        # 1) Semgrep taint（整文件，含污点路径）
        if self._external is not None:
            findings.extend(self._semgrep_recall(code, language, filename))

        # 2) TaintTracker（AST 轻量污点，交叉验证）
        if self._taint_tracker_enabled():
            findings.extend(self._taint_recall(code, language, filename))

        # 3) Prefilter（正则高置信命中作为候选）
        if self._prefilter is not None:
            findings.extend(self._prefilter_recall(code, language))

        return self._dedupe(findings)

    def _maybe_recheck(self, code: str, language: str) -> Optional[dict]:
        """无候选文件的抽样复核：用主扫描 prompt 全量判一次，监控工具层漏报。

        这是 Stage 1 召回率的保险丝——"无候选直判安全"的上限由工具召回率
        决定，抽样复核给出漏报率的在线估计（见 tool_recall_monitor_snapshot）。
        """
        _monitor_incr("no_candidate_total")
        if self.sampling_rate <= 0 or random.random() >= self.sampling_rate:
            return None
        _monitor_incr("recheck_sampled")
        try:
            resp = self.client.generate(
                prompt=build_user_prompt(code=code, language=language),
                system_prompt=self.system_prompt,
                temperature=0.1,
                max_tokens=1024,
                num_ctx=self.num_ctx,
                keep_alive=self._effective_keep_alive(),
            )
            text = resp.get("text", "") if isinstance(resp, dict) else ""
            verdict = parse_verdict(text) if text else None
            hv = normalize_has_vulnerability(verdict.get("has_vulnerability")) if verdict else None
        except Exception as e:
            return {"sampled": True, "has_vulnerability": None, "error": str(e)}
        if hv is True:
            _monitor_incr("recheck_vuln_found")
        return {"sampled": True, "has_vulnerability": hv}

    def _effective_keep_alive(self):
        """裁决/复核的模型驻留策略：keep_alive=0（每次卸载）在 N 次采样下会
        反复重载模型，延迟巨大；采样突发期内保持驻留（300s 后自动释放）。"""
        return 300 if self.keep_alive in (0, None) else self.keep_alive

    def _taint_tracker_enabled(self) -> bool:
        if not self.use_taint_tracker:
            return False
        if self._taint_tracker is None:
            try:
                from graduation_project.taint_tracker import TaintTracker
                self._taint_tracker = TaintTracker()
            except Exception:
                return False
        return True

    def _semgrep_recall(self, code: str, language: str, filename: str) -> list[ToolFinding]:
        """把代码写入临时文件后跑 Semgrep taint，解析候选 finding。"""
        suffix = Path(filename).suffix.lower() or (".py" if language == "python" else ".txt")
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=suffix, delete=False, encoding="utf-8"
            ) as tmp:
                tmp.write(code)
                tmp_path = tmp.name
            raw = self._external.scan_taint(tmp_path, language)
        except Exception as e:
            print(f"[TwoStageScanner] Semgrep taint 执行失败: {e}")
            return []
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        findings: list[ToolFinding] = []
        for item in raw:
            findings.append(ToolFinding(
                rule_id=item.get("rule_id", "semgrep-taint"),
                category="taint",  # semgrep taint 与 taint_tracker 同属污点召回
                source=item.get("source", ""),
                sink=item.get("sink", ""),
                taint_type=item.get("taint_type", "Unknown"),
                source_line=int(item.get("source_line", 0) or 0),
                sink_line=int(item.get("sink_line", 0) or 0),
                path=list(item.get("path", []) or []),
                severity=item.get("severity", "medium"),
                tool=item.get("tool", "semgrep"),
                evidence=item.get("evidence", ""),
            ))
        return findings

    def _taint_recall(self, code: str, language: str, filename: str) -> list[ToolFinding]:
        """用 TaintTracker 做 AST 级污点召回（Semgrep 的补充与交叉验证）。"""
        try:
            paths = self._taint_tracker.trace(code, language=language, filename=filename)
        except Exception as e:
            print(f"[TwoStageScanner] TaintTracker 执行失败: {e}")
            return []
        findings: list[ToolFinding] = []
        for p in paths:
            findings.append(ToolFinding(
                rule_id=f"taint_tracker:{p.taint_type}",
                category="taint",
                source=p.source,
                sink=p.sink,
                taint_type=p.taint_type,
                source_line=p.source_line,
                sink_line=p.sink_line,
                path=list(p.propagation),
                severity=_SEVERITY_BY_TYPE.get(p.taint_type, "medium"),
                tool="taint_tracker",
                evidence="TaintTracker AST 污点分析定位的同文件 source→sink 路径",
            ))
        return findings

    def _prefilter_recall(self, code: str, language: str) -> list[ToolFinding]:
        """Prefilter 高置信命中作为候选（不再短路即终判，改为进裁决层）。

        仅当 prefilter 判 vulnerability=True（明显漏洞特征）时产出候选；
        判 False/None 不产出（安全/模糊样本无需裁决）。
        """
        try:
            result = self._prefilter.scan(code, language)
        except Exception:
            return []
        if not result.has_obvious_vuln:
            return []
        # matched_rules 混有安全规则（漏洞+安全同时命中时）：只取漏洞类规则生成
        # 候选，安全规则的空证据候选会污染裁决层
        vuln_rule_names = {r.name for r in getattr(self._prefilter, "vuln_rules", [])}
        findings: list[ToolFinding] = []
        for rule_name in result.matched_rules:
            if rule_name == "hardcoded_secret_marker":
                continue  # 标记仅抑制安全判定，不直接作为漏洞候选
            if vuln_rule_names and rule_name not in vuln_rule_names:
                continue  # 安全规则/标记不产生候选
            findings.append(ToolFinding(
                rule_id=rule_name,
                category="prefilter",
                source="",
                sink="",
                taint_type=_PREFILTER_TYPE.get(rule_name, "Detected"),
                source_line=0,
                sink_line=0,
                path=[],
                severity=_PREFILTER_SEVERITY.get(rule_name, "medium"),
                tool="prefilter",
                evidence=f"Prefilter 命中漏洞特征规则: {rule_name}",
            ))
        return findings

    @staticmethod
    def _dedupe(findings: list[ToolFinding]) -> list[ToolFinding]:
        """按 (taint_type, normalized_source, normalized_sink) 去重。

        Semgrep 与 TaintTracker 命中同一流时保留一条，工具标注按实际集合合并。
        source/sink 皆空的候选（如 prefilter 规则命中）无法按流去重，
        去重键纳入 rule_id——否则同 taint_type 的多条规则会被误合并成一条，
        丢失规则与证据。
        """
        def _norm(s: str) -> str:
            return re.sub(r"\s+", "", s or "").lower()

        seen: dict[tuple, ToolFinding] = {}
        # 辅助索引：(taint_type, sink_line) → 已见 key。
        # semgrep OSS 的 taint JSON 不含 metavars（source/sink 为空、行号=sink 行），
        # 与 TaintTracker 同流 finding 的主键永不相等；此索引让"空证据 + 同 sink 行
        # + 同类型"的候选能合并到已有 finding 上，避免同一流被裁决两次
        by_sink_line: dict[tuple, tuple] = {}

        # 两遍处理（顺序无关）：先收有证据的 finding 并建索引，再收空证据候选——
        # Stage 1 的召回顺序是 semgrep 在前，单遍处理会让空证据候选抢先进 seen，
        # 导致同流的 taint_tracker finding 无法归并
        def _has_evidence(f: ToolFinding) -> bool:
            return bool(_norm(f.source) or _norm(f.sink))

        ordered = [f for f in findings if _has_evidence(f)] + \
                  [f for f in findings if not _has_evidence(f)]
        for f in ordered:
            norm_src, norm_sink = _norm(f.source), _norm(f.sink)
            key = (f.taint_type or "").lower(), norm_src, norm_sink
            if not norm_src and not norm_sink:
                # 空证据候选：先尝试按 (类型, sink 行) 归并到已有 finding
                line_key = ((f.taint_type or "").lower(), f.sink_line)
                if f.sink_line and line_key in by_sink_line:
                    key = by_sink_line[line_key]
                else:
                    key = key + (f.rule_id,)  # 无法归并则按规则区分，不误合并
            if key in seen:
                existing = seen[key]
                # 合并工具标注（按实际工具集合，而非硬编码）
                if existing.tool != f.tool:
                    tools = set(existing.tool.split("+")) | set(f.tool.split("+"))
                    existing.tool = "+".join(sorted(tools))
                # 补全缺失字段（source/sink/path/行号）
                if not existing.source and f.source:
                    existing.source = f.source
                if not existing.sink and f.sink:
                    existing.sink = f.sink
                if not existing.path and f.path:
                    existing.path = f.path
                if not existing.source_line and f.source_line:
                    existing.source_line = f.source_line
                if not existing.sink_line and f.sink_line:
                    existing.sink_line = f.sink_line
            else:
                seen[key] = f
                # 有证据的 finding 注册 sink 行索引，供后续空证据候选归并
                if (norm_src or norm_sink) and f.sink_line:
                    by_sink_line[((f.taint_type or "").lower(), f.sink_line)] = key
        return list(seen.values())

    @staticmethod
    def _stage1_stats(findings: list[ToolFinding]) -> dict:
        """统计各工具召回数量（合并项按工具集合拆分计数）。"""
        counts = {"semgrep": 0, "taint_tracker": 0, "prefilter": 0}
        merged = 0
        for f in findings:
            tools = f.tool.split("+")
            if len(tools) > 1:
                merged += 1
            for t in tools:
                if t in counts:
                    counts[t] += 1
        return {
            "total_candidates": len(findings),
            "by_tool": counts,
            "merged_cross_tool": merged,
        }

    # ------------------------------------------------------------------
    # Stage 2：LLM 裁决（自一致率）
    # ------------------------------------------------------------------
    def _adjudicate_all(self, findings, code, language, filename, rag_context):
        """对每个候选 finding 做 N 次采样裁决，返回 (adjudications, reviewer)。"""
        adjudications: list[AdjudicationVerdict] = []
        reviewer: list[dict] = []
        for finding in findings:
            code_context = self._slice_context(code, language, finding)
            verdict = self._adjudicate_one(finding, code_context, language, filename, rag_context)
            # 关联回源 finding（含 taint_type/severity），供前端逐条展示投票与置信度
            verdict.finding = finding.to_dict()
            verdict_dict = verdict.to_dict()
            # 置信度映射到最终结论
            if verdict.confirmed:
                if verdict.confidence >= _CONF_AUTO:
                    verdict_dict["decision"] = "confirmed_vulnerability"
                else:
                    verdict_dict["decision"] = "confirmed_review"
                    reviewer.append(verdict_dict)
            else:
                if verdict.confidence >= _CONF_AUTO:
                    verdict_dict["decision"] = "dismissed_safe"
                else:
                    verdict_dict["decision"] = "dismissed_review"
                    reviewer.append(verdict_dict)
            adjudications.append(verdict)
        return adjudications, reviewer

    def _slice_context(self, code: str, language: str, finding: ToolFinding) -> str:
        """切片源码，取包含 source/sink 行的所有 chunk 作为裁决上下文。

        source 与 sink 分属不同 chunk 时两端都必须送达 LLM（只送一端会让
        另一端只剩行号文本，无法验证数据流）；每个 chunk 的代码带行号前缀，
        使 prompt 中的 L 行号可以直接对位。
        """
        try:
            slice_result = self._slicer.slice(code, language=language)
        except Exception:
            return self._with_line_numbers(code, 1)
        target_lines = {finding.source_line, finding.sink_line} - {0, None}
        if not target_lines:
            return self._with_line_numbers(code, 1)

        # 收集所有包含 target 行的 chunk（按起始行排序；同一 chunk 含两端只取一次）
        hit_chunks = [
            c for c in slice_result.chunks
            if set(range(c.start_line, c.end_line + 1)) & target_lines
        ]
        if not hit_chunks:
            return self._with_line_numbers(code, 1)

        orig_lines = code.split("\n")
        parts: list[str] = []
        for c in sorted(hit_chunks, key=lambda x: x.start_line):
            body_count = c.end_line - c.start_line + 1
            chunk_lines = c.code.split("\n")
            # chunk.code = 文件级上下文头 + 函数体（尾部 body_count 行）：
            # 头部单独输出且不带行号，函数体从原文件按行截取保证行号精确。
            # 整文件 chunk（is_full_file）没有拼装头部，禁止拆分——
            # 否则代码以 \n 结尾时 split 多出的尾部空串会让首行被误判为 header
            if not c.is_full_file and len(chunk_lines) > body_count:
                header = chunk_lines[:-body_count]
            else:
                header = []
            body_lines = orig_lines[c.start_line - 1:c.end_line]
            if len(hit_chunks) > 1:
                parts.append(f"# ==== 切片 {c.name}（L{c.start_line}-L{c.end_line}） ====")
            if header:
                parts.append("# ---- 文件级上下文（imports/全局量，仅供参考） ----")
                parts.extend(header)
            parts.append(self._with_line_numbers("\n".join(body_lines), c.start_line))
        return "\n\n".join(parts)

    @staticmethod
    def _with_line_numbers(code: str, start_line: int) -> str:
        """给代码每行加 1-indexed 行号前缀（如 "13| cursor.execute(query)"）。"""
        return "\n".join(
            f"{i}| {line}" for i, line in enumerate(code.split("\n"), start=start_line)
        )

    def _adjudicate_one(
        self, finding: ToolFinding, code_context: str,
        language: str, filename: str, rag_context: Optional[str],
    ) -> AdjudicationVerdict:
        """对单个 finding 做 N 次采样，返回自一致率裁决。

        N 次以 temperature>0 独立采样，多数票决定 confirmed，
        置信度 = 多数方票数 / 有效票数（排除无效票）。
        """
        prompt = build_triage_prompt(
            finding, code_context, language=language,
            filename=filename, rag_context=rag_context,
        )
        votes_true = votes_false = votes_invalid = 0
        raw_outputs: list[str] = []
        reason = ""
        fix = ""

        for _ in range(self.n_samples):
            try:
                result = self.client.generate(
                    prompt=prompt,
                    system_prompt=self.system_prompt,
                    temperature=self.temperature,
                    max_tokens=1024,
                    num_ctx=self.num_ctx,
                    keep_alive=self._effective_keep_alive(),
                )
            except Exception as e:
                print(f"[TwoStageScanner] 裁决推理失败: {e}")
                votes_invalid += 1
                continue

            text = result.get("text", "") if isinstance(result, dict) else ""
            if result.get("error") if isinstance(result, dict) else False:
                votes_invalid += 1
                continue
            raw_outputs.append(text)
            parsed = parse_triage_verdict(text)
            confirmed = _normalize_confirmed(parsed.get("is_confirmed")) if parsed else None
            if confirmed is None:
                votes_invalid += 1
                continue
            if confirmed:
                votes_true += 1
                if not reason:
                    reason = parsed.get("reason", "")
                    fix = parsed.get("fix_suggestion", "")
            else:
                votes_false += 1

        final_confirmed = votes_true > votes_false
        # 置信度分母用"有效票"（votes_true+votes_false）而非 self.n_samples：
        # invalid 票（解析失败/推理出错）不代表"否决"，除以 n_samples 会稀释真实
        # 自一致率。全部票无效时有效分母=1、confidence=0、confirmed=False，
        # 由 _aggregate 的 all_invalid 分支判 None（需复核），避免把"全部解析失败"
        # 误当成低置信"否决"——这就是 invalid 语义的统一入口。
        valid_votes = votes_true + votes_false
        return AdjudicationVerdict(
            confirmed=final_confirmed,
            confidence=max(votes_true, votes_false) / max(valid_votes, 1),
            votes_true=votes_true,
            votes_false=votes_false,
            votes_invalid=votes_invalid,
            # reason/fix 仅在最终判真时保留：最终判假却携带"是漏洞"的论证
            # 会让输出自相矛盾（少数票的论证不代表裁决结论）
            reasoning=reason if final_confirmed else "",
            fix_suggestion=fix if final_confirmed else "",
            raw_outputs=raw_outputs,
        )

    def _retrieve_rag_context(self, code: str) -> Optional[str]:
        """检索裁决用 RAG 知识（与 Scanner 同一 Chroma 知识库）。

        延迟初始化：chromadb 未安装或服务不可用时静默降级为 None（不阻断扫描）。
        """
        if self._chroma is None:
            try:
                from graduation_project.chroma_manager import ChromaManager
                self._chroma = ChromaManager()
            except Exception as e:
                print(f"[TwoStageScanner] RAG 初始化失败，降级无知识裁决: {e}")
                self._chroma = False
        if not self._chroma:
            return None
        try:
            results = self._chroma.query(
                collection_name="vuln_knowledge",
                query_text=code[:2000],
                n_results=3,
            )
            docs = results.get("documents", [])
            return "\n---\n".join(docs) if docs else None
        except Exception as e:
            print(f"[TwoStageScanner] RAG 检索失败: {e}")
            return None

    # ------------------------------------------------------------------
    # 聚合
    # ------------------------------------------------------------------
    def _aggregate(self, result: TwoStageResult) -> None:
        """根据裁决聚合文件级 has_vulnerability。

        规则：
        - 任一 finding 裁决 confirmed=True → 文件判 True
        - 全部 confirmed=False，或无候选 → 文件判 False
        - 有 finding 但全部解析失败（votes_invalid==N 或 votes_true==votes_false 平票）
          → 保守判 None（需复核）
        同时从已确认的裁决中取最高严重度 finding，填充文件级
        vulnerability_type / risk_level（供前端展示真实类型与风险等级）。
        """
        # 文件级漏洞类型/风险：取已确认裁决中严重度最高的 finding
        confirmed = [a for a in result.adjudications if a.confirmed and a.finding]
        if confirmed:
            top = max(confirmed, key=lambda a: _SEV_RANK.get(
                ((a.finding or {}).get("severity") or "medium").lower(), 1))
            sev = ((top.finding or {}).get("severity") or "medium").lower()
            result.risk_level = sev.capitalize()
            taint_type = top.finding.get("taint_type") or ""
            # 统一走 CWE 纠正工具（cwe_normalizer）：Path Traversal → CWE-22 路径穿越，
            # 无映射时回退到 taint_type / rule_id，保证与旧管道信息格式一致
            result.vulnerability_type = (
                normalize_cwe_label(taint_type)
                or (top.finding.get("rule_id") or "")
            )
            # 透出已确认裁决的 source/sink/分析/修复到文件级，供前端卡片收起态
            # 直接展示（与旧管道 r.source/r.sink/explanation/fix_suggestion 对齐）
            if not result.explanation:
                result.explanation = top.reasoning or ""
            if not result.fix_suggestion:
                result.fix_suggestion = top.fix_suggestion or ""
            if not result.source:
                result.source = top.finding.get("source") or ""
            if not result.sink:
                result.sink = top.finding.get("sink") or ""

        if not result.adjudications:
            result.has_vulnerability = False
            return
        # 高置信确认（≥_CONF_AUTO）才能直接判漏洞；低置信确认已进入复核队列，
        # 文件级不能输出确定性 True（否则"需复核"信号在汇总层被掩盖）
        strong_confirmed = any(
            a.confirmed and a.confidence >= _CONF_AUTO for a in result.adjudications
        )
        any_confirmed = any(a.confirmed for a in result.adjudications)
        all_invalid = all(a.votes_invalid >= self.n_samples for a in result.adjudications)
        if strong_confirmed:
            result.has_vulnerability = True
        elif all_invalid:
            result.has_vulnerability = None
            if not result.error:
                result.error = "所有 finding 裁决解析失败，需人工复核"
        elif any_confirmed or result.reviewer_findings:
            # 低置信确认 / 平票 / 低置信否决 → 需复核，文件级判 None
            result.has_vulnerability = None
            if not result.error:
                result.error = "存在低置信或平票裁决，需人工复核"
        else:
            result.has_vulnerability = False


# 各 taint_type 映射到默认严重度（与 design 草稿一致）
_SEVERITY_BY_TYPE = {
    "SQL Injection": "high",
    "Command Injection": "critical",
    "Code Injection": "critical",
    "Insecure Deserialization": "critical",
    "XSS": "medium",
    "Path Traversal": "high",
    "Server-Side Template Injection": "high",
}

# Prefilter 规则 → taint_type / severity（与 scanner.py 的 _PREFILTER_VULN_INFO 对齐）
_PREFILTER_TYPE = {
    "sqli_string_concat": "SQL Injection",
    "sqli_fstring": "SQL Injection",
    "sqli_percent_format": "SQL Injection",
    "cmd_os_system_concat": "Command Injection",
    "cmd_subprocess_shell_concat": "Command Injection",
    "rce_eval_request": "Code Injection",
    "path_traversal_open_concat": "Path Traversal",
    "deser_pickle_loads": "Insecure Deserialization",
    "deser_yaml_unsafe_load": "Insecure Deserialization",
}
_PREFILTER_SEVERITY = {
    "sqli_string_concat": "high",
    "sqli_fstring": "high",
    "sqli_percent_format": "high",
    "cmd_os_system_concat": "critical",
    "cmd_subprocess_shell_concat": "critical",
    "rce_eval_request": "critical",
    "path_traversal_open_concat": "high",
    "deser_pickle_loads": "critical",
    "deser_yaml_unsafe_load": "high",
}


# ---------------------------------------------------------------------------
# 自检（离线，无需 Ollama / semgrep）
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=== 两阶段扫描器自检（离线） ===\n")

    # 1) 裁决输出解析
    ok_parse = True
    cases = [
        ('分析过程...\n```json\n{"is_confirmed": true, "reason": "x", "fix_suggestion": "y"}\n```', True),
        ('{"is_confirmed": false}', False),
        ('"is_confirmed": true', True),
        ('无 JSON', None),
    ]
    for text, exp in cases:
        p = parse_triage_verdict(text)
        got = _normalize_confirmed(p.get("is_confirmed")) if p else None
        ok = got == exp
        ok_parse = ok_parse and ok
        print(f"[{'PASS' if ok else 'FAIL'}] parse: {text[:40]!r} -> {got} (期望 {exp})")

    # 2) 去重逻辑
    from dataclasses import dataclass
    f1 = ToolFinding(rule_id="r1", category="sast", source="request.GET.get('id')",
                     sink="cursor.execute(q)", taint_type="SQL Injection",
                     source_line=1, sink_line=5, path=["q"], severity="high", tool="semgrep")
    f2 = ToolFinding(rule_id="r2", category="taint", source="request.GET.get('id')",
                     sink="cursor.execute(q)", taint_type="SQL Injection",
                     source_line=1, sink_line=5, path=["q"], severity="high", tool="taint_tracker")
    merged = TwoStageScanner._dedupe([f1, f2])
    ok_dedupe = len(merged) == 1 and merged[0].tool == "semgrep+taint_tracker"
    print(f"[{'PASS' if ok_dedupe else 'FAIL'}] 去重: {len(merged)} 条, tool={merged[0].tool if merged else None}")

    # 3) 假 client 的裁决聚合（N=3，2 真 1 假 → confirmed=True, conf=0.667）
    class FakeClient:
        def __init__(self, outputs):
            self.outputs = outputs
            self.i = 0
        def generate(self, **kwargs):
            out = self.outputs[self.i % len(self.outputs)]
            self.i += 1
            return {"text": out, "error": None}

    outputs = [
        '```json\n{"is_confirmed": true, "reason": "参数化缺失", "fix_suggestion": "用参数化"}\n```',
        '```json\n{"is_confirmed": true, "reason": "参数化缺失", "fix_suggestion": "用参数化"}\n```',
        '{"is_confirmed": false}',
    ]
    scanner = TwoStageScanner(client=FakeClient(outputs), system_prompt="sys", n_samples=3)
    finding = ToolFinding(rule_id="r", category="sast", source="s", sink="t",
                          taint_type="SQL Injection", source_line=1, sink_line=5)
    verdict = scanner._adjudicate_one(finding, "code", "python", "", None)
    ok_adjud = (verdict.confirmed is True and verdict.votes_true == 2
                and verdict.votes_false == 1 and abs(verdict.confidence - 0.667) < 0.01)
    print(f"[{'PASS' if ok_adjud else 'FAIL'}] 裁决: confirmed={verdict.confirmed}, "
          f"votes={verdict.votes_true}/{verdict.votes_false}, conf={verdict.confidence:.3f}")

    # 4) 端到端聚合：无候选 → 安全（sampling_rate=0 关闭抽样复核，避免自检随机化）
    ts = TwoStageScanner(client=FakeClient(outputs), system_prompt="sys", n_samples=3,
                         use_semgrep=False, use_taint_tracker=False, use_prefilter=False,
                         sampling_rate=0)
    r = ts.scan_code('x = 1\nprint(x)', "python", "safe.py")
    ok_safe = r.has_vulnerability is False and r.stage1["decision"] == "no_candidate_safe"
    print(f"[{'PASS' if ok_safe else 'FAIL'}] 无候选判安全: has_vuln={r.has_vulnerability}, "
          f"decision={r.stage1.get('decision')}")

    print("\n", "=== 自检通过 ===" if all([ok_parse, ok_dedupe, ok_adjud, ok_safe])
          else "=== 存在失败用例 ===")