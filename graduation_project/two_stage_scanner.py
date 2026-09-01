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
import math
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
from graduation_project.prefilter import Prefilter, PREFILTER_RULE_INFO
from graduation_project.prompts import build_triage_prompt, build_user_prompt
from graduation_project.schema import normalize_has_vulnerability, parse_verdict
from graduation_project.cwe_normalizer import normalize_cwe_label, normalize_with_evidence
from graduation_project.code_slicer import CodeSlicer
from graduation_project.line_normalizer import normalize_line_numbers
from graduation_project.blind_spots import (
    scan_blind_spots, render_for_prompt, build_review_context,
)
from graduation_project.risk_budget import score_file


# ---------------------------------------------------------------------------
# 工具层召回监控（模块级计数器，供 /api 健康检查与论文召回漂移分析使用）
# ---------------------------------------------------------------------------
_MONITOR = {
    "no_candidate_total": 0,    # 无候选直判安全的文件数
    "recheck_sampled": 0,       # 其中被抽样复核的次数
    "recheck_vuln_found": 0,    # 抽样复核发现工具层漏报的次数
    "recheck_vuln_trusted": 0,  # 其中被 LLM 语义兜底采信为漏洞的次数（自适应闭环）
    "suppressed_skipped": 0,    # 抑制池接线后被跳过的候选数（2026-08-15 闭环读取端）
    # 2026-08-29 补：长文件复核走确定性分块预筛时递增（P5，2026-08-24 引入），
    # 此前键缺失 → _monitor_incr 抛 KeyError → _maybe_recheck 异常 → 整文件
    # "分析失败"。长文件（>num_ctx×0.45）无候选时必然踩中。
    "recheck_prescreened": 0,
    # 2026-08-31 补：定向复核（no_candidate_mode="targeted")的分档计数。
    # A/B/C 三档互斥且穷尽，供"注意力预算"章节的帕累托分析取数。
    "recheck_tier_a": 0,        # 高危+盲区：盲区片段 × min(3,n) 票
    "recheck_tier_b": 0,        # 低危+盲区：盲区片段 × 1 票
    "recheck_tier_c": 0,        # 零盲区：不送 LLM（显式留痕"未经 LLM 复核"）
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
    decision: str = ""              # 裁决档位（confirmed_vulnerability/dismissed_safe/
                                    # confirmed_review/dismissed_review/direct）
    vulnerability_type: str = ""    # 模型校正后的真实漏洞类型（is_confirmed 时输出）
    # 判真票的 source/sink 锚点（2026-08-29）：位置型候选自身无证据链文本，
    # 由外层在赋值 finding 后回填，供 _aggregate 透出到顶层。
    src_anchor: str = ""
    sink_anchor: str = ""
    conformal_set: str = ""         # 共形预测三分类（vulnerable/safe/uncertain）
    counterfactual: Optional[dict] = None  # 反事实扰动验证结果（Layer 2）
    evidence_gate: Optional[str] = None    # 确定性证据门拦截原因（sink_defended/no_input_entry）

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
            "decision": self.decision,
            "vulnerability_type": self.vulnerability_type,
            "conformal_set": self.conformal_set,
            "counterfactual": self.counterfactual,
            "evidence_gate": self.evidence_gate,
        }


@dataclass
class TwoStageResult:
    """两阶段扫描的文件级结果。"""
    filename: str
    language: str
    has_vulnerability: Optional[bool]
    stage1: dict = field(default_factory=dict)                    # 工具层统计
    stage1_ctx_warning: bool = False                              # P5 守卫：输入超上下文告警
    findings: list[ToolFinding] = field(default_factory=list)     # 全部候选
    adjudications: list[AdjudicationVerdict] = field(default_factory=list)
    reviewer_findings: list[dict] = field(default_factory=list)   # 低置信需人工复核
    vulnerability_type: str = ""      # 文件级漏洞类型（取已确认裁决中最高严重度 finding）
    vulnerability_types: list = field(default_factory=list)  # 多漏洞支持（2026-08-17）：
                                      # 所有判真且过证据门的 finding 的规范化类型
                                      # （去重保序）；vulnerability_type 保留为 top1 兼容
    risk_level: str = "None"          # 文件级风险等级（同样取最高严重度）
    explanation: str = ""             # 文件级分析说明（取已确认裁决的 reason）
    fix_suggestion: str = ""          # 文件级修复建议（取已确认裁决的 fix_suggestion）
    source: str = ""                  # 文件级 source（取已确认裁决 finding 的 source）
    sink: str = ""                    # 文件级 sink（取已确认裁决 finding 的 sink）
    total_duration: float = 0.0
    error: Optional[str] = None
    raw_vulnerability_type: str = ""  # 文件级漏洞类型原始输出（与 vulnerability_type 一致，
                                      # 两阶段没有 LLM 直接输出 CWE 的环节，为前端兼容保留）
    direct_findings: int = 0          # 直出档 finding（secret/sca）数量
    prefilter_verdict: Optional[bool] = None   # 兼容前端字段（两阶段 prefilter 不短路，恒为 None）
    sliced: bool = False              # 兼容前端字段（两阶段切片只用于裁决上下文，非全文件覆盖）
    chunk_count: int = 1              # 兼容前端字段
    raw_output: str = ""              # 兼容前端字段（两阶段裁决原始输出在 adjudications 内）

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "language": self.language,
            "has_vulnerability": self.has_vulnerability,
            "stage1": self.stage1,
            "stage1_ctx_warning": self.stage1_ctx_warning,
            "findings": [f.to_dict() for f in self.findings],
            "adjudications": [a.to_dict() for a in self.adjudications],
            "reviewer_findings": self.reviewer_findings,
            "vulnerability_type": self.vulnerability_type,
            "vulnerability_types": list(self.vulnerability_types),
            "raw_vulnerability_type": self.raw_vulnerability_type,
            "risk_level": self.risk_level,
            "explanation": self.explanation,
            "fix_suggestion": self.fix_suggestion,
            "source": self.source,
            "sink": self.sink,
            "total_duration": round(self.total_duration, 2),
            # 兼容字段（与 SingleResult 对齐，供前端/下游通用渲染）
            "duration": round(self.total_duration, 2),
            "direct_findings": self.direct_findings,
            "prefilter_verdict": self.prefilter_verdict,
            "sliced": self.sliced,
            "chunk_count": self.chunk_count,
            "raw_output": self.raw_output,
            "error": self.error,
        }


# 置信度阈值：≥0.8 自动结论；0.5~0.8 结论但标记复核；<0.5 或平票→reviewer
_CONF_AUTO = 0.8
_CONF_MANUAL = 0.5

# 严重度排序（用于文件级取最高风险 finding）
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "none": 0}

# 低信任候选类别（第 2.5 代）：位置型规则无语境证据链，是"工具提示不到点上→误导"
# 的重灾区（bandit B 系列 / semgrep 普通规则 / trivy iac）。对它们的共形=vulnerable
# 判定，须再过反事实验证（扰动不翻转 → 降级），防止"工具误报 + 模型全票被带偏"。
_LOW_TRUST_CATEGORIES = frozenset({"sast", "iac"})

# 标准漏洞语义类型白名单（无主告警剔除用，2026-08-17）：裁决层（triage prompt /
# 证据门 / 反事实验证 / 类型校正）全部围绕这些类型工作。位置型规则（sast/iac）
# 的 _infer_taint_type 若落不到白名单内（如 "request-data-write"、"B108" 等
# 乱码/边缘语义），模型无从裁决，剔除出裁决队列交 LLM 全文件复核兜底。
_STANDARD_TAINT_TYPES = frozenset({
    "SQL Injection", "Command Injection", "Code Injection", "XSS",
    "Server-Side Template Injection", "Path Traversal",
    "Insecure Deserialization",
    # 2026-08-29 加：硬编码凭证（CWE-798）。B3 门槛后弱值 secret 转裁决档，
    # 必须给规范类型才能通过本白名单，否则会被当作"无主告警"再次剔除。
    "Hardcoded Credentials",
    # 2026-08-29 加：SSRF（CWE-918）。此前 SSRF 不在白名单 → semgrep 的
    # ssrf-injection 规则被当无主告警剔除，只剩被撞词的 B310 伪装成 Path Traversal。
    "SSRF",
    # --- P2 类型族（2026-08-29 扩容，与 prefilter P2 规则 taint_type 对齐）---
    "Weak Cryptography", "Prototype Pollution", "Open Redirect",
    "Timing Attack", "Integer Overflow", "Log Injection",
    # 2026-08-29 加：TLS 证书验证禁用（CWE-295）。此前 bandit B501 @ line 10
    # 精确命中 typical_20 的 verify=False，却因类型不在白名单被当作"无主告警"
    # 剔除 → 界面显示"0 命中"，实为命中后丢弃（工具层浪费）。
    # 影响面实测：仅 2 段真漏洞样本含 TLS 特征、安全样本 0 段 → 不增加 FP 风险。
    "Insecure TLS",
    # --- 长尾注入族（2026-08-30 待办1，工具层优化指导 §五之六）：白名单此前
    # 只有注入型 + P2 族，XXE/LDAP/NoSQL 的精确告警（bandit B405-B409 XML 族、
    # semgrep ldap 规则等）会被当"无主告警"剔除——与 SSRF 当初被剔除同构。
    # 这三类的 sink 语义各异但证据文本自带规范词（untrusted XML / LDAP filter /
    # MongoDB 查询拼接），可安全推断。
    "XXE", "LDAP Injection", "NoSQL Injection",
    # 2026-08-30 逐条审查补（stage1_candidates_dump 人工审查发现）：SpEL 表达式
    # 注入（CWE-917）——typical_36 的 semgrep spel-injection 精确命中被当无主
    # 剔除（主漏洞证据丢失）。cwe_normalizer 已有 SpEL→CWE-917 映射，类型对齐。
    "SpEL Injection",
    # --- 第四波类型（2026-08-31，长尾注入族 + VFlask 审计缺口配套）：prefilter
    # 第四波新规则的 taint_type 与外部工具同语义告警的推断结果统一进白名单，
    # 防 sast 告警（bandit/semgrep 未来命中同形态）被当"无主告警"剔除。
    "XPath Injection", "Type Juggling", "Mass Assignment",
    "Improper Verification of Cryptographic Signature",   # CWE-347（jwt_verify_disabled）
    "Information Exposure Through Error Message",         # CWE-209（error_info_exposure）
    "Cleartext Storage of Sensitive Information",         # CWE-312（cleartext_sensitive_storage）
    # 2026-08-31 补（NodeGoat 审计）：semgrep express-cookie-settings 族——
    # session(...) 缺 httpOnly/secure/domain/expires/path 配置的 6 条精确告警
    # 此前全部被当"无主告警"剔除（CWE-1004/614 类 cookie flag 缺陷无类型承接）。
    "Insecure Cookie",
    "Unrestricted File Upload",                           # CWE-434（unrestricted_file_upload）
    # --- 第八波（2026-08-31，盲区层收口）：prefilter 新规则类型的白名单
    # 登记（同第四波配套纪律——防未来外部工具命中同形态时被当"无主告警"剔除）。
    "ReDoS",                                              # CWE-1333（redos_nested_quantifier）
    "Weak Password Policy",                               # CWE-521（weak_password_policy_regex）
})

# sast/iac 告警 evidence 中"告警行上下文"片段的标记（P0.3 追加 / _infer_taint_type
# 剥离共用同一常量，防止两处字面量漂移——待办1 2026-08-30）
_EVIDENCE_CTX_MARK = "[告警行上下文]"

# secret 类 SAST 规则（B3，2026-08-29，工具层优化指导 §二）：语义就是"硬编码凭证"
# 的位置型规则——凭证本来就没有 source→sink 污点流（B105/hardcoded-token 被判
# "无主"的根因），此前在无主告警剔除中被直接扔掉，SAST 侧的硬编码凭证证据被浪费。
# 归入 secret 直出档（与 gitleaks/detect-secrets 同档，确定性工具自判，不消耗 LLM）。
# 识别按 rule_id 与 message 双通道，均为规则语义级特征（bandit B105/B106/B107 是
# hardcoded_password 三连规则；semgrep 侧 hardcoded-token/hardcoded-secret 族），
# 非测试集拼写拟合。
_SECRET_SAST_RULE_RE = re.compile(
    r"(?:\bB10[567]\b"
    r"|hardcoded[-_.]?(?:token|secret|password|credential|api[_-]?key))",
    re.IGNORECASE,
)
_SECRET_SAST_MSG_RE = re.compile(
    r"hardcoded?\s+(?:password|passwd|secret|token|credential|api\s?key)",
    re.IGNORECASE,
)

# 框架配置型 secret 的弱值特征（B3 门槛用，2026-08-29）：
#  Flask/Django 的 app.secret_key / SECRET_KEY 是框架必需配置，其值常是
#  "dev_key" / "changeme" / "secret" 这类低熵占位符——bandit B105 会告警，
#  但它既不是"泄露的生产凭证"，也不该顶掉样本的真实漏洞类型（IDOR/CSRF/
#  SSTI 等）。B3 直出前须过凭证强度门槛，与 gitleaks 的判定语义对齐
#  （gitleaks 对这些值全部不响，其 generic-api-key 规则要求熵 3.5+ 且长度足够）。
# 占位符语义词（出现在值中即提示"非真凭证"）：dev/test/example/demo/placeholder 等
_PLACEHOLDER_TOKEN_RE = re.compile(
    r"(?:^|[_-])(?:dev|develop|development|test|testing|example|sample|dummy|"
    r"placeholder|changeme|demo|local|dummy)(?:$|[_-])", re.IGNORECASE,
)
# 高随机性片段：8+ 位含大小写/数字混合（真密钥/令牌的典型特征）
_HIGH_RANDOM_RE = re.compile(r"(?=.*[a-z])(?=.*[A-Z0-9])[A-Za-z0-9]{12,}")

_SECRET_WEAK_VALUE_RE = re.compile(
    r"^(?:dev[_-]?key|dev[_-]?secret|dev[_-]?token|test|testing|changeme|change[_-]?me|"
    r"secret|password|passwd|pwd|admin|root|default|example|sample|dummy|placeholder|"
    r"your[_-]?(?:secret|key|password)|xxx+|abc123|123456|demo|local|development)$",
    re.IGNORECASE,
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_strong_credential(evidence: str) -> bool:
    """B105 类告警的值是否达"可判真凭证"门槛（与 gitleaks 同语义）。

    门槛：① 从 '...' 引号中提取候选字面值；② 长度 ≥ 12 且香农熵 ≥ 3.0，
    或长度 ≥ 20（长随机串熵可能偏低但明显非占位符）；③ 命中弱值词表直接判否。
    引号提取失败的兜底（2026-08-31，typical_06 实锤）：gitleaks 的 Match 字段
    是**裸值**（无引号无赋值，如 "AKIAIOSFODNN7EXAMPLE"）→ 引号分支恒判弱 →
    真凭证被误转裁决档。兜底：evidence 中存在 ≥20 位连续密钥形态 token
    （[A-Za-z0-9+/=_-]，AKIA ID / hex / base64 的共同形态）即判真。
    仍取不到任何值 → 判否，走裁决档由模型判断，避免误直出。
    """
    m = re.search(r"[\"']([^\"']{4,})[\"']", evidence or "")
    if not m:
        # 裸值兜底：gitleaks Match 常为无引号的值本身
        bare = re.search(r"[A-Za-z0-9+/=]{20,}", evidence or "")
        return bool(bare)
    val = m.group(1)
    if _SECRET_WEAK_VALUE_RE.match(val):
        return False
    ent = _shannon_entropy(val)
    # 占位符长串（如 "very_long_dev_secret_key_for_testing_only"）熵与长度都够，
    # 但语义是"开发占位符"而非真凭证 → 命中占位词且无高随机性片段时判弱。
    if _PLACEHOLDER_TOKEN_RE.search(val) and not _HIGH_RANDOM_RE.search(val):
        return False
    return (len(val) >= 12 and ent >= 3.0) or len(val) >= 20

# 复核采信的确定性形态校验（2026-08-18 修正，替代 08-17 的类型白名单）：
# 白名单内容曾被测试集结果反向拟合（FP 类型被排除、TP 类型被收录）——这是
# 针对测试集调参，等同工具作弊，必须废弃。
# 客观规则：复核判真（工具无证据、纯 LLM 全文件语义）采信前，校验"类型与代码
# 形态是否匹配"。仅对**有确定性验证手段**的注入型漏洞做校验：
#   ① 代码中必须存在该类型的标准 sink 特征（否则判的类型与代码不符，如
#      "判 XSS 但代码无任何渲染点"）；
#   ② sink 处不得已有该类型的标准防御（复用 counterfactual._DEFENSE_SIGNATURES，
#      如 abspath 防路径穿越、参数化防 SQL——模型漏看已有防御 = 误判）。
# 无确定性验证手段的类型（CSRF/认证缺失/弱密码/硬编码等缺失型漏洞）不设校验，
# 全票采信——如实标注这是"模型语义兜底"，不是工具保证。
# CWE 编号 → 语义类型（用于查 _DEFENSE_SIGNATURES；仅注入型，公共安全分类）
_RECHECK_CWE_TO_TYPE = {
    "CWE-78": "Command Injection", "CWE-77": "Command Injection",  # 77/78 命令注入同族编号
    "CWE-94": "Code Injection",
    "CWE-89": "SQL Injection", "CWE-79": "XSS", "CWE-80": "XSS",   # 80 为 XSS 子类
    "CWE-22": "Path Traversal", "CWE-1336": "Server-Side Template Injection",
    "CWE-502": "Insecure Deserialization",
}

# 语义类型 → 标准 sink 存在性特征（通用，任何语言代码适用）
_RECHECK_SINK_RE = {
    "Command Injection": re.compile(r"subprocess\.(?:run|Popen|call|check_output|check_call)\(|os\.system\(|os\.popen\(|Runtime\.getRuntime\(|ProcessBuilder|child_process"),
    "Code Injection": re.compile(r"\beval\(|\bexec\(|SpelExpressionParser|ExpressionParser|Ognl|\.fromString\("),
    "SQL Injection": re.compile(r"\.execute(?:Query|Update|Many)?\(|executemany\(|raw\(|session\.execute\("),
    "XSS": re.compile(r"innerHTML|document\.write\(|insertAdjacentHTML|\.html\(|render(?:\(|_template)|return\s+[fF]['\"]|dangerouslySetInnerHTML|innerText\s*=|html\s*=\s*f['\"]|return\s+['\"][^'\"]*['\"]\s*\+"),
    "Path Traversal": re.compile(r"open\(|\.save\(|extractall\(|\.extract\(|os\.path\.join|os\.path\.realpath|readFile|createReadStream|File\(|getResource\("),
    "Server-Side Template Injection": re.compile(r"from_string\(|Environment\(|Template\(|render(?:\(|_template)|freemarker|velocity"),
    "Insecure Deserialization": re.compile(r"pickle\.loads\(|yaml\.load\(|readObject\(|ObjectInputStream|json\.loads\(|parseObject\(|defineClass\("),
}

# 跨文件调用检测（2026-08-18）：提取 import 符号后检查其是否被调用
#（f(...) 或 obj.f(...)）。被调函数的 sink 在当前文件不可见——形态校验无法
# 静态否定"类型与代码不符"，因此视为"有外部 sink 语义依据"。仅定义 getter
# 不调用导入函数的代码（如 crossfile_01 判 XSS）无任何 sink 依据，照常拦截。
_IMPORT_RE = re.compile(
    r"(?:from\s+[\w.]+\s+import\s+([\w,\s]+)|import\s+([\w.]+)(?:\s+as\s+[\w]+)?)",
    re.MULTILINE,
)

# 函数/类定义检测（2026-08-18）：复核门 ③ 用它区分"纯顶层字面量脚本"
#（无函数定义 → 无数据流接口 → 注入型判真需输入入口）与"有函数/类的代码"
#（参数接口 = 潜在外部输入）。多语言覆盖（Python/JS/TS/Java/PHP）。
_HAS_FUNCTION_DEF_RE = re.compile(
    r"\b(?:def|function|class)\s+\w+|=>\s*\{|public\s+(?:static\s+)?[\w<>\[\],\s]+\s+\w+\s*\(",
    re.MULTILINE,
)


def _has_cross_file_call(code: str) -> bool:
    imported: set[str] = set()
    for m in _IMPORT_RE.finditer(code):
        if m.group(1):  # from x import a, b
            imported.update(n.strip() for n in m.group(1).split(",") if n.strip())
        elif m.group(2):  # import x / import x.y
            imported.add(m.group(2).split(".")[0])
    if not imported:
        return False
    for name in imported:
        if re.search(rf"\b{re.escape(name)}\s*\(", code) or \
                re.search(rf"\.{re.escape(name)}\s*\(", code):
            return True
    return False

# 外部输入入口模式（确定性证据门用）：文件含任一模式即存在污点源可能；
# 全无入口的模块级字面量脚本（如 noise_03：name = "admin" 硬编码拼接）不可能
# 产生外部可控污点，泛规则对其的 SQLi/命令注入类命中是模式匹配误报。
# 2026-08-15 修复：删除 `def xxx(` / `function xxx(` / `=>` 三组模式——函数定义
# ≠外部输入，Python 代码几乎都含 def、JS/TS 几乎都含 =>，原模式使证据门 2
# 对真实代码永远放行（近乎死代码），只对纯模块级脚本生效。
_INPUT_ENTRY = re.compile(
    r"request\.|\.GET\b|\.POST\b|\.args\b|\.form\b|\.cookies\b|\.query\b|\.body\b|"
    r"\binput\(|sys\.argv|os\.environ|os\.getenv|"
    r"json\.load|yaml\.load|\.read\(\)|\.readlines\(\)|recv\(|socket\.|"
    # PHP 超全局（2026-08-30 补，typical_09 实锤）：此前 PHP 的 $_GET/$_POST/
    # $_REQUEST/$_COOKIE/php://input 全不识别 → 门 2 误判"无输入入口"，
    # 3:0 判真被 evidence_gate 拦成复核（跨语言盲区：原自检用例全为 Python）
    r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\b|php://input"
)

# 外部可控输入入口（判假守卫专用，**不含** .read()/.readlines()）：
# 与 _INPUT_ENTRY 的区别：后者把文件内容也当输入源（注入场景合理），但判假守卫
# 要判断"本文件是否有自己的输入接口"，helper 里的 f.read() 是把内容返回调用方，
# 不是本文件的数据流起点（crossfile_02_input 实测：含 .read() 会被误判有入口）。
_EXT_ENTRY_RE = re.compile(
    r"request\.|\.GET\b|\.POST\b|\.args\b|\.form\b|\.cookies\b|\.query\b|\.body\b|"
    r"\binput\(|sys\.argv|os\.environ|os\.getenv|"
    r"json\.load|yaml\.load|recv\(|socket\.|@RequestParam|@PathVariable|getParameter\("
)
_DEF_SIG_RE = re.compile(
    r"^\s*(?:def\s+(\w+)\s*\(([^)]*)\)|function\s+(\w+)\s*\(([^)]*)\)|"
    r"(?:public|private|protected)?\s*\w+\s+(\w+)\s*\(([^)]*)\)\s*\{)", re.M
)
_SINK_CALL_RE = re.compile(
    r"\b(open|execute|eval|exec|system|popen|run|loads|load|readObject|subprocess\.|Popen)\s*\("
)
# A 型判假守卫用：跨文件自定义导入
_FROM_IMPORT_RE = re.compile(r"^\s*from\s+([A-Za-z_][\w\.]*)\s+import\s+(.+)$", re.M)
_STD_MODULES = frozenset({
    "os", "sys", "re", "json", "time", "datetime", "hashlib", "sqlite3", "logging",
    "typing", "subprocess", "base64", "random", "secrets", "urllib", "socket",
    "threading", "csv", "uuid", "collections", "itertools", "functools", "pathlib",
    "tempfile", "shutil", "glob", "math", "io", "copy", "abc", "enum", "dataclasses",
    "flask", "django", "jinja2", "yaml", "pickle", "requests", "boto3", "pymongo",
    "ldap", "lxml", "Crypto", "jwt", "tarfile", "zipfile", "express", "fs", "path",
})


def _has_external_sink_call(code: str) -> bool:
    """A 型数据流中断：本文件有外部可控 source，但危险 sink 位于**被调用的
    项目内自定义模块**中（本文件无标准 sink）。

    语义：source（如 request.args）流入自定义函数（如 safe_read_file），
    该函数是否安全取决于**另一个文件**的实现。单文件扫描看不到它，
    "无候选 + 复核查无漏洞"直接判安全即静默放行（hard_crossfile_02_sink
    实测 FN：同一文件两次扫描一次判真一次判安全，纯凭采样运气）。

    触发条件（三条同时成立，缺一不可）：
      ① 本文件存在外部可控输入入口
      ② 本文件没有任何标准危险 sink（sink 确实缺失）
      ③ 调用了从非标准库模块导入的函数（数据流跨越文件边界）

    规则自证性：数据流完整性是漏洞判定的前置条件——source 在、sink 不在、
    且调用了外部函数，则 sink 极可能在该外部函数中。非测试集拟合。
    87 段全量离线验证：命中 1 段（hard_crossfile_02_sink，expected=true），
    8 个典型安全样本零误伤（均有标准 sink 或无自定义导入）。
    """
    if not _EXT_ENTRY_RE.search(code):
        return False
    if _SINK_CALL_RE.search(code):
        return False
    custom_fns: set[str] = set()
    for m in _FROM_IMPORT_RE.finditer(code):
        if m.group(1).split(".")[0] in _STD_MODULES:
            continue
        for name in m.group(2).split(","):
            fn = name.strip().split(" as ")[-1].strip()
            if fn:
                custom_fns.add(fn)
    if not custom_fns:
        return False
    return any(re.search(rf"\b{re.escape(fn)}\s*\(", code) for fn in custom_fns)


def _anchor_line(text: str, code: str) -> int:
    """从 "line N: ..." 锚点文本中取纠正后的行号（失败返回 0）。

    用于证据链回填时同步行号：位置型候选的行号由工具给出（可能是告警行、块头行），
    而判真票的文本锚点由模型给出——两者不一致时会自相矛盾。此处复用
    line_normalizer 的内容定位（行文本内容可靠、行号易错），取纠正后的行号。
    """
    if not text or not code:
        return 0
    try:
        # 从**纠正后的文本**取行号：normalize 幂等时（行号本就正确）anchors 为空，
        # 直接读 anchors 会得到 0；输出文本恒为 "line N: ..." 格式，从中提取最稳。
        corrected, _ = normalize_line_numbers(text, code, return_anchors=True)
    except Exception:
        return 0
    m = re.search(r"line\s+(\d+)", corrected or "")
    return int(m.group(1)) if m else 0


def _param_names(sig: str) -> set[str]:
    """从函数签名提取形参名（去默认值/类型标注/self/cls）。"""
    return {
        p.strip().split("=")[0].split(":")[0].strip()
        for p in sig.split(",") if p.strip()
    } - {"self", "cls"}


def _has_param_driven_sink(code: str) -> bool:
    """B 型数据流中断（helper 型）：本文件无自己的外部输入入口，但函数体内存在
    危险 sink，且 sink 实参经变量展开后依赖该函数形参。

    语义：这类文件是 helper/库函数，污点来源在**调用方**，单文件扫描既不能证明
    调用方安全、也不能证明危险——数据流在文件边界中断，"无候选 + 复核查无漏洞"
    直接判安全属静默放行（crossfile_02_input 实测 FN，且稳定复现）。

    规则通用性自证（非测试集拟合）：安全分析的基本原则是"数据流不完整时不能
    判定安全"；此处仅当①无任何外部可控入口 ②函数有形参 ③危险 sink 实参依赖
    形参 三条同时成立才触发。87 段全量离线验证命中 3 段（crossfile_02_input /
    longfile_01 / longfile_02），全部 expected=true，零安全样本误伤。
    """
    if _EXT_ENTRY_RE.search(code):
        return False
    for m in _DEF_SIG_RE.finditer(code):
        sig = next((g for g in (m.group(2), m.group(4), m.group(6)) if g is not None), "")
        params = _param_names(sig)
        if not params:
            continue
        start = m.end()
        nxt = _DEF_SIG_RE.search(code, start)
        body = code[start: nxt.start() if nxt else len(code)]
        assigns = {a.group(1): a.group(2)
                   for a in re.finditer(r"^\s*(\w+)\s*=\s*(.+?)\s*$", body, re.M)}
        for sm in _SINK_CALL_RE.finditer(body):
            expanded = body[sm.end(): sm.end() + 120]
            for _ in range(2):  # 变量依赖最多展开 2 跳（覆盖 `x = join(a, b); open(x)`）
                for var, rhs in assigns.items():
                    if re.search(rf"\b{re.escape(var)}\b", expanded):
                        expanded = expanded + " " + rhs
            if any(re.search(rf"\b{re.escape(p)}\b", expanded) for p in params):
                return True
    return False


# 外部工具分档（Stage 1 召回维度 → 裁决方式）：
# - 裁决档（taint/prefilter/sast/iac）：误报率高、真伪难辨，进 LLM 裁决层（A/C 档）
# - 直出档（secret/sca）：确定性工具自判即可，召回即作为已确认 finding，不消耗 LLM（B 档）
#   secret=硬编码密钥（gitleaks/detect-secrets），sca=依赖漏洞（trivy fs/pip-audit）
_ADJUDICATE_CATEGORIES = frozenset({"taint", "prefilter", "sast", "iac"})
_DIRECT_CATEGORIES = frozenset({"secret", "sca"})


# ---------------------------------------------------------------------------
# 裁决结果解析
# ---------------------------------------------------------------------------
def _extract_json_objects(text: str) -> list[str]:
    """从文本中收集所有完整 JSON 对象候选（花括号平衡匹配）。

    非贪婪 `{.*?}` 在 reason 等字段含 `}` 时会提前截断导致 JSON 解析失败，
    这里从每个 `{` 起做括号深度匹配，收集所有能完整闭合的对象。
    若第一个候选是伪 JSON（如"格式示例 {a: 1}"），调用方会继续尝试下一个。
    """
    candidates: list[str] = []
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
                    candidates.append(text[start:i + 1])
                    start = -1
    return candidates


def parse_triage_verdict(raw_output: str) -> Optional[dict]:
    """从裁决模型输出中解析判定 JSON。

    双格式兼容（2026-08-20 修复）：
      - is_confirmed 格式（triage_default 系 prompt）
      - has_vulnerability 格式（triage_train_aligned：system=ALPHA05_PROMPT + aligned schema，
        与 α0.5 训练格式一致）——此前只认 is_confirmed，aligned 模式下模型按 prompt 输出
        has_vulnerability 时全被判 invalid → 候选裁决全转 review（真实 CVE 集 11/11 实锤）。
        注释长期声称"双格式兼容"但代码从未实现，现已补齐。

    兼容 ```json ... ``` 围栏与裸 JSON。解析失败返回 None。
    """
    if not raw_output:
        return None
    # 提取 ```json ... ``` 围栏
    fences = re.findall(r"```(?:json)?\s*(.*?)\s*```", raw_output, re.DOTALL)
    candidates = fences + [raw_output]
    for text in candidates:
        for obj in _extract_json_objects(text):
            try:
                parsed = json.loads(obj)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                if "is_confirmed" in parsed:
                    return parsed
                if "has_vulnerability" in parsed:
                    # 归一化为 is_confirmed 语义（_adjudicate_one 统一消费）
                    # 2026-08-29 补：source/sink/explanation 此前未透传
                    # （只取了 reason/type/fix）→ 判真票的证据链锚点全部丢失，
                    # 位置型候选（无 source/sink 文本）导致顶层证据链恒空。
                    # reason/explanation 兼容：aligned schema 用 reason，主扫描
                    # schema 用 explanation；模型偶有混用，回退避免说明为空。
                    _reason = (parsed.get("reason") or "").strip() \
                        or (parsed.get("explanation") or "").strip()
                    return {"is_confirmed": parsed["has_vulnerability"],
                            "has_vulnerability": parsed.get("has_vulnerability"),
                            "reason": _reason,
                            "vulnerability_type": parsed.get("vulnerability_type", ""),
                            "fix_suggestion": parsed.get("fix_suggestion", ""),
                            "source": parsed.get("source", ""),
                            "sink": parsed.get("sink", ""),
                            "explanation": parsed.get("explanation", "")}
    # 字段级兜底（双格式）
    m = re.search(r'"is_confirmed"\s*:\s*(true|false)', raw_output, re.IGNORECASE)
    if m:
        return {"is_confirmed": m.group(1).lower() == "true"}
    m = re.search(r'"has_vulnerability"\s*:\s*(true|false)', raw_output, re.IGNORECASE)
    if m:
        return {"is_confirmed": m.group(1).lower() == "true",
                "has_vulnerability": m.group(1).lower() == "true"}
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
        n_samples: 自一致率采样次数 N（默认 3，与生产/评估 fixed5 组态对齐）。
        temperature: 采样温度（>0 保证投票多样性，默认 0.7）。
        keep_alive: 模型卸载策略（透传给 client.generate）。
        num_ctx: 上下文长度（透传）。
        use_rag: 是否对裁决注入 RAG 上下文（None=跟随 VULN_SCANNER_RAG 环境变量）。
        use_semgrep: 是否启用 Semgrep taint 召回（默认 True；未安装自动降级）。
        use_taint_tracker: 是否启用 TaintTracker 召回（默认 True）。
        use_prefilter: 是否启用 Prefilter 召回（默认 True）。
        use_external: 是否启用外部位置型工具召回（secret/sca/sast/iac，默认 True；
            未安装的工具自动降级）。secret/sca 直出不裁决，sast/iac 进裁决。
        no_candidate_mode: 无候选文件的复核策略——"sampled"（默认，10% 抽样
            LLM 复核，监控工具层漏报率）或 "full_recheck"（每个无候选文件都全量
            LLM 复核，消除"无证据判安全"的静默放行，供安全关键场景）。
    """

    # 定向复核（no_candidate_mode="targeted"）的档位阈值。
    # A 档门槛：文件风险分 ≥ 此值，或高优先级盲区 ≥ TARGETED_HIGH_SPOTS 条。
    # 12.0 的依据（risk_budget 自检实测）：含外部源+sink+入口点的业务文件得分
    # 约 20~40；纯工具层/DTO 为负分。12 足以把"有实际攻击面"与"无"分开。
    TARGETED_HIGH_RISK_SCORE = 12.0
    TARGETED_HIGH_SPOTS = 2

    def __init__(
        self,
        client,
        system_prompt: str,
        n_samples: int = 3,
        temperature: float = 0.7,
        keep_alive=0,
        num_ctx: Optional[int] = None,
        use_rag: Optional[bool] = None,
        use_semgrep: bool = True,
        use_taint_tracker: bool = True,
        use_prefilter: bool = True,
        use_external: bool = True,
        sampling_rate: Optional[float] = None,
        no_candidate_mode: str = "sampled",
        trust_llm_recheck: bool = True,
        use_conformal: bool = True,
        use_signal_feedback: bool = True,
        use_counterfactual: bool = True,
        triage_aligned: bool = False,
        use_blind_spots: Optional[bool] = None,
    ):
        self.client = client
        self.system_prompt = system_prompt
        # 训练对齐裁决（2026-08-17 推导）：triage_train_aligned 变体下，裁决 user prompt
        # 输出 schema 用 has_vulnerability（对齐 α0.5 训练格式），而非 is_confirmed。
        # 该标志同时让 _adjudicate_one 的解析走 has_vulnerability 优先（双格式兼容）。
        self.triage_aligned = triage_aligned
        self.n_samples = max(1, min(int(n_samples), 10))
        self.temperature = temperature
        self.keep_alive = keep_alive
        self.num_ctx = num_ctx or int(os.environ.get("VULN_SCANNER_NUM_CTX", "8192"))
        # RAG 默认跟随环境变量 VULN_SCANNER_RAG（与旧 Scanner 一致）；显式传参优先
        self.use_rag = (
            use_rag if use_rag is not None
            else os.environ.get("VULN_SCANNER_RAG", "0") == "1"
        )
        self.use_semgrep = use_semgrep
        self.use_taint_tracker = use_taint_tracker
        self.use_prefilter = use_prefilter
        # 外部位置型工具召回（secret/sca/sast/iac）开关（B/C 档）
        self.use_external = use_external
        # 无候选文件的复核策略：
        #   "sampled"     —— 10% 抽样 LLM 复核（监控工具层漏报率，省算力）
        #   "full_recheck"—— 每个无候选文件都全量 LLM 复核（消除"无证据判安全"，
        #                     供 URL/GitHub 等安全关键场景）
        #   "targeted"    —— 三档定向复核（2026-08-31）：按"文件风险分 × 盲区命中"
        #                     分配注意力，零盲区文件不送 LLM。大仓库场景下替代
        #                     full_recheck——后者对每个无候选文件都做全文件 × N 票，
        #                     成本随仓库规模线性爆炸且大多花在零风险文件上。
        self.no_candidate_mode = (
            no_candidate_mode
            if no_candidate_mode in ("sampled", "full_recheck", "targeted")
            else "sampled"
        )
        # 工具层盲区提醒（graduation_project/blind_spots.py）：
        # 把"工具写不了规则或写了会误报爆炸"的位置以行级提示注入 prompt，
        # 只描述工具的能力边界，不产生 finding、不进裁决、永不进抑制池。
        # 默认开启（VULN_SCANNER_BLIND_SPOTS=0 关闭，供 FP 影响消融）。
        self.use_blind_spots = (
            use_blind_spots if use_blind_spots is not None
            else os.environ.get("VULN_SCANNER_BLIND_SPOTS", "1") == "1"
        )
        # 自适应闭环（决策记录见 docs/方法论_工具模型自适应闭环.md）：
        # 无候选复核判 True 时采信 LLM（语义兜底），而非转人工 review。
        # 论文消融对比需关闭此开关复现旧行为。
        self.trust_llm_recheck = trust_llm_recheck
        # 第 2.5 代：共形预测门控（统计保证的置信度）+ 信号注册表（信任分级回填）
        # 默认启用；论文消融可关闭（--no-signal-feedback 对应）。
        self.use_conformal = use_conformal
        self.use_signal_feedback = use_signal_feedback
        self.use_counterfactual = use_counterfactual
        self._conformal = None
        self._signal_registry = None
        self._counterfactual = None
        if use_conformal:
            try:
                from graduation_project.conformal import ConformalPredictor
                self._conformal = ConformalPredictor(alpha=0.1)
                # 2026-08-15 接线：生产路径自动加载评估侧导出的校准阈值（Layer 1
                # 此前只在 exp_07 显式 --calibrate-from 时生效，生产恒未校准）。
                # eval_two_stage.py 校准后经 save_calibration 导出到
                # models/conformal_calibration.json；无文件时保持未校准（门控自动
                # 降级为旧投票逻辑）。VULN_SCANNER_CONFORMAL_CALIB 指定路径，=0 禁用。
                calib_path = os.environ.get(
                    "VULN_SCANNER_CONFORMAL_CALIB",
                    str(Path(__file__).resolve().parent.parent / "models" / "conformal_calibration.json"),
                )
                if calib_path != "0" and self._conformal.load_calibration(calib_path):
                    print(f"[TwoStageScanner] 共形校准已加载: {calib_path} "
                          f"({self._conformal.thresholds()})")
            except Exception as e:
                print(f"[TwoStageScanner] 共形预测器初始化失败（降级自一致率）: {e}")
        if use_signal_feedback:
            try:
                from graduation_project.signal_registry import get_signal_registry
                self._signal_registry = get_signal_registry()
            except Exception as e:
                print(f"[TwoStageScanner] 信号注册表初始化失败（降级无回填）: {e}")
        if use_counterfactual:
            try:
                from graduation_project.counterfactual import CounterfactualVerifier
                self._counterfactual = CounterfactualVerifier(
                    client=client, system_prompt=system_prompt, num_ctx=self.num_ctx)
            except Exception as e:
                print(f"[TwoStageScanner] 反事实验证器初始化失败（降级无扰动验证）: {e}")

        self._external = ExternalScanner() if (use_semgrep or use_external) else None
        self._taint_tracker = None
        self._prefilter = Prefilter() if use_prefilter else None
        self._slicer = CodeSlicer(min_lines=150)
        self._chroma = None  # 延迟初始化（首次用 RAG 时才连 Chroma）
        # 无候选直判安全路径的抽样复核比例（默认 10%，VULN_SCANNER_RECHECK_RATE 可调）
        self.sampling_rate = float(
            sampling_rate if sampling_rate is not None
            else os.environ.get("VULN_SCANNER_RECHECK_RATE", "0.1")
        )
        # 抑制/剔除标记（2026-08-18 补回，08-16 审查 #4 修复在 git checkout 事故重建中
        # 丢失）：本文件发生候选被抑制池跳过 / 无主告警剔除时置 True，无候选分支据此
        # 强制 LLM 复核（否则生产 sampled 模式 90% 静默放行）。请求级使用，每次扫描
        # 开始时复位。
        self._last_suppressed = False
        # §五之四 留痕（2026-08-30）：被抑制池跳过 / 被无主剔除的规则 id 在请求级
        # 累积，写入 stage1 字典（suppressed_by_registry / dropped_unowned）——
        # 消除"工具层零召回无任何提示"的静默性（与 B1 排除逻辑自我实现预言同构）。
        self._last_suppressed_rules: list[str] = []
        self._dropped_unowned_rules: list[str] = []

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------
    def sync_runtime(self, client=None, system_prompt: Optional[str] = None) -> None:
        """同步推理运行时（switch_model 后由上层调用）。

        2026-08-15 修复：此前反事实验证器在构造时捕获 client/system_prompt，
        后端切模型后只同步主扫描器（main.py），Layer 2 的翻转判定永远用旧
        prompt 跑。现在主链与 _counterfactual 一并跟随（client 原先因原地
        mutate 侥幸同对象，属巧合而非设计）。
        """
        if client is not None:
            self.client = client
        if system_prompt is not None:
            self.system_prompt = system_prompt
        if self._counterfactual is not None:
            self._counterfactual.sync_runtime(client=client, system_prompt=system_prompt)

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
        # 2026-08-15 修复：请求级 n_samples 不再突变写回 self.n_samples——
        # 后端全局单例曾被一次请求的参数永久改写，之后所有不传参的请求都
        # 用新默认值。改为仅本次扫描生效（下游 _adjudicate/_maybe_recheck 读
        # self.n_samples，扫描结束在 finally 恢复原值；_model_lock 串行下无竞态）。
        restore_n = None
        if n_samples is not None:
            n_eff = max(1, min(int(n_samples), 10))
            if n_eff != self.n_samples:
                restore_n = self.n_samples
                self.n_samples = n_eff
        rag_enabled = self.use_rag if use_rag is None else use_rag
        start = time.time()

        # 空文件/纯空白守卫（2026-08-30，DVNA 的 __init__.py 实锤）：空内容
        # 进入 full_recheck 兜底会被送 LLM"复核空气"，产出无意义的复核条目。
        # 空文件不构成漏洞载体，直接判安全短路返回。
        if not code or not code.strip():
            result = TwoStageResult(
                filename=filename, language=language, has_vulnerability=False,
                stage1={"decision": "empty_file_skipped", "candidates": 0},
                explanation="空文件（0 字节或纯空白），无可分析的代码内容。",
            )
            result.error = None
            return result

        try:
            return self._scan_code_inner(code, language, filename, rag_enabled, start)
        finally:
            if restore_n is not None:
                self.n_samples = restore_n

    def _scan_code_inner(self, code: str, language: str, filename: str,
                         rag_enabled: bool, start: float) -> TwoStageResult:
        """scan_code 的实际执行体（n_samples 已按请求生效，由调用方负责恢复）。"""

        result = TwoStageResult(
            filename=filename, language=language, has_vulnerability=None,
        )

        if not code or not code.strip():
            result.error = "empty code"
            result.total_duration = time.time() - start
            return result

        # P5 守卫（2026-08-23）：粗估 token（代码/中文混合 ~2 字符/token），
        # 超过上下文窗口 90% 时告警——ollama 会静默截断输入导致漏检。
        est_tokens = len(code) // 2 + code.count("\n")
        if est_tokens > self.num_ctx * 0.9:
            print(f"[ctx 守卫] {filename or 'inline'}: 约 {est_tokens} tokens "
                  f"> num_ctx {self.num_ctx}×0.9，输入可能被静默截断", flush=True)
            result.stage1_ctx_warning = True

        # 请求级复位抑制/剔除标记（候选被抑制池跳过或剔除 → 无候选分支强制复核）
        self._last_suppressed = False
        self._last_suppressed_rules = []
        self._dropped_unowned_rules = []
        self._last_tool_status = {}  # P2-9：外部工具执行状态（_stage1_recall 中更新）
        # 工具层盲区（请求级）：Stage 1 之后计算，裁决/复核两条路径共用同一份，
        # 保证"同一文件的盲区提醒"在一次扫描内完全一致（可复现）。
        self._last_blind_spots = None

        # Stage 1：工具召回
        findings = self._stage1_recall(code, language, filename)
        # 工具层盲区定位（纯确定性，无 LLM）：无论有无候选都算——
        # 有候选 → 附在裁决上下文（零额外调用）；无候选 → 决定定向复核档位与片段。
        if self.use_blind_spots:
            try:
                self._last_blind_spots = scan_blind_spots(code)
            except Exception as e:
                # 盲区是**旁路提示**，任何异常都不得中断召回主流程
                # （与 _drop_irrelevant_positional 的留痕容器同因）
                print(f"[TwoStageScanner] 盲区扫描失败（降级无提醒）: {e}")
                self._last_blind_spots = None
        result.findings = findings
        result.stage1 = self._stage1_stats(findings)
        result.stage1["recall_duration"] = round(time.time() - start, 2)
        # §五之四 留痕（2026-08-30）：抑制池跳过 / 无主告警剔除的规则在 stage1
        # 字典可见——"某样本工具层零召回"由此可归因（是没命中，还是命中后被
        # 抑制/剔除），消除静默性；评估与前端可据此审计抑制池健康度。
        if self._last_suppressed_rules:
            result.stage1["suppressed_by_registry"] = {
                "count": len(self._last_suppressed_rules),
                "rule_ids": sorted(set(self._last_suppressed_rules)),
            }
        if self._dropped_unowned_rules:
            result.stage1["dropped_unowned"] = {
                "count": len(self._dropped_unowned_rules),
                "rule_ids": sorted(set(self._dropped_unowned_rules)),
            }
        # P2-9（2026-08-31）：外部工具执行状态写进 stage1。"工具层零召回"由此
        # 可归因到执行层：ok=正常跑完 / empty=无输出 / parse_error=输出不可解析 /
        # timeout / not_found / os_error。仅在有异常状态时记录，正常 ok 不占字典。
        abnormal = {t: s for t, s in self._last_tool_status.items() if s != "ok"}
        if abnormal:
            result.stage1["tool_status"] = abnormal
        if self._last_blind_spots is not None and self._last_blind_spots.count:
            # 盲区留痕（§五之四 同构思路）：与 suppressed/dropped 一样写进 stage1，
            # 让"模型看到了什么提示"可被审计——盲区提醒会实质影响模型判断，
            # 不可见即不可控。
            result.stage1["blind_spots"] = self._last_blind_spots.to_dict()

        # 无候选 → 判安全但复核：sampled=按比例抽样复核（监控工具层召回漂移）；
        # full_recheck=全量 LLM 复核（安全关键场景，消除"无证据判安全"的静默放行）；
        # targeted=三档定向复核（按风险分 × 盲区分配注意力，大仓库默认）。
        # force=本文件发生抑制跳过/无主告警剔除（_last_suppressed）→ 强制复核
        if not findings:
            recheck = self._maybe_recheck(
                code, language, force=self._last_suppressed, filename=filename)
            result.has_vulnerability = False
            result.stage1["decision"] = "no_candidate_safe"
            if recheck is not None:
                result.stage1["recheck"] = recheck
                if recheck.get("tier") == "C":
                    # 定向复核 C 档：零盲区 → 未送 LLM。
                    # 关键：这不是"复核判安全"（那需要 LLM 真的看过），而是
                    # "注意力预算未覆盖"。故 decision 单独取值，且**不转人工**——
                    # 否则每个零风险文件都会变成一条待办，review 队列被淹没。
                    # 留痕在 stage1.recheck 里（tier/C），前端与审计可区分二者。
                    result.has_vulnerability = False
                    result.stage1["decision"] = "no_candidate_no_blind_spot"
                    result.explanation = (
                        "工具层无候选，且未命中任何工具层盲区形态——该文件未获得"
                        "LLM 复核预算（定向复核 C 档）。这不等于经 LLM 确认安全。")
                    result.total_duration = time.time() - start
                    return result
                if recheck.get("has_vulnerability") is True:
                    n = int(recheck.get("n") or 1)
                    votes_true = int(recheck.get("votes_true") or (1 if n == 1 else 0))
                    unanimous = n > 0 and votes_true == n
                    # 定向复核 B 档（低危+盲区，单票）：n=1 时的"全票"只是"没人
                    # 反对"，不是"三票一致"。无工具证据的采信必须是最高置信级别，
                    # 故 B 档判真一律转人工复核（走下方 recheck_low_conf_review）。
                    if recheck.get("tier") == "B":
                        unanimous = False
                    if self.trust_llm_recheck and unanimous:
                        # 复核采信门（2026-08-18 修正）：无候选复核是全凭 LLM 的
                        # 最高置信采信路径。注入型漏洞必须与代码形态匹配（sink 存在
                        # + 无标准防御），否则转 review——客观规则，非测试集拟合
                        # （safe_04 有 abspath 防御仍判 CWE-22、noise_05 参数化仍判
                        # CWE-89、crossfile_01 无渲染点仍判 CWE-79 由此拦截）。
                        vt_raw = recheck.get("vulnerability_type") or ""
                        plausible, reject_reason = self._recheck_type_plausible(
                            code, language, vt_raw)
                        if not plausible:
                            result.has_vulnerability = None
                            result.stage1["decision"] = "recheck_unverified_type_review"
                            result.error = (f"复核全票判 {vt_raw[:40]}，但代码形态不匹配"
                                            f"（{reject_reason}），转人工复核")
                            result.stage1["recheck"] = recheck
                            result.total_duration = time.time() - start
                            return result
                        # 自适应闭环（方法论_工具模型自适应闭环.md 决策点 2）：工具层
                        # 漏召（无候选）由 LLM 语义兜底，复核判 True 即采信为漏洞。
                        # 依据：16 个工具盲区样本纯 LLM 判定正确 15/16——模型天然会，
                        # 架构不应把模型能力锁死在工具之下。保留"漏召"标记供召回监控。
                        # 全票门（2026-08-15）：仅全票一致的复核判真才采信——无工具
                        # 证据的采信必须是最高置信级别。
                        result.has_vulnerability = True
                        result.stage1["decision"] = "no_candidate_recheck_vuln"
                        _monitor_incr("recheck_vuln_trusted")
                        # 回填类型信息（2026-08-15 修复）：recheck 采信此前丢失
                        # vulnerability_type——判定对了标号没了，11 个盲区样本
                        # strict_recall 被工程缺陷吞掉
                        vt = recheck.get("vulnerability_type") or ""
                        if vt:
                            # evidence 通道（2026-08-29）：LLM 复核的 explanation 是
                            # 类型纠偏的最后证据源——模型编号记岔（如原型污染标 912）
                            # 但 explanation 含高特异形态词（__proto__/原型污染）时，
                            # normalize_with_evidence 可覆盖。守卫逻辑在 cwe_normalizer 内。
                            result.vulnerability_type = (
                                normalize_with_evidence(vt, recheck.get("explanation") or "")
                                or normalize_cwe_label(vt) or vt
                            )
                            result.raw_vulnerability_type = vt
                        # P3（2026-08-23）：多漏洞聚合——其余判真票类型不再丢失
                        for t in (recheck.get("types") or []):
                            nt = normalize_cwe_label(t) or t
                            if nt and nt not in (result.vulnerability_types or []):
                                result.vulnerability_types.append(nt)
                        if recheck.get("risk_level"):
                            result.risk_level = recheck["risk_level"]
                        # 2026-08-29 补：source/sink 是 LLM 输出的 "line N:" 锚定文本，
                        # 行号易数错，与 fix_suggestion 同样接 line_normalizer 纠正——
                        # 此前只纠正 fix_suggestion，出现"修复行号对、证据链行号错"
                        # 的不一致（hard_cve_02 实锤）。无锚点文本原样返回，对兜底
                        # 说明文本无副作用。
                        src = normalize_line_numbers(recheck.get("source") or "", code) if code else (recheck.get("source") or "")
                        snk = normalize_line_numbers(recheck.get("sink") or "", code) if code else (recheck.get("sink") or "")
                        # explanation 纠正一次、两处复用（2026-08-29）：顶层
                        # explanation 与 adjudication.reasoning 必须同源同版，
                        # 否则前端"收起态分析说明（已纠）vs 裁决区分析说明（原始）"
                        # 同屏两个行号版本（hard_cve_02 第 4 次扫描实锤）。
                        _expl_fixed = (
                            normalize_line_numbers(recheck.get("explanation") or "", code)
                            if code else (recheck.get("explanation") or "")
                        )
                        if recheck.get("explanation") and not result.explanation:
                            result.explanation = _expl_fixed
                        fix = recheck.get("fix_suggestion") or ""
                        if fix and not result.fix_suggestion:
                            result.fix_suggestion = (
                                normalize_line_numbers(fix, code) if code else fix
                            )
                        # 2026-08-15 修复（证据链）：此前该路径 has_vulnerability=True
                        # 但 findings/adjudications 全空——API 消费者拿到"有漏洞"却
                        # 无 source/sink 行级证据。现从 recheck 判真票构造合成
                        # finding + 直采信裁决，结构性证据链补齐（source/sink 取
                        # recheck verdict 输出，无则用说明文本兜底）。
                        synthetic = ToolFinding(
                            rule_id="llm_recheck", category="llm",
                            source=src or (recheck.get("explanation") or "LLM 复核判真（Stage 1 未召回）")[:80],
                            sink=snk or "（见 explanation：全文件语义分析）",
                            taint_type=vt or "Unknown",
                            source_line=0, sink_line=0, path=[],
                            severity=(recheck.get("risk_level") or "medium").lower(),
                            tool="llm_recheck",
                            evidence=recheck.get("explanation") or "无候选复核全票判真",
                        )
                        result.findings.append(synthetic)
                        result.adjudications.append(AdjudicationVerdict(
                            confirmed=True, confidence=1.0,
                            votes_true=int(recheck.get("votes_true") or 1),
                            votes_false=int(recheck.get("votes_false") or 0),
                            votes_invalid=int(recheck.get("votes_invalid") or 0),
                            reasoning=_expl_fixed,
                            fix_suggestion=result.fix_suggestion,
                            finding=synthetic.to_dict(),
                            decision="confirmed_vulnerability",
                            vulnerability_type=vt or "",
                        ))
                        # 信号注册表 learn_pool 接线（2026-08-15：add_to_learn_pool
                        # 此前全仓库无调用方）：工具层漏召但 LLM 全票判中的文件
                        # 特征收录进待学习池，供后续召回漂移监控/指纹级召回。
                        if self._signal_registry is not None:
                            self._signal_registry.add_to_learn_pool({
                                "file": filename or "inline",
                                "feature": f"llm_only:{(vt or 'unknown')}",
                                "evidence": (recheck.get("explanation") or "")[:200],
                                # 2026-08-18 补：无候选采信路径本就全票门（votes_true==n），
                                # 与兜底分支（has_candidate_recheck_vuln）一致带 unanimous 标记，
                                # 否则 add_to_learn_pool 的门控直接 return（死写入）。
                                "unanimous": True,
                            })
                    elif self.trust_llm_recheck:
                        # 多数判漏洞但非全票：不采信，转人工（防过度自信后端 recheck 误报）
                        result.has_vulnerability = None
                        result.stage1["decision"] = "recheck_low_conf_review"
                        result.error = "复核多数判漏洞但未全票一致（Stage 1 未召回），需人工复核"
                    else:
                        # 旧行为（保守）：复核命中转人工复核，不直接采信
                        result.has_vulnerability = None
                        result.stage1["decision"] = "recheck_hit_review"
                        result.error = "复核发现疑似漏洞（Stage 1 未召回），需人工复核"
                elif recheck.get("has_vulnerability") is False:
                    # 复核判安全：LLM 全量确认无漏洞，采信为安全（full_recheck 路径）
                    #
                    # 判假守卫（2026-08-29）：与"复核判真需全票"对称——判真侧有
                    # unanimous 全票门防过度采信，判假侧此前零门槛，任何一次
                    # 复核查无漏洞即静默判安全。但**数据流在文件边界中断**的文件
                    # （helper 型：无自身输入入口、危险 sink 由形参驱动，污点来源
                    # 在调用方）单文件扫描无法证明其安全——LLM 只看当前文件必然
                    # 判安全（crossfile_02_input 稳定 FN 实证）。此类转人工复核。
                    if _has_param_driven_sink(code):
                        result.has_vulnerability = None
                        result.stage1["decision"] = "recheck_incomplete_flow_review"
                        result.error = (
                            "数据流不完整：本文件无自身输入入口，危险 sink 由函数参数驱动"
                            "（helper/库函数，污点来源在调用方）——单文件扫描无法判定安全，"
                            "需结合调用方或项目级上下文人工复核")
                    elif _has_external_sink_call(code):
                        # A 型：source 在本文件、sink 在被调用的项目内自定义模块
                        result.has_vulnerability = None
                        result.stage1["decision"] = "recheck_incomplete_flow_review"
                        result.error = (
                            "数据流不完整：本文件有外部可控输入，但危险 sink 位于被调用的"
                            "自定义模块中——单文件扫描无法判定安全，需结合被调用文件或"
                            "项目级上下文人工复核")
                    else:
                        result.stage1["decision"] = "no_candidate_recheck_safe"
                else:
                    # 复核结果未知（推理异常/平票/解析失败）（2026-08-18 补回，
                    # 08-16 审查 #2 修复在 git checkout 事故重建中丢失）：既未判真
                    # 也未判安全，不能静默停在 no_candidate_safe，转人工复核。
                    result.has_vulnerability = None
                    result.stage1["decision"] = "recheck_unknown_review"
                    result.error = (recheck.get("error")
                                    or "复核结果未知（异常或平票），需人工复核")
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

        # Layer 2：反事实扰动验证（判中且高置信的 finding 施加防御扰动，验裁决翻转）
        if self._counterfactual is not None and code:
            self._counterfactual_pass(adjudications, code, language, filename)

        # 确定性证据门（零 LLM 成本）：sink 已防御 / 无输入入口的判中降权复核
        if code:
            self._evidence_gate_pass(adjudications, code, language)

        # 聚合最终结论
        self._aggregate(result, code=code)
        # 裁决全否决兜底（2026-08-17 修复）：全部候选 finding 被裁决否决时，
        # 文件被判安全——但裁决式任务只问"工具告警是否为真"，模型不会自主发现
        # 工具没召回的漏洞（规则覆盖不可能 100%），工具盲区在裁决路径上被静默放行。
        # 复用无候选复核通道（_maybe_recheck：开放式 build_user_prompt + system_prompt
        # 全文件分析 + 双格式解析 + N 票全票门）对判安全文件做一次全文件复核，
        # 命中且全票判真 → 采信为漏洞（与无候选 trust_llm_recheck 同门槛）。
        if (result.has_vulnerability is False and result.adjudications
                and self.trust_llm_recheck and code):
            recheck = self._maybe_recheck(
                code, language, force=True, count_monitor=False, filename=filename)
            if recheck is not None and recheck.get("has_vulnerability") is True:
                n = int(recheck.get("n") or 1)
                votes_true = int(recheck.get("votes_true") or (1 if n == 1 else 0))
                if n > 0 and votes_true == n:
                    # 复核采信门（2026-08-18，与无候选分支同因同标准）：客观形态校验，
                    # 非测试集拟合（见 _recheck_type_plausible 注释）。
                    vt_raw = recheck.get("vulnerability_type") or ""
                    plausible, reject_reason = self._recheck_type_plausible(
                        code, language, vt_raw)
                    if not plausible:
                        result.stage1["decision"] = "has_candidate_recheck_unverified_review"
                        result.error = (f"兜底复核全票判 {vt_raw[:40]}，但代码形态不匹配"
                                        f"（{reject_reason}），转人工复核")
                        result.stage1["recheck"] = recheck
                        result.total_duration = time.time() - start
                        return result
                    # 全票判真才采信（与 no_candidate 分支的 trust_llm_recheck 门槛一致）
                    result.has_vulnerability = True
                    result.stage1["decision"] = "has_candidate_recheck_vuln"
                    _monitor_incr("recheck_vuln_trusted")
                    vt = normalize_cwe_label(vt_raw) or vt_raw
                    if vt:
                        result.vulnerability_type = vt
                        result.raw_vulnerability_type = vt_raw
                    for t in (recheck.get("types") or []):
                        nt = normalize_cwe_label(t) or t
                        if nt and nt not in (result.vulnerability_types or []):
                            result.vulnerability_types.append(nt)
                    if recheck.get("risk_level"):
                        result.risk_level = recheck["risk_level"]
                    # explanation 纠正一次、两处复用（同 no_candidate 采信块）：
                    # 顶层 explanation 与 adjudication.reasoning 同源同版
                    _expl_fixed = (
                        normalize_line_numbers(recheck.get("explanation") or "", code)
                        if code else (recheck.get("explanation") or "")
                    )
                    if recheck.get("explanation") and not result.explanation:
                        result.explanation = _expl_fixed
                    fix = recheck.get("fix_suggestion") or ""
                    if fix and not result.fix_suggestion:
                        result.fix_suggestion = (
                            normalize_line_numbers(fix, code) if code else fix
                        )
                    src = normalize_line_numbers(recheck.get("source") or "", code) if code else (recheck.get("source") or "")
                    snk = normalize_line_numbers(recheck.get("sink") or "", code) if code else (recheck.get("sink") or "")
                    synthetic = ToolFinding(
                        rule_id="llm_recheck", category="llm",
                        source=src or (recheck.get("explanation") or "LLM 复核判真（裁决全否决，工具未召回）")[:80],
                        sink=snk or "（见 explanation：全文件语义分析）",
                        taint_type=vt or "Unknown",
                        source_line=0, sink_line=0, path=[],
                        severity=(recheck.get("risk_level") or "medium").lower(),
                        tool="llm_recheck",
                        evidence=recheck.get("explanation") or "裁决全否决后全文件复核全票判真",
                    )
                    result.findings.append(synthetic)
                    result.adjudications.append(AdjudicationVerdict(
                        confirmed=True, confidence=1.0,
                        votes_true=votes_true,
                        votes_false=int(recheck.get("votes_false") or 0),
                        votes_invalid=int(recheck.get("votes_invalid") or 0),
                        reasoning=_expl_fixed,
                        fix_suggestion=result.fix_suggestion,
                        finding=synthetic.to_dict(),
                        decision="confirmed_vulnerability",
                        vulnerability_type=vt or "",
                    ))
                    # 信号注册表 learn_pool 接线（与 no_candidate 采信块一致）
                    if self._signal_registry is not None:
                        self._signal_registry.add_to_learn_pool({
                            "file": filename or "inline",
                            "feature": f"llm_only:{(vt or 'unknown')}",
                            "evidence": (recheck.get("explanation") or "")[:200],
                            "unanimous": True,
                        })
        # Judge-safe guard on the candidate path (2026-08-29): after all adjudications
        # are dismissed AND the fallback recheck also says safe, still verify data-flow
        # completeness. Previously the guard lived only in the no-candidate branch, so
        # cross-file samples that WERE recalled but then dismissed sailed through to
        # "safe" (hard_crossfile_02_input: prefilter correctly flagged
        # path_traversal_open_join, model voted 0/3, fallback recheck said safe).
        if (result.has_vulnerability is False and code
                and (_has_param_driven_sink(code) or _has_external_sink_call(code))):
            result.has_vulnerability = None
            result.stage1["decision"] = "dismissed_incomplete_flow_review"
            result.error = (
                "数据流不完整，单文件扫描无法判定安全：本文件的危险操作依赖其他文件"
                "（helper 型参数驱动，或 sink 位于被调用的自定义模块中），"
                "需结合调用方或项目级上下文人工复核")
        result.total_duration = time.time() - start
        return result

    @staticmethod
    def _infer_taint_type(finding: dict) -> str:
        """推断 finding 的漏洞类型（反事实验证选防御模板用）。

        优先取 taint_type；sast/iac 位置型候选的 taint_type 是 rule_id（如 "B602"），
        从 rule_id/evidence 关键词推断真实类型（subprocess/os.system→命令注入，
        execute/拼接→SQL，return f-string→XSS，open→路径穿越，from_string→SSTI）。

        """
        tt = (finding.get("taint_type") or "")
        # 证据上下文剥离（待办1，2026-08-30）：sast/iac 告警的 evidence 附带
        # [告警行上下文] 源码片段，行上下文只说明"在哪里"（sink 邻域代码），
        # 不说明"是什么"——hard_cve_03 实锤：semgrep request-data-write 因
        # 上下文含 open(/extractall 被推断成 Path Traversal，带着错误类型标注
        # 进裁决诱导模型投错票（同一文件三次扫描三结论）。类型/族归因只准用
        # 告警自身语义描述。裁决 prompt 不受影响（P0.3 上下文本就是给 LLM 看
        # 的，那里需要"在哪里"）。
        ev = str(finding.get("evidence") or "")
        if _EVIDENCE_CTX_MARK in ev:
            ev = ev.split(_EVIDENCE_CTX_MARK, 1)[0]
        text = " ".join(str(x) for x in [
            finding.get("taint_type"), finding.get("rule_id"),
            ev, finding.get("message"),
        ] if x).lower()
        # 语义类型名（如 "Command Injection"）直接用；规则号/长路径（B602、
        # models.semgrep_rules.xxx）是工具内部标识，须按关键词推断真实类型。
        is_semantic = tt and not re.fullmatch(r"B\d+|[\w.]+", tt) and " " in tt.strip()
        if is_semantic and tt.lower() not in ("unknown", "detected"):
            return tt
        # 注意：text 已 lower()，规则号正则必须用小写才匹配（2026-08-15 修复：
        # 原大写 B608 使规则号推断成为死代码，全靠 evidence 关键词兜底）
        # b605（start_process_with_a_shell，os.system/popen）：消息 "Starting a
        # process with a shell"——2026-08-30 审查补（hard_cve_01 实锤：与链级
        # 候选同 sink 的精确 bandit 证据被剔除，多工具一致信号丢失）
        if ("subprocess" in text or "os.system" in text or "command" in text
                or "process with a shell" in text
                or re.search(r"b60[23457]", text)):
            return "Command Injection"
        # --- 长尾注入族（2026-08-30 待办1，白名单扩容配套推断分支）---
        # NoSQL 必须在 SQL 之前判定："nosql" 含 "sql" 子串，先判 SQL 会把
        # NoSQL 注入吞掉（cwe_normalizer 2026-08-18 修过同款顺序陷阱）。
        if ("nosql" in text or "no sql" in text or "no-sql" in text
                or "mongodb" in text or "mongo" in text):
            return "NoSQL Injection"
        if "ldap" in text:
            return "LDAP Injection"
        # XXE：bandit B405-B409（XML 解析器黑名单族）消息统一含 "untrusted XML"，
        # semgrep 侧为 entity/doctype 语义。裸 "xml" 不做依据（太宽，会撞
        # XMLDecoder 等反序列化形态）。
        if ("xxe" in text or "untrusted xml" in text
                or "xml external entity" in text or "entity expansion" in text
                or re.search(r"b40[5-9]", text)):
            return "XXE"
        # XPath 注入（2026-08-31 第四波）：lxml .xpath / Java XPath 评估语义。
        # 裸 "xpath" 专属性强（无第二漏洞语义），可安全归型。
        if "xpath" in text:
            return "XPath Injection"
        # SpEL（2026-08-30 逐条审查补）：typical_36 的 semgrep spel-injection
        # 精确命中被当无主剔除（主漏洞 CWE-94/917 证据丢失）。cwe_normalizer
        # 已有 SpEL→CWE-917 映射。ognl（2026-08-31 第四波补）：OGNL 表达式求值
        # 与 SpEL 同属"表达式注入"族，cwe_normalizer 的 ognl 关键词同归 CWE-917。
        if ("spel" in text or "ognl" in text or "expression parser" in text):
            return "SpEL Injection"
        # Code Injection（2026-08-30 逐条审查补）：eval 族告警（bandit B307、
        # semgrep eval-detected/user-eval）此前无推断分支——typical_08 的 3 条
        # 精确告警全被剔除。必须在 SQL 之前判定：eval 告警消息含 "execute
        # arbitrary code"，SQL 分支的 "execute" 会抢走。\beval\b 词边界避开
        # literal_eval（推荐写法）与 evaluate；\bexec\b 避开 execute/executable。
        if (re.search(r"\beval\b|\bexec\b", text) or "b307" in text
                or "insecure function" in text):
            return "Code Injection"
        if "execute" in text or "sql" in text or re.search(r"b608|b609", text):
            return "SQL Injection"
        if "format-string" in text or "html" in text or "xss" in text or "innerhtml" in text:
            return "XSS"
        # Insecure TLS（2026-08-29 加）：仅用**证书验证专有术语**，不用裸
        # verify=False —— 后者在 JWT 场景是"不校验签名"（CWE-347），语义不同。
        # 实测两条 TLS 规则的 evidence 均含 certificate/SSL 专词，可精准区分。
        if ("certificate" in text or "certification validation" in text
                or "cert_none" in text or "check_hostname" in text
                or "create_unverified" in text or "rejectunauthorized" in text
                or "b501" in text):
            return "Insecure TLS"
        # SSRF（2026-08-29 加）：须在 Path Traversal 之前判定——urlopen/requests
        # 的文本含 "open(" 子串，若先判 Path Traversal 会把 SSRF 撞成路径穿越
        # （typical_07 / hard_cve_04 实锤：B310 伪装成 Path Traversal 过白名单，
        #  真正的 semgrep ssrf 规则又因 SSRF 不在白名单被剔除 → SSRF 语义整条丢失）
        if ("urlopen" in text or "urlretrieve" in text or "requests.get" in text
                or "requests.post" in text or "httpclient" in text or "new url" in text
                or "urllib" in text or "ssrf" in text or "fetch(" in text
                or "b310" in text):
            return "SSRF"
        # 词边界 \bopen：避免 urlopen 的 "open(" 子串误判为文件打开。
        # tarfile/extractall 裸词（2026-08-30 审查补）：B202 消息
        # "tarfile.extractall used without any validation" 不带括号——上下文
        # 剥离（待办1）后原先靠行上下文撞词的推断失援，须由告警自身语义承接
        # （hard_cve_07 实锤）。
        if (re.search(r"\bopen\s*\(", text) or ".save(" in text or "extractall" in text
                or ".extract(" in text or "tarfile" in text or "os.path.join" in text
                or "os.path.realpath" in text or "readfile" in text
                or "createreadstream" in text or "file(" in text or "getresource(" in text):
            return "Path Traversal"
        if "from_string" in text or "template" in text or "ssti" in text:
            return "Server-Side Template Injection"
        if "pickle" in text or "deserial" in text or "yaml" in text:
            return "Insecure Deserialization"
        # fastjson（2026-08-31 第四波补）：JSON.parseObject / fastjson 语义归
        # 反序列化——hard_cve_08（CWE-502）族的 semgrep/bandit 同语义告警承接。
        if "parseobject" in text or "fastjson" in text:
            return "Insecure Deserialization"
        # JWT 签名校验关闭（2026-08-31 第四波补）：jwt/verify_signature 专属性
        # 强，无撞词。注意在 TLS 分支之前无碍——TLS 用 certificate 专词，JWT
        # 证据不含；反过来 JWT 分支的 "verify" 语义不能裸用（B501 evidence 是
        # "verify=False" 但含 certificate 专词 → 走 TLS 分支，不冲突）。
        if ("jwt" in text or "verify_signature" in text
                or "none algorithm" in text or "algorithm.**none**" in text):
            return "Improper Verification of Cryptographic Signature"
        # ↓↓↓ P2 类型族（2026-08-29，与 prefilter P2 规则 taint_type 对齐）：
        # 这些类型模型完全可以裁决，但此前既无 _infer_taint_type 分支、
        # 又不在 _STANDARD_TAINT_TYPES 白名单 → bandit/semgrep 带精确行号的
        # 证据被当作"无主告警"剔除，只剩 prefilter 无行号规则（typical_17 实锤：
        # B324 + semgrep md5 两条带行号证据全被剔除）。
        # 弱哈希/弱随机/硬编码 IV/弱密码算法
        # b311/pseudo-random（2026-08-30 审查补）：B311 消息 "Standard
        # pseudo-random generators are not cryptographically secure" 不含 weak
        # 词——typical_19 的精确 bandit 证据此前被剔除
        if ("md5" in text or "sha1" in text or "des(" in text or "rc4" in text
                or "weak" in text and "hash" in text or "b324" in text
                or "insecure-hash" in text or "hardcoded-iv" in text
                or "crypto" in text and "weak" in text or "random" in text and "weak" in text
                or "b311" in text or "pseudo-random" in text):
            return "Weak Cryptography"
        # 原型污染
        if ("__proto__" in text or "prototype" in text and "pollution" in text
                or "prototype_pollution" in text or "merge" in text and "proto" in text):
            return "Prototype Pollution"
        # 开放重定向
        if ("redirect" in text or "open_redirect" in text or "url_for" in text
                and "redirect" in text):
            return "Open Redirect"
        # 时序攻击
        if ("timing" in text or "constant-time" in text or "compare_digest" in text
                or "timing_unsafe" in text):
            return "Timing Attack"
        # 整数溢出
        if ("overflow" in text or "integer_overflow" in text or "wraparound" in text):
            return "Integer Overflow"
        # 日志注入
        if ("log_injection" in text or "logger" in text or "logging" in text
                and ("inject" in text or "newline" in text or "crlf" in text)):
            return "Log Injection"
        # 不安全 Cookie 配置（2026-08-31，NodeGoat 审计）：semgrep
        # express-cookie-settings 族 rule_id 特有片段（no-httponly/no-secure/
        # cookie-settings）——证据词专属性强，无撞词面。
        if ("no-httponly" in text or "no-secure" in text
                or "cookie-settings" in text or "cookie-flags" in text):
            return "Insecure Cookie"
        return tt

    def _counterfactual_pass(self, adjudications, code, language, filename) -> None:
        """对高置信判中的 finding 做反事实扰动验证（Layer 2）。

        触发条件（方案 1，防"工具误报+模型全票被带偏"）：
          - 低信任类别（sast/iac 位置型规则，无语境证据链）：判中即触发（防
            safe_08/safe_17 类——工具候选是误报、模型全票判中）。
          - 高信任类别（taint/prefilter，有 source→sink 证据链）：仅共形=uncertain
            时触发（报告二§四：共形筛不确定 → 反事实验证），高置信不重复验证。
        扰动后裁决翻转 → 模型理解防御（真阳性）；不变 → 模式匹配（标记存疑）。
        验证结果写回 adjudication.counterfactual，供聚合/回填决策使用。
        """
        for verdict in adjudications:
            f = verdict.finding or {}
            category = (f.get("category") or "")
            low_trust = category in _LOW_TRUST_CATEGORIES
            if not verdict.confirmed:
                continue
            if low_trust:
                # 低信任类别（sast/iac 位置型规则）：confirmed 即触发反事实验证
                # （不限置信度——低置信确认正是"模型没把握"最该验证的，safe_17 类
                # format-string T2/F1 全靠它拦截）
                pass
            elif verdict.confidence >= _CONF_AUTO and verdict.conformal_set == "uncertain":
                pass  # 高信任高置信 + 共形不确定：反事实验证
            else:
                continue  # 高信任且共形非不确定：不重复验证
            taint_type = self._infer_taint_type(f)
            sink_line = int(f.get("sink_line") or 0)
            if not taint_type or sink_line <= 0:
                continue
            # 2026-08-15 修复：改用 finding 级裁决 prompt（问"该 finding 是否成立"），
            # 原开放扫描 prompt 问"整文件有无漏洞"——多 finding 文件修掉一个还剩
            # 另一个 → 不翻转 → 真理解防御的裁决被误标"模式匹配"（方向保守但有偏）。
            # 行内替换不改变行号，扰动后仍可用同一 finding 构造 triage 上下文。
            from graduation_project.prompts import build_triage_prompt
            finding_obj = ToolFinding(
                rule_id=f.get("rule_id") or "cf", category=f.get("category") or "",
                source=f.get("source") or "", sink=f.get("sink") or "",
                taint_type=f.get("taint_type") or taint_type,
                source_line=int(f.get("source_line") or 0), sink_line=sink_line,
                path=list(f.get("path") or []), severity=f.get("severity") or "medium",
                tool=f.get("tool") or "", evidence=f.get("evidence") or "",
            )
            def _build_prompt(perturbed_code: str, language: str) -> str:
                ctx = self._with_line_numbers(perturbed_code, 1)
                return build_triage_prompt(finding_obj, ctx, language=language,
                                           aligned=self.triage_aligned)
            result = self._counterfactual.verify(
                code=code, language=language, taint_type=taint_type,
                sink_line=sink_line, build_prompt=_build_prompt,
                source_line=int(f.get("source_line") or 0),
            )
            if result.applicable:
                verdict.counterfactual = result.to_dict()

    def _evidence_gate_pass(self, adjudications, code: str, language: str) -> None:
        """确定性证据门（第 2.5 代补充层，2026-08-15）：零 LLM 成本的静态核验。

        背景（四维矩阵复盘）：transformers（bf16）端 FP 全部是"全票但错"——共形/
        反事实验证依赖的投票分歧信号在高精度后端上不出现（Q4 量化噪声天然压制
        模式匹配型捷径，bf16 保留了过度自信），统计门结构性失明。本门与后端无关：

          - sink_defended：sink 邻域（前 4 后 3 行）已含该漏洞类型的已知防御特征
            （复用 counterfactual._DEFENSE_SIGNATURES：参数化 execute / shlex.quote /
            html.escape / realpath / autoescape / json.loads）。模型没识别已有防御
            → 疑似模式匹配误报（noise_02 类：参数化正确的查询被泛规则命中后全票确认）。
          - no_input_entry：纯顶层字面量脚本且无外部输入入口（request/input/argv/
            environ）——2026-08-18 起不再把"函数定义"计入入口（08-15 已从正则删除，
            注释过期已修正），且与复核门③对齐：仅对**无任何函数/类定义的模块级
            脚本**应用本门（noise_03/06 类：字面量拼接被 B608 命中）。有函数/类接口
            的代码视参数为潜在外部输入（longfile_01 的 export_report(table) 由外部
            调用方传入），本门不拦——否则真漏洞被误降级 review。

        命中不否决（不判 False），仅把该 finding 排除出"直接判漏洞"依据，转人工
        复核——门是保守的：宁可 review 不错杀 TP（真漏洞的 sink 邻域不会出现
        完整防御特征，真污点文件必有输入入口）。
        """
        verifiable = (language or "").lower() in {"python", "py", "javascript", "js", "typescript", "ts"}
        if not code or not verifiable:
            return
        try:
            # 懒加载防循环导入（counterfactual 反向懒加载本模块的解析函数）
            from graduation_project.counterfactual import _DEFENSE_SIGNATURES
        except Exception:
            return
        lines = code.splitlines()
        has_entry = bool(_INPUT_ENTRY.search(code))
        # 2026-08-18：与复核门③（_recheck_type_plausible）对齐——仅对"无任何函数/
        # 类定义的纯顶层脚本"应用 no_input_entry。有函数/类接口的代码视函数参数为
        # 潜在外部输入（调用方可能传入外部数据），污点可能有源头，本门不拦。
        has_func_def = bool(_HAS_FUNCTION_DEF_RE.search(code))
        for verdict in adjudications:
            if not verdict.confirmed or verdict.evidence_gate:
                continue
            f = verdict.finding or {}
            sig = _DEFENSE_SIGNATURES.get(self._infer_taint_type(f))
            if sig is None:
                continue
            sink_line = int(f.get("sink_line") or 0)
            # 门 1：sink 邻域已含该类型防御特征 → 模型漏看已有防御
            if sink_line > 0:
                lo = max(0, sink_line - 1 - 4)
                hi = min(len(lines), sink_line - 1 + 4)
                if sig.search("\n".join(lines[lo:hi])):
                    verdict.evidence_gate = "sink_defended"
                    continue
            # 门 2：纯顶层字面量脚本且无外部输入入口 → 污点无从产生
            if not has_entry and not has_func_def:
                verdict.evidence_gate = "no_input_entry"

    # ------------------------------------------------------------------
    # Stage 1：工具召回（并行：semgrep taint / taint_tracker / prefilter / external）
    # ------------------------------------------------------------------
    def _stage1_recall(self, code: str, language: str, filename: str) -> list[ToolFinding]:
        """并行调用工具层召回候选 finding，合并去重 + 归一化。

        召回维度：
          - semgrep taint（整文件污点流） + TaintTracker（AST 轻量污点）→ 裁决档
          - Prefilter（正则高置信命中）→ 裁决档
          - 外部位置型工具（secret/sca/sast/iac）→ 按 _DIRECT_CATEGORIES 分档

        2026-08-15 修复：原实现四个召回块顺序执行（semgrep/external 各为
        subprocess，最坏情况 60s 超时逐个叠加），与"并行，近零成本"的文档
        口径不符。现改线程池并行——subprocess 型工具释放 GIL，真实批量扫描
        延迟从"求和"降为"取最大"。
        """
        from concurrent.futures import ThreadPoolExecutor

        # taint_tracker 惰性初始化在主线程先触发（AST 解析器加载非线程安全期）
        self._taint_tracker_enabled()

        def _semgrep():
            if self._external is not None and self.use_semgrep:
                return self._semgrep_recall(code, language, filename)
            return []

        def _taint():
            if self._taint_tracker_enabled():
                return self._taint_recall(code, language, filename)
            return []

        def _prefilter():
            if self._prefilter is not None:
                return self._prefilter_recall(code, language)
            return []

        def _external():
            if self._external is not None and self.use_external:
                return self._external_positional_recall(code, language, filename)
            return []

        findings: list[ToolFinding] = []
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(fn) for fn in (_semgrep, _taint, _prefilter, _external)]
            for fut in futures:
                try:
                    findings.extend(fut.result())
                except Exception as e:
                    print(f"[TwoStageScanner] 召回维度失败（已跳过）: {e}")
        findings = self._drop_irrelevant_positional(findings)
        return self._dedupe(self._apply_signal_registry(findings))

    # ------------------------------------------------------------------
    # 无主告警剔除（2026-08-17）：工具不会的就别让它瞎说
    # ------------------------------------------------------------------
    def _drop_irrelevant_positional(self, findings: list[ToolFinding]) -> list[ToolFinding]:
        """裁决前剔除无主告警：语义类型不在标准漏洞分类内的位置型规则。

        背景（2026-08-17 工具盲区实锤）：hard_cve_03 被 "request-data-write"、
        hard_owasp_01 被与文件上传无关的 format-string 告警命中——位置型规则
        （sast/iac）命中的常是**文件里真实存在但与主漏洞无关**的代码特征，其
        rule_id 是乱码级语义（如 request-data-write），不属于本项目裁决层可
        裁决的漏洞分类（SQL/Command/Code/XSS/SSTI/PathTraversal/反序列化）。
        triage prompt 的 taint_type 直接填这种乱码 → 模型无从裁决只会瞎投票，
        且无关告警会锁死裁决式 prompt 的注意力、掩盖真实漏洞。

        剔除策略（保守）：仅对位置型规则（sast/iac）按"语义类型白名单"过滤，
        直出档（secret/sca）、带证据链的 taint/prefilter 一律不动。被剔除的
        文件若因此落入无候选 → 强制复核（_last_suppressed=True 复用抑制语义，
        见 _maybe_recheck force 分支）→ 开放式全文件 LLM 分析兜底真实漏洞。

        B3 例外（2026-08-29）：secret 类 SAST 规则（B105/B106/B107/hardcoded-token
        等）不剔除，转 category="secret" 归入直出档——凭证类告警本来就没有
        source→sink 污点流，按"无主"剔除会浪费确定性证据；转档后与 gitleaks
        同通道直出（_direct_adjudication，不消耗 LLM 采样）。
        """
        dropped: list[str] = []
        re_routed: list[str] = []
        kept: list[ToolFinding] = []
        # 留痕容器按需补齐（2026-08-30）：本方法会在 __init__ 之外被直接调用——
        # 离线审计/回归脚本为跑纯 Stage 1 会用 __new__ 绕过构造（不接 LLM client），
        # 此时 _dropped_unowned_rules 尚未初始化 → 剔除命中即 AttributeError，
        # 整个文件的审计中断（audit_stage1.py 实锤）。留痕是**旁路记录**，不该
        # 有能力中断主流程——这与 B1 类"静默/崩溃源于接入方式"是同一类问题。
        if not hasattr(self, "_dropped_unowned_rules"):
            self._dropped_unowned_rules = []
        if not hasattr(self, "_last_suppressed_rules"):
            self._last_suppressed_rules = []
        for f in findings:
            if f.category == "secret":
                # 2026-08-31 统一门槛（§9.19 实锤）：凭证强度门槛此前只接了
                # sast 通道（B105 经 _is_secret_class_alert 转档时判定），
                # gitleaks/detect-secrets 的**原生 secret 候选完全绕过**——
                # detect-secrets 修复绝对路径缺陷后首次大量产出，其 Secret
                # Keyword 插件对测试惯用弱密码（admin123）直接告警 → 绕门槛
                # 直出（1:0，免 LLM）→ _aggregate top1 被 "Secret Keyword"
                # 抢占（typical_14/15/16/bypass_05/crossfile_03_sink 五段，
                # 08-30 时模型经无候选兜底独立归因出的主类型通道被关闭）。
                # 同一个凭证，bandit 看到要过门槛、detect-secrets 看到直接
                # 直出——门槛语义必须按"凭证内容强度"统一，不分工具：
                #   过门槛（真凭证形态）→ 保持 secret 直出（typical_06/
                #     hardcoded_secret_01 等，B3 直出增益保留）；
                #   不过（弱值/取不到字面值）→ 转裁决档（category→sast 与
                #     B105 弱值完全对称），类型规范化 Hardcoded Credentials，
                #     交模型裁决——evidence 现含命中行原文（runner 层增强），
                #     模型有判断材料。
                if _is_strong_credential(f.evidence or ""):
                    # 直出的真凭证同样规范化类型：裸工具 type 名（Secret Keyword）
                    # 进 top1 会成为无法归因的显示（与 B105 转档同语义，§9.19）
                    f.taint_type = "Hardcoded Credentials"
                    kept.append(f)
                    continue
                f.category = "sast"
                f.taint_type = "Hardcoded Credentials"
                re_routed.append(f.rule_id or "")
                kept.append(f)
                continue
            if f.category in ("sast", "iac"):
                claimed = self._infer_taint_type(f.to_dict())
                if claimed not in _STANDARD_TAINT_TYPES:
                    if self._is_secret_class_alert(f):
                        # 2026-08-29 门槛（用户实锤修正）：B3 把 secret 类 SAST 规则
                        # 转直出档，但 bandit B105 常命中的是框架必需配置
                        # （app.secret_key = "dev_key"）——10 个样本里 8 个被这种
                        # 弱值候选顶掉真实漏洞类型（IDOR/CSRF/SSTI），且直出不经过
                        # 模型、类型停在原始 "B105" 无法归因为 CWE-798。
                        # 现加凭证强度门槛（与 gitleaks 同语义：长度+熵）：
                        #   过门槛 → 直出档（真凭证，如 typical_06/hard_bypass_06）；
                        #   不过   → 转裁决档并给规范类型 "Hardcoded Credentials"，
                        #            由模型判断，不再顶掉主漏洞类型。
                        if _is_strong_credential(f.evidence or ""):
                            f.category = "secret"
                            f.taint_type = "Hardcoded Credentials"
                            re_routed.append(f.rule_id or claimed or "")
                            kept.append(f)
                            continue
                        # 弱值：转裁决档（保持 sast 分类），类型规范化为 CWE-798 可归
                        f.taint_type = "Hardcoded Credentials"
                        kept.append(f)
                        continue
                    # 非 secret 类的乱码语义照常剔除（2026-08-29 修复：此分支曾
                    # 在 B3 门槛改造中丢失，导致无主告警剔除整体失效）
                    dropped.append(f.rule_id or claimed or "")
                    continue
            kept.append(f)
        if re_routed:
            print(f"[TwoStageScanner] secret 类 SAST 规则转直出档 {len(re_routed)} 条"
                  f"（{sorted(set(re_routed))[:6]}）")
        if dropped:
            # 复用抑制语义：本文件发生"候选被剔除"，无候选分支必须强制复核，
            # 防止生产 sampled 模式下 90% 静默放行（与审查 #4 同机制）
            self._last_suppressed = True
            self._dropped_unowned_rules.extend(dropped)  # §五之四：stage1 留痕
            print(f"[TwoStageScanner] 剔除无主告警 {len(dropped)} 条"
                  f"（{sorted(set(dropped))[:6]}）→ 交 LLM 全文件复核兜底")
        return kept

    @staticmethod
    def _is_secret_class_alert(f: "ToolFinding") -> bool:
        """该位置型告警是否属 secret 类规则（B105/B106/B107/hardcoded-token 等）。"""
        return bool(
            _SECRET_SAST_RULE_RE.search(f.rule_id or "")
            or _SECRET_SAST_MSG_RE.search(f.evidence or "")
            or _SECRET_SAST_MSG_RE.search((f.taint_type or ""))
        )

    # ------------------------------------------------------------------
    # 复核采信的形态校验（2026-08-18）
    # ------------------------------------------------------------------
    def _recheck_type_plausible(self, code: str, language: str, vt_raw: str) -> tuple[bool, str]:
        """客观校验复核判真类型与代码形态是否匹配（无候选/兜底复核采信前调用）。

        设计原则（用户 2026-08-18 明令）：不得针对测试集拟合规则——白名单式的
        "某某类型可采信"已被废弃（内容受测试集结果反向影响）。本方法只用**公共
        安全知识**做确定性校验，对任何代码一视同仁：

        - 注入型漏洞（SQL/命令/代码/XSS/路径穿越/SSTI/反序列化——有标准 sink 和
          标准防御的）：复核判真必须满足
            ① 代码中存在该类型的标准 sink 特征（_RECHECK_SINK_RE）；
            ② sink 处没有该类型的标准防御（counterfactual._DEFENSE_SIGNATURES，
               复用确定性证据门同一张防御表——abspath 防路径穿越、参数化防 SQL、
               autoescape 防 SSTI、shlex.quote/列表参数防命令注入等）。
          任一不满足 → 判的类型与代码不符（如"判 XSS 但无渲染点"、"有 abspath
          防御仍判路径穿越"），转人工复核，不得采信。
        - 缺失型/其他漏洞（CSRF/认证缺失/弱密码/硬编码/竞态/XXE 等——无确定性
          验证手段的）：不做形态校验，全票采信。**如实标注**：这是"模型语义
          兜底"，不是工具保证；其可靠度由全票门（3/3）支撑。

        Args:
            code: 被复核的完整源码。
            language: 语言标签（仅做可校验性判定，规则本身与语言无关）。
            vt_raw: 模型复核输出的 vulnerability_type 原串。

        Returns:
            (plausible, reason)。plausible=True 表示可采信；False 时 reason 说明
            形态不匹配的具体原因（注入型且不满足 ①/②）。
        """
        _m = re.search(r"CWE[- ]?(\d+)", vt_raw or "")
        if not _m:
            return True, ""  # 无 CWE 编号：不做校验（评估侧另有类型纠正）
        vt_num = f"CWE-{_m.group(1)}"
        ttype = _RECHECK_CWE_TO_TYPE.get(vt_num)
        if ttype is None:
            # 缺失型/其他类型：无确定性校验手段，全票采信（模型语义兜底）
            return True, ""
        sink_re = _RECHECK_SINK_RE.get(ttype)
        if sink_re is None:
            return True, ""
        if not code or not code.strip():
            return False, "无代码内容"
        # ① 标准 sink 必须存在：本文件 sink 特征，或调用了导入的外部函数
        #（跨文件样本的 sink 在外部文件，如 hard_crossfile_02 的 safe_read_file
        #  定义在另一文件——本文件只有调用点。"调用导入函数"= 可能存在外部
        #  sink，是通用语义依据，非针对样本；仅定义 getter 不调用导入函数的
        #  代码（如 crossfile_01 判 XSS）无任何 sink 依据，照常拦截。）
        has_sink = bool(sink_re.search(code))
        if not has_sink:
            has_sink = _has_cross_file_call(code)
        if not has_sink:
            return False, f"代码中无 {ttype} 的标准 sink 特征"
        # ③ 无输入入口检查（2026-08-18）：**仅对无任何函数/类定义的纯顶层脚本**
        # 应用——顶层脚本无 request/input/env 输入且无函数参数接口时，注入型
        # 判真不可信（noise_03 字面量拼 SQL、noise_06 硬编码串跑 subprocess）。
        # 有函数/类定义的代码视为"存在数据流接口"（参数可能来自外部调用，
        # 如 longfile_01 的 export_report(table) 由外部传入、cve_05 的 Spring
        # 数据绑定），跳过本门——与确定性证据门 2 的"模块级字面量脚本"语义
        # 一致（证据门 2 同样只对无函数定义脚本判 no_input_entry）。
        if not _HAS_FUNCTION_DEF_RE.search(code) and not _INPUT_ENTRY.search(code):
            return False, "纯顶层字面量脚本且无外部输入入口，注入型判定无污点来源"
        # ② 标准防御检查（复用确定性证据门的防御签名表）。复核门判的是**文件级
        # 漏洞存在性**：只要存在**一个**无防御的该类型 sink，该类型漏洞就可能
        # 成立（longfile_01 有 15 处 execute，参数化行虽多但 L318 的拼接 query
        # 无防御 → 模型判真合理）；仅当**所有**该类型 sink 都带防御时，才是
        # "模型漏看已有防御"（误判，如 safe_01 唯一 execute 参数化）。
        # 防御检查限定在 sink 邻域（±8 行），全文件搜索会把长文件里其他函数
        # 的参数化误当"该 sink 已防御"。
        try:
            from graduation_project.counterfactual import _DEFENSE_SIGNATURES
            sig = _DEFENSE_SIGNATURES.get(ttype)
            if sig is not None:
                sink_lines = [i for i, ln in enumerate(code.split("\n")) if sink_re.search(ln)]
                lines = code.split("\n")
                undefended_exist = False
                all_defended = True
                for sl in sink_lines:
                    lo = max(0, sl - 8)
                    hi = min(len(lines), sl + 9)
                    if sig.search("\n".join(lines[lo:hi])):
                        continue  # 该 sink 有防御
                    undefended_exist = True
                    all_defended = False
                    break
                if all_defended and sink_lines:
                    return False, f"所有 {ttype} 的标准 sink 均已防御（模型漏看已有防御）"
        except Exception:
            pass
        return True, ""

    # ------------------------------------------------------------------
    # 信号注册表接线（2026-08-15：自适应闭环此前"只写不读"，本方法是读取端）
    # ------------------------------------------------------------------
    def _apply_signal_registry(self, findings: list[ToolFinding]) -> list[ToolFinding]:
        """用回填信号过滤与重排候选：抑制池跳过 + 高置信信号优先。

        - 抑制池（is_suppressed）：该规则被 ≥2 独立文件高置信否定过 → 工具
          "见到该特征直接跳过"。仅作用于裁决档（taint/prefilter/sast/iac）；
          直出档（secret/sca，确定性工具）不受模型意见影响。被跳过的候选
          计入 stage1 统计（suppressed_skipped），供召回监控。
        - 优先级（boost_priority）：已回填高置信信号的规则候选排前，优先获得
          裁决注意力（候选顺序影响 LLM 上下文组织）。
        """
        reg = self._signal_registry
        if reg is None or not findings:
            return findings
        # 留痕容器按需补齐（2026-08-30）：与 _drop_irrelevant_positional 同因——
        # 本方法可在 __init__ 之外被直接调用（离线审计脚本用 __new__ 绕过构造），
        # 缺字段会让"抑制留痕"反过来中断召回主流程。
        if not hasattr(self, "_last_suppressed_rules"):
            self._last_suppressed_rules = []
        kept: list[ToolFinding] = []
        skipped: list[str] = []
        for f in findings:
            if (f.category in _ADJUDICATE_CATEGORIES and f.rule_id
                    and reg.is_suppressed(f.rule_id)):
                skipped.append(f.rule_id)
                continue
            kept.append(f)
        if skipped:
            for _ in skipped:
                _monitor_incr("suppressed_skipped")
            self._last_suppressed_rules.extend(skipped)  # §五之四：stage1 留痕
            # 候选被抑制池跳过 → 本文件可能落入无候选：标记强制复核（08-16 审查 #4，
            # 2026-08-18 补回：抑制跳过后若不再产生候选，无候选分支须 force 复核）
            self._last_suppressed = True
        kept.sort(key=lambda f: -reg.boost_priority(f.rule_id or ""))
        return kept

    # ------------------------------------------------------------------
    # 无候选长文件分块预筛（P5 升级，2026-08-24）
    # ------------------------------------------------------------------
    # 通用安全词表（语言习语级，来源为公开漏洞知识而非任何测试样本；登记 P6 表：
    # 层=无候选分块预筛 / 触发=est_tokens > num_ctx*0.45 / 依据=弱点挖掘报告 第九、十节）。
    _PRESCREEN_SINK_RE = re.compile(
        r"(\.execute\(|\.executemany\(|\.query\(|\.queryrow\(|queryrow\(|"
        r"os\.system\(|subprocess\.|popen\(|runtime\.getruntime\(\)|processbuilder|"
        r"child_process|execcommand|\beval\(|new function\(|settimeout\(\s*['\"]|"
        r"unserialize\(|pickle\.loads\(|objectinputstream|readobject\(|"
        r"xmlparserfactory|documentbuilderfactory|saxparserfactory|"
        r"external-general-entities|xpath\.evaluate\(|xpathcompile\(|"
        r"sendredirect\(|redirect\(\s*[a-z_]|urlfetch|httpclient\.(get|post)|requests\.(get|post)|"
        r"\bmd5\b|\bsha1\b|\bdes\b|\becb\b|cipher\.getinstance|"
        r"open\(\s*[^)]*\+|readfile\(|file_get_contents|os\.open\(|ioutil\.readfile)", re.I)
    _PRESCREEN_SOURCE_RE = re.compile(
        r"(request\.|\bparams\b|\bargs\b\[|query_params|getparameter\(|headers\[|header\(|"
        r"\bbody\b|form\[|formdata|cookies?\[|argv|stdin|environ|os\.args|r\.url|"
        r"reader\.readline|scanner\.|bufferedreader|inputstream)", re.I)
    _PRESCREEN_ENTRY_RE = re.compile(
        r"(@app\.route|@router\.|@restcontroller|@requestmapping|@getmapping|@postmapping|"
        r"@api_view|@csrf_exempt|func\s+\w*handler|http\.responsewriter|app\.(get|post|use)\(|"
        r"router\.(get|post)\(|def (do_get|do_post)\(|public .*\(\s*(httpservletrequest|context))", re.I)

    def _prescreen_chunks(self, code: str, language: str):
        """长文件无候选复核前的确定性分块预筛。

        函数级切块 → 每块按通用词表打分（sink 命中×3 + 外部源×2 + 入口点×1，
        单模式计次封顶 5 防单行刷分）→ 取 top-k 块拼成复核上下文。
        纯确定性：同码必同选；全部零分时取前 k 块保底。失败返回 (None, None)
        回退整文件行为。返回 (切片文本列表, 可观测信息)。
        """
        info = {"engaged": True}
        try:
            sl = self._slicer.slice(code, language=language)
            chunks = [c for c in sl.chunks if not getattr(c, "is_full_file", False)]
        except Exception as e:
            info["fallback"] = f"slicer_error:{e}"
            return None, info
        if not chunks:
            # 无函数结构（顶层脚本/巨型函数）→ 固定行窗保底切分（150 行/窗），
            # 不回退整文件——那正是静默截断的老路
            lines_all = code.split("\n")
            win = 150

            class _Win:
                pass

            chunks = []
            for i in range(0, len(lines_all), win):
                w = _Win()
                w.name = f"window_L{i + 1}-{min(i + win, len(lines_all))}"
                w.start_line = i + 1
                w.end_line = min(i + win, len(lines_all))
                w.code = "\n".join(lines_all[i:w.end_line])
                chunks.append(w)
        scored = []
        for c in chunks:
            text = c.code
            n_sink = sum(min(len(p.findall(text)), 5) * w for p, w in
                         ((self._PRESCREEN_SINK_RE, 3),))
            n_src = sum(min(len(p.findall(text)), 5) * w for p, w in
                        ((self._PRESCREEN_SOURCE_RE, 2),))
            n_ent = sum(min(len(p.findall(text)), 5) * w for p, w in
                        ((self._PRESCREEN_ENTRY_RE, 1),))
            scored.append((n_sink + n_src + n_ent, c))
        # 正分块优先；全零时才按原顺序取前 k（保底）
        k = max(1, int(os.environ.get("VULN_SCANNER_PRESCREEN_TOPK", "3")))
        positive = [t for t in scored if t[0] > 0]
        pool = sorted(positive, key=lambda t: (-t[0], getattr(t[1], "start_line", 0))) \
            if positive else scored[:k]
        budget = int(self.num_ctx * 0.45)  # 复核输入 token 预算（≈2字符/token）
        parts, picked_info, used = [], [], 0
        for score, c in pool[:k]:
            body_lines = code.split("\n")[getattr(c, "start_line", 1) - 1:
                                          getattr(c, "end_line", 0)]
            body = "\n".join(body_lines)
            est = len(body) // 2
            if used + est > budget and parts:
                break
            used += est
            name = getattr(c, "name", "") or "chunk"
            parts.append(f"# ==== 预筛切片 {name}（L{c.start_line}-L{c.end_line}，"
                         f"信号分 {score}）====\n"
                         + self._with_line_numbers(body, c.start_line))
            picked_info.append({"chunk": name, "start": c.start_line,
                                "end": c.end_line, "score": score})
        if not parts:
            info["fallback"] = "empty_pick"
            return None, info
        info["picked"] = picked_info
        info["n_chunks_total"] = len(chunks)
        return parts, info

    def _maybe_recheck(self, code: str, language: str, force: bool = False,
                       count_monitor: bool = True, filename: str = "") -> Optional[dict]:
        """无候选文件的 LLM 复核：监控 Stage 1 召回漂移，或全量复核消除静默放行。

        - no_candidate_mode="sampled"：按 sampling_rate 抽样（默认 10%），用主扫描
          prompt 全量判一次，给出工具层漏报率的在线估计（tool_recall_monitor_snapshot）。
        - no_candidate_mode="full_recheck"：每个无候选文件都复核（采样率视为 1），
          供 URL/GitHub 等安全关键场景——"无候选"不再直接判安全，先问一次 LLM。
        - no_candidate_mode="targeted"（2026-08-31）：三档定向复核，按"文件风险分
          × 盲区命中"分配注意力，零盲区文件不送 LLM。大仓库替代 full_recheck。
        - force=True（审查 #4，2026-08-16）：本文件发生抑制跳过时强制复核。
        - count_monitor=False（裁决全否决兜底调用）：该场景文件有候选，不算
          "无候选"文件，no_candidate_total 是召回监控指标，不能被污染。

        Returns:
            {"sampled": True, "has_vulnerability": bool|None}；未抽样时返回 None。
            targeted 模式下 C 档返回 {"sampled": False, "tier": "C", ...}。
        """
        if count_monitor:
            _monitor_incr("no_candidate_total")
        if self.no_candidate_mode == "targeted" and not force:
            # 定向复核：三档。force 时不走此路（抑制跳过的文件必须真复核，
            # 否则 §五之四 的"静默放行"会以另一种形式复现）。
            return self._targeted_recheck(code, language, filename=filename)
        if force:
            sampled = True
        elif self.no_candidate_mode == "full_recheck":
            sampled = True
        elif self.sampling_rate <= 0 or random.random() >= self.sampling_rate:
            return None
        else:
            sampled = True
        _monitor_incr("recheck_sampled")
        # 全票门（2026-08-15）：复核改为 N=min(3, n_samples) 次采样投票。单次复核在
        # bf16 后端会把 safe_09 类正确授权检查误判为漏洞（四维矩阵 transformers FP
        # 根因之一）；投票后仅全票一致的"有漏洞"才具备被采信（trust_llm_recheck）
        # 的资格，多数但非全票 → 转人工复核。
        n = max(1, min(3, self.n_samples))
        # P5 升级（2026-08-24，rolling_dev 实测）：长文件无候选复核此前整文件进 LLM——
        # transformers 后端 OOM、ollama 静默截断后"自信判安全"（00071/00074 实锤，
        # 见 docs/弱点挖掘报告 第十节）。改为确定性分块预筛：函数级切块、通用安全
        # 词表打分（sink/外部源/入口点，语言习语级知识，无任何测试样本拟合），
        # 只复核 top-k 块；复核判真后的类型形态门仍用原文件全文校验。
        recheck_code, prescreen_info = code, None
        est_tokens = len(code) // 2 + code.count("\n")
        if est_tokens > self.num_ctx * 0.45:
            picked, prescreen_info = self._prescreen_chunks(code, language)
            if picked:
                recheck_code = "\n\n".join(picked)
                _monitor_incr("recheck_prescreened")
        votes_true = votes_false = votes_invalid = 0
        true_verdict: Optional[dict] = None  # 首个判真票的完整 verdict（类型/等级/说明）
        true_types: list = []  # P3 修复（2026-08-23）：收集全部判真票类型——此前只取首票，
                               # 多漏洞文件走复核通道时其余漏洞类型被静默丢弃
        try:
            # N 票统一经 _sample_votes 获取（2026-08-30）：vLLM 下单请求批量
            # 采样（服务端共享 prefill），其余后端逐条循环，语义一致。
            recheck_prompt = build_user_prompt(code=recheck_code, language=language)
            vote_results = self._sample_votes(
                recheck_prompt, n,
                # 2026-08-15 修复：不再硬编码 0.7 无视 self.temperature——
                # 多票采样需要足够温度打破同模态重复（取配置与 0.7 的较大值），
                # 单票直接用调用方配置（默认低温稳定）。
                temperature=(max(self.temperature, 0.7) if n > 1 else self.temperature),
            )
            for resp in vote_results:
                text = resp.get("text", "") if isinstance(resp, dict) else ""
                verdict = parse_verdict(text) if text else None
                hv_i = normalize_has_vulnerability(verdict.get("has_vulnerability")) if verdict else None
                if hv_i is True:
                    votes_true += 1
                    if verdict:
                        if true_verdict is None:
                            true_verdict = verdict
                        vt_i = (verdict.get("vulnerability_type") or "").strip()
                        if vt_i and vt_i.lower() not in ("none", "n/a", "unknown") \
                                and vt_i not in true_types:
                            true_types.append(vt_i)
                elif hv_i is False:
                    votes_false += 1
                else:
                    votes_invalid += 1
        except Exception as e:
            return {"sampled": True, "has_vulnerability": None, "error": str(e),
                    "votes_true": votes_true, "votes_false": votes_false,
                    "votes_invalid": votes_invalid, "n": n,
                    "prescreen": prescreen_info}
        if votes_true > votes_false:
            hv = True
        elif votes_false > votes_true:
            hv = False
        else:
            hv = None
        if hv is True:
            _monitor_incr("recheck_vuln_found")
        out = {"sampled": True, "has_vulnerability": hv,
               "votes_true": votes_true, "votes_false": votes_false,
               "votes_invalid": votes_invalid, "n": n}
        if prescreen_info:
            out["prescreen"] = prescreen_info  # 预筛可观测：选了哪些块、分数多少
        if true_types:
            out["types"] = true_types  # 全部判真票类型，供多漏洞聚合（P3）
        # 透传首个判真票的类型信息（2026-08-15 修复：此前 recheck 采信为漏洞
        # 但丢失 vulnerability_type/risk_level，11 个盲区样本 strict_recall 被
        # 工程缺陷吞掉——判定对了标号没了）
        if true_verdict:
            for k in ("vulnerability_type", "risk_level", "explanation", "fix_suggestion",
                      "source", "sink"):
                v = true_verdict.get(k) or ""
                if v and v.lower() not in ("none", "no fix needed", "n/a"):
                    out[k] = v
        return out

    # ------------------------------------------------------------------
    # 三档定向复核（2026-08-31，no_candidate_mode="targeted"）
    # ------------------------------------------------------------------
    def _targeted_recheck(self, code: str, language: str,
                          filename: str = "") -> dict:
        """按"文件风险分 × 盲区命中"给无候选文件分配 LLM 注意力。

        为什么需要它：full_recheck 对每个无候选文件都做**全文件 × min(3,n) 票**，
        成本随文件数线性爆炸，且大部分预算花在零风险文件（utils/dto/常量表）上。
        大仓库 50 文件 × 3 票 × 全文件上下文，是分钟到十分钟量级。

        三档（2026-08-31 修正，见下方 §为什么零盲区不等于不送）：
          A 档｜有盲区 且（风险分 ≥ TARGETED_HIGH_RISK_SCORE，或高优先级盲区 ≥ 2 条）
              → 盲区片段 × min(3, n_samples) 票（与 full_recheck 同置信级别）
          B 档｜有盲区但低危；**或零盲区但高风险分**
              → 片段 × 1 票。单票判真**不具采信资格**（由 scan_code 的
                tier=="B" 判断拦下转 review）——"一票通过"是没人反对，不是三票
                一致，而无工具证据的采信必须是最高置信级别。
          C 档｜零盲区 且 低风险分
              → 不送 LLM，返回 tier="C" 由上层显式留痕"未获得复核预算"；
                但仍按 sampling_rate 抽样（默认 10%），抽样命中降级为 B 档。

        § 为什么"零盲区"不能直接等于"不送 LLM"（自检实证）：
          盲区规则覆盖的是**工具写不了规则**的形态（越权、过滤可绕过性…），
          而 SQL 注入/命令注入/路径穿越/XSS 这类**工具本该召回**的形态并不在
          盲区表里。若一律按"零盲区→跳过"处理，一旦工具因规则不覆盖、语言不
          支持、新框架而零召回，这些漏洞就被静默放行——正是本项目一贯要消除
          的静默性。故加两道保险：
            1) 风险分高（有外部源+sink+入口点 = 有实际攻击面）却零召回，是
               **工具失效的信号**，比"文件没内容"更值得复核 → 降 B 档；
            2) C 档按 sampling_rate 抽样复核，在线估计"零盲区文件的漏报率"
               （复用 sampled 模式原有的监控语义，非新增机制）。

        省时的两个来源（可分别关掉做消融）：
          1. C 档省掉整次调用（大仓库的主要收益）；
          2. A/B 档把"整文件"换成"盲区片段"（自检实测 5575→285 字符，5.1%），
             模型从"读 1000 行找漏洞"变成"看几个带行号的 13 行片段判漏洞"。
        """
        report = self._last_blind_spots
        if report is None:
            # 兜底：盲区扫描被关闭或失败时临时算一次（保证档位判定始终有依据）
            try:
                report = scan_blind_spots(code)
            except Exception:
                report = None

        risk = score_file(filename or "", language, code)
        n_spots = report.count if report else 0

        # ---- 档位判定 ----
        if n_spots > 0:
            if (risk.score >= self.TARGETED_HIGH_RISK_SCORE
                    or report.high_priority_count >= self.TARGETED_HIGH_SPOTS):
                tier, why = "A", "high_risk_or_high_spots"
            else:
                tier, why = "B", "low_risk_with_spots"
        elif risk.score >= self.TARGETED_HIGH_RISK_SCORE:
            tier, why = "B", "zero_spot_but_high_risk"   # 保险 1：工具失效信号
        else:
            tier, why = "C", "zero_spot_low_risk"

        # ---- 保险 2：C 档抽样（在线监控零盲区文件的漏报率）----
        if tier == "C" and self.sampling_rate > 0 and random.random() < self.sampling_rate:
            tier, why = "B", "c_tier_sampled"

        if tier == "C":
            _monitor_incr("recheck_tier_c")
            return {"sampled": False, "tier": "C", "has_vulnerability": None,
                    "reason": why, "risk_score": round(risk.score, 2)}

        n = max(1, min(3, self.n_samples)) if tier == "A" else 1
        _monitor_incr("recheck_tier_a" if tier == "A" else "recheck_tier_b")
        _monitor_incr("recheck_sampled")

        # ---- 复核上下文：有盲区用盲区片段，零盲区用预筛块/整文件 ----
        prescreen_info = None
        if n_spots > 0:
            # 盲区片段替代整文件；构建失败回退整文件——宁可慢也不能静默看不全
            # （00071/00074：ollama 静默截断后"自信判安全"的教训）。
            ctx = build_review_context(code, report, window=6)
            recheck_code = ctx if ctx else code
        else:
            # 零盲区无定位信息：退化为整文件；超长时走已有的确定性分块预筛
            ctx = None
            recheck_code = code
            est_tokens = len(code) // 2 + code.count("\n")
            if est_tokens > self.num_ctx * 0.45:
                picked, prescreen_info = self._prescreen_chunks(code, language)
                if picked:
                    recheck_code = "\n\n".join(picked)
                    _monitor_incr("recheck_prescreened")

        votes_true = votes_false = votes_invalid = 0
        true_verdict: Optional[dict] = None
        true_types: list = []
        try:
            prompt = build_user_prompt(code=recheck_code, language=language)
            vote_results = self._sample_votes(
                prompt, n,
                temperature=(max(self.temperature, 0.7) if n > 1 else self.temperature),
            )
            for resp in vote_results:
                text = resp.get("text", "") if isinstance(resp, dict) else ""
                verdict = parse_verdict(text) if text else None
                hv_i = (normalize_has_vulnerability(verdict.get("has_vulnerability"))
                        if verdict else None)
                if hv_i is True:
                    votes_true += 1
                    if verdict:
                        if true_verdict is None:
                            true_verdict = verdict
                        vt_i = (verdict.get("vulnerability_type") or "").strip()
                        if (vt_i and vt_i.lower() not in ("none", "n/a", "unknown")
                                and vt_i not in true_types):
                            true_types.append(vt_i)
                elif hv_i is False:
                    votes_false += 1
                else:
                    votes_invalid += 1
        except Exception as e:
            return {"sampled": True, "tier": tier, "has_vulnerability": None,
                    "error": str(e), "votes_true": votes_true,
                    "votes_false": votes_false, "votes_invalid": votes_invalid,
                    "n": n, "risk_score": round(risk.score, 2), "reason": why}

        if votes_true > votes_false:
            hv = True
        elif votes_false > votes_true:
            hv = False
        else:
            hv = None
        if hv is True:
            _monitor_incr("recheck_vuln_found")
        out = {
            "sampled": True, "tier": tier, "reason": why,
            "targeted_context": ctx is not None,   # 是否用了盲区片段（False=整文件回退）
            "has_vulnerability": hv,
            "votes_true": votes_true, "votes_false": votes_false,
            "votes_invalid": votes_invalid, "n": n,
            "risk_score": round(risk.score, 2),
            "blind_spot_count": report.count if report else 0,
        }
        if prescreen_info:
            out["prescreen"] = prescreen_info
        if true_types:
            out["types"] = true_types
        if true_verdict:
            for k in ("vulnerability_type", "risk_level", "explanation",
                      "fix_suggestion", "source", "sink"):
                v = true_verdict.get(k) or ""
                if v and v.lower() not in ("none", "no fix needed", "n/a"):
                    out[k] = v
        return out

    def _effective_keep_alive(self):
        """裁决/复核的模型驻留策略：keep_alive=0（每次卸载）在 N 次采样下会
        反复重载模型，延迟巨大；采样突发期内保持驻留（300s 后自动释放）。"""
        return 300 if self.keep_alive in (0, None) else self.keep_alive

    @property
    def model(self):
        """当前推理模型名（透传 client，供 CLI/上层打印与展示）。"""
        for attr in ("model", "model_id"):
            val = getattr(self.client, attr, None)
            if val:
                return val
        return ""

    def unload(self) -> None:
        """卸载模型释放显存（透传 client；无此能力的后端静默跳过）。"""
        fn = getattr(self.client, "unload_model", None)
        if callable(fn):
            try:
                fn()
            except Exception as e:
                print(f"[TwoStageScanner] 模型卸载失败: {e}")

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
            evidence = item.get("evidence", "")
            # P0.3/P0.4：给裁决层附加 sink/source 行上下文证据，使 LLM 能判断
            # source 是否真用户可控（常量拼接）、sink 参数是否数值插值（int/float）。
            # semgrep OSS taint JSON 不含 source/sink 元数据，行号=start 行=sink 行，
            # 只能取 sink 行附近的真实代码供裁决参考；TaintTracker 路径已精确，
            # 不需要此上下文。
            ctx = self._line_context(code, int(item.get("sink_line", 0) or 0))
            if ctx and item.get("tool") == "semgrep":
                evidence = (evidence + "\n[sink 行上下文]\n" + ctx).strip()
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
                evidence=evidence,
            ))
        return findings

    @staticmethod
    def _line_context(code: str, line: int, radius: int = 3) -> str:
        """提取指定行前后 radius 行的代码文本（1-indexed），供裁决层判断 source 有效性。

        用于 semgrep 这类只报 sink 行的工具：把 sink 行附近的真实代码（含可能
        的常量赋值/数值转换/转义调用）交给 LLM，结合 build_triage_prompt 的判定
        要求（source 有效性 / 数值插值），消解工具规则无语境匹配造成的误报。
        """
        if line <= 0 or not code:
            return ""
        lines = code.splitlines()
        if line > len(lines):
            return ""
        lo = max(0, line - 1 - radius)
        hi = min(len(lines), line + radius)
        # enumerate(start=lo+1) 时 i 已是 lines[lo] 的正确 1-based 行号
        # （lines[lo] 是文件第 lo+1 行），标签不得再加 1——此前 f"{i+1}:..." 把
        # 全部标签 +1 错位（typical_01 实锤：L9 的 request.args.get 被标成 10），
        # 与 TaintTracker 等行号正确的候选在同一 prompt 内互相矛盾。
        return "\n".join(f"{i}:{t}" for i, t in enumerate(lines[lo:hi], start=lo + 1))

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
        # 命中行号（2026-08-29）：prefilter 现在产出 matched_lines，与 matched_rules
        # 一一对应。此前恒为 0 → 裁决档候选无位置，模型须自行全文重新定位
        #（用户实测 14 条无位置候选）。定位不到时 prefilter 记 0，此处同步回落 0。
        hit_lines = list(getattr(result, "matched_lines", None) or [])
        findings: list[ToolFinding] = []
        for idx, rule_name in enumerate(result.matched_rules):
            if rule_name == "hardcoded_secret_marker":
                continue  # 标记仅抑制安全判定，不直接作为漏洞候选
            if vuln_rule_names and rule_name not in vuln_rule_names:
                continue  # 安全规则/标记不产生候选
            ln = int(hit_lines[idx]) if idx < len(hit_lines) else 0
            findings.append(ToolFinding(
                rule_id=rule_name,
                category="prefilter",
                source="",
                sink="",
                taint_type=_PREFILTER_TYPE.get(rule_name, "Detected"),
                source_line=ln,
                sink_line=ln,
                path=[],
                severity=_PREFILTER_SEVERITY.get(rule_name, "medium"),
                tool="prefilter",
                evidence=f"Prefilter 命中漏洞特征规则: {rule_name}",
            ))
        return findings

    def _external_positional_recall(
        self, code: str, language: str, filename: str,
    ) -> list[ToolFinding]:
        """外部位置型工具召回（secret/sca/sast/iac），作为污点/正则召回之外的补充维度。

        与 taint 型召回（source→sink 证据链）不同，这些工具的产出是"文件+行+规则"
        的位置型发现（ExternalFinding 无 source/sink）。按类别映射到 ToolFinding，
        空证据候选由 _dedupe 的 rule_id 键分支处理，不与其他 finding 误合并。

        分档：
          - secret（gitleaks/detect-secrets）、sca（trivy fs/pip-audit）→ 直出档
            （_DIRECT_CATEGORIES）：确定性工具自判即可，裁决层不消耗 LLM
          - sast（bandit + semgrep 普通规则）、iac（trivy config）→ 裁决档：
            误报率高、真伪难辨，进 LLM 裁决（与 taint 候选同规则）
        """
        findings: list[ToolFinding] = []
        suffix = Path(filename).suffix.lower() or (".py" if language == "python" else ".txt")
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=suffix, delete=False, encoding="utf-8"
            ) as tmp:
                tmp.write(code)
                tmp_path = tmp.name
            # 按文件类型分流（2026-08-29 修正 secret 档）：
            #   secret：gitleaks --no-git 对单文件同样有效（实测命中
            #           hard_bypass_06 的 SECRET_API_TOKEN，line 8，generic-api-key）。
            #           此前注释断言"无 .git 时对单文件几乎不命中"已被证伪，且该断言
            #           导致代码文件（.py/.js/.java）被完全排除在 secret 扫描之外——
            #           而硬编码凭证恰恰绝大多数写在代码文件里（typical_06 /
            #           hard_bypass_06 / typical_18 全部零召回即此因）。
            #           现对**所有文件**启用 secret 档；gitleaks 单次 ~70ms，成本可忽略。
            #   sca：   trivy fs 只在依赖清单（requirements.txt 等）上有意义 → 仅非代码文件
            #   iac：   trivy config 只对 terraform/k8s/dockerfile 生效 → 仅非代码文件
            # trivy config 联网卡 60s 超时（已修 --skip-policy-update，双保险）
            code_file_exts = {".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".java", ".php",
                              ".c", ".h", ".cpp", ".cc", ".go", ".rb", ".rs", ".cs"}
            groups: dict[str, list] = {
                "sast": self._external.scan_sast(tmp_path, language),
                "secret": self._external.scan_secrets(tmp_path),
            }
            if suffix not in code_file_exts:
                groups["sca"] = self._external.scan_sca(tmp_path)
                groups["iac"] = self._external.scan_iac(tmp_path)
        except Exception as e:
            print(f"[TwoStageScanner] 外部位置型工具召回失败: {e}")
            return []
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            # P2-9 执行状态留痕（2026-08-31）：工具超时/未找到/解析失败此前与
            # "无命中"在结果上不可区分（B1 静默性同构）。旁路记录，异常不中断。
            try:
                self._last_tool_status = dict(getattr(self._external, "last_status", {}))
            except Exception:
                self._last_tool_status = {}

        for category, items in groups.items():
            for item in items:
                sev = (item.severity or "medium").lower()
                if sev not in _SEV_RANK:
                    sev = "medium"
                evidence = item.message or item.rule_id
                # P0.3：sast/iac 属裁决档且规则无语境匹配（bandit B608 等），
                # 附加报告行附近的代码上下文，供 LLM 判断 source 是否真用户可控。
                if category in ("sast", "iac"):
                    ctx = self._line_context(code, int(item.line or 0))
                    if ctx:
                        evidence = (evidence + "\n" + _EVIDENCE_CTX_MARK + "\n" + ctx).strip()
                findings.append(ToolFinding(
                    rule_id=item.rule_id or f"{item.tool}:unknown",
                    category=category,
                    source="",     # 位置型 finding：无 source/sink，留空由裁决层判定
                    sink="",
                    taint_type=item.rule_id or item.tool,  # 展示用（裁决档 LLM 关注 rule_id/evidence）
                    source_line=int(item.line or 0),
                    sink_line=int(item.line or 0),
                    path=[],
                    severity=sev,
                    tool=item.tool,
                    evidence=evidence,
                ))
        return findings

    @staticmethod
    def _dedupe(findings: list[ToolFinding]) -> list[ToolFinding]:
        """按 (taint_type, normalized_source, normalized_sink) 去重。

        Semgrep 与 TaintTracker 命中同一流时保留一条，工具标注按实际集合合并。
        source/sink 皆空的候选（如 prefilter 规则命中）无法按流去重，
        去重键纳入 rule_id——否则同 taint_type 的多条规则会被误合并成一条，
        丢失规则与证据。

        §三 候选合并（2026-08-29，工具层优化指导）：冗余候选的裁决成本是
        N=3 次/条，同族候选被 1/2 票否决还会制造复核噪声。在此前 (类型, sink 行)
        索引之上补两级归并：
          1. 语义族索引 (family, sink_line)——family 由 _infer_taint_type 从
             rule_id/evidence 推断（B608+SQL 拼接 evidence → "SQL Injection"），
             让 sast 规则号候选与 taint 候选在"同行同族"时归并；
          2. 直出档同位置合并 (secret, sink_line)——bandit B105 与 gitleaks 对
             同一硬编码凭证的告警合并为一条，携带 "bandit+gitleaks" 双工具标记；
          3. 无行号候选（prefilter，source/sink/行号全空）归并到同族唯一候选——
             仅当该族恰好只有一条已见候选（无歧义）时归并，多条并存时保留。
        """
        def _norm(s: str) -> str:
            return re.sub(r"\s+", "", s or "").lower()

        seen: dict[tuple, ToolFinding] = {}
        # 辅助索引：(taint_type, sink_line) → 已见 key。
        # semgrep OSS 的 taint JSON 不含 metavars（source/sink 为空、行号=sink 行），
        # 与 TaintTracker 同流 finding 的主键永不相等；此索引让"空证据 + 同 sink 行
        # + 同类型"的候选能合并到已有 finding 上，避免同一流被裁决两次
        by_sink_line: dict[tuple, tuple] = {}
        # 2026-08-31：有证据候选的二级索引 (类型, source, sink 行) → key。
        # TaintTracker 对同一调用会产出 sink 文本不同的两条（dvna L39 实测：
        # 'cp:exec' 与 'exec('，source 同为 req.body、行同为 39），主键
        # (类型, source, sink) 因 sink 文本差异永不相等，导致同一流进裁决两次。
        by_src_line: dict[tuple, tuple] = {}
        # §三：语义族索引与族内 key 集合（无行号候选的歧义判定用）
        by_family_line: dict[tuple, tuple] = {}
        family_keys: dict[str, set] = {}
        # §三：直出档同位置合并索引（category, sink_line）→ key
        by_direct_line: dict[tuple, tuple] = {}

        # 两遍处理（顺序无关）：先收有证据的 finding 并建索引，再收空证据候选——
        # Stage 1 的召回顺序是 semgrep 在前，单遍处理会让空证据候选抢先进 seen，
        # 导致同流的 taint_tracker finding 无法归并
        def _has_evidence(f: ToolFinding) -> bool:
            return bool(_norm(f.source) or _norm(f.sink))

        # 类型写回（2026-08-31，工具层优化指导 §9.8）：把工具内部标识统一成
        # 语义名。候选的 taint_type 常是工具内部标识——bandit 的 B608/B324、
        # semgrep 的**规则文件路径**；而 _infer_taint_type 能从 rule_id/evidence
        # 推断出语义名（B608+SQL 拼接 → "SQL Injection"）。此前推断结果**只用于
        # 归并分组、从不写回字段**，导致：
        #   ① 进裁决的候选带着 `B608` 这种标识，模型只能靠 evidence 自己理解，
        #      裁决输入质量受损（同一份信息，语义名比规则号直白得多）；
        #   ② 审计/监控看到的类型与生产归并实际依据的类型不一致（测量偏差）。
        # 写回后 _infer_taint_type 是**幂等**的（已是语义名时原样返回），
        # 故不影响归并键的稳定性。
        # 注意：仅当推断成功且与原值不同才覆盖，推断不出时保留原值——
        # 宁可让裁决层看到规则号，也不能把有信息的类型抹成空。
        for f in findings:
            try:
                inferred = TwoStageScanner._infer_taint_type(f.to_dict())
            except Exception:
                inferred = ""
            if inferred and inferred != f.taint_type:
                f.taint_type = inferred

        def _family(f: ToolFinding) -> str:
            """语义族键：语义类型名本身；规则号/长路径经 _infer_taint_type 推断。"""
            inferred = TwoStageScanner._infer_taint_type(f.to_dict())
            return (inferred or f.taint_type or "").strip().lower()

        # 第三遍级序：有证据 → 空证据有行号 → 空证据无行号（最抽象的最后归并）
        with_line_no_ev = [f for f in findings
                           if not _has_evidence(f) and f.sink_line]
        no_line = [f for f in findings
                   if not _has_evidence(f) and not f.sink_line]
        ordered = ([f for f in findings if _has_evidence(f)]
                   + with_line_no_ev + no_line)
        for f in ordered:
            norm_src, norm_sink = _norm(f.source), _norm(f.sink)
            key = (f.taint_type or "").lower(), norm_src, norm_sink
            family = _family(f)
            # 二级归并（2026-08-31）：有证据候选在主键未命中时，按
            # (类型, source, sink 行) 归并——仅 sink 文本描述不同属同一流。
            # 三条件（类型+source+行）比主键只放宽 sink 文本一项，不会把
            # 同行的不同 sink 调用（exec(a); exec(b)）误并——那种情况 source
            # 不同（不同实参变量），此处要求 source 归一化后完全相同。
            if (key not in seen and (norm_src or norm_sink) and f.sink_line):
                alt = by_src_line.get(
                    ((f.taint_type or "").lower(), norm_src, f.sink_line))
                if alt is not None:
                    key = alt
            if not norm_src and not norm_sink:
                # 空证据候选：依次尝试 (类型, sink 行) / (语义族, sink 行) /
                # 直出档 (category, sink 行) 归并到已有 finding
                line_key = ((f.taint_type or "").lower(), f.sink_line)
                fam_line_key = (family, f.sink_line)
                direct_key = (f.category, f.sink_line)
                if f.sink_line and line_key in by_sink_line:
                    key = by_sink_line[line_key]
                elif f.sink_line and fam_line_key in by_family_line:
                    key = by_family_line[fam_line_key]
                elif (f.sink_line and f.category in _DIRECT_CATEGORIES
                        and direct_key in by_direct_line):
                    key = by_direct_line[direct_key]
                elif not f.sink_line:
                    # 无行号（prefilter 形态）：仅当同族恰好一条已见候选（无歧义）时归并
                    fam_keys = family_keys.get(family, set())
                    if len(fam_keys) == 1:
                        key = next(iter(fam_keys))
                    else:
                        key = key + (f.rule_id,)  # 无法归并则按规则区分，不误合并
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
                # §三：多工具证据合并（不同工具对同一流的描述互补，裁决层可参考）
                if f.evidence and f.evidence not in existing.evidence:
                    existing.evidence = (
                        f"{existing.evidence}\n[{f.tool}] {f.evidence}"
                        if existing.evidence else f.evidence)
            else:
                seen[key] = f
                # 有证据的 finding 注册 sink 行索引，供后续空证据候选归并
                if (norm_src or norm_sink) and f.sink_line:
                    by_sink_line[((f.taint_type or "").lower(), f.sink_line)] = key
                    # setdefault：归到首个（有证据候选先处理，证据最完整）
                    by_src_line.setdefault(
                        ((f.taint_type or "").lower(), norm_src, f.sink_line), key)
                # §三：语义族/直出档索引对所有已见候选登记（含空证据有行号者）
                if f.sink_line:
                    by_family_line.setdefault((family, f.sink_line), key)
                    if f.category in _DIRECT_CATEGORIES:
                        by_direct_line.setdefault((f.category, f.sink_line), key)
                family_keys.setdefault(family, set()).add(key)
        return list(seen.values())

    @staticmethod
    def _stage1_stats(findings: list[ToolFinding]) -> dict:
        """统计各工具召回数量（合并项按工具集合拆分计数）。"""
        counts = {
            "semgrep": 0, "taint_tracker": 0, "prefilter": 0,
            "bandit": 0, "semgrep_rules": 0, "gitleaks": 0,
            "detect-secrets": 0, "trivy": 0, "pip-audit": 0,
        }
        merged = 0
        direct = 0
        for f in findings:
            tools = f.tool.split("+")
            if len(tools) > 1:
                merged += 1
            for t in tools:
                if t in counts:
                    counts[t] += 1
            if f.category in _DIRECT_CATEGORIES:
                direct += 1
        return {
            "total_candidates": len(findings),
            "by_tool": counts,
            "merged_cross_tool": merged,
            "direct_findings": direct,  # secret/sca 直出（不裁决）数量
        }

    @staticmethod
    def _is_direct_category(category: str) -> bool:
        """该类别 finding 是否走直出（不裁决）：secret/sca 确定性工具自判即可。"""
        return (category or "") in _DIRECT_CATEGORIES

    # ------------------------------------------------------------------
    # Stage 2：LLM 裁决（自一致率）
    # ------------------------------------------------------------------
    def _adjudicate_all(self, findings, code, language, filename, rag_context):
        """对每个候选 finding 做 N 次采样裁决，返回 (adjudications, reviewer)。

        直出档 finding（secret/sca，确定性工具自判）不消耗 LLM 采样：
        直接生成 confirmed=True 的直出裁决；裁决档（taint/prefilter/sast/iac）
        照常走 N 采样自一致率裁决。
        """
        adjudications: list[AdjudicationVerdict] = []
        reviewer: list[dict] = []
        # 盲区提醒注入（2026-08-31）：有候选时把行级盲区提醒附在裁决上下文，
        # **零额外 LLM 调用**——复用本就存在的裁决采样。
        # 只注入第一个裁决档候选：盲区提醒是"文件级"信息，对每个候选重复注入
        # 会产生 N(采样) × M(候选) 倍的冗余 prefill，而信息量完全相同。
        blind_text = ""
        if self.use_blind_spots and self._last_blind_spots:
            blind_text = render_for_prompt(self._last_blind_spots)
        blind_injected = False
        for finding in findings:
            if self._is_direct_category(finding.category):
                verdict = self._direct_adjudication(finding)
            else:
                code_context = self._slice_context(code, language, finding)
                if blind_text and not blind_injected:
                    code_context = code_context + "\n\n" + blind_text
                    blind_injected = True
                verdict = self._adjudicate_one(finding, code_context, language, filename, rag_context)
            # 关联回源 finding（含 taint_type/severity），供前端逐条展示投票与置信度
            verdict.finding = finding.to_dict()
            # 证据链回填（2026-08-29）：位置型候选（B501/B310 等）无 source/sink 文本，
            # 用判真票锚点补齐，供 _aggregate 透出到顶层（前端证据链卡片依赖）。
            # 必须**同时同步行号**——否则会出现"文本写 line 9、行号徽标标 L10"
            # 的自相矛盾（typical_20 实拍：B501 的 source 文本 line 9 却标 L10）。
            if verdict.confirmed and (verdict.src_anchor or verdict.sink_anchor):
                _fd = verdict.finding
                if verdict.src_anchor and not (_fd.get("source") or "").strip():
                    _fd["source"] = verdict.src_anchor
                    _ln = _anchor_line(verdict.src_anchor, code)
                    if _ln:
                        _fd["source_line"] = _ln
                if verdict.sink_anchor and not (_fd.get("sink") or "").strip():
                    _fd["sink"] = verdict.sink_anchor
                    _ln = _anchor_line(verdict.sink_anchor, code)
                    if _ln:
                        _fd["sink_line"] = _ln
            # 先定档位再 to_dict，保证 verdict_dict 携带 decision
            if self._is_direct_category(finding.category):
                verdict.decision = "direct"  # 直出档：确定性工具自判，无 LLM 采样
            elif verdict.confirmed:
                if verdict.confidence >= _CONF_AUTO:
                    verdict.decision = "confirmed_vulnerability"
                else:
                    verdict.decision = "confirmed_review"
            else:
                if verdict.confidence >= _CONF_AUTO:
                    verdict.decision = "dismissed_safe"
                else:
                    verdict.decision = "dismissed_review"
            verdict_dict = verdict.to_dict()
            if verdict.decision in ("confirmed_review", "dismissed_review"):
                reviewer.append(verdict_dict)
            adjudications.append(verdict)
        return adjudications, reviewer

    @staticmethod
    def _direct_adjudication(finding: ToolFinding) -> AdjudicationVerdict:
        """直出档 finding 的免 LLM 裁决（secret/sca 确定性工具自判）。

        返回 confirmed=True（投票 1/1、置信度 1.0，等价于高置信确认），
        但用 decision 显式标注 direct 语义，避免与 LLM 裁决混淆。
        """
        return AdjudicationVerdict(
            confirmed=True,
            confidence=1.0,
            votes_true=1,
            votes_false=0,
            votes_invalid=0,
            reasoning=f"确定性工具直出（{finding.tool}）：{finding.evidence}",
            fix_suggestion="",
            raw_outputs=[],
        )

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
            # 调用点证据链（2026-08-17 修复）：长文件切片只含目标函数体，被切掉的
            # 调用方是"函数参数是否用户可控"的关键证据——如 B608 命中
            # StatsService.export_report(table) 的拼接 SQL，但调用方在另一函数，
            # 模型无法确认 table 来自外部输入 → 1/2 判假（hard_longfile_01 FN 根因）。
            # 本函数级切片（函数名可见于切片头）裁剪出对 target 函数的调用行。
            call_lines = self._find_call_lines(orig_lines, c, language, code)
            if call_lines:
                parts.append("# ---- 该函数的外部调用点（函数参数来源证据，关键于判定是否用户可控） ----")
                parts.append(self._with_line_numbers("\n".join(call_lines), 1))
        return "\n\n".join(parts)

    @staticmethod
    def _find_call_lines(orig_lines: list[str], chunk, language: str, code: str) -> list[str]:
        """收集对切片目标函数的显式调用行（无命名上下文时返回空）。"""
        name = getattr(chunk, "name", None)
        if not name or getattr(chunk, "is_full_file", False):
            return []  # 整文件已在上下文中，无需补调用点
        target_name = name.split(".")[-1]
        # 定义行识别（2026-08-18 补 Java）：`def/class 名(`（Python）或
        # 修饰符开头的方法声明 `public/private/static ... 名(`（Java）。排除
        # "定义行"不被误当调用点——此前 Java 方法声明行会被收集进调用点证据。
        def _is_def_line(ln: str) -> bool:
            return re.match(
                r"(?:\s*(?:def|class)\s+"
                r"|\s*(?:(?:public|private|protected|static|final|abstract|synchronized)\s+)+"
                r"[\w<>,.\[\]\s]*\s)"
                + re.escape(target_name) + r"\s*\(",
                ln,
            ) is not None
        # 排除目标函数自身的定义行，避免把 def 行误当调用
        body_lines = orig_lines[chunk.start_line - 1:chunk.end_line]
        body_def = next(
            (ln for ln in body_lines if _is_def_line(ln)),
            None,
        )
        calls: list[str] = []
        seen: set[str] = set()
        for i, raw in enumerate(orig_lines):
            ln = raw.strip()
            if not ln or ln.startswith("#") or ln.startswith("//"):
                continue
            # 精确匹配调用点：`target_name(`（可带对象/self/类前缀），
            # 且不是 def/class/方法声明定义行、不是 target_name 自身的函数体行
            if not re.search(r"\b" + re.escape(target_name) + r"\s*\(", ln):
                continue
            if _is_def_line(ln):
                continue
            if body_def is not None and re.search(
                    r"\b" + re.escape(target_name) + r"\s*\(", ln) and \
                    chunk.start_line - 1 <= i < chunk.end_line:
                continue  # 目标函数体内部的行（含递归/其他调用）
            if ln in seen:
                continue
            seen.add(ln)
            calls.append(f"L{i + 1}: {ln}")
            if len(calls) >= 6:
                break
        return calls

    @staticmethod
    def _with_line_numbers(code: str, start_line: int) -> str:
        """给代码每行加 1-indexed 行号前缀（如 "13| cursor.execute(query)"）。"""
        return "\n".join(
            f"{i}| {line}" for i, line in enumerate(code.split("\n"), start=start_line)
        )

    def _sample_votes(self, prompt: str, n: int, temperature: float) -> list:
        """N 次采样统一入口（2026-08-30 vLLM 批量采样接线）。

        client 支持 generate_n（vLLM OpenAI n 参数）且 n>1 时，单请求批量
        采样——服务端对同一 prompt 的 n 条采样共享 prefill（parallel
        sampling），消除 N 次串行请求重复 pay 全量 prefill 的吞吐瓶颈；
        否则（Ollama / transformers / llamacpp）逐条 generate 循环，语义不变。

        返回 generate 结构 dict 列表；批量整体异常时抛给调用方（裁决侧
        逐票计 invalid、复核侧走原有整体 error 返回），单条失败为该项
        error 非空——与循环版逐票异常语义一致。
        """
        max_tokens = int(os.environ.get("VULN_SCANNER_MAX_TOKENS", "2048"))
        gen_n = getattr(self.client, "generate_n", None)
        if n > 1 and callable(gen_n):
            try:
                return gen_n(
                    prompt=prompt, n=n,
                    system_prompt=self.system_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    num_ctx=self.num_ctx,
                    keep_alive=self._effective_keep_alive(),
                )
            except Exception as e:
                print(f"[TwoStageScanner] generate_n 批量采样失败，退化为逐条: {e}")
        return [
            self.client.generate(
                prompt=prompt,
                system_prompt=self.system_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
                num_ctx=self.num_ctx,
                keep_alive=self._effective_keep_alive(),
            )
            for _ in range(n)
        ]

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
            aligned=self.triage_aligned,
        )
        votes_true = votes_false = votes_invalid = 0
        raw_outputs: list[str] = []
        reason = ""
        fix = ""
        # 判真票的 source/sink 锚点（2026-08-29：回填给无位置的位置型候选）
        adj_src = ""
        adj_sink = ""

        # N 票统一经 _sample_votes 获取（2026-08-30）：client 支持 generate_n
        # （vLLM）时单请求批量采样（服务端共享 prefill），否则逐条循环——
        # 两种路径的逐票解析/无效票语义完全一致
        try:
            vote_results = self._sample_votes(prompt, self.n_samples, self.temperature)
        except Exception as e:
            print(f"[TwoStageScanner] 裁决推理失败: {e}")
            vote_results = [{"error": f"{type(e).__name__}: {e}"} for _ in range(self.n_samples)]
        for result in vote_results:
            text = result.get("text", "") if isinstance(result, dict) else ""
            if result.get("error") if isinstance(result, dict) else False:
                votes_invalid += 1
                continue
            raw_outputs.append(text)
            parsed = parse_triage_verdict(text)
            confirmed = _normalize_confirmed(parsed.get("is_confirmed")) if parsed else None
            # 解析失败兜底：client 支持约束解码（generate_structured）时重试一次，
            # 消除"裁决输出 JSON 损坏"导致的无效票（与旧 Scanner 的 structured fallback 对齐）
            if confirmed is None and hasattr(self.client, "generate_structured"):
                try:
                    structured_result = self.client.generate_structured(
                        prompt=prompt,
                        system_prompt=self.system_prompt,
                        temperature=self.temperature,
                        max_tokens=int(os.environ.get("VULN_SCANNER_MAX_TOKENS", "2048")),
                        num_ctx=self.num_ctx,
                        keep_alive=self._effective_keep_alive(),
                    )
                except Exception:
                    structured_result = {"text": "", "error": "structured retry failed"}
                s_text = structured_result.get("text", "") if isinstance(structured_result, dict) else ""
                if not (structured_result.get("error") if isinstance(structured_result, dict) else True) and s_text:
                    raw_outputs.append(s_text)
                    parsed = parse_triage_verdict(s_text)
                    confirmed = _normalize_confirmed(parsed.get("is_confirmed")) if parsed else None
            if confirmed is None:
                votes_invalid += 1
                continue
            if confirmed:
                votes_true += 1
                if not reason:
                    reason = parsed.get("reason", "")
                    fix = parsed.get("fix_suggestion", "")
                # 2026-08-29 补：裁决模型输出的 source/sink 此前被丢弃（只取了
                # reason/fix）。位置型候选（B501/B310 等）自身无 source/sink 文本，
                # 导致顶层证据链恒空（模拟前端分析实锤：判真 3/0 但 source/sink/
                # explanation 全空）。首个判真票的锚点回写到 finding，供
                # _aggregate 取用（行号已在彼处纠正）。
                if not adj_src:
                    adj_src = (parsed.get("source") or "").strip()
                if not adj_sink:
                    adj_sink = (parsed.get("sink") or "").strip()
            else:
                votes_false += 1

        final_confirmed = votes_true > votes_false
        # 置信度分母用"有效票"（votes_true+votes_false）而非 self.n_samples：
        # invalid 票（解析失败/推理出错）不代表"否决"，除以 n_samples 会稀释真实
        # 自一致率。全部票无效时有效分母=1、confidence=0、confirmed=False，
        # 由 _aggregate 的 all_invalid 分支判 None（需复核），避免把"全部解析失败"
        # 误当成低置信"否决"——这就是 invalid 语义的统一入口。
        valid_votes = votes_true + votes_false
        # 模型校正的真实漏洞类型：取首个判真采样的 vulnerability_type（is_confirmed=true 时）
        corrected_type = ""
        if final_confirmed:
            for out in raw_outputs:
                p = parse_triage_verdict(out)
                if p and p.get("is_confirmed") is True:
                    vt = (p.get("vulnerability_type") or "").strip()
                    if vt and vt.lower() not in ("none", "n/a", "unknown"):
                        corrected_type = vt[:60]
                        break
        verdict = AdjudicationVerdict(
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
            vulnerability_type=corrected_type,
        )

        # 共形预测门控（Layer 1）：N 采样投票 → 三分类（带覆盖率保证的置信判断）
        if self._conformal is not None and self._conformal.calibrated():
            verdict.conformal_set = self._conformal.predict(
                votes_true, votes_false, votes_invalid, self.n_samples)

        # 锚点暂存（2026-08-29）：verdict.finding 由外层 _adjudicate_all 赋值，
        # 此处不能回填；写入字段待外层处理。
        verdict.src_anchor = adj_src
        verdict.sink_anchor = adj_sink

        # 信号回填（模型帮助工具，按信任分级门控）：
        #   全票一致的判定才记录；高置信否定 → 抑制池；confirmed → 置信+类型校正
        if self._signal_registry is not None:
            rule_id = (finding.rule_id or "")
            self._signal_registry.record(
                rule_id=rule_id,
                confirmed=final_confirmed and valid_votes == self.n_samples,
                n=self.n_samples, votes_true=votes_true,
                votes_false=votes_false, votes_invalid=votes_invalid,
                file=filename, taint_type=finding.taint_type,
                corrected_type=corrected_type,
            )
        return verdict

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
    def _aggregate(self, result: TwoStageResult, code: str = "") -> None:
        """根据裁决聚合文件级 has_vulnerability。

        规则：
        - 任一 finding 裁决 confirmed=True → 文件判 True
        - 全部 confirmed=False，或无候选 → 文件判 False
        - 有 finding 但全部解析失败（votes_invalid==N 或 votes_true==votes_false 平票）
          → 保守判 None（需复核）
        同时从已确认的裁决中取最高严重度 finding，填充文件级
        vulnerability_type / risk_level（供前端展示真实类型与风险等级）。

        code: 原始源码文本。用于对文件级 fix_suggestion（LLM 产出的行号锚定
              文本）做行号纠正；source/sink 来自确定性工具层（行号准确），
              不需要纠正。
        """
        # 直出档（secret/sca）finding 数量：确定性工具直出，不消耗 LLM 采样
        result.direct_findings = sum(
            1 for f in result.findings if self._is_direct_category(f.category)
        )
        # 文件级漏洞类型/风险：取已确认裁决中严重度最高的 finding
        confirmed = [a for a in result.adjudications if a.confirmed and a.finding]
        if confirmed:
            top = max(confirmed, key=lambda a: _SEV_RANK.get(
                ((a.finding or {}).get("severity") or "medium").lower(), 1))
            sev = ((top.finding or {}).get("severity") or "medium").lower()
            result.risk_level = sev.capitalize()
            taint_type = top.finding.get("taint_type") or ""
            rule_id = top.finding.get("rule_id") or ""
            # 类型校正（第 2.5 代）：裁决层输出的真实漏洞类型优先于工具 rule_id 硬映射
            # （工具泛规则常把越权/CSRF/IDOR 误标 XSS；模型校正后工具标注随之修正）
            corrected = ""
            # 原始输出文本（纠正前）→ 与投票键一一对应，供 raw_vulnerability_type
            # 使用（2026-08-29 修复：此前 raw 取的是 top finding 的 taint_type/
            # rule_id，与 vulnerability_type 的投票来源不同源，前端把两者拼成
            # "模型输出 → 纠正后"展示时出现 "Timing Attack → CWE-312" 这类
            # 无因果关系的误导性映射）
            #
            # 必须定义在此（2026-08-30 修复作用域缺陷）：此前本行位于下方
            # `if not corrected:` 块内，当 corrected 来自 signal_registry 校正分支
            # （如 B501 → CWE-295、taint_tracker:SQL Injection → CWE-89 等已提交
            # corrected_type 的规则）时整块被跳过，块外第 2655 行访问该变量抛
            # UnboundLocalError，导致整个 _aggregate 中断、前端显示"分析失败"
            # （typical_20_insecure_tls.py 实锤）。
            raw_texts: dict[str, str] = {}
            # 多数票优先（2026-09-01，工具层优化指导 §8.9 第 2 项"top1 与多漏洞
            # 列表同源化"）：此前 signal_registry 的规则级 corrected_type 短路在
            # 多数票**之前**——最高 severity 工具规则命中注册表映射时，模型独立
            # 归因被无视，top1 与 vulnerability_types 脱节（typical_08_eval
            # top1=78 vs vts=[94]、hard_cve_03 top1=798 vs vts=[89] 实锤）。
            # 现改为：有模型类型票时 top1 取多数票类型（与模型归因同源）；
            # 注册表映射仅兜底——模型全体未输出类型时保持 B501→CWE-295 等
            # 历史校正能力不丢失。
            type_votes: dict[str, list[int]] = {}
            for a in confirmed:
                t = (a.vulnerability_type or "").strip()
                if not t:
                    continue
                raw_texts.setdefault(t, t)
                tool_label = normalize_cwe_label(
                    (a.finding or {}).get("taint_type") or "") or ""
                is_echo = bool(tool_label) and (
                    normalize_cwe_label(t) or t) == tool_label
                sev_rank = _SEV_RANK.get(
                    ((a.finding or {}).get("severity") or "medium").lower(), 1)
                bucket = type_votes.setdefault(t, [0, 0, 0])
                bucket[0] += 1
                if not is_echo:
                    bucket[1] += 1
                bucket[2] = max(bucket[2], sev_rank)
            if type_votes:
                corrected = max(
                    type_votes,
                    key=lambda t: tuple(type_votes[t]),
                )
            elif self._signal_registry is not None:
                corrected = self._signal_registry.corrected_taint_type(rule_id)
            # 统一走 CWE 纠正工具（cwe_normalizer）：Path Traversal → CWE-22 路径穿越，
            # 无映射时回退到 taint_type / rule_id，保证与旧管道信息格式一致。
            # 2026-08-29 修复：多数票分支此前**跳过纠正器**直接采用模型原始文本
            # （hard_bypass_06 实锤：模型输出 "Timing Attack" 直接成为最终类型，
            # 未经纠正为 CWE-208，strict 口径必然 miss）。现三分支一律过纠正器。
            if corrected:
                result.vulnerability_type = normalize_cwe_label(corrected) or corrected
            else:
                result.vulnerability_type = normalize_cwe_label(taint_type) or rule_id
            # 多漏洞收集（2026-08-17）：所有判真且过证据门的 finding 的类型
            # （模型校正 > 工具 taint > rule_id），去重保序，供前端展示全部确认
            # 漏洞（如 SSTI 样本同时确认 XSS + SSTI）。vulnerability_type 仍是 top1。
            types: list[str] = []
            for a in confirmed:
                if a.evidence_gate:
                    continue  # 与 _aggregate 底部 majority_confirm 的 evidence_gate 门一致
                fd = a.finding or {}
                # 取值优先级不变（模型校正 > 工具 taint > rule_id），但**取到后统一
                # 过 normalize_cwe_label**（2026-08-30，工具层优化指导 §8.9 第 3 项）：
                # 此前仅兜底复核分支做了归一化，裁决主分支直接把模型原文入库，
                # 导致同一编号两套官方名并存（"CWE-78 Command Injection" vs
                # "CWE-78 OS Command Injection"、"Wraparound" vs "Wrap-up"），
                # 前端两处显示不一致。归一化后重复项由下方保序去重自然合并。
                raw_t = (a.vulnerability_type or "").strip()
                if not raw_t:
                    raw_t = str(fd.get("taint_type") or "").strip()
                if not raw_t or raw_t.lower() in ("none", "unknown", "detected"):
                    raw_t = str(fd.get("rule_id") or "").strip()
                t = normalize_cwe_label(raw_t) or raw_t
                if t and t not in types:
                    types.append(t)
            result.vulnerability_types = types
            # 原始类型（纠正前）：前端据此展示"工具原始标注 → CWE Normalizer 纠正"过程。
            # 必须与 vulnerability_type **同源**（2026-08-29）：走多数票分支时取
            # 该类型的模型原始输出；仅当回退到工具标注时才用 taint_type/rule_id，
            # 否则会拼出无因果关系的"纠正前后"（hard_bypass_06 实锤）。
            result.raw_vulnerability_type = raw_texts.get(corrected or "") or taint_type or rule_id
            # 透出已确认裁决的 source/sink/分析/修复到文件级，供前端卡片收起态
            # 直接展示（与旧管道 r.source/r.sink/explanation/fix_suggestion 对齐）。
            # source/sink/explanation 均接行号纠正（2026-08-29）；explanation 仅
            # 依赖同文本内部锚 delta 传播（跨字段 hint 已撤销，防纠错）。
            if not result.source:
                result.source = normalize_line_numbers(top.finding.get("source") or "", code)
            if not result.sink:
                result.sink = normalize_line_numbers(top.finding.get("sink") or "", code)
            if not result.explanation:
                result.explanation = normalize_line_numbers(top.reasoning or "", code)
            if not result.fix_suggestion:
                result.fix_suggestion = top.fix_suggestion or ""
            # 行号纠正（与旧 Scanner 同思路）：LLM 产出的 fix_suggestion 是
            # "line N:" 锚定文本，行号容易数错但行文本内容可靠，用内容定位真实行号
            if (result.fix_suggestion
                    and result.fix_suggestion not in ("N/A", "no fix needed")
                    and code):
                result.fix_suggestion = normalize_line_numbers(
                    result.fix_suggestion, code)

        if not result.adjudications:
            result.has_vulnerability = False
            return
        # 文件级 True 的两条通道（2026-08-18 注释修正，消除与底部 majority_confirm 的
        # 表面矛盾）：
        #   (a) 高置信确认（≥_CONF_AUTO）：单条 finding 的高置信判中直接判 True；
        #   (b) 存在性多数判真（底部 majority_confirm）：漏洞判定是存在性的——任一
        #       finding 多数票判真（votes_true > votes_false）即文件存在该漏洞。
        # 低置信确认（0.5~0.8）虽计入 reviewer_findings（前端展示"需复核"），但只要
        # 存在性成立，文件级仍输出 True（2026-08-16 修复，避免无关 finding 否决票
        # 对冲掉提示到点的判真）。两通道都排除 evidence_gate 拦截的判中（sink 已防御/
        # 无输入入口 → 疑似模式匹配误报）。
        strong_confirmed = any(
            a.confirmed and a.confidence >= _CONF_AUTO and not a.evidence_gate
            for a in result.adjudications
        )
        # Layer 2 反事实验证降级：**仅当原始代码已含同类防御（already_defended=True）**
        # 才降级——模型没识别已有防御 = 误报（safe_08 类）。
        # 未含防御（already_defended=False）的 finding 不做扰动降级：
        #   真漏洞扰动后仍判漏洞（flipped=False）是正确行为，绝不能降级（2026-08-14
        #   回归：13 个真漏洞被误降级 review）。扰动后判安全（flipped=True）是模型
        #   理解防御的证据，更不降级。
        cf_unflipped = any(
            a.counterfactual
            and a.counterfactual.get("already_defended")
            and (a.finding or {}).get("category") in _LOW_TRUST_CATEGORIES
            for a in result.adjudications
        )
        any_confirmed = any(a.confirmed for a in result.adjudications)
        all_invalid = all(a.votes_invalid >= self.n_samples for a in result.adjudications)

        # 共形集接管（第 2.5 代）：所有有共形集的裁决一致时优先采信（统计保证）。
        # 共形预测的 {漏洞}/{安全} 是带 1-α 覆盖率保证的预测集——全部落入 {安全}
        # 即高置信真阴性（个别低置信否决票不影响，统计上仍安全）；全部 {漏洞} 即
        # 高置信真阳性。仅在校准后（calibrated）生效；未校准走旧投票逻辑。
        cf_sets = [a.conformal_set for a in result.adjudications if a.conformal_set]
        cf_unanimous = bool(cf_sets) and len(cf_sets) == len(result.adjudications) \
            and all(s == cf_sets[0] for s in cf_sets)
        if cf_unanimous and cf_sets[0] == "safe" and not any_confirmed:
            # 2026-08-15 修复：safe 接管补 any_confirmed 门——与 vulnerable 方向的
            # strong_confirmed 门对称。原实现无此门，可吞掉低置信 confirmed 的裁决，
            # 与下方"低置信确认必须进 review"（elif any_confirmed → None）原则冲突。
            # 有任一判中时落到旧投票逻辑（进 review），统计保证不覆盖单点证据。
            result.has_vulnerability = False
            result.error = ""
            return
        # vulnerable 接管必须存在高置信判中（≥_CONF_AUTO）：共形会把 T2/F1(0.667)
        # 也判 vulnerable（净化校准后阈值放宽），低置信判中不能直接判漏洞（safe_05
        # 类 FP 根因），须走 strong_confirmed 分支（进 review 或反事实验证）。
        if cf_unanimous and cf_sets[0] == "vulnerable" and strong_confirmed and not cf_unflipped:
            result.has_vulnerability = True
            return

        if strong_confirmed and not cf_unflipped:
            result.has_vulnerability = True
        elif strong_confirmed and cf_unflipped:
            # 模式匹配存疑：保守转复核（论文口径"反事实验证存疑"）
            result.has_vulnerability = None
            if not result.error:
                result.error = "反事实验证未翻转（模式匹配存疑），需人工复核"
        elif all_invalid:
            result.has_vulnerability = None
            if not result.error:
                result.error = "所有 finding 裁决解析失败，需人工复核"
        else:
            # 多数判真采信（2026-08-16/17 修复，存在性判定）：漏洞判定是存在性的——
            # 文件里只要有任一工具召回 finding 多数票判真（votes_true > votes_false）
            # 就该报 True，不该被无关 finding 的否决票对冲（hard_cve_03 的 B108 T2/F1
            # 判真 + django T1/F2 判假、typical_13 的 taint XSS 判真 + flask 判假等
            # 4 个 review 全是"提示到点的 finding 判真 + 无关 finding 判假"对冲）。
            # 数据佐证：判真 finding 19 条全在漏洞样本、安全样本 0 条（工具召回类）。
            # 排除 category=="llm" 的合成 finding（recheck 复核路径，走 trust_llm_recheck
            # 全票门槛，不参与本存在性判定——混入会把 crossfile 安全样本的复核误判
            # 放大成 FP）。
            # 2026-08-17 修复：排除 evidence_gate 拦截的判真。safe_03 实锤：subprocess
            # 列表参数 3 个 finding 全命中 sink_defended，但原实现 majority_confirm
            # 只查 confirmed 绕过 evidence_gate → FP。与 strong_confirmed 的
            # `not a.evidence_gate` 对齐（证据门拦截 = 疑似模式匹配误报）。
            _confirmed_cnt = sum(
                1 for a in result.adjudications
                if a.confirmed and a.votes_true > a.votes_false
                and (a.finding or {}).get("category") != "llm"
                and not a.evidence_gate
            )
            if _confirmed_cnt > 0:
                result.has_vulnerability = True
            elif any_confirmed or result.reviewer_findings:
                # 低置信确认 / 平票 / 低置信否决 / 证据门拦截 → 需复核，文件级判 None
                result.has_vulnerability = None
                if not result.error:
                    gated = sorted({a.evidence_gate for a in result.adjudications
                                    if a.confirmed and a.evidence_gate})
                    if gated:
                        result.error = "证据门拦截（%s）：sink 已防御或无可信污点源，疑似模式匹配误报，需人工复核" % "/".join(gated)
                    else:
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

# Prefilter 规则 → taint_type / severity（统一来自 prefilter.PREFILTER_RULE_INFO，
# 与 scanner.py 的 _PREFILTER_VULN_INFO 同一数据源，避免两份映射漂移）
_PREFILTER_TYPE = {name: meta["taint_type"] for name, meta in PREFILTER_RULE_INFO.items()}
_PREFILTER_SEVERITY = {name: meta["severity"] for name, meta in PREFILTER_RULE_INFO.items()}


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
                         use_external=False, sampling_rate=0)
    r = ts.scan_code('x = 1\nprint(x)', "python", "safe.py")
    ok_safe = r.has_vulnerability is False and r.stage1["decision"] == "no_candidate_safe"
    print(f"[{'PASS' if ok_safe else 'FAIL'}] 无候选判安全: has_vuln={r.has_vulnerability}, "
          f"decision={r.stage1.get('decision')}")

    # 5) 直出档裁决：secret/sca finding 不消耗 LLM 采样（直接判真，decision=direct）
    direct = ToolFinding(rule_id="generic-api-key", category="secret", source="", sink="",
                         taint_type="generic-api-key", source_line=3, sink_line=3,
                         severity="high", tool="gitleaks",
                         evidence="发现疑似 AWS Access Key")
    d_verdict = ts._adjudicate_all([direct], 'code', "python", "", None)
    d = d_verdict[0][0]
    ok_direct = (d.confirmed is True and d.confidence == 1.0
                 and d.decision == "direct" and d.votes_true == 1)
    print(f"[{'PASS' if ok_direct else 'FAIL'}] 直出档裁决: confirmed={d.confirmed}, "
          f"decision={d.decision}")

    # 6) full_recheck 模式：无候选文件全量 LLM 复核（消除"无证据判安全"）。
    # 复核走主扫描 prompt + 7 字段 verdict 解析，FakeClient 需返回该格式。
    class FakeVerdictClient:
        def __init__(self, outputs):
            self.outputs = outputs
            self.i = 0
        def generate(self, **kwargs):
            out = self.outputs[self.i % len(self.outputs)]
            self.i += 1
            return {"text": out, "error": None}

    safe_verdict = '{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "None"}'
    ts2 = TwoStageScanner(client=FakeVerdictClient([safe_verdict]), system_prompt="sys", n_samples=3,
                          use_semgrep=False, use_taint_tracker=False, use_prefilter=False,
                          use_external=False, no_candidate_mode="full_recheck")
    r2 = ts2.scan_code('x = 1\nprint(x)', "python", "safe2.py")
    ok_full = r2.stage1["decision"] == "no_candidate_recheck_safe"
    print(f"[{'PASS' if ok_full else 'FAIL'}] full_recheck 复核: decision={r2.stage1.get('decision')}, "
          f"has_vuln={r2.has_vulnerability}")

    # 7) RAG 默认跟随环境变量 VULN_SCANNER_RAG（不显式传参时）
    import os as _os
    _os.environ["VULN_SCANNER_RAG"] = "1"
    ts_rag = TwoStageScanner(client=FakeClient(outputs), system_prompt="sys")
    ok_rag_default = ts_rag.use_rag is True
    _os.environ["VULN_SCANNER_RAG"] = "0"
    ts_rag_off = TwoStageScanner(client=FakeClient(outputs), system_prompt="sys")
    ok_rag_default = ok_rag_default and ts_rag_off.use_rag is False
    print(f"[{'PASS' if ok_rag_default else 'FAIL'}] RAG 默认跟随环境变量: use_rag={ts_rag_off.use_rag}")

    # 8) 确定性证据门：sink 已防御（参数化 execute）→ 判中降权，文件转复核
    noise02_code = (
        'from flask import Flask, request\n'
        'app = Flask(__name__)\n'
        '@app.route("/login")\n'
        'def login():\n'
        '    username = request.args.get("username", "")\n'
        '    cursor.execute(\n'
        '        "SELECT * FROM users WHERE name = ? AND pass = ?",\n'
        '        (username, password),\n'
        '    )\n'
    )
    gate_finding = ToolFinding(rule_id="python-sqli-taint", category="taint",
                               source="request.args.get('username')",
                               sink="cursor.execute(...)", taint_type="SQL Injection",
                               source_line=5, sink_line=6, severity="high", tool="semgrep")
    v1 = AdjudicationVerdict(confirmed=True, confidence=1.0, votes_true=3, votes_false=0,
                             votes_invalid=0, finding=gate_finding.to_dict())
    ts_gate = TwoStageScanner(client=FakeClient(outputs), system_prompt="sys")
    ts_gate._evidence_gate_pass([v1], noise02_code, "python")
    ok_gate1 = v1.evidence_gate == "sink_defended"
    print(f"[{'PASS' if ok_gate1 else 'FAIL'}] 证据门·sink已防御: gate={v1.evidence_gate}")

    # 9) 确定性证据门：无输入入口（模块级字面量脚本）→ no_input_entry
    noise03_code = (
        'name = "admin"\n'
        'query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
        'cursor.execute(query)\n'
    )
    gate_finding2 = ToolFinding(rule_id="B608", category="sast", source="name", sink="cursor.execute(query)",
                                taint_type="SQL Injection", source_line=1, sink_line=3,
                                severity="medium", tool="bandit")
    v2 = AdjudicationVerdict(confirmed=True, confidence=1.0, votes_true=3, votes_false=0,
                             votes_invalid=0, finding=gate_finding2.to_dict())
    ts_gate._evidence_gate_pass([v2], noise03_code, "python")
    ok_gate2 = v2.evidence_gate == "no_input_entry"
    print(f"[{'PASS' if ok_gate2 else 'FAIL'}] 证据门·无输入入口: gate={v2.evidence_gate}")

    # 10) 证据门不误伤真漏洞：request 输入 + 非参数化拼接 → 不拦截
    vuln_code = (
        'from flask import request\n'
        'def search():\n'
        '    keyword = request.args.get("q", "")\n'
        '    cursor.execute("SELECT * FROM t WHERE name LIKE \'%" + keyword + "%\'")\n'
    )
    v3 = AdjudicationVerdict(confirmed=True, confidence=1.0, votes_true=3, votes_false=0,
                             votes_invalid=0, finding=gate_finding.to_dict())
    v3.finding["sink_line"] = 4
    ts_gate._evidence_gate_pass([v3], vuln_code, "python")
    ok_gate3 = v3.evidence_gate is None
    print(f"[{'PASS' if ok_gate3 else 'FAIL'}] 证据门·真漏洞放行: gate={v3.evidence_gate}")

    # 11) recheck 类型回填：盲区样本复核全票判真采信时，vulnerability_type 不再丢失
    vuln_verdict = ('{"has_vulnerability": true, "vulnerability_type": "CWE-611 XXE", '
                    '"risk_level": "High", "explanation": "外部实体未禁用", '
                    '"fix_suggestion": "line 5: 禁用 DTD"}')
    ts3 = TwoStageScanner(client=FakeVerdictClient([vuln_verdict]), system_prompt="sys", n_samples=3,
                          use_semgrep=False, use_taint_tracker=False, use_prefilter=False,
                          use_external=False, no_candidate_mode="full_recheck")
    r3 = ts3.scan_code('import xml\nfrom flask import request\n'
                       'def parse():\n    d = request.data\n    xml.parse(d)\n', "python", "xxe.py")
    ok_recheck_type = (r3.has_vulnerability is True
                       and "CWE-611" in r3.vulnerability_type
                       and r3.stage1["decision"] == "no_candidate_recheck_vuln")
    print(f"[{'PASS' if ok_recheck_type else 'FAIL'}] recheck类型回填: type={r3.vulnerability_type!r}, "
          f"dec={r3.stage1.get('decision')}")

    # 12) 裁决 prompt 防锚定（2026-08-29 §四 升级为按证据类型分级）：
    #     无链 sast → 位置型警示；带链 taint → 链级高信任标注（含推翻须指认断点）；
    #     category=taint 但链为空（semgrep OSS 形态）→ 降级为位置型警示。
    from graduation_project.prompts import build_triage_prompt
    sast_f = ToolFinding(rule_id="B608", category="sast", source="", sink="",
                         taint_type="B608", source_line=1, sink_line=3, severity="medium", tool="bandit")
    taint_f = ToolFinding(rule_id="t-sql", category="taint", source="request.args.get('q')",
                          sink="cursor.execute(q)", taint_type="SQL Injection",
                          source_line=2, sink_line=5, severity="high", tool="taint_tracker")
    empty_taint_f = ToolFinding(rule_id="sqli-taint", category="taint", source="", sink="",
                                taint_type="SQL Injection", source_line=5, sink_line=5,
                                severity="high", tool="semgrep")
    p_sast = build_triage_prompt(sast_f, "code", "python")
    p_taint = build_triage_prompt(taint_f, "code", "python")
    p_taint_empty = build_triage_prompt(empty_taint_f, "code", "python")
    # CWE 编号锚断言（2026-08-31，§9.21 A/B）：taint_f 的语义名 "SQL Injection"
    # 须在类型行透出标准分类 "CWE-89"；sast_f 的裸规则号 "B608" 无映射 → 无锚但
    # 仍须带"语义一致"指令（旧断言引用的 "CWE-862" 是已删除的示例文本）。
    ok_anchor = ("历史误报率高" in p_sast and "独立判定" in p_sast
                 and "历史误报率高" not in p_taint
                 and "语义一致" in p_sast and "标准分类 CWE-89" in p_taint
                 and "数据流链" in p_taint and "断点" in p_taint
                 and "历史误报率高" in p_taint_empty)
    print(f"[{'PASS' if ok_anchor else 'FAIL'}] 裁决prompt信任分级: "
          f"sast警示={'历史误报率高' in p_sast}, taint链标注={'数据流链' in p_taint}, "
          f"无链taint降级={'历史误报率高' in p_taint_empty}")

    # 13) 文件级类型多数票 + 回声降权（2026-08-15 修复）：复刻 typical_17_md5_password
    #     的真实裁决组合——5 判中：CWE-79×2（其一为 xss-taint 回声票）、CWE-327×2
    #     （均独立判断）、CWE-759×1。旧实现取第一个非空类型 → 锚定的 CWE-79；
    #     多数票平票（2:2）时独立票胜出 → CWE-327。
    def _av(t, f_taint, sev="medium"):
        return AdjudicationVerdict(
            confirmed=True, confidence=1.0, votes_true=3, votes_false=0, votes_invalid=0,
            vulnerability_type=t,
            finding={"taint_type": f_taint, "rule_id": f_taint, "severity": sev,
                     "source": "", "sink": "", "sink_line": 1})
    res_mj = TwoStageResult(filename="typical_17.py", language="python",
                            has_vulnerability=None)
    res_mj.adjudications = [
        _av("CWE-79 Cross-site Scripting (XSS)", "XSS", "high"),      # 回声票（工具XSS→模型XSS）
        _av("CWE-327 Use of a Broken or Risky Cryptographic Algorithm", "B324"),
        _av("CWE-327 Use of a Broken or Risky Cryptographic Algorithm", "insecure-hash-algo-md5"),
        _av("CWE-759 Cryptographic Misconfiguration", "md5-used-as-password"),
        _av("CWE-79 Cross-site Scripting (XSS)", "directly-returned-format-string", "low"),
    ]
    ts_gate._aggregate(res_mj, code="")
    ok_majority = "CWE-327" in res_mj.vulnerability_type
    print(f"[{'PASS' if ok_majority else 'FAIL'}] 类型多数票+回声降权: type={res_mj.vulnerability_type!r}")

    # 14) 证据门正则修复（2026-08-15）：def/=> 不再算"输入入口"——带无关辅助
    #     函数的纯字面量拼接脚本仍应被 no_input_entry 拦截
    code_with_def = "def helper(x):\n    return x + 1\nq = \"SELECT * FROM t WHERE n=\" + \"admin\""
    has_entry = bool(_INPUT_ENTRY.search(code_with_def))
    ok_entry = not has_entry
    print(f"[{'PASS' if ok_entry else 'FAIL'}] 证据门正则: 带无关def的纯字面量 has_entry={has_entry} (期望 False)")

    # 15) n_samples 请求级不泄漏（2026-08-15）：scan_code(n_samples=1) 后
    #     单例默认值不被改写
    leak_scanner = TwoStageScanner(client=FakeClient(outputs), system_prompt="sys", n_samples=3)
    leak_scanner._stage1_recall = lambda *a, **k: []  # 跳过工具层
    leak_scanner.scan_code("x=1", "python", "t.py", n_samples=1)
    ok_noleak = leak_scanner.n_samples == 3
    print(f"[{'PASS' if ok_noleak else 'FAIL'}] n_samples不泄漏: scan 后默认={leak_scanner.n_samples} (期望 3)")

    # 16) 信号注册表读取端接线（2026-08-15）：抑制规则的候选被过滤，
    #     直出档不受影响
    import tempfile as _tf
    from pathlib import Path as _P
    from graduation_project.signal_registry import SignalRegistry as _SR
    _reg = _SR(path=_P(_tf.mkdtemp()) / "reg.json", enabled=True)
    _reg.record("bad.rule", confirmed=False, n=3, votes_true=0, votes_false=3,
                votes_invalid=0, file="a.py")
    _reg.record("bad.rule", confirmed=False, n=3, votes_true=0, votes_false=3,
                votes_invalid=0, file="b.py")
    wired = TwoStageScanner(client=FakeClient(outputs), system_prompt="sys")
    wired._signal_registry = _reg
    fs = [
        ToolFinding(rule_id="bad.rule", category="sast", source="", sink="",
                     taint_type="X", source_line=0, sink_line=1, tool="bandit"),
        ToolFinding(rule_id="good.rule", category="sast", source="", sink="",
                     taint_type="Y", source_line=0, sink_line=2, tool="bandit"),
        ToolFinding(rule_id="bad.rule", category="secret", source="", sink="",
                     taint_type="Z", source_line=0, sink_line=3, tool="gitleaks"),
    ]
    kept = wired._apply_signal_registry(list(fs))
    rules = [f.rule_id for f in kept]
    ok_wire = rules.count("bad.rule") == 1 and "good.rule" in rules  # 裁决档被抑制，secret 直出档保留
    print(f"[{'PASS' if ok_wire else 'FAIL'}] 抑制池接线: kept={rules} (期望 bad.rule 仅剩 secret 档)")

    # 17) recheck 采信路径证据链（2026-08-15）：no_candidate_recheck_vuln 现在
    #     产出 findings/adjudications（此前全空）
    cf_scanner = TwoStageScanner(client=FakeClient([
        '```json\n{"has_vulnerability": true, "vulnerability_type": "CWE-89 SQL Injection",'
        '"risk_level": "High", "source": "line 2: request.args.get", '
        '"sink": "line 4: cursor.execute", "explanation": "拼接SQL", '
        '"fix_suggestion": "参数化查询"}\n```'
    ] * 3), system_prompt="sys", n_samples=3, trust_llm_recheck=True,
        no_candidate_mode="full_recheck")
    cf_scanner._stage1_recall = lambda *a, **k: []
    res_cf = cf_scanner.scan_code("q = request.args.get('q')\ncursor.execute('...' + q)", "python", "s.py")
    ok_chain = (res_cf.stage1.get("decision") == "no_candidate_recheck_vuln"
                and len(res_cf.findings) == 1 and len(res_cf.adjudications) == 1
                # 2026-08-29 起证据链接行号纠正：模型误报的 line 2 纠正为真实 line 1
                and res_cf.findings[0].source.startswith("line 1"))
    print(f"[{'PASS' if ok_chain else 'FAIL'}] recheck证据链: findings={len(res_cf.findings)}, "
          f"adjudications={len(res_cf.adjudications)}, src={res_cf.findings[0].source[:30] if res_cf.findings else None!r}")

    # 18) B3（2026-08-29）：secret 类 SAST 规则不再按"无主告警"剔除，
    #     转 category="secret" 归入直出档；非 secret 的乱码语义照常剔除。
    ts_b3 = TwoStageScanner(client=FakeClient(outputs), system_prompt="sys")
    b3_findings = [
        ToolFinding(rule_id="B105", category="sast", source="", sink="",
                    taint_type="B105", source_line=3, sink_line=3,
                    severity="low", tool="bandit",
                    evidence="Possible hardcoded password: 'AKIAIOSFODNN7EXAMPLE'"),
        ToolFinding(rule_id="models.semgrep_rules.generic.hardcoded-token",
                    category="sast", source="", sink="", taint_type="x",
                    source_line=8, sink_line=8, severity="medium", tool="semgrep",
                    evidence="hardcoded token value 's3cr3t_t0k3n_abc123xyz'"),
        ToolFinding(rule_id="request-data-write", category="sast", source="", sink="",
                    taint_type="request-data-write", source_line=9, sink_line=9,
                    severity="low", tool="semgrep", evidence="request-data-write"),
    ]
    kept_b3 = ts_b3._drop_irrelevant_positional(b3_findings)
    b3_cats = {f.rule_id.split(".")[-1]: f.category for f in kept_b3}
    ok_b3 = (b3_cats.get("B105") == "secret"
             and b3_cats.get("hardcoded-token") == "secret"
             and "request-data-write" not in b3_cats
             and ts_b3._is_direct_category(kept_b3[0].category))
    print(f"[{'PASS' if ok_b3 else 'FAIL'}] B3 secret类转直出: {b3_cats} "
          f"(B105/hardcoded-token→secret, request-data-write→剔除)")

    # 18b) B3 凭证门槛（2026-08-29 用户实锤修正）：框架配置型弱值
    #      （app.secret_key = "dev_key"）不得直出顶掉真实漏洞类型；
    #      强凭证（真密钥）仍直出。
    ts_b3b = TwoStageScanner(client=FakeClient(outputs), system_prompt="sys")
    weak = ToolFinding(rule_id="B105", category="sast", source="", sink="",
                       taint_type="B105", source_line=5, sink_line=5,
                       severity="low", tool="bandit",
                       evidence="Possible hardcoded password: 'dev_key'")
    strong = ToolFinding(rule_id="B105", category="sast", source="", sink="",
                         taint_type="B105", source_line=8, sink_line=8,
                         severity="low", tool="bandit",
                         evidence="Possible hardcoded password: 'sup3r_s3cret_t0k3n_very_long'")
    kept_b3b = ts_b3b._drop_irrelevant_positional([weak, strong])
    cats_b3b = {f.sink_line: f.category for f in kept_b3b}
    ok_b3b = (cats_b3b.get(5) == "sast"          # 弱值→裁决档，由模型判断
              and cats_b3b.get(8) == "secret"    # 强凭证→直出
              and all(f.taint_type == "Hardcoded Credentials" for f in kept_b3b))
    print(f"[{'PASS' if ok_b3b else 'FAIL'}] B3 凭证门槛: {cats_b3b} "
          f"(弱值→裁决档sast, 强凭证→直出secret, 类型均归一 Hardcoded Credentials)")

    # 19) §三（2026-08-29）：族级归并——sast 规则号候选按推断语义族与 taint 候选
    #     同行合并；prefilter 无行号候选归并到同族唯一候选；直出档同位置合并。
    tj = ToolFinding(rule_id="t-sql", category="taint", source="request.args.get('q')",
                     sink="cursor.execute(q)", taint_type="SQL Injection",
                     source_line=1, sink_line=5, path=["q"], severity="high", tool="taint_tracker")
    sast_b608 = ToolFinding(rule_id="B608", category="sast", source="", sink="",
                            taint_type="B608", source_line=5, sink_line=5,
                            severity="medium", tool="bandit",
                            evidence="Possible SQL injection vector")
    pf_sql = ToolFinding(rule_id="sqli_string_concat", category="prefilter", source="", sink="",
                         taint_type="SQL Injection", source_line=0, sink_line=0,
                         severity="high", tool="prefilter",
                         evidence="Prefilter 命中漏洞特征规则: sqli_string_concat")
    merged3 = TwoStageScanner._dedupe([tj, sast_b608, pf_sql])
    ok_dedupe3 = (len(merged3) == 1
                  and merged3[0].tool == "bandit+prefilter+taint_tracker")
    print(f"[{'PASS' if ok_dedupe3 else 'FAIL'}] §三族级归并: {len(merged3)} 条, "
          f"tool={merged3[0].tool if merged3 else None}")
    # 直出档同位置合并：bandit B105（转 secret 档）与 gitleaks 同行告警并一条
    b105 = ToolFinding(rule_id="B105", category="secret", source="", sink="",
                       taint_type="B105", source_line=3, sink_line=3,
                       severity="low", tool="bandit", evidence="hardcoded password")
    glk = ToolFinding(rule_id="generic-api-key", category="secret", source="", sink="",
                      taint_type="generic-api-key", source_line=3, sink_line=3,
                      severity="high", tool="gitleaks", evidence="generic-api-key")
    merged4 = TwoStageScanner._dedupe([b105, glk])
    ok_dedupe4 = (len(merged4) == 1
                  and merged4[0].tool == "bandit+gitleaks"
                  and "generic-api-key" in merged4[0].evidence)
    print(f"[{'PASS' if ok_dedupe4 else 'FAIL'}] §三直出档同行合并: {len(merged4)} 条, "
          f"tool={merged4[0].tool if merged4 else None}")
    # 歧义保护：同族两条不同位置候选时，无行号候选不归并（保持 3 条）
    tj2 = ToolFinding(rule_id="t-sql2", category="taint", source="request.form['a']",
                      sink="cursor.execute(q2)", taint_type="SQL Injection",
                      source_line=10, sink_line=20, severity="high", tool="taint_tracker")
    merged5 = TwoStageScanner._dedupe([tj, tj2, pf_sql])
    ok_dedupe5 = len(merged5) == 3
    print(f"[{'PASS' if ok_dedupe5 else 'FAIL'}] §三歧义保护: 同族双候选时无行号候选保留 "
          f"({len(merged5)} 条, 期望 3)")

    # 20) _aggregate 的 raw_vulnerability_type 作用域（2026-08-30 回归）：
    #     corrected 由 signal_registry 校正分支产出时（如 B501 → CWE-295），
    #     raw_texts 曾定义在多数票块内，块外访问抛 UnboundLocalError → 整个
    #     _aggregate 中断、前端显示"分析失败"（typical_20_insecure_tls.py 实锤）。
    #     2026-09-01 起（§8.9#2 同源化）多数票优先于注册表，注册表兜底仅在
    #     **模型未输出类型**时生效——本用例的裁决不带 vulnerability_type，
    #     正好覆盖该兜底分支（raw=工具标注，保持"工具原始 → 纠正后"展示语义）。
    from graduation_project.signal_registry import SignalRegistry
    with tempfile.TemporaryDirectory() as _td:
        _reg = SignalRegistry(path=Path(_td) / "reg.json", enabled=True)
        for _f in ("a.py", "b.py"):     # ≥MIN_AGREE_SAMPLES 个独立样本才提交校正
            _reg.record("B501-X", confirmed=True, n=3, votes_true=3, votes_false=0,
                        votes_invalid=0, file=_f, taint_type="B501-X",
                        corrected_type="CWE-295 Improper Certificate Validation")
        _ts = object.__new__(TwoStageScanner)   # 绕过 __init__：用例不依赖 LLM client
        _ts.n_samples = 3
        _ts._signal_registry = _reg
        _ts._conformal = None
        _ts._counterfactual = None
        _res = TwoStageResult(filename="t.py", language="python",
                              has_vulnerability=None, findings=[])
        _res.adjudications = [AdjudicationVerdict(
            confirmed=True, confidence=1.0, votes_true=3, votes_false=0, votes_invalid=0,
            reasoning="r", fix_suggestion="f", decision="confirmed_vulnerability",
            finding={"rule_id": "B501-X", "category": "sast", "severity": "high",
                     "taint_type": "B501-X", "source": "line 1: x", "sink": "line 2: y"})]
        try:
            _ts._aggregate(_res, "x = 1\ny = 2\n")
            # 模型无类型票 → 注册表校正兜底，raw=工具标注
            ok_rawtype = (_res.vulnerability_type == "CWE-295 Improper Certificate Validation"
                          and _res.raw_vulnerability_type == "B501-X")
        except Exception as _e:          # 修复前此处抛 UnboundLocalError
            ok_rawtype = False
            print(f"      异常: {type(_e).__name__}: {_e}")
    print(f"[{'PASS' if ok_rawtype else 'FAIL'}] §四 raw 类型作用域(registry 兜底分支): "
          f"{_res.vulnerability_type!r} <- raw {_res.raw_vulnerability_type!r}")

    # 27) top1 与模型归因同源化（2026-09-01，§8.9 第 2 项）：模型类型票存在时，
    #     top1 必须取多数票类型，signal_registry 的规则级 corrected_type 仅兜底。
    #     复刻 typical_08_eval 实锤：最高 severity 工具规则（注册表已提交 78 校正）
    #     vs 模型独立归因 94——旧逻辑注册表短路 → top1=78 与 vts=[94] 脱节。
    with tempfile.TemporaryDirectory() as _td2:
        _reg2 = SignalRegistry(path=Path(_td2) / "reg.json", enabled=True)
        for _f in ("a.py", "b.py"):
            _reg2.record("crit-tool-rule", confirmed=True, n=3, votes_true=3,
                         votes_false=0, votes_invalid=0, file=_f,
                         taint_type="crit-tool-rule",
                         corrected_type="CWE-78 OS Command Injection")
        _ts2 = object.__new__(TwoStageScanner)
        _ts2.n_samples = 3
        _ts2._signal_registry = _reg2
        _ts2._conformal = None
        _ts2._counterfactual = None
        _res2 = TwoStageResult(filename="t8.py", language="python",
                               has_vulnerability=None, findings=[])
        # 高严重度工具候选（注册表映射 78）+ 模型 2 票归因 94（独立票）
        _res2.adjudications = [
            AdjudicationVerdict(
                confirmed=True, confidence=1.0, votes_true=3, votes_false=0,
                votes_invalid=0, reasoning="r", decision="confirmed_vulnerability",
                finding={"rule_id": "crit-tool-rule", "category": "sast",
                         "severity": "critical", "taint_type": "crit-tool-rule",
                         "source": "", "sink": "", "sink_line": 1},
                vulnerability_type="CWE-94 Improper Control of Generation of Code"),
            AdjudicationVerdict(
                confirmed=True, confidence=1.0, votes_true=3, votes_false=0,
                votes_invalid=0, reasoning="r", decision="confirmed_vulnerability",
                finding={"rule_id": "other-rule", "category": "sast",
                         "severity": "medium", "taint_type": "other-rule",
                         "source": "", "sink": "", "sink_line": 2},
                vulnerability_type="CWE-94 Improper Control of Generation of Code"),
        ]
        try:
            _ts2._aggregate(_res2, "x = 1\n")
            ok_t1src = ("CWE-94" in _res2.vulnerability_type
                        and any("CWE-94" in t for t in (_res2.vulnerability_types or [])))
        except Exception as _e:
            ok_t1src = False
            print(f"      异常: {type(_e).__name__}: {_e}")
    print(f"[{'PASS' if ok_t1src else 'FAIL'}] §8.9#2 top1 同源化(票型>注册表): "
          f"top1={_res2.vulnerability_type!r} vts={_res2.vulnerability_types!r} (期望 CWE-94)")

    # 21) 待办1（2026-08-30）：_infer_taint_type 证据上下文剥离——行上下文只说明
    #     "在哪里"，不说明"是什么"。hard_cve_03 实锤：request-data-write 的告警
    #     描述不含任何 sink 词，但附带的行上下文含 open(/extractall → 被撞词成
    #     Path Traversal 过白名单逃过剔除，带着错误类型标注进裁决诱导模型投票。
    rdw_rule = "models.semgrep_rules.python.request-data-write"
    rdw_ctx = ToolFinding(rule_id=rdw_rule, category="sast", source="", sink="",
                          taint_type=rdw_rule, source_line=8, sink_line=8,
                          severity="medium", tool="semgrep",
                          evidence="Found user-controlled request data passed into "
                                   "'.write(...)'.\n[告警行上下文]\n"
                                   "8:@app.route(\"/extract\")\n9:open(tmp)\n10:tar.extractall(...)")
    rdw_clean = ToolFinding(rule_id=rdw_rule, category="sast", source="", sink="",
                            taint_type=rdw_rule, source_line=8, sink_line=8,
                            severity="medium", tool="semgrep",
                            evidence="Found user-controlled request data passed into '.write(...)'.")
    claimed_ctx = TwoStageScanner._infer_taint_type(rdw_ctx.to_dict())
    claimed_clean = TwoStageScanner._infer_taint_type(rdw_clean.to_dict())
    ok_strip = (claimed_ctx not in _STANDARD_TAINT_TYPES      # 不再伪装成白名单类型
                and claimed_ctx == claimed_clean              # 有无上下文结论一致
                and claimed_clean == rdw_rule)                # 语义中立 → 保留原标注
    print(f"[{'PASS' if ok_strip else 'FAIL'}] 待办1 证据上下文剥离: 带上下文={claimed_ctx!r} "
          f"不带={claimed_clean!r} (均应为规则号且不落白名单)")
    # 剥离后落白名单外 → 无主剔除照常生效（转 LLM 兜底），且剔除留痕落实例
    kept_strip = object.__new__(TwoStageScanner)
    kept_strip._dropped_unowned_rules = []
    kept_strip2 = kept_strip._drop_irrelevant_positional([rdw_ctx])
    ok_strip = ok_strip and kept_strip2 == [] \
        and kept_strip._dropped_unowned_rules == [rdw_rule]
    print(f"[{'PASS' if ok_strip else 'FAIL'}] 待办1 剔除+留痕: kept={len(kept_strip2)}, "
          f"dropped_unowned={kept_strip._dropped_unowned_rules}")
    # 长尾类型推断分支（白名单扩容配套）：典型告警语义词 → 正确类型
    ok_tail = all([
        TwoStageScanner._infer_taint_type({"taint_type": "B405", "rule_id": "B405",
            "evidence": "Using xml.etree.ElementTree to parse untrusted XML data "
                        "is known to be vulnerable to XML attacks"}) == "XXE",
        TwoStageScanner._infer_taint_type({"taint_type": "ldap-rule", "rule_id": "ldap-rule",
            "evidence": "User input in LDAP filter construction"}) == "LDAP Injection",
        TwoStageScanner._infer_taint_type({"taint_type": "nosql-rule", "rule_id": "nosql-rule",
            "evidence": "MongoDB query built from request data"}) == "NoSQL Injection",
        # 2026-08-30 逐条审查补的 6 个分支：
        TwoStageScanner._infer_taint_type({"taint_type": "B307", "rule_id": "B307",
            "evidence": "Use of possibly insecure function - consider using safer "
                        "ast.literal_eval."}) == "Code Injection",
        TwoStageScanner._infer_taint_type({"taint_type": "B506", "rule_id": "B506",
            "evidence": "Use of unsafe yaml load. Allows instantiation of arbitrary "
                        "objects. Consider yaml.safe_load()."}) == "Insecure Deserialization",
        TwoStageScanner._infer_taint_type({"taint_type": "B605", "rule_id": "B605",
            "evidence": "Starting a process with a shell: Seems safe, but may be "
                        "changed in the future, consider rewriting without shell"}) == "Command Injection",
        TwoStageScanner._infer_taint_type({"taint_type": "B311", "rule_id": "B311",
            "evidence": "Standard pseudo-random generators are not cryptographically "
                        "secure."}) == "Weak Cryptography",
        TwoStageScanner._infer_taint_type({"taint_type": "spel-rule", "rule_id": "spel-rule",
            "evidence": "Detection of SpEL expression injection"}) == "SpEL Injection",
        TwoStageScanner._infer_taint_type({"taint_type": "B202", "rule_id": "B202",
            "evidence": "tarfile.extractall used without any validation. Please check "
                        "and discard dangerous members."}) == "Path Traversal",
        # 负样本：literal_eval（安全推荐写法）与 evaluate 不被词边界误伤
        TwoStageScanner._infer_taint_type({"taint_type": "safe-rule", "rule_id": "safe-rule",
            "evidence": "ast.literal_eval is the recommended safe alternative"}) == "safe-rule",
        TwoStageScanner._infer_taint_type({"taint_type": "safe-rule", "rule_id": "safe-rule",
            "evidence": "The parsed result is evaluated and cached for reuse"}) == "safe-rule",
    ])
    print(f"[{'PASS' if ok_tail else 'FAIL'}] 待办1 长尾类型推断: XXE/LDAP/NoSQL 分支")

    # 22) §五之四 抑制留痕（2026-08-30）：候选被抑制池跳过时 stage1 字典留痕
    #     suppressed_by_registry——"工具层零召回"由此可归因（没命中 vs 命中后被抑制），
    #     消除静默性；且受保护的自有链级规则（taint_tracker:*）不被抑制。
    with tempfile.TemporaryDirectory() as _td2:
        _reg2 = SignalRegistry(path=Path(_td2) / "reg.json", enabled=True)
        for _f in ("a.py", "b.py"):     # ≥2 独立文件全票否决 → 普通规则进抑制池
            _reg2.record("B888-T", confirmed=False, n=3, votes_true=0, votes_false=3,
                         votes_invalid=0, file=_f)
        _ts2 = TwoStageScanner(client=FakeClient(outputs), system_prompt="sys",
                               use_semgrep=False, use_taint_tracker=False,
                               use_prefilter=False, use_external=False,
                               sampling_rate=0, use_conformal=False,
                               use_signal_feedback=False, use_counterfactual=False)
        _ts2._signal_registry = _reg2
        _sup_finding = ToolFinding(rule_id="B888-T", category="sast", source="", sink="",
                                   taint_type="B888-T", source_line=1, sink_line=1,
                                   severity="medium", tool="bandit", evidence="x")
        _own_finding = ToolFinding(rule_id="taint_tracker:SQL Injection", category="taint",
                                   source="request.args.get('q')", sink="cursor.execute(q)",
                                   taint_type="SQL Injection", source_line=1, sink_line=2,
                                   path=["q"], severity="high", tool="taint_tracker")

        def _fake_recall(code, language, filename):
            return _ts2._dedupe(_ts2._apply_signal_registry([_sup_finding, _own_finding]))

        _ts2._stage1_recall = _fake_recall
        _r2s = _ts2.scan_code("x = 1\n", "python", "sup.py")
        # B888-T 被跳过并留痕；自有 taint 链级候选保留（§五之四保护，即便被
        # 全票否决 2 次也不进抑制池——本例它根本未被否定，保护读端兜底）
        ok_trace = (_r2s.findings and _r2s.findings[0].rule_id == "taint_tracker:SQL Injection"
                    and _r2s.stage1.get("suppressed_by_registry", {}).get("rule_ids") == ["B888-T"])
    print(f"[{'PASS' if ok_trace else 'FAIL'}] §五之四 抑制留痕: "
          f"suppressed_by_registry={_r2s.stage1.get('suppressed_by_registry')}, "
          f"剩余候选={[f.rule_id for f in _r2s.findings]}")

    # 23) §8.9 第 3 项：vulnerability_types 元素统一过 normalize_cwe_label。
    #     同一 CWE 的两套官方名（"CWE-78 OS Command Injection" vs
    #     "CWE-78 Command Injection"）此前在**裁决主分支**直接入库，仅兜底复核
    #     分支归一化 → 前端两处显示同一漏洞两个名字。归一化后重复项由保序去重合并。
    _ts3 = TwoStageScanner(client=FakeClient(
        ['```json\n{"is_confirmed": true, "reason": "拼接未净化", '
         '"vulnerability_type": "CWE-78 OS Command Injection"}\n```'] * 3
        + ['```json\n{"is_confirmed": true, "reason": "拼接未净化", '
           '"vulnerability_type": "CWE-78 Command Injection"}\n```'] * 3),
        system_prompt="sys", n_samples=3,
        use_semgrep=False, use_taint_tracker=False, use_prefilter=False,
        use_external=False, sampling_rate=0, use_conformal=False,
        use_signal_feedback=False, use_counterfactual=False)
    _c1 = ToolFinding(rule_id="B605", category="sast", source="request.args['h']",
                      sink="os.system(cmd)", taint_type="Command Injection",
                      source_line=1, sink_line=2, severity="high", tool="bandit")
    _c2 = ToolFinding(rule_id="B602", category="sast", source="request.args['h']",
                      sink="subprocess.Popen(cmd, shell=True)",
                      taint_type="Command Injection",
                      source_line=1, sink_line=5, severity="high", tool="bandit")
    _ts3._stage1_recall = lambda code, language, filename: [_c1, _c2]
    # 样本代码须自带外部输入入口：否则确定性证据门（门 2，无输入入口）会把两条
    # 候选拦下转人工复核，vulnerability_types 恒空——门本身是对的，是构造问题。
    _r3 = _ts3.scan_code(
        "from flask import request\n"
        "import os, subprocess\n"
        "def run():\n"
        "    h = request.args.get('h')\n"
        "    os.system('ping ' + h)\n",
        "python", "cmdi.py")
    ok_tnorm = _r3.vulnerability_types == ["CWE-78 Command Injection"]
    print(f"[{'PASS' if ok_tnorm else 'FAIL'}] §8.9 类型归一化: "
          f"vulnerability_types={_r3.vulnerability_types} "
          f"(期望 ['CWE-78 Command Injection']，两条候选为同一 CWE 的两套官方名)")

    # --- 用例 #24（2026-08-31 第四波）：长尾注入族 prefilter 规则端到端 ---
    # 8 条规则各自的命中 / 安全对照不命中；prefilter 候选的 taint_type 直通
    # _stage1_recall（不落 _PREFILTER_TYPE 之外的类型，防"Detected"退化）。
    ok_wave4 = True
    _pf = Prefilter()
    _w4_rules = {r.name: r for r in _pf.vuln_rules}
    _w4_cases = [
        ("xxe_unprotected_parse",
         "from flask import request\nfrom lxml import etree\n"
         "p = etree.XMLParser()\nroot = etree.fromstring(request.get_data(), parser=p)\n",
         True),
        ("xxe_unprotected_parse",
         "from lxml import etree\n"
         "p = etree.XMLParser(resolve_entities=False, no_network=True)\n"
         "root = etree.fromstring(data, parser=p)\n", False),
        ("ldap_injection",
         "import ldap\nu = request.args.get('u')\n"
         "f = f'(uid={u})'\n"
         "conn = ldap.initialize('ldap://x')\n"
         "conn.search_s('dc=x', ldap.SCOPE_SUBTREE, f)\n", True),
        ("ldap_injection",
         "import ldap\nu = request.args.get('u')\n"
         "conn.search_s('dc=x', ldap.SCOPE_SUBTREE, '(uid=%s)', [u])\n", False),
        ("nosql_query_injection",
         "from pymongo import MongoClient\nu = request.form.get('u')\n"
         "db.users.find_one({'user': u, 'pass': p})\n", True),
        ("xpath_injection",
         "x = f\"//user[username='{u}']\"\nr = tree.xpath(x)\n", True),
        ("php_loose_compare", "<?php\nif ($u_token == $expected) { }\n"
         "$u_token = $_GET['token'];\n", True),
        ("php_loose_compare", "<?php\nif ($_POST['p'] == $_POST['c']) {}\n", False),
        ("mass_assignment_setattr",
         "data = request.get_json()\n"
         "for key, value in data.items():\n    setattr(user, key, value)\n", True),
        ("deser_fastjson",
         "import com.alibaba.fastjson.JSON;\nObject o = JSON.parseObject(body);\n",
         True),
        ("ognl_expression_injection",
         "String m = \"Error: \" + request.getHeader(\"C-Type\");\n"
         "Object r = Ognl.getValue(m, ctx, null);\n", True),
    ]
    for _name, _code, _want in _w4_cases:
        _hit = _w4_rules[_name].match(_code)
        if _hit != _want:
            ok_wave4 = False
            print(f"  [FAIL] {_name}: hit={_hit} (期望 {_want})")
    print(f"[{'PASS' if ok_wave4 else 'FAIL'}] 第四波长尾注入族: "
          f"{len(_w4_cases)} 例（XXE/LDAP/NoSQL/XPath/PHP/setattr/fastjson/OGNL）")

    # --- 用例 #25（2026-08-31）：三档定向复核 + 工具层盲区提醒 --------------
    # 背景：大仓库里 no_candidate_mode="full_recheck" 对每个无候选文件都做
    # 全文件 × min(3,n) 票，成本随文件数线性爆炸。定向复核按"文件风险分 ×
    # 盲区命中"分配注意力，零盲区文件不送 LLM。
    class _RecClient:
        """记录每次调用的 prompt，用于验证"是否真的没调 LLM"与注入内容。"""

        def __init__(self, outputs):
            self.outputs = outputs
            self.i = 0
            self.prompts: list[str] = []

        def generate(self, **kwargs):
            self.prompts.append(kwargs.get("prompt", "") or "")
            out = self.outputs[self.i % len(self.outputs)]
            self.i += 1
            return {"text": out, "error": None}

    def _mk_targeted(code_replies, n_samples=3, sampling_rate=0.0):
        # sampling_rate 显式传 0：C 档抽样是随机行为，测试必须确定性。
        # （抽样本身有单独用例 25a-2 验证）
        return TwoStageScanner(
            client=_RecClient(code_replies), system_prompt="sys", n_samples=n_samples,
            use_semgrep=False, use_taint_tracker=False, use_prefilter=False,
            use_external=False, no_candidate_mode="targeted", sampling_rate=sampling_rate,
            use_conformal=False, use_signal_feedback=False, use_counterfactual=False)

    _safe_v = '{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "None"}'
    _vuln_v = ('{"has_vulnerability": true, "vulnerability_type": "CWE-639", '
               '"risk_level": "High", "explanation": "无归属校验"}')

    # 25a) C 档：零盲区的纯计算文件 → 一次 LLM 都不该调
    _zero = "\n".join(f"v{i} = {i} * 2 + 1" for i in range(1, 40))
    ts_c = _mk_targeted([_safe_v])
    rc = ts_c.scan_code(_zero, "python", "utils/calc.py")
    ok_t_c = (rc.stage1["decision"] == "no_candidate_no_blind_spot"
              and rc.has_vulnerability is False
              and len(ts_c.client.prompts) == 0)   # 关键：零 LLM 调用
    print(f"[{'PASS' if ok_t_c else 'FAIL'}] 定向复核 C 档（零盲区不调 LLM）: "
          f"decision={rc.stage1['decision']}, has_vuln={rc.has_vulnerability}, "
          f"LLM 调用={len(ts_c.client.prompts)} 次（期望 0）")

    # 25a-2) 零盲区但**高风险分** → 降 B 档，仍要送 LLM。
    #   这是 targeted 的关键安全阀：盲区表覆盖的是"工具写不了规则"的形态，
    #   而 SQL 注入/命令注入这类工具本该召回的形态并不在表里。文件有实际攻击面
    #   （外部源+sink+入口点，风险分高）却零召回，是**工具失效的信号**，
    #   比"文件没内容"更值得复核——否则就是静默放行。
    _sqli = ("import sqlite3\nfrom flask import request\n\n"
             "@app.route('/s')\ndef search():\n"
             "    q = request.args.get('q')\n"
             "    conn = sqlite3.connect('t.db')\n"
             "    rows = conn.execute(\"SELECT * FROM t WHERE n = '\" + q + \"'\")\n"
             "    return rows\n")
    ts_c2 = _mk_targeted([_safe_v])
    rc2 = ts_c2.scan_code(_sqli, "python", "app/api/search.py")
    _re_c2 = rc2.stage1.get("recheck") or {}
    ok_t_c2 = (_re_c2.get("tier") == "B"
               and _re_c2.get("reason") == "zero_spot_but_high_risk"
               and len(ts_c2.client.prompts) == 1)   # 送了，且只 1 票
    print(f"[{'PASS' if ok_t_c2 else 'FAIL'}] 零盲区但高风险分（安全阀）: "
          f"tier={_re_c2.get('tier')}(期望 B), reason={_re_c2.get('reason')}, "
          f"风险分={_re_c2.get('risk_score')}, LLM 调用={len(ts_c2.client.prompts)}（期望 1）")

    # 25a-3) C 档抽样：sampling_rate=1.0 时零盲区低危文件也送（在线监控漏报率）
    ts_c3 = _mk_targeted([_safe_v], sampling_rate=1.0)
    rc3 = ts_c3.scan_code(_zero, "python", "utils/calc.py")
    _re_c3 = rc3.stage1.get("recheck") or {}
    ok_t_c3 = (_re_c3.get("tier") == "B"
               and _re_c3.get("reason") == "c_tier_sampled"
               and len(ts_c3.client.prompts) == 1)
    print(f"[{'PASS' if ok_t_c3 else 'FAIL'}] C 档抽样复核（漏报率监控）: "
          f"tier={_re_c3.get('tier')}(期望 B), reason={_re_c3.get('reason')}, "
          f"LLM 调用={len(ts_c3.client.prompts)}（期望 1）")

    # 25b) A 档：高危路径 + 越权盲区 → 盲区片段 × min(3,n) 票，且用定向上下文
    # 样本须足够长（尾部补 24 行无关工具函数）：build_review_context 有收益闸门
    # （片段须比原文省 40% 以上才启用定向）——7 行小样本的片段=全文件+header，
    # 永远过不了闸门，定向恒回退整文件（2026-08-31 修复：该用例上线即 FAIL，
    # 因样本过短而非功能缺陷；片段闸门本身是防"定向不省反费"的正确设计）。
    _idor = ("from flask import request\n"
             "from app.models import Order\n"
             "@app.route('/order')\n"
             "def view_order():\n"
             "    oid = request.args.get('order_id')\n"
             "    order = Order.query.get(oid)\n"
             "    return render(order)\n"
             + "".join(
                 f"def _util_{i}(a, b):\n"
                 f"    total = (a or 0) + (b or 0)\n"
                 f"    if total > 10:\n"
                 f"        return round(total * 0.9, 2)\n"
                 f"    return total\n\n"
                 for i in range(1, 9)))
    ts_a = _mk_targeted([_safe_v] * 3)
    ra = ts_a.scan_code(_idor, "python", "app/api/auth/order.py")
    _re_a = ra.stage1.get("recheck") or {}
    # 送进 LLM 的必须是**盲区片段**（build_review_context 打的 "盲区片段" 头），
    # 而不是整文件——这是定向复核"省时间"的来源。
    _a_prompt = ts_a.client.prompts[0] if ts_a.client.prompts else ""
    ok_t_a = (_re_a.get("tier") == "A" and _re_a.get("n") == 3
              and _re_a.get("targeted_context") is True
              and "盲区片段" in _a_prompt
              and ra.stage1["decision"] in
              ("no_candidate_recheck_safe", "recheck_incomplete_flow_review"))
    print(f"[{'PASS' if ok_t_a else 'FAIL'}] 定向复核 A 档: tier={_re_a.get('tier')}, "
          f"n={_re_a.get('n')}, 定向上下文={_re_a.get('targeted_context')}, "
          f"prompt 含盲区片段={'盲区片段' in _a_prompt}, "
          f"decision={ra.stage1['decision']}")

    # 25c) B 档：低危路径 + 低优先级盲区 → 单票；单票判真**不得采信**（转人工）
    # 样本须是"真低危"：无入口点、无外部源，仅有一个弱随机盲区。
    # （用 _idor 不行——它虽在 utils/ 下但内容密度分仍很高，会落到 A 档）
    _low = ("import random\n"
            "def gen_id():\n"
            "    return str(random.random())[:8]\n")
    ts_b = _mk_targeted([_vuln_v])
    rb = ts_b.scan_code(_low, "python", "utils/legacy_helper.py")
    _re_b = rb.stage1.get("recheck") or {}
    ok_t_b = (_re_b.get("tier") == "B" and _re_b.get("n") == 1
              and rb.has_vulnerability is None          # 未被采信为漏洞
              and rb.stage1["decision"] == "recheck_low_conf_review")
    print(f"[{'PASS' if ok_t_b else 'FAIL'}] 定向复核 B 档（单票不采信）: "
          f"tier={_re_b.get('tier')}, n={_re_b.get('n')}, "
          f"has_vuln={rb.has_vulnerability}（期望 None）, "
          f"decision={rb.stage1['decision']}")

    # 25d) blind_spots 写进 stage1（可审计），且盲区片段带原始行号
    ok_t_bs = (ra.stage1.get("blind_spots", {}).get("count", 0) > 0
               and any(s["category"] == "authorization"
                       for s in ra.stage1["blind_spots"]["spots"]))
    print(f"[{'PASS' if ok_t_bs else 'FAIL'}] 盲区留痕: "
          f"count={ra.stage1.get('blind_spots', {}).get('count')}, "
          f"类别={[s['category'] for s in ra.stage1.get('blind_spots', {}).get('spots', [])]}")

    # 25e) 有候选时盲区提醒注入裁决 prompt（零额外调用），且只注入一次
    _ts_bs = TwoStageScanner(
        client=_RecClient(['```json\n{"is_confirmed": false, "reason": "已参数化"}\n```'] * 6),
        system_prompt="sys", n_samples=3,
        use_semgrep=False, use_taint_tracker=False, use_prefilter=False,
        use_external=False, sampling_rate=0, no_candidate_mode="targeted",
        use_conformal=False, use_signal_feedback=False, use_counterfactual=False)
    _f = ToolFinding(rule_id="B608", category="sast", source="request.args.get('id')",
                     sink="cursor.execute(q)", taint_type="SQL Injection",
                     source_line=2, sink_line=4, severity="high", tool="bandit")
    _ts_bs._stage1_recall = lambda code, language, filename: [_f, _f]
    _ts_bs.scan_code(_idor, "python", "app/api/auth/order.py")
    # 两个候选 × 3 票 = 6 次裁决调用（+3 次裁决全否决兜底复核，用 build_user_prompt
    # 不含提醒）。盲区提醒只注入首个裁决档候选 → 恰好 n_samples 次调用含提醒。
    _injected = sum(1 for p in _ts_bs.client.prompts if "工具层盲区提醒" in p)
    ok_t_inj = _injected == _ts_bs.n_samples
    print(f"[{'PASS' if ok_t_inj else 'FAIL'}] 盲区注入裁决（零额外调用、只注首个候选）: "
          f"总调用={len(_ts_bs.client.prompts)}, 含提醒={_injected}"
          f"（期望 {_ts_bs.n_samples}=n_samples）")

    # 25f) 盲区永不进抑制池：盲区扫描/注入后 SignalRegistry 不得新增任何信号。
    # 用临时 registry 隔离（默认路径会加载生产历史的 62 条信号，与本用例无关）。
    from graduation_project.signal_registry import reset_signal_registry
    import tempfile as _tf
    _reg_bs = reset_signal_registry(
        path=Path(_tf.mkdtemp()) / "reg.json", enabled=True)
    _before = _reg_bs.stats()["signals_total"]
    ts_c2 = _mk_targeted([_safe_v] * 3)
    ts_c2._signal_registry = _reg_bs
    ts_c2.scan_code(_idor, "python", "app/api/auth/order.py")
    ok_t_noreg = _reg_bs.stats()["signals_total"] == _before
    print(f"[{'PASS' if ok_t_noreg else 'FAIL'}] 盲区不进抑制池: "
          f"扫描前={_before} → 扫描后={_reg_bs.stats()['signals_total']}（期望不变）")

    # 25g) use_blind_spots=False 时完全不注入（论文消融开关）
    ts_off = _mk_targeted([_safe_v] * 3)
    ts_off.use_blind_spots = False
    r_off = ts_off.scan_code(_idor, "python", "app/api/auth/order.py")
    ok_t_off = (not any("工具层盲区提醒" in p for p in ts_off.client.prompts)
                and "blind_spots" not in (r_off.stage1 or {}))
    print(f"[{'PASS' if ok_t_off else 'FAIL'}] 盲区开关可关（消融）: "
          f"注入={any('工具层盲区提醒' in p for p in ts_off.client.prompts)}"
          f"（期望 False）, stage1 含 blind_spots="
          f"{'blind_spots' in (r_off.stage1 or {})}（期望 False）")

    # --- 用例 #26（2026-08-31，§9.19）：secret 候选凭证强度门槛的对称性 ------
    # 门槛此前只接 sast 通道（B105），gitleaks/detect-secrets 原生 secret 候选
    # 完全绕过——detect-secrets 修复绝对路径缺陷后弱值（admin123）直出抢 top1
    # （五段实锤）。门槛语义必须按"凭证内容强度"统一，不分工具：
    #   弱值 secret → category 转 sast 裁决档（与 B105 弱值对称）
    #   真凭证 secret → 保持直出 + 类型规范化 Hardcoded Credentials
    ts_sec = TwoStageScanner.__new__(TwoStageScanner)
    _sec_weak = ToolFinding(rule_id="Secret Keyword", category="secret", source="",
                            sink="", taint_type="Secret Keyword", source_line=4,
                            sink_line=4, severity="high", tool="detect-secrets",
                            evidence='检测到疑似密钥: Secret Keyword\n[命中行] password = "admin123"')
    _sec_strong = ToolFinding(rule_id="aws-access-key-id", category="secret", source="",
                              sink="", taint_type="aws-access-key-id", source_line=3,
                              sink_line=3, severity="high", tool="gitleaks",
                              evidence='AWS Access Key\n[命中行] key = "AKIAIOSFODNN7EXAMPLE"')
    _kept_sec = ts_sec._drop_irrelevant_positional([_sec_weak, _sec_strong])
    _by_rule = {f.rule_id: f for f in _kept_sec}
    ok_secret_gate = (
        _by_rule["Secret Keyword"].category == "sast"
        and _by_rule["Secret Keyword"].taint_type == "Hardcoded Credentials"
        and _by_rule["aws-access-key-id"].category == "secret"
        and _by_rule["aws-access-key-id"].taint_type == "Hardcoded Credentials")
    print(f"[{'PASS' if ok_secret_gate else 'FAIL'}] secret 凭证门槛对称性: "
          f"弱值→{_by_rule['Secret Keyword'].category}/"
          f"{_by_rule['Secret Keyword'].taint_type}（期望 sast/Hardcoded Credentials）, "
          f"真凭证→{_by_rule['aws-access-key-id'].category}/"
          f"{_by_rule['aws-access-key-id'].taint_type}（期望 secret/Hardcoded Credentials）")

    print("\n", "=== 自检通过 ===" if all([ok_parse, ok_dedupe, ok_adjud, ok_safe,
          ok_direct, ok_full, ok_rag_default, ok_gate1, ok_gate2, ok_gate3,
          ok_recheck_type, ok_anchor, ok_majority, ok_entry, ok_noleak,
          ok_wire, ok_chain, ok_b3, ok_b3b, ok_dedupe3, ok_dedupe4, ok_dedupe5,
          ok_rawtype, ok_strip, ok_tail, ok_trace, ok_tnorm, ok_wave4,
          ok_t_c, ok_t_c2, ok_t_c3, ok_t_a, ok_t_b, ok_t_bs, ok_t_inj,
          ok_t_noreg, ok_t_off, ok_secret_gate, ok_t1src])
          else "=== 存在失败用例 ===")
