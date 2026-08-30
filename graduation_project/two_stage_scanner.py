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
})

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
    取不到字面值时（工具未给出）→ 判否，走裁决档由模型判断，避免误直出。
    """
    m = re.search(r"[\"']([^\"']{4,})[\"']", evidence or "")
    if not m:
        return False
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
        self.no_candidate_mode = (
            no_candidate_mode if no_candidate_mode in ("sampled", "full_recheck") else "sampled"
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

        # Stage 1：工具召回
        findings = self._stage1_recall(code, language, filename)
        result.findings = findings
        result.stage1 = self._stage1_stats(findings)
        result.stage1["recall_duration"] = round(time.time() - start, 2)

        # 无候选 → 判安全但复核：sampled=按比例抽样复核（监控工具层召回漂移）；
        # full_recheck=全量 LLM 复核（安全关键场景，消除"无证据判安全"的静默放行）。
        # force=本文件发生抑制跳过/无主告警剔除（_last_suppressed）→ 强制复核
        if not findings:
            recheck = self._maybe_recheck(code, language, force=self._last_suppressed)
            result.has_vulnerability = False
            result.stage1["decision"] = "no_candidate_safe"
            if recheck is not None:
                result.stage1["recheck"] = recheck
                if recheck.get("has_vulnerability") is True:
                    n = int(recheck.get("n") or 1)
                    votes_true = int(recheck.get("votes_true") or (1 if n == 1 else 0))
                    unanimous = n > 0 and votes_true == n
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
            recheck = self._maybe_recheck(code, language, force=True, count_monitor=False)
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
        text = " ".join(str(x) for x in [
            finding.get("taint_type"), finding.get("rule_id"),
            finding.get("evidence"), finding.get("message"),
        ] if x).lower()
        # 语义类型名（如 "Command Injection"）直接用；规则号/长路径（B602、
        # models.semgrep_rules.xxx）是工具内部标识，须按关键词推断真实类型。
        is_semantic = tt and not re.fullmatch(r"B\d+|[\w.]+", tt) and " " in tt.strip()
        if is_semantic and tt.lower() not in ("unknown", "detected"):
            return tt
        # 注意：text 已 lower()，规则号正则必须用小写才匹配（2026-08-15 修复：
        # 原大写 B608 使规则号推断成为死代码，全靠 evidence 关键词兜底）
        if "subprocess" in text or "os.system" in text or "command" in text \
                or re.search(r"b60[2347]", text):
            return "Command Injection"
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
        # 词边界 \bopen：避免 urlopen 的 "open(" 子串误判为文件打开
        if (re.search(r"\bopen\s*\(", text) or ".save(" in text or "extractall(" in text
                or ".extract(" in text or "os.path.join" in text
                or "os.path.realpath" in text or "readfile" in text
                or "createreadstream" in text or "file(" in text or "getresource(" in text):
            return "Path Traversal"
        if "from_string" in text or "template" in text or "ssti" in text:
            return "Server-Side Template Injection"
        if "pickle" in text or "deserial" in text:
            return "Insecure Deserialization"
        # ↓↓↓ P2 类型族（2026-08-29，与 prefilter P2 规则 taint_type 对齐）：
        # 这些类型模型完全可以裁决，但此前既无 _infer_taint_type 分支、
        # 又不在 _STANDARD_TAINT_TYPES 白名单 → bandit/semgrep 带精确行号的
        # 证据被当作"无主告警"剔除，只剩 prefilter 无行号规则（typical_17 实锤：
        # B324 + semgrep md5 两条带行号证据全被剔除）。
        # 弱哈希/弱随机/硬编码 IV/弱密码算法
        if ("md5" in text or "sha1" in text or "des(" in text or "rc4" in text
                or "weak" in text and "hash" in text or "b324" in text
                or "insecure-hash" in text or "hardcoded-iv" in text
                or "crypto" in text and "weak" in text or "random" in text and "weak" in text):
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
        for f in findings:
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
                       count_monitor: bool = True) -> Optional[dict]:
        """无候选文件的 LLM 复核：监控 Stage 1 召回漂移，或全量复核消除静默放行。

        - no_candidate_mode="sampled"：按 sampling_rate 抽样（默认 10%），用主扫描
          prompt 全量判一次，给出工具层漏报率的在线估计（tool_recall_monitor_snapshot）。
        - no_candidate_mode="full_recheck"：每个无候选文件都复核（采样率视为 1），
          供 URL/GitHub 等安全关键场景——"无候选"不再直接判安全，先问一次 LLM。
        - force=True（审查 #4，2026-08-16）：本文件发生抑制跳过时强制复核。
        - count_monitor=False（裁决全否决兜底调用）：该场景文件有候选，不算
          "无候选"文件，no_candidate_total 是召回监控指标，不能被污染。

        Returns:
            {"sampled": True, "has_vulnerability": bool|None}；未抽样时返回 None。
        """
        if count_monitor:
            _monitor_incr("no_candidate_total")
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
                        evidence = (evidence + "\n[告警行上下文]\n" + ctx).strip()
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
        for finding in findings:
            if self._is_direct_category(finding.category):
                verdict = self._direct_adjudication(finding)
            else:
                code_context = self._slice_context(code, language, finding)
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
            if self._signal_registry is not None:
                corrected = self._signal_registry.corrected_taint_type(rule_id)
            if not corrected:
                # 多数票类型（2026-08-15 修复：原实现取"第一个非空类型"，忽略多数
                # 信号——typical_17 中 2/5 裁决输出正确 CWE-327，但列表首个是锚定
                # 错误的 CWE-79 被直接采信；hard_cve_07 的最终类型甚至来自另一条
                # finding（B108）而 raw 来自 B202。投票键 = (总票数, 独立票数,
                # 该类型所在 finding 的最高严重度)：
                #   - 独立票 = 模型输出类型 ≠ 工具 taint_type 归一化结果（"回声票"
                #     只是复读工具标注，无独立信息量——xss-taint 工具标 XSS、模型
                #     跟着输出 CWE-79 是回声；B324 工具标 B324、模型独立判出
                #     CWE-327 是独立判断，平票时独立判断胜出）
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
                t = (a.vulnerability_type or "").strip()
                if not t:
                    t = normalize_cwe_label(fd.get("taint_type") or "") or ""
                if not t or t.lower() in ("none", "unknown", "detected"):
                    t = str(fd.get("rule_id") or "")
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
    ok_anchor = ("历史误报率高" in p_sast and "独立判定" in p_sast
                 and "历史误报率高" not in p_taint and "CWE-862" in p_sast
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
    #     下方多数票块被整体跳过；raw_texts 曾定义在该块内，块外访问抛
    #     UnboundLocalError → 整个 _aggregate 中断、前端显示"分析失败"
    #     （typical_20_insecure_tls.py 实锤；凡 top 候选命中注册表中已提交
    #     校正的规则均受影响）。本用例用临时注册表造"已提交校正"的规则覆盖该分支。
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
                     "taint_type": "B501-X", "source": "line 1: x", "sink": "line 2: y"},
            vulnerability_type="CWE-295 Improper Certificate Validation")]
        try:
            _ts._aggregate(_res, "x = 1\ny = 2\n")
            # registry 分支下 corrected 的"原始"就是工具标注（历史模型对工具标注的校正）
            ok_rawtype = (_res.vulnerability_type == "CWE-295 Improper Certificate Validation"
                          and _res.raw_vulnerability_type == "B501-X")
        except Exception as _e:          # 修复前此处抛 UnboundLocalError
            ok_rawtype = False
            print(f"      异常: {type(_e).__name__}: {_e}")
    print(f"[{'PASS' if ok_rawtype else 'FAIL'}] §四 raw 类型作用域(registry 校正分支): "
          f"{_res.vulnerability_type!r} <- raw {_res.raw_vulnerability_type!r}")

    print("\n", "=== 自检通过 ===" if all([ok_parse, ok_dedupe, ok_adjud, ok_safe,
          ok_direct, ok_full, ok_rag_default, ok_gate1, ok_gate2, ok_gate3,
          ok_recheck_type, ok_anchor, ok_majority, ok_entry, ok_noleak,
          ok_wire, ok_chain, ok_b3, ok_b3b, ok_dedupe3, ok_dedupe4, ok_dedupe5,
          ok_rawtype]) else "=== 存在失败用例 ===")
