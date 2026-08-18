"""
CWE 标号自动纠正工具。

背景：模型输出 vulnerability_type（如 "CWE-89 SQL注入"）时，语义分类（是
SQL 注入还是命令注入）通常正确，但 CWE *编号* 是纯记忆任务，容易记错
（如把 SQL 注入写成 CWE-29）。本工具在模型输出之后做确定性纠正：从输出
文本中识别语义漏洞类型，覆盖为规范 CWE 标签。

设计要点：
- 纯 Python 查表 + 关键词匹配，**不进模型上下文、不增加任何 token/资源消耗**；
- 只识别本表覆盖的常见漏洞类型；表外长尾（CWE-117 日志注入、CWE-327 弱密码
  学、CSRF 等）**原样返回，不做破坏性覆盖**；
- 幂等：输入已是规范标签时输出不变。
- 适用于所有"LLM 直接输出 vulnerability_type"的场景（/api/analyze、batch、
  url、github、vllm、multi-model），在两阶段扫描中同样复用（喂入 tool 派生的
  taint_type）。
"""

from __future__ import annotations

import re

# (关键词列表, 规范 CWE 标签)。按"更具体优先"排列，避免子串歧义。
# 关键词同时覆盖中英文，均为较独特子串，不与其它类别互相包含。
# 标签统一为 CWE 官方标准英文名（与旧管道模型输出风格一致）。
_CWE_BY_KEYWORD: list[tuple[tuple[str, ...], str]] = [
    # 2026-08-18 补：NoSQL 注入须在 "sql" 之前——"nosql"/"no sql" 含 "sql" 子串，
    # 原顺序会把 NoSQL 注入误归一为 CWE-89（应为 CWE-943 NoSQL 注入）。
    (("nosql", "no sql", "no-sql"), "CWE-943 Improper Neutralization of Special Elements in Data Query Logic"),
    (("sql", "sql注入"), "CWE-89 SQL Injection"),
    (("command injection", "命令注入", "cmdi"), "CWE-78 Command Injection"),
    (("code injection", "代码注入", "codei"), "CWE-94 Code Injection"),
    # 表达式语言注入（SPEL/OGNL/EL 等）：CWE-917 是 CWE-94 的子类（更精确）。
    # 模型对 SPEL/OGNL 类漏洞常输出更精确的 917，而测试集旧标注用父类 94；
    # 归一后统一到 917，配合 cwe_family_match 的父子族宽松匹配（strict 口径）。
    (("expression language injection", "expression injection", "expression language", "spel", "ognl", "表达式注入"), "CWE-917 Improper Neutralization of Special Elements in Data Query Logic"),
    (("insecure deserialization", "反序列化", "deserial", "pickle"), "CWE-502 Deserialization of Untrusted Data"),
    (("cross-site", "cross site", "xss", "跨站"), "CWE-79 Cross-Site Scripting"),
    (("path traversal", "directory traversal", "路径穿越", "path_traversal"), "CWE-22 Path Traversal"),
    # SSTI 统一归一到 CWE-1336（与 87 合成集 / CVE-fix 测试集的严格评估标注一致）。
    # 注意：CWE-94（Code Injection）是 CWE-1336 的父类编号，旧归一曾用 CWE-94，
    # 会造成 UI 显示层与严格评估层对"SSTI 正确编号"给出不同答案，故改为 1336。
    (("server-side template injection", "模板注入", "ssti"), "CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine"),
    (("log injection", "日志注入", "logi"), "CWE-117 Improper Output Neutralization for Logs"),
    # 认证/会话/凭证类（2026-08-17 补，供 normalize_with_evidence 从分析文本二次
    # 提取类型时使用——这些类型模型常分析对但标号记错或直接落工具 rule_id）：
    (("cross-site request forgery", "csrf", "跨站请求伪造"), "CWE-352 Cross-Site Request Forgery"),
    (("session fixation", "会话固定"), "CWE-384 Session Fixation"),
    (("hardcoded credential", "hardcoded secret", "hardcoded token", "硬编码凭据", "硬编码凭证"), "CWE-798 Use of Hard-Coded Credentials"),
    (("jwt", "json web token"), "CWE-347 Improper Verification of Cryptographic Signature"),
]

# 短规则 ID 类关键词：裸子串会误命中 "logical"、"cmdi_xxx" 等上下文，
# 用 \b 词边界收紧为独立词。
_BOUNDED_KEYWORDS = frozenset({"cmdi", "codei", "logi"})


def normalize_cwe_label(raw: str) -> str:
    """纠正模型输出的 CWE 标号。

    Args:
        raw: 模型输出的 vulnerability_type（如 "CWE-29 SQL注入"、"SQL Injection"、
            "none"、""、None）。

    Returns:
        规范 CWE 标签（如 "CWE-89 SQL注入"）；无法从文本识别语义类型时原样返回
        （不改动表外长尾类型）。输入为 none/空时返回 "none"。
    """
    if not raw:
        return "none"
    text = raw.strip()
    if not text or text.lower() == "none":
        return "none"
    lowered = text.lower()
    for keywords, label in _CWE_BY_KEYWORD:
        for k in keywords:
            if k in _BOUNDED_KEYWORDS:
                if re.search(rf"\b{re.escape(k)}\b", lowered):
                    return label
            elif k in lowered:
                return label
    return text


# 父子族映射（strict 匹配宽松口径，2026-08-17）：CWE 是树形分类，子类漏洞
# 本质上也属于父类。模型报子类、测试集标父类（或反之）应算"同族命中"。
# 典型：CWE-917（表达式注入）⊂ CWE-94（代码注入）；CWE-1336（SSTI）⊂ CWE-94；
# CWE-80（XSS）⊂ CWE-79。子类编号 → 直接父类编号。
_CWE_PARENT_OF: dict[str, str] = {
    "CWE-917": "CWE-94",
    "CWE-1336": "CWE-94",
    "CWE-80": "CWE-79",
}


def normalize_with_evidence(vulnerability_type: str, evidence: str = "") -> str:
    """vulnerability_type 为空/落规则 ID/表外类型时，用分析文本（explanation/reason）
    二次提取漏洞类型（2026-08-17）。

    场景：模型分析文本写对了（"构成 CSRF"/"硬编码凭证"），但 vulnerability_type
    字段记错编号（CWE-639）或直接落工具 rule_id（B608）。此时字段文本无法纠正，
    但 evidence 里有关键词。

    优先级（防覆盖模型明确判断）：
      1. 字段命中表内语义关键词 → 直接用规范标签（含同义纠正，如 "SQL注入"→89）；
      2. 字段未命中（空/rule_id/表外如 CWE-639 Authorization Bypass）→ 用 evidence
         关键词二次提取，命中返回规范标签；
      3. 都未命中 → normalize_cwe_label 原样返回（不破坏性覆盖表外类型）。

    Args:
        vulnerability_type: 模型输出的类型字段（可能为 ""/None/rule_id/乱码/表外编号）。
        evidence: 模型的分析文本（reason/explanation），可为空。

    Returns:
        规范 CWE 标签；无法识别时与 normalize_cwe_label 语义一致。
    """
    def _hit(text: str, keywords: tuple) -> bool:
        for k in keywords:
            if k in _BOUNDED_KEYWORDS:
                if re.search(rf"\b{re.escape(k)}\b", text.lower()):
                    return True
            elif k in text.lower():
                return True
        return False

    field = (vulnerability_type or "").strip()
    if field and field.lower() != "none":
        for keywords, label in _CWE_BY_KEYWORD:
            if _hit(field, keywords):
                return label  # 字段明确命中表内语义 → 用字段（不被 evidence 覆盖）
    if evidence:
        for keywords, label in _CWE_BY_KEYWORD:
            if _hit(evidence, keywords):
                return label
    return normalize_cwe_label(vulnerability_type)


def cwe_family_match(reported: str, expected: str) -> bool:
    """判断两个 CWE 标签是否同族命中（编号相等或父子关系）。

    用于严格评估：模型报 CWE-917（SPEL 注入）而测试集标 CWE-94（代码注入）时，
    按严格"编号相等"会判不匹配，但 917 ⊂ 94 语义上确实命中。
    normalize 后调用；参数为 normalize_cwe_label 的输出（含 "CWE-编号 名称" 或
    原样文本），取纯编号比较。
    """
    def _num(s: str) -> str:
        m = re.search(r"CWE[- ]?(\d+)", s or "")
        return f"CWE-{m.group(1)}" if m else ""
    rn, en = _num(reported), _num(expected)
    if not rn or not en:
        return False
    if rn == en:
        return True
    # 子类命中父类（reported 是 expected 的后代）
    seen = set()
    cur = rn
    while cur in _CWE_PARENT_OF and cur not in seen:
        seen.add(cur)
        cur = _CWE_PARENT_OF[cur]
        if cur == en:
            return True
    # 父类命中子类（expected 是 reported 的后代）
    seen = set()
    cur = en
    while cur in _CWE_PARENT_OF and cur not in seen:
        seen.add(cur)
        cur = _CWE_PARENT_OF[cur]
        if cur == rn:
            return True
    return False


if __name__ == "__main__":
    print("=== CWE 标号纠正自检（离线） ===\n")
    cases = [
        # (输入, 期望输出)
        ("CWE-29 SQL注入", "CWE-89 SQL Injection"),          # 编号记错 → 纠正
        ("CWE-89 sql injection", "CWE-89 SQL Injection"),     # 英文 → 规范英文
        ("SQL Injection", "CWE-89 SQL Injection"),
        ("命令注入", "CWE-78 Command Injection"),
        ("CWE-78 Command Injection", "CWE-78 Command Injection"),
        ("cmdi", "CWE-78 Command Injection"),                        # 规则 ID 短词 → 词边界命中
        ("codei", "CWE-94 Code Injection"),
        ("logi", "CWE-117 Improper Output Neutralization for Logs"),
        ("logical bug", "logical bug"),                              # "logi" 不应匹配 "logical"
        ("cmdispatch", "cmdispatch"),                                # "cmdi" 不应匹配 "cmdispatch"
        ("Path Traversal", "CWE-22 Path Traversal"),
        ("XSS", "CWE-79 Cross-Site Scripting"),
        ("Insecure Deserialization", "CWE-502 Deserialization of Untrusted Data"),
        ("Server-Side Template Injection", "CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine"),
        ("CWE-89 Log Injection", "CWE-117 Improper Output Neutralization for Logs"),  # 编号错 + 语义正确 → 纠正
        ("日志注入", "CWE-117 Improper Output Neutralization for Logs"),
        ("CWE-117 日志注入", "CWE-117 Improper Output Neutralization for Logs"),
        ("CSRF", "CWE-352 Cross-Site Request Forgery"),
        ("none", "none"),
        ("", "none"),
        (None, "none"),
    ]
    ok = True
    for raw, exp in cases:
        got = normalize_cwe_label(raw)
        passed = got == exp
        ok = ok and passed
        print(f"[{'PASS' if passed else 'FAIL'}] {raw!r} -> {got!r} (期望 {exp!r})")
    print(f"\n{'全部通过' if ok else '存在失败'}")
