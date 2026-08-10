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
    (("sql", "sql注入"), "CWE-89 SQL Injection"),
    (("command injection", "命令注入", "cmdi"), "CWE-78 Command Injection"),
    (("code injection", "代码注入", "codei"), "CWE-94 Code Injection"),
    (("insecure deserialization", "反序列化", "deserial", "pickle"), "CWE-502 Deserialization of Untrusted Data"),
    (("cross-site", "cross site", "xss", "跨站"), "CWE-79 Cross-Site Scripting"),
    (("path traversal", "directory traversal", "路径穿越", "path_traversal"), "CWE-22 Path Traversal"),
    # SSTI 统一归一到 CWE-1336（与 87 合成集 / CVE-fix 测试集的严格评估标注一致）。
    # 注意：CWE-94（Code Injection）是 CWE-1336 的父类编号，旧归一曾用 CWE-94，
    # 会造成 UI 显示层与严格评估层对"SSTI 正确编号"给出不同答案，故改为 1336。
    (("server-side template injection", "模板注入", "ssti"), "CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine"),
    (("log injection", "日志注入", "logi"), "CWE-117 Improper Output Neutralization for Logs"),
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
        ("CSRF", "CSRF"),
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
