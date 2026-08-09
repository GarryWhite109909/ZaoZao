#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""全面清洗最终训练数据（exp_06 云端训练用）。

修复项（基于逐维度体检发现的问题）：
  1. CWE 标签归一化：100 个唯一标签 → 按 CWE 编号统一为官方标准英文名。
     修复同编号多写法（CWE-434 6种 / CWE-98 4种 / CWE-123、409 等）与中英文混用。
  2. user prompt 统一：两套格式（"分析以下代码" 5841 条 + "代码片段（文件名）" 1791 条）
     → 全部重建为 build_user_prompt(code, language, filename) 标准格式，与推理一致。
  3. system prompt 统一：统一为 BASE_PROMPT（与 evaluate.py 推理一致）。

用法：
  python3 clean_final.py \
      --in data/quality/final_train_chatml_quality.jsonl \
      --out data/quality/final_train_chatml_quality_clean.jsonl
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "文档/code/毕业设计"))
from graduation_project.prompts import BASE_PROMPT, build_user_prompt

# ---------------------------------------------------------------------------
# CWE 编号 → 官方标准英文名 映射（覆盖数据中出现的全部编号）
# ---------------------------------------------------------------------------
CWE_STANDARD = {
    89: "SQL Injection",
    78: "OS Command Injection",
    798: "Use of Hard-coded Credentials",
    79: "Cross-site Scripting (XSS)",
    77: "Command Injection",
    22: "Path Traversal",
    352: "Cross-Site Request Forgery (CSRF)",
    918: "Server-Side Request Forgery (SSRF)",
    502: "Deserialization of Untrusted Data",
    611: "Improper Restriction of XML External Entity References",
    90: "Improper Neutralization of Special Elements in an LDAP Query",
    190: "Integer Overflow or Wraparound",
    416: "Use After Free",
    862: "Missing Authorization",
    639: "Authorization Bypass Through User-Controlled Key",
    306: "Missing Authentication for Critical Function",
    117: "Improper Output Neutralization for Logs",
    601: "URL Redirection to Untrusted Site",
    732: "Incorrect Permission Assignment for Critical Resource",
    94: "Improper Control of Generation of Code ('Code Injection')",
    1336: "Improper Neutralization of Special Elements Used in a Template Engine",
    326: "Inadequate Encryption Strength",
    88: "Improper Neutralization of Argument Delimiters",
    134: "Use of Externally-Controlled Format String",
    912: "Backdoor",
    749: "Exposed Dangerous Method",
    276: "Incorrect Default Permissions",
    1188: "Insecure Default Permissions",
    95: "Improper Neutralization of Directives in Dynamically Evaluated Code",
    643: "Improper Neutralization of Data within XPath Expressions",
    327: "Use of a Broken or Risky Cryptographic Algorithm",
    384: "Session Fixation",
    120: "Buffer Copy without Checking Size",
    330: "Use of Insufficiently Random Values",
    121: "Stack-based Buffer Overflow",
    787: "Out-of-bounds Write",
    943: "Improper Neutralization of Special Elements in Data Query Logic",
    125: "Out-of-bounds Read",
    415: "Double Free",
    209: "Generation of Error Message Containing Sensitive Information",
    441: "Unintentional Proxy or Intermediary",
    367: "Time-of-check Time-of-use (TOCTOU) Race Condition",
    122: "Heap-based Buffer Overflow",
    1333: "Inefficient Regular Expression Complexity",
    362: "Concurrent Execution using Shared Resource with Improper Synchronization",
    434: "Unrestricted Upload of File with Dangerous Type",
    208: "Observable Timing Discrepancy",
    613: "Insufficient Session Expiration",
    73: "External Control of File Name or Path",
    915: "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    917: "Improper Neutralization of Special Elements used in an Expression Language",
    476: "NULL Pointer Dereference",
    347: "Improper Verification of Cryptographic Signature",
    329: "Not Using a Random IV with CBC Mode",
    98: "Improper Control of Filename for Include/Require",
    409: "Improper Handling of Highly Compressed Data",
    200: "Exposure of Sensitive Information",
    1321: "Improperly Controlled Modification of Object Prototype Attributes",
    843: "Access of Resource Using Incompatible Type",
    123: "Write-what-where Condition",
    295: "Improper Certificate Validation",
    204: "Observable Response Discrepancy",
    287: "Improper Authentication",
    113: "Improper Neutralization of CRLF Sequences",
    770: "Allocation of Resources without Limits",
    319: "Cleartext Transmission of Sensitive Information",
    401: "Missing Release of Memory after Effective Lifetime",
    93: "Improper Neutralization of CRLF Sequences",
    532: "Insertion of Sensitive Information into Log File",
    400: "Uncontrolled Resource Consumption",
    91: "XML Injection",
    610: "Externally Controlled Reference to a Resource in Another Sphere",
    797: "Improper Filtering of Special Elements",
    759: "Use of a One-Way Hash without a Salt",
}

# 编译：编号前缀 → 标准标签（用于替换 assistant JSON 与正文中的 CWE 提及）
_CWE_PATTERNS = []
for num, name in CWE_STANDARD.items():
    _CWE_PATTERNS.append(
        (re.compile(rf"CWE-{num}\b[^\"\n]*", re.IGNORECASE), f"CWE-{num} {name}")
    )


def normalize_cwe_text(text: str) -> str:
    """把文本中出现的 `CWE-<编号>任意后缀` 统一为标准 `CWE-<编号> <标准名>`。"""
    for pat, std in _CWE_PATTERNS:
        text = pat.sub(std, text)
    return text


def extract_code_and_meta(user: str) -> tuple[str, str, str, str]:
    """从 user 文本提取 (代码, 语言, 文件名)。返回 (code, lang, filename, 描述前文)。"""
    # 匹配代码块 ```lang\n...\n```
    m = re.search(r"```(\w*)\n(.*?)```", user, re.DOTALL)
    code = m.group(2) if m else ""
    lang = m.group(1) if m else "text"
    # 尝试提取文件名（代码片段（文件名: xxx，语言: yyy））
    fm = re.search(r"文件名:\s*([^，,)\s]+)", user)
    filename = fm.group(1) if fm else None
    return code, lang, filename, user


def clean_record(record: dict, stats: dict) -> dict:
    msgs = record["messages"]
    if len(msgs) != 3:
        stats["bad_msg_count"] += 1
        return record

    # 1) system 统一为 BASE_PROMPT
    if msgs[0]["content"] != BASE_PROMPT:
        stats["sys_changed"] += 1
        msgs[0]["content"] = BASE_PROMPT

    # 2) user 重建为 build_user_prompt 格式
    code, lang, filename, _ = extract_code_and_meta(msgs[1]["content"])
    new_user = build_user_prompt(code, language=lang, filename=filename)
    if new_user != msgs[1]["content"]:
        stats["user_changed"] += 1
        msgs[1]["content"] = new_user

    # 3) assistant：CWE 归一化（正文 + JSON 字段）
    old_assistant = msgs[2]["content"]
    new_assistant = normalize_cwe_text(old_assistant)
    if new_assistant != old_assistant:
        stats["cwe_changed"] += 1
        msgs[2]["content"] = new_assistant

    record["messages"] = msgs
    return record


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="data/quality/final_train_chatml_quality.jsonl")
    ap.add_argument("--out", dest="out", default="data/quality/final_train_chatml_quality_clean.jsonl")
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(args.inp, encoding="utf-8") if l.strip()]
    print(f"读取 {len(rows)} 条")

    stats = {
        "sys_changed": 0, "user_changed": 0, "cwe_changed": 0, "bad_msg_count": 0,
    }
    cleaned = [clean_record(r, stats) for r in rows]

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for r in cleaned:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"\n输出: {out} ({len(cleaned)} 条)")
    print(f"统计: {stats}")

    # 残留 CWE 标签检查（应只剩标准名 + none）
    from collections import Counter
    cwe_vals = Counter()
    for r in cleaned:
        a = r["messages"][2]["content"]
        m = re.search(r'"vulnerability_type":\s*"([^"]+)"', a)
        if m:
            cwe_vals[m.group(1).strip()] += 1
    print(f"\n清洗后唯一 CWE 标签数: {len(cwe_vals)}")
    # 检查是否还有非标准标签
    std_set = {f"CWE-{k} {v}" for k, v in CWE_STANDARD.items()} | {"none"}
    non_std = {k: v for k, v in cwe_vals.items() if k not in std_set}
    print(f"非标准标签数: {len(non_std)}")
    for k, v in list(non_std.items())[:20]:
        print(f"  ⚠️ \"{k}\": {v}")


if __name__ == "__main__":
    main()
