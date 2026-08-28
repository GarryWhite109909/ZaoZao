#!/usr/bin/env python3
"""alpha06-v2.8 清洗构建（v2.7 外科手术版，2026-08-28）。

对外部审计（2026-08-28）P0/P1 项的确定性修复，全程无模型参与：

P0-1 生成元话语毒化（12 条剔除，逐条人工读原文确认）：
  T 毒（CoT 自认"无漏洞，为满足要求硬标"）：#38 #161 #203 #208 #243 #1382 #1752
  F 毒（CoT 论证存在漏洞，JSON 标 false——教模型放过真漏洞）：#3709 #3798 #4902
  机制编造（声称 off-by-one，官方 patch 实为 zip-slip 路径穿越）：#8639
P0-2 同 prompt 反向标签对（#8060 vs #8076）：种子 corpus_00150.py
  expected_present=True ⇒ 保留 #8060（方向正确），剔 #8076。
P1-3 vulnerability_type 格式归一：CWE-<num>[ :：]... → "CWE-<num> <官方名>"
  （约 25 个已知族；原描述中的括注/斜杠后缀保留），全量 old→new 进报告供复核。
P1-4 risk_level 大小写归一：{critical,high,medium,low} → 首字母大写（v2.3 回归）。
P2 附加：hv=true 且 fix_suggestion='no fix needed' 的 3 条剔除（契约自相矛盾）。

不动的（审计 P2/P3，决定记录而非手术）：
  safe 侧 92 条 sink 语义注记（教学意图好，2% 方差可接受，制度文档记为合法变体）；
  48 条无行号锚的依赖型 fix（语义可接受）；crossfile "L1:line N:" 三格式（消歧合理）；
  evidence 层行号引用门失真（门与切片行号前缀的口径问题，非数据错误）；风格异质性（训后观察）。
"""
import json
import re
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SRC = BASE / "data/final_train_chatml_alpha06_v2_7.jsonl"
OUT = BASE / "data/final_train_chatml_alpha06_v2_8.jsonl"
REPORT = BASE / "data/build_alpha06_v2_8_report.md"
CANONICAL = ["has_vulnerability", "vulnerability_type", "risk_level",
             "source", "sink", "explanation", "fix_suggestion"]

DROP = {38, 161, 203, 208, 243, 1382, 1752,          # T 毒
        3709, 3798, 4902,                            # F 毒
        8639,                                        # 机制编造
        8076}                                        # P0-2 反向半边

OFFICIAL = {
    "22": "Path Traversal", "78": "OS Command Injection", "77": "Command Injection",
    "79": "Cross-site Scripting (XSS)", "89": "SQL Injection", "94": "Code Injection",
    "502": "Deserialization of Untrusted Data",
    "611": "Improper Restriction of XML External Entity References",
    "352": "Cross-Site Request Forgery (CSRF)", "601": "URL Redirection to Untrusted Site (Open Redirect)",
    "798": "Use of Hard-coded Credentials", "862": "Missing Authorization",
    "639": "Authorization Bypass Through User-Controlled Key",
    "918": "Server-Side Request Forgery (SSRF)", "1336": "Improper Neutralization of Special Elements Used in a Template Engine",
    "327": "Use of a Broken or Risky Cryptographic Algorithm",
    "90": "Improper Neutralization of Special Elements in an LDAP Query",
    "117": "Improper Output Neutralization for Logs", "416": "Use After Free",
    "863": "Incorrect Authorization", "306": "Missing Authentication for Critical Function",
    "190": "Integer Overflow or Wraparound", "400": "Uncontrolled Resource Consumption",
    "434": "Unrestricted Upload of File with Dangerous Type", "441": "Unintended Proxy or Intermediary",
    "1427": "LLM Prompt Injection via Tool Invocation", "942": "Permissive Cross-origin Resource Sharing Policy",
}
RISK = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


def canonical_vt(vt: str):
    """CWE-<num>[ :：]<随意写法> → CWE-<num> <官方名>[ 保留的限定后缀]"""
    m = re.match(r"CWE-(\d+)\s*[:：]?\s*(.*)$", vt.strip(), re.S)
    if not m:
        return vt, False
    num, rest = m.group(1), (m.group(2) or "").strip()
    official = OFFICIAL.get(num)
    if not official:
        return vt, False
    if not rest:
        new = f"CWE-{num} {official}"
        return new, new != vt
    low_r, low_o = rest.lower(), official.lower()
    if low_r == low_o:
        return vt, False
    if low_r.startswith(low_o):
        # 主体就是官方名（含官方名自带括注），只保留其后的附加说明
        extra = rest[len(official):].strip()
        new = f"CWE-{num} {official}" + (f" {extra}" if extra else "")
        return new, new != vt
    # 其余写法（中文别名/裸名/错名）：重建为官方名，仅保留官方名中没有的
    # 尾部括注/斜杠限定（避免 (SSRF) 双写）
    tail = ""
    mt = re.search(r"([（(][^（）()]*[）)]|/[^/（(]+)$", rest)
    if mt and mt.group(1) not in official:
        tail = " " + mt.group(1)
    new = f"CWE-{num} {official}{tail}".strip()
    return new, new != vt


def main():
    recs = [json.loads(l) for l in SRC.read_text(encoding="utf-8").splitlines() if l.strip()]
    stats = {"in": len(recs), "drop_p0": 0, "drop_fixna": 0, "vt_norm": 0,
             "risk_norm": 0, "out": 0}
    vt_log, risk_log = [], []

    out = []
    for i, r in enumerate(recs):
        if i in DROP:
            stats["drop_p0"] += 1
            continue
        a = r["messages"][2]["content"]
        m = re.search(r"```json\s*(\{.*?\})\s*```", a, re.S)
        if not m:
            out.append(r)
            continue
        try:
            obj = json.loads(m.group(1))
        except json.JSONDecodeError:
            out.append(r)
            continue
        hv = obj.get("has_vulnerability")
        changed = False
        # P1-4 risk_level 大小写
        rl = obj.get("risk_level")
        if isinstance(rl, str) and rl.lower() in RISK and rl != RISK[rl.lower()]:
            risk_log.append((i, rl, RISK[rl.lower()]))
            obj["risk_level"] = RISK[rl.lower()]
            changed = True
            stats["risk_norm"] += 1
        # P1-3 类型格式（仅漏洞侧；安全侧保持 none）
        if hv is True:
            vt = obj.get("vulnerability_type")
            if isinstance(vt, str) and re.match(r"CWE-\d+", vt):
                new_vt, diff = canonical_vt(vt)
                if diff:
                    vt_log.append((i, vt, new_vt))
                    obj["vulnerability_type"] = new_vt
                    changed = True
                    stats["vt_norm"] += 1
            # P2 附加：漏洞却 no fix needed
            fs = str(obj.get("fix_suggestion", ""))
            if fs.strip().lower() == "no fix needed":
                stats["drop_fixna"] += 1
                continue
        if changed:
            ordered = {k: obj[k] for k in CANONICAL if k in obj}
            for k, v in obj.items():
                if k not in ordered:
                    ordered[k] = v
            new_a = a[:m.start()] + "```json\n" + \
                json.dumps(ordered, ensure_ascii=False) + "\n```" + a[m.end():]
            r["messages"][2]["content"] = new_a
        out.append(r)

    stats["out"] = len(out)
    with open(OUT, "w", encoding="utf-8") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    lines = [
        "# alpha06-v2.8 清洗构建报告\n",
        f"- 输入 v2.7 {stats['in']} → 输出 **{stats['out']}**",
        f"- P0 剔除 {stats['drop_p0']} 条（12 名单见脚本头注）| fix='no fix needed' 剔除 {stats['drop_fixna']} 条",
        f"- 类型格式归一 {stats['vt_norm']} 条 | risk_level 归一 {stats['risk_norm']} 条",
        "",
        "## 类型归一明细（人工复核用）",
    ]
    lines += [f"- #{i}: {old!r} → {new!r}" for i, old, new in vt_log]
    lines += ["", "## risk_level 归一明细"]
    lines += [f"- #{i}: {o!r} → {n!r}" for i, o, n in risk_log[:40]]
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines[:14]))
    print(f"报告: {REPORT}")


if __name__ == "__main__":
    main()
