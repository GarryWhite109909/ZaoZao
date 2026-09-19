# -*- coding: utf-8 -*-
"""DeepSeek 叙事体 → 结构化记录适配器"""
import json, re
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
src = (BASE / "corpus/diffpair_wave1/results/result.txt").read_text(encoding="utf-8")
blocks = re.split(r"(?=### diffpair-)", src)
records = []

for b in blocks:
    hm = re.match(r"### (diffpair-\S+) (版本A|版本B)", b)
    if not hm:
        continue
    sid, ver = hm.group(1), hm.group(2)
    rec_id = f"{sid}-{'PRE' if ver == '版本A' else 'POST'}"

    cv = re.search(r"结论[:：]\s*存在漏洞=(\w+)\s*\|\s*(CWE-\d+[^|]*|无)\s*\|\s*(\w+)", b)
    if not cv:
        cv = re.search(r"存在漏洞=(\w+).*?(CWE-\d+|none).*?(\w+)", b)
    has_v = cv.group(1) == "true" if cv else None
    cwe = cv.group(2).strip() if cv else "none"
    risk = cv.group(3) if cv else "Medium"

    entry = re.search(r"入口[:：]\s*(.+?)(?=\n链|\n防御|\n载荷|\n组合|\n锚句|\n结论|\n修复|\n- |\Z)", b, re.S)
    chain = re.search(r"链[:：]\s*(.+?)(?=\n防御|\n载荷|\n组合|\n锚句|\n结论|\n修复|\n- |\Z)", b, re.S)
    dfns = re.search(r"防御[:：]\s*(.+?)(?=\n载荷|\n组合|\n锚句|\n结论|\n修复|\n- |\Z)", b, re.S)
    attrib = re.search(r"行归因[:：]\s*(.+?)(?=\n锚句|\n结论|\n修复|\n- |\Z)", b, re.S)

    records.append({
        "id": rec_id, "orig_id": sid, "version": ver,
        "has_vulnerability": has_v, "cwe": cwe, "risk": risk,
        "entry": (entry.group(1).strip()[:300] if entry else ""),
        "chain": (chain.group(1).strip()[:400] if chain else ""),
        "defense": (dfns.group(1).strip()[:600] if dfns else ""),
        "attribution": (attrib.group(1).strip()[:300] if attrib else ""),
    })

print(f"适配出 {len(records)} 条记录")
pre = [r for r in records if r["version"] == "版本A"]
post = [r for r in records if r["version"] == "版本B"]
print(f"PRE: {len(pre)} | POST: {len(post)}")
has_v_count = sum(1 for r in records if r["has_vulnerability"] is not None)
print(f"有判定: {has_v_count}/{len(records)}")

out = BASE / "corpus/diffpair_wave1/parsed/deepseek_adapter.jsonl"
with out.open("w", encoding="utf-8", newline="\n") as f:
    for r in records:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
print(f"→ {out}")
