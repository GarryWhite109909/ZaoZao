#!/usr/bin/env python3
"""v2.7 审计第六段：收尾核验。"""
import json
import re
from collections import Counter
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data/final_train_chatml_alpha06_v2_7.jsonl"
OUT = Path(__file__).resolve().parent / "_audit_v2_7_probe6_out.txt"
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)

rows = [json.loads(l) for l in DATA.read_text(encoding="utf-8").splitlines() if l.strip()]
buf = []
def w(s=""):
    buf.append(str(s))

# 1) 新增层 risk_level 词表
rl = Counter()
for i in range(8639, 8778):
    m = JSON_RE.search(rows[i]["messages"][2]["content"])
    if m:
        obj = json.loads(m.group(1))
        rl[obj.get("risk_level")] += 1
w(f"新增层 risk_level: {dict(rl)}")

# 全库小写 risk 复查
rl_all = Counter()
for i, r in enumerate(rows):
    m = JSON_RE.search(r["messages"][2]["content"])
    if m:
        try:
            obj = json.loads(m.group(1))
        except Exception:
            continue
        if obj.get("has_vulnerability") is True and "is_confirmed" not in obj:
            rl_all[obj.get("risk_level")] += 1
w(f"全库 vuln risk_level: {dict(rl_all)}")

# 2) #1752 结构
a = rows[1752]["messages"][2]["content"]
w(f"\n#1752 assistant 前 600: {a[:600]!r}")
w(f"#1752 assistant 总长 {len(a)}, JSON 块位置 {[m.start() for m in JSON_RE.finditer(a)]}")
m = JSON_RE.search(a)
obj = json.loads(m.group(1))
w(f"#1752 obj: {json.dumps(obj, ensure_ascii=False)[:400]}")

# 3) #8060 vs #8076 判定核对（同 user）
for i in (8060, 8076):
    m = JSON_RE.search(rows[i]["messages"][2]["content"])
    obj = json.loads(m.group(1))
    w(f"#{i} hv={obj.get('has_vulnerability')} vt={obj.get('vulnerability_type')}")

# 4) assistant 以代码块开头（无 CoT）的样本数
import re as _re
no_cot = []
for i, r in enumerate(rows):
    a = r["messages"][2]["content"]
    if a.lstrip().startswith("```") and not a.lstrip().startswith("```json"):
        no_cot.append(i)
w(f"\nassistant 以代码块开头: {len(no_cot)} 条 {no_cot[:15]}")

# 5) 空间统计：source/sink 字段带 'L1:' 文件前缀的样本数
pref = 0
for i, r in enumerate(rows):
    m = JSON_RE.search(r["messages"][2]["content"])
    if m:
        try:
            obj = json.loads(m.group(1))
        except Exception:
            continue
        if str(obj.get("source", "")).startswith("L") and ":" in str(obj.get("source", ""))[:4]:
            pref += 1
w(f"source 字段带 L<n>: 前缀: {pref} 条")

OUT.write_text("\n".join(buf), encoding="utf-8")
print("written")
