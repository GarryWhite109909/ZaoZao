#!/usr/bin/env python3
"""v2.9 深挖 III：4 条高嫌疑样本全文裁定。"""
import json
import re
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data/final_train_chatml_alpha06_v2_9.jsonl"
OUT = Path(__file__).resolve().parent / "_audit_v2_9_triage3_out.txt"
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
CODE_RE = re.compile(r"```([\w+#./-]*)\n(.*?)\n```", re.S)

rows = [json.loads(l) for l in DATA.read_text(encoding="utf-8").splitlines() if l.strip()]
buf = []
def w(s=""):
    buf.append(str(s))

for i in (3690, 4726, 5271, 8560, 8565):
    r = rows[i]
    meta = r.get("meta") or {}
    a = r["messages"][2]["content"]
    m = JSON_RE.search(a)
    obj = json.loads(m.group(1)) if m else {}
    w(f"\n{'='*70}\n#{i} kind={meta.get('kind')} hv={obj.get('has_vulnerability')} vt={obj.get('vulnerability_type')}")
    w("EXPLANATION: " + str(obj.get("explanation")))
    w("SOURCE: " + str(obj.get("source")))
    w("SINK: " + str(obj.get("sink")))
    w("FIX: " + str(obj.get("fix_suggestion")))
    w("\nCoT 前 1200 字:")
    w(a[: m.start()][:1200])
    # 代码关键行
    blocks = CODE_RE.findall(r["messages"][1]["content"])
    if blocks:
        body = max(blocks, key=lambda x: len(x[1]))[1]
        w("\n代码前 600 字: " + body[:600])

OUT.write_text("\n".join(buf), encoding="utf-8")
print("written")
