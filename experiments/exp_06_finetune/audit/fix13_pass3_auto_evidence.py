# -*- coding: utf-8 -*-
"""从 review 证据自动提取行号修正映射,为剩余 FIX 条目生成 evidence 级 reline ops。

只对【仍含旧锚 token】的字段下手;映射不明确/字段不含锚 → 跳过留给人工批。
输出: out/fix13_ops_pass3_auto_evidence.jsonl
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
OUT = Path(__file__).resolve().parent / "agent_audit_v2_14" / "out"

import glob as g
wb = [json.loads(l) for l in (OUT / "fix13_workbench.jsonl").open(encoding="utf-8")]
done = set()
_base = OUT / "fix13_ops_pass3.jsonl"
_opfiles = [str(_base)] if _base.exists() else []
_opfiles += sorted(g.glob(str(OUT / "fix13_ops_pass3_b*.json")))
def load_ops(f):
    txt = open(f, encoding="utf-8").read().strip()
    if not txt:
        return []
    if txt.startswith("["):
        return json.loads(txt)
    return [json.loads(l) for l in txt.split("\n") if l.strip()]

done_ids_fields = set()
for f in _opfiles:
    for o in load_ops(f):
        done.add(o["id"])
        if "field" in o:
            done_ids_fields.add((o["id"], o["field"]))
        if "fields" in o:
            for fld in o["fields"]:
                done_ids_fields.add((o["id"], fld))
p1 = {}
for l in (OUT / "fix13_ops_pass1.jsonl").open(encoding="utf-8"):
    o = json.loads(l)
    if o["op"] == "reline":
        p1.setdefault((o["id"], o["field"]), []).extend(o["moves"])

# 证据中的映射对:『line X:...』实际(在|为)? L?Y / 『第X行...』实际 Y
PAIRS = [
    re.compile(r"[「`\"]?line\s*(\d{1,4})[」`\"：:][^。；;\n]{0,80}?实际(?:在|为)?\s*(?:line\s*)?L?(\d{1,4})\b"),
    re.compile(r"[「`\"]?line\s*(\d{1,4})[」`\"：:][^。；;\n]{0,40}——实际(?:在|为)?\s*(?:line\s*)?L?(\d{1,4})\b"),
    re.compile(r"「([^「」]{2,40})」实际(?:在)?\s*L?(\d{1,4})\b"),
]
FIELD_TOKENS = {
    "source": lambda t: re.findall(r"line\s*(\d{1,4})", t),
    "sink": lambda t: re.findall(r"line\s*(\d{1,4})", t),
    "fix_suggestion": lambda t: re.findall(r"line\s*(\d{1,4})", t),
    "explanation": lambda t: re.findall(r"line\s*(\d{1,4})|第\s*(\d{1,4})\s*行", t),
}

def get_moves(field_text, pairs):
    toks = FIELD_TOKENS[field_text and "x" and "source"]  # placeholder unused
    return []

ops = []
skipped = []
for it in wb:
    rid = it["id"]
    if rid in done:
        continue
    ev = "；".join(e["evidence"] for e in it["review_errors"])
    pairs = []
    for pat in PAIRS[:2]:
        for m in pat.finditer(ev):
            old, new = int(m.group(1)), int(m.group(2))
            if 0 < new <= len(it["code_lines"]) and old != new:
                pairs.append((old, new))
    # 模式3:『<引语含 第X行/line X>」实际 Y』 —— 旧行号从引语内提取
    for m in PAIRS[2].finditer(ev):
        new = int(m.group(2))
        inner = m.group(1)
        mo = re.search(r"(?:line\s*|第\s*)(\d{1,4})", inner, re.I)
        if mo:
            old = int(mo.group(1))
            if 0 < new <= len(it["code_lines"]) and old != new:
                pairs.append((old, new))
    if not pairs:
        continue
    tj = it["teacher_json"] or {}
    for fld in ("source", "sink", "fix_suggestion", "explanation"):
        t = str(tj.get(fld, "") or "")
        if not t:
            continue
        olds = sorted({o for o, n in pairs if re.search(rf"line\s*{o}\b", t) or re.search(rf"第\s*{o}\s*行", t)})
        if not olds:
            continue
        # 已有该字段的处理(pass1/pass3 任意批)则跳过避免冲突
        if (rid, fld) in p1 or (rid, fld) in done_ids_fields:
            continue
        moves = [[o, n] for o, n in pairs if o in olds]
        ops.append({"id": rid, "op": "reline", "field": fld, "moves": moves,
                    "method": "evidence_auto", "why": "证据映射自动提取:" + ";".join(f"{o}->{n}" for o, n in moves)})

with (OUT / "fix13_ops_pass3_auto_evidence.jsonl").open("w", encoding="utf-8") as f:
    for o in ops:
        f.write(json.dumps(o, ensure_ascii=False) + "\n")
from collections import Counter
print("auto evidence relines:", len(ops), "| fields:", dict(Counter(o["field"] for o in ops)),
      "| ids:", len({o['id'] for o in ops}))
