#!/usr/bin/env python3
"""终扫：'应为 true/false' 类第 5 种供词句式。"""
import json
import re
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data/final_train_chatml_alpha06_v2_9.jsonl"
rows = [json.loads(l) for l in DATA.read_text(encoding="utf-8").splitlines() if l.strip()]
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)

PAT = re.compile(r"应(?:该)?(?:输出|判定|为|填|标)[^。\n]{0,8}(true|false|有漏洞|无漏洞|漏洞|安全)|has_vulnerability\s*应为|应判为")
hits = []
for i, r in enumerate(rows):
    a = r["messages"][2]["content"]
    for mm in PAT.finditer(a):
        s = max(0, mm.start() - 60)
        ctx = a[s: mm.end() + 100].replace("\n", " ")
        m = JSON_RE.search(a)
        hv = None
        if m:
            try:
                hv = json.loads(m.group(1)).get("has_vulnerability")
            except Exception:
                pass
        hits.append((i, hv, ctx))
        break

print(f"命中 {len(hits)}")
for i, hv, ctx in hits:
    print(f"\n#{i} hv={hv}\n   ...{ctx}...")
