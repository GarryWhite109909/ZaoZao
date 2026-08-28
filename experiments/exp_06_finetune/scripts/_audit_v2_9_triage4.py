#!/usr/bin/env python3
"""v2.9 深挖 IV：漏网供词句式终扫。"""
import json
import re
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data/final_train_chatml_alpha06_v2_9.jsonl"
rows = [json.loads(l) for l in DATA.read_text(encoding="utf-8").splitlines() if l.strip()]

CONFESS2 = ["根据要求", "按要求", "题目要求", "按任务", "指令要求", "被指定",
            "标记为无漏洞", "标记为有漏洞", "标为漏洞", "标为安全", "判定方向要求"]
hits = []
for i, r in enumerate(rows):
    a = r["messages"][2]["content"]
    f = [t for t in CONFESS2 if t in a]
    if f:
        p = a.find(f[0])
        hits.append((i, f, a[max(0, p - 60): p + 100].replace("\n", " ")))
print(f"命中 {len(hits)} 条")
for i, f, ctx in hits:
    print(f"#{i} {f}\n   ...{ctx}...")
