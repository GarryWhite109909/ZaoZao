#!/usr/bin/env python3
"""v2.8 补充审计 IV：#4692 型"自白式错标"全库定向扫描。"""
import json
import re
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data/final_train_chatml_alpha06_v2_8.jsonl"
OUT = Path(__file__).resolve().parent / "_audit_v2_8_extra4_out.txt"
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)

rows = [json.loads(l) for l in DATA.read_text(encoding="utf-8").splitlines() if l.strip()]
buf = []
def w(s=""):
    buf.append(str(s))

# 自白式措辞：教师明确表示标签与自己的判断不符
CONFESS = [
    "根据指令", "指令要求", "应标记为", "标注为有漏洞", "标注为无漏洞",
    "实际不安全", "实际无漏洞", "实际存在漏洞", "实际没有漏洞",
    "被要求", "任务指定", "要求为 false", "要求为 true", "要求为false", "要求为true",
    "此处结论为", "但标注为", "标签应为", "本应标记", "本应标注", "按题目要求",
]
hits = []
for i, r in enumerate(rows):
    a = r["messages"][2]["content"]
    m = JSON_RE.search(a)
    obj = None
    if m:
        try:
            obj = json.loads(m.group(1))
        except Exception:
            pass
    found = [t for t in CONFESS if t in a]
    if found:
        # 提取命中上下文
        ctxs = []
        for t in found[:2]:
            p = a.find(t)
            ctxs.append(a[max(0, p - 50): p + 100].replace("\n", " "))
        hv = obj.get("has_vulnerability") if obj else "?"
        hits.append((i, hv, found, ctxs))

w(f"自白式措辞命中: {len(hits)} 条")
for i, hv, found, ctxs in hits:
    w(f"\n#{i} hv={hv} 命中={found}")
    for c in ctxs:
        w(f"   ...{c}...")

OUT.write_text("\n".join(buf), encoding="utf-8")
print(f"hits={len(hits)}")
