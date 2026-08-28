#!/usr/bin/env python3
"""终验：毒词命中按方向过滤 + hv=False 侧的'漏洞成立'逐条裁定。"""
import json
import re
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data/final_train_chatml_alpha06_v2_9.jsonl"
rows = [json.loads(l) for l in DATA.read_text(encoding="utf-8").splitlines() if l.strip()]
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)

def get_obj(r):
    m = JSON_RE.search(r["messages"][2]["content"])
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except Exception:
        return None

CONFESS = ["根据指令", "指令要求", "应标记为", "标注为有漏洞", "标注为无漏洞", "实际不安全",
           "实际无漏洞", "被要求", "要求为 false", "要求为 true", "此处结论为", "但标注为",
           "本应标记", "按题目要求", "为满足", "需假设", "需修正", "已生成", "生成要求",
           "根据要求", "按要求必须", "标记为无漏洞", "标记为有漏洞", "整体不安全",
           "实际存在 CWE", "实际存在CWE", "漏洞成立", "负样本必须"]

susp = []  # hv=False 侧命中
benign_t = 0
for i, r in enumerate(rows):
    a = r["messages"][2]["content"]
    f = [t for t in CONFESS if t in a]
    if not f:
        continue
    obj = get_obj(r)
    hv = obj.get("has_vulnerability") if obj else None
    if hv is False:
        p = a.find(f[0])
        susp.append((i, f, a[max(0, p - 80): p + 120].replace("\n", " ")))
    else:
        benign_t += 1  # vuln 侧说漏洞成立 = 正常

print(f"hv=True 侧命中（正常结论表述）: {benign_t}")
print(f"hv=False 侧命中（需逐条裁定）: {len(susp)}")
for i, f, ctx in susp:
    print(f"\n#{i} {f}\n   ...{ctx}...")
