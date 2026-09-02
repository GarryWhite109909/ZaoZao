# -*- coding: utf-8 -*-
"""定位 6257:头匹配行 vs pack 全指纹,找分歧点。"""
import json, re, sys, hashlib
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
FENCE = re.compile(r"```[\w+#.\-/]*[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)
NUMPREFIX = re.compile(r"^\s*\d+\s*\|\s?")

def norm_code(c):
    return "".join("".join(c.split()).replace('"', "").replace("'", "").lower())
def strip_num(b):
    return "\n".join(NUMPREFIX.sub("", l) for l in b.split("\n"))

# pack 侧 6257 完整代码
txt = (Path("web_review_v3") / "pack_11.txt").read_text(encoding="utf-8")
parts = re.split(r"###\s*id=(\d+)[^\n]*\n\[CODE\]\n", txt)
pack_code = None
for k in range(1, len(parts) - 1, 2):
    if int(parts[k]) == 6257:
        pack_code = strip_num(parts[k + 1].split("[ANALYSIS]")[0])
nc_pack = norm_code(pack_code)
print(f"pack 6257 归一长度: {len(nc_pack)}")

# 全库:头 60 匹配的行
head60 = nc_pack[:60]
cands = []
for lineno, line in enumerate(open(DATA, encoding="utf-8"), 1):
    if not line.strip():
        continue
    rec = json.loads(line)
    ms = list(FENCE.finditer(rec["messages"][1]["content"]))
    if len(ms) != 1:
        continue
    nc_row = norm_code(ms[0].group(1))
    if nc_row.startswith(head60):
        cands.append((lineno, nc_row))
print(f"头60匹配行: {[c[0] for c in cands]}")
for lineno, nc_row in cands:
    # 找首分歧
    div = None
    for i, (x, y) in enumerate(zip(nc_pack, nc_row)):
        if x != y:
            div = i
            break
    if div is None:
        div = min(len(nc_pack), len(nc_row))
    print(f"  行{lineno}: 长度={len(nc_row)} 首分歧@{div}")
    print(f"    pack[{max(0,div-15)}:{div+25}] = {nc_pack[max(0,div-15):div+25]!r}")
    print(f"    row [{max(0,div-15)}:{div+25}] = {nc_row[max(0,div-15):div+25]!r}")
    # 行的 hv
    JB = re.compile(r"```json\s*(.*?)```", re.S)
    o = json.loads(JB.findall(json.loads(open(DATA, encoding='utf-8').read().split('\n')[lineno-1])['messages'][2]['content'])[-1])
    print(f"    hv={o.get('has_vulnerability')} vt={str(o.get('vulnerability_type'))[:40]}")
