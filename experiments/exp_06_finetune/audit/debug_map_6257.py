# -*- coding: utf-8 -*-
"""调试 map_result_ids:为什么 6257 在 map 上下文中未命中。"""
import json, re, sys, hashlib
from pathlib import Path
from collections import defaultdict
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
PACKS = BASE / "audit/web_review_v3"  # BASE=exp_06_finetune
FENCE = re.compile(r"```[\w+#.\-/]*[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)
NUMPREFIX = re.compile(r"^\s*\d+\s*\|\s?")

def norm_code(c):
    return "".join("".join(c.split()).replace('"', "").replace("'", "").lower())

def strip_num(b):
    return "\n".join(NUMPREFIX.sub("", l) for l in b.split("\n"))

# 完全复刻 map 的提取
pack_ids = {}
for fn in sorted(PACKS.glob("pack_*.txt")):
    txt = fn.read_text(encoding="utf-8")
    parts = re.split(r"###\s*id=(\d+)[^\n]*\n\[CODE\]\n", txt)
    for k in range(1, len(parts) - 1, 2):
        wid = int(parts[k])
        seg = parts[k + 1]
        code = seg.split("[ANALYSIS]")[0]
        if wid not in pack_ids or len(code) > len(pack_ids[wid]):
            pack_ids[wid] = strip_num(code)

print("pack_ids 总数:", len(pack_ids))
c6257 = pack_ids.get(6257)
print("6257 pack 归一头60:", norm_code(c6257)[:60] if c6257 else None)
print("6257 pack 原始头60:", c6257[:60] if c6257 else None)

# 完全复刻 map 的 row_code 构建
row_code = {}
for lineno, line in enumerate(open(DATA, encoding="utf-8"), 1):
    if not line.strip():
        continue
    rec = json.loads(line)
    ms = list(FENCE.finditer(rec["messages"][1]["content"]))
    if len(ms) != 1:
        continue
    row_code[lineno] = norm_code(ms[0].group(1))

print("row_code 行数:", len(row_code))
print("row_code[6206]:", row_code.get(6206, "<无>")[:60])
nc = norm_code(c6257) if c6257 else ""
print("6257 归一:", nc[:60])
print("相等:", nc == row_code.get(6206))
# 全库找 6257 pack 归一指纹
hits = [ln for ln, nc2 in row_code.items() if nc2 == nc]
print("全库精确命中行:", hits[:5] if hits else "无")
