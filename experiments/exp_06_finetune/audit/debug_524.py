# -*- coding: utf-8 -*-
"""调试:524 的 pack 代码指纹 vs 全库行。"""
import json, re, sys, hashlib
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
AUD = Path(__file__).resolve().parent
BASE = AUD.parent
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
FENCE = re.compile(r"```[\w+#.\-/]*[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)
NUMPREFIX = re.compile(r"^\s*\d+\s*\|\s?")

def norm_code(code):
    return "".join("".join(code.split()).replace('"', "").replace("'", "").lower())

def strip_num(block):
    return "\n".join(NUMPREFIX.sub("", l) for l in block.split("\n"))

# pack_04 里 524 的代码
txt = (AUD / "web_review_v3" / "pack_04.txt").read_text(encoding="utf-8")
parts = re.split(r"###\s*id=(\d+)[^\n]*\n\[CODE\]\n", txt)
seg524 = None
for k in range(1, len(parts) - 1, 2):
    if int(parts[k]) == 524:
        seg524 = parts[k + 1]
if seg524 is None:
    print("pack_04 里没找到 524"); sys.exit(1)
code_pack = seg524.split("[ANALYSIS]")[0]
code_pack = strip_num(code_pack)
nc_pack = norm_code(code_pack)
print("pack 524 归一指纹头 100:", nc_pack[:100])

# 全库行逐个比
hit = []
for lineno, line in enumerate(open(DATA, encoding="utf-8"), 1):
    if not line.strip():
        continue
    rec = json.loads(line)
    ms = list(FENCE.finditer(rec["messages"][1]["content"]))
    if len(ms) != 1:
        continue
    nc_row = norm_code(ms[0].group(1))
    if nc_pack == nc_row:
        hit.append(lineno)
    elif nc_pack[:80] and nc_pack[:80] in nc_row:
        hit.append(("prefix", lineno))
print("精确命中行:", hit[:5] if hit else "无")
# 前缀命中
pref = nc_pack[:60]
pref_hits = []
for lineno, line in enumerate(open(DATA, encoding="utf-8"), 1):
    if not line.strip(): continue
    rec = json.loads(line)
    ms = list(FENCE.finditer(rec["messages"][1]["content"]))
    if len(ms) != 1: continue
    nc_row = norm_code(ms[0].group(1))
    if pref in nc_row:
        pref_hits.append(lineno)
print("前缀60命中行:", pref_hits[:5] if pref_hits else "无")
