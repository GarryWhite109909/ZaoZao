# -*- coding: utf-8 -*-
"""把 g20 信任边界辨析组蒸馏产出合并进 v2_15。

1. 从 _wave1_out/success.jsonl 过滤 orig 以 "g20-" 开头的记录
2. 产出 corpus/repair_wave/g20_trust_boundary.jsonl（溯源包）
3. 查重(归一 md5) + 契约校验后追加进 v2_15，source_pack=g20/trust_boundary
4. 自检
产出 audit/adjudicate_v2_15/merge_g20_out.txt
"""
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]  # exp_06_finetune/
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
OUT_WAVE = BASE / "corpus/repair_wave/_wave1_out/success.jsonl"
PACK = BASE / "corpus/repair_wave/g20_trust_boundary.jsonl"
OUT_LOG = BASE / "audit/adjudicate_v2_15/merge_g20_out.txt"

CONTRACT = ["has_vulnerability", "vulnerability_type", "risk_level",
            "source", "sink", "explanation", "fix_suggestion"]
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)

LOG = []
def P(*a):
    LOG.append(" ".join(str(x) for x in a))

def norm_md5(s):
    return hashlib.md5(re.sub(r"\s+", "", s).encode()).hexdigest()

# 收集 g20 蒸馏产出
g20_recs = []
origs = Counter()
if OUT_WAVE.exists():
    for l in OUT_WAVE.open(encoding="utf-8"):
        if not l.strip():
            continue
        rec = json.loads(l)
        o = str(rec.get("fix_distill", {}).get("orig", ""))
        if o.startswith("g20-"):
            g20_recs.append(rec)
            origs[o] += 1
P(f"g20 蒸馏产出: {len(g20_recs)} 条 | {dict(origs)}")
if not g20_recs:
    P("!! 无 g20 产出，退出")
    OUT_LOG.write_text("\n".join(LOG) + "\n", encoding="utf-8")
    sys.exit(1)

# 写溯源包
with PACK.open("w", encoding="utf-8") as f:
    for rec in g20_recs:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
P(f"溯源包: {PACK.name}")

# 查重集合
lines = DATA.read_text(encoding="utf-8").split("\n")
user_md5, assist_md5 = set(), set()
for l in lines:
    if not l.strip():
        continue
    rec = json.loads(l)
    user_md5.add(norm_md5(rec["messages"][1]["content"]))
    assist_md5.add(norm_md5(rec["messages"][2]["content"]))

# 合并
appended, dupe, bad_contract = 0, 0, 0
for rec in g20_recs:
    msgs = rec["messages"]
    if len(msgs) != 3:
        bad_contract += 1
        continue
    blk = JSON_BLOCK.findall(msgs[2]["content"])
    ok = False
    if blk:
        try:
            ok = list(json.loads(blk[-1]).keys()) == CONTRACT
        except Exception:
            ok = False
    if not ok:
        bad_contract += 1
        P(f"  !! {rec.get('fix_distill', {}).get('orig')}: 契约不符，跳过")
        continue
    um, am = norm_md5(msgs[1]["content"]), norm_md5(msgs[2]["content"])
    if um in user_md5 or am in assist_md5:
        dupe += 1
        continue
    rec.setdefault("fix_distill", {})["source_pack"] = "g20/trust_boundary"
    lines.append(json.dumps(rec, ensure_ascii=False))
    user_md5.add(um); assist_md5.add(am)
    appended += 1
P(f"追加 {appended} / 查重拦截 {dupe} / 契约拒 {bad_contract}")

DATA.write_text("\n".join(lines), encoding="utf-8")

# 自检
n = 0
hv = Counter()
bad_json = 0
for l in lines:
    if not l.strip():
        continue
    n += 1
    rec = json.loads(l)
    try:
        o = json.loads(JSON_BLOCK.findall(rec["messages"][2]["content"])[-1])
        hv[str(o.get("has_vulnerability"))] += 1
    except Exception:
        bad_json += 1
P(f"自检: v2_15 总条数 {n} | JSON 失败 {bad_json} | 正负 {dict(hv)}")
(OUT_LOG).write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("\n".join(LOG))
