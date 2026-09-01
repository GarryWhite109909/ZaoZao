# -*- coding: utf-8 -*-
"""把 v2_15a 批次的可回收增量并入当前 v2_15(wave1 修复基底)。

1. P0-A 改标 3 条(509/932/7547,v2_14 行号 → v2_15 行号重映射,old_guard 校验)
2. 追加 g9-g19 成品语料包(137 条,GLM-5.3-flash 产出,当时已过 dual/F8/锚句门)
   —— 元数据标注 source_pack 便于溯源
3. 查重(user/assistant 归一 md5)与自检
产出 audit/merge_v2_15_wave1_incr_out.txt;改动直接写回 v2_15。
"""
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
V2_14 = BASE / "data/final_train_chatml_alpha06_v2_14.jsonl"
CORPUS = BASE / "corpus/repair_wave"
AUD = BASE / "audit"
OUT_LOG = AUD / "merge_v2_15_wave1_incr_out.txt"

APPEND_PACKS = ["g9_1321", "g10_915", "g11_1336", "g12_1336_79", "g13_1336_134",
                "g14_priority", "g15_fromstring", "g17_priority_authz",
                "g18_authz_family", "g19_134_boundary", "g16_adjud_15a"]
CONTRACT = ["has_vulnerability", "vulnerability_type", "risk_level",
            "source", "sink", "explanation", "fix_suggestion"]
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)

RELABELS = {
    509:  {"new_cwe": "CWE-78", "old_guard": re.compile(r"CWE-134|格式串")},
    932:  {"new_cwe": "CWE-89", "old_guard": re.compile(r"CWE-1336|模板引擎|模板注入")},
    7547: {"new_cwe": "CWE-79", "old_guard": re.compile(r"CWE-1336|SSTI|模板引擎")},
}

LOG = []
def P(*a):
    LOG.append(" ".join(str(x) for x in a))

def norm_md5(s):
    return hashlib.md5(re.sub(r"\s+", "", s).encode()).hexdigest()

def load_jsonl(p):
    return [json.loads(l) for l in p.open(encoding="utf-8") if l.strip()]

# ---- v2_14 行号 -> v2_15 行号重映射表 ----
del_ids = {json.loads(l)["id"] for l in (AUD / "agent_audit_v2_14/out/manifest_DELETE.jsonl").open(encoding="utf-8") if l.strip()} | {8288, 8968}
id2v15 = {}
n_kept = 0
for i in range(1, 10022):
    if i in del_ids:
        continue
    n_kept += 1
    id2v15[i] = n_kept

lines = DATA.read_text(encoding="utf-8").split("\n")
P(f"当前 v2_15: {sum(1 for l in lines if l.strip())} 条")

# ---- 1) P0-A 改标 ----
for v14_id, spec in RELABELS.items():
    ln = id2v15.get(v14_id)
    if ln is None:
        P(f"  !! {v14_id} 已被删除,跳过改标")
        continue
    rec = json.loads(lines[ln - 1])
    a = rec["messages"][2]["content"]
    ms = list(JSON_BLOCK.finditer(a))
    o = json.loads(ms[-1].group(1))
    vt = str(o.get("vulnerability_type", ""))
    if not spec["old_guard"].search(vt):
        P(f"  line {ln}(v2_14 {v14_id}): vt={vt!r} 不匹配 old_guard,跳过")
        continue
    # 规范全名取自库内
    m = re.match(r"(CWE-\d+)\s+(.+)", vt)
    o["vulnerability_type"] = f"{spec['new_cwe']} {m.group(2) if m else ''}".strip()
    new_vt = o["vulnerability_type"]
    a2 = a[: ms[-1].start()] + "```json\n" + json.dumps(o, ensure_ascii=False) + "\n```" + a[ms[-1].end():]
    rec["messages"][2]["content"] = a2
    lines[ln - 1] = json.dumps(rec, ensure_ascii=False)
    P(f"  line {ln}(v2_14 {v14_id}): {vt!r} -> {new_vt!r}")

# ---- 2) 追加 g9-g19 ----
user_md5 = set()
assist_md5 = set()
for l in lines:
    if not l.strip():
        continue
    rec = json.loads(l)
    user_md5.add(norm_md5(rec["messages"][1]["content"]))
    assist_md5.add(norm_md5(rec["messages"][2]["content"]))

appended = 0
dupe = 0
pack_stat = Counter()
for pack in APPEND_PACKS:
    p = CORPUS / f"{pack}.jsonl"
    for rec in load_jsonl(p):
        msgs = rec["messages"]
        if len(msgs) != 3:
            P(f"  !! {pack}: 非 3 元组消息,跳过")
            continue
        um, am = norm_md5(msgs[1]["content"]), norm_md5(msgs[2]["content"])
        if um in user_md5 or am in assist_md5:
            dupe += 1
            continue
        blk = JSON_BLOCK.findall(msgs[2]["content"])
        okc = False
        if blk:
            try:
                okc = list(json.loads(blk[-1]).keys()) == CONTRACT
            except Exception:
                okc = False
        if not okc:
            P(f"  !! {pack}: 契约不符,跳过")
            continue
        rec.setdefault("fix_distill", {})["source_pack"] = f"v2_15a/{pack}"
        lines.append(json.dumps(rec, ensure_ascii=False))
        user_md5.add(um); assist_md5.add(am)
        appended += 1
        pack_stat[pack] += 1
P(f"  追加 {appended} 条 / 查重拦截 {dupe} / 包分布 {dict(pack_stat)}")

DATA.write_text("\n".join(lines), encoding="utf-8")

# ---- 3) 自检 ----
P("")
P("== 自检 ==")
sys_cnt = Counter()
bad_json = 0
hv = Counter()
n = 0
for l in lines:
    if not l.strip():
        continue
    n += 1
    rec = json.loads(l)
    sys_cnt[hashlib.md5(rec["messages"][0]["content"].encode()).hexdigest()[:8]] += 1
    blk = JSON_BLOCK.findall(rec["messages"][2]["content"])
    try:
        o = json.loads(blk[-1])
        hv[str(o.get("has_vulnerability"))] += 1
    except Exception:
        bad_json += 1
P(f"  总条数 {n} | system 版本 {dict(sys_cnt)} | JSON 失败 {bad_json} | 正负 {dict(hv)}")

(AUD / "merge_v2_15_wave1_incr_out.txt").write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("\n".join(LOG[-6:]))
