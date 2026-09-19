# -*- coding: utf-8 -*-
"""
v2_17 治理构建（2026-09-09 晚，用户令"治理开始"）

v2_17 = v2_16 − purge 86 行（P模板泄漏24 + A2同码反标2 + C空代码25 + B压sink伪代码19
        + F实测真破损13 + D JSON损坏2 + E围栏1），27 条外围示意备案保留。
执行纪律：
  - 逐行断言 anchor_code_md5 与 purge 队列一致（内容锚防错删）
  - purge∩FLIP 13 行 / purge∩终裁 1 行：删除优先于裁决，changelog 留痕
  - 产出 new_line_map.json：FLIP/终裁 存活行 旧行号→新行号（内容哈希重映射）
  - v2_16 原文件保留不动；v2_17 为新文件 + sha256 台账
"""
import json, re, sys, hashlib, collections
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[1]
SRC = BASE / "data/final_train_chatml_alpha06_v2_16.jsonl"
DST = BASE / "data/final_train_chatml_alpha06_v2_17.jsonl"
BAK = BASE / "data/final_train_chatml_alpha06_v2_17.purge_source_v2_16_snapshot.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"
PQ = BASE / "audit/purge_queue_v2_17_20260909.jsonl"

rows = [json.loads(l) for l in SRC.open(encoding="utf-8") if l.strip()]
purge = [json.loads(l) for l in PQ.open(encoding="utf-8") if l.strip()]


def code_of(u):
    fs = re.findall(r"```[A-Za-z0-9_+\-]*\n(.*?)```", u, re.S)
    return max(fs, key=len) if fs else ""


def md5(code):
    return hashlib.md5(code.strip().encode("utf-8", "replace")).hexdigest()[:16]


# 保留类（备案）不删
KEEP_KINDS = {"B_示意HIGH_外围"}
to_purge = {q["line"]: q for q in purge if q["disposition"] != "备案保留" or q["kind"] not in KEEP_KINDS}
to_purge = {ln: q for ln, q in to_purge.items() if q["line"] in to_purge}
hard = {ln: q for ln, q in to_purge.items() if q["disposition"] in ("PURGE",) or q["kind"] in
        ("P_契约模板泄漏", "A2_同码反标_框架转储", "C_空代码残片", "B_示意HIGH_压sink",
         "F_实测真破损", "D_结论JSON损坏", "E_围栏未闭合", "A_同码反标")}

removed, kept, errors = [], [], []
new_rows = []
new_index = 0
old2new = {}
for i, r in enumerate(rows, 1):
    if i in hard:
        q = hard[i]
        u = [m["content"] for m in r["messages"] if m["role"] == "user"][0]
        actual = md5(code_of(u))
        if actual != q.get("anchor_code_md5"):
            errors.append((i, q["kind"], actual, q.get("anchor_code_md5")))
            continue
        removed.append((i, q["kind"], q["reason"][:60]))
        continue
    new_index += 1
    old2new[i] = new_index
    new_rows.append(r)

assert not errors, f"内容锚不匹配，中止: {errors[:5]}"
with DST.open("w", encoding="utf-8", newline="\n") as f:
    for r in new_rows:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

with CHANGELOG.open("a", encoding="utf-8") as f:
    for ln, kind, reason in removed:
        f.write(json.dumps({"date": "2026-09-09", "step": "3.1_v2_17_governance_purge", "action": "DELETE",
                            "row_line_before": ln, "kind": kind, "reason": reason,
                            "basis": "purge_queue_v2_17_20260909 内容锚定；毒样本/脏样本治理（用户批准）",
                            "label_basis": "n/a"}, ensure_ascii=False) + "\n")

sha = hashlib.sha256(DST.read_bytes()).hexdigest()
kc = collections.Counter(k for _, k, _ in removed)
print(f"v2_17 构建完成: {len(rows)} → {len(new_rows)} 行（purge {len(removed)}）")
for k, n in kc.most_common():
    print(f"  {k:<22} {n:>3}")
print(f"sha256: {sha[:32]}…")
print(f"备份: {BAK.name}（purge 前源快照引用）；changelog +{len(removed)}")

# FLIP / 终裁 行重映射
FLAGS = {}
for l in (BASE / "corpus/redistill_wave/verify_report.jsonl").open(encoding="utf-8"):
    r = json.loads(l)
    if r.get("line"):
        FLAGS[r["line"]] = r.get("flags", [])
flip_old = sorted(ln for ln, fl in FLAGS.items() if any(f.startswith("FLIP") for f in fl))
final_old = [113, 153, 218, 1542, 1665, 3489, 3900, 7996, 8055]
remap = {"flip": {}, "final": {}, "purged_flip": [], "purged_final": []}
for ln in flip_old:
    if ln in hard:
        remap["purged_flip"].append(ln)
    elif ln in old2new:
        remap["flip"][str(ln)] = old2new[ln]
for ln in final_old:
    if ln in hard:
        remap["purged_final"].append(ln)
    elif ln in old2new:
        remap["final"][str(ln)] = old2new[ln]
out = BASE / "audit/治理后行号重映射_20260909.json"
json.dump(remap, out.open("w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(f"FLIP 存活 {len(remap['flip'])}（purge 吸收 {len(remap['purged_flip'])}）；"
      f"终裁存活 {len(remap['final'])}（purge 吸收 {len(remap['purged_final'])}）→ {out.name}")
