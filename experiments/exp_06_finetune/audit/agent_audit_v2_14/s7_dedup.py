# -*- coding: utf-8 -*-
"""S7 去重与冲突：精确去重、近重复聚类、"近重复但结论矛盾"簇、评测集污染。

输出：out/s7_out.txt + out/s7_exact_dups.jsonl + out/s7_conflict_clusters.jsonl
"""
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acommon import BASE, OUT, load_rows, code_blocks, last_json, write_jsonl, pct, hash01

LOG = []


def P(*a):
    LOG.append(" ".join(str(x) for x in a))


rows, _ = load_rows()

# ---- 预取 code / 结论 ----
items = []
for r in rows:
    rid = r["id"]
    u = r["rec"]["messages"][1]["content"]
    blocks = code_blocks(u)
    code = "\n\n".join(c for _, c in blocks)
    a = r["rec"]["messages"][2]["content"]
    o, _, _ = last_json(a)
    hv = o.get("has_vulnerability") if isinstance(o, dict) else None
    vt = str(o.get("vulnerability_type", "")) if isinstance(o, dict) else ""
    cwe = re.findall(r"CWE-(\d+)", vt)
    items.append({"id": rid, "code": code, "hv": hv, "cwe": cwe[0] if cwe else None,
                  "code_hash": hash01(code), "asst_hash": hash01(a),
                  "user_hash": hash01(u)})

# ---- 精确去重 ----
by_code = defaultdict(list)
by_asst = defaultdict(list)
by_full = defaultdict(list)
for it in items:
    by_code[it["code_hash"]].append(it["id"])
    by_asst[it["asst_hash"]].append(it["id"])
    by_full[it["user_hash"] + "|" + it["asst_hash"]].append(it["id"])
exact_code = {h: ids for h, ids in by_code.items() if len(ids) > 1}
exact_asst = {h: ids for h, ids in by_asst.items() if len(ids) > 1}
exact_full = {h: ids for h, ids in by_full.items() if len(ids) > 1}
P(f"精确重复（user 内容指纹）: {sum(len(v) - 1 for v in exact_full.values())} 条冗余，{len(exact_full)} 组")
P(f"精确重复（代码指纹）: {sum(len(v) - 1 for v in exact_code.values())} 条冗余，{len(exact_code)} 组")
P(f"精确重复（assistant 指纹）: {sum(len(v) - 1 for v in exact_asst.values())} 条冗余，{len(exact_asst)} 组")
dup_ids = sorted(i for ids in exact_full.values() for i in ids[1:])
write_jsonl(OUT / "s7_exact_dups.jsonl",
            [{"group": k, "ids": v} for k, v in exact_full.items()])

# ---- 近重复：词 5-gram shingle + 倒排候选 ----
def shingles(code):
    toks = re.findall(r"\w+", code.lower())
    return {" ".join(toks[i:i + 5]) for i in range(max(0, len(toks) - 4))}

SH = []
for it in items:
    SH.append(shingles(it["code"]) if it["code"] else set())

df = Counter()
for s in SH:
    for sh in s:
        df[sh] += 1
rare = {sh for sh, c in df.items() if c <= 60}

inv = defaultdict(list)
for idx, s in enumerate(SH):
    for sh in s:
        if sh in rare:
            inv[sh].append(idx)

pair_count = Counter()
for sh, ids in inv.items():
    if 1 < len(ids) <= 30:
        ids = sorted(ids)
        for a in range(len(ids)):
            for b in range(a + 1, len(ids)):
                pair_count[(ids[a], ids[b])] += 1

cand = [(p, c) for p, c in pair_count.items() if c >= 3]
P(f"近重复候选对（共享稀有 shingle≥3）: {len(cand)}")

# Jaccard 精算
def jac(a, b):
    sa, sb = SH[a], SH[b]
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    return inter / (len(sa) + len(sb) - inter)

near = []
for (a, b), _ in cand:
    j = jac(a, b)
    if j >= 0.8:
        near.append((a, b, j))
near.sort(key=lambda x: -x[2])
P(f"近重复对（Jaccard≥0.8）: {len(near)}")

# 并查集聚类
parent = list(range(len(items)))
def find(x):
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x
for a, b, _ in near:
    ra, rb = find(a), find(b)
    if ra != rb:
        parent[ra] = rb
clusters = defaultdict(list)
for idx in range(len(items)):
    clusters[find(idx)].append(idx)
big = [c for c in clusters.values() if len(c) > 1 and any(SH[i] for i in c)]
P(f"近重复簇（≥2 成员）: {len(big)}")

# ---- 矛盾簇：同簇内 has_vuln 或主 CWE 不一致 ----
conflicts = []
for c in big:
    hvs = {items[i]["hv"] for i in c}
    cwes = {items[i]["cwe"] for i in c}
    if (True in hvs and False in hvs) or (len(hvs) == 1 and True in hvs and len(cwes) > 1):
        conflicts.append({
            "members": [{"id": items[i]["id"], "hv": items[i]["hv"],
                         "cwe": items[i]["cwe"], "jac_max": 0.0} for i in c],
        })
# 补 jac
for cf in conflicts:
    ids = [m["id"] for m in cf["members"]]
    idxs = [items.index(next(x for x in items if x["id"] == i)) for i in ids] if False else None
P(f"矛盾簇: {len(conflicts)}")
for cf in conflicts[:40]:
    P(f"  {[ (m['id'], m['hv'], m['cwe']) for m in cf['members'] ]}")
write_jsonl(OUT / "s7_conflict_clusters.jsonl", conflicts)

# ---- 评测集污染 ----
P("")
P("== 评测集污染检查 ==")
eval_paths = []
for pat in ("experiments/exp_07_two_stage_eval/**/*.jsonl",
            "experiments/exp_06_finetune/testset_cve_fix/**/*.jsonl",
            "experiments/exp_06_finetune/data/*eval*.jsonl",
            "experiments/exp_06_finetune/data/*test*.jsonl",
            "experiments/exp_06_finetune/data/*holdout*.jsonl"):
    eval_paths += [p for p in BASE.parent.glob(pat) if p.is_file() and "v2_" not in p.name or "eval" in p.name or "test" in p.name or "holdout" in p.name]
eval_paths = sorted(set(eval_paths))
if not eval_paths:
    # 宽松找一次
    for p in (BASE.parent / "experiments").rglob("*.jsonl"):
        n = p.name.lower()
        if any(k in n for k in ("eval", "test", "holdout", "triage")) and "train" not in n and "redistill" not in n and "manifest" not in n and "wave" not in n:
            eval_paths.append(p)
eval_paths = sorted(set(eval_paths))[:20]
train_hashes = {it["user_hash"] for it in items}
train_code_hashes = {it["code_hash"] for it in items}
for p in eval_paths:
    n_hit_user = n_hit_code = n_total = 0
    try:
        with p.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except Exception:
                    continue
                n_total += 1
                txt = json.dumps(o, ensure_ascii=False)
                if hash01(txt) in train_hashes:
                    n_hit_user += 1
                # 提取其代码
                m = re.findall(r"```[\w+#.\-]*\r?\n(.*?)(?:```|\Z)", txt, re.S)
                if m and hash01("\n".join(m)) in train_code_hashes:
                    n_hit_code += 1
    except Exception as e:
        P(f"  {p.name}: 读取失败 {e}")
        continue
    P(f"  {p.relative_to(BASE.parent)}: {n_total} 条，user 指纹命中 {n_hit_user}，代码指纹命中 {n_hit_code}")

(OUT / "s7_out.txt").write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("\n".join(LOG))
