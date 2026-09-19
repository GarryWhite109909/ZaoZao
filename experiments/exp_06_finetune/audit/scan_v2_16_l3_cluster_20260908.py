# -*- coding: utf-8 -*-
"""v2_16 清洗步骤 1.5：L3 全库簇反查（方法论 §2.3 G6 前置）。

1. 训练侧内部同源簇：数据集行与行之间的代码近重复（规范化非注释行 containment）。
   同一真实文件的多个化身若全在训练侧 → 过拟合风险（DiverseVul per-repo 配额同理）。
2. 隔离种子衍生反查：与 corpus_cluster_manifest 中 QUARANTINE_TRAIN 文件的内容交集
   （purge 后应为 0，双保险验证）。
3. 产出：audit/scan_v2_16_l3_cluster_flags.json（簇清单，供 build 层 G6 簇内配额与
   蒸馏切分以簇为单位使用）。
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
MANIFEST = BASE / "results/corpus_cluster_manifest.json"
OUT = BASE / "audit/scan_v2_16_l3_cluster_flags.json"

FENCE = re.compile(r"```[a-zA-Z0-9+#]*\n(.*?)```", re.S)
J_T = 0.50          # 对称 Jaccard：同文件化身的真实近重影通常 ≥0.7；
                    # 仅共享样板代码（Flask 骨架等）的不同样本 J≈0.2-0.4，
                    # 用 max-containment 0.45 会把 1791 行样本链成一个假巨簇（20260908 首跑教训）


def norm_lines(code: str):
    out = set()
    for ln in code.splitlines():
        s = ln.strip()
        if not s or s.startswith(("#", "//")):
            continue
        s = re.sub(r"\s+", " ", s).lower()
        if len(s) >= 8:
            out.add(s)
    return out


def main():
    rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
    print(f"库内 {len(rows)} 行")

    docs = {}
    for i, r in enumerate(rows):
        code = "\n".join(FENCE.findall(r["messages"][1]["content"]))
        nl = norm_lines(code)
        if nl:
            docs[i] = nl
    print(f"有代码的行: {len(docs)}")

    # 倒排索引粗筛
    inv = defaultdict(set)
    for i, nl in docs.items():
        for s in nl:
            inv[s].add(i)

    pairs = set()
    for i, nl in docs.items():
        cand = defaultdict(int)
        for s in nl:
            for j in inv[s]:
                if j != i:
                    cand[j] += 1
        for j, c in cand.items():
            if j > i:
                continue
            overlap = c
            jac = overlap / (len(docs[i]) + len(docs[j]) - overlap)
            if jac >= J_T:
                pairs.add((j, i))
    print(f"近重复行对: {len(pairs)}")

    # 并查集聚簇
    parent = {i: i for i in docs}
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for a, b in pairs:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    clusters = defaultdict(list)
    for i in docs:
        clusters[find(i)].append(i)
    multi = {k: sorted(v) for k, v in clusters.items() if len(v) > 1}
    print(f"多行簇: {len(multi)}")

    # 隔离种子内容反查（双保险）
    m = json.loads(MANIFEST.read_text(encoding="utf-8"))
    seeds = {}
    for rel, info in m["roles"].items():
        if info.get("role") == "QUARANTINE_TRAIN":
            p = BASE / "corpus" / rel
            if p.exists():
                seeds[rel] = norm_lines(p.read_text(errors="replace"))
    seed_hits = []
    for i, nl in docs.items():
        for rel, snl in seeds.items():
            if nl and snl:
                inter = len(nl & snl)
                if inter / max(1, min(len(nl), len(snl))) >= J_T:
                    seed_hits.append({"row": i + 1, "seed": rel, "overlap": round(inter / min(len(nl), len(snl)), 2)})
    print(f"隔离种子内容命中: {len(seed_hits)}（预期 0）")

    # 行元信息摘要
    out_rows = []
    for k, members in sorted(multi.items(), key=lambda kv: -len(kv[1])):
        out_rows.append({
            "rows_1based": [i + 1 for i in members],
            "kinds": [(rows[i].get("meta") or {}).get("kind") for i in members],
            "cves": sorted({((rows[i].get("meta") or {}).get("cve") or "")
                            for i in members if (rows[i].get("meta") or {}).get("cve")}),
            "sizes": [len(docs[i]) for i in members],
        })
    OUT.write_text(json.dumps({
        "date": "2026-09-08", "threshold_max_containment": J_T,
        "n_rows": len(rows), "n_multi_clusters": len(multi),
        "seed_hits": seed_hits,
        "clusters": out_rows,
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"→ {OUT.name}")
    for c in out_rows[:15]:
        print(" ", len(c["rows_1based"]), c["rows_1based"][:8], c["kinds"][:8], c["cves"])


if __name__ == "__main__":
    main()
