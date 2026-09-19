# -*- coding: utf-8 -*-
"""v2_16 清洗步骤 1.1：purge 隔离种子衍生样本（方法论 L3 / §1.3 第 1 项）。

纪律（对账记录 20260907 附8 教训）：
- 定位一律用 meta 指纹（seed_file + cve + kind），禁止行号缓存（行号已多次漂移）；
- 唯一性断言：命中数与预期不符即中止，不落盘；
- 幂等：重跑零命中即通过（可并入 build 的 --purge-quarantined-seeds 例行步）；
- 备份/快照由台账统一管理（snapshot_v2_15_pre_v2_16clean_20260908.jsonl）。

隔离种子来源：results/corpus_cluster_blocklist.json（4 个文件）+
results/corpus_cluster_manifest.json 中 role==QUARANTINE_TRAIN 的成员。
已知泄漏：corpus_00188.py（glances actions.py，簇 48）衍生裁决对 2 条，
CVE-2026-68518。其余 3 个种子预期 0 衍生（本脚本同时反查并留账）。
"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]          # exp_06_finetune/
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"
MANIFEST = BASE / "results/corpus_cluster_manifest.json"
BLOCKLIST = BASE / "results/corpus_cluster_blocklist.json"


def quarantined_seed_files():
    """簇 manifest 中 QUARANTINE_TRAIN 的种子文件名集合。"""
    m = json.loads(MANIFEST.read_text(encoding="utf-8"))
    seeds = set()
    for rel, info in m["roles"].items():
        if info.get("role") == "QUARANTINE_TRAIN":
            seeds.add(rel.split("/", 1)[1])
    # blocklist 中的文件名并集（gen 管线过滤用名单，同一批隔离资产）
    try:
        seeds |= set(json.loads(BLOCKLIST.read_text(encoding="utf-8"))["filenames"])
    except Exception:
        pass
    return seeds


def row_fingerprint(row):
    """提取 (seed_file, cve, kind) 指纹；无 meta.seed_file 的行返回 None。"""
    meta = row.get("meta") or {}
    if not isinstance(meta, dict):
        return None
    return meta.get("seed_file"), meta.get("cve"), meta.get("kind")


def main():
    seeds = quarantined_seed_files()
    print(f"隔离种子文件（QUARANTINE_TRAIN ∪ blocklist）: {len(seeds)} 个 -> {sorted(seeds)}")

    rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
    n_before = len(rows)
    print(f"当前库: {n_before} 条")

    # 反查全部隔离种子的在库衍生（不只 00188）
    hits = []          # (idx, seed, cve, kind)
    seed_row_count = {}
    for i, r in enumerate(rows):
        fp = row_fingerprint(r)
        if fp and fp[0] in seeds:
            hits.append((i, fp))
            seed_row_count[fp[0]] = seed_row_count.get(fp[0], 0) + 1

    print("各隔离种子在库衍生计数:", seed_row_count or "无")

    # 处置规则：全部删除（隔离种子的衍生样本无条件 purge，方法论 L3）
    # 唯一性断言：00188 家族必须恰好 2 条（9/7 已裁定的裁决对），其余种子允许 0
    expect = {("corpus_00188.py", "CVE-2026-68518"): 2}
    got = {}
    for _, fp in hits:
        key = (fp[0], fp[1])
        got[key] = got.get(key, 0) + 1
    if not got:
        print("PASS（幂等：无隔离种子衍生残留，无需动作）")
        return
    if got != expect:
        print(f"[中止] 指纹命中与预期不符: got={got} expect={expect}")
        print("       请人工核对新增命中（可能是新泄漏或种子表更新），更新 expect 后重跑。")
        sys.exit(2)

    drop_idx = {i for i, _ in hits}
    kept = [r for i, r in enumerate(rows) if i not in drop_idx]
    n_after = len(kept)
    print(f"purge {len(drop_idx)} 条 -> {n_after} 条")

    # 逐条 changelog 留痕
    with CHANGELOG.open("a", encoding="utf-8") as f:
        for i in sorted(drop_idx):
            r = rows[i]
            meta = r["meta"]
            f.write(json.dumps({
                "date": "2026-09-08",
                "step": "1.1_purge_quarantined_seeds",
                "action": "DELETE",
                "locator": {"seed_file": meta.get("seed_file"),
                            "cve": meta.get("cve"),
                            "kind": meta.get("kind")},
                "row_index_before": i,
                "reason": "隔离种子衍生样本（簇48 glances actions.py, QUARANTINE_TRAIN）"
                          "跨池泄漏；训练侧无条件 purge，考题侧保留",
                "basis": "results/corpus_cluster_manifest.json cluster=48; "
                         "web_review_v3 对账记录 20260907",
            }, ensure_ascii=False) + "\n")

    # 落盘（仅在有变更时写）
    if drop_idx:
        with DATA.open("w", encoding="utf-8", newline="\n") as f:
            for r in kept:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"已写回 {DATA.name}")

    # 自检
    rows2 = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
    residual = [1 for r in rows2 if row_fingerprint(r) and row_fingerprint(r)[0] in seeds]
    print(f"自检: 行数 {len(rows2)}（预期 {n_after}）; 隔离种子残留 {len(residual)}（预期 0）")
    assert len(rows2) == n_after and not residual
    print("PASS")


if __name__ == "__main__":
    main()
