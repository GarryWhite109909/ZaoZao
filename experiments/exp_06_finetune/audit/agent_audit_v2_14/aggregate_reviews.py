# -*- coding: utf-8 -*-
"""聚合阶段二审查产出：schema 校验 + id 对账 + 错误统计 + 报告数据。

输出：out/agg_out.txt + out/aggregated.json
"""
import glob
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acommon import OUT

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

VERDICTS = {"DELETE", "FIX", "KEEP", "UNSURE"}
ERR_TYPES = {"false_positive", "false_negative", "wrong_cwe", "missed_vulnerability",
             "line_number_error", "hallucinated_identifier", "hallucinated_behavior",
             "hallucinated_artifact", "analysis_json_mismatch", "poc_invalid",
             "fix_invalid", "fix_half_measure", "fix_context_broken", "fix_format_violation",
             "fix_escape_pollution", "duplicated_fix", "truncated_output",
             "language_label_mismatch", "label_leak_shortcut", "risk_miscalibrated",
             "schema_limitation", "framework_conflict", "vocabulary_inconsistency",
             "teacher_identity_leak", "special_token_contamination", "verbosity", "other"}
SEVS = {"critical", "major", "minor"}
CONF = {"high", "medium", "uncertain"}

LOG = []
problems = []
all_rows = {}
batch_stats = {}
summaries = {}

kit_ids = {}
for kf in sorted(glob.glob(str(OUT / "kits" / "batch_*.jsonl"))):
    bnum = int(re.search(r"batch_(\d+)", kf).group(1))
    kit_ids[bnum] = [json.loads(l)["id"] for l in open(kf, encoding="utf-8")]

for rf in sorted(glob.glob(str(OUT / "reviews" / "review_batch_*.jsonl"))):
    bnum = int(re.search(r"batch_(\d+)", rf).group(1))
    rows = []
    for ln, line in enumerate(open(rf, encoding="utf-8"), 1):
        try:
            x = json.loads(line)
        except Exception as e:
            problems.append(f"batch {bnum} line {ln}: JSON 解析失败 {e}")
            continue
        rid = x.get("id")
        if "verdict" not in x or x["verdict"] not in VERDICTS:
            problems.append(f"batch {bnum} id={rid}: verdict 缺失/非法")
        ind = x.get("independent")
        if not isinstance(ind, dict):
            problems.append(f"batch {bnum} id={rid}: independent 缺失")
        else:
            if ind.get("confidence") not in CONF:
                problems.append(f"batch {bnum} id={rid}: confidence 非法 {ind.get('confidence')}")
        for e in x.get("errors", []):
            if e.get("type") not in ERR_TYPES:
                problems.append(f"batch {bnum} id={rid}: error_type 越界 {e.get('type')}")
            if e.get("severity") not in SEVS:
                problems.append(f"batch {bnum} id={rid}: severity 非法 {e.get('severity')}")
            if not e.get("evidence"):
                problems.append(f"batch {bnum} id={rid}: evidence 缺失")
        rows.append(x)
        all_rows[rid] = x
    vc = Counter(r["verdict"] for r in rows)
    ids = [r["id"] for r in rows]
    dup = [i for i, n in Counter(ids).items() if n > 1]
    if dup:
        problems.append(f"batch {bnum}: 重复 id {dup}")
    missing = set(kit_ids.get(bnum, [])) - set(ids)
    extra = set(ids) - set(kit_ids.get(bnum, []))
    if missing:
        problems.append(f"batch {bnum}: 缺 {len(missing)} 条 {sorted(missing)[:8]}")
    if extra:
        problems.append(f"batch {bnum}: 多 {len(extra)} 条 {sorted(extra)[:8]}")
    batch_stats[bnum] = {"counts": vc, "n": len(rows)}

for sf in sorted(glob.glob(str(OUT / "reviews" / "summary_batch_*.json"))):
    bnum = int(re.search(r"batch_(\d+)", sf).group(1))
    summaries[bnum] = json.load(open(sf, encoding="utf-8"))
    # summary counts 与逐条对账
    vc = batch_stats.get(bnum, {}).get("counts", Counter())
    sc = summaries[bnum].get("counts", {})
    for k in ("KEEP", "FIX", "DELETE", "UNSURE"):
        if sc.get(k, 0) != vc.get(k, 0):
            problems.append(f"batch {bnum}: summary counts {k}={sc.get(k,0)} 与逐条 {vc.get(k,0)} 不符")

# ---- 全局统计 ----
verdict_all = Counter(r["verdict"] for r in all_rows.values())
err_type_sev = Counter()
err_ids = defaultdict(list)
for rid, r in all_rows.items():
    for e in r.get("errors", []):
        err_type_sev[(e["type"], e["severity"])] += 1
        err_ids[e["type"]].append(rid)

crit_ids = sorted({rid for rid, r in all_rows.items()
                   if any(e["severity"] == "critical" for e in r.get("errors", []))})
novels = []
for bnum, s in summaries.items():
    for n in s.get("novel_errors", []):
        novels.append({"batch": bnum, "desc": n})

LOG.append("== 批进度 ==")
LOG.append(f"已完成批: {sorted(batch_stats)}  共 {len(all_rows)} 条样本")
for b in sorted(batch_stats):
    LOG.append(f"  batch {b:03d}: {dict(batch_stats[b]['counts'])}")
LOG.append("")
LOG.append("== verdict 全局 ==")
for v, n in verdict_all.most_common():
    LOG.append(f"  {v}: {n}")
LOG.append("")
LOG.append("== error_type × severity（≥1 次） ==")
for (t, s), n in sorted(err_type_sev.items(), key=lambda x: (-x[1], x[0])):
    LOG.append(f"  {t}/{s}: {n}   ids: {sorted(err_ids[t])[:12]}")
LOG.append("")
LOG.append(f"critical 样本数: {len(crit_ids)} -> {crit_ids[:30]}")
LOG.append("")
LOG.append("== novel errors ==")
for n in novels:
    LOG.append(f"  batch{n['batch']}: {n['desc'][:150]}")
LOG.append("")
LOG.append("== schema/对账问题 ==")
LOG.extend("  " + p for p in problems) if problems else LOG.append("  无")

(OUT / "aggregated.json").write_text(json.dumps({
    "batch_stats": {b: dict(s["counts"]) for b, s in batch_stats.items()},
    "verdict_all": dict(verdict_all),
    "err_type_sev": {f"{t}/{s}": n for (t, s), n in err_type_sev.items()},
    "crit_ids": crit_ids,
    "novels": novels,
    "problems": problems,
}, ensure_ascii=False, indent=1), encoding="utf-8")
report = "\n".join(LOG)
(OUT / "agg_out.txt").write_text(report + "\n", encoding="utf-8")
print(report)
