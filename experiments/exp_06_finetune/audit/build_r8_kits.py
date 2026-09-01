# -*- coding: utf-8 -*-
"""构建 R8 线索池聚焦审查包(566 条 -> 29 批,每批 ≤20)。

每条样本只放与本任务相关的上下文:
  id/lang/family、诱饵注释行、带行号完整代码、教师 JSON 七字段、分析正文前 2200 字符。
输出: out/r8_kits/r8_kit_XX.jsonl + 清单
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "agent_audit_v2_14"))
from acommon import BASE, OUT, load_rows, asst_text, user_text, last_json

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

KIT_DIR = OUT / "r8_kits"
REV_DIR = OUT / "r8_reviews"
KIT_DIR.mkdir(exist_ok=True)
REV_DIR.mkdir(exist_ok=True)

cands = [json.loads(l) for l in (OUT / "repair_v2_15_wave1_scan_candidates.jsonl").open(encoding="utf-8")]
r8 = [c for c in cands if c["family"].startswith("R8")]

# 排除已在 manifest(1.3 主清单)的样本 —— 避免双重裁决
man_fix = {json.loads(l)["id"] for l in (OUT / "manifest_FIX.jsonl").open(encoding="utf-8") if l.strip()}
r8 = [c for c in r8 if c["id"] not in man_fix]
print("排除已在 manifest_FIX 的后剩:", len(r8))

rows, _ = load_rows()
R = {r["id"]: r["rec"] for r in rows}

FENCE = re.compile(r"```([\w+#.\-/]*)[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)

items = []
for c in r8:
    rid = c["id"]
    rec = R[rid]
    u, a = user_text(rec), asst_text(rec)
    code = "\n".join(m.group(2) for m in FENCE.finditer(u))
    lines = code.split("\n")
    numbered = "\n".join(f"{i+1:4d}| {l}" for i, l in enumerate(lines))
    o, _, _ = last_json(a)
    body = a.split("```json")[0] if "```json" in a else a
    items.append({
        "id": rid,
        "lang": c["lang"],
        "family": c["family"],
        "decoy_comments": c["comments"],
        "code_numbered": numbered,
        "teacher_json": {k: o.get(k) for k in ("has_vulnerability", "vulnerability_type",
                                               "risk_level", "source", "sink",
                                               "explanation", "fix_suggestion")} if isinstance(o, dict) else None,
        "analysis_body_head": body[:2200],
    })

BATCH = 20
n_batches = 0
for b in range(0, len(items), BATCH):
    n_batches += 1
    part = items[b:b + BATCH]
    with (KIT_DIR / f"r8_kit_{n_batches:02d}.jsonl").open("w", encoding="utf-8") as f:
        for it in part:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")
print(f"共 {len(items)} 条 -> {n_batches} 个审查包 (每批 {BATCH}) -> {KIT_DIR}")
