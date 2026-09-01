# -*- coding: utf-8 -*-
"""1.3 工作台:234 条 FIX × review 证据 × 代码 × 教师输出 对齐落盘。

输出 out/fix13_workbench.jsonl:
  {id, batch, manifest_errors, review_errors[{type,severity,evidence}], review_note,
   lang, code_numbered, code_lines{n:content}, teacher_json, analysis_head,
   v2_15_line(v2_15 文件中的行号,应用 ops 时定位用)}
同时输出 CWE 规范名映射(库内高频全名)。
"""
import json
import re
import sys
import glob
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "agent_audit_v2_14"))
from acommon import BASE, OUT, load_rows, asst_text, user_text, last_json

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

REV = {}
for f in glob.glob(str(OUT / "reviews" / "review_batch_*.jsonl")):
    for l in open(f, encoding="utf-8"):
        r = json.loads(l)
        REV[r["id"]] = r

fix = [json.loads(l) for l in (OUT / "manifest_FIX.jsonl").open(encoding="utf-8") if l.strip()]

# id -> batch 映射(一次建好)
ID_BATCH = {}
for f in glob.glob(str(OUT / "reviews" / "review_batch_*.jsonl")):
    bnum = re.search(r"batch_(\d+)", f).group(1)
    for l in open(f, encoding="utf-8"):
        ID_BATCH[json.loads(l)["id"]] = bnum

rows, _ = load_rows()
R = {r["id"]: r["rec"] for r in rows}

# v2_15 行号映射(应用 ops 时按行定位;wave1 删除 74 条后行号前移)
del_ids = {json.loads(l)["id"] for l in (OUT / "manifest_DELETE.jsonl").open(encoding="utf-8")} | {8288, 8968}
keep_ids = [r["id"] for r in rows if r["id"] not in del_ids]
v15_line = {rid: k + 1 for k, rid in enumerate(keep_ids)}

FENCE = re.compile(r"```([\w+#.\-/]*)[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)

out = []
cwe_names = Counter()
for x in fix:
    rid = x["id"]
    rec = R[rid]
    u, a = user_text(rec), asst_text(rec)
    code = "\n".join(m.group(2) for m in FENCE.finditer(u))
    code_lines = {i + 1: l for i, l in enumerate(code.split("\n"))}
    numbered = "\n".join(f"{n:4d}| {code_lines[n]}" for n in sorted(code_lines))
    o, _, _ = last_json(a)
    body = a.split("```json")[0] if "```json" in a else a
    r = REV.get(rid, {})
    item = {
        "id": rid,
        "batch": ID_BATCH.get(rid),
        "manifest_errors": x["errors"],
        "review_errors": [{"type": e["type"], "severity": e["severity"], "evidence": e["evidence"]}
                          for e in r.get("errors", []) if isinstance(e, dict)],
        "review_note": r.get("note", ""),
        "lang": (re.search(r"```([\w+#.\-/]*)", u).group(1).lower() if re.search(r"```([\w+#.\-/]*)", u) else ""),
        "code_lines": code_lines,
        "code_numbered": numbered,
        "teacher_json": {k: o.get(k) for k in ("has_vulnerability", "vulnerability_type", "risk_level",
                                               "source", "sink", "explanation", "fix_suggestion")} if isinstance(o, dict) else None,
        "analysis_head": body[:2000],
        "v15_line": v15_line[rid],
    }
    out.append(item)
    if isinstance(o, dict):
        vt = str(o.get("vulnerability_type", ""))
        for m in re.finditer(r"CWE-\d+\s+[^\d;/）)]{4,60}", vt):
            cwe_names[vt.strip()] += 1

with (OUT / "fix13_workbench.jsonl").open("w", encoding="utf-8") as f:
    for it in out:
        f.write(json.dumps(it, ensure_ascii=False) + "\n")

# 库内 CWE 规范名(从 v2_15 全库统计最常见的 vt 全名)
name_count = Counter()
for r in rows:
    if r["id"] in del_ids:
        continue
    o, _, _ = last_json(asst_text(r["rec"]))
    if isinstance(o, dict):
        vt = str(o.get("vulnerability_type", "")).strip()
        if vt and vt != "none":
            name_count[vt] += 1
with (OUT / "cwe_canonical_names.json").open("w", encoding="utf-8") as f:
    json.dump({k: v for k, v in name_count.most_common(200)}, f, ensure_ascii=False, indent=1)
print(f"工作台 {len(out)} 条 -> fix13_workbench.jsonl")
print(f"CWE 规范名 top 类: {len(name_count)} 种")
