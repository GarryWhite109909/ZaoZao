# -*- coding: utf-8 -*-
"""任务3（wave1 续投 123 id）产出解析 + 标签对照（20260913）。

块格式：### diffpair-corpus_XXXXXX 版本A|版本B + learner 栏位 + 自查清单。
对照 manifest 最新标签（含 NVD 改标）：
  A 版期望 = expected_present（true→true 且 CWE 同族 / false→false）
  B 版期望 = false（判 true → 修复无效 FLAG）
输出：results/_part2_parse_20260913.{json,md}
"""
import json
import re
import sys
import collections
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
WAVE = BASE / "corpus" / "diffpair_wave1"
RESULTS = WAVE / "results"

FAMILY = {
    "77": {"77", "78"}, "78": {"78", "77"}, "94": {"94", "95", "1336"}, "95": {"95", "94", "1336"},
    "1336": {"1336", "94", "95"}, "89": {"89", "943"}, "601": {"601", "918", "441"},
    "918": {"918", "601", "441"}, "441": {"441", "918", "601"}, "22": {"22", "73"}, "73": {"73", "22"},
    "798": {"798", "321", "259"}, "862": {"862", "639", "306"}, "863": {"863", "862", "639"},
    "639": {"639", "862", "306"}, "306": {"306", "862", "639"}, "327": {"327", "326", "295"},
    "295": {"295"}, "79": {"79"}, "502": {"502"}, "611": {"611", "776"}, "352": {"352"},
    "90": {"90"}, "20": {"20"}, "347": {"347"}, "321": {"321", "798"}, "400": {"400"},
}

text = (WAVE / "kits_learner" / "result" / "result.txt").read_text(encoding="utf-8", errors="replace")
blocks = [b for b in re.split(r"(?m)^(?=### diffpair-corpus_)", text) if b.startswith("### diffpair-corpus_")]
manifest = json.loads((WAVE / "manifest_PRIVATE.json").read_text(encoding="utf-8"))

rows = []
for b in blocks:
    m = re.match(r"### (diffpair-corpus_\d+) (版本A|版本B)", b)
    if not m:
        continue
    kid, ver = m.group(1), m.group(2)
    concl = re.search(r"结论:\s*存在漏洞=(true|false)([^\n]*)", b)
    hv = concl.group(1) if concl else None
    rest = (concl.group(2) or "") if concl else ""
    mcwe = re.search(r"CWE-(\d+)", rest)
    cwe = f"CWE-{mcwe.group(1)}" if mcwe else None
    anchors = len(re.findall(r"非 CWE-\d+", b))
    mdef = re.search(r"防御:\s*\n(.*?)(?=\n载荷:|\n组合链:|\n锚句:|\n结论:|\Z)", b, re.S)
    line_refs = len(set(re.findall(r"L\d+", mdef.group(1)))) if mdef else 0
    meta = manifest.get(kid)
    rows.append({"kit": kid, "ver": ver, "hv": hv, "cwe": cwe,
                 "anchors": anchors, "def_refs": line_refs,
                 "exp_present": meta.get("expected_present", True) if meta else None,
                 "exp_cwe": meta.get("expected_cwe") if meta else None,
                 "parsed": concl is not None})

# ---- 判定 ----
for r in rows:
    if not r["parsed"] or r["exp_present"] is None:
        r["verdict"] = "no_meta" if r["exp_present"] is None else "parse_err"
        continue
    if r["ver"] == "版本A":
        if r["exp_present"] is False:
            r["verdict"] = "ok_neg" if r["hv"] == "false" else "FN_neg(教师判有洞)"
        else:
            if r["hv"] != "true":
                r["verdict"] = "FN(教师判安全)"
            else:
                tn = re.match(r"CWE-(\d+)", r["cwe"] or "")
                ln = re.match(r"CWE-(\d+)", r["exp_cwe"] or "")
                ok = tn and ln and (ln.group(1) in FAMILY.get(tn.group(1), {tn.group(1)}))
                r["verdict"] = "ok_pos" if ok else f"编号偏差(教师{r['cwe']} vs 标签{r['exp_cwe']})"
    else:  # B
        r["verdict"] = "POST_true(修复无效?)" if r["hv"] == "true" else "ok_safe"

cnt = collections.Counter(r["verdict"] for r in rows)
ids_done = {r["kit"] for r in rows}
missing = sorted(set(manifest) - ids_done - {k for k in manifest if manifest[k].get("status") == "quarantined"})
out = {"summary": dict(cnt), "blocks": len(rows), "unique_ids": len(ids_done),
       "missing_ids": missing, "rows": rows}
(RESULTS / "_part2_parse_20260913.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

L = ["# 任务3 续投产出对照（20260913）", "",
     f"块 {len(rows)} / unique id {len(ids_done)}；分类：{dict(cnt)}", "",
     f"缺产出 id：{len(missing)}（{missing[:12]}{'…' if len(missing) > 12 else ''}）", ""]
for key in sorted(cnt):
    grp = [r for r in rows if r["verdict"] == key]
    L.append(f"## {key}（{len(grp)}）")
    L.append("")
    L.append("| kit | ver | 教师结论 | 标签 | 锚句数 |")
    L.append("|---|---|---|---|---|")
    for r in grp[:60]:
        L.append(f"| {r['kit']} | {r['ver']} | {r['hv']}/{r['cwe'] or '-'} | {r['exp_cwe'] or '-'} | {r['anchors']} |")
    L.append("")
(RESULTS / "_part2_parse_20260913.md").write_text("\n".join(L) + "\n", encoding="utf-8")

print("summary:", dict(cnt))
print("missing ids:", len(missing))
for r in rows:
    if r["verdict"] not in ("ok_pos", "ok_safe", "ok_neg"):
        print(f"  {r['verdict']:24} {r['kit']} {r['ver']} 教师={r['hv']}/{r['cwe']}")
