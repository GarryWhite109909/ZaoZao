# -*- coding: utf-8 -*-
"""wave2 预审统一比对（20260913）：教师产出 vs oracle（A=vuln+CWE / B=safe）。

判定（每对）：
  PASS            A=true 且 CWE 在 oracle 族内，B=false
  TAG_DISPUTE     A=true 但 CWE 在 oracle 族外（教师给了不同编号，附教师CWE）
  COND_A          A=条件性false（样本外依赖，如 00202 型）
  VULN_INVALID    A=false（教师认为 vuln 侧不成立）
  SIDE_B_HOLE     B=true（safe 侧带洞/修复无效）
  PARSE_ERR       缺结论行
输出：results/_wave2_preaudit_compare_20260913.{json,md}
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
    "441": {"441", "918", "601"}, "918": {"918", "601", "441"}, "601": {"601", "918", "441"},
    "95": {"95", "94", "1336"}, "94": {"94", "95", "1336"}, "1336": {"1336", "94", "95"},
    "78": {"78", "77"}, "77": {"77", "78"},
}

# 合并 95 三小批
merged = []
for f in ("wave2_preaudit_results_95_a.txt", "wave2_preaudit_results_95_b.txt", "wave2_preaudit_results_95_c.txt"):
    p = RESULTS / f
    if p.exists():
        merged.append(p.read_text(encoding="utf-8", errors="replace"))
(RESULTS / "wave2_preaudit_results_95.txt").write_text("\n".join(merged), encoding="utf-8", newline="\n")

# oracle: pid -> (cwe, lang)
oracle = {}
for p in WAVE.joinpath("wave2_pairs").glob("*.txt"):
    if p.name.startswith("_"):
        continue
    m = re.match(r"# wave2 pair (\S+) \| (CWE-\d+)", p.read_text(encoding="utf-8").splitlines()[0])
    if m:
        oracle[m.group(1)] = m.group(2)

rows = []
files = ["wave2_preaudit_results_441.txt", "wave2_preaudit_results_95.txt", "wave2_preaudit_results_78.txt"]
blocks = []
for f in files:
    t = (RESULTS / f).read_text(encoding="utf-8", errors="replace")
    blocks += [b for b in re.split(r"(?m)^(?=### wave2-)", t) if b.startswith("### wave2-")]

per = {}  # pid -> {"A": row, "B": row}
for b in blocks:
    m = re.match(r"### wave2-(\S+) (版本A|版本B)", b)
    if not m:
        continue
    pid, ver = m.group(1), m.group(2)
    concl = re.search(r"结论:\s*存在漏洞=(true|false)([^\n]*)", b)
    hv = concl.group(1) if concl else None
    rest = (concl.group(2) or "") if concl else ""
    mcwe = re.search(r"CWE-(\d+)", rest)
    cwe = f"CWE-{mcwe.group(1)}" if mcwe else None
    conditional = bool(re.search(r"条件性|样本外不可证|样本内不可证", rest)) or bool(re.search(r"样本外假设", b))
    per.setdefault(pid, {})[ver] = {"hv": hv, "cwe": cwe, "conditional": conditional,
                                    "concl_rest": rest.strip()[:100]}

for pid, pr in sorted(per.items()):
    ocwe = oracle.get(pid, "CWE-?")
    onum = re.match(r"CWE-(\d+)", ocwe).group(1)
    a, bb = pr.get("版本A", {}), pr.get("版本B", {})
    r = {"pid": pid, "oracle": ocwe, "A": a, "B": bb}
    if not a.get("hv"):
        r["verdict"] = "PARSE_ERR" if not a else "VULN_INVALID"
    elif a["hv"] == "false":
        r["verdict"] = "COND_A" if a.get("conditional") else "VULN_INVALID"
    else:
        anum = re.match(r"CWE-(\d+)", a.get("cwe") or "")
        a_ok = anum and (anum.group(1) == onum or anum.group(1) in FAMILY.get(onum, {onum}))
        if bb.get("hv") == "true":
            r["verdict"] = "SIDE_B_HOLE"
        elif a_ok:
            r["verdict"] = "PASS"
        else:
            r["verdict"] = "TAG_DISPUTE"
    rows.append(r)

cnt = collections.Counter(r["verdict"] for r in rows)
out = {"summary": dict(cnt), "rows": rows}
(RESULTS / "_wave2_preaudit_compare_20260913.json").write_text(
    json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

L = ["# wave2 预审统一比对报告（20260913）", "",
     f"{len(rows)} 对。分类：{dict(cnt)}", ""]
order = ["SIDE_B_HOLE", "VULN_INVALID", "COND_A", "TAG_DISPUTE", "PARSE_ERR", "PASS"]
for key in order:
    grp = [r for r in rows if r["verdict"] == key]
    if not grp:
        continue
    L.append(f"## {key}（{len(grp)}）")
    L.append("")
    L.append("| 对 | oracle | A 判定 | B 判定 | 备注 |")
    L.append("|---|---|---|---|---|")
    for r in grp:
        a, bb = r["A"], r["B"]
        note = ""
        if key == "TAG_DISPUTE":
            note = f"教师判 {a.get('cwe')}"
        if key == "SIDE_B_HOLE":
            note = f"B: {bb.get('cwe')} {bb.get('concl_rest', '')[:50]}"
        if key == "COND_A":
            note = a.get("concl_rest", "")[:60]
        L.append(f"| {r['pid']} | {r['oracle']} | {a.get('hv')}/{a.get('cwe') or '-'} "
                 f"| {bb.get('hv')}/{bb.get('cwe') or '-'} | {note} |")
    L.append("")
(RESULTS / "_wave2_preaudit_compare_20260913.md").write_text("\n".join(L) + "\n", encoding="utf-8")

print("summary:", dict(cnt))
for r in rows:
    if r["verdict"] != "PASS":
        a, bb = r["A"], r["B"]
        print(f"  {r['verdict']:13} {r['pid']:10} oracle={r['oracle']} A={a.get('hv')}/{a.get('cwe')} B={bb.get('hv')}/{bb.get('cwe')}")
