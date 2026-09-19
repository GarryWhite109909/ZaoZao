# -*- coding: utf-8 -*-
"""任务4 正式蒸馏产出 verify（20260913）：C2 一致性 + 编号族对照 + 字眼分级。"""
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
    "918": {"918", "441", "601"}, "441": {"441", "918", "601"}, "95": {"95", "94", "1336"},
    "78": {"78", "77"},
}
oracle = {}
for p in WAVE.joinpath("wave2_pairs").glob("*.txt"):
    if not p.name.startswith("_"):
        m = re.match(r"# wave2 pair (\S+) \| (CWE-\d+)", p.read_text(encoding="utf-8").splitlines()[0])
        if m:
            oracle[m.group(1)] = m.group(2)

blocks = []
for f in sorted(RESULTS.glob("wave2_formal_results_*.txt")):
    t = f.read_text(encoding="utf-8", errors="replace")
    blocks += [(f.name, b) for b in re.split(r"(?m)^(?=### wave2-)", t) if b.startswith("### wave2-")]

per = {}
for fname, b in blocks:
    m = re.match(r"### wave2-(\S+) (版本A|版本B)", b)
    if not m:
        continue
    pid, ver = m.group(1), m.group(2)
    concl = re.search(r"结论:\s*存在漏洞=(true|false)([^\n]*)", b)
    hv = concl.group(1) if concl else None
    rest = (concl.group(2) or "") if concl else ""
    mcwe = re.search(r"CWE-(\d+)", rest)
    cwe = f"CWE-{mcwe.group(1)}" if mcwe else None
    gap = len(re.findall(r"需要补|需补|待补|样本外", b))
    per.setdefault(pid, {})[ver] = {"hv": hv, "cwe": cwe, "gap": gap, "concl": rest.strip()[:70]}

rows = []
for pid, pr in sorted(per.items()):
    ocwe = oracle.get(pid, "?")
    onum = re.match(r"CWE-(\d+)", ocwe).group(1)
    a, bb = pr.get("版本A", {}), pr.get("版本B", {})
    a_ok = a.get("hv") == "true" and a.get("cwe") and re.match(r"CWE-(\d+)", a["cwe"]).group(1) in FAMILY.get(onum, {onum})
    if a.get("hv") != "true":
        v = "A_ERR"
    elif not a_ok:
        v = "A_TAG"
    elif bb.get("hv") == "true":
        v = "B_HOLE"
    else:
        v = "PASS"
    rows.append({"pid": pid, "oracle": ocwe, "verdict": v,
                 "A": f"{a.get('hv')}/{a.get('cwe') or '-'}", "B": f"{bb.get('hv')}/{bb.get('cwe') or '-'}",
                 "A_gap": a.get("gap", 0), "B_gap": bb.get("gap", 0), "B_note": bb.get("concl", "")})

cnt = collections.Counter(r["verdict"] for r in rows)
(RESULTS / "_formal_verify_20260913.json").write_text(
    json.dumps({"summary": dict(cnt), "rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")

print("verify:", dict(cnt))
for r in rows:
    if r["verdict"] != "PASS":
        print(f"  {r['verdict']:7} {r['pid']:10} oracle={r['oracle']} A={r['A']} B={r['B']} | {r['B_note'][:60]}")
