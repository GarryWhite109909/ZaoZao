# -*- coding: utf-8 -*-
"""P3 30 条：NVD 官方 CWE 口径批量拉取（门 D 来源③），与账面标签对照出裁定建议。

限速：无 API key 5 req/30s → 每 7s 一条。产出 results/_gateD_nvd_20260911.{json,md}
"""
import json
import time
import urllib.request
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
CORPUS = BASE / "corpus"
RESULTS = CORPUS / "diffpair_wave1" / "results"

adj = json.loads((RESULTS / "_gateD_adjudication_20260911.json").read_text(encoding="utf-8"))
p3 = [r for r in adj["rows"] if r["class"] == "P3需读码" and r["cve"]]

out = {}
for i, r in enumerate(p3):
    cve = r["cve"]
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
        req = urllib.request.Request(url, headers={"User-Agent": "research/1.0"})
        d = json.loads(urllib.request.urlopen(req, timeout=25).read())
        c = d["vulnerabilities"][0]["cve"]
        cwes = []
        for w in c.get("weaknesses", []):
            for dd in w.get("description", []):
                v = dd.get("value", "")
                if v.startswith("CWE-") and v not in cwes:
                    cwes.append(v)
        out[cve] = {"nvd_cwes": cwes, "label": r["cwe"], "kit": r["kit"]}
        print(f"[{i+1}/{len(p3)}] {cve} nvd={cwes} label={r['cwe']}")
    except Exception as e:
        out[cve] = {"error": f"{type(e).__name__}: {str(e)[:80]}", "label": r["cwe"], "kit": r["kit"]}
        print(f"[{i+1}/{len(p3)}] {cve} ERR {type(e).__name__}")
    if i < len(p3) - 1:
        time.sleep(7)

(RESULTS / "_gateD_nvd_20260911.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

# 对照
same, diff, nores = [], [], []
for cve, o in out.items():
    if "error" in o:
        nores.append((o["kit"], cve, o["error"]))
        continue
    lab = o["label"].replace("CWE-", "")
    nvd_n = [c.replace("CWE-", "") for c in o["nvd_cwes"]]
    if lab in nvd_n:
        same.append((o["kit"], cve, o["label"], o["nvd_cwes"]))
    else:
        diff.append((o["kit"], cve, o["label"], o["nvd_cwes"]))

L = ["# P3 NVD 官方口径对照（门 D 来源③，20260911）", "",
     f"一致 {len(same)} / 不一致 {len(diff)} / 无结果 {len(nores)}", "",
     "## 一致（NVD 背书 → 建议保留）", ""]
for k, c, lab, n in same:
    L.append(f"- {k} {c} 标签 {lab} ∈ NVD {n}")
L.append("")
L.append("## 不一致（NVD 优先 → 改标建议，人工确认）")
L.append("")
L.append("| kit | CVE | 账面标签 | NVD 官方 | 建议改标 |")
L.append("|---|---|---|---|---|")
for k, c, lab, n in diff:
    L.append(f"| {k} | {c} | {lab} | {n} | {n[0] if n else '-'} |")
L.append("")
L.append("## 无结果")
for k, c, e in nores:
    L.append(f"- {k} {c}: {e}")
(RESULTS / "_gateD_nvd_20260911.md").write_text("\n".join(L) + "\n", encoding="utf-8")
print(f"\nsame={len(same)} diff={len(diff)} nores={len(nores)}")
