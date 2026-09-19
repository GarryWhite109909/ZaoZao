# -*- coding: utf-8 -*-
"""门 A fail 全文对齐复扫：机制词/描述词在 seed 全文 + patch 行的联合命中。"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from diffpair_patchlib import parse_patch
from diffpair_gates_v2_20260911 import CWE_MECH, STOPWORDS, WORD_RE, cwe_num

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
CORPUS = BASE / "corpus"
RESULTS = CORPUS / "diffpair_wave1" / "results"

g = json.loads((RESULTS / "_gates_20260911.json").read_text(encoding="utf-8"))
fails = [r for r in g["rows"] if r["gateA"] == "fail" and not r["quarantined"]]
tp = json.loads((CORPUS / "train_pool/manifest.json").read_text(encoding="utf-8"))["samples"]
tpf = {s["file"]: s for s in tp}

rows = []
for r in fails:
    e = tpf.get(r["seed"], {})
    desc = e.get("expected_vulnerability") or ""
    seed_p = CORPUS / "train_pool" / r["seed"]
    seed_text = seed_p.read_text(encoding="utf-8", errors="replace").lower() if seed_p.exists() else ""
    patch_p = CORPUS / e["patch_file"] if e.get("patch_file") else None
    ptext = patch_p.read_text(encoding="utf-8", errors="replace") if (patch_p and patch_p.exists()) else ""
    both = seed_text + "\n" + "\n".join(l for h in parse_patch(ptext) for t, l in h["lines"] if t in "+-").lower()
    cn = cwe_num(r["cwe_now"]) or ""
    mech = CWE_MECH.get(cn, [])
    seed_mech = [w for w in mech if re.search(rf"(?<![a-z]){re.escape(w)}(?![a-z])", both)]
    words = [w.lower() for w in WORD_RE.findall(desc) if w.lower() not in STOPWORDS and len(w) >= 3]
    loose = sorted({w for w in words if w in both})
    rows.append({"kit": r["kit"], "cve": r["cve"], "cwe": r["cwe_now"],
                 "desc_words": len(desc.split()), "mech_hits": seed_mech,
                 "loose_hits": loose[:10], "desc_head": desc[:180].replace("\n", " ")})

# 分类
for r in rows:
    if r["desc_words"] < 30:
        r["class"] = "T2描述空洞"
    elif r["mech_hits"] or len(r["loose_hits"]) >= 5:
        r["class"] = "T3可翻案"
    elif r["desc_words"] < 60 and not r["mech_hits"]:
        r["class"] = "T2b短描述"
    else:
        r["class"] = "T1疑似取材错配"

cnt = {}
for r in rows:
    cnt[r["class"]] = cnt.get(r["class"], 0) + 1

out = {"summary": cnt, "rows": rows}
(RESULTS / "_gateA_fail_triage_20260911.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

L = ["# 门 A fail 30 条分诊 v2（全文对齐复扫，20260911）", "",
     f"分类汇总：{cnt}", "",
     "判据：T2 描述<30词（无对齐信号可用）；T3 机制词/描述词在 seed 全文+patch 联合命中≥阈值（词表/改动行窗口误伤，可翻案）；"
     "T2b 短描述且零命中；T1 长描述但全文零命中（取材错配嫌疑最大）。", "",
     "| kit | CVE | 标签 | 分类 | 描述词 | 全文机制词命中 | 宽松重叠(前5) |", "|---|---|---|---|---|---|---|"]
for r in rows:
    L.append(f"| {r['kit']} | {r['cve'] or '-'} | {r['cwe']} | {r['class']} | {r['desc_words']} "
             f"| {r['mech_hits'] or '无'} | {r['loose_hits'][:5] or '无'} |")
L.append("")
L.append("## 描述摘录")
for r in rows:
    L.append(f"### {r['kit']} [{r['class']}] desc={r['desc_words']}词")
    L.append(f"> {r['desc_head']}…")
    L.append("")
(RESULTS / "_gateA_fail_triage_20260911.md").write_text("\n".join(L) + "\n", encoding="utf-8")
print("summary:", cnt)
for r in rows:
    print(f"  {r['kit']} [{r['class']}] desc={r['desc_words']}w mech={r['mech_hits'][:4]} loose={r['loose_hits'][:4]}")
