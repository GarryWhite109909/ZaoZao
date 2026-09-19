# -*- coding: utf-8 -*-
"""门 A fail 30 条分诊（20260911）：是烂题、可重取、还是词表误伤？

分类判据：
  T1 取材错配——patch 改动文件 与 manifest.source_path（CVE 根因文件）无交集 → 可重取（若 patch 库存在根因文件补丁）
  T2 描述空洞——CVE 描述 < 30 词或无实词 → 无对齐信号可用，重取无用，走弃题/门 D
  T3 词表误伤——描述与改动行有非机制词重叠但低于阈值，或多文件 patch 被 hunk 混流稀释 → 修词表/按文件重扫可翻案
  T4 真烂题——T1 且补丁库无根因文件补丁 → 弃题
输出：results/_gateA_fail_triage_20260911.md + .json
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
CORPUS = BASE / "corpus"
RESULTS = CORPUS / "diffpair_wave1" / "results"

g = json.loads((RESULTS / "_gates_20260911.json").read_text(encoding="utf-8"))
fails = [r for r in g["rows"] if r["gateA"] == "fail" and not r["quarantined"]]

tp = json.loads((CORPUS / "train_pool/manifest.json").read_text(encoding="utf-8"))["samples"]
tp_by_file = {s["file"]: s for s in tp}

DIFF_FILE = re.compile(r"^diff --git a/(\S+) b/(\S+)$", re.M)


def patch_files(patch_text):
    return [m.group(2) for m in DIFF_FILE.finditer(patch_text)]


rows = []
for r in fails:
    kid = r["kit"]
    meta = None
    seed = r["seed"]
    tp_entry = tp_by_file.get(seed)
    patch_rel = tp_entry.get("patch_file") if tp_entry else None
    patch_path = CORPUS / patch_rel if patch_rel else None
    ptext = patch_path.read_text(encoding="utf-8", errors="replace") if (patch_path and patch_path.exists()) else ""
    pf = patch_files(ptext)
    root = (tp_entry or {}).get("source_path") or ""
    desc = (tp_entry or {}).get("expected_vulnerability") or ""
    desc_words = len(desc.split())
    # T1: 根因文件与 patch 文件交集
    root_base = root.split("/")[-1] if root else ""
    overlap = [f for f in pf if root_base and root_base in f] if root_base else []
    # T3: 描述实词与改动行的宽松重叠（不限于机制词）
    blob = "\n".join(re.findall(r"^[+-](.*)$", ptext, re.M)).lower()
    words = [w.lower() for w in re.findall(r"[a-zA-Z][a-zA-Z0-9_]{3,}", desc)]
    loose_hits = sorted({w for w in words if w in blob})[:8]
    cls, note = "", ""
    if not pf and ptext:
        cls, note = "T2", "patch 无 diff --git 头（hunk-only），无法核对文件"
    elif root and not overlap and pf:
        cls = "T1" if desc_words >= 30 else "T1+T2"
        note = f"根因文件 {root} 不在 patch 改动文件 {pf[:3]} 中 → 取材错配"
    elif root and overlap:
        cls, note = "T3", f"根因文件在 patch 内（{overlap[0][:40]}）→ 疑似词表/描述问题，可翻案"
    elif not root:
        cls, note = "T2", "manifest 无 source_path，无根因文件参照"
    else:
        cls, note = "T3", "其他"
    rows.append({"kit": kid, "cve": r["cve"], "cwe_now": r["cwe_now"], "class": cls,
                 "patch_files": pf[:5], "root_file": root, "desc_words": desc_words,
                 "loose_hits": loose_hits, "note": note,
                 "desc_head": desc[:160].replace("\n", " ")})

cnt = {}
for r in rows:
    k = r["class"].split("+")[0]
    cnt[k] = cnt.get(k, 0) + 1

out = {"rows": rows, "summary": cnt}
(RESULTS / "_gateA_fail_triage_20260911.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

L = ["# 门 A fail 30 条分诊（20260911）", "",
     f"分类：{cnt}", "",
     "| kit | CVE | 标签 | 分类 | 判据 |", "|---|---|---|---|---|"]
for r in rows:
    L.append(f"| {r['kit']} | {r['cve'] or '-'} | {r['cwe_now']} | {r['class']} | {r['note']} |")
L.append("")
L.append("## 逐条证据（前 30）")
for r in rows:
    L.append(f"### {r['kit']} ({r['class']})")
    L.append(f"- CVE: {r['cve']} 标签: {r['cwe_now']}")
    L.append(f"- 根因文件(source_path): `{r['root_file'] or 'N/A'}`")
    pf_md = ", ".join("`%s`" % p for p in r["patch_files"]) or "无"
    L.append(f"- patch 改动文件: {pf_md}")
    L.append(f"- CVE 描述 {r['desc_words']} 词: {r['desc_head']}…")
    L.append(f"- 描述词与改动行宽松重叠: {r['loose_hits'] or '无'}")
    L.append("")
(RESULTS / "_gateA_fail_triage_20260911.md").write_text("\n".join(L) + "\n", encoding="utf-8")
print("summary:", cnt)
for r in rows:
    print(f"  {r['kit']} [{r['class']}] {r['note'][:80]}")
