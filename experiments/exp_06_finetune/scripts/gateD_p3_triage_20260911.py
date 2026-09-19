# -*- coding: utf-8 -*-
"""P3 30 条三方对照裁定单：教师独立判断（wave1 蒸馏时不知标签） vs 账面标签 vs 门C要件证据。

门 D 合法真值来源对照：
  - 教师 cwe 判断 = 独立信号（蒸馏时 hint 纪律保证不泄露 expected_cwe）
  - patch 语义 = 来源①（修复代码在修什么）
  - NVD/GHSA = 来源③（人工或后续 web 核对）
裁定规则（建议自动预填）：
  教师CWE 与 标签 同族 → 标签大概率对（保留，弱证据）
  教师CWE 与 标签 异族 → 冲突，需 patch 语义/NVD 定夺（给出修复行参考）
  教师判无洞 且 标签有洞 → 强冲突（教师当时与 patch 对照过）
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
CORPUS = BASE / "corpus"
WAVE = CORPUS / "diffpair_wave1"
RESULTS = WAVE / "results"

adj = json.loads((RESULTS / "_gateD_adjudication_20260911.json").read_text(encoding="utf-8"))
p3 = [r for r in adj["rows"] if r["class"] == "P3需读码"]

# 教师 A 版判断（result_blocks.jsonl）
teacher = {}  # id -> {"cwe":..., "hv":...}
for line in (RESULTS / "result_blocks.jsonl").open(encoding="utf-8"):
    if not line.strip():
        continue
    b = json.loads(line)
    if b.get("version") != "版本A":
        continue
    kid = b.get("id")
    rec = {"cwe": b.get("cwe") or b.get("adjudicated_cwe"), "hv": b.get("has_vulnerability"),
           "note": (b.get("adjudication_note") or "")[:120]}
    teacher[kid] = rec

FAMILY = {
    "77": {"77", "78"}, "78": {"78", "77"}, "94": {"94", "95", "1336"}, "95": {"95", "94", "1336"},
    "1336": {"1336", "94", "95"}, "89": {"89", "943"}, "601": {"601", "918", "441"},
    "918": {"918", "601", "441"}, "441": {"441", "918", "601"}, "22": {"22", "73"}, "73": {"73", "22"},
    "798": {"798", "321", "259"}, "862": {"862", "639", "306"}, "863": {"863", "862", "639"},
    "327": {"327", "326", "295"}, "90": {"90"}, "79": {"79"}, "639": {"639", "862", "306"},
}


def cwe_n(v):
    import re
    m = re.match(r"CWE-(\d+)", (v or "").strip())
    return m.group(1) if m else None


out_rows = []
for r in p3:
    kid8 = r["kit"].replace("diffpair-corpus_", "")
    t = teacher.get(kid8, {})
    t_cwe = t.get("cwe")
    same = False
    conflict = "教师未产出"
    if t_cwe:
        tn, ln = cwe_n(t_cwe), cwe_n(r["cwe"])
        if tn and ln:
            same = tn == ln or tn in FAMILY.get(ln, {ln})
            conflict = "同族/一致" if same else f"冲突(教师判{t_cwe})"
        hv = t.get("hv")
        if hv is False:
            conflict += "·教师判无洞"
    out_rows.append({**r, "teacher_cwe": t_cwe, "relation": conflict})

rel_cnt = {}
for r in out_rows:
    k = r["relation"].split("·")[0]
    rel_cnt[k] = rel_cnt.get(k, 0) + 1
(RESULTS / "_gateD_p3_triage_20260911.json").write_text(
    json.dumps({"summary": rel_cnt, "rows": out_rows}, ensure_ascii=False, indent=1), encoding="utf-8")

L = ["# P3 30 条三方对照裁定单（20260911）", "",
     f"对照结果：{rel_cnt}", "",
     "**裁定规则**：同族 → 建议保留；冲突 → 按门 D 来源定（patch 语义已在列，必要时查 NVD）；"
     "教师判无洞且标签有洞 → 最高优先人工。", "",
     "| kit | 标签 | 教师判断(A版) | 关系 | 修复行(来源①) |", "|---|---|---|---|---|"]
for r in out_rows:
    fixes = " ; ".join(f"`{l[:42]}`" for l in r["patch_adds_head"][:2]) or "-"
    L.append(f"| {r['kit']} | {r['cwe']} | {r['teacher_cwe'] or '未产出'} | {r['relation']} | {fixes} |")
L.append("")
L.append("## 冲突条目证据明细")
for r in out_rows:
    if "冲突" in r["relation"] or "无洞" in r["relation"]:
        L.append(f"### {r['kit']} 标签{r['cwe']} vs 教师{r['teacher_cwe']} ({r['relation']})")
        L.append(f"- CVE: {r['cve']} 描述: {r['desc'][:150]}…")
        L.append(f"- 修复新增行: {[l[:70] for l in r['patch_adds_head'][:4]]}")
        L.append("")
(RESULTS / "_gateD_p3_triage_20260911.md").write_text("\n".join(L) + "\n", encoding="utf-8")
print("summary:", rel_cnt)
for r in out_rows:
    print(f"  {r['kit']} 标签{r['cwe']:9} 教师{str(r['teacher_cwe']):12} {r['relation']}")
