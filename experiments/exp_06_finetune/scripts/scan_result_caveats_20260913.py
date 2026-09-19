# -*- coding: utf-8 -*-
"""产出"问题字眼"全量扫描（20260913）——入库分级维度。

扫描全部已落盘产出，逐块标记三类信号：
  GAP   样本外依赖/待补片段：需要补|需补|待补|请补|要补|需要提供|缺失部分|请把.*补|需要.*实现
  UNCERT 不确定/条件性：样本外|无法证明|无法验证|不可证|待确认|不确定|存疑|无法判定|待查证|条件性|若模板|若官方
  FIX_NEW 幻觉修复风险：修复栏含 新增|引入|添加|安装|导入|新建（提示可能建议不存在的模块/函数，需对照代码人工核）
输出：results/_caveat_scan_20260913.{json,md}，每块给出分级建议：
  clean（无命中）/ gap_noted（UNCERT，结论条件性）/ needs_review（GAP 或 FIX_NEW）
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

FILES = {
    "9_11批": WAVE / "results" / "result.txt",
    "续投批": WAVE / "kits_learner" / "result" / "result.txt",
    "复核批": WAVE / "kits_redistill_truth" / "result" / "result.txt",
    "预审441": RESULTS / "wave2_preaudit_results_441.txt",
    "预审78": RESULTS / "wave2_preaudit_results_78.txt",
}
GAP_RE = re.compile(r"需要补|需补|待补|请补|需要提供|缺失部分|需要.*完整实现")
UNC_RE = re.compile(r"样本外|无法证明|无法验证|不可证|待确认|不确定|存疑|无法判定|待查证")
COND_RE = re.compile(r"条件性")  # 教师诚实标注的条件性结论——合法形态，单列不并入问题
FIXNEW_RE = re.compile(r"新增|引入|添加|安装|导入|新建")


def split_blocks(text):
    return [b for b in re.split(r"(?m)^(?=### )", text) if b.startswith("### ")]


def strip_checklist(block):
    """剥离自查清单（'- [x]/- [ ]' 起始的行及其后），避免固定文案误伤。"""
    lines = block.splitlines()
    out, in_cl = [], False
    for ln in lines:
        if re.match(r"^\s*-\s*\[.\]", ln):
            in_cl = True
        if not in_cl:
            out.append(ln)
    return "\n".join(out)


rows = []
for batch, path in FILES.items():
    if not path.exists():
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    for b in split_blocks(text):
        head = re.match(r"### (\S+)(?: (版本A|版本B))?", b)
        if not head:
            continue
        bid, ver = head.group(1), head.group(2) or ""
        b = strip_checklist(b)  # 剥离自查清单防固定文案误伤
        # 修复栏
        mfix = re.search(r"修复:\s*\n?(.*?)(?=\n- \[|\n### |\Z)", b, re.S)
        fix_text = mfix.group(1) if mfix else ""
        gap = GAP_RE.findall(b)
        unc = UNC_RE.findall(b)
        cond = len(COND_RE.findall(b))
        fixnew = FIXNEW_RE.findall(fix_text)
        grade = "needs_review" if (gap or fixnew) else ("gap_noted" if unc else "clean")
        rows.append({"batch": batch, "id": bid, "ver": ver,
                     "gap_hits": len(gap), "unc_hits": len(unc), "cond_hits": cond,
                     "fixnew_hits": len(fixnew),
                     "gap_ctx": [b[max(0, m.start() - 20):m.start() + 60].replace("\n", " ") for m in re.finditer(GAP_RE, b)][:2],
                     "fixnew_ctx": [fix_text[:100]] if fixnew else [],
                     "grade": grade})

cnt = collections.Counter(r["grade"] for r in rows)
by_batch = collections.defaultdict(collections.Counter)
for r in rows:
    by_batch[r["batch"]][r["grade"]] += 1

out = {"summary": dict(cnt), "by_batch": {k: dict(v) for k, v in by_batch.items()}, "rows": rows}
(RESULTS / "_caveat_scan_20260913.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

L = ["# 产出问题字眼全量扫描（20260913）", "",
     f"总块 {len(rows)}，分级：{dict(cnt)}", ""]
for b, c in by_batch.items():
    L.append(f"- **{b}**：{dict(c)}")
L.append("")
L.append("## needs_review 清单（GAP 待补 / 修复栏含新增类词）")
L.append("")
L.append("| 批 | id | ver | GAP命中 | 修复栏新增词 |")
L.append("|---|---|---|---|---|")
for r in rows:
    if r["grade"] == "needs_review":
        L.append(f"| {r['batch']} | {r['id']} | {r['ver']} | {r['gap_hits']} | {r['fixnew_hits']} |")
L.append("")
L.append("## GAP 上下文抽样（前 12）")
for r in rows:
    if r["gap_hits"]:
        for g in r["gap_ctx"][:1]:
            L.append(f"- **{r['id']} {r['ver']}**: …{g}…")
L.append("")
L.append("## 修复栏新增词抽样（前 12，需对照代码核是否存在）")
n = 0
for r in rows:
    if r["fixnew_hits"] and n < 12:
        for f in r["fixnew_ctx"][:1]:
            L.append(f"- **{r['id']} {r['ver']}**: {f}…")
        n += 1
(RESULTS / "_caveat_scan_20260913.md").write_text("\n".join(L) + "\n", encoding="utf-8")

print("总块:", len(rows), "| 分级:", dict(cnt))
for b, c in by_batch.items():
    print(f"  {b}: {dict(c)}")
