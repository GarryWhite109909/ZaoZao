# -*- coding: utf-8 -*-
"""任务1（redistill 31 包）产出解析 + 真值对照（20260913）。

learner 产出格式：### <id> 头 + 栏位（入口/链/防御/载荷/组合链/锚句/结论/修复）+ 自查。
对照台账：results/_redistill_truth_ledger.json（truth_hv / truth_cwe / flags）。
输出四分类：agree（结论=真值）/ disagree（教师明示推不出）/ conflict（结论≠真值且无 disagree）
           / parse_err。R5 额外检查防御栏行号密度（门E：每条至少 2 个 L 行号引用）。
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
WAVE = BASE / "corpus" / "diffpair_wave1"
RESULTS = WAVE / "results"

text = (WAVE / "kits_redistill_truth" / "result" / "result.txt").read_text(encoding="utf-8", errors="replace")
ledger = {e["id"]: e for e in json.loads((RESULTS / "_redistill_truth_ledger.json").read_text(encoding="utf-8"))["made"]}

# 真值以 manifest 最新状态为准（00160 已按 NVD 改标 639）
manifest = json.loads((WAVE / "manifest_PRIVATE.json").read_text(encoding="utf-8"))
for sid, led in ledger.items():
    kid = led.get("orig_kit")
    if kid and kid in manifest:
        m = manifest[kid]
        led["truth_hv"] = m.get("expected_present", True)
        led["truth_cwe"] = None if m.get("expected_present") is False else m.get("expected_cwe")

# 切块：### redistill-... 头
blocks = re.split(r"(?m)^(?=### redistill-)", text)
blocks = [b for b in blocks if b.startswith("### redistill-")]

rows = []
for b in blocks:
    m = re.match(r"### (\S+)", b)
    sid = m.group(1)
    # 结论行（容错：false/true 后可能直接跟"（条件说明）"而非管道）
    concl = re.search(r"结论:\s*存在漏洞=(true|false)([^\n]*)", b)
    hv_t = concl.group(1) if concl else None
    rest = (concl.group(2) or "") if concl else ""
    mcwe = re.search(r"CWE-(\d+)", rest)
    cwe = f"CWE-{mcwe.group(1)}" if mcwe else None
    concl_rest = rest.strip()[:80] if concl else ""
    # disagree（独立记录或正文声明）
    dis = re.search(r"disagree:\s*(.{0,200})", b)
    # 防御栏行号密度
    mdef = re.search(r"防御:\s*\n(.*?)(?=\n载荷:|\n组合链:|\n锚句:|\n结论:|\Z)", b, re.S)
    def_text = mdef.group(1) if mdef else ""
    line_refs = len(set(re.findall(r"L\d+", def_text)))
    led = ledger.get(sid)
    rows.append({
        "id": sid, "flags": led["flags"] if led else "?", "truth_hv": led["truth_hv"] if led else None,
        "truth_cwe": led.get("truth_cwe") if led else None,
        "teacher_hv": hv_t, "teacher_cwe": cwe, "concl_rest": concl_rest[:80],
        "disagree": dis.group(1)[:160] if dis else None,
        "defense_line_refs": line_refs, "block_chars": len(b),
        "parsed": concl is not None,
    })

for r in rows:
    if r["disagree"] and r["teacher_hv"] is None:
        r["class"] = "disagree"      # 纯 disagree 块（教师明示推不出真值，无结论行）
    elif not r["parsed"]:
        r["class"] = "parse_err"
    elif r["disagree"]:
        # 分两档：结论与真值一致但证据链断在样本外 = agree_qualified（降档可用）；
        # 结论与真值相反 = disagree（回流人工）
        if r["truth_hv"] is not None and (r["teacher_hv"] == "true") == r["truth_hv"]:
            r["class"] = "agree_qualified"
        else:
            r["class"] = "disagree"
    elif r["truth_hv"] is None:
        r["class"] = "no_truth"
    elif (r["teacher_hv"] == "true") == r["truth_hv"]:
        r["class"] = "agree"
        if r["truth_hv"] and r["truth_cwe"] and r["teacher_cwe"]:
            tn = re.match(r"CWE-(\d+)", r["teacher_cwe"])
            ln = re.match(r"CWE-(\d+)", r["truth_cwe"])
            r["cwe_match"] = (tn and ln and tn.group(1) == ln.group(1))
    else:
        r["class"] = "conflict"

cnt = {}
for r in rows:
    cnt[r["class"]] = cnt.get(r["class"], 0) + 1

out = {"summary": cnt, "rows": rows}
(RESULTS / "_redistill_truth_parse_20260913.json").write_text(
    json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

L = ["# 任务1 复核包产出对照（20260913）", "",
     f"31 包全覆盖。四分类：{cnt}", "",
     "## 分类明细", ""]
for cls in ("agree", "agree_qualified", "disagree", "conflict", "parse_err", "no_truth"):
    grp = [r for r in rows if r["class"] == cls]
    if not grp:
        continue
    label = {"agree_qualified": "agree_qualified（结论=真值但证据链断在样本外，降档可用）",
             "disagree": "disagree（教师拒绝/反对真值 → 回流人工）"}.get(cls, cls)
    L.append(f"### {label}（{len(grp)}）")
    L.append("")
    L.append("| id | flags | 真值 | 教师结论 | CWE对照 | 防御行号数 |")
    L.append("|---|---|---|---|---|---|")
    for r in grp:
        tv = ("有洞" if r["truth_hv"] else "无洞") if r["truth_hv"] is not None else "-"
        th = f"{r['teacher_hv']} / {r['teacher_cwe'] or '-'}"
        cm = {True: "一致", False: "**编号不同**"}.get(r.get("cwe_match"), "-") if cls == "agree" else "-"
        L.append(f"| {r['id']} | {'+'.join(r['flags'])} | {tv} {r['truth_cwe'] or ''} | {th} | {cm} | {r['defense_line_refs']} |")
    L.append("")
    for r in grp:
        if r["disagree"]:
            L.append(f"- **{r['id']} disagree**: {r['disagree']}")
        elif cls == "conflict":
            L.append(f"- **{r['id']} conflict**: 教师={r['teacher_hv']}/{r['teacher_cwe']} vs 真值={r['truth_hv']}/{r['truth_cwe']}；结论附言: {r['concl_rest']}")
    L.append("")

# 门E 检查：R5 负样本防御行号密度
r5 = [r for r in rows if "R5" in r["flags"]]
low = [r for r in r5 if r["defense_line_refs"] < 2 and r["class"] == "agree"]
L.append(f"## 门E 检查（R5 负样本 {len(r5)} 条）")
L.append("")
L.append(f"防御栏行号引用 <2 的 agree 条目：{len(low)} 条" + (f"：{[r['id'] for r in low]}" if low else "（全部合格）"))
(RESULTS / "_redistill_truth_parse_20260913.md").write_text("\n".join(L) + "\n", encoding="utf-8")

print("summary:", cnt)
print("R5 防御行号不足:", [r["id"] for r in low])
for r in rows:
    if r["class"] in ("conflict", "disagree"):
        print(f"  {r['class']:9} {r['id']:28} 教师={r['teacher_hv']}/{r['teacher_cwe']} 真值={r['truth_hv']}/{r['truth_cwe']}")
