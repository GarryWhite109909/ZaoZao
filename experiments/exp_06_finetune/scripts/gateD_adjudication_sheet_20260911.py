# -*- coding: utf-8 -*-
"""门 D 裁定单生成（20260911）：把 42 条 pending_lead 做机械预分类 + 逐条证据，压缩人工裁定工作量。

预分类：
  P1 缺失型候选（12 条，修复行含要件）→ 标签大概率对，建议保留，抽查即可
  P2 词表误伤候选（seed 全文 strong 要件>0）→ 门 C 判定窗口问题，可翻案保留
  P3 需读码裁定（全文零要件且修复行零要件）→ 真正需要人/独立真值的部分
每条附：CVE 描述、标签、seed 全文要件明细、修复新增行、建议动作。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from diffpair_patchlib import parse_patch
from diffpair_gates_v2_20260911 import CWE_EVIDENCE, count_evidence, cwe_num

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
CORPUS = BASE / "corpus"
WAVE = CORPUS / "diffpair_wave1"
RESULTS = WAVE / "results"

g = json.loads((RESULTS / "_gates_20260911.json").read_text(encoding="utf-8"))
pend = [r for r in g["rows"] if r["gateC"] == "pending_lead" and not r["quarantined"]]
tp = json.loads((CORPUS / "train_pool/manifest.json").read_text(encoding="utf-8"))["samples"]
tpf = {s["file"]: s for s in tp}

rows = []
for r in pend:
    e = tpf.get(r["seed"], {})
    seed_p = CORPUS / "train_pool" / r["seed"]
    seed_text = seed_p.read_text(encoding="utf-8", errors="replace") if seed_p.exists() else ""
    patch_p = CORPUS / e["patch_file"] if e.get("patch_file") else None
    ptext = patch_p.read_text(encoding="utf-8", errors="replace") if (patch_p and patch_p.exists()) else ""
    adds = "\n".join(l for h in parse_patch(ptext) for t, l in h["lines"] if t == "+")
    cn = cwe_num(r["cwe_now"]) or ""
    sv, wv, sd, wd = count_evidence(seed_text, cn)
    _, av, _, _ = count_evidence(adds, cn)
    if av > 0:
        cls, sug = "P1缺失型", "修复行含要件 → 大概率『因缺失而致的洞』，标签保留，抽查确认"
    elif sv > 0:
        cls, sug = "P2词表误伤", f"A 版全文 strong 要件 {sv} 处 → 门C 复扫窗口问题，翻案保留"
    elif wv > 3:
        cls, sug = "P2b弱信号", f"weak 要件 {wv} 处 → 疑似标签方向可成立，读码快速确认"
    else:
        cls, sug = "P3需读码", "全文与修复行均无要件 → 标签可疑：读码改标 / 踢出 / 查 NVD 官方"
    rows.append({"kit": r["kit"], "cve": r["cve"], "cwe": r["cwe_now"], "class": cls,
                 "suggestion": sug, "seed_strong": sv, "seed_weak": wv, "adds_strong": av,
                 "strong_detail": sd[:5], "desc": (e.get("expected_vulnerability") or "")[:200],
                 "patch_adds_head": [l.strip() for l in adds.splitlines() if l.strip()][:5]})

cnt = {}
for r in rows:
    cnt[r["class"]] = cnt.get(r["class"], 0) + 1
(RESULTS / "_gateD_adjudication_20260911.json").write_text(
    json.dumps({"summary": cnt, "rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")

L = ["# 门 D 裁定单（42 条 pending_lead 机械预分类，20260911）", "",
     f"预分类：{cnt}", "",
     "**怎么用**：P1/P2 基本可以批量采纳（抽 2-3 条复核即可）；你真正要逐条读码的只有 P3（和想更稳妥时的 P2b）。"
     "每条下面已给齐证据，裁定动作 = 在表里勾选：保留 / 改标 <CWE> / 判死踢出。", ""]
for cls in ("P1缺失型", "P2词表误伤", "P2b弱信号", "P3需读码"):
    grp = [r for r in rows if r["class"] == cls]
    if not grp:
        continue
    L.append(f"## {cls}（{len(grp)} 条）")
    L.append("")
    L.append("| kit | CVE | 标签 | A版要件(s/w) | 修复行要件 | 建议 |")
    L.append("|---|---|---|---|---|---|")
    for r in grp:
        L.append(f"| {r['kit']} | {r['cve'] or '-'} | {r['cwe']} | {r['seed_strong']}/{r['seed_weak']} "
                 f"| {r['adds_strong']} | {r['suggestion'][:40]} |")
    L.append("")
    for r in grp:
        L.append(f"### {r['kit']} · {r['cwe']} · {r['cve'] or '-'}")
        L.append(f"- 描述: {r['desc']}…")
        if r["strong_detail"]:
            L.append(f"- A 版要件明细: {r['strong_detail']}")
        if r["patch_adds_head"]:
            L.append("- 修复新增行: " + " ; ".join(f"`{l[:60]}`" for l in r["patch_adds_head"][:3]))
        L.append(f"- 建议: {r['suggestion']}")
        L.append("")
(RESULTS / "_gateD_adjudication_20260911.md").write_text("\n".join(L) + "\n", encoding="utf-8")
print("summary:", cnt)
for r in rows:
    if r["class"] == "P3需读码":
        print(f"  P3 {r['kit']} {r['cwe']} {r['cve']}")
