# -*- coding: utf-8 -*-
"""2026-09-10 落库闭环验证：数据集 13 行新状态 + L1 机检冲突数 修复前/后。"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune")
rows = [json.loads(l) for l in (BASE / "data/final_train_chatml_alpha06_v2_17.jsonl").open(encoding="utf-8") if l.strip()]


def ga(r):
    return [m["content"] for m in r["messages"] if m["role"] == "assistant"][-1]


def verd(a):
    m = re.search(r"```json\s*(.*?)```", a, re.S)
    if not m:
        return None
    v = json.loads(m.group(1))
    hv = v.get("has_vulnerability")
    if isinstance(hv, str):
        hv = hv.strip().lower() == "true"
    c = re.search(r"CWE-(\d+)", str(v.get("vulnerability_type") or ""))
    return (hv, "CWE-" + c.group(1) if c else "none")


TARGETS = {113: "safe", 153: "safe", 218: "safe", 1644: "safe", 7872: "True/CWE-639(无操作)",
           3446: "True/CWE-90", 3854: "safe(叙事升级)", 7900: "safe", 7901: "True/CWE-90",
           3531: "True/CWE-787", 3762: "True/CWE-415", 7090: "True/CWE-94", 7573: "safe"}

print("=" * 74)
print("一、数据集 v2_17 落库结果（13 行在册）")
print("=" * 74)
ok = True
for ln, want in TARGETS.items():
    got = verd(ga(rows[ln - 1]))
    s = f"{'True' if got[0] else 'safe'}/{got[1]}"
    print(f"  行 {ln:5d}  期望 {want:24s} 实际 {s}")
print(f"  总行数：{len(rows)}（应为 10022）")

print()
print("=" * 74)
print("二、L1 机检冲突数：修复前 vs 修复后")
print("=" * 74)
SNAP = BASE / "audit/cwe_offline/nvd_cwe_check_full_20260908.snapshot_pre_rebind_20260910.jsonl"
FIXED = BASE / "audit/cwe_offline/nvd_cwe_check_full_20260908.jsonl"


def conflicts(path):
    objs = [json.loads(l) for l in path.open(encoding="utf-8") if l.strip()]
    bad = []
    for o in objs:
        nvd = set(o.get("nvd_cwes") or [])
        if not nvd or o.get("error"):
            continue
        for s in o["samples"]:
            lab = set(s.get("assistant_labels") or [])
            if lab and not (lab & nvd):
                bad.append((o["cve"], s["line"], sorted(lab), sorted(nvd)))
    return len(objs), sum(len(o["samples"]) for o in objs), bad


for name, p in (("修复前(快照)", SNAP), ("修复后(现行)", FIXED)):
    n_cve, n_bind, bad = conflicts(p)
    print(f"  {name}：{n_cve} 条 CVE / {n_bind} 条绑定 / "
          f"冲突 CVE {len({b[0] for b in bad})} 个（行级 {len(bad)} 项）")
    if name.startswith("修复后") and bad:
        for cve, ln, lab, nvd in bad:
            print(f"      {cve:18s} 行 {ln:5d} 库内 {lab} vs NVD {nvd}")
