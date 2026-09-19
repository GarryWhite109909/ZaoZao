# -*- coding: utf-8 -*-
"""执行 3 条 NVD 依据改标（20260911，Garry 批准）+ 未投喂 kit 盘点。

改标（沿用 9/11 规则：原值存 expected_cwe_original，台账追加）：
  00160: CWE-863 → CWE-639（NVD CVE-2026-69160；教师判无洞 → 同步进重蒸馏队列 R4）
  00270: CWE-90  → CWE-20 （NVD CVE-2022-2232）
  00333: CWE-327 → CWE-347（NVD CVE-2022-23540 = 287/347；按项目预置裁决"JWT 签名验证被禁用→347 非 327"）
"""
import json
import sys
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
CORPUS = BASE / "corpus"
WAVE = CORPUS / "diffpair_wave1"
RESULTS = WAVE / "results"

CHANGES = {
    "diffpair-corpus_00160": ("CWE-639", "NVD CVE-2026-69160 官方=CWE-639；教师判无洞→进重蒸馏队列"),
    "diffpair-corpus_00270": ("CWE-20", "NVD CVE-2022-2232 官方=CWE-20（Class 级，官方口径优先）"),
    "diffpair-corpus_00333": ("CWE-347", "NVD CVE-2022-23540 官方=287/347；按项目预置裁决 JWT 签名验证被禁用→347"),
}

m_path = WAVE / "manifest_PRIVATE.json"
manifest = json.loads(m_path.read_text(encoding="utf-8"))
for kid, (new, why) in CHANGES.items():
    m = manifest[kid]
    m.setdefault("expected_cwe_original", m["expected_cwe"])
    m["expected_cwe"] = new
    m["relabel_nvd_20260911"] = why
m_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
print("改标完成:", {k: (manifest[k]["expected_cwe_original"], manifest[k]["expected_cwe"]) for k in CHANGES})

# 台账（dict 结构，追加 nvd 批次键）
ledger_path = RESULTS / "_relabel_20260911.json"
ledger = json.loads(ledger_path.read_text(encoding="utf-8")) if ledger_path.exists() else {}
batch = {}
for kid, (new, why) in CHANGES.items():
    batch[kid] = {"from": "CWE-863" if kid.endswith("00160") else manifest[kid]["expected_cwe_original"],
                  "to": new, "basis": "NVD 来源③（门D），Garry 20260911 批准", "note": why}
ledger["nvd_20260911"] = {"applied": datetime.now().isoformat(timespec="seconds"), "items": batch}
ledger_path.write_text(json.dumps(ledger, ensure_ascii=False, indent=1), encoding="utf-8")

# 同步 result_blocks 的 label_cwe
blocks = [json.loads(l) for l in (RESULTS / "result_blocks.jsonl").open(encoding="utf-8") if l.strip()]
n = 0
for b in blocks:
    kid = b.get("id")
    if kid in CHANGES:
        b.setdefault("label_cwe_original", b.get("label_cwe"))
        b["label_cwe"] = CHANGES[kid][0]
        b["relabeled_nvd"] = True
        n += 1
(RESULTS / "result_blocks.jsonl").write_text(
    "\n".join(json.dumps(b, ensure_ascii=False) for b in blocks) + "\n", encoding="utf-8")
print(f"result_blocks 同步 {n} 块")

# ---------- 未投喂 kit 盘点 ----------
g = json.loads((RESULTS / "_gates_20260911.json").read_text(encoding="utf-8"))
tpf_ids = set()
for b in blocks:
    tpf_ids.add(b["id"])
all_active = [r for r in g["rows"] if not r["quarantined"]]
unfed = [r for r in all_active if r["kit"] not in tpf_ids]
fed = [r for r in all_active if r["kit"] in tpf_ids]
from collections import Counter
print(f"\nactive {len(all_active)} = 已投喂(有教师输出) {len(fed)} + 未投喂 {len(unfed)}")
print("未投喂 kit 治理状态:")
print("  门A:", Counter(r["gateA"] for r in unfed).most_common())
print("  门C:", Counter(r["gateC"] for r in unfed).most_common())
print("  改标过的:", sum(1 for r in unfed if r.get("relabeled")))
print("  NVD背书:", sum(1 for r in unfed if r["kit"] in
      {"diffpair-corpus_" + k for k in ("00191","00200","00204","00221","00223","00243","00244","00245","00254","00261","00283","00288","00297","00298","00299","00304","00308","00327","00332","00335")}))

detail = [{"kit": r["kit"], "cve": r["cve"], "cwe": r["cwe_now"],
           "gateA": r["gateA"], "gateC": r["gateC"], "relabeled": r.get("relabeled", False)}
          for r in unfed]
(RESULTS / "_unfed_kits_20260911.json").write_text(
    json.dumps({"fed": len(fed), "unfed": len(unfed), "rows": detail}, ensure_ascii=False, indent=1),
    encoding="utf-8")
