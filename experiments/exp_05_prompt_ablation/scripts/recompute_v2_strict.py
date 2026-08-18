# -*- coding: utf-8 -*-
"""exp_05 第二轮（v2）strict 指标离线重算（A2 闭环）。

背景：未决事项 A2 —— exp_05 v2 结果 JSON 的聚合指标未持久化 strict 尺度，
`BASE_PROMPT strict_recall 55.8% 最优` 无存档支撑。v2 原始 JSON 的逐样本
`runs[].parsed_verdict.vulnerability_type` 实际已落盘，本脚本用与
recompute_strict_metrics.py 完全一致的 CWE 纠正口径（normalize + evidence
守卫 + 父子族匹配）从原始输出重算 8+2 变体的 strict 指标，落盘存档。

用法：
    python recompute_v2_strict.py [--write]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "experiments/exp_06_finetune/scripts"))

from recompute_strict_metrics import compute_strict  # noqa: E402

V2_FILES = [
    PROJECT_ROOT / "experiments/exp_05_prompt_ablation/results/exp_05_prompt_ablation_v2.qwen3-8b.ablation_v2.repeat1.20260802_091605.json",
    PROJECT_ROOT / "experiments/exp_05_prompt_ablation/results/exp_05_prompt_ablation_v2.qwen3-8b.ablation_v2.repeat1.20260802_114607.json",
]
OUT = PROJECT_ROOT / "experiments/exp_05_prompt_ablation/results/exp_05_v2_strict_metrics.json"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="把重算结果写盘")
    args = ap.parse_args()

    rows = {}
    for f in V2_FILES:
        d = json.loads(f.read_text(encoding="utf-8"))
        for s in d["samples"]:
            variant = s["variant"]
            runs = s.get("runs") or []
            pv = (runs[0].get("parsed_verdict") or {}) if runs else {}
            rows.setdefault(variant, []).append({
                "file": s.get("file"),
                "expected_present": s.get("expected_present"),
                "expected_cwe": s.get("expected_cwe"),
                "predicted": s.get("majority_verdict"),
                "model_vulnerability_type": (pv or {}).get("vulnerability_type") or "",
                "raw_output": (runs[0].get("raw_output") or "") if runs else "",
            })

    out = {
        "experiment": "exp_05_prompt_ablation_v2（2026-08-02 第二轮消融）",
        "口径": "strict 列全部为 2026-08-18 CWE 纠正口径（normalize + evidence 守卫 + 父子族匹配），"
                "与 recompute_strict_metrics.py / evaluate.py compute_strict_metrics 一致",
        "predicted": "多数表决 majority_verdict（repeat=1，单次即多数）",
        "strict_by_variant": {},
    }
    for variant, records in rows.items():
        out["strict_by_variant"][variant] = compute_strict(records)

    text = json.dumps(out, ensure_ascii=False, indent=2)
    print(text)

    # 顺带回答 A2 原始问题：base（即 BASE_PROMPT）的 strict 是否仍最优
    sb = out["strict_by_variant"]
    best = max(sb, key=lambda v: (sb[v]["strict_recall"] or 0, sb[v]["strict_accuracy"] or 0))
    print("\n== 结论 ==")
    print(f"strict_recall 最高变体: {best}（{sb[best]['strict_recall']}），"
          f"base = {sb['base']['strict_recall']}；旧注释 55.8% 存档现已核验/替代")

    if args.write:
        OUT.write_text(text + "\n", encoding="utf-8")
        print(f"\n已写盘: {OUT}")


if __name__ == "__main__":
    main()
