"""
统一重算所有历史评估文件的 strict 指标（CWE 纠正工具口径）。

背景：2026-08-16 起 compute_strict_metrics 才接入 cwe_normalizer（编号纠正 +
父子族宽松匹配 + evidence 二次提取）。此前的历史文件 strict_metrics 是
"未纠正"口径，与素材库中"纠正后"的数值混用造成混乱。本脚本用当前逻辑
（normalize_cwe_label + normalize_with_evidence + cwe_family_match）对全部
相关结果文件重算 strict 指标，输出 旧值 vs 新值 对照表，供素材库统一口径。

口径（与 evaluate.py 完全一致）：
  - strict_recall = strict_tp / (tp+fn)          主口径，分母不含 parse_fail
  - strict_recall_with_parse_fail = strict_tp / (tp+fn+parse_fail)
  - strict_accuracy = (strict_tp + tn) / valid
  - exp_07 两阶段：剔除 decision 含 "review" 的样本（review 既非 TP 也非 FN，
    与素材库"recall 不含 review"口径一致）

2026-08-18 纠正工具两项修复（重算数字已包含）：
  1. CSRF 关键词移到 "cross-site"（XSS）之前——"cross-site request forgery"
     含 "cross-site" 子串，原顺序把 CSRF 误归一为 CWE-79；
  2. normalize_with_evidence 守卫——字段已含明确 CWE 编号时不再用 evidence
     覆盖（实测误伤：字段 "CWE-798 Use of Hard-coded Credentials" 正确，因
     连字符未命中关键词被 evidence 的 "sql" 覆盖成 CWE-89）。

用法：
    python recompute_strict_metrics.py [--write]
      --write  把重算结果写回各 JSON 文件的 strict_metrics 字段（默认只打印对照）
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.cwe_normalizer import (
    normalize_cwe_label,
    normalize_with_evidence,
    cwe_family_match,
)

_CWE_PATTERN = re.compile(r"(CWE-\d+)", re.IGNORECASE)


def extract_cwe(vulnerability_type: str) -> str:
    if not vulnerability_type:
        return ""
    m = _CWE_PATTERN.search(vulnerability_type)
    return m.group(1).upper() if m else ""


def cwe_matches(model_cwe: str, expected_cwe: str) -> bool:
    if not expected_cwe or expected_cwe.upper() == "N/A":
        return True
    if not model_cwe:
        return False
    expected_cwes = [c.strip().upper() for c in expected_cwe.split(";") if c.strip()]
    return any(cwe_family_match(model_cwe, ec) for ec in expected_cwes)


def compute_strict(records: list[dict], *, two_stage: bool = False) -> dict:
    """与 evaluate.py compute_strict_metrics 一致（当前 CWE 纠正口径）。"""
    # exp_07 口径：review 既非 TP 也非 FN，剔除
    if two_stage:
        records = [r for r in records if "review" not in (r.get("decision") or "")]

    strict_tp = 0
    cwe_mismatch = 0
    for r in records:
        exp = r.get("expected_present")
        pred = r.get("predicted")
        if exp is None or pred is None:
            continue
        if exp and pred:
            if two_stage:
                model_vt = r.get("vulnerability_type", "") or r.get("raw_vulnerability_type", "")
                evidence = r.get("explanation", "") or r.get("reason", "") or ""
            else:
                model_vt = r.get("model_vulnerability_type", "")
                evidence = r.get("raw_output", "") or ""
            expected_cwe = r.get("expected_cwe", "")
            model_cwe = extract_cwe(
                normalize_with_evidence(model_vt, evidence) if evidence else normalize_cwe_label(model_vt)
            )
            if cwe_matches(model_cwe, expected_cwe):
                strict_tp += 1
            else:
                cwe_mismatch += 1

    # 混淆矩阵（与 evaluate.py 的 loose 指标同分母）
    tp = sum(1 for r in records if r.get("expected_present") is True and r.get("predicted") is True)
    fn = sum(1 for r in records if r.get("expected_present") is True and r.get("predicted") is False)
    tn = sum(1 for r in records if r.get("expected_present") is False and r.get("predicted") is False)
    valid = tp + fn + tn + sum(
        1 for r in records if r.get("expected_present") is False and r.get("predicted") is True
    )
    parse_fail_count = sum(
        1 for r in records
        if r.get("expected_present") is True and r.get("predicted") is None
    )

    vuln_total = tp + fn
    strict_recall = strict_tp / vuln_total if vuln_total else None
    strict_accuracy = (strict_tp + tn) / valid if valid else None
    vuln_total_with_parse_fail = vuln_total + parse_fail_count
    strict_recall_with_parse_fail = strict_tp / vuln_total_with_parse_fail if vuln_total_with_parse_fail else None

    return {
        "strict_tp": strict_tp,
        "strict_fn": vuln_total - strict_tp,
        "cwe_mismatch": cwe_mismatch,
        "parse_fail_count": parse_fail_count,
        "strict_recall": round(strict_recall, 4) if strict_recall is not None else None,
        "strict_recall_with_parse_fail": round(strict_recall_with_parse_fail, 4) if strict_recall_with_parse_fail is not None else None,
        "strict_accuracy": round(strict_accuracy, 4) if strict_accuracy is not None else None,
    }


# ---------------------------------------------------------------------------
# 文件清单：论文素材库引用的全部结果文件
# ---------------------------------------------------------------------------
RESULT_FILES = [
    # α0（单阶段，exp_06）
    ("α0 no-merge combined", "experiments/exp_06_finetune/results/alpha0_87_full.json", "single"),
    # α0.5 纯 LLM 消融（exp_06）
    ("α0.5 alpha05_min", "experiments/exp_06_finetune/results/exp_06_eval.finetuned_custom.alpha05_min.20260815_232648.json", "single"),
    ("α0.5 alpha05_lite", "experiments/exp_06_finetune/results/exp_06_eval.finetuned_custom.alpha05_lite.20260816_002243.json", "single"),
    ("α0.5 alpha05", "experiments/exp_06_finetune/results/exp_06_eval.finetuned_custom.alpha05.20260816_012139.json", "single"),
    ("α0.5 combined", "experiments/exp_06_finetune/results/exp_06_eval.finetuned_custom.combined.20260816_023631.json", "single"),
    # v9max（Ollama 发布形态，exp_06）——注意 20260808_131115 是 CVE-fix 20 集
    ("v9max Ollama base (CVE-fix 20)", "experiments/exp_06_finetune/results/exp_06_eval.ollama_garrywhite109909/graduation-vuln-scanner_v9max.20260808_131115.json", "single"),
    ("v9max Ollama anti_fp_cot (87)", "experiments/exp_06_finetune/results/exp_06_eval.ollama_garrywhite109909/graduation-vuln-scanner_v9max.anti_fp_cot.20260808_125027.json", "single"),
    ("v9max Ollama combined (87)", "experiments/exp_06_finetune/results/exp_06_eval.ollama_garrywhite109909/graduation-vuln-scanner_v9max.combined.20260808_130554.json", "single"),
    # 两阶段（exp_07）fixed 系列
    ("exp_07 fixed5（论文主数据）", "experiments/exp_07_two_stage_eval/results/exp_07_two_stage_eval.nivis-alpha0.triage_train_aligned.20260818_104203.json", "two_stage"),
    ("exp_07 fixed3", "experiments/exp_07_two_stage_eval/results/exp_07_two_stage_eval.nivis-alpha0.triage_train_aligned.fixed3.20260818.json", "two_stage"),
    ("exp_07 fixed4", "experiments/exp_07_two_stage_eval/results/exp_07_two_stage_eval.nivis-alpha0.triage_train_aligned.fixed4.20260818.json", "two_stage"),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="把重算结果写回 JSON 文件")
    ap.add_argument("--all", action="store_true",
                    help="批量扫描 exp_06/exp_07 results 全部含 samples 的文件并重算（写回需配合 --write）")
    args = ap.parse_args()

    if args.all:
        jobs = []
        for root in (PROJECT_ROOT / "experiments/exp_06_finetune/results",
                     PROJECT_ROOT / "experiments/exp_07_two_stage_eval/results"):
            for p in sorted(root.rglob("*.json")):
                try:
                    d = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if not isinstance(d, dict) or not d.get("samples"):
                    continue
                samples = d["samples"]
                if not isinstance(samples, list) or not samples:
                    continue
                # 需有 strict 计算基础字段
                s0 = samples[0]
                has_cwe = "expected_cwe" in s0
                if not has_cwe:
                    continue
                two_stage = "decision" in s0
                jobs.append((p.relative_to(PROJECT_ROOT).as_posix(), str(p), two_stage))
        print(f"扫描到 {len(jobs)} 个可重算文件")
    else:
        jobs = [(label, str(PROJECT_ROOT / rel), mode == "two_stage")
                for label, rel, mode in RESULT_FILES]

    print(f"{'变体':<44} {'旧 strict_r':>11} {'新 strict_r':>11} {'新 r_pf':>8} {'旧 strict_acc':>13} {'新 strict_acc':>13}  变化")
    print("-" * 115)

    for label, path_str, two_stage in jobs:
        p = Path(path_str)
        d = json.loads(p.read_text(encoding="utf-8"))
        samples = d["samples"]

        new_sm = compute_strict(samples, two_stage=two_stage)
        old_sm = d.get("strict_metrics") or {}

        def fmt(x):
            return "N/A" if x is None else f"{x:.4f}"

        change_parts = []
        for key, name in (("strict_recall", "recall"), ("strict_accuracy", "acc")):
            ov, nv = old_sm.get(key), new_sm.get(key)
            if ov is not None and nv is not None and abs(ov - nv) > 0.0005:
                change_parts.append(f"{name} {fmt(ov)}→{fmt(nv)}")

        print(
            f"{label[:44]:<44} {fmt(old_sm.get('strict_recall')):>11} {fmt(new_sm['strict_recall']):>11} "
            f"{fmt(new_sm['strict_recall_with_parse_fail']):>8} "
            f"{fmt(old_sm.get('strict_accuracy')):>13} {fmt(new_sm['strict_accuracy']):>13}  {', '.join(change_parts)}"
        )

        if args.write:
            d["strict_metrics"] = new_sm
            d["strict_metrics_note"] = "CWE 纠正口径重算 2026-08-18（CSRF 顺序修复 + evidence 编号守卫）"
            p.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
