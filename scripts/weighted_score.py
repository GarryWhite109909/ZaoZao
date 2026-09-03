"""独立加权评分器：读逐样本结果 JSON 出风险加权分，不碰推理链路。

定位：工程验收 / 迭代追踪辅助指标。论文主表仍用无权重标准指标
（recall / FPR / accuracy / strict），引用加权分时同报 --weights flat 对照。

用法：
  python scripts/weighted_score.py RESULT.json
  python scripts/weighted_score.py RESULT.json --manifest <manifest.json> \
      --weights experiments/scoring_config/weights_20260903.json --show-samples

  # 指定 manifest 可用最新答案覆盖结果内嵌的 expected_*（缺省用内嵌值）
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from experiments.scoring import (
    build_record,
    binary_counts,
    instance_hit,
    load_manifest_samples,
    load_weights,
    score_records,
)

DEFAULT_MANIFEST = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples/manifest.json"
DEFAULT_WEIGHTS = PROJECT_ROOT / "experiments/scoring_config/weights_20260903.json"


def fmt(v) -> str:
    return f"{v:.4f}" if isinstance(v, float) else ("—" if v is None else str(v))


def main() -> None:
    ap = argparse.ArgumentParser(description="风险加权评分器（只读结果文件，不重跑推理）")
    ap.add_argument("result", help="结果 JSON（须含逐样本 samples）")
    ap.add_argument("--manifest", default=None, help="答案 manifest（缺省用结果内嵌 expected_*）")
    ap.add_argument("--weights", default=str(DEFAULT_WEIGHTS), help="'flat' 或权重 JSON 路径")
    ap.add_argument("--show-samples", action="store_true", help="逐样本列出加权贡献")
    args = ap.parse_args()

    data = json.loads(Path(args.result).read_text(encoding="utf-8"))
    samples = data.get("samples") or []
    if not samples:
        raise SystemExit(f"[错误] {args.result} 没有 samples 字段")

    manifest = load_manifest_samples(args.manifest) if args.manifest else None
    risk_weights, credit, weights_note = load_weights(args.weights)

    records = []
    for s in samples:
        ov = manifest.get(s.get("file") or s.get("filename")) if manifest else None
        records.append(build_record(s, expected_override=ov))

    full = score_records(records, risk_weights, credit)
    w = full["weighted"]
    b = full["binary"]
    inst = full["instance"]

    print(f"■ {Path(args.result).name}")
    print(f"  权重表: {weights_note}")
    if manifest:
        print(f"  答案基准: {args.manifest}")
    print()
    print(f"  加权总分 weighted_score = {fmt(w['weighted_score'])}"
          f"   （漏洞侧覆盖 {fmt(w['vuln_coverage_weighted'])} × 权重占比 + 安全侧 {fmt(w['safe_side_score'])}）")
    print(f"  参照: sample_any_recall={fmt(full['strict_anyhit']['sample_any_recall'])}"
          f"  instance_micro={fmt(inst['instance_recall_micro'])}"
          f"  instance_macro={fmt(inst['instance_recall_macro'])}"
          f"  recall={fmt(b['recall'])}  FPR={fmt(b['false_positive_rate'])}")
    if w["unknown_risk_samples"]:
        print(f"  ⚠ {w['unknown_risk_samples']} 条样本 risk_level 缺失，按权重 1.0 计")
        if manifest is None:
            print("    （未指定 --manifest：结果文件通常不含 expected_risk_level 字段，"
                  "风险加权实际未生效。请加 --manifest <答案清单> 后重跑。）")

    if args.show_samples:
        print(f"\n  {'样本':<42}{'判定':<8}{'CWE命中':<12}{'得分':>8}")
        print(f"  {'-' * 74}")
        for r in records:
            if r["expected_present"] is True:
                n = max(len(r["expected_cwes"]), 1)
                if r["review"]:
                    judge, got = "review", f"{credit['review'] * n:.1f}/{n}"
                elif r["predicted"] is True:
                    h = sum(1 for e in r["expected_cwes"] if instance_hit(r, e))
                    judge = "TP" if h else "方向对"
                    got = f"{credit['hit'] * h + credit['direction_only'] * (n - h):.1f}/{n}"
                elif r["predicted"] is None:
                    judge, got = "parse_fail", f"0/{n}"
                else:
                    judge, got = "FN", f"0/{n}"
            else:
                if r["review"]:
                    judge, got = "review(安全)", "0.5/1"
                elif r["predicted"] is False:
                    judge, got = "TN", "1/1"
                elif r["predicted"] is None:
                    judge, got = "invalid", "0/1"
                else:
                    judge, got = "FP", "0/1"
            print(f"  {r['file']:<42}{judge:<8}{got:>12}")


if __name__ == "__main__":
    main()
