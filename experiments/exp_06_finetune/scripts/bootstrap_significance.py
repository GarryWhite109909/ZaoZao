"""
Bootstrap 显著性检验 —— 比较基线 vs 微调的检测指标差异是否显著。

输入：两个 evaluate.py 产生的 JSON 结果文件（--baseline / --finetuned）。
方法：配对 Block Bootstrap 重采样（同一测试集，按 file 配对），N=10000 次。
  - 多种子结果按 file 分组，每个 file 跨所有 seed 的样本作为一个块
  - 每次以 file 为单位有放回抽取 N 个块（N=file 数），块内所有 seed 样本一起抽出
  - 计算两组在本次重采样下的 recall / accuracy / fpr
  - 累计差值分布
输出：
  - 各指标的均值差、95% 置信区间、p 值（双尾：H0: 差值=0）
  - 是否显著（p < 0.05）

用法：
  python bootstrap_significance.py \
      --baseline results/exp_06_eval.baseline.20260707_120000.json \
      --finetuned results/exp_06_eval.finetuned_final.20260707_130000.json

  # 多种子聚合结果：按 file 分组作 block bootstrap（file 跨 seed 整体重采样）
  python bootstrap_significance.py \
      --baseline results/exp_06_eval.baseline_seeds3.*.json \
      --finetuned results/exp_06_eval.finetuned_final_seeds3.*.json \
      --n-bootstrap 10000
"""

import argparse
import json
import random
import sys
from pathlib import Path


def load_samples(path: Path) -> list[list[dict]]:
    """从 evaluate.py 的结果文件加载样本，按 file 分组（块）。

    优先使用 all_runs（多种子），否则退回 samples（单种子）。
    返回 list[list[dict]]：每个 file 一个块，块内为该 file 在所有 seed 的样本。
    block bootstrap 以 file 为重采样单元，避免把 (file, seed) 当独立观测。
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    flat = []
    if data.get("all_runs"):
        # 多种子：收集所有 (sample, seed) 对
        for run in data["all_runs"]:
            for s in run:
                flat.append(s)
    else:
        flat = data.get("samples", [])

    # 按 file 分组（保持首次出现顺序）
    blocks: list[list[dict]] = []
    index: dict = {}
    for s in flat:
        fname = s.get("file")
        if fname not in index:
            index[fname] = len(blocks)
            blocks.append([])
        blocks[index[fname]].append(s)
    return blocks


def compute_metrics(samples: list[dict]) -> dict:
    """从样本列表计算 recall/accuracy/fpr（宽松 + 严格两套口径）。

    宽松口径：parse_fail 不计入分母（单列统计），与历史结果兼容。
    严格口径（*_with_parse_fail）：parse_fail 按真值分流计入分母——
    漏洞样本解析失败计漏报、安全样本解析失败计错误，与 experiments/utils.py
    compute_detection_metrics 的严格口径定义一致（论文主结论优先引用严格口径）。
    若基线与微调的 parse_fail 率不同，只看宽松口径的显著性结论可能翻转。
    """
    tp = sum(1 for s in samples if s["outcome"] == "TP")
    fp = sum(1 for s in samples if s["outcome"] == "FP")
    fn = sum(1 for s in samples if s["outcome"] == "FN")
    tn = sum(1 for s in samples if s["outcome"] == "TN")
    # parse_fail 按真值分流（evaluate.py 样本带 expected_present 字段）
    pf_vuln = sum(1 for s in samples
                  if s["outcome"] == "parse_fail" and s.get("expected_present") is True)
    pf_safe = sum(1 for s in samples
                  if s["outcome"] == "parse_fail" and s.get("expected_present") is not True)
    pf = pf_vuln + pf_safe

    pos = tp + fn  # 真实正例
    neg = fp + tn  # 真实负例
    total = pos + neg  # 不含 parse_fail

    recall = tp / pos if pos > 0 else None
    accuracy = (tp + tn) / total if total > 0 else None
    fpr = fp / neg if neg > 0 else None
    # 严格口径：分母含 parse_fail（漏洞侧计漏报，全部样本计错误）
    pos_strict = pos + pf_vuln
    total_strict = total + pf
    recall_strict = tp / pos_strict if pos_strict > 0 else None
    accuracy_strict = (tp + tn) / total_strict if total_strict > 0 else None
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn, "parse_fail": pf,
        "parse_fail_vuln": pf_vuln, "parse_fail_safe": pf_safe,
        "recall": recall, "accuracy": accuracy, "fpr": fpr,
        "recall_with_parse_fail": recall_strict,
        "accuracy_with_parse_fail": accuracy_strict,
    }


def bootstrap_paired(
    baseline_samples: list[list[dict]],
    finetuned_samples: list[list[dict]],
    n_bootstrap: int,
    seed: int = 42,
) -> dict:
    """配对 Block Bootstrap：以 file 为重采样单元，比较两组指标差。

    每个 file 跨所有 seed 的样本作为一个块整体重采样（块内所有 seed 样本一起
    抽出），避免 (file, seed) 被当作独立观测而高估有效样本量。
    要求两组 file 集合一致且顺序对应（同一测试集）。

    返回各指标的差值分布统计：
      {
        metric: {
          "baseline_mean": float,
          "finetuned_mean": float,
          "diff_mean": float,
          "ci_low": float, "ci_high": float,  # 95% CI
          "p_value": float,                    # 双尾
          "significant": bool,                 # p < 0.05
          "n_bootstrap": int,
        }
      }
    """
    n = len(baseline_samples)
    if n != len(finetuned_samples):
        raise ValueError(
            f"file 块数不匹配：baseline={n}, finetuned={len(finetuned_samples)}。"
            "请确保两个评估文件使用同一测试集且种子一致。"
        )

    # 按 file 配对（块以 file 为单位）
    base_files = [blk[0].get("file") for blk in baseline_samples if blk]
    fine_files = [blk[0].get("file") for blk in finetuned_samples if blk]
    if base_files != fine_files:
        if sorted(base_files) == sorted(fine_files):
            # file 集合一致但顺序不同，按 file 排序后配对
            print("⚠️ 警告：baseline 和 finetuned 的 file 顺序不一致，按 file 排序后配对")
            baseline_samples = sorted(baseline_samples, key=lambda b: b[0].get("file", ""))
            finetuned_samples = sorted(finetuned_samples, key=lambda b: b[0].get("file", ""))
        else:
            raise ValueError(
                "file 集合不匹配，无法按 file 配对。请确保两组评估跑的是同一测试集。\n"
                f"baseline 前 5: {base_files[:5]}\n"
                f"finetuned 前 5: {fine_files[:5]}"
            )

    rng = random.Random(seed)
    # 严格口径（*_with_parse_fail）与宽松口径同时 bootstrap：
    # parse_fail 率不同的两组在两种口径下的显著性结论可能不同
    metrics_list = [
        "recall", "accuracy", "fpr",
        "recall_with_parse_fail", "accuracy_with_parse_fail",
    ]
    diff_dist = {m: [] for m in metrics_list}

    base_flat = [s for blk in baseline_samples for s in blk]
    fine_flat = [s for blk in finetuned_samples for s in blk]
    base_m = compute_metrics(base_flat)
    fine_m = compute_metrics(fine_flat)

    for _ in range(n_bootstrap):
        # 以 file 为单位有放回重采样，块内所有 seed 样本一起抽出
        idx = [rng.randrange(n) for _ in range(n)]
        b_sub = [s for i in idx for s in baseline_samples[i]]
        f_sub = [s for i in idx for s in finetuned_samples[i]]
        b_metrics = compute_metrics(b_sub)
        f_metrics = compute_metrics(f_sub)
        for m in metrics_list:
            if b_metrics[m] is None or f_metrics[m] is None:
                continue
            # recall/accuracy（含严格口径）：微调 - 基线（>0 表示微调更好）
            # fpr：基线 - 微调（>0 表示微调更好，因为 fpr 下降）
            if "fpr" in m:
                diff_dist[m].append(b_metrics[m] - f_metrics[m])
            else:
                diff_dist[m].append(f_metrics[m] - b_metrics[m])

    summary = {}
    for m in metrics_list:
        diffs = diff_dist[m]
        if not diffs:
            summary[m] = None
            continue
        diffs_sorted = sorted(diffs)
        n_diff = len(diffs)
        # 95% CI: 第 2.5 和 97.5 百分位
        ci_low_idx = int(0.025 * n_diff)
        ci_high_idx = int(0.975 * n_diff)
        ci_low = diffs_sorted[ci_low_idx]
        ci_high = diffs_sorted[min(ci_high_idx, n_diff - 1)]

        # 双尾 p 值：|mean_diff| 在 0 的两侧各占多少
        # 等价于：H0 下 diff=0，看观测差值偏离 0 的概率
        # 用 bootstrap 分布中 ≤0 和 ≥0 的比例的两倍（取较小者）
        n_le_zero = sum(1 for d in diffs if d <= 0)
        n_ge_zero = sum(1 for d in diffs if d >= 0)
        # 单侧 p = min(P(diff<=0), P(diff>=0))；双尾 = 2 * 单侧
        p_one_side = min(n_le_zero, n_ge_zero) / n_diff
        p_value = min(1.0, 2 * p_one_side)

        # 微调更好的方向：recall/accuracy（含严格口径）差>0 好，fpr 差>0 好（已转换）
        base_val = base_m[m]
        fine_val = fine_m[m]
        if "fpr" in m:
            diff_point = base_val - fine_val if base_val is not None and fine_val is not None else None
            better = (diff_point is not None and diff_point > 0)
        else:
            diff_point = fine_val - base_val if base_val is not None and fine_val is not None else None
            better = (diff_point is not None and diff_point > 0)

        summary[m] = {
            "baseline_mean": round(base_val, 4) if base_val is not None else None,
            "finetuned_mean": round(fine_val, 4) if fine_val is not None else None,
            "diff_mean": round(sum(diffs) / n_diff, 4),
            "ci_low": round(ci_low, 4),
            "ci_high": round(ci_high, 4),
            "p_value": round(p_value, 4),
            "significant": p_value < 0.05,
            "direction": "finetuned_better" if better else (
                "finetuned_worse" if diff_point is not None and diff_point < 0 else "tie"
            ),
            "n_bootstrap": n_diff,
        }
    return summary


def main():
    parser = argparse.ArgumentParser(description="Bootstrap 显著性检验：baseline vs finetuned")
    parser.add_argument("--baseline", type=str, required=True,
                        help="基线评估结果 JSON 文件")
    parser.add_argument("--finetuned", type=str, required=True,
                        help="微调评估结果 JSON 文件")
    parser.add_argument("--n-bootstrap", type=int, default=10000,
                        help="Bootstrap 迭代次数（默认 10000）")
    parser.add_argument("--seed", type=int, default=42, help="随机种子")
    parser.add_argument("--output", type=str, default=None,
                        help="可选：将结果保存到 JSON 文件")
    args = parser.parse_args()

    baseline_path = Path(args.baseline)
    finetuned_path = Path(args.finetuned)
    if not baseline_path.exists():
        print(f"错误：基线文件不存在: {baseline_path}")
        sys.exit(1)
    if not finetuned_path.exists():
        print(f"错误：微调文件不存在: {finetuned_path}")
        sys.exit(1)

    print(f"加载基线样本: {baseline_path}")
    baseline_samples = load_samples(baseline_path)
    print(f"  样本数: {sum(len(b) for b in baseline_samples)}（{len(baseline_samples)} files）")
    print(f"加载微调样本: {finetuned_path}")
    finetuned_samples = load_samples(finetuned_path)
    print(f"  样本数: {sum(len(b) for b in finetuned_samples)}（{len(finetuned_samples)} files）")

    print(f"\n开始 Bootstrap 检验（n={args.n_bootstrap}, seed={args.seed}）...")
    summary = bootstrap_paired(
        baseline_samples, finetuned_samples,
        n_bootstrap=args.n_bootstrap, seed=args.seed,
    )

    print("\n" + "=" * 72)
    print("Bootstrap 显著性检验结果（配对，双尾）")
    print("=" * 72)
    print(f"{'指标':<14} {'基线':>8} {'微调':>8} {'差值':>8} "
          f"{'95% CI':>22} {'p值':>8} {'显著?':>8}")
    print("-" * 72)
    # 严格口径在前（论文主结论优先引用严格口径，见 experiments/utils.py 约定）
    display = [
        ("recall_with_parse_fail", "recall(严格)"),
        ("accuracy_with_parse_fail", "acc(严格)"),
        ("recall", "recall(宽松)"),
        ("accuracy", "acc(宽松)"),
        ("fpr", "fpr(宽松)"),
    ]
    for key, label in display:
        s = summary[key]
        if s is None:
            print(f"{label:<14}  (无数据)")
            continue
        ci_str = f"[{s['ci_low']:+.4f}, {s['ci_high']:+.4f}]"
        sig_str = "✓" if s["significant"] else "✗"
        # 方向标注：finetuned_better 标 +，worse 标 -
        dir_mark = ""
        if s["direction"] == "finetuned_better":
            dir_mark = " ▲"
        elif s["direction"] == "finetuned_worse":
            dir_mark = " ▼"
        print(f"{label:<14} {s['baseline_mean']:>8.4f} {s['finetuned_mean']:>8.4f} "
              f"{s['diff_mean']:>+8.4f} {ci_str:>22} {s['p_value']:>8.4f} "
              f"{sig_str:>8}{dir_mark}")

    print("\n说明：")
    print("  - 差值 = 微调 - 基线（recall/accuracy 越大越好，fpr 越小越好）")
    print("  - 95% CI 不含 0 ⇒ p < 0.05 ⇒ 显著")
    print("  - ▲ 微调更好，▼ 微调更差")
    print("  - 严格口径把 parse_fail 计入分母（漏洞侧计漏报、安全侧计错误），")
    print("    论文主结论优先引用严格口径；parse_fail 率不同时两口径结论可能不同")

    # 整体结论（以严格口径为准，宽松口径并列展示）
    recall_sig = summary.get("recall_with_parse_fail", {}).get("significant", False) if summary.get("recall_with_parse_fail") else False
    acc_sig = summary.get("accuracy_with_parse_fail", {}).get("significant", False) if summary.get("accuracy_with_parse_fail") else False
    fpr_sig = summary.get("fpr", {}).get("significant", False) if summary.get("fpr") else False
    n_sig = sum([recall_sig, acc_sig, fpr_sig])
    print(f"\n整体（严格口径）：{n_sig}/3 项指标显著（p<0.05）")

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({
                "baseline_file": str(baseline_path),
                "finetuned_file": str(finetuned_path),
                "n_bootstrap": args.n_bootstrap,
                "seed": args.seed,
                "baseline_n_samples": sum(len(b) for b in baseline_samples),
                "finetuned_n_samples": sum(len(b) for b in finetuned_samples),
                "baseline_metrics": compute_metrics([s for b in baseline_samples for s in b]),
                "finetuned_metrics": compute_metrics([s for b in finetuned_samples for s in b]),
                "bootstrap_summary": summary,
            }, f, indent=2, ensure_ascii=False)
        print(f"\n结果已保存: {out_path}")


if __name__ == "__main__":
    main()
