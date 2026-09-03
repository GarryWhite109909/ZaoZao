"""批量统一打分：把历史结果文件全部用 experiments/scoring.py 同一套口径重算，
产出可横向对比的总表（二元 + strict + 实例级 micro/macro + 加权分）。

背景（2026-09-03）：评分体系升级（实例级 + 加权分）后，历史纯 LLM 结果需要用
同一机制重算一遍才能与最新数据对比。本脚本自动识别三种 schema（exp_06 纯
LLM / exp_04~05 repeat 多数表决 / exp_07 两阶段）、按样本文件名前缀自动路由
答案 manifest（87 合成 / CVE-fix / rolling_dev），全部按现行答案重算。

用法：
  # 默认：全量重算 exp_06 系（n>=20 的运行），输出 markdown + json
  python scripts/score_batch.py

  # 指定文件/通配符与输出
  python scripts/score_batch.py "experiments/exp_06_finetune/results/v5/*.json" \
      --md table.md --json table.json

排除规则：_archive_* 目录（Qwen2.5 时代，素材库标注"不可直接对比"）与
n < --min-n 的探针/中断跑默认跳过。
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from experiments.scoring import build_record, load_manifest_samples, load_weights, score_records

MANIFEST_87 = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples/manifest.json"
MANIFEST_CVEFIX = PROJECT_ROOT / "experiments/exp_06_finetune/testset_cve_fix/manifest_eval.json"
MANIFEST_ROLLING = PROJECT_ROOT / "experiments/exp_06_finetune/corpus/rolling_dev/manifest.json"
WEIGHTS = PROJECT_ROOT / "experiments/scoring_config/weights_20260903.json"

DEFAULT_GLOBS = [
    "experiments/exp_06_finetune/results/exp_06_eval*.json",
    "experiments/exp_06_finetune/results/*/*.json",
    "experiments/exp_06_finetune/results/*/*/*.json",
    "experiments/exp_07_two_stage_eval/results/exp_07_full87.baseline*.json",
]

# 精选标签（按路径后缀匹配，未命中回退为文件名）。格式：(路径子串, 标签, 家族排序键)
LABELS = [
    ("baseline/exp_06_eval.ollama_qwen3_8b.20260722_225944", "基线 qwen3-8b 零样本（主锚点）", "01基线"),
    ("baseline/exp_06_eval.ollama_qwen3_8b", "基线 qwen3-8b 零样本（早期重复跑）", "01基线"),
    ("baseline/exp_06_eval.ollama_qwen3-coder_30b", "基线 qwen3-coder-30b 零样本", "01基线"),
    ("v2/exp_06_eval", "v2（首个 SFT）", "02v2"),
    ("v3/exp_06_eval", "v3（CoT 清单化副作用）", "03v3"),
    ("v4_failed", "v4（失败·训练-测试泄漏）", "04v4x"),
    ("v5/exp_06_eval.finetuned_custom.20260726_085555", "v5（首个可信基线）", "05v5"),
    ("v5/exp_06_eval", "v5（早期重复跑）", "05v5"),
    ("v6_failed", "v6（失败·负迁移）", "06v6x"),
    ("v7/exp_06_eval", "v7（SFT 最佳）", "07v7"),
    ("v8/", "v8（失败·FP 激增）", "08v8x"),
    ("20260807_003239", "v9max（HF 云端 ckpt，87 合成主数据）", "09v9max"),
    ("20260806_224403", "v9max（HF 云端 ckpt，CVE-fix 跑A）", "09v9max"),
    ("20260806_233553", "v9max（HF 云端 ckpt，CVE-fix 跑B）", "09v9max"),
    ("graduation-vuln-scanner_v9max.20260808_123836", "v9max（Ollama Q4_K_M·base，87 合成）", "09v9max"),
    ("graduation-vuln-scanner_v9max.anti_fp_cot.20260808_125027", "v9max（Ollama Q4_K_M·anti_fp_cot）", "09v9max"),
    ("graduation-vuln-scanner_v9max.combined.20260808_130554", "v9max（Ollama Q4_K_M·combined）", "09v9max"),
    ("graduation-vuln-scanner_v9max.20260808_131115", "v9max（Ollama Q4_K_M·base，CVE-fix）", "09v9max"),
    ("graduation-vuln-scanner_v9max.combined.20260808_131725", "v9max（Ollama Q4_K_M·combined，CVE-fix）", "09v9max"),
    ("ollama_garrywhite109909/nivis-alpha0", "α0（Ollama）", "10a0"),
    ("20260812_013842", "α0·base", "10a0"),
    ("20260812_041620", "α0·zero_shot", "10a0"),
    ("20260812_061028", "α0·cot", "10a0"),
    ("20260812_071857", "α0·few_shot", "10a0"),
    ("20260812_051132", "α0·whitelist_only", "10a0"),
    ("20260812_022813", "α0·lite", "10a0"),
    ("20260812_084818", "α0·short", "10a0"),
    ("20260812_094124", "α0·no_rules", "10a0"),
    ("20260812_031259", "α0·anti_fp_cot", "10a0"),
    ("20260812_104830", "α0·strict_schema", "10a0"),
    ("20260812_082222", "α0·combined", "10a0"),
    ("20260811_222657", "α0·combined（08-11 首跑）", "10a0"),
    ("20260812_002656", "α0·combined（中断 85/87）", "10a0"),
    ("20260812_234641", "α0·combined_nosource", "10a0"),
    ("alpha05.20260824_000011", "α0.5·rolling_dev 裸判（8/24 主跑）", "11a05"),
    ("alpha05.20260824_005532", "α0.5·rolling_dev 裸判（中断 47/50）", "11a05"),
    ("combined_nosource.20260816_035517", "α0.5·combined_nosource（08-16）", "11a05"),
    ("alpha05_min.20260815_232648", "α0.5·min", "11a05"),
    ("alpha05_lite.20260816_002243", "α0.5·lite", "11a05"),
    ("alpha05.20260816_012139", "α0.5·full", "11a05"),
    ("combined.20260816_023631", "α0.5·combined（纯 LLM 主数据）", "11a05"),
    ("combined.20260816_051142", "α0.5·combined（重复跑）", "11a05"),
    ("combined.20260820_003830", "α0.5·combined no-merge（CVE-fix 补跑）", "11a05"),
    ("exp_07_full87.baseline_noTools_cns", "两阶段管道·裸 LLM 对照（09-01）", "12对照"),
]


def label_for(path: str) -> tuple[str, str]:
    for sub, label, family in LABELS:
        if sub in path:
            return label, family
    return Path(path).name, "99其他"


def detect_testset(samples: list[dict]) -> str:
    fname = str(samples[0].get("file") or "")
    if fname.startswith("cve_fix"):
        return "cve_fix"
    if fname.startswith("corpus_"):
        return "rolling_dev"
    return "87合成"


def fmt(v) -> str:
    return f"{v:.3f}" if isinstance(v, float) else ("—" if v is None else str(v))


def main() -> None:
    ap = argparse.ArgumentParser(description="批量统一打分（同一套口径重算历史结果）")
    ap.add_argument("patterns", nargs="*", help="结果 JSON glob（缺省用内置全量清单）")
    ap.add_argument("--min-n", type=int, default=20, help="少于该样本数的运行跳过（探针/中断）")
    ap.add_argument("--weights", default=str(WEIGHTS))
    ap.add_argument("--md", default=None, help="markdown 表输出路径")
    ap.add_argument("--json", dest="json_out", default=None, help="json 输出路径")
    args = ap.parse_args()

    patterns = args.patterns or DEFAULT_GLOBS
    paths: list[str] = []
    for pat in patterns:
        paths.extend(glob.glob(str(PROJECT_ROOT / pat)))
    paths = sorted(set(paths))

    manifests = {
        "87合成": load_manifest_samples(MANIFEST_87),
        "cve_fix": load_manifest_samples(MANIFEST_CVEFIX),
        "rolling_dev": load_manifest_samples(MANIFEST_ROLLING),
    }
    risk_weights, credit, weights_note = load_weights(args.weights)

    rows, skipped = [], []
    for p in paths:
        rp = Path(p)
        rel = str(rp.relative_to(PROJECT_ROOT)).replace("\\", "/")
        if "_archive" in rel or rel.startswith("results"):
            skipped.append((rel, "归档/非法路径"))
            continue
        try:
            d = json.loads(rp.read_text(encoding="utf-8"))
        except Exception as e:
            skipped.append((rel, f"读取失败 {e}"))
            continue
        samples = d.get("samples") or []
        if len(samples) < args.min_n:
            skipped.append((rel, f"n={len(samples)} < {args.min_n}"))
            continue
        ts = detect_testset(samples)
        man = manifests[ts]
        records, unmatched = [], 0
        for s in samples:
            ov = man.get(s.get("file") or s.get("filename"))
            if ov is None:
                unmatched += 1
            records.append(build_record(s, expected_override=ov))
        out = score_records(records, risk_weights, credit)
        b, sa, inst, w = out["binary"], out["strict_anyhit"], out["instance"], out["weighted"]
        label, family = label_for(rel)
        undecided = b["review_vuln"] + b["review_safe"]
        n = len(samples)
        rows.append({
            "label": label, "family": family, "file": rel, "testset": ts, "n": n,
            "recall": b["recall"], "fpr": b["false_positive_rate"], "acc": b["accuracy"],
            "strict_any": sa["sample_any_recall"], "cwe_mismatch": sa["cwe_mismatch"],
            "micro": inst["instance_recall_micro"], "macro": inst["instance_recall_macro"],
            "full_cov": inst["full_coverage_rate"], "weighted": w["weighted_score"],
            "undecided_rate": round(undecided / n, 3) if n else None,
            "parse_fail": b["invalid"], "unmatched": unmatched,
            "meta_model": d.get("model") or d.get("meta", {}).get("model") or "",
        })

    rows.sort(key=lambda r: (r["testset"], r["family"], r["file"]))

    print(f"统一打分总表 [权重: {weights_note}]  acc=已裁决口径，未决/parse_fail 单列\n")
    header = f"{'标签':<34}{'测试集':<10}{'n':>4} {'recall':>7} {'FPR':>7} {'acc':>7} {'strict':>7} {'micro':>7} {'macro':>7} {'加权':>7} {'未决':>6} {'pf':>4}"
    print(header)
    print("-" * len(header))
    for r in rows:
        flag = " ⚠unmatched" if r["unmatched"] else ""
        print(f"{r['label'][:33]:<34}{r['testset']:<10}{r['n']:>4} {fmt(r['recall']):>7} {fmt(r['fpr']):>7} "
              f"{fmt(r['acc']):>7} {fmt(r['strict_any']):>7} {fmt(r['micro']):>7} {fmt(r['macro']):>7} "
              f"{fmt(r['weighted']):>7} {fmt(r['undecided_rate']):>6} {r['parse_fail']:>4}{flag}")

    if skipped:
        print(f"\n跳过 {len(skipped)} 个文件：")
        for rel, why in skipped:
            print(f"  - {rel}（{why}）")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nJSON 已写入: {args.json_out}")
    if args.md:
        lines = [
            f"# 统一打分总表（{rows[0]['testset'] if rows else ''}等，自动生成）",
            "",
            f"> 由 `scripts/score_batch.py` 于 2026-09-03 生成；权重表 {Path(args.weights).name}；",
            "> acc=已裁决口径 (TP+TN)/(TP+TN+FP+FN)；strict=样本级任一命中（CWE 纠正口径）；",
            "> micro/macro=实例级 recall；加权=风险加权分（部分得分 命中1.0/方向对0.5/review 0.5）；",
            "> 未决=review 未决率（两阶段）或 parse_fail；全部按现行答案 manifest 重算。",
            "",
            "| 标签 | 测试集 | n | recall | FPR | acc | strict | micro | macro | 加权 | 未决 |",
            "|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        for r in rows:
            lines.append(
                f"| {r['label']} | {r['testset']} | {r['n']} | {fmt(r['recall'])} | {fmt(r['fpr'])} | "
                f"{fmt(r['acc'])} | {fmt(r['strict_any'])} | {fmt(r['micro'])} | {fmt(r['macro'])} | "
                f"{fmt(r['weighted'])} | {fmt(r['undecided_rate'])} |")
        Path(args.md).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Markdown 已写入: {args.md}")


if __name__ == "__main__":
    main()
