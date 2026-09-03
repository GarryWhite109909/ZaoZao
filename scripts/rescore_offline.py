"""离线重打分：对已有结果文件换答案重算全部口径，不重跑推理。

背景（2026-09-02 官方口径答案修正）：修正只动了 CWE 归因、无标签翻转，
二元指标不受影响；strict / 实例级口径需按新旧答案各算一遍量化差异。
结果文件存有逐样本预测（expected_* 内嵌值可能已过时，一律以 manifest 为准）。

用法：
  # 单文件，新旧答案对比（--answers-old 缺省时自动找同目录 *.bak_2026-09-02_officialfix）
  python scripts/rescore_offline.py experiments/exp_07_two_stage_eval/results/exp_07_full87.wave8_ctx16384_final.20260902.json

  # 指定 manifest 与旧答案快照、权重表
  python scripts/rescore_offline.py RESULT.json \
      --manifest experiments/exp_04_hard_samples/samples/manifest.json \
      --answers-old experiments/exp_04_hard_samples/samples/manifest.json.bak_2026-09-02_officialfix \
      --weights experiments/scoring_config/weights_20260903.json

  # 多文件 + 机器可读输出
  python scripts/rescore_offline.py A.json B.json --json rescore_out.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from experiments.scoring import build_record, load_manifest_samples, load_weights, score_records

DEFAULT_MANIFEST = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples/manifest.json"
DEFAULT_WEIGHTS = PROJECT_ROOT / "experiments/scoring_config/weights_20260903.json"


def resolve_old_manifest(manifest_path: Path, answers_old: str | None) -> Path | None:
    if answers_old:
        return Path(answers_old)
    for bak in sorted(manifest_path.parent.glob(manifest_path.name + ".bak_*")):
        return bak  # 字典序最早 = 改动前最完整的快照
    return None


def rescore_one(result_path: Path, manifest_new: dict[str, dict], manifest_old: dict[str, dict] | None,
                weights_spec: str) -> tuple[dict, list[str]]:
    data = json.loads(result_path.read_text(encoding="utf-8"))
    samples = data.get("samples") or []
    if not samples:
        raise SystemExit(f"[错误] {result_path} 没有 samples 字段")

    risk_weights, credit, weights_note = load_weights(weights_spec)

    def score_with(manifest: dict[str, dict] | None) -> tuple[dict, list[str]]:
        records = []
        unmatched = []
        for s in samples:
            fname = s.get("file") or s.get("filename")
            ov = manifest.get(fname) if manifest else None
            if manifest is not None and ov is None:
                unmatched.append(fname)
            records.append(build_record(s, expected_override=ov))
        out = score_records(records, risk_weights, credit)
        out["_weights"] = weights_note
        return out, unmatched

    new, unmatched = score_with(manifest_new)
    old, _ = score_with(manifest_old) if manifest_old else (None, [])
    return {"new": new, "old": old}, unmatched


def fmt(v) -> str:
    return f"{v:.4f}" if isinstance(v, float) else ("—" if v is None else str(v))


def delta(old_v, new_v) -> str:
    if isinstance(old_v, float) and isinstance(new_v, float):
        d = new_v - old_v
        return f"{d:+.4f}" if abs(d) > 1e-9 else "0"
    return "—"


def print_report(result_path: Path, out: dict, unmatched: list[str]) -> None:
    print(f"\n{'=' * 72}\n■ {result_path.name}   [权重: {out['new']['_weights']}]\n{'=' * 72}")
    if unmatched:
        print(f"  ⚠ {len(unmatched)} 条样本未在 manifest 中找到（按结果内嵌答案计）："
              f"{', '.join(unmatched[:5])}{' ...' if len(unmatched) > 5 else ''}")
    rows = [
        ("recall（二元）", ("binary", "recall")),
        ("FPR（二元）", ("binary", "false_positive_rate")),
        ("accuracy（二元）", ("binary", "accuracy")),
        ("sample_any_recall（样本级strict）", ("strict_anyhit", "sample_any_recall")),
        ("cwe_mismatch", ("strict_anyhit", "cwe_mismatch")),
        ("instance_recall_micro", ("instance", "instance_recall_micro")),
        ("instance_recall_macro", ("instance", "instance_recall_macro")),
        ("full_coverage_rate（all-hit）", ("instance", "full_coverage_rate")),
        ("weighted_score", ("weighted", "weighted_score")),
        ("vuln_coverage_weighted", ("weighted", "vuln_coverage_weighted")),
    ]
    old, new = out["old"], out["new"]
    print(f"  {'指标':<32}{'旧答案':>10}{'新答案':>10}{'Δ':>10}")
    print(f"  {'-' * 62}")
    for label, path in rows:
        node_new, node_old = new, old
        for k in path:
            node_new = node_new.get(k) if node_new else None
            node_old = node_old.get(k) if node_old else None
        if old is None:
            print(f"  {label:<32}{'—':>10}{fmt(node_new):>10}")
        else:
            print(f"  {label:<32}{fmt(node_old):>10}{fmt(node_new):>10}{delta(node_old, node_new):>10}")
    b = new["binary"]
    print(f"\n  混淆矩阵（新答案）: TP={b['tp']} FN={b['fn']} TN={b['tn']} FP={b['fp']}"
          f" | review: 漏洞{b['review_vuln']}/安全{b['review_safe']} | parse_fail/invalid={b['invalid']}")
    if old is not None:
        ob = old["binary"]
        same = (ob["tp"], ob["fn"], ob["tn"], ob["fp"]) == (b["tp"], b["fn"], b["tn"], b["fp"])
        print(f"  二元指标新旧答案一致性: {'一致（标签无翻转，符合预期）' if same else '不一致！请人工核查答案变更'}")
    per = new["instance"]["per_cwe_recall"]
    weak = {c: v for c, v in per.items() if v["recall"] < 1.0}
    if weak:
        print("  未满分 CWE 类别: " + ", ".join(
            f"{c}({v['hit']}/{v['total']})" for c, v in sorted(weak.items())))


def main() -> None:
    ap = argparse.ArgumentParser(description="离线重打分：换答案重算全部口径（不重跑推理）")
    ap.add_argument("results", nargs="+", help="结果 JSON（须含逐样本 samples）")
    ap.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="现行答案 manifest")
    ap.add_argument("--answers-old", default=None, help="旧答案快照（缺省自动找 manifest 同名 .bak_*）")
    ap.add_argument("--weights", default=str(DEFAULT_WEIGHTS), help="'flat' 或权重 JSON 路径")
    ap.add_argument("--json", dest="json_out", default=None, help="机器可读输出路径")
    args = ap.parse_args()

    manifest_path = Path(args.manifest)
    manifest_new = load_manifest_samples(manifest_path)
    old_path = resolve_old_manifest(manifest_path, args.answers_old)
    manifest_old = load_manifest_samples(old_path) if old_path else None
    print(f"现行答案: {manifest_path}（{len(manifest_new)} 条）")
    if manifest_old:
        print(f"旧答案快照: {old_path}")
    else:
        print("未找到旧答案快照，只按现行答案出一份全套口径。")

    all_out = {}
    for rp in map(Path, args.results):
        out, unmatched = rescore_one(rp, manifest_new, manifest_old, args.weights)
        all_out[rp.name] = {"unmatched": unmatched, **out}
        print_report(rp, out, unmatched)

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(all_out, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n机器可读结果已写入: {args.json_out}")


if __name__ == "__main__":
    main()
