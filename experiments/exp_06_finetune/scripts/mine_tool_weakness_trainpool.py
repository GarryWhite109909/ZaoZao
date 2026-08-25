#!/usr/bin/env python3
"""纯工具层扫描 train_pool（开发侧，无 LLM、无 GPU）：工具覆盖弱点矩阵。

对每条样本只跑 _stage1_recall（与生产完全同一路径），记录：
  - 是否有候选（无候选 = 生产走全文件复核的昂贵路径）
  - 各工具开火情况（semgrep / taint_tracker / prefilter / external）
输出按 CWE×语言 的覆盖矩阵 JSON + 控制台摘要。
"""
import argparse
import collections
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.two_stage_scanner import TwoStageScanner


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default=str(
        PROJECT_ROOT / "experiments/exp_06_finetune/results/tool_mining_train_pool.json"))
    args = ap.parse_args()

    corpus = PROJECT_ROOT / "experiments/exp_06_finetune/corpus/train_pool"
    manifest = json.loads((corpus / "manifest.json").read_text())
    samples = manifest["samples"]
    if args.limit:
        samples = samples[: args.limit]

    # client=None：_stage1_recall 不触 LLM；system_prompt 置空
    scanner = TwoStageScanner(client=None, system_prompt="", num_ctx=8192,
                              use_conformal=False, use_signal_feedback=False)

    rows, t0 = [], time.time()
    for i, s in enumerate(samples):
        code_path = corpus / s["file"]
        code = code_path.read_text(errors="replace")
        t1 = time.time()
        try:
            findings = scanner._stage1_recall(code, s.get("language", "").lower(), s["file"])
        except Exception as e:
            findings = []
            print(f"[err] {s['file']}: {e}", flush=True)
        tools = sorted({f.tool for f in findings})
        rows.append({
            "file": s["file"], "cwe": s.get("expected_cwe"), "lang": s.get("language"),
            "frameworks": s.get("frameworks") or [],
            "n_findings": len(findings), "tools": tools,
            "has_candidate": bool(findings),
            "elapsed": round(time.time() - t1, 1),
        })
        if (i + 1) % 20 == 0:
            print(f"[{i+1}/{len(samples)}] 累计 {time.time()-t0:.0f}s", flush=True)

    cov = sum(1 for r in rows if r["has_candidate"])
    by_cwe = collections.defaultdict(lambda: [0, 0])
    by_lang = collections.defaultdict(lambda: [0, 0])
    by_tool = collections.Counter()
    for r in rows:
        by_cwe[r["cwe"]][0] += r["has_candidate"]
        by_cwe[r["cwe"]][1] += 1
        by_lang[r["lang"]][0] += r["has_candidate"]
        by_lang[r["lang"]][1] += 1
        for t in r["tools"]:
            by_tool[t] += 1

    print(f"\n=== train_pool {len(rows)} 条纯工具覆盖 ===")
    print(f"总覆盖（有候选）: {cov}/{len(rows)} = {cov/len(rows):.0%}")
    print("按工具开火文件数:", dict(by_tool.most_common()))
    print("\n覆盖最差的 CWE（<50% 且 ≥3 条）:")
    for cwe, (hit, n) in sorted(by_cwe.items(), key=lambda x: x[1][0]/max(x[1][1],1)):
        if n >= 3 and hit/n < 0.5:
            print(f"  {cwe}: {hit}/{n}")
    print("\n按语言:")
    for lang, (hit, n) in sorted(by_lang.items(), key=lambda x: -x[1][1]):
        print(f"  {lang}: {hit}/{n} = {hit/n:.0%}")

    out = {"summary": {"total": len(rows), "covered": cov,
                       "by_tool": dict(by_tool),
                       "by_cwe": {k: v for k, v in by_cwe.items()},
                       "by_lang": {k: v for k, v in by_lang.items()}},
           "rows": rows}
    Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=1))
    print(f"\n已保存: {args.out}")


if __name__ == "__main__":
    main()
