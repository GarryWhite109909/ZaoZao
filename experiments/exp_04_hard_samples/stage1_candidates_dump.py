"""Stage 1 静态候选 dump（离线，纯工具管线，不调用 LLM）。

用途（2026-08-30，工具层优化指导 §五之六 待办1 验证 + 逐条人工审查）：
  对 exp_04 87 段全量跑修复后的 Stage1 召回（与 --no-signal-feedback 同口径：
  纯静态管线、禁用抑制池读写），把**裁决层实际可见的候选清单**连同完整证据
  文本落盘，供逐条人工审查：
    ① 候选合不合理（是否指向真实漏洞特征）
    ② 会不会误导模型（类型归因 / 证据文本 / 信任标注）
    ③ 有无该产出却未产出的候选（对照 manifest 期望类型）

  注意：本脚本只负责"跑工具 + 摆候选"，合理性判断由人工完成——不设任何
  自动"合理/不合理"判定（脚本统计指标会掩盖逐条证据的问题，§五之二 B1 教训）。

用法：
  python experiments/exp_04_hard_samples/stage1_candidates_dump.py
输出：
  results/stage1_candidates.{ts}.json   全量候选明细（含 evidence 全文）
"""

import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.two_stage_scanner import TwoStageScanner
from experiments.utils import load_manifest, read_sample_code

MANIFEST_PATH = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples/manifest.json"
SAMPLES_DIR = MANIFEST_PATH.parent
OUTPUT_DIR = PROJECT_ROOT / "experiments/exp_04_hard_samples/results"


def main() -> None:
    manifest, records = load_manifest(MANIFEST_PATH)
    print(f"样本: {len(records)} 段（manifest={MANIFEST_PATH.name}）")

    # 与 --no-signal-feedback 同口径：注册表禁用（不读不写）、共形/反事实关闭。
    # client=None：Stage1 召回只走静态工具，不触 LLM。
    scanner = TwoStageScanner(
        client=None, system_prompt="", n_samples=3,
        use_conformal=False, use_signal_feedback=False, use_counterfactual=False,
    )

    out = []
    t0 = time.time()
    for i, rec in enumerate(records):
        fname = rec.get("file", "")
        code = read_sample_code(SAMPLES_DIR, fname)
        if code is None:
            print(f"[{i+1}/{len(records)}] {fname}: 样本文件缺失，跳过")
            continue
        lang = (rec.get("language") or "python").lower()
        # 与 scan_code 的请求级复位同口径（§五之四 留痕是请求级生命周期，
        # 直接调 _stage1_recall 必须自行复位，否则跨样本累积）
        scanner._last_suppressed_rules = []
        scanner._dropped_unowned_rules = []
        findings = scanner._stage1_recall(code, lang, fname)
        # 抑制/剔除留痕（§五之四）：零召回可归因（没命中 vs 命中后被抑制/剔除）
        sup = sorted(set(scanner._last_suppressed_rules))
        drop = sorted(set(scanner._dropped_unowned_rules))
        out.append({
            "file": fname,
            "language": lang,
            "expected_present": rec.get("expected_present"),
            "expected_cwe": rec.get("expected_cwe", ""),
            "n_candidates": len(findings),
            "suppressed_by_registry": sup,
            "dropped_unowned": drop,
            "candidates": [{
                "rule_id": f.rule_id,
                "category": f.category,
                "taint_type": f.taint_type,
                "tool": f.tool,
                "severity": f.severity,
                "source_line": f.source_line,
                "sink_line": f.sink_line,
                "source": f.source,
                "sink": f.sink,
                "path": f.path,
                "evidence": f.evidence,
            } for f in findings],
        })
        flag = ""
        if sup:
            flag += f" [抑制:{len(sup)}]"
        if drop:
            flag += f" [剔除:{len(drop)}]"
        print(f"[{i+1}/{len(records)}] {fname}: {len(findings)} 候选{flag}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUTPUT_DIR / f"stage1_candidates.{time.strftime('%Y%m%d_%H%M%S')}.json"
    out_path.write_text(json.dumps({
        "meta": {
            "pipeline": "stage1 static recall (--no-signal-feedback 口径)",
            "no_llm": True,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_s": round(time.time() - t0, 1),
        },
        "samples": out,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n完成: {len(out)} 段, 耗时 {time.time()-t0:.0f}s → {out_path}")


if __name__ == "__main__":
    main()
