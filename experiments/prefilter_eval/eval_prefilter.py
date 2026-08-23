"""预筛层（prefilter）独立评估脚本。

目的：在 87 段合成集 + 20 段 CVE-fix 真实集上单独跑 prefilter（不经过 LLM），
计算其准确度/严格准确度，填补"预筛层无独立评估"的空白。

为什么需要这个脚本：
- evaluate.py 计算的 strict_accuracy 是针对 Qwen3-8B 微调模型的，不评估 prefilter。
- prefilter 在主流程中只做前置标记 / 短路 LLM，从未被独立度量。
- 论文需要引用"预筛层严格准确度"，必须实测，不能臆造。

口径定义（与 evaluate.py 的 strict_accuracy 对齐）：
- prefilter 不输出 CWE，但其命中规则名天然对应 CWE（见 RULE_TO_CWE）。
- strict_TP = prefilter 判 True 且命中漏洞规则的 CWE 与 expected_cwe 匹配。
- strict_accuracy = (strict_TP + TN) / N，其中 N 为总样本数；
  verdict=None（弃权交 LLM）与 CWE 不匹配均视为未正确判定（算入分母不算入分子）。
- 同时给出"明确判定子集上的精度"（分母=明确判定数，None 不计入），
  这更贴合 prefilter"高精度低召回、宁可漏判不可误判"的设计目标。

用法：
    python experiments/prefilter_eval/eval_prefilter.py
    python experiments/prefilter_eval/eval_prefilter.py --testset synthetic
    python experiments/prefilter_eval/eval_prefilter.py --testset cve_fix
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prefilter import Prefilter  # noqa: E402

# ---------------------------------------------------------------------------
# 测试集定位
# ---------------------------------------------------------------------------
SYNTHETIC_MANIFEST = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples/manifest.json"
SYNTHETIC_SAMPLES_DIR = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples"
CVE_FIX_MANIFEST = PROJECT_ROOT / "experiments/exp_06_finetune/testset_cve_fix/manifest.json"
CVE_FIX_SAMPLES_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/testset_cve_fix"
OUTPUT_DIR = PROJECT_ROOT / "experiments/prefilter_eval/results"

# ---------------------------------------------------------------------------
# prefilter 规则名 → CWE 映射
# ---------------------------------------------------------------------------
# 依据 prefilter.py 中 _build_vuln_rules 的规则语义建立。
# 安全规则不对应 CWE（命中即判安全，不参与 strict_TP 的 CWE 校验）。
RULE_TO_CWE: dict[str, str] = {
    "sqli_string_concat": "CWE-89",
    "sqli_fstring": "CWE-89",
    "sqli_percent_format": "CWE-89",
    "cmd_os_system_concat": "CWE-78",
    "cmd_subprocess_shell_concat": "CWE-78",
    "rce_eval_request": "CWE-95",
    "path_traversal_open_concat": "CWE-22",
    # hardcoded_secret 已降级为安全抑制标记（不判 True），不参与 strict_TP 的 CWE 校验
    "deser_pickle_loads": "CWE-502",
    "deser_yaml_unsafe_load": "CWE-502",
}


def read_sample_code(samples_dir: Path, filename: str) -> str | None:
    """读取样本代码文件，不存在返回 None。"""
    p = samples_dir / filename
    if not p.exists():
        return None
    return p.read_text(encoding="utf-8", errors="replace")


def load_records(manifest_path: Path) -> list[dict]:
    with manifest_path.open(encoding="utf-8") as f:
        data = json.load(f)
    return data.get("samples", [])


def parse_expected_cwes(expected_cwe: str) -> list[str]:
    """expected_cwe 形如 'CWE-89' 或 'CWE-1336; CWE-94; CWE-918'，返回大写列表。"""
    if not expected_cwe:
        return []
    return [c.strip().upper() for c in expected_cwe.split(";") if c.strip()]


def build_code(samples_dir: Path, rec: dict) -> str | None:
    """读取样本代码，并模仿 evaluate.py 的跨文件样本处理。"""
    filename = rec["file"]
    code = read_sample_code(samples_dir, filename)
    if code is None:
        return None
    # 跨文件样本：sink 文件拼上对应 input 文件作为上下文（与 evaluate.py 一致）
    if "crossfile" in filename and filename.endswith("_sink.py"):
        input_file = filename.replace("_sink.py", "_input.py")
        input_code = read_sample_code(samples_dir, input_file)
        if input_code:
            code = f"# 配套输入层文件 {input_file}\n{input_code}\n\n# 当前 sink 文件\n{code}"
    return code


def evaluate_one(pf: Prefilter, code: str, language: str) -> dict:
    """对单段代码跑 prefilter，返回判定细节。"""
    r = pf.scan(code, language=language)
    # 命中的漏洞规则对应的 CWE 集合（仅 verdict=True 时有意义，但统一算出便于审计）
    hit_vuln_rules = [name for name in r.matched_rules if name in RULE_TO_CWE]
    hit_cwes = sorted({RULE_TO_CWE[name] for name in hit_vuln_rules})
    return {
        "preliminary_verdict": r.preliminary_verdict,  # True/False/None
        "confidence": r.confidence,
        "matched_rules": r.matched_rules,
        "hit_vuln_rules": hit_vuln_rules,
        "hit_cwes": hit_cwes,
        "has_obvious_vuln": r.has_obvious_vuln,
        "has_obvious_safe": r.has_obvious_safe,
    }


def compute_metrics(records: list[dict]) -> dict:
    """计算多口径指标。"""
    n = len(records)
    vuln_total = sum(1 for r in records if r["expected_present"])
    safe_total = sum(1 for r in records if not r["expected_present"])

    # loose 混淆矩阵
    tp = tn = fp = fn = abstain = 0
    # strict（CWE 匹配口径）
    strict_tp = 0
    strict_fn = 0  # 漏洞样本未严格命中（判 False / None / True但CWE不匹配）
    strict_unverifiable = 0  # expected_cwe 缺失（N/A），无法校验 CWE，既不计 TP 也不计 FN
    cwe_mismatch = 0  # 判对方向(True) 但 CWE 不匹配
    abstain_vuln = 0  # 漏洞样本弃权
    abstain_safe = 0  # 安全样本弃权

    per_sample = []
    for r in records:
        verdict = r["prefilter_verdict"]
        expected = r["expected_present"]
        hit_cwes = r["hit_cwes"]
        expected_cwes = parse_expected_cwes(r["expected_cwe"])

        # loose
        if verdict is None:
            abstain += 1
            if expected:
                abstain_vuln += 1
            else:
                abstain_safe += 1
        elif verdict and expected:
            tp += 1
        elif not verdict and not expected:
            tn += 1
        elif verdict and not expected:
            fp += 1
        else:  # not verdict and expected
            fn += 1

        # strict（仅影响漏洞样本的 TP/FN 划分，安全样本 TN/FP 与 loose 一致）
        if expected:
            if verdict is True:
                # 需要 CWE 匹配
                if not expected_cwes:
                    # expected_cwe 缺失（如 N/A）→ 无法校验，从 strict 分母中剔除。
                    # 注意：原先"保守计为 strict_TP"实际是**虚高** strict 指标
                    # （未验证的样本按正确计），方向与注释相反，已修正
                    strict_unverifiable += 1
                elif set(hit_cwes) & set(expected_cwes):
                    strict_tp += 1
                else:
                    cwe_mismatch += 1
                    strict_fn += 1
            else:
                # verdict False 或 None
                strict_fn += 1
        # 安全样本：strict 的 TN/FP 与 loose 一致，已在上面累计

    decided = tp + tn + fp + fn  # 明确判定数 = 被调用且短路 LLM 的样本
    decided_true = tp + fp        # prefilter 判"漏洞"(True) 的样本
    decided_false = tn + fn       # prefilter 判"安全"(False) 的样本

    # 全样本口径（None 算错）—— 仅供参考，对 prefilter 不公平（弃权非其职责）
    loose_accuracy_full = (tp + tn) / n if n else None
    strict_accuracy_full = (strict_tp + tn) / n if n else None

    # 【主口径】被调用子集准确率：分母=明确判定数，弃权(None)不计入
    # 这才是衡量 prefilter "判了就要对" 的正确口径
    # strict 口径再把"无法校验 CWE"的样本从分母剔除（既不算对也不算错）
    strict_decided = decided - strict_unverifiable
    loose_accuracy_decided = (tp + tn) / decided if decided else None
    strict_accuracy_decided = (strict_tp + tn) / strict_decided if strict_decided else None

    # 判"漏洞"(True) 子集准确率：prefilter 判 True 会直接报告漏洞
    # strict 分母同样剔除"无法校验 CWE"的样本（全部落在 decided_true 内），
    # 与上方 strict_accuracy_decided 的剔除规则一致；原先分母不剔除会导致
    # 这些样本既不计对也未剔除，被重复惩罚
    strict_decided_true = decided_true - strict_unverifiable
    true_loose_accuracy = tp / decided_true if decided_true else None
    true_strict_accuracy = strict_tp / strict_decided_true if strict_decided_true else None
    # 判"安全"(False) 子集准确率：prefilter 判 False 会直接放行（短路 LLM，风险更高）
    # strict 口径对这一侧没有可剔除项：CWE 校验只作用于判 True 的漏洞样本
    # （strict_unverifiable 全部在 decided_true 内），因此严格≡宽松，显式标注
    # 避免误以为存在两种口径
    false_loose_accuracy = tn / decided_false if decided_false else None
    false_strict_accuracy = false_loose_accuracy

    # 覆盖率 / 短路率
    coverage = decided / n if n else None
    # 漏洞召回（None 算漏报）；strict 召回分母剔除无法校验 CWE 的样本
    recall = tp / vuln_total if vuln_total else None
    strict_vuln_total = vuln_total - strict_unverifiable
    strict_recall = strict_tp / strict_vuln_total if strict_vuln_total else None
    # 安全误报（None 不算 FP，分母仍为 safe_total）
    fpr = fp / safe_total if safe_total else None

    return {
        "n": n,
        "vuln_total": vuln_total,
        "safe_total": safe_total,
        "confusion": {
            "tp": tp, "tn": tn, "fp": fp, "fn": fn, "abstain": abstain,
            "decided": decided,
            "abstain_vuln": abstain_vuln, "abstain_safe": abstain_safe,
        },
        "strict_confusion": {
            "strict_tp": strict_tp, "strict_fn": strict_fn,
            "strict_unverifiable": strict_unverifiable,
            "cwe_mismatch": cwe_mismatch,
            # 安全样本的 TN/FP 与 loose 一致
            "tn": tn, "fp": fp,
        },
        "loose_accuracy_full": round(loose_accuracy_full, 4) if loose_accuracy_full is not None else None,
        "strict_accuracy_full": round(strict_accuracy_full, 4) if strict_accuracy_full is not None else None,
        "loose_accuracy_decided": round(loose_accuracy_decided, 4) if loose_accuracy_decided is not None else None,
        "strict_accuracy_decided": round(strict_accuracy_decided, 4) if strict_accuracy_decided is not None else None,
        "decided_true": decided_true,
        "decided_false": decided_false,
        "true_loose_accuracy": round(true_loose_accuracy, 4) if true_loose_accuracy is not None else None,
        "true_strict_accuracy": round(true_strict_accuracy, 4) if true_strict_accuracy is not None else None,
        "false_loose_accuracy": round(false_loose_accuracy, 4) if false_loose_accuracy is not None else None,
        "false_strict_accuracy": round(false_strict_accuracy, 4) if false_strict_accuracy is not None else None,
        "coverage": round(coverage, 4) if coverage is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "strict_recall": round(strict_recall, 4) if strict_recall is not None else None,
        "fpr": round(fpr, 4) if fpr is not None else None,
        "per_sample": per_sample,
    }


def run_testset(pf: Prefilter, manifest_path: Path, samples_dir: Path, name: str) -> dict:
    records = load_records(manifest_path)
    print(f"\n===== {name}（{len(records)} 段）=====")
    print(f"manifest: {manifest_path}")
    detailed = []
    missing = []
    for i, rec in enumerate(records):
        code = build_code(samples_dir, rec)
        if code is None:
            missing.append(rec["file"])
            continue
        info = evaluate_one(pf, code, rec.get("language", "python"))
        detailed.append({
            "file": rec["file"],
            "language": rec.get("language", ""),
            "category": rec.get("category", ""),
            "difficulty": rec.get("difficulty", ""),
            "expected_present": rec["expected_present"],
            "expected_cwe": rec.get("expected_cwe", ""),
            "prefilter_verdict": info["preliminary_verdict"],
            "confidence": info["confidence"],
            "matched_rules": info["matched_rules"],
            "hit_vuln_rules": info["hit_vuln_rules"],
            "hit_cwes": info["hit_cwes"],
        })
        verdict_str = {True: "漏洞", False: "安全", None: "弃权"}[info["preliminary_verdict"]]
        print(f"[{i+1}/{len(records)}] {rec['file']} → {verdict_str} "
              f"(conf={info['confidence']}, rules={info['matched_rules']})")
    if missing:
        print(f"⚠️ 缺失 {len(missing)} 个样本文件: {missing}")

    metrics = compute_metrics(detailed)
    metrics["testset"] = name
    metrics["manifest"] = str(manifest_path)
    metrics["samples_dir"] = str(samples_dir)
    metrics["missing_files"] = missing
    # 把逐样本明细挂到 metrics（compute_metrics 里 per_sample 是空的，直接覆盖）
    metrics["per_sample"] = detailed
    return metrics


def print_metrics(m: dict, name: str) -> None:
    print(f"\n----- {name} 指标 -----")
    c = m["confusion"]
    sc = m["strict_confusion"]
    print(f"样本总数 N={m['n']}（漏洞 {m['vuln_total']} / 安全 {m['safe_total']}）")
    print(f"  被调用（明确判定）{c['decided']} 个 / 弃权 {c['abstain']} 个"
          f"（漏洞弃权 {c['abstain_vuln']}，安全弃权 {c['abstain_safe']}）")
    print(f"  混淆矩阵: TP={c['tp']} TN={c['tn']} FP={c['fp']} FN={c['fn']}")
    print(f"  严格混淆: strict_TP={sc['strict_tp']} strict_FN={sc['strict_fn']}"
          f"（CWE不匹配={sc['cwe_mismatch']}）| 安全侧 TN={sc['tn']} FP={sc['fp']}")

    print(f"\n【主口径：被调用子集准确率（分母=明确判定数 {c['decided']}，弃权不计入）】")
    print(f"  ★ loose_accuracy  (方向)  = {m['loose_accuracy_decided']}")
    print(f"  ★ strict_accuracy (CWE匹配) = {m['strict_accuracy_decided']}   ← 预筛层严格准确度")

    print(f"\n【判 True / 判 False 分解（短路 LLM 的两类判定风险不同）】")
    print(f"  判'漏洞'(True)  {m['decided_true']} 个: "
          f"方向准确={m['true_loose_accuracy']}  严格准确={m['true_strict_accuracy']}")
    print(f"  判'安全'(False) {m['decided_false']} 个: "
          f"方向准确={m['false_loose_accuracy']}  严格准确={m['false_strict_accuracy']}"
          f"  ← 判 False 会直接放行，风险更高")

    print(f"\n【其他】")
    print(f"  覆盖率/短路率    = {m['coverage']}（prefilter 给出明确判定的比例）")
    print(f"  recall(漏洞)     = {m['recall']}    strict_recall = {m['strict_recall']}")
    print(f"  FPR(安全)        = {m['fpr']}")
    print(f"\n【参考：全样本口径（弃权算错，分母=N={m['n']}，对 prefilter 不公平）】")
    print(f"  loose_accuracy   = {m['loose_accuracy_full']}   strict_accuracy = {m['strict_accuracy_full']}")


def main():
    parser = argparse.ArgumentParser(description="预筛层 prefilter 独立评估")
    parser.add_argument("--testset", choices=["all", "synthetic", "cve_fix"], default="all")
    args = parser.parse_args()

    pf = Prefilter()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")

    results = {}
    if args.testset in ("all", "synthetic"):
        m = run_testset(pf, SYNTHETIC_MANIFEST, SYNTHETIC_SAMPLES_DIR, "synthetic_87")
        print_metrics(m, "合成集 87 段")
        results["synthetic"] = m
    if args.testset in ("all", "cve_fix"):
        m = run_testset(pf, CVE_FIX_MANIFEST, CVE_FIX_SAMPLES_DIR, "cve_fix_20")
        print_metrics(m, "CVE-fix 真实集 20 段")
        results["cve_fix"] = m

    out_file = OUTPUT_DIR / f"prefilter_eval.{args.testset}.{ts}.json"
    with out_file.open("w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n结果已保存: {out_file}")


if __name__ == "__main__":
    main()
