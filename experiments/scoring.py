"""实验评分共享库 —— 实例级 micro/macro 记账 + 风险加权评分。

2026-09-03 引入（官方口径答案修正落地之后），配套三个入口：
  - scripts/rescore_offline.py：对已有结果文件换答案重算全部口径（不重跑推理）
  - scripts/weighted_score.py：独立加权评分器（读逐样本 JSON 出分）
  - evaluate.py compute_strict_metrics：顺带产出实例级 micro/macro

口径约定（与 evaluate.py strict 口径、exp_07 wave8 汇总口径对齐）：
  - 预期实例集 = expected_cwe 按分号拆分的 CWE 编号集合（去重、忽略顺序——
    2026-09-02 spring4shell 这类仅顺序变化的修正不再产生虚假差异）。
  - 实例命中 = 模型 CWE 集合中存在 p 使 cwe_family_match(p, e)（父子族宽松，
    与 evaluate.py cwe_matches 同一套判定）。
  - review 样本（exp_07 schema 中 predicted=None，同 eval_two_stage.py 汇总口径）
    不进二元/strict/实例自动指标；其不确定性由加权分的 review=0.5 承接。
  - parse_fail（predicted=None）的实例计 0 分且计入分母（*_with_parse_fail 精神）。

多漏洞样本三件套：
  - instance_recall_micro：Σ命中实例 / Σ预期实例（覆盖度主指标）
  - sample_any_recall：样本级任一命中（与历史 strict_recall 可比）
  - instance_recall_macro：按 CWE 类别求 recall 后平均（暴露小类盲区）

风险加权分（工程验收定位，论文主表仍用无权重标准指标）：
  Score = Σ(w·c) / Σ(w·n_inst)，w 取 manifest 的 expected_risk_level 映射，
  部分得分 c：实例命中 1.0 / 判对方向但 CWE 未命中 0.5 / review 0.5 / 漏报 0；
  安全样本权重固定 1，正确拒绝 1.0、误报 0、review 0.5。
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.cwe_normalizer import cwe_family_match, normalize_cwe_label, normalize_with_evidence

_CWE_RE = re.compile(r"(CWE-\d+)", re.IGNORECASE)

# 部分得分表（可用权重文件里的 credit 覆盖）
DEFAULT_CREDIT = {"hit": 1.0, "direction_only": 0.5, "review": 0.5, "safe_correct": 1.0}


# ---------------------------------------------------------------------------
# 输入归一
# ---------------------------------------------------------------------------

def coerce_bool(v) -> bool | None:
    """manifest/结果里的 expected_present 可能是 bool、'True'/'False' 字符串或 None。"""
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("true", "1", "yes"):
        return True
    if s in ("false", "0", "no"):
        return False
    return None


def parse_expected_cwes(expected_cwe) -> list[str]:
    """'CWE-89; CWE-22' -> ['CWE-22', 'CWE-89']（去重、忽略顺序）。"""
    return sorted({m.upper() for m in _CWE_RE.findall(str(expected_cwe or ""))})


def _model_cwes_exp06(sample: dict) -> list[str]:
    """exp_06 evaluate 口径：model_vulnerability_type 过 normalizer 后取编号。

    与 evaluate.py compute_strict_metrics 的 model_cwe 计算逐字对齐
    （normalize_with_evidence 兜底 raw_output；extract_cwe 只取**第一个**编号——
    归一化标签可能附带近族提及，多取会虚高 strict，2026-09-03 对账修正）。
    """
    vt = sample.get("model_vulnerability_type") or sample.get("vulnerability_type") or ""
    if not vt:
        return []
    evidence = sample.get("raw_output") or ""
    label = normalize_with_evidence(vt, evidence) if evidence else normalize_cwe_label(vt)
    m = _CWE_RE.search(label)
    return [m.group(1).upper()] if m else []


def _model_cwes_exp07(sample: dict) -> list[str]:
    """exp_07 两阶段口径：pipeline 已输出规范标签，直接收集编号不二次纠正。"""
    parts: list[str] = []
    vt_list = sample.get("vulnerability_types")
    if isinstance(vt_list, list):
        parts.extend(str(x) for x in vt_list)
    for key in ("vulnerability_type", "raw_vulnerability_type"):
        if sample.get(key):
            parts.append(str(sample[key]))
    return sorted({m.upper() for m in _CWE_RE.findall("; ".join(parts))})


def _model_cwes_exp04(sample: dict) -> list[str]:
    """exp_04/05 repeat 口径：从多数表决一致的 run 里收集 vulnerability_type。

    parsed_verdict 可能是真 dict 也可能是字符串 repr，两种都处理；
    全部 run 解析失败时退回从 raw_output 兜底提取。
    """
    parts: list[str] = []
    for r in sample.get("runs") or []:
        pv = r.get("parsed_verdict")
        if isinstance(pv, dict):
            parts.append(str(pv.get("vulnerability_type") or ""))
        elif isinstance(pv, str) and pv.strip():
            m = re.search(r"['\"]vulnerability_type['\"]:\s*['\"]([^'\"]*)['\"]", pv)
            if m:
                parts.append(m.group(1))
            else:
                parts.append(pv)
    if not parts:
        parts.append(str(sample.get("raw_output") or ""))
    return sorted({m.upper() for m in _CWE_RE.findall("; ".join(parts))})


def build_record(sample: dict, expected_override: dict | None = None) -> dict:
    """把任一 schema 的逐样本记录归一成评分记录。

    expected_override：manifest（或其历史快照）里同 file 条目的 expected_* 字段。
    结果文件里内嵌的 expected_cwe 可能是旧答案，重算时一律以 override 为准。
    """
    ov = expected_override or {}
    exp_present = coerce_bool(ov.get("expected_present", sample.get("expected_present")))
    expected_cwe_raw = ov.get("expected_cwe", sample.get("expected_cwe", ""))
    predicted = coerce_bool(sample.get("predicted"))
    if predicted is None and "model_has_vulnerability" in sample:
        predicted = coerce_bool(sample.get("model_has_vulnerability"))
    if predicted is None and "majority_verdict" in sample:
        predicted = coerce_bool(sample.get("majority_verdict"))
    # review 判定与 eval_two_stage.py 汇总口径一致：predicted=None = 送人工复核
    # （仅两阶段 schema；exp_06 纯模型评估的 predicted=None 是 parse_fail，不算 review）
    is_exp07 = "decision" in sample or "vulnerability_types" in sample or sample.get("schema") == "exp07"
    review = bool(is_exp07 and predicted is None)
    if sample.get("schema") == "exp06":
        model_cwes = _model_cwes_exp06(sample)
    elif sample.get("schema") == "exp07":
        model_cwes = _model_cwes_exp07(sample)
    elif sample.get("schema") == "exp04" or "majority_verdict" in sample:
        model_cwes = _model_cwes_exp04(sample)
    elif is_exp07:
        model_cwes = _model_cwes_exp07(sample)
    else:
        model_cwes = _model_cwes_exp06(sample)
    return {
        "file": sample.get("file") or sample.get("filename") or "?",
        "expected_present": exp_present,
        "predicted": predicted,
        "review": review,
        "expected_cwes": parse_expected_cwes(expected_cwe_raw),
        "model_cwes": model_cwes,
        "risk_level": (ov.get("expected_risk_level") or sample.get("expected_risk_level") or "").strip() or None,
    }


# ---------------------------------------------------------------------------
# 指标
# ---------------------------------------------------------------------------

def instance_hit(record: dict, expected_cwe: str) -> bool:
    return any(cwe_family_match(p, expected_cwe) for p in record["model_cwes"])


def binary_counts(records: list[dict]) -> dict:
    """二元混淆矩阵，口径与 eval_two_stage.py 汇总逐字对齐：

    - review（exp_07 predicted=None）不进混淆矩阵，单列 review_vuln / review_safe；
    - recall = tp/(tp+fn)，FPR = fp/(fp+tn)，accuracy = (tp+tn)/(tp+tn+fp+fn)
      （三者分母都只含已裁决样本）；
    - exp_06 的 predicted=None（parse_fail，非 review）计 invalid。
    """
    tp = tn = fp = fn = invalid = 0
    review_vuln = review_safe = 0
    for r in records:
        exp, pred = r["expected_present"], r["predicted"]
        if exp is None:
            invalid += 1
            continue
        if r["review"]:
            if exp:
                review_vuln += 1
            else:
                review_safe += 1
            continue
        if pred is None:
            invalid += 1
            continue
        if exp and pred:
            tp += 1
        elif exp and not pred:
            fn += 1
        elif not exp and pred:
            fp += 1
        else:
            tn += 1
    vuln_total = tp + fn + review_vuln
    safe_total = tn + fp + review_safe
    decided = tp + tn + fp + fn
    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "invalid": invalid,
        "review_vuln": review_vuln, "review_safe": review_safe,
        "vuln_total": vuln_total, "safe_total": safe_total,
        "recall": round(tp / (tp + fn), 4) if (tp + fn) else None,
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else None,
        "accuracy": round((tp + tn) / decided, 4) if decided else None,
    }


def strict_anyhit_counts(records: list[dict]) -> dict:
    """样本级 strict（任一实例命中即算），与历史 strict_recall 口径可比。

    review 样本与二元口径一致地排除（等待人工裁决，不进自动指标）。
    """
    strict_tp = cwe_mismatch = parse_fail = 0
    for r in records:
        if r["expected_present"] is not True or r["review"]:
            continue
        if r["predicted"] is None:
            parse_fail += 1
            continue
        if not r["predicted"]:
            continue
        if any(instance_hit(r, e) for e in r["expected_cwes"]):
            strict_tp += 1
        else:
            cwe_mismatch += 1
    vuln_total = strict_tp + cwe_mismatch + parse_fail
    return {
        "strict_tp": strict_tp,
        "cwe_mismatch": cwe_mismatch,
        "parse_fail_count": parse_fail,
        "sample_any_recall": round(strict_tp / vuln_total, 4) if vuln_total else None,
    }


def instance_metrics(records: list[dict]) -> dict:
    """实例级记账：micro / macro / per-CWE / 全覆盖样本率。

    全覆盖 = 漏洞样本预测 True 且其全部预期实例命中（all-hit 严格口径）。
    review 样本不进自动口径（同 binary/strict）；parse_fail（exp_06
    predicted=None）实例计 0 且计入分母——诚实覆盖口径，对应项目
    "论文优先引用 *_with_parse_fail" 的纪律。
    """
    total = hits = 0
    full_cov = vuln_samples = 0
    per: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # cwe -> [hit, total]
    for r in records:
        if r["expected_present"] is not True or r["review"]:
            continue
        vuln_samples += 1
        exps = r["expected_cwes"] or ["?"]
        h = sum(1 for e in exps if instance_hit(r, e))
        hits += h
        total += len(exps)
        if r["predicted"] is True and exps and h == len(exps):
            full_cov += 1
        for e in exps:
            per[e][1] += 1
            if instance_hit(r, e):
                per[e][0] += 1
    recalls = [h / n for h, n in per.values() if n]
    return {
        "instance_total": total,
        "instance_hits": hits,
        "instance_recall_micro": round(hits / total, 4) if total else None,
        "instance_recall_macro": round(sum(recalls) / len(recalls), 4) if recalls else None,
        "full_coverage_rate": round(full_cov / vuln_samples, 4) if vuln_samples else None,
        "per_cwe_recall": {
            cwe: {"hit": h, "total": n, "recall": round(h / n, 4)}
            for cwe, (h, n) in sorted(per.items())
        },
    }


def compute_weighted(records: list[dict], risk_weights: dict, credit: dict | None = None) -> dict:
    """风险加权分。risk_weights 形如 {"Critical": 1.0, ...} 或 {"*": 1.0}（flat）。"""
    credit = {**DEFAULT_CREDIT, **(credit or {})}
    vuln_num = vuln_den = safe_num = safe_den = 0.0
    unknown_risk = 0
    for r in records:
        if r["expected_present"] is True:
            if risk_weights.get("*") is not None:
                w = risk_weights["*"]
            elif r["risk_level"] and r["risk_level"] in risk_weights:
                w = float(risk_weights[r["risk_level"]])
            else:
                w = 1.0
                unknown_risk += 1
            n = max(len(r["expected_cwes"]), 1)
            if r["review"]:
                c = credit["review"] * n
            elif r["predicted"] is True:
                h = sum(1 for e in r["expected_cwes"] if instance_hit(r, e))
                c = credit["hit"] * h + credit["direction_only"] * (n - h)
            else:  # 判 False 或 parse_fail：漏报 0 分
                c = 0.0
            vuln_num += w * c
            vuln_den += w * n
        elif r["expected_present"] is False:
            if r["review"]:
                c = credit["review"]
            elif r["predicted"] is False:
                c = credit["safe_correct"]
            else:
                c = 0.0
            safe_num += c
            safe_den += 1
    overall = (vuln_num + safe_num) / (vuln_den + safe_den) if (vuln_den + safe_den) else None
    return {
        "weighted_score": round(overall, 4) if overall is not None else None,
        "vuln_coverage_weighted": round(vuln_num / vuln_den, 4) if vuln_den else None,
        "safe_side_score": round(safe_num / safe_den, 4) if safe_den else None,
        "vuln_denominator": round(vuln_den, 2),
        "unknown_risk_samples": unknown_risk,
    }


def score_records(records: list[dict], risk_weights: dict, credit: dict | None = None) -> dict:
    """全套口径一次算齐：二元 + 样本级 strict + 实例级 + 加权分。"""
    return {
        "binary": binary_counts(records),
        "strict_anyhit": strict_anyhit_counts(records),
        "instance": instance_metrics(records),
        "weighted": compute_weighted(records, risk_weights, credit),
    }


# ---------------------------------------------------------------------------
# IO 辅助
# ---------------------------------------------------------------------------

def load_weights(spec: str) -> tuple[dict, dict, str]:
    """'flat' 或权重 JSON 路径 -> (risk_weights, credit, 描述)。"""
    if spec == "flat":
        return {"*": 1.0}, dict(DEFAULT_CREDIT), "flat（全部权重=1，敏感性对照）"
    cfg = json.loads(Path(spec).read_text(encoding="utf-8"))
    return dict(cfg["risk_level_weights"]), dict(cfg.get("credit", DEFAULT_CREDIT)), str(cfg.get("frozen_at", spec))


def load_manifest_samples(path: str | Path) -> dict[str, dict]:
    """manifest -> {file: sample}，供 build_record 的 expected_override 使用。"""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    samples = data["samples"] if isinstance(data, dict) else data
    return {s["file"]: s for s in samples}
