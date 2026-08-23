"""实验公共工具函数 —— 供 exp_01 / exp_02 / exp_03 / exp_04 共享。

抽取 manifest 加载、样本读取、结果落盘、检出指标统计等通用逻辑，
避免每个实验脚本重复实现。所有实验脚本统一使用本模块的函数，
确保结果格式与统计口径一致。

典型用法:
    from experiments.utils import (
        load_manifest, read_sample_code, save_results_json,
        build_rag_context, upsert_sample,
        compute_detection_metrics, print_summary,
    )
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from graduation_project.chroma_manager import ChromaManager


def load_manifest(manifest_path: Path) -> tuple[dict, list[dict]]:
    """加载样本清单 manifest.json。

    Args:
        manifest_path: manifest.json 的路径

    Returns:
        (manifest_dict, samples_list)

    Raises:
        FileNotFoundError: manifest 不存在
        KeyError: manifest 缺少 samples 字段
    """
    if not manifest_path.exists():
        raise FileNotFoundError(f"找不到 manifest: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if "samples" not in manifest:
        raise KeyError(f"manifest 缺少 samples 字段: {manifest_path}")
    return manifest, manifest["samples"]


def read_sample_code(samples_dir: Path, filename: str) -> Optional[str]:
    """读取样本代码文件内容。文件不存在时返回 None 并打印警告。"""
    path = samples_dir / filename
    if not path.exists():
        print(f"[跳过] 样本文件不存在: {path}", file=sys.stderr)
        return None
    return path.read_text(encoding="utf-8")


def save_results_json(results_path: Path, results: dict) -> None:
    """把结果 dict 写入 JSON（增量落盘，UTF-8，缩进 2）。"""
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def build_rag_context(
    query_code: str,
    cm: ChromaManager,
    collection_name: str,
    top_k: int = 3,
) -> tuple[str, list[dict]]:
    """用代码内容查询 Chroma 知识库，构建 RAG 上下文。

    Args:
        query_code: 待分析的代码全文（作为查询文本）
        cm: ChromaManager 实例
        collection_name: 知识库集合名
        top_k: 检索 Top-K 条相关知识

    Returns:
        (rag_context_str, retrieval_records)
        - rag_context_str: 拼接好的知识上下文，注入 prompt
        - retrieval_records: 每条检索结果的元信息（id/type/distance/safe_pattern），用于结果记录

    知识标签策略：
        - metadata.safe_pattern=True  → 标注「安全模式」(帮助避免误报)
        - 否则                        → 标注「危险模式」(漏洞特征参考)
    显式标签有助于 LLM 区分两类知识的用法，避免把安全模式知识当成漏洞证据。
    """
    results = cm.query(collection_name, query_code, n_results=top_k)

    ids = results.get("ids", [])
    documents = results.get("documents", [])
    distances = results.get("distances", [])
    metadatas = results.get("metadatas", [])

    retrieval_records = []
    context_parts = []
    for i, (doc, dist, meta) in enumerate(zip(
        documents,
        distances,
        metadatas,
    )):
        is_safe = bool(meta.get("safe_pattern", False))
        tag = "安全模式" if is_safe else "危险模式"
        retrieval_records.append({
            "rank": i + 1,
            "id": ids[i] if i < len(ids) else None,
            "type": meta.get("type"),
            "cwe": meta.get("cwe"),
            "distance": round(dist, 4),
            "safe_pattern": is_safe,
            "tag": tag,
        })
        context_parts.append(
            f"【知识 {i+1}】[{tag}] ({meta.get('type', '未知')} / {meta.get('cwe', '')})\n{doc}"
        )

    rag_context = "\n\n".join(context_parts) if context_parts else ""
    return rag_context, retrieval_records


def upsert_sample(samples_list: list[dict], sample_record: dict) -> None:
    """按 file 字段 upsert 样本记录到列表中（用于增量落盘）。"""
    for i, s in enumerate(samples_list):
        if s.get("file") == sample_record.get("file"):
            samples_list[i] = sample_record
            return
    samples_list.append(sample_record)


def default_results_path(
    results_dir: Path,
    experiment: str,
    model: str | None = None,
    extra_tag: str | None = None,
    suffix: str = "json",
) -> Path:
    """生成带模型名、时间戳的结果文件路径，避免 results.json 被反复覆盖。

    Args:
        results_dir: 结果目录
        experiment: 实验标识（如 exp_01_basic_scan）
        model: 模型名（会安全化，如 qwen2.5-coder:7b → qwen2.5-coder-7b）
        extra_tag: 额外标签（如 ablation 模式、topk 等）
        suffix: 文件后缀

    Returns:
        路径形如 results/<experiment>.<model>.<tag>.<timestamp>.json

    注意：路径含时间戳，每次运行都不同。--resume 直接用此路径判断 exists()
    会永不命中。resume 场景请配合 find_latest_results_path() 使用：先找最新
    同前缀文件，找到则续跑，找不到再用 default_results_path 生成新路径。
    """
    results_dir = Path(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    safe_model = model.replace(":", "-").replace("/", "-") if model else "nomodel"
    parts = [experiment, safe_model]
    if extra_tag:
        parts.append(extra_tag)
    parts.append(ts)
    filename = ".".join(parts) + f".{suffix}"
    return results_dir / filename


def find_latest_results_path(
    results_dir: Path,
    experiment: str,
    model: str | None = None,
    extra_tag: str | None = None,
    suffix: str = "json",
) -> Optional[Path]:
    """按前缀匹配查找最新的结果文件，供 --resume 使用。

    default_results_path 生成的路径含时间戳，每次运行都不同，直接 exists()
    判断会永不命中。本函数按 experiment/model/extra_tag 构造前缀（不含时间戳），
    用 glob 找所有匹配文件，返回按文件名（含时间戳，字典序=时间序）排序的最新一个。

    Returns:
        最新匹配文件的 Path；无匹配返回 None。
    """
    results_dir = Path(results_dir)
    if not results_dir.exists():
        return None
    safe_model = model.replace(":", "-").replace("/", "-") if model else "nomodel"
    parts = [experiment, safe_model]
    if extra_tag:
        parts.append(extra_tag)
    prefix = ".".join(parts) + "."
    pattern = f"{prefix}*.{suffix}"
    matches = sorted(results_dir.glob(pattern))
    return matches[-1] if matches else None


def new_results_envelope(experiment: str, **extra) -> dict:
    """创建结果文件的外层信封（统一字段：experiment/started_at/samples + extra）。"""
    env = {
        "experiment": experiment,
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "samples": [],
    }
    env.update(extra)
    return env


def compute_detection_metrics(
    records: list[dict],
    expected_field: str = "expected_present",
    predicted_field: str = "model_has_vulnerability",
) -> dict:
    """从结果记录列表计算检出指标。

    要求每条 record 含 expected_field（真值）与 predicted_field（模型判定）字段。
    缺字段或值为 None 的样本计入 invalid，不参与 TP/FP/FN/TN。

    Returns:
        {
            "total": int, "valid": int, "invalid": int,
            "tp": int, "tn": int, "fp": int, "fn": int,
            "vuln_total": int, "safe_total": int,
            "recall": float|None,       # 漏洞样本召回率 = tp/(tp+fn)
            "false_positive_rate": float|None,  # 安全样本误报率 = fp/(fp+tn)
            "accuracy": float|None,     # 总体准确率 = (tp+tn)/valid
            # 严格口径（含 parse_fail，避免解析失败样本被剔除分母导致指标偏乐观）：
            "recall_with_parse_fail": float|None,   # tp/(tp+fn+invalid_vuln) parse_fail 计入漏报
            "accuracy_with_parse_fail": float|None, # (tp+tn)/(total) parse_fail 计入错误
            "elapsed_stats": {"avg": float, "max": float, "min": float, "sum": float, "count": int},
        }

    指标口径说明：
        主指标（recall/accuracy）沿用排除 invalid 的口径，与历史结果兼容；
        严格口径（*_with_parse_fail）把 parse_fail（解析失败/空输出）计入漏报/错误，
        分母含全部样本，反映模型真实可用性。两个口径同时报告，避免单一口径偏乐观。
        论文主结论应优先引用严格口径。
    """
    tp = tn = fp = fn = 0
    elapsed_list: list[float] = []
    invalid = 0
    invalid_vuln = 0   # 漏洞样本中解析失败数（parse_fail 计入漏报）
    invalid_safe = 0   # 安全样本中解析失败数

    for r in records:
        exp = r.get(expected_field)
        pred = r.get(predicted_field)
        # 收集耗时（若有）
        el = r.get("elapsed_seconds")
        if isinstance(el, (int, float)):
            elapsed_list.append(el)

        if exp is None or pred is None:
            invalid += 1
            if exp is True:
                invalid_vuln += 1
            elif exp is False:
                invalid_safe += 1
            continue
        if exp and pred:
            tp += 1
        elif (not exp) and (not pred):
            tn += 1
        elif exp and (not pred):
            fn += 1
        else:
            fp += 1

    valid = tp + tn + fp + fn
    vuln_total = tp + fn
    safe_total = tn + fp

    recall = (tp / vuln_total) if vuln_total else None
    fpr = (fp / safe_total) if safe_total else None
    accuracy = (tp + tn) / valid if valid else None

    # 严格口径：parse_fail 计入漏报（recall 分母 += invalid_vuln）/错误（accuracy 分母 = total）
    vuln_total_with_parse_fail = vuln_total + invalid_vuln
    recall_with_parse_fail = (tp / vuln_total_with_parse_fail) if vuln_total_with_parse_fail else None
    total = len(records)
    accuracy_with_parse_fail = (tp + tn) / total if total else None

    elapsed_stats = {
        "avg": round(sum(elapsed_list) / len(elapsed_list), 2) if elapsed_list else None,
        "max": round(max(elapsed_list), 2) if elapsed_list else None,
        "min": round(min(elapsed_list), 2) if elapsed_list else None,
        "sum": round(sum(elapsed_list), 2) if elapsed_list else None,
        "count": len(elapsed_list),
    }

    return {
        "total": len(records),
        "valid": valid,
        "invalid": invalid,
        "invalid_vuln": invalid_vuln,
        "invalid_safe": invalid_safe,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "vuln_total": vuln_total, "safe_total": safe_total,
        "recall": recall,
        "false_positive_rate": fpr,
        "accuracy": accuracy,
        "recall_with_parse_fail": round(recall_with_parse_fail, 4) if recall_with_parse_fail is not None else None,
        "accuracy_with_parse_fail": round(accuracy_with_parse_fail, 4) if accuracy_with_parse_fail is not None else None,
        "elapsed_stats": elapsed_stats,
    }


def format_metrics_text(metrics: dict) -> str:
    """把指标格式化为可读文本（用于打印 / 写入报告）。"""
    def pct(x):
        return "N/A" if x is None else f"{x*100:.1f}%"

    m = metrics
    lines = [
        f"样本总数: {m['total']}（有效 {m['valid']}，无效 {m['invalid']}）",
        f"TP={m['tp']}  TN={m['tn']}  FP={m['fp']}  FN={m['fn']}",
        f"漏洞样本召回率 = {m['tp']}/{m['vuln_total']} = {pct(m['recall'])}",
        f"安全样本误报率 = {m['fp']}/{m['safe_total']} = {pct(m['false_positive_rate'])}",
        f"总体准确率 = {m['tp']+m['tn']}/{m['valid']} = {pct(m['accuracy'])}",
    ]
    # 严格口径（含 parse_fail）：parse_fail 计入漏报/错误，分母含全部样本
    rwpf = m.get("recall_with_parse_fail")
    awpf = m.get("accuracy_with_parse_fail")
    if rwpf is not None or awpf is not None:
        lines.append(f"--- 严格口径（parse_fail 计入漏报/错误，论文主结论应优先引用）---")
        lines.append(f"严格召回率 = {m['tp']}/{m['vuln_total']+m.get('invalid_vuln', 0)} = {pct(rwpf)}")
        lines.append(f"严格准确率 = {m['tp']+m['tn']}/{m['total']} = {pct(awpf)}")
    es = m["elapsed_stats"]
    if es["count"]:
        lines.append(
            f"耗时: 平均 {es['avg']}s  最长 {es['max']}s  最短 {es['min']}s  总和 {es['sum']}s"
        )
    return "\n".join(lines)


def print_summary(metrics: dict) -> None:
    """打印汇总指标到 stdout。"""
    print(format_metrics_text(metrics))


# ---------------------------------------------------------------------------
# P1-4 新增：重复实验与置信区间统计
# ---------------------------------------------------------------------------

def wilson_score_interval(successes: int, total: int, z: float = 1.96) -> Optional[tuple[float, float]]:
    """Wilson score 95% 置信区间（默认 z=1.96）。

    相比"正态近似"在比例接近 0 或 1 时更稳定，适合小样本比例的 CI 估计。

    Args:
        successes: 成功次数（如正确判定数）
        total: 总试验数
        z: z 值，1.96 对应 95% CI

    Returns:
        (lower, upper) 区间，均为 [0, 1]；total=0 时返回 None
    """
    if total <= 0:
        return None
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    margin = z * ((p * (1 - p) / total + z * z / (4 * total * total)) ** 0.5) / denom
    return (round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4))


def majority_vote(verdicts: list) -> Optional[bool]:
    """对多次判定的二值结果做多数表决。

    None 值（解析失败）不参与投票，但计入法定人数：有效票必须超过总票数的
    一半，表决才成立，否则返回 None（弃权/需复核）——防止 [True, None, None]
    这类两次解析失败、仅剩唯一有效票的结果被当成"多数表决"结论。
    平票时倾向 True（保守判定为漏洞）。
    """
    if not verdicts:
        return None
    valid = [v for v in verdicts if v is not None]
    if not valid:
        return None
    if len(valid) <= len(verdicts) / 2:
        return None  # 有效票未过半，表决不成立
    true_count = sum(1 for v in valid if v)
    return true_count >= len(valid) / 2


def compute_elapsed_stats(elapsed_list: list) -> dict:
    """计算耗时分布：均值 / 标准差 / 中位数 / p95 / min / max。

    P1-7 中位数已支持，P1-4 在此基础上增加 std 与 p95。
    """
    if not elapsed_list:
        return {"count": 0, "mean": None, "std": None, "median": None,
                "min": None, "max": None, "p95": None, "sum": None}
    sorted_list = sorted(elapsed_list)
    n = len(sorted_list)
    # p95：取 95 分位数（线性插值）
    if n == 1:
        p95 = sorted_list[0]
    else:
        idx = 0.95 * (n - 1)
        lo = int(idx)
        hi = min(lo + 1, n - 1)
        frac = idx - lo
        p95 = sorted_list[lo] * (1 - frac) + sorted_list[hi] * frac
    return {
        "count": n,
        "mean": round(statistics.mean(elapsed_list), 2),
        "std": round(statistics.stdev(elapsed_list), 2) if n > 1 else 0.0,
        "median": round(statistics.median(elapsed_list), 2),
        "min": round(min(elapsed_list), 2),
        "max": round(max(elapsed_list), 2),
        "p95": round(p95, 2),
        "sum": round(sum(elapsed_list), 2),
    }


def compute_repeat_metrics(records: list[dict]) -> dict:
    """聚合多次重复实验的指标。

    输入 records 是单次实验的记录列表（每条 record 对应一次 sample × run），
    要求每条 record 至少含 file / expected_present / model_has_vulnerability /
    elapsed_seconds 字段。

    返回:
        - per_sample: 每个样本的多次判定聚合（多数表决、一致率、耗时分布）
        - 总体指标（基于多数表决结果计算 TP/FP/FN/TN）
        - accuracy / recall / FPR 的 Wilson 95% 置信区间
        - 总体耗时分布
    """
    by_file = defaultdict(list)
    for r in records:
        by_file[r.get("file", "unknown")].append(r)

    per_sample = []
    for filename, runs in sorted(by_file.items()):
        verdicts = [r.get("model_has_vulnerability") for r in runs]
        elapsed = [r.get("elapsed_seconds") for r in runs
                   if isinstance(r.get("elapsed_seconds"), (int, float))]
        expected = runs[0].get("expected_present")
        majority = majority_vote(verdicts)
        valid = [v for v in verdicts if v is not None]
        if valid:
            true_count = sum(1 for v in valid if v)
            agreement = max(true_count, len(valid) - true_count) / len(valid)
        else:
            agreement = 0.0
        per_sample.append({
            "file": filename,
            "runs": len(runs),
            "expected_present": expected,
            "majority_verdict": majority,
            "agreement_rate": round(agreement, 4),
            "true_count_in_runs": sum(1 for v in verdicts if v is True),
            "none_count_in_runs": sum(1 for v in verdicts if v is None),
            "elapsed_stats": compute_elapsed_stats(elapsed),
        })

    # 基于多数表决的总体指标
    tp = tn = fp = fn = 0
    for s in per_sample:
        exp = s["expected_present"]
        pred = s["majority_verdict"]
        if exp is None or pred is None:
            continue
        if exp and pred:
            tp += 1
        elif (not exp) and (not pred):
            tn += 1
        elif exp and (not pred):
            fn += 1
        else:
            fp += 1

    valid = tp + tn + fp + fn
    vuln_total = tp + fn
    safe_total = tn + fp
    recall = tp / vuln_total if vuln_total else None
    fpr = fp / safe_total if safe_total else None
    accuracy = (tp + tn) / valid if valid else None

    # 直接从 records 收集所有 per-run 耗时，避免用均值重建导致 median/std/p95 失真
    all_elapsed = []
    for runs in by_file.values():
        for r in runs:
            e = r.get("elapsed_seconds")
            if isinstance(e, (int, float)):
                all_elapsed.append(e)

    return {
        "total_samples": len(per_sample),
        "total_runs": sum(s["runs"] for s in per_sample),
        "valid_samples": valid,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "vuln_total": vuln_total, "safe_total": safe_total,
        "recall": recall,
        "false_positive_rate": fpr,
        "accuracy": accuracy,
        "accuracy_ci_95": wilson_score_interval(tp + tn, valid),
        "recall_ci_95": wilson_score_interval(tp, vuln_total),
        "fpr_ci_95": wilson_score_interval(fp, safe_total),
        "elapsed_overall": compute_elapsed_stats(all_elapsed),
        "per_sample": per_sample,
    }


def format_repeat_metrics_text(metrics: dict) -> str:
    """把重复实验指标格式化为可读文本。"""
    def pct(x):
        return "N/A" if x is None else f"{x*100:.1f}%"
    def ci_text(ci):
        if ci is None:
            return "N/A"
        return f"[{ci[0]*100:.1f}%, {ci[1]*100:.1f}%]"

    m = metrics
    lines = [
        f"样本总数: {m['total_samples']}（共 {m['total_runs']} 次运行，有效 {m['valid_samples']}）",
        f"基于多数表决：TP={m['tp']}  TN={m['tn']}  FP={m['fp']}  FN={m['fn']}",
        f"召回率 = {m['tp']}/{m['vuln_total']} = {pct(m['recall'])}  95% CI {ci_text(m['recall_ci_95'])}",
        f"误报率 = {m['fp']}/{m['safe_total']} = {pct(m['false_positive_rate'])}  95% CI {ci_text(m['fpr_ci_95'])}",
        f"准确率 = {m['tp']+m['tn']}/{m['valid_samples']} = {pct(m['accuracy'])}  95% CI {ci_text(m['accuracy_ci_95'])}",
    ]
    es = m["elapsed_overall"]
    if es["count"]:
        lines.append(
            f"耗时: 均值 {es['mean']}s  中位数 {es['median']}s  标准差 {es['std']}s  "
            f"p95 {es['p95']}s  最长 {es['max']}s  最短 {es['min']}s"
        )
    # 一致率统计
    agreements = [s["agreement_rate"] for s in m["per_sample"]]
    if agreements:
        lines.append(
            f"单样本多数表决一致率: 均值 {statistics.mean(agreements):.3f}  "
            f"最低 {min(agreements):.3f}"
        )
    return "\n".join(lines)


def print_repeat_summary(metrics: dict) -> None:
    """打印重复实验汇总指标到 stdout。"""
    print(format_repeat_metrics_text(metrics))


if __name__ == "__main__":
    # 自检：单次实验指标
    demo = [
        {"expected_present": True, "model_has_vulnerability": True, "elapsed_seconds": 50.0},
        {"expected_present": True, "model_has_vulnerability": False, "elapsed_seconds": 55.0},
        {"expected_present": False, "model_has_vulnerability": False, "elapsed_seconds": 40.0},
        {"expected_present": False, "model_has_vulnerability": True, "elapsed_seconds": 60.0},
        {"expected_present": True, "model_has_vulnerability": None, "elapsed_seconds": None},
    ]
    print("=== 单次实验指标 ===")
    m = compute_detection_metrics(demo)
    print_summary(m)

    # 自检：重复实验 + 置信区间
    print("\n=== 重复实验 + 置信区间 ===")
    demo_repeat = [
        # sample A：3 次都判 True，期望 True
        {"file": "a.py", "expected_present": True, "model_has_vulnerability": True, "elapsed_seconds": 40.0},
        {"file": "a.py", "expected_present": True, "model_has_vulnerability": True, "elapsed_seconds": 42.0},
        {"file": "a.py", "expected_present": True, "model_has_vulnerability": True, "elapsed_seconds": 38.0},
        # sample B：2 True 1 False，期望 True
        {"file": "b.py", "expected_present": True, "model_has_vulnerability": True, "elapsed_seconds": 50.0},
        {"file": "b.py", "expected_present": True, "model_has_vulnerability": False, "elapsed_seconds": 48.0},
        {"file": "b.py", "expected_present": True, "model_has_vulnerability": True, "elapsed_seconds": 52.0},
        # sample C：3 次都判 False，期望 False
        {"file": "c.py", "expected_present": False, "model_has_vulnerability": False, "elapsed_seconds": 30.0},
        {"file": "c.py", "expected_present": False, "model_has_vulnerability": False, "elapsed_seconds": 32.0},
        {"file": "c.py", "expected_present": False, "model_has_vulnerability": False, "elapsed_seconds": 28.0},
    ]
    rm = compute_repeat_metrics(demo_repeat)
    print_repeat_summary(rm)
    print(f"\nWilson CI 自检 (8/10): {wilson_score_interval(8, 10)}")
    print(f"Wilson CI 自检 (0/3): {wilson_score_interval(0, 3)}")
    print(f"Wilson CI 自检 (3/3): {wilson_score_interval(3, 3)}")
