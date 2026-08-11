#!/usr/bin/env python3
"""审计训练数据的 CoT 长度与推理步数。

基于 DeepSeek-R1 蒸馏到 8B 的官方经验：
  - CoT 步数应截断在 3-5 步
  - 响应从 1120 token 压到 590 token 后，准确率从 63% 升到 89%
  - 长链直接照搬会导致小模型"边想边说还反复修改"

本脚本扫描训练数据，标记超过阈值的样本，输出审计报告。
不修改原数据，仅输出报告供决策。

用法：
    PYTHONPATH=../../.. python3 audit_cot_length.py [--data-file xxx.jsonl] [--max-steps 5] [--max-tokens 590]
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DATA = ROOT / "experiments/exp_06_finetune/data/train_chatml_v9_augmented.jsonl"

# 阈值（基于 DeepSeek-R1 蒸馏经验 + 文档《docs/方法论_新蒸馏方法论》要求）
DEFAULT_MAX_STEPS = 5
DEFAULT_MAX_TOKENS = 590


def extract_cot(assistant_content: str) -> str:
    """提取 assistant 响应中 JSON 之前的 CoT 部分。"""
    # 优先匹配 ```json 代码块
    match = re.search(r"```json\s*\{", assistant_content)
    if match:
        return assistant_content[: match.start()].strip()
    # 兜底：匹配最后一个顶层 JSON 对象（非贪婪从最后一个 { ... } ）
    # 找最后一个看起来像 verdict 的 JSON
    matches = list(re.finditer(r'\{\s*"has_vulnerability"', assistant_content))
    if matches:
        return assistant_content[: matches[-1].start()].strip()
    # 找不到 JSON，整体当 CoT
    return assistant_content.strip()


def extract_verdict(assistant_content: str) -> dict | None:
    """提取 verdict JSON 对象。"""
    # 匹配 ```json ... ```
    match = re.search(r"```json\s*(\{.*?\})\s*```", assistant_content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # 兜底：匹配 { "has_vulnerability" ... }
    matches = re.findall(r'\{\s*"has_vulnerability".*?\}', assistant_content, re.DOTALL)
    for m in reversed(matches):
        try:
            return json.loads(m)
        except json.JSONDecodeError:
            continue
    return None


def count_reasoning_steps(cot: str) -> int:
    """统计显式编号的推理步数。

    匹配模式：
      - "1." "2." "3、" 等阿拉伯数字编号
      - "步骤1" "步骤 1"
      - "第一步" "第二步"
    """
    # 匹配行首的编号（允许前导空白）
    numbered = re.findall(r"(?:^|\n)\s*(\d+)[\.\)、]", cot)
    # 匹配"步骤N"
    step_kw = re.findall(r"步骤\s*(\d+)", cot)
    # 匹配"第X步"
    chinese_num = "一二三四五六七八九十"
    chinese_steps = re.findall(r"第([{}])步".format(chinese_num), cot)
    return max(len(numbered), len(step_kw), len(chinese_steps))


def estimate_tokens(text: str) -> float:
    """粗略估算 token 数。

    Qwen3 tokenizer 对中文约 1.5-2 字符/token，英文约 4 字符/token，代码符号约 2-3 字符/token。
    混合代码（中英+符号）经验值：约 2.5 字符/token。
    """
    if not text:
        return 0.0
    # 简化估算：字符数 / 2.5
    return len(text) / 2.5


def audit_sample(sample: dict, max_steps: int, max_tokens: float) -> dict:
    """审计单条样本，返回审计结果。"""
    messages = sample.get("messages", [])
    assistant_content = ""
    for m in messages:
        if m.get("role") == "assistant":
            assistant_content = m.get("content", "")
            break

    cot = extract_cot(assistant_content)
    verdict = extract_verdict(assistant_content)
    steps = count_reasoning_steps(cot)
    cot_tokens = estimate_tokens(cot)
    total_tokens = estimate_tokens(assistant_content)

    issues = []
    if steps > max_steps:
        issues.append(f"steps={steps}>{max_steps}")
    if cot_tokens > max_tokens:
        issues.append(f"cot_tokens={cot_tokens:.0f}>{max_tokens}")

    # 额外质量检查
    if verdict is None:
        issues.append("verdict_missing")
    else:
        has_vuln = verdict.get("has_vulnerability")
        vuln_type = verdict.get("vulnerability_type", "")
        if has_vuln and (not vuln_type or vuln_type == "none"):
            issues.append("inconsistent_has_vuln_but_no_type")
        if not has_vuln and vuln_type and vuln_type != "none":
            issues.append("inconsistent_no_vuln_but_has_type")

    return {
        "cot_chars": len(cot),
        "cot_tokens": cot_tokens,
        "total_tokens": total_tokens,
        "steps": steps,
        "verdict_present": verdict is not None,
        "issues": issues,
    }


def main():
    parser = argparse.ArgumentParser(description="审计 CoT 长度与推理步数")
    parser.add_argument("--data-file", default=str(DEFAULT_DATA), help="训练数据 jsonl 路径")
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS, help="推理步数上限")
    parser.add_argument("--max-tokens", type=float, default=DEFAULT_MAX_TOKENS, help="CoT token 上限")
    parser.add_argument("--show-samples", type=int, default=10, help="显示前 N 个问题样本详情")
    args = parser.parse_args()

    data_file = Path(args.data_file)
    if not data_file.exists():
        print(f"ERROR: 数据文件不存在: {data_file}")
        return

    samples = []
    with data_file.open() as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))

    print(f"=" * 70)
    print(f"CoT 长度审计报告")
    print(f"=" * 70)
    print(f"数据文件: {data_file}")
    print(f"样本总数: {len(samples)}")
    print(f"阈值: max_steps={args.max_steps}, max_tokens={args.max_tokens}")
    print()

    # 审计所有样本
    results = []
    for i, s in enumerate(samples):
        r = audit_sample(s, args.max_steps, args.max_tokens)
        r["index"] = i
        results.append(r)

    # 统计
    all_steps = [r["steps"] for r in results]
    all_cot_tokens = [r["cot_tokens"] for r in results]
    all_total_tokens = [r["total_tokens"] for r in results]

    print(f"--- 推理步数统计 ---")
    print(f"  min={min(all_steps)}, max={max(all_steps)}, "
          f"mean={statistics.mean(all_steps):.2f}, median={statistics.median(all_steps)}")
    step_dist = {}
    for s in all_steps:
        step_dist[s] = step_dist.get(s, 0) + 1
    print(f"  分布: {dict(sorted(step_dist.items()))}")
    over_step = [r for r in results if r["steps"] > args.max_steps]
    print(f"  超过 {args.max_steps} 步: {len(over_step)} 条 ({len(over_step)/len(results)*100:.1f}%)")
    print()

    print(f"--- CoT token 统计（估算，2.5 字符/token）---")
    print(f"  min={min(all_cot_tokens):.0f}, max={max(all_cot_tokens):.0f}, "
          f"mean={statistics.mean(all_cot_tokens):.0f}, median={statistics.median(all_cot_tokens):.0f}")
    over_token = [r for r in results if r["cot_tokens"] > args.max_tokens]
    print(f"  超过 {args.max_tokens} token: {len(over_token)} 条 ({len(over_token)/len(results)*100:.1f}%)")
    print()

    print(f"--- 整体 assistant 响应 token 统计 ---")
    print(f"  min={min(all_total_tokens):.0f}, max={max(all_total_tokens):.0f}, "
          f"mean={statistics.mean(all_total_tokens):.0f}, median={statistics.median(all_total_tokens):.0f}")
    print()

    # verdict 缺失
    no_verdict = [r for r in results if not r["verdict_present"]]
    print(f"--- verdict 缺失 ---")
    print(f"  {len(no_verdict)} 条 ({len(no_verdict)/len(results)*100:.1f}%)")
    print()

    # 一致性问题
    inconsistent = [r for r in results if any("inconsistent" in i for i in r["issues"])]
    print(f"--- 一致性问题（has_vulnerability 与 vulnerability_type 矛盾）---")
    print(f"  {len(inconsistent)} 条")
    print()

    # 综合问题样本
    problematic = [r for r in results if r["issues"]]
    print(f"--- 综合问题样本 ---")
    print(f"  共 {len(problematic)} 条有问题 ({len(problematic)/len(results)*100:.1f}%)")
    print()

    # 显示前 N 个问题样本
    if args.show_samples > 0 and problematic:
        print(f"--- 前 {min(args.show_samples, len(problematic))} 个问题样本详情 ---")
        for r in problematic[:args.show_samples]:
            print(f"  [#{r['index']}] steps={r['steps']}, cot_tokens={r['cot_tokens']:.0f}, "
                  f"total_tokens={r['total_tokens']:.0f}, issues={r['issues']}")
        print()

    # 建议
    print(f"=" * 70)
    print(f"建议")
    print(f"=" * 70)
    if len(over_step) > 0:
        print(f"  - {len(over_step)} 条样本超过 {args.max_steps} 步推理，建议压缩为 ≤5 步")
    if len(over_token) > 0:
        print(f"  - {len(over_token)} 条样本 CoT 超过 {args.max_tokens} token，建议截断关键步骤")
    if len(no_verdict) > 0:
        print(f"  - {len(no_verdict)} 条样本 verdict JSON 缺失，必须修复")
    if len(inconsistent) > 0:
        print(f"  - {len(inconsistent)} 条样本 has_vulnerability 与 vulnerability_type 矛盾，必须修复")
    if not problematic:
        print(f"  - 所有样本均通过审计，无需修改")
    print()

    # 输出问题样本索引到文件
    if problematic:
        out_file = data_file.parent / f"{data_file.stem}_cot_audit_report.json"
        report = {
            "data_file": str(data_file),
            "total_samples": len(samples),
            "thresholds": {"max_steps": args.max_steps, "max_tokens": args.max_tokens},
            "stats": {
                "steps_mean": statistics.mean(all_steps),
                "steps_max": max(all_steps),
                "cot_tokens_mean": statistics.mean(all_cot_tokens),
                "cot_tokens_max": max(all_cot_tokens),
                "over_step_count": len(over_step),
                "over_token_count": len(over_token),
                "no_verdict_count": len(no_verdict),
                "inconsistent_count": len(inconsistent),
                "problematic_count": len(problematic),
            },
            "problematic_indices": [{"index": r["index"], "steps": r["steps"],
                                     "cot_tokens": round(r["cot_tokens"]),
                                     "issues": r["issues"]} for r in problematic],
        }
        with out_file.open("w") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"问题样本详情已写入: {out_file}")


if __name__ == "__main__":
    main()
