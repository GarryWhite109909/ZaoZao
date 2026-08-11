"""On-policy DPO 偏好对构建 —— 从 evaluate.py 评估错题生成 chosen/rejected 对。

设计依据：docs/方法论_Nivis-α1训练.md §3.1。
与 generate_dpo_pairs.py（手写 CCoT 对比样本）的关键区别：
  - **rejected 是模型自己的真实错误输出**（on-policy），DPO 文献与项目实践
    （dpo_fp_pairs_v5）均表明 on-policy rejected 远优于手写错误推理；
  - chosen 由教师模型对同一代码重新生成（结论强制对齐 ground truth），
    教师不可用时回退为模板构造并标记 needs_review。

输入：evaluate.py 的结果 JSON（含 samples 数组，字段见 evaluate.py 结果记录：
  file / language / original_code / expected_present / expected_cwe /
  expected_vulnerability / outcome / raw_output）

输出：data/dpo_onpolicy_pairs.jsonl，每行：
  {"prompt": ChatML, "chosen": ..., "rejected": ...,
   "meta": {"file", "outcome", "chosen_source": "teacher"|"template"}}

用法：
  # 离线模板模式（无教师，chosen 标记 needs_review，仅供链路验证）
  PYTHONPATH=. python experiments/exp_06_finetune/scripts/generate_dpo_pairs_onpolicy.py \
      --eval-results <evaluate输出.json> --offline

  # 教师模式（Ollama 本地教师生成 chosen，结论与 GT 交叉校验）
  PYTHONPATH=. python experiments/exp_06_finetune/scripts/generate_dpo_pairs_onpolicy.py \
      --eval-results <evaluate输出.json> --teacher qwen2.5-coder:14b
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import BASE_PROMPT, build_user_prompt
from graduation_project.schema import normalize_has_vulnerability, parse_verdict

DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"
OLLAMA_URL = "http://localhost:11434"

# 压缩 CoT 模板（与《docs/方法论_新蒸馏方法论》一致：8B 学不会长推理链，chosen 必须短）
TEMPLATE_COT_VULN = (
    "分析：代码中 {source_desc} 的输入未经校验流入 {sink_desc}，"
    "构成 {cwe}。数据流路径可达且无任何消毒/参数化处理。"
)
TEMPLATE_COT_SAFE = (
    "分析：代码对输入进行了正确处理（参数化/白名单/编码转义），"
    "source 与 sink 之间不存在可达的未消毒数据流，未发现漏洞。"
)


def load_eval_results(path: Path) -> list[dict]:
    """加载 evaluate.py 结果 JSON，返回 samples 记录列表。"""
    data = json.loads(path.read_text(encoding="utf-8"))
    samples = data.get("samples", data if isinstance(data, list) else [])
    return [s for s in samples if isinstance(s, dict)]


def build_prompt(code: str, language: str) -> str:
    """构造 ChatML prompt（与 train_dpo.py 期望的格式一致，system 用 BASE_PROMPT）。"""
    user = build_user_prompt(code=code, language=language)  # 不传 filename（防泄漏修复后签名保留）
    return (
        f"<|im_start|>system\n{BASE_PROMPT}<|im_end|>\n"
        f"<|im_start|>user\n{user}<|im_end|>\n"
        f"<|im_start|>assistant\n"
    )


def verdict_json(has_vuln: bool, rec: dict) -> str:
    """按 ground truth 构造正确结论 JSON 块。"""
    verdict = {
        "has_vulnerability": has_vuln,
        "vulnerability_type": (rec.get("expected_cwe") or "未知类型") if has_vuln else "none",
        "risk_level": "High" if has_vuln else "None",
        "source": "见分析" if has_vuln else "N/A",
        "sink": "见分析" if has_vuln else "N/A",
        "explanation": rec.get("expected_vulnerability", "") if has_vuln else "安全模式",
        "fix_suggestion": "见分析" if has_vuln else "no fix needed",
    }
    return "```json\n" + json.dumps(verdict, ensure_ascii=False, indent=2) + "\n```"


def template_chosen(rec: dict) -> str:
    """离线模板 chosen（标记 needs_review，仅用于链路验证/占位）。"""
    has_vuln = bool(rec.get("expected_present"))
    cot = TEMPLATE_COT_VULN.format(
        source_desc="用户可控", sink_desc="危险函数",
        cwe=rec.get("expected_cwe", "未知类型"),
    ) if has_vuln else TEMPLATE_COT_SAFE
    return f"{cot}\n\n### 最终结论：\n{verdict_json(has_vuln, rec)}<|im_end|>"


def call_teacher(teacher: str, code: str, language: str, timeout: int = 180) -> str | None:
    """调用 Ollama 教师模型分析代码，返回回复文本（失败返回 None）。"""
    import requests
    payload = {
        "model": teacher,
        "messages": [
            {"role": "system", "content": BASE_PROMPT},
            {"role": "user", "content": build_user_prompt(code=code, language=language)},
        ],
        "stream": False,
        "options": {"temperature": 0.3},
    }
    try:
        resp = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=timeout)
        resp.raise_for_status()
        return resp.json().get("message", {}).get("content", "")
    except Exception as e:
        print(f"    [教师调用失败] {e}")
        return None


def teacher_chosen(teacher: str, rec: dict) -> tuple[str | None, str]:
    """教师生成 chosen，结论与 ground truth 交叉校验。

    Returns:
        (chosen_text, source_tag)；教师结论与 GT 冲突时回退模板。
    """
    code, language = rec.get("original_code", ""), rec.get("language", "python")
    expected = bool(rec.get("expected_present"))
    reply = call_teacher(teacher, code, language)
    if not reply:
        return None, "teacher_fail"
    verdict = parse_verdict(reply)
    predicted = normalize_has_vulnerability(verdict.get("has_vulnerability")) if verdict else None
    if predicted != expected:
        # 教师也错（可能是真难样本）→ 回退模板，交人工队列
        return None, "teacher_disagree"
    # 结论一致：采用教师推理文本 + 强制对齐 GT 的结论块
    cot_end = reply.find("```json")
    cot = reply[:cot_end].strip() if cot_end > 0 else reply.strip()
    chosen = f"{cot}\n\n### 最终结论：\n{verdict_json(expected, rec)}<|im_end|>"
    return chosen, "teacher"


def extract_pairs(records: list[dict], include_parse_fail: bool) -> list[dict]:
    """筛选错题记录（FN/FP，可选 parse_fail）。"""
    valid_outcomes = {"FN", "FP"} | ({"parse_fail"} if include_parse_fail else set())
    out = []
    for rec in records:
        if rec.get("outcome") not in valid_outcomes:
            continue
        raw = (rec.get("raw_output") or "").strip()
        if not raw or not rec.get("original_code"):
            continue  # 无原始输出或原始代码，无法构造 on-policy 对
        out.append(rec)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="On-policy DPO 偏好对构建")
    ap.add_argument("--eval-results", required=True, help="evaluate.py 结果 JSON 路径")
    ap.add_argument("--output", default=str(DATA_DIR / "dpo_onpolicy_pairs.jsonl"))
    ap.add_argument("--teacher", default=None, help="Ollama 教师模型名（不传则需 --offline）")
    ap.add_argument("--offline", action="store_true", help="离线模板模式（chosen 标记 template）")
    ap.add_argument("--include-parse-fail", action="store_true",
                    help="parse_fail 样本也入对（rejected 为无法解析的原始输出）")
    ap.add_argument("--fn-fp-ratio", type=float, default=2.0,
                    help="FN:FP 目标比例（默认 2:1，防 DPO 过度保守化）")
    ap.add_argument("--max-pairs", type=int, default=0, help="最多输出对数（0=不限）")
    args = ap.parse_args()

    if not args.teacher and not args.offline:
        ap.error("需指定 --teacher 或显式 --offline")

    records = load_eval_results(Path(args.eval_results))
    errors = extract_pairs(records, args.include_parse_fail)
    fn = [r for r in errors if r["outcome"] == "FN"]
    fp = [r for r in errors if r["outcome"] == "FP"]
    pf = [r for r in errors if r["outcome"] == "parse_fail"]
    print(f"评估记录 {len(records)} 条 → 错题 {len(errors)} 条（FN={len(fn)} FP={len(fp)} parse_fail={len(pf)}）")

    # FN:FP 比例控制：FN 全保留（主要纠偏对象），FP 超比例时下采样
    if fn and len(fp) > len(fn) / args.fn_fp_ratio:
        keep = max(1, int(len(fn) / args.fn_fp_ratio))
        print(f"FP 下采样: {len(fp)} → {keep}（维持 FN:FP≈{args.fn_fp_ratio}:1）")
        fp = fp[:keep]
    selected = fn + fp + pf
    if args.max_pairs:
        selected = selected[: args.max_pairs]

    pairs, stats = [], {"teacher": 0, "template": 0, "teacher_disagree": 0, "teacher_fail": 0}
    for i, rec in enumerate(selected, 1):
        rejected_raw = rec["raw_output"].strip()
        # rejected 补 ChatML 结束符（模型原输出通常被截断，补全保证 DPO 格式完整）
        rejected = rejected_raw if rejected_raw.endswith("<|im_end|>") else rejected_raw + "<|im_end|>"

        if args.offline:
            chosen, tag = template_chosen(rec), "template"
        else:
            chosen, tag = teacher_chosen(args.teacher, rec)
            if chosen is None:
                chosen = template_chosen(rec)
        stats[tag] = stats.get(tag, 0) + 1

        pairs.append({
            "prompt": build_prompt(rec["original_code"], rec.get("language", "python")),
            "chosen": chosen,
            "rejected": rejected,
            "meta": {
                "file": rec.get("file", ""),
                "outcome": rec.get("outcome", ""),
                "chosen_source": tag,
                "needs_review": tag != "teacher",
            },
        })
        print(f"  [{i}/{len(selected)}] {rec.get('file', '?')} ({rec.get('outcome')}) → chosen={tag}")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for p in pairs:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")

    print(f"\n输出: {out_path}（{len(pairs)} 对）")
    print(f"chosen 来源统计: {stats}")
    if stats.get("template") or stats.get("teacher_disagree"):
        print("⚠ 含 template/teacher_disagree 对（meta.needs_review=true），"
              "建议人工复核或教师重生成后再合入训练（见 merge_dpo_data.py）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
