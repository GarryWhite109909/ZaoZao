"""
两阶段扫描全量稳定性评估脚本 —— 用真实 App 工具链（TwoStageScanner）跑 exp_04 87 段测试集。

目的：
  1. 验证工具链稳定性：Stage 1 工具召回 + Stage 2 LLM 裁决在真实调用路径上的表现。
  2. 定位漏报根因在 Stage1（工具未召回）还是 Stage2（裁决判错）。
  3. 暴露工具层盲区（无 source 型漏洞：整数溢出/弱随机/授权缺失/IDOR 等工具规则缺失），
     为工具链补充规则 / 增强提供证据。

与 evaluate.py 的区别：
  - evaluate.py 让 LLM 对整段代码做开放生成（source→sink→判定），测的是"纯 LLM 能力"。
  - 本脚本走 TwoStageScanner.scan_code()，Stage 1 静态工具先召回候选，Stage 2 LLM 只做
    封闭二分类裁决（is_confirmed），测的是"工具链 + 裁决"的完整管线（即 App 真实路径）。

裁决层后端：
  - 复用 OllamaClient（http://localhost:11434），模型 = 自研 α0（garrywhite109909/nivis-alpha0）。
  - system_prompt = --variant 指定的评估变体（默认 combined_nosource，α1 漏报修复最优）。
  - 需先启动 ollama serve 且 OLLAMA_MODELS 指向项目 models/ollama（见 bootstrap.py）。

用法（真实终端，需 GPU + Ollama）：
  # 全量 87 段，combined_nosource 裁决，full_recheck（消除静默放行）
  python eval_two_stage.py --model garrywhite109909/nivis-alpha0 --variant combined_nosource

  # 只跑指定样本（FN 冒烟）
  python eval_two_stage.py --only-files typical_29_integer_overflow.java

  # 断点续跑（跳过已评估样本）
  python eval_two_stage.py --resume

  # Stage 2 采样次数（默认 3，平衡速度与置信度）
  python eval_two_stage.py --n-samples 3

输出：
  - results/exp_07_two_stage_eval.{model}.{variant}.{ts}.json
  - 含总体指标 + 每样本明细（expected / predicted / stage1 findings / 工具命中 / 裁决）+ 工具盲区分析
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

# 多设备保护：Session 内强制 GPU 0（Ollama 后端不直接占用，但保持与全项目一致）
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")
os.environ.setdefault("HIP_VISIBLE_DEVICES", "0")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.two_stage_scanner import TwoStageScanner
from graduation_project.prompts import get_eval_system_prompt, EVAL_SYSTEM_VARIANTS
from graduation_project.transformers_client import create_llm_client
from experiments.utils import (
    load_manifest, read_sample_code, compute_detection_metrics, save_results_json,
)

MANIFEST_PATH = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples/manifest.json"
SAMPLES_DIR = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples"
OUTPUT_DIR = PROJECT_ROOT / "experiments/exp_07_two_stage_eval/results"
DEFAULT_MODEL = "garrywhite109909/nivis-alpha0"

# 工具类别 → 工具名映射（用于盲区分析：定位某 finding 由哪个工具召回）
# 注意：category 值以 two_stage_scanner.py 实际设置为准——
#   "taint"（semgrep taint + TaintTracker 合并）、"prefilter"、"secret"、"sca"、"sast"、"iac"
_TOOL_BY_CATEGORY = {
    "taint": "semgrep+TaintTracker",
    "prefilter": "Prefilter",
    "secret": "rich-secret",
    "sca": "trivy",
    "sast": "semgrep-sast",
    "iac": "trivy-iac",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="两阶段扫描全量稳定性评估（工具召回 + LLM 裁决）"
    )
    parser.add_argument("--backend", type=str, default="ollama",
                        choices=["ollama", "transformers", "llamacpp", "vllm"],
                        help="裁决推理后端（默认 ollama）。各后端精度不同，端到端结果可能不同。"
                             "transformers=NF4基座+FP16 LoRA进程内；llamacpp=Q4 GGUF+运行时LoRA；"
                             "vllm=OpenAI兼容API服务。")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL,
                        help=f"Ollama 裁决模型名（仅 ollama 后端，默认 {DEFAULT_MODEL}）")
    parser.add_argument("--adapter", type=str, default="",
                        help="transformers/llamacpp 后端的 LoRA adapter 目录（默认自动探测 models/adapter）")
    parser.add_argument("--base-model", type=str, default="",
                        help="transformers 后端的基座模型（默认自动探测 models/transformers）；"
                             "llamacpp 后端用 VULN_SCANNER_GGUF 环境变量指定基座 GGUF")
    parser.add_argument("--base-url", type=str, default="",
                        help="vllm 后端服务地址（默认 http://localhost:8000）")
    parser.add_argument("--variant", choices=list(EVAL_SYSTEM_VARIANTS),
                        default="combined_nosource",
                        help=f"裁决层 system prompt 变体（默认 combined_nosource，α1 漏报修复最优）。候选: {EVAL_SYSTEM_VARIANTS}")
    parser.add_argument("--n-samples", type=int, default=3,
                        help="Stage 2 自一致率采样次数 N（默认 3；越大执行越多样但越慢）")
    parser.add_argument("--temperature", type=float, default=0.7,
                        help="裁决采样温度（>0 保证投票多样性，默认 0.7）")
    parser.add_argument("--num-ctx", type=int, default=8192,
                        help="裁决上下文窗口 token 数（默认 8192）")
    parser.add_argument("--no-candidate-mode", choices=["sampled", "full_recheck"],
                        default="full_recheck",
                        help="无候选文件复核策略（默认 full_recheck=全量 LLM 复核，消除静默放行）")
    # 第 2.5 代架构开关（默认全开，论文消融关闭复现旧行为）
    parser.add_argument("--no-trust-llm-recheck", action="store_true",
                        help="关闭无候选复核采信 LLM（回退转人工 review）")
    parser.add_argument("--no-conformal", action="store_true",
                        help="关闭共形预测门控（回退自一致率置信）")
    parser.add_argument("--no-signal-feedback", action="store_true",
                        help="关闭信号回填（模型不帮助工具）")
    parser.add_argument("--no-counterfactual", action="store_true",
                        help="关闭反事实扰动验证（Layer 2）")
    parser.add_argument("--calibrate-from", type=str, default=None,
                        help="共形校准源：历史评估结果 JSON（含 adjudications 投票 + expected）")
    parser.add_argument("--no-calibrate-clean", action="store_true",
                        help="校准集不做净化（保留判错样本，对照实验）")
    # 工具开关（默认全开，复现 App 真实路径）
    parser.add_argument("--no-semgrep", action="store_true", dest="no_semgrep",
                        help="禁用 semgrep taint 召回")
    parser.add_argument("--no-taint-tracker", action="store_true", dest="no_taint_tracker",
                        help="禁用 TaintTracker 召回")
    parser.add_argument("--no-prefilter", action="store_true", dest="no_prefilter",
                        help="禁用 Prefilter 召回")
    parser.add_argument("--no-external", action="store_true", dest="no_external",
                        help="禁用外部位置型工具（secret/sca/sast/iac）召回")
    parser.add_argument("--only-files", type=str, default=None,
                        help="只评估指定文件名（逗号分隔）；默认评估全部")
    parser.add_argument("--resume", action="store_true",
                        help="断点续跑：跳过已评估样本（按 file 匹配已有结果）")
    parser.add_argument("--output", type=str, default=None,
                        help="结果 JSON 输出路径（默认自动生成）")
    return parser.parse_args()


def _hfv_to_str(hv) -> str:
    """has_vulnerability 三态 → 字符串"""
    if hv is True:
        return "true"
    if hv is False:
        return "false"
    return "review"  # None = 需人工复核


def _load_calibration_samples(history_json: str, only_correct: bool = True) -> list[dict]:
    """从历史评估结果构建共形校准集。

    每样本 = (某 finding 的投票统计, 该样本的真实标签)。标签取自 expected_present
    （漏洞=True / 安全=False）；只有真实标签已知的投票才能校准共形阈值。

    净化（only_correct=True，方案 2）：排除"样本最终判错"的 adjudications——
    工具误报 + 模型全票判中（safe_04/safe_08/safe_17 类）会让校准阈值偏向
    "全票≈漏洞"，导致分布外误报被放行。只保留正确判定的投票，阈值才反映
    "模型的真实判定质量"而非"误报样本的投票形态"。
    """
    import glob
    paths = [history_json]
    if "*" in history_json:
        paths = sorted(glob.glob(history_json))
    samples: list[dict] = []
    seen = set()
    for p in paths:
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception as e:
            print(f"[conformal] 校准源解析失败 {p}: {e}")
            continue
        for s in d.get("samples", []):
            exp = s.get("expected_present")
            if exp is None:
                continue
            if only_correct:
                pred = s.get("predicted")
                ok = (exp is True and pred is True) or (exp is False and pred is False)
                if not ok:
                    continue  # 净化：排除判错样本
            for a in s.get("adjudications", []):
                key = (p, s.get("file"), a.get("rule_id"))
                if key in seen:
                    continue
                seen.add(key)
                samples.append({
                    "votes_true": int(a.get("votes_true", 0)),
                    "votes_false": int(a.get("votes_false", 0)),
                    "votes_invalid": int(a.get("votes_invalid", 0)),
                    "n": int(s.get("n_samples", 3) or 3),
                    "label": bool(exp),
                })
    return samples


def _build_client(args):
    """按 --backend 构造裁决客户端（复用 App 的统一客户端工厂）。
    - ollama: OllamaClient(model=...)，连本地服务
    - vllm: VLLMClient(base_url=..., model=...)，连 OpenAI 兼容服务
    - transformers: TransformersClient(model_id=..., adapter=..., num_ctx=...)，进程内
    - llamacpp: LlamaCppClient(base_gguf=..., adapter=..., num_ctx=...)，进程内

    进程内后端（transformers/llamacpp）由 TwoStageScanner 首次调用时懒加载，
    不做启动即检查（check_connection 只在服务型后端可靠）。
    """
    backend = args.backend.strip().lower()
    if backend == "ollama":
        return create_llm_client("ollama", model=args.model)
    if backend == "vllm":
        return create_llm_client("vllm", base_url=args.base_url or "http://localhost:8000",
                                 model=args.model if args.model != DEFAULT_MODEL else None)
    if backend == "transformers":
        from graduation_project.paths import resolve_base_model_path, resolve_adapter_path
        return create_llm_client(
            "transformers",
            model_id=args.base_model or resolve_base_model_path("models/transformers/Qwen3-8B"),
            adapter=args.adapter or resolve_adapter_path("models/adapter"),
            num_ctx=args.num_ctx,
            merge=True,
        )
    if backend == "llamacpp":
        from graduation_project.paths import resolve_adapter_path
        return create_llm_client(
            "llamacpp",
            base_gguf=os.environ.get("VULN_SCANNER_GGUF", ""),
            adapter=args.adapter or resolve_adapter_path("models/adapter"),
            num_ctx=args.num_ctx,
        )
    raise ValueError(f"未知后端: {args.backend}")


def _client_ready(client, backend: str) -> bool:
    """服务型后端（ollama/vllm）启动时检查连接；进程内后端跳过（懒加载）。"""
    backend = backend.strip().lower()
    if backend in ("ollama", "vllm"):
        if not client.check_connection():
            if backend == "ollama":
                print("错误：无法连接 Ollama（localhost:11434）。请先运行 ollama serve，"
                      "并确认 OLLAMA_MODELS 指向项目 models/ollama。")
            else:
                print("错误：无法连接 vLLM 服务。请先启动 vLLM 服务并确认 --base-url。")
            return False
    else:
        print(f"进程内后端 {backend}：连接检查延迟到首次推理（懒加载），不在此处阻塞。")
    return True


def main() -> None:
    args = parse_args()

    # 1) 加载测试集
    print(f"测试集 manifest: {MANIFEST_PATH}")
    manifest, records = load_manifest(MANIFEST_PATH)
    if args.only_files:
        keep = {f.strip() for f in args.only_files.split(",") if f.strip()}
        records = [r for r in records if r.get("file") in keep]
        print(f"--only-files 过滤：仅评估 {len(records)} 段（{args.only_files}）")
    print(f"测试样本: {len(records)} 段")

    # 2) 构建裁决客户端（多后端）+ 构建裁决 system_prompt
    system_prompt = get_eval_system_prompt(args.variant)
    print(f"裁决 system prompt 变体: {args.variant}（{len(system_prompt)} 字符）")

    client = _build_client(args)
    if not _client_ready(client, args.backend):
        sys.exit(1)

    # 3) 构建两阶段扫描器（复现 App 真实工具链）
    scanner = TwoStageScanner(
        client=client,
        system_prompt=system_prompt,
        n_samples=args.n_samples,
        temperature=args.temperature,
        keep_alive=300,  # 采样突发期驻留 5 分钟，避免反复重载
        num_ctx=args.num_ctx,
        use_semgrep=not args.no_semgrep,
        use_taint_tracker=not args.no_taint_tracker,
        use_prefilter=not args.no_prefilter,
        use_external=not args.no_external,
        no_candidate_mode=args.no_candidate_mode,
        trust_llm_recheck=not args.no_trust_llm_recheck,
        use_conformal=not args.no_conformal,
        use_signal_feedback=not args.no_signal_feedback,
        use_counterfactual=not args.no_counterfactual,
    )
    # 共形预测器校准：从历史评估结果（adjudications 的投票 + 已知标签）拟合阈值
    if not args.no_conformal and scanner._conformal is not None and args.calibrate_from:
        calib = _load_calibration_samples(args.calibrate_from, only_correct=not args.no_calibrate_clean)
        if len(calib) >= 4:
            scanner._conformal.fit(calib)
            print(f"[conformal] 已从 {args.calibrate_from} 校准 "
                  f"({len(calib)} 样本, clean={not args.no_calibrate_clean}, "
                  f"{scanner._conformal.thresholds()})")
        else:
            print(f"[conformal] 校准样本不足（{len(calib)}），共形门控保持未校准")
    print(f"工具链: semgrep={not args.no_semgrep}, taint_tracker={not args.no_taint_tracker}, "
          f"prefilter={not args.no_prefilter}, external={not args.no_external} | "
          f"no_candidate={args.no_candidate_mode} | N采样={args.n_samples} | "
          f"trust={not args.no_trust_llm_recheck} | conformal={not args.no_conformal} | "
          f"signal_feedback={not args.no_signal_feedback} | counterfactual={not args.no_counterfactual}")

    # 4) 结果承载
    results = []
    seen = set()

    # 5) 断点续跑：加载已有结果，跳过已评估样本
    cand_output = args.output or (
        OUTPUT_DIR / f"exp_07_two_stage_eval.{args.model.split('/')[-1]}.{args.variant}.{time.strftime('%Y%m%d_%H%M%S')}.json"
    )
    cand_output = Path(cand_output)
    if args.resume and cand_output.exists():
        try:
            prev = json.loads(cand_output.read_text(encoding="utf-8"))
            # seen 按 file 去重判定（无论 predicted 是否为 None）：
            # 中断产生的 exception 样本（predicted=None）也视为"已处理"，重跑会重复
            # append 造成样本翻倍（2026-08-14 实测 87 段变 104 段）。已处理的样本
            # 一律跳过；本次扫描结束时用去重后的全量覆盖写盘。
            seen = {s["file"] for s in prev.get("samples", [])}
            results = prev.get("samples", [])
            print(f"[resume] 已有 {len(results)} 条结果，跳过 {len(seen)} 个已评估样本")
        except Exception as e:
            print(f"[resume] 读取已有结果失败，从头开始: {e}")

    # 6) 逐样本扫描
    t_start = time.time()
    for i, rec in enumerate(records):
        fname = rec.get("file", "")
        if fname in seen:
            continue
        code = read_sample_code(SAMPLES_DIR, fname)
        if code is None:
            continue
        lang = (rec.get("language") or "python").lower()
        exp = rec.get("expected_present")
        exp_cwe = rec.get("expected_cwe", "")

        t0 = time.time()
        try:
            r = scanner.scan_code(code=code, language=lang, filename=fname)
        except Exception as e:
            print(f"[异常] {fname}: {e}")
            r = None
        dur = time.time() - t0

        if r is None:
            record = {
                "file": fname, "language": lang,
                "expected_present": exp, "expected_cwe": exp_cwe,
                "predicted": None, "decision": "exception", "error": str(e),
                "duration": round(dur, 2), "stage1_new": 0, "tools_hit": [],
                "adjudications": [], "reviewer_findings": [],
            }
            results.append(record)
            continue

        # 工具命中归类
        tools_hit = sorted({
            _TOOL_BY_CATEGORY.get(f.category, f.category or "unknown")
            for f in r.findings
        })
        stage1 = r.stage1 or {}
        record = {
            "file": fname, "language": lang,
            "expected_present": exp, "expected_cwe": exp_cwe,
            "predicted": r.has_vulnerability,
            "predicted_str": _hfv_to_str(r.has_vulnerability),
            "decision": stage1.get("decision", ""),
            "vulnerability_type": r.vulnerability_type,
            "raw_vulnerability_type": r.raw_vulnerability_type,
            "risk_level": r.risk_level,
            "explanation": (r.explanation or "")[:300],
            "fix_suggestion": (r.fix_suggestion or "")[:200],
            "error": r.error,
            "duration": round(dur, 2),
            "stage1": stage1,
            "stage1_new": len(r.findings),
            "tools_hit": tools_hit,
            # 每个 finding 的裁决结果（供漏报/误报归因）
            "adjudications": [
                {
                    "rule_id": (a.finding or {}).get("rule_id"),
                    "category": (a.finding or {}).get("category"),
                    "taint_type": (a.finding or {}).get("taint_type"),
                    "confirmed": a.confirmed,
                    "confidence": a.confidence,
                    "votes_true": a.votes_true,
                    "votes_false": a.votes_false,
                    "votes_invalid": a.votes_invalid,
                    "reason": (a.reasoning or "")[:150],
                    # 第 2.5 代字段（论文消融对比用）
                    "vulnerability_type": a.vulnerability_type,
                    "conformal_set": a.conformal_set,
                    "counterfactual": a.counterfactual,
                }
                for a in r.adjudications
            ],
            "reviewer_findings": [
                {"rule_id": rf.get("rule_id"), "category": rf.get("category"),
                 "taint_type": rf.get("taint_type"), "confidence": rf.get("confidence")}
                for rf in r.reviewer_findings
            ],
        }
        results.append(record)
        print(f"[{i+1}/{len(records)}] {fname} -> {record['predicted_str']} "
              f"(findings={record['stage1_new']}, tools={record['tools_hit']}, {dur:.0f}s)")

        # 增量落盘（每样本保存，防中断丢失）
        save_results_json(cand_output, {
            "meta": {
                "backend": args.backend,
                "model": args.model, "adapter": args.adapter, "variant": args.variant,
                "n_samples": args.n_samples, "temperature": args.temperature,
                "no_candidate_mode": args.no_candidate_mode,
                "tools": {"semgrep": not args.no_semgrep, "taint_tracker": not args.no_taint_tracker,
                          "prefilter": not args.no_prefilter, "external": not args.no_external},
                # 第 2.5 代架构开关（论文消融可辨）
                "trust_llm_recheck": not args.no_trust_llm_recheck,
                "conformal": not args.no_conformal,
                "signal_feedback": not args.no_signal_feedback,
                "counterfactual": not args.no_counterfactual,
                "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            },
            "samples": results,
        })

    total_dur = time.time() - t_start
    print(f"\n扫描完成: {len(results)} 段, 总耗时 {total_dur:.0f}s")

    # 7a) 去重（resume 叠加可能产生重复样本，保留每文件最新一条）
    seen_final: set[str] = set()
    dedup_results = []
    for s in results:
        if s["file"] in seen_final:
            continue
        seen_final.add(s["file"])
        dedup_results.append(s)
    if len(dedup_results) != len(results):
        print(f"[resume] 去重：{len(results)} → {len(dedup_results)} 条")
        results = dedup_results

    # 7) 汇总指标
    # 区分三态：漏洞样本 only（expected=True）看 recall；安全样本（expected=False）看 FPR
    # None（review）= 需复核，既不算 TP 也不算 FN，单独统计
    vuln = [s for s in results if s["expected_present"] is True]
    safe = [s for s in results if s["expected_present"] is False]

    tp = sum(1 for s in vuln if s["predicted"] is True)
    fn = sum(1 for s in vuln if s["predicted"] is False)
    review_vuln = sum(1 for s in vuln if s["predicted"] is None)
    tn = sum(1 for s in safe if s["predicted"] is False)
    fp = sum(1 for s in safe if s["predicted"] is True)
    review_safe = sum(1 for s in safe if s["predicted"] is None)

    recall = tp / (tp + fn) if (tp + fn) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else None

    # 工具层盲区分析：expected 漏洞样本中，各工具是否召回（判断漏报是否工具层失职）
    # 有候选但裁决 False → Stage2 漏报；无候选（工具未召回）→ Stage1 漏报
    fn_by_stage = {"stage1_no_candidate": 0, "stage2_rejected": 0, "review": 0}
    tool_cover = {}  # category → {有候选, 无候选}
    fn_details = []
    for s in vuln:
        if s["predicted"] is True:
            continue
        if s["predicted"] is None:
            fn_by_stage["review"] += 1
            continue
        if s["stage1_new"] == 0:
            fn_by_stage["stage1_no_candidate"] += 1
            fn_details.append({"file": s["file"], "stage": "stage1_no_candidate",
                               "expected_cwe": s["expected_cwe"], "tools": s["tools_hit"]})
        else:
            fn_by_stage["stage2_rejected"] += 1
            fn_details.append({"file": s["file"], "stage": "stage2_rejected",
                               "expected_cwe": s["expected_cwe"], "tools": s["tools_hit"],
                               "adjudications": s["adjudications"]})

    summary = {
        "total": len(results),
        "vuln_total": len(vuln), "safe_total": len(safe),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "review_vuln": review_vuln, "review_safe": review_safe,
        "recall": round(recall, 4) if recall is not None else None,
        "fpr": round(fpr, 4) if fpr is not None else None,
        "accuracy": round(acc, 4) if acc is not None else None,
        "fn_by_stage": fn_by_stage,
        "fn_details": fn_details,
        "total_duration": round(total_dur, 2),
    }

    # 8) 落盘 + 打印
    out_data = {
        "meta": {
            "backend": args.backend,
            "model": args.model, "adapter": args.adapter, "variant": args.variant,
            "n_samples": args.n_samples, "temperature": args.temperature,
            "no_candidate_mode": args.no_candidate_mode,
            "tools": {"semgrep": not args.no_semgrep, "taint_tracker": not args.no_taint_tracker,
                      "prefilter": not args.no_prefilter, "external": not args.no_external},
            # 第 2.5 代架构开关（修复：最终落盘曾缺失，导致 transformers 结果无法辨档）
            "trust_llm_recheck": not args.no_trust_llm_recheck,
            "conformal": not args.no_conformal,
            "signal_feedback": not args.no_signal_feedback,
            "counterfactual": not args.no_counterfactual,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
        "summary": summary,
        "samples": results,
    }
    save_results_json(cand_output, out_data)

    print(f"\n===== 两阶段扫描汇总（{args.backend} / {args.variant}）=====")
    print(f"  样本总数: {summary['total']}（漏洞 {len(vuln)} / 安全 {len(safe)}）")
    print(f"  TP={tp} TN={tn} FP={fp} FN={fn} | 复核(vuln)={review_vuln} 复核(safe)={review_safe}")
    print(f"  recall={summary['recall']}  fpr={summary['fpr']}  acc={summary['accuracy']}")
    print(f"  漏报归因: 工具未召回(Stage1)={fn_by_stage['stage1_no_candidate']} | "
          f"裁决否决(Stage2)={fn_by_stage['stage2_rejected']} | 复核(None)={fn_by_stage['review']}")
    if fn_details:
        print("\n  漏报明细:")
        for d in fn_details:
            print(f"    [{d['stage']}] {d['file']} (exp={d['expected_cwe']}, tools={d['tools']})")
    print(f"\n结果已保存: {cand_output}")


if __name__ == "__main__":
    main()