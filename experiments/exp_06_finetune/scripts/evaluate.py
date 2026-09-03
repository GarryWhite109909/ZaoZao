"""
微调效果评估脚本 —— 在 exp_04 87 段测试集上对比微调前后模型表现。

支持两种模式：
  --mode baseline   评估模型在代码漏洞检测任务上的表现（当前基座：Qwen3-8B）
  --mode finetuned  评估加载了 LoRA adapter 的微调模型

P0 改造（glm 建议）：
  - 默认 temperature=0.0, do_sample=False（确定性解码），消除采样随机性
  - --seeds N 跑 N 个种子取均值±标准差（多种子显著性检验）
  - --checkpoint 指定评估哪个 checkpoint（checkpoint-36 / checkpoint-45 / final）

用法（在 AI conda 环境中运行，需 GPU）：
  # 评估基座（对照组，确定性解码）
  python3 evaluate.py --mode baseline

  # 评估微调后（默认 final adapter，确定性解码）
  python3 evaluate.py --mode finetuned

  # 对比 checkpoint-36 vs checkpoint-45 vs final，各跑 3 个种子
  python3 evaluate.py --mode finetuned \
      --checkpoint checkpoint-36 --seeds 3
  python3 evaluate.py --mode finetuned \
      --checkpoint checkpoint-45 --seeds 3
  python3 evaluate.py --mode finetuned \
      --checkpoint final --seeds 3
"""

import argparse
import json
import os
import re
import statistics
import sys
import time
from pathlib import Path

# ROCm 多设备保护：在 import torch 前强制只用 GPU 0
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")
os.environ.setdefault("HIP_VISIBLE_DEVICES", "0")

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import (
    BASE_PROMPT as SYSTEM_PROMPT,
    build_user_prompt,
    get_eval_system_prompt,
    EVAL_SYSTEM_VARIANTS,
)
from graduation_project.schema import parse_verdict, normalize_has_vulnerability
from graduation_project.fix_verifier import FixVerifier, extract_line_refs, has_code_fence
from graduation_project.cwe_normalizer import normalize_cwe_label, normalize_with_evidence, cwe_family_match  # strict CWE 编号纠正（2026-08-16/17）
from experiments.utils import (
    load_manifest, read_sample_code, compute_detection_metrics,
    compute_repeat_metrics, save_results_json,
)
from experiments.scoring import build_record, instance_metrics  # 实例级 micro/macro 记账（2026-09-03）

# Ollama 后端（延迟导入，仅 --ollama-model 时使用）
_ollama_client = None
_ollama_model_name = None  # 记录当前 Ollama 模型名，用于 Qwen3 thinking mode 检测

MODEL_ID = "Qwen/Qwen3-8B"  # 默认 Qwen3-8B（Instruct），与训练脚本一致
MANIFEST_PATH = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples/manifest.json"
SAMPLES_DIR = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples"
OUTPUT_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/results"
# 默认 LoRA 输出根目录，用于 --checkpoint 简写解析
# 注意：原值 `lora_r16_a32_e3_s42/best` 是 Qwen2.5 时代的路径，已不存在。
# Qwen3-8B 时代本地 SFT 输出命名统一为 `lora_r{r}_a{a}_e{e}_lr{lr}_s{seed}_rslora{...}`，
# 此处指向最近一次本地 Qwen3 SFT 产物（lora_r8_a16_e3_lr0.0001_s42_rsloraqwen3_8b_sft_p2_v4/best）。
# 云端蒸馏产物（v8/v9/v9max、α0）不在本地 outputs/ 下，需显式 --adapter-path 指定。
DEFAULT_LORA_ROOT = PROJECT_ROOT / "experiments/exp_06_finetune/outputs/lora_r8_a16_e3_lr0.0001_s42_rsloraqwen3_8b_sft_p2_v4/best"


# ---------------------------------------------------------------------------
# Self-Verification 后处理（P2-7）
# ---------------------------------------------------------------------------
# 动机：typical_19 出现"推理对结论错"的结论漂移——CoT 识别出 random.choices
# 是伪随机，JSON 却标 has_vulnerability=false 并捏造"已用 secrets"。仅靠
# SYSTEM_PROMPT_LITE 的一致性约束（P0-1）是软约束，模型可能仍不一致。
# Self-Verification 在首轮生成后追加一轮校验，让模型自检 CoT→JSON 一致性。
#
# 成本：增加一轮推理（~15s/样本），可选启用（--self-verify）。
SELF_VERIFY_PROMPT = (
    "请对你上面的回答进行自检：\n"
    "1. 你的分析过程（CoT）中识别了哪些风险？\n"
    "2. JSON 结论中的 has_vulnerability 是否与 CoT 推理结论一致？\n"
    "   - 若 CoT 识别出风险（如“弱随机”“不安全”“存在漏洞”），JSON 不得标 false；\n"
    "   - 若 CoT 未识别出风险，JSON 不得标 true。\n"
    "3. 如果不一致，请修正 JSON 结论。\n"
    "4. 如果一致，请原样输出 JSON 结论。\n"
    "请只输出最终的 JSON 对象（用 ```json 包裹），不需要重复分析过程。"
)


# ---------------------------------------------------------------------------
# 严格评估：校验 vulnerability_type + CWE（P0-2）
# ---------------------------------------------------------------------------
# 动机：当前评估只看 has_vulnerability 布尔值，不校验漏洞类型和 CWE。
# 部分样本"蒙对了方向但分析错误"（如 Spring4Shell 标成 CWE-89 SSTI），
# 严格指标把这些"水份 TP"降级为 strict_FN，暴露模型真实能力。
_CWE_PATTERN = re.compile(r'(CWE-\d+)', re.IGNORECASE)


def extract_cwe(vulnerability_type: str) -> str:
    """从 vulnerability_type 字符串中提取 CWE 编号。

    >>> extract_cwe("CWE-89 SQL注入")
    'CWE-89'
    >>> extract_cwe("none")
    ''
    >>> extract_cwe("CWE-79 XSS")
    'CWE-79'
    """
    if not vulnerability_type:
        return ""
    m = _CWE_PATTERN.search(vulnerability_type)
    return m.group(1).upper() if m else ""


def cwe_matches(model_cwe: str, expected_cwe: str) -> bool:
    """检查模型输出的 CWE 是否与预期匹配。

    预期为 "N/A" 或空时（安全样本），不参与 CWE 匹配，返回 True。
    支持分号分隔的多 CWE 预期值（如 "CWE-434; CWE-22"），匹配任一即可。
    2026-08-17：改用 cwe_family_match 做父子族宽松（CWE-917 ⊂ CWE-94 等），
    模型报子类而测试集标父类（或反之）不再误判不匹配。
    """
    if not expected_cwe or expected_cwe.upper() == "N/A":
        return True
    if not model_cwe:
        return False
    expected_cwes = [c.strip().upper() for c in expected_cwe.split(";") if c.strip()]
    return any(cwe_family_match(model_cwe, ec) for ec in expected_cwes)


def compute_strict_metrics(results: list[dict]) -> dict:
    """计算严格指标：has_vulnerability 正确 AND CWE 匹配才算 strict_TP。

    安全样本（expected_present=False）的 TN/FP 不受 CWE 校验影响，
    严格指标只影响漏洞样本的 TP/FN 划分。
    """
    strict_tp = 0
    cwe_mismatch = 0  # has_vulnerability 判对但 CWE 标错

    for r in results:
        exp = r.get("expected_present")
        pred = r.get("predicted")
        if exp is None or pred is None:
            continue
        if exp and pred:
            # 漏洞样本且模型也判 True → 检查 CWE
            model_vt = r.get("model_vulnerability_type", "")
            expected_cwe = r.get("expected_cwe", "")
            # 2026-08-16 修复：先过 cwe_normalizer 再提取编号——normalizer 的设计
            # 意图就是"模型输出后确定性纠正编号记忆错误"（docstring：CWE 编号是
            # 纯记忆任务易记错，如 CWE-77 vs CWE-78 同为命令注入）。此前 strict
            # 计算直接 extract 原始编号，纠正工具形同虚设——模型语义分类正确
            # （"Command Injection"）却因编号差异被记 cwe_mismatch，冤枉分析能力。
            # 现在：语义分类对 + normalizer 编号纠正 → strict_tp。
            # 2026-08-17：vulnerability_type 落规则 ID/表外时，用模型原始输出
            # （raw_output 含分析文本）二次提取类型（normalize_with_evidence）——
            # 模型分析写对（"构成 CSRF"）但类型字段记错（CWE-639）的样本由此救回。
            evidence = r.get("raw_output", "") or ""
            model_cwe = extract_cwe(
                normalize_with_evidence(model_vt, evidence) if evidence else normalize_cwe_label(model_vt)
            )
            if cwe_matches(model_cwe, expected_cwe):
                strict_tp += 1
            else:
                cwe_mismatch += 1

    loose = compute_detection_metrics(results)
    vuln_total = loose["vuln_total"]
    valid = loose["valid"]
    tn = loose["tn"]

    # 统计漏洞样本中 parse_fail 的数量（predicted 为 None 的漏洞样本）
    parse_fail_count = sum(
        1 for r in results
        if r.get("expected_present") is True and r.get("predicted") is None
    )

    strict_fn = vuln_total - strict_tp
    strict_recall = strict_tp / vuln_total if vuln_total else None
    strict_accuracy = (strict_tp + tn) / valid if valid else None
    # 含 parse_fail 的召回率：分母加上 parse_fail 的漏洞样本，避免被人为抬高
    vuln_total_with_parse_fail = vuln_total + parse_fail_count  # 含 parse_fail 的漏洞样本
    strict_recall_with_parse_fail = strict_tp / vuln_total_with_parse_fail if vuln_total_with_parse_fail else None

    # 实例级记账（2026-09-03）：strict 的"命中任一 CWE 即算"会高估多漏洞样本的
    # 覆盖（3 个漏洞只找出 1 个记满分）。micro 按 (样本, 预期CWE) 逐实例记 0/1，
    # macro 按 CWE 类别平均暴露小类盲区。判定复用同一套 cwe_family_match，
    # model_cwe 提取链路与上方 strict 循环一致（experiments/scoring.py）。
    # 只增键不改键：历史结果文件解析方不受影响。
    inst = instance_metrics([build_record(r) for r in results])

    return {
        "strict_tp": strict_tp,
        "strict_fn": strict_fn,
        "cwe_mismatch": cwe_mismatch,
        "parse_fail_count": parse_fail_count,
        "strict_recall": round(strict_recall, 4) if strict_recall is not None else None,
        "strict_recall_with_parse_fail": round(strict_recall_with_parse_fail, 4) if strict_recall_with_parse_fail is not None else None,
        "strict_accuracy": round(strict_accuracy, 4) if strict_accuracy is not None else None,
        "instance_total": inst["instance_total"],
        "instance_hits": inst["instance_hits"],
        "instance_recall_micro": inst["instance_recall_micro"],
        "instance_recall_macro": inst["instance_recall_macro"],
        "full_coverage_rate": inst["full_coverage_rate"],
        "per_cwe_recall": inst["per_cwe_recall"],
    }


# ---------------------------------------------------------------------------
# 修复建议评估（2026-08-08 起：行号锚定的局部修复建议）
# ---------------------------------------------------------------------------
# 动机：schema 的 fix_suggestion 已改为"行号锚定的简短修复建议"（单行、不含
# 完整代码），FixVerifier 的"完整代码抽取→语法校验→危险模式移除"只对仍输出
# 代码块的样本有意义。主指标改为：
#   1. fix_suggested_rate：漏洞且判 True 的样本中给出非空建议的比例
#   2. fix_anchored_rate：建议含行号引用且所有引用行号都落在代码真实行数内
#      （自动抓"第几行"幻觉）
# 代码块指标（fix_extracted/fix_syntax_ok/fix_usable）保留为辅助口径。
_LANG_MAP = {
    "python": "python", "py": "python", "python3": "python",
    "javascript": "javascript", "js": "javascript", "node": "javascript",
    "java": "java",
}

def lang_for_fix(language: str) -> str:
    """把 manifest 的 language 字段映射到 FixVerifier 支持的语法标签。"""
    return _LANG_MAP.get((language or "").strip().lower(), (language or "").strip().lower())


def compute_fix_metrics(results: list[dict], verifier: FixVerifier) -> dict:
    """计算修复建议指标。

    只对"漏洞样本且模型判 True"的样本做修复校验（真正的修复场景）。
    安全样本（expected_present=False）或模型判 False 的样本不参与修复建议统计。

    Returns:
        {
            "fix_applicable": 应尝试修复的样本数（漏洞且模型判 True）
            "fix_suggested": 给出非空建议的数量
            "fix_suggested_rate": fix_suggested / fix_applicable
            "fix_anchored": 行号引用全部落在代码行数范围内的数量
            "fix_anchored_rate": fix_anchored / fix_applicable
            "fix_line_ref_invalid": 有行号引用但至少一个超出代码行数范围的数量
            "fix_extracted": 建议含代码围栏且能抽到代码块的数量（辅助口径）
            "fix_syntax_ok": 上述代码块语法通过的数量
            "fix_removed_vuln": 危险模式移除的数量（tests_passed=True）
            "fix_usable": 语法通过 且 危险模式移除 的数量（辅助口径）
            "fix_usable_rate": fix_usable / fix_applicable
            "fix_issues": {reason: count} 各类问题计数
            "per_sample": 每个样本的修复校验结果
        }
    """
    fix_applicable = 0
    fix_suggested = 0
    fix_anchored = 0
    fix_line_ref_invalid = 0
    fix_extracted = 0
    fix_syntax_ok = 0
    fix_removed_vuln = 0
    fix_usable = 0
    issues: dict[str, int] = {}
    per_sample = []

    for r in results:
        # 只对"漏洞样本 + 模型判 True"做修复校验
        if r.get("expected_present") is not True:
            continue
        if r.get("predicted") is not True:
            continue
        fix_applicable += 1

        original_code = r.get("original_code", "")
        fix_suggestion = r.get("model_fix_suggestion", "")
        language = lang_for_fix(r.get("language", ""))

        # 主口径 1：是否给出非空建议
        suggested = bool((fix_suggestion or "").strip())
        if suggested:
            fix_suggested += 1
        else:
            issues["模型未输出fix_suggestion"] = issues.get("模型未输出fix_suggestion", 0) + 1

        # 主口径 2：行号引用是否落在真实代码行数内
        line_refs = extract_line_refs(fix_suggestion or "")
        total_lines = len((original_code or "").split("\n"))
        refs_valid = bool(line_refs) and all(1 <= n <= total_lines for n in line_refs)
        if line_refs and not refs_valid:
            fix_line_ref_invalid += 1
            issues["行号超出代码范围"] = issues.get("行号超出代码范围", 0) + 1
        if refs_valid:
            fix_anchored += 1

        # 辅助口径：仍输出代码围栏时，用 FixVerifier 做旧式校验
        code_block = has_code_fence(fix_suggestion or "")
        vres = verifier.verify_fix(original_code, fix_suggestion, language=language) if code_block else None
        if vres is None:
            if suggested and not code_block:
                issues["建议未含代码块（新格式正常）"] = issues.get("建议未含代码块（新格式正常）", 0) + 1
        else:
            if vres.fixed_code is None:
                issues["未抽到代码块"] = issues.get("未抽到代码块", 0) + 1
            else:
                fix_extracted += 1
                if vres.syntax_valid:
                    fix_syntax_ok += 1
                else:
                    issues["语法错误"] = issues.get("语法错误", 0) + 1
                if vres.tests_passed is True:
                    fix_removed_vuln += 1
                elif vres.tests_passed is False:
                    issues["危险模式仍在"] = issues.get("危险模式仍在", 0) + 1
            if vres.syntax_valid and (vres.tests_passed is True):
                fix_usable += 1

        per_sample.append({
            "file": r.get("file", ""),
            "language": r.get("language", ""),
            "expected_cwe": r.get("expected_cwe", ""),
            "model_vulnerability_type": r.get("model_vulnerability_type", ""),
            "fix_suggested": suggested,
            "line_refs": sorted(line_refs),
            "total_lines": total_lines,
            "fix_anchored": refs_valid,
            "fix_code_block": code_block,
            "fix_extracted": vres.fixed_code is not None if vres else False,
            "syntax_valid": vres.syntax_valid if vres else None,
            "tests_passed": vres.tests_passed if vres else None,
            "fix_usable": (vres.syntax_valid and vres.tests_passed is True) if vres else False,
            "error_message": vres.error_message if vres else None,
        })

    fix_suggested_rate = fix_suggested / fix_applicable if fix_applicable else None
    fix_anchored_rate = fix_anchored / fix_applicable if fix_applicable else None
    fix_usable_rate = fix_usable / fix_applicable if fix_applicable else None
    return {
        "fix_applicable": fix_applicable,
        "fix_suggested": fix_suggested,
        "fix_suggested_rate": round(fix_suggested_rate, 4) if fix_suggested_rate is not None else None,
        "fix_anchored": fix_anchored,
        "fix_anchored_rate": round(fix_anchored_rate, 4) if fix_anchored_rate is not None else None,
        "fix_line_ref_invalid": fix_line_ref_invalid,
        "fix_extracted": fix_extracted,
        "fix_syntax_ok": fix_syntax_ok,
        "fix_removed_vuln": fix_removed_vuln,
        "fix_usable": fix_usable,
        "fix_usable_rate": round(fix_usable_rate, 4) if fix_usable_rate is not None else None,
        "fix_issues": issues,
        "per_sample": per_sample,
    }


def resolve_adapter_path(checkpoint: str | None, adapter_path: str | None) -> str | None:
    """把 --checkpoint 简写（如 checkpoint-36）解析为完整路径。

    优先级：--adapter-path 显式路径 > --checkpoint 简写 > None
    """
    if adapter_path:
        return adapter_path
    if checkpoint:
        # checkpoint=final → .../lora_r8_a16_e3_lr0.0001_s42_rsloraqwen3_8b_sft_p2_v4/best/final
        # checkpoint=checkpoint-36 → .../.../best/checkpoint-36
        return str(DEFAULT_LORA_ROOT / checkpoint)
    return None


def load_model(mode: str, adapter_path: str | None, quantize_4bit: bool, model_id: str = MODEL_ID,
               merge: bool = True):
    """加载模型 + tokenizer。

    Args:
        merge: True 时合并 LoRA 进基座（推理快，但 NF4 基座下 LoRA 增量精度有损）；
            False 时保留 PeftModel 运行时叠加（LoRA FP16 精度最大，推理更慢）。
    """
    print(f"加载 tokenizer: {model_id}")
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    dtype = torch.float16
    bnb_config = None
    if quantize_4bit:
        from transformers import BitsAndBytesConfig
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
        )
        print(f"启用 4bit NF4 量化推理")

    print(f"加载模型: {model_id} (mode={mode}, {'4bit' if bnb_config else 'fp16'})")
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        quantization_config=bnb_config,
        device_map={"": 0},
        trust_remote_code=True,
        torch_dtype=dtype,
        attn_implementation="sdpa",  # 推理用 sdpa 比 eager 快很多
    )

    if mode == "finetuned" and adapter_path:
        print(f"加载 LoRA adapter: {adapter_path}")
        model = PeftModel.from_pretrained(model, adapter_path)
        if merge:
            model = model.merge_and_unload()  # 合并 LoRA 权重加速推理
            print("LoRA 已合并")
        else:
            print("不合并 LoRA：保留 PeftModel 运行时叠加（FP16 精度最大，推理更慢）")

    model.eval()
    return model, tokenizer


def generate_response(
    model, tokenizer, messages,
    max_new_tokens=2048,
    temperature=0.0,
    do_sample=False,
) -> str:
    """用 ChatML 模板生成回复。

    P0 改造：默认 temperature=0.0, do_sample=False（确定性贪心解码），
    消除采样随机性，使评估结果可复现。多种子评估通过 --seeds 重复跑实现。

    max_new_tokens=2048：与 generate_response_ollama 对齐。Qwen3-8B 在长代码上倾向
    写超长分析（13 项 CWE 逐个检查），1024 tokens 会截断 JSON 导致 parse_fail
    （hard_longfile_03_hidden_ssti.py 案例：2104 字符分析还没开始 JSON）。

    若 do_sample=True，需配合 temperature>0 / top_p，否则回退到贪心。
    """
    text = tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True,
        enable_thinking=False,  # Qwen3: 禁用 thinking mode，直接输出 JSON
    )
    inputs = tokenizer(text, return_tensors="pt").to(model.device)
    gen_kwargs = {
        "max_new_tokens": max_new_tokens,
        "pad_token_id": tokenizer.pad_token_id,
    }
    if do_sample and temperature > 0:
        gen_kwargs["do_sample"] = True
        gen_kwargs["temperature"] = temperature
        gen_kwargs["top_p"] = 0.9
    else:
        gen_kwargs["do_sample"] = False  # 确定性贪心解码
    with torch.no_grad():
        outputs = model.generate(**inputs, **gen_kwargs)
    # 只取新生成的部分
    input_len = inputs["input_ids"].shape[1]
    response = tokenizer.decode(outputs[0][input_len:], skip_special_tokens=True)
    return response


def generate_batch_response(model, tokenizer, messages_list,
                            max_new_tokens=2048, num_ctx=8192,
                            temperature=0.0, do_sample=False):
    """批量生成回复（左 padding 对齐，返回与 generate_response 等价的列表）。

    batch 只改变"几条序列并行解码"，贪心解码下每个序列逐 token argmax，
    结果与单条逐条算逐 token 一致，准确率不变，仅摊薄权重读取提升功耗/吞吐。

    num_ctx 越小、单批可容纳样本越多；反之须调小 batch。左 padding 下
    取生成区需按 batch 逐行截断，行间长度可不同。
    """
    if not messages_list:
        return []
    # 用 apply_chat_template 逐条构造文本（与 generate_response 完全一致）
    texts = []
    for messages in messages_list:
        texts.append(tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True,
            enable_thinking=False,
        ))
    max_input = max(1, num_ctx - max_new_tokens)
    old_side = tokenizer.padding_side
    tokenizer.padding_side = "left"
    enc = tokenizer(texts, return_tensors="pt", padding=True,
                    truncation=True, max_length=max_input)
    tokenizer.padding_side = old_side
    enc = {k: v.to(model.device) for k, v in enc.items()}
    gen_kwargs = {
        "max_new_tokens": max_new_tokens,
        "pad_token_id": tokenizer.pad_token_id,
    }
    if do_sample and temperature > 0:
        gen_kwargs["do_sample"] = True
        gen_kwargs["temperature"] = temperature
        gen_kwargs["top_p"] = 0.9
    else:
        gen_kwargs["do_sample"] = False
    with torch.no_grad():
        outputs = model.generate(**enc, **gen_kwargs)
    padded_len = enc["input_ids"].shape[1]
    eos = tokenizer.eos_token_id
    responses = []
    for i in range(len(messages_list)):
        row = outputs[i][padded_len:]
        if eos is not None:
            pos = (row == eos).nonzero(as_tuple=True)[0]
            if len(pos) > 0:
                row = row[:pos[0]]
        responses.append(tokenizer.decode(row, skip_special_tokens=True))
    return responses


def generate_response_ollama(
    messages,
    max_new_tokens=2048,
    temperature=0.0,
    num_ctx=16384,
    num_gpu=None,
) -> str:
    """用 Ollama 后端生成回复（接口与 generate_response 对齐）。

    用于评估本地 Ollama 模型（如 qwen3-coder:30b），
    无需 HuggingFace transformers 加载，支持 CPU+GPU 混合推理。

    Qwen3 thinking mode 由 OllamaClient 自动处理（chat API + think:false），
    无需在此追加 /no_think 后缀或剥离思考块。

    max_new_tokens=2048：Qwen3-8B 在长代码（如 hard_longfile_03_hidden_ssti.py
    181 行）上倾向写超长分析（13 项 CWE 逐个检查），1024 tokens 不足以写完
    分析+JSON，导致输出被截断无 JSON 块而 parse_fail。2048 可覆盖。
    """
    global _ollama_client, _ollama_model_name
    if _ollama_client is None:
        raise RuntimeError("OllamaClient 未初始化")

    # 从 messages 中提取 system 和 user prompt
    system_prompt = ""
    user_prompt = ""
    for msg in messages:
        if msg["role"] == "system":
            system_prompt = msg["content"]
        elif msg["role"] == "user":
            user_prompt = msg["content"]

    result = _ollama_client.generate(
        prompt=user_prompt,
        system_prompt=system_prompt,
        temperature=temperature,
        max_tokens=max_new_tokens,
        num_ctx=num_ctx,
        num_gpu=num_gpu,
        keep_alive=300,  # 评估期间常驻 5 分钟（空闲超时自动释放）
    )
    if result.get("error"):
        raise RuntimeError(f"Ollama error: {result['error']}")

    return result.get("text", "")


def evaluate(model, tokenizer, manifest_records,
             temperature=0.0, do_sample=False, run_seed=42,
             samples_dir=None, self_verify=False, ollama_num_gpu=None, ollama_num_ctx=16384,
             rag_cm=None, rag_collection="vulnerability_knowledge", rag_top_k=3,
             system_prompt=None):
    """在样本集上评估，返回结果列表。

    P0 改造：接受 temperature / do_sample / run_seed 参数。
    run_seed 用于在多种子评估时设置 torch 随机种子（仅对 do_sample=True 有效）。

    P2-7 改造：self_verify=True 时，首轮生成后追加一轮校验，让模型自检
    CoT→JSON 一致性。能检测 typical_19 那种结论漂移（推理对结论错）。

    RAG 改造（docs/方法.md §3 L1）：rag_cm 传入时，每个样本的代码作为 query
    检索 Chroma 知识库，返回 Top-K 条 CWE 规则注入 prompt。
    解决 Phase 1 发现的 33/87 CWE 错标问题。
    """
    if do_sample and run_seed is not None:
        torch.manual_seed(run_seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(run_seed)

    results = []
    for i, rec in enumerate(manifest_records):
        filename = rec["file"]
        language = rec["language"]
        expected_present = rec["expected_present"]

        # 读取代码
        code_samples_dir = samples_dir if samples_dir is not None else SAMPLES_DIR
        code = read_sample_code(code_samples_dir, filename)
        if code is None:
            print(f"[{i+1}/{len(manifest_records)}] 跳过 {filename}（代码不存在）")
            continue

        # 跨文件样本处理
        # 注意：注释里不写文件名（input_file/filename 含 crossfile/sink/input 等标签词，
        # 会暗示模型这是跨文件污点分析场景，造成答案泄漏）。仅用中性描述。
        if "crossfile" in filename and filename.endswith("_sink.py"):
            input_file = filename.replace("_sink.py", "_input.py")
            input_code = read_sample_code(code_samples_dir, input_file)
            if input_code:
                code = f"# 相关代码上下文（同项目另一文件）\n{input_code}\n\n# 待分析的目标代码\n{code}"

        # RAG 检索（参考 docs/方法.md §3 L1）
        rag_context = None
        rag_retrieval = None
        if rag_cm is not None:
            try:
                # 复用项目已有的 build_rag_context 工具函数
                from experiments.utils import build_rag_context as _build_rag
                rag_context, rag_retrieval = _build_rag(
                    query_code=code,
                    cm=rag_cm,
                    collection_name=rag_collection,
                    top_k=rag_top_k,
                )
            except Exception as e:
                print(f"  ⚠️ RAG 检索失败: {e}")
                rag_context = None

        # 构造消息
        user_prompt = build_user_prompt(
            code=code, language=language, filename=filename,
            rag_context=rag_context,
        )
        messages = [
            {"role": "system", "content": system_prompt or SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        # 推理
        t0 = time.time()
        elapsed = 0.0  # 初始化，避免异常时 UnboundLocalError
        verify_output = None  # P2-7: self-verify 第二轮输出
        verdict_corrected = False  # P2-7: 标记结论是否被修正
        verify_parse_fail = False  # P2-7: 校验轮 JSON 解析失败标记
        try:
            if _ollama_client is not None:
                raw_output = generate_response_ollama(
                    messages,
                    temperature=temperature,
                    num_ctx=ollama_num_ctx,
                    num_gpu=ollama_num_gpu,
                )
            else:
                raw_output = generate_response(
                    model, tokenizer, messages,
                    temperature=temperature, do_sample=do_sample,
                )
            verdict = parse_verdict(raw_output)
            predicted = normalize_has_vulnerability(verdict.get("has_vulnerability") if verdict else None)
            model_vulnerability_type = verdict.get("vulnerability_type", "") if verdict else ""
            model_fix_suggestion = verdict.get("fix_suggestion", "") if verdict else ""
            elapsed = time.time() - t0

            # P2-7: Self-Verification 后处理
            if self_verify and verdict is not None:
                verify_messages = messages + [
                    {"role": "assistant", "content": raw_output},
                    {"role": "user", "content": SELF_VERIFY_PROMPT},
                ]
                if _ollama_client is not None:
                    verify_output = generate_response_ollama(
                        verify_messages,
                        max_new_tokens=512,
                        temperature=temperature,
                        num_ctx=ollama_num_ctx,
                        num_gpu=ollama_num_gpu,
                    )
                else:
                    verify_output = generate_response(
                        model, tokenizer, verify_messages,
                        max_new_tokens=512,  # 校验只需输出 JSON，不需要长 CoT
                        temperature=temperature, do_sample=do_sample,
                    )
                corrected_verdict = parse_verdict(verify_output)
                if corrected_verdict is not None:
                    corrected_predicted = normalize_has_vulnerability(
                        corrected_verdict.get("has_vulnerability"))
                    # 如果校验后的结论与原始不同，说明模型自检发现了不一致
                    if corrected_predicted is not None and corrected_predicted != predicted:
                        verdict_corrected = True
                        predicted = corrected_predicted
                        model_vulnerability_type = corrected_verdict.get("vulnerability_type", "")
                    elif corrected_predicted is not None:
                        # 结论一致，但可能修正了 vulnerability_type
                        if corrected_verdict.get("vulnerability_type", "") != model_vulnerability_type:
                            model_vulnerability_type = corrected_verdict.get("vulnerability_type", "")
                            verdict_corrected = True
                else:
                    # 校验轮 JSON 解析失败，记录标记（保留原结论）
                    verify_parse_fail = True
        except Exception as e:
            elapsed = time.time() - t0
            raw_output = f"ERROR: {e}"
            verdict = None
            predicted = None
            model_vulnerability_type = ""
            model_fix_suggestion = ""

        # 判定
        if predicted is None:
            outcome = "parse_fail"
        elif predicted == expected_present:
            outcome = "TP" if expected_present else "TN"
        else:
            outcome = "FP" if not expected_present else "FN"

        result = {
            "file": filename,
            "language": language,
            "category": rec.get("category", ""),
            "difficulty": rec.get("difficulty", ""),
            "expected_present": expected_present,
            "model_has_vulnerability": predicted,  # 与 utils.compute_detection_metrics 默认字段对齐
            "predicted": predicted,  # 保留兼容字段
            "model_vulnerability_type": model_vulnerability_type,  # P0-2: 严格评估用
            "model_fix_suggestion": model_fix_suggestion,  # 修复可用性评估用
            "original_code": code,  # 修复可用性评估用（原始代码）
            "outcome": outcome,
            "expected_vulnerability": rec.get("expected_vulnerability", ""),
            "expected_cwe": rec.get("expected_cwe", ""),
            "raw_output": raw_output,
            "elapsed_seconds": round(elapsed, 2),  # 与 utils 期望字段对齐
            "elapsed": round(elapsed, 2),
            "run_seed": run_seed,  # 标记本次评估的种子（多种子聚合用）
            "verify_output": verify_output,  # P2-7: self-verify 第二轮输出
            "verdict_corrected": verdict_corrected,  # P2-7: 结论是否被修正
            "verify_parse_fail": verify_parse_fail,  # P2-7: 校验轮 JSON 解析失败
            "rag_retrieval": rag_retrieval,  # RAG 检索记录（每条知识的 cwe/distance/safe_pattern）
        }
        corrected_tag = " [corrected]" if verdict_corrected else ""
        results.append(result)
        print(f"[{i+1}/{len(manifest_records)}] {filename} → {outcome}{corrected_tag} ({elapsed:.1f}s)", flush=True)

    return results


def _run_batch_with_retry(model, tokenizer, grp, num_ctx, temperature, do_sample):
    """批量生成，OOM 时自动降级一半重试，避免整批被标记 parse_fail。

    返回 (raw_outputs, error)：
      - raw_outputs: 与 grp 等长的列表（每条 string 或 None）
      - error: 若整批最终失败（含降级到 1 仍失败），返回错误串；否则 None
    """
    cur_batch = len(grp)
    while cur_batch >= 1:
        try:
            msgs = [m for (m, *_ ) in grp[:cur_batch]]
            out = generate_batch_response(
                model, tokenizer, msgs,
                max_new_tokens=2048, num_ctx=num_ctx,
                temperature=temperature, do_sample=do_sample,
            )
            # 补足降级后缺失的位置为 None（调用方会按单条逐条处理）
            return out + [None] * (len(grp) - cur_batch), None
        except Exception as e:
            low = str(e).lower()
            oom = ("out of memory" in low
                   or ("cuda" in low and "allocate" in low)
                   or ("hip" in low and "allocate" in low))
            if oom and cur_batch > 1:
                new_batch = cur_batch // 2
                print(f"  ⚠️ batch={cur_batch} OOM，降级为 batch={new_batch} 重试", flush=True)
                torch.cuda.empty_cache()
                cur_batch = new_batch
                continue
            # 非 OOM 或已降到 1 仍失败：整批失败
            return [None] * len(grp), str(e)
    return [None] * len(grp), "unknown batch error"


def evaluate_batched(model, tokenizer, manifest_records,
                     temperature=0.0, do_sample=False, run_seed=42,
                     samples_dir=None, batch=4, num_ctx=8192,
                     system_prompt=None):
    """批量评估（HF 后端专用）—— 与 evaluate() 输出结构完全一致，仅推理走 batch。

    将样本按 batch 分组，组内并行生成（generate_batch_response），贪心解码
    结果与单条逐条算逐 token 一致，仅提速不降准确率。不支持 RAG / self-verify
    （调用方已在 main() 拦截）。
    """
    if do_sample and run_seed is not None:
        torch.manual_seed(run_seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(run_seed)

    results = []
    code_samples_dir = samples_dir if samples_dir is not None else SAMPLES_DIR
    total = len(manifest_records)
    # 先构造全部样本的 (消息, 元数据)，再分批推理
    items = []
    for rec in manifest_records:
        filename = rec["file"]
        language = rec["language"]
        code = read_sample_code(code_samples_dir, filename)
        if code is None:
            print(f"跳过 {filename}（代码不存在）")
            continue
        if "crossfile" in filename and filename.endswith("_sink.py"):
            input_file = filename.replace("_sink.py", "_input.py")
            input_code = read_sample_code(code_samples_dir, input_file)
            if input_code:
                code = f"# 相关代码上下文（同项目另一文件）\n{input_code}\n\n# 待分析的目标代码\n{code}"
        user_prompt = build_user_prompt(code=code, language=language, filename=filename)
        messages = [
            {"role": "system", "content": system_prompt or SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]
        items.append((messages, rec, filename, language, code))

    total = len(items)
    idx = 0
    while idx < total:
        grp = items[idx:idx + batch]
        t0 = time.time()
        raw_outputs, batch_error = _run_batch_with_retry(
            model, tokenizer, grp, num_ctx, temperature, do_sample,
        )

        for (messages, rec, filename, language, code), raw_output in zip(grp, raw_outputs):
            expected_present = rec["expected_present"]
            elapsed = time.time() - t0
            if raw_output is None:
                raw_output = f"ERROR: {batch_error}"
                predicted = None
                model_vulnerability_type = ""
                model_fix_suggestion = ""
            else:
                verdict = parse_verdict(raw_output)
                predicted = normalize_has_vulnerability(verdict.get("has_vulnerability") if verdict else None)
                model_vulnerability_type = verdict.get("vulnerability_type", "") if verdict else ""
                model_fix_suggestion = verdict.get("fix_suggestion", "") if verdict else ""

            if predicted is None:
                outcome = "parse_fail"
            elif predicted == expected_present:
                outcome = "TP" if expected_present else "TN"
            else:
                outcome = "FP" if not expected_present else "FN"

            result = {
                "file": filename,
                "language": language,
                "category": rec.get("category", ""),
                "difficulty": rec.get("difficulty", ""),
                "expected_present": expected_present,
                "model_has_vulnerability": predicted,
                "predicted": predicted,
                "model_vulnerability_type": model_vulnerability_type,
                "model_fix_suggestion": model_fix_suggestion,
                "original_code": code,
                "outcome": outcome,
                "expected_vulnerability": rec.get("expected_vulnerability", ""),
                "expected_cwe": rec.get("expected_cwe", ""),
                "raw_output": raw_output,
                "elapsed_seconds": round(elapsed, 2),
                "elapsed": round(elapsed, 2),
                "run_seed": run_seed,
                "verify_output": None,
                "verdict_corrected": False,
                "verify_parse_fail": False,
                "rag_retrieval": None,
            }
            results.append(result)
            print(f"[{len(results)}/{total}] {filename} → {outcome} ({elapsed:.1f}s)", flush=True)
        idx += batch

    return results


def aggregate_multiseed(all_runs: list[list[dict]]) -> dict:
    """聚合多种子评估结果，返回每个种子的单次指标 + 总体均值±标准差。

    all_runs: 每个 run 是一次完整 evaluate() 的结果列表。
    返回:
        {
            "per_seed": [{seed, metrics}, ...],
            "mean": {recall, accuracy, fpr},
            "std":  {recall, accuracy, fpr},
        }
    """
    per_seed = []
    recall_list, acc_list, fpr_list = [], [], []
    for run_results in all_runs:
        m = compute_detection_metrics(run_results)
        seed = run_results[0].get("run_seed", 0) if run_results else 0
        per_seed.append({"seed": seed, "metrics": m})
        if m["recall"] is not None:
            recall_list.append(m["recall"])
        if m["accuracy"] is not None:
            acc_list.append(m["accuracy"])
        if m["false_positive_rate"] is not None:
            fpr_list.append(m["false_positive_rate"])

    def stats(vals):
        if not vals:
            return None
        if len(vals) == 1:
            return {"mean": round(vals[0], 4), "std": 0.0}
        return {"mean": round(statistics.mean(vals), 4),
                "std": round(statistics.stdev(vals), 4)}

    # 构造 mean_metrics：rate 字段取多种子均值，count 字段取 run1 的值（保持整数口径）
    base_metrics = per_seed[0]["metrics"] if per_seed else {}
    mean_metrics = dict(base_metrics)  # 以 run1 为基底
    if recall_list:
        mean_metrics["recall"] = round(statistics.mean(recall_list), 4)
    if acc_list:
        mean_metrics["accuracy"] = round(statistics.mean(acc_list), 4)
    if fpr_list:
        mean_metrics["false_positive_rate"] = round(statistics.mean(fpr_list), 4)
    # 多种子模式下 count 字段不代表整体，置 None 避免与 rate 均值矛盾
    for _k in ("tp", "tn", "fp", "fn", "vuln_total", "safe_total", "valid"):
        if _k in mean_metrics:
            mean_metrics[_k] = None
    mean_metrics["multiseed"] = True

    return {
        "per_seed": per_seed,
        "mean_recall": stats(recall_list),
        "mean_accuracy": stats(acc_list),
        "mean_fpr": stats(fpr_list),
        "mean_metrics": mean_metrics,
    }


def main():
    parser = argparse.ArgumentParser(description="评估微调前后模型")
    parser.add_argument("--mode", choices=["baseline", "finetuned"], required=True)
    parser.add_argument("--adapter-path", type=str, default=None,
                        help="LoRA adapter 路径（finetuned 模式必填，与 --checkpoint 二选一）")
    parser.add_argument("--checkpoint", type=str, default=None,
                        help="checkpoint 简写：checkpoint-36 / checkpoint-45 / final（自动解析路径）")
    parser.add_argument("--quantize-4bit", action="store_true", default=True,
                        help="用 4bit 量化加载（默认启用，7B 需要；--no-4bit 禁用）")
    parser.add_argument("--no-4bit", action="store_false", dest="quantize_4bit",
                        help="禁用 4bit 量化，用 fp16（3B 模型可用）")
    parser.add_argument("--no-merge", action="store_true",
                        help="不合并 LoRA，运行时叠加（保留 adapter FP16 精度最大，推理更慢）")
    parser.add_argument("--model-id", type=str, default=MODEL_ID,
                        help=f"基座模型 ID（默认 {MODEL_ID}）")
    parser.add_argument("--limit", type=int, default=0, help="只评估前 N 个样本（0=全部）")
    parser.add_argument("--start-index", type=int, default=0,
                        help="从第 N 个样本开始评估（0=从头；>0 用于断点续跑，跳过已评估样本）")
    parser.add_argument("--only-files", type=str, default=None,
                        help="只评估指定文件名（逗号分隔，如 a.py,b.py；默认评估全部）用于 FN 冒烟验证")
    parser.add_argument("--manifest-path", type=str, default=None,
                        help="指定测试集 manifest 路径（默认 exp_04_hard_samples，可改为 CVE-fix）")
    parser.add_argument("--samples-dir", type=str, default=None,
                        help="指定代码样本目录（默认与 manifest 同目录）")
    # P0 改造：确定性解码 + 多种子
    parser.add_argument("--temperature", type=float, default=0.0,
                        help="采样温度（默认 0.0 确定性贪心解码）")
    parser.add_argument("--do-sample", action="store_true",
                        help="启用采样（默认 False 确定性；启用时需 temperature>0）")
    parser.add_argument("--seeds", type=int, default=1,
                        help="跑 N 个种子取均值±标准差（默认 1；>1 时自动启用 do_sample）")
    # P2-7: Self-Verification 后处理
    parser.add_argument("--self-verify", action="store_true",
                        help="启用 Self-Verification 后处理：首轮生成后追加一轮校验，"
                             "让模型自检 CoT→JSON 一致性（增加 ~15s/样本，能检测结论漂移）")
    # v9max prompt 对照：选择 system prompt 变体（默认 combined=最优，见 v9max 3 变体对照）
    parser.add_argument("--variant", choices=list(EVAL_SYSTEM_VARIANTS), default="combined",
                        help=f"评估用 system prompt 变体（默认 combined，v9max 最优）。候选: {EVAL_SYSTEM_VARIANTS}。"
                             f"base=BASE_PROMPT(训练对齐基线)，combined=白名单+few-shot+CoT(实证最优)，"
                             f"anti_fp_cot=v9max 专用减误报 CoT。")
    # Ollama 后端
    parser.add_argument("--ollama-model", type=str, default=None,
                        help="用 Ollama 后端评估（如 qwen3-coder:30b），跳过 HF 模型加载")
    parser.add_argument("--num-gpu", type=int, default=None,
                        help="Ollama GPU offload 层数（大模型 20b+ 需部分 offload；None=自动）")
    parser.add_argument("--num-ctx", type=int, default=16384,
                        help="Ollama 上下文窗口 token 数（默认 16384）")
    # RAG 检索增强（参考 docs/方法.md §3 L1）
    parser.add_argument("--rag", action="store_true",
                        help="启用 RAG 检索：从 vulnerability_knowledge 知识库检索 Top-3 相关条目注入 prompt。"
                             "解决 Phase 1 发现的 CWE 错标问题（33/87 样本判对方向但 CWE 标错）")
    parser.add_argument("--rag-top-k", type=int, default=3,
                        help="RAG 检索 Top-K 条知识（默认 3）")
    parser.add_argument("--rag-collection", type=str, default="vulnerability_knowledge",
                        help="Chroma 知识库 collection 名（默认 vulnerability_knowledge，72 条 CWE 规则）")
    # batch 推理（HF 后端专用，摊薄权重读取提升功耗/吞吐）
    parser.add_argument("--batch", type=int, default=1,
                        help="批量推理 batch size（默认 1=单条串行；>1 时 HF 后端按批生成，"
                             "贪心解码结果与单条完全一致，仅提速不降准确率。16G 显存实测安全值≈4）")
    parser.add_argument("--batch-num-ctx", type=int, default=8192,
                        help="batch 模式下上下文窗口 token 数（默认 8192，与 batch_probe 实测对齐；"
                             "num_ctx 越大单批可容纳样本越少，需相应调小 batch）")
    args = parser.parse_args()

    # 解析 adapter 路径
    adapter_path = resolve_adapter_path(args.checkpoint, args.adapter_path)
    if args.mode == "finetuned" and not adapter_path:
        print("错误：finetuned 模式需要 --adapter-path 或 --checkpoint")
        sys.exit(1)
    if args.mode == "finetuned" and not Path(adapter_path).exists():
        print(f"错误：adapter 路径不存在: {adapter_path}")
        sys.exit(1)

    # 多种子评估时强制启用采样（确定性解码下多种子无意义）
    do_sample = args.do_sample
    if args.seeds > 1:
        do_sample = True
        if args.temperature == 0.0:
            args.temperature = 0.1  # 多种子需要采样，默认 0.1
        print(f"多种子评估({args.seeds})：自动启用 do_sample, temperature={args.temperature}")

    # 检查 GPU（Ollama 后端不需要）
    use_ollama = args.ollama_model is not None
    if not use_ollama and not torch.cuda.is_available():
        print("错误：未检测到 GPU。请在真实终端运行（非 IDE 沙箱）。")
        sys.exit(1)

    # 加载测试集（支持自定义 manifest 路径，用于 CVE-fix held-out 测试集）
    manifest_path = Path(args.manifest_path) if args.manifest_path else MANIFEST_PATH
    samples_dir = Path(args.samples_dir) if args.samples_dir else None
    print(f"测试集 manifest: {manifest_path}")
    manifest, records = load_manifest(manifest_path)
    if args.start_index > 0:
        records = records[args.start_index:]
        print(f"断点续跑：跳过前 {args.start_index} 个样本，从 index={args.start_index} 开始")
    if args.limit > 0:
        records = records[:args.limit]
    if args.only_files:
        keep = {f.strip() for f in args.only_files.split(",") if f.strip()}
        records = [r for r in records if r.get("file") in keep]
        print(f"--only-files 过滤：仅评估 {len(records)} 段（{args.only_files}）")
    print(f"测试样本: {len(records)} 段")

    # 加载模型
    if use_ollama:
        global _ollama_client, _ollama_model_name
        from graduation_project.llm_client import OllamaClient
        _ollama_client = OllamaClient(model=args.ollama_model)
        _ollama_model_name = args.ollama_model  # 记录模型名，供 thinking mode 检测
        if not _ollama_client.check_connection():
            print(f"错误：无法连接 Ollama（localhost:11434），请先运行 ollama serve")
            sys.exit(1)
        is_qwen3 = "qwen3" in args.ollama_model.lower()
        print(f"Ollama 后端: {args.ollama_model} (num_gpu={args.num_gpu}, num_ctx={args.num_ctx})"
              f"{' [Qwen3: chat API + think:false]' if is_qwen3 else ''}")
        model, tokenizer = None, None
    else:
        model, tokenizer = load_model(args.mode, adapter_path, args.quantize_4bit, args.model_id,
                                      merge=not args.no_merge)

    # 多种子评估
    all_runs = []
    seed_list = [42 + i * 1000 for i in range(args.seeds)]  # 42, 1042, 2042 ...
    if args.self_verify:
        print("已启用 Self-Verification 后处理（每样本增加一轮校验）")

    # RAG 初始化
    rag_cm = None
    if args.rag:
        try:
            from graduation_project.chroma_manager import ChromaManager
            rag_cm = ChromaManager()
            # 验证 collection 存在
            col = rag_cm.client.get_collection(args.rag_collection)
            print(f"已启用 RAG 检索: collection={args.rag_collection}, total={col.count()}, top_k={args.rag_top_k}")
        except Exception as e:
            print(f"⚠️ RAG 初始化失败，降级为无 RAG 模式: {e}")
            rag_cm = None

    print(f"\n开始评估（mode={args.mode}, seeds={seed_list}, do_sample={do_sample}, temp={args.temperature}, self_verify={args.self_verify}, rag={rag_cm is not None}）...")
    # batch 推理仅适用于 HF 后端且未启用 RAG/self-verify（它们依赖逐样本二次交互）
    use_batch = (args.batch > 1 and not use_ollama and not args.self_verify and rag_cm is None)
    if args.batch > 1 and not use_batch:
        print(f"提示：--batch 仅适用于 HF 后端且未启用 RAG/self-verify，已回退单条串行(batch=1)")
    try:
        for run_idx, seed in enumerate(seed_list):
            print(f"\n===== Run {run_idx+1}/{args.seeds} (seed={seed}) =====")
            if use_batch:
                run_results = evaluate_batched(
                    model, tokenizer, records,
                    temperature=args.temperature, do_sample=do_sample, run_seed=seed,
                    samples_dir=samples_dir, batch=args.batch, num_ctx=args.batch_num_ctx,
                    system_prompt=get_eval_system_prompt(args.variant),
                )
            else:
                run_results = evaluate(
                    model, tokenizer, records,
                    temperature=args.temperature, do_sample=do_sample, run_seed=seed,
                    samples_dir=samples_dir,
                    self_verify=args.self_verify,
                    ollama_num_gpu=args.num_gpu,
                    ollama_num_ctx=args.num_ctx,
                    rag_cm=rag_cm,
                    rag_collection=args.rag_collection,
                    rag_top_k=args.rag_top_k,
                    system_prompt=get_eval_system_prompt(args.variant),
                )
            all_runs.append(run_results)

        # 用第一个 run 的结果作为"代表"保存（单种子时就是唯一结果）
        representative_results = all_runs[0]
        metrics = compute_detection_metrics(representative_results)
        print("\n=== 单次指标（run 1, seed={}）===".format(seed_list[0]))
        for k, v in metrics.items():
            print(f"  {k}: {v}")

        # P0-2: 严格指标（校验 vulnerability_type + CWE）
        strict_metrics = compute_strict_metrics(representative_results)
        print("\n=== 严格指标（has_vulnerability + CWE 匹配）===")
        print(f"  strict_tp: {strict_metrics['strict_tp']}  (loose TP={metrics['tp']})")
        print(f"  cwe_mismatch: {strict_metrics['cwe_mismatch']}  (判对方向但 CWE 标错)")
        print(f"  parse_fail_count: {strict_metrics['parse_fail_count']}  (漏洞样本中解析失败数)")
        print(f"  strict_recall: {strict_metrics['strict_recall']}  (loose recall={metrics['recall']})")
        print(f"  strict_recall_with_parse_fail: {strict_metrics['strict_recall_with_parse_fail']}  (含 parse_fail 的召回率)")
        print(f"  strict_accuracy: {strict_metrics['strict_accuracy']}  (loose accuracy={metrics['accuracy']})")
        print(f"  instance_recall_micro: {strict_metrics['instance_recall_micro']}  "
              f"(macro={strict_metrics['instance_recall_macro']}, 全覆盖率={strict_metrics['full_coverage_rate']}, "
              f"实例 {strict_metrics['instance_hits']}/{strict_metrics['instance_total']})")

        # 修复建议评估（主指标：给出建议 + 行号锚定）
        fix_verifier = FixVerifier(timeout=30)
        fix_metrics = compute_fix_metrics(representative_results, fix_verifier)
        print("\n=== 修复建议评估 ===")
        print(f"  应修复样本（漏洞且判True）: {fix_metrics['fix_applicable']}")
        print(f"  ★给出建议: {fix_metrics['fix_suggested']} "
              f"({fix_metrics['fix_suggested_rate']}) | 行号锚定合法: {fix_metrics['fix_anchored']} "
              f"({fix_metrics['fix_anchored_rate']})")
        if fix_metrics["fix_line_ref_invalid"]:
            print(f"  行号超出代码范围: {fix_metrics['fix_line_ref_invalid']}")
        print(f"  [辅助口径·旧代码块格式] 抽到代码块: {fix_metrics['fix_extracted']} | "
              f"语法通过: {fix_metrics['fix_syntax_ok']} | 修复可用: {fix_metrics['fix_usable']} "
              f"({fix_metrics['fix_usable_rate']})")
        if fix_metrics['fix_issues']:
            print(f"  问题计数: {fix_metrics['fix_issues']}")

        # 多种子聚合
        multi_summary = None
        if args.seeds > 1:
            multi_summary = aggregate_multiseed(all_runs)
            print("\n=== 多种子聚合（{} seeds）===".format(args.seeds))
            for ps in multi_summary["per_seed"]:
                m = ps["metrics"]
                print(f"  seed={ps['seed']}: recall={m['recall']}, accuracy={m['accuracy']}, fpr={m['false_positive_rate']}")
            print(f"  recall   均值±std: {multi_summary['mean_recall']}")
            print(f"  accuracy 均值±std: {multi_summary['mean_accuracy']}")
            print(f"  fpr      均值±std: {multi_summary['mean_fpr']}")

        # 保存结果
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        tag = args.mode
        if args.ollama_model:
            tag = f"ollama_{args.ollama_model.replace(':', '_')}"
        elif args.mode == "finetuned":
            ck_tag = args.checkpoint or "custom"
            tag = f"finetuned_{ck_tag}"
        if args.variant != "base":
            tag += f".{args.variant}"
        if args.seeds > 1:
            tag += f"_seeds{args.seeds}"
        out_file = OUTPUT_DIR / f"exp_06_eval.{tag}.{ts}.json"
        output_data = {
            "experiment": "exp_06_finetune_eval",
            "model": f"{args.ollama_model or args.model_id}-{args.mode}",
            "checkpoint": args.checkpoint or (args.adapter_path or ""),
            "ollama_model": args.ollama_model,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "decoding": {"temperature": args.temperature, "do_sample": do_sample, "seeds": seed_list},
            "samples": representative_results,
            "all_runs": all_runs if args.seeds > 1 else None,
            "metrics": metrics,  # 来自 run1 (seed=42)
            "strict_metrics": strict_metrics,
            "fix_metrics": fix_metrics,  # 修复建议评估
            "multiseed_summary": multi_summary,
        }
        # 多种子场景：额外保存 metrics_mean 字段（多种子均值），供下游对比脚本使用
        if multi_summary:
            output_data["metrics_mean"] = multi_summary.get("mean_metrics", {})
        save_results_json(out_file, output_data)
        print(f"\n结果已保存: {out_file}")
    finally:
        # 卸载 Ollama 模型，释放 GPU 显存
        if _ollama_client is not None:
            print("正在卸载 Ollama 模型...")
            _ollama_client.unload_model()
            print("Ollama 模型已卸载，GPU 显存已释放")
        elif model is not None:
            # HF 模型显存释放
            del model
            torch.cuda.empty_cache()
            print("HF 模型已释放，GPU 显存已清空")

    # 打印混淆矩阵（基于第一个 run）
    tp = sum(1 for r in representative_results if r["outcome"] == "TP")
    fp = sum(1 for r in representative_results if r["outcome"] == "FP")
    fn = sum(1 for r in representative_results if r["outcome"] == "FN")
    tn = sum(1 for r in representative_results if r["outcome"] == "TN")
    pf = sum(1 for r in representative_results if r["outcome"] == "parse_fail")
    print(f"\n混淆矩阵(run1): TP={tp} FP={fp} FN={fn} TN={tn} (parse_fail={pf})")
    print(f"严格混淆矩阵:   strict_TP={strict_metrics['strict_tp']} strict_FN={strict_metrics['strict_fn']} "
          f"(CWE 不匹配={strict_metrics['cwe_mismatch']})")

    # P2-7: Self-Verification 修正统计
    if args.self_verify:
        corrected_count = sum(1 for r in representative_results if r.get("verdict_corrected"))
        print(f"\nSelf-Verification 修正: {corrected_count}/{len(representative_results)} 个样本的结论被修正")


if __name__ == "__main__":
    main()
