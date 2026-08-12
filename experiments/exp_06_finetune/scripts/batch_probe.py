"""batch 上限实测脚本 —— 用真实评估负载（训练 prompt + 87 段代码 + max_new=2048）测最大 batch。

用法（AI 环境，ROCm GPU）：
    HIP_VISIBLE_DEVICES=0 CUDA_VISIBLE_DEVICES=0 python batch_probe.py

从 batch=1 起逐步翻倍，记录每档显存峰值，直到 OOM；输出建议 batch。
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")
os.environ.setdefault("HIP_VISIBLE_DEVICES", "0")

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

from graduation_project.prompts import V3_PROMPT, build_user_prompt
from experiments.utils import load_manifest, read_sample_code

BASE = PROJECT_ROOT / "models/transformers/Qwen3-8B"
ADAPTER = PROJECT_ROOT / "models/adapter"
MANIFEST = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples/manifest.json"
SAMPLES = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples"
MAX_NEW = 2048
NUM_CTX = 8192


def load():
    tokenizer = AutoTokenizer.from_pretrained(BASE, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    bnb = BitsAndBytesConfig(
        load_in_4bit=True, bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16, bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        BASE, quantization_config=bnb, device_map={"": 0},
        trust_remote_code=True, torch_dtype=torch.float16,
        attn_implementation="sdpa",
    )
    model = PeftModel.from_pretrained(model, ADAPTER)  # 不合并，与评估一致
    model.eval()
    return model, tokenizer


def build_prompts(n: int) -> list[str]:
    """取前 n 段真实代码，构造与评估一致的 user prompt（含跨文件拼接）。"""
    manifest, records = load_manifest(MANIFEST)
    prompts = []
    for rec in records[:n]:
        filename = rec["file"]
        code = read_sample_code(SAMPLES, filename)
        if code is None:
            continue
        if "crossfile" in filename and filename.endswith("_sink.py"):
            input_file = filename.replace("_sink.py", "_input.py")
            input_code = read_sample_code(SAMPLES, input_file)
            if input_code:
                code = f"# 相关代码上下文（同项目另一文件）\n{input_code}\n\n# 待分析的目标代码\n{code}"
        prompts.append(build_user_prompt(code=code, language=rec["language"], filename=filename))
    return prompts


def main():
    model, tokenizer = load()
    prompts = build_prompts(64)
    print(f"已构造 {len(prompts)} 条真实评估 prompt")

    # 估算每条 prompt 的 token 数（决定实际 batch 上限受 prefill 还是 KV 限制）
    lens = [len(tokenizer(p, add_special_tokens=False)["input_ids"]) for p in prompts]
    print(f"prompt token 分布: min={min(lens)} max={max(lens)} avg={sum(lens)//len(lens)}")

    results = []
    batch = 1
    while batch <= len(prompts):
        torch.cuda.empty_cache()
        torch.cuda.reset_peak_memory_stats()
        run = prompts[:batch]
        try:
            t0 = time.time()
            # 左 padding 批量编码
            old_side = tokenizer.padding_side
            tokenizer.padding_side = "left"
            enc = tokenizer(
                ["<|im_start|>system\n" + V3_PROMPT + "<|im_end|>\n<|im_start|>user\n" + p + "<|im_end|>\n<|im_start|>assistant\n" for p in run],
                return_tensors="pt", padding=True, truncation=True,
                max_length=NUM_CTX - MAX_NEW,
            )
            tokenizer.padding_side = old_side
            enc = {k: v.to(model.device) for k, v in enc.items()}
            with torch.no_grad():
                # 只测 prefill+少量 decode 的显存峰值；用 max_new=1 快速出峰值
                model.generate(**enc, max_new_tokens=1, do_sample=False,
                               pad_token_id=tokenizer.pad_token_id)
            peak = torch.cuda.max_memory_allocated() / 1e9
            dt = time.time() - t0
            results.append((batch, round(peak, 2), round(dt, 2)))
            print(f"batch={batch:2d}  显存峰值={peak:5.2f}GB  prefill耗时={dt:5.2f}s  ✓")
            batch *= 2
        except Exception as e:
            msg = str(e)
            low = msg.lower()
            oom = "out of memory" in low or "cuda" in low and "allocate" in low or "hip" in low and "allocate" in low
            for b, p, d in results:
                print(f"  batch={b:2d}: peak={p}GB")
            print(f"\nbatch={batch} 失败: {'OOM' if oom else '其他错误'}: {msg}")
            print(f"建议最大 batch ≈ {results[-1][0] if results else 1}")
            # 释放
            del enc
            torch.cuda.empty_cache()
            break

    # 输出汇总
    print("\n=== batch 上限汇总 ===")
    for b, p, d in results:
        print(f"  batch={b:2d}  peak={p:5.2f}GB  prefill={d}s")
    if results:
        best = results[-1][0]
        print(f"16G 显存下安全 batch ≈ {best}（峰值 {results[-1][1]}GB）")


if __name__ == "__main__":
    main()