"""LoRA 微调脚本 —— 云端版（A100/H100 80GB，bf16 原生训练，无需 4bit 量化）。

与本地版 train_qlora.py 的区别：
  - 去掉 ROCm 特性（HIP bug 规避、fp32 提升、eager attention 等）
  - 使用 bf16 原生混合精度（A100+ 支持，比 fp16 更稳，无 GradScaler，不会 NaN）
  - 不用 bitsandbytes 4bit 量化（本地 16GB 才需要；云端 80GB 直接跑 bf16）
  - max_seq_length 默认 12288：与 alpha06 构建脚本 TRAIN_MAX_LEN 对齐（全量样本实测 max≈10336 tokens），无需截断
  - batch_size 默认 8 + grad_accum 1 = 有效 batch 8（80GB 显存宽裕，单卡直放）

方法：LoRA（默认 r=8, alpha=16, rsLoRA 默认开启）+ 梯度检查点
数据：final_train_chatml_alpha05.jsonl（与脚本同目录，7972 条，α0.5 最终训练集：
      统一 ALPHA05_PROMPT(1467字符) + 泄露门禁 + 全量审计 PASS；
      含盲区/痛点/归因/真实CVE 补充。triage 独立在 supplement_alpha05_triage.jsonl，
      配 triage_default prompt，供裁决任务单独微调，勿混入主扫描训练）

云端用法（已装 torch/transformers/trl/peft/datasets）：
  python train_qlora_cloud.py
  python train_qlora_cloud.py --subset 50 --max-steps 5   # 快速验证
  python train_qlora_cloud.py --data-file /path/to/other.jsonl
  python train_qlora_cloud.py --recycle-dev              # 阶段1看 eval loss 曲线 + 选 best，
                                                         # 阶段2把 dev 回收进全量续训（final training on full data）

说明：
  - 脚本和数据文件放在同一目录即可，无需特定文件夹结构
  - bf16 原生训练，数值稳定，不会出现本地 4bit 的 NaN/梯度爆炸
  - max_grad_norm=1.0 + rsLoRA + warmup + cosine 多重防护，梯度爆炸风险极低
  - load_best_model_at_end=True 自动选 dev loss 最低的 checkpoint
  - 默认禁用 early stopping（和本地成功配方一致，让 cosine 走完）
  - 数据太大可选 --subset 限制条数做快速验证
  - assistant_only_loss=True 需要 chat_template 包含 {% generation %} 标签，
    Qwen3 默认模板不含此标签，脚本已自动注入修改后的模板
  - --recycle-dev 注意：回收后 dev 的 eval_loss 不再代表泛化（模型已见过），
    最终泛化指标必须用独立测试集（如 testset_cve_fix）评估
"""

import argparse
import json
import os
import random
import sys
from pathlib import Path

# ── HuggingFace 镜像（国内必设；必须在 transformers/datasets/trl import 前生效）──
# 用 setdefault：若你已手动 export 了别的镜像（或想用真 HF），不会被覆盖
os.environ.setdefault("HF_ENDPOINT", "https://hf-mirror.com")

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
)
from trl import SFTConfig, SFTTrainer

# ── 路径：基于脚本自身所在目录，云端随意放，不依赖项目目录结构 ──
SCRIPT_DIR = Path(__file__).resolve().parent
DATA_FILE = SCRIPT_DIR / "final_train_chatml_alpha05.jsonl"
OUTPUT_DIR = SCRIPT_DIR / "outputs"
LOG_DIR = SCRIPT_DIR / "logs"
MODEL_ID = "Qwen/Qwen3-8B"

# ── Qwen3 修改版 chat_template：在 assistant 部分包裹 {% generation %} 标签 ──
# 原版 Qwen3 模板不含此标签，导致 assistant_only_loss=True 时 loss mask 全部错误。
# 参考: https://huggingface.co/docs/trl/en/sft_trainer#train-on-assistant-messages-only
# 参考: https://github.com/huggingface/transformers/issues/34172
QWEN3_CHAT_TEMPLATE_WITH_GENERATION = """{%- if tools %}
  {{- '<|im_start|>system\\n' }}
  {%- if messages[0]['role'] == 'system' %}
    {{- messages[0]['content'] + '\\n\\n' }}
  {%- else %}
    {{- 'You are Qwen, created by Alibaba Cloud. You are a helpful assistant.' }}
  {%- endif %}
  {{- "# Tools\\n\\nYou may call one or more functions to assist with the user query.\\n\\nYou are provided with function signatures within <tools></tools> XML tags:\\n<tools>" }}
  {%- for tool in tools %}
    {{- "\\n" }}
    {{- tool | tojson }}
  {%- endfor %}
  {{- "\\n</tools>\\n\\nFor each function call, return a json object with function name and arguments within <tool_call></tool_call> XML tags:\\n<tool_call>\\n{\\"name\\": <function-name>, \\"arguments\\": <args-json-object>}\\n</tool_call><|im_end|>\\n" }}
{%- else %}
  {%- if messages[0]['role'] == 'system' %}
    {{- '<|im_start|>system\\n' + messages[0]['content'] + '<|im_end|>\\n' }}
  {%- endif %}
{%- endif %}
{%- for message in messages %}
  {%- if (message.role == "user") or (message.role == "system" and not loop.first) %}
    {{- '<|im_start|>' + message.role + '\\n' + message.content + '<|im_end|>' + '\\n' }}
  {%- elif message.role == "assistant" %}
    {%- set content = message.content %}
    {%- set reasoning_content = '' %}
    {%- if message.reasoning_content is defined and message.reasoning_content is not none %}
      {%- set reasoning_content = message.reasoning_content %}
    {%- else %}
      {%- if '</think>' in message.content %}
        {%- set content = message.content.split('</think>')[-1].lstrip('\\n') %}
        {%- set reasoning_content = message.content.split('</think>')[0].rstrip('\\n').split('<think>')[-1].lstrip('\\n') %}
      {%- endif %}
    {%- endif %}
    {% generation %}
      {{- '<|im_start|>' + message.role + '\\n' + content }}
      {%- if message.tool_calls %}
        {%- for tool_call in message.tool_calls %}
          {%- if tool_call.function %}
            {%- set tool_call = tool_call.function %}
          {%- endif %}
          {{- '\\n<tool_call>\\n{\\"name\\": \\"' }}
          {{- tool_call.name }}
          {{- '\\", \\"arguments\\": ' }}
          {%- if tool_call.arguments is string %}
            {{- tool_call.arguments }}
          {%- else %}
            {{- tool_call.arguments | tojson }}
          {%- endif %}
          {{- '}\\n</tool_call>' }}
        {%- endfor %}
      {%- endif %}
      {{- '<|im_end|>\\n' }}
    {% endgeneration %}
  {%- elif message.role == "tool" %}
    {%- if loop.first or (messages[loop.index0 - 1].role != "tool") %}
      {{- '<|im_start|>user' }}
    {%- endif %}
    {{- '\\n<tool_response>\\n' }}
    {{- message.content }}
    {{- '\\n</tool_response>' }}
    {%- if loop.last or (messages[loop.index0 + 1].role != "tool") %}
      {{- '<|im_end|>\\n' }}
    {%- endif %}
  {%- endif %}
{%- endfor %}
{%- if add_generation_prompt %}
  {{- '<|im_start|>assistant\\n' }}
  {%- if enable_thinking is defined and enable_thinking is false %}
    {{- '<think>\\n\\n</think>\\n\\n' }}
  {%- endif %}
{%- endif %}"""


def load_chatml_dataset(path: Path, subset: int | None = None) -> Dataset:
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    if subset is not None:
        records = records[:subset]
    print(f"加载 {len(records)} 条样本")
    return Dataset.from_list(records)


def split_train_dev(dataset: Dataset, dev_ratio: float, seed: int = 42):
    n = len(dataset)
    n_dev = max(1, int(n * dev_ratio))
    rng = random.Random(seed)
    indices = list(range(n))
    rng.shuffle(indices)
    dev_indices = set(indices[:n_dev])
    train_records = [dataset[i] for i in range(n) if i not in dev_indices]
    dev_records = [dataset[i] for i in range(n) if i in dev_indices]
    print(f"分拆：train={len(train_records)} dev={len(dev_records)}（dev_ratio={dev_ratio}）")
    return Dataset.from_list(train_records), Dataset.from_list(dev_records)


def main():
    parser = argparse.ArgumentParser(description="云端 LoRA 微调 Qwen3-8B（bf16 原生）")
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=8, help="每设备 batch size（云端 80GB，默认 8，显存宽裕）")
    parser.add_argument("--grad-accum", type=int, default=1, help="梯度累积（默认 1，有效 batch=8）")
    parser.add_argument("--lr", type=float, default=1e-4)
    parser.add_argument("--lora-r", type=int, default=8)
    parser.add_argument("--lora-alpha", type=int, default=16)
    parser.add_argument("--lora-dropout", type=float, default=0.1)
    parser.add_argument("--no-rslora", action="store_true",
                        help="禁用 rsLoRA（默认开启：Phase1 sweep 表明 lr=1e-4 + rsLoRA(r=8) 最优）")
    parser.add_argument("--max-seq-length", type=int, default=12288,
                        help="默认 12288：与 build_alpha06_final_v2_1/v2_2 的 TRAIN_MAX_LEN 对齐"
                             "（alpha06 实测全量样本 max≈10336 tokens；旧默认 6144 会把 6144~10336 "
                             "的样本截断在 JSON 中段，恰好违反构建侧长度守门初衷）")
    parser.add_argument("--save-steps", type=int, default=200)
    parser.add_argument("--eval-steps", type=int, default=None)
    parser.add_argument("--logging-steps", type=int, default=5)
    parser.add_argument("--warmup-ratio", type=float, default=0.1,
                        help="默认 0.1(总步数 10%% 预热，避免开局梯度冲击)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--model-id", type=str, default=MODEL_ID)
    parser.add_argument("--data-file", type=str, default=None)
    parser.add_argument("--dev-ratio", type=float, default=0.15)
    parser.add_argument("--no-early-stopping", action="store_true")
    parser.add_argument("--early-stopping-patience", type=int, default=2)
    parser.add_argument("--no-load-best", action="store_true")
    parser.add_argument("--output-suffix", type=str, default="")
    parser.add_argument("--subset", type=int, default=None, help="只取前 N 条（快速验证用）")
    parser.add_argument("--max-steps", type=int, default=-1)
    parser.add_argument("--dtype", type=str, default="bf16", choices=["bf16", "fp16"],
                        help="混合精度（A100+ 用 bf16；旧卡无 bf16 用 fp16）")
    # 第 2 阶段：回收 dev 集（final training on full data）
    parser.add_argument("--recycle-dev", action="store_true",
                        help="阶段1（分 dev 看 eval loss 曲线 + 选 best）完成后，把 dev 集回收进训练，"
                             "用全量数据续训最终模型。标准做法：train/dev 只用于模型选择，"
                             "最终模型在全量数据上训练，避免宝贵的 dev 数据浪费。")
    parser.add_argument("--recycle-epochs", type=float, default=1.0,
                        help="回收阶段在全量数据上续训的 epochs（默认 1.0 = 全量过一遍；"
                             "数据少时建议 1.0，过久易过拟合）")
    args = parser.parse_args()

    data_file = Path(args.data_file) if args.data_file else DATA_FILE
    use_bf16 = args.dtype == "bf16"
    use_rslora = not args.no_rslora

    if not torch.cuda.is_available():
        print("错误：未检测到 GPU")
        sys.exit(1)
    n_gpus = torch.cuda.device_count()
    print(f"检测到 GPU 数量: {n_gpus}")
    print(f"GPU: {torch.cuda.get_device_name(0)}")
    print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB")

    print(f"训练数据: {data_file}")
    full_dataset = load_chatml_dataset(data_file, args.subset)
    # train/dev 划分种子跟随 --seed（原先硬编码 42，改 seed 只影响训练采样
    # 不影响划分，复现实验时划分会悄悄漂移）
    train_dataset, dev_dataset = split_train_dev(full_dataset, args.dev_ratio, seed=args.seed)

    print(f"加载 tokenizer: {args.model_id}")
    tokenizer = AutoTokenizer.from_pretrained(args.model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    if "qwen3" in args.model_id.lower():
        # 1) 注入带 {% generation %} 标签的 chat_template，使 assistant_only_loss 正确工作
        tokenizer.chat_template = QWEN3_CHAT_TEMPLATE_WITH_GENERATION
        print("Qwen3: 已注入带 {% generation %} 标签的 chat_template（assistant_only_loss 必需）")

        # 2) patch apply_chat_template 默认 enable_thinking=False
        _orig_apply = tokenizer.apply_chat_template
        def _patched_apply(*args, **kwargs):
            kwargs.setdefault("enable_thinking", False)
            return _orig_apply(*args, **kwargs)
        tokenizer.apply_chat_template = _patched_apply
        print("Qwen3: 已 patch apply_chat_template 默认 enable_thinking=False")

    print(f"加载模型: {args.model_id} ({args.dtype} 原生，无量化)")
    model = AutoModelForCausalLM.from_pretrained(
        args.model_id,
        torch_dtype=torch.bfloat16 if use_bf16 else torch.float16,
        device_map="auto",
        trust_remote_code=True,
    )
    model.config.use_cache = False
    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()

    lora_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        use_rslora=use_rslora,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
    )
    peft_tags = []
    if use_rslora:
        peft_tags.append("rslora")
    peft_tag = ("_" + "_".join(peft_tags)) if peft_tags else ""
    print(f"LoRA: r={args.lora_r} alpha={args.lora_alpha} dropout={args.lora_dropout} rslora={use_rslora}")
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    output_dir = OUTPUT_DIR / f"lora_r{args.lora_r}_a{args.lora_alpha}_e{args.epochs}_lr{args.lr:g}_s{args.seed}{peft_tag}{args.output_suffix}"
    output_dir.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    short_run = args.max_steps > 0

    sft_config = SFTConfig(
        output_dir=str(output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=args.warmup_ratio,
        max_grad_norm=1.0,
        logging_steps=args.logging_steps,
        save_strategy="no" if short_run else "steps",
        save_steps=args.save_steps,
        save_total_limit=10,
        max_steps=args.max_steps,
        bf16=use_bf16,
        fp16=not use_bf16,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        optim="adamw_torch",
        weight_decay=0.01,
        seed=args.seed,
        max_length=args.max_seq_length,
        packing=False,
        dataset_text_field=None,
        assistant_only_loss=True,  # 只对 assistant 部分计算 loss（依赖 chat_template 的 {% generation %} 标签）
        report_to="none",
        logging_dir=str(LOG_DIR),
        eval_strategy="no" if short_run else "steps",
        eval_steps=args.eval_steps if args.eval_steps else args.save_steps,
        load_best_model_at_end=(not short_run) and (not args.no_load_best),
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        per_device_eval_batch_size=args.batch_size,
        dataloader_pin_memory=False,
    )

    trainer = SFTTrainer(
        model=model,
        args=sft_config,
        train_dataset=train_dataset,
        eval_dataset=dev_dataset,
        processing_class=tokenizer,
    )

    print(f"\n开始训练: {args.epochs} epochs, lr={args.lr}, batch={args.batch_size}x{args.grad_accum}, seed={args.seed}")
    print(f"train={len(train_dataset)} dev={len(dev_dataset)}")
    print(f"输出目录: {output_dir}")
    train_result = trainer.train()

    if short_run:
        print(f"\n✅ 短跑模式完成（max_steps={args.max_steps}），不保存模型")
        for k, v in train_result.metrics.items():
            print(f"   {k}: {v}")
        return

    best_dir = output_dir / "best"
    trainer.save_model(str(best_dir))
    trainer.save_state()
    if args.no_load_best:
        print(f"\n（--no-load-best：model 为 final 状态）LoRA adapter 已保存到: {best_dir}")
    else:
        print(f"\nBest LoRA adapter（按 dev_loss 选）已保存到: {best_dir}")

    # ---- 第 2 阶段：回收 dev 集（--recycle-dev）----
    # 方法论：train/dev 划分只用于「模型选择」（看 eval loss 曲线、early stopping、选 best epoch），
    # 不是用来报告最终泛化的。确认曲线健康后把 dev 并回训练、用全量数据续训最终模型，
    # 是标准的 "final training on full data"，避免宝贵的 dev 数据浪费。
    # ⚠️ 边界：回收后 dev 的 eval_loss 不再代表泛化（模型已见过它）；最终指标必须来自
    #    从未进过训练集的独立测试集（如 testset_cve_fix）。
    if args.recycle_dev and not short_run:
        eff_batch = args.batch_size * args.grad_accum
        full_len = len(full_dataset)
        recycle_steps = max(1, int(round(args.recycle_epochs * full_len / eff_batch)))
        recycled_dir = output_dir / "recycled"
        print(f"\n[阶段2/回收dev] 把 {len(dev_dataset)} 条 dev 并回训练，全量 {full_len} 条续训 "
              f"{args.recycle_epochs} epoch ≈ {recycle_steps} 步（从阶段1 best 继续，关闭 eval）")
        sft_config2 = SFTConfig(
            output_dir=str(recycled_dir),
            num_train_epochs=args.recycle_epochs,
            per_device_train_batch_size=args.batch_size,
            gradient_accumulation_steps=args.grad_accum,
            learning_rate=args.lr,
            lr_scheduler_type="cosine",
            warmup_ratio=args.warmup_ratio,
            max_grad_norm=1.0,
            logging_steps=args.logging_steps,
            save_strategy="steps",
            save_steps=args.save_steps,
            save_total_limit=2,          # 回收阶段只留最后两个 checkpoint
            bf16=use_bf16,
            fp16=not use_bf16,
            gradient_checkpointing=True,
            gradient_checkpointing_kwargs={"use_reentrant": False},
            optim="adamw_torch",
            weight_decay=0.01,
            seed=args.seed,
            max_length=args.max_seq_length,
            packing=False,
            dataset_text_field=None,
            assistant_only_loss=True,
            report_to="none",
            logging_dir=str(LOG_DIR),
            eval_strategy="no",          # 曲线已在阶段1确认，回收阶段不再评估
            dataloader_pin_memory=False,
        )
        # model 在阶段1结束时已回滚到 best（load_best_model_at_end=True）
        trainer2 = SFTTrainer(
            model=model,
            args=sft_config2,
            train_dataset=full_dataset,  # 全量（train + dev）
            processing_class=tokenizer,
        )
        trainer2.train()
        trainer2.save_model(str(recycled_dir))
        trainer2.save_state()
        print(f"[阶段2/回收dev] 全量续训完成，最终模型已保存到: {recycled_dir}")
        print(f"   ⚠️ 此模型已见过 dev 数据：其泛化指标必须用独立测试集（如 testset_cve_fix）评估，")
        print(f"      回收后的 dev eval_loss 不再代表泛化，仅能证明阶段1选型正确。")

    metrics = train_result.metrics
    print("\n训练指标:")
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    if trainer.state.log_history:
        print("\nDev loss 历史:")
        for entry in trainer.state.log_history:
            if "eval_loss" in entry:
                print(f"  epoch={entry.get('epoch', 0):.2f}  eval_loss={entry['eval_loss']:.4f}")

    log_file = LOG_DIR / f"train_log_cloud_r{args.lora_r}_e{args.epochs}_lr{args.lr:g}_s{args.seed}{peft_tag}{args.output_suffix}.json"
    with open(log_file, "w") as f:
        json.dump(
            {
                "args": vars(args),
                "metrics": metrics,
                "model": args.model_id,
                "dtype": args.dtype,
                "train_samples": len(train_dataset),
                "dev_samples": len(dev_dataset),
                "log_history": trainer.state.log_history,
            },
            f, indent=2, ensure_ascii=False,
        )
    print(f"训练日志: {log_file}")


if __name__ == "__main__":
    main()
