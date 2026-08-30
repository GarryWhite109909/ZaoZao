"""QLoRA 微调脚本 —— 支持 Qwen3-8B（4bit）或 3B（fp16）。

数据：experiments/exp_06_finetune/data/train_chatml_v5_clean.jsonl（默认，当前最佳 SFT 数据）
      可通过 --data-file 切换其他实验数据
基座：Qwen/Qwen3-8B（默认，4bit QLoRA）
      Qwen/Qwen2.5-Coder-3B-Instruct（--model-id 指定，fp16 LoRA）
方法：4bit NF4 量化 + LoRA（默认 r=8, alpha=16）+ 梯度检查点
硬件：AMD Radeon RX 9060 XT 16GB + ROCm 7.2
      8B 4bit 实测：峰值 14.8GB（余量 1.2GB），batch=1 seq=2048 梯度检查点开启

防过拟合措施：
  - 从训练集分 15% 作 dev，按 dev loss 选 best checkpoint
  - EarlyStoppingCallback：dev loss 连续 patience 轮不降则停
  - load_best_model_at_end=True：训练结束自动回滚到 best checkpoint
  - 推荐 epochs=2, lr=1e-4（1万条蒸馏数据，rsLoRA r=8 + early stopping）
  - 可选 --recycle-dev：阶段1（dev 分拆画 eval loss 曲线 + 选 best）确认健康后，
    阶段2 把 dev 并回训练、用全量数据续训最终模型（final training on full data）。
    注意：回收后 dev 的 eval_loss 不再代表泛化，最终指标须用独立测试集（如 testset_cve_fix）。

用法（在 AI conda 环境中运行，需 GPU 访问）：
  # 自定义数据训练：与 v5 相同配置，仅数据不同
  HF_HUB_OFFLINE=1 TORCH_ROCM_AOTRITON_ENABLE_EXPERIMENTAL=1 python3 train_qlora.py \
      --data-file data/train_chatml_v5_clean.jsonl \
      --epochs 3 --batch-size 1 --grad-accum 8 --lr 1e-4 --lora-r 8 --use-rslora \
      --output-suffix _v5

  # 3B fp16（用 --no-4bit + --model-id 切换）
  HF_HUB_OFFLINE=1 python3 train_qlora.py \
      --model-id Qwen/Qwen2.5-Coder-3B-Instruct --no-4bit
"""

import argparse
import json
import os
import random
import sys
from pathlib import Path

# ROCm 可能报告多个 GPU 设备，在 import torch 前强制只用 GPU 0
# 防止 Trainer 自动启用 DataParallel 跨不存在设备导致 "invalid device ordinal"
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")
os.environ.setdefault("HIP_VISIBLE_DEVICES", "0")

import torch

# TunableOp 启用（PyTorch 2.11+ 三种模式：recording / tuning / deploy）
# 参考 docs/方法.md §12.1：TunableOp 离线调优可带来 ~15% 端到端加速
# 工作流：
#   1. Recording: PYTORCH_TUNABLEOP_RECORD_UNTUNED=1 + PYTORCH_TUNABLEOP_TUNING=0
#      → 跑训练时把所有 GEMM shape 写入 cwd/tunableop_untuned0.csv（atexit 时 flush）
#   2. Offline Tuning: 用 torch.cuda.tunable.tune_gemm_in_file() 调优 untuned csv
#      → 输出 tuned csv（包含每个 GEMM 的最优 kernel）
#   3. Deploy: PYTORCH_TUNABLEOP_FILE_NAME=tuned.csv + PYTORCH_TUNABLEOP_TUNING=0
#      → 训练时自动读 tuned csv 用最优 kernel
if os.environ.get("PYTORCH_TUNABLEOP_ENABLED", "0") == "1":
    try:
        t = torch.cuda.tunable
        t.enable(True)  # 总开关（替换默认 GEMM 调度为 TunableOp）
        # recording 模式：记录未调优的 GEMM shape 到 untuned csv
        if os.environ.get("PYTORCH_TUNABLEOP_RECORD_UNTUNED", "0") == "1":
            t.record_untuned_enable(True)
            t.tuning_enable(False)  # 不调优，只记录
        else:
            # deploy 模式：读取已有 tuned csv 用最优 kernel
            t.tuning_enable(False)
            tuned_csv = os.environ.get("PYTORCH_TUNABLEOP_FILE_NAME")
            if tuned_csv:
                t.set_filename(tuned_csv)
        print(f"TunableOp 已启用: enabled={t.is_enabled()} "
              f"tuning={t.tuning_is_enabled()} "
              f"record_untuned={t.record_untuned_is_enabled()} "
              f"file={t.get_filename()}")
    except Exception as e:
        print(f"⚠️ TunableOp 启用失败: {e}")

from datasets import Dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    EarlyStoppingCallback,
    TrainingArguments,
)
from trl import SFTConfig, SFTTrainer

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/train_chatml_v5_clean.jsonl"
OUTPUT_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/outputs"
LOG_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/logs"
MODEL_ID = "Qwen/Qwen3-8B"  # 默认 Qwen3-8B（Instruct），4bit QLoRA 实测可行


def load_chatml_dataset(path: Path) -> Dataset:
    """加载 ChatML jsonl 为 HF Dataset。"""
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    print(f"加载 {len(records)} 条样本")
    return Dataset.from_list(records)


def assert_no_truncation(dataset, tokenizer, max_seq_length: int, allow: bool = False):
    """P2-20 硬断言：防止 max_seq_length 不足导致 JSON 结论被静默截断。

    TRL SFTTrainer 对超长样本静默截断——截断点落在 JSON 结论中段时该样本
    的监督信号直接损坏（v2_12 审计：max_seq_length=2048 时 23.4% 样本 JSON
    被切掉）。此处在训练前对全量样本做真实分词统计，超限即报错退出。
    """
    texts = [tokenizer.apply_chat_template(r["messages"], tokenize=False) for r in dataset]
    lens = [len(ids) for ids in tokenizer(texts, add_special_tokens=False)["input_ids"]]
    over = [n for n in lens if n > max_seq_length]
    if not over:
        print(f"长度硬断言通过: max={max(lens)} tokens <= max_seq_length={max_seq_length}")
        return
    print(f"!! 长度硬断言失败: {len(over)}/{len(lens)} 条样本超过 max_seq_length={max_seq_length}"
          f"（最长 {max(lens)} tokens），JSON 结论将被截断。")
    if allow:
        print("   --allow-truncation 已启用，继续训练（这些样本监督信号损坏，后果自负）。")
        return
    print("   处理：调大 --max-seq-length（alpha06_v2_13 清洗后实测上限约 8.1k tokens，"
          "云端脚本默认 12288 足够；本地默认 2048 必然失败——该数据集应在云端训练），")
    print("        或确认可接受截断后加 --allow-truncation。")
    sys.exit(1)


def split_train_dev(dataset: Dataset, dev_ratio: float, seed: int = 42) -> tuple[Dataset, Dataset]:
    """按 dev_ratio 分拆训练集与验证集（P0 改造：避免过拟合，按 dev loss 选 best）。

    用 seed 固定随机性，保证多种子训练时 dev 集一致（仅训练种子不同）。
    返回 (train_dataset, dev_dataset)。
    """
    n = len(dataset)
    n_dev = max(1, int(n * dev_ratio))
    n_train = n - n_dev
    # 用 seed 打乱索引
    rng = random.Random(seed)
    indices = list(range(n))
    rng.shuffle(indices)
    dev_indices = set(indices[:n_dev])
    train_records = [dataset[i] for i in range(n) if i not in dev_indices]
    dev_records = [dataset[i] for i in range(n) if i in dev_indices]
    print(f"分拆：train={len(train_records)} dev={len(dev_records)}（dev_ratio={dev_ratio}）")
    return Dataset.from_list(train_records), Dataset.from_list(dev_records)


def try_4bit_quant(use_4bit: bool) -> BitsAndBytesConfig | None:
    """配置 4bit 量化。bitsandbytes 在 ROCm 上易段错误，默认禁用。"""
    if not use_4bit:
        print("禁用 4bit 量化（fp16 LoRA + 梯度检查点模式）")
        return None
    try:
        import bitsandbytes as bnb  # noqa: F401
        print(f"bitsandbytes {bnb.__version__} 可用，尝试 4bit 量化")
        return BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
        )
    except Exception as e:
        print(f"bitsandbytes 4bit 不可用: {e}")
        print("降级为 fp16 LoRA + 梯度检查点")
        return None


def main():
    parser = argparse.ArgumentParser(description="QLoRA 微调 Qwen3-8B")
    parser.add_argument("--epochs", type=int, default=2,
                        help="训练轮数（默认 2；1万条蒸馏数据×2epoch，early stopping 兜底）")
    parser.add_argument("--batch-size", type=int, default=1, help="每设备 batch size")
    parser.add_argument("--grad-accum", type=int, default=8, help="梯度累积步数")
    parser.add_argument("--lr", type=float, default=1e-4,
                        help="学习率（默认 1e-4；QLoRA 标准值，配合 rsLoRA r=8）")
    parser.add_argument("--lora-r", type=int, default=8,
                        help="LoRA rank（默认 8；r=16 干预过强，r=8 足以学补盲样本）")
    parser.add_argument("--lora-alpha", type=int, default=16,
                        help="LoRA alpha（默认 16，保持 alpha=2*r）")
    parser.add_argument("--lora-dropout", type=float, default=0.1,
                        help="LoRA dropout（默认 0.1；高容量 r=32+ 建议降到 0.05）")
    parser.add_argument("--use-rslora", action="store_true",
                        help="启用 rsLoRA（缩放因子 1/r → 1/√r，高 rank 更稳定，零额外成本）")
    parser.add_argument("--use-dora", action="store_true",
                        help="启用 DoRA（权重分解为 magnitude+direction，PEFT 0.19+ 支持；"
                             "注意：DoRA + 4bit QLoRA 在 ROCm 上需单独验证兼容性）")
    parser.add_argument("--max-seq-length", type=int, default=2048, help="最大序列长度")
    parser.add_argument("--allow-truncation", action="store_true",
                        help="允许超长样本被截断（跳过 P2-20 长度硬断言，不建议）")
    parser.add_argument("--save-steps", type=int, default=50, help="每 N 步保存 checkpoint（防中断丢进度）")
    parser.add_argument("--eval-steps", type=int, default=None,
                        help="每 N 步评估 dev（默认与 save-steps 相同；可调大降低 eval 开销，"
                             "如 save=50 / eval=200，保存频繁但评估稀疏）")
    parser.add_argument("--logging-steps", type=int, default=5, help="每 N 步记录日志")
    parser.add_argument("--warmup-ratio", type=float, default=0.05, help="warmup 比例")
    parser.add_argument("--seed", type=int, default=42, help="随机种子")
    parser.add_argument("--model-id", type=str, default=MODEL_ID,
                        help=f"基座模型 ID（默认 {MODEL_ID}）")
    parser.add_argument("--no-4bit", action="store_true",
                        help="禁用 4bit 量化，用 fp16（3B 模型可用；7B fp16 在 16GB 上 OOM）")
    parser.add_argument("--data-file", type=str, default=None,
                        help="训练数据 jsonl 路径（默认 data/train_chatml_v2.jsonl）")
    # P0 改造：验证集 + early stopping
    parser.add_argument("--dev-ratio", type=float, default=0.15,
                        help="验证集比例（默认 0.15，即 15%% 作 dev）")
    parser.add_argument("--early-stopping-patience", type=int, default=2,
                        help="EarlyStopping 耐心值：dev loss 连续 N 轮不降则停（默认 2）")
    parser.add_argument("--no-early-stopping", action="store_true",
                        help="禁用 early stopping（仍会分 dev 集评估，但不提前停）")
    parser.add_argument("--no-load-best", action="store_true",
                        help="禁用 load_best_model_at_end（训练结束不自动回滚到 best）。"
                             "启用后 save_steps 与 eval_steps 可独立设置（如 save=50/eval=200），"
                             "适合防中断频繁保存 + 稀疏评估；训练结束后手动从各 checkpoint 的 eval_loss 选 best")
    parser.add_argument("--output-suffix", type=str, default="",
                        help="输出目录后缀（如 _7b），避免不同基座模型覆盖同名目录")
    parser.add_argument("--max-steps", type=int, default=-1,
                        help="最大训练步数（默认 -1 不启用；>0 时覆盖 epochs，"
                             "用于 TunableOp recording 等短跑场景）")
    parser.add_argument("--resume", type=str, default="",
                        help="从 checkpoint 恢复训练（传入 checkpoint 目录路径）")
    # 第 2 阶段：回收 dev 集（final training on full data）
    parser.add_argument("--recycle-dev", action="store_true",
                        help="阶段1（分 dev 看 eval loss 曲线 + 选 best）完成后，把 dev 集回收进训练，"
                             "用全量数据续训最终模型。标准做法：train/dev 只用于模型选择，"
                             "最终模型在全量数据上训练，避免宝贵的 dev 数据浪费。")
    parser.add_argument("--recycle-epochs", type=float, default=1.0,
                        help="回收阶段在全量数据上续训的 epochs（默认 1.0 = 全量过一遍；"
                             "数据少时建议 1.0，过久易过拟合）")
    args = parser.parse_args()

    # 解析数据文件路径
    data_file = Path(args.data_file) if args.data_file else DATA_FILE
    model_id = args.model_id
    use_4bit = not args.no_4bit

    # 检查 GPU
    if not torch.cuda.is_available():
        print("错误：未检测到 CUDA/HIP GPU。请在有 GPU 的环境中运行。")
        print("提示：若在 IDE 沙箱中，需在真实终端运行此脚本。")
        sys.exit(1)
    n_gpus = torch.cuda.device_count()
    print(f"检测到 GPU 数量: {n_gpus}")
    if n_gpus > 1:
        print(f"警告：检测到 {n_gpus} 个 GPU，但单卡训练模式只使用 GPU 0。")
        print("  设置 CUDA_VISIBLE_DEVICES=0 避免多 GPU DataParallel 报错。")
        os.environ["CUDA_VISIBLE_DEVICES"] = "0"
        os.environ["HIP_VISIBLE_DEVICES"] = "0"
        # 重新检查（环境变量需在 torch.cuda 初始化前设置才生效，
        # 若已初始化则只能警告，建议用户在运行脚本前设置）
    print(f"GPU: {torch.cuda.get_device_name(0)}")
    print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB")

    # 加载数据并分拆 dev
    print(f"训练数据: {data_file}")
    full_dataset = load_chatml_dataset(data_file)
    train_dataset, dev_dataset = split_train_dev(full_dataset, args.dev_ratio, seed=42)

    # 加载 tokenizer
    print(f"加载 tokenizer: {model_id}")
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Qwen3: 禁用 thinking mode（TRL SFTTrainer 内部调用 apply_chat_template
    # 时不传 enable_thinking 参数，Qwen3 默认 True 会破坏训练）
    if "qwen3" in model_id.lower():
        _orig_apply = tokenizer.apply_chat_template
        def _patched_apply(*args, **kwargs):
            kwargs.setdefault("enable_thinking", False)
            return _orig_apply(*args, **kwargs)
        tokenizer.apply_chat_template = _patched_apply
        print("Qwen3: 已 patch apply_chat_template 默认 enable_thinking=False")

    # P2-20 硬断言：数据集最长样本必须完整放进 max_seq_length，否则 JSON 结论被截断
    assert_no_truncation(full_dataset, tokenizer, args.max_seq_length, allow=args.allow_truncation)

    # 加载模型（4bit 或 fp16）
    bnb_config = try_4bit_quant(use_4bit)
    print(f"加载模型: {model_id} ({'4bit' if bnb_config else 'fp16'})")
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        quantization_config=bnb_config,
        device_map={"": 0},  # ROCm 上 "auto" 易段错误，强制单 GPU
        trust_remote_code=True,
        torch_dtype=torch.float16,
        attn_implementation="eager",  # RDNA4 上 sdpa 反向传播触发 hipErrorIllegalAddress，改用 eager（纯 PyTorch，最稳定）
    )
    model.config.use_cache = False  # 训练时关闭 KV cache

    # 准备 kbit 训练
    if bnb_config is not None:
        model = prepare_model_for_kbit_training(model)
    else:
        model.gradient_checkpointing_enable()
        model.enable_input_require_grads()

    # LoRA 配置
    # P0 优化：支持 rsLoRA（1/√r 缩放，高 rank 更稳定）和 DoRA（magnitude+direction 分解）
    # 参考 docs/方法.md §8.1：rsLoRA + DoRA 是零额外成本的 PEFT 升级
    lora_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        use_rslora=args.use_rslora,  # rsLoRA：缩放因子 1/r → 1/√r
        use_dora=args.use_dora,      # DoRA：权重分解为 magnitude + direction
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
    )
    peft_tags = []
    if args.use_rslora:
        peft_tags.append("rslora")
    if args.use_dora:
        peft_tags.append("dora")
    peft_tag = ("_" + "_".join(peft_tags)) if peft_tags else ""
    print(f"LoRA 配置: r={args.lora_r} alpha={args.lora_alpha} dropout={args.lora_dropout}"
          f" rslora={args.use_rslora} dora={args.use_dora}")
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # fp32 LoRA 参数：ROCm 上 GradScaler 与模型内部 bf16 参数不兼容，
    # 改为把 LoRA 可训练参数提升到 fp32（梯度天然不下溢，无需 GradScaler）
    # 额外开销极小：43M 参数 × 4 bytes ≈ 172MB
    n_upcast = 0
    for param in model.parameters():
        if param.requires_grad and param.dtype != torch.float32:
            param.data = param.data.to(torch.float32)
            n_upcast += 1
    print(f"LoRA 参数提升到 fp32: {n_upcast} 个 tensor")

    # SFT 配置（P0 改造：加 eval + load_best）
    output_dir = OUTPUT_DIR / f"lora_r{args.lora_r}_a{args.lora_alpha}_e{args.epochs}_lr{args.lr:g}_s{args.seed}{peft_tag}{args.output_suffix}"
    output_dir.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # max_steps > 0 时（TunableOp recording 等短跑场景）禁用 eval/save/load_best，
    # 否则 load_best_model_at_end 会因无 checkpoint 报错
    short_run = args.max_steps > 0

    sft_config = SFTConfig(
        output_dir=str(output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=args.warmup_ratio,
        max_grad_norm=1.0,  # 梯度裁剪：防止梯度爆炸导致 NaN eval_loss
        logging_steps=args.logging_steps,
        save_strategy="no" if short_run else "steps",  # 按步保存（避免崩溃丢失进度）
        save_steps=args.save_steps,
        save_total_limit=10,  # 加大：防 load_best_model_at_end 时 best checkpoint 已被删
        max_steps=args.max_steps,  # >0 时覆盖 epochs（用于 TunableOp recording 短跑）
        bf16=False,  # RDNA4 不支持 bf16
        fp16=False,  # 不用 GradScaler（ROCm 上 GradScaler 与模型内部 bf16 参数不兼容）
                     # 改用 fp32 LoRA 参数防止梯度下溢（见 get_peft_model 后的 dtype 提升）
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        optim="adamw_torch",  # RDNA4 上 paged_adamw_8bit 可能造成模型状态静默损坏
        weight_decay=0.01,  # L2 正则化：防止权重过大导致 fp16 前向溢出
        seed=args.seed,
        max_length=args.max_seq_length,  # TRL 1.7+ 改名为 max_length
        packing=False,  # ROCm 上 packing 需 flash-attn，关闭避免 cross-contamination + 省 VRAM
        dataset_text_field=None,  # 使用 messages 字段
        assistant_only_loss=True,  # 只对 assistant 部分计算 loss
        report_to="none",
        logging_dir=str(LOG_DIR),
        # P0 改造：验证集评估 + best checkpoint（短跑模式下禁用）
        eval_strategy="no" if short_run else "steps",  # 按步评估 dev
        eval_steps=args.eval_steps if args.eval_steps else args.save_steps,  # 默认与保存对齐，可独立调大
        load_best_model_at_end=(not short_run) and (not args.no_load_best),  # 训练结束回滚到 best checkpoint
        metric_for_best_model="eval_loss",  # 按 dev loss 选 best
        greater_is_better=False,  # loss 越小越好
        # OOM 修复：dev 评估 batch_size 降到 1 + 累积 16 步，与训练一致
        per_device_eval_batch_size=1,
        eval_accumulation_steps=16,
        dataloader_pin_memory=False,  # 省一点 CPU→GPU 拷贝开销
    )

    # EarlyStoppingCallback
    callbacks = []
    if not args.no_early_stopping and not short_run:
        callbacks.append(EarlyStoppingCallback(
            early_stopping_patience=args.early_stopping_patience,
            early_stopping_threshold=0.001,  # dev loss 降幅 < 0.001 视为无改善
        ))
        print(f"启用 EarlyStopping：patience={args.early_stopping_patience}, threshold=0.001")
    else:
        if short_run:
            print("禁用 EarlyStopping（短跑模式 max_steps>0，无 eval）")
        else:
            print("禁用 EarlyStopping（仍会评估 dev 并存 best checkpoint）")

    # Trainer
    trainer = SFTTrainer(
        model=model,
        args=sft_config,
        train_dataset=train_dataset,
        eval_dataset=dev_dataset,  # P0 改造：传入 dev 集
        processing_class=tokenizer,
        callbacks=callbacks,
    )

    # 训练
    print(f"\n开始训练: {args.epochs} epochs, lr={args.lr}, batch={args.batch_size}x{args.grad_accum}, seed={args.seed}")
    print(f"train={len(train_dataset)} dev={len(dev_dataset)}")
    print(f"输出目录: {output_dir}")
    train_result = trainer.train(resume_from_checkpoint=args.resume if args.resume else None)

    # 短跑模式（TunableOp recording 等）不保存模型，直接结束
    if short_run:
        print(f"\n✅ 短跑模式完成（max_steps={args.max_steps}），不保存模型")
        print(f"   训练指标:")
        for k, v in train_result.metrics.items():
            print(f"   {k}: {v}")
        return

    # 保存 best 模型（load_best_model_at_end=True 已把 best 加载回 model）
    best_dir = output_dir / "best"
    trainer.save_model(str(best_dir))
    trainer.save_state()
    if args.no_load_best:
        print(f"\n（--no-load-best：model 为 final 状态）LoRA adapter 已保存到: {best_dir}")
        print(f"  如需 best，请从各 checkpoint 的 eval_loss 手动选择。")
    else:
        print(f"\nBest LoRA adapter（按 dev_loss 选）已保存到: {best_dir}")

    # 也保存 final（训练结束时的状态，可能不是 best）
    final_dir = output_dir / "final"
    # 注意：load_best_model_at_end=True 时 model 已是 best，final 与 best 相同
    # 但 trainer_state 记录了完整训练过程
    print(f"（load_best_model_at_end=True，final 即 best）")

    # ---- 第 2 阶段：回收 dev 集（--recycle-dev）----
    # 方法论：train/dev 划分只用于「模型选择」（看 eval loss 曲线、early stopping、选 best epoch），
    # 不是用来报告最终泛化的。确认曲线健康后把 dev 并回训练、用全量数据续训最终模型，
    # 是标准的 "final training on full data"，避免宝贵的 dev 数据浪费。
    # ⚠️ 边界：回收后 dev 的 eval_loss 不再代表泛化（模型已见过它）；最终指标必须来自
    #    从未进过训练集的独立测试集（如 testset_cve_fix）。不要拿回收后的 dev loss 当泛化证据。
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
            bf16=False,
            fp16=False,
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

    # 训练指标
    metrics = train_result.metrics
    print("\n训练指标:")
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    # 打印 dev 评估历史
    if trainer.state.log_history:
        print("\nDev loss 历史:")
        for entry in trainer.state.log_history:
            if "eval_loss" in entry:
                print(f"  epoch={entry.get('epoch', 0):.2f}  eval_loss={entry['eval_loss']:.4f}")

    # 保存训练日志（文件名含 lr + peft 标识，避免 sweep 各组互相覆盖）
    log_file = LOG_DIR / f"train_log_r{args.lora_r}_e{args.epochs}_lr{args.lr:g}_s{args.seed}{peft_tag}{args.output_suffix}.json"
    with open(log_file, "w") as f:
        json.dump(
            {
                "args": vars(args),
                "metrics": metrics,
                "model": model_id,
                "quantization": "4bit" if bnb_config else "fp16",
                "train_samples": len(train_dataset),
                "dev_samples": len(dev_dataset),
                "log_history": trainer.state.log_history,
            },
            f, indent=2, ensure_ascii=False,
        )
    print(f"训练日志: {log_file}")


if __name__ == "__main__":
    main()
