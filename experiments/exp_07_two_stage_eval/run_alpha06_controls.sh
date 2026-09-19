#!/bin/bash
# rolling_dev50 归因补全对照（2×2 矩阵缺的两个格）
# 对照1: alpha06_stage2 + combined_nosource —— 固定 prompt 看权重效应
# 对照2: alpha05_stage2 + triage_train_aligned —— 固定权重看 prompt 效应
set -u
cd /home/zane/文档/code/毕业设计
export PYTHONPATH=/home/zane/文档/code/毕业设计
export CUDA_VISIBLE_DEVICES=0
export HIP_VISIBLE_DEVICES=0
export HF_HUB_OFFLINE=1
TS=$(date +%Y%m%d_%H%M%S)
E07=experiments/exp_07_two_stage_eval
LOG=experiments/exp_06_finetune/logs/alpha06_controls_$TS.log
MAN=experiments/exp_06_finetune/corpus/rolling_dev/manifest.json

run() { echo "[$(date '+%F %T')] === $1 start ===" | tee -a "$LOG"; shift; "$@" 2>&1 | tee -a "$LOG"; echo "[$(date '+%F %T')] === end rc=${PIPESTATUS[0]} ===" | tee -a "$LOG"; }

run "ctrl1_alpha06+combined_nosource" \
  python3 $E07/eval_two_stage.py --backend transformers \
    --adapter models/adapter_alpha06_stage2 --variant combined_nosource \
    --num-ctx 16384 --n-samples 3 --temperature 0.7 --resume \
    --manifest-path $MAN \
    --output $E07/results/exp_07_rollingdev50.alpha06_combined_nosource.$TS.json

run "ctrl2_alpha05+triage_train_aligned" \
  python3 $E07/eval_two_stage.py --backend transformers \
    --adapter models/adapter_alpha05_stage2 --variant triage_train_aligned \
    --num-ctx 16384 --n-samples 3 --temperature 0.7 --resume \
    --manifest-path $MAN \
    --output $E07/results/exp_07_rollingdev50.alpha05_triage_aligned.$TS.json

echo "[$(date '+%F %T')] controls done" | tee -a "$LOG"
