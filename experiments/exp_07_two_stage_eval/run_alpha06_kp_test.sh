#!/bin/bash
# triage_kp 知识增补变体验证 + cvefix20 归因补全（GPU 空闲后执行）
# 顺序：kp 变体最先（回答"蒸馏知识点进推理 prompt 是否有效"）
set -u
cd /home/zane/文档/code/毕业设计
export PYTHONPATH=/home/zane/文档/code/毕业设计
export CUDA_VISIBLE_DEVICES=0
export HIP_VISIBLE_DEVICES=0
export HF_HUB_OFFLINE=1
TS=$(date +%Y%m%d_%H%M%S)
E07=experiments/exp_07_two_stage_eval
LOG=experiments/exp_06_finetune/logs/alpha06_kp_test_$TS.log
MAN20=experiments/exp_06_finetune/testset_cve_fix/manifest.json

run() {
  local name="$1"; shift
  echo "[$(date '+%F %T')] === $name start ===" | tee -a "$LOG"
  "$@" 2>&1 | tee -a "$LOG"
  echo "[$(date '+%F %T')] === $name end rc=${PIPESTATUS[0]} ===" | tee -a "$LOG"
}

EVAL="python3 $E07/eval_two_stage.py --backend transformers --num-ctx 16384 --n-samples 3 --temperature 0.7"

# 1) α06 + triage_kp @ cvefix20 —— 主实验：FN 翻转验证
run "kp_alpha06_cvefix20" $EVAL --adapter models/adapter_alpha06_stage2 --variant triage_kp \
  --resume --manifest-path $MAN20 --output $E07/results/exp_07_cvefix20.alpha06_triage_kp.$TS.json

# 2) α06 + combined_nosource @ cvefix20 —— 归因矩阵补全（权重效应）
run "ctrl_alpha06_cns_cvefix20" $EVAL --adapter models/adapter_alpha06_stage2 --variant combined_nosource \
  --resume --manifest-path $MAN20 --output $E07/results/exp_07_cvefix20.alpha06_combined_nosource.$TS.json

# 3) α05 + triage @ cvefix20 —— 归因矩阵补全（prompt 效应）
run "ctrl_alpha05_triage_cvefix20" $EVAL --adapter models/adapter_alpha05_stage2 --variant triage_train_aligned \
  --resume --manifest-path $MAN20 --output $E07/results/exp_07_cvefix20.alpha05_triage_aligned.$TS.json

echo "[$(date '+%F %T')] kp_test done" | tee -a "$LOG"
