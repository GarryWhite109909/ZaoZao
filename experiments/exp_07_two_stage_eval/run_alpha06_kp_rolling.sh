#!/bin/bash
# triage_kp @ rolling_dev50 —— 部署视角补全（全量块在第三个真实集上的表现）
set -u
cd /home/zane/文档/code/毕业设计
export PYTHONPATH=/home/zane/文档/code/毕业设计
export CUDA_VISIBLE_DEVICES=0
export HIP_VISIBLE_DEVICES=0
export HF_HUB_OFFLINE=1
TS=$(date +%Y%m%d_%H%M%S)
E07=experiments/exp_07_two_stage_eval
LOG=experiments/exp_06_finetune/logs/alpha06_kp_rolling_$TS.log
echo "[$(date '+%F %T')] === kp_rollingdev50 start ===" | tee -a "$LOG"
python3 $E07/eval_two_stage.py --backend transformers \
  --adapter models/adapter_alpha06_stage2 --variant triage_kp \
  --num-ctx 16384 --n-samples 3 --temperature 0.7 --resume \
  --manifest-path experiments/exp_06_finetune/corpus/rolling_dev/manifest.json \
  --output $E07/results/exp_07_rollingdev50.alpha06_triage_kp.$TS.json 2>&1 | tee -a "$LOG"
echo "[$(date '+%F %T')] === end rc=${PIPESTATUS[0]} ===" | tee -a "$LOG"
