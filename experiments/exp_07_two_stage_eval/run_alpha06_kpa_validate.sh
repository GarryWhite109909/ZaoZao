#!/bin/bash
# triage_kp_a（仅切片可达性规则）双集验证：87 门槛 + cvefix20 增益
set -u
cd /home/zane/文档/code/毕业设计
export PYTHONPATH=/home/zane/文档/code/毕业设计
export CUDA_VISIBLE_DEVICES=0
export HIP_VISIBLE_DEVICES=0
export HF_HUB_OFFLINE=1
TS=$(date +%Y%m%d_%H%M%S)
E07=experiments/exp_07_two_stage_eval
LOG=experiments/exp_06_finetune/logs/alpha06_kpa_$TS.log
EVAL="python3 $E07/eval_two_stage.py --backend transformers --adapter models/adapter_alpha06_stage2 --variant triage_kp_a --num-ctx 16384 --n-samples 3 --temperature 0.7"
run() { local n="$1"; shift; echo "[$(date '+%F %T')] === $n start ===" | tee -a "$LOG"; "$@" 2>&1 | tee -a "$LOG"; echo "[$(date '+%F %T')] === $n end rc=${PIPESTATUS[0]} ===" | tee -a "$LOG"; }
run "kpa_cvefix20" $EVAL --resume --manifest-path experiments/exp_06_finetune/testset_cve_fix/manifest.json \
  --output $E07/results/exp_07_cvefix20.alpha06_triage_kp_a.$TS.json
run "kpa_full87" $EVAL --resume \
  --output $E07/results/exp_07_full87.alpha06_triage_kp_a.$TS.json
echo "[$(date '+%F %T')] kpa validate done" | tee -a "$LOG"
