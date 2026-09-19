#!/bin/bash
# alpha06 全量评测链（wave8 组态）：87 合成 + 20 cve_fix + 50 rolling_dev + 4 真实仓库
# 组态：transformers NF4 基座 + adapter_alpha06_stage2、triage_train_aligned、
#       N=3、T=0.7、ctx16384、full_recheck、四路工具全开、信任层全开
#       （signal_feedback 用隔离注册表，conformal 不做 in-sample 校准——与 wave8 相同）
# 断点续跑：每个阶段都带 --resume 且输出文件名固定（时间戳在首次启动时生成并写
# 入 OUTPUT_STAMP 文件）；重复执行本脚本时，已完成阶段秒级空转通过，中断阶段
# 从最后一个已落盘样本继续。
set -u
cd /home/zane/文档/code/毕业设计
export PYTHONPATH=/home/zane/文档/code/毕业设计
export CUDA_VISIBLE_DEVICES=0
export HIP_VISIBLE_DEVICES=0
export HF_HUB_OFFLINE=1
export VULN_SCANNER_ADAPTER=models/adapter_alpha06_stage2

STAMP_FILE=experiments/exp_06_finetune/logs/alpha06_eval_chain.stamp
if [ -f "$STAMP_FILE" ]; then
  TS=$(cat "$STAMP_FILE")
else
  TS=$(date +%Y%m%d_%H%M%S)
  mkdir -p "$(dirname "$STAMP_FILE")"
  echo "$TS" > "$STAMP_FILE"
fi

E07=experiments/exp_07_two_stage_eval
E08=experiments/exp_08_repo_benchmark
OUT87=$E07/results/exp_07_full87.alpha06_wave8_ctx16384.$TS.json
OUT20=$E07/results/exp_07_cvefix20.alpha06_wave8_ctx16384.$TS.json
OUT50=$E07/results/exp_07_rollingdev50.alpha06_wave8_ctx16384.$TS.json
LOG=experiments/exp_06_finetune/logs/alpha06_eval_chain_$TS.log
mkdir -p experiments/exp_06_finetune/logs

echo "[$(date '+%F %T')] chain start/resume, outputs stamped $TS" | tee -a "$LOG"

run_stage() {  # $1=名称 其后=命令...
  local name="$1"; shift
  echo "[$(date '+%F %T')] === $name start ===" | tee -a "$LOG"
  "$@" 2>&1 | tee -a "$LOG"
  echo "[$(date '+%F %T')] === $name end rc=${PIPESTATUS[0]} ===" | tee -a "$LOG"
  return 0  # 单阶段失败不阻断后续阶段
}

EVAL07="python3 $E07/eval_two_stage.py --backend transformers --adapter models/adapter_alpha06_stage2 --variant triage_train_aligned --num-ctx 16384 --n-samples 3 --temperature 0.7"

run_stage "87合成" $EVAL07 --resume --output "$OUT87"
run_stage "cvefix20" $EVAL07 --resume --output "$OUT20" \
  --manifest-path experiments/exp_06_finetune/testset_cve_fix/manifest.json
run_stage "rollingdev50" $EVAL07 --resume --output "$OUT50" \
  --manifest-path experiments/exp_06_finetune/corpus/rolling_dev/manifest.json

for repo in dvna nodegoat php-goof vflask; do
  case $repo in
    dvna) manifest=manifest_dvna.json; dir=repos/dvna;;
    nodegoat) manifest=manifest_nodegoat.json; dir=repos/nodegoat;;
    php-goof) manifest=manifest_php-goof.json; dir=repos/php-goof;;
    vflask) manifest=manifest_vflask.json; dir=repos/Vulnerable-Flask-App;;
  esac
  run_stage "repo_$repo" \
    python3 $E08/eval_repo.py --manifest $E08/$manifest --repo-dir $E08/$dir \
      --num-ctx 16384 --resume --output "$E08/results/repo_eval.$repo.alpha06.$TS.json"
done

echo "[$(date '+%F %T')] chain done" | tee -a "$LOG"
