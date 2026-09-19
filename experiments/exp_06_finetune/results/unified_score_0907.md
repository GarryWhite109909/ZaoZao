# 统一打分总表（rolling_dev等，自动生成）

> 由 `scripts/score_batch.py` 于 2026-09-03 生成；权重表 weights_20260903.json；
> acc=已裁决口径 (TP+TN)/(TP+TN+FP+FN)；strict=样本级任一命中（CWE 纠正口径）；
> micro/macro=实例级 recall；加权=风险加权分（部分得分 命中1.0/方向对0.5/review 0.5）；
> 未决=review 未决率（两阶段）或 parse_fail；全部按现行答案 manifest 重算。

| 标签 | 测试集 | n | recall | FPR | acc | strict | micro | macro | 加权 | 未决 |
|---|---|---|---|---|---|---|---|---|---|---|
| exp_06_eval.baseline.combined.20260907_013044.json | rolling_dev | 50 | 0.351 | — | 0.351 | 0.115 | 0.120 | 0.103 | 0.160 | 0.000 |
| exp_06_eval.finetuned_custom.combined.20260907_073657.json | rolling_dev | 50 | 0.595 | — | 0.595 | 0.143 | 0.160 | 0.135 | 0.270 | 0.000 |
| exp_07_two_stage_eval.nivis-alpha0.combined_nosource.20260907_013050.json | rolling_dev | 50 | 0.645 | — | 0.645 | 0.450 | 0.290 | 0.244 | 0.480 | 0.380 |
