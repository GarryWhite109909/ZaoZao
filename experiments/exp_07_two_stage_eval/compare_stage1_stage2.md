# stage1 vs stage2 adapter 对比（2026-08-18 补跑）

## 背景
两阶段训练（α0.5）产出两个 adapter：`models/adapter_alpha05_stage1`（stage1 best）
与 `models/adapter_alpha05_stage2`（stage2 回收 dev 续训的上线物）。`paths.py`
`_pick_best` 打分为 stage2 优先（stage2=4 > stage1=3），但此前无实证对比。
本对比在真实 CVE-fix 测试集上验证两个 adapter 的端到端表现。

## 方法
同一测试集（CVE-fix 20 段）、同一干净环境配置（`--no-signal-feedback`、
transformers 后端、`triage_train_aligned`、N=3），仅 adapter 不同：

```bash
# stage2（已跑，A6）：
python experiments/exp_07_two_stage_eval/eval_two_stage.py \
  --backend transformers --adapter models/adapter_alpha05_stage2 \
  --variant triage_train_aligned --n-samples 3 --no-signal-feedback \
  --manifest-path experiments/exp_06_finetune/testset_cve_fix/manifest.json \
  --samples-dir experiments/exp_06_finetune/testset_cve_fix

# stage1（待跑）：
python experiments/exp_07_two_stage_eval/eval_two_stage.py \
  --backend transformers --adapter models/adapter_alpha05_stage1 \
  --variant triage_train_aligned --n-samples 3 --no-signal-feedback \
  --manifest-path experiments/exp_06_finetune/testset_cve_fix/manifest.json \
  --samples-dir experiments/exp_06_finetune/testset_cve_fix
```

## 结果
| adapter | recall | FPR | acc | strict_recall | strict_acc | review | 结果文件 |
|---|---|---|---|---|---|---|---|
| stage1 | **0.5714**（TP=4 FN=3） | -（无安全样本） | 0.5714 | **0.5714** | 0.5714 | 13 | `exp_07_two_stage_eval.nivis-alpha0.triage_train_aligned.20260819_004700.json` |
| stage2 | 0.5556（TP=5 FN=4） | - | 0.5556 | 0.4444 | 0.4444 | 11 | `exp_07_two_stage_eval.nivis-alpha0.triage_train_aligned.20260818_230036.json` |

> strict 列以 `recompute_strict_metrics.py` 纠正口径为准（CWE Normalizer 后比对）。
> 两档均无安全样本（CVE-fix 全 vuln），FPR 无定义；acc 为全量口径 (TP+TN)/20，review 入分母。

## 结论（2026-08-19 补跑完成）

- **两 adapter 判定高度一致（18/20 相同）**：差异仅 2 个——`cve_fix_0004.py`（stage1 保守 review vs stage2 漏判 false）与 `cve_fix_0021.java`（stage1 保守 review vs stage2 判真 true）。stage1 的 review 更多（13 vs 11），TP 略少（4 vs 5）但 FN 也少（3 vs 4）。
- **recall（不含 review）stage1 略高（0.571 vs 0.556）**，主要因 review 分母不同，非判定能力实质差异；**strict_recall stage1 更高（0.571 vs 0.444）**：stage1 的 4 个 TP 全部 CWE 归因正确（cwe_mismatch=0），stage2 有 1 个 mismatch。
- **两档工具召回均判真 0 个**，TP 全部来自无候选 → LLM 全文件复核兜底；真实 CVE 集上工具规则覆盖不足是共性瓶颈（见素材库 1.1.14 ⑤）。
- **stage2（回收 dev 续训的上线物）在判定保守性与归因一致性上略逊 stage1**：stage2 把 0021 判成 true（正确）但把 0004 漏判成 false（错），stage1 两处都保守转 review（不犯 FN 但需人工）。**"stage2 上线物优先"（paths.py 打分）在判别力上无实证优势，但 stage2 更接近训练分布终点（dev 回收续训），本对比显示差异主要体现为保守性而非准确性**。论文若引用两阶段 CVE-fix 真实集数据，用 stage2（系统默认上线物）为佳，注明 stage1 同配置对照结论。
