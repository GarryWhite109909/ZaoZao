# stage1 vs stage2 adapter 对比（2026-08-18/19 补跑）

## 背景
两阶段训练（α0.5）产出两个 adapter：`models/adapter_alpha05_stage1`（stage1 best）
与 `models/adapter_alpha05_stage2`（stage2 回收 dev 续训的上线物）。`paths.py`
`_pick_best` 打分为 stage2 优先（stage2=4 > stage1=3），但此前无实证对比。
本对比在两个测试集上验证两个 adapter 的端到端表现：
- **87 段合成集**（α0 系列主测试集，fixed5 达标数据即 stage2 在此集的结果）——**stage2 已有（fixed5），stage1 补跑中**；
- **CVE-fix 20 段真实集**（2026-08-18/19 已跑完两个 adapter）。

## 方法
同一测试集、同一干净环境配置（`--no-signal-feedback`、transformers 后端、
`triage_train_aligned`、N=3），仅 adapter 不同：

```bash
# 87 段合成集（默认 manifest = exp_04 87 段）：
python experiments/exp_07_two_stage_eval/eval_two_stage.py \
  --backend transformers --adapter models/adapter_alpha05_stage2 \
  --variant triage_train_aligned --n-samples 3 --no-signal-feedback          # stage2 = fixed5（已有）
python experiments/exp_07_two_stage_eval/eval_two_stage.py \
  --backend transformers --adapter models/adapter_alpha05_stage1 \
  --variant triage_train_aligned --n-samples 3 --no-signal-feedback          # stage1（补跑中，预计 5-7h）

# CVE-fix 20 段真实集（2026-08-18/19 已完成）：
python experiments/exp_07_two_stage_eval/eval_two_stage.py \
  --backend transformers --adapter models/adapter_alpha05_stage{1,2} \
  --variant triage_train_aligned --n-samples 3 --no-signal-feedback \
  --manifest-path experiments/exp_06_finetune/testset_cve_fix/manifest.json \
  --samples-dir experiments/exp_06_finetune/testset_cve_fix
```

## 结果

### CVE-fix 20 段真实集（已完成）
| adapter | recall | FPR | acc | strict_recall | strict_acc | review | 结果文件 |
|---|---|---|---|---|---|---|---|
| stage1 | **0.5714**（TP=4 FN=3） | -（无安全样本） | 0.5714 | **0.5714** | 0.5714 | 13 | `exp_07_two_stage_eval.nivis-alpha0.triage_train_aligned.20260819_004700.json` |
| stage2 | 0.5556（TP=5 FN=4） | - | 0.5556 | 0.4444 | 0.4444 | 11 | `exp_07_two_stage_eval.nivis-alpha0.triage_train_aligned.20260818_230036.json` |

> strict 列以 `recompute_strict_metrics.py` 纠正口径为准（CWE Normalizer 后比对）。
> 两档均无安全样本（CVE-fix 全 vuln），FPR 无定义；acc 为全量口径 (TP+TN)/20，review 入分母。

### 87 段合成集（stage2 = fixed5 已有；stage1 补跑完成 2026-08-19）
| adapter | recall | FPR | acc | strict_recall | strict_acc | review | 结果文件 |
|---|---|---|---|---|---|---|---|
| stage1 | 1.000* | 0.0* | 1.0* | 0.864 | 0.893 | **59** | `exp_07_two_stage_eval.nivis-alpha0.triage_train_aligned.20260819_112555.json` |
| stage2（fixed5） | **1.000** | **0.043** | **0.862** | 0.811 | 0.847 | **11** | `exp_07_two_stage_eval.nivis-alpha0.triage_train_aligned.20260818_104203.json` |

> \* stage1 的 recall/FPR/acc 为"不含 review"口径的虚高值——它把 **59/87 判成 review（需人工复核）**，只确定判了 28 个（TP=22 TN=6），recall 1.0 / FPR 0.0 是因为 review 不计入分母。全量口径下 stage1 实际"确定判定率"仅 32%（28/87），远超 stage2 的 87%（76/87）。

## 结论（2026-08-19 两测试集补跑完成）

### CVE-fix 真实集（已完成，2026-08-19）
- **两 adapter 判定高度一致（18/20 相同）**：差异仅 2 个——`cve_fix_0004.py`（stage1 保守 review vs stage2 漏判 false）与 `cve_fix_0021.java`（stage1 保守 review vs stage2 判真 true）。stage1 的 review 更多（13 vs 11），TP 略少（4 vs 5）但 FN 也少（3 vs 4）。
- **recall（不含 review）stage1 略高（0.571 vs 0.556）**，主要因 review 分母不同，非判定能力实质差异；**strict_recall stage1 更高（0.571 vs 0.444）**：stage1 的 4 个 TP 全部 CWE 归因正确（cwe_mismatch=0），stage2 有 1 个 mismatch。
- **两档工具召回均判真 0 个**，TP 全部来自无候选 → LLM 全文件复核兜底；真实 CVE 集上工具规则覆盖不足是共性瓶颈（见素材库 1.1.14 ⑤）。
- **stage2（回收 dev 续训的上线物）在判定保守性与归因一致性上略逊 stage1**：stage2 把 0021 判成 true（正确）但把 0004 漏判成 false（错），stage1 两处都保守转 review（不犯 FN 但需人工）。**"stage2 上线物优先"（paths.py 打分）在判别力上无实证优势，但 stage2 更接近训练分布终点（dev 回收续训），本对比显示差异主要体现为保守性而非准确性**。论文若引用两阶段 CVE-fix 真实集数据，用 stage2（系统默认上线物）为佳，注明 stage1 同配置对照结论。

### 87 段合成集（2026-08-19 补跑完成）
- **stage2 显著优于 stage1**：fixed5 在 87 段上确定判 76/87（TP=53 TN=22 FP=1）、仅 11 个 review；stage1 只确定判 28/87、59 个 review。48/87 样本判定不同，全部是 stage1 转 review（32 个 fixed5 判 true → review，16 个判 false → review）。
- **review 真因（2026-08-19 深挖）：stage1 在裁决任务上 100% 输出解析失败（invalid 票），不是"保守否决"**——stage1 的 141 条候选裁决 adjudication **全部 3 票 invalid**（423 票无一有效：`votes_true=0 votes_false=0 invalid=3`，confidence=0），聚合层无有效票 → 转 review；stage2 同批 144 条 adjudication **invalid=0 全部有效**（典型_01：stage1 3×invalid → review，stage2 votes 2:1/3:0 确认判真）。`no_candidate_recheck` 通道（LLM 全文件复核）两档接近，差异完全集中在**候选裁决（adjudicate）环节的输出格式**上。
- **机制解释（与"训练分布对齐"叙事同源）**：两个 adapter 用同一份 `final_train_chatml_alpha05.jsonl`（7972 条，全部 `has_vulnerability` 格式，**无 triage 适配样本**——`supplement_alpha05_triage.jsonl` 只有生成脚本、未实际微调）训练；triage_train_aligned 对两者是同一条 prompt。stage1（分 dev 选 best）未学会"对带工具 evidence 的封闭二分类 finding 输出可解析判定"；stage2（recycle-dev 回收 dev 全量续训 1 epoch，权重相对差异 29.6%）学会了。**recycle 续训的价值 = 裁决任务格式对齐 + 判定能力，而非评估配置倾斜**。
- **评估公平性核查（2026-08-19 逐项确认）**：两跑 meta 逐字段一致（backend/variant/n_samples/temperature/tools/trust/conformal/counterfactual/signal_feedback 全同，仅 adapter 不同）；`--no-signal-feedback` 抑制池未加载未写盘（`models/signal_registry.json` mtime 早于两跑）；`VULN_SCANNER_CONFORMAL_CALIB=0` 禁用共形校准加载（两跑同）；确定性证据门为代码内统一逻辑无开关。**结论：对比条件完全公平，差异是模型能力（权重）差异，不是配置/数据/环境倾斜。**
- **strict 口径**：stage1 strict_recall 0.864 / strict_acc 0.893 略高于 fixed5（0.811 / 0.847）——但 stage1 分母只剩 22 个确定判真（59 个 review 剔除），且其"判真"全部来自 `no_candidate_recheck` 复核通道（非裁决），小样本虚高，不代表归因更好。
- **决定性结论（支持 stage2 上线物优先）**：stage2（回收 dev 续训）在 87 段主测试集上把"裁决输出 100% invalid"修复为"100% 有效"，确定判定率从 32% 提升到 87%，保持 recall 1.000 / FPR 0.043。**paths.py 的 stage2 优先打分有据可依——回收续训直接决定了裁决任务能否工作。**
- 综合两个测试集：CVE-fix 真实集上 stage1 的"高 recall"同样是 invalid 假象（review 多不是保守而是判不了），stage2 在真实集上能通过复核通道确认 5 个 TP。**系统默认/论文主数据用 stage2（fixed5）结论不变且更稳。**
