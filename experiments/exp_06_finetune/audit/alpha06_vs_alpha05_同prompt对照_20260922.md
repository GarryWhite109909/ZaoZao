# α06 vs α05 同 prompt 对照（2026-09-22 复核）

> 触发：Garry 回忆「alpha06 出来时 87 测试集成绩好像还不错，但 CVE 很差，就去尝试优化 prompt 和其他方面，看是不是这个环境不适合 alpha06 发挥」。
> 结论：**记忆准确，且比他记的更细**——同 prompt 同组态下，α06 在 87 合成集持平、在两个真实面上一致退化 ~21pp。
> 数据来源：`experiments/exp_07_two_stage_eval/results/exp_07_*.json`（全部运行 `n_samples=3`、`no_candidate_mode=full_recheck`、`signal_feedback=True`，可横向比较）

## 一、干净对照：同一个 variant（`triage_train_aligned`）

α05 与 α06 都用 `triage_train_aligned` 跑过，这是唯一不受 prompt 变更干扰的对照：

| 测试集 | α05_stage2 | α06_stage2 | 差 |
|---|---|---|---|
| **87 合成** | 1.000 / FPR 0.048 / acc 0.987 ¹ | **1.000 / FPR 0.038 / acc 0.987** | **持平**（FPR 略优 0.010） |
| **真实 CVE 片段 20** | **0.941** | 0.722 | **−21.9 pp** |
| **真实完整文件 50（rolling_dev）** | **0.600** | 0.393 | **−20.7 pp** |

¹ α05 的 87 行取自 `exp_07_full87.local_alpha05_rerun.20260831`（04adapter 为空、variant=`triage_train_aligned`）。

**读法**：退化**只发生在真实面**，合成面持平 ⇒ 指向**泛化退化**，而不是"推理环境不适合 α06"。若是环境/推理问题，合成面应同步退化。

## 二、当时做的 prompt 补偿，效果有多大

α06 自身在不同 variant 间的对比（同模型、同组态）：

| 测试集 | `triage_train_aligned`（基线） | `triage_kp`（知识增补） | `triage_kp_a` |
|---|---|---|---|
| CVE-fix 20 | 0.722 | **0.867（+14.5 pp）** | 0.778 |
| rolling_dev 50 | 0.393 | 0.394（**≈ 无效**） | — |
| 87 合成 | 1.000 | 0.961 | 0.979 |

**读法**：
- prompt 补偿在 CVE 片段上**确实有效**（+14.5 pp），说明"入口不可见≠不可达"这类推理侧知识能补一部分；
- 但在**真实完整文件上完全无效**（0.393 → 0.394）——那类失败不是知识缺口，是长文件/切片场景下的判别漂移；
- 两个面都仍**低于 α05**（0.941 / 0.600）⇒ **prompt 补偿没有补齐缺口**。

## 三、代码里已有这次归因（不是我新发现的）

`graduation_project/prompts.py:795` 的 `_build_knowledge_supplement()` docstring（2026-09-18）原文写着：

> 背景：α06 在真实 CVE 集（cve_fix20 / rolling_dev50）二元召回大幅回退而 87 合成集持平。
> 归因（exp_07 alpha06 评测 + 训练数据审计）发现两个可由推理侧知识弥补的断点：
> 1. **v2_26 训练数据安全侧 22% 用"入口封闭/不可达"式论证（α05 仅 5%）**——模型在切片场景把"入口不可见"当"不可达"→ 无候选复核层判真 14→7 腰斩。

⇒ 团队当时已经定位到「**α06 的训据 v2_26 里"入口封闭"式论证占比从 α05 的 5% 涨到 22%**」这一条数据侧原因，并做了 prompt 侧补偿。本文件是把它的**量化对照**补齐。

## 四、α06 训练事实（`models/alpha06log/`）

| 项 | 值 |
|---|---|
| 训练时间 | 2026-09-17（日志 `train06_0917_1101.log`） |
| 训练数据 | **v2_26**（`train_log_cloud_r8_e2_lr0.0001_s42_rslora_alpha06_v2_26.json`） |
| 配置 | rsLoRA / r=8 / epoch=2 / lr=1e-4 / seed=42 |
| 收敛 | epoch 1.0 / global_step 1256 / train_loss 0.7373 / train_runtime 14,735 s（≈4.1 h） |
| 产物 | `models/adapter_alpha06_stage1`、`adapter_alpha06_stage2`（各 87 MB） |

## 五、若要继续追这条线，建议的下一步（未执行）

1. **同面重跑 α05 vs α06 的 `triage_kp`**（当前 α05 只有 `triage_train_aligned`）——把 prompt 这个变量也消掉，才能判断"知识增补对 α05 是否同样有效"；
2. **看 v2_26 与 alpha05 训据的"入口封闭式论证"占比差**（22% vs 5%）是怎么来的——是清洗/替换引入的，还是本来就如此；这直接决定"改 prompt"能不能替代"改数据"；
3. rolling_dev 上 α06 的 **FN 明细**（`fn_by_stage` + `fn_details`）已随每次运行落盘，可直接看是 stage1 零召回还是 stage2 否决占主导。

## 六、对交付的影响

**无**。产品实际用的适配器是 α05_stage2（`models/adapter_alpha05_stage2`，已随包）；发布的 Ollama 形态是 v9max。α06 **未接入产品**，只作为训练产物留在仓库、且**未随交付包**（`models/adapter_alpha06_*` 已在打包排除清单里）。
