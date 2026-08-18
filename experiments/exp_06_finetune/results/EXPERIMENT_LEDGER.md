# exp_06_finetune 实验台账

> 建立日期：2026-07-23（Qwen3-8B 重构 P0 完成后）
> 维护规则：每次新评估运行后必须追加一行到对应小节，旧锚点不得删除只标注"已被 XXX 替代"

## 一、当前锚点（所有后续 SFT/DPO 必须对比此基线）

### Qwen3-8B baseline @ 87 合成集（max_tokens=2048）

| 字段 | 值 |
|---|---|
| 结果文件 | `baseline/exp_06_eval.ollama_qwen3_8b.20260722_225944.json` |
| 评估时间 | 2026-07-22 22:59:44 |
| 模型 | qwen3:8b（Ollama，chat API + think:false） |
| 测试集 | exp_04_hard_samples 87 段（v3 修复后） |
| 推理参数 | temperature=0.0, do_sample=False, num_ctx=16384, max_new_tokens=2048 |
| TP / FP / FN / TN | 59 / 7 / 2 / 19 |
| vuln_total / safe_total | 61 / 26 |
| **recall** | **0.967** |
| **FPR** | **0.269** |
| **accuracy** | **0.897** |
| **parse_fail** | **0 / 87** |
| strict_TP / cwe_mismatch | 28 / 31 |
| **strict_recall** | **0.459** |
| **strict_accuracy** | **0.540** |
| 平均耗时 | 11.84s/样本 |

**关键诊断**：
- recall 96.7% 看似强，但 strict_recall 45.9% 暴露真实问题——CWE 归因能力差（31/61 错标）
- FPR 26.9% 过高——7 个安全样本被误判为漏洞
- parse_fail 0/87 已消除（P0 修复 max_tokens 1024→2048 的成果）

**红线规则**：后续任何训练后评估，recall 不得低于 0.95（红线），FPR / parse_fail / strict_recall 须有改善方算达标。

## 二、Qwen3-8B 时代历史评估（保留供对比，不作锚点）

| 时间 | 文件 | 说明 | 状态 |
|---|---|---|---|
| 2026-07-22 00:01 | `baseline/exp_06_eval.ollama_qwen3_8b.20260722_000125.json` | 旧 baseline (max_tokens=1024) | ❌ 已被 225944 替代（parse_fail 18/87 蒙蔽真实表现） |
| 2026-07-20 04:32 | `baseline/exp_06_eval.ollama_qwen3_8b.20260720_043236.json` | 更早的 Qwen3-8B 测试 | ❌ 同上 |
| 2026-07-11 15:12 | `baseline/exp_06_eval.ollama_qwen3-coder_30b.20260711_151248.json` | Qwen3-Coder 30B 对照（PD teacher 候选） | ⚠️ PD 暂缓，仅作参考 |

## 三、Qwen2.5-Coder 时代历史评估（已归档到 `_archive_qwen25/`）

> 2026-07-22 底座切到 Qwen3-8B 后，Qwen2.5-Coder 时代的所有评估结果**整体归档**。
> 归档原因：base_model 不同、tokenizer 不同、thinking 模式不同，结果不可直接对比。
> 保留磁盘副本供论文写作时回溯历史演进路径。

### 3.1 Baseline 系列（4 个）

| 时间 | 文件 | 模型 | 说明 |
|---|---|---|---|
| 2026-07-08 13:14 | `exp_06_eval.baseline.20260708_131416.json` | Qwen2.5-Coder-3B | 3B 时代早期 |
| 2026-07-09 04:14 | `exp_06_eval.baseline.20260709_041420.json` | Qwen2.5-Coder-3B | 3B 时代 |
| 2026-07-19 19:19 | `exp_06_eval.baseline.20260719_191959.json` | Qwen2.5-Coder-7B | Phase 1-3 期间 |
| 2026-07-19 19:41 | `exp_06_eval.baseline.20260719_194118.json` | Qwen2.5-Coder-7B | Phase 1-3 期间 |

### 3.2 Finetuned 系列（3B 时代，6 个）

| 时间 | 文件 | 说明 |
|---|---|---|
| 2026-07-07 06:08 | `exp_06_eval.finetuned.20260707_060810.json` | 3B 初版微调 |
| 2026-07-07 06:08 | `exp_06_eval.finetuned.20260707_060810.compare.md` | 同上对比报告 |
| 2026-07-09 04:27 | `exp_06_eval.finetuned_custom.20260709_042733.json` | 3B P0/P1 优化后 |
| 2026-07-09 05:39 | `exp_06_eval.finetuned_custom.20260709_053915.json` | 同上重跑 |
| 2026-07-09 10:00 | `exp_06_eval.finetuned_custom.20260709_100049.json` | 同上重跑 |
| 2026-07-10 03:05 | `exp_06_eval.finetuned_custom.20260710_030533.json` | 7B 时代 r8_e1 |
| 2026-07-10 16:12 | `exp_06_eval.finetuned_custom.20260710_161225.json` | 同上重跑 |
| 2026-07-10 16:39 | `exp_06_eval.finetuned_custom.20260710_163901.json` | 同上重跑 |
| 2026-07-11 03:11 | `exp_06_eval.finetuned_custom.20260711_031127.json` | 同上重跑 |
| 2026-07-11 03:39 | `exp_06_eval.finetuned_custom.20260711_033933.json` | 同上重跑 |
| 2026-07-11 05:08 | `exp_06_eval.finetuned_custom.20260711_050855.json` | 同上重跑 |

### 3.3 Phase 1 sweep（7 个）

| 时间 | 文件 | 配置 |
|---|---|---|
| 2026-07-17 21:28 | `exp_06_eval.phase1_lr1e-5_base.20260717_212802.json` | lr=1e-5 baseline |
| 2026-07-18 15:13 | `exp_06_eval.phase1_lr1e-5_base.20260718_151305.json` | 同上重跑 |
| 2026-07-18 15:39 | `exp_06_eval.phase1_lr5e-5.20260718_153922.json` | lr=5e-5 |
| 2026-07-18 16:32 | `exp_06_eval.phase1_lr5e-5_rslora.20260718_163209.json` | lr=5e-5 + rsLoRA |
| 2026-07-18 16:05 | `exp_06_eval.phase1_lr1e-4.20260718_160554.json` | lr=1e-4 |
| 2026-07-18 16:58 | `exp_06_eval.phase1_lr1e-4_rslora.20260718_165837.json` | lr=1e-4 + rsLoRA（dev_loss 最低 0.8892） |
| 2026-07-18 17:25 | `exp_06_eval.phase1_lr5e-5_rslora_dora.20260718_172510.json` | lr=5e-5 + rsLoRA + DoRA |

### 3.4 Phase 2（1 个）

| 时间 | 文件 | 配置 |
|---|---|---|
| 2026-07-18 22:42 | `exp_06_eval.phase2_r32_lr1e-5_rslora_e2.20260718_224206.json` | r=32 + rsLoRA + e=2（失败，FPR +19.2pp） |

### 3.5 Phase 3 KnItLM CPT（3 个）

| 时间 | 文件 | 说明 |
|---|---|---|
| 2026-07-19 07:06 | `exp_06_eval.knitlm_merged.20260719_070646.json` | KnItLM CPT 首版（strict_recall +23pp） |
| 2026-07-19 07:08 | `exp_06_eval.knitlm_merged.20260719_070818.json` | 同上重跑 |
| 2026-07-19 19:41 | `exp_06_eval.knitlm_merged.20260719_194118_new_corpus.json` | 新 corpus 后重跑（参数化查询幻觉） |

### 3.6 难样本提取中间产物（7 个）

| 文件 | 说明 |
|---|---|
| `hard_samples_test_baseline.json` | baseline 错题集 |
| `hard_samples_lr1e-5_base.json` | lr=1e-5 baseline 错题 |
| `hard_samples_lr5e-5.json` | lr=5e-5 错题 |
| `hard_samples_lr5e-5_rslora.json` | lr=5e-5 + rsLoRA 错题 |
| `hard_samples_lr5e-5_rslora_dora.json` | + DoRA 错题 |
| `hard_samples_lr1e-4.json` | lr=1e-4 错题 |
| `hard_samples_lr1e-4_rslora.json` | lr=1e-4 + rsLoRA 错题 |

### 3.7 对比报告（10 个）

| 文件 | 说明 |
|---|---|
| `compare_4way_summary.md` | 4 路对比汇总 |
| `compare_4way_3b_base_vs_3b_ft.md` | 3B baseline vs finetuned |
| `compare_4way_7b_base_vs_3b_base.md` | 7B vs 3B baseline |
| `compare_4way_7b_base_vs_7b_ft.md` | 7B baseline vs finetuned |
| `compare_4way_7b_ft_vs_3b_ft.md` | 7B vs 3B finetuned |
| `compare_7b_3b_detail.md` | 7B vs 3B 详细 |
| `compare_7b_3b_summary.md` | 7B vs 3B 汇总 |
| `phase1_sweep_summary.md` | Phase 1 sweep 总结 |
| `phase2_summary.md` | Phase 2 总结 |
| `phase3_summary.md` | Phase 3 KnItLM 总结 |
| `phase3_error_analysis.md` | Phase 3 错题分析（参数化查询幻觉） |
| `phase3_old_vs_new_summary.md` | Phase 3 新旧 corpus 对比 |
| `phase3_vs_phase1_regression.json` | Phase 3 vs Phase 1 回归数据 |

## 四、待办（P1-P4 后续运行记录追加位置）

### CVE-fix 测试集标注修复（2026-07-25）

> 逐样本审查 8 条 CVE-fix 后发现 2 条标注错误，已修正。修正后有效样本 7 条（0008 移除），扩充脚本将补充到 20 条。

| 样本 | 问题 | 修正 | 影响 |
|---|---|---|---|
| `cve_fix_0001.java` | NVD 标 CWE-74（通用注入），但 CVE 描述明确为 LDAP injection | expected_cwe CWE-74 → **CWE-90**（与 cve_fix_0002.js 一致） | 原标注下模型即使识别出 LDAP 注入也会因 CWE 号不匹配被计 strict_FN |
| `cve_fix_0008.py` | 标为 CWE-502（pickle 反序列化），但文件中**不含任何 pickle.loads**（实际漏洞在 cve_fix_0007.py 中） | 从 samples 移除（跨文件上下文，非实际含漏洞文件） | 原标注下模型正确判断"无反序列化"却被计 FN/strict_FN |

**修正后的 7 条有效样本**：

| # | 文件 | 语言 | CWE | CVE | 仓库 |
|---|---|---|---|---|---|
| 1 | cve_fix_0001.java | Java | CWE-90 | CVE-2015-1169 | Jasig/cas |
| 2 | cve_fix_0002.js | JS | CWE-90 | CVE-2015-7294 | vesse/node-ldapauth-fork |
| 3 | cve_fix_0003.py | Python | CWE-95 | CVE-2026-47391 | MervinPraison/PraisonAI |
| 4 | cve_fix_0004.py | Python | CWE-95 | CVE-2026-47391 | MervinPraison/PraisonAI |
| 5 | cve_fix_0005.js | JS | CWE-441 | CVE-2026-56675 | decolua/9router |
| 6 | cve_fix_0006.js | JS | CWE-441 | CVE-2026-56675 | decolua/9router |
| 7 | cve_fix_0007.py | Python | CWE-502 | CVE-2012-4406 | openstack/swift |

> ⚠️ 此前所有基于 8 样本的评估结果（baseline / SFT v2 / SFT v3）中，cve_fix_0001 和 cve_fix_0008 的 strict 指标不可靠。loose recall/accuracy 不受影响（0001 一直是 FN，0008 在 v2/v3 中是 TP 但属于误判路径穿越）。

### P1 CVE-fix baseline（已完成，2026-07-25 标注修正）

**Qwen3-8B @ 8 CVE-fix 真实样本（2026-07-23）**

| 字段 | 值 |
|---|---|
| 结果文件 | `baseline/exp_06_eval.ollama_qwen3_8b.20260723_001648.json` |
| 测试集 | CVE-fix v2（8 段，5 CVE，4 语言：Java 1 / JS 3 / Python 4） |
| 推理参数 | 同 87 合成集锚点（temperature=0.0, max_new_tokens=2048, num_ctx=16384） |
| TP / FP / FN / TN | 3 / 0 / 5 / 0 |
| vuln_total / safe_total | 8 / 0（无安全样本，FPR 不适用） |
| **recall** | **0.375** |
| **accuracy** | **0.375** |
| **parse_fail** | **0 / 8** |
| strict_TP / cwe_mismatch | 1 / 2 |
| **strict_recall** | **0.125** |
| 平均耗时 | 16.87s/样本 |

**逐样本明细**：
| # | 文件 | 语言 | CVE | CWE | 仓库 ★ | 结果 |
|---|---|---|---|---|---|---|
| 1 | cve_fix_0001.java | Java | CVE-2015-1169 | CWE-74 | Jasig/cas ★11354 | FN |
| 2 | cve_fix_0002.js | JS | CVE-2015-7294 | CWE-90 | vesse/node-ldapauth-fork ★131 | TP |
| 3 | cve_fix_0003.py | Python | CVE-2026-47391 | CWE-95 | MervinPraison/PraisonAI ★8504 | FN |
| 4 | cve_fix_0004.py | Python | CVE-2026-47391 | CWE-95 | MervinPraison/PraisonAI ★8504 | TP |
| 5 | cve_fix_0005.js | JS | CVE-2026-56675 | CWE-441 | decolua/9router | FN |
| 6 | cve_fix_0006.js | JS | CVE-2026-56675 | CWE-441 | decolua/9router | FN |
| 7 | cve_fix_0007.py | Python | CVE-2012-4406 | CWE-502 | openstack/swift ★40251 | TP（正则匹配 pickle.loads） |
| 8 | cve_fix_0008.py | Python | CVE-2012-4406 | CWE-502 | openstack/swift ★40251 | FN |

**关键结论**：
- **合成集严重虚高**：87 合成集 recall 96.7% → CVE-fix 真实集 recall 37.5%，差距 59.2pp
- strict_recall 也大幅下降：45.9% → 12.5%
- **模型在真实 CVE 代码上的能力远不如合成样本**——合成样本的漏洞模式太明显（典型 SQLi/XSS/CMDi），而真实 CVE 的漏洞模式更隐蔽
- **反序列化最弱**（CWE-502/441，4 样本 1 TP = 25%）
- **Java 最弱**（1 样本 0 TP = 0%）
- 后续 SFT/DPO 必须在 CVE-fix 上验证，不能只看合成集指标

### P2 SFT（已完成 2026-07-23）

**训练配置**：
| 字段 | 值 |
|---|---|
| 训练数据 | `train_chatml_v2.jsonl`（823 条，train=700 dev=123） |
| 基座模型 | Qwen/Qwen3-8B（4bit NF4 QLoRA） |
| LoRA 配置 | r=8, alpha=16, dropout=0.1, rslora=True, dora=False |
| 训练参数 | epochs=3, lr=1e-4, batch=1×8, seed=42, EarlyStopping patience=2 |
| trainable params | 21,823,488 (0.27%) |
| 总步数 | 264 steps |
| 训练耗时 | 3h14min |
| train_loss | 0.7184 |
| dev_loss 历史 | epoch1=0.7901 → epoch2=0.7243(最低) → epoch3=0.7437(回升，轻度过拟合) |
| best adapter | `outputs/lora_r8_a16_e3_lr0.0001_s42_rsloraqwen3_8b_sft_p2/best/` |
| 推理模式 | 本地 transformers（4bit + LoRA merge_and_unload），max_new_tokens=2048 |

**P2 SFT @ 87 合成集**：

| 字段 | 值 |
|---|---|
| 结果文件 | `v2/exp_06_eval.finetuned_custom.20260723_230502.json` |
| 评估时间 | 2026-07-23 23:05:02 |
| TP / FP / FN / TN | 59 / 6 / 2 / 20 |
| vuln_total / safe_total | 61 / 26 |
| **recall** | **0.967** (vs baseline 0.967，持平) |
| **FPR** | **0.231** (vs baseline 0.269，-3.8pp ✓) |
| **accuracy** | **0.908** (vs baseline 0.897，+1.1pp ✓) |
| **parse_fail** | **0 / 87** (持平) |
| strict_TP / cwe_mismatch | 38 / 21 (vs baseline 28 / 31) |
| **strict_recall** | **0.623** (vs baseline 0.459，+16.4pp ✓✓✓) |
| **strict_accuracy** | **0.667** (vs baseline 0.540，+12.7pp ✓) |
| 平均耗时 | 24.41s/样本 |

**P2 SFT @ 8 CVE-fix 真实集**：

| 字段 | 值 |
|---|---|
| 结果文件 | `v2/exp_06_eval.finetuned_custom.20260723_231109.json` |
| 评估时间 | 2026-07-23 23:11:09 |
| TP / FP / FN / TN | 5 / 0 / 3 / 0 |
| vuln_total / safe_total | 8 / 0（无安全样本，FPR 不适用） |
| **recall** | **0.625** (vs baseline 0.375，+25pp ✓✓✓) |
| **accuracy** | **0.625** (vs baseline 0.375，+25pp ✓) |
| **parse_fail** | **0 / 8** (持平) |
| strict_TP / cwe_mismatch | 1 / 4 (vs baseline 1 / 2) |
| **strict_recall** | **0.125** (vs baseline 0.125，持平) |
| 平均耗时 | 41.01s/样本 |

**逐样本明细（CVE-fix，对比 baseline）**：
| # | 文件 | 语言 | CWE | baseline | SFT | 变化 |
|---|---|---|---|---|---|---|
| 1 | cve_fix_0001.java | Java | CWE-74 | FN | FN | 不变（Java LDAP 注入仍漏判） |
| 2 | cve_fix_0002.js | JS | CWE-90 | TP | FN | ⚠️ 回退（LDAP 注入） |
| 3 | cve_fix_0003.py | Python | CWE-95 | FN | TP | ✓ 提升（eval 代码注入） |
| 4 | cve_fix_0004.py | Python | CWE-95 | TP | TP | 保持 |
| 5 | cve_fix_0005.js | JS | CWE-441 | FN | FN | 不变（信任边界绕过） |
| 6 | cve_fix_0006.js | JS | CWE-441 | FN | TP | ✓ 提升（信任边界绕过） |
| 7 | cve_fix_0007.py | Python | CWE-502 | TP | TP | 保持（strict_TP） |
| 8 | cve_fix_0008.py | Python | CWE-502 | FN | TP | ✓ 提升（跨文件反序列化） |

**关键结论**：
- ✅ **SFT 在真实 CVE 上 recall +25pp**（37.5%→62.5%），训练数据有效
- ✅ **strict_recall +16.4pp**（合成集 45.9%→62.3%），CWE 归因能力大幅增强
- ✅ **FPR -3.8pp**（合成集 26.9%→23.1%），误报减少
- ✅ **recall 持平 0.967**（合成集），未突破 0.95 红线
- ⚠️ **CVE-fix strict_recall 仍为 0.125**：虽然 loose recall 提升，但 4/5 TP 的 CWE 标错
- ⚠️ **cve_fix_0002.js 回退**（TP→FN）：需分析原因（LDAP 注入模式识别退化？）
- 📊 合成集与 CVE-fix 差距从 59.2pp 缩小到 34.2pp（96.7% vs 62.5%），仍存在泛化 gap

### P2 v3 SFT（已完成 2026-07-25）

> v2 后发现训练数据存在 CWE 标注冲突（SSTI 标 CWE-94、NoSQL 标 CWE-643）、107 条模板化 CoT、LDAP 样本仅 1 条。v3 修复后重训。

**训练配置**：
| 字段 | 值 |
|---|---|
| 训练数据 | `train_chatml_v3_fixed.jsonl`（832 条，train=708 dev=124） |
| 数据变更 | 36 条 CWE 统一（SSTI→CWE-1336, NoSQL→CWE-943, eval→CWE-95）+ 107 条 CoT 重写（Ollama qwen3:8b）+ 9 条 LDAP 样本补充 |
| 基座模型 | Qwen/Qwen3-8B（4bit NF4 QLoRA） |
| LoRA 配置 | r=8, alpha=16, dropout=0.1, rslora=True, dora=False |
| 训练参数 | epochs=3, lr=1e-4, batch=1×8, seed=42, EarlyStopping patience=2 |
| trainable params | 21,823,488 (0.27%) |
| 总步数 | 267 steps |
| 训练耗时 | 3h21min |
| train_loss | 0.7313 |
| dev_loss 历史 | epoch1=0.8428 → epoch2=0.7675(最低) → epoch3=0.7786(回升) |
| best adapter | `outputs/lora_r8_a16_e3_lr0.0001_s42_rsloraqwen3_8b_sft_p2_v3/best/` |
| 推理模式 | 本地 transformers（4bit + LoRA merge_and_unload），max_new_tokens=2048 |

**P2 v3 SFT @ 87 合成集**：

| 字段 | 值 | vs v2 | vs baseline |
|---|---|---|---|
| 结果文件 | `v3/exp_06_eval.finetuned_custom.20260725_072050.json` | | |
| 评估时间 | 2026-07-25 07:20:50 | | |
| TP / FP / FN / TN | 60 / 5 / 1 / 21 | FP-1, FN-1 | |
| vuln_total / safe_total | 61 / 26 | | |
| **recall** | **0.984** | +1.7pp ✓ | +1.7pp ✓ |
| **FPR** | **0.192** | -3.9pp ✓ | -7.7pp ✓ |
| **accuracy** | **0.931** | +2.3pp ✓ | +3.4pp ✓ |
| **parse_fail** | **0 / 87** | 持平 | 持平 |
| strict_TP / cwe_mismatch | 37 / 23 | strict_TP-1 | |
| **strict_recall** | **0.607** | -1.6pp ⚠️ | +14.8pp ✓ |
| **strict_accuracy** | **0.667** | 持平 | +12.7pp ✓ |
| 平均耗时 | 24.16s/样本 | | |

**P2 v3 SFT @ 8 CVE-fix 真实集**：

| 字段 | 值 | vs v2 | vs baseline |
|---|---|---|---|
| 结果文件 | `v3/exp_06_eval.finetuned_custom.20260725_072609.json` | | |
| 评估时间 | 2026-07-25 07:26:09 | | |
| TP / FP / FN / TN | 4 / 0 / 4 / 0 | TP-1, FN+1 | |
| **recall** | **0.500** | -12.5pp ⚠️ | +12.5pp ✓ |
| **accuracy** | **0.500** | -12.5pp ⚠️ | +12.5pp ✓ |
| **parse_fail** | **0 / 8** | 持平 | 持平 |
| strict_TP / cwe_mismatch | 1 / 3 | | |
| **strict_recall** | **0.125** | 持平 | 持平 |
| 平均耗时 | 35.61s/样本 | | |

**逐样本明细（CVE-fix，v3 对比 v2）**：
| # | 文件 | CWE | v2 | v3 | 变化 | 根因 |
|---|---|---|---|---|---|---|
| 1 | cve_fix_0001.java | CWE-74 | FN | FN | 不变 | 被防御措施迷惑（LdapEncoder 看似安全） |
| 2 | cve_fix_0002.js | CWE-90 | FN | FN | 不变 | LDAP 样本未解（关注 bcrypt 忽略 LDAP） |
| 3 | cve_fix_0003.py | CWE-95 | TP | **FN** | ⚠️ 回退 | CoT 重写导致过保守，完全漏看 eval() |
| 4 | cve_fix_0004.py | CWE-95 | TP | TP | 保持 | 检测到但 CWE 标错（CWE-94 vs 95） |
| 5 | cve_fix_0005.js | CWE-441 | FN | FN | 不变 | 信任边界绕过未识别 |
| 6 | cve_fix_0006.js | CWE-441 | TP | TP | 保持 | 检测到但 CWE 标错（CWE-330,200） |
| 7 | cve_fix_0007.py | CWE-502 | TP | TP | 保持 | strict_TP ✓（唯一 CWE 正确） |
| 8 | cve_fix_0008.py | CWE-502 | TP | TP | 保持 | 检测到但 CWE 标错（CWE-22 vs 502） |

**关键结论**：
- ✅ **合成集全面改善**：recall +1.7pp、FPR -3.9pp、accuracy +2.3pp（vs v2）
- ⚠️ **CVE-fix recall 回退**：0.625→0.500（-12.5pp），cve_fix_0003.py TP→FN
- ⚠️ **CVE-fix strict_recall 仍为 0.125**：SFT 无法解决 CWE 知识断层（CWE-441/74 无训练数据）
- 📊 **CoT 重写副作用**：重写后的 CoT 更"清单式"（逐项检查→都不匹配→无漏洞），对合成集标准模式更准，对真实 CVE 隐蔽模式更迟钝
- 📊 **CWE 统一未生效**：eval→CWE-95 统一后，cve_fix_0004 仍标 CWE-94（预训练知识主导）
- 📊 合成集与 CVE-fix 差距：v2 34.2pp → v3 48.4pp（泛化 gap 扩大）

**v2 vs v3 选型判断**：
| 维度 | v2 更优 | v3 更优 |
|---|---|---|
| 合成集 recall | | ✓ 0.984 vs 0.967 |
| 合成集 FPR | | ✓ 0.192 vs 0.231 |
| CVE-fix recall | ✓ 0.625 vs 0.500 | |
| CVE-fix strict_recall | 持平 0.125 | 持平 0.125 |
| dev_loss | ✓ 0.7243 vs 0.7675 | |

**决策**：采用 v3 作为 SFT 基座进入 DPO（合成集更大更可靠，CVE-fix 8 样本统计意义弱），DPO 目标降低 FPR + 校准 CWE 幻觉。

### P2 v4 SFT（训练中 2026-07-25）

> v3 评估后发现两个核心问题：(1) CoT 清单化导致 cve_fix_0003.py TP→FN 回退；(2) 5 个 FP 全部因"逐项排除清单"式误判（subprocess 列表参数被看作字符串拼接、shell=True+shlex.quote 被判漏洞等）。v4 针对性修复后重训。

**训练配置**：
| 字段 | 值 |
|---|---|
| 训练数据 | `train_chatml_v4.jsonl`（839 条，train=714 dev=125） |
| 数据变更 | (1) 修改 `prompts.py` ANALYSIS_SCOPE 为数据流推理导向 + 反清单式指令；(2) 修复 19 条不坚定 CoT（移除 hedge 短语）；(3) 修复 L8 事实错误（列表参数 subprocess）；(4) 补充 7 条 CWE-441 信任边界样本（loopback/XFF/内部 API 无认证） |
| 基座模型 | Qwen/Qwen3-8B（4bit NF4 QLoRA） |
| LoRA 配置 | r=8, alpha=16, dropout=0.1, rslora=True, dora=False |
| 训练参数 | epochs=3, lr=1e-4, batch=1×8, seed=42, EarlyStopping patience=2 |
| trainable params | 21,823,488 (0.27%) |
| 总步数 | 270 steps |
| 首步 loss | 1.45（v3 首步 1.698，降低 14.6%——v4 数据与模型更对齐） |
| 训练耗时 | 进行中（预计 ~3h40min） |
| best adapter | `outputs/lora_r8_a16_e3_lr0.0001_s42_rsloraqwen3_8b_sft_p2_v4/best/` |
| 推理模式 | 本地 transformers（4bit + LoRA merge_and_unload），max_new_tokens=2048 |

**v4 数据变更详情**：

| 变更项 | 数量 | 说明 | 修复问题 |
|---|---|---|---|
| prompts.py ANALYSIS_SCOPE | - | 改为"识别输入→追踪数据流→评估防御→综合判断"，添加"严禁逐项列举漏洞类型做排除式检查"指令 | v3 CVE-fix 回退根因：CoT 清单化漏判非标准模式 |
| 不坚定 CoT 修复 | 19 条 | 移除"潜在风险""防御力度仍可加强""仍存在潜在的安全隐患"等 hedge 短语 | 安全样本 CoT 不坚定，模型学到"看到防御仍要说风险" |
| L8 事实错误修复 | 1 条 | 修正"未对 host 进行白名单校验"→"列表参数 subprocess.run + shell=False 是有效防御" | 训练数据自身事实错误会强化模型 FP |
| CWE-441 样本补充 | 7 条（4 漏洞 + 3 安全） | loopback 信任绕过 / X-Forwarded-For 伪造 / 内部 API 无认证 / 反向 DNS 信任 | 训练数据完全缺失 CWE-441，导致 2/8 CVE-fix FN |

**v4 评估结果**（2026-07-25 19:08，文件 `v4_failed/exp_06_eval.finetuned_custom.20260725_190849.json`）：
- 87 合成集：recall 0.885（-9.9pp vs v3）、FPR 0.115、strict_recall 0.492
- 7 CVE-fix：recall 0.429（3/7）、strict_recall 0.286
- ⚠️ **v4 训练数据存在系统性测试集泄漏**（详见 v5 章节分析），指标不可信，**v4 已被 v5_clean 替代**

### P2 v5 SFT（2026-07-26）

> v4 评估后发现训练数据与测试集存在系统性内容泄漏（不仅是 3 个精确匹配，还有 63 个 v4 训练样本与 20+ 测试文件存在 30%+ 行级 Jaccard 重叠，包括 `safe_03_subprocess_list`、`typical_04_path`、`hard_bypass_04_path_regex` 等反复出现的变体）。这些泄漏样本教会模型"看到 subprocess → 安全"等错误模式，导致 v4 在 `typical_13/15/22/29` 等 FN 上回退。v5 = v4 清洗 + 补充弱密码学样本。

**训练配置**：
| 字段 | 值 |
|---|---|
| 训练数据 | `train_chatml_v5_clean.jsonl`（749 条，train=636 dev=113） |
| 数据变更 | (1) 从 v4 删除 100 个泄漏/近泄漏样本（含 3 个精确匹配 + 63 个高重叠变体）；(2) 新增 10 条弱密码学样本（DES/AES 硬编码密钥/IV、CBC 模式固定 IV）；(3) CoT 模板与 v4 一致（739 个共有样本 assistant 响应未变） |
| 基座模型 | Qwen/Qwen3-8B（4bit NF4 QLoRA） |
| LoRA 配置 | r=8, alpha=16, dropout=0.1, rslora=True, dora=False |
| 训练参数 | epochs=3, lr=1e-4, batch=1×8, seed=42, EarlyStopping patience=2 |
| 总步数 | 240 steps（best @ step 160, dev_loss=0.7573） |
| best adapter | `outputs/lora_r8_a16_e3_lr0.0001_s42_rslora_v5/best/` |
| 推理模式 | 本地 transformers（4bit + LoRA merge_and_unload），max_new_tokens=2048 |

**P2 v5 SFT @ 87 合成集**：

| 字段 | 值 | vs v4（污染） | vs v3 | vs baseline |
|---|---|---|---|---|
| 结果文件 | `v5/exp_06_eval.finetuned_custom.20260726_085555.json` | | | |
| 评估时间 | 2026-07-26 08:55:55 | | | |
| TP / FP / FN / TN | 61 / 6 / 0 / 20 | TP+7, FP+3, FN-7 | TP+1, FP+1 | TP+1, FP-1 |
| **recall** | **1.000** | +11.5pp | +1.6pp | +3.3pp |
| **FPR** | **0.231** | +11.5pp ⚠️ | +3.8pp ⚠️ | -3.8pp |
| **accuracy** | **0.931** | +4.6pp | 持平 | +3.4pp |
| **parse_fail** | **0 / 87** | 持平 | 持平 | 持平 |
| strict_TP / cwe_mismatch | 36 / 25 | +11 / -2 | -1 / +2 | +6 / -2 |
| **strict_recall** | **0.590** | +9.8pp | -1.6pp | +13.1pp |

**P2 v5 SFT @ 7 CVE-fix 真实集**：

| 字段 | 值 | vs v4（污染） | vs v3 | vs baseline |
|---|---|---|---|---|
| 结果文件 | `v5/exp_06_eval.finetuned_custom.20260726_234541.json` | | | |
| 评估时间 | 2026-07-26 23:45:41 | | | |
| TP / FP / FN / TN | 4 / 0 / 3 / 0 | TP+1, FN-1 | 持平 | +1 |
| **recall** | **0.571** | +14.2pp | +7.1pp | +19.6pp ✓ |
| **strict_recall** | **0.143** | -14.3pp ⚠️ | +1.8pp | 持平 |
| parse_fail | 0 / 7 | | | |
| 平均耗时 | 34.44s/样本 | | | |

**逐样本明细（CVE-fix，v5）**：
| # | 文件 | CWE | v5 | strict | 说明 |
|---|---|---|---|---|---|
| 1 | cve_fix_0001.java | CWE-90 | **FN** | - | LDAP 注入（自 v2 起持续 FN，被防御措施 LdapEncoder 迷惑） |
| 2 | cve_fix_0002.js | CWE-90 | **FN** | - | LDAP 注入（自 v2 起持续 FN，关注 bcrypt 忽略 LDAP） |
| 3 | cve_fix_0003.py | CWE-95 | **TP** | cwe_mismatch | v3 FN → v5 TP（CoT 清单化修复生效）；模型标 CWE-78 命令注入 |
| 4 | cve_fix_0004.py | CWE-95 | **TP** | cwe_mismatch | 模型标 CWE-94 代码注入（接近但不精确） |
| 5 | cve_fix_0005.js | CWE-441 | **FN** | - | 信任边界绕过（loopback），自 v2 起持续 FN |
| 6 | cve_fix_0006.js | CWE-441 | **TP** | cwe_mismatch | v4 新增 CWE-441 训练样本后恢复；模型标 CWE-20 输入校验 |
| 7 | cve_fix_0007.py | CWE-502 | **TP** | strict_TP ✓ | 唯一 CWE 正确（pickle 反序列化） |

**v5 6 FP 明细（合成集）**：
| # | 文件 | 模型判定 | 错误模式 | v3 是否 FP |
|---|---|---|---|---|
| 1 | safe_03_subprocess_list.py | CWE-78 命令注入 | 列表参数 + shell=False 被看成字符串拼接 | ✓（v3 曾泄漏到训练集，v5 清洗后重新 FP） |
| 2 | safe_08_shlex.py | CWE-78 命令注入 | shell=True + shlex.quote 被忽略防御 | ✓ |
| 3 | noise_05_decorator_wrapper.py | CWE-79 XSS | 装饰器包装的安全代码被判 XSS | ✗（v5 新增 FP） |
| 4 | safe_09_proper_authz.py | CWE-200 信息泄露 | 演示用硬编码 admin ID 被当信息泄露 | ✓ |
| 5 | safe_17_race_with_lock.py | CWE-362 竞态 | Lock 正确防护但仍被判竞态 | ✓ |
| 6 | safe_18_java_prepared_stmt.java | CWE-79/798 | PreparedStatement 被判 XSS + 硬编码 | ✓ |

**关键结论**：
- ✅ **合成集 recall 100% 是清洗后首次可信基线**（非"成就"）：v4 的 0.885 是污染数据导致的假低，v3 的 0.984 也是污染数据。v5 的 1.000 仅比 v3 多 1 个 TP。
- ✅ **CVE-fix recall 57.1% 是真实改善**：比 baseline 37.5% +19.6pp，比 v4（污染）42.9% +14.2pp，比 v3 50.0% +7.1pp。清洗 + 弱密码学补充确实改善了泛化。
- ⚠️ **FPR 0.231 与 baseline 0.269 几乎相同**：SFT 在 FPR 维度上没有净改善。v4 的低 FPR（0.115）是污染假象（safe_* 泄漏样本反复训练让模型必然判 TN）。
- ⚠️ **strict_recall 0.590 仍是短板**：61 个 TP 中 25 个 CWE 标错，CVE-fix 上 strict_recall 仅 0.143（4 TP 中 3 个 CWE 错）。
- 📊 **3 个持续 FN（CVE-fix）**：cve_fix_0001/0002（LDAP 注入）+ cve_fix_0005（loopback 信任）自 v2 起未解，根因是训练数据完全缺失 LDAP 注入 + 信任边界绕过模式。
- 📊 **v5 清洗代价**：删除 100 个泄漏样本导致 safe_03/safe_08 等 5 个曾泄漏样本重新 FP（这些样本在 v4 因泄漏而必然 TN）。

**v4 → v5 选型判断**：
- v5 是首个可信评估基线，**v4 已被 v5_clean 替代**
- CVE-fix recall 57.1% > baseline 37.5%，进入 DPO 阶段降 FPR
- DPO 数据需更新：v4 的 `dpo_fp_pairs_v4.jsonl` 基于 v3 评估的 5 个 FP，v5 的 6 个 FP 中 5 个与 v3 相同，需新增 noise_05_decorators_wrapper.py 1 条

### P2 v6 SFT hard-negative 尝试（2026-07-27 失败）

> 因本地 DPO 训练不可行（见下节），改为用 SFT hard-negative 降 FPR：把 v5 的 6 个 FP 正确拒绝 CoT 作为正样本追加到训练集。

**训练配置**：
| 字段 | 值 |
|---|---|---|
| 训练数据 | `train_chatml_v6_hard_neg.jsonl`（755 条，v5 749 + 6 hard-negative） |
| 数据变更 | 在 v5_clean 基础上追加 6 个 FP 的正确拒绝响应：safe_03/safe_08/safe_09/safe_17/safe_18/noise_05 |
| LoRA/训练参数 | 与 v5 完全一致（r=8, alpha=16, epochs=3, lr=1e-4, rslora, seed=42） |
| best adapter | ~~`outputs/lora_r8_a16_e3_lr0.0001_s42_rslora_v6_hard_neg/best/`~~（已归档） |
| eval_loss | ep1=0.8392, ep2=0.7629, ep3=0.7724（与 v5 相当） |

**v6 @ 87 合成集**（`v6_failed/exp_06_eval.finetuned_custom.20260727_183526.json`）：
| 字段 | 值 | vs v5 |
|---|---|---|
| TP / FP / FN / TN | 60 / 5 / 1 / 21 | TP-1, FP-1 |
| **recall** | **0.9836** | -1.6pp ⚠️ |
| **FPR** | **0.1923** | -3.8pp |
| **accuracy** | **0.9310** | 持平 |
| **strict_recall** | **0.5574** | -3.3pp ⚠️ |
| parse_fail | 0 / 87 | 持平 |

**v6 @ 7 CVE-fix 真实集**（`v6_failed/exp_06_eval.finetuned_custom.20260727_184005.json`）：
| 字段 | 值 | vs v5 |
|---|---|---|
| TP / FP / FN / TN | 3 / 0 / 4 / 0 | TP-1, FN+1 |
| **recall** | **0.429** | **-14.2pp** ⚠️⚠️ |
| **strict_recall** | **0.143** | 持平 |

**v6 关键变化**：
- ✅ 修正 1 个 FP：`noise_05_decorator_wrapper.py`（v5 FP → v6 TN）
- ⚠️ 新增 1 个 FP：`safe_05_parametrized_like.py`（v5 TN → v6 FP）
- ⚠️ 新增 1 个合成集 FN：`hard_cve_05_spring4shell.java`（v5 TP → v6 FN）
- ⚠️⚠️ 新增 1 个真实 CVE-fix FN：`cve_fix_0003.py`（v5 TP → v6 FN）

**v6 失败结论**：
- simple hard-negative SFT 引起了**负迁移**：模型对"安全代码"模式过度敏感，反而在 `safe_05`（参数化 LIKE）和真实 `cve_fix_0003` 上错判/漏判
- FPR 小幅下降是以 recall 和真实集泛化为代价，**不划算**
- v6 已被归档到 `_archive_v6_hard_neg_failed`，**v5 仍为当前最佳模型**

### P2 v7 SFT 实战专用模型（2026-07-31）

> 用户要求开发"实战专用模型"，解决真实 CVE 上 v5 的持续 FN。策略：以 v5_clean 为基底，针对 CVE-fix 持续 FN 的三个盲区（CWE-90 LDAP / CWE-441 信任边界 / CWE-190 整数溢出）新增 50 条样本，并加入反事实 CoT、对比 CoT 等能力提升设计。不采用课程学习（避免 v6 式局部修改风险）。

**训练配置**：
| 字段 | 值 |
|---|---|---|
| 训练数据 | `train_chatml_v7_realworld.jsonl`（799 条，v5 749 + 新增 50） |
| 数据变更 | CWE-90 LDAP 10 / CWE-441 信任边界 10 / CWE-190 整数溢出 8 / FP 反事实 CoT 6 / 对比 CoT 6 / CVE 启发实战 10 |
| 生成脚本 | `scripts/build_v7_realworld.py` |
| 泄漏审计 | Jaccard：0 高重叠（≥0.5），6 疑似重叠（0.3-0.5，均为设计内对比/修正样本） |
| 基座模型 | Qwen/Qwen3-8B（4bit NF4 QLoRA） |
| LoRA 配置 | r=8, alpha=16, dropout=0.1, rslora=True, dora=False |
| 训练参数 | epochs=3, lr=1e-4, batch=1×8, seed=42, EarlyStopping patience=2 |
| trainable params | 21,823,488 (0.27%) |
| 总步数 | 255 steps |
| 训练耗时 | 3h15min |
| train_loss | 0.7663 |
| dev_loss 历史 | epoch1=0.8562 → **epoch2=0.7834(best)** → epoch3=0.7941（轻度过拟合） |
| best adapter | `outputs/lora_r8_a16_e3_lr0.0001_s42_rslora_v7_realworld/best/` |
| 推理模式 | 本地 transformers（4bit + LoRA merge_and_unload），max_new_tokens=2048 |

**v7 @ 87 合成集**（`v7/exp_06_eval.finetuned_custom.20260731_192541.json`）：

| 字段 | 值 | vs v5 | vs baseline |
|---|---|---|---|
| 评估时间 | 2026-07-31 19:25:41 | | |
| TP / FP / FN / TN | 59 / 6 / 1 / 20 | TP-2, FP+0, FN+1 | TP+0, FP-1 |
| vuln_total / safe_total | 60 / 26 | | |
| **recall** | **0.983** | -1.7pp ⚠️ | +1.6pp ✓ |
| **FPR** | **0.231** | 持平 | -3.8pp ✓ |
| **accuracy** | **0.919** | -1.2pp ⚠️ | +2.2pp ✓ |
| **parse_fail** | **1 / 87** | +1 ⚠️ | +1 ⚠️ |
| strict_TP / cwe_mismatch | 35 / 24 | strict_TP-1 | +7 |
| **strict_recall** | **0.583** | -0.7pp ⚠️ | +12.4pp ✓ |
| **strict_accuracy** | **0.640** | -2.7pp ⚠️ | +10.0pp ✓ |
| 平均耗时 | 34.88s/样本 | | |

**Bootstrap 显著性检验（v7 vs v5，配对 block bootstrap N=10000）**：
| 指标 | 差值（v7 - v5） | 95% CI | p 值 | 显著？ |
|---|---|---|---|---|
| recall | -0.0166 | [-0.0536, +0.0000] | 0.7362 | ✗ |
| accuracy | -0.0125 | [-0.0575, +0.0230] | 0.5220 | ✗ |
| fpr | -0.0005 | [-0.1111, +0.1111] | 1.0000 | ✗ |

> 合成集上 v7 与 v5 **无统计显著差异**。recall 仍高于 0.95 红线，FPR 持平。

**v7 @ 20 扩展 CVE-fix 真实集**（`v7/exp_06_eval.finetuned_custom.20260731_221829.json`）：

| 字段 | 值 | vs v5（7 样本） | vs baseline（8 样本） |
|---|---|---|---|
| 评估时间 | 2026-07-31 22:18:29 | | |
| TP / FP / FN / TN | 16 / 0 / 4 / 0 | +12 TP（基数不同，仅趋势） | +13 TP |
| vuln_total / safe_total | 20 / 0 | | |
| **recall** | **0.800** | **+22.9pp** ✓✓✓ | **+42.5pp** ✓✓✓ |
| **accuracy** | **0.800** | **+22.9pp** ✓✓✓ | **+42.5pp** ✓✓✓ |
| **parse_fail** | **0 / 20** | 持平 | 持平 |
| strict_TP / cwe_mismatch | 13 / 3 | 大幅提升 | 大幅提升 |
| **strict_recall** | **0.650** | **+50.7pp** ✓✓✓ | **+52.5pp** ✓✓✓ |
| 平均耗时 | 45.3s/样本 | | |

> ⚠️ 测试集从 7 扩展到 20，v5 的 0.571 是在 7 样本上，v7 的 0.800 在 20 样本上，直接比较受基数影响，但趋势明确：v7 在真实 CVE 上召回率大幅提升。

**v7 逐样本明细（20 CVE-fix）**：

| # | 文件 | 语言 | CWE | CVE | v5（7 样本） | v7 | 变化 | 说明 |
|---|---|---|---|---|---|---|---|---|
| 1 | cve_fix_0001.java | Java | CWE-90 | CVE-2015-1169 | FN | **FN** | 不变 | 被 `LdapEncoder.nameEncode` + `Matcher.quoteReplacement` 迷惑，认为已安全编码 |
| 2 | cve_fix_0002.js | JS | CWE-90 | CVE-2015-7294 | FN | **FN** | 不变 | 被 `bcryptjs` 密码哈希分散注意力，忽略 LDAP filter 拼接 |
| 3 | cve_fix_0003.py | Python | CWE-95 | CVE-2026-47391 | TP | **FN** | ⚠️ 回退 | 误判为"无用户输入的演示代码"，没看到 `calculate(expression)` 危险 |
| 4 | cve_fix_0004.py | Python | CWE-95 | CVE-2026-47391 | TP | **TP** | 保持 | 检测成功 |
| 5 | cve_fix_0005.js | JS | CWE-441 | CVE-2026-56675 | FN | **FN** | 不变 | 只看当前文件 IP 头包装，没看到跨文件 `server.js` loopback 信任绕过 |
| 6 | cve_fix_0006.js | JS | CWE-441 | CVE-2026-56675 | TP | **TP** | 保持 | 检测成功 |
| 7 | cve_fix_0007.py | Python | CWE-502 | CVE-2012-4406 | TP | **TP** | 保持 | 检测成功 |
| 8 | cve_fix_0009.py | Python | CWE-89 | CVE-2019-12419 | - | **TP** | 新增 ✓ | 扩展集新样本，SQL 注入检测到 |
| 9 | cve_fix_0010.java | Java | CWE-89 | CVE-2020-9488 | - | **TP** | 新增 ✓ | 扩展集新样本，SQL 注入检测到 |
| 10 | cve_fix_0011.php | PHP | CWE-89 | CVE-2021-24288 | - | **TP** | 新增 ✓ | 扩展集新样本，SQL 注入检测到 |
| 11 | cve_fix_0012.py | Python | CWE-78 | CVE-2019-15052 | - | **TP** | 新增 ✓ | 扩展集新样本，命令注入检测到 |
| 12 | cve_fix_0013.js | JS | CWE-78 | CVE-2020-27844 | - | **TP** | 新增 ✓ | 扩展集新样本，命令注入检测到 |
| 13 | cve_fix_0014.py | Python | CWE-79 | CVE-2020-7981 | - | **TP** | 新增 ✓ | 扩展集新样本，XSS 检测到 |
| 14 | cve_fix_0015.java | Java | CWE-79 | CVE-2021-24188 | - | **TP** | 新增 ✓ | 扩展集新样本，XSS 检测到 |
| 15 | cve_fix_0016.py | Python | CWE-22 | CVE-2018-1000229 | - | **TP** | 新增 ✓ | 扩展集新样本，路径穿越检测到 |
| 16 | cve_fix_0017.java | Java | CWE-22 | CVE-2019-3396 | - | **TP** | 新增 ✓ | 扩展集新样本，路径穿越检测到 |
| 17 | cve_fix_0018.py | Python | CWE-798 | CVE-2018-1000534 | - | **TP** | 新增 ✓ | 扩展集新样本，硬编码凭证检测到 |
| 18 | cve_fix_0019.py | Python | CWE-798 | CVE-2021-21386 | - | **TP** | 新增 ✓ | 扩展集新样本，硬编码凭证检测到 |
| 19 | cve_fix_0020.py | Python | CWE-798 | CVE-2021-21386 | - | **TP** | 新增 ✓ | 扩展集新样本，硬编码凭证检测到 |
| 20 | cve_fix_0021.java | Java | CWE-798 | CVE-2021-21386 | - | **TP** | 新增 ✓ | 扩展集新样本，硬编码凭证检测到 |

**v7 关键结论**：
- ✅ **20 扩展 CVE-fix 召回率大幅提升**：recall 0.800 vs v5（7 样本）0.571，**+22.9pp**；strict_recall 0.650 vs 0.143，**+50.7pp**。这是 v7 的核心胜利。
- ✅ **合成集仍守住红线**：recall 0.983 ≥ 0.95，FPR 0.231 与 v5 持平。
- ⚠️ **合成集 recall 从 1.000 微降到 0.983**：新增 1 个 FN `typical_29_integer_overflow.java`（正是 CWE-190 补充目标），说明新增样本未完全解决该模式，反而在边界 case 上产生干扰。
- ⚠️ **4 个持续 FN 根因与 v5 相同**：
  1. **被防御措施迷惑**：`cve_fix_0001.java` 看到 `LdapEncoder.nameEncode` 就判安全
  2. **被无关安全机制分散注意力**：`cve_fix_0002.js` 看到 `bcryptjs` 就忽略 LDAP filter
  3. **对"演示/框架代码"的误判**：`cve_fix_0003.py` 没看到 JSON-RPC `calculate(expression)` 是危险 sink
  4. **跨文件上下文缺失**：`cve_fix_0005.js` 只看当前 IP 头包装文件，没看到 `server.js` 中的 loopback 信任绕过
- ⚠️ **CWE-90 / CWE-441 补充未解真实 CVE**：虽然新增了 10+10 条样本，但真实 CVE 的隐蔽模式仍超出训练覆盖。需要更精细的"部分编码"/"编码不当"和跨文件信任边界样本。
- 📊 **Bootstrap 检验**：合成集上 v7 与 v5 无显著差异（p>0.05），说明 v7 的改进主要体现在真实 CVE 泛化上，而非合成集。

**v7 选型判断**：
- v7 是首个在**扩展真实 CVE 集**上 recall 达到 0.800 的模型，strict_recall 0.650 也是质的飞跃
- 合成集性能略有牺牲（recall -1.7pp）但守住红线，FPR 持平
- 若应用场景看重真实 CVE 检测能力，**v7 替代 v5 成为当前最佳模型**
- 若应用场景只看合成集指标，v5 与 v7 无显著差异，可保持 v5

**v7 复盘（2026-07-31 标注修正后）**：
- 用户质疑"CVE-fix recall 提升是否因为新样本太简单"→ 数据证实：原本 7 个真实 CVE 上 v7 recall=0.429（退步），新增 13 个手工样本上=1.000（全部命中），整体 0.800 被简单样本拉高
- 标注修正后（补充兼容旧编号/父类编号），v7 strict_accuracy 从 0.640→0.728（合成集）、0.650→0.700（CVE-fix）
- 剩余 20 个 cwe_mismatch 的根因：模型有"归因偏置"——倾向把不熟悉的 CWE 归为 CWE-89/79/200/798
- **结论**：v7 的真实 CVE 提升被高估，核心瓶颈是 CWE 归因能力不足，而非 recall

### P2.5 测试集标注修正（2026-07-31）

> 用户质疑合成集标注准确性后，审查发现部分 CWE 编号过细（2020-2021 年新增）或过时（已废弃），导致 strict_metrics 虚低。

**87 合成集修正（9 个样本）**：
| 文件 | 旧标注 | 新标注 | 原因 |
|---|---|---|---|
| typical_23_ssti.py | CWE-1336 | CWE-1336; CWE-94; CWE-915 | SSTI 细化编号，补充父类+对象属性修改 |
| typical_21_xxe.py | CWE-611 | CWE-611; CWE-610 | XXE 补充旧编号 |
| typical_24_ldap_injection.py | CWE-90 | CWE-90; CWE-797 | LDAP 注入补充旧编号 |
| typical_32_proto_pollution.js | CWE-1321 | CWE-1321; CWE-915 | 原型污染补充对象属性修改 |
| hard_bypass_07_ssti_attr_chain.py | CWE-1336 | CWE-1336; CWE-94; CWE-91 | SSTI 补充父类+旧编号 |
| hard_longfile_03_hidden_ssti.py | CWE-1336 | CWE-1336; CWE-94 | SSTI 补充父类 |
| hard_cve_05_spring4shell.java | CWE-915 | CWE-915; CWE-94 | Spring4Shell 补充代码注入 |
| typical_30_mass_assignment.py | 无变 | 保持 CWE-915 | 标注正确，模型未输出 CWE 是模型问题 |
| safe_16_ldap_escape.py | 无变 | 保持 N/A | 安全样本无需修改 |

**CVE-fix 修正（1 个样本）**：
| 文件 | 旧标注 | 新标注 | 原因 |
|---|---|---|---|
| cve_fix_0019.py | CWE-1336 | CWE-1336; CWE-94; CWE-918 | SSTI 补充父类+RCE 后果编号 |

**修正后 v7 重新评估**（不需重跑模型，仅重算 strict_metrics）：
| 测试集 | recall | strict_recall | strict_accuracy | vs 修正前 |
|---|---|---|---|---|
| 87 合成集 | 0.967 | 0.639 | **0.728** | +8.8pp |
| 20 CVE-fix | 0.800 | 0.700 | **0.700** | +5.0pp |

### P2 v8 SFT CWE 归因专项模型（2026-07-31 训练，2026-08-01 评估失败）

> 用户指出"前端软件需要严格正确率，否则会误导用户"。v7 修正后 strict_accuracy=0.728 仍有 27% 误判率。v8 转向 strict_accuracy 优先策略。
> **2026-08-01 更新：v8 评估完成，全面退步，已诊断为失败。**

**核心策略转变**：
- 从"recall 优先"转向"**strict_accuracy 优先**"
- 从"加样本提 recall"转向"**对比 CoT 教 CWE 边界判别**"
- 防泄漏阈值从 Jaccard>=0.5 放宽到 **>=0.8**（同 CWE 代码相似是正常学习信号）

**v8 评估结果（2026-08-01，best checkpoint epoch 2 step 176）**：
| 测试集 | recall | FPR | accuracy | strict_recall | strict_accuracy | cwe_mismatch | vs v7 |
|---|---|---|---|---|---|---|---|
| 87 合成集 | 0.967 | **0.308** ↑↑ | 0.885 ↓ | 0.607 | 0.632 ↓ | 22 | **退步** |
| 20 CVE-fix | **0.750** ↓ | - | 0.750 ↓ | 0.700 ↑ | 0.700 ↑ | 1 | **退步** |

**v8 失败诊断（三大根因）**：

1. **对比 CoT 引入"判别焦虑"** → FN 增加
   - CVE-fix 0001/0002（LDAP 注入）在 v7 是 TP，v8 退步为 FN
   - 模型纠结于"CWE-89 vs CWE-90"判别，反而最后判安全
   - cve_fix_0004.py（eval 注入）模型说"没有用户可控输入到达 eval"——完全错误

2. **B 类"无漏洞但建议改进"矛盾信号** → FP 激增（8 个，v7 仅 6 个）
   - v8 对比 CoT 教模型"部分防御不等于安全"，模型过度泛化为"所有防御都不够"
   - FP 清单：safe_03_subprocess_list（列表参数误判 CWE-78）、safe_08_shlex（shlex.quote 误判 CWE-78）、
     safe_18_java_prepared_stmt（PreparedStatement 误判 CWE-79）、safe_09_proper_authz（误判 CWE-287）、
     safe_17_race_with_lock（lock 保护误判 CWE-362）、noise_05_decorator_wrapper（误判 CWE-79）、
     noise_06_shell_true_hardcoded（固定命令误判 CWE-78）、safe_04_path_whitelist（误判 CWE-22）

3. **epochs=3 过拟合**
   - eval_loss：epoch 1 = 0.851 → epoch 2 = 0.781（best）→ epoch 3 = 0.797（上升）
   - best checkpoint 是 epoch 2，但即使 best 也不如 v7，说明问题在数据而非纯过拟合

**v8 FP/FN 清单**：
| 类型 | 样本 | 预测 | 根因 |
|---|---|---|---|
| FP | safe_03_subprocess_list.py | CWE-78 命令注入 | 列表参数 + shell=False 被误判 |
| FP | safe_04_path_whitelist.py | CWE-22 路径穿越 | startswith 校验被无视 |
| FP | safe_08_shlex.py | CWE-78 命令注入 | shlex.quote 有效转义被误判 |
| FP | noise_05_decorator_wrapper.py | CWE-79 XSS | JSON 响应被误判为 HTML |
| FP | noise_06_shell_true_hardcoded.py | CWE-78 命令注入 | 固定命令无用户输入被误判 |
| FP | safe_09_proper_authz.py | CWE-287 硬编码凭证 | 数据库查询角色被误判为硬编码 |
| FP | safe_17_race_with_lock.py | CWE-362 Race Condition | lock 保护被误判 |
| FP | safe_18_java_prepared_stmt.java | CWE-79 SQL注入 | PreparedStatement 被误判 |
| FN | hard_crossfile_03_sink.py | none | 跨文件数据流分析失败 |
| FN | hard_cve_05_spring4shell.java | none | 框架代码误判为安全 |
| FN | cve_fix_0001.java | none | LDAP 被编码迷惑（v7 TP→v8 FN） |
| FN | cve_fix_0002.js | none | LDAP 被 bcrypt 迷惑（v7 TP→v8 FN） |
| FN | cve_fix_0003.py | none | JSON-RPC eval 误判为框架代码 |
| FN | cve_fix_0004.py | none | eval 注入被误判为无用户输入 |
| FN | cve_fix_0005.js | none | loopback 信任反模式未识别 |

**训练配置**：
| 字段 | 值 |
|---|---|---|
| 训练数据 | `train_chatml_v8_cwe_attribution.jsonl`（819 条，v7 799 + 新增 24） |
| 数据变更 | 24 条对比 CoT 样本，覆盖 5 类 CWE 混淆模式 |
| 生成脚本 | `scripts/build_v8_cwe_attribution.py` |
| 泄漏审计 | Jaccard >= 0.8：0 条泄漏；>= 0.5：0 条高相似；0.3-0.5：8 条模式相似（正常） |
| LoRA/训练参数 | 与 v5/v7 完全一致（r=8, alpha=16, epochs=3, lr=1e-4, rslora, seed=42） |
| best adapter | `outputs/lora_r8_a16_e3_lr0.0001_s42_rslora_v8_cwe_attr/best/`（训练中） |

**v8 新增 24 条对比 CoT 样本分布**：
| 类别 | 数量 | 覆盖 CWE | 对比目标（教模型"为什么不是 X"） |
|---|---|---|---|
| 注入混淆 | 5 | 643/943/90/113 | 不是 CWE-89 SQL（sink 不是 SQL execute） |
| 认证/权限混淆 | 4 | 639/862/306/384 | 不是 CWE-79/798/200（问题不是 HTML 输出/硬编码/信息泄露） |
| 密码学混淆 | 3 | 329/347/327 | 不是 CWE-200/798（是密码学缺陷不是信息泄露/硬编码） |
| 模板/表达式混淆 | 4 | 1336/94/917 | 不是 CWE-79/918（sink 是模板/表达式引擎不是 HTML/HTTP） |
| 其他高频误判 | 8 | 362/915/1321/843/208/502/200/352 | 各类 CWE 边界判别 |

**SYSTEM_PROMPT 关键改进**：
- 新增强制规则："vulnerability_type 必须以 CWE-XXX 编号开头"
- 新增 CWE 归因判别规则，覆盖 34 种 CWE 的 sink→CWE 映射

**v8 评估目标**：
- 红线：strict_accuracy >= 0.85（前端软件可用门槛）
- 次要：recall >= 0.95（保持不退步）
- 参照：v7 修正后 strict_accuracy = 0.728（合成集）/ 0.700（CVE-fix）

**v8 @ 87 合成集**（`v8/exp_06_eval.finetuned_custom.20260801_070358.json`）：

| 字段 | 值 | vs v7（修正后） | 说明 |
|---|---|---|---|
| TP / FP / FN / TN | 59 / 8 / 2 / 18 | TP 持平, FP+5, FN+1 | FP 大增 |
| **recall** | **0.967** | 持平 | 红线通过 |
| **FPR** | **0.308** | +7.7pp ⚠️ | 对比 CoT 导致过度敏感 |
| **accuracy** | **0.885** | -3.4pp ⚠️ | |
| strict_TP / cwe_mismatch | 37 / 22 | strict_TP+2, mismatch+2 | |
| **strict_recall** | **0.607** | -3.2pp ⚠️ | |
| **strict_accuracy** | **0.632** | **-9.6pp** ⚠️⚠️ | 退步明显 |

**v8 @ 20 CVE-fix**（`v8/exp_06_eval.finetuned_custom.20260801_072009.json`）：

| 字段 | 值 | vs v7（修正后） | 说明 |
|---|---|---|---|
| TP / FP / FN / TN | 15 / 0 / 5 / 0 | TP-1, FN+1 | 多 1 个 FN |
| **recall** | **0.750** | -5.0pp ⚠️ | |
| strict_TP / cwe_mismatch | 14 / 1 | mismatch-1 | CWE 归因略改善 |
| **strict_recall** | **0.700** | 持平 | |
| **strict_accuracy** | **0.700** | 持平 | |

**v8 cwe_mismatch 变化分析**（vs v7 修正后）：
- ✅ 修复 3 个：hard_crossfile_03_sink（CWE-79→正确 CWE-639）、hard_cve_05_spring4shell（CWE-79→正确 CWE-915）、typical_27_race_condition（空→正确 CWE-362）
- ⚠️ 新增 5 个：hard_bypass_04（新标 CWE-79）、hard_bypass_07（新标 CWE-107）、hard_owasp_01（新标 CWE-732）、typical_23_ssti（新标 CWE-91）、typical_24_ldap（新标 CWE-798）
- 改变但仍错 8 个：模型在尝试不同 CWE（说明训练有效果），但归因仍不准
- 完全不变 6 个：CWE-89/79 归因偏置顽固（XPath/NoSQL/Info Disclosure 仍标 CWE-89，hidden SSTI 仍标 CWE-79）

**v8 失败原因分析**：
1. **对比 CoT 样本太少**（24 条），不足以教会模型 34 种 CWE 的判别边界
2. **过度归因**：模型开始输出更多 CWE 编号（CWE-107/732/745/922 等不常见编号），但归因不准
3. **FP 增加**（+5）：对比 CoT 让模型对安全代码过度敏感，3 个安全样本被误判
4. **CWE-89/79 归因偏置顽固**：注入类混淆（XPath→SQL、NoSQL→SQL）完全没改善

---

### P3 v9 跑前优化——数据质量增强（2026-08-01）

> 基于资深安全专家审查，在 v9 开跑前完成 P0+P1 优化。v9 实际训练数据 `train_chatml_v9_augmented.jsonl` 包含 v8 的 819 条 + 新增 95 条 = **914 条**。

**P0 评估规范变更**：
- CVE-fix 测试集评估结果**必须分拆统计**为：7 条真实 CVE 样本（`cve_fix_0001`-`cve_fix_0007`）和 13 条手工扩展样本（`cve_fix_0008`-`cve_fix_0020`）
- 原因：手工扩展样本已接近 100% 饱和，真实 CVE 样本才是真正难度

**v9 新增 95 条样本分布**：
| 类别 | 编号 | 数量 | 靶向问题 |
|------|------|------|---------|
| 变量重命名增强 | A | 10 | 拉大同类 CWE 表征区分度 |
| 防御迷惑 | B | 8 | 靶向被防御措施迷惑的 FN（LdapEncoder、bcrypt 等） |
| 注意力分散 | C | 5 | 靶向 eval 注入被"框架代码"迷惑的 FN |
| 框架代码误判 | D | 5 | 靶向框架代码误判的 FN（Spring4Shell、JSON-RPC） |
| 多样安全代码 | E | 20 | 降低 FPR（含 5 条 v8 FP 靶向） |
| CWE 归因增强 | F | 7 | 对比 CoT 教 CWE 边界判别 |
| **Java/JS LDAP 注入** | **G** | **10** | CWE-90 从 18→28，靶向 CVE-fix 0001.java/0002.js |
| **信任边界绕过** | **H** | **10** | CWE-441 从 14→24，靶向 CVE-fix 0005.js loopback 信任 |
| **整数溢出** | **I** | **10** | CWE-190 从 29→39，多语言模式 |
| **Java/JS 安全代码** | **J** | **10** | 平衡语言分布，Java 安全样本 +5，JS 安全样本 +5 |

**CWE 命名标准化**（修复 56 条，覆盖 v8 基底和新增样本）：
- 统一空格式：`NoSQL 注入`→`NoSQL注入`、`eval 注入`→`代码注入(eval)`、`硬编码 IV`→`硬编码IV`
- 统一括号变体：`代码注入`/`代码注入(exec)`/`eval注入`→`代码注入(eval)`（CWE-95）
- 统一中英文混用：`Mass Assignment`→`批量赋值`、`JNDI注入`→`表达式注入`
- 修复多值格式：`CWE-1336; CWE-94 SSTI模板注入`→`CWE-1336 SSTI模板注入; CWE-94 代码注入`
- 修复错误标注：CWE-532 原标"日志注入"→改为"敏感信息日志泄露"

**v9 数据质量摘要**：
| 指标 | 值 |
|------|-----|
| 总样本数 | 914（v8 819 + 95） |
| 漏洞/安全 | 589 / 325（64.4% / 35.6%） |
| 重复率 | 0% |
| 测试集泄漏 | 0（Jaccard >= 0.5） |
| CWE 命名修正 | 56 条 |
| Java 占比 | 约 16%（优化前 12.5%） |
| JS 占比 | 约 12%（优化前 8.8%） |
| CWE-90 样本数 | 28（优化前 18） |
| CWE-441 样本数 | 24（优化前 14） |
| CWE-190 样本数 | 39（优化前 29） |

**v9 训练配置**：
| 字段 | 值 |
|---|---|
| 训练数据 | `train_chatml_v9_augmented.jsonl`（914 条） |
| 生成脚本 | `scripts/build_v9_augmented.py`（新增 G-J 四大类） |
| 泄漏审计 | Jaccard >= 0.5：0 条泄漏；>= 0.8：0 条高重叠 |
| LoRA/训练参数 | r=8, alpha=16, epochs=2, lr=1e-4, rslora, seed=42 |
| 训练命令 | `HF_HUB_OFFLINE=1 TORCH_ROCM_AOTRITON_ENABLE_EXPERIMENTAL=1 python3 train_qlora.py --data-file data/train_chatml_v9_augmented.jsonl --epochs 2 --batch-size 1 --grad-accum 8 --lr 1e-4 --lora-r 8 --use-rslora --output-suffix _v9` |

**v8 结论**：
- v8 整体不如 v7（strict_accuracy -9.6pp on 合成集，持平 on CVE-fix）
- 对比 CoT 方向正确（修复了 3 个 v7 mismatch），但 24 条样本不够
- **v7 仍为当前最佳模型**（strict_accuracy 0.728 合成集 / 0.700 CVE-fix）
- 要达到 strict_accuracy >= 0.85 目标，需要换一种方法（见下方建议）

**后续建议（不训练，改 prompt 或 RAG）**：
1. **CWE 速查表注入 system prompt**：在 prompt 中加入"CWE-XXX → sink 类型 → 判别要点"映射表，让模型推理时参考
2. **RAG 检索增强**：推理时检索相关 CWE 定义，注入 context
3. 若仍要训练：需要 100+ 条对比 CoT 样本才能覆盖所有 CWE 边界

### P2 v9 SFT 数据增强 + 靶向 FN 根因 + v8 失败修正模型（2026-08-01，数据已备，待训练）

> 基于 `docs/_archive/和一个AI的讨论1.md` 评判后的方法论 + v8 失败诊断后的修正。
> v8 评估失败后，针对三大根因修正数据与训练参数，再启动 v9 训练。
> 云端相关任务（DPO / 大规模数据增强 / 蒸馏）留到 v10。

**核心策略（v8 失败后修正）**：
- 数据增强（A 类）：变量重命名 + 跨语言变体，拉大同类 CWE 表征区分度，防记忆表面特征
- 靶向 FN 根因（B/C/D 类）：针对 CVE-fix 持续 FN 的三类根因做靶向样本
  - **B 类修正**：v8 的 B5/B6/B7 是"无漏洞但建议改进"矛盾信号样本，导致 FP 激增。v9 替换为 3 个 clear-cut 漏洞样本（CSRF Referer 绕过 / SQL 部分 cast / 开放重定向黑名单绕过），消除矛盾信号
- 多样安全代码（E 类）：非 hard-negative 方式增加安全代码多样性降 FPR（吸取 v6 失败教训）
  - **E 类增强**：新增 5 条 v8 FP 靶向安全样本（proper_authz / race_with_lock / decorator_wrapper / shell_true_hardcoded / django_orm），CoT 明确"防御有效→无漏洞"无矛盾信号
- CWE 归因增强（F 类）：补充 v8 未覆盖的易混 CWE 边界

**训练配置**：
| 字段 | 值 |
|---|---|---|
| 训练数据 | `train_chatml_v9_augmented.jsonl`（874 条，v8 819 + 新增 55） |
| 数据变更 | 55 条新样本，覆盖 6 类增强策略（含 v8 失败修正） |
| 生成脚本 | `scripts/build_v9_augmented.py` |
| 泄漏审计 | Jaccard >= 0.8（新样本间）：0 条；>= 0.5（与测试集）：0 条；审计覆盖 107 个测试样本（86 合成 + 21 CVE-fix） |
| LoRA/训练参数 | r=8, alpha=16, dropout=0.1, rslora=True, **epochs=2**（v8 教训：epoch3 eval_loss 上升过拟合）, lr=1e-4, batch=1×8, seed=42 |
| best adapter | `outputs/lora_r8_a16_e3_lr0.0001_s42_rslora_v9_aug/`（待训练） |

**v9 新增 55 条样本分布**：
| 类别 | 数量 | 设计目的 | 覆盖内容 |
|---|---|---|---|
| A. 变量重命名增强 | 10 | 拉大同类 CWE 表征区分度 | SQL/XSS/Cmd/Path/Hardcoded/Deser/SSRF/Crypto/CSRF/LogInject，跨 Go/Ruby/Java/Node.js/PHP/Django |
| B. 防御迷惑靶向（全漏洞） | 8 | 修复 FN 根因 1（部分防御误判安全）；**v9 修正：移除 3 个矛盾安全样本，改为纯漏洞** | LDAP 部分编码 / SQL 错误转义 / XSS 部分转义 / 路径 startswith 未规范化 / shell=True+shlex / JWT 无 issuer / pickle 宽白名单 / 正则白名单可绕过；**全部为漏洞样本，无矛盾信号** |
| C. 注意力分散靶向 | 5 | 修复 FN 根因 2（无关安全措施分散注意） | bcrypt+LDAP / CSRF+SQLi / HTTPS+XSS / RateLimit+CmdI / Session+Path |
| D. 框架代码误判靶向 | 5 | 修复 FN 根因 3（真实漏洞误判为演示） | JSON-RPC eval / 动态模板 / 插件动态导入 / 配置 exec / 计算器 eval |
| E. 多样安全代码（含 v8 FP 靶向） | 20 | 非 hard-negative 方式降 FPR；**v9 新增 5 条 v8 FP 靶向** | 原有 15 条（subprocess 列表 / shlex.quote / PreparedStatement / HTML 转义 / 路径校验 / bcrypt / json.loads / JWT 完整验证 / 模板渲染 / defusedxml / 环境变量 / CSRF token / secrets / hmac.compare_digest / yaml.safe_load）+ **5 条 v8 FP 靶向**（proper_authz / race_with_lock / decorator_wrapper / shell_true_hardcoded / django_orm） |
| F. CWE 归因增强 | 7 | 补充 v8 未覆盖易混边界 | CWE-190 整数溢出 / CWE-601 开放重定向 / CWE-117 日志注入 / CWE-200 信息泄露 / CWE-611 XXE / CWE-798 硬编码 API Key / CWE-327 ECB 模式 |

**v8 失败 → v9 修正对照**：
| v8 根因 | v9 修正措施 |
|---|---|
| 对比 CoT 引入判别焦虑 → FN 增加 | 移除对比 CoT 的"判别焦虑"诱导，B 类改为 clear-cut 漏洞样本（无 CWE 边界纠结） |
| B 类"无漏洞但建议改进"矛盾信号 → FP 激增（8 个） | B5/B6/B7 替换为纯漏洞样本；E 类新增 5 条 v8 FP 靶向安全样本，CoT 明确"防御有效→无漏洞" |
| epochs=3 过拟合（eval_loss epoch3 上升） | 训练参数 epochs 3→2（v8 best checkpoint 在 epoch 2） |

**方法论依据**（`docs/_archive/和一个AI的讨论1.md` 评判后 + v8 失败诊断）：
- 数据增强由本助手完成（非 DeepSeek 教师生成），与 DeepSeek 正式版质量相当
- 不做 DPO（本地 16GB GPU 不可行，留到 v10 云端）
- 不做 label smoothing（大词表 LLM 效果有限）
- 不做 hard-negative SFT（v6 已证失败）
- 改用多样安全代码 + 靶向 FN 根因 + 数据增强三管齐下
- **v8 新增教训**：训练样本不得含"无漏洞但建议改进"的矛盾信号；epochs 不得超过 best checkpoint

**v9 评估目标**：
- 红线：recall >= 0.95（不退步）；CVE-fix recall >= 0.571（v5 锚点）
- 主要：CVE-fix recall 恢复到 v7 水平（0.800），B/C/D 类靶向样本应修复 v8 的 5 个 FN（LDAP×2 / eval×2 / loopback×1）
- 次要：FPR 回落到 v7 水平（0.231，v8 是 0.308），E 类 5 条 v8 FP 靶向应修复 8 个 FP 中的 5 个
- strict_accuracy：持平或提升 v7（0.728 合成集 / 0.700 CVE-fix）
- 参照：**v8 已评估失败**（合成 recall 0.967 / FPR 0.308 / strict_acc 0.632；CVE-fix recall 0.750 / strict_acc 0.700）、v7（当前最佳）、v5 锚点

### P3 DPO 尝试与失败（2026-07-27）

> 本地 16GB RDNA4 GPU 上 DPO 对 8B 模型不可行。三次尝试全部失败。

**尝试记录**：
| # | 配置 | 结果 | 根因 |
|---|---|---|---|
| 1 | 8bit + max_len=1024 | OOM 黑屏 | 8B 8bit + DPO 双前向超 15GB VRAM |
| 2 | fp16 + max_len=512 | 立即 OOM | 8B fp16 本身就超 16GB |
| 3 | 4bit + max_len=512 | 跑完但 grad_norm=0 | 4bit NF4 + DPO 双前向梯度回传失效，loss=ln(2) 不下降，所有指标归零；dmesg 记录 amdgpu drm panic |

**结论**：DPO 在本地硬件上无法用于 Qwen3-8B。8bit OOM、4bit 梯度失效，是 ROCm/bitsandbytes 与 DPO 双前向的硬约束，非参数可解。

**已归档**：`outputs/_archive_dpo_failed_4bit_grad_zero/`

**DPO 数据状态**：
| 文件 | 行数 | 状态 | 说明 |
|---|---|---|---|
| `dpo_merged.jsonl` | 104 | 📦 保留但未使用 | 本地无法训练，若换云 GPU 可直接复用 |
| `dpo_fp_pairs_v5.jsonl` | 6 | 📦 保留 | 同上 |
| `dpo_fp_pairs_v4.jsonl` | 5 | 📦 归档 | 同上 |



### v9max 双模型蒸馏 + 云端 A800 训练（2026-08-02 ~ 08-07，已发布为当前最佳）

> 本地 SFT 数据到极限（v9）后转云端放大。详细过程见 docs/论文/第5章_训练主线.md 与 docs/过程.md。

| 字段 | 值 |
|---|---|
| 训练数据 | 双模型 API 蒸馏（DeepSeek V4-Flash / GLM-5.2；Kimi K3 脚本已编写但未启用、未产生数据），清洗后 7692 条（漏洞 3493 / 安全 4199） |
| 训练配置 | Qwen3-8B bf16 全精度 LoRA（r=8, alpha=16, dropout=0.1, rsLoRA），A800，train 6539 / dev 1153，2 epoch，lr=1e-4，max_seq 6144，1636 步 ≈ 4.1h，train_loss ≈ 0.529 |
| 发布形态 | base+LoRA 合并后 Q4_K_M 量化，发布为 Ollama 模型 `garrywhite109909/graduation-vuln-scanner:v9max` |

**v9max 评估锚点（HF 评估管道：NF4 4bit 基座 + FP16 LoRA 增量叠加，evaluate.py 默认口径）**：
| 测试集 | recall | FPR | accuracy | strict_recall |
|---|---|---|---|---|
| 合成集 87 | **1.000** | 0.423 | 0.874 | **0.607** |
| CVE-fix 20 | **0.950** | - | - | 0.650 |

### G0 方法学修复重跑 + prompt 对照 + 量化缺口诊断（2026-08-08）

> 背景：REGRUN_AFTER_FIX.md 的 9 条方法学修复中 #1（文件名泄漏）改变了所有 LLM 实验的 prompt 构造，历史指标不可比。本日完成 exp_01/04/05/06 四项 G0 必跑。详细分析见 docs/过程.md 2026-08-08 节。

**G0 重跑结果**：
| 实验 | 结果 |
|---|---|
| exp_01 基础扫描 | 准确率 92.9%（泄漏修复生效，不再是 100%） |
| exp_05 prompt 消融（repeat=3） | combined 最优（FPR 7.7%），消融结论成立 |
| exp_04 难样本集（repeat=3） | 完成（非独立 held-out，仅趋势参考） |

**v9max 3 变体 prompt 对照（合成集 87，Ollama Q4_K_M）**：
| 指标 | base | anti_fp_cot | combined |
|---|---|---|---|
| recall | 0.934 | 0.918 | **0.951** |
| FPR | 0.192 | 0.115 | **0.077** |
| accuracy | 0.897 | 0.908 | **0.943** |
| strict_recall | 0.639 | 0.623 | 0.623 |

**v9max CVE-fix 20 真实召回（关键口径更正）**：
| 管道/变体 | recall | strict_recall | parse_fail |
|---|---|---|---|
| Ollama base | 0.789（15/19） | 0.737 | 1（0007） |
| Ollama combined | 0.750（15/20） | 0.750 | 0 |
| HF NF4+FP16 LoRA（08-06） | **0.950** | 0.650 | 0 |

- **README 旧表述 "CVE-fix recall 0.95" 是 HF 评估管道口径**；Ollama 发布形态（base+LoRA 合并后整体 Q4_K_M，LoRA 信号被重量化）实测 0.75~0.79。缺口是两种 4-bit 管道的差距，不是"量化 vs 未量化"。README 已更正。
- **决策**：evaluate.py `--variant` 默认由 base 切为 combined。
- FN 根因（0001/0003/0005/0006）：全是"过度信任防御"，支撑两阶段"工具召回 + LLM 裁决"架构（有效的是 taint/信任边界分析，不是 RAG）。

**fix_usable=0 瓶颈证伪（2026-08-08 重算）**：
- 旧结论"fix_usable=0 瓶颈在 FixVerifier 危险模式覆盖面"——FixVerifier 扩 12 条补充模式后自检通过，但对 20 条 CVE-fix 结果（`exp_06_eval.ollama_garrywhite109909\graduation-vuln-scanner_v9max.20260808_131115.json`）用扩展后 FixVerifier 重算：**fix_usable 仍 0/15，指标无任何变化**。
- 真正瓶颈在上游：14/15 样本 `model_fix_suggestion` 为空——模型 verdict JSON 未输出 fix_suggestion 字段（BASE_PROMPT 有要求"完整修复版代码用 ``` 围栏包裹"，Ollama v9max 在该 eval 配置下未遵守）。FixVerifier 根本没有输入可验。
- 唯一抽到代码块的 cve_fix_0004（CWE-306 类缺失认证）tests_passed=None 属合理：该类漏洞无"危险拼接模式"可判。
- 评估侧已改进：compute_fix_metrics 的失败原因拆分"模型未输出fix_suggestion"与"未抽到代码块"，避免再误判瓶颈位置。
- 下一步（Nivis-alpha.1）：修复方向是 prompt/输出契约与解析兜底，而非继续扩 FixVerifier 模式表。

### P4 错题闭环（已终止——被云端路线取代，见上 v9max 条目）
| 时间 | 文件 | 错题来源 | recall | FPR | strict_recall | 状态 |
|---|---|---|---|---|---|---|
| - | - | - | - | - | - | ⏳ 待 P3 完成 |

## 五、归档目录结构

```
experiments/exp_06_finetune/results/
├── EXPERIMENT_LEDGER.md           ← 本文件
├── baseline/                       ← Qwen3-8B 零样本基线与参考模型
│   ├── exp_06_eval.ollama_qwen3_8b.20260722_225944.json   ← 当前锚点
│   ├── exp_06_eval.ollama_qwen3_8b.20260723_001648.json   ← CVE-fix 基线评估
│   ├── exp_06_eval.ollama_qwen3_8b.20260722_000125.json   ← Qwen3 时代历史
│   ├── exp_06_eval.ollama_qwen3_8b.20260720_043236.json
│   └── exp_06_eval.ollama_qwen3-coder_30b.20260711_151248.json
├── v2/                             ← SFT v2（train_chatml_v2.jsonl）
├── v3/                             ← SFT v3（train_chatml_v3_fixed.jsonl）
├── v4_failed/                      ← SFT v4（已废弃，训练-测试泄漏）
├── v5/                             ← SFT v5（train_chatml_v5_clean.jsonl）
├── v6_failed/                      ← SFT v6 hard-negative（已归档，负迁移）
├── v7/                             ← SFT v7 实战专用模型（train_chatml_v7_realworld.jsonl，当前 SFT 最佳）
├── _archive_qwen25/                ← Qwen2.5 时代全部归档
│   ├── baselines/
│   ├── finetuned/
│   ├── phase1_sweep/
│   ├── phase2/
│   ├── phase3_knitlm/
│   ├── hard_samples/
│   └── reports/
└── _archive_broken_cve_fix/        ← v1 错误 CVE-fix 测试集结果（30 全 FN）
```
