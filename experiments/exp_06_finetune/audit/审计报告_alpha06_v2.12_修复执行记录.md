# alpha06_v2.12 数据集体检 —— 修复执行记录

- 执行日期：2026-08-28
- 修复脚本：`audit/repair_v2_13.py`（可复现，从 v2_12 原文件一键重建全部产物）
- 输入：`data/final_train_chatml_alpha06_v2_12.jsonl`（8984 条，未改动）
- 输出数据：`data/final_train_chatml_alpha06_v2_13.jsonl`（**8637 条**）
- 执行日志：`audit/repair_v2_13_out.txt`
- 重蒸馏清单：`audit/redistill_manifest_v2_13.jsonl`（1010 条，含 user 全文）
- 行号复核清单：`audit/lineno_review_v2_13.jsonl`（7 条）

---

## 1. 修复项执行结果（对照报告第 9 节清单）

| # | 级别 | 报告要求 | 执行结果 |
|---|---|---|---|
| 1 | P0 | risk_level 小写 `none` → `None`（4553 条） | ✅ 已归一 4553 条；v2_13 中 risk_level 合法值 100% |
| 2 | P0 | 剔除/重蒸馏 13 条教师独白 | ✅ 剔除 **18 条**（报告 13 条 + 8774/8776/8810/8813/8843 —— a2[D] 超长样本与 a3[1] 泄漏命中 40~196 次的同一批病灶，含 JSON 解析失败的 8797/8826）。剔除后 assistant 最长从 128653 → 5469 字符 |
| 3 | P0 | 24 条异种契约转写为主契约 | ✅ 全部转写：`is_confirmed`→`has_vulnerability`、`reason`→`explanation`、source/sink 按 user 污染源/危险点行号重建（`line N: …`）、严重度→risk_level、system 统一为主契约 prompt。true 15 / false 9，与 evidence_adjudication 36 条形态一致（裁决任务样本现为 60 条同构） |
| 4 | P0 | 6 条矛盾标签翻转或剔除 | ✅ **剔除**（报告备选方案）。探查发现比报告更深一层：这 6 条（608/1309/1323/1358/1430/1432）均为 fix_distill 蒸馏产物，**正文引用行号与 user 代码错位**（如 608 正文分析"第 57 行 grep"在 user 中不存在），且 JSON 字段文本与正文互相矛盾。机械翻转或重建字段都会残留错误 → 整族剔除 |
| 5 | P0 | 290 条空壳分析重蒸馏 | ✅ 290 条剔除（x72+x52 相同 assistant 组全在内），全部进重蒸馏清单 |
| 6 | P0 | 1179 条 explanation=N/A 补齐 | ✅ 部分：从分析正文"结论："提取填充 **202 条**；663 条（结论过短如"代码安全"/无结论步骤）无法可靠提取 → **保留在训练集**（标签正确），进重蒸馏清单待教师补写 |
| 7 | P1 | 删 cvss/fix_code 字段（731 条） | ✅ cvss_vector+cvss_score 661 条、fix_code 70 条，字段全部移除 |
| 8 | P1 | sink 行号校验修正（~430 处） | ⚠️ 部分：宽松判定 miss 中，唯一候选才自动修正，实际修正 7 处（含转写样本），日志逐处可查；5 处多候选 + 2 处无候选进 `lineno_review_v2_13.jsonl` 待人工。fix_suggestion 锚点不自动修（"应改为 X"描述匹配新代码属正常形态，自动修反而会改错） |
| 9 | P1 | 18 条 vulnerability_type 归一 | ✅ 归一 **20 条**（报告 18 条 + 自检多发现 2 条 `CWE-400/CWE-789` 合并形态）：纯编号补官方英文名、冒号改空格、多 CWE 合并取主类型。统一为 `CWE-编号 官方英文名`（与主库 4272 条主流风格一致）。v2_13 中违规 0 |
| 10-14 | P1 | 「看似危险实安全」400+ / evidence 正例 / variant_trust / blacklist_bypass / 极难样本 | ❌ 需教师生成新数据，不在本次范围（见第 4 节） |
| 15 | P2 | 19 种 1-shot CWE 剔除 | ✅ 按报告口径（findall 全计数==1）检出 16 种、剔除 14 条。19→16 差异：CWE-170/282/789 的唯一样本正是被归一的 8303/8519/8130（归一为主流 CWE 后不再是 1-shot）；16 种中 470/617 共享同一样本故 14 条 |
| 16-17 | P2 | TS/C#/Kotlin、请求走私等专项 | ❌ 需教师生成新数据（同上） |
| 18 | P2 | 安全样本 source/sink/fix 规范放宽 | ✅ system prompt 已更新全库（source/sink 允许"锚定+不可控说明"，fix 允许一句加固建议）。**训练与推理必须同步使用新 prompt**（见第 5 节） |
| 19 | P2 | explanation 长度收敛 | ❌ 需教师重蒸馏，未执行 |
| 20 | P2 | 训练脚本 max_seq_length 硬断言 | ✅ 已加到 `scripts/train_qlora.py` 与 `cloud_train/train_qlora_cloud.py`：训练前对全量样本真实分词，超限即退出（可 `--allow-truncation` 跳过）。本地默认 2048 会被正确拦截 |

## 2. 剔除与保留统计

```
剔除合计 347 条：
  教师独白        18（safe）
  矛盾标签         6（vuln）
  空壳分析       290（safe）
  重复 assistant 组残余 19（空壳外 x3/x2 组，模板坍塌兜底清理）
  1-shot CWE      14
  （集合间有少量重叠，去重后 347）

v2_13 = 8637 条，正负 4272 : 4365（48.6% : 51.4%）
```

## 3. 独立复检（对 v2_13 重跑关键审计）

```
risk_level 分布   : {High: 2606, Medium: 519, Critical: 1125, None: 4365, Low: 22}  → 合法值 100%
多余字段          : 无（cvss_*/fix_code/is_confirmed/reason 全部为 0）
vulnerability_type: 非规范 0
JSON 解析失败     : 0（8797/8826 两条毒样本已随独白剔除）
system prompt     : 全库单一版本（异种契约 24 条已转写）
assistant 重复组  : 0（x72/x52/x3/x2 全清）
正负比            : 4272 : 4365
超长样本          : assistant max 5469 字符（原 128653）；整体 token 上限约 8.1k < 12288
残余 explanation=N/A: 663 条（7.7%，均在重蒸馏清单）
```

抽查确认：转写样本 8069 的 source 行号经内容校验修正为 `line 10`（代码 10 行 `q = request.args.get('q')`）；8092 修正为 source `line 11` / sink `line 12`，均与代码一致。

## 4. 剩余工作（需教师模型，本次不涉及）

1. **重蒸馏 1010 条**（`redistill_manifest_v2_13.jsonl`，每条含 reason/kind/user 全文/note）：
   - `teacher_monologue` 18：重蒸馏补回该 task_key 的跨文件安全对照
   - `shell_analysis` 290 + `duplicate_assistant` 19：重跑真实分析
   - `explanation_na` 663：只需补写 explanation 结论摘要（分析正文可用）
   - `contradictory_label` 6：重跑全文分析（正文行号已与代码错位）
   - `oneshot_cwe` 14：补到 8+ 条或永久放弃该 CWE
2. **P1 新数据生成**：看似危险实安全 +200、evidence_adjudication 正例 +23、variant_trust +54、blacklist_bypass +56、score≥14 极难样本 +200
3. **P2 新数据生成**：TS/C#/Kotlin 各 150+、请求走私/缓存投毒/依赖混淆专项
4. **P1-8 收尾**：`lineno_review_v2_13.jsonl` 7 条人工修正

## 5. 部署提醒（重要）

- **system prompt 已变更**（P2-18 放宽规范，+~60 token）：v2_13 训出的模型推理时**必须使用新 system prompt**（取自 v2_13 数据集内任意样本的 system 字段），否则训练/推理分布不一致。
- 云端训练请上传 `data/final_train_chatml_alpha06_v2_13.jsonl` 并以 `--data-file` 指定；云端脚本默认 `max_seq_length=12288`，硬断言会自动校验通过。
- 本地 `train_qlora.py` 默认 `max_seq_length=2048`，对本数据集会被硬断言拦截（预期行为）——本地 16GB 无法容纳 8k 序列，该数据集应在云端训练。
