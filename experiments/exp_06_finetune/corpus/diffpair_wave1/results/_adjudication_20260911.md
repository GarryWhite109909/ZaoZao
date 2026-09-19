# 43 条人工裁定 · 落实报告（20260911）

来源：Garry 逐条人工裁定。**未改任何一行教师正文**；只动 `manifest` 的 `expected_cwe`/`expected_present` 与台账字段。

## 一、落定结果

| 类别 | 条数 | 含义 |
|---|---|---|
| 保留原标签 | 4 | 00018→1336、00132→601、00019→1336、00094→441 |
| 改标 | 17 | 见下表 |
| 判无洞（id 级） | **20 个 id** | A 侧无可利用漏洞 → 该样本成为**负样本** |
| 存疑（带备选） | 4 | 00155(400/918)、00145(409/400)、00117(无洞/20)、00008(346/352) |

### 判无洞的 20 个 id → `expected_present = false`

`00011 00020 00034 00035 00037 00048 00049 00096 00097 00098 00108 00117 00124 00133 00139 00143 00147 00150 00158 00177`

> 这 20 个包**不再是"有洞的差分对"**。已在 manifest 标 `expected_present=false`，可当负样本用；若你的流程只吃"差分对"，这批需要单独处置（见第四节）。

### 标签落定 21 条（**改标 17** + **保留原值 4**：00018 / 00019 / 00094 / 00132）

| id | 原标签 | 真 CWE | 存疑备选 |
|---|---|---|---|
| diffpair-corpus_00007 | CWE-1336 | **CWE-22** | — |
| diffpair-corpus_00008 | CWE-1336 | **CWE-346** | CWE-352 |
| diffpair-corpus_00013 | CWE-1336 | **CWE-862** | — |
| diffpair-corpus_00014 | CWE-1336 | **CWE-639** | — |
| diffpair-corpus_00018 | CWE-1336 | **CWE-1336** | — |
| diffpair-corpus_00019 | CWE-1336 | **CWE-1336** | — |
| diffpair-corpus_00036 | CWE-22 | **CWE-862** | — |
| diffpair-corpus_00094 | CWE-441 | **CWE-441** | — |
| diffpair-corpus_00099 | CWE-441 | **CWE-918** | — |
| diffpair-corpus_00100 | CWE-441 | **CWE-862** | — |
| diffpair-corpus_00132 | CWE-601 | **CWE-601** | — |
| diffpair-corpus_00134 | CWE-601 | **CWE-918** | — |
| diffpair-corpus_00145 | CWE-611 | **CWE-409** | CWE-400 |
| diffpair-corpus_00155 | CWE-611 | **CWE-400** | CWE-918 |
| diffpair-corpus_00160 | CWE-639 | **CWE-863** | — |
| diffpair-corpus_00161 | CWE-639 | **CWE-863** | — |
| diffpair-corpus_00162 | CWE-639 | **CWE-863** | — |
| diffpair-corpus_00165 | CWE-639 | **CWE-862** | — |
| diffpair-corpus_00175 | CWE-77 | **CWE-78** | — |
| diffpair-corpus_00178 | CWE-77 | **CWE-78** | — |
| diffpair-corpus_00179 | CWE-77 | **CWE-78** | — |

## 二、★ 裁定把模型打掉了多少（44 个 A 版块）

| 判定 | 块数 | 明细 |
|---|---|---|
| 一致 | 28 | 13 例"真值有洞且编号对" + 15 例"都是无洞" |
| **模型误报** | 7 | 00007 L56, 00007 L68, 00037 L925, 00097 L1660, 00098 L1687, 00117 L2460, 00177 L4545 |
| **★模型漏报** | 5 | 00018 L486, 00132 L2868, 00155 L3651, 00160 L3730, 00162 L3842 |
| **编号错** | 4 | 00008 L114, 00019 L527, 00094 L1534, 00145 L3179 |

| **结论：44 块中 28 块与真值一致、16 块冲突。冲突的 16 块若照原样入库，就是在教模型答错。** | | |

## 三、16 块冲突清单（已标 `usable=false`）

| id | 行 | 真值 | 模型答 | 冲突类型 |
|---|---|---|---|---|
| diffpair-corpus_00018 | L486 | CWE-1336 | false / CWE-1336 | ★模型漏报 |
| diffpair-corpus_00132 | L2868 | CWE-601 | false / CWE-79 | ★模型漏报 |
| diffpair-corpus_00155 | L3651 | CWE-400 | false / CWE-918 | ★模型漏报 |
| diffpair-corpus_00160 | L3730 | CWE-863 | false / CWE-22 | ★模型漏报 |
| diffpair-corpus_00162 | L3842 | CWE-863 | false / CWE-863 | ★模型漏报 |
| diffpair-corpus_00007 | L56 | 无洞 | true / CWE-22 | 模型误报（真值无洞） |
| diffpair-corpus_00007 | L68 | 无洞 | true / CWE-248 | 模型误报（真值无洞） |
| diffpair-corpus_00037 | L925 | 无洞 | true / CWE-88 | 模型误报（真值无洞） |
| diffpair-corpus_00097 | L1660 | 无洞 | true / CWE-918 | 模型误报（真值无洞） |
| diffpair-corpus_00098 | L1687 | 无洞 | true / CWE-400 | 模型误报（真值无洞） |
| diffpair-corpus_00117 | L2460 | 无洞 | true / CWE-20 | 模型误报（真值无洞） |
| diffpair-corpus_00177 | L4545 | 无洞 | true / CWE-78 | 模型误报（真值无洞） |
| diffpair-corpus_00094 | L1534 | CWE-441 | true / CWE-295 | 编号错（模型 CWE-295） |
| diffpair-corpus_00008 | L114 | CWE-346 | true / CWE-352 | 编号错（模型 CWE-352） |
| diffpair-corpus_00145 | L3179 | CWE-409 | true / CWE-400 | 编号错（模型 CWE-400） |
| diffpair-corpus_00019 | L527 | CWE-1336 | true / CWE-98 | 编号错（模型 CWE-98） |

## 四、这 16 块怎么处理（三选一，我没动正文）

| 方案 | 做法 | 代价 | 效果 |
|---|---|---|---|
| (a) 只改结论行 | 把 `结论:` 那行替换成真值 | 5 分钟 | **不推荐**：结论对了、但防御/载荷/锚句仍在论证旧结论 → 自相矛盾的样本 |
| **(b) 整块剔除** | 从派生数据集里跳过这 16 块 | 0（现成标记） | 干净，损失 16 块监督信号 |
| **(c) 带真值重跑** | 用真值当 ground truth 让强模型重分析这 16 例 | 要调 API | 最优：得到推理与结论都对的 16 块 |

我的建议：**先按 (b) 让本批可用**（`result_blocks.jsonl` 里 `usable=false` 即是清单），有空再走 (c)。

## 五、状态总表

| 项 | 值 |
|---|---|
| manifest | 246 条 ｜ `quarantined` 8 ｜ `expected_present=false` 20 ｜ 改标 16+17 |
| `kits/` / `kits_learner/` | 各 238 |
| `result_blocks.jsonl` | 223 条，新增 `adjudicated_cwe/adjudicated_hv/truth_verdict/usable` |
| A 版块可用性 | 一致 28 ｜ 冲突 16 ｜ 未裁定 67 |
| 备份 | `manifest_PRIVATE.json.bak-20260911`、`result.txt.bak-20260911` |