---
name: vuln-scan-sample-triage
description: 对 AI 漏洞扫描器（两阶段：工具召回 + LLM 裁决）逐样本诊断扫描结果的正确性，定位问题归属（工具层 / 推理工程层 / 训练数据层），实施修复或写入优化文档。This skill should be used when the user pastes a scan result card from the Web frontend (or describes a wrong verdict / wrong CWE / wrong line number / misleading UI), asks "是答案错了还是分析对了但工具层没起作用", "分析一下这个样本", "哪里有问题", or drives a batch audit of tool-prompt quality.
---

# 漏洞扫描结果逐样本诊断与修复

## 用途

对毕业设计「AI 漏洞扫描器」的单次扫描结果做端到端诊断：判断判定是否正确、类型归因是否正确、
行号是否正确、修复建议是否有效、前端展示是否误导，并据此定位问题归属、实施修复或写入优化文档。

## 协作模式（用户与助手的分工）

用户（项目负责人）的工作：
- 在 Web 前端逐条扫描测试集样本（`exp_04_hard_samples`，87 段），把结果卡片**原文粘贴**给助手
- 独立完成**数据层**工作：alpha06 数据蒸馏 / 清洗 / 标签治理 / 训练集冻结
- 会主动提交「提示质量审计」问题清单（逐条列出工具层误导证据），并要求助手逐条修复或写进文档

助手的工作：
- 接收结果卡片 → 逐字段诊断 → 先查工具层 → 再归因训练层 → 能修则修，修不动写文档
- 不擅自改动用户正在做的数据管线 / 训练集文件
- 每次改动 `.py` 后必须说明「是否需要重启后端 + 重启后应看到什么」

## 核心诊断流程

### 第 1 步：逐字段核对（不要跳过）

对每张卡片核对这六项，逐项给出「✓ / ✗ + 依据」：

| 字段 | 核对方法 |
|---|---|
| 判定 `has_vulnerability` | 与 `manifest.json` 的 `expected_present` 比对 |
| 类型 `vulnerability_type` | 与 `expected_cwe` 比对（注意多标注用 `;` 分隔，命中任一即 strict hit）|
| 行号 source / sink / explanation / fix | 读样本源码数真实行号，逐锚点验证 |
| 修复建议 | 是否真实有效（防伪修复，见下）|
| 工具层链路 | `stage1.by_tool` 是否有召回；**零召回要实测是"没命中"还是"命中后被丢弃"** |
| 前端展示 | 是否有误导（文案、徽章、重复卡片、颜色语义）|

### 第 2 步：归因——先工具层，后训练层

**铁律：每次漏判/误判，先查工具层是否把证据送到模型面前，再归因到模型/训练层。**

- 工具层问题 = 模型**没看到**证据（零召回、候选被剔除、类型标注乱码、行号错位、证据链丢弃）
- 训练层问题 = 模型**看到了却判错**（概念混淆、叙事漂移、主次排序缺失、幻觉类型、硬性知识错误）

诊断手段（离线复现，不依赖真实 LLM）：注入 mock client 跑 `TwoStageScanner.scan_code()`，
直接调 `Prefilter().scan()` / `ExternalScanner().scan_sast()` / `TaintTracker().trace()` /
`_infer_taint_type()` / `_drop_irrelevant_positional()` 观察每步产物。

**零召回必须区分两种情形**（关键，曾误判）：
```python
ts = TwoStageScanner(client=mock, use_semgrep=True, ...)
fs = ts._stage1_recall(code, lang, filename)     # 剔除+去重后的最终候选
# 若 len(fs)==0，再单独跑 ExternalScanner().scan_sast() 看工具原始输出
# 原始有输出但 fs==0 → 是"命中后被丢弃"（剔除规则误杀），不是工具能力问题
```

### 第 3 步：修复判定——紧急 vs 该拖

| 判据 | 紧急（现在修）| 该拖（写文档待办）|
|---|---|---|
| 是否改变判定结果 | 否（只改展示/标准化/提示）| 是（改变候选集合）|
| 能否离线独立验证 | 能（自检 + 端到端 + 全量 87 段回归）| 不能（需真实 LLM / 重跑评估）|
| 是否动 fixed5 基线 | 不动 | 会动 |

**"会动 fixed5 基线"= 改变任一 Stage 1 候选集合**（剔除、扩充、改类型推断），
因为 fixed5 的 recall 1.000 / FPR 0.043 是在旧候选行为下测得的。这类改动须
**重跑 87 段全量**并做对照表后才可合并；不能单独改。

### 第 4 步：修复实施流程

1. **离线最小复现**：用 mock client 构造能稳定复现问题的最小输入
2. **通用规则修复**：不得针对样本特判（见「规则泛化三关」）
3. **跑模块自检**：四个模块均有离线自检入口
4. **全量 87 段回归**：统计候选数变化、真漏洞 0 候选样本数、安全样本误伤数
5. **模拟前端分析**：注入 mock 跑 `scan_code().to_dict()`，检查前端依赖字段是否完整
6. **更新文档**：训练层 / 工具层二选一

### 第 5 步：重启判断（先查再说，不要口头断言）

```bash
ps -eo pid,lstart,cmd | grep bootstrap          # 后端启动时间
stat -c '%y' graduation_project/*.py            # 代码修改时间
```
- 改动 `.py` 且**晚于**进程启动 → 需重启，重启后说明预期看到什么
- 只改 `.html` → 静态资源已 `no-cache`，刷新即可（首次需硬刷一次）
- 只改 `.md` → 无需重启

## 规则泛化三关（新增工具规则必须过）

1. **语言级事实**：规则里的字面量是不是该语言/标准库的**唯一或标准**写法？
   出现具体变量名、函数名、样本文件名 → 过拟合，退回
2. **形态抽象**：匹配的是**结构特征**（构造 API → 消费 sink）还是**拼写特征**？
   只认 `+` 拼接却不认 `os.path.join`；只认 Python 不认 Java 同形态 → 覆盖不全，退回
3. **独立集验证**：在**规则设计时未接触**的数据集（如 `testset_cve_fix`）上能否命中同类真漏洞且不误伤？
   只在设计集有 TP → 不能证明泛化，退回

`_infer_taint_type` 分支顺序按**信号强度**重排（先 TLS 证书专词，再 SSRF，再 Path Traversal），
避免 `urlopen` 撞词 `open(`、`requests.get(url, verify=False)` 被 SSRF 抢占。

## 失败模式速查

完整定义见两份文档（见下）。常见：

- **F1** 近邻概念编号方差（同形态多次采样给不同 CWE）
- **F2** 叙事视角漂移（explanation 用了别的 CWE 的叙事）
- **F3** 硬性知识错误（如"`==` 是恒定时间比较"、"extractall path 是常量故无路径穿越"）
- **F4** 捏造 API（如 `logging.escape()`）
- **F5** 伪修复（值比较挡不住键名注入 / 参数化矛盾于"确认漏洞" / 修复与判定严重性不匹配）
- **F6** 行号噪声（说明/修复行号 ±2~3，推理端 line_normalizer 兜底、数据侧治本）
  ——完整定义在训练层文档 P1-C，本表列出仅为编号连续
- **F7** 主次排序缺失（选了真实的伴生/次类型，未选主类型）→ **工程侧无解**，硬编码主次=答案泄漏
- **F8** 幻觉类型被投票机制放大（"独立票"加分机制让幻觉票胜出）

## 关键路径

| 用途 | 路径 |
|---|---|
| 测试集 87 段 + 标注 | `experiments/exp_04_hard_samples/samples/`（`manifest.json`）|
| 独立验证集（20 段真实 CVE）| `experiments/exp_06_finetune/testset_cve_fix/` |
| fixed5 基线结果 | `experiments/exp_07_two_stage_eval/results/*20260818_104203.json` |
| 工具层优化文档 | `experiments/exp_04_hard_samples/工具层优化指导_Stage1召回质量与改进.md` |
| 仓库级基准与审计 | `experiments/exp_08_repo_benchmark/`（audit_stage1.py / manifest_*.json / repos/）|
| 训练层优化文档 | `experiments/exp_06_finetune/audit/优化建议_alpha06_日志类CWE归因辨析_v2_14.md` |
| 扫描核心 | `graduation_project/two_stage_scanner.py` |
| 行号纠正 | `graduation_project/line_normalizer.py` |
| CWE 纠正 | `graduation_project/cwe_normalizer.py` |
| 正则预筛 | `graduation_project/prefilter.py` |
| 污点追踪 | `graduation_project/taint_tracker.py` |
| 外部工具 | `graduation_project/external_scanner.py` |
| 前端 | `app/backend/static/scan.html`；后端 `app/backend/main.py` |

## 模块自检入口（改动后必跑）

```bash
# 环境纪律（§9.7 环境教训）：项目指定 conda 环境 graproj（README §614）。
# 报"缺依赖"前必须穷举 conda/uv/pyenv/venv/系统 python；永不往系统 python 强装。
GRAPROJ_PY=/home/zane/miniconda3/envs/graproj/bin/python
for m in line_normalizer cwe_normalizer prefilter two_stage_scanner taint_tracker; do
  $GRAPROJ_PY graduation_project/$m.py 2>&1 | tail -1
done
$GRAPROJ_PY -c "import app.backend.main"   # 后端可导入性
```

## 已踩过的坑（防止复发）

1. **`normalize_line_numbers(return_anchors=True)` 幂等时返回空 anchors** → 直接读 anchors 得 0。
   需从**输出文本**（恒为 `line N:` 格式）提取行号，兼顾"正确取原号/错误取纠正后号"。
2. **改 `_drop_irrelevant_positional` 多分支时丢失 `dropped` 分支** → 无主告警剔除整体失效。
   改多分支必须保留 else/dropped 落点，靠 B3 自检用例兜底。
3. **在 `_adjudicate_one` 内回填 `verdict.finding` 无效** —— 该字段由外层 `_adjudicate_all`
   赋值（此时为 None）。改为 verdict 暂存字段 + 外层回填。
4. **证据链回填只补文本未同步行号** → 卡内出现"文本 line 9 / 徽标 L10"自相矛盾。
5. **注释里的"观察结论"可能是自我实现的预言**（如"gitleaks 无 .git 时不命中"实为缺 `--no-git`
   参数导致）。工具接入后必须做"已知阳性样本冒烟"验证。
6. **强行归并不同语义的候选会制造虚假置信度**（2/1 + 2/1 合并成 4/2）——宁可显示两张卡。
7. **分支内定义的变量在分支外使用 → 生产路径 UnboundLocalError**（2026-08-30 实锤）：
   `_aggregate` 里 `raw_texts` 定义在 `if not corrected:` 块内，一旦 `corrected` 由
   **signal_registry 校正分支**产出（`B501 → CWE-295`、`taint_tracker:SQL Injection →
   CWE-89` 等 14 条已提交 `corrected_type` 的规则），整块被跳过 → 块外访问抛异常 →
   整个 `_aggregate` 中断 → 前端显示"分析失败"（typical_20 在**已算出正确答案之后**崩）。
   判据：新增块内变量时自问"另一分支会不会用到它"；自检用例必须覆盖**被跳过的那个分支**
   （临时 `SignalRegistry` 造"已提交校正"的规则即可离线覆盖）。

## 常见误判提醒

- **"分析失败"不一定是真失败**：两阶段 `has_vulnerability=null` 是「需人工复核」语义。
  前端若显示红色失败卡，先查 `_kind` 是否被旧持久化数据标为 error（已加迁移逻辑）。
- **工具层修复后可能暴露"多漏洞共现"**：工具不再丢弃证据时，真实存在的多漏洞会显现，
  顶层类型可能与单标注的 `expected_cwe` 不同。判断标准是两个漏洞是否都真实（可能属标注漏标）。
- **不要把工具层 bug 归给模型**：先用 mock 复现确认证据有没有送到模型面前。
