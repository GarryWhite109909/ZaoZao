---
name: tool-defect-audit
description:
  对 AI 漏洞扫描器的工具层（Stage 1 静态召回：bandit/semgrep/taint_tracker/prefilter）
  做缺陷挖掘与修复迭代。流程：选定样本/URL/仓库 → 建标准答案（逐行源码实读）→
  纯工具跑一遍 → 逐条审计候选产出（A 盲区/B 错标/C 噪声/D 剔除存疑）→ 定性修复
  （规则/类型推断/剔除规则）→ 复测回归。This skill should be used when the user
  asks to "提升工具层/Stage1 性能"、"审计候选"、"找工具缺陷"、"建仓库基准/标准答案"、
  "对账扫描结果"、"跑批教学仓库"，or pastes candidate lists / audit results for triage.
---

# 工具层缺陷审计与修复（candidate-level audit loop）

## 环境（先于一切，§9.7 环境教训）

**项目指定环境：`conda activate graproj`（Python 3.11，README §614），或直接用
绝对路径 `/home/zane/miniconda3/envs/graproj/bin/python`。** 全文所有 `python3`
命令均指该解释器。报"环境缺依赖"之前必须：查 README/docs 指定环境 → 穷举本机
环境（conda/uv/pyenv/venv/系统 python）→ 全都没有才动手装；**永远不往系统
python 强装包**（PEP 668 拦截就是信号）。uv tools 里的 semgrep venv 是残缺的，
跑工具层必须走 conda 环境。

## 定位与铁律

本 skill 只动 **Stage 1 工具层**（候选供给），不碰模型权重。铁律：

1. **先工具层后训练层**：任何 miss，先证伪"候选根本没到模型面前"（零候选/被剔除/类型错标），
   再归因模型。票型里有票但最终 miss → 才是训练层数据。
2. **审计本身零模型**：候选是否合理由确定性规则判定（形态匹配/注释行/无行号/重复），
   绝不为"看候选"而加载 LLM——GPU 留给跑批。
3. **每次改动过泛化三关**：语言级事实（字面量是否标准写法）→ 形态抽象（结构特征非拼写）
   → 独立集验证（设计时未接触的仓库能命中真洞不误伤）。
4. **动候选集合 = 动 fixed5 基线**：修复后必须 87 段全量回归 + 影响样本对照表。
5. **发现级口径**：多发现文件的指标数 confirmed 列表（票型全列出），不用顶层单值
   `vulnerability_type`——单值口径系统性低估（§9.6 教训）。

## 工作流（五步循环）

### 第 1 步：选定审计对象

三类来源，按信息密度选：
- **教学仓库**（首选，有官方答案）：dvna / NodeGoat / DVWA(vulnerabilities/ 子目录) /
  php-goof / juice-shop(精选目录)。规模约束：待扫代码文件 ≤30，否则只取子目录。
- **单文件样本**：exp_04 87 段（已有 manifest）或用户提供的任何代码。
- **URL/在线资产**：fetch_url 抓取后同单文件流程。

仓库获取：`git clone --depth 1` 到 `experiments/exp_08_repo_benchmark/repos/<name>/`。

### 第 2 步：建标准答案（manifest）

写 `experiments/exp_08_repo_benchmark/manifest_<name>.json`，格式（模板见
manifest_dvna.json / manifest_vflask.json）：

```json
{
  "repo": "owner/name", "benchmark_version": "1.0",
  "known_answers_source": "逐行源码实读 + 官方分册/README 意图",
  "files": [
    {"file": "path/relative.py", "language": "python",
     "expected_present": true, "expected_risk_level": "High",
     "expected_findings": [
       {"cwe": "CWE-89", "line": 10, "note": "一句话证据"}],
     "notes": "安全文件写误报反例说明（供蒸馏池）"}
  ]
}
```

标注纪律：
- **逐行实读**，不凭 README 猜；行号 = sink 核心行。
- 只标**源码可静态判定**的真实发现；框架默认缓解的意图型漏洞（如 lxml 禁实体）
  写进 notes 不进 expected_findings。
- 第三方库产物（压缩 JS/vendor）**排除在审计域外**（notes 里写明）。
- 安全文件也要条目（`expected_present: false`）——它们是误报对账的一半。
- 有官方答案的仓库（config/vulns.js 类 OWASP 分册）先映射再实读修正。

### 第 3 步：纯工具跑一遍 + 候选审计

```bash
# 整仓审计（零 LLM，秒级）：A 盲区 / B 类型错标 / C 噪声 / D 剔除存疑 自动标记
$GRAPROJ_PY experiments/exp_08_repo_benchmark/audit_stage1.py \
  --manifest experiments/exp_08_repo_benchmark/manifest_<name>.json \
  --repo-dir experiments/exp_08_repo_benchmark/repos/<name>

# 单文件调试
$GRAPROJ_PY audit_stage1.py --manifest ... --repo-dir ... --file core/appHandler.js
```

审计四类的判定依据（audit_stage1.py 已实现，含语义名→CWE 映射表）：
- **A 盲区**：expected 行 ±2 内无任何存活候选 → 新规则机会
- **B 错标**：候选在但类型对不上（先核对审计工具自身的语义映射表，排除口径误判——
  XXE 教训：semgrep 已召回而审计说盲区，是审计先错）
- **C 噪声**：进裁决但与 expected 无关 → 跑确定性四问（无行号/注释行/类型↔形态
  匹配/重复），"疑不合理"即修复候选
- **D 剔除存疑**：相关候选被剔除 → 核对剔除规则该不该放行

### 第 4 步：修复（按类分流）

| 类 | 修法 | 常见落点 |
|---|---|---|
| A 盲区 | 新预筛规则 / sink 模式 / source 模式 | prefilter.py / taint_tracker._SINK_DEFINITIONS / _SOURCE_PATTERNS |
| B 错标 | 类型推断修正 / 语言级 sink 禁用（`_SINK_LANG_DISABLED`：JS 的 render(/.save( 是框架 API）| taint_tracker.py |
| C 噪声 | 收紧触发条件 / 剔除规则 / 语义映射修正 | prefilter.py / _drop_irrelevant_positional |
| D 误杀 | 放宽剔除条件或加白名单 | _drop_irrelevant_positional |

修复纪律：
- 先定位**真实形态**（语言生态语义：同调用名在不同语言语义不同——JS `exec(`=命令注入、
  `render(`/`.save(`=框架 API；Python 里是污点 sink）。
- **新增/修改 prefilter 规则必须同步登记 `PREFILTER_RULE_INFO`（含 `cwe` 字段）**：
  评测器 eval_prefilter 的 CWE 映射从它派生（§9.13.1 单一真源），不登记会被
  静默计成"CWE 不匹配"。
- 每修一条在审计清单的对应行打勾，**立即复测 audit**（秒级）确认 A/B 消失且不产新 C。
- 模块自检：`$GRAPROJ_PY graduation_project/{prefilter,taint_tracker}.py` 等
  （`GRAPROJ_PY=/home/zane/miniconda3/envs/graproj/bin/python`）。
- 修复完成跑 **87 段全量静态回归**（工具层口径，零 LLM）：

  ```bash
  $GRAPROJ_PY experiments/exp_04_hard_samples/stage1_candidates_dump.py
  ```

  对照基线统计四项：候选总数 / 零召回×真 / 候选≥3 的样本数 / 安全噪声样本候选数
  （当前基线见"已知基线"节）。eval_two_stage.py 的 LLM 跑批是第 5 步对账用，
  **不是**工具层回归的口径。产出对照表后才算合并。
- **复测纪律（§9.7 教训 1）**：审计清单与复测数字一律以实跑时间戳为准；
  复测必须与首轮**同环境同口径**，否则"复测"本身是新的污染源。

### 第 5 步：LLM 跑批对账（可选，GPU 任务）

```bash
$GRAPROJ_PY experiments/exp_08_repo_benchmark/eval_repo.py \
  --manifest ... --repo-dir ... --backend transformers --resume
```

产出：文件级 TP/TN/FP/复核 + **发现级 recall**（confirmed 列表 vs expected）+
三列对照（A=外部工具原始 / B=系统确认 / C=已知答案）+ extra 清单（人工定性：
清单漏标 or 真误报）。FN 归因按票型分流：票型里无票 → 回第 4 步（工具层）；
有票被否决 → 训练层（写入 v2_15 反例池）。

## 素材沉淀（每轮必做）

- 误报/漏报样本 + 源码对照 → v2_15 蒸馏反例池（experiments/exp_06_finetune/audit/
  v2_15_deferred_queue.md §3），格式见该文件 §3.3/3.4。
- 审计结论/修复记录 → 工具层文档
  （experiments/exp_04_hard_samples/工具层优化指导_Stage1召回质量与改进.md §九）。
- 单次运行不得出"最稳/稳定"结论；跨运行漂移样本标"待复测"。

## 已知基线（快照日期 2026-08-31；**引用前先对照文档最新节数字，此节会过期**）

> 历史教训：本节曾硬编码 2026-08-30 的旧口径数字（DVNA 模式类别口径、VFlask
> 38% recall），与文档后续修正（§9.8 测量口径修正、§9.6 工具层审计、§9.9 补
> 规则）脱节——**跨轮对比必须回源文档对应节，本表只作快速定位**。

| 基准 | 当前状态 | 权威出处 |
|---|---|---|
| 冒烟自测 | 10 PASS / 0 FAIL / 0 SKIP（detect-secrets 已由 SKIP 转 PASS，§9.16.1） | 文档 §9.16.6 |
| DVNA 11 条 expected | OK 5 · B 2 · A 4（manifest 逐条口径）| 文档 §9.9.4 |
| VFlask 17 条 expected | OK 13 · B 1 · A 3 | 文档 §9.9.4 |
| php-goof 7 条 expected | OK 5 · A 3（全为版本/间接源边界，零修复）| 文档 §9.19 |
| NodeGoat 24 条 expected | OK 13 · A 10（结构性边界）· B 0（第七波后）| 文档 §9.20 |
| 87 段工具层静态回归 | 总候选 132；零召回 15/87；零召回×真 3（spring4shell 框架版/cve_03 设计内/crossfile 架构级）；安全样本候选 17（**零新增误报是硬约束**，任何波次破坏它即回退） | 文档 §9.16.6 + dump 实跑 |
| 87 段 prefilter 独立评测 | recall 0.7377 · strict_acc 0.9434 · FP=0 | 文档 §9.14.5 |
| 87 段生产组态（LLM） | 三轮回填：门槛前 strict 77.2% → 门槛后 81.5% → **编号锚（§9.21.5b）子集验证修 5/10 miss，全量推算 ≈90.7%**；锚已默认生效（prompts.py）。仍 miss：2 段 798 抢占（§8.8 授权候选）、1 段标注（typical_20）、crossfile ×3（标注争议/架构） | 文档 §9.21 |

### 工具层已知边界（§9.16 沉淀，改动前必读）

1. detect-secrets 必须以 **cwd=文件目录 + basename** 调用（1.5.0 对绝对路径
   恒空 results）；冒烟对无外部依赖工具的零召回判 FAIL，不得降级 SKIP。
2. Java/JS source 是**方法名级**模式（`getParameter(` 等），请求对象形参
   命名自由；新增语言判定必须带该语言**多形态变体**自检用例。
3. `_BODY_TYPES` 含 catch/except/finally 子句；`_CALL_NODE_TYPES` 含 PHP
   `member_call_expression`；`_compile` 对 `.`/`->` 前缀用子串匹配。
4. 新 sink 类型必须同步登记 `_SINK_RANK`（否则截断时垫底被丢）与
   `_SINK_LANG_ONLY`（键须与 pattern 字面含括号完全一致，否则限定静默失效）。
5. LDAP `search_s` 参数化判定矩阵已入自检（占位符计数不能整串 findall）。
6. semgrep sast/taint 共享单次执行缓存（`_semgrep_execute_cached`），按
   `"-taint"` 后缀分流；改分流条件须同时保证另一侧不双计。
7. 外部工具执行状态留痕在 `ExternalScanner.last_status` →
   `stage1["tool_status"]`（仅异常状态）；排查零召回先看它。
8. **semgrep 并发竞态**（§9.18）：同机多进程（评估 × 审计/audit）时 semgrep-core
   偶发 exit 2（results=0 + errors=1，整体崩），崩溃率与并发强度正相关
   （独跑 0%、并发约 40%）。`_semgrep_execute_cached` 已对 errors 非空自动
   重试 1 次——不要移除；审计/评估同机并发是默认场景，假设竞态存在。
9. **追加文档节前当场再查最大节号**（并行会话会同时落盘新节）：
   `grep -n "^### 9." 文档 | tail -1` 取尾号 +1，**写入后复查是否撞号**
   ——§9.17/9.20 两次撞号（risk_budget vs exp_01、NodeGoat vs 重跑对账）。
10. **教学仓库的注释块是形态陷阱（§9.20）**：NodeGoat/DVWA 风格把"修复代码"
    注释在漏洞旁（`/* Fix for Ax ... */`），形态与漏洞完全一致——新行级规则
    必须先剥 `/* */` 块注释（用换行占位保行号）再逐行判，否则命中注释示例而
    漏真 sink。`_code_wo_comment_lines` 只处理整行注释，不覆盖块注释。
11. **A 盲区定性顺序（§9.20 固化）**：先查剔除留痕（`stage1.dropped_unowned` /
    运行日志"剔除无主告警"行）→ 再查审计器 `_SEMANTIC_TO_CWE` 映射 → 最后才是
    引擎规则缺失。"零候选"可能实为"命中后被扔"（cookie 族 6 条实锤）。

## 参考脚本位置（项目内，不随 skill 分发）

- 审计：`experiments/exp_08_repo_benchmark/audit_stage1.py`
- 对账：`experiments/exp_08_repo_benchmark/eval_repo.py`
- manifest 模板：同目录 manifest_dvna.json / manifest_vflask.json
- 跑批引擎：`experiments/exp_07_two_stage_eval/eval_two_stage.py`（--only-files
  逗号分隔；--resume 断点续跑；--output 固定路径才能续）
