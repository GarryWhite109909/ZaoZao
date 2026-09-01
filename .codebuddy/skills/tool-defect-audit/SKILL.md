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

四类来源，按信息密度÷成本排序（同成本时取信息密度高者）：

| 优先级 | 来源 | 规模 | 标注成本 | 备注 |
|---|---|---|---|---|
| 1 | **语料池补丁对** `exp_06_finetune/corpus/rolling_dev` + `_safe` | 50+47 | **零**（自带 manifest + patch） | 真实 CVE，§9.23 已建基线：差分判别率 2% |
| 2 | **语料池 FP 压力面** `corpus/train_pool` + `_fixed` | 291+301 | 零 | 五语言，测误报/崩溃，不测召回 |
| 3 | **教学仓库**（官方答案）：dvna / NodeGoat / DVWA(vulnerabilities/ 子目录) / php-goof / juice-shop(精选目录) | — | **高**（逐行实读） | 规模约束：待扫代码文件 ≤30，否则只取子目录 |
| 4 | **单文件样本**：exp_04 87 段（已有 manifest）或用户提供的任何代码 | — | 中 | |
| 5 | **URL/在线资产**：fetch_url 抓取后同单文件流程 | — | 中 | 通道已定义，2026-09-01 前 0 次使用 |

**不选**：`long_file_raw` / `checklist_raw`（CoT 分析文本非代码）；
`testset_cve_fix.broken_*`（标注与代码错位，仅作素材不作基准）。

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
12. **补丁对差分是唯一与标签无关的可靠度量，但判别成功 ≠ 语义正确（§9.23/§9.26）**：
    工具 `experiments/exp_08_repo_benchmark/patchpair_diff.py`（口径复用
    `audit_stage1.collect_raw_candidates`）。分类：`STRONG`(v>0,f=0) /
    `WEAK`(v>f>0) / `REVERSE`(f>v>0，**不可计入判别**) / `same_count`(噪声) /
    `both_zero`(零召回) / `reversed`(纯误报)。
    - 基线：rolling_dev 2%（47 对）、**train_pool 3.8%**（291 对）。
    - **必须附"语义正确率"**：逐一追查强判别的命中规则与推断类型。实测 11 个
      强判别中仅 5 个语义正确（1.7% vs 3.8%，**单一数字会高估 2.2 倍**）。
      典型蹭中：4 个 CWE-1336(SSTI) 全靠 bandit **B701**(autoescape→XSS)
      命中，修复把 `Environment()` 换成 `SandboxedEnvironment()` 后 B701
      恰好不触发——差分"成功"但报的是 79 不是 1336。
    - 判定某 CWE"无形态、不立项"前，先确认它的现有召回不是蹭中来的。
    - **分类顺序：`both_zero` 必须最先判**。写成 `v==f` 在前会让 v=f=0
      被误记为"同数噪声"（实测虚报 62 个）。优先复用 `patchpair_diff.py`，
      不要重写度量逻辑（§9.27.6）。
13. **87 段基线（2026-09-01 更正）**：**124 / 15 / 3 / 17**（总候选/零召回/
    零召回×真/安全样本候选）。旧值 132 自 §9.18 起被引用，昨晚并行改动后
    已变（核对 `20260831_215301` 起均为 124）。87 段语言分布
    py75/php2/js2/**java8/无 Go** → 纯 Go 规则对其零影响。
14. **自定义 semgrep 规则落点**：`graduation_project/semgrep_rules/`
    （=`_TAINT_RULES_DIR`）。该目录被 `--config` 挂载，且 `_run_semgrep`
    采集**所有非 `-taint` 结尾**规则 → 普通形态规则也生效，且不碰
    `models/semgrep_rules/`（官方产物，保持可同步上游）。命名以 `-taint`
    结尾才会走 taint 解析（见 §9.27.7）。
15. **"规则数量 ≠ 有效覆盖"，评估要看形态交集（§9.27）**：Go 有 67 条规则、
    CWE-94 有 2 条，命令注入却零覆盖——官方 `dangerous-exec-cmd` 只匹配
    `exec.Cmd{...}`（语料 0 样本），而真实写法 `exec.Command(` 有 4 个样本。
    **先跑阳性对照**证伪"工具没跑"，再看规则形态 × 语料形态的交集。
16. **Go 已近形态天花板，不再追加（§9.27.5）**：CWE-22(17 样本) 真实召回
    0/17、CWE-1336(10) 无形态、CWE-639/862(9) 结构性盲区。Go 判别率经本轮
    补规则后 1.3% → 2.6%（76 对，强判别 1 → 2）。
17. **判定"结构性不可解"前，先确认所有通道都跑过（§9.28）**：§9.19 曾在
    SAST+secret 的测量结果上判 php-goof 3 条盲区"版本敏感、零代码修复"，
    实际 **trivy SCA 三条全覆盖**（CVE-2022-28368 / CVE-2021-3603 /
    CVE-2019-10010）——工具一直在，是管道没接（审计脚本从不调用 scan_sca）。
18. **冒烟通过 ≠ 通道接通（§9.28）**：`scan_sca` 在 tool_smoke_test.py 有
    覆盖，但真正的审计入口 `audit_stage1.py` 从不调用它 → trivy 在
    §9.9~§9.27 全部仓库审计中零生效。检查通道是否真在用，要查**生产路径的
    调用点**，不是冒烟测试。
19. **"按文件类型分流"的逻辑要确认在所有调用场景下成立（§9.28）**：
    `two_stage_scanner.py:2446` 的 `if suffix not in code_file_exts` 在单文件
    场景正确（.py 里没依赖清单），在**仓库审计**场景错误（依赖清单从未被
    单独扫描）。
20. **新增通道先做独立小节，不并入既有判定（§9.28）**：SCA 是**项目级**
    证据（"用了有漏洞的库"），非行级（"第 N 行触发"）。先并列呈现并做零扰动
    diff 验证，口径讨论清楚后再决定是否合并。
21. **阳性对照的值要避开 allowlist（§9.28）**：AWS/GitHub 的**文档示例
    key**（如 `AKIAIOSFODNN7EXAMPLE`）已被主流 secret 扫描器收录为
    allowlist，用它做阳性对照会得到"工具坏了"的假结论。用真实格式的随机值。
22. **标注可信度分级引用（§9.29）**：差分结论可引用全部数据面；CWE 分组
    结论只可引用 A 级（87 段/仓库逐行实读）；corpus 系（CVE 映射自动生成）
    的 expected_cwe 只可做粗分组统计（硬错率 ~12%），**不可用于单样本
    定性**。新数据面接入前先跑 10% 标注抽验（patch/描述/代码三方一致），
    不过 95% 就只可用与标注无关的度量。
23. **patch 文件 ≠ 答案，文件对实际 diff 才是（§9.29）**：patch 语料有三类
    缺陷——缺失（40/305）、**错位**（corpus_00071 型：patch 是 GHSA-f4vv
    授权修复，文件对却是 md5→sha256）、不可验证（minified bundle）。
    验证语义一律 `git diff --no-index -u` 两侧文件重算，patch 只当索引。
24. **测量假象优先于实体结论（§9.29）**：反直觉数据先排查格式/字段/路径/
    管道（系统 `diff` 是 normal 格式 `<`/`>`，unified 是 `-`/`+`——grep 错
    格式得"空 diff"假象；JSON 字段名记错让验证脚本空转），再怀疑标注，
    最后才怀疑度量管道。差分报告发布前跑 `verify_strong.py`
    （sha + 3×重跑）作为准入检查。
13. **从 commit/CVE 映射来的标注必须抽验（§9.20 + §9.23）**：抽验
    `source_path` 与实际代码一致。两次实锤：broken_20260722（CVE 号与 x/sys
    ioctl 文件错位）、corpus_00002（描述写 unsafe eval 却标 CWE-89）。
    语料池 `expected_cwe` 硬错率实测 ~12%，**用 patch diff 而非
    expected_cwe 作 ground truth**。
14. **真实 CVE 上别指望形态规则（§9.23 基线的用途）**：CVE 补丁对差分判别率
    仅 2%——真实漏洞多为"缺参数门控/不完整修复/转义顺序"，模式匹配天然失效。
    这类数据面当"难度标尺"与"形态挖掘素材"，**不当召回基准**（全盲区无区分度）。
15. **立项前先做可检测性评估（§9.24）**：覆盖矩阵上的"最大空洞"不等于"最该
    填的洞"。CWE-1336 曾是最大空洞（0 规则、44 样本），评估后 77% 无静态
    形态 → 不立项。跑 `experiments/prefilter_eval/patch_detectability.py`
    （sink 词典法）与 `patch_fix_nature.py`（修复性质分类法），**双法交叉、
    取区间不取点值**（实测 17%~30%）。
16. **形态规则的天花板是 17%~30%，定位应下调为"第一道粗筛"（§9.24）**：
    真实 CVE 的修复 82% 是"在漏洞行之外加校验"或"纯逻辑重构"，漏洞行与
    正常代码同形。最反直觉的是 **CWE-89 SQLi 的 A 类修复仅 1/18**——87 段
    上的高召回是合成/教学样本的"教科书拼接形态"造成的，**不可外推**。
    投入应转向可检测率 ≥47% 的类（502/611/601/90/94/441），
    ≤16% 的类（89/862/798/918）继续加规则边际收益趋零。
17. **GPU 跑批严禁双实例（2026-09-01 实锤事故）**：本机 17GB 显存（ROCm），
    两个 transformers 推理进程同时跑必然 OOM，且**互相污染结果**——
    事故链：kill 了 nohup 包装进程但真正的 python 工作进程存活 → 启动第二个
    → 双实例抢显存 → 两个都崩，已完成的 25 段全是废数据（LLM 调用失败被记成
    review，耗时 0.1~3s 与正常 100~800s 差异明显，可据此识别污染）。
    启动跑批**必须**三步校验：
    ```bash
    ps aux | grep eval_two_stage | grep -v grep | wc -l   # ① 启动前：须为 0
    nohup $PY ... & echo "PID $!"                          # ② 启动
    sleep 5; ps aux | grep eval_two_stage | grep -v grep | wc -l  # ③ 须恰为 1
    ```
    终止跑批要用 `ps` 找**实际 python 工作进程**（非 nohup 包装 PID），
    kill 后再次 `ps` 确认归零。长跑批期间可并行零 LLM 审计任务（不占 GPU），
    但**绝不再启动第二个 GPU 任务**。
18. **跑批前先冻结工具层**：工具层代码（prefilter / taint_tracker / prompts /
    external_scanner / two_stage_scanner）有未提交改动时跑 LLM 对账 = 数据
    无效——跑批耗时数小时，跑到一半工具层变了则前后样本不同源、结论不可比。
    2026-09-01 曾启动 16384 对照跑批后才改 prefilter.py / prompts.py，
    白跑 55 分钟只能终止废弃。**顺序：先静态回归确认冻结 → 再启动 LLM 跑批。**
19. **裸 LLM 基线必须用评估最优 prompt**：测"模型不依赖候选的原始能力"时，
    `--variant` 选 **combined_nosource**（5056 字符，纯 LLM 场景最优），
    **不能**用 triage_train_aligned（1982 字符，依赖候选锚对齐，无候选时
    无从对齐）。并加 `--no-semgrep --no-taint-tracker --no-prefilter
    --no-external` 四关，让全部样本走零候选 full_recheck 整文件路径。
    用途：裸基线 vs 带工具基线的差值 = 工具层净增益；裸基线判对而带工具
    miss 的样本 = **候选误导面**（工具给了弱/错证据反干扰模型）。
20. **跨口径数字不可直接比较**：对比 strict hit 前必须核对 `num_ctx`
    （生产 16GB ROCm 档为 **16384**，eval 默认 **6144**，差 2.7 倍）。
    08-30 基线用 16384、后续重跑用 6144，两者 strict hit（86.7% vs 83.6%）
    不可直接相减——差异里混着 num_ctx 损失与模型能力，须跑同口径 16384
    对照才能分离归因。同理：子集 A/B 结果**不得外推全量**（曾由 14 段子集
    推"92.6%"，全量实测仅 83.6%）。

## 参考脚本位置（项目内，不随 skill 分发）

- 审计：`experiments/exp_08_repo_benchmark/audit_stage1.py`
- 对账：`experiments/exp_08_repo_benchmark/eval_repo.py`
- manifest 模板：同目录 manifest_dvna.json / manifest_vflask.json
- 跑批引擎：`experiments/exp_07_two_stage_eval/eval_two_stage.py`（--only-files
  逗号分隔；--resume 断点续跑；--output 固定路径才能续）
