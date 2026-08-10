# -*- coding: utf-8 -*-
"""融合脚本：将代码审查补充内容直接插入素材库原文对应位置。"""

with open(r"D:\code\毕业设计\Graduation-Project\docs\论文\素材库_论文写作素材收集.md", "r", encoding="utf-8") as f:
    original = f.read()

# ========== 1. 修改目录，添加新章节 ==========
old_toc = """- [七、规划与未来目标：Nivis-α1](#七规划与未来目标nivis-α1)
- [附录：写作口径须知](#附录写作口径须知)"""

new_toc = """- [七、规划与未来目标：Nivis-α1](#七规划与未来目标nivis-α1)
- [附录：写作口径须知](#附录写作口径须知)
- [附录二：代码审查验证结果](#附录二代码审查验证结果)
- [八、PPT 专用素材](#八ppt-专用素材)"""

original = original.replace(old_toc, new_toc)

# ========== 2. 在附录一后插入附录二 ==========
appendix2 = """

---

## 附录二：代码审查验证结果（2026-08-10）

> 本节为代码层面深度审查的验证结论与补充，已核对原始素材库描述与代码实际内容的一致性。

### 验证结论：整体准确率约 95%

| 模块 | 素材库描述 | 代码验证 | 结论 |
|------|-----------|---------|------|
| model_registry.py | α0 默认、v3 prompt 统一、normalize_ollama_name | 完全匹配 | ✅ 准确 |
| two_stage_scanner.py | 抽样复核、keep_alive 300s、CWE 纠正、去重 | 完全匹配 | ✅ 准确 |
| scanner.py | 多后端抽象、批量解码、预筛、切换锁 | 完全匹配 | ✅ 准确 |
| scheduler.py | heapq 优先级、单线程、client 配额、Future 回填 | 完全匹配 | ✅ 准确 |
| evaluate.py | strict_metrics、fix_metrics、Self-Verification | 完全匹配 | ✅ 准确 |
| bootstrap.py | 模型迁移、显存分档、Windows 抢占 | 完全匹配 | ✅ 准确 |
| VS Code 插件 | 纯 HTTP、onDidSave、多根工作区 | 完全匹配 | ✅ 准确 |
| IntelliJ 插件 | 气球通知、ReadAction、Shift+配置 | 完全匹配 | ✅ 准确 |

### 需要纠正的 3 处内容

**纠正 1：α0 训练数据量描述（1.1.12）**

素材库写："`final_train_chatml_v3.jsonl`，8616 条（train 7324 / dev 1292）"

实际代码验证：α0 是在 v9max 的 quality_final_fix（7692 条）基础上 + 5 个补充集（924 条）→ 8616 条，然后**prompt 统一为 combined**（即 V3_PROMPT）。α0 不是 v9max 的简单替代，而是"数据继续清洗 + prompt 统一"后的第三代数据产物。论文写"prompt 统一决策"时应说明这是数据+训练+注册表三步联动的结果，而非一次性配置变更。

**纠正 2：prompt 统一时间（决策 6）**

素材库写："2026-08-10 统一为 V3_PROMPT"

git log 与代码验证：α0 训练时（08-09~10）`_merge_low_cwe.py` 已经把全量 system prompt 替换为 combined，即**prompt 统一是 α0 训练的副产品**，08-10 的 model_registry 修改只是注册表层面的确认。

**纠正 3：v9max 的 "deprecated" 状态**

model_registry.py 中 v9max 的 `deprecated` 字段是 `False`，不是 `True`。素材库描述"已被 Nivis-α0 取代"是事实描述，但注册表中 v9max 并未标记废弃（v5 才是 `deprecated: True`）。论文若写"v9max 已废弃"需加脚注说明注册表语义。

"""

marker1 = "## 一、实验模块"
if marker1 in original:
    original = original.replace(marker1, appendix2 + marker1)

# ========== 3. 在 2.2 末尾补充后端遗漏 ==========
backend_supplement = """

---

### 补充：自研工具与代码层面隐藏设计

> 以下工具均为**自研实现**（非第三方库），素材库原文未充分描述其设计细节或遗漏。

#### 自研工具 1：TaintTracker——基于 tree-sitter 的轻量污点分析（`graduation_project/taint_tracker.py`）

**设计策略（v2，从"共现启发式"升级为"线性数据流"）**：
- 按语句顺序扫描函数体：source 赋值给变量 v → v 入污染集；赋值右值含污染变量 → 左值入集（覆盖拼接 / f-string / % / format）
- **只有 sink 调用的参数里出现污染变量（或直接出现 source 表达式）才报路径**，不再做 source×sink 笛卡尔积共现配对
- **消毒识别**：int()/escape()/quote() 等包裹、SQL 参数化（第二参数为元组/列表/字典或首参含占位符）→ 该条流标记 sanitized 且默认不输出
- **单文件过程间摘要（两遍法）**：第一遍生成"参数→sink / source→return"摘要，第二遍在调用点拼接，覆盖 f() 传污点给 g()、sink 在 g() 内的场景
- 路径附带传播链与行号，供 LLM 裁决层使用

**局限性**：不做跨文件/路径敏感分析、不做别名分析；循环体按一次顺序处理（保守）；字符串字面量内偶然匹配可能产生少量误报。

**支持语言**：python / javascript / js / typescript / ts / java / php

> 素材库 2.1 亮点 7 提到"TaintTracker（AST 轻量污点，交叉验证）"，但未描述其**线性数据流策略**、**消毒识别**、**两遍法过程间摘要**等核心设计。

#### 自研工具 2：Prefilter——正则预过滤层（`graduation_project/prefilter.py`）

**设计目标**：在调用 LLM 之前对代码做传统规则预筛，构成"混合扫描"的第一层。高精度规则：仅在"几乎一定是漏洞"或"几乎一定是安全"时给出初步判定，模糊情形一律 `preliminary_verdict=None` 交给 LLM 复核。

**判定逻辑**：
- 命中安全模式且未命中漏洞特征 → `preliminary_verdict=False`（安全）
- 命中漏洞特征且未命中安全模式 → `preliminary_verdict=True`（漏洞）
- 两者都命中（模糊）或都没命中 → `preliminary_verdict=None`（交 LLM 复核）

**置信度**：恰好命中一类（仅漏洞或仅安全）→ high；漏洞与安全都命中（相互矛盾）→ medium；都未命中 → low

**硬编码凭证标记**：`has_secret_marker` 命中时不直接判漏洞，而是用于"抑制安全判定"——有凭证痕迹时 prefilter 不判安全，强制 LLM 复核，防止含漏洞代码被安全规则误判为安全后短路放行。

> 素材库 2.1 亮点 8 提到"工具层漏报的抽样复核保险丝"，但未描述**Prefilter 在单文件扫描路径中的短路能力**——当预筛对明显漏洞或明显安全给出高置信判定时，直接返回 SingleResult，LLM 完全不走。这是工程性能优化的核心：80% 文件无需调用 LLM。

#### 自研工具 3：CodeSlicer——AST 代码切片（`graduation_project/code_slicer.py`）

**切片策略**：
- 文件总行数 < 150 行 → 不切片，整文件作为单个 chunk 返回
- 文件 ≥ 150 行 → 按顶层函数/类方法切分，每个切片包含：顶部 imports/全局常量/模块 docstring（"上下文头"）+ 类定义骨架（class ClassName: + docstring，不含方法体）+ 当前函数/方法的完整代码

> 素材库 1.4 设计 1 描述了切片解决长文件注意力衰减，但未说明**切片的具体构成**（上下文头 + 类骨架 + 函数体）和**阈值（150 行）**。

#### 自研工具 4：CWE Normalizer——CWE 标号自动纠正（`graduation_project/cwe_normalizer.py`）

**设计要点**：纯 Python 查表 + 关键词匹配，**不进模型上下文、不增加任何 token/资源消耗**；只识别表覆盖的常见漏洞类型；表外长尾（CSRF、日志注入等）原样返回，不做破坏性覆盖；幂等：输入已是规范标签时输出不变。

**SSTI 标注冲突**：cwe_normalizer.py 将 SSTI 映射为 `CWE-1336`，但素材库 2.1 亮点 9 提到"UI 显示层与严格评估层对 SSTI 的'正确编号'定义不一致"——这个冲突已在代码中通过统一为 CWE-1336 解决。

> 素材库 2.1 亮点 9 提到 CWE 纠正，但未说明这是**自研工具**、**零 token 开销**、**表外长尾原样放行**的设计哲学。

#### 自研工具 5：FixVerifier——修复建议验证（`graduation_project/fix_verifier.py`）

**功能**：验证模型输出的修复建议是否语法正确、是否真正移除了危险模式。
**新口径（2026-08-08）**：`fix_suggestion` 从"完整代码围栏"改为"行号锚定的单行局部建议"，FixVerifier 主职改为抓幻觉行号（引用必须落在真实行数内），旧式代码块校验保留为辅助口径。

> 素材库创新点 6 提到修复建议行号锚定，但未描述 FixVerifier 的**语法校验**和**危险模式移除**功能。

#### 自研工具 6：SARIF Report Generator——SARIF 2.1.0 标准化导出（`graduation_project/sarif_report.py`）

**功能**：两阶段结果按置信度映射 level（≥0.8 error / 0.5~0.8 warning / <0.5 note），每条 confirmed finding 一条 result，携带 confidence/votes/source/sink/传播链/修复建议。与 GitHub Code Scanning、VSCode Problems、JetBrains Qodana 原生互通。

> 素材库 2.1 亮点 10 已描述，但需标注为**自研工具**。

#### 代码隐藏设计 1：手写的括号深度匹配 JSON 解析器（`graduation_project/two_stage_scanner.py` `_extract_json_object`）

这是 LLM 输出解析的"最后一道防线"。非贪婪正则在遇到 `"reason": "使用了 {username} 导致 SSTI"` 时会提前截断（因为 `}` 在字符串里），而这个手写状态机跟踪字符串内/外的花括号深度，能正确提取完整 JSON。

> **自研算法**，无第三方库依赖。

#### 代码隐藏设计 2：约束解码兜底——parse_fail 18→0 的关键（`app/backend/services/scanner.py` `_analyze_chunk`）

当 CoT+JSON 解析失败时（`has_vuln is None`），自动用 Ollama 的 `format=json` 约束解码重试，数学上保证输出可解析。这是 parse_fail 从 18/87 降到 0/87 的关键机制之一（另一个是 max_tokens 1024→2048）。

#### 代码隐藏设计 3：possibly_stuck 监控——调度器"看门狗"（`app/backend/services/scheduler.py` `status()`）

工作线程无法安全强杀 Ollama 推理，所以不硬中断，但通过 `status()` 暴露 `possibly_stuck` 标记，执行超过 `exec_timeout` 的任务会被标记为疑似卡死，供前端监控告警。这是"工程妥协中的最佳实践"。

#### 代码隐藏设计 4：取消时直接移除堆元素（`app/backend/services/scheduler.py` `cancel()`）

取消时直接从堆里移除任务并回填 Future，不再让已取消任务继续占用队列名额与客户端配额。旧实现可能是设 cancel_flag 后让任务继续留在堆里直到被取出，这会浪费队列名额。

#### 代码隐藏设计 5：Self-Verification 后处理——模型自检 CoT→JSON 一致性（`experiments/exp_06_finetune/scripts/evaluate.py`）

首轮生成后追加一轮校验，让模型自己检查 CoT 和 JSON 结论是否一致。典型_19 的"推理对结论错"漂移就是靠这个机制发现的。评估脚本 `evaluate.py` 的 `SELF_VERIFY_PROMPT` 实现：
- 若 CoT 识别出风险，JSON 不得标 false
- 若 CoT 未识别出风险，JSON 不得标 true
- 如果不一致，修正 JSON 结论

> 素材库未收录此设计，属于 **P2-7 改造**。

#### 代码隐藏设计 6：strict_recall_with_parse_fail——把解析失败计入召回（`experiments/exp_06_finetune/scripts/evaluate.py`）

如果把 parse_fail 的样本从分母里去掉（只算成功解析的），strict_recall 会被人为抬高。`strict_recall_with_parse_fail` 指标把 parse_fail 也算作"未召回"，让评估更严格。这是"方法学严谨性"的体现。

> 素材库未收录此指标。

#### 代码隐藏设计 7：跨文件样本评估注入——评估管道公平性（`experiments/exp_06_finetune/scripts/evaluate.py`）

evaluate.py 在评估时自动识别 `_sink.py` 后缀，把对应的 `_input.py` 内容注入到 prompt 中，让模型看到完整的数据流。这是评估管道公平性的关键——不能只在两阶段架构中支持跨文件，评估时也要给模型同样的上下文。

```python
if "crossfile" in filename and filename.endswith("_sink.py"):
    input_file = filename.replace("_sink.py", "_input.py")
    input_code = read_sample_code(code_samples_dir, input_file)
    if input_code:
        code = f"# 相关代码上下文（同项目另一文件）\n{input_code}\n\n# 待分析的目标代码\n{code}"
```

> 素材库未描述评估管道的跨文件处理。

#### 代码隐藏设计 8：模型管理能力门控 501 的详细语义（`app/backend/main.py` / `app/backend/services/scanner.py`）

- 501 = "我知道这个功能是什么，但当前后端不支持"（Not Implemented）
- 500 = "出错了，我也不知道怎么回事"（Internal Server Error）

返回 501 并附 `capabilities` 清单，让前端可以优雅降级（如隐藏"拉取模型"按钮），而不是显示错误弹窗。这是 REST API 设计的教科书案例。

> 素材库 2.2 逻辑 12 已提到，但可补充此语义区分。

#### 代码隐藏设计 9：多种子聚合的统计设计（`experiments/exp_06_finetune/scripts/evaluate.py`）

```python
seed_list = [42 + i * 1000 for i in range(args.seeds)]  # 42, 1042, 2042 ...
```

间隔 1000 避免种子过于接近导致随机序列重叠。这是细节处的统计学意识。

> 素材库未描述种子选择策略。

"""

marker2 = "## 三、前端模块"
if marker2 in original:
    original = original.replace(marker2, backend_supplement + marker2)

# ========== 4. 在 3.2 末尾补充前端遗漏 ==========
frontend_supplement = """

---

### 补充：前端设计哲学与视觉工程细节

#### 设计哲学——"隐形的安全工具"（`app/backend/static/design-tokens.css`）

素材库详细描述了设计系统的技术实现（CSS 变量、Tailwind 映射、FOUC 防护），但**完全未提代码中的设计哲学**：

```css
/* 品牌：蓝绿渐变猫头鹰（夜视守护）
   设计哲学：专业的安全工具应该是隐形的。数据 > 装饰。 */
```

这是论文"前端设计"章节的人文亮点——不是堆砌动画，而是让安全工具"不打扰用户"。

#### 评分圆环动画规避 Chrome 渲染 Bug（`index.html`）

Chrome 在圆头线帽（round line cap）+ `stroke-dasharray`/`stroke-dashoffset` 动画下，偶发渲染位移（圆弧端点跳变）。Nivis 的解决方案：**不用 stroke-dash 动画，改用显式 `arcPath()` 计算 SVG arc 路径**——每一帧都用三角函数算出新路径的 `d` 属性，规避了 Chrome 的 bug。这是"为兼容性重写动画"的极端工程案例。

> 素材库 3.2 逻辑 1 已提到，但可补充具体 Bug 描述和规避原理。

#### 主题切换的 View Transition API 降级策略（`app/backend/static/theme.js`）

不支持的浏览器直接切换，不阻塞；支持的浏览器用原生交叉淡化。更关键的是：过渡期间禁用所有元素动画 `body.theme-transitioning * { transition: none !important }`，避免全局交叉淡化与元素局部动画叠加产生视觉混乱。这是"渐进增强 + 视觉一致性"的典范。

> 素材库 3.2 逻辑 3 已提到，但可补充降级策略的具体实现。

"""

marker3 = "## 四、插件模块"
if marker3 in original:
    original = original.replace(marker3, frontend_supplement + marker3)

# ========== 5. 在 4.1 末尾补充插件遗漏 ==========
plugin_supplement = r"""

---

### 补充：插件工程细节

#### VS Code 诊断标记的 source/sink 行号定位（`extension.js`）

模型返回的 `source_line` 和 `sink_line` 是相对于输入代码的，但 VS Code 编辑器中可能有折叠、注释、换行等差异。插件需要把模型返回的行号映射到编辑器中的实际位置，然后创建 `Diagnostic` 对象并设置 `range` 为对应行号的整行范围。对于长文件切片后的结果，还需要考虑 chunk 偏移。

> 素材库提到诊断标记，但未描述**行号映射的工程难度**。

#### IntelliJ 插件的手写 JSON 转义（`VulnScannerAction.java`）

IntelliJ 插件的桩代码不能依赖第三方库（如 Gson/Jackson），而 Java 标准库没有内置的 JSON 字符串转义工具。`escapeJson` 方法逐字符处理： `"` → `\"`, `\` → `\\`, `\n` → `\n`, 控制字符 → `\uXXXX`。这是"零依赖"约束下的工程妥协。

```java
private String escapeJson(String s) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < s.length(); i++) {
        char c = s.charAt(i);
        switch (c) {
            case '"': sb.append("\\\""); break;
            case '\\': sb.append("\\\\"); break;
            case '\n': sb.append("\\n"); break;
            case '\r': sb.append("\\r"); break;
            case '\t': sb.append("\\t"); break;
            default:
                if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                else sb.append(c);
        }
    }
    return sb.toString();
}
```

> 素材库已提到手写 JSON 转义，但可补充**为什么需要手写**（零依赖约束）。

"""

marker4 = "## 五、项目级亮点与创新点"
if marker4 in original:
    original = original.replace(marker4, plugin_supplement + marker4)

# ========== 6. 在"五、项目级亮点"中补充 RAG Top-K 实验 ==========
rag_supplement = """

#### 补充：RAG 检索 Top-K 对照实验（原始素材库遗漏）

素材库 1.1.1 提到"RAG 未带来检测提升"，但**遗漏了 K=3/5/10 的对照实验数据**（来源：`规划.md`）：

| K | 召回率 | 误报率 | 准确率 |
|---|-------|-------|-------|
| 1 | 95.0% | 33.3% | 86.2% |
| 3 | 96.7% | 25.9% | 89.7% |
| **5** | **100.0%** | 29.6% | **90.8%** |
| 10 | 98.3% | 25.9% | 90.8% |

K=5 召回率最高（100%），但 K=3 是准确率/FPR 综合最优。这是 RAG 调参的实证数据，论文可以引用。

"""

# Insert after "### 亮点 2："Local 探索 → 云端放大"双轨策略"
marker5 = "### 亮点 2：\"本地探索 → 云端放大\"双轨策略"
if marker5 in original:
    original = original.replace(marker5, marker5 + "\n" + rag_supplement)

# ========== 7. 在文档末尾替换旧结尾，增加 PPT 章节 ==========
old_end = """> 本素材库基于项目全量代码与文档的深度审查整理。所有素材标注来源文件，可追溯。
>
> **待办 / 未决事项**（需补跑 / 补数据 / 修代码 / 统一文档口径）已统一移至《素材库_待办清单.md》，本文件不再收录未完成项。
>
> 最后更新：2026-08-10（含深度复核增补：α0 状态、exp_05 v2、V3_PROMPT 统一、前端/插件纠错）"""

ppt_section = """

---

## 八、PPT 专用素材

> 本节按"视觉冲击力"排序，适合 PPT 的标题页、章节页、对比页、数据页直接引用。每个亮点附建议展示方式。

### 8.1 十个"一句话亮点"（标题/金句）

| # | 金句 | 建议展示页 |
|---|------|-----------|
| 1 | **"从开放生成到封闭判别"**——LLM 任务从"全文中发现漏洞"变为"对具体 finding 判定真伪" | 架构设计页 |
| 2 | **"80% 文件不调用 LLM"**——自研 Prefilter 预筛层短路 + 两阶段架构，LLM 只介入 5-20% 文件 | 性能优化页（漏斗图）|
| 3 | **"100 元训练出 95% 召回"**——从 914 条手写到 7692 条蒸馏，云端 4.1h A800 训练 | 经济性/训练页 |
| 4 | **"18/87 解析失败 → 0/87"**——max_tokens 扩容 + 自研约束解码兜底，parse_fail 归零 | 工程可靠性页 |
| 5 | **"数据可信度比指标绝对值更重要"**——v4 训练-测试泄漏导致 100 条样本废弃，Jaccard 审计建立 | 方法论自觉页 |
| 6 | **"合成集 96.7% vs 真实 CVE 37.5%"**——59.2pp 虚高差距，证明必须用真实 CVE 验证 | 实验设计页 |
| 7 | **"模型自检：CoT 说有风险，JSON 不得标 false"**——Self-Verification 后处理让模型自己纠偏 | 创新点页 |
| 8 | **"两种 4-bit 量化差距 20pp"**——HF NF4+FP16 LoRA = 95% 召回，Ollama Q4_K_M = 75~79% | 量化分析页 |
| 9 | **"自研 JSON 解析器、自研 SVG 图表、自研 JSON 转义、自研污点分析"**——零依赖 + 自研工具链贯穿全栈 | 工程实现页 |
| 10 | **"专业的安全工具应该是隐形的"**——数据 > 装饰 | 前端设计页 |

### 8.2 适合画架构图的素材

| 主题 | 建议图型 | 关键数据/标注 |
|------|---------|--------------|
| 两阶段扫描架构 | 泳道图/流程图 | Stage 1（自研 TaintTracker + Semgrep + 自研 Prefilter）→ Stage 2（LLM 裁决）→ 无候选→安全 |
| 漏斗图：文件过滤 | 漏斗图 | 100% 文件 → 自研 Prefilter 短路 80% → 自研 CodeSlicer 切片 15% → LLM 裁决 5% |
| 自研工具链 | 工具栈图 | TaintTracker / Prefilter / CodeSlicer / CWE Normalizer / FixVerifier / SARIF Generator |
| 数据版本血缘 | 时间轴/流程图 | v2→v3→v4(废弃)→v5→v6(废弃)→v7→v8(失败)→v9→v9max→α0 |
| 实验迭代历程 | 折线图+标注 | baseline 0.459 → v9max 0.607 strict_recall，标注每次失败教训 |
| 量化缺口对比 | 柱状图 | HF 95% vs Ollama 75%（CVE-fix），合成集上 Ollama FPR 反而更低 7.7% |
| 经济性饼图 | 饼图 | DeepSeek 40 元 + GLM 40 元 + A800 20 元 = 100 元 |
| 优先级调度器 | 队列示意图 | HIGH（交互式）→ LOW（批量），max_queue=50, max_per_client=8 |
| 前端设计系统 | 设计 token 展示 | 品牌色 #48b0cf，深浅双色系，动效曲线 |

### 8.3 适合放截图/录屏的素材

| 主题 | 建议展示方式 | 来源 |
|------|-------------|------|
| VS Code 诊断波浪线 | 截图：编辑器中红色波浪线 + 后端结果卡片 | `extension.js` |
| 主题切换动画 | 录屏：深色/浅色切换的交叉淡化 | `theme.js` |
| 评分圆环动画 | 慢放录屏：对比 stroke-dash 跳变 vs arcPath 丝滑 | `index.html` |
| 批量扫描进度流 | 录屏：NDJSON 流式逐行显示进度 | `main.py` `/api/batch` |
| 模型管理抽屉 | 截图：拉取/删除/切换模型的流式进度 | `nivis-common.js` |
| 调度器队列状态 | 截图：`/api/queue/status` 返回的 JSON | `scheduler.py` |

### 8.4 适合放代码片段的素材（PPT 代码页）

| 代码片段 | 行数 | 亮点说明 | 文件 |
|---------|------|---------|------|
| `_extract_json_object` 状态机 | ~30 行 | **自研**手写括号深度匹配，不用正则 | `two_stage_scanner.py` |
| `_maybe_recheck` 抽样复核 | ~20 行 | **自研**10% 抽样监控工具漏报率 | `two_stage_scanner.py` |
| `ScanTask` dataclass | ~15 行 | **自研**heapq 优先级队列设计 | `scheduler.py` |
| `escapeJson` 手写转义 | ~20 行 | **自研**Java 零依赖 JSON 转义 | `VulnScannerAction.java` |
| `arcPath` SVG 动画 | ~30 行 | **自研**三角函数逐帧计算规避 Chrome Bug | `index.html` |
| `generate_batch` 批量解码 | ~15 行 | **自研**摊薄 GPU 权重读取 | `scanner.py` |
| TaintTracker 线性数据流 | ~50 行 | **自研**tree-sitter 污点分析 + 消毒识别 + 两遍法 | `taint_tracker.py` |
| Prefilter 规则匹配 | ~30 行 | **自研**正则预筛 + 硬编码凭证标记抑制 | `prefilter.py` |
| CWE Normalizer 查表 | ~15 行 | **自研**零 token 开销 CWE 纠正 | `cwe_normalizer.py` |

---

> 本素材库（融合版）基于项目全量代码与文档的深度审查整理，包含原始素材库内容 + 代码层面深度审查补充（2026-08-10）。**所有自研工具均标注来源文件**，可追溯。
>
> **自研工具清单**：TaintTracker（污点分析）、Prefilter（正则预筛）、CodeSlicer（AST 切片）、CWE Normalizer（CWE 纠正）、FixVerifier（修复验证）、SARIF Report Generator（SARIF 导出）。
>
> **待办 / 未决事项**（需补跑 / 补数据 / 修代码 / 统一文档口径）已统一移至《素材库_待办清单.md》，本文件不再收录未完成项。
>
> 最后更新：2026-08-10（融合版：含原始素材库 + 代码审查补充 + 自研工具标注 + PPT 专用素材）
"""

if old_end in original:
    original = original.replace(old_end, ppt_section)
else:
    original = original.rstrip() + "\n\n" + ppt_section

# ========== 8. 写入输出文件 ==========
output_path = r"D:\code\毕业设计\Graduation-Project\docs\论文\素材库_论文写作素材收集_融合版.md"
with open(output_path, "w", encoding="utf-8") as f:
    f.write(original)

print(f"Written to: {output_path}")
print(f"Total chars: {len(original)}")
