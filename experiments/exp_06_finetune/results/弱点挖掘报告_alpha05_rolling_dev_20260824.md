# alpha05 弱点挖掘报告（rolling_dev + real-safe，2026-08-24）

> 模型层口径：evaluate.py 单条贪心解码、system=alpha05 训练原版、无工具层参与。
> 引擎：Qwen3-8B NF4 + adapter_alpha05_stage2 (ROCm/RX 9060 XT 16G)。
> 数据：rolling_dev 50 条（vuln，2026 真实 CVE，冻结）+ real-safe 47 条（离线补丁重建，本次新建）。

## 一、总指标（模型层，历史首个干净基线）

| 指标 | 值 | 说明 |
|---|---|---|
| recall（loose，vuln 50） | **0.457** (21/46) | 4 条长文件 OOM 工件不计入分母 |
| **真实 FPR（safe 47）** | **0.60** (25/42) | **史上首次测量**，5 条 OOM 工件除外 |
| strict recall（CWE 匹配） | **0.065** (3/46) | 21 个 TP 中 18 个 CWE 标错 |
| 配对准确率（同文件两侧都对） | 0.10 (4/42) | |
| 翻转一致性（vuln 判对时 safe 也判对） | **0.20** (4/20) | 16 次漏洞版报对、修复版仍报 |

对照：cve_fix20 recall 0.88 —— 该集 7/20 文件与 alpha05 训练数据存在亚阈值重叠（宽松口径实测），
分数被记忆抬高；rolling_dev（0 重叠）才是真实泛化水平。

## 二、FN 根因分类（25 条解剖）

### 1. 污点源枚举过窄——库代码/间接输入盲区（~11 条，最大根因）
模型只认 request/input/argv 类显式 web 入口；以下均被判"无用户可控输入→安全"：
- 库函数参数即污点边界（corpus_00001.js JSONata 原型污染、00041.py、00055.java、00073.py、00081.php WordPress 调用栈）
- 文件/协议内容作为输入（00060.java PDF 解析、00082.go、00030.go）
- 配置/构造函数传入（00055.java）
训练数据几乎全是带显式入口的 web handler；wave2 的 46 条 nosource_safe 全是顶层脚本形态
（实测 44/46），教的是窄规则"顶层无入口=安全"，未教"库函数参数=入口"。这是数据空缺不是错误教学。

### 2. sink 词表/语义知识缺口（~10 条）
模型危险 sink 清单 = execute/system/open/eval，以下类型系统性盲：
- 弱加密 CWE-327（00042/43：jwt.verify/MessageDigest 被当"安全处理"）
- 整数溢出 CWE-190（00030/51/82："仅用于格式判断"）
- XXE/XPath CWE-611（00060/61/88：XPath.evaluate 本身就是 sink）
- CSRF/IDOR 逻辑类（00052/63/84：无数据流形态的漏洞）
- 硬编码凭证 CWE-798（00071/72：system 明文教了规则2 仍漏——训练样本形态单一）

### 3. 过度信任净化（~4 条，文档记载根因在真实数据复现）
- 00067/68.py：`_sanitize_value` 替换 shell 操作符被判有效（黑名单可绕过）；jwt.verify 被当万能防御
- 00005.java：白名单机制被信任（SSTI）
- 00054.js：XFF 信任问题未被理解（找注入而非信任边界）

## 三、类型归因塌缩（strict 口径杀手）

21 个 TP 中：**11 个标成 CWE-78 OS Command Injection**（真类是 SSTI/重定向/CSRF/反序列化/路径穿越/SSRF），
另编造 CWE-915/903/737/732/287/932/912/745 等"编号+望文生义名称"组合，或张冠李戴（CWE-79 SQL Injection）。
根因假设：训练头部 CWE-89(262)/CWE-78(228) 主导 + 长尾类型演示不足 → 判"有危险"后默认贴头部标签。
影响两阶段管线的 _recheck_type_plausible 形态门（类型错→真漏洞可能被拦转 review）。

## 四、FP 根因（25 条 + 翻转失败 16 条）

1. **修复识别失败（核心）**：vuln 判对但官方修复版仍报警 16/20。修复加的防御/校验（htmlspecialchars、
   CIDR 白名单、参数化）不被识别为有效。与 FN 根因 3 同源：防御有效性判断能力弱，两个方向都受害。
2. **猜测式报警**：理由高频出现"可能注入/潜在注入/可能执行"——真实代码数据流复杂度超出训练分布，
   确定性知识不足时退化为形态触发（看到数据流+危险词就猜），即 87 段上诊断的形态触发 FP 在真实数据再现。
3. 口径注记：safe 标签="修复了原 CVE"，不保证无其他漏洞，0.60 的 FPR 含少量高估；
   但 16/20 翻转失败与猜测式措辞表明主体是真 FP。

## 五、矿场覆盖度结论（现有数据能否全面找弱点）

已测：真实 CVE 形态 FN（21 CWE 族×5 语言）、真实 FPR、配对边界锐度 —— L1 交付。
不可测（L1 固有盲区，需 L2 手写探针 50~60 题补）：框架习语 FN（nextjs middleware 型，rolling_dev 框架标记仅 gin3/spring2/flask2/fastapi1）、
跨文件污点（0 条）、无污点硬安全（字面量/假 sink）、minimal pair 边界（L1 配对已部分覆盖）。
另有 4+5 条长文件因 16G 显存 OOM 未测（见工程发现）。

## 六、工程发现（自动排障记录）

1. **--batch>1 在 ROCm 上不可信**：batch=4 时 2/4 样本输出劣化（parse_fail），单条重跑变 TP；
   与贪心等价的假设在 AMD 数值路径上不成立。本机评估一律 batch=1。
2. **长文件 OOM**：代码 >~4000 token 时 prefill 全位置 logits 物化挤爆 16G（vuln 4 条 + safe 5 条，
   expandable_segments 仅救回 1 条）。对应计划 P5 长度守门，部署层同样存在。可改 ollama/llama.cpp 后端或分片。
3. rolling_dev 补丁文件缺 diff 头且末行无换行（构建脚本已适配：build_rolling_dev_safe.py，
   47/50 成功，3 条 Go 上下文不匹配按方案跳过）。

## 七、行动映射（alpha06-v2 SFT / DPO）

| 弱点 | 修法 | 载体 |
|---|---|---|
| 库代码参数盲区（最大 FN 根因） | "函数参数即污点边界"跨语义结构演示 100~200 条（库代码/协议输入/框架回调三形态） | SFT |
| sink 词表缺口 | XPath/XXE/弱加密/整数溢出/CSRF/硬编码凭证各族补演示 + 真实 CVE 种子 | SFT |
| 净化过度信任 | 黑名单绕过 minimal pair（已在 wave2 D 类设计中，未生成） | SFT |
| 修复识别失败（翻转 0.20） | wave1 修复对已有 286 对，但真实代码防御形态多样——教师以真实 fix commit 为种子扩防御形态谱 | SFT |
| CWE-78 塌缩 | 长尾类型样本配比 + 结论单类型约束强化；strict 口径进评估 | SFT+评估 |
| 猜测式报警 | "无证据不猜测"CoT 演示 + safe 侧 CoT 引用具体防御行号 | SFT，DPO 补 |
| （本轮 25 FP + 25 FN 的 raw_output） | on-policy 偏好对燃料——但属 alpha05 策略，只作 SFT 参考；DPO 等 alpha06 训后重挖 | DPO 备用 |

## 八、产物清单

- `results/mining_merged_rolling_dev_20260824.json`（vuln 50 合并结果，含 raw_output）
- `results/mining_real_safe_20260824.json`（safe 47 结果）
- `results/弱点挖掘报告_alpha05_rolling_dev_20260824.md`（本文件）
- `corpus/rolling_dev_safe/`（47 条 + manifest + safe_map.json）
- `scripts/build_rolling_dev_safe.py`、`scripts/analyze_mining_run.py`（可复用）

## 九、工具层弱点矩阵（2026-08-24 增补，纯工具扫描 train_pool 291 条）

脚本：`scripts/mine_tool_weakness_trainpool.py`（与生产 `_stage1_recall` 完全同路径，无 LLM）

| 维度 | 结果 |
|---|---|
| 总覆盖（有候选） | **37/291 = 13%** |
| 按语言 | PHP **4%**(3/76)、Go **5%**(4/76)、Java 10%、JS 10%、Python 33%（工具层 Python 中心的直接证据；Go+PHP 占语料一半） |
| 全盲或近全盲 CWE | 190(0/7)、441(0/7)、601(0/10)、327(1/22)、89(1/19)、79(1/18)、798(1/18)、918(1/17) |
| 工具开火分布 | semgrep 25 / bandit 16 / taint_tracker 12 / prefilter 3 |

生产含义：87% 的真实漏洞文件拿不到候选 → 走全文件复核昂贵路径（两阶段跑实测前 4 条 rolling_dev
全部 findings=0），且长文件在该路径撞 OOM/静默截断。工具召回率是成本与精度的共同上限。

抽样观察：未覆盖尾部的漏洞形态大量是间接模式（错误消息里的 Sprintf 不是漏洞点，
真正的污点链藏在框架封装后面）——手工补词表不可 scaling，须走补丁驱动挖掘。

### 提升路径（泛化导向，防作弊纪律）

**纪律（对应审查报告 P6"隐性测试集拟合痕迹"，违反即作弊）：**
1. 新规则只允许命名漏洞语义模式（语言习语/API 形态级），禁止引用任何测试文件名/CVE 号/样本名；
2. 规则开发只用 train_pool（训练侧资产）+ patches/ 修复 diff；rolling_dev 只测量不调参
   （发布前一次），最终验证走 L2 探针 tool_blindspot_hint 与 L3 时间盲测；
3. 每条规则登记 P6 表（管线层 × 触发条件 × 来源依据：通用规则 / 经验阈值）；
4. 一切阈值（邻域行数、评分权重）只在开发池上选；验收标准 = held-out 覆盖/定位提升，
   不接受"某测试集分数变了"作为依据。

**杠杆（按性价比）：**
1. **补丁驱动词表挖掘**：291 条全带修复 patch。聚合每类 CWE 的 diff 变更行
   （删除行=漏洞 API 形态、新增行=防御形态），自动产出 Go database/sql+Sprintf 拼接、
   PHP mysqli/PDO 拼接、XML 解析器配置等候选规则素材——从"修复如何修"反推"漏洞长什么样"，
   这是泛化路径，与逐个手写规则有本质区别；
2. taint_tracker/prefilter 的 source/sink 表按上述素材做语言扩展（当前 Python 中心）;
3. 无候选长文件：确定性分块预筛（函数切块+语义打分取 top-k 复核），P5 守卫从告警升级为行动；
4. 每轮规则更新后在 train_pool 内部留出片（按 CVE id 哈希后 20%）+ rolling_dev 复测覆盖率，
   增量必须可归因到新增规则的语义类别。

## 十、两阶段对比结果（2026-08-24 完成，50 条全量，12802s）

`results/two_stage_mining_rolling_dev_20260824.json`（transformers + triage_train_aligned + N=3）

### 端到端 vs 纯模型

| 口径 | 纯模型直推 | 两阶段（工具+裁决） |
|---|---|---|
| recall | 0.457 (21/46) | **0.32 全量口径** (16/50)；不含 review 0.47 (16/34) |
| review 率 | 0（无投票机制） | **32%** (16/50)，跨全 CWE 族 |
| 判定构成 | TP21/FN25 | TP16/FN18/review16 |

### 关键归因（交叉表，按 predicted 字段修正）

- **真·救回仅 6 条，且全部来自无候选全文件复核的 N=3 投票**（llm 路径，蛮力），
  与工具无关；
- **真·丢失 5 条**：3 条投票翻转判 safe + **2 条切片裁决推翻真实漏洞**
  （00056.java CWE-502、00078.py CWE-918，均带 semgrep 候选仍被否决）；
- **切片裁决路径只触发 5/50**（确定性工具覆盖 10%，与 train_pool 13% 一致），
  且触发时 **4/5 推翻工具给出的污点链证据**——00067/68.py 在纯模型下因"过度信任
  sanitize"漏报，带上 semgrep+TaintTracker 的 source→sink 链后**依然**否决。

### 结论：当前架构下"工具提示"价值≈0，瓶颈在两端

1. **工具端**：10~13% 覆盖率使切片路径近乎不启用（第九节补丁驱动挖掘针对此）；
2. **裁决端（新发现）**：即使工具给出完整污点链，模型也以 4/5 概率推翻。
   修复不能走"工具说了算"的捷径（同样作弊），正确做法是把污点链纳入裁决
   检查清单强制逐条回应（prompt 层）+ 训练数据加入"有工具证据时的正确裁决"
   演示（SFT 层）；
3. **长文件实锤恶化**：不再 OOM 报错，但更隐蔽——00071/74 静默截断后自信判
   safe（真实漏洞）、00066/75 异常吞掉转 unknown review（10s/2s 即失败）、
   00080 低置信 review。P5 从理论风险变为五种具体坏结局，无候选分块预筛
   必须做。

### 对论文/答辩的意义

"两阶段架构在合成集上收益明显、在真实 2026 CVE 上工具召回坍塌导致架构优势
消失"——这是诚实的消融结论；配合第九节的提升路径，正好构成"发现问题→
归因→改进方案"的完整闭环叙事。

## 十一、三线修复落地（2026-08-24 并行执行）

| 线 | 内容 | 状态 |
|---|---|---|
| ① 补丁驱动词表挖掘 | `scripts/mine_patch_vocab.py`：291 条修复 diff → **74 个 CWE×语言桶**的漏洞/防御 API 形状素材（`results/patch_vocab_material.{json,md}`）。已见真实信号：CWE-1336 PHP 桶 `$view->renderstring`（漏洞侧）vs `$view->rendersandboxedstring`（仅防御侧）即 October CMS 官方修复模式。噪声（注释/测试脚手架）留待人工筛选规则时过滤——素材定位是给规则作者供弹药，不自动产规则（防作弊纪律） | ✅ 完成 |
| ②a 裁决证据消费条款 | `prompts.py build_triage_prompt`：带传播链的 finding 强制新增「证据链逐段核验」——逐跳回应或指认断点行+断因，"笼统说有防御"不再构成有效否定；位置型（无链）告警保持独立判定不受影响。自检通过、回归 23/23 绿 | ✅ 完成 |
| ③ 无候选分块预筛 | `two_stage_scanner.py _prescreen_chunks`：长文件（>num_ctx*0.45）复核前确定性切块（函数级，无结构退化为 150 行窗）、通用安全词表打分（sink×3/外部源×2/入口×1，单模式封顶防刷分）、正分块优先取 top-k（VULN_SCANNER_PRESCREEN_TOPK，默认3）；类型形态门仍用原全文。预筛信息入 recheck 可观测字段。三个冒烟全过（函数结构选中漏洞块/行窗保底/正分优先），回归 23/23 绿 | ✅ 完成 |
| ②b 证据消费 SFT 演示生成器 | `scripts/gen_evidence_adjudication_demos.py`：种子=污点链命中真漏洞（正例，教确认每跳）+ 官方修复版上工具仍开火（反例，教指认断点）——两种最缺的裁决演示。产出与生产裁决同构（system=ALPHA05_PROMPT/user=build_triage_prompt）。**已完成蒸馏：37 条入库（正例 7 / 反例 30），方向校验零错误**；抽检确认逐段核验行为到位（反例能指认断点行 L101/L102 的 escape() 中和点并检查替代通道）。工程坑：思考型教师模型会把 max_tokens 花在思维链导致 content 空——提到 8000 + reasoning_content 兜底后成功率 34/35 | ✅ 完成 |

**验收口径**（防作弊）：②a/③ 的效果验证只允许在 rolling_dev 复测（一次性）+ L2 探针 +
L3 时间盲测上进行；train_pool 内部按 CVE 哈希留出片用于迭代调参。

## 十二、alpha06-v2 冻结（2026-08-25）

`build_alpha06_final_v2.py` → `data/final_train_chatml_alpha06_v2.jsonl`

| 来源 | 条数 | 对应弱点 |
|---|---|---|
| 旧 alpha05 清洗集 | 7599+574wave1 等（同 v1 管道） | — |
| wave2 语义结构变体 | 201（framework 122 / nosource 67 / **crossfile 6 / trust pair 6**，含盲区栈目标） | 跨文件失明、信任边界 FN、习语盲区 |
| **检查清单 CoT** | **105**（19 CWE 族分层） | 清单演示率 0.1%→3.8%（158/4160 漏洞样本含第二入口核验） |
| **证据消费裁决演示** | **37**（正 7/反 30） | 切片裁决 4/5 推翻污点链 |
| triage 裁决样本 | 24 | review 弱点 |

- 泄漏门：31 剔除（新增 realsafe 对照后比 v1 多命中 1）；断言门：61 阻断；
- **最终冻结：8530 条**。
- 工程教训（复用必读）：`call_teacher(key, user_prompt, max_tokens)` 无 system 参数，
  调用方极易把 schema 文本错位成 max_tokens——本轮清单脚本因此全灭过一轮（教师
  收不到代码）。思考型教师 max_tokens 建议 ≥8000 并做 reasoning_content 兜底。
