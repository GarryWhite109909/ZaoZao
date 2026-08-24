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
