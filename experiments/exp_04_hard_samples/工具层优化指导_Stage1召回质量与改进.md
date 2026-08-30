# Stage 1 工具层优化指导 —— 召回质量实证与改进清单

- 整理日期：2026-08-29
- 数据来源：① fixed5 全量 87 段评估（`exp_07_two_stage_eval/...20260818_104203.json`）逐样本
  `stage1.by_tool/decision` 统计；② α0.5 前端 11 轮实拍；③ 工具离线实测复现
- 姊妹文档：`优化建议_alpha06_日志类CWE归因辨析_v2_14.md`（模型/训练侧）。本文聚焦**工具召回层**

---

## 一、工具层现状：数据是难看的

```
87 段全量（fixed5）：
  Stage 1 零召回            36 段（41%）
    其中「期望有漏洞」       25 段  ← 工具完全没看到
  无候选 → LLM 兜底判真      24 段
  有候选 → 模型否决后复核翻案  3 段
  工具累计命中：semgrep 93 · bandit 32 · taint_tracker 18 · prefilter 4
```

**结论：系统当前的有效召回有相当比例是 LLM 全文复核扛下来的，工具层只覆盖了约半数样本。**
这解释了前端"模型全文复核发现（非工具召回）"徽章为何高频出现——它不是异常，是现状。

### 25 段「零召回 × 真漏洞」的 category 画像（工具覆盖缺口清单）

| category | 段数 | 代表样本 | 缺口性质 |
|---|---|---|---|
| cve_real | 3 | spring4shell / struts2-ognl / fastjson | Java 框架级漏洞，无对应规则 |
| open_redirect | 2 | typical_12 / typical_31 | 无 redirect sink 规则 |
| weak_cryptography | 2 | typical_18（硬编码IV）/ typical_19（弱随机） | 无 crypto 规则 |
| hardcoded_secret | 1 | typical_06（AWS key） | **secret 档，已定位接入 bug（见 §二）** |
| log_injection | 1 | hard_cve_02 | 无 log sink 规则 |
| prototype_pollution | 1 | typical_32 | 无递归 merge 键名规则 |
| integer_overflow | 1 | typical_29 | 无算术溢出规则 |
| timing_attack | 1 | hard_bypass_06 | 无 `==` 比较 token 规则 |
| cross_file_helper | 1 | crossfile_02_input | 跨文件数据流（架构级） |
| xxe / ldap / nosql / xpath / mass_assignment / idor / session_fixation / insecure_tls / missing_authorization / type_juggling / code_injection | 各 1 | — | 均无对应规则 |

→ **缺口高度分散**（16 个 category 各 1~3 段），不是"补一条规则能解决"，而是**规则库整体覆盖面不足**。

---

## 二、已定位并修复的接入层 Bug（不是工具能力问题）

### B1（已修，2026-08-29）：secret 档对代码文件整体关闭 + gitleaks 缺 --no-git

**两处叠加，导致 secret 检测在代码文件上必然零召回：**

1. `two_stage_scanner.py`（原 L1648）：`if suffix not in code_file_exts` 才跑 secret ——
   `.py/.js/.java` 被排除，而硬编码凭证绝大多数写在代码文件里
2. `external_scanner._run_gitleaks`：命令缺 `--no-git`，gitleaks 默认走 git 历史模式，
   管道用 `NamedTemporaryFile`（无 `.git`）扫描 → 必然零输出

**注释里的"gitleaks 无 .git 时对单文件几乎不命中"是个自我实现的预言**——工具没坏，
是调用方式让它必然不命中，然后这个"观察结果"又被写成注释反过来正当化了排除逻辑。

**实测证据**（离线手工跑，加 `--no-git`）：
```
$ gitleaks detect --source <dir> --no-git --report-format json
{"RuleID":"generic-api-key","StartLine":8,"Secret":"sup3r_s3cret_t0k3n_very_long",
 "File":"hard_bypass_06_auth_string_compare.py","Entropy":3.896}   ← 精确命中，耗时 73.8ms
```

**修复**：两处均改（secret 档对全文件启用 + 补 `--no-git`）。
**验证**：hard_bypass_06 召回 0 → 1 条候选；safe_01/noise_06/safe_11/typical_01 零误报。

**教训（写入规范）**：工具接入后必须做"已知阳性样本冒烟"——用一个必然命中的最小样例验证
调用链，否则"零召回"会被误读成"该工具对这类代码无效"，进而固化成错误的排除逻辑。

### B2（已修，2026-08-29 第二波）：typical_06 / typical_18 —— 规则覆盖问题

修复 B1 后这两个样本 gitleaks 仍 0 命中，原因是规则语义：
- typical_06：`AWS_ACCESS_KEY_ID = "AKIA..."` —— generic-api-key 未覆盖 AWS 前缀形态
- typical_18：`SECRET_KEY = b"this_is_a_hardcoded_secret_key_32_byte"[:32]` —— 字节串字面量 + 切片表达式

**修复**：新增 `graduation_project/gitleaks_rules.toml`（`[extend] useDefault=true`
追加于默认规则集之上，不替换），两条自定义规则均按"语言/工具规范形态"声明：
- `aws-access-key-id`：AWS 官方 Access Key ID 格式（AKIA/ASIA/ABIA/ACCA + 16 位）
- `python-bytes-literal-secret`：凭证语义命名标识符 ← Python 字节串字面量（`b"..."`
  是 Python 特有语法，天然语言隔离）

接线：`external_scanner._run_gitleaks` 挂 `--config`（规则文件缺失时降级为默认
规则集）。**冒烟自测首跑即抓到该接线的初版 bug**（`cmd[3:3]` 插值位置把
`--source` 与其路径值拆散 → 静默零输出）——P0 冒烟自测价值的直接实证。

**验证**：typical_06 → aws-access-key-id 命中、typical_18 → python-bytes-literal-secret
命中、hard_bypass_06 → generic-api-key（默认规则不受影响）；safe/noise 全 24 段零误报。

### B3（已修，2026-08-29 第二波）：secret 类 SAST 规则归入直出档

修复：`_drop_irrelevant_positional` 中，位置型告警按"无主"剔除前先过
`_is_secret_class_alert` 甄别（rule_id 通道：B105/B106/B107、hardcoded-token 族；
message 通道：hardcoded password/secret/token/credential）。命中者转
`category="secret"`，与 gitleaks 同通道直出（`_direct_adjudication`，不消耗 LLM）。
非 secret 的乱码语义照常剔除、照常触发强制复核。

**验证**：typical_15/16、hard_crossfile_03_sink（`app.secret_key = "dev_key"` 被
B105 命中）等 11 段经 secret 直出通道获得确定性 finding；`_DIRECT_CATEGORIES`
聚合路径复用既有逻辑，文件级 has_vulnerability=True 由直出裁决驱动。

---

## 三、候选冗余（成本与噪声问题）

```
候选数 ≥3 的样本：20/87（23%）
  hard_owasp_02_dvwa_sql 8 · hard_cve_01_samba 7 · typical_03_cmd 6
  typical_05_pickle 6 · hard_bypass_02_cmd_strip 6 · typical_28 6 ...
```

同一漏洞被多个工具/多条规则重复告警（如 typical_28 一条 SQLi 出 4 条候选：
Semgrep×2 + TaintTracker×1 + Prefilter×1）→ **每条都要跑 N=3 次采样裁决**，
4 条候选 = 12 次 LLM 调用，且 3 条最终被 1/2 否决（平票转复核），既费算力又制造噪声。

→ 建议（已实施，2026-08-29 第二波）：候选合并去重——设计见 §五之三。

---

## 四、工具到点但模型否决（证据说服力问题）

```
有候选且模型全部判假：14/87
  其中 safe/noise 类 12 段（正确否决 ✓）
  其余为跨文件/上下文依赖型（模型缺外部函数语义 → 否决）
```

典型：`typical_04`（TaintTracker×1 正确到点）→ 模型 0/3 否决 → 复核翻案 3/0；
`hard_bypass_04` 同型。**工具是对的，模型第一遍是错的**——说明工具证据在裁决 prompt 中
说服力不足，或者是 `sast` 档的"低信任标注"（`_TRUST_NOTES.sast`）诱导模型怀疑正确告警。

→ 建议（已实施，2026-08-29 第二波）：信任标注改按**证据类型**分级——设计见 §五之三。

---

## 五、优先级建议

> 状态更新（2026-08-29 第二波实施后）：P0/P1 全部落地，P2 首批规则族已上线，
> 复测数据见 §五之三。剩余缺口为框架级/长尾 category（§五之五）。

| 优先级 | 项 | 性质 | 状态 |
|---|---|---|---|
| P0 | secret 档接入修复（B1） | 接入 bug，真实召回提升 | ✅ 已修并验证 |
| P0 | 工具冒烟自测（每个工具 1 个必然命中的样例，CI 可跑） | 防 B1 类问题复发 | ✅ 已建 `scripts/tool_smoke_test.py`，首跑即抓到 B2 接线 bug |
| P1 | secret 类 SAST 规则归入直出档（B3） | 已有证据被浪费 | ✅ 已做（`_is_secret_class_alert` 甄别 → 转 secret 直出） |
| P1 | gitleaks 自定义规则补 AWS key / 字节串字面量（B2） | 规则覆盖 | ✅ 已做（`gitleaks_rules.toml`，extend useDefault） |
| P1 | 候选合并去重（§三） | 成本 + 噪声 | ✅ 已做（`_dedupe` 族级归并，候选≥3 样本 20→10） |
| P2 | 补零召回 category 的规则（首批：open redirect / log / timing / crypto×3 / proto×2 / overflow） | 覆盖面 | ✅ 首批已做（§五之三）；剩余框架级 category 见 §五之五 |
| P2 | 污点链证据在裁决 prompt 中的差异化利用（§四） | 裁决层协同 | ✅ 已做（按证据类型分级信任标注） |
| P1 | 信号抑制池的样本级盲区（§五之四，本轮新发现） | 召回损耗 | ⚠️ 已定位、待治理 |
| — | 跨文件数据流（crossfile 全族） | 架构级，需项目级上下文 | 单文件管道外，论文标注局限 |

## 五之二、规则层实锤缺陷：os.path.join 形态零覆盖（已修，2026-08-29）

### 现象

`hard_crossfile_02_input.py` 全工具零召回（实测 semgrep/taint_tracker/prefilter/bandit 全 0），
**工具层根本没提示到点上**——此前"工具到点、模型错"的归因是错误外推（把
typical_04 的情况套到全部路径穿越样本上，而 typical_04 其实**同样零召回**）。

### 根因：规则只认 `+` 号拼接，漏掉 Python 主流写法

```python
# 原规则 path_traversal_open_concat：open(...) 参数区含 "+"  → 命中
f = open("/data/" + filename)                    # ✓ 命中

# Python 实际主流写法（无 "+"）                    → 全部漏
filepath = os.path.join(base_dir, filename)
f = open(filepath, "r")                          # ✗ 漏（结果先赋变量再传）
f = open(os.path.join(base_dir, filename), "r")  # ✗ 漏（内嵌但无 + 号）
```

**量化（87 段全量）**：使用 `os.path.join` + `open` 的样本 6 段，其中 CWE-22 路径穿越 4 段
（typical_04 / hard_bypass_04 / hard_cve_07 / hard_crossfile_02_input）——**原规则命中 0/4**。

### 修复：新增 `path_traversal_open_join` 规则 + 变量级 1 跳追踪

- 新增 `_join_flows_to_sink`：收集被赋值为 `os.path.join(...)` 结果的变量名，再检查
  路径类 sink（`open`/`extractall`/`send_file`/`shutil.*`）实参是否引用该变量，
  或直接内嵌 join 调用
- 新增 `_PATH_SINK_KEYS` 与对应 sink 正则（tar.extractall 覆盖 CVE-2007-4559/2025-4517 形态）

### 泛化纪律（新增规则必须过这三关）

> **"漏洞规则写不完"的前提是规则按样本写。规则必须按「语言/框架的标准写法」写。**

| 关卡 | 检查内容 | 不通过的表现 |
|---|---|---|
| **1. 语言级事实** | 规则里的字面量是不是该语言/标准库的唯一或标准写法？ | 出现具体变量名（`base_dir`）、函数名（`safe_read_file`）、文件名 → 过拟合 |
| **2. 形态抽象** | 匹配的是结构特征（构造 API → 消费 sink）还是拼写特征？ | 只认 `+` 拼接却不认 `os.path.join`；只认 Python 不认 Java 同形态 → 覆盖不全 |
| **3. 独立集验证** | 在规则设计时未接触的数据集上能否命中同类型真漏洞且不误伤？ | 只在设计集有 TP → 不能证明泛化 |

**验证证据（path_traversal_open_join）**：

| 检验 | 结果 |
|---|---|
| 设计集 exp_04（87） | TP=4 FP=0 |
| **独立集 CVE-fix（20，零接触）** | **TP=2 FP=0**（cve_fix_0016.py Python、cve_fix_0017.java Java）|
| 跨语言形态抽查 | Python `os.path.join` / Java IO `new File(d,n)` / Java NIO `Paths.get` / Node `path.join` 全命中；Java 常量路径（安全）不误报 |
| 模块自检 | prefilter 全部用例通过（含新增 3 例）|

**独立集验证暴露并修复的泛化缺口**：初版只覆盖 Python，`cve_fix_0017.java`
（`new File(targetDir, entryName)`）漏检——同语义、不同语法。修复方式是按语言族
声明 API 表，而不是逐个加规则：

```python
_PATH_JOIN_PATTERNS = (os.path.join | path.join | Paths.get | new File(dir, name))
_PATH_SINK_KEYS     = (open | extractall | send_file | shutil | FileInput* | Files.* | fs.*)
```

新增语言 = 表里加一行，**不改匹配逻辑**。这才是规则可持续的写法。

**已知待办（不阻塞）**：Java 侧"前缀校验"安全规则尚未覆盖
（`getCanonicalPath().startsWith(...)`），Java 加固写法会判漏洞，应补 path_safe 系列的 Java 形态。

### 验证

| 项 | 结果 |
|---|---|
| 87 段全量 | 命中 5 段：路径穿越 TP=4，命令注入 1（longfile_02，join 结果进 shell 命令）|
| 安全样本误伤 | **FP=0**（safe_04 因前缀校验仍判安全）|
| 端到端管道 | 4 段从 0 召回 → 各 1~3 条候选，走正常 `has_candidate_adjudicate` 路径 |
| 模块自检 | prefilter 20+3 项全过（新增 3 例：变量传递 / 直接内嵌 / 冲突回落）|

**规则自证性**：路径拼接结果流入文件操作 sink 即构成"外部可控片段进入路径"的结构
特征，与"含 + 号"等价（都是未净化的路径构造），非样本特判。

## 五之三、第二波实施：P2 首批规则族 + 候选合并 + 信任分级（已实施，2026-08-29）

### P2 首批规则（prefilter.py，全部按 §五之二 泛化纪律三关卡设计）

| 规则 | CWE | 漏洞形态（语言/框架标准写法） | 命中样本 |
|---|---|---|---|
| `open_redirect` | CWE-601 | redirect 类 sink（`redirect(`尾缀通用覆盖 Flask/Django/Express/sendRedirect）参数区出现输入源，或引用输入派生变量（1 跳） | typical_12 / typical_31 |
| `log_injection` | CWE-117 | log sink（logging/logger/log.*，`(?<!console\.)` 排除前端）+ 输入（f-string 内插是主流写法，参数区匹配须保留字符串原文） | hard_cve_02 |
| `timing_unsafe_compare` | CWE-208 | 输入派生的凭证/签名变量（token/secret/signature/…词根）参与 `==`/`!=`；**排除 session 内令牌比对**（CSRF 校验标准写法，safe_13 实测后补） | hard_bypass_06 |
| `crypto_weak_hash` | CWE-327 | hashlib.md5/sha1、Crypto.Hash.MD5/SHA1、MessageDigest MD5/SHA-1、createHash('md5') | — |
| `crypto_weak_cipher` | CWE-327 | MODE_ECB、`"X/ECB/"`、DES/DESede/Blowfish/RC4、createCipheriv des/ecb | — |
| `crypto_weak_random` | CWE-338 | 安全语义目标（token/password/…）← random.choices 等可预测 API（os.urandom / SystemRandom / secrets 不在表内 = CSPRNG 天然豁免） | typical_19 |
| `crypto_hardcoded_iv` | CWE-329 | `*IV = b"..."`（大写 IV 后缀是标准命名；**不用** IGNORECASE，排除 activity/derive 等普通词）或 `iv=` 字面量 | typical_18 |
| `proto_pollution_merge` | CWE-1321 | for-in 键遍历 + 键下标写入 + merge 族 API 收 req.body（JS 递归合并三件套，AND 语义） | typical_32 |
| `proto_pollution_direct` | CWE-1321 | `['__proto__'] =` / `__proto__ =` / `.constructor.prototype =` | — |
| `integer_overflow_ext_arith` | CWE-190 | 定宽类型声明 ← 外部来源操作数乘法（@RequestParam/@PathVariable 数值形参、scanf %d、parseInt(request…)）；声明语法即语言隔离（Python int 任意精度不适用） | typical_29 |

配套：`path_canonical_startswith` 安全规则（Java `getCanonicalPath().startsWith` /
NIO `toRealPath().startsWith`，§五之二"已知待办"清账）；cwe_normalizer 登记
CWE-601/117/208/327/329/338/1321/190 规范标签——**只收短语级关键词**
（"weak cryptography"），不收 md5/sha1 裸词：工具 rule_id（insecure-hash-algo-md5）
会经 normalize 参与"回声票"判定（`_aggregate` 的 is_echo），裸词命中会把模型独立
判断误判成复读工具——实施中实际触发过一次该回归（two_stage 自检 #13，
typical_17 实锤行为），已撤销并以注释固化禁令。

### 候选合并去重（`_dedupe` 重写，§三 落地）

在既有 `(taint_type, source, sink)` 主键与 `(类型, sink 行)` 索引之上补三级归并：

1. **语义族索引** `(family, sink_line)`：family 由 `_infer_taint_type` 从
   rule_id/evidence 推断（B608+拼接 evidence → "SQL Injection"）——sast 规则号
   候选与 taint 候选"同行同族"归并（typical_28 的 4 条候选 → 1 条）；
2. **直出档同位置合并** `(secret, sink_line)`：B105（B3 转档后）与 gitleaks 对
   同一凭证的告警并一条，携带 `bandit+gitleaks` 多工具标记；
3. **无行号候选归并**（prefilter，行号全空）：仅当同族**恰好一条**已见候选
   （无歧义）时归并，多条并存时保留（歧义保护由 two_stage 自检 #19 固化）。

合并时补全缺失字段并追加证据（`[tool2] evidence2`），裁决层可见多工具一致；
多工具标记经既有 `tool="a+b"` 机制透出。

### 裁决信任分级按证据类型（§四 落地，prompts.py）

`build_triage_prompt` 的来源可信度标注不再按 category 查表，改按**证据类型**分级：

- 带真实 source→sink 链（TaintTracker / semgrep taint 带 metavars）→
  **链级高信任标注**：链路由数据流引擎得出、方向可靠，"若要推翻必须指认断点
  行号与断因，泛泛的『代码有过滤』不构成有效推翻"——直接回应 typical_04 /
  hard_bypass_04 的"工具到点、模型 0/3 否决、复核翻案"失败模式；
- category=taint 但链为空（semgrep OSS 无 metavars 的形态）→ 降级为位置型警示
  （补齐"挂着 taint 类别却无链"的信任误标）；
- sast/iac/prefilter（无链）→ 既有位置型/正则标注不变。

### 工具冒烟自测（P0 落地，`scripts/tool_smoke_test.py`）

每个工具一组"必然命中阳性样例 + 必然安全样例"，走**项目真实调用链**
（ExternalScanner 各 runner / Prefilter / TaintTracker / secret 直出分发）：
未安装 → SKIP；已安装但阳性零召回 → FAIL（退出码 1，CI 可拦）。trivy(sca/iac)、
pip-audit、detect-secrets 依赖本地漏洞库/网络，零召回按 SKIP 降级不拦 CI。
**首跑即抓到 B2 接线的初版 bug**（`cmd[3:3]` 插值把 `--source` 与路径值拆散 →
静默零输出）——"先查调用链、勿解读为工具无效"的教训由脚本字面固化在 FAIL 提示里。

### 第二波复测（与基线同口径：`--no-signal-feedback` 纯静态管线，禁用抑制池）

| 指标 | 基线（08-18 eval） | 第二波复测 |
|---|---|---|
| Stage 1 零召回 | 36/87（41%） | **23/87（26%）** |
| 零召回 × 期望真 | 25 | **12** |
| 候选数 ≥3 的样本 | 20/87（23%） | **10/87（11%）** |
| 直出档（secret/sca）确定性 finding 覆盖 | 0 段（secret 档当时对代码文件关闭） | **11 段** |
| 安全样本（26 段）中出现候选 | 15 | 15（新规则仅 timing 误触发 safe_13，已修） |

新捞回 13 段全部 expected=true：typical_06 / 12 / 15 / 16 / 18 / 19 / 29 / 31 / 32、
hard_bypass_06、hard_cve_02、hard_crossfile_02_input、hard_crossfile_03_sink。
自检矩阵：prefilter 42 例、two_stage 24 例、cwe_normalizer 全例、
tool_smoke_test 9 PASS / 1 SKIP，全过。

## 五之四、新发现：信号抑制池的样本级盲区（待治理）

复测中实测：生产 `models/signal_registry.json` 已积累 12 条被抑制规则
（门槛 = ≥2 个独立文件被高置信否定，设计如此），其中包括：

- 项目**自有** taint 规则 `graduation_project.semgrep_rules.python-sqli-taint` /
  `python-xss-taint`——被抑制意味着这两族的 source→sink 候选在**所有文件**上
  静默消失（本次复测 typical_02 XSS / safe 系列的差异即此因）；
- bandit B608/B602/B607 等主流注入规则。

**性质**：抑制池按"规则"粒度惩罚，但规则是否误报取决于"文件"——
B608 在 hard_bypass_01（replace 假净化）是否决性证据，在别的文件可能是
正确告警。规则级抑制 → 样本级盲区，且**静默**（工具层零召回，无任何提示），
与 B1 的"排除逻辑自我实现预言"同构。

**口径提示**：评估/论文数据必须用 `--no-signal-feedback`（纯静态管线），
否则工具层数据混入运行期学习状态、不可复现。

**待治理建议**：① 自有 taint 规则（带完整证据链）不进抑制池，或抑制降级为
"候选降权"而非"静默跳过"；② 抑制命中时在 stage1 决策中留痕（如
`suppressed_by_registry` 计数），消除静默性。

## 五之五、剩余零召回缺口（第二波复测后，12 段，均为框架级/长尾）

首批 P2 规则落地后剩余的零召回 × 期望真清单——特征是"漏洞语义在框架层，
单文件正则无标准形态可写"或"需要项目级上下文"：

| 样本 | category | 缺口性质 |
|---|---|---|
| hard_cve_05_spring4shell / hard_cve_06_struts2_ognl / hard_cve_08_fastjson_deser | Java 框架 CVE | 框架层漏洞形态（参数绑定/OGNL/反序列化开关），无对应规则 |
| typical_36_java_spel | SpEL 注入 | 表达式注入 sink（SpelExpressionParser）未建规则 |
| typical_21_xxe | XXE | XML 解析器特性开关（disallow-doctype-decl），缺失型 |
| typical_24_ldap / typical_25_nosql / typical_26_xpath | 注入族长尾 | sink 语义各异（LDAP filter/NosQL query/XPath），可分期补 |
| typical_30_mass_assignment | Mass Assignment | 框架层（强参数/白名单缺失），缺失型 |
| typical_20_insecure_tls | Insecure TLS | 配置型（verify=False 已有形态，但该样本为协议版本配置） |
| typical_33_php_type_juggling | Type Juggling | PHP 松散比较 `==` 语义，语言特性级 |
| hard_crossfile_02_sink | 跨文件 | 数据流在文件边界中断，架构级（论文标注局限） |

→ 处理原则维持 §五之二 泛化纪律：能写出"语言/框架标准写法"的（SpEL sink、
XXE 开关、PHP `==` 敏感比较）分期补；写不出的（框架 CVE、跨文件）留给
LLM 兜底通道并在论文中如实标注。

## 五之三、待办（会动 fixed5 基线，需重跑全量评估后再决定）

### 已修：Insecure TLS（CWE-295）类型缺失 → 精确告警被丢弃（2026-08-29）

**现象**：`typical_20_insecure_tls.py` 界面显示"各工具均 0 命中"，
但实测 **bandit B501 @ line 10 精确命中** `requests.get(url, verify=False)`，
semgrep `disabled-cert-validation` 同样命中 —— 是**命中后被"无主告警剔除"丢弃**。

**根因**：`_infer_taint_type` 无法识别 TLS 类（无对应关键词）→ 返回 rule_id →
不在 `_STANDARD_TAINT_TYPES` 白名单 → 按"无主告警"剔除。

**修复**：白名单加 `Insecure TLS` + 类型推断加**证书专有术语**分支
（`certificate` / `certification validation` / `CERT_NONE` / `check_hostname` /
`create_unverified` / `rejectUnauthorized` / `b501`）。

**为何不用裸 `verify=False`**：该写法在 JWT 场景是"不校验签名"（CWE-347，
hard_bypass_08），语义与 TLS 证书校验完全不同 —— 用专有词可精准区分
（实测两条 TLS 规则 evidence 均含 `SSL certificate` / `certificate verification`，
JWT 规则不含）。

**影响面实测**：
- 含 TLS 特征的真漏洞样本 **2 段**（typical_20 CWE-295、另一段）、**安全样本 0 段**
  → 不增加 FP 风险
- 端到端：typical_20 候选 **0 → 1 条**（B501 保留，走正常裁决而非兜底）
- hard_bypass_08（JWT）未被误判为 TLS ✓
- 10 个安全样本候选数无变化 ✓
- 四模块自检通过

### 待办 1：证据行上下文污染类型推断（hard_cve_03 三次扫描三结论）

**现象**：同一 `hard_cve_03_tarfile_2025_4517.py`（期望 CWE-22）三次扫描：

| 次序 | 结论 | 性质 |
|---|---|---|
| 1 | 中危 CWE-918 SSRF | 类型错 |
| 2 | 安全 | **FN（漏报）** |
| 3 | 中危 CWE-89 SQL 注入 | 类型错 |

**根因（已定位）**：`ExternalFinding.evidence` 会在告警描述后附带
`[告警行上下文]` 源码片段，`_infer_taint_type` 拿整段做关键词匹配 →
semgrep 的 `request-data-write`（用户可控数据写入）因上下文含
`open(`/`extractall` 被推断为 **Path Traversal**（落入标准类型白名单）→
逃过"无主告警剔除"→ 带着错误类型标注进裁决诱导模型投错票。实测证据：

```
rule=models.semgrep_rules...request-data-write
  evidence = "Found user-controlled request data passed into '.write(...)'.
              [告警行上下文] 8:@app.route("/extract" ... open(tmp) ... extractall"
  inferred = "Path Traversal"   ← 被行上下文污染
```

**修复尝试与回滚**：剥离 `[告警行上下文]` 后仅用告警描述推断 —— 该样本
从"2 条错误候选"变为"剔除后 0 候选 + 强制复核兜底"（符合设计意图），
但**全量 87 段回归暴露严重副作用**：15 段真漏洞样本候选归零
（SSRF / XXE / LDAP / NoSQL / 弱密码 / 开放重定向等）——
`_STANDARD_TAINT_TYPES` 白名单只有 7 类注入型漏洞，"不在白名单即剔除"
误杀了所有非注入型漏洞的告警。同时自检用例「B3 secret类转直出」失败。

→ **已回滚**（恢复 fixed5 基线行为）。

**建议方案（下次做，三项一起上）**：
1. 扩展 `_STANDARD_TAINT_TYPES` 覆盖非注入型：SSRF / XXE / LDAP / NoSQL /
   Open Redirect / Weak Crypto / Hardcoded Credential 等
2. 同时启用证据上下文剥离（行上下文只说明"在哪里"，不说明"是什么"）
3. 重跑 87 段全量 + 与 fixed5 做对照表（零召回 41% → ?、复核判真 24 → ?、
   recall/FPR 是否回退）

### 待办 2：Java 路径安全规则缺失

Java 侧前缀校验（`getCanonicalPath().startsWith(...)`）未纳入 `path_safe`
安全规则，Java 加固写法会被判漏洞。按 `_PATH_JOIN_PATTERNS` 同款方式补一行。

### 待办 3：候选合并去重（§三）

23% 样本 ≥3 条候选，每条消耗 N=3 次采样。同（族, sink 行）归并 + 多工具标记，
能显著降成本与噪声。


## 五之四、2026-08-29 夜间批量修复（用户提示质量审计驱动）

用户逐条审计提示质量后提交问题清单，以下为**已实施并验证**的修复：

| # | 问题 | 修复 | 验证 |
|---|---|---|---|
| 1 | `_line_context` 行号标签整体 +1（波 47 条）| `f"{i+1}:{t}" → f"{i}:{t}"` | typical_01 上下文 `9:` 对应真实 L9 ✓ |
| 2 | TaintTracker 对 if/try 块内 sink 产出"块头行"伪路径 | `_sink_nodes_in` 跳过 body 块范围；文本兜底仅限非复合语句 | hard_cve_01 sinkL=11 ✓、typical_28 sinkL=14 ✓；新增复合语句回归用例 |
| 3 | B105 直出档把框架配置型 secret 直接判真（8/10 类型归因错）| 凭证强度门槛（长度+熵+占位符检测，与 gitleaks 同语义）；过门槛→直出，不过→转裁决档并归一 `Hardcoded Credentials`(CWE-798) | 弱值 8/8 转裁决档 ✓、真凭证 3/3 仍直出 ✓；弱值词表含占位符检测（拦 `very_long_dev_secret_key_for_testing_only`）|
| 4 | B310 被上下文"撞词"成 Path Traversal，SSRF 语义丢失 | 新增 `SSRF` 类型（在 Path Traversal 之前判定）+ `\bopen` 词边界（避开 urlopen）+ 白名单加 SSRF | typical_07/hard_cve_04 → SSRF ✓；路径穿越样本不误判 ✓ |
| 5 | 白名单未随 P2 规则族扩展（typical_17 弱哈希证据被剔除）| `_infer_taint_type` 补齐 P2 分支（Weak Cryptography / Prototype Pollution / Open Redirect / Timing Attack / Integer Overflow / Log Injection）+ 白名单同步扩容 | typical_17 的 B324 带行号保留 ✓ |
| 6 | 14 条裁决档候选无位置（prefilter match 丢行号）| prefilter 新增 `matched_lines` 字段 + `_hit_line()` 定位；two_stage 接入；定位不到回落 0（向下兼容）| 无位置候选 14 → 6 条 ✓ |
| 7 | 判真票的 source/sink 证据链被丢弃（顶层恒空）| `parse_triage_verdict` 透传 source/sink；`_adjudicate_one` 暂存锚点；`_adjudicate_all` 在 finding 赋值后回填；reason/explanation 兼容回退 | 模拟前端分析 typical_20：所有字段完整 ✓ |

### 判定顺序修正（重要）

`_infer_taint_type` 的分支顺序会直接影响类型归因，已按"信号强度"重排：
TLS 证书专有词（certificate/verify=False）**先于** SSRF（requests.get），
SSRF **先于** Path Traversal（避免 urlopen 撞词 open(）。
实测三类互不干扰。

### 修复过程中发现并规避的两个陷阱（供后续参考）

1. **改动 `_drop_irrelevant_positional` 时丢失了 `dropped` 分支** → 无主告警剔除
   整体失效（request-data-write 未被剔除）。自检的 B3 用例立即捕获。
   → 教训：改多分支条件时必须保留 else/dropped 落点，靠自检兜底。
2. **在 `_adjudicate_one` 内回填 `verdict.finding` 无效** —— 该字段由外层
   `_adjudicate_all` 赋值（此时为 None）。→ 改为暂存字段、外层回填。

### 第 8 项：证据链回填未同步行号（2026-08-30 实测修复）

第 7 项回填只补了 source/sink **文本**，未同步 **行号** → 出现"文本写 `line 9`、
行号徽标标 `L10`"的自相矛盾（typical_20 实拍：B501 的 source 文本 line 9 却标 L10）。
已修：回填时用 `_anchor_line()` 从判真票锚点取**纠正后**的行号，同步写入
`source_line`/`sink_line`。

**踩坑**：`normalize_line_numbers(..., return_anchors=True)` 在**幂等**时（行号本就
正确、无需纠正）返回空 anchors —— 直接读 anchors 会得到 0。改为从**输出文本**
（恒为 `line N:` 格式）提取行号：正确文本取原行号、错误文本取纠正后行号，两者兼顾。

验证：typical_20 三条候选 srcL=9 / sinkL=10，与文本声明完全一致 ✓。

### 实测反馈：修复暴露了"多漏洞共现 + 单标注"冲突（typical_20）

修复后 typical_20 工具层**召回 5 条**（此前 0 命中），但顶层类型从 CWE-295
变成 **CWE-918**：

| 裁决 | 模型输出类型 | 真实性 |
|---|---|---|
| B501（bandit）| CWE-295 不当证书验证 | 真实（`verify=False`）|
| semgrep ssrf-injection-requests | CWE-918 SSRF | 真实（`url` 用户可控、无 scheme/host 白名单）|
| B113 | CWE-918 SSRF | 真实 |

**两个漏洞都成立**，模型按"危害可达性"（SSRF 可打内网/云元数据 > 证书验证）选了
CWE-918 —— **符合我定的主次规则，是正确行为**。冲突源于 manifest 只标了 CWE-295、
漏标 CWE-918（与 hard_longfile_03 漏标 CWE-79 同类）。

→ 属**标注待办**（用户标签治理范畴），非工程退化。建议把 CWE-918 补进 typical_20
标注（或接受二选一命中）。

### 修不动 / 需重跑评估后决定

- **抑制池压掉真阳性**（typical_02、hard_bypass_03、typical_23、hard_bypass_07、
  typical_13、typical_27、hard_crossfile_01_sink、hard_longfile_01）：
  干净进程下这些样本**均有候选**（1~3 条），说明是生产进程**累积抑制池**导致
  （跨跑污染）。修复需改抑制池机制（衰减/上限/白名单保护），属"会动 fixed5 基线"
  的改动，须重跑 87 段全量评估后决定。
- **safe_18 taint 链自相矛盾**（sink 标签 executeQuery 配 L14 实为 getConnection 行）：
  TaintTracker 的 Java sink 行号定位问题，影响单个安全样本，暂不修（无 FP 风险，
  模型可消解）。
- **其余弱提示**（semgrep 命令注入候选忽略列表参数/shlex 转义、hard_cve_03 的
  request-data-write 偏靶、B701 对 SSTI 旁敲）：已知精度边界，模型能消解，不修。

## 六、判假守卫：数据流不完整不得静默判安全（已实施，2026-08-29）

### 问题：判真有全票门、判假零门槛的不对称

```
复核判真 → trust_llm_recheck + unanimous 全票门（防过度采信）
复核判假 → 直接 no_candidate_recheck_safe（零门槛，静默放行）
```

**helper 型文件**（无自身输入入口、危险 sink 由函数形参驱动、污点来源在调用方）
必然踩中这个不对称：LLM 只看当前文件 → 看不到污染来源 → 判安全 → 静默放行。
`hard_crossfile_02_input.py` 稳定复现 FN（多次扫描结果一致）。

### 修复：`_has_param_driven_sink` 守卫

触发条件（三条同时成立，缺一不可）：
1. 本文件**无任何外部可控输入入口**（`_EXT_ENTRY_RE`）
2. 存在函数定义且有形参
3. 函数体内危险 sink 的实参，经变量赋值展开（≤2 跳）后**依赖该函数形参**

→ 转 `recheck_incomplete_flow_review`（has_vulnerability=None），提示需结合调用方复核。

**规则自证性**：来自安全分析基本原则——"数据流不完整时不得判定安全"，
非测试集拟合。

**87 段全量离线验证**：命中 3 段，全部 `expected=true`，零安全样本误伤：

| 命中样本 | expected | 语义 |
|---|---|---|
| hard_crossfile_02_input.py | true | helper，filename 参数 → open（本次 FN）|
| hard_longfile_01_hidden_sql.py | true | `export_report(table)` 参数拼接 SQL |
| hard_longfile_02_hidden_cmd.py | true | `backup_to_archive(archive_name)` 参数进 shell |

**端到端验证**：3 段转 `recheck_incomplete_flow_review`；
safe_01/02/04/08/17、noise_03 六段仍正常 `no_candidate_recheck_safe`，零误拦。

注：后两段 fixed5 已判 true（走有候选路径），守卫仅在它们复核判安全时兜底，
不改变现有正确判定。

### 顺带修复：`_MONITOR` 缺 `recheck_prescreened` 键

长文件（> num_ctx×0.45）无候选时走分块预筛分支 → `_monitor_incr("recheck_prescreened")`
→ KeyError → `_maybe_recheck` 抛异常 → 整文件"分析失败"。已补键，
并全量核对 `_monitor_incr` 使用键与定义键一致（无缺失）。

## 七、与论文口径的关系

- **诚实标注**：fixed5 recall 1.000 是在"41% 样本工具零召回、24 段靠 LLM 兜底"的前提下取得的。
  论文叙事应避免"工具召回 + LLM 裁决"被读成"工具主要负责召回"——当前实际是
  **LLM 兜底承担了近三成有效发现**，工具层的作用是"给高置信候选 + 降低 FPR"。
- 这条如实写反而是加分项：它印证了方法论中"LLM 不应被工具能力锁死"的设计决策
  （`trust_llm_recheck` 兜底通道的价值由数据支撑）。
- 工具层改进（P0/P1）落地后应重跑全量评估，与 fixed5 做对照表（零召回率 41% → ?、
  兜底判真数 24 → ?），这是可写进论文的工具层消融实验。

**第二波消融数据已就绪（2026-08-29，工具层离线复测，LLM 层待重跑）**：

| 维度 | 基线（08-18） | 第二波工具层 |
|---|---|---|
| Stage 1 零召回率 | 41%（36/87） | **26%（23/87）** |
| 零召回 × 期望真 | 25 段 | **12 段** |
| 候选 ≥3 的样本（冗余度） | 23%（20/87） | **11%（10/87）** |
| 直出档确定性 finding 覆盖 | 4 段 | **11 段** |

工具层消融实验的设计口径：① 基线（08-18 规则+调用方式）；② +接入修复（B1/B2/B3）；
③ +首批 P2 规则族；④ +候选合并。每层都能独立归因（本轮 13 段新捞回的逐样本
清单见 §五之三）。注意：**LLM 兜底判真数（24 → ?）要等裁决层重跑才有**——
工具层捞回的 13 段会从"兜底通道"转移到"有候选裁决通道"，预计兜底承担率
显著下降，这正是"工具层为 LLM 减负"叙事的数据。

## 八、后置待办（2026-08-30，raw_texts 作用域崩溃诊断的遗留项）

### 8.1 typical_20 的 SSRF 共现——标注层决策，工程侧不擅动（等标签治理定夺）

工具层实测（离线 scan_sast）`typical_20_insecure_tls.py` 共 5 命中：

| 规则 | 行 | 语义 |
|---|---|---|
| B501 | L10 | verify=False 关闭证书校验（标注主类型 CWE-295）|
| B113 | L10 | requests 无 timeout（伴生，低危）|
| flask ssrf-requests | L10 | request.args 数据直连 requests.get |
| django ssrf-injection-requests | L9 | 同上（跨框架规则命中 flask 代码）|
| requests disabled-cert-validation | L10 | 与 B501 同语义 |

manifest 只标了 CWE-295，但 **SSRF（CWE-918）在这段代码里客观存在**
（`request.args.get("url")` → `requests.get(url)`，用户可控 URL 直连）。
raw_texts 崩溃修复 + B501 白名单放行后，重扫时若模型确认了 SSRF 候选，
top1 可能变为 CWE-918——**届时属"多漏洞共现/标注漏标"，不是类型归因错误**，
按 F7（主次排序缺失，工程侧无解）处理。待决：是否给 typical_20 补标
`CWE-295;CWE-918`（多标注用 `;` 分隔即可 strict hit）→ 由标签治理定，
不在工具层代码里特判。

### 8.2 崩溃窗口期（08-29 → 08-30 修复前）的扫描产物需复核

2026-08-29 引入 `raw_texts` 时埋下 UnboundLocalError：凡 `_aggregate` 中
top confirmed finding 的 rule_id 命中**信号注册表已提交 corrected_type 的规则**
（当前 14 条：B501、B301、deser_pickle_loads、sqli_percent_format、
`taint_tracker:{Path Traversal, SQL Injection, Command Injection, Code Injection,
Insecure Deserialization}` + 4 条 semgrep 规则），整个 `_aggregate` 中断 →
该文件显示"分析失败"。此窗口期内产生的**任何批量扫描/评估结果**（若有），
命中上述规则的样本需逐个复核是否被记为失败；此后端窗口仅一天，但任何
08-29 之后导出的结果文件都过一遍 `_kind == "error"` 统计再入库。

### 8.3 验证待办（重启后端后执行）

1. 重扫 `typical_20_insecure_tls.py`：预期 True / CWE-295 / High，
   与标注 strict hit；"分析失败"卡片消失。
2. 顺带观察 SSRF 候选是否被确认（若出现 CWE-918，转 8.1 决策）。

### 8.4 pyflakes 体检遗留的琐碎项（不修，仅记录）

| 位置 | 现象 | 结论 |
|---|---|---|
| vllm_client.py:311 | `Union["OllamaClient", ...]` 字符串注解，pyflakes 报 undefined name | 误报：函数体内延迟导入（L327），运行时无害 |
| line_normalizer.py:269 | `propagated` 赋值后未读取 | 无害残留标志位，逻辑本身正确（fixed 已直接生效）|
| two_stage_scanner.py:1283 | 循环变量遮蔽模块级 import `build_triage_prompt` | 运行时无影响，重命名可消，低优先 |

### 8.5 CWE-798 抢占文件级类型（2026-08-30 实锤，工具层修复建议 P1）

**现象**（两套组态一致复现，跨组态稳健）：`typical_15_missing_authz`（期望 862）、
`typical_16_session_fixation`（384）、`typical_22_csrf`（352）、`hard_bypass_05_csrf_same_origin`（352）、
`hard_bypass_08_jwt_none_alg`（347）、`hard_crossfile_03_sink`（639）——六段主漏洞为
鉴权/会话/CSRF 类的样本，文件级 `vulnerability_type` 全被顶成 **CWE-798 硬编码凭证**。

**工具层查证**（票型证据，评估组态 JSON）：

```
typical_15_missing_authz  候选仅 1 条：B105 (2真/1假) → conf → top1=CWE-798
hard_crossfile_03_sink    候选仅 1 条：B105 (2真/1假) → top1=CWE-798
hard_bypass_05            评估组态 B105 0/3 全否决、xss-t 1/2 否决 → 全否决应判 False
                          生产组态 B105 判真 → top1=798（组态差异，但机制相同）
```

**根因链（工具层）**：
1. **授权类（CWE-862/639/306/384/352/347）工具层零召回**——已有记载的盲区
   （无 source 型漏洞：授权缺失/IDOR/会话固定，正则与污点追踪均无能为力）；
2. 这些样本里的测试惯用硬编码密码（`password="admin123"` 等）被 **B105 召回**，
   成为**唯一/仅有的可确认候选**；
3. B105 判真后按 `_aggregate` top1 规则（confirmed 中取最高 severity）成为
   文件级类型 → 798 盖过样本主类型。

**修复建议（按可改性分级）**：

| 级别 | 建议 | 说明 |
|---|---|---|
| P1 可立即修 | `vulnerability_types` 已透出全部 confirmed 类型（多漏洞支持），前端"全部确认漏洞"区已正确显示；但 `vulnerability_type`(top1) 单独出现时前端语义为"该文件漏洞类型"，798 误导主类型 | 过渡方案：无其他 confirmed 候选、且 B105/secret 族为唯一 confirmed 时，前端类型行追加"（含伴生凭证发现）"标注。纯展示，不改判定 |
| P1 治本 | **授权类 P2 预筛规则**：`@app.route`/Spring `@Mapping` 装饰的 handler，函数体直接返回数据或执行写操作，且函数体+模块级均无 session/token/permission/is_admin 检查特征 → `missing_authz_suspect` 候选交 LLM 裁决 | 六段样本会全部获得 authz 候选进裁决，确认后类型自然正确。**必须过泛化三关 + 87 段回归**（会动 fixed5 候选集合）|
| 观察 | B105 在"测试代码硬编码密码"上模型本身摇摆（2:1/0:3 都出现）| bandit LOW severity 特征本身成立，不建议工具层压制 B105（typical_06 主漏洞就是 798，一刀切会伤真阳性）|

### 8.6 跨文件 input 文件兜底 FP（2026-08-30 实锤，标注层决策 + 守卫建议）

**现象**：`hard_crossfile_03_input.py`（期望 False，helper 拆分的输入文件）
生产组态判 **True / CWE-1336**（评估组态 True / CWE-112，两套组态类型漂移但都判真）。

**工具层查证**：`tools=['llm']`——工具层**零召回**，`llm_recheck` 兜底 3:0 全票判真。
即：这是**无候选 LLM 兜底通道（full_recheck）**的产物，不是工具召回错误。

**归因**：跨文件拆分样本的"input 文件"有输入入口、无本文件危险 sink——
`_has_param_driven_sink` 守卫的触发条件（无入口+形参驱动 sink）不匹配；
LLM 单文件视角下数据流不完整仍按"存在风险"判真。

**修复建议**：

| 级别 | 建议 | 说明 |
|---|---|---|
| 需回归验证 | 无候选复核路径新增守卫：文件**只有输入入口、工具层零命中、且无危险 sink 调用**时，LLM 判真降级为 review（不判 True）| **风险高**：fixed5 里 24 段真漏洞靠兜底通道判真，此守卫可能误伤；必须 87 段全量对照后才可合并 |
| 标注层决策 | helper 拆分文件单独算不算漏洞（manifest 说不算；单文件视角下"有输入即风险"是合理推断）| 产品语义与标注语义的分歧，由标签治理定：若维持"不算"，评估时该样本按特例豁免；若算，改 manifest |

### 8.7 组态差异量化（2026-08-30 实测，"同样本同配置不同结果"的用户观察）

`hard_bypass_03_xss_replace`：评估组态（combined_nosource 5056字 prompt）票型摇摆进
review；生产组态（ALPHA05_PROMPT 1982字 + triage_aligned）干净判 True/CWE-79。
**system prompt + 裁决 schema 差异是主要变量**，temperature=0.7×N=3 采样叠加放大。
待办：typical_08（94/95）、typical_23（1336/79）各跑 3 轮生产组态测翻转率，
若翻转率 >1/3，考虑生产 temperature 0.7→0.3（投票内多样性仍存，判定稳定性提升）。

### 8.8 P2 预筛规则设计草案：`missing_authz_suspect`（2026-08-30，治 798 抢占的治本项）

**设计依据**：§8.5 六段实证 + fixed5 时代即已记载的授权类零召回盲区（无 source 型：
授权缺失/IDOR/会话固定/CSRF，污点追踪与正则均覆盖不到）。

**触发条件（Python 版，全部满足才产出候选）**：

1. handler 形态：函数被 `@app.route` / `@router.get|post|put|delete`（Flask/FastAPI）
   或类方法被 `@GetMapping/@PostMapping/@RequestMapping`（Java）装饰；
2. 函数体含敏感操作特征之一：DB 写（execute + INSERT/UPDATE/DELETE 字样）、
   文件写、`db.query/commit`、返回数据集（query.all()/fetchall() 后 return）、
   用户数据修改（user.password/email 等属性赋值）；
3. **全文件无访问控制特征**（模块级+函数体均无）：`session[`、`current_user`、
   `login_required`、`@token_required`、`permission`、`is_admin`、`role`、
   `Depends(`、`get_current_user`、`verify_token`。

→ 产出 `category=prefilter, severity=high, taint_type="Missing Authorization"` 候选，
交 LLM 裁决确认具体族（862 缺失 / 639 IDOR / 384 会话固定 / 352 CSRF / 347 JWT）。

**红线**：
- 特征 3 的"无访问控制"必须**全文件扫描**——helper 里调用了 `get_current_user()`
  也算有检查（哪怕主文件没有），防误报；
- 纯静态页面/公开 API（登录、注册、健康检查路由名）排除；
- **必须过泛化三关 + 87 段全量回归**（动候选集合，fixed5 24 段兜底样本会转移通道）。

**预期收益**：§8.5 六段全部获得 authz 候选进裁决，模型确认后文件级类型归正；
同时覆盖 v2_15 训练侧"授权族辨析组"的推理端配套（模型判对类型后工具层不再回拖）。

**独立集验证建议**：在 `testset_cve_fix` 的授权类 CVE（若存在）+ 手工构造 3 段
安全对照（有 login_required 的同形态 handler）上验证 TP/FP。

