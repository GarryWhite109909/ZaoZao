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
> 状态更新（2026-08-30 第三波）：抑制池治理（§五之四）落地；待办 1 三项方案
> 落地（证据上下文剥离 + 白名单扩容 + 工具层复测）；另完成 87 段候选**逐条
> 人工审查**，6 族被丢弃的精确告警救援（§五之八）。剩余缺口为框架级/长尾
> category（§五之五）。

| 优先级 | 项 | 性质 | 状态 |
|---|---|---|---|
| P0 | secret 档接入修复（B1） | 接入 bug，真实召回提升 | ✅ 已修并验证 |
| P0 | 工具冒烟自测（每个工具 1 个必然命中的样例，CI 可跑） | 防 B1 类问题复发 | ✅ 已建 `scripts/tool_smoke_test.py`，首跑即抓到 B2 接线 bug |
| P1 | secret 类 SAST 规则归入直出档（B3） | 已有证据被浪费 | ✅ 已做（`_is_secret_class_alert` 甄别 → 转 secret 直出） |
| P1 | gitleaks 自定义规则补 AWS key / 字节串字面量（B2） | 规则覆盖 | ✅ 已做（`gitleaks_rules.toml`，extend useDefault） |
| P1 | 候选合并去重（§三） | 成本 + 噪声 | ✅ 已做（`_dedupe` 族级归并，候选≥3 样本 20→10） |
| P2 | 补零召回 category 的规则（首批：open redirect / log / timing / crypto×3 / proto×2 / overflow） | 覆盖面 | ✅ 首批已做（§五之三）；剩余框架级 category 见 §五之五 |
| P2 | 污点链证据在裁决 prompt 中的差异化利用（§四） | 裁决层协同 | ✅ 已做（按证据类型分级信任标注） |
| P1 | 信号抑制池的样本级盲区（§五之四，本轮新发现） | 召回损耗 | ✅ 已治理（2026-08-30：自有链级规则不抑制 + 抑制留痕 `suppressed_by_registry`） |
| P1 | 待办 1：证据上下文污染类型推断（§五之六 待办 1） | 类型归因错误 | ✅ 已实施（2026-08-30：上下文剥离 + 白名单扩容 XXE/LDAP/NoSQL/SpEL，工具层复测通过；LLM 裁决层重跑待算力） |
| P1 | 87 段候选逐条人工审查（§五之八，第三波） | 证据浪费/静默丢弃 | ✅ 已完成（6 族被丢弃精确告警救援：B307/eval 族、B506、B605、B311、spel-injection、B202；安全样本零新增候选） |
| — | 跨文件数据流（crossfile 全族） | 架构级，需项目级上下文 | 单文件管道外，论文标注局限 |

## 五之二、规则层实锤缺陷：os.path.join 形态零覆盖（已修，2026-08-29）

> **编号说明（2026-08-30 整理）**：§五之二～§五之八 是「五、优先级建议」的补充节，
> 按文档中的出现顺序编号。早期追加时「待办」「夜间批量修复」与「第二波实施」
> 「抑制池盲区」撞号（曾各有两个 §五之三 / §五之四），本次已重排为唯一编号：
> **待办 → §五之六、夜间修复 → §五之七、原 §五之六（第三波审查）→ §五之八**。
> 旧编号的历史引用按此表换算。

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
| 直出档（secret/sca）确定性 finding 覆盖 | 0 段（secret 档当时对代码文件关闭） | **11 段**³ |
| 安全样本（26 段）中出现候选 | 15 | 15（新规则仅 timing 误触发 safe_13，已修） |

³ 夜间修复 #3（凭证强度门槛，同日晚于本表复测）收紧后，弱值转裁决档、
  直出覆盖变为 3 段（真凭证）；第三波复测全表见 §七 与 §五之八。

新捞回 13 段全部 expected=true：typical_06 / 12 / 15 / 16 / 18 / 19 / 29 / 31 / 32、
hard_bypass_06、hard_cve_02、hard_crossfile_02_input、hard_crossfile_03_sink。
自检矩阵：prefilter 42 例、two_stage 24 例、cwe_normalizer 全例、
tool_smoke_test 9 PASS / 1 SKIP，全过。

## 五之四、新发现：信号抑制池的样本级盲区（✅ 已治理，2026-08-30）

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

**评估口径（2026-08-30 定稿，按目的选择、报告必须标注）**：

- **归因/消融口径**：`--no-signal-feedback`（纯静态管线）——可复现、样本顺序
  无关、与 fixed5 基线同口径，用于逐层归因（§七 消融表）与规则改动验证
  （本工具层优化指导内所有复测数字均此口径）；
- **系统口径（生产形态，含自适应闭环）**：feedback 开启 + 每轮隔离注册表
  （eval_two_stage 已内置，跨跑不共享不污染生产）——衡量"系统上线后跑起来
  的真实效果"。此口径此前的风险是运行期抑制静默吞候选；**抑制池治理
  （本节）落地后已封堵主要病灶**（自有链级规则不再被压制、抑制命中在
  stage1 留痕可审计），故该口径可用且更贴近部署形态；
- 跨轮对比必须同口径；论文中两种口径可并行报告（静态工具层 vs 完整闭环），
  如实标注即可。

**待治理建议**：① 自有 taint 规则（带完整证据链）不进抑制池，或抑制降级为
"候选降权"而非"静默跳过"；② 抑制命中时在 stage1 决策中留痕（如
`suppressed_by_registry` 计数），消除静默性。

**治理实施（2026-08-30，方案 ①+② 均落地）**：

1. **自有链级规则保护（写端 + 读端双口径）**——`signal_registry.py` 新增
   `_PROTECTED_RULE_PREFIXES = ("taint_tracker:", "graduation_project.semgrep_rules.")`：
   - 写端：`record()` 否定达到抑制门槛时，受保护规则**不置 suppressed**（否定
     计数照常累计，供后续"按文件粒度降权"治理取数）；
   - 读端：`is_suppressed()` 对受保护规则豁免——历史 JSON 残留的
     `suppressed=True`（保护上线前写入）不再生效，写读必须同口径。
   - 识别用**结构性前缀**（自有引擎/自有规则目录），非样本拼写拟合。
2. **抑制留痕（读端）**——`two_stage_scanner.py` 的 `_apply_signal_registry` /
   `_drop_irrelevant_positional` 记录被跳过/被剔除的 rule_id，`scan_code` 写入
   stage1 字典：`suppressed_by_registry`（规则级抑制命中）与 `dropped_unowned`
   （无主告警剔除）。"某样本工具层零召回"由此可归因：是没命中，还是命中后被
   抑制/剔除——评估与前端的静默性消除（B1 同构问题闭环）。
3. **自检用例**——signal_registry 自检新增 3b（≥2 独立文件全票否决自有规则仍
   不抑制、否定计数照常累计）、3c（历史残留 suppressed 读端豁免）；
   two_stage 自检新增 #21（上下文剥离）、#22（抑制留痕端到端：B888-T 被跳过
   留痕、`taint_tracker:*` 链级候选保留）。

注：生产 `models/signal_registry.json` 当前 signals=0（文档记录的 12 条抑制
规则已不在），但机制性缺陷仍在——只要进程继续累积否定，盲区会复发，故治理
照常实施。

## 五之五、剩余零召回缺口（第三波复测后，11 段，均为框架级/长尾）

首批 P2 规则落地后剩余的零召回 × 期望真清单——特征是"漏洞语义在框架层，
单文件正则无标准形态可写"或"需要项目级上下文"（typical_36 SpEL 已在第三波
捞回，见 §五之八；hard_cve_03 为设计内 0 候选 + 强制复核兜底，非缺口）：

| 样本 | category | 缺口性质 |
|---|---|---|
| hard_cve_05_spring4shell / hard_cve_06_struts2_ognl / hard_cve_08_fastjson_deser | Java 框架 CVE | 框架层漏洞形态（参数绑定/OGNL/反序列化开关），无对应规则 |
| typical_21_xxe | XXE | XML 解析器特性开关（disallow-doctype-decl），缺失型 |
| typical_24_ldap / typical_25_nosql / typical_26_xpath | 注入族长尾 | sink 语义各异（LDAP filter/NosQL query/XPath），可分期补 |
| typical_30_mass_assignment | Mass Assignment | 框架层（强参数/白名单缺失），缺失型 |
| typical_20_insecure_tls | Insecure TLS | 配置型（verify=False 已有形态，但该样本为协议版本配置） |
| typical_33_php_type_juggling | Type Juggling | PHP 松散比较 `==` 语义，语言特性级 |
| hard_crossfile_02_sink | 跨文件 | 数据流在文件边界中断，架构级（论文标注局限） |

→ 处理原则维持 §五之二 泛化纪律：能写出"语言/框架标准写法"的（SpEL sink、
XXE 开关、PHP `==` 敏感比较）分期补；写不出的（框架 CVE、跨文件）留给
LLM 兜底通道并在论文中如实标注。

## 五之六、待办（会动 fixed5 基线，需重跑全量评估后再决定）

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

**建议方案（三项一起上）——已实施（2026-08-30 第三波）**：
1. ✅ 扩展 `_STANDARD_TAINT_TYPES` 覆盖非注入型：SSRF / Open Redirect /
   Weak Crypto / Hardcoded Credential（第二波已做）+ **XXE / LDAP Injection /
   NoSQL Injection / SpEL Injection**（第三波补齐，NoSQL/LDAP/XXE 为白名单
   扩容配套推断分支，SpEL 见 §五之八）
2. ✅ 证据上下文剥离：`_infer_taint_type` 仅取 `[告警行上下文]` 标记**之前**的
   告警语义描述（标记常量 `_EVIDENCE_CTX_MARK` 与追加处共用，防字面量漂移）；
   裁决 prompt 不受影响（P0.3 上下文本就是给 LLM 看"在哪里"的）
3. ✅ 工具层复测（87 段静态管线，`--no-signal-feedback` 口径）：
   - hard_cve_03 从"2 条错误候选"变为"0 候选 + 强制复核兜底"（符合设计意图，
     诱导模型投错票的错误类型标注消失）
   - 安全/噪声样本候选 17 → 17（零回退）；配套 6 族精确告警救援见 §五之八
   - **LLM 裁决层重跑（recall/FPR/兜底判真数 24→?）待算力，不在本机跑**

### 待办 2：Java 路径安全规则缺失（✅ 已完成，§五之二配套清账）

Java 侧前缀校验安全规则已作为 `path_canonical_startswith` 落地
（`getCanonicalPath().startsWith` / NIO `toRealPath().startsWith`，见
§五之二"配套"项与本表 TLS 修复之后的泛化纪律记录）。

### 待办 3：候选合并去重（§三）（✅ 已完成，§五之三）

同（族, sink 行）归并 + 多工具标记已落地，候选≥3 样本 20 → 10（第三波复测
进一步降至 8，见 §五之八）。


## 五之七、2026-08-29 夜间批量修复（用户提示质量审计驱动）

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

## 五之八、第三波：87 段候选逐条人工审查 + 精确告警救援（2026-08-30）

> 方法论前提：**脚本统计只负责"跑工具、把候选摆出来"，合理性判断人工逐条做**
> （脚本自动判定会掩盖逐条证据的问题，B1 教训的同型——统计指标好看 ≠ 证据健康）。
> 工具：`experiments/exp_04_hard_samples/stage1_candidates_dump.py`（纯静态管线、
> `--no-signal-feedback` 口径、不调 LLM），逐样本输出候选的 rule_id/类型/行号/
> 完整证据文本，对照 manifest 期望类型与样本源码逐条审。

### 审查结论总览

87 段、修复前 102 条候选 + 14 段有剔除留痕，逐条过三问：
① 候选合不合理（是否指向真实漏洞特征）；② 会不会误导模型（类型归因/证据文本）；
③ 有无该产出却未产出的候选。

- **设计内行为确认（无需修）**：safe_01/02/03/05/06/07/08/13/17 等安全样本的
  链级/审计候选全部是"真数据流 + 防御在裁决层识别"（参数化/shlex/白名单/
  html.escape/int 转换），类型归因正确，不算误导；typical_14/15/16 等 B105
  弱值按凭证门槛转裁决档（夜间修复 #3 语义）；typical_20 的 SSRF 共现照
  §8.1 口径（多漏洞共现，非归因错）。
- **发现 6 族"工具命中、管线丢弃"**（该产出却未产出，全部修复）：

| # | 样本 | 被丢弃告警 | 根因 | 修复 | 落地形态 |
|---|---|---|---|---|---|
| 1 | typical_08（CWE-94） | B307 / eval-detected / user-eval ×3 | `_infer_taint_type` **无 Code Injection 分支**，eval 族语义无从归型 | 新增分支：`\beval\b\|\bexec\b` 词边界 + `b307`/`insecure function`；**置于 SQL 之前**（eval 告警消息含 "execute arbitrary code"，会被 SQL 分支的 "execute" 抢走） | B307/eval-detected 与链级候选同行归并、user-eval 独立入裁决档 |
| 2 | typical_36（CWE-94/917） | semgrep spel-injection（**主漏洞证据**） | 无 SpEL 类型与分支 | 白名单加 "SpEL Injection" + 分支 `spel`（cwe_normalizer 已有 SpEL→CWE-917 映射） | 0 → 1 候选，零召回×真 12 → 11 |
| 3 | hard_cve_07（CWE-22） | B202 tarfile.extractall | 上下文剥离副作用：此前 B202 靠行上下文的 `extractall(` 撞词过白名单，剥离后失援；其消息 "tarfile.extractall used without..." **不带括号** | Path 分支 `extractall(`→裸 `extractall` + `tarfile` 词 | B202 与 path_traversal_open_join 归并为 `bandit+prefilter` 双工具候选，**且补齐了行号 L19**（open_join 无行号的缺陷顺带消除） |
| 4 | hard_cve_01（CWE-78） | B605 | 消息 "Starting a process with a shell" 不含 "command"/"subprocess" | 命令注入分支加 `b605` + `process with a shell` | 与链级候选同 sink 行归并，多工具一致证据补齐 |
| 5 | typical_19（CWE-330） | B311 | 消息 "Standard pseudo-random generators are not cryptographically secure" 不含 "weak" | 弱加密分支加 `b311` + `pseudo-random` | 与 crypto_weak_random 归并（bandit+prefilter） |
| 6 | typical_11（CWE-502） | B506 | deserial 分支只认 pickle/deserial，不认 yaml | 加 `yaml` 词 | 与链级候选归并（bandit+prefilter+semgrep+taint_tracker 四工具一致） |

### 复测（与第二波同口径）

| 指标 | 第二波 | 第三波（本波后） |
|---|---|---|
| Stage 1 零召回 | 23/87（26%） | 23/87（26%，构成更健康：hard_cve_03 由"2 条错误候选"转设计内 0 候选+强制复核，typical_36 捞回） |
| 零召回 × 期望真 | 12 | **11**（typical_36 捞回） |
| 候选数 ≥3 的样本 | 10/87 | **8/87**（救援以"归并进链级候选"落地，冗余度反降） |
| 安全/噪声样本候选 | 17 | 17（**零新增**） |
| 剔除留痕段 | 12 | **7**（全部为确认无类型语义的部署/风格类告警，见下） |

自检矩阵：prefilter / two_stage（新增 #21 剥离、#22 抑制留痕、#21 附 6 分支+
2 负样本）/ cwe_normalizer / signal_registry（新增 3b/3c）全过；
tool_smoke_test 9 PASS / 1 SKIP。

### 剩余剔除项逐条裁决（确认丢弃合理，记录防再议）

- **B108**（hard_cve_03 / hard_longfile_02，硬编码临时目录）：语义是 CWE-377
  次要标签，两样本主漏洞均有候选/复核兜底；裁决层无对应类型契约，为单样本
  次要标签扩白名单 = 契约膨胀，**缓期**（若后续标签治理确认 CWE-377 共现
  标注价值再议）。
- **B104 / avoid_app_run_with_bad_host**（绑 0.0.0.0/坏 host）、**B113**
  （requests 无 timeout）、**B110**（try/except pass）、**B413**（pycrypto
  import）：部署配置/风格提示类，无标准漏洞语义类型，丢弃合理。
- **request-data-write**（hard_cve_03/07 的写入类告警）：剥离后语义中立
  （"用户数据写入"，无类型指向），按设计剔除交兜底复核——这正是待办 1 的
  目标行为（不再伪装成 Path Traversal 污染归因）。

### 零召回缺口现状（第三波后，11 段，均无任何告警产生——非丢弃）

§五之五清单去掉 typical_36（已捞回）后不变：框架 CVE×3、XXE、LDAP、NoSQL、
XPath、Mass Assignment、Type Juggling、hard_cve_03（设计内 0 候选走强制复核）、
hard_crossfile_02_sink（架构级）。全部无工具告警可救，处理原则不变（能写
标准写法的分期补，写不出的论文如实标注）。


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

| 维度 | 基线（08-18） | 第二波工具层 | 第三波（08-30，含逐条审查救援） |
|---|---|---|---|
| Stage 1 零召回率 | 41%（36/87） | **26%（23/87）** | 26%（23/87，构成更健康¹） |
| 零召回 × 期望真 | 25 段 | **12 段** | **11 段**（typical_36 捞回） |
| 候选 ≥3 的样本（冗余度） | 23%（20/87） | **11%（10/87）** | **9%（8/87）** |
| 直出档确定性 finding 覆盖 | 4 段 | 11 段² | **3 段**² |
| LLM 兜底判真数（no_candidate_recheck_vuln） | 24 段 | **12 段**（08-30 全量评估实测³） | 待第三波工具层重跑（预计 11：typical_36 转裁决通道） |

¹ hard_cve_03 从"2 条错误类型候选"转设计内"0 候选 + 强制复核兜底"（待办 1
  上下文剥离），typical_36 由 0 → 1。
² 第二波的 11 段是"夜间修复 #3 之前"的口径（B105 弱值也直出）；#3 收紧门槛后
  弱值 8 段转裁决档、仅真凭证直出（typical_06 / hard_bypass_06 / typical_18），
  与该修复自身记录"弱值 8/8 转裁决档、真凭证 3/3 直出"一致。
³ 远程 08-30 全量评估（transformers / combined_nosource / full_recheck / N=3）：
  recall 1.0（55 TP + 6 复核转人工，0 FN）、FPR 0.1、acc 0.973；**兜底判真
  24 → 12，减半**——"工具层为 LLM 减负"叙事的数据。两点口径说明：① 该评估
  signal_feedback 开启（隔离注册表，系统口径），运行中累积抑制了自有 sqli/xss
  taint 规则等 4 条（§8.5 核对注 3）——抑制池治理落地后此病灶已封堵，系统口径
  可继续用，与静态口径（消融归因）并行报告并各自标注；② 工具层为
  第二波状态（第三波 6 族救援与上下文剥离未包含）。

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
（当时 14 条：B501、B301、deser_pickle_loads、sqli_percent_format、
`taint_tracker:{Path Traversal, SQL Injection, Command Injection, Code Injection,
Insecure Deserialization}` + 4 条 semgrep 规则），整个 `_aggregate` 中断 →
该文件显示"分析失败"。此窗口期内产生的**任何批量扫描/评估结果**（若有），
命中上述规则的样本需逐个复核是否被记为失败；此后端窗口仅一天，但任何
08-29 之后导出的结果文件都过一遍 `_kind == "error"` 统计再入库。

（2026-08-30 补记：生产 `models/signal_registry.json` 现已为空 signals=0——
上述 14 条 corrected 规则与 12 条抑制规则均不在，历史数据疑被重置；§8.2 的
窗口期复核义务仅对"引用窗口期内导出的旧结果文件"适用。注册表为空同时意味着
§五之四 的治理修复落地时无存量迁移负担。）

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

**本地核对（2026-08-30，第三波静态 dump + 远程全量评估 JSON 交叉验证）**：

1. **票型证据核实一致**：typical_15 / typical_16 / hard_crossfile_03_sink 候选
   仅 B105 一条（2:1 或 3:0 判真 → top1=798）；typical_22 / hard_bypass_05 /
   hard_bypass_08 为 B105 + xss-taint 双候选（xss 被 1:2 否决、B105 判真 →
   798 顶替；bypass_05 双双否决 → review）。typical_14 是反例：xss-taint 3:0
   胜出，798 未抢占——但 top1 变成 **CWE-306**（模型把"未校验归属的订单查询"
   判成认证缺失而非标注的 639/79），属裁决层类型漂移/标注口径问题，非工具层。
2. **§8.8 草案按严格条件 2 在六段上 0 触发**（静态逐条核对，详见 §8.8 核对注）：
   宽口径"直接返回数据"又会在 safe_02（/comment 返回 HTML）等安全样本上制造
   候选。**条件 2 的"敏感操作"定义需先重定，本仓暂不实现**，等标签治理定案。
3. **评估运行期抑制实锤**：远程 08-30 全量评估（feedback 开启、隔离注册表）
   运行中累积抑制了 `python-sqli-taint` / `python-xss-taint` / B404 /
   format-string 四条规则——§五之四 盲区在真实评估里发生（recall 仍 1.0 由
   兜底扛住）。第三波抑制池保护落地后此路径已封堵（自有规则不再被压制、
   抑制留痕进 stage1 可审计）；feedback-on 系统口径此后可用，但**报告须标注
   口径**，消融/归因对比仍用 `--no-signal-feedback`（§五之四 评估口径定稿）。
4. **过渡方案已实施（2026-08-30，纯展示不改判定）**：`scan.html` 漏洞卡类型行
   新增「伴生凭证发现」徽标——唯一 confirmed 候选属 secret 族时显示
   （secret 族识别：B105/B106/B107 / hardcoded-* / Hardcoded Credentials /
   gitleaks 规则名，与后端 `_SECRET_SAST_RULE_RE` 同语义）。同步：
   `mock_frontend_card.py` 补 R7 渲染核对规则（注意其 `issues["_notes"]` 是
   整体覆写，R7 必须在赋值后追加）。验证：逻辑三用例（B105 唯一 confirmed
   显示 / SQL 链级不显示 / 双 secret 直出显示）+ 远程评估 JSON 逐样本模拟
   （798 抢占五段显示、bypass_05 无 confirmed 不显示、typical_20/01/14 不
   显示）。治本项（§8.8 规则）仍缓期，见该节核对注。

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

**本地核对（2026-08-30，87 段静态 dump 逐条验证，暂缓实现的原因）**：

按触发条件严格版（条件 2 = DB 写/文件写/数据集返回/用户数据修改）逐条核对
§8.5 六段，**0 触发**——六段的"敏感操作"要么在注释里（typical_22
"演示：实际执行转账"、hard_bypass_05/08），要么是纯字符串返回
（typical_15），要么被红线排除（typical_16 的 /login），要么是无查询调用的
helper 透传（hard_crossfile_03_sink）。宽口径（8.5 表格的"直接返回数据"）
虽能让六段获得候选，但静态核对面板上 safe_02 /comment（返回转义 HTML）、
safe_17 /withdraw_safe（返回 f-string）等安全样本同样满足"handler + 返回数据
+ 无访问控制特征字样"——safe_17 有 `with lock` 但不在访问控制词表内。
**结论：条件 2 的敏感操作定义是本规则成立与否的关键，需先定案再实现**；
候选方案（供标签治理/用户决策）：宽口径 + 扩访问控制词表（`with lock`/
`session[` 归属校验形态）+ 接受安全样本上的裁决档成本（模型可否决），
或仅按"B105 族为唯一候选"的文件补造 authz 竞争候选（更窄但样本形）。

### 8.9 生产组态全量卡实拍终版结论（2026-08-30，87 段，推翻/修正 §8.5 部分定性）

**数据**：`results/frontend_card_check_20260830_140158.json`（ALPHA05_PROMPT +
triage_aligned + full_recheck + n=3 + num_ctx 16384 + 生产注册表，逐项对齐
main.py/bootstrap，对齐检查表见日志头部）。

**判定层**：TP=59 TN=21 FP=1（crossfile_01_input/943）→ **FPR 4.2%**
（评估组态 10% 的 2 个 FP 中 crossfile_03_input 在生产组态转复核）；复核 6
（真 2：typical_09/longfile_01；安 4）。**strict recall 0.967 / loose 1.0**。

**类型层 strict hit 52/59 = 88.2%**（评估组态 ~75%）。生产组态 7 个 miss 重新归因：

| 样本 | 判 | 期望 | 归因层 |
|---|---|---|---|
| typical_08_eval | top1=78 | 94 | **工具层**：模型归因 95/94 基本对（多漏洞列表可证），top1 被 severity 更高的工具 78 finding 抢占——top1 与模型归因**不同源** |
| hard_cve_03_tarfile | top1=798 | 22;377 | **工具层**：同上，vts=[89] 与 top1=798 脱节 |
| crossfile_03_sink | 798 | 639 | 工具层残留（§8.5 机制，仅此 1 段）|
| typical_15 / bypass_08 | 287 | 862 / 347 | **训练层**：287（认证不当）大筐吃掉授权/验证专号——无候选兜底时模型独立归因的边界问题 |
| typical_22_csrf | 862 | 352 | **训练层**：CSRF vs 授权缺失（锚表已立仍错 → v2_15 加量）|
| typical_30_mass_assign | 862 | 915 | **训练层**：mass assignment 的 915 专号未内化 |

**§8.5 定性修正（重要）**：798 抢占六连是**评估组态特有现象**——生产组态下
B105 被否决、模型经无候选兜底**独立归因**出 287/862/384/352（6 段中 3 段直接
strict hit）。P2 授权规则（§8.8）的价值从"治 798"重定位为"**把无候选兜底转成
有候选裁决**"——降低复核率、给类型归因提供工具锚（兜底归因漂移问题见训练层
v2_15 §3.1）。**"无工具锚点时模型类型归因不稳"由本数据再次确证**。

**新增修复项**：

1. **【已修】PHP 入口正则盲区**（typical_09 实锤）：`_INPUT_ENTRY` 缺
   `$_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER/php://input` → 门 2 误拦 PHP 的
   3:0 判真。已补正则 + 自检通过 + typical_09 复验识别入口 + Python 回归 PASS。
   预期重扫后 typical_09 复核 → True（strict recall 0.967 → 0.984）。
   **教训：08-29 加门时自检用例全是 Python——今后新增语言相关判定必须带
   该语言的阳性用例。**
2. **top1 与多漏洞列表同源化**（typical_08/cve_03 实锤）：`vulnerability_type`
   按 severity 取 finding 类型，`vulnerability_types` 是模型归因列表，两者可脱节。
   建议：有模型类型票时 top1 优先取多数票类型，工具 rule_id 映射仅兜底。
   **【已修 2026-09-01，见 §9.25】**：实锤根因是 `signal_registry.corrected_taint_type`
   短路在多数票**之前**——最高 severity 规则命中注册表映射时模型归因被无视。
   现多数票优先、注册表仅兜底（模型无类型票时保持 B501→CWE-295 校正能力）；
   自检用例 #27 验证票型>注册表、#20 改为覆盖注册表兜底分支。
3. **types 元素统一 normalize**（10 段展示不一致中 8 段实为此问题）：
   "CWE-78 Command Injection" vs "CWE-78 OS Command Injection"、"Wraparound" vs
   "Wrap-up"——同一编号两套官方名，前端两处显示会不一致。修复：`vulnerability_types`
   元素统一过 `normalize_cwe_label`（纯展示层，低风险）。
   **【已修 2026-08-30 晚，见 §9.7 #4】**：根因是归一化只加在**兜底复核分支**，
   裁决主分支直接入库模型原文；现按"取值优先级不变、取到后统一 normalize"收口，
   重复项由保序去重合并。自检新增用例 #23（两条候选两套官方名 → 合并为 1 条）。

### 8.10 单次"最稳"结论被生产实拍推翻（2026-08-30，稳定性方法论教训）

`hard_cve_05_spring4shell.java`：14:01 全量卡实拍 3:0 判 915（strict hit，曾进
"最稳截图推荐"清单）；17:36 用户生产实拍同组态 3:0 判 943（miss）。**两次全票、
结论不同**——temperature 0.7 下模型在 915/943/94 近邻间落不同吸引盆，全票
不等于稳定。已定性训练层（Spring 绑定族锚缺失，见 v2_15 §3.4）。

**方法论修正**：
1. "零问题样本"清单**不得**基于单次运行出"最稳"结论——推荐展示样例前，
   对候选样本至少 2 次独立运行取交集（或 temp 降至 0.3 复测一次一致才入清单）；
2. 全票（confidence=1.0）仅说明"该次采样内自洽"，跨运行稳定性需独立测量；
3. 兜底通道（无候选 full_recheck）样本的稳定性风险天然更高（无工具锚，
   模型自由归因），标注"工具层漏报 · 兜底"徽章的卡进截图清单前须复测。

### 8.11 前端产品化遗留三件（2026-08-30 用户实拍）

| # | 问题 | 根因 | 状态/建议 |
|---|---|---|---|
| 1 | 跳转离开页面 → "接着分析但不出结果" | 导航终止前端 fetch；**后端调度器继续跑完**，结果无人接收 | 轻量已修：`beforeunload` 提醒（scan.html）。**【彻底方案已修 2026-09-01，见 §9.25】**：后端 `job_id` 暂存 + `GET /api/scan/result/{job_id}` 领取端点 + 前端回站拉取（sessionStorage 留痕、限次重试）|
| 2 | 评级不一致：实扫卡"高危" vs 样本库详情卡"中危"（typical_20/CWE-295）| 两处不同源：实扫 risk_level=裁决层（B501 bandit=high）；样本库详情卡风险来自 **CWE 知识库通用等级**（295 通用标中危），未优先读 demo manifest 的 `expected_risk_level: High` | **【已修 2026-08-31，§9.22.3】**：cwe.html 详情弹窗 `expectedRiskByCwe` manifest 静态标注优先，知识库通用等级括注辅助（已在位，本行此前漏同步）|
| 3 | 样本库落后于训练集类型覆盖 | v2_14 已含 287/862/915/917/1336/502 等类型，demo 87 段还是旧口径；今天 miss 的授权族/绑定族恰是样本库空白 | **知识库页已更新（cwe.html，2026-08-30）**：CWE-295 medium→high（与实扫 B501=high 对齐）；新增 6 条训练集已覆盖类型：862 授权缺失 / 915 批量赋值 / 917 SpEL 注入 / 347 签名校验 / 117 日志注入 / 943 查询中性化（均含漏洞/安全双代码例）。**扫描样本库（samples/demo 87 段）补样仍待办**：v2_15 训完后从训练数据反选 |

## 九、仓库级基准与候选审计（exp_08，2026-08-30 新开）

**方法论**（用户确立的快速提升路径）：工具扫多仓库/URL → `audit_stage1.py` 逐条审计
候选（A 盲区 / B 类型错标 / C 无关噪声 / D 剔除存疑）→ 逐条归因 → 修规则 → 复测。
对账脚本（eval_repo.py 发现级 recall）只回答"结果好不好"，审计脚本回答"为什么"。

### 9.1 首轮 DVNA 整仓审计结果（10 文件，零 LLM 秒级）

> **口径警告**：本表按**模式类别**计数（"semgrep 规则族"是一类而非一条 finding），
> 与 §9.8 按 manifest 11 条 finding 逐条计数的口径**不同，不可直接相减**。
> 且本表的 B 类是在**未走 `_infer_taint_type` 的旧判定口径**下得出的，
> 存在系统性高估——**修正后的最新数据以 §9.8 为准**（DVNA：OK 6 / A 4 / B 1）。

| 类 | 数量 | 明细 | 修复项 |
|---|---|---|---|
| OK | 5 | SQL 拼接(89)、命令注入(78)、开放重定向(601)、反序列化(502)、semgrep 规则族 | — |
| **B 错标** | 4 | **JS ORM find 形态**：`Model.find({where:{id:req.*}})` 被 taint_tracker 判成 **Path Traversal / SSTI**（应归 IDOR/639 或至少不误标）；mathjs.eval 判 Code Injection(94) 而 expected 95（eval 注入近邻） | P1：taint_tracker JS 模型查询形态的类型推断；94/95 近邻验收 |
| **A 盲区** | 4 | **JS XXE 规则缺失**（libxmljs parseXmlString noent:true 无任何候选）；密码重置令牌可预测链路（md5(login)）无规则；用户全量信息暴露（信息类工具盲区，预期内） | P1：JS XXE 规则（libxmljs/jsdom/express-xml）；P2：弱重置令牌规则 |
| **C 噪声** | 1 | prefilter `timing_unsafe_compare` 无行号候选打在无关联文件 | 核对规则触发条件（疑似 `==` 比较 + md5 字样泛匹配）|
| D 剔除确认 | 7 | session cookie 配置族 6 条 + hardcoded-secret 转 secret 直出档 | 剔除正确（配置审计类不属注入裁决域）|

### 9.2 仓库基准指标口径（与 exp_07 的分工）

- **文件级**：TP/TN/FP/复核（对齐 exp_07 口径）
- **发现级 recall**：单文件多发现，`|expected ∩ confirmed| / |expected|`。
  分母以 `manifest_dvna.json` 的 `expected_findings` 为准，**当前 11 条**
  （appHandler 9 + authHandler 2；§9.1 首轮时口径为 10 条，后补入
  appHandler L207 CWE-200 信息暴露，分母随之变化——**引用分母时必须写明条目
  来源与时间戳**，否则跨轮 recall 不可比）
- **三列对照**：A=外部工具原始输出（不进裁决）、B=系统最终确认、C=已知答案
- FN 归因必须走审计清单：A 类（工具盲区）→ 修规则；B 类（错标误导裁决）→ 修类型推断；
  有候选且类型对但最终 miss → 裁决层问题（这才是训练层数据）

### 9.3 首个真实仓库（Vulnerable-Flask-App）判真复核——2 误报实证（2026-08-30）

9 文件判真 4，人工核实：**2 真 2 错**，错的模式一致——**把"模板/客户端上下文"
当成"服务端污点上下文"**。这 2 条是仓库扫描新暴露的盲区类型（单文件教学样本
source 清晰，真实仓库的模板文件里"数据从哪来"需跨文件追踪），已定为 v2_15
蒸馏反例素材 + 工具层上下文规则素材。

| 文件·判定 | 源码事实 | 错因层 |
|---|---|---|
| layout.html **CWE-918 SSRF** | L5 `@import url(fonts.googleapis.com)` 是**浏览器**发起的请求，非服务端；explanation 自己都说"样式被篡改"（内容注入叙事）| 模型把"URL 常量"当"服务端可控请求目标"。**蒸馏反例**：静态资源引用（font/css/img src）≠ SSRF sink |
| index.html **CWE-79 XSS** | L12 `{{ url[0] }}` 的 url 来自 `app.url_map.iter_rules()`——**服务端路由表，用户不可控**；Flask autoescape 默认开启 | 模型把"模板变量"泛当"用户输入"。**蒸馏反例**：render_template 传入的、由服务端路由表/配置构成的变量 ≠ 污点 source |
| app/app.py top1=22 | 确认列表无 22（top1 与多漏洞列表脱节实锤）；真漏洞 **502**（L329 yaml.load，3:0 确认）；L323 路径有 secure_filename(L320) 防御——22 连候选都没有 | 展示层 top1 规则（§8.9 已立项）；**蒸馏反例**：secure_filename 后拼接 ≠ 路径穿越 |
| 附带确认 611 XXE | yaml.load 是 YAML 反序列化（已 502 确认），611 是 XML 实体——类型撞车 | **蒸馏反例**：yaml.load → 502，不产出 611 |
| 附带确认 89/327 | L261 `%s` 拼接 execute、L141 md5 存密码——均真 | ✅ |

**衍生动作（已执行）**：posture.html 扫描概览补"需人工复核"第三态（此前 5 个
None 被静默丢弃，安全占比口径失真）。

**工具层上下文规则（仓库模式 P1）**：模板文件（render_template 目标）的候选
携带"source 可控性"元数据——工具层已可静态判定（url_map 构造 / config 常量 /
request.* 三分），作为裁决上下文注入而非让模型猜。

### 9.4 首批修复落地（2026-08-30，DVNA 审计驱动）

| # | 修复 | 文件 | 验证 |
|---|---|---|---|
| 1 | **JS/TS 语言级 sink 禁用**：`render(`、`.save(` 在 JS/TS 是 Express 视图渲染 / ORM 持久化，非污点 sink（Python 语义保留）。新增 `_SINK_LANG_DISABLED` 表 + 语句级/节点级/文本兜底三处过滤 | taint_tracker.py | taint 自检 PASS；DVNA appHandler.js 伪 SSTI/Path **5→0**，真候选（cmd L39 / code L196）保留 |
| 2 | **空文件守卫**：`scan_code` 入口对 0 字节/纯空白短路返回安全（decision=empty_file_skipped），不再送 LLM 复核"空气" | two_stage_scanner.py | 零模型验证：空串/纯空白均 `hv=False` 短路 |
| 3 | 审计工具 `audit_stage1.py`（零模型）：四路召回中间态保留 + A/B/C/D 自动标记 + C 类确定性四问核验（无行号/注释行/类型↔代码形态匹配/重复报告）——"候选是否合理"由规则引擎判定，不消耗模型 | exp_08/audit_stage1.py | DVNA 整仓 10 文件秒级出清单 |

**未修（记档）**：
- XXE "盲区"实为审计口径误判——semgrep `express-libxml-noent` 已召回 L235（首轮匹配漏判，已修正匹配逻辑）
- mathjs.eval 判 94 vs expected 95：近邻可接受（eval 求值语义双属），v2_15 辨析组一并覆盖
- authHandler 的 md5 重置令牌链路：prefilter timing_unsafe_compare 已打到该文件（无行号），发现存在但形态弱——P2 定向规则（弱重置令牌 = md5(login) 作 token）
- ~~**回归待验**：修复动 JS 候选集合 → typical_10/32 两段 JS 回归跑批中~~
  **回归已完成（2026-08-30 晚）**：87 段全量零回退（零召回 23/87、零召回×真 11、
  候选≥3 的 8/87、安全样本候选 17，与第三波复测逐项一致）；JS 两段回归结果：
  - typical_10 ✅ CWE-78（3:0 确认）
  - typical_32 ❌ **类型 miss**：工具层 `taint_type=Prototype Pollution` 正确，
    模型 3:0 判成 **CWE-918 SSRF**，期望 `1321;915`——**训练层问题**（蒸馏素材
    缺原型污染形态），工具层无需再动；已入 v2_15 素材清单
- **§9.4 #1 验证结论复核（2026-08-31 更正）**：实跑确认伪 SSTI/Path 为 0，
  修复生效。当前 appHandler.js 候选 3 条：L11 SQL 注入（`.query(`，§9.7 #1 新
  sink）、L39 命令注入、L196 代码注入。
  清单里残留的 4 条 SSTI 是**修复前未重跑的旧产物**——这一点成立；但上一轮我
  把它归因于"依赖缺失导致的陈旧数据"是**错误归因**，真因有二：① 清单未随修复
  重跑；② 我用来对比的"复测"是在**缺 semgrep 的环境**跑的降级数据（见 §9.7
  环境教训），把它当成了首轮基准，导致 L10 被误判为盲区。

### 9.5 后续批次路线（自主推进，不需确认）

1. DVNA LLM 跑批（10 文件对账）→ 2. Vulnerable-Flask-App manifest（已扫结果可直接对账）→
3. php-goof / NodeGoat manifest 标注（逐文件读源码）→ 4. 每轮审计 A/B 类 → 规则修复 → 复测，
FN/误报样本同步进 v2_15 蒸馏反例池（§9.3 模式）

### 9.6 VFlask 标准答案 + 首次对账（2026-08-30，仓库级指标首发）

`manifest_vflask.json`（9 文件全量源码实读）：app.py 14 发现（11 主 CWE：798/347/79/
1336×2/327/209/312/639×2/89/502/434）、e2e_zap.py 2 发现（295/798）、layout.html 1 弱项
（CWE-311 http 明文字体，info 级不计 miss）、其余 5 文件安全（含 1 空文件 + 1 第三方库）。

**23:19 扫描对账**（文件级）：TP=2 TN=2 FP=2 复核=3。

| 指标 | 数值 | 解读 |
|---|---|---|
| 文件级 FPR | 2/4 = **50%**（误报：index.html 79、yaml_test 352）| 仓库模板形态的误报是主要出血点 |
| **发现级 recall** | **5/13 ≈ 38%**（app.py 确认 327/89/502/209/330；e2e 中 295）| 仓库形态远低于单文件测试集（88%+）。~~15%~~ 首版口径错误：只对账顶层单值 `vulnerability_type`，漏掉确认列表——**发现级必须数 confirmed 列表**（教训入档：多发现文件的单值口径系统性低估）|
| 复核占比 | 3/9 | 模板上下文规则（§9.3）落地后应降 |

**app.py 票型解剖**（339 行，9 候选进裁决）：确认 6（327/89/502/330/209 各 3:0 +
1:0）、否决 3（1:2×2、1:0 无类型）。**miss 的 7 个主 CWE（798/347/79/1336×2/312/639×2）
在票型里根本没有对应票**——不是模型否决，是**候选根本没进裁决**。两个嫌疑：
① CodeSlicer（min_lines=150）切片后每块缺全文件视野，L26-28 的硬编码密钥、L97
的 insecure_verify 等落在被稀释区；② 工具层对这些形态（JWT verify=False 的
347、ORM get IDOR、模板串 SSTI）零召回。**P1 验证：app.py 关闭切片跑一次对账**
（差异 = 切片稀释贡献；剩余 = 规则盲区）。

### 9.7 第二轮修复落地（2026-08-30 晚，依赖齐备后复测驱动）

**环境教训（本轮第一教训，2026-08-31 更正）**：上一轮我在系统 `python3.11` 上
跑不通自检，就断言"环境缺依赖"，并据此往系统 python 强装了 semgrep/numpy
（`--break-system-packages`）——**两步都是错的**。事实是：项目本来就配好了环境
`~/miniconda3`（Python 3.13 + tree-sitter 全语种 + semgrep 1.172 + bandit +
detect-secrets + numpy + torch），首轮审计（§9.1）正是在这套环境跑的（§9.1 的
OK 里含"semgrep 规则族"、§9.4 记"semgrep express-libxml-noent 已召回 L235"，
均可证）。我只查了 `which python3` 和 `pip list`，没有找 conda / uv / miniconda
就下了结论，还把"我的解释器缺依赖"外推成"首轮也缺依赖"。
**纪律：报"环境缺依赖"前，必须先查项目 README / docs 确认指定环境，再穷举本机
环境（conda/uv/pyenv/venv/系统 python），确认全都没有，才能动手装；更不得往系统
python 强装（PEP 668 拦就是信号）。**
本项目指定环境（README §614、docs/过程.md）：**`conda activate graproj`**
（Python 3.11，tree-sitter 全语种 + semgrep 1.168 + bandit 1.9.4 + numpy 2.4.6
+ torch 齐备）。本项目涉及的全部环境（截至 2026-08-31 盘点）：
- **graproj（conda，3.11）**：README 指定，依赖全齐 → 主力环境
- **base（conda，3.13）**、**AI（conda，3.13）**：依赖亦齐，可作备用
- **uv tools**（`~/.local/share/uv/tools/`）：`bandit` 完好可用；
  **`semgrep` 的 venv 是残缺的**（6-29 半途安装，venv 内只有 python 无
  semgrep 可执行文件）→ PATH 上**从来没有**可用的 semgrep 命令，跑工具层须
  经 conda 环境，不要指望 uv 那个
- **系统 python（3.14）**：不含项目依赖（已恢复原状，见下）本文**最终**复测均以
`/home/zane/miniconda3/envs/graproj/bin/python` 执行（过程中曾用 conda base
（Python 3.13）跑过若干轮，87 段回归与 DVNA 审计结果**与 graproj 逐项一致**：
总候选 104、OK 4 / A 4 / B 3 / C 0 —— 说明结论不依赖 conda 环境的具体版本）。

> 上一轮我给**系统 python 的用户目录**（`~/.local/lib/python3.14/site-packages`）
> 装了 numpy / semgrep / tree-sitter 全套，属**环境污染**。
> **已于 2026-08-31 完成清理**：按 dist-info 安装日期精确区分批次（8-30 为我
> 误装、8-02 的 `git_filter_repo` 为环境原有），卸载 54 个包（8 个主包 + 46 个
> 依赖）并清除孤儿目录；`git_filter_repo` 经 import 验证完好。危害不只是留
> 垃圾——装完后系统 python 也能跑通自检，制造"环境已修好"的假象，
> 反而掩盖了"没用对 conda 环境"这个真问题。conda 各环境不受影响。
> **清理纪律**：`pip uninstall` 批量卸载会因依赖顺序漏删（第一轮 46 个只成功
> 26 个），且中断会留下 `~xxx.dist-info` 无效分布导致后续批量命令静默失败
> （返回 0 却什么都没删）——**必须逐个包复查 dist-info 是否真的消失**，不能只看
> pip 的退出码。

| # | 修复 | 文件 | 验证 |
|---|---|---|---|
| 1 | **JS/TS ORM 原生查询 sink**：新增 `.query(` → SQL Injection，并新增 `_SINK_LANG_ONLY` 限定仅 JS/TS 生效 | taint_tracker.py | `document.querySelector`、Python `Model.objects.query` 均不误报（**注**：L10 首轮即为 OK，非本项修复的转好，见下方口径说明）|
| 2 | **sink 标签匹配语义修正**：pattern 末尾的 `(` 只是书写约定，被 `_core` 剥离后**不参与匹配** → `.query(` 会命中 `document.querySelector`。新增 `_sink_label_for_head` / `_sink_label_for_text`，要求匹配止于调用头部末尾 | taint_tracker.py | 87 段零回退 + DOM/Python 双负样本入自检 |
| 3 | **参数化检查覆盖"直接 source"分支**：此前参数化判定只挂在"污染变量"分支，`db.query("... ?", [req.body.id])` 这类**直接写 source 的标准参数化写法**一律绕过——新 sink 会把它判成注入 | taint_tracker.py | 自检 4 例；87 段安全样本候选 17 不变 |
| 4 | **`vulnerability_types` 统一归一化**（§8.9 第 3 项收口）：裁决主分支此前直接入库模型原文，仅兜底复核分支归一化 → 同一 CWE 两套官方名并存 | two_stage_scanner.py | 自检新增用例 #23：两条候选（`CWE-78 OS Command Injection` / `CWE-78 Command Injection`）→ 合并为 1 条规范名 |
| 5 | **match_func 型规则行号回填**：`_Rule.line_func` + `_timing_hit_line`（命中判定与行号**同源**，避免"命中行 A、行号指 B"） | prefilter.py | authHandler 候选获得真实行号 L49 |
| 6 | **timing 内联通道**：`_input_var_names` 只收集**赋值目标**，`if (req.query.token == md5(req.query.login))` 这类内联比较完全漏召回 | prefilter.py | authHandler **CWE-640 由 A 盲区 → B 错标**（候选已指向 L49 真弱点）|
| 7 | **timing 精度收紧**：两侧均直接取自请求（`req.body.password == req.body.cpassword`）是**字段一致性校验**，攻击者两侧都能控制，响应差异不泄露服务端秘密 | prefilter.py | **C 类噪声 2 → 0**（appHandler L152 / passport L64 均消失），真命中 L49 保留 |
| 8 | **留痕容器按需补齐**：`_drop_irrelevant_positional` / `_apply_signal_registry` 依赖 `__init__` 字段，审计脚本用 `__new__` 绕过构造 → AttributeError 中断**整仓**审计 | two_stage_scanner.py + audit_stage1.py | 审计恢复；**留痕是旁路记录，不该有能力中断召回主流程**（与 B1"静默/崩溃源于接入方式"同类）|
| 9 | **`tool_smoke_test.py` 缺依赖兜底**：无 ImportError 处理时整体 traceback，已 PASS 的 6 条一并吞掉，P0 防线形同失效 | scripts/tool_smoke_test.py | 收敛为 SKIP 且退出码 0，与脚本自身"缺依赖降级不拦 CI"语义一致 |
| 10 | **`.query(` 误报修复（Express `req.query`）**：`_sink_nodes_in` 会遍历到 `req.query.id` 的**内层成员节点**，其头部为 `req.query`，`.query` 恰在末尾 → 被判成数据库查询 sink。修复：带 `(` 的 sink 声明的是"调用"，**必须对调用节点生效**（`is_call`）| taint_tracker.py | DVNA L77/L187/L188 三条误报清零；新增正样本（`client.query(sql+var)`）+ 负样本（`req.query.id`、`querySelector`）入自检 |
| 11 | **`is_call` 第二个调用点补齐**：`_sink_label_for_head` 在 `_sink_nodes_in` 内部与**语句级扫描**各调一次，上一轮只改了前者 → 带 `(` 的 sink 在语句级被判 None、静默退回文本兜底，而兜底 `args` 是整条语句、参数化无从判定（JS 单行箭头函数 `db.query(sql,[p])` 被误报）| taint_tracker.py | 参数化用例由 FAIL 转 PASS；appHandler 回到 3 条真候选 |

**复测结果（DVNA，conda 环境，与首轮同口径）**：按 manifest 的 11 条 expected
finding 逐条判定 —— **OK 4 · A 盲区 4 · B 类型错标 3 · C 无关噪声 0**。

> **口径说明（重要）**：§9.1 首轮的"OK 5 / B 4 / A 4 / C 1"是按**模式类别**
> 计数（OK 里的"semgrep 规则族"是一个类别、不对应单条 finding），与本次按
> manifest 11 条 finding 逐条计数**不是同一口径，不可直接相减**。
> 上一轮我把两者并列比较，并据此写"L10 由 A 盲区 → OK"是**错的**：首轮 §9.1 的
> OK 第一条就是"SQL 拼接(89)"，L10 首轮即为 OK。我看到"L10 A 盲区"是因为自己
> 用缺 semgrep 的解释器跑，那一路候选全缺——**是环境造成的假盲区，不是首轮事实**。
> 首轮与本轮唯一可比的量是：manifest 未变的条目 + 两轮各自的定性结论。

| expected | 首轮（§9.1 定性） | 本轮 | 归因 |
|---|---|---|---|
| L10 CWE-89 | **OK**（SQL 拼接） | **OK** | 一致；无变化 |
| L49 CWE-640 | 未识别（在 A 盲区"密码重置令牌链路"里） | **B 错标** | #6 内联通道：候选已落在 L49 真弱点上 |
| L152 CWE-601 / passport L64 | C 噪声（timing 无行号） | 已消失 | #7 精度收紧 |
| L235 CWE-611 | A 盲区"XXE 规则缺失" | **B 错标** | #9.4 已修正：semgrep 本就召回了，是首轮匹配逻辑漏判 |
| typical_10 `req.query.file` | — | 误报已消除 | #10（本轮新加的 `.query(` sink 曾把它判成 SQL 注入）|

**剩余 A 盲区（4 条，逐条定性）**：
- **CWE-639 ×2**（L107/L144）：`Model.find({where:{id:req.*}})` —— ORM 参数化
  查询**本身是安全写法**，缺的是"未校验资源归属"，属**缺失型**漏洞，与 §8.5
  授权类同构，污点追踪无标准形态可匹配 → **不修，记档**
- **CWE-200**（L207）：`findAll({})` 后全量 json 返回，同为缺失型
- **CWE-330**（L78）：`md5(login)` 作重置令牌，无 sink 形态；同源链路已由
  timing 候选覆盖（L49），仍待 §9.4 记档的 P2 定向规则

**剩余 B 错标（3 条）**：
- L197（CWE-95 vs 判 94 Code Injection）：eval 求值语义近邻，v2_15 辨析组覆盖
- L235（CWE-611）：semgrep `express-libxml-noent` 已召回，但类型落成规则名
  未映射到 611 —— **规则名→CWE 映射缺口**，待批处理
- L49（CWE-640 vs 判 Timing Attack）：**命中行正确、类型是两个不同侧面**
  （`md5(login)` 作令牌既是弱随机 330，也是时序不安全比较 208），模型可消解

**新增规则纪律复核（三关）**：
- `.query(`：Node 数据访问层的**标准 API 名**（mysql/mysql2/pg/sqlite3/Sequelize
  共用，与 Python `cursor.execute` 地位对等），非某仓库变量命名 → 关卡 1、2 通过；
  独立集验证：DOM `querySelector` / Python `.query` / Express `req.query`
  三负样本 + 87 段零回退 → 关卡 3 通过
- timing 两侧排除：语言无关的**安全分析事实**（时序侧信道成立需至少一侧为服务端
  秘密）→ 关卡 1、2 通过；正样本（`token == md5(login)`）+ 负样本（session CSRF、
  常量比较、字段一致性）→ 关卡 3 通过

**纪律复核暴露的漏洞（`.query(` 三关"通过"却仍带误报）**：我上一轮给 `.query(`
做的独立验证只覆盖了 `document.querySelector` 和 Python `.query` 两个负样本，
**没有覆盖 `req.query`** —— 而后者恰恰是 JS 里最常见的同名冲突形态（Express 读
取 URL 查询参数）。三关过了 ≠ 安全，**负样本集必须穷举该 API 名的所有常见语义**
（数据库查询 / DOM 选择器 / 请求参数 / ORM 惰性查询集），漏一个就是一次误报事故。
现四条负样本（`querySelector` / `Model.objects.query` / `req.query.id` /
参数化 `db.query(sql,[p])`）均已入自检。

**方法论教训**

1. **陈旧产物 + 错误基准 = 双重误导**（§9.4 #1 复核）。§9.4 写着"伪 SSTI/Path
   5→0"，清单里却列着 4 条 SSTI。实跑证明修复生效，残留的 4 条是**修复前未重跑
   的旧产物**。但我在核对时，用来对比的"复测"是自己在**缺 semgrep 的解释器**上
   跑的降级数据，于是又得出"L10 由 OK 变盲区"的反向错误结论。
   **纪律：审计清单与复测数字一律以实跑时间戳为准；且复测必须与首轮同环境同
   口径**，否则"复测"本身就是一个新的污染源。
2. **"环境缺依赖"是重结论，必须穷举后再下**。我只查了 `which python3` 就断言
   缺依赖并强装包，实际项目 conda 环境齐全。**纪律见本节开头"环境教训"。**
3. **同判定多调用点，改一处必查全部**（本轮第三次栽在这上面）。`_sink_lang_allowed`
   三处过滤、`_sink_label_for_head` 两处调用——我在 `#8` 的注释里刚写下"避免改
   一处漏两处重演"，转头就在 `is_call` 上重犯，且失败形态更隐蔽：不是报错，而是
   **静默退回文本兜底**，把结构化参数降级成整条语句，参数化检查失效。
   **纪律：改判定函数签名时，先 grep 全部调用点；优先把判定收进单一入口
   （像 `_sink_lang_allowed` 那样），而不是让调用方各自传参。**

### 9.8 审计测量口径修正：B 类被系统性高估（2026-08-31）

**这是本轮最重要的一条，且它不是"漏洞"，是"测量工具的偏差"。**

`audit_stage1.py` 判定"类型是否对齐"时，只看候选的 **`taint_type` 字段**：

```python
type_match = [... if exp_num in _types_to_cwes(r["taint_type"] + " " + r["rule_id"])]
```

但候选的 `taint_type` 常是工具内部标识——bandit 的 `B608`/`B324`/`B501`、
semgrep 的**规则文件路径**（`models.semgrep_rules.python.flask...`）。而生产链路里
`_dedupe` 的语义族归并用的是 **`_infer_taint_type()` 推断后的语义名**
（two_stage_scanner 2218 行）。**推断结果只用于归并分组，从不写回 `taint_type`
字段**——于是审计看到"类型是 B608"，生产看到"语义族是 SQL Injection"，
**同一个候选在两处口径不同**。

后果：候选类型其实正确、只是没写回字段，却被算成"B 类型错标"。

**实测（VFlask app.py，24 条原始候选）**：`B608`→SQL Injection、`B324`→Weak
Cryptography、`B311`→Weak Cryptography、`B506`→Insecure Deserialization、
semgrep 路径→SSTI / XSS / SQL Injection / Weak Cryptography。**21 条里有 17 条
原始类型与推断类型不同**。

**修正**：`candidate_rows` 同步计算 `inferred_type`，判定改为
`原始类型 + 推断类型 + rule_id` 三口径取并集，与生产 `_dedupe` 对齐；
`_SEMANTIC_TO_CWE` 补 798 / 295 / 327 三项（VFlask 实锤缺口）。

**修正前后对比**（同一份代码、同一份 manifest，只改判定口径）：

| 仓库 | 旧口径 | 新口径 |
|---|---|---|
| **VFlask** 17 条 | OK 1 · A 6 · **B 10** | **OK 9** · A 6 · **B 2** |
| **DVNA** 11 条 | OK 4 · A 4 · **B 3** | **OK 5** · A 4 · **B 2** |

> **更正记录**：本表 DVNA 一行初版写的是"新口径 OK 6 · B 1"，**是错的**——
> 当时未核对实际输出、按"L235 转 OK 且 L197 也转 OK"推算得出。实测
> `stage1_audit.dvna.all.md` 为 **OK 5 · A 4 · B 2**（L197 的候选类型是
> `Code Injection`(94)，标准答案是 `CWE-95`(eval 注入)，两者不同编号，
> 始终判 B）。**文档里的对比数字必须逐行取自实际输出，不得推算。**

其中 DVNA **L235 CWE-611 由 B → OK**——正是 §9.7 记的"规则名→CWE 映射缺口，
待批处理"那条，修正口径后自动解决，无需单独补映射。

**教训**：
1. **测量工具的口径必须与被测对象的口径一致**。审计脚本"复刻 `_stage1_recall`"
   时复刻了数据，却漏了生产在归并时额外施加的语义推断——**复刻流程 ≠ 复刻
   语义**。凡"复刻生产逻辑"的测量脚本，都要回头核对生产是否在别处改写了
   被测量字段。
2. **指标突然变差时，先怀疑测量工具**。VFlask OK 只有 1/17 是个异常值，如果
   当时直接据此去"修规则"，会朝着一个不存在的问题使劲（真正该修的是审计脚本）。
3. **"类型错标"和"字段没写回"是两回事**。前者是真缺陷，后者只是表示层差异。
   审计要区分二者，否则会把后者的量全算到前者头上。

**顺带确认的一个事实**：semgrep 输出里**有** `extra.metadata.cwe`（如
`render-template-string` 规则标 `CWE-96`），但代码从未提取，类型全靠
evidence/rule 关键词推断。目前**不打算改**：semgrep 的 CWE 标注口径与本项目
标准答案不一致（semgrep 标 96「静态代码注入」，本项目标准答案标 1336「SSTI」），
若改用 metadata 反而会**降低** OK 率。是否引入需先统一 CWE 口径，**记档待决策**。

**遗留（真实 A 盲区）**：347（JWT verify=False）、209（异常回显）、
312（信用卡明文）、639×2（IDOR）、434（文件上传）、311（layout，info 级不计）。
其中 639×2 与 §8.5 授权类同构 → 不修记档。
**前 4 条已于 2026-08-31 补规则修复，见 §9.9。**

### 9.9 标准答案核验 + 4 条真盲区规则 + 类型写回（2026-08-31）

#### 9.9.1 标准答案核验：官方没有清单，按权威 CWE 定义逐条校验

用户提出"去网上找标准答案"。核查结论：**不存在官方标准答案**——
we45/Vulnerable-Flask-App 的 README 全文只有一句
`> This is a ZAP Test. Hope it works ;)` 加 "Intentionally Vulnerable Flask app
for use in Demos"，**没有漏洞清单**；OWASP 项目页（nest.owasp.org）为空白模板。
manifest 里的标注系源码实读得出，故改按**权威 CWE 定义**逐条校验分类准确性。

| 条目 | 原标注 | 核验结论 | 依据 |
|---|---|---|---|
| L141 md5 存密码 | 327 | **改为 916** | CWE-916 官方定义「密码哈希计算强度不足」；CodeQL `js/insufficient-password-hash` 同为 916。327 是"用了有风险算法"的**工具粒度**，bandit B324 只能到此 |
| L62 `admin/admin123` | 798 | **维持 798**，note 补 1392 | 代码内硬编码种子凭证 → 798 成立；另属 CWE-1392「使用默认凭证」，二者同一缺陷的不同侧面 |
| L97 `jwt.decode(verify=False)` | 347 | **确认无误** | CWE-347「密码签名校验不当」；CISA 通告与多个 CVE（如 CVE-2025-20248）均用 347 标记签名校验失效 |
| L208/L231 IDOR | 639 | **确认无误** | CodeQL `cs/web/insecure-direct-object-reference` 标注 `external/cwe/cwe-639`；CVE-2026-25567 亦用 639 |
| L294 文件上传 | 434 | **确认无误** | CWE-434「危险类型文件无限制上传」。原判 B 是因 L295 的 `random.randint`(B311 弱随机) 在 ±2 行内邻近误配，**与 434 无关** |
| 其余 89/79/1336/502/798/295/311 | — | 逐条确认无误 | — |

**关键区分——标准答案粒度 vs 工具能力粒度**：md5 存密码的精确分类是 916，
但工具（bandit B324）只能产出"弱哈希算法"(327)。若标准答案定 916 而判定只认
327，这条会**永远判 B**，可工具语义其实是对的。故在 `_SEMANTIC_TO_CWE` 中把
`weak cryptography` 映射为 **`327|916` 同语义组**，二者任一命中即算对齐。
**不要用标准答案的精度去惩罚工具的能力上限。**

#### 9.9.2 补 4 条定向规则（VFlask OK 9 → 13）

| 规则 | CWE | 形态依据（泛化三关卡） | 验证 |
|---|---|---|---|
| `jwt_verify_disabled` | 347 | PyJWT 标准参数 `verify=False` / `options={"verify_signature": False}` | L97 命中；`jwt.decode(t, KEY, algorithms=["HS256"])` 不命中 |
| `error_info_exposure` | 209 | 语言无关：`except ... as <name>` 绑定的异常变量被 `str()` 后 return | L148 命中；`logging.error(str(e))`、`return str(result)` 均不命中 |
| `cleartext_sensitive_storage` | 312 | 字段语义词根（`ccn/credit_card/cvv/ssn/iban`，PCI-DSS 术语）+ 持久化调用 | L160 命中；普通表单入库不命中 |
| `unrestricted_file_upload` | 434 | Flask `request.files` + `.save()` 标准上传 API | L294 命中；有 `allowed_file` 白名单的不命中 |

**VFlask 结果**：OK **9 → 13**，B 2 → 1，A 6 → 3。

**过程中修掉的两个自身缺陷**（都由 87 段回归暴露，非推测）：
1. **`error_info_exposure` 初版误报**：正则 `str\(\w+\)` 匹配任意变量，把
   `return str(result)`、`str(user_id)` 也当异常回显 → safe_16_ldap_escape、
   hard_crossfile_03_input 两个**安全样本**新增候选。改为追踪
   `except ... as <name>` 绑定的变量名，误报清零。
2. **`cleartext_sensitive_storage` 初版漏召回**：设了 `exclude` 排除"文件内存在
   加密调用"，但 **exclude 是文件级判定**——VFlask L141 的 `hashlib.md5`(密码)
   与 L160 的 ccn 毫无关系，却把整条 312 规则排除了。改为不设 exclude，
   "是否明文"交裁决层（字段级语义，正则判不了）。

**另一处行号定位问题**：本规则是双 pattern AND（敏感字段 + 持久化调用），
`_hit_line` 取**行号最小的命中 pattern** → VFlask 的持久化调用在 L64、
敏感字段在 L160，行号落到无关的 L64，审计判定（L160±2）错失。
新增 `_line_of()` 辅助 + `line_func`，让多 pattern 规则显式声明"哪一条是漏洞
主体"。**多 pattern 规则必须配 line_func**，否则行号会指向上下文而非漏洞。

**87 段回归（新增规则后）**：总候选 104 → 106（+2，均来自真漏洞样本
hard_owasp_01_file_upload、hard_bypass_08_jwt_none_alg）；
**安全样本候选 17 保持不变**（无新增误报）；零召回 23/87 不变。

#### 9.9.3 类型写回（生产侧，§9.8 的根因修复）

§9.8 指出审计与生产口径不一致的根因是**推断结果只用于归并分组、从不写回
字段**。本轮在 `_dedupe` 开头补写回：

```python
for f in findings:
    inferred = TwoStageScanner._infer_taint_type(f.to_dict())
    if inferred and inferred != f.taint_type:
        f.taint_type = inferred
```

收益：
- **裁决输入质量提升**：进裁决的候选从 `B608`、semgrep 规则文件路径，变成
  `SQL Injection` / `Insecure Deserialization` / `Weak Cryptography` 等语义名。
  同一份信息，语义名比规则号直白得多。
- **消除 §9.8 的测量偏差**：生产与审计口径就此统一（审计侧的 `inferred_type`
  兼容逻辑保留，作为双保险）。

安全性验证：
- `_infer_taint_type` **幂等**（已是语义名时原样返回），写回不影响归并键稳定性
- 87 段回归**逐文件候选数完全一致**（106 / 零召回 23 / 安全样本 17 / 剔除留痕 7）
- 8 个模块自检 FAIL=0

设计取舍：仅当推断成功才覆盖，推断不出时**保留原值**——宁可让裁决层看到
规则号，也不能把有信息的类型抹成空。

#### 9.9.4 本轮最终状态

| 仓库 | 状态 |
|---|---|
| **VFlask** 17 条 | **OK 13** · B 1（L112 XSS）· A 3（L208/L231 IDOR、layout L311 info 级）|
| **DVNA** 11 条 | OK 5 · B 2（L197 CWE-95 vs 94、L49 CWE-640 vs 208）· A 4 |

剩余 A 盲区定性：
- **639×2（IDOR）**：缺失型漏洞（ORM 查询本身安全，缺的是归属校验），
  与 §8.5 授权类同构 → **不修，记档**
- **CWE-95 / CWE-640**（B 类）：命中行正确、类型是两个不同侧面。
  `mathjs.eval()` 判 94(代码注入) vs 标准答案 95(eval 注入)；
  `md5(login)` 作令牌判 208(时序比较) vs 标准答案 640(弱重置令牌)。
  **模型可消解**，属裁决层优化空间，非工具层缺陷
- **CWE-112 XSS**：同区域 XSS+SSTI 双语义，工具只出 SSTI 一条（另一条被
  归并吸收），需裁决层区分

**教训（本轮第 4 条）**：我在 §9.8 表格里写的 DVNA 数字（OK 6 · B 1）是**凭推算
而非实际输出**写下的，实测为 OK 5 · B 2。与 §9.7 教训 1（陈旧产物）同源：
**文档里的每一个对比数字都必须逐行取自实际输出，推算、记忆、推测都不可信**——
它们比没有数字更危险，因为看起来有依据。

### 9.10 cve_fix 20 段首轮审计 + 数据资产全量盘点（2026-08-31）

**数据资产全量盘点**（用户提示后补全，此前只知 87 段）：
- 带标注：exp_04 87 段 + **exp_01 14 段** + **testset_cve_fix 20 段**（含 source_repo/
  source_sha/taint_path/vuln_patterns/fix_idea 富字段）→ 141 段可审计
- 语料池 2271 文件（corpus/）：taint_boundary_raw 150、framework_safe_raw 145、
  long_file_raw 745、blindspot_teaching_raw 104……**命名即工具层弱点分类**，
  mining 素材（远期）
- 历史专项：prefilter_eval（0801 三份结果）可做规则回归对比

**cve_fix 审计结果**（22 发现级审计点）：

| 判定 | 数量 | 明细 |
|---|---|---|
| OK（召回+类型对）| **13** | 502/78×2/79×2/22×2/798/1336/918/611/89×2（java）——最小化 CVE 片段形态工具层覆盖良好 |
| A 真盲区 | 5 | **LDAP 注入 90×2**（filter 拼接无规则，P2）；**CWE-441×2**（冷门，P3 缓）；**PHP 文件 0011**（语言支持缺口，路线图）|
| 标注存疑 | 4 | 0003/0004 的 95（agent 框架示例，eval 是设计意图）、0019 的 94/918（最小化文件只含 SSTI 部分，多标签超范围）——**测试集杂质，转标注治理** |

**与 §9.9 的衔接**：本审计的 miss 里有 347/209/312 吗——没有（本集 20 段不含这三类形态）；
§9.9.2 的 4 条规则（jwt_verify_disabled/error_info_exposure/cleartext_sensitive_storage/
unrestricted_file_upload）是 VFlask 对账驱动的，与本集互补。两集合计后仍缺的定向规则：
LDAP 注入 90（本集 ×2，P2 立项）。

**待办补记**：① exp_01 14 段尚未跑审计（本轮只盘点未执行）；② 0019 的 jwt 形态
若与 §9.9.2 jwt_verify_disabled 规则形态一致，重扫时应转 OK（验收项）。

**审计工具自身修了 3 个 bug**（fail-loud 改造的额外收益）：
1. `__new__` 绕过致 _taint_recall 静默失败 → taint 独立实例直调 + 失败显式抛错
2. TaintPath/ToolFinding 结构不齐 → 复刻 _taint_recall 归一化（audit 内）
3. **无行号 manifest（line=0）时行号匹配恒假 → 全部假"盲区"** → 退化为纯类型匹配
   （教训：审计工具的"A 盲区"结论在自身故障时全不可信——先证明工具没错，再定引擎有错）

**召回基线更新**：cve_fix 发现级召回 13/22 = 59%（真实 CVE 形态）；87 段类型命中
88.2%（单文件）；仓库大文件 38%（§9.6）。三档差距 = 切片稀释 + 框架/冷门规则缺口，
全部在工具层射程内。

### 9.11 训练集形态 mining——泛化差距图谱（2026-08-31，战略转向：形态规则 > 逐仓补规则）

**用户确立**：泛化性能是项目价值核心，逐仓补规则不可持续。训练集（16609 条，
含代码块 16583 个）是现成的"期望形态频谱"——`mine_train_forms.py` 解析出
**1804 个形态签名**，与工具层 sink 覆盖求差集即泛化差距图谱。

**跨语言 sink 缺口 Top**（频次 = 该形态在训练集出现次数 ≈ 一条规则的可泛化收益）：

| 形态 | 频次 | 现状 | 修复 |
|---|---|---|---|
| `require('child_process')` 解构族（execFile 226 / execSync 202 / spawn 65）| **668** | **零覆盖**：taint_tracker 只有 `child_process.exec(` 精确串，require 解构导入后裸调 execFile/execSync/spawn 全漏 | **P1**：JS import-aware sink——解析 require 行建符号表，`execFile(`/`spawn(` 裸调命中 Command Injection |
| `exec(回调)` Node 异步形态（`exec(VAR, (err,stdout)=>{...})`）| 86 | exec( 有覆盖（94/78 override），但回调第二参数形态未见误报 | 观察 |
| `Runtime.getRuntime().exec(` Java | 63 | 已覆盖 | — |
| `$obj = unserialize($VAR)` PHP | PHP unserialize 零覆盖（形态 mining 未见直证，但 php-goof 在队列）| **P1**：PHP 反序列化 + `$_GET/$_POST` source（taint_tracker 已有 source，缺 PHP sink 连接验证）|
| `.redirect(...)->with(` Laravel 链式 | 27 | redirect( 有覆盖，链式尾部行无污点 | 观察 |

**TAINT_PATH 字段**：训练集该字段全空/未填——形态频谱以代码块 mining 为主。

**方法论固化**：每轮"训练集 mining → 差集 → 形态规则 → DVNA/VFlask/87 段三场
复测"为一迭代；规则只写**形态签名级**（require 解构族），禁止样本特判（泛化三关
语言级事实关先行）。下次大版本模型训练（v2_15）后语料换血，mining 重跑即可
拿到新形态频谱——**工具层进化与模型进化共用同一数据源，同步迭代**。

**第一修已落地：import-aware cp sink**（taint_tracker.py）：
- `_collect_cp_symbols`：解析 `const {execFile, execSync, spawn} = require('child_process')`
  解构名 + `const cp = require(...)` 命名空间名（含 `cp.*` 通配形式）
- `_analyze_scope` 2b 补记：独立于常规 sinks 循环（execFile 不在 sink 表，
  放循环内永远跑不到——第一版逻辑位置错误，复测时抓出），直接遍历调用节点比对
  解构名/命名空间名，参数含污点 → 补 Command Injection 路径
- 六项验证全 PASS：execFile/execSync/spawn 三解构变体 + cp.execFile 命名空间 +
  fs 安全对照（非 cp 导入零候选）+ Python 直传回归（列表参数零召回是 0817
  语境安全设计行为，非回归）

**工具层逐条审计（2026-08-31 补跑，`audit_stage1.py`，零 LLM）**

§9.6 此前只有 LLM **实扫**对账（发现级 recall 5/13≈38%），回答的是"模型表现
如何"；而"38% 的缺口里多少源于工具层没召回"——**此前从未测过**。补跑结果
（17 条 expected finding）：**OK 9 · A 盲区 6 · B 类型错标 2**
（B 类已按 §9.8 修正判定口径）。

| expected | 判定 | 覆盖候选 | 归因 |
|---|---|---|---|
| L26/L62 CWE-798 硬编码密钥/弱凭证 | **OK** | bandit B105 ×4 | — |
| L97 CWE-347 `jwt.decode(verify=False)` | **A 盲区** | 无 | JWT 签名不校验，无 sink 形态 |
| L112 CWE-79 404 页 XSS | B | semgrep SSTI @L114 | 同区域 XSS+SSTI 双语义，工具只出 SSTI 一条 |
| L114/L281 CWE-1336 SSTI | **OK** | semgrep render-template-string | — |
| L141 CWE-327 md5 存密码 | **OK** | bandit B324 + semgrep md5 ×2 + prefilter | — |
| L148 CWE-209 `str(e.message)` 回显 | **A 盲区** | 无 | 异常信息泄露，无 sink 形态 |
| L160 CWE-312 信用卡明文存库 | **A 盲区** | 无 | 缺失型（应加密未加密），无污点形态 |
| L208/L231 CWE-639 IDOR | **A 盲区** ×2 | 无 | 缺失型（未校验归属），与 §8.5 授权类同构 → **不修，记档** |
| L261 CWE-89 `%s` 拼接 SQL | **OK** | bandit B608 + semgrep tainted-sql-string | — |
| L329 CWE-502 `yaml.load` | **OK** | bandit B506 + semgrep + prefilter | — |
| L294 CWE-434 任意文件上传 | B（实为 A） | bandit B311 @L295 | B311 是弱随机与上传无关，行号±2 邻近误判；**434 规则缺失是真盲区** |
| e2e_zap L18 CWE-295 | **OK** | bandit B501 + semgrep disabled-cert-validation | — |
| e2e_zap L15 CWE-798 | **OK** | bandit B105 | — |
| layout L5 CWE-311 | A 盲区 | 无 | info 级，不计 miss（§9.6 口径）|

**结论**：工具层**语义召回 9/16 ≈ 56%**（layout info 级不计分母），显著高于
LLM 实扫的 38%。§9.6 那句"工具层对这些形态零召回"的猜测**只对了一半**：
347/209/312/639×2 确实零召回（5 条真盲区，含被误判为 B 的 434），但
**798/79/1336×2 工具层全都召回了**——丢分发生在**裁决层**（模型否决或未进
裁决），不是工具层。

**修正 §9.6 的 P1 待办**：原计划"关闭切片跑对账以分离切片稀释 vs 规则盲区"。
有了工具层审计作对照后可直接定位，无需再靠开关切片做差分实验：
**工具层零召回 = 规则盲区**；**工具层已召回但实扫 miss = 切片稀释或裁决层
否决**（需另查）。

> 上表为**补 4 条规则之前**的状态。补规则后的最新数据见 **§9.9**
> （VFlask OK 9 → **13**）。


### 9.12 第四波：长尾注入族 8 规则——§五之五 零召回清单清账（2026-08-31）

> 定位：§五之五「剩余零召回缺口（11 段）」中"能写出语言/框架标准写法"的项，
> 加上 §9.10 立项的「LDAP 注入 90（P2 立项）」。**逐条"修不了 vs 没修"判定先行**
> （用户要求：不修的必须说清是真修不了还是没修），可修的 8 类本轮全落地。

#### 9.12.1 逐条判定：真修不了 vs 能修未修

| 缺口样本 | 判定 | 依据 |
|---|---|---|
| typical_21 XXE | **能修未修**（本轮修）| 解析器加固开关是标准 API 参数（resolve_entities/disallow-doctype-decl），缺失型中有标准安全开关可查 |
| typical_24 LDAP | **能修未修**（本轮修）| filter 由 f-string/拼接构造是注入形态；参数化传参（safe_16）是标准安全写法 |
| typical_25 NoSQL | **能修未修**（本轮修）| 请求值直进 Mongo 查询文档字面量；类型强制 str() 是标准安全写法 |
| typical_26 XPath | **能修未修**（本轮修）| 表达式构造后传 .xpath( 求值，形态同 SQL 拼接 |
| typical_33 PHP 类型混淆 | **能修未修**（本轮修）| `==` 松散比较是 PHP 语言特性级形态，$_ 超全局天然语言隔离 |
| typical_30 Mass Assignment | **能修未修**（本轮修）| setattr 动态属性写入是 Python 标准 API，正常业务代码极少用 |
| hard_cve_06 Struts2 OGNL | **能修未修**（本轮修）| Ognl.getValue/parseExpression 是库专有 API，无第二语义 |
| hard_cve_08 fastjson | **能修未修**（本轮修）| JSON.parseObject 是 fastjson 特有 API（org.json/Gson/Jackson 均不同名） |
| hard_cve_05 spring4shell | **真修不了** | POJO 参数绑定是 Spring MVC **官方标准用法**，漏洞在框架版本（<5.3.18）；写规则会 FP 掉所有正常 Spring controller |
| hard_cve_03 tarfile | 设计内不修（维持）| 0 候选 + 强制复核兜底，上下文剥离后的正确行为（§五之六 待办1） |
| hard_crossfile_02_sink | 架构级不修（维持）| 跨文件数据流，单文件管道外（论文标注局限） |
| VFlask 639×2 / CWE-200 / DVNA 639 | 缺失型不修（维持，§9.9 同判）| ORM 查询本身安全，缺的是归属/字段过滤逻辑，无污点形态 |

#### 9.12.2 落地的 8 条规则（prefilter.py，全部过泛化三关）

| 规则 | CWE | 形态 | 标准安全写法豁免 |
|---|---|---|---|
| `xxe_unprotected_parse` | 611 | XML 解析 sink（lxml/minidom/parseString + Java `.parse(` 宽 sink×DocumentBuilderFactory 上下文守卫）× 输入，且全文件**无加固特征** | resolve_entities=False / disallow-doctype-decl / defusedxml / noent:false（_XXE_SAFE_RE，**注释行剥离后判定**） |
| `ldap_injection` | 90 | filter 经 f-string/模板串/拼接构造 → search_s/ldap_search（`.search(` 需 ldap 上下文守卫）| 参数化传参 `[username]` 作独立参数（safe_16）；字面量 filter 非构造式不收集 |
| `nosql_query_injection` | 943 | find/find_one/findOne 参数区为查询文档（`{`）且含输入；文件需 mongo 上下文守卫 | 值经 str()/int() 类型强制（typical_25 fix_idea 形态） |
| `xpath_injection` | 643 | f-string 构造表达式 → `.xpath(` | 常量表达式不收集 |
| `php_loose_compare` | 843 | 凭证词 + 弱比较 `==` + 输入关联（$_ 超全局或其 1 跳变量）| `===` 强比较；两侧均 $_ 的字段一致性（确认密码） |
| `mass_assignment_setattr` | 915 | dict 键值遍历（输入派生）+ setattr 引用循环变量 | 白名单过滤（allowed_fields/`if key in` 等，_MASS_ASSIGN_SAFE_RE，注释剥离后判定） |
| `deser_fastjson` | 502 | JSON.parseObject（无守卫）；裸 JSON.parse 须 fastjson import 守卫（JS 同名 API 是安全解析） | Gson/Jackson/org.json 不同名天然不撞 |
| `ognl_expression_injection` | 917 | Ognl.getValue/parseExpression 参数区含构造式输入 | — |

配套：`_constructed_var_names`（f-string/JS 模板串/拼接/格式化构造且引用输入的
变量，1 跳）、`_code_wo_comment_lines`（整行注释剥离——**CVE-fix 独立集实锤的
注释污染**：cve_fix_0021 把 `// Missing: setFeature(...disallow-doctype-decl...)`
写在注释里，_XXE_SAFE_RE 文件级搜索被注释命中 → 漏洞版被误判"已加固"漏报）；
`_STANDARD_TAINT_TYPES` + XPath Injection/Type Juggling/Mass Assignment/347/209/312/434
语义名；`_infer_taint_type` + XPath/OGNL/fastjson/JWT 推断分支；cwe_normalizer +
611/643/915/843/434/312/209/347 短语级映射（**不收 xml/xpath 等裸词**，回声票纪律）。

#### 9.12.3 验证矩阵（三关全过）

| 关 | 结果 |
|---|---|
| 87 段（设计集） | 8 段全部 0→候选（21/24/25/26/30/33/cve_06/cve_08，全 expected=true）；**零召回×真 11 → 3**（剩余 = spring4shell 真修不了 + cve_03 设计内 + crossfile_02_sink 架构级）；**安全/噪声候选 14 持平（零新增）**；候选≥3 的 10 持平 |
| 独立集 cve_fix（零接触） | cve_fix_0021（CWE-611）由**漏报 → 命中 @L25**（注释污染修复后）；cve_fix_0001（CWE-90 标注，实为占位符替换+LdapEncoder.nameEncode 转义）不命中为**正确**——占位符替换形态不追（转义有无正则判不了，记档）；其余 18 段零误报 |
| 安全对照 | safe_14（defused）/ safe_16（LDAP 参数化）/ safe_09 / typical_09 不误报；9 个独立构造负样本（Java setFeature、参数化 LDAP、Mongo str() 强制、PHP `===`、确认密码、白名单 setattr、常量 xpath、Gson、Sequelize findOne）全不命中 |
| 仓库级 | VFlask 6 文件 + DVNA 14 文件全仓扫描：**第四波规则 0 新增候选**（无 mongo/ldap/OGNL 上下文 → 守卫正确关闭） |
| 自检 | prefilter 全过；two_stage 新增用例 #24（11 例：8 正 + 3 负）全过；cwe_normalizer 全过 |

**已知边界（记档）**：
- cve_fix_0002（CWE-90，ldapauth 库源码）：`{{username}}` 占位符替换 + 形参污点
  + 2 跳 object 字段传递（searchFilter→opts.filter→search(options)），正则层
  三重射程外（`.replace(/</g)` 是转义安全写法，只有 `{{...}}` 占位符形态可区分，
  但 2 跳与跨文件无法兼顾）→ 不追，维持 §9.10 的 A 盲区判定；
- JS 无 mongo 字样的抽象层文件（`db.collection(...)` 不带 require）NoSQL 漏报
  ——Sequelize `findOne({where:...})` 同形负样本（node_sequelize）证明守卫必要，
  精度取舍，跨文件上下文是架构级局限；
- Java XXE 分离形态（parse 行与输入行断链）按文件级输入关联兜底，更强精度需
  变量级 2 跳（现 1 跳）；
- 行内注释中的守卫词仍会命中 _XXE_SAFE_RE（只剥整行注释，http:// URL 防误伤）。

**LLM 裁决层重跑待算力**（同 §五之六 待办1 口径）：候选类型均带规范 taint_type
（XXE→CWE-611 等），裁决通过后 8 段应转"有候选裁决"通道，兜底判真数预期 12 → ~4。

---

### 9.13 度量先行：两处「测量缺陷」修正（2026-08-31）

**教训**：动手改工具前先验证度量本身可信。本轮发现两处测量缺陷都在**系统性
低估**工具层能力，若照单全收会导出错误结论（"prefilter 很弱，该砍掉"）。

#### 9.13.1 评测器 CWE 映射表漂移（prefilter 严格准确度被低估 3 倍）

`experiments/prefilter_eval/eval_prefilter.py` 维护了一份**手工副本**
`RULE_TO_CWE`（仅 9 条），而 prefilter 实际已有 32 条漏洞规则。新增规则的
CWE 在副本里查不到 → 被计成「CWE 不匹配」。

实锤：87 段里 25 例「CWE 不匹配」的命中规则**全部为空列表**——即规则已正确
命中并判对方向（29/29 TP、FP=0），只是评测器不认识规则名。

修复：改为从 `PREFILTER_RULE_INFO` **派生**（单一真源），新增规则只要在
prefilter 里登记 `cwe` 字段，评测自动覆盖，两份表不再可能漂移。

| 指标（87 段） | 修正前 | 修正后 |
|---|---|---|
| strict_accuracy | 0.3243 | **0.9459** |
| strict_TP（CWE 匹配） | 4 | **27** |
| CWE 不匹配 | 25 | **2** |

#### 9.13.2 审计脚本去向判定用键匹配（凭空多出一倍候选）

`audit_stage1.py::candidate_rows` 用「键是否在 final 集合里」判定去向，而键是
`(rule_id, 行, 类型)`——被 `_dedupe` **合并掉**的那条与保留下来的那条键完全
相同，于是两条原始候选都被标成「进裁决」，并连锁触发「重复候选」误报。

dvna L39 实锤：final 实际只有 1 条，报告却显示 2 条进裁决。

修复：改为**计数配额**（某键在 final 中出现 n 次，则 raw 中前 n 条算进裁决，
其余算被合并）；`dedupe_check` 同步只统计最终进裁决的候选。

---

### 9.14 第五波：核心注入族形态缺口（2026-08-31）

§9.12 补的是**长尾注入族**（XXE/LDAP/NoSQL/XPath…）。本波补的是 OWASP 主流
类别的**形态缺口**——旧规则只认「输入直接出现在 sink 调用内」的内联字面量，
而真实代码主流是「先构造变量、再把变量传入 sink」的 1 跳形态，以及 f-string /
模板字符串等非拼接构造式。

#### 9.14.1 落地的 4 条规则（prefilter.py）

| 规则 | CWE | 补的形态 | sink 依据（语言/库级标准 API） |
|---|---|---|---|
| `sqli_constructed_query` | CWE-89 | 1 跳变量传入、f-string、`%`/`.format` | `.execute/.executemany/.executescript`（PEP 249）、`.executeQuery/.executeUpdate`（JDBC）、`mysqli_query` |
| `cmd_injection_shell` | CWE-78 | Python f-string、JS 模板字符串 | `subprocess.*`+`shell=True`、`os.system`、`exec(`（**仅** child_process 引入时） |
| `xss_unescaped_output` | CWE-79 | prefilter 此前**完全无** XSS 规则 | 三要素：HTML 标签字面量 + 输入拼接/插值 + 输出 sink |
| `ssrf_request_from_input` | CWE-918 | prefilter 此前**完全无** SSRF 规则 | `urlopen/urlretrieve`、`requests.*`、`axios.*`、`http(s).request`、`curl_exec` |

共用一套 1 跳消解（`_split_first_arg` / `_assigned_expr_line`）与构造识别
（`_expr_is_constructed`）。上下文守卫沿用 §9.12 纪律：裸 `.execute(` 与 Java
线程池 `ExecutorService.execute(Runnable)` 同名 → 加 `_SQL_CTX_RE`；JS `exec(`
= 命令注入而 Python `exec(` = 代码执行 → 加 `_JS_CHILDPROCESS_RE`；裸 `fetch(`
是浏览器端取数、无 SSRF 语义 → 不纳入 sink 表。

#### 9.14.2 精度约束（全部由安全对照样本实锤，非臆测）

首轮上线即产生 4 个 FP，逐条定位后加约束，最终 **FP 归零**：

| 样本 | 误报原因 | 约束 |
|---|---|---|
| `safe_06_csp_header` | 已 `html.escape` | `_XSS_SAFE_RE`（转义后再插 HTML 是标准修复） |
| `safe_15_ssti_escape` | Jinja `{{ x }}` 被当字符串插值；且有 autoescape | 剥模板占位符后再判插值；`_XSS_SAFE_RE` |
| `safe_08_shlex` | 已 `shlex.quote`（shell 引号转义） | `_CMD_SAFE_RE` |
| `noise_03_harden` | ① 常量 `"admin"` 被当变量；② SQL 文本里的 `FROM`/`WHERE` 被当拼接标识符 | `_is_constant_var`；标识符提取一律在**剥离字符串字面量后**的文本上做 |

第 ② 条是**二次修复**：首次只修了变量引用分支，拼接标识符分支仍在原文上取词，
把 SQL 关键字当成变量（`FROM` 未在本文件赋值 → 判非常量 → 命中）。

#### 9.14.3 行号口径：1 跳形态报构造行而非 sink 行

VFlask L265 首次报出后被审计判为「C 无关候选」——不是误报，是**行号偏了 4 行**：
manifest 标 CWE-89@261（`%` 构造行），规则报 265（`execute` 行），超出 ±2 容差。

修正：1 跳形态报**查询文本的构造行**（漏洞主体是「把输入拼进语句」这一步，
sink 只是执行点；标准答案与真实漏洞报告均按构造行标注）。内联形态构造与
sink 同行，两种口径自然一致。修正后 L261 由 A 盲区转 OK。

#### 9.14.4 伴生修复：TaintTracker 同流双报去重

调试 dvna 时发现 taint_tracker 对**同一条流**产出两条候选，sink 描述分别为
`cp:exec` 与 `exec(`（`source` 与行均相同）。主键 `(类型, source, sink)` 因
sink 文本差异永不相等 → 同一漏洞进裁决两次，白耗 N=3 次采样。

修复：`_dedupe` 增加二级索引 `by_src_line`，有证据候选在主键未命中时按
`(类型, source, sink 行)` 归并。放宽的只有 sink 文本一项，同行的不同 sink
调用（`exec(a); exec(b)`）因 source 不同不会被误并。

#### 9.14.5 验证矩阵

| 关 | 结果 |
|---|---|
| prefilter 独立评测（87 段） | recall 0.4754→**0.7377**；strict_acc **0.9434**；**FP=0**（不劣化）；覆盖率 0.4253→0.6092 |
| prefilter 独立评测（cve_fix 20） | recall 0.35→**0.60**；strict_acc **0.75**；FP=0 |
| 独立集仓库（VFlask，零接触） | **L261 CWE-89 由 A 盲区转 OK**；C 类噪声表**清零**；OK 13 保持 |
| 独立集仓库（DVNA） | OK 5 保持；无新增 C 噪声；重复候选误报消除 |
| 冒烟 | `scripts/tool_smoke_test.py` **PASS=9 FAIL=0** |
| 自检 | prefilter 全过；taint_tracker / cwe_normalizer 全过 |

#### 9.14.6 诚实口径：87 段上是冗余佐证，真实增益在仓库

必须区分两个层面，避免把 prefilter 的独立召回增益当成系统召回增益：

| 层面 | 修复前 | 修复后 | 结论 |
|---|---|---|---|
| 87 段 Stage 1 判定 | OK 44 / A 41 | OK 44 / A 41 | **无变化** |
| 87 段候选数 | raw 181 → final 98 | raw 201 → final 100 | 新规则贡献 20 条原始候选，**18 条并入已有候选**，仅 2 条独立新增 |

原因：87 段合成集的注入类样本已被 semgrep/bandit/taint_tracker 覆盖，prefilter
新增多为**交叉佐证**（多工具一致的候选在裁决层更不易被 1/2 票否决，对应
§三「冗余候选制造复核噪声」的反面）。真实召回增益来自 VFlask L261——那里其他
工具都没覆盖到，prefilter 补上了。

prefilter 召回提升的**直接收益是短路率**：判 True 的样本不再调用 LLM，87 段上
判 True 由 29 → 45（FP 恒为 0，故短路安全）。

**已知边界（记档）**：
- 1 跳为限：`q = build(user); execute(q)` 这类 2 跳仍漏，需变量级数据流（架构级）；
- `_assigned_expr_line` 按行首形态取赋值，跨行赋值的续行部分不入表达式
  （Java 多行拼接 SQL 实测靠首行已能判定，但不保证全部形态）；
- XSS 三要素里的「输出 sink」用正则近似，模板自动转义以外的间接输出（`return`
  到上层拼装）可能漏；
- SSRF 只覆盖显式 HTTP 客户端调用，经封装函数/SDK 的间接请求不追。

### 9.15 两波收口：注释免疫全覆盖 + 构造检测共享原语（2026-08-31）

§9.12（第四波长尾族）与 §9.14（第五波主流族）并行落地后发现三处不一致，本轮
全部收口——**两波共用的判定逻辑必须建立在同一组原语上，否则下次改形态要改两处
（§9.7 方法论教训 3"判定收进单一入口"）**。

| # | 问题 | 修复 |
|---|---|---|
| 1 | **注释免疫不对称**：§9.12.2 给 `_XXE_SAFE_RE`/`_MASS_ASSIGN_SAFE_RE` 加了整行注释剥离（cve_fix_0021 教训），§9.14 的 `_XSS_SAFE_RE`/`_CMD_SAFE_RE`/`_SSRF_SAFE_RE` 仍在原始文本上判——文件里任何注释提到 `html.escape`/`shlex.quote`/`allowlist` 都会整体豁免对应规则（同款失败模式潜伏） | 三处判定统一走 `_code_wo_comment_lines`；新行为验证：注释提 shlex/escape 的真漏洞正确报出，safe_06/08/15（防御在代码行）不受影响 |
| 2 | **构造检测双实现分叉**：第四波 `_constructed_var_names`（变量级收集）与第五波 `_expr_is_constructed`（表达式级判定）各有一套字符串构造识别，能力互缺——前者无字符串剥离（noise_03 教训②未同步）、后者不认 JS 模板串 | 抽出模块级共享原语 `_strip_str_literals`（剥 `'`/`"` 字面量、反引号串**保留 `${}` 插值段**——插值是真实代码引用）；两侧统一调用；`_expr_is_constructed` 构造形态 ④→⑤（补模板串）。两个 API 保留：变量级（sink 参数区引用检查）与表达式级（1 跳消解）本就是同一机制的两个粒度，原语已归一 |
| 3 | **`sql_execute` sink 缺 `.query(`**：Node mysql/pg 标准查询 API（§9.7 #1 已在 taint_tracker 论证标准性）在 prefilter 侧缺失，`db.query(sql)` 1 跳形态漏召回 | 补入 sink 表（词边界天然避开 `req.query.id`/`querySelector`，`_SQL_CTX_RE` 守卫兜底）；`req.query` 取值与非 SQL 上下文负样本验证不误报 |

**验证（全量，零回退）**：三模块自检全过；eval_prefilter 87 段 strict_acc 0.9434 /
recall 0.7377 / FP=0、cve_fix strict_acc 0.75 / recall 0.60——与 §9.14.5 逐项一致；
87 段静态回归四项指标持平（零召回 15、零召回×真 3、候选≥3 的 10、安全样本候选 14）。
候选明细仅两处 2→1 且均为**归并改善**：typical_10（taint_tracker 同流双报被 §9.14.4
去重收进多工具候选）、hard_longfile_01（prefilter 行号对齐构造行 L317 后与 bandit
B608 归并为 `bandit+prefilter` 双工具候选——多工具一致证据，§三 冗余治理的正向形态）。

**skill 同步**（`.codebuddy/skills/`）：tool-defect-audit 补环境铁律（graproj，
§9.7 教训的操作化）、87 段回归命令改为 dump 静态口径（eval_two_stage 归第 5 步
LLM 对账）、新规则登记 `PREFILTER_RULE_INFO` 纪律（§9.13.1 单一真源）、复测同
环境同口径纪律；过期基线节改为指针式快照（历史数字曾与文档修正脱节）。
vuln-scan-sample-triage 补环境纪律、F6 跳号注解（行号噪声，定义在训练层文档
P1-C）、关键路径补 exp_08 仓库基准。

### 9.16 第六波：逐工具健康诊断 → 2 个 P0 接入缺陷 + 语言覆盖补齐（2026-08-31）

> 触发方式：对"每个工具还有无可优化处"做**逐工具健康检查**——冒烟 + 87 段
> dump 的语言×工具覆盖矩阵 + 最小样例对照实验 + 内部方法分步追踪。两个 P0
> 都不是"规则不够"，而是**调用方式让工具必然零召回**（B1 同型第 3、4 次）。

#### 9.16.1 P0-1：detect-secrets 对绝对路径必然零召回（SKIP 后门掩盖）

| 调用形态 | `password = "hunter2_hunter2_secret"` |
|---|---|
| CLI 直跑（相对路径） | 召回 `Secret Keyword` |
| 接入层 `scan --all-files /abs/path.py` | **`results: {}`** |
| cwd=文件目录 + basename | 召回 `Secret Keyword` + `AWS Access Key` |

detect-secrets 1.5.0 对绝对路径不扫描；接入层固定传绝对路径 → 该工具**整个
项目周期从未产出过任何发现**。掩盖机制：冒烟脚本把"阳性零召回"显式降级为
SKIP（注释"插件/版本相关"）——**B1 的核心纪律是"零召回先查调用链"，把零召回
设计成免检等于在最需要它的地方废除它**。

修复：`_run_detect_secrets` 改为 cwd=目录 + basename；filename 回填原 path。
收益（87 段）：secret 通道 3 → 8 段（typical_15/16/33、crossfile_03_sink、
longfile_03 新增），安全样本零误报；VFlask 审计中 L26/L62/L15 的 798 发现
获得 bandit+gitleaks+detect-secrets 三工具一致。

**冒烟脚本修订**：SKIP 只授予"环境不具备"（trivy 漏洞库/pip-audit 网络），
**不授予零召回**；detect-secrets（无外部依赖）零召回改判 FAIL，FAIL 提示
固化"先查调用链路径形态，勿归因为插件或版本"。

#### 9.16.2 P0-2：Java/JS source 硬编码变量名 → taint_tracker 跨语言失效

`_SOURCE_PATTERNS["java"]` 写的是 `request.getParameter`——**变量名锁进了
模式**，而 Java 请求对象是形参、命名自由。实测 87 段 8 个 Java 样本
taint_tracker 贡献恒为 0。**自检用例恰好用 `request` 变量名 → 自检永远
通过**——自检样例与被锁的假设同名，就永远发现不了这个假设（§8.9 教训 1
的推论：新语言判定必须带该语言**多形态**阳性用例）。

修复：Java 改**方法名级**（`getParameter(` / `getHeader(` / `getParameterValues(`
/ `getInputStream(` / `getReader(` / `getQueryString(` 等 Servlet 专有方法，
无第二语义）；JS/TS 补 `request.` 变体与 `req.headers/cookies/files`。

#### 9.16.3 两个解析层缺陷（修 source 后暴露）

1. **catch/except 块整体不可见**：`_BODY_TYPES` 缺 `catch_clause`/
   `except_clause`/`finally_clause` → `_iter_statements` 对 try 的子句**既不
   递归也不 yield**，块内赋值与 sink 全盲；且 sink 节点仍会被 try_statement
   级扫描看到 → "只见 sink 不见污点"半盲。hard_cve_06 的 `request.getHeader`
   赋值 + `Ognl.getValue` 双双落在 catch 内 → 零召回。Python 侧 except 同样
   受益（自检补 6 行内联链用例）。
2. **无参 sink 回退整条语句**：`Object obj = ois.readObject();` 的 arg_joined
   回退用 stmt_text，把刚标记为污点的赋值目标 obj 也算进去 → 同一漏洞两条
   readObject 路径（chain 多出 obj 自己喂自己）。改为取赋值右值。

#### 9.16.4 语言 sink 补齐 + 无歧义族 sink（链级证据升级）

- **Java 专有**（`_SINK_LANG_ONLY` 限定）：`new File(` / `Paths.get(` /
  `FileInputStream(/OutputStream/Reader/Writer` / `ObjectInputStream(` /
  `readObject(` / `parseObject(`（fastjson 专有）/ `parseExpression(`（SpEL）/
  `Ognl.getValue(`。
- **PHP 专有**：`mysqli_query(` / `mysql_query(` / `->query(`（PDO/mysqli OO，
  需 `_CALL_NODE_TYPES` 补 `member_call_expression`）/ `unserialize(` /
  `file_get_contents(` / `shell_exec(` / `passthru(` / `proc_open(` /
  `curl_exec(` / `ldap_search(`。此前整张表 PHP 只有 `system(` 可用。
- **无歧义族**（不新增召回，把 prefilter 已有召回**升级为链级高信任证据**，
  §五之三 信任分级的兑现）：`.xpath(` / `search_s(` / `urlopen(` /
  `urlretrieve(` / `axios(.get/.post(` / `http.request(` / `redirect(`。
  收录标准 = API 名在该生态无第二语义；`.parse(`/`find(` 等需上下文守卫的
  宽名仍留在 prefilter。
- **`_SINK_RANK` 补登记**：新增类型不登记 rank 会在 `_MAX_PATHS_PER_SCOPE`
  截断时垫底被丢——"加了对的规则却没进裁决"的隐形坑。
- **`_compile` 补 `->` 前缀分支**：`->query` 加标识符断言会在 `$pdo->query`
  失配（前字符是 `o`）→ PHP OO 查询整类漏。
- **LDAP 参数化误报**：新 `search_s(` sink 上线即误报 safe_16（python-ldap
  参数化形态 `search_s(base, scope, filter, [attrs])` 与 SQL 占位符同构）。
  判定矩阵（已入自检）：常量模板+占位符数==列表元素数 → 安全；占位符数
  不匹配 → 报；模板变量被污染 → 报。**占位符计数不能整串 findall**
  （`_PARAM_PLACEHOLDER_RE` 匹配带引号整串，`(uid=%s)(cn=%s)` 只返回一次）
  → 改在去引号内容上逐个计数。且模板参须**先筛常量参再查占位符**
  （base 参 `"dc=x"` 是常量但无占位符，先取首个常量参会把它当模板）。

#### 9.16.5 P2 两项

- **P2-9 执行状态留痕**：`ExternalScanner.last_status`（ok/empty/parse_error/
  timeout/not_found/os_error），two_stage 写入 `stage1["tool_status"]`
  （仅异常状态）。此前 20+ 处降级 `return []` 全静默——工具超时与"无命中"
  不可区分（B1 静默性同构）。留痕是旁路，不干预主流程。
- **P2-8 semgrep 合并**：`_semgrep_execute_cached` 同文件一次执行
  （registry 包 + taint 目录），两路解析从缓存按 `"-taint"` 后缀分流，
  互不双计。单文件 2.04s → 1.31s（-36%），缓存命中 0.07s。

#### 9.16.6 验证矩阵

| 关 | 结果 |
|---|---|
| 冒烟 | **10 PASS / 0 FAIL / 0 SKIP**（detect-secrets 由 SKIP 转 PASS） |
| 模块自检 | taint_tracker 31 例（新增 20+：Java/JS 变体、catch 块、PHP 四象限、LDAP 参数化矩阵）、two_stage（含 #25b 修复）、prefilter、cwe_normalizer 全过 |
| 87 段（14:49 终版 vs 13:49 基线） | 总候选 117 → **132**（+15 全部来自 13 个真漏洞样本）；**安全样本候选 17 持平（零新增误报）**；零召回 15 / 零召回×真 3 持平 |
| Java 样本 | 34 获链级候选（semgrep+taint 归并）；35 ObjectInputStream+readObject；36 SpEL；cve_06 Ognl；cve_08 fastjson——5/8 从零到链级 |
| 仓库级 | VFlask OK 13 · B 1 · A 3；DVNA OK 5 · B 2 · A 4——**与 §9.9.4 逐项一致**（零回退） |
| prefilter 独立评测 | 87 段 recall 0.7377 / strict_acc 0.9434 / FP=0；cve_fix 0.60 / 0.75——与 §9.14.5 逐项一致 |
| P2-8 等价性 | 终版 dump 与合并前逐文件候选一致（零变化） |

**候选≥3 的样本 10 → 17 说明**：+7 段全部是真漏洞样本获得**多工具一致证据**
（如 open_redirect 族 taint+semgrep+prefilter 三通道），非同漏洞重复告警
（同族同行已归并）——§三 冗余治理的正向形态，裁决层更不易被单票否决。

#### 9.16.7 方法论沉淀

1. **"零召回降级 SKIP"只授予环境不具备**。冒烟防线的作用是把零召回变成
   FAIL 让人去查调用链；把零召回本身设计成 SKIP，防线在最需要的地方失效
   （detect-secrets 整个生命周期零产出的直接原因）。
2. **自检用例必须与被测代码"不同假设"**。旧 Java 自检写 `request.getParameter`，
   与源码硬编码的 `request` 同名 → 永远 PASS。新语言判定必须带该语言的
   变体形态（req/request/httpRequest…），单一形态等于没测。
3. **修 A 暴露 B 是常态**：修完 source（9.16.2）Java 仍 5/8 零召回 → sink
   缺失；修完 sink 又暴露 catch 盲区与参数化误报——**逐层修、每层复测**，
   不要试图一次写完。
4. **二分定位洗清嫌疑**：P2-9 上线后 two_stage 自检 #25b FAIL，移除 P2-9
   重跑仍 FAIL → P2-9 无辜；真因是 blind_spots 用例样本过短（7 行文件的
   片段省不过 40% 闸门），属前会话遗留设计缺陷。**用例期望值也要核对**——
   本波两次因期望行号数错而假 FAIL（catch 用例、模板污染用例）。
5. **stash 对照对未提交工作区无效**：工作区本身就有大量未提交改动时，
   `git stash` 回退的是旧版本而非"本波改动前"，对照结论不可信；
   应做**针对性移除重跑**（只撤本波改动）。

---

### 9.16 盲区提醒独立验证：从 2/7 到 7/7（2026-08-31）

`graduation_project/blind_spots.py`（用户实现，8 类 21 条 + 三硬约束 + 已接线
`two_stage_scanner`）此前**只有模块自检**（自出题）。按 §9.13「度量先行」纪律，
用**审计中实际发现的 A 盲区**（dvna 4 处 + VFlask 3 处，均为 manifest 标注的真
漏洞）做独立验证——初测仅 **2/7**。缺口与修复如下。

#### 9.16.1 四处缺口与修复

| # | 缺口 | 根因 | 修复 |
|---|---|---|---|
| 1 | dvna L144/L145 IDOR（与 L107 同形） | `per_category_cap=2` 直接**丢弃**超限位置：3 处 IDOR 只提醒前 2 处，漏的正是真漏洞 | cap 改为限制**条目数**而非位置数：超限位置并入代表条目的 `extra_lines`（prompt 里"同类另见 Lx/Ly"，条目数不变不稀释注意力）；`build_review_context` 按 `all_lines` 提取片段（不丢覆盖） |
| 2 | VFlask L208/L231 IDOR | 变量流只做 **1 跳**：`content = request.json` 污染的是 `content`，而 sink 用的是 `customer_id`（2 跳派生） | 加传播闭包 `_PROPAGATE_RE` + `TTAINT_PROPAGATION_HOPS=2`（迭代至不动点）；更深链仍属 TaintTracker/模型职责 |
| 3 | VFlask L231（路由参数形态） | 输入源只认 `request.*`，不认 **URL 路径变量**：`@app.route('/get/<cust_id>')` → `get_customer(cust_id)` 整链 0 提醒 | 加 `_ROUTE_PARAM_RE`（Flask `<x>` / Django `<c:x>` / Express `:x` / Spring `{x}`，均为官方文档标准路由语法）；只在路由装饰器行内匹配，非路由上下文的 `<div>` 不误伤 |
| 4 | layout.html L5 CWE-311、appHandler L207 CWE-200 | 规则表无明文传输类；无"无过滤批量查询"信息暴露形态 | 补 2 条低优先级规则（`http://` 明文引用 priority 2、`findAll()` 无过滤 priority 3） |

#### 9.16.2 伴生缺陷：定向复核在短文件上"名存实亡"

补规则后做泛化验证，发现 `build_review_context` 在短文件/压缩产物上**反而比
原文更长**（dvna `config/server.js` **131%**、`jquery.min.js` **100.1%**）——
window 片段互相重叠合并≈整文件，还多出行号前缀。此时"定向复核"已无省时意义，
却仍承担片段拼接与行号映射的失真风险。

修复：加**收益闸门** `MIN_SAVING_RATIO = 0.6`——片段占原文 60% 以上时返回
`None`，调用方回退整文件（`two_stage_scanner` 已是 `ctx if ctx else code`，
文件本就小时全量复核并不贵）。

| | 改动前 | 改动后 |
|---|---|---|
| dvna 平均压缩率 | 81.1% | **37.1%** |
| VFlask 平均压缩率 | 56.9% | **22.6%** |
| 片段 >50% 原文的文件 | dvna 3/5、VFlask 5/7 | **0 / 0** |

（注：闸门按**字符**占比判定——自检用例曾因填充行过短，出现"覆盖 49% 行数却
折算成 66% 字符"被正确挡下，已改用真实长度样本。）

#### 9.16.3 验证

| 关 | 结果 |
|---|---|
| 独立集（真实审计盲区 7 处） | **定位 7/7、模型可见 7/7**（`all_lines` ±2 容差 + 片段/整文件回退双通道确认） |
| 模块自检 | **12/12 全过**（新增 4 组：二跳传播、路由参数、同类超限不丢位置、收益闸门） |
| 措辞纪律 | 23/23 条全部含"请确认"、无定性词（新增 2 条同样合规） |
| 泛化（两仓 22 文件全扫） | 提醒未泛滥：仅 5 个文件盲区≥3，第三方压缩 JS 由收益闸门自然回退 |
| 回归 | 冒烟 PASS=9 FAIL=0；prefilter 87 段 strict_acc 0.9434 / recall 0.7377 / FP=0 持平；dvna OK 5、VFlask OK 13 无回退 |

#### 9.16.4 口径说明

盲区提醒**不产生 finding、不影响 `has_vulnerability`**（模块三硬约束），故上表
的 7/7 是"模型能看到几处"，**不等于**召回提升——模型是否据此判真需第 5 步
LLM 跑批对账才能证实。盲区的价值在于把"静默漏报"变成"显式提示"，与
`suppressed_by_registry` / `dropped_unowned` / `BudgetPlan.uncovered` 同一消除
静默性原则。

---

### 9.17 risk_budget 预算调度独立验证（2026-08-31）

用户实现的 `graduation_project/risk_budget.py`（文件风险打分 + 预算分配，
已接线 `github_scan` 与 CLI 批量路径）此前只有模块自检（自出题）。本轮按
§9.13「度量先行」纪律做独立验证：**用有标准答案的数据集，在同等预算下对比
「旧：walk 顺序截断」vs「新：风险调度」能否保住漏洞文件**。

实验脚本（可复用）：`experiments/exp_08_repo_benchmark/eval_risk_budget.py`
（三数据集 × 7 档预算 + **随机顺序截断期望**基线——87 段文件名字母序恰好把
vuln 密集的 hard_* 排最前，直接对比旧策略会高估它，必须以随机为公平底线）。

#### 9.17.1 结果

| 数据集（GT 数） | 发现 |
|---|---|
| dvna（GT 2） | GT 排名 **#0 / #3**（14 文件）；预算≥5 全覆盖；预算=3 时新策略以 `server.js` 换出 `appHandler`——**非实质回退**：server.js 的硬编码凭证是 semgrep 审计中确认过的真实漏洞（L24 形态核验通过），只是 manifest 审计范围未收录（GT 完整性假象） |
| VFlask（GT 2） | GT 排名 **#1 / #2**（9 文件）；全预算档全覆盖，零回退 |
| exp04_87（GT 61） | 新策略 ≈ 随机基线（@10: 7 vs 7.2；@20: 15 vs 14.2；@50: 36 vs 35.1）；旧 walk 顺序（9/18/25）系字母序运气，非代表性 |

#### 9.17.2 87 段 ≈ 随机是**预期内**的（但暴露了一个真缺口）

87 段的 26 个安全对照**按设计就长得危险**（参数化查询/shlex.quote/autoescape
——有 sink、有入口、有输入，但已缓解）。存在性打分**原理上分不开"漏洞"与
"缓解了的漏洞形态"**——那是 prefilter/LLM 的职责（漏洞中位排名 44 vs 安全
32.5，前 20 名混入 9 个安全文件）。真实仓库里绝大多数文件是 boring 的
（DTO/常量/UI），打分器的本职是分离"值得看/不值得看"，该集不含 boring 文件，
测不出这项价值。**不要用 87 段的 precision@N 评价风险调度**。

但归因过程暴露了一个真缺口：**纯硬编码凭证文件对调度器不可见**——
`typical_06_secret.py`（CWE-798，无 sink/入口/输入）排名 **86/87**。真实仓库
里这类文件往往很"安静"，预算紧张时 CWE-798 整类被饿死。

**修复**（语言级事实，非样本拟合）：`_SECRET_HINT_RE`——凭证语义标识符
（secret/password/api_key/token/credential…）**赋值为非空字符串字面量**。
env/配置读取（`os.getenv`/`process.env`）与空值是标准安全写法，天然不命中
（右侧须以引号开头）；`==` 比较用 `(?<![=!<>])=(?!=)` 排除。定位是**弱风险
提示**（W=4/处，cap 2，只影响预算排序，不产生判定）。

| 验证 | 结果 |
|---|---|
| 87 段副作用 | **13 个漏洞文件正确提权，0 个安全文件误提**（safe_13 的 `csrf_token = secrets.token_hex()` 为函数调用不命中——字面量要求即精度守卫） |
| typical_06_secret | 排名 86→84、score 3.0→7.0（仍靠后：该文件仅此一个信号，如实记录） |
| 87 段覆盖 | @8/15/20/50 由 6/10/11/35 → **7/10/15/36** |
| dvna | server.js（真实凭证）按语义上浮——预算=3 的换位即来源于此，见上表归因 |
| 模块自检 | 10/10（新增凭证提示 2 组：字面量提权/env/空值/比较不误计） |
| 编译 | CLI 与后端入口 py_compile 通过 |

#### 9.17.3 结论与边界

**结论：优化保留**。真实仓库上 GT 稳定进头部、全预算档无实质回退、uncovered
显式回报与折叠闸门设计合理（高危文件永不折叠）；补充凭证提示后 CWE-798 类
"安静文件"不再被系统性饿死。

**边界（记档）**：
- 打分对"缓解了的漏洞形态"无分辨力（原理性，87 段 ≈ 随机的根因）——预算的
  价值在真实仓库的"interesting vs boring"分离，勿用对抗集 precision@N 评价；
- `typical_06_secret` 类纯凭证文件仍排中后段（单信号天花板）；若要更高优先级
  需把"凭证字面量"升为独立档位——本轮不做（避免为设计集调权重）；
- manifest GT 不完整时（如 dvna server.js），"新策略换出 GT 文件"可能恰是
  正确行为——用 GT 覆盖率评价预算调度须先核对 GT 完整性；
- 折叠闸门 `FOLD_MAX_RISK_SCORE=0.0` 依赖"分数<0 才折叠"，W_PATH_LOW 调权
  时需联动复核。

### 9.18 exp_01 14 段首轮审计：semgrep 并发竞态 + 审计器映射缺口（2026-08-31）

> 数据面背景：exp_01_basic_scan 14 段（py/js/java/php 基础形态 + 2 safe 对照）
> 是 §9.10 盘点后**最后一个进入审计循环的既有数据面**。走 skill 全流程：
> 逐行实读建 manifest（exp_08_repo_benchmark/manifest_exp01.json）→ 纯工具审计
> → 修复 → 复测。全程与 87 段 LLM 跑批**并发**执行（审计零 LLM，不占 GPU）。

#### 9.18.1 首轮结果与两个缺陷

首轮审计：13 OK + 1 B（hardcoded_secret_02.java）+ **0 A 盲区 + 0 C 噪声 +
safe 两段零误报**——第六波后的工具层在这套基础形态集上覆盖完整。两个缺陷：

| # | 缺陷 | 根因 | 修复 |
|---|---|---|---|
| 1 | hardcoded_secret_02.java 判 B | detect-secrets 的 rule_id 是**插件 type 名**（Secret Keyword / AWS Access Key / Hex High Entropy String…），审计器 `_SEMANTIC_TO_CWE` 无映射 → 类型正确被判 B（§9.8 同型：测量工具先于引擎——detect-secrets 修复绝对路径缺陷后首次产出候选，随即暴露） | 映射表补 7 个 secret 族 type 名 → B 转 OK |
| 2 | **semgrep 并发竞态**：semgrep-core 偶发 exit 2（"Error while matching"），失败模式 results=0 + errors=1（整体崩） | 多进程并发（exp_01 审计 × 87 段 LLM 跑批同机）争抢 semgrep 内部缓存/临时目录。崩溃率与并发强度正相关：独跑 0%、与跑批并发约 40%（dump 期间 29 次/87 段）；跑批日志同现 16 次 | `_semgrep_execute_cached` 对 errors 非空的执行**重试 1 次**（0.3s 退避）；无 errors 的正常空结果不重试（防双倍耗时） |

**竞态的实际损失量化（修复前）**：跑批 16 次报错仅 typical_35 丢 1 条候选
（semgrep 的 XSS 弱证据，静态审计本判 B 错标，两条 taint 主票完整、终判不受
影响）——损耗被多工具冗余兜住，但机制上"偶发整文件 semgrep 全空 + 零留痕"
不可接受。留痕缺口：errors 分支此前不写 `last_status`，已补（errors_retry:N）。

**重试验证**：修复后 dump（与跑批并发，29 次报错）→ 87 段四项指标与 14:49
基线**逐样本零差异**（总候选 132 / 零召回 15 / 零召回×真 3 / 安全样本候选 17），
29 次竞态全部被重试兜住；exp_01 复测 **14/14 全 OK**；冒烟 10 PASS。

#### 9.18.2 exp_01 的审计结论（对比其他数据面的定位）

- 14 段覆盖 6 类基础形态（SQLi/XSS/CmdI/PathTrav/798/502）× 4 语言 + 2 安全对照，
  **无官方答案**（合成教学样本），manifest 按权威 CWE 定义逐行标注（findings 级）。
- 与 87 段的分工：87 段是"难样本 + 多漏洞共现"集，exp_01 是"教科书形态"集——
  后者零 A 盲区说明第六波后的规则库对**入门形态**已全覆盖；真正的剩余缺口
  （缺失型/框架级/跨文件）集中在 §五之五 与 §9.9.4 清单。
- PHP 第一样本（xss_01）曾因竞态掉成 A 盲区——修复重试后恢复。**PHP 的召回
  面仍薄**（本批仅 1 段 XSS；echo 直出形态 prefilter 不认，靠 semgrep registry），
  php-goof 审计（未跑）是下一个 PHP 验证场。

#### 9.18.3 方法论

1. **并发是新的故障注入器**：同机多进程跑 semgrep 时崩溃率 0%→40%，此前的
   "工具稳不稳"结论全部建立在独跑之上。P2-9 留痕（errors_retry 状态）+ 重试
   是并发场景的基本卫生；涉及外部工具的并行评估/审计应默认假设竞态存在。
2. **审计全程零 LLM 的价值再次兑现**：与 GPU 跑批完全并行，CPU 空闲时段的
   数据面清欠不与算力任务冲突。

### 9.19 php-goof 首轮审计：PHP 仓库形态首发，3 条盲区全为版本/间接源边界（2026-08-31）

§9.18.2 预告的"PHP 验证场"兑现。对象 `snyk-labs/php-goof`（Snyk 官方 PHP 漏洞演示应用，
8 个 PHP 文件，`exploits/` 下 2 个载荷字体文件按纪律排除审计域外）。manifest
（`manifest_php-goof.json`）逐行实读 + 官方 readme 漏洞演示映射
（SNYK-PHP-LEAGUECOMMONMARK-174004 / SNYK-PHP-PHPMAILERPHPMAILER-1311001 /
SNYK-PHP-DOMPDFDOMPDF-2428942），composer.lock 核对 dompdf v1.2.0 /
league/commonmark 0.18.2 / phpmailer v6.4.1 与演示版本一致。

**结果（零 LLM 审计，`stage1_audit.php-goof.all.md`）：OK 5 · A 盲区 3 · B 0**。
7 条 expected 命中 5：

| 发现 | 覆盖 | 工具/链路 |
|---|---|---|
| func.php L13 SQLi | ✓ | semgrep |
| tasks.php L11 / L27 SQLi（UPDATE/DELETE） | ✓ | semgrep（L13 缓解形态与 L11 去重合并） |
| index.php L39 反射 XSS | ✓ | semgrep |
| db.php L4 硬编码口令 | ✓ | detect-secrets `Secret Keyword` → CWE-798 语义映射首次在 PHP 验证 |
| index.php L65 / pdf.php L39 / mail.php L19 | **A 盲区** | 见下，逐条定性 |

**A 盲区逐条定性（三条全部不修——泛化三关不过，属结构性边界而非规则缺失）**：

1. **index.php L65 CommonMark XSS**：`echo $converter->convertToHtml(urldecode($row['title']))`。
   source 是 **DB 间接源**（`$row[...]`），PHP source 模型只认超全局数组——把 DB 行
   读值纳为 source 会让一切 PHP 数据库应用误报爆炸；且利用性依赖 commonmark
   0.18.2 的 unsafe-link 实体绕过（新版 `html_input=escape` 默认安全），版本敏感。
   → 数据流分析/SCA 域，行级形态工具不追。
2. **pdf.php L39 dompdf RCE**：`$dompdf->loadHtml($html)`（L30 用户输入拼接 +
   L10 `setIsRemoteEnabled(true)`）。`loadHtml(` 撞 **DOMDocument::loadHtml**
   （XML 解析语义，相关 CWE 是 611）——同调用名双语义，加 sink 必在 DOMDocument
   场景制造 B 类错标（§9.16 JS `exec(`/`render(`/`.save(` 同型教训）。
   → 配置组合 + 版本敏感 + 双语义，不修。
3. **mail.php L19 PHPMailer validateAddress**：phpmailer 6.4.1 的
   `validateAddress` 缺省回调 `'PHP'` 是**版本特有行为**；修复版及一切正常应用
   中它是最常见的邮箱校验调用，加 sink 误报极高。
   → SCA 域（依赖版本感知），应用侧无稳定静态形态。

**零代码修复 → 候选集合不动 → fixed5 基线免回归**（132/15/3/17 口径不变）。

**PHP 召回面结论更新（对 §9.18.2 "PHP 召回面仍薄"的回应）**：教科书 SQLi/XSS/798
形态已全覆盖（含 PDO/mysqli OO 与过程式双形态、反射与存储两种 XSS 出口），剩余
盲区全部是"版本敏感 + DB 间接源/双语义"类——**PHP 无需第七波补规则**，规则库
在该语言上的下一层缺口已从"形态规则"升维到"数据流/版本感知"架构能力。

**对账口径两条**：
- exploit 载荷文件（gotcha_font.php 内嵌 `<?php phpinfo(); ?>`）的 semgrep
  `phpinfo-use` 告警被无主告警剔除 → 0 候选，与"排除域外"预期一致（剔除规则
  对载荷文件反而正确）。
- tasks.php L13（INSERT `$title`，入库前经 urlencode 编码引号）按标注纪律
  "框架/标准库默认缓解写 notes 不进 expected"处理——semgrep 果然照报
  （拼接进 SQL 就报，宁可信其有口径），因与 expected L11 同类型同文件去重合并，
  未计 B/C，口径无扰动。"缓解写 notes"的反向价值首次实测。

### 9.20 NodeGoat 首轮审计 → 第七波修复：cookie 映射缺口 + $where/needle/autoescape 三规则 + sink 行号锚定（2026-08-31）

对象 `OWASP/NodeGoat`（OWASP 官方 Node.js 教学库，审计域 26 文件 = 24 服务端 JS +
2 个用户输入渲染视图；assets/vendor、test/、Gruntfile 排除域外）。manifest
（`manifest_nodegoat.json`）逐行实读 + 代码内官方 "Fix for Ax" 注释块逐条核对，
24 条 expected（覆盖 A1-1 SSJS eval / A1-2 NoSQL $where / A1-3 Log Injection /
A2 明文口令与弱策略 / A3 autoescape:false / A4 IDOR / A5-A8 配置注释 /
ReDoS / SSRF）。

#### 9.20.1 首轮 → 修复后对照

首轮 **OK 7 · A 16 · B 1** → 第七波修复后 **OK 13 · A 10 · B 0**（24 条 expected）。
修复四项：

1. **Insecure Cookie 类型承接（首轮 6 条无主告警剔除 → D 类假盲区）**：
   semgrep express-cookie-settings 族（session(...) 缺 httpOnly/secure/domain/
   expires/path 共 6 条精确告警）全部被当无主告警剔除——server.js L78 CWE-1004
   的"盲区"实为命中后丢弃（§9.18 同构：不是工具没命中，是管线把它扔了）。
   修复三表联动：`_infer_taint_type` 加 cookie 分支（rule_id 特有片段
   no-httponly/no-secure/cookie-settings 专属性强无撞词）→
   `_STANDARD_TAINT_TYPES` 加 "Insecure Cookie" → 审计器 `_SEMANTIC_TO_CWE`
   加 `"insecure cookie": "1004|614"`（no-secure 精确分类是 614，工具粒度只有
   "缺配置"一档，双编号对齐——§9.8 口径先例）；cwe_normalizer 同步 1004/614。
2. **$where 操作符注入规则（A 盲区 → 真）**：`nosql_where_injection`
   （CWE-943）。MongoDB `$where` 接受 JS 字符串并服务端 eval（官方文档行为），
   同行 AND：`$where` +（模板 `${}` 或字符串拼接）。语言级事实：$where 是
   MongoDB 标准操作符，JS 模板/Python 拼接同形态；常量串不触发。
   **两个教训**：① 块注释剥离必须先行——官方注释掉的修复示例（L64-76 块注释）
   恰好含 $where+插值形态，首版命中注释行 L73 而漏真 sink L78（自检与真实文件
   双重暴露）；② 行内注释剥离对 `/* */` 无效，`_code_wo_comment_lines` 只处理
   整行注释——新行级规则默认先用保行号的块注释替换再逐行判。
3. **needle HTTP 客户端 → SSRF（A 盲区 → 真）**：research.js L16
   `needle.get(req.query.url + req.query.symbol)` 零召回实锤 Node 客户端缺口。
   prefilter `http_client` sink 表加 `needle.(get|post|...)`；taint
   `_SINK_DEFINITIONS` 加 `needle.get(`/`needle.post(`（`_SINK_LANG_ONLY`
   JS 专有；SSRF 已有 `_SINK_RANK=3` 免登记）。
4. **模板 autoescape 显式关闭 → XSS（A 盲区 → 真）**：
   `template_autoescape_disabled`（CWE-79）。`autoescape\s*[:=]\s*(false|0)`
   是 swig/jinja2/nunjucks 标准选项的显式禁用（server.js L137 实锤；Python 侧
   `Environment(autoescape=False)` 同形态），True/注释提及不触发。

**附带质量修复——taint sink 行号锚定**：contributions.js 的 eval 候选此前
sink_line 记为 handler 定义行 L28（箭头函数整体是一条语句，`stmt.start` 在
L28，eval 在 L32，注释行隔开 → 审计 ±2 外判 A）。修复：sink 路径的 sink_line
一律取 **sink 调用节点自身行**（含 cp 分支），复合语句/多行调用场景行号精度
普遍提升。taint 自检加"箭头 handler 内 eval"回归用例（期望 L3 非 L1）。
87 段回归证明此修复零扰动（见下）。

**manifest 口径修正（非工具缺陷）**：all.js L9 cryptoKey expected 由 CWE-321
改为父类 798——`Secret Keyword` 工具粒度只到"硬编码凭证"，321 是 798 子类，
B 转 OK（粒度对齐，不是错标）。

#### 9.20.2 剩余 10 条 A 盲区定性（全部结构性边界，零代码修复）

| 形态 | 为什么不修 |
|---|---|
| server.js L145 http 明文服务 | 部署形态相关（反代/TLS 终结是主流），静态判定必高误报 |
| profile-dao L62 ssn / user-dao L25 password 明文落库 | 敏感字段赋值→持久化是数据流语义，行级规则会误伤一切 `x.ssn = y` |
| allocations.js L23 IDOR（CWE-639） | 授权类结构性盲区（VFlask 同款，§9.6 已定性） |
| profile.js L59 ReDoS 嵌套量词 | 需对正则字面量做正则分析（新能力域），列为未来规则机会 |
| profile.js L65 render 回传 body 值 XSS | 渲染数据流泛形态，每处 res.render 都会命中，噪声不可控 |
| session.js L64 console.log 日志注入 | `console.` 被全局排除（浏览器端无 CWE-117 语义）；Node 后端 console.log 恰是服务端日志——**运行时双语义**，正则层不可判，与 LSP/require 上下文分析才有解 |
| session.js L144 弱口令正则 | 需对正则质量做语义评判（.{1,20} 是否过弱），非形态匹配 |
| views ×2（swig `{{ }}`） | 模板层语法 JS 工具链不解析——**模板层=当前工具域外**，与 vendor 同级豁免可写入后续 manifest 纪律 |

#### 9.20.3 回归与泛化验证

- 87 段全量静态回归（`stage1_candidates.20260831_144901.json`，第六波终态；
  190511 中间版已被工作区清理，四项指标与其完全一致）：总候选 132 /
  零召回 15 / 零召回×真 3（清单一致）/ 安全样本候选 17——**四项与基线逐项零
  差异，零新增误报**（$where/needle/autoescape 形态在 87 段中不存在，第七波
  是纯新增覆盖面，且 sink_line 锚定修复未改变任何样本的候选集合）。
- 模块自检：prefilter / taint_tracker / two_stage_scanner / cwe_normalizer
  全部通过（新增 8 条用例）；冒烟 10 PASS / 0 FAIL；后端可导入。
- 三关自检：$where=MongoDB 标准操作符（语言级事实✓）· $where+插值同行 AND
  （结构特征非拼写✓）· pymongo JS/Python 双形态（多语言变体✓）。needle 与
  axios 同族论证（§9.15）；autoescape 为引擎标准选项名（跨语言✓）。

#### 9.21.5 门槛修复后的第二轮重跑（rerun2）：正反两面与问题归位

重跑（`exp_07_full87.local_alpha05_rerun2.20260831.json`）验证门槛修复：

| 指标 | 门槛前（rerun1） | 门槛后（rerun2） |
|---|---|---|
| 判定 | TP56 TN20 FP1 复核10 | TP52 TN23 **FP2** FN0 复核10（真9/安1） |
| strict hit | 77.2%（44/57） | **81.5%（44/54）** |
| 修复的旧 miss | — | hard_owasp_01（F9 主案例）/ typical_18 / typical_23 |
| 兜底判真 | 3 | 4（**cve_03 兜底判 true/22 strict hit——设计内路径首次完整兑现**） |
| FP | 1 | 2（crossfile_03_input 回归，§8.6 标注争议段非新回归） |

**复核构成大变（真漏洞 5→9）的机制**：secret 弱值转裁决档后与 B105 归并成
"bandit+detect-secrets"双工具候选 → 多工具一致证据让模型对测试弱密码从
0:3 否决转为 2:1 判真（§五之三 正反面）→ 两种走向：
- typical_14/16/bypass_05：判真 → **798 抢占回归**（§8.5 原始形态，来源从
  直出特权变成归并加成）；
- typical_15/25/27/29/31/13/21：全否决 → 转复核（recall 1.0 由复核兜底，
  生产上 9 个真样本转人工 = 用户成本）。

**典型_32 从幻觉组合（"CWE-77 认证"）收敛为 917 近邻错**——F9/F10 教师
锚尚未训练，漂移方向的收敛属随机；v2_15 素材已入池（deferred_queue §3.5）。

**结论：门槛修复达成"消除错误来源"（直出特权清零、strict hit +4.3pt），
但把问题推回本来的位置——§8.5/§8.8 授权类候选缺失 + B105 弱值裁决摇摆 +
伴生 798 抢占。P2 `missing_authz_suspect`（§8.8）的紧迫性升级：现在的
起点是干净的（无直出干扰），主候选供给到位后 strict hit 的 798/授权段
才有解。**

#### 9.21.5a Prompt CWE 编号锚（用户查证驱动，A/B 进行中）

用户核查裁决 prompt 实现发现 F9 的另一半根因在 prompt 工程（不只在蒸馏）：
`build_triage_prompt` 类型行只给语义名（"Prototype Pollution"），**不给编号**，
且明确指令"vulnerability_type 必须来自你自己的分析"——模型须自行完成
语义名→编号映射，映射到近邻（917/441/862）正是 rerun2 的 miss 形态；更关键：
`2. 漏洞类型独立判定` 条目的示例文本 *"如鉴权缺失是 CWE-862，不是工具标的
类型"* **直接教模型偏离工具标注输出 862**——typical_22（期望 352）输 862
可能不是概念混淆而是被示例引导。

**修复（prompts.py，四处收口）**：
1. 类型行注入编号锚：`normalize_cwe_label(taint_type)` 提取标准分类
   （"Prototype Pollution" → "标准分类 CWE-1321"），裸规则号（B608）无映射
   则不加锚；
2. 解绑指令改为"**vulnerability_type 须与所确认候选的漏洞语义一致**；如你的
   分析指向不同类型，请给出判断依据"（保留反锚定空间，counterfactual/
   conformal 不受影响）；
3. 两分支的"漏洞类型独立判定"条目与两处 JSON schema 字段说明同步收口
   （删除 862 反例文本，改为"不得照抄工具标注，也不得输出与候选语义无关的
   类型"）；
4. 自检信任分级用例断言更新（"标准分类 CWE-89" in p_taint——SQL Injection
   语义名的锚生效验证）。

自检全过、冒烟 10 PASS。**A/B 设计**：A 组（编号锚）跑 miss 10 段 + 对照 4 段
（typical_01/06/24/23——已 strict hit 且类型行带编号，验证锚不伤已对样本），
B 组 = rerun2 现有数据。若 A 组编号级 miss（917/441/862）消失且对照组不回退，
则"训练层"再切掉一半，v2_15 辨析组预算集中到真正的家族混淆（352-vs-862 等）。#### 9.21.5b 编号锚 A/B 结果：修复 5/10 miss，编号级错误全灭（2026-09-01）

A 组（编号锚，`ab_cwe_anchor.groupA.20260831.json`）vs B 组（rerun2）：

| 样本 | B（无锚） | A（锚） | 判定 |
|---|---|---|---|
| typical_32 | "CWE-917"（幻觉近邻） | **CWE-1321 全称**（与工具标注逐字一致） | **修好** |
| bypass_08 | "CWE-441 Unintentional Proxy" | **CWE-347**（正确编号） | **修好** |
| typical_33 | "CWE-862 Missing Authorization" | **CWE-843 Type Confusion** | **修好** |
| bypass_05 | 798 抢占 | **CWE-352**（正确主类型，模型基于 same_origin 绕过自证） | **修好** |
| typical_14 | 798 抢占 | **79**（期望双标注 639;79 命中） | **修好** |
| crossfile_01/03_input | 判真（FP） | review | FP→转人工（改善） |
| typical_16 / typical_22 | 798 抢占 | 798 抢占（B105 归并候选判真） | 仍 miss → §8.8 |
| typical_20 | 918 | 918 | 仍 miss → 标注层 |
| 对照 typical_01/06/23 | true+hit | true+hit | 无回退 |
| 对照 typical_24 | true 3:0 | review 1:2 → **复跑×2 均 3:0 true** | 采样方差，非锚伤害 |

**结论**：编号级映射错误（917/441/862）在锚下**全灭**——用户查证"模型从未见过
编号"的判断完全成立，F9 的 prompt 侧根因修复兑现。10 段 miss：修 5、转 review 2
（FP 改善）、仍 miss 3（2 段归 §8.8、1 段归标注层）。对照 4 段中 typical_24 的
review 为 N=3 采样方差（锚组态复跑×2 均 3:0 恢复 true），非锚伤害。

**strict hit 推算**：87 段口径 44→49/54 ≈ **90.7%**（超 08-30 基线 88.2%）。
"训练层独占"的 3 段（32/33/bypass_08）被 prompt 工程收复——v2_15 辨析组预算
集中到：352-vs-862 家族混淆（typical_22 在锚下仍被 B105 归并票压过）、
1321 之外的新锚需求消除、§8.8 授权候选（typical_16/22 的 798 抢占）。

**遗留决策**：锚已默认生效（prompts.py 全局）。N=3 抖动（typical_24 型）的
系统性治理（N=5 或温度 0.3，§8.7 待办）仍挂起待算力。

#### 9.21.6 温度与投票多样性：降温度不是过拟合，但确有代价（2026-09-01）

用户提问："温度降低会不会导致泛化性能差、出现类似过拟合？"——**方向对、机制
需要澄清，结论是不降温度**。

**机制澄清**：温度是**纯推理参数，不改任何权重** → 统计学习意义的过拟合
（记忆训练数据、测试集退化）在物理上不可能由温度引起。用户担心的现象有真实
对应物，叫**模式坍缩（mode collapse）**：低温（0.3）使输出分布锐化、趋近贪心
解码 → 模型行为收敛到"训练数据中最常见的高频叙事"；高温（0.7）保留低概率
token 的采样机会 → 少数派但正确的判断有机会出现。**这正是"像过拟合"的行为层
表现：过度贴合训练主导模式。**

**本项目对低温特别敏感的三条实证**：

1. **代码已有设计意图**（two_stage_scanner L2031-2034）：多票采样路径强制
   `temperature=max(self.temperature, 0.7)`——即使配置 0.3 也走 0.7，注释明写
   "多票采样需要足够温度打破同模态重复"。这是 08-15 的既有修复，防止投票退化
   成三张相同的票。
2. **分歧率是信息源**（实测票型分布）：rerun2 全量 **44.5%**、A 组 **53.8%**
   的候选票型含分歧（非 3:0/0:3）。这些分歧**正是正确判断的来源**——
   bypass_05 的修好机制就是 `xss候选 2:1 改判 352`：两票偏离工具标注、输出
   正确但低频的 352。**若温度压到 0.3，这类少数派判断的出现率显著下降**。
3. **自一致率失去区分度**：三次采样恒一致 → confidence 恒 1.0 → conformal
   校准与复核判定依赖的不确定性信号被摧毁。

**结论**：降温度的**风险 > 收益**。收益仅"缓解 typical_24 型采样方差"，
而 N=5 能在**不损失多样性**的前提下解决同一问题；代价是独立票比例下降
（corrected_type 的信息源）+ 低频正确判断（352/384/1321 家族，恰是当前 miss）
出现率下降。
→ **推荐顺序：N=5（保多样性、加票数）> 降温度（牺牲多样性换稳定）> 不动。**

#### 9.21.7 标签治理决策：typical_20 补标 CWE-918（2026-09-01）

§8.1 的待决项落定。源码复核（L9 `request.args.get("url")` → L10
`requests.get(url, verify=False)`，**无 scheme/host 白名单**）——标准 SSRF
proxy 形态，918 客观成立，与 295 是同两行代码的两个缺陷侧面而非工具误标。

manifest 改为 `expected_cwe: "CWE-295;CWE-918"`（多标注 `;` 分隔，命中任一即
strict hit），并写入 `expected_cwe_note` 记录决策依据（防后续再议）。

**效果**：模型输出 `CWE-918 SSRF` 在补标后 strict hit 成立（此前被判 miss 的
原因是模型按危害可达性选 918 属**正确行为**，F7 工程侧无解）。

**全量推演（rerun2 基线 44/54 = 81.5%，脚本重算口径 45/54 = 83.3%）**：
+ 编号锚修复 5 段 → 50/54 = **92.6%**；再 + 补标 typical_20 → 51/54 = **94.4%**
（对照 08-30 基线 88.2%）。**注：锚的 5 段修复来自 14 段子集 A/B，全量数字待
一次完整重跑确认（子集平均耗时更短、GPU 状态不同，可能引入偏差）。**

#### 9.21.8 §8.8 授权候选：口径修正后 87 段零 FP，但独立集不通过（2026-09-01）

用户定调"遇到的局限都尽力修复"→ 重开 §8.8。先修正我自己此前错判的口径。

**此前的错误**：探针用 `return ` 当"敏感操作" → 宽口径 57 FP、窄口径 0 TP，
据此建议不实施。**那是口径错误，不是形态不存在**（与 §9.16.4 的 PHP 教训同型：
我一度因样例构造问题把整语言判为失效）。

**正确形态**（源码实读 3 个授权类样本后提取）：
- **352/862/306**：路由路径或函数名含**资源语义动词**（/transfer、/admin/delete_user…）
  + HTTP 写方法（POST/PUT/DELETE，RFC 7231）+ 全文件无 CSRF/权限校验特征
- **384**：`/login` 路由 + session 赋值 + 无 `session.clear()/regenerate`（Flask
  官方会话固定防护写法）

87 段实测（69 个 handler 文件）：

| 形态 | 授权类 TP | 其它漏洞段 | **安全段 FP** |
|---|---|---|---|
| 路由语义动词 + 写方法 + 无 CSRF | 2（typical_22 的 352、typical_13 的 306） | 3 | **0** |
| /login + session 赋值 + 无 regen | 1（typical_16 的 384） | 0 | **0** |

**但独立集验证不通过**（4 个仓库 122 个文件，DVNA/VFlask/NodeGoat/php-goof）：
**敏感路由命中 0**——真实仓库的路由命名是 `/login` `/signup` `/resetpw`
`/profile` `/useredit` `/benefits`，**无一条含 /transfer、/delete、/admin 类
动词**。即该形态建立在 87 段教学样本的命名习惯上，泛化三关之三（独立集验证）
不成立——在 87 段上"零 FP"只是因为命名分布恰好。

→ **不实施**（与 §9.19 php-goof 的三条 A 盲区同判：结构性边界而非规则缺失）。
typical_16/22 的 798 抢占**留给数据层**：另一端正在修数据层，模型需在"只有
伴生凭证候选"时具备归因能力（这正是 v2_15 蒸馏锚"伴生凭证 vs 主漏洞"要覆盖
的形态，deferred_queue §3.5 已登记）。

#### 9.21.4 方法论

1. **"无主告警剔除"日志是 D 类假盲区的首选证据源**：首轮审计的 server.js L78
   "零候选"与剔除日志里的 express-cookie 6 条直接对上——审计时先看剔除留痕
   （`stage1.dropped_unowned`）再定性 A，能省一轮错误归因。
2. **注释块是教学仓库的陷阱**：官方把"修复代码"注释在旁边（NodeGoat 风格），
   形态与漏洞完全一致——行级规则必须默认剥块注释（保行号占位），否则命中
   示例而非真 sink。这条对 DVWA/NodeGoat 类带修复注释的仓库是通用前提。
3. **审计器自身是第一嫌疑**：本轮 5 项修复中 2 项是测量层（_SEMANTIC_TO_CWE
   缺口、manifest 粒度口径），与 §9.8/§9.18 的"测量工具先于引擎"三连——
   A 盲区定性顺序固定为：剔除留痕 → 审计器映射 → 引擎规则。

### 9.21 生产组态全量重跑对账 + secret 直出门槛的通道漏洞（2026-08-31）

> 背景：第六波（§9.16）+ §9.17/9.18 修复全部落地后，按"完全对齐 APP"的组态
> 重跑 87 段 LLM（transformers / triage_train_aligned / num_ctx 6144 / N=3 /
> full_recheck，base 环境 ROCm——§9.7 "远程算力"表述更正：就是本机）。
> 逐项组态核对表见对账记录；两处口径保持与 08-30 一致（共形不加载生产文件、
> signal_feedback 隔离注册表）。

#### 9.21.1 重跑对账：兜底闭环达成

| 指标 | 08-30 全量 | **本轮（第六波工具层后）** | 解读 |
|---|---|---|---|
| 判定 | TP59 TN21 FP1 复核6 | TP56 TN20 **FP1** 复核10 | FP 仍为 1 且同一样本（crossfile_01_input/943） |
| strict recall | 1.0 | **1.0**（FN=0） | 保持 |
| **兜底判真（tools=llm）** | **12** | **3** | **-75%，"工具层为 LLM 减负"闭环**：剩余 3 段全部是"不修清单"成员（spring4shell 框架版 / crossfile 架构级 ×2） |
| 兜底判真占比 | 20%（12/60） | **5.3%（3/57）** | 论文核心叙事数据 |

#### 9.21.2 类型层回退的根因：secret 直出档的通道漏洞

strict hit 77.2%（44/57），miss 13 段归因：**secret 抢占 ×5**（detect-secrets
副作用）+ 共现/伴生 ×2 + 纯裁决漂移 ×6（→ v2_15 反例池 §3.5）。

**抢占机制（票型实锤）**：detect-secrets 绝对路径缺陷修复后（§9.16.1）首次
大量产出，其候选 `category="secret"` → **命中 `_is_direct_category` 直出档
（1:0，免 LLM）→ 完全绕过凭证强度门槛**。门槛（夜间修复 #3）只接了 sast
通道（B105 经转档判定）；同一个测试弱密码 `admin123`，bandit 看到要过门槛
（0:3 否决），detect-secrets 看到直接直出——**门槛语义按工具分叉，按内容
才是对的**。八个月前 B1 的"注释里的自我实现预言"在此的变体：门槛的正当性
建立在"B105 会命中弱值"上，而 secret 工具通道从设计起就没进门槛。

**修复（门槛统一 + 证据增强）**：
1. runner 层：gitleaks message 附 `Match` 命中行原文；detect-secrets 按行号
   读源文件附命中行（其 JSON 无命中文本）。此前 secret 候选 evidence 只有
   "检测到疑似密钥: <type>"——门槛取不到值、模型没材料，双重缺陷。
2. two_stage 层：`_drop_irrelevant_positional` 对 **category=secret 一律过
   `_is_strong_credential`**：过 → 保持直出 + 类型规范化 Hardcoded
   Credentials（裸 "Secret Keyword" 进 top1 无法归因 CWE）；不过 → category
   转 sast 裁决档（与 B105 弱值完全对称）交模型。
3. 门槛函数补**裸值兜底**：gitleaks 的 Match 常无引号（`AKIAIOSFODNN7EXAMPLE`
   裸值）→ 引号提取恒失败 → 真凭证误判弱（typical_06 实锤）。兜底：≥20 位
   连续密钥形态 token（AKIA/hex/base64 共同形态）判真。

**验证**：自检 #26（弱值→sast 裁决档 / 真凭证→直出，对称性）；门槛五场景
（AKIA 裸值/引号弱值/引号真值/无值/hex 裸值）全过；冒烟 10 PASS；87 段静态
回归——总候选 132→124（-8 全部是"同凭证 B105+detect-secrets 归并成一条双
工具候选"的**去重改善**），零召回 15 / 零召回×真 3 / **安全样本候选 17 持平**；
真凭证直出 4 段全保留（typical_06/18、bypass_06、typical_33）。

**预期（重跑验证中，`exp_07_full87.local_alpha05_rerun2`）**：5 段抢占消失
→ B105 裁决否决 → 无候选兜底通道恢复 → 模型独立归因主类型（08-30 数据：
287/862/384 三段直接 strict hit）→ strict hit 回升方向 88%。

#### 9.21.3 复核 6 → 10 的构成

新增复核 4 段：safe_03/04（候选面变大后安全样本也出现裁决票）、typical_13、
typical_21。08-30 复核的 typical_09（PHP 入口正则修复兑现 §8.3）、longfile_01
本轮直接判真。复核非错误（转人工语义），但 secret 门槛修复后应回落。

#### 9.21.4 方法论

1. **门槛的完整性=按内容不按通道**。凡"只接了 A 通道的门槛"，B 通道新增
   供给时必然绕过——secret 候选的三条来源（sast 转档 / gitleaks / detect-
   secrets）在修复前只有第一条过门槛。新增数据源接入时，逐条核对它经过的
   每一道既有门。
2. **直出档是绕过 LLM 的特权通道，特权必须配门槛**。1:0 直出的置信度语义
   是"确定性工具自判"，工具判定弱值时（Secret Keyword 对 admin123 响）
   特权就成了抢占的直通车。
3. **对账先钻一个反常点**：strict hit 回退 11 个点没有平均用力，先钻最大的
   miss 簇（Secret Keyword ×5）→ 票型 1:0 → category=secret → 直出分支——
   四步定位到根因，比全面扫描快得多。

### 9.22 指导文档全量核验 + 第八波：盲区层收口（2026-08-31 晚，用户指令驱动）

> 用户指令：① 检查"已优化"是否属实、是否优化到位；② 检查"不可能优化、只能进
> 盲区提醒层"的是否属实；③ 没优化的优化掉。
> **结论先行**：① 已修项全部属实（四层核验，文档数字零勘误）；② "只能进盲区
> 提醒层"的判定**一半不属实**——多数类别在盲区提醒层**没有对应规则**，实测
> 0 提醒，实为"既未修也未提醒"的悬空态；③ 本波把其中有标准形态的 4 类接进
> finding 通道、5 类接进提醒通道，剩余真修不了清单收口为 7 类。

#### 9.22.1 属实性核验：四层证据，全部通过

| 层 | 内容 | 结果 |
|---|---|---|
| 模块自检 | prefilter / taint_tracker / two_stage（含 #21~#26）/ cwe_normalizer / signal_registry / blind_spots / risk_budget | 全过（graproj 环境）|
| 工具冒烟 | `tool_smoke_test.py` | 10 PASS / 0 FAIL / 0 SKIP（与 §9.16.6 一致）|
| 87 段静态回归 | 19:14 dump 复算四项指标 | 总候选 124 / 零召回 15 / 零召回×真 3（清单=不修三成员）/ 安全样本候选 17 条——与 §9.21 终态逐项一致 |
| 代码抽查 | B1（--no-git）/ B2（gitleaks_rules.toml 两规则）/ B3（`_is_secret_class_alert`+`_is_strong_credential` 双向门槛）/ §五之三 prompts 信任分级 / §五之四 `_PROTECTED_RULE_PREFIXES` / §五之六 `_EVIDENCE_CTX_MARK` 剥离 / §9.9.3 类型写回 / §9.12×8 / §9.14×4 / §9.16 P0-1 detect-secrets cwd+basename、P0-2 Java 方法级 source、catch/except/finally 块 / §9.20 四项 / §9.21 secret 门槛统一 | 全部在位 |

**-8 归并逐样本核实**：对比 14:49 与 19:14 两份 dump，8 个变化样本全部是
`bandit` + `detect-secrets` → `bandit+detect-secrets` 的同凭证归并（bypass_05/
bypass_08/crossfile_03_sink/longfile_03/typical_14/15/16/22），无候选丢失——
§9.21.2"去重改善"记载属实。候选≥3 样本数 17→14 为归并伴随效果（3 个样本掉出
≥3 档），非回退。

**LLM 层重跑状态**：rerun1（08-31 19:56 完成的 87 段全量）与 §9.21.1/9.21.2
一致——TP56/TN20/FP1（同 crossfile_01_input）/复核 10/兜底判真 3；**抢占×5
票型实锤**（typical_14/15/16、bypass_05、crossfile_03_sink 的 top1 均为
Secret Keyword）。secret 门槛修复后的 rerun2 仅完成 18/87（typical_01~12 全
strict hit、safe 全判 False，方向健康），**strict hit 回升的完整验证仍未闭合，
待跑完**。

#### 9.22.2 「修不了 → 盲区提醒层」判定复核：一半不属实

核验方法：不引文档原话，用**宣称进入盲区提醒层的真实样本逐个跑
`scan_blind_spots`**（盲区层的独立验证早已证明它能 7/7 提醒 IDOR——前提是
表里有对应规则；实测大量类别没有）：

| 类别（代表样本） | 宣称 | 实测盲区提醒 | 判定 |
|---|---|---|---|
| IDOR（VFlask L208/231、DVNA L11/107/145） | 提醒层接管 | ✓ 7/7 | 属实 |
| 跨文件（crossfile 族） | 架构级 + §六守卫 | ✓ 守卫转复核 | 属实 |
| 授权缺失/会话固定/CSRF（typical_15/16/22、bypass_05） | （隐含提醒层兜底） | **✗ 0 提醒** | **悬空** |
| Spring 框架绑定（hard_cve_05 spring4shell） | 真修不了（正确）| **✗ 0 提醒** | **悬空** |
| NodeGoat：ReDoS L59 / console 日志 L64 / 弱口令 L144 / ssn 落库 L62 / http 明文 L145 / 密码明文 user-dao L25 | 不修 / 未来规则机会 | **✗ 0 提醒** | **悬空，且部分其实能修** |
| php-goof 3 条（CommonMark XSS / dompdf RCE / PHPMailer） | SCA/数据流域不修 | ✗（未宣称接管） | 不修判定维持成立 |
| typical_15 角色/权限缺失 | §8.8 缓期等标签治理 | ✗ | 缓期理由**成立**（"敏感操作"定义未定案，宽口径在 safe_02/17 同形） |

**悬空的根因**：盲区提醒层的规则表建好后，后续审计新发现的"不修"类别**没有
回灌进表**——模块迭代断在最后一公里（与 B1"接入让工具必然零召回"同构：
机制在，接线上有洞）。

#### 9.22.3 第八波落地：4 条 finding 规则 + 5 条盲区提醒

**复核推翻的两个"修不了"论断**（先修度量再修引擎的又一实例）：
- "console.log 运行时双语义，正则层不可判"——**文件级可判**：require/启动 API
  + Express handler 惯用法（`req.session`/`res.render` 只在服务端出现）守卫，
  浏览器端整类豁免；且 nodegoat 全仓"console.非字面量参数"仅 1~2 行，噪声
  担忧不成立（泛形态噪声是 `res.render` 的问题，不是 console 的问题）。
- "ReDoS 需对正则字面量做正则分析（新能力域）"——**嵌套量词是纯结构特征**
  （分组内含量词+分组后紧跟量词），行级正则可判，量词只在字面量跨度内搜索
  （裸算术 `(a+b)*c` 不触发）。

| 通道 | 条目 | 形态依据（泛化三关） |
|---|---|---|
| prefilter | `redos_nested_quantifier`（CWE-1333） | 嵌套量词×动态求用（.test/match/exec）双 AND；正/负样本入自检 |
| prefilter | `log_injection_console`（CWE-117） | `_JS_SERVER_CTX_RE` 文件级门 + 参数区剥字符串后含标识符（共享原语） |
| prefilter | `weak_password_policy_regex`（CWE-521） | pass/pwd 词根标识符 ← `.{1,N}` 任意字符有界量词 |
| prefilter | `cleartext_sensitive_storage_field`（CWE-312） | mongo 持久化上下文×文档持久化调用（排除 cipher.update 伪证）×`obj.敏感字段=裸标识符` 三 AND；password 不入表（safe_11 同形，归提醒层） |
| blind_spots | 会话固定（AUTHORIZATION，3） | 登录态写入会话存储（typical_16 L13 命中） |
| blind_spots | 写方法路由的访问控制/CSRF（AUTHORIZATION，3） | 只认 `methods=['POST'...]`/`@PostMapping` 语言级事实；不收裸 Express `app.post(`（防无差别泛滥） |
| blind_spots | Spring POJO 绑定（FRAMEWORK，3） | `@*Mapping` + 大写类型形参（排除 String/Model 等 18 个标量/框架类型）；spring4shell 命中 |
| blind_spots | 口令明文落库（CRYPTO，2） | password 字段裸赋值/简写属性；已哈希写法（右侧函数调用）豁免；user-dao L25 命中 |
| blind_spots | http 明文服务（CONFIG，2） | `http.createServer(` 与 `https.createServer` 是不同 API 名，无第二语义；server.js L145 命中 |

配套登记：`PREFILTER_RULE_INFO` ×4（§9.13.1 单一真源纪律）、
`_STANDARD_TAINT_TYPES` +ReDoS/Weak Password Policy、cwe_normalizer
+1333/521 短语级映射（不收 regex/正则裸词——回声票纪律）、审计器
`_SEMANTIC_TO_CWE` +log injection/redos/weak password policy 三项、
`_strip_block_comments_keep_lines` 收口为共用原语（§9.20 教训②操作化，
新行级规则默认先剥块注释）。

**前端待办清账（§8.11#2）**：cwe.html 详情弹窗风险等级改为"演示样本 manifest
静态标注优先，知识库通用等级括注辅助"（`expectedRiskByCwe` 取该 CWE 样本的
最高 `expected_risk_level`；安全对照不计入）——typical_20 实扫高危 vs 详情卡
中危的口径冲突消除。§8.11#1（后端"最近结果"端点）仍待办。

#### 9.22.4 验证矩阵（三场回归，零回退）

| 关 | 结果 |
|---|---|
| 87 段静态回归 | 总候选 124 / 零召回 15 / 零召回×真 3 / 安全样本候选 17 条——与第八波前**逐样本零差异**（Δ=0；四条新规则在合成集无形态对应，收益在仓库）|
| 盲区提醒泛化 | typical_16（L7 写路由+L13 会话写入）/ typical_22（L7）/ bypass_05（L10）/ spring4shell（L10 双提醒）/ server.js L145 / user-dao L25 / session.js L116/230 全命中；safe_10 会话写入同样提醒（提醒层无判定影响，模型消解）；safe 负样本（String 形参、https、纯字面量 console）零误提 |
| 仓库审计 | **nodegoat OK 13→17 · A 10→6 · B 0 · C 0**（四条 A→OK：ReDoS L59/console L64/弱口令 L144/ssn L62，行号全部精确命中）；dvna OK 5·A 4·B 2、vflask OK 13·A 3·B 1、php-goof OK 5·A 3·B 0——与 §9.9.4/§9.19 基线逐项一致（零回退）|
| 自检 | prefilter（新增 13 用例：4 正 + 9 负）、blind_spots（新增 #13 五条提醒正负样本）、two_stage / cwe_normalizer 全过；冒烟 10 PASS |
| 模块自检正负样本纪律 | ReDoS 负样本=算术括号/单量词分组；console 负样本=浏览器端/纯字面量；弱口令负样本=邮箱正则/非 pass 词根；312 负样本=cipher.update/已加密写法 |

#### 9.22.5 收口后的"不修"清单（每条复核过依据，非悬空）

| 类别 | 依据 |
|---|---|
| spring4shell（框架级） | Spring 官方标准用法，漏洞在框架版本；finding 会 FP 掉所有 controller。**已有 POJO 绑定盲区提醒兜底** |
| typical_15 角色缺失（862） | §8.8 维持缓期：有登录检查、缺**角色**检查，"敏感操作"定义是规则成立前提，等标签治理定案 |
| 跨文件（crossfile 全族） | 架构级，§六守卫 + CROSS_BOUNDARY 提醒已覆盖可达部分 |
| IDOR/信息暴露缺失型（639×3、CWE-200、allocations-dao） | ORM 查询本身安全，缺的是归属校验逻辑；AUTHORIZATION 提醒层已接管可及形态 |
| 模板层 ×2（swig views） | 模板语法在 JS 工具链解析域外（与 vendor 同级的域豁免，manifest 纪律） |
| render 回传 XSS（profile.js L65） | `res.render` 泛形态，每处渲染都命中，提醒无信息量、finding 噪声不可控——唯一"提醒也不加"的项，如实记档 |
| php-goof 3 条 | 版本敏感（SCA 域）+ DB 间接源 + 双语义，行级形态不可达（§9.19 维持） |

**方法论沉淀**：① "只能进提醒层"的移交必须**落地为表内规则并复测命中**——
宣称移交 ≠ 实际接管，验收标准是被提醒（本轮的悬空即缺失这道验收）；
② "正则层不可判"的论断要区分**行级不可判**与**文件级不可判**——console
双语义在文件级一判即中；③ 测量先行的逆定理：**每轮审计判出的"不修"清单，
要在下一轮用盲区层实测反向验收一次**（提醒了没有），否则清单变成单向账本。

### 9.23 语料池首次接入：CVE 补丁对基准的建立与真实召回基线（2026-09-01）

数据面切换：从"教学仓库/合成样本"转向自建语料池
`exp_06_finetune/corpus/rolling_dev`（50）+ `rolling_dev_safe`（47）。
本节的定位是**建立基线与口径**，不是修规则——先证明这个数据面可测、测的是什么。

#### 9.23.1 数据面定性（先于测量，差点误判）

初次跑出 48/50 "A 盲区（零候选）"时，第一反应是管线故障或标注错——**两个都排除**：

- **不是管线故障**：`ExternalScanner.scan_sast` 单独跑同一批文件有候选
  （Python 5/13），且 /tmp 与仓库内结果一致（排除 ignore/interfile 干扰）。
- **不是标注方向错**：`diff` + `patches/*.patch` 双重确认——
  `rolling_dev/corpus_00067.py` 是**修复前**（`secure_popen(cmd_full)` 无
  `allow_operators` 门控），`rolling_dev_safe/` 同名文件是**修复后**（新增
  `allow_operators()`），patch 的 `+` 行即修复。标注方向正确。

**真实原因**：这是**真实 OSS CVE 的补丁对基准**（Glances / sqlparse / Pimcore /
Gogs / MagicMirror² / WordPressCS 等），漏洞形态是"缺一个参数门控""不完整修复
（incomplete fix）""转义顺序错误"——教科书式模式匹配天然失效。
`corpus_00067` 的 CVE 本身就是"上一个 GHSA 修复不完整"，文件里还留着
`_sanitize_value` 这个**部分缓解**，极易被误读成"已修复样本"。

#### 9.23.2 基线测量：差分判别率 2%

用**补丁对差分**（同一文件漏洞侧 vs 修复侧的候选数差）作为主指标——它
**不依赖 CWE 标签**，是本数据面唯一可靠的口径。47 个可配对样本：

| 情形 | 数量 | 含义 |
|---|---|---|
| 漏洞侧有候选 / 修复侧无 | **1**（corpus_00002.py） | 唯一真正判别成功 |
| 两侧均无候选 | 35 | 漏洞侧零召回，无从判别 |
| 两侧候选数**完全相同** | 10 | 命中与补丁无关的**版本无关噪声** |
| 修复侧有 / 漏洞侧无 | 1（corpus_00059.java） | 反向，纯误报 |

→ **差分判别率 1/47 = 2%**；漏洞侧"有候选"比例 11/47 = 23%（但其中 10 个
在修复侧数量相同，说明命中的不是该 CVE）。

**与既有基线的落差**：87 段 OK 52%、NodeGoat OK 13/24 —— 那两个数据面是
教学/合成形态；真实 CVE 上工具层判别能力约 **2%**。87 段的 OK 率是**乐观估计**，
不可外推到真实代码。

#### 9.23.3 一条反直觉的度量教训：类型匹配"OK"可能是巧合

按 CWE 类型匹配（`line=0` 口径）漏洞池得 OK 2（corpus_00056.java、
corpus_00057.py，均 CWE-502）——**但这两个文件在修复侧的候选数完全相同**
（1=1、3=3）。即：工具在修复后的代码上产出同样多的候选，说明它命中的
根本不是那个 CVE，"OK"只是类型碰上了。

→ **纪律**：CWE 类型匹配判定为 OK 的样本，必须用补丁对差分复核；
只有"漏洞侧有、修复侧无"才算真命中。类型匹配单独使用会系统性高估召回。

#### 9.23.4 数据质量：CWE 标签硬错率 ~12%（影响微调语料）

用漏洞描述文本反推 CWE 做启发式筛查，32/50 个可核对样本中 12 例疑似；
**逐条人工核对后**：4 例硬错、4 例父类/子类或相邻类（可接受）、
4 例标签正确（启发式误判）。硬错率 **4/32 ≈ 12.5%**：

| 样本 | 标注 | 描述实指 |
|---|---|---|
| corpus_00001.js | CWE-89 | JSONata 任意代码执行（94/1321） |
| corpus_00002.py | CWE-89 | Xinference `unsafe eval()`（94） |
| corpus_00004.php | CWE-1336 | 绕过文件名随机化越权下载（639/862） |
| corpus_00054.js | CWE-441 | MagicMirror² SSRF（918） |

**影响面**：`exp_06_finetune/corpus` 是微调语料池，12% 的 CWE 标签硬错会
直接污染训练目标——这已超出工具层范围，属**数据治理事项**，需单独立项。
（粒度差异如 95/94、77/88、327/347 不计入硬错。）

#### 9.23.5 本数据面的正确用法（结论）

1. **不当召回基准**：当前全盲区，区分度不足（2%），测不出规则改动的收益。
2. **当"真实代码难度标尺"**：规则集每次大改后跑一次，看判别率是否从 2% 爬升
   ——它是防止"在合成样本上刷分"的对照锚。
3. **当形态挖掘素材（当前最大价值）**：47 个 patch diff 的 `-` 行是**官方确认
   的漏洞位置**，且不受 CWE 标签错误影响 → 应优先用 diff 而非 `expected_cwe`
   作为 ground truth 来挖形态（见下节推进方向）。
4. **ground truth 纪律**：凡"从 commit/CVE 映射来的标注"，必须抽验
   `source_path` 与实际代码一致（§9.20 broken_20260722 与本节 corpus_00002
   两次证明该抽验不可省）。

### 9.24 patches 形态 mining：形态规则天花板的量化（2026-09-01）

承接 §9.23.5 第 3 条（patch diff 是形态挖掘的正确素材）。对象
`corpus/patches/` 305 个 CVE diff（258 个可映射到 manifest，五语言均衡：
PHP 67 / Go 63 / Python 62 / Java 39 / JS 27），含 **1532 个 `-` 行
（官方确认漏洞位置）+ 6327 个 `+` 行（官方修复形态）**。

本节的核心产出是**两个负结果**——它们共同量化了形态规则的天花板，
直接否证"继续加规则就能提升真实召回"的隐含假设。

#### 9.24.1 负结果一：CWE-1336（最大空洞）77% 无静态形态

§9.23 测得 CWE-1336 是覆盖矩阵上最大空洞（全语言 0 规则、44 样本需求），
看似是 B 层追加规则的最佳靶子。逐样本核查 22 个 patch 后**否证**：

| 形态类 | 数量 | 例子 |
|---|---|---|
| **A 类：API 选择错误**（可静态检测） | **5**（23%） | PHP `renderString()` → 修复 `renderSandboxedString()`；Python Jinja2 `Environment`/`Template` → 修复 `SandboxedEnvironment` |
| **B 类：验证/策略配置缺失**（无静态形态） | **17**（77%） | Twig `SecurityPolicy` 未限类（corpus_00301）、pydantic 模板变量未校验（corpus_00302）、框架级沙箱策略（00307-00324 大部分） |

且 A 类那 5 个本身也难写：`renderString` 是 **Craft CMS 专有 API 名**
（违反泛化三关第 2 条"结构特征非拼写"）；Jinja2 `Environment(` 需导入上下文
才能与 `os.environ` / `string.Template` 区分（正则层不可靠）。
→ **CWE-1336 不立项**。"最大空洞"不等于"最该填的洞"——空洞的原因可能就是
它填不上。

#### 9.24.2 负结果二：形态可检测率 17%~30%（双法交叉验证）

用两个**相互独立**的方法对全部 256 个（n≥3 的 CWE）样本评估：

**方法 1 — sink 词典法**（漏洞侧 `-` 行是否含现有工具 sink 词典中的任一形态）：

| CWE | 样本 | 可检测 | | CWE | 样本 | 可检测 |
|---|---|---|---|---|---|---|
| CWE-502 | 17 | **52%** | | CWE-1336 | 22 | 36% |
| CWE-601 | 10 | **50%** | | CWE-22 | 23 | 30% |
| CWE-90 | 6 | **50%** | | CWE-77 | 13 | 30% |
| CWE-94 | 6 | **50%** | | CWE-352 | 7 | 28% |
| CWE-611 | 17 | **47%** | | CWE-327 | 22 | 27% |
| CWE-441 | 7 | **42%** | | CWE-79 | 18 | 22% |
| CWE-190 | 5 | 40% | | CWE-89 | 18 | **16%** |
| CWE-78 | 9 | 33% | | CWE-862 | 8 | **12%** |
| CWE-639 | 13 | 23% | | CWE-798 | 18 | **11%** |
| | | | | CWE-918 | 17 | **11%** |

合计 **30%**（78/256）。按语言：Python 38% > PHP 35% > JS 33% > Go 25% >
**Java 17%**。

**方法 2 — 修复性质分类法**（更严格：按 patch 的改动性质分四类）：

| 类 | 含义 | 数量 | 占比 |
|---|---|---|---|
| A | 漏洞侧有危险调用 + 修复侧引入安全 API（**形态可学**） | 25 | 10% |
| B | 仅删改危险调用（**形态可学**，需 API 对知识） | 20 | 8% |
| C | 修复侧仅加校验，漏洞行词面无危险特征（**不可学**） | 109 | 43% |
| D | 纯结构/逻辑重构（**不可学**） | 102 | 40% |

→ **形态可学（A+B）仅 17%，不可学（C+D）82%**。

两法结论一致（30% 偏乐观 / 17% 偏严格），真实天花板落在 **17%~30%**。
方法 1 对"字面量型"（798）与"结构型"（862）不适用，属乐观上界。

#### 9.24.3 最反直觉的一条：SQLi 在真实 CVE 上几乎无用

**CWE-89 是 A 类（加参数化/转义）仅 1/18，C 类（在别处加校验）11/18、
D 类 6/18。**

含义：真实代码里的 SQLi 修复**不是"把拼接改成参数化"**——漏洞行本身往往
就是一句普通的 `cursor.execute(sql)`，与正常代码无词面差异；修复发生在
**参数来源处**（加类型校验、加白名单、换 ORM 查询构造）。行级形态工具
看到的漏洞行与正确代码同形，**原理上无从判别**。

这与 87 段基线上 SQLi 类规则的高命中率形成尖锐对比：合成/教学样本的
SQLi 是"教科书拼接形态"（`"... %s" % user_input`），真实 CVE 不是。
→ **87 段上的高召回是数据面形态造成的，不可外推**（§9.23 已警示，本节量化）。

#### 9.24.4 对规则投入策略的直接指导

按可检测率重排投入优先级：

- **值得投入（可检测率 ≥47%）**：CWE-502 反序列化（52%）、CWE-611 XXE（47%）、
  CWE-601 开放重定向（50%）、CWE-90 LDAP、CWE-94 代码注入、CWE-441。
  共同点：**危险 API 本身即漏洞标识**（`ObjectInputStream.readObject`、
  `xstream.fromXML`、无校验的 `redirect(userInput)`）——不需要理解上下文。
- **不该再投入（≤16%）**：CWE-89 SQLi（16%）、CWE-862 授权（12%）、
  CWE-798 凭据（11%）、CWE-918 SSRF（11%）。继续加形态规则**边际收益趋零**；
  这四类要走别的路（数据流/SCA/配置面）。
  - 注：798 在 87 段上靠 detect-secrets/gitleaks 有产出，那是**字面量+熵值**
    通道，不是形态规则通道——本节结论只约束形态规则，不否定 secret 扫描器。
- **语言侧**：Java 可检测率最低（17%/12%）——Java 生态漏洞多为框架配置与
  授权缺失，形态规则收益最小；投入应偏向 Python/PHP。

#### 9.24.5 方法论沉淀

1. **"最大空洞"不等于"最该填的洞"**：先做可检测性评估再立项，否则会在
   填不上的洞上浪费整轮（CWE-1336 险些立项）。
2. **两个数，两个方法，互相印证**：单一方法的词典构成会主导结果（方法 1 的
   `render`/`Template` 宽松词让 1336 从 23% 升到 36%）。凡"量化天花板"类
   结论，必须双法交叉并给出区间而非点值。
3. **patch 的修复侧是免费的负样本矿**：`+` 行直接给出"官方认可的安全写法"
   （`filepath.Join` / `shlex.quote` / `setObjectInputFilter` / `dbf.setFeature` /
   `htmlspecialchars` / `secure_filename`），写规则时的"不误报对照"不必再
   靠猜。这是 patches 相对教学仓库的最大增量价值。
4. **形态规则的定位应下调为"第一道粗筛"**：天花板 17%~30% 意味着它不可能
   成为主力召回手段，主力必须来自数据流/跨文件/版本感知——§9.19（PHP
   版本/间接源）、§9.20（授权/间接源）、本节（真实 CVE 重构型）三处独立证据
   指向同一结论。

### 9.25 第二轮全量核验 + 第九波：遗留待办清账（2026-09-01，用户指令驱动）

> 用户指令（同 §9.22）：① 已优化的查属实、查到位；② "只能进盲区提醒层"的
> 查属实；③ 没优化的优化掉。本轮为 §9.22 之后的独立复验（不引旧结论，实测驱动），
> 并把 §9.22 之后仍悬空的工程项清掉。

#### 9.25.1 属实性复验结果

| 项 | 方法 | 结果 |
|---|---|---|
| 模块自检 | prefilter / taint_tracker / two_stage（含新 #27）/ cwe_normalizer / signal_registry / blind_spots / risk_budget / prompts 全跑 | 全过（graproj 环境）|
| 工具冒烟 | tool_smoke_test.py | 10 PASS / 0 FAIL / 0 SKIP |
| 盲区提醒命中 | §9.22.3 声称的 7 个样本逐个跑 `scan_blind_spots` | **7/7 属实且行号精确**：typical_16 L7/L13、typical_22 L7、bypass_05 L10、spring4shell L10 双提醒、nodegoat server.js L145、user-dao L25（+52/53）、session.js L116/230；vflask app.py IDOR L208/231 精确命中 |
| 「不修」清单依据抽查 | typical_15 代码实读（有 `session` 登录检查、无角色检查→缓期理由成立）；crossfile 守卫 `_has_param_driven_sink` 在位（two_stage L552）| 维持成立 |
| 已修抽查 | B1 `--no-git`、B2 gitleaks_rules.toml、B3 `_is_strong_credential`、`_EVIDENCE_CTX_MARK`、`_PROTECTED_RULE_PREFIXES`、`path_canonical_startswith` | 全部在位 |
| §8.2 崩溃窗口产物复核义务 | 扫全部 results/backend JSON（158 个文件）查 `_kind=="error"` | **0 命中**，复核义务闭合 |

**新发现（本轮唯一"已优化未到位"实锤）**：prefilter 自检摘要报
"存在失败用例"但全部用例 PASS——2026-09-01 新增的重叠检测把 WARN
（有意分层提示）折进了 `all_pass`，自相矛盾。已修：4 对家族规则⊇具体规则
（sqli_fstring/sqli_percent_format ⊂ sqli_constructed_query、cmd_os_system_concat/
cmd_subprocess_shell_concat ⊂ cmd_injection_shell）登记为 `_ACCEPTED_OVERLAPS`
白名单（人工裁决：家族规则管类型归一、具体规则保留行精度且被冒烟/审计映射
引用，候选合并按 (族, 行) 去重无双计）；白名单外的新重叠仍 WARN，且不再计入失败。

#### 9.25.2 第九波落地：两项遗留待办清账

**1. §8.9#2 top1 与多漏洞列表同源化（已修，含自检 #27）**

实锤根因比 §8.9 的描述更精确：不是"按 severity 取类型"本身，而是
`signal_registry.corrected_taint_type(rule_id)` **短路在多数票之前**
（two_stage `_aggregate`）——最高 severity 规则命中注册表映射时（typical_08 的
78、cve_03 的 798），模型独立归因（94/89）被整体跳过。修复：多数票优先，
注册表映射仅兜底（模型全体未输出类型时保持 B501→CWE-295 等历史校正能力，
§9.9.3 类型写回不失效）。配套：自检 #20 改为覆盖"模型无类型票 → 注册表兜底"
分支（raw=工具标注语义保持），新增 #27 复刻 typical_08 票型>注册表场景。
**口径提醒**：本修复动的是聚合层类型选择，Stage-1 候选零影响；LLM 层
top1 变化待下次全量评估自然验证，无需单独重跑。

**2. §8.11#1 后端"最近结果"端点 + 前端回站领取（已修）**

- 后端（main.py）：`AnalyzeRequest/TwoStageRequest` 增 `job_id`；
  `_stash_unclaimed`（内存环形 50 条 × 1h TTL，线程安全）；
  `GET /api/scan/result/{job_id}`（取走即删；404=不存在/仍在计算，410=过期）。
  功能测试三路径（claim/404/expired）通过。
- 前端（scan.html）：singleAnalyze 生成 job_id 并 sessionStorage 留痕
  （filename/lang/code/attempts），成功即清痕；页面加载 800ms 后
  `reclaimUnclaimedResults()`——404 限 5 次×15s 重试（后端可能仍在算），
  其余状态一律清痕防堆积；领取成功 `addResult` + toast 提示。
  全部 `<script>` 块 Node 语法校验通过。
- 批量通道（NDJSON 流式）不接：流式天然边扫边收，中断已收部分已持久化。

#### 9.25.3 剩余未优化项盘点（逐条归因，非悬空）

| 项 | 归因 | 状态 |
|---|---|---|
| §五之六待办1 LLM 裁决层重跑 / §9.21 rerun2（18/87）| 算力 | 待远程跑完，工具层侧无可做 |
| §8.7 temperature 翻转率（typical_08/23 各 3 轮）| 算力 | 同上 |
| §8.1 typical_20 补标 CWE-918 / §8.5 798 抢占标注面 / §8.6 helper 拆分文件语义 / §8.8 missing_authz_suspect"敏感操作"定义 | 标注治理（用户决策）| 维持缓期，工具层不擅动 |
| §8.11#3 样本库 87 段补样 | 数据治理 | 等 v2_15 训完反选 |
| safe_18 taint Java sink 行号 | 单安全样本、无 FP 风险、模型可消解（§五之七维持）| 不修判定维持 |
| swig 模板 ×2 / php-goof 3 条 / render 回传 XSS | 域外/SCA/提醒无信息量（§9.22.5）| 不修判定维持 |
| pyflakes 三琐碎项（§8.4）| 误报/无害残留 | 不修判定维持 |

**方法论沉淀**：① 自检摘要与用例结果矛盾（全 PASS 报失败）说明"摘要位"本身
也要有回归覆盖——任何折进 all_pass 的检查必须是真正的失败判据，提示性 WARN
必须旁路；② "建议方案"在文档里躺 48h+ 且实现成本 <1h 的（如 §8.9#2），
下次核验应直接实现而非再次记录。

### 9.26 train_pool 291 对全量差分：判别率 3.8%，语义正确率 1.7%（2026-09-01）

§9.23 的 2% 判别率建立在 47 对样本上，本轮用 `train_pool`（**291 对**，6.2 倍
样本量）复验，并新增"语义正确率"这一层度量。工具
`experiments/exp_08_repo_benchmark/patchpair_diff.py`（口径复用
`audit_stage1.collect_raw_candidates`，与既有报告可横向对比）。

**口径一致性校验先行**：同一脚本对 rolling_dev 重跑，完整复现 §9.23 的
1/10/35/1 分布与 2% 判别率 → 脚本可信，两个数据面可直接比较。

#### 9.26.1 结果：2% 是小样本偶然，但真实水平仍只有 3.8%

| 分类 | 数量 | 含义 |
|---|---|---|
| **强判别**（漏洞侧有候选 / 修复侧清零） | **11** | 最强判别 |
| 弱判别（漏洞侧多于修复侧，>0） | 3 | 可能是噪声抖动 |
| 反向（修复侧候选**更多**） | 4 | 绝不可计入判别 |
| 噪声（两侧候选数相同） | 44 | 与补丁无关 |
| 双零（两侧均无候选） | 226 | 漏洞侧零召回 |
| 反向（修复侧有 / 漏洞侧无） | 3 | 纯误报 |

→ **严格判别率 11/291 = 3.8%**（宽松 14/291 = 4.8%）。
→ 漏洞侧"有候选" 62/291 = 21%，但其中 44 个两侧同数 → **精确率仅 29%**。

**按语言（严格口径）**：python 5/70 = **7%** > javascript 2/29 = 6% >
java 1/40 = 2% ≈ php 2/76 = 2% > go 1/76 = **1%**。
Python 领先与 §9.24.2 的"可检测率 Python 最高 38%"互相印证（两个独立方法、
两个独立数据面同向）。

#### 9.26.2 最关键发现：判别成功 ≠ 检测语义正确（11 个里只有 5 个算数）

逐一追查 11 个强判别的**命中规则与推断类型**：

| 样本 | 标注 CWE | 命中规则 | 推断类型 | 语义 |
|---|---|---|---|---|
| corpus_00071.go | 327 | semgrep go.lang.security | Weak Cryptography | ✓ |
| corpus_00217.js | 79 | xss_unescaped_output | XSS | ✓ |
| corpus_00225.java | 798 | generic-api-key | Hardcoded Credential | ✓ |
| corpus_00227.php | 798 | Base64 High Entropy + Secret | Hardcoded Credential | ✓ |
| corpus_00328.py | 22 | path_traversal_open_join | Path Traversal | ✓ |
| corpus_00024 / 00310 / 00314 / 00320.py | 1336 | **B701** | **XSS** | ✗ **蹭中** |
| corpus_00097.js | 441 | log_injection | Log Injection | ✗ 错配 |
| corpus_00246.php | 862 | semgrep php.lang.security | XSS | ✗ 错配 |

→ **语义正确的强判别 = 5/291 = 1.7%**（而非 3.8%）。

**蹭中机制（4 个 CWE-1336 全中同一条）**：bandit **B701** 检测
`jinja2.Environment()` 未开 autoescape（XSS 语义）；而该 CVE 的修复是把
`Environment()` 换成 `SandboxedEnvironment()`——**B701 恰好不再触发**，于是
差分判定"成功"。但工具报的是 XSS(CWE-79)，真实漏洞是 SSTI(CWE-1336)。
差分只能证明"候选在修复后消失"，**证明不了工具检测到了那个漏洞**。

**5 个语义正确的共同点**：全部是**危险 API / 字面量本身即漏洞标识**
（`md5`/`sha1` 调用、`xss_unescaped_output`、`generic-api-key`/高熵串、
`path_traversal_open_join`）——与 §9.24.4 的"值得投入"判断一致，且 798 走的是
secret 扫描器（字面量+熵）通道而非形态规则，不违背 798 形态可检测率仅 11% 的结论。

#### 9.26.3 对 §9.24.1 的修正（结论保留，理由改写）

§9.24.1 据 22 个 patch 判 CWE-1336"77% 无静态形态、不立项"。
**不立项的结论仍然成立，但理由改为**：不是"检测不到"，而是"现有召回是
bandit B701 借来的、且类型错配（报 79 而非 1336），补 SSTI 规则无收益"。
教训：判定某 CWE"无形态"前，要先确认它的现有召回不是蹭中来的。

#### 9.26.4 过程中修掉的一个度量缺陷（会污染所有后续复用）

`patchpair_diff.py` 初版把 `v>f` 与 `f>v` 一并归入 `partial` 并计入判别，
导致"修复侧候选反而更多"的反向样本被误计为真判别——**train_pool 实测虚高
4 个（6% → 4.8%，严格口径 3.8%）**。已改为严格按方向拆分
`STRONG / WEAK / REVERSE`，并在脚本输出中固化"判别成功 ≠ 语义正确"的警告。
rolling_dev 12 对小样本回归验证通过。

#### 9.26.5 方法论

1. **任何"判别率"都必须附"语义正确率"**：差分度量的充要性只到
   "候选随修复消失"，不到"检测语义正确"。报告单一数字会系统性高估
   （本例 **2.2 倍**）。追查成本很低（11 个样本逐个查命中规则即可）。
2. **修度量工具优先于修引擎**：本轮唯一的代码改动是度量脚本的分类 bug。
   与 §9.8/§9.18/§9.20 的"测量先于引擎"四连同构。
3. **两个数据面、两个方法、同向印证**才算稳：Python 在"可检测率"（§9.24.2，
   38%）与"判别率"（本节，7%）上均领先，Go 在两处均垫底（25% / 1%）——
   这个排序可作为后续投入的语言优先级依据。

### 9.27 Go 专项：官方规则形态错位，追加 shell 解释器规则（2026-09-01）

按 §9.26.5 第 3 条的语言优先级，处理垫底的 Go（判别率 1.3%、零召回 62/76）。
本节是 **B 层（官方工具调用与配置）** 的一次完整实践：不改官方规则，只在之上
追加自定义规则。

#### 9.27.1 阳性对照先行：官方 Go 规则其实在跑

先证伪"Go 规则没生效"这个假设。构造 4 个阳性对照（`md5.New()` /
`exec.Command` / SQL 拼接 / `InsecureSkipVerify`）直跑 semgrep：

| 对照 | 结果 | 规则 |
|---|---|---|
| `md5.New()` | ✓ 命中 | `crypto.use_of_weak_crypto.use-of-md5` |
| `db.Query("..." + id)` | ✓ 命中 | `database.string-formatted-query` |
| `exec.Command("/bin/sh","-c",cmd)` | ✗ **零命中** | — |
| `tls.Config{InsecureSkipVerify:true}` | ✗ **零命中** | — |

→ 规则在跑（2/4 命中），**不是配置/执行问题**，是覆盖缺口。

#### 9.27.2 根因：官方规则覆盖的是语料里不存在的形态

`go.lang.security.audit.dangerous-exec-cmd`（CWE-94）的 pattern 只匹配
**`exec.Cmd{...}` 结构体字面量**，完全不匹配 `exec.Command(...)` 函数调用。
而语料池实测：

| 形态 | train_pool(76) | rolling_dev(14) |
|---|---|---|
| `exec.Command(` | **4** | 0 |
| `exec.Cmd{` | **0** | 0 |

→ **官方规则覆盖的恰恰是 0 个样本的形态**。Go 有 67 条规则、CWE-94 有 2 条，
但命令注入实质零覆盖。这是"规则数量 ≠ 有效覆盖"的直接证据。

#### 9.27.3 补规则：shell 解释器形态（CWE-78）

新增 `graduation_project/semgrep_rules/go_cmdi_shell.yaml`（非 taint 规则，
由 `_run_semgrep` 采集；与 gitleaks_rules.toml 同一手法：不编辑官方规则）。

检测"shell 解释器程序 + 执行标志"的组合结构：`sh/bash/zsh/ksh -c`、
`cmd /c`、`powershell -Command`、`/bin/sh -c`，并覆盖 `exec.CommandContext`
同族形态。

**为什么用普通形态规则而非 taint**：这类调用的危害与参数来源无关——只要命令串
过 shell，元字符即可注入，**shell 标志本身就是危险信号**，不依赖 source 追踪。
（对照：corpus_00177/00181 的 source 是 YAML 配置字段，taint 追不到。）

**泛化三关**：① `sh -c`/`cmd /c`/`powershell -Command` 是 POSIX/Windows 标准
shell 调用约定（语言级事实）；② 检测的是"解释器程序 + 执行标志"的组合结构，
非某个专有 API 名；③ 同语义形态存在于 Python `shell=True`、JS
`child_process.exec`、PHP `shell_exec`、Java `Runtime.exec("sh -c")`。

**不覆盖**：`exec.Command(cmd[0], cmd[1:]...)` 数组形式（无 shell）——需判断
cmd 是否用户可控，属数据流域，交 Stage 2 裁决（§9.24 已证其不可静态判别）。

#### 9.27.4 效果：Go 强判别 1 → 2，判别率 1.3% → 2.6%

Go 全量差分（76 对，加规则后）：

| 分类 | 数 |
|---|---|
| **强判别** | **2**（corpus_00071 CWE-327、corpus_00185 CWE-77） |
| 两侧同数噪声 | 12 |
| 两侧零候选 | 62 |

**新规则贡献 corpus_00185**（漏洞侧 1 / 修复侧 0，原为 0/0 双零）。
语义核对：规则报 CWE-78，标注 CWE-77 —— 78 是 77 的子类，按 §9.23.4 的
粒度标准属可接受，**语义正确** ✓。

**精度验证**：修复侧全池（train_pool_fixed 300 个文件）仅命中 2 条，且均位于
`corpus_00197_fixed.go`——该样本漏洞侧同样命中（v=f=1），属"两侧同数"噪声，
且那确实是真实的 `exec.CommandContext(ctx,"sh","-c",command)` 调用，
**规则命中正确，只是该 CVE 的修复点不在那里**。→ 无误报。

#### 9.27.5 Go 剩余缺口的定性（不再投入）

| 需求 | 样本 | 现状 | 判定 |
|---|---|---|---|
| CWE-22 路径遍历 | 17 | 现有 2 条规则，实测**真实召回 0/17**（2 个命中的是 Secret/Base64 蹭中） | 修补丁多为配置校验，§9.24 已证形态不可学 |
| CWE-1336 SSTI | 10 | §9.24.1 已判无形态 | 不立项 |
| CWE-639/862 授权 | 9 | 结构性盲区 | 不立项 |
| CWE-918 SSRF | 5 | 1 条规则 `tainted-url-host` | 覆盖存在，未深挖 |

→ **Go 不再追加形态规则**。67 条官方规则 + 本轮 1 条自定义，已接近形态天花板。

#### 9.27.6 两个必须记录的坑

1. **基线数字已变（非本轮改动）**：87 段总候选 **132 → 124**。核对 4 个历史
   dump 确认：昨晚 21:53 的 `20260831_215301` 已是 124，本轮加规则前后均为
   124 —— **本轮零扰动**（87 段语言分布 py75/php2/js2/java8，**不含 Go**，
   故新规则对其天然无影响）。132 这个数字自 §9.18 起被当作基线引用，
   现更正为 **124/15/3/17**（零召回与零召回×真清单未变）。
2. **差分分类的顺序 bug（一次性脚本内，已修正）**：判定顺序写成
   `STRONG → WEAK → v==f → ... → both_zero`，导致 `v=f=0` 先命中 `v==f`
   被误记为"同数噪声"（实测虚报 62 个 same、0 个 both_zero）。
   **正确顺序：`both_zero` 必须最先判**。`patchpair_diff.py` 中的顺序是对的
   （§9.26.4 已固化），本次是临时脚本重犯——**度量逻辑应复用脚本而非重写**。

#### 9.27.7 方法论

1. **先证伪"工具没跑"再找规则缺口**：4 个阳性对照只需 4 次 CLI 调用，就能把
   "Go 零召回"从"配置/执行问题"定位到"覆盖问题"，省掉一轮错误归因
   （§五之六 同构：先判定解释，再动手）。
2. **"规则数量 ≠ 有效覆盖"**：Go 有 67 条规则、CWE-94 有 2 条，命令注入却
   零覆盖——因为覆盖的是语料里 0 样本的形态。评估覆盖要看
   **规则形态 × 语料形态的实际交集**，不是规则条数。
3. **自定义规则放 `graduation_project/semgrep_rules/`**（`_TAINT_RULES_DIR`）：
   该目录被 `--config` 挂载、且 `_run_semgrep` 采集所有非 `-taint` 结尾规则，
   因此普通形态规则也能生效，且完全不碰 `models/semgrep_rules/`（官方产物，
   保持可同步上游）。

### 9.28 SCA 通道首次实测：trivy 全程空转，§9.19 的"不修"结论被推翻（2026-09-01）

本轮验证 B 层两个此前从未测过的工具：**gitleaks**（阳性对照）与 **trivy**
（首次完整实测）。后者产出了本日最重要的发现——**它推翻了 §9.19 的一个结论**。

#### 9.28.1 gitleaks：工具正常，此前判断无误

阳性对照（AWS key / GitHub token / RSA 私钥 / 高熵串）首轮报 "no leaks
found" —— **是我的构造问题**：用了 AWS 文档示例 key
（`AKIAIOSFODNN7EXAMPLE`），被 gitleaks 正确 allowlist。换真实格式后立即命中。
对比还顺带验证了 §9.21 的 B 层工作有效：

| 配置 | 命中 |
|---|---|
| 默认规则集 | 3 条（stripe / slack / aws-access-token） |
| **项目配置**（含 `gitleaks_rules.toml` 扩展） | **4 条**（多出 `aws-access-key-id` 自定义规则） |

#### 9.28.2 trivy：阳性对照正常，但语料池天然不适用

阳性对照（`requirements.txt` 含 flask 0.5 / django 1.2 / pyyaml 3.10，
`go.mod` 含 gin 1.3.0）→ **77 个漏洞**（requirements 53 + go.mod 24），工具正常。

但语料池（`train_pool` 等）是**单文件代码样本、无依赖清单** → trivy fs
天然零产出。这是**数据面不匹配，不是工具缺陷**：SCA 的正确数据面是仓库。

#### 9.28.3 核心发现：trivy 在全部仓库审计中零生效

转向已 clone 的 4 个仓库（都有依赖清单，却从未跑过 SCA）：

| 仓库 | 依赖清单 | trivy 产出 |
|---|---|---|
| **nodegoat** | package-lock.json | **85 个**（CRITICAL 11 / HIGH 43） |
| **php-goof** | composer.lock | **22 个**（CRITICAL 5 / HIGH 6） |
| dvna | 仅 package.json（**无 lock**） | 0（trivy 需 lock 文件） |

**根因在 `two_stage_scanner.py:2440-2448`**：SCA/IaC 分流是**按后缀**的——

```python
# sca：trivy fs 只在依赖清单（requirements.txt 等）上有意义 → 仅非代码文件
if suffix not in code_file_exts:
    groups["sca"] = self._external.scan_sca(tmp_path)
```

该判据为"单文件扫描"设计（一个 .py 文件里确实没有依赖清单，成立）；但
仓库审计是**逐代码文件**调用，依赖清单从未被单独扫描 → **trivy 在
§9.9~§9.27 的全部仓库审计中零生效**。工具一直在，是管道没接。

#### 9.28.4 §9.19 结论修正：不是"不可解"，是"通道没接"

§9.19 对 php-goof 的 3 条 A 盲区判定为"版本/配置敏感、结构性边界、零代码
修复"。trivy 实测**三条全部覆盖**：

| §9.19 判定 | trivy 实测 |
|---|---|
| index.php L65 CommonMark XSS（"间接源、不修"） | **CVE-2019-10010**（XSS double-encoded entities）✓ |
| pdf.php L39 dompdf RCE（"版本敏感、不修"） | **CVE-2022-28368 CRITICAL**（Remote code injection via remote fonts）✓ |
| mail.php L19 PHPMailer（"版本特有、不修"） | **CVE-2021-3603 HIGH** ✓ |

**结论修正**：那 3 条在"行级形态工具"框架下确实不可解（这点仍成立），
但"零代码修复"是错的——SCA 通道本就能覆盖，缺的是管道接入。
**教训：判定某缺陷"结构性不可解"前，先确认所有通道都跑过了。** §9.19 只在
SAST+secret 的测量结果上就下了"不修"结论，而 SCA 通道当时根本没启用。

#### 9.28.5 修复：给审计脚本接上依赖清单扫描

`audit_stage1.py` 新增 `collect_dep_vulns()` + `_render_deps()`，识别
`_DEP_MANIFESTS`（package-lock/yarn.lock/composer.lock/requirements.txt/
go.sum/Gemfile.lock/pom.xml 等 14 种），用 `ExternalScanner._run_trivy_fs`
逐个扫描，渲染为**独立小节**。

**口径设计（关键）**：SCA 产出是**项目级**证据（"本项目用了有漏洞的库版本"），
不是行级（"应用在第 N 行触发了该漏洞"）。它证明不了 `pdf.php` L39 就是
dompdf RCE 的触发点。因此作为独立小节附加，**不参与 expected_findings 的
A/B/C 判定**，避免污染既有基线。

**零扰动验证**（php-goof，带/不带 SCA 各跑一次，diff 判定结果）：
```
A) 带 SCA   : OK 5 (db/func/index L39/tasks×2) + A 盲区 3 (index L65/pdf L39/mail L19)
B) --skip-deps: 完全相同
diff → ✓ 完全一致
```
nodegoat：SCA 85 个漏洞，A/B/C 判定同前。

（注：nodegoat 本次 OK 17 / A 6，与 §9.20 记录的 OK 13 / A 10 不同——
先前归因给"并行会话 14:19/14:26 对 `two_stage_scanner.py` / `prefilter.py`
的改动"，**该归因有误（2026-09-01 晚复核）**：那两处改动分别是 `_aggregate`
类型选择（LLM 聚合层）与 prefilter 自检统计（测试代码），均不在
`collect_raw_candidates` 的 stage1 候选路径上，不可能改变 OK/A 计数。
真实差异源与 §9.27.6 发现的 87 段候选 132→124 同源：**8-31 晚规则变更**
（在 §9.20 记录之后落地的 prefilter/semgrep 新规则），属预期内的基线漂移，
非本轮 SCA 改动所致。）

#### 9.28.6 方法论

1. **"工具不可用"与"管道没接"是两回事**：trivy 已集成在
   `ExternalScanner.scan_sca()`，冒烟测试也覆盖了它（tool_smoke_test.py:200），
   但真正的审计入口 `audit_stage1.py` 从不调用 → 冒烟通过 ≠ 通道接通。
   **冒烟测试只验证函数可调用，不验证它在生产路径上被调用。**
2. **分流逻辑的条件在换场景后可能失效**：`suffix not in code_file_exts`
   在单文件场景正确，在仓库场景错误。凡"按文件类型分流"的逻辑，都要确认
   它在**所有调用场景**下成立。
3. **新增通道先做独立小节，不动既有判定**：SCA 与行级 expected 不同维度，
   强行合并会污染基线（§9.23.3 的"类型匹配 OK 是巧合"同型教训）。先并列
   呈现，等口径讨论清楚再决定是否合并。
4. **阳性对照的构造值要避开 allowlist**：AWS/GitHub 的文档示例 key 已被
   主流 secret 扫描器收录为 allowlist（正确行为），用它做阳性对照会得到
   "工具坏了"的假结论。

### 9.29 标注与答案质量审计：各数据面可信度分级与差池清单（2026-09-01）

用户提问："待测试和已测试数据的答案准确吗？会不会因为答案不准确导致
优化和真理有差池？" 本节是正面回答：逐数据面给出可信度分级、已实证的
差池、以及对既有优化结论的影响评估。**结论先行：核心优化结论全部建立在
绕开标注的度量设计上，经受住了本轮抽验；但有 3 处结论需要加警示、2 处
流程教训必须记录。**

#### 9.29.1 各数据面标注质量分级

| 数据面 | 标注来源 | 可信度 | 已实证问题 |
|---|---|---|---|
| 87 段（exp_04） | 用户手工构造 + 两轮治理（8-18 / 8-29 补标注在案） | **A** | 仅已知缓期项（§8.1 补标 918、§8.5 798 抢占、§8.8 授权定义），属记录在案的偏差 |
| php-goof / nodegoat / VFlask | 逐行实读 + 官方资料交叉（Snyk 编号 / 官方注释 / 用户复核） | **A** | php-goof 3 条"不可解"实为 SCA 通道缺失（§9.28 已修正——这是**答案不完整**而非标注错误） |
| dvna | 早期 manifest | **B-** | §9.18.2 明示 GT 不完整，4 个 A 盲区部分可能是 GT 缺失 |
| rolling_dev（50） | CVE 映射自动生成 | **C+** | expected_cwe 硬错率 ~12%（§9.23.4：4/32 逐条核对） |
| train_pool（291） | CVE 映射自动生成 | **C** | 本轮新实证：**patch 文件与文件对不同源**（见 9.29.2）；40 个样本缺 patch（Go 16）；00217 的 patch 是 minified bundle 无法验证 |
| testset_cve_fix.broken | CVE 映射 | **D（已废弃）** | CVE 与文件错位实锤，未用于任何结论 |
| cve_fix 20 段 | manifest_eval.json | **未抽验** | — |
| corpus raw 516（待测试面） | 目录级分类 + LANG 头 | **未验证** | 使用前必须先抽验，特别是 taint_boundary 的 CWE 归类 |

#### 9.29.2 train_pool 深度抽验：patch 文件三类质量缺陷

对 §9.26.2 的 11 个 STRONG 样本逐一追查 patch 内容（原判定依据是
"工具类型=标注类型"，**没查过 patch**）：

| 样本 | 标注 | patch 实况 | 判定 |
|---|---|---|---|
| corpus_00071.go | 327 (CVE-2024-55885 MD5 缓存碰撞) | **patch 是 guest token 授权修复（GHSA-f4vv-55c2-5789），与文件对（md5→sha256）不同源** | patch 错位；**文件对正确**（diff 实锤 md5→sha256），标注正确，semgrep 命中语义正确 ✓ |
| corpus_00217.js | 79 | patch 仅 4 行 minified bundle diff | **无法验证**（打包产物） |
| corpus_00225.java | 798 | 硬编码 secret → 环境变量读取 | ✓ |
| corpus_00227.php | 798 | 硬编码 oauth token → 空串 | ✓ |
| corpus_00328.py | 22 | os.path.realpath() 加固 | ✓ |
| corpus_00246.php | 862 | 未验 | 原判"错配（报79）"依据仅为类型对比，patch 未查——**待验** |
| corpus_00097.js | 441 | 未验 | 同上 |

**patch 语料三类缺陷定级**：缺失（40/305，13%）＜ 错位（00071 型，
patch 与文件对不同源）＜ 不可验证（bundle 类，diff 无人工可读信息）。
错位类最危险：**patch mining 会把"授权修复形态"统计进"327 弱加密"的
形态组**——§9.24 的形态归纳按 CWE 分组，组内混入错位 patch 是系统性噪声。

**§9.26.2 语义正确率修正**：5/11 中，4 个铁证（00071/00225/00227/00328）、
4 个 B701 蹭中维持原判（机制由 patch 内容 Environment→Sandboxed 直接证实，
不依赖标注）、3 个未验（00097/00246/00217）。**严格可证区间 4~8/11**
（36%~73%），语义正确率区间 **1.4%~2.7%**。原报告 1.7% 落在区间内，
**方向结论不变**（语义正确率远低于判别率 3.8%），但 00097/00246 的
"错配"二字应降级为"未验证"。

#### 9.29.3 差分管道可信度重验：11/11 通过（含一次自我纠错）

过程中我一度误判"度量管道有非确定性 bug"（因 corpus_00071 的
`diff` 输出为空）。重验（`verify_strong.py`，沉淀为资产）：

- 11 个 STRONG 全部 **3 次重跑 v/f 完全一致** + **sha 确认文件对真实不同**
  → 差分管道无稳定性问题；
- "diff 为空"是**我的测量假象**：系统 `diff` 输出 **normal 格式**（`<`/`>`），
  我 grep 的是 unified 格式（`-`/`+`）→ 假空。用 `git diff --no-index -u`
  或先确认格式可避免；
- 连带修正：verify 脚本两次空转（JSON 字段名 v/f vs vuln/fixed 记错）。

**方法论教训（§9.29.4）**：下"标注错"结论前，先穷尽**测量层假象**
（格式错配 / 字段名错位 / 路径错误 / exit code 链断裂吞掉输出）。
本轮顺序应是：sha → diff -u → patch 三层证据齐了再定性。我实际走了
"先怪标注 → 再怪管道 → 最后发现是自己 grep 格式错" 的弯路，三层里
只有 sha 那层是直接可信的。

#### 9.29.4 对既有优化结论的影响评估（最终清单）

**不受影响（度量设计绕开了标注，本轮抽验加固）**：

| 结论 | 依据 |
|---|---|
| 差分判别率 2% / 3.8% / 2.6%(Go) | 只依赖 vuln/safe 文件对（官方修复版），不读标注 |
| 11 个 STRONG 可信 | 3×重跑 + sha 双验（本轮） |
| B701 蹭中机制 | patch 内容（Environment→Sandboxed）直接证实 |
| Go exec.Cmd 形态错位 | 阳性对照 + 语料形态统计 |
| SCA 通道缺失（trivy 107 洞零生效） | 与标注无关 |
| 形态天花板 17%~30% 的总量 | patch 是官方答案；但 **CWE 归组可能被 00071 型错位污染** |

**需要加警示 / 降级**：

| 结论 | 修正 |
|---|---|
| §9.26.2 语义正确率 1.7% | 改为区间 1.4%~2.7%，00097/00246 "错配"→"未验证" |
| §9.24.4 CWE 投入优先级 | 组间排序有漂移风险（错位 patch 污染分组），但大组（502 n=17、22 n=23、1336 n=22）方向稳；**小样本组（n<5）的排序不可单独引用** |
| dvna 的 4 个 A 盲区 | 加"GT 不完整"警示（原已记录，重申） |
| 87 段 fixed5 基线的"零召回×真 3 个" | 抽验通过（标注具体 + 治理在案），维持；但 hard_cve_03/05 的多标注（22;377 / 915;94;79）中"真"指任一匹配 |

**待测试面的准入门槛（新增纪律）**：corpus raw 516 与 cve_fix 20 段在
接入任何度量前，先跑 10% 标注抽验（patch/描述/代码三方一致性）；
抽验不过 95% 的数据面只可用"与标注无关"的度量（差分/形态统计），
不可用 CWE 分组度量。

#### 9.29.5 方法论

1. **答案质量要分层引用**：差分结论可引用全部数据面；CWE 分组结论只可
   引用 A 级数据面（87 段/仓库）；corpus 的 expected_cwe 只可用于
   "粗分组统计"，不可用于单样本定性。
2. **patch ≠ 答案**：patch 文件本身有三类缺陷（缺失/错位/不可验证），
   "官方 diff"的可信度以**文件对实际 diff** 为准（`git diff --no-index -u`
   两侧文件），patch 文件只是索引。
3. **测量假象优先于实体结论**：出现反直觉数据（如"diff 为空但 sha 不同"），
   先排查格式/字段/路径/管道（5 分钟），再怀疑标注（半天），最后才怀疑
   度量管道本身。本轮的顺序反了，浪费两轮验证。
4. **verify_strong.py 入库**：任何差分报告发布前跑一遍（sha + 3×重跑），
   作为"判别可信"的准入检查。

### 9.30 第十波：patch 审计落地 + SCA 接生产 + alpha0 首测记录（2026-09-01 晚）

> 用户指令："数据层缺陷与 05 模型弱点要写进文档并落实到数据上"。本节收账：
> §9.29.2 的 4 个悬置项全部关账并落到数据面（patch_audit.json）；
> §9.28 的 SCA 断点在最后一个生产入口（github-scan）补接；
> 附 nivis-alpha0 模型 87 段首测里程碑（来历勘误见 9.30.3）。

#### 9.30.1 patch 审计落地：train_pool/patch_audit.json

**4 个悬置项全部关账**（patch 内容 + 文件对 diff + 漏洞侧行号三证）：

| 样本 | §9.29.2 状态 | 本次定案 | 证据 |
|---|---|---|---|
| corpus_00097.js | 未验证 | **确认错配**（回到 §9.26.2 原判）| patch 剥离 `req.url` query（CWE-441 语义）；工具报 log_injection 与修复语义无关 |
| corpus_00246.php | 未验证 | **部分正确**（新定性）| patch 同时修 862 主漏洞（补 UserIsAdmin）+ 次生 XSS（漏洞侧 L54-55 未转义 `$comment['tag']` 直出 HTML 实证存在，patch htmlspecialchars 修复）；工具报 XSS = 检测到真实次生漏洞，非错配；主标注 862 未被覆盖 |
| corpus_00071.go | patch 错位 | 错位实锤落档 | patch 内容为 guest token 认证修复（GHSA-f4vv-55c2-5789），与文件对（md5→sha256）不同源；**标注与文件对可信**，patch 标记 MISMATCHED，形态/patch mining 跳过 |
| corpus_00217.js | bundle 不可验证 | 维持，落档 | 5 行 minified diff |

**§9.29.2 数据修正**：「缺失 patch 40（Go 16）」为**过时口径**——实测
291/291 全部有 patch_file 且在盘（8-23 后按 CVE ID 重命名 + source_sha 批量
补拉已生效）。**patch 缺失率 0%**，patch mining 只需跳过 00071（错位）与
00217（不可验证）两个样本。

**落地形式**：`experiments/exp_06_finetune/corpus/train_pool/patch_audit.json`
（sidecar，不动 manifest 本体）。此后任何 patch mining / 形态归纳脚本应先读
它。语义正确率结论维持：区间 1.4%~2.7%，11 个 STRONG 定性全关账
（4 铁证 + 1 部分 + 1 错配 + 1 不可验证 + 4 B701 蹭中）。

#### 9.30.2 SCA 通道接生产：github-scan 端点（§9.28 断点的最后一处）

§9.28.5 只修了审计脚本入口（audit_stage1.py）；**生产路径排查发现
`/api/github-scan` 存在同构断点**：`_clone_and_collect` 的收集阶段
`ext not in EXT_TO_LANG: continue` 把 package-lock.json / go.sum 等 14 种
依赖清单在**收集期**丢弃——清单永远到不了扫描器的 SCA 分支（L2446 的
按后缀分流对清单是通的，但清单根本进不来）。

**修复**（main.py，§9.28.5 口径原样复用）：
- `_clone_and_collect` 增收依赖清单路径（文件名精确匹配 `_DEP_MANIFEST_NAMES`
  14 种；不读内容不占代码硬上限；上限 50 防异常仓库）；
- `github_scan` 对清单并行跑 `_scan_dep_manifests`（逐清单
  `ExternalScanner.scan_sca`，失败留 error 条目不静默）；
- 响应新增 `dependency_vulnerabilities` **项目级独立小节** + 
  `dep_manifests_found` 计数；**不计入** vulnerable/safe 统计，不污染 FPR 基线。

**验证**：py_compile 通过；伪仓库实测（node_modules 内清单被跳过 ✓、
readme.md 不混入 ✓）；阳性清单（flask==0.5）trivy 报 8 条 ✓。
批量上传端点天然通（不过滤扩展名，.json 清单走扫描器 SCA 分支）。

至此 SCA 三个入口全部接通：audit_stage1（§9.28.5）、批量上传（原生通）、
github-scan（本节）。

#### 9.30.3 nivis-alpha0（garrywhite109909/nivis-alpha0）87 段首测里程碑

> **来历（2026-09-01 晚用户确认）**：nivis-alpha0 = **云端 A800 SFT 训练出的
> LoRA adapter**（HF: garrywhite109909/nivis-alpha0），下载后**接 Qwen3-8B
> 基座**本地 transformers 推理（评测 meta `backend=transformers` 即此）。
> 用户口径：**当前测的是 alpha0.5，为以后训练 0.6 做准备**——即本轮
> anchor_full 是 0.5 的验收测量，其结果（含唯一 FP 的失败分析）直接喂给
> 0.6 的训练决策。注意与数据版本名区分：alpha06 **数据**已冻结（8-23）但
> **训练未开始**；本节初稿"云端 SFT 模型/alpha06 数据训练"的归因已勘误。

| 配置 | 结果 | 对照 |
|---|---|---|
| **anchor_full**（全工具，87/87 完整） | **recall 100% / FPR 4.76%**（TP54 TN20 **FP1** FN0）review_v7+review_s5，3.4h | local_alpha05_rerun2：FPR 8%（FP2）；锚点 Qwen3-8B：FPR 26.9% |
| anchor_ctx16384（22/87 中断） | 待 `--resume` 补跑 | — |
| baseline_noTools_cns（34/87 中断，纯模型消融） | 待补跑——**「模型真正理解文件」能力的关键基线** | — |

- 唯一 FP = hard_crossfile_03_input（CWE-862，无候选全量复核通道误判）——
  跨文件弱点仍在；**2026-09-01 晚勘误**：wave2 四份数据（含 crossfile_safe_pairs
  128 条）经哈希验证**已在 v2_13/v2_14 批次入库**（此前"wave2 未入训"判断
  有误，见 v2_15 指导文档 §6.1 对账），故该 FP 反映的是**现有跨文件样本对
  "输入文件单独看无洞"形态覆盖不足**，0.6 增量走 g20-g24 更难样本而非补入库；
- 87 段无 Next.js 样本，框架习语盲区修复与否本轮**不可测**；
- FPR 26.9%（锚点）→ 8%（local_alpha05）→ 4.76%（nivis-alpha0）为客观阶梯；
  adapter 间差异的归因（数据/配方/训练超参）以云端训练任务记录为准。

#### 9.30.4 方法论

1. **悬置项要"三证关账"**：patch 内容 + 文件对 diff + 漏洞侧行号实证，
   三证齐才能把"未验证"改成任何结论（00097/00246 各走了三层证据）；
2. **统计口径要带时间戳**：「缺失 40」在补拉后已变为 0，引用历史数字前
   先重测（成本：一条 python -c）；审计结论落 sidecar 文件而非只写文档，
   脚本可读、文档可引；
3. **一个断点多处复现**：同构缺陷（按后缀/扩展名分流）在 audit 与 github-scan
   两个入口各断一次——修完一个入口必须问"还有哪条路进同一个函数"。
4. **归因语句只能写 meta/日志里真实存在的字段**（2026-09-01 晚勘误教训）：
   模型 ID 长得像 HF 仓库 ≠ 云端推理（评测 meta 明写 transformers 本地）；
   "数据集已冻结" ≠ "训练已完成"（alpha06 冻结 8-23 但用户明示尚未开训）。
   把推断写成事实，被用户一眼识破——结论可以超前，因果必须贴证据。

## 十、跨机协作看板（2026-09-01 建，两台机器共用的唯一待办清单）

> 分工：**实测机**（产出本文档的机器）跑评测/工具审计/代码修复；
> **数据机**（对端）按本文档优化训练数据。用户记不清对端是否已做——
> 所以每项都带"**是否已做速查**"（在数据机上跑一条命令即可判断）。
> 纪律：任一台机器完成一项，就把状态列改 ✅ 并注明日期，防止重复做。
> 本机快照截至 2026-09-01 晚，数据机上的状态以对端磁盘为准。

### 10.1 数据机待办 → 已迁移（2026-09-01 晚）

**数据层待办的唯一来源已改为
`experiments/exp_06_finetune/audit/优化建议_alpha06_日志类CWE归因辨析_v2_15.md` §六**
（v2_14 与 v2_15 经 diff 确认 v2_15 为严格超集，v2_14 已删除；其 §6.1 D1~D8
含 wave2 入训、标注抽验、patch 过滤、prompt 措辞等全部数据机事项，并附
速查命令）。本节仅保留指针防重复维护；实测机待办见 10.2，核对基准见 10.3。

### 10.2 实测机待办（本机保留，勿移交）

| # | 事项 | 状态 | 说明 |
|---|---|---|---|
| S1 | **两份中断评测 `--resume` 补跑**：anchor_ctx16384（22/87）、baseline_noTools_cns（34/87） | ⏳ 等算力 | 后者是**纯模型消融**（工具全关）——量化"模型真正理解真实文件"能力的关键基线，跑完后与 anchor_full 差分即工具加持增量 |
| S2 | temperature 翻转率（typical_08/23 各 3 轮） | ⏳ 等算力 | §8.7 遗留 |
| S3 | L2 锚定探针集 50~60 题 | ⏳ 解锁 | alpha06 已冻结（8-23），污染门条件已满足，可开工（测试集建设方案.md §3） |
| S4 | rerun2 完成后的 LLM 裁决层指标复核 | 部分：alpha0 anchor_full 已记 §9.30.3 | 剩余：rolling_dev 50+47 的 alpha0 差分评估（首个真实 FPR，L1 发布前必测） |

### 10.3 已完成勿重做（两台机器核对基准，截至 2026-09-01 晚）

| 项 | 落点 | 完成日 |
|---|---|---|
| alpha06 训练集 8316 条冻结 | `data/final_train_chatml_alpha06.jsonl` | 8-23 |
| patch 缺失补拉（291/291 全在盘） | `corpus/patches/`（按 CVE ID 命名） | 8-23 补拉，9-01 实测确认 |
| patch 审计 sidecar（00071 错位/00217 不可验证/00097 错配/00246 部分正确） | `corpus/train_pool/patch_audit.json` | 9-01 |
| SCA 三入口接通（audit_stage1 / batch 原生通 / github-scan） | audit_stage1.py + main.py `_DEP_MANIFEST_NAMES` | 9-01 |
| Go shell 解释器规则 | `graduation_project/semgrep_rules/go_cmdi_shell.yaml` | 9-01 |
| prefilter 自检白名单（4 对有意分层） | prefilter.py `_ACCEPTED_OVERLAPS` | 9-01 |
| §8.9#2 top1 与模型归因同源化 + 自检 #27 | two_stage_scanner.py `_aggregate` | 9-01 |
| §8.11#1 回站领取（job_id 暂存 + 前端拉取） | main.py + scan.html | 9-01 |
| patchpair_diff 反向样本度量修复 | exp_08_repo_benchmark/patchpair_diff.py | 9-01 |
| 前端回站领取 / nodegoat 归因修正 / §9.26~9.30 全部记录 | 本文 §9.26~§9.30 | 9-01 |
