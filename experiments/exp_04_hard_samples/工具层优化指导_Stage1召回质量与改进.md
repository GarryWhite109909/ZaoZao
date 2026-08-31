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
   **动 fixed5 基线，需全量回归。**
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
| 1 | 跳转离开页面 → "接着分析但不出结果" | 导航终止前端 fetch；**后端调度器继续跑完**，结果无人接收 | 轻量已修：`beforeunload` 提醒（scan.html）。彻底方案：后端加"最近结果"查询端点 + 页面回站拉取未取走结果（工程项，待办）|
| 2 | 评级不一致：实扫卡"高危" vs 样本库详情卡"中危"（typical_20/CWE-295）| 两处不同源：实扫 risk_level=裁决层（B501 bandit=high）；样本库详情卡风险来自 **CWE 知识库通用等级**（295 通用标中危），未优先读 demo manifest 的 `expected_risk_level: High` | 待修：样本库详情卡风险优先取 manifest 静态标注，CWE 通用等级降为辅助展示（纯前端）|
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
**工具层零召回 = 规则盲区**（5 条：347/209/312/639×2/434）；
**工具层已召回但实扫 miss = 切片稀释或裁决层否决**（需另查）。

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
| **DVNA** 11 条 | OK 4 · A 4 · **B 3** | **OK 6** · A 4 · **B 1** |

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

**遗留（真实 A 盲区，均为缺失型或需定向规则）**：347（JWT verify=False）、
209（异常回显）、312（信用卡明文）、639×2（IDOR）、434（文件上传）、
311（layout，info 级不计）。其中 639×2 与 §8.5 授权类同构 → 不修记档。

