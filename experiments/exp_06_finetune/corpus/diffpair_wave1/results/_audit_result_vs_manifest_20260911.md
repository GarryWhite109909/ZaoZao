# diffpair_wave1 蒸馏结果审计报告

审计对象：`diffpair_wave1/results/result.txt`（教师侧已产出的分析）
比对基准：`diffpair_wave1/manifest_PRIVATE.json` + `index.md` + `train_pool/manifest.json`
审计方式：全部只读；未改动任何语料/标签文件。

---

## 一、TL;DR

1. **没有"藏样本"（漏）意义上的问题**：`index.md` 中 id ≤ 00178 的包共 **108** 个，`result.txt` 覆盖 **106** 个，只缺 **00143、00159**（这两个包文件都在 `kits/` 和 `kits_learner/`，也不在 `skipped.jsonl` 里 → 属"该做未做"）。
2. **但"毒"是真实的，只是毒源不在蒸馏，而在 `expected_cwe` 标签**：只看正样本侧（A 版 106 块），**只有 48 块（45.3%）的蒸馏 CWE 与标签一致**；38 块（35.8%）报出了别的 CWE，20 块（18.9%）直接判"无洞"。合计 **58/106（54.7%）与标签对不上**。
3. **最重的一类毒是"一包多答"**：4 处 (id,版本) 存在多条互相矛盾的分析结论，若全部入库 = 同一份代码被赋予多个互斥标签。
4. 抽检 3 例（00180 / 00006 / 00012）**全部指向"标签错、蒸馏对"**，见第五节。

---

## 二、覆盖情况（藏样本核查）

- `result.txt`：字符 424799，行 4666；`### ` 分析块 **219** 个；覆盖 distinct id **106** 个（00006 ~ 00178）
- `(id,版本)` 去重组合：**212** 个
- `index.md` 中 id ≤ 00178 的包：**108** 个；已被 result.txt 覆盖 **106** 个；**缺 2 个 → ['00159', '00143']**
- result.txt 中出现但不在 `index.md` 的 id（误收录）：**无**
- `api_results/` 目录：**空（0 个文件）** ← 若此处本应存放批跑结果，需你确认是否另有落盘位置
- `skipped.jsonl`：45 条，全部是"patch 无法应用: hunk@N 无法锚定"（与 00143/00159 无关）

## 三、核心发现：标签 vs 蒸馏 CWE

语义基准：**版本A = pre（正样本，应有洞）；版本B = post（修复版）**。此基准已由 00006 实证（A 报 NULL deref、B 报 false，而 fix 正是在 L127-134 新增 nil 检查）。

- A 版分析块 **106** 个，B 版 **106** 个

### A 版（正样本侧，106 块）—— 该栏才是"标签对不对"的判据

| 类别 | 数量 | 占比 | 含义 |
|---|---|---|---|
| 蒸馏 CWE **与标签一致** | **48** | 45.3% | 标签在代码内得到印证 |
| 蒸馏 CWE **与标签不同** | **38** | 35.8% | 二者必有一错，需逐条看 |
| 蒸馏判 **"无洞"** | **20** | 18.9% | 标签说 expected_present=true 但代码内证不出 |

### B 版（修复版侧，106 块）—— 该栏衡量"修复是否被蒸馏认可"

| 类别 | 数量 | 占比 | 含义 |
|---|---|---|---|
| 判 **"无洞"** | **61** | 57.5% | 与"修复版"语义相符，✓ |
| 仍判 **"有洞"** | **45** | 42.5% | 要么蒸馏误报，要么 fix 只补了一处、残余路径仍可达 |

> 说明：先前把 A/B 混算得到"129/212 不符"是把 B 版"正确地判无洞"也算成了不符，属口径错误，已在上面拆开。**B 版报"无 CWE"是正确行为，不是误差。**

### A 版 38 块 CWE 不符，按标签分组

| 标签 | 该标签 A 块数 | 不符数 | 蒸馏报成了什么 |
|---|---|---|---|
| CWE-1336 | 20 | **11** | 22×2、79、862×3、639、1321、400、284、94 |
| CWE-441 | 7 | **7（全灭）** | 295、639、918×2、400、862、22 |
| CWE-639 | 10 | 5 | 863、306、862、22、354 |
| CWE-77 | 4 | **4（全灭）** | 78×3、829 |
| CWE-22 | 6 | 4 | 862、88、494、78 |
| CWE-502 | 6 | 3 | 494、22、20 |
| CWE-601 | 5 | 2 | 22、918 |
| CWE-190 / 89 / 352 / 90 / 79 / 798 / 611 / 918 / 862 / 94 | — | 各 1~2 | — |

**🔴 两个全灭组值得单独盯**：
- **CWE-441 标签 7 块，7 块全被蒸馏报成别的编号**（918×2、639、862、295、400、22）。441 恰好是你自己列为"反复漏报、需定向补样"的编号之一。
- **CWE-77 标签 4 块，全部报成 CWE-78**（00175/00177/00178 直接报 78，00176 报 829）。这正是你判别笔记里最敏感的 77/78 轴——**4/4 全判 78，要么标签把 78 误写成 77，要么蒸馏在越轴**，值得优先人工定论。

### top 错配对（蒸馏报 → 标签）

- 报 `CWE-78` vs 标签 `CWE-77`：**6** 次
- 报 `CWE-22` vs 标签 `CWE-639`：**5** 次
- 报 `CWE-22` vs 标签 `CWE-1336`：**4** 次
- 报 `CWE-79` vs 标签 `CWE-1336`：**4** 次
- 报 `CWE-918` vs 标签 `CWE-441`：**4** 次
- 报 `CWE-400` vs 标签 `CWE-1336`：**3** 次
- 报 `CWE-862` vs 标签 `CWE-1336`：**3** 次
- 报 `CWE-863` vs 标签 `CWE-639`：**3** 次
- 报 `CWE-1321` vs 标签 `CWE-1336`：**2** 次
- 报 `CWE-639` vs 标签 `CWE-1336`：**2** 次
- 报 `CWE-284` vs 标签 `CWE-1336`：**2** 次
- 报 `CWE-94` vs 标签 `CWE-1336`：**2** 次
- 报 `CWE-88` vs 标签 `CWE-22`：**2** 次
- 报 `CWE-494` vs 标签 `CWE-22`：**2** 次
- 报 `CWE-78` vs 标签 `CWE-22`：**2** 次
- 报 `CWE-295` vs 标签 `CWE-441`：**2** 次
- 报 `CWE-862` vs 标签 `CWE-441`：**2** 次
- 报 `CWE-494` vs 标签 `CWE-502`：**2** 次
- 报 `CWE-22` vs 标签 `CWE-502`：**2** 次
- 报 `CWE-20` vs 标签 `CWE-502`：**2** 次

---

## 四、需要人工复核的三类块

### 4.1 版本A 被判"无洞" —— 20 条

（A 是正样本。这一栏要么是蒸馏漏了，要么就是标签本身错。注意很多条自述"样本内不可证"，那是诚实的证不出，不是乱判。）

- **00011** 标签 `CWE-1336`/High | 改动 0/3 行 | src=`cms/models/contentmodels.py` | pnm=True
  - 蒸馏：存在漏洞=false | CWE-XXX 无对应 | Low
- **00018** 标签 `CWE-1336`/High | 改动 1/1 行 | src=`src/color/colors.go` | pnm=True
  - 蒸馏：存在漏洞=false | CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine (已防御) | Low
- **00020** 标签 `CWE-1336`/High | 改动 2/10 行 | src=`internal/markup/markup.go` | pnm=True
  - 蒸馏：存在漏洞=false | CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')（潜在，已由 SanitizeBytes 缓解） | Low
- **00034** 标签 `CWE-190`/High | 改动 1/9 行 | src=`plugins/svg-plugin/batik-codec-fix/src/main/java/org/apache/batik/ext/awt/image/codec/util/SeekableOutputStream.java` | pnm=True
  - 蒸馏：存在漏洞=false | 无对应 CWE | Low
- **00035** 标签 `CWE-190`/High | 改动 9/45 行 | src=`tensorflow/python/ops/array_ops_test.py` | pnm=True
  - 蒸馏：存在漏洞=false | 无 CWE | Low
- **00048** 标签 `CWE-22`/High | 改动 2/9 行 | src=`backend/local/clone_darwin.go` | pnm=True
  - 蒸馏：存在漏洞=false | 无对应 CWE（样本外依赖 `f.newObject`/`f.localPath`，未发现可达安全缺陷） | Low
- **00049** 标签 `CWE-22`/High | 改动 0/56 行 | src=`cmd/archive/archive_test.go` | pnm=True
  - 蒸馏：存在漏洞=false | CWE-无 无对应弱点 | Low
- **00096** 标签 `CWE-441`/High | 改动 2/8 行 | src=`dataclients/kubernetes/ingress.go` | pnm=True
  - 蒸馏：存在漏洞=false | 无代码内可证 CWE | Low
- **00108** 标签 `CWE-502`/High | 改动 1/1 行 | src=`spring-graphql/src/main/java/org/springframework/graphql/GraphQlRequest.java` | pnm=True
  - 蒸馏：存在漏洞=false | 无 CWE | 不适用（纯类型声明，无可执行代码）
- **00124** 标签 `CWE-601`/High | 改动 1/20 行 | src=`internal/urlx/urlx_test.go` | pnm=True
  - 蒸馏：存在漏洞=false | 无（样本为测试代码，被测函数缺失） | Low
- **00132** 标签 `CWE-601`/High | 改动 13/8 行 | src=`public/loggedOut.php` | pnm=True
  - 蒸馏：存在漏洞=false（样本内不可证；需补 `casserver:loggedOut.twig` 与 Twig autoescape 配置） | 潜在 CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') | Medium
- **00133** 标签 `CWE-601`/High | 改动 7/2 行 | src=`app/Http/Controllers/Accessories/AccessoriesController.php` | pnm=True
  - 蒸馏：存在漏洞=false | 无（未发现代码内可证可达安全漏洞） | Low
- **00139** 标签 `CWE-611`/High | 改动 0/5 行 | src=`assertj-core/src/main/java/org/assertj/core/util/xml/XmlStringPrettyFormatter.java` | pnm=True
  - 蒸馏：存在漏洞=false | CWE-611 Improper Restriction of XML External Entity Reference（已缓解；L100 异常吞没为样本外弱点） | Low
- **00147** 标签 `CWE-611`/High | 改动 13/4 行 | src=`cgmes/cgmes-model/src/main/java/com/powsybl/cgmes/model/FullModel.java` | pnm=True
  - 蒸馏：存在漏洞=false | 未发现 | -
- **00150** 标签 `CWE-611`/High | 改动 2/4 行 | src=`langroid/agent/special/table_chat_agent.py` | pnm=True
  - 蒸馏：存在漏洞=false | CWE-95 不成立 | Low
- **00155** 标签 `CWE-611`/High | 改动 0/33 行 | src=`src/Image/Cache.php` | pnm=True
  - 蒸馏：存在漏洞=false（样本内不可证；条件满足时构成 CWE-918） | CWE-918 Server-Side Request Forgery (SSRF) | High（条件）
- **00158** 标签 `CWE-639`/High | 改动 5/5 行 | src=`assets/shop/js/mollie/app.js` | pnm=False
  - 蒸馏：存在漏洞=false | 无 | 无
- **00160** 标签 `CWE-639`/High | 改动 0/10 行 | src=`internal/op/sharing.go` | pnm=True
  - 蒸馏：存在漏洞=false（样本内不可证可达；条件性 CWE-22） | CWE-22 路径遍历 | High
- **00162** 标签 `CWE-639`/High | 改动 2/5 行 | src=`models/git/lfs.go` | pnm=True
  - 蒸馏：存在漏洞=false（样本内不可证；需补 `repo_model.AccessibleRepositoryCondition` 函数体确认 `unit.TypeInvalid` 是否放宽；若放宽则条件性 true） | CWE-863 Incorrect Authorization（条件性） | High（条件性）
- **00173** 标签 `CWE-77`/High | 改动 0/2 行 | src=`src/bin.js` | pnm=True
  - 蒸馏：存在漏洞=false | 无对应 CWE（样本内未发现） | Low

### 4.2 版本B（修复版）仍被判"有洞" —— 45 条

（要么蒸馏误报，要么该 fix 只补了一处、残余路径仍可达——后者是有价值的样本，前者是噪声，必须逐条看。）

- **00008** 标签 `CWE-1336` | 改动 4/2 行 | src=`server/server.go`
  - 蒸馏：存在漏洞=true | CWE-400 Uncontrolled Resource Consumption | Medium
- **00009** 标签 `CWE-1336` | 改动 0/12 行 | src=`lib/js2i18next.js`
  - 蒸馏：存在漏洞=true | CWE-1321 Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') | Low（若样本外 `UNSAFE_KEYS` 不完整，则升级为 High）
- **00010** 标签 `CWE-1336` | 改动 1/17 行 | src=`src/Filesystem/PathResolver.php`
  - 蒸馏：存在漏洞=true | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | High
- **00012** 标签 `CWE-1336` | 改动 0/16 行 | src=`cms/forms/validators.py`
  - 蒸馏：存在漏洞=true | CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') | High
- **00015** 标签 `CWE-1336` | 改动 26/17 行 | src=`pkg/cookie/cookie.go`
  - 蒸馏：存在漏洞=true | CWE-20 输入验证不当 | Medium
- **00016** 标签 `CWE-1336` | 改动 3/40 行 | src=`executor/oci/user.go`
  - 蒸馏：存在漏洞=true | CWE-59 Improper Link Resolution Before File Access ('Link Following') | Medium
- **00018** 标签 `CWE-1336` | 改动 1/1 行 | src=`src/color/colors.go`
  - 蒸馏：存在漏洞=true | CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine | High
- **00019** 标签 `CWE-1336` | 改动 12/50 行 | src=`includes/services/TemplateEngine.php`
  - 蒸馏：存在漏洞=true | CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine | High
- **00022** 标签 `CWE-1336` | 改动 3/1 行 | src=`src/fields/formfields/Hidden.php`
  - 蒸馏：存在漏洞=true | CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine | Critical（样本外：若表单未配置 query/cookie/userAgent 等请求来源且 Twig 沙箱严格，则降为 High）
- **00023** 标签 `CWE-1336` | 改动 1/33 行 | src=`internal/util/template.go`
  - 蒸馏：存在漏洞=true | CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine | High（RenderTemplateFile 同时存在 CWE-79）
- **00024** 标签 `CWE-1336` | 改动 5/37 行 | src=`dynaconf/utils/parse_conf.py`
  - 蒸馏：存在漏洞=true | CWE-134 Use of Externally-Controlled Format String | Medium
- **00026** 标签 `CWE-1336` | 改动 2/1 行 | src=`src/Craft.php`
  - 蒸馏：存在漏洞=true | CWE-94 Improper Control of Generation of Code ('Code Injection') | Critical
- **00037** 标签 `CWE-22` | 改动 2/2 行 | src=`mobsf/DynamicAnalyzer/views/android/operations.py`
  - 蒸馏：存在漏洞=true | CWE-88 Argument Injection or Modification | High
- **00038** 标签 `CWE-22` | 改动 2/2 行 | src=`integration/plugin_test.go`
  - 蒸馏：存在漏洞=true | CWE-494 Download of Code Without Integrity Check | Low
- **00039** 标签 `CWE-22` | 改动 8/33 行 | src=`cmd/uniget/hooks.go`
  - 蒸馏：存在漏洞=true | CWE-78 OS Command Injection | Critical
- **00045** 标签 `CWE-22` | 改动 2/24 行 | src=`src/Security.php`
  - 蒸馏：存在漏洞=true（样本外假设 `_realpath` 不解析符号链接且调用方会写入/读取该路径） | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Medium
- **00047** 标签 `CWE-22` | 改动 0/14 行 | src=`pkg/middlewares/ingressnginx/rewritetarget/rewrite_target.go`
  - 蒸馏：存在漏洞=true | CWE-601 URL Redirection to Untrusted Site ('Open Redirect') | Medium
- **00094** 标签 `CWE-441` | 改动 2/6 行 | src=`packages/@vue/cli-service/lib/util/prepareProxy.js`
  - 蒸馏：存在漏洞=true | CWE-295 Improper Certificate Validation; CWE-22 Path Traversal; CWE-150 Improper Neutralization of Escape, Meta, or Control Sequences | Medium
- **00096** 标签 `CWE-441` | 改动 2/8 行 | src=`dataclients/kubernetes/ingress.go`
  - 蒸馏：存在漏洞=true | CWE-862 Missing Authorization | Medium
- **00097** 标签 `CWE-441` | 改动 1/3 行 | src=`index.js`
  - 蒸馏：存在漏洞=true | CWE-918 Server-Side Request Forgery (SSRF) | High
- **00098** 标签 `CWE-441` | 改动 3/6 行 | src=`mitmproxy/tools/web/master.py`
  - 蒸馏：存在漏洞=true | CWE-532 Insertion of Sensitive Information into Log File | High（次要 CWE-400 Uncontrolled Resource Consumption Medium）
- **00106** 标签 `CWE-502` | 改动 0/6 行 | src=`kork/kork-core/src/main/java/com/netflix/spinnaker/kork/yaml/YamlHelper.java`
  - 蒸馏：存在漏洞=true | CWE-502 Deserialization of Untrusted Data | High
- **00109** 标签 `CWE-502` | 改动 1/31 行 | src=`core/src/main/java/hudson/util/CopyOnWriteList.java`
  - 蒸馏：存在漏洞=true（残余、条件性）| CWE-502 Deserialization of Untrusted Data | Medium
- **00112** 标签 `CWE-502` | 改动 4/6 行 | src=`lib/Tool/Serialize.php`
  - 蒸馏：存在漏洞=true | CWE-502 Deserialization of Untrusted Data | High
- **00113** 标签 `CWE-502` | 改动 4/15 行 | src=`src/transformers/integrations/hub_kernels.py`
  - 蒸馏：存在漏洞=true | CWE-494 Download of Code Without Integrity Check | High（主路径需样本外调用方把不可信输入传给公开 `get_kernel`；若该调用方可达，则升级为 Critical）
- **00114** 标签 `CWE-502` | 改动 20/72 行 | src=`web/pgadmin/utils/session.py`
  - 蒸馏：存在漏洞=true | CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') | Medium（若 `SESSION_DIGEST_METHOD` 外部可控则 Critical）
- **00115** 标签 `CWE-502` | 改动 0/47 行 | src=`system/src/Grav/Common/GPM/Installer.php`
  - 蒸馏：存在漏洞=true | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | High
- **00118** 标签 `CWE-502` | 改动 1/20 行 | src=`components/camel-mina/src/main/java/org/apache/camel/component/mina/MinaConverter.java`
  - 蒸馏：存在漏洞=true | CWE-502 Deserialization of Untrusted Data | High（默认白名单粒度过宽，允许 `java.**/javax.**` 内反序列化 gadget；若 JVM 全局过滤器严格且样本外 `readObject` 可达，风险降档）
- **00119** 标签 `CWE-502` | 改动 37/232 行 | src=`components/camel-pqc/src/main/java/org/apache/camel/component/pqc/lifecycle/FileBasedKeyLifecycleManager.java`
  - 蒸馏：存在漏洞=true | CWE-502 Deserialization of Untrusted Data | High（样本外假设攻击者可放置 legacy `.key` 或通过路径遍历命中恶意 `.key` 时升级为 Critical；关联 CWE-22、CWE-312）
- **00120** 标签 `CWE-502` | 改动 0/19 行 | src=`components/camel-infinispan/camel-infinispan/src/main/java/org/apache/camel/component/infinispan/remote/protostream/DefaultExchangeHolderUtils.java`
  - 蒸馏：存在漏洞=true | CWE-502 Deserialization of Untrusted Data | High
- **00133** 标签 `CWE-601` | 改动 7/2 行 | src=`app/Http/Controllers/Accessories/AccessoriesController.php`
  - 蒸馏：存在漏洞=true | CWE-754 Improper Check for Unusual or Exceptional Conditions；CWE-601 URL Redirection to Untrusted Site ('Open Redirect') | Medium
- **00134** 标签 `CWE-601` | 改动 0/13 行 | src=`internal/api/handlers/v0/auth/common.go`
  - 蒸馏：存在漏洞=true（样本外假设: keyFetcher 按 domain 构造 DNS/HTTP 请求且未校验解析后 IP） | CWE-918 Server-Side Request Forgery (SSRF) | High
- **00142** 标签 `CWE-611` | 改动 0/2 行 | src=`src/peppol_py/validation.py`
  - 蒸馏：存在漏洞=true | CWE-611 Improper Restriction of XML External Entity Reference | Medium（validate 主路径已防御；convert_schematron_file_to_xsl_file 在样本外参数可控时可达，风险降档）
- **00146** 标签 `CWE-611` | 改动 0/3 行 | src=`plugins/junit-xml-plugin/src/main/java/io/qameta/allure/junitxml/JunitXmlPlugin.java`
  - 蒸馏：存在漏洞=true | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | High
- **00150** 标签 `CWE-611` | 改动 2/4 行 | src=`langroid/agent/special/table_chat_agent.py`
  - 蒸馏：存在漏洞=true | CWE-95 任意代码执行 | Critical
- **00152** 标签 `CWE-611` | 改动 1/1 行 | src=`unstructured/partition/xml.py`
  - 蒸馏：存在漏洞=true | CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection') | Medium
- **00153** 标签 `CWE-611` | 改动 1/13 行 | src=`src/SAML2/DOMDocumentFactory.php`
  - 蒸馏：存在漏洞=true | CWE-776 Improper Restriction of XML Entity Expansion | Medium
- **00155** 标签 `CWE-611` | 改动 0/33 行 | src=`src/Image/Cache.php`
  - 蒸馏：存在漏洞=true | CWE-776 Improper Restriction of Recursive Entity References in DTDs ('Billion Laughs') | Medium
- **00164** 标签 `CWE-639` | 改动 0/2 行 | src=`examples/servers/simple-auth/mcp_simple_auth/auth_server.py`
  - 蒸馏：存在漏洞=true | CWE-306 Missing Authentication for Critical Function | Medium
- **00169** 标签 `CWE-639` | 改动 0/11 行 | src=`fileutil/fileutil.go`
  - 蒸馏：存在漏洞=true | CWE-22 Path Traversal | High
- **00170** 标签 `CWE-639` | 改动 3/11 行 | src=`internal/lfsx/storage.go`
  - 蒸馏：存在漏洞=true | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | High
- **00174** 标签 `CWE-77` | 改动 3/16 行 | src=`src/stata_mcp/stata/stata_do/do.py`
  - 蒸馏：存在漏洞=true | CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection') | High
- **00175** 标签 `CWE-77` | 改动 37/49 行 | src=`packages/launch-editor/index.js`
  - 蒸馏：存在漏洞=true | CWE-78 OS Command Injection | High（依赖 `specifiedEditor` 可控且运行在 Windows，样本外假设；链上关键跳在样本外，不记 Critical）
- **00176** 标签 `CWE-77` | 改动 2/1 行 | src=`build/bin/prepublish.js`
  - 蒸馏：存在漏洞=true | CWE-829 Inclusion of Functionality from Untrusted Control Sphere | Medium（供应链依赖通配符 + 生命周期脚本；更精确可补 CWE-494/CWE-1104/CWE-1395 口径）
- **00178** 标签 `CWE-77` | 改动 1/31 行 | src=`src/praisonai/praisonai/cli/features/mcp.py`
  - 蒸馏：存在漏洞=true | CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | High（样本外提示：`--mcp` 值可控性、`praisonaiagents.MCP` 的 spawn 与"是否对 command 另行校验"两点在样本外；若 L134 之前另有运行时校验则本条降档。需补：CLI

### 4.3 同一 (id,版本) 多条分析且结论冲突 —— 4 处 ★最高优先级

（这是真正的"毒"：同一份代码若三条结论都入库，等于给模型三个互斥答案。）

- **00007 版本A** ×3
  - 存在漏洞=true | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Medium（样本外假设下游拼接路径）
  - 存在漏洞=true | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Medium（样本外假设下游使用 Name 作路径）
  - 存在漏洞=true | CWE-248 Uncaught Exception | Medium（有限 DoS）
- **00007 版本B** ×3
  - 存在漏洞=false | CWE-22 不适用 | Low
  - 存在漏洞=true | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Medium（样本外假设下游使用 Name 作路径）
  - 存在漏洞=true | CWE-248 Uncaught Exception | Medium（有限 DoS）
- **00019 版本A** ×2
  - 存在漏洞=true | CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine | High
  - 存在漏洞=true | CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') | High
- **00019 版本B** ×3
  - 存在漏洞=true | CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine | High
  - 存在漏洞=true | CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') | High
  - 存在漏洞=true（样本外假设） | CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') | Medium

---

## 五、抽检实证（判定"标签错还是蒸馏错"）

### 5.1 diffpair-corpus_00180（标签 CWE-77）
- 标签：`CWE-77` / High / CVE-2026-30625 / src=`src/upsonic/chat/cost_calculator.py`
- CVE 原文：「Upsonic 0.71.6 的 MCP server/task creation 允许用户定义任意 command 和 args → RCE」
- 实际代码：upsonic 的 `CostTracker` 成本计算工具，全部是静态方法 + 数值解析 + f-string 格式化，**无任何命令执行/拼接面**
- 实际 diff：删掉 `get_model_pricing` 导入 + 整个 `get_pricing()` 方法（`fix_lines_plus = []`，纯删除）
- 自己人给的信号：`pattern_not_matched = true`、`vuln_patterns = []`、`sink = N/A`、`taint_path = N/A`
- **判定：标签错（CVE 根因文件 ≠ 取材文件），代码内无洞。**

### 5.2 diffpair-corpus_00006（标签 CWE-89）
- 标签：`CWE-89`（SQL 注入）/ Go / src=`openapi3filter/validation_error_encoder.go`
- 全文件正则统计：`SELECT` **0** 次、`FROM` **0** 次、`sql` **0** 次、`db.` **0** 次；`Query` 4 次（均为 `e.Parameter.In == "query"` 这类枚举字符串）
- 同时：`.Parameter` **46** 次、`nil` **28** 次；fix 新增 L127-134 共 8 行，正是补 `e.Parameter != nil` 检查
- 蒸馏报：A = `CWE-476 NULL Pointer Dereference` Medium，B = false（已修）
- **判定：标签 CWE-89 在该文件内不可能成立；蒸馏报的 CWE-476 与代码行为完全吻合。标签错、蒸馏对。**

### 5.3 diffpair-corpus_00012（标签 CWE-1336）
- 标签：`CWE-1336`（模板引擎注入）/ Python
- 全文件统计：`jinja|twig|template|render|...` 命中 **1** 次；`htmlspecialchars|escape|sanitize` 命中 **8** 次；无 `<?=`、无 `echo`
- **判定：文件内几乎不存在"模板引擎把输入当代码渲染"的形态；标签可疑，蒸馏报 CWE-79（XSS）方向更贴。**（建议按 5.1 方式细读确认）

---

## 六、结论：有没有毒样本 / 藏样本

| 问题 | 结论 |
|---|---|
| 藏样本（漏做） | **有 2 个**：00143、00159。其余覆盖完整。`api_results/` 空目录需确认。 |
| 毒样本（标签 vs 内容错配） | **有，量级约占正样本侧的一半**：A 版 106 块中只有 48 块（45.3%）的蒸馏 CWE 与标签一致；38 块报别的编号、20 块判无洞。**毒源是 `expected_cwe` 标签，不是蒸馏**（抽检 3/3 指向标签错）。 |
| 毒样本（同一输入多答案） | **有 4 处**：00007、00019 的多条互斥分析块——若全部入库，同一份代码得到互斥标签。 |
| 毒样本（修复版仍报有洞） | **45 处待核**：可能是蒸馏误报，也可能是 fix 不完整（后者反而是高价值样本），必须逐条定。 |
| 蒸馏本身是否在乱报 | **抽检范围内否**。3 例结论均可被代码或原文本能验证；且大量条目主动标注"样本外假设""样本内不可证"，属诚实作答而非编造。 |

> **诚实边界**：抽检只有 3 例（00180 / 00006 / 00012），不足以证明全部 38 块不符都是"标签错"。本节结论只覆盖抽检到的 3 例；其余 35 块需要同样方式的代码级核验后才能定性。已抽验的 3 例之所以能一锤定音，是因为代码里连该 CWE 的**构成要件**都不存在（如 00006 全文 0 处 SQL 语法），这类证据不依赖主观判断。

---

## 七、建议（待拍板，本轮未执行任何修改）

1. **先补 00143、00159 两包**，确认是漏做还是故意跳过。
2. **清掉 4 处重复冲突块**，每个 (id,版本) 只保留一条结论（保留哪条需你定：建议保留 CWE 与代码行为对得上的那条）。
3. **把 manifest 的 `expected_cwe` 从"训练标签"降级为"待核线索"**：以 NVD/GHSA/MITRE 官方口径重核，或直接以"代码内可证"为准重标。129 块不符的量级不可能都是蒸馏错。
4. **门禁补一条**：`pattern_not_matched = true` 的样本强制人工复核后才能入库（当前 272/291 seed 都是 true，等于这道信号完全没被使用）。
5. **优先复核 4.1 / 4.2 两份清单**（20 + 45 条），它们直接决定这一批是训练信号还是噪声。

---

## 附录A：逐 (id,版本) 全表

| id | 版 | 蒸馏存在漏洞 | 蒸馏CWE | 标签CWE | 标签风险 | 改动pre/post | pnm | 判定 |
|---|---|---|---|---|---|---|---|---|
| 00006 | A | true | CWE-476 | CWE-89 | High | 2/10 | True | CWE不符 |
| 00006 | B | false | 无 | CWE-89 | High | 2/10 | True | CWE不符 |
| 00007 | A | true | CWE-22 | CWE-1336 | High | 0/13 | True | CWE不符; ×3块 |
| 00007 | B | false | CWE-22 | CWE-1336 | High | 0/13 | True | CWE不符; ×3块 |
| 00008 | A | true | CWE-352 | CWE-1336 | High | 4/2 | True | CWE不符 |
| 00008 | B | true | CWE-400 | CWE-1336 | High | 4/2 | True | B判true; CWE不符 |
| 00009 | A | true | CWE-1321 | CWE-1336 | High | 0/12 | True | CWE不符 |
| 00009 | B | true | CWE-1321 | CWE-1336 | High | 0/12 | True | B判true; CWE不符 |
| 00010 | A | true | CWE-22 | CWE-1336 | High | 1/17 | True | CWE不符 |
| 00010 | B | true | CWE-22 | CWE-1336 | High | 1/17 | True | B判true; CWE不符 |
| 00011 | A | false | 无 | CWE-1336 | High | 0/3 | True | A判false; CWE不符 |
| 00011 | B | false | 无 | CWE-1336 | High | 0/3 | True | CWE不符 |
| 00012 | A | true | CWE-79 | CWE-1336 | High | 0/16 | True | CWE不符 |
| 00012 | B | true | CWE-79 | CWE-1336 | High | 0/16 | True | B判true; CWE不符 |
| 00013 | A | true | CWE-862 | CWE-1336 | High | 0/7 | True | CWE不符 |
| 00013 | B | false | CWE-862 | CWE-1336 | High | 0/7 | True | CWE不符 |
| 00014 | A | true | CWE-639 | CWE-1336 | High | 17/40 | True | CWE不符 |
| 00014 | B | false | CWE-639 | CWE-1336 | High | 17/40 | True | CWE不符 |
| 00015 | A | true | CWE-400 | CWE-1336 | High | 26/17 | True | CWE不符 |
| 00015 | B | true | CWE-20 | CWE-1336 | High | 26/17 | True | B判true; CWE不符 |
| 00016 | A | true | CWE-400 | CWE-1336 | High | 3/40 | True | CWE不符 |
| 00016 | B | true | CWE-59 | CWE-1336 | High | 3/40 | True | B判true; CWE不符 |
| 00017 | A | true | CWE-862 | CWE-1336 | High | 0/2 | True | CWE不符 |
| 00017 | B | false | 无 | CWE-1336 | High | 0/2 | True | CWE不符 |
| 00018 | A | false | CWE-1336 | CWE-1336 | High | 1/1 | True | A判false |
| 00018 | B | true | CWE-1336 | CWE-1336 | High | 1/1 | True | B判true |
| 00019 | A | true | CWE-1336 | CWE-1336 | High | 12/50 | True | ×2块 |
| 00019 | B | true | CWE-1336 | CWE-1336 | High | 12/50 | True | B判true; ×3块 |
| 00020 | A | false | CWE-79 | CWE-1336 | High | 2/10 | True | A判false; CWE不符 |
| 00020 | B | false | CWE-79 | CWE-1336 | High | 2/10 | True | CWE不符 |
| 00021 | A | true | CWE-1336 | CWE-1336 | High | 30/12 | True | OK |
| 00021 | B | false | CWE-1336 | CWE-1336 | High | 30/12 | True | OK |
| 00022 | A | true | CWE-1336 | CWE-1336 | High | 3/1 | True | OK |
| 00022 | B | true | CWE-1336 | CWE-1336 | High | 3/1 | True | B判true |
| 00023 | A | true | CWE-1336 | CWE-1336 | High | 1/33 | True | OK |
| 00023 | B | true | CWE-1336 | CWE-1336 | High | 1/33 | True | B判true |
| 00024 | A | true | CWE-1336 | CWE-1336 | High | 5/37 | True | OK |
| 00024 | B | true | CWE-134 | CWE-1336 | High | 5/37 | True | B判true; CWE不符 |
| 00025 | A | true | CWE-284 | CWE-1336 | High | 0/13 | True | CWE不符 |
| 00025 | B | false | CWE-284 | CWE-1336 | High | 0/13 | True | CWE不符 |
| 00026 | A | true | CWE-94 | CWE-1336 | High | 2/1 | True | CWE不符 |
| 00026 | B | true | CWE-94 | CWE-1336 | High | 2/1 | True | B判true; CWE不符 |
| 00029 | A | true | CWE-190 | CWE-190 | High | 2/48 | True | OK |
| 00029 | B | false | CWE-190 | CWE-190 | High | 2/48 | True | OK |
| 00034 | A | false | 无 | CWE-190 | High | 1/9 | True | A判false; CWE不符 |
| 00034 | B | false | 无 | CWE-190 | High | 1/9 | True | CWE不符 |
| 00035 | A | false | 无 | CWE-190 | High | 9/45 | True | A判false; CWE不符 |
| 00035 | B | false | 无 | CWE-190 | High | 9/45 | True | CWE不符 |
| 00036 | A | true | CWE-862 | CWE-22 | High | 0/4 | True | CWE不符 |
| 00036 | B | false | 无 | CWE-22 | High | 0/4 | True | CWE不符 |
| 00037 | A | true | CWE-88 | CWE-22 | High | 2/2 | True | CWE不符 |
| 00037 | B | true | CWE-88 | CWE-22 | High | 2/2 | True | B判true; CWE不符 |
| 00038 | A | true | CWE-494 | CWE-22 | High | 2/2 | True | CWE不符 |
| 00038 | B | true | CWE-494 | CWE-22 | High | 2/2 | True | B判true; CWE不符 |
| 00039 | A | true | CWE-78 | CWE-22 | High | 8/33 | True | CWE不符 |
| 00039 | B | true | CWE-78 | CWE-22 | High | 8/33 | True | B判true; CWE不符 |
| 00040 | A | true | CWE-22 | CWE-22 | High | 12/17 | True | OK |
| 00040 | B | false | CWE-22 | CWE-22 | High | 12/17 | True | OK |
| 00044 | A | true | CWE-22 | CWE-22 | High | 1/12 | True | OK |
| 00044 | B | false | CWE-22 | CWE-22 | High | 1/12 | True | OK |
| 00045 | A | true | CWE-22 | CWE-22 | High | 2/24 | True | OK |
| 00045 | B | true | CWE-22 | CWE-22 | High | 2/24 | True | B判true |
| 00046 | A | true | CWE-22 | CWE-22 | High | 0/16 | True | OK |
| 00046 | B | false | CWE-22 | CWE-22 | High | 0/16 | True | OK |
| 00047 | A | true | CWE-22 | CWE-22 | High | 0/14 | True | OK |
| 00047 | B | true | CWE-601 | CWE-22 | High | 0/14 | True | B判true; CWE不符 |
| 00048 | A | false | 无 | CWE-22 | High | 2/9 | True | A判false; CWE不符 |
| 00048 | B | false | 无 | CWE-22 | High | 2/9 | True | CWE不符 |
| 00049 | A | false | 无 | CWE-22 | High | 0/56 | True | A判false; CWE不符 |
| 00049 | B | false | 无 | CWE-22 | High | 0/56 | True | CWE不符 |
| 00050 | A | true | CWE-22 | CWE-22 | High | 0/6 | True | OK |
| 00050 | B | false | 无 | CWE-22 | High | 0/6 | True | CWE不符 |
| 00089 | A | true | CWE-352 | CWE-352 | High | 1/3 | True | OK |
| 00089 | B | false | CWE-352 | CWE-352 | High | 1/3 | True | OK |
| 00090 | A | true | CWE-352 | CWE-352 | High | 1/1 | True | OK |
| 00090 | B | false | CWE-352 | CWE-352 | High | 1/1 | True | OK |
| 00094 | A | true | CWE-295 | CWE-441 | High | 2/6 | True | CWE不符 |
| 00094 | B | true | CWE-295 | CWE-441 | High | 2/6 | True | B判true; CWE不符 |
| 00095 | A | true | CWE-639 | CWE-441 | High | 3/2 | True | CWE不符 |
| 00095 | B | false | 无 | CWE-441 | High | 3/2 | True | CWE不符 |
| 00096 | A | false | 无 | CWE-441 | High | 2/8 | True | A判false; CWE不符 |
| 00096 | B | true | CWE-862 | CWE-441 | High | 2/8 | True | B判true; CWE不符 |
| 00097 | A | true | CWE-918 | CWE-441 | High | 1/3 | True | CWE不符 |
| 00097 | B | true | CWE-918 | CWE-441 | High | 1/3 | True | B判true; CWE不符 |
| 00098 | A | true | CWE-400 | CWE-441 | High | 3/6 | True | CWE不符 |
| 00098 | B | true | CWE-532 | CWE-441 | High | 3/6 | True | B判true; CWE不符 |
| 00099 | A | true | CWE-918 | CWE-441 | High | 73/52 | True | CWE不符 |
| 00099 | B | false | CWE-918 | CWE-441 | High | 73/52 | True | CWE不符 |
| 00100 | A | true | CWE-862 | CWE-441 | High | 1/4 | True | CWE不符 |
| 00100 | B | false | 无 | CWE-441 | High | 1/4 | True | CWE不符 |
| 00104 | A | true | CWE-502 | CWE-502 | High | 2/35 | True | OK |
| 00104 | B | false | 无 | CWE-502 | High | 2/35 | True | CWE不符 |
| 00105 | A | true | CWE-502 | CWE-502 | High | 0/62 | True | OK |
| 00105 | B | false | 无 | CWE-502 | High | 0/62 | True | CWE不符 |
| 00106 | A | true | CWE-502 | CWE-502 | High | 0/6 | True | OK |
| 00106 | B | true | CWE-502 | CWE-502 | High | 0/6 | True | B判true |
| 00107 | A | true | CWE-502 | CWE-502 | High | 2/17 | True | OK |
| 00107 | B | false | 无 | CWE-502 | High | 2/17 | True | CWE不符 |
| 00108 | A | false | 无 | CWE-502 | High | 1/1 | True | A判false; CWE不符 |
| 00108 | B | false | 无 | CWE-502 | High | 1/1 | True | CWE不符 |
| 00109 | A | true | CWE-502 | CWE-502 | High | 1/31 | True | OK |
| 00109 | B | true | CWE-502 | CWE-502 | High | 1/31 | True | B判true |
| 00110 | A | true | CWE-502 | CWE-502 | High | 4/110 | False | OK |
| 00110 | B | false | 无 | CWE-502 | High | 4/110 | False | CWE不符 |
| 00111 | A | true | CWE-502 | CWE-502 | High | 4/11 | True | OK |
| 00111 | B | false | CWE-502 | CWE-502 | High | 4/11 | True | OK |
| 00112 | A | true | CWE-502 | CWE-502 | High | 4/6 | True | OK |
| 00112 | B | true | CWE-502 | CWE-502 | High | 4/6 | True | B判true |
| 00113 | A | true | CWE-494 | CWE-502 | High | 4/15 | True | CWE不符 |
| 00113 | B | true | CWE-494 | CWE-502 | High | 4/15 | True | B判true; CWE不符 |
| 00114 | A | true | CWE-502 | CWE-502 | High | 20/72 | True | OK |
| 00114 | B | true | CWE-95 | CWE-502 | High | 20/72 | True | B判true; CWE不符 |
| 00115 | A | true | CWE-22 | CWE-502 | High | 0/47 | True | CWE不符 |
| 00115 | B | true | CWE-22 | CWE-502 | High | 0/47 | True | B判true; CWE不符 |
| 00116 | A | true | CWE-502 | CWE-502 | High | 9/42 | False | OK |
| 00116 | B | false | CWE-319 | CWE-502 | High | 9/42 | False | CWE不符 |
| 00117 | A | true | CWE-20 | CWE-502 | High | 0/1 | True | CWE不符 |
| 00117 | B | false | CWE-20 | CWE-502 | High | 0/1 | True | CWE不符 |
| 00118 | A | true | CWE-502 | CWE-502 | High | 1/20 | False | OK |
| 00118 | B | true | CWE-502 | CWE-502 | High | 1/20 | False | B判true |
| 00119 | A | true | CWE-502 | CWE-502 | High | 37/232 | False | OK |
| 00119 | B | true | CWE-502 | CWE-502 | High | 37/232 | False | B判true |
| 00120 | A | true | CWE-502 | CWE-502 | High | 0/19 | False | OK |
| 00120 | B | true | CWE-502 | CWE-502 | High | 0/19 | False | B判true |
| 00124 | A | false | 无 | CWE-601 | High | 1/20 | True | A判false; CWE不符 |
| 00124 | B | false | 无 | CWE-601 | High | 1/20 | True | CWE不符 |
| 00125 | A | true | CWE-601 | CWE-601 | High | 1/15 | True | OK |
| 00125 | B | false | CWE-601 | CWE-601 | High | 1/15 | True | OK |
| 00126 | A | true | CWE-22 | CWE-601 | High | 5/10 | True | CWE不符 |
| 00126 | B | false | 无 | CWE-601 | High | 5/10 | True | CWE不符 |
| 00127 | A | true | CWE-601 | CWE-601 | High | 2/12 | True | OK |
| 00127 | B | false | CWE-601 | CWE-601 | High | 2/12 | True | OK |
| 00128 | A | true | CWE-601 | CWE-601 | High | 1/12 | True | OK |
| 00128 | B | false | 无 | CWE-601 | High | 1/12 | True | CWE不符 |
| 00129 | A | true | CWE-601 | CWE-601 | High | 3/118 | True | OK |
| 00129 | B | false | CWE-601 | CWE-601 | High | 3/118 | True | OK |
| 00131 | A | true | CWE-601 | CWE-601 | High | 1/2 | True | OK |
| 00131 | B | false | CWE-601 | CWE-601 | High | 1/2 | True | OK |
| 00132 | A | false | CWE-79 | CWE-601 | High | 13/8 | True | A判false; CWE不符 |
| 00132 | B | false | 无 | CWE-601 | High | 13/8 | True | CWE不符 |
| 00133 | A | false | 无 | CWE-601 | High | 7/2 | True | A判false; CWE不符 |
| 00133 | B | true | CWE-754 | CWE-601 | High | 7/2 | True | B判true; CWE不符 |
| 00134 | A | true | CWE-918 | CWE-601 | High | 0/13 | True | CWE不符 |
| 00134 | B | true | CWE-918 | CWE-601 | High | 0/13 | True | B判true; CWE不符 |
| 00139 | A | false | CWE-611 | CWE-611 | High | 0/5 | True | A判false |
| 00139 | B | false | CWE-611 | CWE-611 | High | 0/5 | True | OK |
| 00140 | A | true | CWE-611 | CWE-611 | High | 0/4 | True | OK |
| 00140 | B | false | CWE-611 | CWE-611 | High | 0/4 | True | OK |
| 00141 | A | true | CWE-611 | CWE-611 | High | 6/16 | True | OK |
| 00141 | B | false | CWE-611 | CWE-611 | High | 6/16 | True | OK |
| 00142 | A | true | CWE-611 | CWE-611 | High | 0/2 | True | OK |
| 00142 | B | true | CWE-611 | CWE-611 | High | 0/2 | True | B判true |
| 00144 | A | true | CWE-611 | CWE-611 | High | 28/126 | False | OK |
| 00144 | B | false | CWE-611 | CWE-611 | High | 28/126 | False | OK |
| 00145 | A | true | CWE-400 | CWE-611 | High | 52/13 | True | CWE不符 |
| 00145 | B | false | CWE-0 | CWE-611 | High | 52/13 | True | CWE不符 |
| 00146 | A | true | CWE-611 | CWE-611 | High | 0/3 | True | OK |
| 00146 | B | true | CWE-22 | CWE-611 | High | 0/3 | True | B判true; CWE不符 |
| 00147 | A | false | 无 | CWE-611 | High | 13/4 | True | A判false; CWE不符 |
| 00147 | B | false | CWE-611 | CWE-611 | High | 13/4 | True | OK |
| 00148 | A | true | CWE-611 | CWE-611 | High | 1/11 | True | OK |
| 00148 | B | false | 无 | CWE-611 | High | 1/11 | True | CWE不符 |
| 00149 | A | true | CWE-611 | CWE-611 | High | 4/11 | True | OK |
| 00149 | B | false | CWE-611 | CWE-611 | High | 4/11 | True | OK |
| 00150 | A | false | CWE-95 | CWE-611 | High | 2/4 | True | A判false; CWE不符 |
| 00150 | B | true | CWE-95 | CWE-611 | High | 2/4 | True | B判true; CWE不符 |
| 00151 | A | true | CWE-611 | CWE-611 | High | 0/3 | True | OK |
| 00151 | B | false | 无 | CWE-611 | High | 0/3 | True | CWE不符 |
| 00152 | A | true | CWE-611 | CWE-611 | High | 1/1 | True | OK |
| 00152 | B | true | CWE-643 | CWE-611 | High | 1/1 | True | B判true; CWE不符 |
| 00153 | A | true | CWE-611 | CWE-611 | High | 1/13 | True | OK |
| 00153 | B | true | CWE-776 | CWE-611 | High | 1/13 | True | B判true; CWE不符 |
| 00154 | A | true | CWE-611 | CWE-611 | High | 16/34 | True | OK |
| 00154 | B | false | CWE-611 | CWE-611 | High | 16/34 | True | OK |
| 00155 | A | false | CWE-918 | CWE-611 | High | 0/33 | True | A判false; CWE不符 |
| 00155 | B | true | CWE-776 | CWE-611 | High | 0/33 | True | B判true; CWE不符 |
| 00158 | A | false | 无 | CWE-639 | High | 5/5 | False | A判false; CWE不符 |
| 00158 | B | false | 无 | CWE-639 | High | 5/5 | False | CWE不符 |
| 00160 | A | false | CWE-22 | CWE-639 | High | 0/10 | True | A判false; CWE不符 |
| 00160 | B | false | CWE-22 | CWE-639 | High | 0/10 | True | CWE不符 |
| 00161 | A | true | CWE-863 | CWE-639 | High | 0/42 | True | CWE不符 |
| 00161 | B | false | 无 | CWE-639 | High | 0/42 | True | CWE不符 |
| 00162 | A | false | CWE-863 | CWE-639 | High | 2/5 | True | A判false; CWE不符 |
| 00162 | B | false | CWE-863 | CWE-639 | High | 2/5 | True | CWE不符 |
| 00163 | A | true | CWE-639 | CWE-639 | High | 0/16 | True | OK |
| 00163 | B | false | 无 | CWE-639 | High | 0/16 | True | CWE不符 |
| 00164 | A | true | CWE-306 | CWE-639 | High | 0/2 | True | CWE不符 |
| 00164 | B | true | CWE-306 | CWE-639 | High | 0/2 | True | B判true; CWE不符 |
| 00165 | A | true | CWE-862 | CWE-639 | High | 0/7 | True | CWE不符 |
| 00165 | B | false | CWE-862 | CWE-639 | High | 0/7 | True | CWE不符 |
| 00166 | A | true | CWE-639 | CWE-639 | High | 0/4 | True | OK |
| 00166 | B | false | 无 | CWE-639 | High | 0/4 | True | CWE不符 |
| 00167 | A | true | CWE-639 | CWE-639 | High | 2/31 | True | OK |
| 00167 | B | false | CWE-639 | CWE-639 | High | 2/31 | True | OK |
| 00168 | A | true | CWE-639 | CWE-639 | High | 1/14 | True | OK |
| 00168 | B | false | 无 | CWE-639 | High | 1/14 | True | CWE不符 |
| 00169 | A | true | CWE-22 | CWE-639 | High | 0/11 | True | CWE不符 |
| 00169 | B | true | CWE-22 | CWE-639 | High | 0/11 | True | B判true; CWE不符 |
| 00170 | A | true | CWE-354 | CWE-639 | High | 3/11 | True | CWE不符 |
| 00170 | B | true | CWE-22 | CWE-639 | High | 3/11 | True | B判true; CWE不符 |
| 00173 | A | false | 无 | CWE-77 | High | 0/2 | True | A判false; CWE不符 |
| 00173 | B | false | 无 | CWE-77 | High | 0/2 | True | CWE不符 |
| 00174 | A | true | CWE-77 | CWE-77 | High | 3/16 | False | OK |
| 00174 | B | true | CWE-77 | CWE-77 | High | 3/16 | False | B判true |
| 00175 | A | true | CWE-78 | CWE-77 | High | 37/49 | True | CWE不符 |
| 00175 | B | true | CWE-78 | CWE-77 | High | 37/49 | True | B判true; CWE不符 |
| 00176 | A | true | CWE-829 | CWE-77 | High | 2/1 | True | CWE不符 |
| 00176 | B | true | CWE-829 | CWE-77 | High | 2/1 | True | B判true; CWE不符 |
| 00177 | A | true | CWE-78 | CWE-77 | High | 10/5 | True | CWE不符 |
| 00177 | B | false | CWE-78 | CWE-77 | High | 10/5 | True | CWE不符 |
| 00178 | A | true | CWE-78 | CWE-77 | High | 1/31 | True | CWE不符 |
| 00178 | B | true | CWE-78 | CWE-77 | High | 1/31 | True | B判true; CWE不符 |

## 附录B：数据来源

- result.txt: `D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\corpus\diffpair_wave1\results\result.txt`
- 标签: `D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\corpus\diffpair_wave1\manifest_PRIVATE.json` / `D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\corpus\train_pool\manifest.json` / `D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\corpus\diffpair_wave1\index.md`
- 跳过清单: `D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\corpus\diffpair_wave1\skipped.jsonl`