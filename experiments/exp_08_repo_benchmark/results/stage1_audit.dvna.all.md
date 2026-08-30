# Stage 1 候选审计清单 —— appsecco/dvna

**审计统计**：OK 4 · A 盲区 3 · B 类型错标 4（A/B 逐条归因后写入工具层文档修复）


四类问题：A 盲区（该产出没产出）/ B 类型错标 / C 无关候选 / D 剔除存疑

## core/appHandler.js（原始候选 14 → 最终 9）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-89 | 10 | OK（候选覆盖且类型对） | semgrep·models.semgrep_rules.javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection·L11 | — |
| CWE-78 | 39 | OK（候选覆盖且类型对） | taint_tracker·Command Injection·L39 | — |
| CWE-639 | 107 | B 候选在但类型错标 | taint_tracker·Path Traversal·L107<br>taint_tracker·Path Traversal·L107 | — |
| CWE-639 | 144 | B 候选在但类型错标 | taint_tracker·Server-Side Template Injection·L145<br>taint_tracker·Server-Side Template Injection·L145<br>taint_tracker·Path Traversal·L145 | — |
| CWE-601 | 188 | OK（候选覆盖且类型对） | prefilter+semgrep·models.semgrep_rules.javascript.express.security.audit.express-open-redirect.express-open-redirect·L188 | — |
| CWE-95 | 197 | B 候选在但类型错标 | taint_tracker·Code Injection·L196<br>taint_tracker·Server-Side Template Injection·L196 | — |
| CWE-502 | 218 | OK（候选覆盖且类型对） | semgrep·models.semgrep_rules.javascript.express.security.audit.express-third-party-object-deserialization.express-third-party-object-deserialization·L218 | — |
| CWE-611 | 235 | B 候选在但类型错标 | semgrep·models.semgrep_rules.javascript.express.security.audit.express-libxml-noent.express-libxml-noent·L235 | — |
| CWE-200 | 207 | A 盲区（零候选） | — | — |

### 重复候选（同规则+同类型+同行多报，去重失败信号）

- taint_tracker·Path Traversal·L107
- taint_tracker·Server-Side Template Injection·L145

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | taint_tracker | taint_tracker:Command Injection | Command Injection | 39 | critical |
| 进裁决 | taint_tracker | taint_tracker:Path Traversal | Path Traversal | 107 | high |
| 进裁决 | taint_tracker | taint_tracker:Path Traversal | Path Traversal | 107 | high |
| 进裁决 | taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 145 | high |
| 进裁决 | taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 145 | high |
| 去重合并 | taint_tracker | taint_tracker:Path Traversal | Path Traversal | 145 | high |
| 进裁决 | taint_tracker | taint_tracker:Code Injection | Code Injection | 196 | critical |
| 去重合并 | taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 196 | high |
| 去重合并 | prefilter | open_redirect | Open Redirect | 0 | medium |
| 进裁决 | prefilter | timing_unsafe_compare | Timing Attack | 0 | medium |
| 进裁决 | semgrep | models.semgrep_rules.javascript.sequeliz | models.semgrep_rules.javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | 11 | high |
| 进裁决 | prefilter+semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-open-redirect.express-open-redirect | 188 | medium |
| 进裁决 | semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-third-party-object-deserialization.express-third-party-object-deserialization | 218 | medium |
| 进裁决 | semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-libxml-noent.express-libxml-noent | 235 | high |

## core/authHandler.js（原始候选 4 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-640 | 49 | A 盲区（零候选） | — | — |
| CWE-330 | 78 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 43 | TaintTracker AST 污点分析定位的同文件 source→sink  | 形态核验通过 |
| taint_tracker | taint_tracker:Path Traversal | Path Traversal | 72 | TaintTracker AST 污点分析定位的同文件 source→sink  | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 43 | high |
| 去重合并 | taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 71 | high |
| 进裁决 | taint_tracker | taint_tracker:Path Traversal | Path Traversal | 72 | high |
| 进裁决 | prefilter | timing_unsafe_compare | Timing Attack | 0 | medium |

## routes/app.js（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 22 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_邻行形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 22 | high |

## server.js（原始候选 7 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | models.semgrep_rules.javascript.express. | Hardcoded Credentials | 24 | A hard-coded credential was detected. It | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 被剔除/抑制 | semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-cookie-settings.express-cookie-session-default-name | 23 | medium |
| 被剔除/抑制 | semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-domain | 23 | medium |
| 被剔除/抑制 | semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-expires | 23 | medium |
| 被剔除/抑制 | semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-httponly | 23 | medium |
| 被剔除/抑制 | semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-path | 23 | medium |
| 被剔除/抑制 | semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-secure | 23 | medium |
| 进裁决 | semgrep | models.semgrep_rules.javascript.express. | Hardcoded Credentials | 24 | medium |

## config/server.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## config/db.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## core/passport.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## models/index.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## models/user.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## models/product.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
