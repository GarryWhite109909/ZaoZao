# Stage 1 候选审计清单 —— appsecco/dvna

**审计统计**：OK 5 · A 盲区 4 · B 类型错标 2（A/B 逐条归因后写入工具层文档修复）


四类问题：A 盲区（该产出没产出）/ B 类型错标 / C 无关候选 / D 剔除存疑

## core/appHandler.js（原始候选 12 → 最终 7）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-89 | 10 | OK（候选覆盖且类型对） | semgrep+taint_tracker·SQL Injection·L11<br>semgrep·SQL Injection·L11 | — |
| CWE-78 | 39 | OK（候选覆盖且类型对） | prefilter+taint_tracker·Command Injection·L39<br>taint_tracker·Command Injection·L39<br>prefilter·Command Injection·L39 | — |
| CWE-639 | 107 | A 盲区（零候选） | — | — |
| CWE-639 | 144 | A 盲区（零候选） | — | — |
| CWE-601 | 188 | OK（候选覆盖且类型对） | prefilter+semgrep+taint_tracker·Open Redirect·L188<br>semgrep·Open Redirect·L188 | — |
| CWE-95 | 197 | B 候选在但类型错标 | taint_tracker·Code Injection·L196 | — |
| CWE-502 | 218 | OK（候选覆盖且类型对） | semgrep·Insecure Deserialization·L218 | — |
| CWE-611 | 235 | OK（候选覆盖且类型对） | semgrep·XXE·L235 | — |
| CWE-200 | 207 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | unrestricted_file_upload | Unrestricted File Upload | 119 | Prefilter 命中漏洞特征规则: unrestricted_file_up | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep+taint_tracker | taint_tracker:SQL Injection | SQL Injection | 11 | high |
| 进裁决 | prefilter+taint_tracker | taint_tracker:Command Injection | Command Injection | 39 | critical |
| 去重合并 | taint_tracker | taint_tracker:Command Injection | Command Injection | 39 | critical |
| 进裁决 | prefilter+semgrep+taint_tracker | taint_tracker:Open Redirect | Open Redirect | 188 | medium |
| 进裁决 | taint_tracker | taint_tracker:Code Injection | Code Injection | 196 | critical |
| 去重合并 | prefilter | open_redirect | Open Redirect | 0 | medium |
| 进裁决 | prefilter | unrestricted_file_upload | Unrestricted File Upload | 119 | medium |
| 去重合并 | prefilter | cmd_injection_shell | Command Injection | 39 | critical |
| 去重合并 | semgrep | models.semgrep_rules.javascript.sequeliz | SQL Injection | 11 | high |
| 去重合并 | semgrep | models.semgrep_rules.javascript.express. | Open Redirect | 188 | medium |
| 进裁决 | semgrep | models.semgrep_rules.javascript.express. | Insecure Deserialization | 218 | medium |
| 进裁决 | semgrep | models.semgrep_rules.javascript.express. | XXE | 235 | high |

## core/authHandler.js（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-640 | 49 | B 候选在但类型错标 | prefilter·Timing Attack·L49 | — |
| CWE-330 | 78 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | timing_unsafe_compare | Timing Attack | 49 | medium |

## routes/app.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## server.js（原始候选 8 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| detect-secrets+semgrep | models.semgrep_rules.javascript.express. | Hardcoded Credentials | 24 | A hard-coded credential was detected. It | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 被剔除/抑制 | semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-cookie-settings.express-cookie-session-default-name | 23 | medium |
| 被剔除/抑制 | semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-domain | 23 | medium |
| 被剔除/抑制 | semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-expires | 23 | medium |
| 被剔除/抑制 | semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-httponly | 23 | medium |
| 被剔除/抑制 | semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-path | 23 | medium |
| 被剔除/抑制 | semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-secure | 23 | medium |
| 进裁决 | detect-secrets+semgrep | models.semgrep_rules.javascript.express. | Hardcoded Credentials | 24 | medium |
| 去重合并 | detect-secrets | Secret Keyword | Secret Keyword | 24 | high |

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
