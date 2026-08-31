# Stage 1 候选审计清单 —— OWASP/NodeGoat

**审计统计**：OK 13 · A 盲区 10 · B 类型错标 0（A/B 逐条归因后写入工具层文档修复）


四类问题：A 盲区（该产出没产出）/ B 类型错标 / C 无关候选 / D 剔除存疑

## server.js（原始候选 7 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-79 | 137 | OK（候选覆盖且类型对） | prefilter·XSS·L137 | — |
| CWE-311 | 145 | A 盲区（零候选） | — | — |
| CWE-1004 | 78 | OK（候选覆盖且类型对） | semgrep·Insecure Cookie·L78<br>semgrep·Insecure Cookie·L78<br>semgrep·Insecure Cookie·L78<br>semgrep·Insecure Cookie·L78<br>semgrep·Insecure Cookie·L78<br>semgrep·Insecure Cookie·L78 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | template_autoescape_disabled | XSS | 137 | high |
| 进裁决 | semgrep | models.semgrep_rules.javascript.express. | Insecure Cookie | 78 | medium |
| 去重合并 | semgrep | models.semgrep_rules.javascript.express. | Insecure Cookie | 78 | medium |
| 去重合并 | semgrep | models.semgrep_rules.javascript.express. | Insecure Cookie | 78 | medium |
| 去重合并 | semgrep | models.semgrep_rules.javascript.express. | Insecure Cookie | 78 | medium |
| 去重合并 | semgrep | models.semgrep_rules.javascript.express. | Insecure Cookie | 78 | medium |
| 去重合并 | semgrep | models.semgrep_rules.javascript.express. | Insecure Cookie | 78 | medium |

## config/config.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## config/env/all.js（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-798 | 8 | OK（候选覆盖且类型对） | detect-secrets·Secret Keyword·L8 | — |
| CWE-798 | 9 | OK（候选覆盖且类型对） | detect-secrets·Secret Keyword·L8 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | detect-secrets | Secret Keyword | Secret Keyword | 8 | high |

## config/env/development.js（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-798 | 6 | OK（候选覆盖且类型对） | detect-secrets+gitleaks·generic-api-key·L6<br>detect-secrets·Secret Keyword·L6 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | detect-secrets+gitleaks | generic-api-key | generic-api-key | 6 | high |
| 去重合并 | detect-secrets | Secret Keyword | Secret Keyword | 6 | high |

## config/env/production.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## config/env/test.js（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-798 | 6 | OK（候选覆盖且类型对） | detect-secrets+gitleaks·generic-api-key·L6<br>detect-secrets·Secret Keyword·L6 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | detect-secrets+gitleaks | generic-api-key | generic-api-key | 6 | high |
| 去重合并 | detect-secrets | Secret Keyword | Secret Keyword | 6 | high |

## app/data/allocations-dao.js（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-943 | 78 | OK（候选覆盖且类型对） | prefilter·NoSQL Injection·L78 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | nosql_where_injection | NoSQL Injection | 78 | critical |

## app/data/benefits-dao.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/data/contributions-dao.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/data/memos-dao.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/data/profile-dao.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-312 | 62 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/data/research-dao.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/data/user-dao.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-256 | 25 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/routes/allocations.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-639 | 23 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/routes/benefits.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/routes/contributions.js（原始候选 6 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-94 | 32 | OK（候选覆盖且类型对） | taint_tracker·Code Injection·L32<br>taint_tracker·Code Injection·L33<br>taint_tracker·Code Injection·L34<br>semgrep·Command Injection·L32<br>semgrep·Command Injection·L33<br>semgrep·Command Injection·L34 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | taint_tracker | taint_tracker:Code Injection | Code Injection | 32 | critical |
| 去重合并 | taint_tracker | taint_tracker:Code Injection | Code Injection | 33 | critical |
| 去重合并 | taint_tracker | taint_tracker:Code Injection | Code Injection | 34 | critical |
| 进裁决 | semgrep | models.semgrep_rules.javascript.lang.sec | Command Injection | 32 | high |
| 去重合并 | semgrep | models.semgrep_rules.javascript.lang.sec | Command Injection | 33 | high |
| 去重合并 | semgrep | models.semgrep_rules.javascript.lang.sec | Command Injection | 34 | high |

## app/routes/error.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/routes/index.js（原始候选 3 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-601 | 72 | OK（候选覆盖且类型对） | prefilter+semgrep+taint_tracker·Open Redirect·L72<br>semgrep·Open Redirect·L72 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter+semgrep+taint_tracker | taint_tracker:Open Redirect | Open Redirect | 72 | medium |
| 去重合并 | prefilter | open_redirect | Open Redirect | 0 | medium |
| 去重合并 | semgrep | models.semgrep_rules.javascript.express. | Open Redirect | 72 | medium |

## app/routes/memos.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/routes/profile.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-1333 | 59 | A 盲区（零候选） | — | — |
| CWE-79 | 65 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/routes/research.js（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-918 | 16 | OK（候选覆盖且类型对） | prefilter·SSRF·L16 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | ssrf_request_from_input | SSRF | 16 | high |

## app/routes/session.js（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-117 | 64 | A 盲区（零候选） | — | — |
| CWE-521 | 144 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| detect-secrets | Secret Keyword | Secret Keyword | 61 | 检测到疑似密钥: Secret Keyword | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | detect-secrets | Secret Keyword | Secret Keyword | 61 | high |
| 去重合并 | detect-secrets | Secret Keyword | Secret Keyword | 172 | high |

## app/routes/tutorial.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/views/allocations.html（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-79 | 15 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/views/memos.html（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-79 | 31 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## artifacts/db-reset.js（原始候选 3 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-798 | 18 | OK（候选覆盖且类型对） | detect-secrets·Secret Keyword·L18 | — |
| CWE-798 | 27 | OK（候选覆盖且类型对） | detect-secrets·Secret Keyword·L27 | — |
| CWE-798 | 35 | OK（候选覆盖且类型对） | detect-secrets·Secret Keyword·L35 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | detect-secrets | Secret Keyword | Secret Keyword | 18 | high |
| 去重合并 | detect-secrets | Secret Keyword | Secret Keyword | 27 | high |
| 去重合并 | detect-secrets | Secret Keyword | Secret Keyword | 35 | high |
