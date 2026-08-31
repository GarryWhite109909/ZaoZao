# Stage 1 候选审计清单 —— snyk-labs/php-goof

**审计统计**：OK 5 · A 盲区 3 · B 类型错标 0（A/B 逐条归因后写入工具层文档修复）


四类问题：A 盲区（该产出没产出）/ B 类型错标 / C 无关候选 / D 剔除存疑

## func.php（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-89 | 13 | OK（候选覆盖且类型对） | semgrep·SQL Injection·L13 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | models.semgrep_rules.php.lang.security.i | SQL Injection | 13 | high |

## tasks.php（原始候选 3 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-89 | 11 | OK（候选覆盖且类型对） | semgrep·SQL Injection·L11<br>semgrep·SQL Injection·L13 | — |
| CWE-89 | 27 | OK（候选覆盖且类型对） | semgrep·SQL Injection·L27 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | models.semgrep_rules.php.lang.security.i | SQL Injection | 11 | high |
| 去重合并 | semgrep | models.semgrep_rules.php.lang.security.i | SQL Injection | 13 | high |
| 去重合并 | semgrep | models.semgrep_rules.php.lang.security.i | SQL Injection | 27 | high |

## index.php（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-79 | 39 | OK（候选覆盖且类型对） | semgrep·XSS·L39 | — |
| CWE-79 | 65 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | models.semgrep_rules.php.lang.security.i | XSS | 39 | high |

## pdf.php（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-94 | 39 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## db.php（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-798 | 4 | OK（候选覆盖且类型对） | detect-secrets·Secret Keyword·L4 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | detect-secrets | Secret Keyword | Secret Keyword | 4 | high |

## mail.php（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-94 | 19 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## exploits/gotcha_font.php（原始候选 1 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 被剔除/抑制 | semgrep | models.semgrep_rules.php.lang.security.p | models.semgrep_rules.php.lang.security.phpinfo-use.phpinfo-use | 8 | high |

## exploits/rshell_font.php（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
