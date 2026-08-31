# Stage 1 候选审计清单 —— local/exp_01_basic_scan

**审计统计**：OK 13 · A 盲区 0 · B 类型错标 0（A/B 逐条归因后写入工具层文档修复）


四类问题：A 盲区（该产出没产出）/ B 类型错标 / C 无关候选 / D 剔除存疑

## sql_injection_01.py（原始候选 5 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-89 | 15 | OK（候选覆盖且类型对） | semgrep·SQL Injection·L15<br>semgrep+taint_tracker·SQL Injection·L15<br>bandit+prefilter+semgrep·SQL Injection·L14<br>bandit·SQL Injection·L14<br>semgrep·SQL Injection·L14 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 去重合并 | semgrep | graduation_project.semgrep_rules.python- | SQL Injection | 15 | high |
| 进裁决 | semgrep+taint_tracker | taint_tracker:SQL Injection | SQL Injection | 15 | high |
| 进裁决 | bandit+prefilter+semgrep | sqli_constructed_query | SQL Injection | 14 | critical |
| 去重合并 | bandit | B608 | SQL Injection | 14 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | SQL Injection | 14 | high |

## sql_injection_02.py（原始候选 6 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-89 | 8 | OK（候选覆盖且类型对） | semgrep·SQL Injection·L8<br>bandit+prefilter+semgrep+taint_tracker·SQL Injection·L8<br>prefilter·SQL Injection·L8<br>prefilter·SQL Injection·L8<br>bandit·SQL Injection·L8<br>semgrep·SQL Injection·L6 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 去重合并 | semgrep | graduation_project.semgrep_rules.python- | SQL Injection | 8 | high |
| 进裁决 | bandit+prefilter+semgrep+taint_tracker | taint_tracker:SQL Injection | SQL Injection | 8 | high |
| 去重合并 | prefilter | sqli_fstring | SQL Injection | 8 | high |
| 去重合并 | prefilter | sqli_constructed_query | SQL Injection | 8 | critical |
| 去重合并 | bandit | B608 | SQL Injection | 8 | medium |
| 进裁决 | semgrep | models.semgrep_rules.python.django.secur | SQL Injection | 6 | medium |

## xss_01.php（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-79 | 9 | OK（候选覆盖且类型对） | semgrep·XSS·L9<br>semgrep·XSS·L10 | — |
| CWE-79 | 10 | OK（候选覆盖且类型对） | semgrep·XSS·L9<br>semgrep·XSS·L10 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | models.semgrep_rules.php.lang.security.i | XSS | 9 | high |
| 去重合并 | semgrep | models.semgrep_rules.php.lang.security.i | XSS | 10 | high |

## xss_02.js（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-79 | 8 | OK（候选覆盖且类型对） | prefilter+semgrep·XSS·L6<br>semgrep·XSS·L6 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter+semgrep | xss_unescaped_output | XSS | 6 | high |
| 去重合并 | semgrep | models.semgrep_rules.javascript.express. | XSS | 6 | medium |

## command_injection_01.py（原始候选 10 → 最终 5）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-78 | 10 | OK（候选覆盖且类型对） | semgrep·Command Injection·L10<br>prefilter+semgrep+taint_tracker·Command Injection·L10<br>bandit+prefilter+semgrep·Command Injection·L12<br>prefilter·Command Injection·L10<br>bandit·Command Injection·L12<br>semgrep·Command Injection·L10<br>semgrep·Command Injection·L11<br>semgrep·Command Injection·L12 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit | B404 | Command Injection | 1 | Consider possible security implications  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 去重合并 | semgrep | graduation_project.semgrep_rules.python- | Command Injection | 10 | critical |
| 进裁决 | prefilter+semgrep+taint_tracker | taint_tracker:Command Injection | Command Injection | 10 | critical |
| 进裁决 | bandit+prefilter+semgrep | cmd_subprocess_shell_concat | Command Injection | 12 | critical |
| 进裁决 | prefilter | path_traversal_open_concat | Path Traversal | 0 | high |
| 去重合并 | prefilter | cmd_injection_shell | Command Injection | 10 | critical |
| 进裁决 | bandit | B404 | Command Injection | 1 | low |
| 去重合并 | bandit | B602 | Command Injection | 12 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | Command Injection | 10 | high |
| 进裁决 | semgrep | models.semgrep_rules.python.lang.securit | Command Injection | 11 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Command Injection | 12 | high |

## command_injection_02.js（原始候选 3 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-78 | 7 | OK（候选覆盖且类型对） | prefilter+taint_tracker·Command Injection·L7<br>taint_tracker·Command Injection·L7<br>prefilter·Command Injection·L7 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter+taint_tracker | taint_tracker:Command Injection | Command Injection | 7 | critical |
| 去重合并 | taint_tracker | taint_tracker:Command Injection | Command Injection | 7 | critical |
| 去重合并 | prefilter | cmd_injection_shell | Command Injection | 7 | critical |

## path_traversal_01.py（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-22 | 15 | OK（候选覆盖且类型对） | prefilter+taint_tracker·Path Traversal·L15 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter+taint_tracker | taint_tracker:Path Traversal | Path Traversal | 15 | high |
| 去重合并 | prefilter | path_traversal_open_join | Path Traversal | 0 | high |

## path_traversal_02.java（原始候选 5 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-22 | 15 | OK（候选覆盖且类型对） | taint_tracker·Path Traversal·L15 | semgrep·models.semgrep_rules.java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal·L15 |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| taint_tracker | taint_tracker:Path Traversal | Path Traversal | 20 | TaintTracker AST 污点分析定位的同文件 source→sink  | 形态核验通过 |
| semgrep | models.semgrep_rules.java.lang.security. | XSS | 22 | Detected a request with potential user-i | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | taint_tracker | taint_tracker:Path Traversal | Path Traversal | 15 | high |
| 进裁决 | taint_tracker | taint_tracker:Path Traversal | Path Traversal | 20 | high |
| 被剔除/抑制 | semgrep | models.semgrep_rules.java.lang.security. | models.semgrep_rules.java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal | 15 | high |
| 被剔除/抑制 | semgrep | models.semgrep_rules.java.lang.security. | models.semgrep_rules.java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal | 20 | high |
| 进裁决 | semgrep | models.semgrep_rules.java.lang.security. | XSS | 22 | medium |

## hardcoded_secret_01.py（原始候选 6 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-798 | 3 | OK（候选覆盖且类型对） | bandit+detect-secrets·Hardcoded Credentials·L4<br>gitleaks·aws-access-key-id·L3<br>detect-secrets·AWS Access Key·L4<br>detect-secrets·Base64 High Entropy String·L4<br>detect-secrets·Secret Keyword·L4 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | models.semgrep_rules.python.boto3.securi | Hardcoded Credentials | 9 | A hard-coded credential was detected. It | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit+detect-secrets | B105 | Hardcoded Credentials | 4 | low |
| 进裁决 | semgrep | models.semgrep_rules.python.boto3.securi | Hardcoded Credentials | 9 | medium |
| 进裁决 | gitleaks | aws-access-key-id | aws-access-key-id | 3 | high |
| 去重合并 | detect-secrets | AWS Access Key | AWS Access Key | 4 | high |
| 去重合并 | detect-secrets | Base64 High Entropy String | Base64 High Entropy String | 4 | high |
| 去重合并 | detect-secrets | Secret Keyword | Secret Keyword | 4 | high |

## hardcoded_secret_02.java（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-798 | 9 | OK（候选覆盖且类型对） | detect-secrets·Secret Keyword·L9 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | detect-secrets | Secret Keyword | Secret Keyword | 9 | high |

## insecure_deserialization_01.py（原始候选 6 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-502 | 12 | OK（候选覆盖且类型对） | bandit+prefilter+semgrep+taint_tracker·Insecure Deserialization·L12<br>prefilter·Insecure Deserialization·L12<br>bandit·Insecure Deserialization·L12<br>semgrep·Insecure Deserialization·L12<br>semgrep·Insecure Deserialization·L12 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit | B403 | Insecure Deserialization | 1 | Consider possible security implications  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit+prefilter+semgrep+taint_tracker | taint_tracker:Insecure Deserialization | Insecure Deserialization | 12 | critical |
| 去重合并 | prefilter | deser_pickle_loads | Insecure Deserialization | 12 | critical |
| 进裁决 | bandit | B403 | Insecure Deserialization | 1 | low |
| 去重合并 | bandit | B301 | Insecure Deserialization | 12 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | Insecure Deserialization | 12 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Insecure Deserialization | 12 | medium |

## insecure_deserialization_02.java（原始候选 3 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-502 | 16 | OK（候选覆盖且类型对） | semgrep+taint_tracker·Insecure Deserialization·L15<br>semgrep·Insecure Deserialization·L15<br>semgrep·XSS·L17 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep+taint_tracker | taint_tracker:Insecure Deserialization | Insecure Deserialization | 15 | critical |
| 去重合并 | semgrep | models.semgrep_rules.java.lang.security. | Insecure Deserialization | 15 | medium |
| 进裁决 | semgrep | models.semgrep_rules.java.lang.security. | XSS | 17 | medium |

## safe_01_parameterized_query.py（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | graduation_project.semgrep_rules.python- | SQL Injection | 15 | 污点命中：用户可控输入流入 SQL 执行，疑似 SQL 注入（待 LLM 裁决） | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | graduation_project.semgrep_rules.python- | SQL Injection | 15 | high |

## safe_02_subprocess_list.py（原始候选 4 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit+semgrep | graduation_project.semgrep_rules.python- | Command Injection | 12 | 污点命中：用户可控输入流入命令执行，疑似命令注入（待 LLM 裁决）
[sink | 疑不合理：Q2_形态匹配 |
| bandit | B404 | Command Injection | 1 | Consider possible security implications  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit+semgrep | graduation_project.semgrep_rules.python- | Command Injection | 12 | critical |
| 进裁决 | bandit | B404 | Command Injection | 1 | low |
| 去重合并 | bandit | B607 | Command Injection | 12 | low |
| 去重合并 | bandit | B603 | Command Injection | 12 | low |
