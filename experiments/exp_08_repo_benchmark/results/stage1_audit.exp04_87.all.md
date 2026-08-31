# Stage 1 候选审计清单 —— exp_04_87

**⚠️ 历史快照（2026-08-31 11:54，第五波末状态）**：本清单的 OK 44 / A 41 反映
的是第六波（§9.16）修复**之前**的工具层状态，行号/候选数均为当时口径。
第六波后 87 段四项指标已变为（14:49 版）：总候选 132、零召回 15、零召回×真 3、
安全样本候选 17——本清单中的多数 A 盲区已在第六波修复（Java/PHP/JS source·sink、
catch 块、LDAP 等）。保留本文件仅作 §9.8 逐条人工审查的证据链，**勿引用为当前状态**。


**审计统计**：OK 44 · A 盲区 41 · B 类型错标 0（A/B 逐条归因后写入工具层文档修复）


四类问题：A 盲区（该产出没产出）/ B 类型错标 / C 无关候选 / D 剔除存疑

## typical_01_sql.py（原始候选 5 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-89 | 0 | OK（候选覆盖且类型对） | semgrep·SQL Injection·L13<br>semgrep+taint_tracker·SQL Injection·L13<br>bandit+prefilter+semgrep·SQL Injection·L12<br>bandit·SQL Injection·L12<br>semgrep·SQL Injection·L12 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep+taint_tracker | taint_tracker:SQL Injection | SQL Injection | 13 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |
| bandit+prefilter+semgrep | sqli_constructed_query | SQL Injection | 12 | Prefilter 命中漏洞特征规则: sqli_constructed_que | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 去重合并 | semgrep | graduation_project.semgrep_rules.python- | SQL Injection | 13 | high |
| 进裁决 | semgrep+taint_tracker | taint_tracker:SQL Injection | SQL Injection | 13 | high |
| 进裁决 | bandit+prefilter+semgrep | sqli_constructed_query | SQL Injection | 12 | critical |
| 去重合并 | bandit | B608 | SQL Injection | 12 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | SQL Injection | 12 | high |

## typical_02_xss.py（原始候选 4 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-79 | 0 | OK（候选覆盖且类型对） | prefilter+semgrep·XSS·L9<br>semgrep·XSS·L9<br>semgrep·XSS·L9<br>semgrep·XSS·L10 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter+semgrep | xss_unescaped_output | XSS | 9 | Prefilter 命中漏洞特征规则: xss_unescaped_output | 形态核验通过 |
| semgrep | models.semgrep_rules.python.flask.securi | XSS | 10 | Detected Flask route directly returning  | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter+semgrep | xss_unescaped_output | XSS | 9 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.django.secur | XSS | 9 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 9 | medium |
| 进裁决 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 10 | medium |

## typical_03_cmd.py（原始候选 8 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-78 | 0 | OK（候选覆盖且类型对） | semgrep·Command Injection·L10<br>bandit+prefilter+semgrep+taint_tracker·Command Injection·L10<br>prefilter·Command Injection·L10<br>bandit·Command Injection·L1<br>bandit·Command Injection·L10<br>semgrep·Command Injection·L10<br>semgrep·Command Injection·L10<br>semgrep·Command Injection·L10 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit+prefilter+semgrep+taint_tracker | taint_tracker:Command Injection | Command Injection | 10 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 去重合并 | semgrep | graduation_project.semgrep_rules.python- | Command Injection | 10 | critical |
| 进裁决 | bandit+prefilter+semgrep+taint_tracker | taint_tracker:Command Injection | Command Injection | 10 | critical |
| 去重合并 | prefilter | cmd_injection_shell | Command Injection | 10 | critical |
| 进裁决 | bandit | B404 | Command Injection | 1 | low |
| 去重合并 | bandit | B602 | Command Injection | 10 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | Command Injection | 10 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Command Injection | 10 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Command Injection | 10 | high |

## typical_04_path.py（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-22 | 0 | OK（候选覆盖且类型对） | prefilter+taint_tracker·Path Traversal·L12<br>prefilter·Path Traversal·L0 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter+taint_tracker | taint_tracker:Path Traversal | Path Traversal | 12 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter+taint_tracker | taint_tracker:Path Traversal | Path Traversal | 12 | high |
| 去重合并 | prefilter | path_traversal_open_join | Path Traversal | 0 | high |

## typical_05_pickle.py（原始候选 6 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-502 | 0 | OK（候选覆盖且类型对） | bandit+prefilter+semgrep+taint_tracker·Insecure Deserialization·L10<br>prefilter·Insecure Deserialization·L10<br>bandit·Insecure Deserialization·L1<br>bandit·Insecure Deserialization·L10<br>semgrep·Insecure Deserialization·L10<br>semgrep·Insecure Deserialization·L10 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit+prefilter+semgrep+taint_tracker | taint_tracker:Insecure Deserialization | Insecure Deserialization | 10 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit+prefilter+semgrep+taint_tracker | taint_tracker:Insecure Deserialization | Insecure Deserialization | 10 | critical |
| 去重合并 | prefilter | deser_pickle_loads | Insecure Deserialization | 10 | critical |
| 进裁决 | bandit | B403 | Insecure Deserialization | 1 | low |
| 去重合并 | bandit | B301 | Insecure Deserialization | 10 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | Insecure Deserialization | 10 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Insecure Deserialization | 10 | medium |

## typical_06_secret.py（原始候选 3 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-798 | 0 | OK（候选覆盖且类型对） | bandit·Hardcoded Credentials·L4<br>semgrep·Hardcoded Credentials·L9 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit | B105 | Hardcoded Credentials | 4 | Possible hardcoded password: 'wJalrXUtnF | 形态核验通过 |
| semgrep | models.semgrep_rules.python.boto3.securi | Hardcoded Credentials | 9 | A hard-coded credential was detected. It | 形态核验通过 |
| gitleaks | aws-access-key-id | aws-access-key-id | 3 | AWS Access Key ID literal (AKIA/ASIA/ABI | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit | B105 | Hardcoded Credentials | 4 | low |
| 进裁决 | semgrep | models.semgrep_rules.python.boto3.securi | Hardcoded Credentials | 9 | medium |
| 进裁决 | gitleaks | aws-access-key-id | aws-access-key-id | 3 | high |

## typical_07_ssrf.py（原始候选 3 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-918 | 0 | OK（候选覆盖且类型对） | bandit+prefilter+semgrep·SSRF·L10<br>bandit·SSRF·L10<br>semgrep·SSRF·L10 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit+prefilter+semgrep | ssrf_request_from_input | SSRF | 10 | Prefilter 命中漏洞特征规则: ssrf_request_from_in | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit+prefilter+semgrep | ssrf_request_from_input | SSRF | 10 | high |
| 去重合并 | bandit | B310 | SSRF | 10 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | SSRF | 10 | medium |

## typical_08_eval.py（原始候选 8 → 最终 4）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-94 | 0 | OK（候选覆盖且类型对） | semgrep·Code Injection·L9<br>semgrep·Code Injection·L10<br>bandit+semgrep+taint_tracker·Code Injection·L9<br>bandit·Code Injection·L9<br>semgrep·Code Injection·L8<br>semgrep·Code Injection·L9<br>semgrep·Code Injection·L9 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | graduation_project.semgrep_rules.python- | Code Injection | 10 | 污点命中：用户可控输入流入未转义的 HTML/CSS 输出，疑似反射型 XSS（ | 疑不合理：Q2_邻行形态匹配 |
| bandit+semgrep+taint_tracker | taint_tracker:Code Injection | Code Injection | 9 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |
| semgrep | models.semgrep_rules.python.django.secur | Code Injection | 8 | Found user data in a call to 'eval'. Thi | 疑不合理：Q2_邻行形态匹配 |
| semgrep | models.semgrep_rules.python.flask.securi | XSS | 10 | Detected Flask route directly returning  | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 去重合并 | semgrep | graduation_project.semgrep_rules.python- | Code Injection | 9 | critical |
| 进裁决 | semgrep | graduation_project.semgrep_rules.python- | Code Injection | 10 | medium |
| 进裁决 | bandit+semgrep+taint_tracker | taint_tracker:Code Injection | Code Injection | 9 | critical |
| 去重合并 | bandit | B307 | Code Injection | 9 | medium |
| 进裁决 | semgrep | models.semgrep_rules.python.django.secur | Code Injection | 8 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | Code Injection | 9 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Code Injection | 9 | medium |
| 进裁决 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 10 | medium |

## typical_09_xss_php.php（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-79 | 0 | OK（候选覆盖且类型对） | prefilter+semgrep·XSS·L4<br>semgrep·XSS·L4 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter+semgrep | xss_unescaped_output | XSS | 4 | Prefilter 命中漏洞特征规则: xss_unescaped_output | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter+semgrep | xss_unescaped_output | XSS | 4 | high |
| 去重合并 | semgrep | models.semgrep_rules.php.lang.security.i | XSS | 4 | high |

## typical_10_cmd_js.js（原始候选 4 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-78 | 0 | OK（候选覆盖且类型对） | prefilter+semgrep+taint_tracker·Command Injection·L7<br>taint_tracker·Command Injection·L7<br>prefilter·Command Injection·L7<br>semgrep·Command Injection·L7 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter+semgrep+taint_tracker | taint_tracker:Command Injection | Command Injection | 7 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter+semgrep+taint_tracker | taint_tracker:Command Injection | Command Injection | 7 | critical |
| 去重合并 | taint_tracker | taint_tracker:Command Injection | Command Injection | 7 | critical |
| 去重合并 | prefilter | cmd_injection_shell | Command Injection | 7 | critical |
| 去重合并 | semgrep | models.semgrep_rules.javascript.lang.sec | Command Injection | 7 | high |

## typical_11_yaml.py（原始候选 5 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-502 | 0 | OK（候选覆盖且类型对） | bandit+prefilter+semgrep+taint_tracker·Insecure Deserialization·L10<br>prefilter·Insecure Deserialization·L10<br>bandit·Insecure Deserialization·L10<br>semgrep·Insecure Deserialization·L10<br>semgrep·Insecure Deserialization·L10 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit+prefilter+semgrep+taint_tracker | taint_tracker:Insecure Deserialization | Insecure Deserialization | 10 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit+prefilter+semgrep+taint_tracker | taint_tracker:Insecure Deserialization | Insecure Deserialization | 10 | critical |
| 去重合并 | prefilter | deser_yaml_unsafe_load | Insecure Deserialization | 10 | high |
| 去重合并 | bandit | B506 | Insecure Deserialization | 10 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | Insecure Deserialization | 10 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Insecure Deserialization | 10 | high |

## typical_12_open_redirect.py（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-601 | 0 | OK（候选覆盖且类型对） | prefilter·Open Redirect·L0<br>prefilter+semgrep·Open Redirect·L8 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter+semgrep | models.semgrep_rules.python.flask.securi | Open Redirect | 8 | Data from request is passed to redirect( | 疑不合理：Q2_邻行形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 去重合并 | prefilter | open_redirect | Open Redirect | 0 | medium |
| 进裁决 | prefilter+semgrep | models.semgrep_rules.python.flask.securi | Open Redirect | 8 | high |

## hard_bypass_01_sql_replace.py（原始候选 6 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-89 | 0 | OK（候选覆盖且类型对） | semgrep·SQL Injection·L13<br>bandit+prefilter+semgrep+taint_tracker·SQL Injection·L13<br>prefilter·SQL Injection·L13<br>prefilter·SQL Injection·L13<br>bandit·SQL Injection·L13<br>semgrep·SQL Injection·L13 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit+prefilter+semgrep+taint_tracker | taint_tracker:SQL Injection | SQL Injection | 13 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 去重合并 | semgrep | graduation_project.semgrep_rules.python- | SQL Injection | 13 | high |
| 进裁决 | bandit+prefilter+semgrep+taint_tracker | taint_tracker:SQL Injection | SQL Injection | 13 | high |
| 去重合并 | prefilter | sqli_percent_format | SQL Injection | 13 | high |
| 去重合并 | prefilter | sqli_constructed_query | SQL Injection | 13 | critical |
| 去重合并 | bandit | B608 | SQL Injection | 13 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | SQL Injection | 13 | high |

## hard_bypass_02_cmd_strip.py（原始候选 8 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-78 | 0 | OK（候选覆盖且类型对） | semgrep·Command Injection·L10<br>bandit+prefilter+semgrep+taint_tracker·Command Injection·L10<br>prefilter·Command Injection·L10<br>bandit·Command Injection·L1<br>bandit·Command Injection·L10<br>semgrep·Command Injection·L10<br>semgrep·Command Injection·L10<br>semgrep·Command Injection·L10 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit+prefilter+semgrep+taint_tracker | taint_tracker:Command Injection | Command Injection | 10 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 去重合并 | semgrep | graduation_project.semgrep_rules.python- | Command Injection | 10 | critical |
| 进裁决 | bandit+prefilter+semgrep+taint_tracker | taint_tracker:Command Injection | Command Injection | 10 | critical |
| 去重合并 | prefilter | cmd_injection_shell | Command Injection | 10 | critical |
| 进裁决 | bandit | B404 | Command Injection | 1 | low |
| 去重合并 | bandit | B602 | Command Injection | 10 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | Command Injection | 10 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Command Injection | 10 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Command Injection | 10 | high |

## hard_bypass_03_xss_replace.py（原始候选 5 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-79 | 0 | OK（候选覆盖且类型对） | prefilter+semgrep·XSS·L10<br>prefilter·XSS·L10<br>semgrep·XSS·L10<br>semgrep·XSS·L10<br>semgrep·XSS·L10 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter+semgrep | graduation_project.semgrep_rules.python- | XSS | 10 | 污点命中：用户可控输入流入未转义的 HTML/CSS 输出，疑似反射型 XSS（ | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter+semgrep | graduation_project.semgrep_rules.python- | XSS | 10 | medium |
| 去重合并 | prefilter | xss_unescaped_output | XSS | 10 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 10 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.django.secur | XSS | 10 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 10 | medium |

## hard_bypass_04_path_regex.py（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-22 | 0 | OK（候选覆盖且类型对） | prefilter+taint_tracker·Path Traversal·L15<br>prefilter·Path Traversal·L0 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter+taint_tracker | taint_tracker:Path Traversal | Path Traversal | 15 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter+taint_tracker | taint_tracker:Path Traversal | Path Traversal | 15 | high |
| 去重合并 | prefilter | path_traversal_open_join | Path Traversal | 0 | high |

## hard_crossfile_01_sink.py（原始候选 2 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-89 | 0 | OK（候选覆盖且类型对） | prefilter·SQL Injection·L14<br>bandit·SQL Injection·L15 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | sqli_constructed_query | SQL Injection | 14 | Prefilter 命中漏洞特征规则: sqli_constructed_que | 疑不合理：Q2_形态匹配 |
| bandit | B608 | SQL Injection | 15 | Possible SQL injection vector through st | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | sqli_constructed_query | SQL Injection | 14 | critical |
| 进裁决 | bandit | B608 | SQL Injection | 15 | medium |

## hard_crossfile_02_input.py（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-22 | 0 | OK（候选覆盖且类型对） | prefilter·Path Traversal·L0 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | path_traversal_open_join | Path Traversal | 0 | high |

## hard_crossfile_02_sink.py（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-22 | 0 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## hard_cve_01_samba_2017_7494.py（原始候选 8 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-78 | 0 | OK（候选覆盖且类型对） | semgrep·Command Injection·L11<br>semgrep·Command Injection·L12<br>bandit+prefilter+semgrep+taint_tracker·Command Injection·L11<br>prefilter·Command Injection·L11<br>bandit·Command Injection·L11<br>semgrep·Command Injection·L11<br>semgrep·Command Injection·L11 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | graduation_project.semgrep_rules.python- | Command Injection | 12 | 污点命中：用户可控输入流入未转义的 HTML/CSS 输出，疑似反射型 XSS（ | 疑不合理：Q2_邻行形态匹配 |
| bandit+prefilter+semgrep+taint_tracker | taint_tracker:Command Injection | Command Injection | 11 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |
| semgrep | models.semgrep_rules.python.flask.securi | XSS | 12 | Detected Flask route directly returning  | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 去重合并 | semgrep | graduation_project.semgrep_rules.python- | Command Injection | 11 | critical |
| 进裁决 | semgrep | graduation_project.semgrep_rules.python- | Command Injection | 12 | medium |
| 进裁决 | bandit+prefilter+semgrep+taint_tracker | taint_tracker:Command Injection | Command Injection | 11 | critical |
| 去重合并 | prefilter | cmd_injection_shell | Command Injection | 11 | critical |
| 去重合并 | bandit | B605 | Command Injection | 11 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | Command Injection | 11 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Command Injection | 11 | high |
| 进裁决 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 12 | medium |

## hard_cve_02_python_log_injection.py（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-117 | 0 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | log_injection | Log Injection | 0 | medium |

## hard_cve_03_tarfile_2025_4517.py（原始候选 2 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-22 | 0 | A 盲区（零候选） | — | — |
| CWE-377 | 0 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 被剔除/抑制 | bandit | B108 | B108 | 10 | medium |
| 被剔除/抑制 | semgrep | models.semgrep_rules.python.django.secur | models.semgrep_rules.python.django.security.injection.request-data-write.request-data-write | 9 | medium |

## hard_cve_04_ssrf_urllib.py（原始候选 3 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-918 | 0 | OK（候选覆盖且类型对） | bandit+prefilter+semgrep·SSRF·L11<br>bandit·SSRF·L11<br>semgrep·SSRF·L11 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit+prefilter+semgrep | ssrf_request_from_input | SSRF | 11 | Prefilter 命中漏洞特征规则: ssrf_request_from_in | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit+prefilter+semgrep | ssrf_request_from_input | SSRF | 11 | high |
| 去重合并 | bandit | B310 | SSRF | 11 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | SSRF | 11 | medium |

## hard_longfile_01_hidden_sql.py（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-89 | 0 | OK（候选覆盖且类型对） | bandit+prefilter·SQL Injection·L317<br>bandit·SQL Injection·L317 | — |
| CWE-760 | 0 | A 盲区（零候选） | — | — |
| CWE-208 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit+prefilter | sqli_constructed_query | SQL Injection | 317 | Prefilter 命中漏洞特征规则: sqli_constructed_que | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit+prefilter | sqli_constructed_query | SQL Injection | 317 | critical |
| 去重合并 | bandit | B608 | SQL Injection | 317 | medium |

## hard_owasp_01_file_upload.py（原始候选 3 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-434 | 0 | OK（候选覆盖且类型对） | prefilter·Unrestricted File Upload·L10 | — |
| CWE-22 | 0 | OK（候选覆盖且类型对） | taint_tracker·Path Traversal·L15 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| taint_tracker | taint_tracker:Path Traversal | Path Traversal | 15 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_邻行形态匹配 |
| prefilter | unrestricted_file_upload | Unrestricted File Upload | 10 | Prefilter 命中漏洞特征规则: unrestricted_file_up | 形态核验通过 |
| semgrep | models.semgrep_rules.python.flask.securi | XSS | 16 | Detected Flask route directly returning  | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | taint_tracker | taint_tracker:Path Traversal | Path Traversal | 15 | high |
| 进裁决 | prefilter | unrestricted_file_upload | Unrestricted File Upload | 10 | medium |
| 进裁决 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 16 | medium |

## hard_longfile_02_hidden_cmd.py（原始候选 6 → 最终 4）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-78 | 0 | OK（候选覆盖且类型对） | prefilter·Command Injection·L205<br>bandit·Command Injection·L204<br>bandit+semgrep·Command Injection·L207<br>semgrep·Command Injection·L207 | — |
| CWE-377 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | cmd_injection_shell | Command Injection | 205 | Prefilter 命中漏洞特征规则: cmd_injection_shell | 疑不合理：Q2_形态匹配 |
| bandit | B404 | Command Injection | 204 | Consider possible security implications  | 疑不合理：Q2_形态匹配 |
| bandit+semgrep | B602 | Command Injection | 207 | subprocess call with shell=True identifi | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | path_traversal_open_join | Path Traversal | 0 | high |
| 进裁决 | prefilter | cmd_injection_shell | Command Injection | 205 | critical |
| 被剔除/抑制 | bandit | B108 | B108 | 21 | medium |
| 进裁决 | bandit | B404 | Command Injection | 204 | low |
| 进裁决 | bandit+semgrep | B602 | Command Injection | 207 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Command Injection | 207 | high |

## hard_owasp_02_dvwa_sql.py（原始候选 11 → 最终 5）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-89 | 0 | OK（候选覆盖且类型对） | semgrep·SQL Injection·L13<br>semgrep·SQL Injection·L16<br>semgrep+taint_tracker·SQL Injection·L13<br>bandit+prefilter+semgrep·SQL Injection·L12<br>bandit·SQL Injection·L12<br>semgrep·SQL Injection·L9<br>semgrep·SQL Injection·L12 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | graduation_project.semgrep_rules.python- | SQL Injection | 16 | 污点命中：用户可控输入流入未转义的 HTML/CSS 输出，疑似反射型 XSS（ | 形态核验通过 |
| semgrep+taint_tracker | taint_tracker:SQL Injection | SQL Injection | 13 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |
| bandit+prefilter+semgrep | sqli_constructed_query | SQL Injection | 12 | Prefilter 命中漏洞特征规则: sqli_constructed_que | 疑不合理：Q2_形态匹配 |
| prefilter+semgrep | xss_unescaped_output | XSS | 16 | Prefilter 命中漏洞特征规则: xss_unescaped_output | 形态核验通过 |
| semgrep | models.semgrep_rules.python.django.secur | SQL Injection | 9 | User-controlled data from a request is p | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 去重合并 | semgrep | graduation_project.semgrep_rules.python- | SQL Injection | 13 | high |
| 进裁决 | semgrep | graduation_project.semgrep_rules.python- | SQL Injection | 16 | medium |
| 进裁决 | semgrep+taint_tracker | taint_tracker:SQL Injection | SQL Injection | 13 | high |
| 进裁决 | bandit+prefilter+semgrep | sqli_constructed_query | SQL Injection | 12 | critical |
| 进裁决 | prefilter+semgrep | xss_unescaped_output | XSS | 16 | high |
| 去重合并 | bandit | B608 | SQL Injection | 12 | medium |
| 进裁决 | semgrep | models.semgrep_rules.python.django.secur | SQL Injection | 9 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | SQL Injection | 12 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 16 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.django.secur | XSS | 16 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 16 | medium |

## typical_13_auth_bypass.py（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-306 | 0 | A 盲区（零候选） | — | — |
| CWE-79 | 0 | OK（候选覆盖且类型对） | semgrep·XSS·L11<br>semgrep·XSS·L11 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | graduation_project.semgrep_rules.python- | XSS | 11 | 污点命中：用户可控输入流入未转义的 HTML/CSS 输出，疑似反射型 XSS（ | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | graduation_project.semgrep_rules.python- | XSS | 11 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 11 | medium |

## typical_14_idor.py（原始候选 3 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-639 | 0 | A 盲区（零候选） | — | — |
| CWE-79 | 0 | OK（候选覆盖且类型对） | semgrep·XSS·L14<br>semgrep·XSS·L14 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | graduation_project.semgrep_rules.python- | XSS | 14 | 污点命中：用户可控输入流入未转义的 HTML/CSS 输出，疑似反射型 XSS（ | 形态核验通过 |
| bandit | B105 | Hardcoded Credentials | 4 | Possible hardcoded password: 'dev_key'
[ | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | graduation_project.semgrep_rules.python- | XSS | 14 | medium |
| 进裁决 | bandit | B105 | Hardcoded Credentials | 4 | low |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 14 | medium |

## typical_15_missing_authz.py（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-862 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit | B105 | Hardcoded Credentials | 4 | Possible hardcoded password: 'dev_key'
[ | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit | B105 | Hardcoded Credentials | 4 | low |

## typical_16_session_fixation.py（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-384 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit | B105 | Hardcoded Credentials | 4 | Possible hardcoded password: 'dev_key'
[ | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit | B105 | Hardcoded Credentials | 4 | low |

## typical_17_md5_password.py（原始候选 6 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-327 | 0 | OK（候选覆盖且类型对） | bandit+prefilter+semgrep·Weak Cryptography·L11<br>bandit·Weak Cryptography·L11<br>semgrep·Weak Cryptography·L11<br>semgrep·Weak Cryptography·L11 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | graduation_project.semgrep_rules.python- | XSS | 13 | 污点命中：用户可控输入流入未转义的 HTML/CSS 输出，疑似反射型 XSS（ | 形态核验通过 |
| bandit+prefilter+semgrep | crypto_weak_hash | Weak Cryptography | 11 | Prefilter 命中漏洞特征规则: crypto_weak_hash
[ba | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | graduation_project.semgrep_rules.python- | XSS | 13 | medium |
| 进裁决 | bandit+prefilter+semgrep | crypto_weak_hash | Weak Cryptography | 11 | high |
| 去重合并 | bandit | B324 | Weak Cryptography | 11 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Weak Cryptography | 11 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Weak Cryptography | 11 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 13 | medium |

## typical_18_hardcoded_iv.py（原始候选 3 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-329 | 0 | A 盲区（零候选） | — | — |
| CWE-798 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | crypto_hardcoded_iv | Weak Cryptography | 8 | Prefilter 命中漏洞特征规则: crypto_hardcoded_iv | 形态核验通过 |
| gitleaks | python-bytes-literal-secret | python-bytes-literal-secret | 7 | Hardcoded secret assigned as Python byte | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | crypto_hardcoded_iv | Weak Cryptography | 8 | high |
| 被剔除/抑制 | bandit | B413 | B413 | 2 | high |
| 进裁决 | gitleaks | python-bytes-literal-secret | python-bytes-literal-secret | 7 | high |

## typical_19_weak_random.py（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-330 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit+prefilter | crypto_weak_random | Weak Cryptography | 10 | Prefilter 命中漏洞特征规则: crypto_weak_random
[ | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit+prefilter | crypto_weak_random | Weak Cryptography | 10 | medium |
| 去重合并 | bandit | B311 | Weak Cryptography | 10 | low |

## typical_20_insecure_tls.py（原始候选 6 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-295 | 0 | OK（候选覆盖且类型对） | bandit+semgrep·Insecure TLS·L10<br>semgrep·Insecure TLS·L10 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter+semgrep | ssrf_request_from_input | SSRF | 10 | Prefilter 命中漏洞特征规则: ssrf_request_from_in | 疑不合理：Q2_形态匹配 |
| bandit+semgrep | B501 | Insecure TLS | 10 | Call to requests with verify=False disab | 形态核验通过 |
| semgrep | models.semgrep_rules.python.django.secur | SSRF | 9 | Data from request object is passed to a  | 疑不合理：Q2_邻行形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter+semgrep | ssrf_request_from_input | SSRF | 10 | high |
| 进裁决 | bandit+semgrep | B501 | Insecure TLS | 10 | high |
| 被剔除/抑制 | bandit | B113 | B113 | 10 | medium |
| 进裁决 | semgrep | models.semgrep_rules.python.django.secur | SSRF | 9 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | SSRF | 10 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.requests.sec | Insecure TLS | 10 | high |

## typical_21_xxe.py（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-611 | 0 | OK（候选覆盖且类型对） | prefilter·XXE·L11 | — |
| CWE-610 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | xxe_unprotected_parse | XXE | 11 | Prefilter 命中漏洞特征规则: xxe_unprotected_pars | 疑不合理：Q2_邻行形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | xxe_unprotected_parse | XXE | 11 | critical |

## typical_22_csrf.py（原始候选 3 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-352 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | graduation_project.semgrep_rules.python- | XSS | 14 | 污点命中：用户可控输入流入未转义的 HTML/CSS 输出，疑似反射型 XSS（ | 形态核验通过 |
| bandit | B105 | Hardcoded Credentials | 4 | Possible hardcoded password: 'dev_key'
[ | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | graduation_project.semgrep_rules.python- | XSS | 14 | medium |
| 进裁决 | bandit | B105 | Hardcoded Credentials | 4 | low |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 14 | medium |

## typical_23_ssti.py（原始候选 6 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-1336 | 0 | OK（候选覆盖且类型对） | taint_tracker·Server-Side Template Injection·L12 | — |
| CWE-94 | 0 | A 盲区（零候选） | — | — |
| CWE-915 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 12 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |
| prefilter+semgrep | xss_unescaped_output | XSS | 10 | Prefilter 命中漏洞特征规则: xss_unescaped_output | 形态核验通过 |
| bandit+semgrep | B701 | XSS | 11 | By default, jinja2 sets autoescape to Fa | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 12 | high |
| 进裁决 | prefilter+semgrep | xss_unescaped_output | XSS | 10 | high |
| 进裁决 | bandit+semgrep | B701 | XSS | 11 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.django.secur | XSS | 10 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 10 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.jinja2.secur | XSS | 11 | medium |

## typical_24_ldap_injection.py（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-90 | 0 | A 盲区（零候选） | — | — |
| CWE-797 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | ldap_injection | LDAP Injection | 12 | Prefilter 命中漏洞特征规则: ldap_injection | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | ldap_injection | LDAP Injection | 12 | high |

## typical_25_nosql_injection.py（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-943 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | nosql_query_injection | NoSQL Injection | 13 | Prefilter 命中漏洞特征规则: nosql_query_injectio | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | nosql_query_injection | NoSQL Injection | 13 | critical |

## typical_26_xpath_injection.py（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-643 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | xpath_injection | XPath Injection | 13 | Prefilter 命中漏洞特征规则: xpath_injection | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | xpath_injection | XPath Injection | 13 | high |

## typical_27_race_condition.py（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-362 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | graduation_project.semgrep_rules.python- | XSS | 20 | 污点命中：用户可控输入流入未转义的 HTML/CSS 输出，疑似反射型 XSS（ | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | graduation_project.semgrep_rules.python- | XSS | 20 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 20 | medium |

## typical_28_info_disclosure.py（原始候选 8 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-209 | 0 | A 盲区（零候选） | — | — |
| CWE-89 | 0 | OK（候选覆盖且类型对） | semgrep·SQL Injection·L14<br>bandit+prefilter+semgrep+taint_tracker·SQL Injection·L14<br>taint_tracker·SQL Injection·L14<br>prefilter·SQL Injection·L14<br>prefilter·SQL Injection·L14<br>bandit·SQL Injection·L14<br>semgrep·SQL Injection·L9<br>semgrep·SQL Injection·L14 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit+prefilter+semgrep+taint_tracker | taint_tracker:SQL Injection | SQL Injection | 14 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |
| semgrep | models.semgrep_rules.python.django.secur | SQL Injection | 9 | User-controlled data from a request is p | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 去重合并 | semgrep | graduation_project.semgrep_rules.python- | SQL Injection | 14 | high |
| 进裁决 | bandit+prefilter+semgrep+taint_tracker | taint_tracker:SQL Injection | SQL Injection | 14 | high |
| 去重合并 | taint_tracker | taint_tracker:SQL Injection | SQL Injection | 14 | high |
| 去重合并 | prefilter | sqli_fstring | SQL Injection | 14 | high |
| 去重合并 | prefilter | sqli_constructed_query | SQL Injection | 14 | critical |
| 去重合并 | bandit | B608 | SQL Injection | 14 | medium |
| 进裁决 | semgrep | models.semgrep_rules.python.django.secur | SQL Injection | 9 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | SQL Injection | 14 | high |

## typical_29_integer_overflow.java（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-190 | 0 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | integer_overflow_ext_arith | Integer Overflow | 0 | medium |

## typical_30_mass_assignment.py（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-915 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | mass_assignment_setattr | Mass Assignment | 22 | Prefilter 命中漏洞特征规则: mass_assignment_seta | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | mass_assignment_setattr | Mass Assignment | 22 | high |

## typical_31_open_redirect_glob.py（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-601 | 0 | OK（候选覆盖且类型对） | prefilter·Open Redirect·L0<br>prefilter+semgrep·Open Redirect·L8 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter+semgrep | models.semgrep_rules.python.flask.securi | Open Redirect | 8 | Data from request is passed to redirect( | 疑不合理：Q2_邻行形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 去重合并 | prefilter | open_redirect | Open Redirect | 0 | medium |
| 进裁决 | prefilter+semgrep | models.semgrep_rules.python.flask.securi | Open Redirect | 8 | high |

## typical_32_proto_pollution.js（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-1321 | 0 | A 盲区（零候选） | — | — |
| CWE-915 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | proto_pollution_merge | Prototype Pollution | 6 | Prefilter 命中漏洞特征规则: proto_pollution_merg | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | proto_pollution_merge | Prototype Pollution | 6 | high |

## typical_33_php_type_juggling.php（原始候选 2 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-843 | 0 | A 盲区（零候选） | — | — |
| CWE-798 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | timing_unsafe_compare | Timing Attack | 10 | Prefilter 命中漏洞特征规则: timing_unsafe_compar | 疑不合理：Q2_形态匹配 |
| prefilter | php_loose_compare | Type Juggling | 10 | Prefilter 命中漏洞特征规则: php_loose_compare | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | timing_unsafe_compare | Timing Attack | 10 | medium |
| 进裁决 | prefilter | php_loose_compare | Type Juggling | 10 | high |

## typical_34_java_jdbc_sql.java（原始候选 3 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-89 | 0 | OK（候选覆盖且类型对） | semgrep·SQL Injection·L15<br>semgrep·SQL Injection·L18<br>semgrep·SQL Injection·L18 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | models.semgrep_rules.java.lang.security. | SQL Injection | 15 | Detected input from a HTTPServletRequest | 疑不合理：Q2_邻行形态匹配 |
| semgrep | models.semgrep_rules.java.lang.security. | SQL Injection | 18 | Detected a formatted string in a SQL sta | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | models.semgrep_rules.java.lang.security. | SQL Injection | 15 | medium |
| 去重合并 | semgrep | models.semgrep_rules.java.lang.security. | SQL Injection | 18 | medium |
| 进裁决 | semgrep | models.semgrep_rules.java.lang.security. | SQL Injection | 18 | high |

## typical_35_java_deser.java（原始候选 2 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-502 | 0 | OK（候选覆盖且类型对） | semgrep·Insecure Deserialization·L11 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | models.semgrep_rules.java.lang.security. | Insecure Deserialization | 11 | Found object deserialization using Objec | 形态核验通过 |
| semgrep | models.semgrep_rules.java.lang.security. | XSS | 14 | Detected a request with potential user-i | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | models.semgrep_rules.java.lang.security. | Insecure Deserialization | 11 | medium |
| 进裁决 | semgrep | models.semgrep_rules.java.lang.security. | XSS | 14 | medium |

## typical_36_java_spel.java（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-94 | 0 | A 盲区（零候选） | — | — |
| CWE-917 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | models.semgrep_rules.java.spring.securit | SpEL Injection | 9 | A Spring expression is built with a dyna | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | models.semgrep_rules.java.spring.securit | SpEL Injection | 9 | medium |

## hard_bypass_05_csrf_same_origin.py（原始候选 3 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-352 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | graduation_project.semgrep_rules.python- | XSS | 18 | 污点命中：用户可控输入流入未转义的 HTML/CSS 输出，疑似反射型 XSS（ | 形态核验通过 |
| bandit | B105 | Hardcoded Credentials | 7 | Possible hardcoded password: 'dev_key'
[ | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | graduation_project.semgrep_rules.python- | XSS | 18 | medium |
| 进裁决 | bandit | B105 | Hardcoded Credentials | 7 | low |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 18 | medium |

## hard_bypass_06_auth_string_compare.py（原始候选 3 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-208 | 0 | OK（候选覆盖且类型对） | prefilter·Timing Attack·L14 | — |
| CWE-798 | 0 | OK（候选覆盖且类型对） | bandit+gitleaks·Hardcoded Credentials·L8 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | timing_unsafe_compare | Timing Attack | 14 | Prefilter 命中漏洞特征规则: timing_unsafe_compar | 疑不合理：Q2_形态匹配 |
| bandit+gitleaks | B105 | Hardcoded Credentials | 8 | Possible hardcoded password: 'sup3r_s3cr | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | timing_unsafe_compare | Timing Attack | 14 | medium |
| 进裁决 | bandit+gitleaks | B105 | Hardcoded Credentials | 8 | low |
| 去重合并 | gitleaks | generic-api-key | generic-api-key | 8 | high |

## hard_bypass_07_ssti_attr_chain.py（原始候选 3 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-1336 | 0 | OK（候选覆盖且类型对） | taint_tracker·Server-Side Template Injection·L15 | — |
| CWE-94 | 0 | A 盲区（零候选） | — | — |
| CWE-91 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 15 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |
| bandit+semgrep | B701 | XSS | 14 | By default, jinja2 sets autoescape to Fa | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 15 | high |
| 进裁决 | bandit+semgrep | B701 | XSS | 14 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.jinja2.secur | XSS | 14 | medium |

## hard_bypass_08_jwt_none_alg.py（原始候选 4 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-347 | 0 | OK（候选覆盖且类型对） | prefilter·Improper Verification of Cryptographic Signature·L17 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | graduation_project.semgrep_rules.python- | XSS | 18 | 污点命中：用户可控输入流入未转义的 HTML/CSS 输出，疑似反射型 XSS（ | 形态核验通过 |
| prefilter | jwt_verify_disabled | Improper Verification of Cryptographic Signature | 17 | Prefilter 命中漏洞特征规则: jwt_verify_disabled | 形态核验通过 |
| bandit | B105 | Hardcoded Credentials | 8 | Possible hardcoded password: 'dev_secret | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | graduation_project.semgrep_rules.python- | XSS | 18 | medium |
| 进裁决 | prefilter | jwt_verify_disabled | Improper Verification of Cryptographic Signature | 17 | critical |
| 进裁决 | bandit | B105 | Hardcoded Credentials | 8 | low |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 18 | medium |

## hard_crossfile_03_sink.py（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-639 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit | B105 | Hardcoded Credentials | 8 | Possible hardcoded password: 'dev_key'
[ | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit | B105 | Hardcoded Credentials | 8 | low |

## hard_longfile_03_hidden_ssti.py（原始候选 9 → 最终 4）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-1336 | 0 | OK（候选覆盖且类型对） | taint_tracker·Server-Side Template Injection·L147 | — |
| CWE-94 | 0 | A 盲区（零候选） | — | — |
| CWE-79 | 0 | OK（候选覆盖且类型对） | prefilter+semgrep·XSS·L145<br>bandit+semgrep·XSS·L146<br>semgrep·XSS·L145<br>semgrep·XSS·L145<br>semgrep·XSS·L146 | — |
| CWE-798 | 0 | OK（候选覆盖且类型对） | bandit·Hardcoded Credentials·L12 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 147 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |
| prefilter+semgrep | xss_unescaped_output | XSS | 145 | Prefilter 命中漏洞特征规则: xss_unescaped_output | 形态核验通过 |
| bandit | B105 | Hardcoded Credentials | 12 | Possible hardcoded password: 'very_long_ | 形态核验通过 |
| bandit+semgrep | B701 | XSS | 146 | By default, jinja2 sets autoescape to Fa | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 147 | high |
| 进裁决 | prefilter+semgrep | xss_unescaped_output | XSS | 145 | high |
| 进裁决 | bandit | B105 | Hardcoded Credentials | 12 | low |
| 进裁决 | bandit+semgrep | B701 | XSS | 146 | high |
| 被剔除/抑制 | bandit | B104 | B104 | 181 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.django.secur | XSS | 145 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 145 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.jinja2.secur | XSS | 146 | medium |
| 被剔除/抑制 | semgrep | models.semgrep_rules.python.flask.securi | models.semgrep_rules.python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host | 181 | medium |

## hard_cve_05_spring4shell.java（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-915 | 0 | A 盲区（零候选） | — | — |
| CWE-94 | 0 | A 盲区（零候选） | — | — |
| CWE-79 | 0 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## hard_cve_06_struts2_ognl.java（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-917 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | ognl_expression_injection | SpEL Injection | 19 | Prefilter 命中漏洞特征规则: ognl_expression_inje | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | ognl_expression_injection | SpEL Injection | 19 | critical |

## hard_cve_07_tarfile_symlink.py（原始候选 4 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-22 | 0 | OK（候选覆盖且类型对） | prefilter·Path Traversal·L0<br>bandit+prefilter·Path Traversal·L19 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit+prefilter | B202 | Path Traversal | 19 | tarfile.extractall used without any vali | 疑不合理：Q2_邻行形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 去重合并 | prefilter | path_traversal_open_join | Path Traversal | 0 | high |
| 被剔除/抑制 | bandit | B108 | B108 | 9 | medium |
| 进裁决 | bandit+prefilter | B202 | Path Traversal | 19 | high |
| 被剔除/抑制 | semgrep | models.semgrep_rules.python.django.secur | models.semgrep_rules.python.django.security.injection.request-data-write.request-data-write | 14 | medium |

## hard_cve_08_fastjson_deser.java（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-502 | 0 | OK（候选覆盖且类型对） | prefilter·Insecure Deserialization·L12 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | deser_fastjson | Insecure Deserialization | 12 | Prefilter 命中漏洞特征规则: deser_fastjson | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | deser_fastjson | Insecure Deserialization | 12 | critical |
