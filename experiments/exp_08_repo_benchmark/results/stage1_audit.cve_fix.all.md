# Stage 1 候选审计清单 —— experiments/exp_06_finetune/testset_cve_fix/manifest.json

**审计统计**：OK 13 · A 盲区 9 · B 类型错标 0（A/B 逐条归因后写入工具层文档修复）


四类问题：A 盲区（该产出没产出）/ B 类型错标 / C 无关候选 / D 剔除存疑

## cve_fix_0001.java（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-90 | 0 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## cve_fix_0002.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-90 | 0 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## cve_fix_0003.py（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-95 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit+semgrep | B307 | Code Injection | 20 | Use of possibly insecure function - cons | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit+semgrep | B307 | Code Injection | 20 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Code Injection | 20 | medium |

## cve_fix_0004.py（原始候选 3 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-95 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | error_info_exposure | Information Exposure Through Error Message | 38 | Prefilter 命中漏洞特征规则: error_info_exposure | 形态核验通过 |
| bandit+semgrep | B307 | Code Injection | 35 | Use of possibly insecure function - cons | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | error_info_exposure | Information Exposure Through Error Message | 38 | medium |
| 进裁决 | bandit+semgrep | B307 | Code Injection | 35 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Code Injection | 35 | medium |

## cve_fix_0005.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-441 | 0 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## cve_fix_0006.js（原始候选 2 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-441 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | timing_unsafe_compare | Timing Attack | 18 | Prefilter 命中漏洞特征规则: timing_unsafe_compar | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | open_redirect | Open Redirect | 0 | medium |
| 进裁决 | prefilter | timing_unsafe_compare | Timing Attack | 18 | medium |

## cve_fix_0007.py（原始候选 10 → 最终 4）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-502 | 0 | OK（候选覆盖且类型对） | prefilter+semgrep·Insecure Deserialization·L171<br>semgrep·Insecure Deserialization·L141<br>semgrep·Insecure Deserialization·L141<br>semgrep·Insecure Deserialization·L171<br>semgrep·Insecure Deserialization·L171<br>semgrep·Insecure Deserialization·L272<br>semgrep·Insecure Deserialization·L272<br>semgrep·Insecure Deserialization·L305<br>semgrep·Insecure Deserialization·L305 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter+semgrep | deser_pickle_loads | Insecure Deserialization | 171 | Prefilter 命中漏洞特征规则: deser_pickle_loads
[ | 疑不合理：Q2_形态匹配 |
| semgrep | models.semgrep_rules.python.lang.securit | Weak Cryptography | 47 | Detected MD5 hash algorithm which is con | 形态核验通过 |
| semgrep | models.semgrep_rules.python.lang.securit | Insecure Deserialization | 141 | Avoid using `cPickle`, which is known to | 疑不合理：Q2_形态匹配 |
| semgrep | models.semgrep_rules.python.lang.securit | Insecure Deserialization | 272 | Avoid using `pickle`, which is known to  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter+semgrep | deser_pickle_loads | Insecure Deserialization | 171 | critical |
| 进裁决 | semgrep | models.semgrep_rules.python.lang.securit | Weak Cryptography | 47 | medium |
| 进裁决 | semgrep | models.semgrep_rules.python.lang.securit | Insecure Deserialization | 141 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Insecure Deserialization | 141 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Insecure Deserialization | 171 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Insecure Deserialization | 171 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Insecure Deserialization | 272 | medium |
| 进裁决 | semgrep | models.semgrep_rules.python.lang.securit | Insecure Deserialization | 272 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Insecure Deserialization | 305 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Insecure Deserialization | 305 | medium |

## cve_fix_0009.py（原始候选 6 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-89 | 0 | OK（候选覆盖且类型对） | semgrep·SQL Injection·L17<br>semgrep+taint_tracker·SQL Injection·L17<br>bandit+semgrep·SQL Injection·L14<br>semgrep·SQL Injection·L14 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep+taint_tracker | taint_tracker:SQL Injection | SQL Injection | 17 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |
| bandit+semgrep | B608 | SQL Injection | 14 | Possible SQL injection vector through st | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 去重合并 | semgrep | graduation_project.semgrep_rules.python- | SQL Injection | 17 | high |
| 进裁决 | semgrep+taint_tracker | taint_tracker:SQL Injection | SQL Injection | 17 | high |
| 进裁决 | bandit+semgrep | B608 | SQL Injection | 14 | medium |
| 被剔除/抑制 | bandit | B104 | B104 | 31 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | SQL Injection | 14 | high |
| 被剔除/抑制 | semgrep | models.semgrep_rules.python.flask.securi | models.semgrep_rules.python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host | 31 | medium |

## cve_fix_0010.java（原始候选 4 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-89 | 0 | OK（候选覆盖且类型对） | semgrep+taint_tracker·SQL Injection·L28<br>semgrep·SQL Injection·L27<br>semgrep·SQL Injection·L28<br>semgrep·SQL Injection·L28 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep+taint_tracker | taint_tracker:SQL Injection | SQL Injection | 28 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |
| semgrep | models.semgrep_rules.java.lang.security. | SQL Injection | 27 | Detected input from a HTTPServletRequest | 疑不合理：Q2_邻行形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep+taint_tracker | taint_tracker:SQL Injection | SQL Injection | 28 | high |
| 进裁决 | semgrep | models.semgrep_rules.java.lang.security. | SQL Injection | 27 | medium |
| 去重合并 | semgrep | models.semgrep_rules.java.lang.security. | SQL Injection | 28 | medium |
| 去重合并 | semgrep | models.semgrep_rules.java.lang.security. | SQL Injection | 28 | high |

## cve_fix_0011.php（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-89 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | models.semgrep_rules.php.lang.security.i | XSS | 38 | `Echo`ing user input risks cross-site sc | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | models.semgrep_rules.php.lang.security.i | XSS | 38 | high |

## cve_fix_0012.py（原始候选 9 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-78 | 0 | OK（候选覆盖且类型对） | semgrep·Command Injection·L22<br>bandit+semgrep+taint_tracker·Command Injection·L22<br>bandit·Command Injection·L4<br>bandit·Command Injection·L22<br>semgrep·Command Injection·L22<br>semgrep·Command Injection·L22<br>semgrep·Command Injection·L22 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit+semgrep+taint_tracker | taint_tracker:Command Injection | Command Injection | 22 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |
| bandit | B404 | Command Injection | 4 | Consider possible security implications  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 去重合并 | semgrep | graduation_project.semgrep_rules.python- | Command Injection | 22 | critical |
| 进裁决 | bandit+semgrep+taint_tracker | taint_tracker:Command Injection | Command Injection | 22 | critical |
| 进裁决 | bandit | B404 | Command Injection | 4 | low |
| 去重合并 | bandit | B602 | Command Injection | 22 | high |
| 被剔除/抑制 | bandit | B104 | B104 | 30 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | Command Injection | 22 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Command Injection | 22 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Command Injection | 22 | high |
| 被剔除/抑制 | semgrep | models.semgrep_rules.python.flask.securi | models.semgrep_rules.python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host | 30 | medium |

## cve_fix_0013.js（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-78 | 0 | OK（候选覆盖且类型对） | semgrep+taint_tracker·Command Injection·L15<br>semgrep·Command Injection·L15 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep+taint_tracker | taint_tracker:Command Injection | Command Injection | 15 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep+taint_tracker | taint_tracker:Command Injection | Command Injection | 15 | critical |
| 去重合并 | semgrep | models.semgrep_rules.javascript.lang.sec | Command Injection | 15 | high |

## cve_fix_0014.py（原始候选 5 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-79 | 0 | OK（候选覆盖且类型对） | semgrep·XSS·L29<br>semgrep·XSS·L22<br>semgrep·XSS·L22 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | graduation_project.semgrep_rules.python- | XSS | 29 | 污点命中：用户可控输入流入未转义的 HTML/CSS 输出，疑似反射型 XSS（ | 形态核验通过 |
| semgrep | models.semgrep_rules.python.django.secur | XSS | 22 | Detected user input flowing into a manua | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | graduation_project.semgrep_rules.python- | XSS | 29 | medium |
| 被剔除/抑制 | bandit | B104 | B104 | 35 | medium |
| 进裁决 | semgrep | models.semgrep_rules.python.django.secur | XSS | 22 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 22 | medium |
| 被剔除/抑制 | semgrep | models.semgrep_rules.python.flask.securi | models.semgrep_rules.python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host | 35 | medium |

## cve_fix_0015.java（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-79 | 0 | OK（候选覆盖且类型对） | semgrep·XSS·L26<br>semgrep·XSS·L27 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | models.semgrep_rules.java.lang.security. | XSS | 26 | Detected a request with potential user-i | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | models.semgrep_rules.java.lang.security. | XSS | 26 | medium |
| 去重合并 | semgrep | models.semgrep_rules.java.lang.security. | XSS | 27 | medium |

## cve_fix_0016.py（原始候选 3 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-22 | 0 | OK（候选覆盖且类型对） | prefilter·Path Traversal·L0 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | path_traversal_open_join | Path Traversal | 0 | high |
| 被剔除/抑制 | bandit | B104 | B104 | 26 | medium |
| 被剔除/抑制 | semgrep | models.semgrep_rules.python.flask.securi | models.semgrep_rules.python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host | 26 | medium |

## cve_fix_0017.java（原始候选 3 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-22 | 0 | OK（候选覆盖且类型对） | prefilter·Path Traversal·L0 | semgrep·models.semgrep_rules.java.spring.security.injection.tainted-file-path.tainted-file-path·L25<br>semgrep·models.semgrep_rules.java.spring.security.injection.tainted-file-path.tainted-file-path·L26 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | path_traversal_open_join | Path Traversal | 0 | high |
| 被剔除/抑制 | semgrep | models.semgrep_rules.java.spring.securit | models.semgrep_rules.java.spring.security.injection.tainted-file-path.tainted-file-path | 25 | high |
| 被剔除/抑制 | semgrep | models.semgrep_rules.java.spring.securit | models.semgrep_rules.java.spring.security.injection.tainted-file-path.tainted-file-path | 26 | high |

## cve_fix_0018.py（原始候选 6 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-798 | 0 | OK（候选覆盖且类型对） | bandit·Hardcoded Credentials·L13<br>bandit·Hardcoded Credentials·L17 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | graduation_project.semgrep_rules.python- | SQL Injection | 34 | 污点命中：用户可控输入流入 SQL 执行，疑似 SQL 注入（待 LLM 裁决） | 疑不合理：Q2_形态匹配 |
| bandit | B105 | Hardcoded Credentials | 13 | Possible hardcoded password: '0p3nmrs_s3 | 形态核验通过 |
| gitleaks | aws-access-key-id | aws-access-key-id | 16 | AWS Access Key ID literal (AKIA/ASIA/ABI | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | graduation_project.semgrep_rules.python- | SQL Injection | 34 | high |
| 进裁决 | bandit | B105 | Hardcoded Credentials | 13 | low |
| 去重合并 | bandit | B105 | Hardcoded Credentials | 17 | low |
| 被剔除/抑制 | bandit | B104 | B104 | 43 | medium |
| 被剔除/抑制 | semgrep | models.semgrep_rules.python.flask.securi | models.semgrep_rules.python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host | 43 | medium |
| 进裁决 | gitleaks | aws-access-key-id | aws-access-key-id | 16 | high |

## cve_fix_0019.py（原始候选 7 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-1336 | 0 | OK（候选覆盖且类型对） | semgrep+taint_tracker·Server-Side Template Injection·L24<br>taint_tracker·Server-Side Template Injection·L24<br>semgrep·Server-Side Template Injection·L24 | — |
| CWE-94 | 0 | A 盲区（零候选） | — | — |
| CWE-918 | 0 | A 盲区（零候选） | — | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | graduation_project.semgrep_rules.python- | XSS | 24 | 污点命中：用户可控输入流入未转义的 HTML/CSS 输出，疑似反射型 XSS（ | 形态核验通过 |
| semgrep+taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 24 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |
| taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 24 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |
| prefilter | error_info_exposure | Information Exposure Through Error Message | 27 | Prefilter 命中漏洞特征规则: error_info_exposure | 形态核验通过 |

### 重复候选（同规则+同类型+同行多报，去重失败信号）

- taint_tracker·Server-Side Template Injection·L24

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | graduation_project.semgrep_rules.python- | XSS | 24 | medium |
| 进裁决 | semgrep+taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 24 | high |
| 进裁决 | taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 24 | high |
| 进裁决 | prefilter | error_info_exposure | Information Exposure Through Error Message | 27 | medium |
| 被剔除/抑制 | bandit | B104 | B104 | 31 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | Server-Side Template Injection | 24 | medium |
| 被剔除/抑制 | semgrep | models.semgrep_rules.python.flask.securi | models.semgrep_rules.python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host | 31 | medium |

## cve_fix_0020.py（原始候选 5 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-918 | 0 | OK（候选覆盖且类型对） | semgrep·SSRF·L13<br>semgrep·SSRF·L25 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | error_info_exposure | Information Exposure Through Error Message | 32 | Prefilter 命中漏洞特征规则: error_info_exposure | 形态核验通过 |
| semgrep | models.semgrep_rules.python.django.secur | SSRF | 13 | Data from request object is passed to a  | 形态核验通过 |
| semgrep | models.semgrep_rules.python.flask.securi | SSRF | 25 | Data from request object is passed to a  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | error_info_exposure | Information Exposure Through Error Message | 32 | medium |
| 被剔除/抑制 | bandit | B104 | B104 | 36 | medium |
| 进裁决 | semgrep | models.semgrep_rules.python.django.secur | SSRF | 13 | high |
| 进裁决 | semgrep | models.semgrep_rules.python.flask.securi | SSRF | 25 | high |
| 被剔除/抑制 | semgrep | models.semgrep_rules.python.flask.securi | models.semgrep_rules.python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host | 36 | medium |

## cve_fix_0021.java（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-611 | 0 | OK（候选覆盖且类型对） | semgrep·XXE·L22 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | models.semgrep_rules.java.lang.security. | XXE | 22 | DOCTYPE declarations are enabled for thi | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | models.semgrep_rules.java.lang.security. | XXE | 22 | high |
