# Stage 1 候选审计清单 —— we45/Vulnerable-Flask-App

**审计统计**：OK 13 · A 盲区 3 · B 类型错标 1（A/B 逐条归因后写入工具层文档修复）


四类问题：A 盲区（该产出没产出）/ B 类型错标 / C 无关候选 / D 剔除存疑

## app/app.py（原始候选 33 → 最终 15）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-798 | 26 | OK（候选覆盖且类型对） | bandit·Hardcoded Credentials·L26<br>bandit·Hardcoded Credentials·L27<br>bandit·Hardcoded Credentials·L28<br>detect-secrets·Secret Keyword·L26<br>detect-secrets·Secret Keyword·L27<br>detect-secrets·Secret Keyword·L28 | — |
| CWE-798 | 62 | OK（候选覆盖且类型对） | bandit·Hardcoded Credentials·L63<br>detect-secrets·Secret Keyword·L63 | — |
| CWE-347 | 97 | OK（候选覆盖且类型对） | prefilter·Improper Verification of Cryptographic Signature·L97 | — |
| CWE-79 | 112 | B 候选在但类型错标 | semgrep·Server-Side Template Injection·L114 | — |
| CWE-1336 | 114 | OK（候选覆盖且类型对） | semgrep·Server-Side Template Injection·L114 | — |
| CWE-916 | 141 | OK（候选覆盖且类型对） | bandit+prefilter+semgrep·Weak Cryptography·L141<br>bandit·Weak Cryptography·L141<br>semgrep·Weak Cryptography·L141<br>semgrep·Weak Cryptography·L141 | — |
| CWE-209 | 148 | OK（候选覆盖且类型对） | prefilter·Information Exposure Through Error Message·L148 | — |
| CWE-312 | 160 | OK（候选覆盖且类型对） | prefilter·Cleartext Storage of Sensitive Information·L160 | — |
| CWE-639 | 208 | A 盲区（零候选） | — | — |
| CWE-639 | 231 | A 盲区（零候选） | — | — |
| CWE-89 | 261 | OK（候选覆盖且类型对） | bandit+prefilter+semgrep·SQL Injection·L261<br>bandit·SQL Injection·L261<br>semgrep·SQL Injection·L261 | — |
| CWE-1336 | 281 | OK（候选覆盖且类型对） | semgrep·Server-Side Template Injection·L281 | — |
| CWE-502 | 329 | OK（候选覆盖且类型对） | bandit+prefilter+semgrep·Insecure Deserialization·L329<br>bandit·Insecure Deserialization·L329<br>semgrep·Insecure Deserialization·L329 | — |
| CWE-434 | 294 | OK（候选覆盖且类型对） | prefilter·Unrestricted File Upload·L294<br>bandit·Weak Cryptography·L295 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| taint_tracker | taint_tracker:Path Traversal | Path Traversal | 300 | TaintTracker AST 污点分析定位的同文件 source→sink  | 形态核验通过 |
| taint_tracker | taint_tracker:Path Traversal | Path Traversal | 326 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |
| semgrep | models.semgrep_rules.python.flask.securi | Server-Side Template Injection | 103 | Found a template created with string for | 疑不合理：Q2_形态匹配 |
| semgrep | models.semgrep_rules.python.django.secur | XSS | 103 | Detected user input flowing into a manua | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | taint_tracker | taint_tracker:Path Traversal | Path Traversal | 300 | high |
| 去重合并 | taint_tracker | taint_tracker:Path Traversal | Path Traversal | 324 | high |
| 进裁决 | taint_tracker | taint_tracker:Path Traversal | Path Traversal | 326 | high |
| 进裁决 | bandit+prefilter+semgrep | deser_yaml_unsafe_load | Insecure Deserialization | 329 | high |
| 进裁决 | bandit+prefilter+semgrep | crypto_weak_hash | Weak Cryptography | 141 | high |
| 进裁决 | prefilter | jwt_verify_disabled | Improper Verification of Cryptographic Signature | 97 | critical |
| 进裁决 | prefilter | error_info_exposure | Information Exposure Through Error Message | 148 | medium |
| 进裁决 | prefilter | cleartext_sensitive_storage | Cleartext Storage of Sensitive Information | 160 | high |
| 进裁决 | prefilter | unrestricted_file_upload | Unrestricted File Upload | 294 | medium |
| 进裁决 | bandit+prefilter+semgrep | sqli_constructed_query | SQL Injection | 261 | critical |
| 进裁决 | bandit | B105 | Hardcoded Credentials | 26 | low |
| 去重合并 | bandit | B105 | Hardcoded Credentials | 27 | low |
| 去重合并 | bandit | B105 | Hardcoded Credentials | 28 | low |
| 去重合并 | bandit | B105 | Hardcoded Credentials | 63 | low |
| 去重合并 | bandit | B324 | Weak Cryptography | 141 | high |
| 去重合并 | bandit | B608 | SQL Injection | 261 | medium |
| 进裁决 | bandit | B311 | Weak Cryptography | 295 | low |
| 去重合并 | bandit | B311 | Weak Cryptography | 319 | low |
| 去重合并 | bandit | B506 | Insecure Deserialization | 329 | medium |
| 进裁决 | semgrep | models.semgrep_rules.python.flask.securi | Server-Side Template Injection | 103 | high |
| 进裁决 | semgrep | models.semgrep_rules.python.django.secur | XSS | 103 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | XSS | 103 | medium |
| 进裁决 | semgrep | models.semgrep_rules.python.flask.securi | Server-Side Template Injection | 114 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Weak Cryptography | 141 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Weak Cryptography | 141 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | SQL Injection | 261 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | Server-Side Template Injection | 271 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | Server-Side Template Injection | 281 | medium |
| 去重合并 | semgrep | models.semgrep_rules.python.flask.securi | Insecure Deserialization | 329 | high |
| 进裁决 | detect-secrets | Secret Keyword | Secret Keyword | 26 | high |
| 去重合并 | detect-secrets | Secret Keyword | Secret Keyword | 27 | high |
| 去重合并 | detect-secrets | Secret Keyword | Secret Keyword | 28 | high |
| 去重合并 | detect-secrets | Secret Keyword | Secret Keyword | 63 | high |

## tests/e2e_zap.py（原始候选 15 → 最终 5）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-295 | 18 | OK（候选覆盖且类型对） | prefilter·SSRF·L17<br>bandit·Insecure TLS·L18<br>semgrep·Insecure TLS·L17 | bandit·B113·L17 |
| CWE-798 | 15 | OK（候选覆盖且类型对） | prefilter·SSRF·L17<br>bandit·Hardcoded Credentials·L15<br>semgrep·Insecure TLS·L17<br>detect-secrets·Secret Keyword·L15 | bandit·B113·L17 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | ssrf_request_from_input | SSRF | 17 | high |
| 进裁决 | bandit | B105 | Hardcoded Credentials | 15 | low |
| 进裁决 | bandit | B501 | Insecure TLS | 18 | high |
| 被剔除/抑制 | bandit | B113 | B113 | 17 | medium |
| 去重合并 | bandit | B501 | Insecure TLS | 29 | high |
| 被剔除/抑制 | bandit | B113 | B113 | 28 | medium |
| 去重合并 | bandit | B501 | Insecure TLS | 37 | high |
| 被剔除/抑制 | bandit | B113 | B113 | 36 | medium |
| 去重合并 | bandit | B501 | Insecure TLS | 45 | high |
| 被剔除/抑制 | bandit | B113 | B113 | 44 | medium |
| 进裁决 | semgrep | models.semgrep_rules.python.requests.sec | Insecure TLS | 17 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.requests.sec | Insecure TLS | 28 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.requests.sec | Insecure TLS | 36 | high |
| 去重合并 | semgrep | models.semgrep_rules.python.requests.sec | Insecure TLS | 44 | high |
| 进裁决 | detect-secrets | Secret Keyword | Secret Keyword | 15 | high |

## app/templates/layout.html（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-311 | 5 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/templates/index.html（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | models.semgrep_rules.generic.html-templa | XSS | 12 | Detected a template variable used in an  | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | models.semgrep_rules.generic.html-templa | XSS | 12 | medium |

## app/templates/test.html（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/templates/yaml_test.html（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/templates/view.html（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/static/loader.js（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | xss_unescaped_output | XSS | 94 | Prefilter 命中漏洞特征规则: xss_unescaped_output | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | xss_unescaped_output | XSS | 94 | high |

## app/__init__.py（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
