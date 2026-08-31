# Stage 1 候选审计清单 —— we45/Vulnerable-Flask-App

**审计统计**：OK 9 · A 盲区 6 · B 类型错标 2（A/B 逐条归因后写入工具层文档修复）


四类问题：A 盲区（该产出没产出）/ B 类型错标 / C 无关候选 / D 剔除存疑

## app/app.py（原始候选 24 → 最终 10）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-798 | 26 | OK（候选覆盖且类型对） | bandit·Hardcoded Credentials·L26<br>bandit·Hardcoded Credentials·L27<br>bandit·Hardcoded Credentials·L28 | — |
| CWE-798 | 62 | OK（候选覆盖且类型对） | bandit·Hardcoded Credentials·L63 | — |
| CWE-347 | 97 | A 盲区（零候选） | — | — |
| CWE-79 | 112 | B 候选在但类型错标 | semgrep·Server-Side Template Injection(原:home.zane..c)·L114 | — |
| CWE-1336 | 114 | OK（候选覆盖且类型对） | semgrep·Server-Side Template Injection(原:home.zane..c)·L114 | — |
| CWE-916 | 141 | OK（候选覆盖且类型对） | bandit+prefilter+semgrep·Weak Cryptography·L141<br>bandit·Weak Cryptography(原:B324)·L141<br>semgrep·Weak Cryptography(原:home.zane..c)·L141<br>semgrep·Weak Cryptography(原:home.zane..c)·L141 | — |
| CWE-209 | 148 | A 盲区（零候选） | — | — |
| CWE-312 | 160 | A 盲区（零候选） | — | — |
| CWE-639 | 208 | A 盲区（零候选） | — | — |
| CWE-639 | 231 | A 盲区（零候选） | — | — |
| CWE-89 | 261 | OK（候选覆盖且类型对） | bandit+semgrep·SQL Injection(原:B608)·L261<br>semgrep·SQL Injection(原:home.zane..c)·L261 | — |
| CWE-1336 | 281 | OK（候选覆盖且类型对） | semgrep·Server-Side Template Injection(原:home.zane..c)·L281 | — |
| CWE-502 | 329 | OK（候选覆盖且类型对） | bandit+prefilter+semgrep·Insecure Deserialization·L329<br>bandit·Insecure Deserialization(原:B506)·L329<br>semgrep·Insecure Deserialization(原:home.zane..c)·L329 | — |
| CWE-434 | 294 | B 候选在但类型错标 | bandit·Weak Cryptography(原:B311)·L295 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| taint_tracker | taint_tracker:Path Traversal | Path Traversal | 300 | TaintTracker AST 污点分析定位的同文件 source→sink  | 形态核验通过 |
| taint_tracker | taint_tracker:Path Traversal | Path Traversal | 326 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |
| semgrep | home.zane..code..models.semgrep_rules.py | home.zane..code..models.semgrep_rules.python.flask.security.dangerous-template-string.dangerous-template-string | 103 | Found a template created with string for | 形态核验通过 |
| semgrep | home.zane..code..models.semgrep_rules.py | home.zane..code..models.semgrep_rules.python.django.security.injection.raw-html-format.raw-html-format | 103 | Detected user input flowing into a manua | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | taint_tracker | taint_tracker:Path Traversal | Path Traversal | 300 | high |
| 去重合并 | taint_tracker | taint_tracker:Path Traversal | Path Traversal | 324 | high |
| 进裁决 | taint_tracker | taint_tracker:Path Traversal | Path Traversal | 326 | high |
| 进裁决 | bandit+prefilter+semgrep | deser_yaml_unsafe_load | Insecure Deserialization | 329 | high |
| 进裁决 | bandit+prefilter+semgrep | crypto_weak_hash | Weak Cryptography | 141 | high |
| 进裁决 | bandit | B105 | Hardcoded Credentials | 26 | low |
| 去重合并 | bandit | B105 | Hardcoded Credentials | 27 | low |
| 去重合并 | bandit | B105 | Hardcoded Credentials | 28 | low |
| 去重合并 | bandit | B105 | Hardcoded Credentials | 63 | low |
| 去重合并 | bandit | B324 | B324 | 141 | high |
| 进裁决 | bandit+semgrep | B608 | B608 | 261 | medium |
| 进裁决 | bandit | B311 | B311 | 295 | low |
| 去重合并 | bandit | B311 | B311 | 319 | low |
| 去重合并 | bandit | B506 | B506 | 329 | medium |
| 进裁决 | semgrep | home.zane..code..models.semgrep_rules.py | home.zane..code..models.semgrep_rules.python.flask.security.dangerous-template-string.dangerous-template-string | 103 | high |
| 进裁决 | semgrep | home.zane..code..models.semgrep_rules.py | home.zane..code..models.semgrep_rules.python.django.security.injection.raw-html-format.raw-html-format | 103 | medium |
| 去重合并 | semgrep | home.zane..code..models.semgrep_rules.py | home.zane..code..models.semgrep_rules.python.flask.security.injection.raw-html-concat.raw-html-format | 103 | medium |
| 进裁决 | semgrep | home.zane..code..models.semgrep_rules.py | home.zane..code..models.semgrep_rules.python.flask.security.audit.render-template-string.render-template-string | 114 | medium |
| 去重合并 | semgrep | home.zane..code..models.semgrep_rules.py | home.zane..code..models.semgrep_rules.python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5 | 141 | medium |
| 去重合并 | semgrep | home.zane..code..models.semgrep_rules.py | home.zane..code..models.semgrep_rules.python.lang.security.audit.md5-used-as-password.md5-used-as-password | 141 | medium |
| 去重合并 | semgrep | home.zane..code..models.semgrep_rules.py | home.zane..code..models.semgrep_rules.python.flask.security.injection.tainted-sql-string.tainted-sql-string | 261 | high |
| 去重合并 | semgrep | home.zane..code..models.semgrep_rules.py | home.zane..code..models.semgrep_rules.python.flask.security.dangerous-template-string.dangerous-template-string | 271 | high |
| 去重合并 | semgrep | home.zane..code..models.semgrep_rules.py | home.zane..code..models.semgrep_rules.python.flask.security.audit.render-template-string.render-template-string | 281 | medium |
| 去重合并 | semgrep | home.zane..code..models.semgrep_rules.py | home.zane..code..models.semgrep_rules.python.flask.security.insecure-deserialization.insecure-deserialization | 329 | high |

## tests/e2e_zap.py（原始候选 13 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-295 | 18 | OK（候选覆盖且类型对） | bandit·Insecure TLS(原:B501)·L18<br>semgrep·Insecure TLS(原:home.zane..c)·L17 | bandit·B113·L17 |
| CWE-798 | 15 | OK（候选覆盖且类型对） | bandit·Hardcoded Credentials·L15<br>semgrep·Insecure TLS(原:home.zane..c)·L17 | bandit·B113·L17 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit | B105 | Hardcoded Credentials | 15 | low |
| 进裁决 | bandit | B501 | B501 | 18 | high |
| 被剔除/抑制 | bandit | B113 | B113 | 17 | medium |
| 去重合并 | bandit | B501 | B501 | 29 | high |
| 被剔除/抑制 | bandit | B113 | B113 | 28 | medium |
| 去重合并 | bandit | B501 | B501 | 37 | high |
| 被剔除/抑制 | bandit | B113 | B113 | 36 | medium |
| 去重合并 | bandit | B501 | B501 | 45 | high |
| 被剔除/抑制 | bandit | B113 | B113 | 44 | medium |
| 进裁决 | semgrep | home.zane..code..models.semgrep_rules.py | home.zane..code..models.semgrep_rules.python.requests.security.disabled-cert-validation.disabled-cert-validation | 17 | high |
| 去重合并 | semgrep | home.zane..code..models.semgrep_rules.py | home.zane..code..models.semgrep_rules.python.requests.security.disabled-cert-validation.disabled-cert-validation | 28 | high |
| 去重合并 | semgrep | home.zane..code..models.semgrep_rules.py | home.zane..code..models.semgrep_rules.python.requests.security.disabled-cert-validation.disabled-cert-validation | 36 | high |
| 去重合并 | semgrep | home.zane..code..models.semgrep_rules.py | home.zane..code..models.semgrep_rules.python.requests.security.disabled-cert-validation.disabled-cert-validation | 44 | high |

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
| semgrep | home.zane..code..models.semgrep_rules.ge | home.zane..code..models.semgrep_rules.generic.html-templates.security.var-in-href.var-in-href | 12 | Detected a template variable used in an  | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | home.zane..code..models.semgrep_rules.ge | home.zane..code..models.semgrep_rules.generic.html-templates.security.var-in-href.var-in-href | 12 | medium |

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

## app/static/loader.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## app/__init__.py（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
