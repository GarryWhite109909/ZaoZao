# Stage 1 候选审计清单 —— OWASP/NodeGoat

**审计统计**：OK 17 · A 盲区 6 · B 类型错标 0（A/B 逐条归因后写入工具层文档修复）


四类问题：A 盲区（该产出没产出）/ B 类型错标 / C 无关候选 / D 剔除存疑

## server.js（原始候选 8 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-79 | 137 | OK（候选覆盖且类型对） | prefilter·XSS·L137 | — |
| CWE-311 | 145 | A 盲区（零候选） | — | — |
| CWE-1004 | 78 | OK（候选覆盖且类型对） | semgrep·Insecure Cookie·L78<br>semgrep·Insecure Cookie·L78<br>semgrep·Insecure Cookie·L78<br>semgrep·Insecure Cookie·L78<br>semgrep·Insecure Cookie·L78<br>semgrep·Insecure Cookie·L78 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | log_injection_console | Log Injection | 33 | Prefilter 命中漏洞特征规则: log_injection_consol | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | template_autoescape_disabled | XSS | 137 | high |
| 进裁决 | prefilter | log_injection_console | Log Injection | 33 | low |
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
| CWE-798 | 8 | OK（候选覆盖且类型对） | detect-secrets·Hardcoded Credentials·L8 | — |
| CWE-798 | 9 | OK（候选覆盖且类型对） | detect-secrets·Hardcoded Credentials·L8 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | detect-secrets | Secret Keyword | Hardcoded Credentials | 8 | high |

## config/env/development.js（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-798 | 6 | OK（候选覆盖且类型对） | detect-secrets+gitleaks·Hardcoded Credentials·L6<br>detect-secrets·Hardcoded Credentials·L6 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | detect-secrets+gitleaks | generic-api-key | Hardcoded Credentials | 6 | high |
| 去重合并 | detect-secrets | Secret Keyword | Hardcoded Credentials | 6 | high |

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
| CWE-798 | 6 | OK（候选覆盖且类型对） | detect-secrets+gitleaks·Hardcoded Credentials·L6<br>detect-secrets·Hardcoded Credentials·L6 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | detect-secrets+gitleaks | generic-api-key | Hardcoded Credentials | 6 | high |
| 去重合并 | detect-secrets | Secret Keyword | Hardcoded Credentials | 6 | high |

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

## app/data/profile-dao.js（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-312 | 62 | OK（候选覆盖且类型对） | prefilter·Cleartext Storage of Sensitive Information·L62 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | cleartext_sensitive_storage_field | Cleartext Storage of Sensitive Information | 62 | high |

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

## app/routes/error.js（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | log_injection_console | Log Injection | 7 | Prefilter 命中漏洞特征规则: log_injection_consol | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | log_injection_console | Log Injection | 7 | low |

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

## app/routes/profile.js（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-1333 | 59 | OK（候选覆盖且类型对） | prefilter·ReDoS·L59 | — |
| CWE-79 | 65 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | redos_nested_quantifier | ReDoS | 59 | medium |

## app/routes/research.js（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-918 | 16 | OK（候选覆盖且类型对） | prefilter·SSRF·L16 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | ssrf_request_from_input | SSRF | 16 | high |

## app/routes/session.js（原始候选 4 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-117 | 64 | OK（候选覆盖且类型对） | prefilter·Log Injection·L64 | — |
| CWE-521 | 144 | OK（候选覆盖且类型对） | prefilter·Weak Password Policy·L144 | — |

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| detect-secrets | Secret Keyword | Hardcoded Credentials | 61 | 检测到疑似密钥: Secret Keyword
[命中行] const inva | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | log_injection_console | Log Injection | 64 | low |
| 进裁决 | prefilter | weak_password_policy_regex | Weak Password Policy | 144 | medium |
| 进裁决 | detect-secrets | Secret Keyword | Hardcoded Credentials | 61 | high |
| 去重合并 | detect-secrets | Secret Keyword | Hardcoded Credentials | 172 | high |

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
| CWE-798 | 18 | OK（候选覆盖且类型对） | detect-secrets·Hardcoded Credentials·L18 | — |
| CWE-798 | 27 | OK（候选覆盖且类型对） | detect-secrets·Hardcoded Credentials·L27 | — |
| CWE-798 | 35 | OK（候选覆盖且类型对） | detect-secrets·Hardcoded Credentials·L35 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | detect-secrets | Secret Keyword | Hardcoded Credentials | 18 | high |
| 去重合并 | detect-secrets | Secret Keyword | Hardcoded Credentials | 27 | high |
| 去重合并 | detect-secrets | Secret Keyword | Hardcoded Credentials | 35 | high |


---

## 依赖清单 SCA 扫描（trivy fs，§9.28）

依赖漏洞合计 **85** 个：

| 严重度 | 数量 |
|---|---|
| critical | 11 |
| high | 43 |
| medium | 20 |
| low | 11 |

| 清单文件 | 漏洞 ID | 严重度 | 说明 |
|---|---|---|---|
| package-lock.json | CVE-2020-7610 | critical | bson: Deserialization of Untrusted Data could result in Code injection or Excessive CPU load |
| package-lock.json | CVE-2023-45311 | critical | Code injection in fsevents |
| package-lock.json | CVE-2021-44906 | critical | minimist: prototype pollution |
| package-lock.json | CVE-2021-44906 | critical | minimist: prototype pollution |
| package-lock.json | CVE-2021-44906 | critical | minimist: prototype pollution |
| package-lock.json | CVE-2021-44906 | critical | minimist: prototype pollution |
| package-lock.json | CVE-2019-10746 | critical | nodejs-mixin-deep: prototype pollution in function mixin-deep |
| package-lock.json | CVE-2019-10747 | critical | nodejs-set-value: prototype pollution in function set-value |
| package-lock.json | CVE-2019-10747 | critical | nodejs-set-value: prototype pollution in function set-value |
| package-lock.json | CVE-2026-59873 | critical | tar: node-tar: Denial of Service via crafted gzip bomb |
| package-lock.json | CVE-2021-23358 | critical | nodejs-underscore: Arbitrary code execution via the template function |
| package-lock.json | CVE-2024-45590 | high | body-parser: Denial of Service Vulnerability in body-parser |
| package-lock.json | CVE-2026-13149 | high | brace-expansion: Brace-expansion: Denial of Service due to exponential-time complexity |
| package-lock.json | CVE-2026-14257 | high | brace-expansion: Brace-expansion: Denial of Service via memory exhaustion in expand() function |
| package-lock.json | CVE-2026-69152 | high | brace-expansion: DoS via unbounded intermediate arrays, bypassing the CVE-2026-14257 mitigation |
| package-lock.json | CVE-2024-4068 | high | braces: fails to limit the number of characters it can handle |
| package-lock.json | CVE-2017-20165 | high | A vulnerability classified as problematic has been found in debug-js d ... |
| package-lock.json | CVE-2022-38900 | high | decode-uri-component: improper input validation resulting in DoS |
| package-lock.json | CVE-2021-3820 | high | inflect vulnerable to Inefficient Regular Expression Complexity |
| package-lock.json | CVE-2020-7788 | high | nodejs-ini: Prototype pollution via malicious INI file |
| package-lock.json | CVE-2019-20149 | high | nodejs-kind-of: ctorName in index.js allows external user input to overwrite certain internal attributes |
| package-lock.json | CVE-2017-16114 | high | The marked module is vulnerable to a regular expression denial of serv ... |
| package-lock.json | CVE-2022-21680 | high | marked: regular expression block.def may lead Denial of Service |
| package-lock.json | CVE-2022-21681 | high | marked: regular expression inline.reflinkSearch may lead Denial of Service |
| package-lock.json | CVE-2022-3517 | high | nodejs-minimatch: ReDoS via the braceExpand function |
| package-lock.json | CVE-2026-26996 | high | minimatch: minimatch: Denial of Service via specially crafted glob patterns |
| package-lock.json | CVE-2026-27903 | high | minimatch: minimatch: Denial of Service due to unbounded recursive backtracking via crafted glob patterns |
| package-lock.json | CVE-2026-27904 | high | minimatch: Minimatch: Denial of Service via catastrophic backtracking in glob expressions |
| package-lock.json | GHSA-mh5c-679w-hh4r | high | Denial of Service in mongodb |
| package-lock.json | CVE-2022-21803 | high | nconf: Prototype pollution in memory store |
| package-lock.json | CVE-2022-21803 | high | nconf: Prototype pollution in memory store |
| package-lock.json | CVE-2024-45296 | high | path-to-regexp: Backtracking regular expressions cause ReDoS |
| package-lock.json | CVE-2024-52798 | high | path-to-regexp: path-to-regexp Unpatched `path-to-regexp` ReDoS in 0.1.x |
| package-lock.json | CVE-2026-4867 | high | path-to-regexp: path-to-regexp: Denial of Service via catastrophic backtracking from malformed URL parameters |
| package-lock.json | CVE-2022-24999 | high | express: "qs" prototype poisoning causes the hang of the node process |
| package-lock.json | CVE-2022-25883 | high | nodejs-semver: Regular expression denial of service |
| package-lock.json | CVE-2022-25883 | high | nodejs-semver: Regular expression denial of service |
| package-lock.json | CVE-2021-23440 | high | nodejs-set-value: type confusion allows bypass of CVE-2019-10747 |
| package-lock.json | CVE-2021-23440 | high | nodejs-set-value: type confusion allows bypass of CVE-2019-10747 |
| package-lock.json | CVE-2023-25345 | high | Arbitrary local file read vulnerability during template rendering  |
| package-lock.json | CVE-2021-32803 | high | nodejs-tar: Insufficient symlink protection allowing arbitrary file creation and overwrite |
| package-lock.json | CVE-2021-32804 | high | nodejs-tar: Insufficient absolute path sanitization allowing arbitrary file creation and overwrite |
| package-lock.json | CVE-2021-37701 | high | nodejs-tar: Insufficient symlink protection due to directory cache poisoning using symbolic links allowing arb |
| package-lock.json | CVE-2021-37712 | high | nodejs-tar: Insufficient symlink protection due to directory cache poisoning using symbolic links allowing arb |
| package-lock.json | CVE-2021-37713 | high | nodejs-tar: Arbitrary File Creation/Overwrite on Windows via insufficient relative path sanitization |
| package-lock.json | CVE-2026-23745 | high | node-tar: tar: node-tar: Arbitrary file overwrite and symlink poisoning via unsanitized linkpaths in archives |
| package-lock.json | CVE-2026-23950 | high | node-tar: tar: node-tar: Arbitrary file overwrite via Unicode path collision race condition |
| package-lock.json | CVE-2026-24842 | high | node-tar: tar: node-tar: Arbitrary file creation via path traversal bypass in hardlink security check |
| package-lock.json | CVE-2026-26960 | high | node-tar: node-tar: Arbitrary file read/write via malicious archive hardlink creation |
| package-lock.json | CVE-2026-29786 | high | node-tar: hardlink path traversal via drive-relative linkpath |
| package-lock.json | CVE-2026-31802 | high | tar: tar: File overwrite via drive-relative symlink traversal |
| package-lock.json | CVE-2026-59874 | high | tar: Node-tar: Denial of Service via malformed tar archive header |
| package-lock.json | CVE-2026-27601 | high | Underscore.js: Underscore.js: Denial of Service via recursive data structures in flatten and isEqual functions |
| package-lock.json | CVE-2020-7774 | high | nodejs-y18n: prototype pollution vulnerability |
| package-lock.json | CVE-2026-33750 | medium | brace-expansion: brace-expansion: Denial of Service via zero step value in brace pattern |
| package-lock.json | CVE-2019-2391 | medium | Incorrect parsing of certain JSON input may result in js-bson not corr ... |
| package-lock.json | CVE-2024-29041 | medium | express: cause malformed URLs to be evaluated |
| package-lock.json | GHSA-c3m8-x3cg-qm2c | medium | Configuration Override in helmet-csp |
| package-lock.json | CVE-2016-10531 | medium | marked is an application that is meant to parse and compile markdown.  ... |
| package-lock.json | CVE-2017-1000427 | medium | marked version 0.3.6 and earlier is vulnerable to an XSS attack in the ... |
| package-lock.json | CVE-2018-25110 | medium | Marked prior to version 0.3.17 is vulnerable to a Regular Expression D ... |
| package-lock.json | NSWG-ECO-101 | medium | Sanitization bypass using HTML Entities |
| package-lock.json | CVE-2024-4067 | medium | micromatch: vulnerable to Regular Expression Denial of Service |
| package-lock.json | CVE-2020-7598 | medium | nodejs-minimist: prototype pollution allows adding or modifying properties of Object.prototype using a constru |
| package-lock.json | CVE-2020-7598 | medium | nodejs-minimist: prototype pollution allows adding or modifying properties of Object.prototype using a constru |
| package-lock.json | CVE-2020-7598 | medium | nodejs-minimist: prototype pollution allows adding or modifying properties of Object.prototype using a constru |
| package-lock.json | CVE-2017-20162 | medium | Vercel ms Inefficient Regular Expression Complexity vulnerability |
| package-lock.json | CVE-2025-15284 | medium | qs: qs: Denial of Service via improper input validation in array parsing |
| package-lock.json | CVE-2024-28863 | medium | node-tar: denial of service while parsing a tar file due to lack of folders depth validation |
| package-lock.json | CVE-2026-53655 | medium | node-tar: node-tar: File smuggling due to inconsistent tar archive parsing |
| package-lock.json | CVE-2026-59871 | medium | node-tar: node-tar: Denial of Service due to incorrect PAX path handling |
| package-lock.json | CVE-2026-59875 | medium | node-tar: node-tar: Denial of Service via crafted archive with NUL bytes in metadata |
| package-lock.json | GHSA-r292-9mhp-454m | medium | node-tar: Uncontrolled recursion in mapHas/filesFilter allows uncatchable stack-overflow DoS via crafted long- |
| package-lock.json | CVE-2015-8858 | medium | The uglify-js package before 2.6.0 for Node.js allows attackers to cau ... |
| package-lock.json | CVE-2026-12590 | low | body-parser: body-parser: Denial of Service via invalid limit option |
| package-lock.json | CVE-2025-5889 | low | brace-expansion: juliangruber brace-expansion index.js expand redos |
| package-lock.json | CVE-2024-47764 | low | cookie: cookie accepts cookie name, path, and domain with out of bounds characters |
| package-lock.json | CVE-2017-16137 | low | nodejs-debug: Regular expression Denial of Service |
| package-lock.json | CVE-2017-16137 | low | nodejs-debug: Regular expression Denial of Service |
| package-lock.json | CVE-2024-43796 | low | express: Improper Input Handling in Express Redirects |
| package-lock.json | CVE-2025-7339 | low | on-headers: on-headers vulnerable to http response header manipulation |
| package-lock.json | CVE-2024-43799 | low | send: Code Execution Vulnerability in Send Library |
| package-lock.json | CVE-2024-43800 | low | serve-static: Improper Sanitization in serve-static |
| package-lock.json | NSWG-ECO-445 | low | Out-of-bounds Read |
| package-lock.json | NSWG-ECO-445 | low | Out-of-bounds Read |

> 口径：SCA 为**项目级**证据（依赖版本含已知 CVE），非行级；
> 不计入上文 A/B/C 判定（§9.28 口径说明）。