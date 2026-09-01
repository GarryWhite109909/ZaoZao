# Stage 1 候选审计清单 —— experiments/exp_06_finetune/corpus/rolling_dev_safe/manifest.json

**审计统计**：OK 0 · A 盲区 0 · B 类型错标 0（A/B 逐条归因后写入工具层文档修复）


四类问题：A 盲区（该产出没产出）/ B 类型错标 / C 无关候选 / D 剔除存疑

## corpus_00001.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00002.py（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00003.go（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00004.php（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| detect-secrets | Secret Keyword | Hardcoded Credentials | 145 | 检测到疑似密钥: Secret Keyword
[命中行] 'current_p | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | detect-secrets | Secret Keyword | Hardcoded Credentials | 145 | high |

## corpus_00005.java（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00030.go（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00031.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00032.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00033.py（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00041.py（原始候选 1 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 被剔除/抑制 | bandit | B101 | B101 | 232 | low |

## corpus_00042.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00043.java（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00052.php（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00053.php（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00054.js（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | log_injection | Log Injection | 0 | medium |

## corpus_00055.java（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00056.java（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| semgrep | models.semgrep_rules.java.lang.security. | Insecure Deserialization | 266 | Found object deserialization using Objec | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | semgrep | models.semgrep_rules.java.lang.security. | Insecure Deserialization | 266 | medium |

## corpus_00057.py（原始候选 10 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit+prefilter+semgrep | deser_pickle_loads | Insecure Deserialization | 247 | Prefilter 命中漏洞特征规则: deser_pickle_loads
[ | 疑不合理：Q2_形态匹配 |
| bandit | B403 | Insecure Deserialization | 245 | Consider possible security implications  | 疑不合理：Q2_形态匹配 |
| semgrep | models.semgrep_rules.python.lang.securit | Insecure Deserialization | 308 | Avoid using `pickle`, which is known to  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit+prefilter+semgrep | deser_pickle_loads | Insecure Deserialization | 247 | critical |
| 被剔除/抑制 | bandit | B101 | B101 | 131 | low |
| 被剔除/抑制 | bandit | B101 | B101 | 157 | low |
| 被剔除/抑制 | bandit | B614 | B614 | 235 | medium |
| 进裁决 | bandit | B403 | Insecure Deserialization | 245 | low |
| 去重合并 | bandit | B301 | Insecure Deserialization | 247 | medium |
| 被剔除/抑制 | bandit | B101 | B101 | 280 | low |
| 去重合并 | bandit | B403 | Insecure Deserialization | 305 | low |
| 去重合并 | semgrep | models.semgrep_rules.python.lang.securit | Insecure Deserialization | 247 | medium |
| 进裁决 | semgrep | models.semgrep_rules.python.lang.securit | Insecure Deserialization | 308 | medium |

## corpus_00058.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00059.java（原始候选 2 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | open_redirect | Open Redirect | 0 | medium |
| 进裁决 | prefilter | log_injection | Log Injection | 0 | medium |

## corpus_00060.java（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00061.java（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00062.php（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00063.js（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00065.go（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00066.go（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00067.py（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 138 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 138 | high |

## corpus_00068.py（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 122 | TaintTracker AST 污点分析定位的同文件 source→sink  | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 122 | high |

## corpus_00069.php（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00070.php（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00071.py（原始候选 2 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | log_injection | Log Injection | 0 | medium |
| 被剔除/抑制 | bandit | B104 | B104 | 400 | medium |

## corpus_00072.go（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00073.py（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00074.go（原始候选 2 → 最终 2）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| prefilter | timing_unsafe_compare | Timing Attack | 344 | Prefilter 命中漏洞特征规则: timing_unsafe_compar | 形态核验通过 |
| detect-secrets | Secret Keyword | Hardcoded Credentials | 345 | 检测到疑似密钥: Secret Keyword
[命中行] provider.C | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | prefilter | timing_unsafe_compare | Timing Attack | 344 | medium |
| 进裁决 | detect-secrets | Secret Keyword | Hardcoded Credentials | 345 | high |

## corpus_00075.go（原始候选 1 → 最终 1）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| detect-secrets | Basic Auth Credentials | Hardcoded Credentials | 36 | 检测到疑似密钥: Basic Auth Credentials
[命中行] UR | 形态核验通过 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | detect-secrets | Basic Auth Credentials | Hardcoded Credentials | 36 | high |

## corpus_00076.go（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00077.py（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00078.py（原始候选 5 → 最终 3）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）

| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |
|---|---|---|---|---|---|
| bandit | B404 | Command Injection | 11 | Consider possible security implications  | 疑不合理：Q2_形态匹配 |
| bandit | B603 | Command Injection | 96 | subprocess call - check for execution of | 疑不合理：Q2_形态匹配 |
| bandit | B607 | Command Injection | 118 | Starting a process with a partial execut | 疑不合理：Q2_形态匹配 |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | bandit | B404 | Command Injection | 11 | low |
| 去重合并 | bandit | B404 | Command Injection | 19 | low |
| 进裁决 | bandit | B603 | Command Injection | 96 | low |
| 进裁决 | bandit | B607 | Command Injection | 118 | low |
| 去重合并 | bandit | B603 | Command Injection | 118 | low |

## corpus_00079.py（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00080.py（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00081.php（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00082.go（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00083.php（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00085.go（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00086.py（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00087.go（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|

## corpus_00088.java（原始候选 0 → 最终 0）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
