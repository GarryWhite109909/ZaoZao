# Stage 1 候选审计清单 —— appsecco/dvna

**审计统计**：OK 0 · A 盲区 1 · B 类型错标 8（A/B 逐条归因后写入工具层文档修复）


四类问题：A 盲区（该产出没产出）/ B 类型错标 / C 无关候选 / D 剔除存疑

## core/appHandler.js（原始候选 14 → 最终 9）

### expected finding 覆盖情况

| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |
|---|---|---|---|---|
| CWE-89 | 10 | B 候选在但类型错标 | semgrep·models.semgrep_rules.javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection·L11 | — |
| CWE-78 | 39 | B 候选在但类型错标 | taint_tracker·Command Injection·L39 | — |
| CWE-639 | 107 | B 候选在但类型错标 | taint_tracker·Path Traversal·L107<br>taint_tracker·Path Traversal·L107 | — |
| CWE-639 | 144 | B 候选在但类型错标 | taint_tracker·Server-Side Template Injection·L145<br>taint_tracker·Server-Side Template Injection·L145<br>taint_tracker·Path Traversal·L145 | — |
| CWE-601 | 188 | B 候选在但类型错标 | prefilter+semgrep·models.semgrep_rules.javascript.express.security.audit.express-open-redirect.express-open-redirect·L188 | — |
| CWE-95 | 197 | B 候选在但类型错标 | taint_tracker·Code Injection·L196<br>taint_tracker·Server-Side Template Injection·L196 | — |
| CWE-502 | 218 | B 候选在但类型错标 | semgrep·models.semgrep_rules.javascript.express.security.audit.express-third-party-object-deserialization.express-third-party-object-deserialization·L218 | — |
| CWE-611 | 235 | B 候选在但类型错标 | semgrep·models.semgrep_rules.javascript.express.security.audit.express-libxml-noent.express-libxml-noent·L235 | — |
| CWE-200 | 207 | A 盲区（零候选） | — | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | taint_tracker | taint_tracker:Command Injection | Command Injection | 39 | critical |
| 进裁决 | taint_tracker | taint_tracker:Path Traversal | Path Traversal | 107 | high |
| 进裁决 | taint_tracker | taint_tracker:Path Traversal | Path Traversal | 107 | high |
| 进裁决 | taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 145 | high |
| 进裁决 | taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 145 | high |
| 去重合并 | taint_tracker | taint_tracker:Path Traversal | Path Traversal | 145 | high |
| 进裁决 | taint_tracker | taint_tracker:Code Injection | Code Injection | 196 | critical |
| 去重合并 | taint_tracker | taint_tracker:Server-Side Template Injec | Server-Side Template Injection | 196 | high |
| 去重合并 | prefilter | open_redirect | Open Redirect | 0 | medium |
| 进裁决 | prefilter | timing_unsafe_compare | Timing Attack | 0 | medium |
| 进裁决 | semgrep | models.semgrep_rules.javascript.sequeliz | models.semgrep_rules.javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | 11 | high |
| 进裁决 | prefilter+semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-open-redirect.express-open-redirect | 188 | medium |
| 进裁决 | semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-third-party-object-deserialization.express-third-party-object-deserialization | 218 | medium |
| 进裁决 | semgrep | models.semgrep_rules.javascript.express. | models.semgrep_rules.javascript.express.security.audit.express-libxml-noent.express-libxml-noent | 235 | high |
