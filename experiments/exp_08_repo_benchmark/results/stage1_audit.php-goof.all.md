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
| CWE-798 | 4 | OK（候选覆盖且类型对） | detect-secrets·Hardcoded Credentials·L4 | — |

### 全部原始候选去向

| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |
|---|---|---|---|---|---|
| 进裁决 | detect-secrets | Secret Keyword | Hardcoded Credentials | 4 | high |

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


---

## 依赖清单 SCA 扫描（trivy fs，§9.28）

依赖漏洞合计 **22** 个：

| 严重度 | 数量 |
|---|---|
| critical | 5 |
| high | 6 |
| medium | 9 |
| low | 2 |

| 清单文件 | 漏洞 ID | 严重度 | 说明 |
|---|---|---|---|
| composer.lock | CVE-2021-3838 | critical | DomPDF before version 2.0.0 is vulnerable to PHAR deserialization due  ... |
| composer.lock | CVE-2021-3902 | critical | An improper restriction of external entities (XXE) vulnerability in do ... |
| composer.lock | CVE-2022-28368 | critical | Remote code injection via remote fonts |
| composer.lock | CVE-2023-23924 | critical | Dompdf vulnerable to URI validation failure on SVG parsing |
| composer.lock | GHSA-97m3-52wr-xvv2 | critical | Dompdf's usage of vulnerable version of phenx/php-svg-lib leads to restriction bypass and potential RCE |
| composer.lock | CVE-2022-41343 | high | Remote file inclusion |
| composer.lock | CVE-2023-50262 | high | Dompdf is an HTML to PDF converter for PHP. When parsing SVG images Do ... |
| composer.lock | CVE-2026-71488 | high | league/commonmark is a PHP library for parsing and rendering CommonMar ... |
| composer.lock | GHSA-c2pc-g5qf-rfrf | high | league/commonmark's quadratic complexity bugs may lead to a denial of service |
| composer.lock | CVE-2021-34551 | high | RCE affecting Windows hosts via UNC paths to translation files |
| composer.lock | CVE-2021-3603 | high | PHPMailer 6.4.1 and earlier contain a vulnerability that can result in ... |
| composer.lock | CVE-2022-0085 | medium | Server-Side Request Forgery in dompdf/dompdf |
| composer.lock | CVE-2022-2400 | medium | External Control of File Name or Path in GitHub repository dompdf/domp ... |
| composer.lock | CVE-2026-56722 | medium | Dompdf is an HTML to PDF converter for PHP. In versions 3.15 and prior ... |
| composer.lock | CVE-2026-59941 | medium | Dompdf is an HTML to PDF converter for PHP. Versions 3.15 and prior ac ... |
| composer.lock | CVE-2026-59942 | medium | Dompdf is an HTML to PDF converter for PHP. Versions 3.15 and prior ar ... |
| composer.lock | CVE-2026-59943 | medium | Dompdf is an HTML to PDF converter for PHP. In versions 3.15 and prior ... |
| composer.lock | CVE-2019-10010 | medium | XSS vulnerability with double-encoded entities |
| composer.lock | CVE-2023-50251 | medium | php-svg-lib is an SVG file parsing / rendering library. Prior to versi ... |
| composer.lock | CVE-2024-25117 | medium | php-svg-lib is a scalable vector graphics (SVG) file parsing/rendering ... |
| composer.lock | CVE-2026-55554 | low | Dompdf is an HTML to PDF converter for PHP. In versions 3.15 and prior ... |
| composer.lock | CVE-2026-55555 | low | Dompdf is an HTML to PDF converter for PHP. Versions 3.15 and prior ar ... |

> 口径：SCA 为**项目级**证据（依赖版本含已知 CVE），非行级；
> 不计入上文 A/B/C 判定（§9.28 口径说明）。