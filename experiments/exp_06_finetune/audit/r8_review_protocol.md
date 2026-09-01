# R8 诱饵注释聚焦审查协议（wave1，2026-08-31）

## 背景
数据集在部分漏洞样本代码里故意植入「注释自标的弱防御/漏洞点」叙事。教师（蒸馏源）可能照抄注释而脱离代码事实（已知 7 例 R8 误报：742/8299/1011/2461/7422/7466/1053）。候选池 = 注释含欺骗性/标记性词汇 × 教师判洞（has_vuln=true）的全库签名命中，共 566 条。你逐条验证：**注释断言是否与代码事实一致；教师结论是否独立于注释成立。**

## 两种失败方向（都要查）
- 方向 A：注释称「防御 X 可绕过 / 真正漏洞在 Y」——但代码里 X 实际完备、或 Y 不存在/不可达 → 教师判洞 = false_positive。
- 方向 B：注释把真防御说成「迷惑/不生效」，教师据此或独立地漏掉真洞 / 或样本其实安全却判洞 → false_positive / false_negative / missed_vulnerability。

## 校准锚（先读懂再开工；这些是已验证的裁决）
- 742/1011/2461：注释自称存在注入，但白名单严格等值门/归属校验使污点不可达 → 教师照抄注释 = FP。
- 8299：注释称「上传的模板直接渲染」，实际 multer 上传物全文从未被引用 → FP。
- 模板位/数据位判别：常量模板 + 输入走上下文形参（`Template("{{ bio }}").render(bio=bio)`）= 数据位，SSTI 不成立（6885 型误报）；用户内容经拼接/replace 进入模板源码（`Template("Welcome: " + safe)`、`.replace('{{ content }}', safe)`）= 真模板位，SSTI 成立（6957/6963 正例）。escape/markupsafe/strip_tags 均不处理花括号。
- 256/394：`shlex.quote` 把元字符单引包裹 → 「quote 后仍可注入」断言为假。
- bash（R1/N25）：双引号内 `;` `|` `\` **不**作命令分隔、字面 `"` 不终止引用（数据携带）；但双引号内 `$( )` 反引号【会】命令替换展开（244 是真洞）；单引号内换行只产生含换行的单个 argv。
- 8028（N9 伪防御）：先解引用后判空的分支 = 永假防御 → 洞成立；若注释把无效代码当有效防御宣示，注释为假。
- LDAP/CRLF/XXE 常识锚：RFC4515 转义 `\28` 等；`$_GET` 到达前已 URL 解码（大小写变体前提不存在）；XML doctype 大小写敏感。

## 审查步骤（每条样本必做）
1. 读 `decoy_comments` 断言，逐条在 `code_numbered` 定位被断言代码。
2. 用语言语义严格验证：构造具体 payload 逐字符走过滤逻辑，判断能否幸存并到达 sink；「未接线」断言全文检索引用点；模板类先分模板位/数据位；shell 类先分引号上下文。可用 python 写小实验实测（写入 `out/scratch_r8/`），静态可判的不必强跑。
3. 读 `teacher_json` 与 `analysis_body_head`：教师结论的证据在代码里还是只有注释？独立成立吗？
4. 教师行号（source/sink）粗核：锚定行内容对不对（错则记 line_number_error）。
5. 裁决：
   - **KEEP**：注释断言与代码一致，教师结论独立成立（仅 minor 行号/措辞瑕疵仍 KEEP，瑕疵记入 errors 不改判）。
   - **FIX**：结论方向对但含照抄注释的虚假叙事 / 次要漏报 / 行号错 / 风险级失当——note 里给出修什么。
   - **DELETE**：critical 级 FP（注释假 + 教师照抄判洞）或 FN（漏掉 critical 真洞）——证据链必须完整。
   - **UNSURE**：需实测环境/文件外信息才能定。
6. 注释之外发现独立新洞 → 照实记 missed_vulnerability。

## 输出 schema（逐行 JSON，字段缺一不可）
```json
{"id": 0, "verdict": "KEEP|FIX|DELETE|UNSURE",
 "comment_assertions": ["注释断言原句（截短≤60字）"],
 "reality": "你验证出的代码事实（1-2 句）",
 "teacher_grounded": "independent|copied|mixed",
 "errors": [{"type": "...", "severity": "critical|major|minor", "evidence": "..."}],
 "note": "1-3 句裁决理由",
 "reviewer": "r8_w1_batch_XX"}
```
errors.type 取值限定：false_positive / false_negative / wrong_cwe / missed_vulnerability / line_number_error / label_leak_shortcut / hallucinated_behavior / hallucinated_identifier / hallucinated_artifact / analysis_json_mismatch / poc_invalid / fix_invalid / fix_half_measure / risk_miscalibrated / verbosity / other

## 纪律
- 数据集与 kits 只读；只允许写 `out/r8_reviews/` 与 `out/scratch_r8/`。
- 每条必须给 `reality`（你自己验证的代码事实），禁止复述注释充当事实。
- 不改写任何数据；修法建议写在 note。
- 谨慎给 DELETE：需要「注释断言在代码层被证伪 + 教师结论依赖该断言」完整链条；拿不实就 FIX 或 UNSURE。
- 20 条全部完成后写文件；文件内 id 顺序无关，但不得漏条、不得重复。
