# Go/PHP semgrep 自研规则补充工作报告 —— 2026-10-09

> 任务：按全景弱点调研《优化建议_全景弱点调研_20260927.md》§2.2 规则需求单，补
> Go 5 条 + PHP 6 条 semgrep 规则，素材取自 `patch_vocab_material.{md,json}`
> （train_pool 291 条修复 diff 的 CWE×语言桶），规则只命名语言习语/API 形态。
> 验证流程执行 P6 纪律：需求单样本只做"一次过"验证，禁止对着样本迭代调试模式；
> safe 集 FP 护栏允许通用形态迭代。
> 本报告是工作记录，样本号只出现在这里（规则文件内零样本号，已 grep 自查）。

---

## 0. 结论速览

| 项 | 结果 |
|---|---|
| 规则条数 | Go 5（`go_ssrf_redirect_sqli.yaml`）+ PHP 6（`php_eval_unserialize_xss.yaml`） |
| `--validate` | 两个文件全部通过（5 + 6 rules, 0 configuration error） |
| 需求单样本命中 | **0/8**（Go 00074/00087/00065·66，PHP 00081/00083；见 §3 验证矩阵与原因） |
| 规则功能证明 | 11/11 在合成习语自测上开火；train_pool 干净源下 go-ssrf 7 文件、go-cmdi 1 文件、php-xss 2 文件开火 |
| FPR 单测 | rolling_dev_safe(47)：基线 0 → 加新规则 0（**新增 FP=0**）；87safe(26)：基线 1 → 加新规则 1（同一条既有 python-xss-taint，**新增 FP=0**） |

**诚实结论**：本批规则在"语言习语形态"上是完备且 FP 干净的（合成习语 + train_pool 双证），
但 rolling_dev50 的需求单样本**一个都没打中**——根因是这批真实 CVE 样本的 source/sink
都不在标准库 API 表面：source 走框架 Request 对象/JSON 结构体字段/函数参数（单文件
semgrep taint 的 source 建模盲区），或 vuln/safe 对在 sink 处逐字同构（00087）。
调研 §2.3 预期的"有锚率 13/50 → ≥25/50"**未由本批规则达成**，缺口见 §4 未决问题。

---

## 1. 方法与纪律执行记录

### 1.1 流程

1. 基线先行：新规则落盘前对两组 safe 集跑现有 `graduation_project/semgrep_rules/`（6 yaml）；
2. 规则编写：模式只取需求单 API 形态 + patch_vocab 桶形状 + 标准库 API 族；
3. 一次过验证：对新规则跑需求单对应样本；不命中→只允许对照 patch_vocab/标准库 API 族修一次；
4. FPR 门：safe 集上出现 FP → 允许修通用护栏（禁止样本拟合）；
5. 合成习语自测：自写教科书形态片段（非任何测试样本），证明每条规则在其设计形态上能开火。

### 1.2 关键事故与修复：`$HTTP_RAW_POST_DATA` 通配符 metavariable（影响全部 6 条 PHP 规则）

PHP 超全局中 `$_GET`/`$_POST` 以 `_` 开头，semgrep 解析为**字面量标识符**（实验证实：
pattern `$_GET` 不匹配 `$_SERVER`），可直接作 source；但 `$HTTP_RAW_POST_DATA` 匹配
metavariable 命名规则 `[A-Z_][A-Z0-9_]*`，被解析成**匹配任意变量的 metavariable**——
它作为 source 等于"全文件每个变量都是污点源"。实测后果：常量实参的
`header("Content-Type: application/json")`、静态 `Database::prepare("常量SQL")`、
`include 项目常量路径` 全部开火（rolling_dev_safe 上 8 条 FP 即此根因）。

修复：从全部 6 条 PHP 规则删除 `$HTTP_RAW_POST_DATA` source（该变量 PHP 7.2 起废弃、
8.0 移除，`file_get_contents("php://input")` 覆盖同一需求）。修复后 safe 集 FP 归零，
但也暴露出此前 rolling_dev 上的一批"命中"（php-eval 00081:266 等）同样是通配符伪命中
（见 §3）。

**教训入册**：PHP 规则的 source 白名单里，任何 `$UPPER_CASE` 形态的变量都必须先验证
其不是 metavariable（`$_` 前缀安全，纯大写开头不安全）。

### 1.3 护栏迭代记录（全部为通用形态，非样本拟合）

| 迭代 | 触发 | 护栏内容 | 性质 |
|---|---|---|---|
| unserialize options 排除收窄 | 合成测试设计期 | 仅排除 `allowed_classes => false/[]`（PHP 官方文档定义的构造性防御）；数组白名单可绕过仍命中 | 官方语义 |
| 删 `$HTTP_RAW_POST_DATA` | safe 集 8 FP | source 全改为 `$_` 前缀超全局 + php://input | 解析语义修复 |
| go-open-redirect 函数边界 | safe 00087 对 1 FP | 该规则 `taint_assume_safe_functions: true`：跳转目标经函数/方法组装（OAuth AuthCodeURL 等）视为传播边界，只锚直接流（FormValue/Query().Get 及其字符串拼接） | 调用深度护栏（文件头注已声明偏离全局 false 约定） |
| go-deserialize sink 块拆分 | 合成自测零命中 | 原 sink 块里 `focus-metavariable: $DATA` 与 `$SRC` 并列成合取，恒不匹配；拆成两组各带一个 focus | 语法缺陷修复（非样本调试） |

---

## 2. 逐条规则：模式要点与验证

### 2.1 Go：`graduation_project/semgrep_rules/go_ssrf_redirect_sqli.yaml`

| 规则 | CWE | 模式要点 | source | 验证 |
|---|---|---|---|---|
| go-ssrf-request-taint | 918 | sink=net/http 请求构造 URL 实参（NewRequest/NewRequestWithContext focus URL；Get/Head/Post/PostForm 及 `$CLIENT.Get` 方法族同型） | net/http 请求输入 API（FormValue/Query().Get/Header.Get/Body/Cookie/Referer/UA/Host/RequestURI/Form/PostForm） | 合成 `http.Get(r.URL.Query().Get("fetch"))` 命中；train_pool 7 文件开火；**00074 未命中**（原因 §3） |
| go-open-redirect-taint | 601 | sink=`http.Redirect($W,$R,$URL,$CODE)` focus URL；`taint_assume_safe_functions: true`（函数边界=调用深度护栏） | 同上 | 合成 `http.Redirect(w, r, r.FormValue("next"), 302)` 命中；**00087 未命中**（护栏后，原因 §3） |
| go-cmdi-concat-taint | 77 | sink=`exec.Command/CommandContext` 整调用（任一实参受污点即命中，覆盖 git clone 类子命令实参注入） | 请求输入 + `os.Getenv/os.LookupEnv/os.Args` | 合成 `exec.Command("git","clone", r.FormValue("repo"))` 命中；train_pool corpus_00039.go 开火；**00065/66 未命中**（原因 §3） |
| go-sqli-sprintf-taint | 89 | sink=Query/QueryRow/QueryContext/QueryRowContext/Exec/ExecContext 的**查询文本实参**（focus-metavariable）；参数化绑定值（可变参）不在 sink；fmt.Sprintf 内联与变量中转两形态均覆盖（污点经 Sprintf 传播） | 请求输入 + env | 合成 `db.Query(q)`（q=fmt.Sprintf(...FormValue...)）与内联 `db.Exec(fmt.Sprintf(...))` 均命中；rolling/train_pool 无对应形态样本 |
| go-deserialize-taint | 502 | sink 两组各带一个 focus：`yaml.Unmarshal/xml.Unmarshal($DATA)` focus $DATA；`yaml.NewDecoder/xml.NewDecoder($SRC)` focus $SRC | net/http 请求输入（Body 等） | 合成 `yaml.Unmarshal(body, &cfg)`、`xml.NewDecoder(r.Body)` 均命中（body=io.ReadAll(r.Body)） |

### 2.2 PHP：`graduation_project/semgrep_rules/php_eval_unserialize_xss.yaml`

六条共享 source：`$_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER`（字面量超全局，含下标访问）
+ `file_get_contents("php://input")`；全部 `taint_assume_safe_functions: false`。

| 规则 | CWE | 模式要点 | sanitizers / 护栏 | 验证 |
|---|---|---|---|---|
| php-eval-taint | 95 | sink=`eval(...)` | 无 | 合成 `eval($_POST['cmd'])` 命中；**00081 未命中**（原因 §3） |
| php-unserialize-taint | 502 | sink=`unserialize($DATA)`；pattern-not 仅排除 `["allowed_classes" => false]` 与 `=> []` 两种官方构造性防御；数组白名单仍命中交裁决 | 同上 | 合成 `unserialize($_COOKIE['blob'])` 命中；**00083/00053 未命中**（原因 §3） |
| php-file-inclusion-taint | 98 | sink=`include/include_once/require/require_once $F`（语句与括号两形态同匹配，实测 `include $F` 同时命中 `include($F)`） | 无 | 合成 `include $_GET['tpl']`、`require_once $_REQUEST['page']` 命中 |
| php-xss-echo-taint | 79 | sink=`echo $X;` focus $X（实测同型命中 `print $x;`、`print($x)`、`<?= $x ?>` 短标签）；`print($X)` 备用 | htmlspecialchars/htmlentities/strip_tags/intval/urlencode | 合成（t4）echo/print/短标签三形态命中；train_pool 00246/253 开火（干净源）；**00069/00070 未命中**（原因 §3） |
| php-sqli-taint | 89 | sink=mysql_query/mysql_db_query/mysqli_query/mysqli_real_query/mysqli_prepare + `$DB->query/exec/prepare`（三代 DB API 查询文本） | mysqli_real_escape_string/mysql_real_escape_string/mysqli_escape_string/`$DB->quote/escape/quoteIdentifier`（patch_vocab CWE-89 PHP 防御侧形状）/intval | 合成 `$db->query("...". $_GET['n'])`、`$db->prepare("...". $_POST['c'])` 命中；**00083 未命中**（原因 §3） |
| php-header-taint | 113 | sink=`header($H, ...)` | 无 | 合成 `header("Location: " . $_GET['url'])` 命中 |

---

## 3. 需求单样本验证矩阵（一次过 + 每规则至多一次素材驱动修复）

| 需求单项 | 样本 | 结果 | 原因（未命中时） |
|---|---|---|---|
| Go `http.NewRequest*`+用户 URL | corpus_00074.go (GT 862) | **未命中** | sink 不在 net/http 标准面：请求目标经项目自有客户端包装/配置结构体字段（patch_vocab CWE-918 Go 防御侧 `http.client`/`makewithhttpclient` 佐证包装习语）；且该样本 GT 是 862 授权缺失，sink 形态规则原理上不覆盖"缺授权"（§3.5 数据层域）。一次修已用（补 `$CLIENT.Get` 方法族）。功能另证：合成命中 + train_pool 7 文件 |
| Go `redirect(FormValue(...))` | corpus_00087.go (GT 601) | **未命中**（护栏后） | vuln/safe 对在 sink 处**逐字同构**（NewLogin 的 OAuth AuthCodeURL 组装跳转两版相同），修复在 `s.Redirect` 内的迭代 unescape 数据规范化——单文件规则无法区分；函数边界护栏使间接流（经变量/组装函数）不再命中。修复位于 FPR 门允许的护栏迭代 |
| Go `exec.Command` 拼接 | corpus_00065/66.go (GT 77) | **未命中** | 命令成分来自配置/JSON 结构体字段与项目自有包装（patch_vocab CWE-77 Go 桶 `runcmd` 为项目函数，禁写；`os.lookupenv`/`strings.join` 形态已覆盖）；semgrep 单文件 taint 无法把结构体字段建为 source。一次修已用（补 `os.Args`）。功能另证：合成命中 + train_pool corpus_00039.go |
| Go `db.Query(fmt.Sprintf(...))` | 需求单无样本 | validate ✓ + 合成命中 | —— |
| Go `yaml.Unmarshal`/`xml.NewDecoder` | 需求单无样本 | validate ✓ + 合成命中 | —— |
| PHP `eval(` | corpus_00081.php (GT 95) | **未命中** | 此前 266 行命中系 `$HTTP_RAW_POST_DATA` 通配符伪命中；真实污点不经超全局直达 eval（疑经框架 Request 对象/函数参数，单文件 taint source 盲区）。素材 CWE-94 PHP 桶仅 preg_match/preg_replace/eval 本地形状，无新 source 可加。合成 `eval($_POST['cmd'])` 证 sink 形态正确 |
| PHP `unserialize(` | corpus_00083.php (+00053, GT 502/89) | **未命中** | 同上：输入不经超全局（疑经参数/DB 行/文件），素材形状（unserialize+base64_decode）已覆盖；护栏修复一次已用（options 排除收窄为官方安全形态）。合成命中 |
| PHP `include $var / require $var` | 需求单无样本 | validate ✓ + 合成命中 | —— |
| PHP `echo $var`（XSS） | corpus_00069/70.php (GT 79) | **未命中** | 输出经项目模板/显示函数（patch_vocab CWE-79 PHP 漏洞侧形状 `string_display_line`/`lang_get` 等全为项目函数，禁写）；echo/print/短标签 sink 形态合成三连命中 + train_pool 两文件开火 |
| PHP `mysql_/mysqli/PDO` 查询串拼接 | corpus_00083.php (GT 89) | **未命中** | sink 为框架私有查询 API（patch_vocab CWE-89 PHP 漏洞侧 `$datahandler->start`/`process_datamap`/`$parser->parse` 全为项目 API）；标准三代 DB API sink 形态合成命中 |
| PHP `header(...)` 注入 | 需求单无样本 | validate ✓ + 合成命中 | —— |

---

## 4. FPR 单测（入库门：新增 FP 必须为 0）

命令口径：`semgrep scan --json --quiet --metrics=off --config graduation_project/semgrep_rules <targets>`
（等价 run_baseline.py `--tool semgrep --semgrep-config graduation_project/semgrep_rules`；
基线=目录仅含既有 6 yaml，对比=加入两个新 yaml 后同口径重跑）。

| safe 集 | 基线 findings | 加新规则 findings | 新增 FP |
|---|---|---|---|
| rolling_dev_safe（47 corpus 文件） | 0 | 0 | **0** ✓ |
| 87 集 safe 子集（26 文件，25 py + 1 java） | 1（python-xss-taint @ safe_17_race_with_lock.py:16，既有） | 1（同一条同文件同行，逐项比对一致） | **0** ✓ |

补充观测：
- 护栏迭代中间态曾出现 rolling_dev_safe 8 条 FP（$HTTP_RAW_POST_DATA 通配符事故，见 §1.2）与 1 条 FP（go-open-redirect 间接流），均已由通用护栏归零；
- train_pool 全池跑新规则 29 条 findings，errors 仅 2 条 PartialParsing（corpus_00089.php:17 / corpus_00331.go:646，semgrep 自身解析局限，与本批规则无关）；
- 合成习语自测文件（工作目录内，未入库）：11/11 规则开火（Go 5 + PHP 6，见 §2 各条）。

---

## 5. 未决问题

1. **需求单样本 0/8 命中 = §2.3 的有锚率验收线（13/50→≥25/50）未达成**。根因分层：
   (a) source 盲区——框架 Request 对象（`$request->input` 等）/JSON 解码结构体字段/函数参数，
   semgrep 单文件 taint 无法泛化建模；(b) 项目自有包装 sink/source（`runcmd`、`string_display_line`
   等，P6 禁止写样本专属标识符）；(c) vuln/safe 同构对（00087）。这三类正是调研 §1.1 预筛词表
   与 §3.2 形态规格清单的域，建议：**工具层规则（本批）+ 预筛词表（§1.1-3）+ 裁决层证据消费**
   三通道合并对账后重测有锚率，不要只靠 semgrep 规则单通道背指标。
2. **PHP 通配符 metavariable 陷阱需入册**：写规则时 `$UPPER_CASE` 形态一律先验证是否被解析为
   metavariable（`$_GET` 安全、`$HTTP_RAW_POST_DATA` 不安全）。本报告 §1.2 有实测证据。
3. `php-sqli-taint` 的 `$DB->prepare` sink 会把"预处理语句里拼接"报为候选（构造上仍是注入面，
   但参数绑定才是修复）；`$DB->query/exec` 无 receiver 类型约束（ORM query builder 同名方法
   会进候选）——按两阶段架构"工具召回+裁决抑制"设计意图保留，裁决层需认识这两种形态。
4. `go-open-redirect-taint` 的函数边界护栏牺牲了间接流召回（组装函数参与的跳转链不再锚定）；
   若后续 TaintTracker（AST 轻量污点）扩展 Go，可由其承接间接流。
5. 87 集 safe 子集全为 Python/Java，本批 Go/PHP 规则在该集上结构性无 FP 面；真正的 FP 回归面
   在 rolling_dev_safe 的 19 个 go/php 文件，本次已覆盖为零。后续每次规则变更都应重跑 §4 两组。
6. train_pool 冒烟显示 go-ssrf 在 7 个文件上开火（含 CWE-798/1336 桶文件）——其中可能含
   非 SSRF 语义的候选（如 cookie 构造），按"只召回不终判"设计交裁决层，但建议在 α06/α07
   复测时关注这些候选的类型归因走向。

---

## 附：验证命令备忘

```bash
SEMGREP=/d/miniconda/Scripts/semgrep
cd /d/code/毕业设计/Graduation-Project
# validate
$SEMGREP --validate --config graduation_project/semgrep_rules/go_ssrf_redirect_sqli.yaml
$SEMGREP --validate --config graduation_project/semgrep_rules/php_eval_unserialize_xss.yaml
# FPR 单测（基线 vs 加新规则，各跑一次目录口径）
$SEMGREP scan --json --quiet --metrics=off --config graduation_project/semgrep_rules \
  experiments/exp_06_finetune/corpus/rolling_dev_safe
$SEMGREP scan --json --quiet --metrics=off --config graduation_project/semgrep_rules \
  experiments/exp_04_hard_samples/samples/safe_*.py  # 26 个 safe 文件按 manifest expected_present=false 过滤
# 需求单样本验证（rolling_dev vuln 侧 go/php 文件）
$SEMGREP scan --json --quiet --metrics=off \
  --config graduation_project/semgrep_rules/go_ssrf_redirect_sqli.yaml \
  --config graduation_project/semgrep_rules/php_eval_unserialize_xss.yaml \
  experiments/exp_06_finetune/corpus/rolling_dev/*.go experiments/exp_06_finetune/corpus/rolling_dev/*.php
```
