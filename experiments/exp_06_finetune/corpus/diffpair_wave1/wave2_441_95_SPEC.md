# wave2 规格书：CWE-441 / CWE-95 定向补弱（2026-09-08）

> 依据：方法论 §2.1（真实 CVE 定向补弱类）+ 9/7 测评结论——441（代理/回环信任）与
> 95（eval 注入）是唯一反复漏报的族，存量仅 ~41/32 条且形态旧。目标：30-50 对
> 2026 形态正负对（vuln/safe 各半），走与 wave1 相同的 kits→教师→parse→verify→merge 管道。

## 生成契约（每对必须满足，g25/g26 教训固化）

1. **oracle 先行**：每对入库前先写断言——vuln 侧给出可机检的污点路径
   （source 行 → 中间跳 → sink 行，逐行引用代码）；safe 侧给出可机检的防御链
   （哪一行、什么机制、为何不可旁路）。断言写不出 → 样本不生成。
2. **手写样本先过独立审查**：我（执行者）手写的代码先由教师按"找茬"任务审一轮
   （预审 kits），确认"单缺陷隔离、无附带洞"后再进正式蒸馏包——g25 第一版 7/16
   带隐蔽漏洞的教训。
3. **hint 给判别标准不给结论**：任务包只写"按 441 的官方判据核验
   （'request would appear to be coming from the product'）"，不写"这是 441"。
4. **行号锚定在生成时**：explanation 引行号必须带片段；merge 时跑 normalize 校验。
5. **辨析锚句**：441 对必须含"非 918/601 因为…"（代理语义 vs 取回语义 vs 浏览器重定向）；
   95 对必须含"非 94 因为…/非 78 因为…"（eval 求值 vs 拼接生成 vs 命令注入）。
6. **成对同码**：vuln/safe 两侧代码除防御行外逐字相同——差分对才是判别边界教学单元。

## CWE-441 形态清单（目标 ≥15 对，8 vuln / 7 safe）

| # | 形态 | vuln 侧 oracle 要点 | safe 侧防御（成对） |
|---|---|---|---|
| 441-01 | 出站代理信任 X-Forwarded-For 做限流/审计判定 | XFF 可由客户端注入，限流判定 line N | 仅取 socket 对端 IP（line N 新增），XFF 仅记录 |
| 441-02 | directConnect/内网标记由请求头决定 | header `X-Internal: true` 即绕过鉴权 | 内网标记改由网络层（listen 地址）判定 |
| 441-03 | 回环地址白名单绕过（::ffff:127.0.0.1 / 0.0.0.0） | ip 比对族表缺口 | ipaddress 归一 + 全段覆盖（含 mapped IPv6） |
| 441-04 | 下载服务透传用户 URL 且信任其证书链 | SSRF + 中继语义 | allowlist + 证书校验固定 |
| 441-05 | CDN/代理链 trust ip 头数量可预测（X-Real-IP 链） | 最左 XFF 信任 | 已知代理数固定 + 跳数校验 |
| 441-06 | 反向代理后端用 Host 头生成绝对 URL（password reset 投毒） | Host 可控 → 链接投毒 | 服务端配置基准 URL |
| 441-07 | Webhook 回调 URL 由注册者提供且以内网身份出站 | 回调 → 内网探测 | 出站 allowlist + 禁回环段 |

## CWE-95 形态清单（目标 ≥15 对，8 vuln / 7 safe）

| # | 形态 | vuln 侧 oracle 要点 | safe 侧防御（成对） |
|---|---|---|---|
| 95-01 | 规则引擎/表达式配置经 eval 执行（yaml/json 配置内表达式） | 配置值 → eval line N | AST 白名单求值器或表达式编译受限子集 |
| 95-02 | 动态排序/过滤字段名进 eval | sort 参数 → eval("sorted(x, key=lambda i: i." + f + ")") | 字段名白名单映射表 |
| 95-03 | eval(compile(code, ...)) 且 code 由模板拼出 | 拼接链逐跳 | 沙箱子解释器/去 eval 化改查表 |
| 95-04 | localStorage/环境变量取"公式"进 eval | 非请求通道但仍用户可控 | 数值解析器（ast.literal_eval 或手写 parser） |
| 95-05 | Node `new Function(userExpr)` 动态谓词 | expr → Function 构造器 | jsonlogic/jsonata 受限 DSL |
| 95-06 | PHP 变量变量 `$$key` / preg_replace /e 残留 | 可变变量覆盖 | 显式键白名单 |
| 95-07 | Java ScriptEngine.eval（nashorn/groovy）接收规则字符串 | 引擎直评 | ProtectedTask/沙箱 classloader + 超时 |

## 流程

1. 本执行者按形态清单写代码对 + oracle 断言（`wave2_pairs/` 目录，每对一文件含断言头）。
2. 生成**预审 kits**（找茬任务：教师只审"代码里有没有我断言之外的缺陷"）→ 你网页投喂。
3. 预审通过的对 → 组装正式蒸馏 kits（直接分析任务，同 wave1 协议）→ 投喂 → verify → merge。
4. 量纲：441 ≥15 对 + 95 ≥15 对 ≈ 60 条训练行（对×2），加 wave1 的 ~490 行。

## wave1/wave2 入库共同门（重申）

verify PASS → G6 簇检查（incarn_in_train 字段）→ 人工抽验 ≥10% → 并入 v2_15 活文件 →
build v2_17（或 v2_16 增量重跑）→ 冻结 → verify → lock。

---

## 【2026-09-09 增补】CWE-78 单侧族补 safe（≥15 对 ≈ 30 行）

> 依据：78 现存 503 行**全部为 vuln 标签**（单侧族），仅 39 行有 safe 簇邻居——
> 教的是"subprocess/os.system 形态=vuln"的过拟合，正是 baseline FPR 27% 的方向。
> **决策记录**：78 封顶提案经测量否决（88% 簇孤立、近全同仅 6 行、毒脏仅 4 行，删除会砍真信息），
> 改为生成 safe 侧对照。沿用上方 6 条生成契约，不重复。

### 78-safe 形态清单（每对 = vuln 骨架 + 同码 safe 化，vuln 侧给污点路径断言，safe 侧给防御链断言）

| # | 形态 | vuln 侧（对照面） | safe 侧防御（成对同码） |
|---|---|---|---|
| 78-S-01 | Python 列表形式不经 shell | `subprocess.run(f"ping -c 1 {host}", shell=True)` | `subprocess.run(["ping","-c","1",host])`——host 含 `; rm -rf` 也只是字面 argv |
| 78-S-02 | shlex.quote 转义 | `"ping -c 1 " + host` 直接进 shell | `shell=True` 但 `shlex.quote(host)`——注入文本被转义为字面参数 |
| 78-S-03 | 命令名白名单 | 命令名由用户输入决定后执行 | 命令名取自 allowlist 字典，用户只能选 key，参数独立传 |
| 78-S-04 | 枚举模板派发 | f-string 由输入拼出整条命令 | `CMD_TEMPLATES[choice]` 固定模板字典派发 |
| 78-S-05 | Java ProcessBuilder 列表 | `Runtime.getRuntime().exec("sh -c " + input)` | `new ProcessBuilder("ping","-c","1",input)` 无 shell |
| 78-S-06 | Go 分片参数 | `exec.Command("sh","-c","ping "+host)` | `exec.Command("ping","-c","1",host)` |
| 78-S-07 | Node execFile | `exec(\`cmd ${input}\`)`（默认 shell）| `execFile(cmd,[args])`（默认无 shell）|
| 78-S-08 | PHP escapeshellarg | `shell_exec("ping -c 1 ".$host)` | `shell_exec("ping -c 1 ".escapeshellarg($host))` |
| 78-S-09 | ⚠️边界对·列表形式仍注入 | `subprocess.run(["sh","-c",user_cmd])` / `find -exec` / `git --upload-pack`——argv 含解释器或执行语义参数，**列表形式不豁免** | 同列表形式但 argv 无解释器/语义参数 |
| 78-S-10 | ⚠️边界对·固定 sudo 管理命令 | sudo 后接用户可控子命令 | `sudo` 身份固定 + 子命令白名单（部署假设保守写法，争议则弃）|

### 78 专属附加契约

1. **镜像锚句**：78-S-01 与 78-S-09 互为镜像——safe 侧必须写"列表形式安全**因为** argv 无解释器语义"，
   vuln 侧必须写"同为列表形式**但** argv 含 `sh -c`/`-exec`/`--upload-pack`，故仍 78"。
   这一对直接对着 system prompt 锚句，教的是模型最易犯的错。
2. **vuln 对锚句**：非 CWE-22（无路径穿越）/ 非 CWE-95（无 eval 求值）/ 非 CWE-74（注入目标是 OS 命令而非其他解释器）。
3. **safe 侧 G5 断言**：防御链必须回答"为何不可旁路"——quote 的转义语义、列表形式的解释器语义、白名单的封闭性，逐条点行。
4. PHP 形态注意 escapeshellarg 与 escapeshellcmd 的差异（前者参数级、后者命令级），叙事不得混用。
