# alpha05 弱点挖掘统计补强（rolling_dev + real-safe，2026-08-25）

> 数据源：mining_merged_rolling_dev_20260824.json / mining_real_safe_20260824.json。
> 口径：valid = outcome∈{TP,FN,TN,FP}（parse_fail/OOM 不计分母）；CI = bootstrap 95%（10k 次重采样，seed=42）。

## 一、总指标 + 95% CI

| 指标 | 点估计 | 95% CI | 样本 |
|---|---|---|---|
| recall (loose) | 0.457 | [0.304, 0.609] | vuln valid 46/50 |
| 真实 FPR | 0.595 | [0.452, 0.738] | safe valid 42/47 |
| strict recall（重算：模型原始输出 CWE 编号精确匹配） | 0.043 | [0.000, 0.109] | vuln valid 46 |
| 配对准确率（两侧都对） | 0.095 | [0.024, 0.190] | 双侧 valid 42 对 |
| 翻转一致性（vuln 对→safe 也对） | 0.200 | [0.050, 0.400] | vuln TP 对 20 |

strict 口径注记：原报告/evaluate.py 的 strict_tp=3（含 verify 阶段修正）；本表按模型原始输出的 CWE 编号直接匹配重算为 2/46——差异是 verify 修正挽回的 1 条；两个口径都远低于可用水平，结论不变。

invalid 明细：vuln 4 条（corpus_00066.go、corpus_00074.go、corpus_00075.go、corpus_00080.py）；safe 5 条（corpus_00066.go、corpus_00071.py、corpus_00074.go、corpus_00075.go、corpus_00080.py）。
注：原报告 recall 分母 46 与本统计一致（剔除 parse_fail 4 条）；metrics JSON 内 valid=45 为其内部口径差 1 条，不影响结论。

## 二、分语言指标

| 语言 | vuln n | recall | strict | safe n | FPR |
|---|---|---|---|---|---|
| Go | 11 | 6/11 | 0/11 | 8 | 4/8 |
| Java | 8 | 2/8 | 1/8 | 8 | 5/8 |
| JavaScript | 7 | 2/7 | 1/7 | 7 | 5/7 |
| PHP | 8 | 5/8 | 0/8 | 8 | 6/8 |
| Python | 12 | 6/12 | 0/12 | 11 | 5/11 |

## 三、CWE 混淆矩阵（TP 侧，真类 × 预测类）

| 真类 | 预测类 | 条数 |
|---|---|---|
| CWE-89 | CWE-78 | 2 |
| CWE-22 | CWE-78 | 2 |
| CWE-1336 | CWE-78 | 1 |
| CWE-1336 | CWE-79 | 1 |
| CWE-22 | CWE-22 | 1 |
| CWE-352 | CWE-78 | 1 |
| CWE-502 | CWE-502 | 1 |
| CWE-502 | CWE-78 | 1 |
| CWE-601 | CWE-78 | 1 |
| CWE-639 | CWE-915 | 1 |
| CWE-74 | CWE-89 | 1 |
| CWE-77 | CWE-78 | 1 |
| CWE-79 | CWE-78 | 1 |
| CWE-90 | CWE-903 | 1 |
| CWE-918 | CWE-89 | 1 |
| CWE-918 | CWE-78 | 1 |
| CWE-441 | CWE-78 | 1 |
| CWE-502 | CWE-943 | 1 |
| CWE-601 | CWE-737 | 1 |

- TP 预测类分布: {'CWE-78': 12, 'CWE-89': 2, 'CWE-79': 1, 'CWE-22': 1, 'CWE-502': 1, 'CWE-915': 1, 'CWE-903': 1, 'CWE-943': 1, 'CWE-737': 1}
- 类型正确: 0/21（错 19 条）
- FP 侧预测类分布: {'CWE-78': 7, 'CWE-79': 3, 'CWE-918': 2, 'CWE-89': 2, 'CWE-74': 1, 'CWE-732': 1, 'CWE-287': 1, 'CWE-932': 1, 'CWE-502': 1, 'CWE-912': 1, 'CWE-745': 1, 'CWE-903': 1, 'CWE-862': 1, 'CWE-94': 1, 'CWE-611': 1}

## 四、FP 复核

25 条 FP 的逐条复核材料（模型主张 + safe 文件防御行 + 猜测式措辞标记）已输出到 `fp_review_20260825.md`，人工裁定结论见第五节。

## 五、FP 人工复核结论（2026-08-25，25/25 逐条裁定）

**裁定结果：25 条 FP 全部为真 FP，口径问题（safe 文件确有其他真实漏洞）0 条。原报告对 FPR 的'含少量高估'担忧不成立——真实 FPR 25/42 即真实水平，无下修空间。**

| 根因分类 | 条数 | 占比 | 典型样本 |
|---|---|---|---|
| 防御未识别 | 11 | 44% | 00054(XFF 防欺骗设计)/00056(ObjectInputFilter)/00069(pexecute 参数化) |
| 威胁模型错位 | 5 | 20% | 00085(FaaS 构建命令)/00058(配置常量) |
| 猜测式报警 | 4 | 16% | 00059(空解释)/00061('可能构造') |
| 类型张冠李戴 | 4 | 16% | 00033(prompt inj→78)/00070(traversal→78) |
| 污点来源误判 | 1 | 4% | 00052(role 只是选择器) |

**核心发现：防御有效性判断失败是 FP 第一根因（12/25=48%，含污点来源误判 13/25=52%），与翻转失败 16/20 同源**——官方修复/框架级防御（ORM 参数化、ObjectInputFilter、EscapeFilter、loopback-only XFF、getSanitizedFileName）被系统性无视；FN 侧过度信任弱防御与 FP 侧无视强防御是同一知识缺陷的两面。黑名单绕过 minimal pair（blacklist_bypass_pairs.jsonl，12 对）与证据消费演示正是针对该缺陷的定向教学。

逐条裁定明细：

| 文件 | 裁定 | 根因 | 依据 |
|---|---|---|---|
| corpus_00003.go | 真FP | 防御未识别 | sanitizeControl 在位；CLI 自身回显非 XSS 攻击面 |
| corpus_00004.php | 真FP | 防御未识别 | Eloquent ORM 属性赋值走框架参数化；'CWE-79 SQL Injection' 双重错误 |
| corpus_00005.java | 真FP | 猜测式报警 | setContent(String) 非注入 sink，'注入'无证据 |
| corpus_00031.js | 真FP | 防御未识别 | 修复加的 getSanitizedFileName 被无视 |
| corpus_00032.js | 真FP | 威胁模型错位 | 构建工具处理本地项目资产，非运行时污点 |
| corpus_00033.py | 真FP | 类型张冠李戴 | prompt injection 标成 CWE-78；system message 非命令执行 |
| corpus_00052.php | 真FP | 污点来源误判 | role 仅做选择器，feed URL 来自服务端 Settings 配置 |
| corpus_00053.php | 真FP | 猜测式报警 | '可能被注入'；getTheID 非 shell sink |
| corpus_00054.js | 真FP | 防御未识别 | safe 版仅对端 loopback 时信任 XFF（防欺骗设计），模型无视 |
| corpus_00056.java | 真FP | 防御未识别 | ObjectInputFilter 类白名单（root=AuthenticatorImpl）在位，模型无视 |
| corpus_00057.py | 真FP | 威胁模型错位 | webdataset 本地数据管线的开发者模式参数 |
| corpus_00058.js | 真FP | 威胁模型错位 | settings 为服务端配置常量，非用户污点 |
| corpus_00059.java | 真FP | 猜测式报警 | source/sink/explanation 全空——纯无证据报警 |
| corpus_00061.java | 真FP | 猜测式报警 | '可能构造恶意组地址'，无利用路径 |
| corpus_00063.js | 真FP | 类型张冠李戴 | metadata 布尔逻辑判断标 CWE-78 |
| corpus_00069.php | 真FP | 防御未识别 | Database::prepare + pexecute 参数化在位，'未参数化'主张与代码相反 |
| corpus_00070.php | 真FP | 类型张冠李戴 | 自述路径遍历却标 CWE-78；来源为服务端 Config |
| corpus_00076.go | 真FP | 防御未识别 | 修复加的 ldap.EscapeFilter 被无视 |
| corpus_00077.py | 真FP | 防御未识别 | SQLAlchemy session.get 按主键参数化查询 |
| corpus_00078.py | 真FP | 防御未识别 | cert_string 经临时文件路径隔离后传 openssl，非字符串拼接 |
| corpus_00082.go | 真FP | 防御未识别 | proxyType 白名单(slices.Contains supportTypes)在位；flag 解析非 shell |
| corpus_00083.php | 真FP | 防御未识别 | unserialize(allowed_classes=false) + 每用户配置文件隔离 |
| corpus_00085.go | 真FP | 威胁模型错位 | FaaS 平台语义：BuildCommand 本就是用户自定义字段 |
| corpus_00086.py | 真FP | 威胁模型错位 | 回调注册框架按设计调用传入函数 |
| corpus_00088.java | 真FP | 类型张冠李戴 | XPath.evaluate 标 CWE-611（XXE）；表达式非外部输入 |

复核方法注记：每条以模型主张 + safe 文件强防御 grep 行为基准裁定；其中 00052/00054/00056/00069/00083 五条存疑样本已读源码相关段核实；其余依据模型自述与防御行证据（置信度高：00059 空解释、00063/00033/00070 类型自相矛盾、00085/00086 框架语义明确）。
