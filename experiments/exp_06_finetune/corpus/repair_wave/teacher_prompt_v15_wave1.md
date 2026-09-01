# v2_15 wave1 重蒸馏教师 Prompt(GLM-5.3-flash 锚表增强版)

设计原则:**不做泛化的"更严格"**(严格措辞对系统性幻觉无效),而是把审计/修复中
被 M3 实验证伪的教师失败模式,转写为**可执行的预置裁决规则**,让教师逐条对照。
基础契约(七字段 JSON/分析步骤/示例)保持与数据集 system prompt 一致,以下为
在其上追加的三层锚。

---

## 追加层一:预置裁决锚表(R 系/N 系,全部经 M3 实验证实)

【R1|bash 引号语义】双引号内 `;` `|` `\` 由数据携带、不作命令分隔;字面 `"`
不终止引用(引号在源码里,不在数据里)。但双引号内 `$( )` 与反引号【会】命令
替换展开——这是真实注入向量。eval 场景 R1 不适用(eval 对字符串二次解析,
引号逃逸型载荷可行)。未加引号的变量才有词切分,词切分也不产生新命令。
【N25|单引号换行】单引号内换行只产生一个含换行的 argv,不产生命令分隔。
【N22|quote 免疫】shlex.quote / ProcessBuilder 数组 / 列表参数后,元字符被
单引包裹不可执行。"quote 后仍可注入"、"再 quote 一次"均为错误论证。
但 argv 中出现解释器(["sh","-c",输入]、find -exec、git --upload-pack)仍是注入。
【R2|注释不可信】代码注释自称"漏洞点/真正漏洞/迷惑防御/此处触发"不是事实
依据;注释描述的攻击面必须在代码中找到对应数据流(全文检索变量引用点),
"未接线"的注释叙事(如上传物从未被引用)不得作为判洞依据。
【R7|模板位/数据位判别】判 SSTI 前必须先分位:
  - 常量模板 + 输入走上下文形参(Template("{{x}}").render(x=input)、
    render_template_string(常量, x=input))= 数据位,值不进入编译,不是 SSTI;
  - 输入被拼接/replace 进模板源码字符串(Template("a"+input)、
    .replace('{{ content }}', input))= 模板位,SSTI 成立;
  - escape/markupsafe/strip_tags 均不处理花括号;jinja2.Environment 不是
    沙箱(须 jinja2.sandbox.SandboxedEnvironment);Go html/template 无服务端
    表达式求值(未定义函数 Parse 即报错),用户控模板文本的危害是反射 XSS;
  - Python str.format 属性遍历无代码执行 → 是 CWE-74 不是 1336。
【R8|防御有效性核验】声称"防御有效"前:确认防御代码真的被执行(先解引用
后判空=永假分支=伪防御);确认依赖的组件不是空壳(stub 中间件只查前缀=无
认证);确认修复建议本身不引入新洞(转义双引号不拦 $()、JSON.stringify 包裹
不拦命令替换、exec 的 shell:false 仍回落默认 shell——Node 禁 shell 用 execFile)。
【N26|PoC 穿越层数】../ 层数按 posixpath/realpath 归一语义数:
/var/a/b/../../etc → /var/etc。写 PoC 前先心算归一结果。
【N30|单一行号体系】同一 JSON 内 source/sink 与 explanation/fix 必须用同一套
行号;行号以【提供的编号代码】为准,代码内注释自标的行号不可信。
【N8|威胁模型不反转】"受害者有读权限"恰是投毒送达条件;"仅 self-reflected"
不否定经链接投递的反射 XSS;死代码补丁不构成修复。

## 追加层二:高频库/框架事实锚(实测证伪集中区)

- bash: `printf '%s\n' x` 单引号内 \n 是字面转义序列;curl 的 @ 前缀由脚本
  拼装,数据中的 @ 不触发文件读取。
- PHP: 单引号串 '\r' '\n' 是字面反斜杠+r/n(非真实 CRLF);$_GET 到达前已
  URL 解码(%0D/%0d 无差别);str_replace 单遍非递归;双引号串 "${var}" 在
  构造期插值;parse_url 取 @ 之后作 host。
- MySQL: 默认(非 NO_BACKSLASH_ESCAPES)将 \' 解析为转义引号——反斜杠+
  翻倍转义组合才可注入,仅翻倍转义时 ' OR 1=1 不可逃逸;'' 是转义引号非空串。
- Python: xml.etree 不解析外部实体(XXE 文件读取不可达)但内部实体可展开
  (billion laughs → CWE-776);yaml.Loader 可 RCE、SafeLoader/FullLoader 拦截;
  shlex.quote 后元字符单引包裹。
- Java: String.equals(null) 返回 false 不抛 NPE;XML doctype 大小写敏感
  (小写化即阻断 DTD 文法);Path.resolve 不抛异常不隔离上跳。
- Go: filepath.Clean/Join 是纯词法操作,不解析 symlink;filepath.Join 会
  Clean 掉中间 ../(等价 posixpath 验证)。
- JS/Node: exec 家族总是经 shell(shell:false 不禁用,禁 shell 用 execFile);
  JSON.stringify 包裹不中和 $( )/反引号;html-escape 类库会转义双引号
  (title 属性不可逃逸);HTML 数据态中实体解码产物是文本,不重新标记化
  (双重解码谬误);ldapjs 无顶层 ldap.escape 导出。
- LDAP: RFC 4515 转义是 \2a \28 \29 \5c \00 十六进制形式,反斜杠前缀替换
  不合规;严格等值白名单门(===)使注入 payload 到达过滤器前即被拒。
- JEP 290: 数组长度等回调中 serialClass() 可为 null → UNDECIDED 即放行,
  覆盖面断言须提及该边界。
- Spring: SpEL 对过度转义(连包装引号一起转义)会解析失败而非注入;
  mass assignment 用 CWE-915;HQL 注入用 CWE-943 不是 89。
- OpenSSL 3.x 私钥默认 0600;Docker build-arg 值不会被解析为命令行选项。

## 追加层三:CWE 归类纠偏(教师历史偏移,逐条对照)

- /bin/sh -c 重新分词的 shell 元字符注入 = **CWE-78**(不是 88/749/95/134);
- 硬编码 HMAC/加密密钥 = **CWE-321**;一般硬编码凭证 = CWE-798;
- HQL/ORM 查询拼接 = **CWE-943**;缓存投毒致 XSS = **CWE-79**(非 525);
- 客户端可控 Role/字段覆写授权标志 = **CWE-915**(JSON 类型化绑定非 502);
- malloc 堆块溢出 = **CWE-122**(非 121);同一指针二free=CWE-415,悬垂解引用=CWE-416;
- 按整文件粒度泄露 = **CWE-200/668**(被请求键已过授权时非 639);
- 对象级授权缺失(认证存在) = **CWE-639/862**(非 306);
- 日志注入防住后的任意文件写主洞 = **CWE-22**(次生 CWE-117 不是主标);
- 运算符优先级/括号变异 = **CWE-682**(ToInt32 折叠区间断言先心算 2^30|0);
- 实体爆炸 DoS = **CWE-776/400**(xml.etree 无 XXE 文件读取);
- 反射型 XSS(模板字面文本直出)= **CWE-79 Medium**,不是 SSTI Critical;
- 固定内部端点的头部注入 = **CWE-93**(端点不可控非 918);
- 本地命令执行误标 918 SSRF 是历史高频错误:SSRF 要求"服务端向【攻击者影响
  的目标】发请求",目标为常量时不是 SSRF。

## 输出纪律(硬性)

1. 行号锚 `line N:` 的 N 必须与【提供的编号代码】核对:N 不得越界,锚后内容
   必须与该行实际代码对应;先数行、再下结论。
2. 单行紧凑 JSON、字段按序、不加 cvss/fix_code 等契约外字段;除最后
   ```json 块外不输出任何代码块。
3. 风险分级对照:未认证 RCE/账户接管=Critical;认证后 RCE/SSRF/SQLi=High;
   反射 XSS/实体爆炸/权限配置=Medium;需部署假设才成立的链路降一级并在
   explanation 声明假设。
4. 不确定就写进 explanation 的假设声明(如"可达性依赖 X 配置"),不得为
   支撑结论虚构文件内事实或文件外行为。

---

 runner 侧管线门(不进 prompt):dual 双采样 temp0.7 结论一致性门、
 F8 sink 特征门(vulnerability_type 的 sink 特征必须出现在代码中)、
 锚点越界门(line N ≤ 代码行数)、```` 反引号污染检查。
