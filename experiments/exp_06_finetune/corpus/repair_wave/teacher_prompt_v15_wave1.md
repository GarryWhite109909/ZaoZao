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

## 追加层四:信任边界与配置语义锚(R6 家族,g20 辨析组)

判定"输入是否构成攻击面"时先声明信任层级,再论证可达性;不得把部署者/管理员
输入默认为攻击者输入:

- R1. HTTP 请求参数/头/体、文件上传内容:攻击者可控;端点若无文件内可见的
  鉴权/授权边界,直接计入。
- R2. CLI 参数、环境变量:仅本机使用者/部署者可控,本身不是攻击面;仅当值被
  转发到其他攻击者可达上下文(如 Web API 代执行)时才成立。
- R3. 配置文件(deploy.conf/yaml/json):同 R2;除非文件内可见"配置值来源于
  请求/上传"。
- R4. 管理员后台配置(DB 存的 webhook/option):受管理权限保护,非文件内攻击面;
  若存在低权限可篡改路径,风险外移至配置面,explanation 记边界注记。
- R5. 代码内默认凭据/密钥字面量:一律 CWE-798(规则 2),与信任层级无关。
- R6. opt-in 不安全开关(InsecureSkipVerify 等):显式由部署者选择 -> safe+
  加固建议;代码对请求可控输入无条件启用 -> vuln(CWE-295)。
- R7. 模板输出层:引擎默认转义(autoescape)下判 vuln 必须指出转义被显式关闭
  或 raw 输出的文件内路径;缺省转义行为不构成漏洞。
- R8. 服务端内存状态无界增长(map/缓存):判 DoS 必须论证文件内可见的外部触发
  入口;仅内部调用可达 -> safe+加固建议。
- R9. 文件外行为(其他文件/安装脚本/供应链):不在本文件判定范围,论证引用
  文件外行为视为无效。
- R10. CLI 自执行:程序按使用者意图执行使用者提供的命令(本机同权)不是漏洞;
  同一形态搬到多用户服务端代执行(端点代跑租户输入)则为 CWE-78。

双向要求:判 vuln 必须给出文件内攻击者可控 source 行与 sink 行的完整链;
判 safe 必须在 explanation 记录加固建议与隔离边界注记。

## 追加层五:g21-g24 辨析组锚(密码学互斥/证据层级/主次关系/CSRF·PHP/命令·代码注入)

【F12 密码学族互斥边界】密码学缺陷是三个不同性质的问题,禁止笼统归为"弱加密":
1. CWE-327 = 算法本身强度不足/已被破解(md5/sha1/DES/RC4/ECB 模式)——锚句
   "算法强度不足",与密钥/IV 生成方式、随机源**无关**。
2. CWE-329 = IV/Nonce 硬编码或可预测(IV = b"..." 字面量、iv= 常量、计数器固定)
   ——锚句"IV 不可重用";**不是**算法强度问题(使用 AES-256 仍应标 329)。
3. CWE-330/338 = 随机值不可预测性不足(random.random()/random.choices()/
   Math.random() 生成 token/密码/会话 ID)——锚句"随机源可预测";338 是 330 的
   ChildOf 子类(MITRE 明示),二者同语义不同粒度,标注任一均可。
互斥判据(按序提问,先命中者为准):a. 缺陷在"用了哪个算法"→327;b. 缺陷在
"IV/Nonce 怎么来的"→329;c. 缺陷在"随机值怎么生成的"→330/338。
叙事互斥:329 的 explanation 禁止"弱算法"叙事;330/338 的 explanation 禁止以
md5/sha1/破解作论证;327 的 explanation 禁止把随机源写成主因。

【F11 判定纪律:证据层级与定论义务】证据强度只影响置信度,不影响"是否应当给出结论":
- E3(完整 source→sink 污点链)→ 必须直接确认,禁止"需运行时验证/证据不足/需
  更多上下文"作为结论;explanation 使用锚句"存在完整污点链,可直接确认"。
- E2(仅 sink 位置命中,无完整链)→ 结合代码上下文判断;防御代码存在且有效才可否决。
- E1(无任何工具候选)→ 才适用"需人工复核"表述。
反模式:对 E3 证据输出"无法确认"——把不确定性判断当成免责声明。

【F10 主次关系与伴生凭证】多漏洞共现时按危害可达性排序取主类型:
可 RCE/可绕过认证 > 可读取任意数据 > 信息泄露 > 输出未转义;JSON 契约只有单一
vulnerability_type 字段,伴生漏洞不单开字段,其同时成立的事实与理由必须写入
explanation(不得因选了主类型而否认伴生存在)。
secret/硬编码凭证告警在场时:它在该场景是**伴生发现**,主类型由攻击面语义决定
(无 token 校验=CWE-352;会话未被轮换=CWE-384;对象越权=CWE-639/862;上传无
类型校验=CWE-434);CWE-798 同时成立但不得作为 top1。代码中出现 password/secret
常量不改变攻击面主类型的判定。

【CSRF vs XSS 边界】场景有 CSRF token 的生成/回显、但服务端**不校验** →
CWE-352(攻击面是"借用已认证会话发请求",不是"脚本注入");仅当用户可控数据
**未转义进入 HTML 响应体**才是 CWE-79。修复叙事:352 的修复是服务端 token
校验/SameSite cookie;确认 352 时禁止输出转义类修复(语义错位)。

【PHP 弱比较族】用户输入与秘密值做 == 比较("0e..." md5 碰撞/"1"=="1.0" 类型
混淆)→ CWE-843(Incompatible Type/type juggling);修复只允许 hash('sha256', x)
后 === 严格比较 / === 强比较;CWE-200/204(信息暴露/时序)至多是伴生视角,不得
作为该场景主类型。

【CWE-77 vs CWE-78 边界(2026-09-02 按 MITRE 官方 4.20 修正)】CWE-78 = OS 命令注入,
**不要求 shell 解释层在场**,官方含两种亚型:①输入含命令分隔符等特殊元素,拼进命令串
经 shell/system()/execSync 执行(元字符注入);②应用接受输入**完全选择运行哪个程序**
——subprocess.run([user_cmd]) 列表形式、exec.Command(用户命令)、spawn(用户命令名)
等无 shell 形态,命令名/参数整体可控,同样判 **CWE-78**(第二亚型;无 shell 时攻击者
仅不能同行组合多条命令,危害略降但仍可控任意程序)。
CWE-77 = 命令注入泛化父类,**专用于非 OS shell 的命令语言**注入:sed 脚本表达式
(CVE-2022-1509)、SNMP 命令(CVE-2020-11698)、MVG 图形语言(CVE-2019-12921)、
IMAP/SMTP 命令、LDAP/正则等自定义命令语言。**OS 命令场景一律判 78,禁止因"无
shell"而改判 77**(官方明确警告 77 常被误用)。仅当注入目标是非 OS 的命令解释器/
协议命令语言时才判 77。

【CWE-94 vs CWE-95 边界】CWE-95:输入作为"指令"直接进入动态求值(eval()/exec()
的求值语义,输入即被执行的表达式/语句)。CWE-94:输入作为"代码素材"参与代码
文本的**生成**再执行(输入被拼接进生成的源码/函数体/表达式模板再 compile+exec,
含 SpEL/OGNL 表达式注入)。输入被直接求值 → 95;输入被拼进生成的代码文本 → 94。

【CWE-88 参数注入(2026-09-02 增,官方口径测试集审查 §四组1)】程序名硬编码固定、
用户输入只落到**参数位**并能注入额外开关/选项(如 git rebase --exec <x>) →
CWE-88。注意**评测口径**:NVD 惯例对"参数注入导致 RCE"常标 CWE-77(如 Gogs
CVE 官方标 77),在真实 CVE 集上按 NVD 口径判 77 亦可接受;训练集一律按官方
精确语义标 88/77(非 OS 命令语言),不做混淆。

【CWE-347 vs CWE-327 双口径(2026-09-02 增,官方口径测试集审查 §四组6)】
JWT/签名场景存在官方语义与 NVD 实践的分裂,两者都对、按来源标注:
- **验签这一步没做/做错**(alg=none 不校验、密钥取自未验证头部) → **CWE-347**
  (Improper Verification of Cryptographic Signature),官方语义最精确;
- **算法本身弱/被破解**(用 MD5/SHA1 做签名摘要) → **CWE-327**。
NVD 对部分 JWT CVE(如 Parse Server)官方标 327,测试集维持其来源标注并记
dual-convention;蒸馏产出按上述官方语义取 347,不得因见到 NVD 标 327 而改判。

【CWE-918 vs CWE-441 边界(2026-09-02 增,官方口径测试集审查 §四组4)】
服务端替攻击者**取回 URL 内容**(fetch/urlopen 目标未校验) → CWE-918 SSRF;
攻击者借产品的**身份/网络位置**发请求(loopback 信任、directConnect 转发,
"request would appear to be coming from the product") → CWE-441;
骗用户浏览器跳转到外站(响应 Location/redirect) → CWE-601。

【CWE-352 不是主洞终点(2026-09-02 增)】CSRF 常只是**投递链**而非根因:若
advisory/NVD 标了别的 CWE(如 CSV 导入 unserialize → CWE-502),主洞跟 advisory
标根因,CSRF 仅作伴生写入 explanation(见 F10 主次规则)。

## 追加层六:safe 侧防御识别(g25 防御演示组,2026-09-02 增)

遇到"危险 API + 可达输入"的形状时,**先检查文件内是否存在有效防御代码,再决定是否
判洞**,不得见到危险 sink 就默认判洞:

- 配置/开关防御(实测 FP 64% 来源,模型历史 100% 全盲):显式开启安全选项 = 攻击面关闭。
  例如 requests verify=True(且服务端证书被验证)/ ssl 默认校验上下文 / 未设
  InsecureSkipVerify 的 TLS 配置 / 危险反序列化组件被配置禁用 / debug 关闭。
  —— 判定:有危险 sink 但攻击面被安全配置显式关闭 → safe,explanation 锚句
  "安全配置项被显式设置 → 对应攻击面关闭";除非文件内存在"关闭该配置"的可达路径,
  才判 vuln。
- realpath/归一防御(实测 FP 来源,模型历史 100% 全盲):路径在拼接/打开前先做
  归一(realpath/normalize/Clean/Resolve)并**前缀或白名单校验**,拦截 ../ 逃逸。
  例:realpath(user_path) 后校验 startswith(BASE_DIR) / Path.resolve 后做目录前缀
  校验 / filepath.Clean + strings.HasPrefix / send_file 前 realpath+允许目录白名单。
  —— 判定:归一 + 目录前缀校验(锚后内容逐字符比对,含 .. 归一后再判) → safe;
  仅 normalize 不做前缀校验、或只做 contains 检查仍可 ../ 逃逸 → vuln(CWE-22)。
- 区分"防御有效"与"伪防御"(对照 R8):防御须真实可达、非永假分支、非空壳组件;
  校验目标是路径本身(归一后),不是后缀/文件名包含(可绕过)。

双向要求:判 vuln 必须给出文件内攻击者可控 source 到 sink 的完整链且防御确被旁路;
判 safe 的 explanation 必须指明"哪一行哪段防御代码关闭了哪个攻击面"并记录加固边界。

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
