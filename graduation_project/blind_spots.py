"""工具层盲区定位（2026-08-31）——"提示注意力"而非"增加判定"。

问题：工具（semgrep/bandit/taint_tracker）只能召回**可规则化**的漏洞形态。
有一大类风险是"规则写不了"或"写了会误报爆炸"的：

  - 授权/越权（IDOR）：需要知道"谁可以访问什么"的业务语义；
  - 过滤是否可绕过：`replace()` 去掉 `../` 能否挡住双重编码？取决于下游；
  - 跨函数/跨文件污点：本文件的污点链在函数边界断裂；
  - 加密用法是否安全：ECB/固定 IV 是否有害取决于数据敏感性；
  - 隐式信任边界：`X-Forwarded-For` 在这个部署里是否可信。

这些若写成规则 → 要么漏得厉害，要么误报爆炸（本项目 §五之四 已实证：
规则级抑制把 python-xss-taint 全族压没，代价远高于保留候选的裁决成本）。

方案：把它们做成**行级盲区提醒**注入 prompt——只描述"工具看不到什么"，
把判断权完整交给模型。三条硬约束（缺一不可，否则就是换皮的告警）：

  1. **不产生 finding**：盲区不进 `findings`、不进裁决、不影响 `has_vulnerability`。
  2. **永不进 SignalRegistry**：盲区被模型否定是**正常且高频**的（它本来就是
     低置信提示），一旦允许回填抑制池，这套机制会在几轮扫描后自我清空
     （§五之四 教训的直接推论）。
  3. **中性措辞**：统一用"工具无法判定 X，请确认 X"，**绝不写"此处存在
     XX 漏洞"**——后者会锚定模型、抬高判真率（prompts._TRUST_NOTE_CHAIN
     已实证：prompt 里的信任标注会实质影响模型判断）。

知识来源：**先验分类**（CWE Top 25 / OWASP 的公开漏洞形态），与
`SignalRegistry.learn_pool`（从样本挖掘 + 独立验证集审批转正）严格分离，
防止样本过拟合。

纯确定性：同输入必同输出。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# 盲区类别
# ---------------------------------------------------------------------------
CROSS_BOUNDARY = "cross_boundary"    # 跨函数/跨文件数据流（污点链在函数边界断裂）
SANITIZER = "sanitizer"              # 上下文相关净化（黑名单/替换/正则能否挡住绕过）
AUTHORIZATION = "authorization"      # 授权与业务逻辑（越权/IDOR/条件竞争）
TRUST_BOUNDARY = "trust_boundary"    # 隐式信任边界（代理头/TLS/SSRF 白名单）
FRAMEWORK = "framework"              # 框架特性（批量赋值/ORM 原生通道/自动转义）
CRYPTO = "crypto"                    # 加密误用（弱哈希/ECB/固定 IV/弱随机）
CONFIG = "config"                    # 安全配置（debug/CORS/cookie 属性）
SERIALIZATION = "serialization"      # 不可信反序列化

_CATEGORY_LABELS = {
    CROSS_BOUNDARY: "跨边界数据流",
    SANITIZER: "过滤完备性",
    AUTHORIZATION: "授权与业务逻辑",
    TRUST_BOUNDARY: "信任边界",
    FRAMEWORK: "框架特性",
    CRYPTO: "密码学用法",
    CONFIG: "安全配置",
    SERIALIZATION: "反序列化",
}

# ---------------------------------------------------------------------------
# 规则表：(类别, 正则, 中性提醒文本, 优先级)
#
# 措辞纪律（改动本表时必须遵守）：
#   - 描述**工具的能力边界**，不是描述漏洞；
#   - 以"请确认……"收尾，把判断权交还模型；
#   - 不出现"存在漏洞/危险/可被攻击"等定性词。
# ---------------------------------------------------------------------------
_BLIND_SPOT_RULES: list[tuple[str, re.Pattern, str, int]] = [
    # --- 授权与业务逻辑（工具盲区最深：需要业务语义）----------------------- priority 5
    (AUTHORIZATION,
     re.compile(r"\b(get|find|filter|query|delete|update|select|fetch|load)\s*\("
                r"[^)]*(id|uid|user_id|account|order|owner|doc|file|record|invoice)"
                r"[^)]*(request\.|params|args|body|form|query_params|input)", re.I),
     "外部提供的标识符直接用于数据访问，工具无法判定是否存在针对当前用户的归属/"
     "授权校验，请确认是否存在越权访问（IDOR）的可能。", 5),
    (AUTHORIZATION,
     re.compile(r"(request\.|params|args|body|form|query_params)[^\n]{0,80}"
                r"(id|uid|user_id|account|order|owner|doc_id|file_id)"
                r"[^\n]{0,80}\b(get|find|filter|query|delete|update)\s*\(", re.I),
     "外部输入参与到数据查询/删除/更新操作，工具无法判定该操作是否校验了操作者权限，"
     "请确认是否有授权检查。", 5),

    (AUTHORIZATION,
     # 无过滤批量查询（CWE-200 信息暴露面）：findAll()/find({}) 不设条件地取出
     # 全表数据。是否越权取决于"这些记录是否都属于调用者"，需业务语义。
     # 误提示率高（正常列表接口同形），故优先级低于 IDOR——本模块的取舍是
     # "误提示交给模型消解，漏提示才是代价"，但排序上让确定性更高的形态优先。
     re.compile(r"\.(?:findAll|find_all|findMany|find_many|\ball|list)\s*\("
                r"\s*(?:\{\s*\}|\{\s*where\s*:\s*\{\s*\}\s*\})?\s*\)", re.I),
     "执行了无过滤条件的批量数据查询，工具无法判定返回范围是否超出了调用者应可见的"
     "范围，请确认是否存在越权可见的信息暴露。", 3),

    # --- 过滤完备性（能否绕过取决于下游语境）-------------------------------- priority 4
    (SANITIZER,
     re.compile(r"(\.replace\(|re\.sub\(|str_replace\(|preg_replace\(|"
                r"\.strip\(|\.translate\(|escape\()", re.I),
     "此处使用字符串替换/正则过滤，工具无法判定其对所有绕过形态（URL 编码、"
     "双重编码、大小写变体、null 字节、路径分隔符变体）是否完备，"
     "请确认过滤是否可被绕过。", 4),
    (SANITIZER,
     re.compile(r"(blacklist|blocklist|denylist|forbidden|banned|disallowed|"
                r"illegal_chars|bad_chars)", re.I),
     "使用黑名单机制做安全决策，工具无法判定名单的完备性，请确认是否存在未覆盖的绕过输入。", 4),

    # --- 信任边界 ----------------------------------------------------------- priority 4
    (TRUST_BOUNDARY,
     re.compile(r"(x-forwarded-for|x-forwarded-host|x-real-ip|client-ip|"
                r"x-client-ip|remote_addr|remote-addr|http_x_forwarded)", re.I),
     "使用了可伪造的 HTTP 请求头（反向代理头/IP），工具无法判定该值在此部署中是否"
     "真由可信代理注入，请确认其是否可被客户端伪造。", 4),
    (TRUST_BOUNDARY,
     re.compile(r"jwt\.decode\s*\((?![^)]*(verify|algorithms|options|audience|issuer))", re.I),
     "JWT 解码未显式指定校验参数，工具无法判定签名与算法是否被校验，"
     "请确认是否校验了签名并限定算法白名单。", 4),
    (TRUST_BOUNDARY,
     re.compile(r"(verify\s*=\s*false|verify\s*=\s*0|rejectunauthorized\s*:\s*false|"
                r"node_tls_reject_unauthorized|insecureskipverify|"
                r"curlsslverifypeer\s*,\s*false)", re.I),
     "禁用了 TLS/证书校验，工具无法判定该连接是否面向不可信网络，"
     "请确认是否存在中间人攻击的风险。", 4),
    (TRUST_BOUNDARY,
     re.compile(r"(127\.0\.0\.1|localhost|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                r"192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
                r"::1|0\.0\.0\.0)", re.I),
     "以 IP/主机名作为安全放行条件（SSRF 白名单的常见形态），工具无法判定该判断"
     "是否能覆盖所有绕过写法（DNS rebinding、重定向、IPv6、十进制/八进制 IP），"
     "请确认白名单的完备性。", 4),

    # --- 反序列化 ----------------------------------------------------------- priority 4
    (SERIALIZATION,
     re.compile(r"(pickle\.loads?\(|cPickle\.loads?\(|unserialize\(|"
                r"yaml\.load\s*\((?![^)]*(safe_loader|SafeLoader))|"
                r"objectinputstream|readobject\s*\(|jsonpickle\.decode\(|"
                r"marshal\.loads?\(|php://input)", re.I),
     "对外部数据进行反序列化，工具无法判定该数据来源是否可信，"
     "请确认反序列化的数据是否可能被攻击者控制。", 4),

    # --- 跨边界数据流 ------------------------------------------------------- priority 3
    (CROSS_BOUNDARY,
     re.compile(r"^\s*(session|g|cache|redis|memcache|app\.config|current_app|globals?)"
                r"\s*[\[.][^\]]{0,40}\]\s*=[^\n]*(request\.|params|args|body|form|cookie|"
                r"header|input)", re.I | re.M),
     "外部输入被写入跨函数/跨请求共享状态（session/全局缓存），工具无法追踪该值在"
     "其它函数中的消费点，请确认消费点是否将其用于危险操作。", 3),
    (CROSS_BOUNDARY,
     re.compile(r"return\s+[^\n]{0,120}(request\.|params\[|args\[|body\[|form\[|"
                r"query_params|getparameter\()", re.I),
     "外部输入经 return 传出本函数，工具无法分析调用方如何使用该返回值，"
     "请确认调用链下游是否存在危险使用。", 3),

    # --- 框架特性 ----------------------------------------------------------- priority 3
    (FRAMEWORK,
     re.compile(r"(\*\*\s*(request\.|params|body|form|json|data|kwargs)|"
                r"(update|create|filter|setattr)\s*\(\s*\*\*)", re.I),
     "将外部输入字典整体展开传入（**kwargs），工具无法判定目标是否限制了可写字段"
     "（批量赋值 / mass assignment），请确认是否存在字段白名单。", 3),
    (FRAMEWORK,
     re.compile(r"(\.raw\(|\.extra\(|executescript\(|from\s+sql|\.execute\(\s*f?['\"][^'\"]*%s)",
                re.I),
     "使用了绕过 ORM 参数化的原生 SQL 通道，工具的注入检测难以覆盖该路径，"
     "请确认拼接内容是否受外部输入影响。", 3),
    (FRAMEWORK,
     re.compile(r"(autoescape\s*=\s*false|markup\(|\|\s*safe\b|dangerouslysetinnerhtml|"
                r"innerhtml\s*=|escape\s*=\s*false|\.html\()", re.I),
     "关闭或绕过了模板/输出自动转义，工具无法判定输出到该位置的内容是否全部经过"
     "转义，请确认是否存在未转义的外部输入。", 3),

    # --- 密码学用法 --------------------------------------------------------- priority 3
    (CRYPTO,
     re.compile(r"(\bmd5\s*\(|\bsha1\s*\(|hashlib\.new\(\s*['\"](md5|sha1)|"
                r"messagedigest\.getinstance\(\s*['\"](md5|sha-1|sha1)|\bdes\b|\brc4\b)",
                re.I),
     "使用了已被攻破的哈希/加密算法，工具无法判定其用途是否属于安全敏感场景"
     "（口令/签名/完整性校验），请确认该算法是否用于安全目的。", 3),
    (CRYPTO,
     re.compile(r"(\becb\b|/ecb/|mode\s*=\s*['\"]?ecb|"
                r"iv\s*=\s*['\"][^'\"]{0,32}['\"]|"
                r"createcipheriv\(\s*['\"][^'\"]+['\"]\s*,\s*['\"][^'\"]{1,32}['\"])",
                re.I),
     "分组密码使用了 ECB 模式或固定 IV，工具无法判定其是否导致密文可区分/可重放，"
     "请确认加密模式与 IV 的生成方式。", 3),

    # --- 安全配置 ----------------------------------------------------------- priority 2
    (CONFIG,
     re.compile(r"(debug\s*=\s*true|debug_mode\s*=\s*true|app\.run\([^)]*debug\s*=\s*true|"
                r"app_debug\s*=\s*true)", re.I),
     "开启了调试模式，工具无法判定该配置是否会进入生产环境，请确认其部署范围。", 2),
    (CONFIG,
     re.compile(r"(access-control-allow-origin['\"\s:=]{0,6}\*|"
                r"allow_origins\s*=\s*\[?\s*['\"]\*|cors\([^)]*origins\s*=\s*['\"]\*|"
                r"origins\s*=\s*['\"]\*['\"])", re.I),
     "CORS 允许任意来源，工具无法判定该策略是否被浏览器端凭据请求利用，"
     "请确认是否配合了凭据（credentials）与来源校验。", 2),
    (CONFIG,
     re.compile(r"(httponly\s*=\s*false|secure\s*=\s*false|samesite\s*=\s*['\"]?none)",
                re.I),
     "Cookie 安全属性被关闭，工具无法判定该 Cookie 是否承载会话凭据，"
     "请确认其敏感性与作用域。", 2),
    (CONFIG,
     # 明文加载外部资源（CWE-319）：HTML/CSS 的 @import/src/href/url() 写死
     # http:// —— 语言级事实（协议出现在资源地址里即为明文）。是否为真实风险
     # 取决于部署（内网/回源/CDN 终结 TLS），工具无法判定，故只提醒。
     re.compile(r"(@import\s+url\(\s*['\"]?|url\(\s*['\"]?|"
                r"\bsrc\s*=\s*['\"]|\bhref\s*=\s*['\"]|"
                r"url\s*:\s*['\"])http://", re.I),
     "以明文 http:// 引用外部资源，工具无法判定该资源传输是否经过不可信网络、"
     "以及是否存在内容被篡改的风险，请确认是否应使用 https。", 2),

    # --- 弱随机（噪音最大，优先级最低）-------------------------------------- priority 2
    (CRYPTO,
     re.compile(r"(random\.random\(|random\.randint\(|random\.choice\(|"
                r"math\.random\(|new\s+random\(|mt_rand\(|rand\(\s*\))", re.I),
     "使用了非密码学安全随机数，工具无法判定其是否用于安全敏感值"
     "（token/密钥/盐/口令重置码），请确认该随机值是否可被预测。", 2),

    # =========================================================================
    # --- 2026-08-31 第八波：盲区层收口（指导文档 §9.20.2 / §8.5 复核后补入）---
    #
    # 背景：本轮核验发现，指导文档里归入"盲区提醒层"的多类形态在本表中
    # **没有对应规则**——会话固定/CSRF 授权族（87 段 typical_15/16/22 实测
    # 0 提醒）、Spring POJO 绑定（hard_cve_05 0 提醒）、NodeGoat 的密码明文
    # 落库与 http 明文服务（均 0 提醒）。它们此前"既未修、也未提醒"。
    # 本批 5 条把"有行级形态可提示"的类接进提醒层；备注：
    #   - ReDoS / 服务端 console 日志注入 / 弱口令正则 / 312 参数直赋落库
    #     已升级为 prefilter finding 通道（见 prefilter.py 第八波），不再重复；
    #   - missing authorization 的"敏感操作"定义仍待标签治理定案（§8.8 缓期
    #     维持），本批不越权代行；
    #   - CSRF 不做精确判定，仅在"写方法路由"这一语言级事实上提醒。
    # =========================================================================

    # --- 会话固定（CWE-384，typical_16 实锤 0 提醒）------------------------ priority 3
    (AUTHORIZATION,
     re.compile(r"(?:req(?:uest)?\.session|(?<![\w.])session)\s*"
                r"(?:\.\s*|\[\s*['\"]?)(?:user|userid|uid|username|account|"
                r"login|email|member)\w*['\"]?\s*\]?\s*=[^=]", re.I),
     "登录态被写入会话存储，工具无法判定写入前是否重新生成了会话标识"
     "（session regeneration），请确认是否存在会话固定风险。", 3),

    # --- 状态变更路由的访问控制 / CSRF（CWE-352/862，typical_22 实锤 0 提醒）---
    # 触发只依赖语言级事实：路由声明为写方法（Flask/FastAPI methods=[POST..] /
    # Spring @Post|Put|DeleteMapping）。是否有防护属业务语义，交给模型确认。
    # 不收裸 Express app.post(：服务端仓库几乎每文件都有，提醒无差别泛滥。
    (AUTHORIZATION,
     re.compile(r"@(?:\w+\.)?route\s*\([^)]*methods\s*=\s*\[[^\]]*"
                r"['\"](?:POST|PUT|DELETE|PATCH)['\"][^\]]*\]"
                r"|@(?:Post|Put|Delete|Patch)Mapping\b", re.I),
     "该路由声明为状态变更方法（POST/PUT/DELETE/PATCH），工具无法判定其是否"
     "具备访问控制与 CSRF 防护，请确认是否存在 token 校验与权限检查。", 3),

    # --- Spring MVC POJO 参数绑定（CWE-915/Spring4Shell 面，hard_cve_05 实锤
    #     0 提醒）------------------------------------------------------------- priority 3
    # 语言级事实：@*Mapping 方法以业务对象作形参时，请求参数自动绑定到同名字段
    # （Spring MVC 官方行为）。漏洞不在"用了绑定"而在"未限定可绑定字段"——
    # 写成 finding 会 FP 掉所有正常 controller（§9.12.1 原判正确），但作为
    # 提醒恰如其分。排除显式标量注解形参（@RequestParam/@PathVariable 等）。
    (FRAMEWORK,
     re.compile(r"@(?:Request|Post|Put|Patch|Delete)Mapping[^\n]*\n"
                r"(?:[ \t]*@[^\n]*\n)*"
                r"[ \t]*(?:public|protected|private)?[^\n(]*?\(\s*"
                r"(?:@[A-Za-z]+\s+)?"
                r"(?!(?:String|Integer|Long|Boolean|Double|Float|BigDecimal|Model|"
                r"ModelMap|MultipartFile|Principal|BindingResult|Errors|SessionStatus|"
                r"Locale|Map|List|Pageable|Authentication|HttpServletRequest|"
                r"HttpServletResponse|HttpSession)\b)"
                r"[A-Z][\w<>\[\].]*\s+[a-z]\w*\s*(?=[,)])", re.I),
     "Spring MVC 处理方法以业务对象作形参，请求参数会自动绑定到同名字段，"
     "工具无法判定可绑定字段是否受白名单限制，请确认敏感字段（如 role/"
     "isAdmin/price）能否被外部绑定覆盖。", 3),

    # --- 口令明文落库（CWE-256，NodeGoat user-dao L25 实锤 0 提醒）---------
    # 为什么不做 finding：password 字段的请求取值行在登录流程安全样本
    # （safe_11 bcrypt 形态）完全同形，文件级规则区分不了"哈希后入库"与
    # "明文入库"；提醒层的价值在于"入库前是否哈希"值得模型看一眼。
    # 右侧仅认裸标识符/简写属性——bcrypt.hashSync(...) 这类已哈希写法豁免。
    (CRYPTO,
     re.compile(r"\.\s*(?:password|passwd|pwd)\w*\s*=\s*[A-Za-z_$][\w$]*\s*[;,)\n]"
                r"|(?:^|[{,\s])(?:password|passwd|pwd)\s*:\s*[A-Za-z_$][\w$]*\s*[,}]"
                r"|(?:^|[{,\s])(?:password|passwd|pwd)\s*(?:,\s*(?://|$)|//)", re.I | re.M),
     "口令字段被赋值或随对象写入持久化，工具无法判定入库前是否已做单向加密"
     "（哈希加盐），请确认存储链路是否存在明文口令。", 2),

    # --- http 明文服务（CWE-319 面，NodeGoat server.js L145 实锤 0 提醒）---
    # 语言级事实：http.createServer 与 https.createServer 是不同 API 名，
    # 无第二语义；是否有碍取决于部署（TLS 终结/反代），属提醒不属判定。
    (CONFIG,
     re.compile(r"\bhttp\.createServer\s*\(", re.I),
     "服务端以 http 模块明文监听，工具无法判定部署链路中是否有 TLS 终结"
     "（反向代理/网关），请确认传输层加密由哪一层负责。", 2),

    # =========================================================================
    # --- 2026-09-01 第二批：盲区层缺口补齐（全规则泛化审计 r3/r4 实锤）-------
    #
    # 审计发现：LDAP 注入 / XML 外部实体解析 / Go 语句拼接在盲区层均为
    # 零覆盖——形态规则（prefilter/taint_tracker）能命中部分，但盲区提醒
    # 层没有对应规则，导致这些族在形态不精确命中时"既未修也未提醒"。
    # =========================================================================

    # --- LDAP 注入（CWE-90，盲区层原有零覆盖，prefilter 只覆盖 Python）------
    # 语言级事实：LDAP filter 语法 "(uid=...)" 是 LDAP 查询的标准构造，
    # 外部输入拼入 filter 字符串 = 攻击者可注入 LDAP 语法改变查询逻辑。
    # 不限于 search_s：simple_bind 的 DN 拼接同样可注入。
    (TRUST_BOUNDARY,
     re.compile(r"(?:search_s?\s*\(|simple_bind\s*\(|ldap_search\s*\()"
                r"[^)]*(?:\+\s*\w|f['\"]|\.\s*(?:format|replace)\s*\(|%\s*\w)"
                r"|\(\s*(?:uid|cn|sn|ou|mail|dc)\s*=\s*['\"]?\s*[\.\+\{%]", re.I),
     "外部输入被拼入 LDAP 查询过滤器，工具无法判定该值是否经过 LDAP 转义"
     "（ldap.filter.escape_filter_chars 或参数化绑定），请确认是否存在 "
     "LDAP 注入风险。", 3),

    # --- XML 外部实体解析（CWE-611，盲区层原有零覆盖）------------------------
    # 语言级事实：xml.etree.ElementTree.fromstring / lxml.etree.fromstring /
    # xml.dom.minidom.parseString 是 Python XML 解析的标准 API 名。
    # 是否禁用了外部实体取决于解析器配置（defusedxml / resolve_entities），
    # 正则层不可判——提醒层的价值在于让模型确认解析器加固状态。
    (SERIALIZATION,
     re.compile(r"(?:xml\.etree\.ElementTree|xml\.dom\.minidom)"
                r"\s*\.\s*(?:fromstring|parse|parseString)\s*\("
                r"|(?:fromstring|parseString)\s*\(\s*(?:request\.|body|data|input)"
                r"|xml\.parsers\.expat\b"
                r"|libxml2\b|simplexml_load", re.I),
     "XML 解析器直接解析外部数据，工具无法判定该解析器是否禁用了外部实体"
     "（XXE）与 DTD，请确认是否使用了 defusedxml 或等效加固配置。", 3),

    # --- Go 语句拼接（盲区层原有零覆盖，Go 工具层整体不支持）-----------------
    # 语言级事实：Go 的 exec.Command("sh","-c",input) 是 shell 注入标准形态；
    # db.Query("..."+input) 是 SQL 拼接标准形态。Go 工具层不支持
    # （tree_sitter_go 未装），盲区提醒是唯一防线。
    (FRAMEWORK,
     re.compile(r"exec\.Command\s*\([^)]*[\"']sh[\"'][^)]*[\"']-c[\"']"
                r"|exec\.command\s*\([^)]*[\"']sh[\"'][^)]*[\"']-c[\"']"
                r"|(?:db\.)?(?:query|exec|queryrow)\s*\(\s*[\"`][^\"`]*\+", re.I),
     "Go 代码检测到 shell/SQL 语句拼接，工具层不支持 Go 污点分析，"
     "请确认拼接的内容是否包含未经净化的外部输入。", 3),
]

# --- 授权盲区的变量流追踪（AUTHORIZATION 专用）--------------------------------
# 为什么需要超出纯正则：真实越权代码几乎总是**跨语句**的——
#     oid = request.args.get('order_id')     # 污染源在 L5
#     order = Order.query.get(oid)           # 数据访问在 L6
# 任何单行正则都无法把这两行关联起来（自检 1 实锤：纯行级规则 0 命中）。
# 这里做**极轻量**的单文件变量名匹配：不识别消毒、不追踪跨函数（那是
# TaintTracker 的职责），只标出"外部输入流向数据访问"这个**值得模型看一眼**
# 的位置——是否存在授权检查，完全交给模型判定（这正是本模块的定位）。
_EXT_SOURCE_ASSIGN_RE = re.compile(
    r"(?:^|[^\w.])([A-Za-z_]\w{0,40})\s*(?:\[[^\]]*\])?\s*=\s*[^\n]*"
    r"(request\.|params\[|params\.|args\[|args\.|body\[|body\.|form\[|form\.|"
    r"query_params|queryparams|getparameter\(|getParameter\(|headers\[|cookies\[)",
    re.I)

# 二跳传播（2026-08-31）：`oid = payload['id']` 这类"从已污染容器取值"的赋值。
# 为什么需要：真实代码的输入几乎不直接进入 sink，而是先落进容器变量再取字段
# （VFlask 实锤：`content = request.json` → `customer_id = content['id']` →
# `Customer.query.get(customer_id)`）。仅 1 跳时 tainted={content}，而 sink 用的
# 是 customer_id，关联不上 → IDOR 盲区整类漏提示。
# 这是标准污点传播的第 2 跳（不识别消毒、不追跨函数，见下方说明），
# 传播深度封顶 TTAINT_PROPAGATION_HOPS 次迭代以防无限扩散。
_PROPAGATE_RE = re.compile(
    r"(?:^|[^\w.])([A-Za-z_]\w{0,40})\s*(?:\[[^\]]*\])?\s*=\s*"
    r"([A-Za-z_]\w{0,40})\s*(?:\[[^\]]*\]|\.\w+)",
    re.I)

# 传播迭代上限：2 次即覆盖 "request → 容器 → 字段" 链。更深传递链属
# TaintTracker / 模型职责——本模块只标出"值得看一眼"的位置，不做完整数据流。
TTAINT_PROPAGATION_HOPS = 2

# 路由参数（URL 路径变量）作为外部输入源（2026-08-31）。
# 依据：各框架**官方文档的标准路由语法**——变量直接取自 URL，是外部可控输入，
# 与 request.args / req.body 同级。缺了这一路，凡"路径参数 → 数据访问"的
# IDOR 形态都无从关联（VFlask 实锤：@app.route('/get/<cust_id>') → get_customer
# (cust_id) → Customer.query.get(cust_id) 整条链 0 提醒）。
# 只匹配**路由装饰器/注册语句**内的变量语法，非路由上下文的 `<div>`、`:x` 不误伤。
_ROUTE_PARAM_RE = re.compile(
    r"@\w+\.route\(\s*['\"][^'\"]*?<(?:\w+\s*:\s*)?([A-Za-z_]\w*)>"   # Flask
    r"|\bpath\(\s*['\"][^'\"]*?<(?:\w+\s*:\s*)?([A-Za-z_]\w*)>"        # Django
    r"|\bapp\.(?:get|post|put|delete|all)\(\s*['\"][^'\"]*?:([A-Za-z_]\w*)"  # Express
    r"|@(?:Get|Post|Put|Delete|Request)Mapping\([^)]*?\{([A-Za-z_]\w*)\}",  # Spring
    re.I)
_DATA_ACCESS_RE = re.compile(
    r"\b(get|find|filter|query|delete|update|fetch|load|remove|"
    r"get_object_or_404|findById|findOne|find_by_id|getbyid)\s*\(\s*([A-Za-z_]\w{0,40})",
    re.I)
_AUTH_FLOW_NOTE = (
    "外部输入经变量流向数据访问操作，工具无法判定是否存在针对当前用户的归属/"
    "授权校验，请确认是否存在越权访问（IDOR）的可能。"
)

# 限量：防止提醒淹没模型（超过 5 条后注意力稀释，且会抬高判真率）
MAX_TOTAL = 5
PER_CATEGORY_CAP = 2


@dataclass
class BlindSpot:
    """单个行级盲区提醒。"""
    category: str
    line_start: int
    line_end: int
    snippet: str          # 证据行（trim 后）
    note: str             # 中性提醒文本
    priority: int = 0
    # 同类别被 per_category_cap 截断的**其它位置**（2026-08-31）。
    # 为什么需要：cap 的初衷是"防某一类刷屏、稀释注意力"，但直接丢弃会让
    # 同文件的第 3 处同类盲区彻底消失——dvna 实锤：3 处 IDOR 形态（L11/L107/
    # L145）只提醒了前 2 处，漏掉的那处正好是真漏洞所在。
    # 于是 cap 改为"条目数"限制而非"位置数"限制：代表条目保留，其余位置记入
    # 本字段——prompt 里仍是一行（不稀释注意力），但 build_review_context
    # 会把它们一并纳入定向复核片段（不丢覆盖）。
    extra_lines: list[int] = field(default_factory=list)

    @property
    def category_label(self) -> str:
        return _CATEGORY_LABELS.get(self.category, self.category)

    @property
    def all_lines(self) -> list[int]:
        """本条提醒覆盖的全部行号（代表行 + 同类附加行，升序去重）。"""
        return sorted(set([self.line_start] + list(self.extra_lines)))

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "category_label": self.category_label,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "snippet": self.snippet,
            "note": self.note,
            "priority": self.priority,
            "extra_lines": list(self.extra_lines),
        }


@dataclass
class BlindSpotReport:
    """一个文件的盲区扫描结果。"""
    spots: list[BlindSpot] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.spots)

    @property
    def high_priority_count(self) -> int:
        """高优先级（授权/过滤/信任边界/反序列化）盲区数量——决定复核档位的信号。"""
        return sum(1 for s in self.spots if s.priority >= 4)

    def to_dict(self) -> dict:
        return {"count": self.count,
                "high_priority_count": self.high_priority_count,
                "spots": [s.to_dict() for s in self.spots]}


def _trim(line: str, limit: int = 160) -> str:
    line = line.rstrip()
    return line if len(line) <= limit else line[:limit] + " …"


def _scan_authorization_flow(lines: list[str]) -> list[BlindSpot]:
    """外部输入 → 数据访问 的单文件变量流盲区（授权/IDOR）。

    仅做变量名集合匹配（见 _EXT_SOURCE_ASSIGN_RE 处的说明）：不识别消毒、
    不追踪跨函数。因此它必然存在"看起来像 IDOR 但实际有授权检查"的条目——
    这是**设计使然**：本模块产出的是提示而非告警，误提示由模型在上下文中
    消解，而漏提示（真 IDOR 无人提醒）才是本模块要防的代价。
    """
    # 一跳：右侧直接出现外部源 → 该变量被污染
    tainted: set[str] = set()
    for raw in lines:
        for m in _EXT_SOURCE_ASSIGN_RE.finditer(raw):
            tainted.add(m.group(1))
        # 路由参数：URL 路径变量是外部输入（框架级事实，见 _ROUTE_PARAM_RE）
        for m in _ROUTE_PARAM_RE.finditer(raw):
            for g in m.groups():
                if g:
                    tainted.add(g)

    # 二跳起：从已污染变量派生的变量同样被污染（迭代至不动点或达上限）
    for _ in range(TTAINT_PROPAGATION_HOPS):
        grew = False
        for raw in lines:
            for m in _PROPAGATE_RE.finditer(raw):
                target, src = m.group(1), m.group(2)
                if src in tainted and target not in tainted:
                    tainted.add(target)
                    grew = True
        if not grew:
            break

    if not tainted:
        return []

    spots: list[BlindSpot] = []
    for lineno, raw in enumerate(lines, start=1):
        for m in _DATA_ACCESS_RE.finditer(raw):
            if m.group(2) in tainted:
                spots.append(BlindSpot(
                    category=AUTHORIZATION, line_start=lineno, line_end=lineno,
                    snippet=_trim(raw), note=_AUTH_FLOW_NOTE, priority=5))
                break  # 每行最多一条，防单行刷屏
    return spots


def scan_blind_spots(code: str, max_total: int = MAX_TOTAL,
                     per_category_cap: int = PER_CATEGORY_CAP) -> BlindSpotReport:
    """扫描代码中的工具层盲区（行级、确定性）。

    两条通道：
      1. 正则形态规则（_BLIND_SPOT_RULES）——单行可判定的形态；
      2. 变量流追踪（_scan_authorization_flow）——跨语句的授权盲区。

    Args:
        code: 源代码全文
        max_total: 单文件返回的盲区上限（防注意力稀释）
        per_category_cap: 单类别上限（防某一类刷屏）

    Returns:
        BlindSpotReport（按 priority 降序、行号升序）

    注意：本函数**不判定是否存在漏洞**，只标注"工具看不到的位置"。
    """
    if not code or not code.strip():
        return BlindSpotReport()

    lines = code.split("\n")
    candidates: list[BlindSpot] = []

    # 通道 1：行级形态规则
    for category, pattern, note, priority in _BLIND_SPOT_RULES:
        for m in pattern.finditer(code):
            # 字符偏移 → 行号（1-based）
            line_no = code.count("\n", 0, m.start()) + 1
            snippet = _trim(lines[line_no - 1]) if line_no <= len(lines) else ""
            candidates.append(BlindSpot(
                category=category, line_start=line_no, line_end=line_no,
                snippet=snippet, note=note, priority=priority))

    # 通道 2：跨语句变量流（授权盲区）
    candidates.extend(_scan_authorization_flow(lines))

    # 统一限量：优先级降序 → 行号升序；每类封顶 + 同类同行去重
    #
    # 2026-08-31 修正：cap 超限的位置**不再丢弃**，而是并入同类代表条目的
    # extra_lines。理由见 BlindSpot.extra_lines 注释——cap 该限制的是"提醒
    # 条目数"（注意力成本），不应顺带抹掉位置（覆盖成本）。
    found: list[BlindSpot] = []
    per_cat: dict[str, int] = {}
    by_cat: dict[str, BlindSpot] = {}   # 每类的代表条目（首个入选者）
    for s in sorted(candidates, key=lambda x: (-x.priority, x.line_start)):
        rep = by_cat.get(s.category)
        if rep is not None and rep.line_start == s.line_start:
            continue                     # 同类同行去重
        if per_cat.get(s.category, 0) >= per_category_cap:
            # 超 cap：位置并入代表条目（仅记首次出现的行，避免重复累积）
            if rep is not None and s.line_start not in rep.extra_lines:
                rep.extra_lines.append(s.line_start)
            continue
        found.append(s)
        per_cat[s.category] = per_cat.get(s.category, 0) + 1
        by_cat.setdefault(s.category, s)

    for s in found:
        s.extra_lines.sort()
    return BlindSpotReport(spots=found[:max_total])


# ---------------------------------------------------------------------------
# 输出：注入 prompt 的提醒文本
# ---------------------------------------------------------------------------
_PROMPT_HEADER = (
    "【工具层盲区提醒】以下位置的性质**工具无法判定**（不是告警，不代表存在漏洞）。"
    "工具只能召回可规则化的形态，而这些位置是否有问题取决于上下文，"
    "需要你自行沿数据流确认后再下结论；若确认无问题，照常判安全即可。"
)


def render_for_prompt(report: BlindSpotReport) -> str:
    """把盲区渲染成注入 user prompt 的文本（有候选时的零成本通道）。

    措辞纪律：头部显式声明"不是告警"，每条 note 均描述工具的能力边界。
    """
    if not report.spots:
        return ""
    parts = [_PROMPT_HEADER]
    for s in report.spots:
        # 同类附加位置以"另见 Lx/Ly"补在同一条里——保持条目数不变（不稀释
        # 注意力），但位置信息不丢（模型可一并确认）。
        extra = (f"（同类另见 L{('/L').join(str(x) for x in s.extra_lines)}）"
                 if s.extra_lines else "")
        parts.append(
            f"- L{s.line_start} [{s.category_label}] {s.note}{extra}"
            + (f"\n  证据：`{s.snippet}`" if s.snippet else "")
        )
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# 输出：定向复核上下文（把"全文件复核"换成"盲区片段复核"）
# ---------------------------------------------------------------------------
# 定向复核的**收益闸门**（2026-08-31）：片段拼接后若仍占原文 min_saving 以上
# 比例，说明"定向"没有实际收益——返回 None 让调用方回退原行为。
# 为什么需要：短文件与压缩产物（min.js）里，window 片段会互相重叠合并成
# 近乎整文件，再叠加行号前缀反而**比原文更长**（dvna config/server.js 实测
# 131%、jquery.min.js 100.1%）。此时"定向复核"名存实亡，却仍要承担片段拼接
# 与行号映射的复杂度和失真风险。文件本就小时全量复核并不贵，回退更划算。
MIN_SAVING_RATIO = 0.6   # 片段须比原文至少省 40%


def build_review_context(
    code: str,
    report: BlindSpotReport,
    window: int = 6,
    max_chars: int = 3000,
    min_saving: float = MIN_SAVING_RATIO,
) -> Optional[str]:
    """把盲区行 ± window 行的片段拼成复核上下文（替代整文件进 LLM）。

    这是"定向复核省时间"的来源：模型从"读 1000 行找漏洞"变成
    "看几个 10 行片段判漏洞"。片段带原始行号，保证模型给出的行号可直接映射。

    Args:
        code: 源代码全文
        report: scan_blind_spots 的结果
        window: 每个盲区行上下各取的行数
        max_chars: 总字符预算（超出后不再追加片段）

    Returns:
        拼接好的带行号片段文本；无盲区或超预算时返回 None（调用方回退旧行为）。
    """
    if not report.spots or not code:
        return None
    lines = code.split("\n")

    # 合并重叠区间（邻近盲区行会共享上下文，避免重复）
    # 取 all_lines 而非 line_start：同类被 cap 截断的位置（extra_lines）同样
    # 需要片段——模型看到它们才谈得上"确认"（2026-08-31，见 extra_lines 注释）。
    ranges: list[tuple[int, int]] = []
    all_lines = sorted({ln for s in report.spots for ln in s.all_lines})
    for ln in all_lines:
        lo = max(1, ln - window)
        hi = min(len(lines), ln + window)
        if ranges and lo <= ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], hi))
        else:
            ranges.append((lo, hi))

    parts: list[str] = []
    used = 0
    for lo, hi in ranges:
        body = "\n".join(f"{i}: {lines[i - 1]}" for i in range(lo, hi + 1))
        header = (f"# ==== 盲区片段 L{lo}-L{hi}"
                  f"（{_range_categories(report, lo, hi)}）====")
        block = header + "\n" + body
        if used + len(block) > max_chars and parts:
            break
        used += len(block)
        parts.append(block)
    if not parts:
        return None
    result = "\n\n".join(parts)
    # 收益闸门：省不下足够内容时定向无意义，回退整文件（见 MIN_SAVING_RATIO）
    if len(result) >= len(code) * min_saving:
        return None
    return result


def _range_categories(report: BlindSpotReport, lo: int, hi: int) -> str:
    cats = []
    for s in report.spots:
        # 用 all_lines：片段范围已含 extra_lines，类别标注须与之同源，
        # 否则会出现"片段里有一段、但标注的类别里没有它"的不一致。
        if any(lo <= ln <= hi for ln in s.all_lines) and s.category_label not in cats:
            cats.append(s.category_label)
    return "、".join(cats) or "盲区"


# ---------------------------------------------------------------------------
# 自检（离线）
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    print("=== 工具层盲区定位 自检（离线）===\n")

    # 1) 能定位到工具规则覆盖不到的形态
    idor = ("from flask import request\n"
            "from app.models import Order\n"
            "@app.route('/order')\n"
            "def view_order():\n"
            "    oid = request.args.get('order_id')\n"
            "    order = Order.query.get(oid)\n"
            "    return render(order)\n")
    rep = scan_blind_spots(idor)
    has_auth = any(s.category == AUTHORIZATION for s in rep.spots)
    ok1 = has_auth and rep.spots[0].line_start == 6
    print(f"[{'PASS' if ok1 else 'FAIL'}] 越权(IDOR)盲区定位: "
          f"命中={has_auth}, 行号={[ (s.category, s.line_start) for s in rep.spots ]}")

    # 2) 措辞纪律：不得出现定性词（"存在漏洞/危险/可被攻击"等）
    BANNED = ("存在漏洞", "是漏洞", "危险代码", "可被攻击", "已经被攻击",
              "攻击者可以利用", "肯定存在", "必然存在")
    bad = [w for w in BANNED if any(w in r[2] for r in _BLIND_SPOT_RULES)]
    ok2 = not bad
    print(f"[{'PASS' if ok2 else 'FAIL'}] 措辞中性（无定性词）: 违规词={bad or '无'}")

    # 3) 每条提醒必须以"请确认"收尾（把判断权交还模型），含变量流通道的文案
    all_notes = [r[2] for r in _BLIND_SPOT_RULES] + [_AUTH_FLOW_NOTE]
    ok3 = all(n.rstrip().endswith("。") and "请确认" in n for n in all_notes)
    print(f"[{'PASS' if ok3 else 'FAIL'}] 每条均含'请确认': "
          f"{sum(1 for n in all_notes if '请确认' in n)}/{len(all_notes)}")

    # 4) 限量与每类封顶
    noisy = "\n".join([
        "import random",
        "a = random.random()",
        "b = random.random()",
        "c = random.random()",
        "d = random.random()",
        "e = random.random()",
    ])
    rep2 = scan_blind_spots(noisy)
    per_cat = {}
    for s in rep2.spots:
        per_cat[s.category] = per_cat.get(s.category, 0) + 1
    ok4 = len(rep2.spots) <= MAX_TOTAL and all(v <= PER_CATEGORY_CAP for v in per_cat.values())
    print(f"[{'PASS' if ok4 else 'FAIL'}] 限量: total={len(rep2.spots)}<={MAX_TOTAL}, "
          f"每类={per_cat}")

    # 5) 优先级排序：授权(5) 应排在配置(2) 之前
    mixed = ("DEBUG = True\n"
             "oid = request.args.get('id')\n"
             "row = db.query.get(oid)\n"
             "import random\nx = random.random()\n")
    rep3 = scan_blind_spots(mixed)
    prios = [s.priority for s in rep3.spots]
    ok5 = prios == sorted(prios, reverse=True) and (not prios or prios[0] >= 4)
    print(f"[{'PASS' if ok5 else 'FAIL'}] 优先级降序: {prios}")

    # 6) 定向复核上下文：片段远小于全文，且保留原始行号
    big = "\n".join(f"line{i} = {i}" for i in range(1, 401))
    big_code = big + "\n" + idor
    rep4 = scan_blind_spots(big_code)
    ctx = build_review_context(big_code, rep4, window=6)
    ratio = (len(ctx) / len(big_code) * 100) if ctx else 0.0
    ok6 = (ctx is not None and rep4.count > 0 and len(ctx) < len(big_code) // 2
           and any(f"{s.line_start}:" in ctx for s in rep4.spots))
    print(f"[{'PASS' if ok6 else 'FAIL'}] 定向上下文压缩: "
          f"全文={len(big_code)}字符 → 上下文={len(ctx) if ctx else 0}字符 "
          f"({ratio:.1f}%), 盲区={rep4.count}")

    # 7) 无盲区 → 上下文为 None（调用方回退旧行为），空代码不崩
    ok7 = build_review_context("x = 1\n", scan_blind_spots("x = 1\n")) is None \
        and scan_blind_spots("").count == 0
    print(f"[{'PASS' if ok7 else 'FAIL'}] 空结果/空输入安全: ctx=None, 空码 count=0")

    # 8) prompt 渲染含免责声明
    rendered = render_for_prompt(rep)
    ok8 = rendered and "不是告警" in rendered and "不代表存在漏洞" in rendered
    print(f"[{'PASS' if ok8 else 'FAIL'}] prompt 免责声明: "
          f"长度={len(rendered)}, 含声明={ok8}")

    # 9) 二跳传播（2026-08-31）：request → 容器 → 字段 → 数据访问
    #    真实代码的 IDOR 几乎都是这个形态，1 跳关联不上（VFlask L208 实锤）
    two_hop = "\n".join([
        "def get_customer():",
        "    content = request.json",
        "    customer_id = content['id']",
        "    rec = Customer.query.get(customer_id)",
        "    return rec",
    ])
    rep9 = scan_blind_spots(two_hop)
    ok9 = any(s.category == AUTHORIZATION and s.line_start == 4 for s in rep9.spots)
    print(f"[{'PASS' if ok9 else 'FAIL'}] 二跳传播(容器取字段): "
          f"L4命中={ok9}, 命中={[(s.category, s.line_start) for s in rep9.spots]}")

    # 10) 路由参数作为外部输入源（Flask/Django/Express/Spring 标准路由语法）
    route = "\n".join([
        "@app.route('/get/<cust_id>', methods=['GET'])",
        "def get_customer(cust_id):",
        "    rec = Customer.query.get(cust_id)",
        "    return rec",
    ])
    rep10 = scan_blind_spots(route)
    ok10 = any(s.category == AUTHORIZATION and s.line_start == 3 for s in rep10.spots)
    print(f"[{'PASS' if ok10 else 'FAIL'}] 路由参数(URL路径变量): "
          f"L3命中={ok10}, 命中={[(s.category, s.line_start) for s in rep10.spots]}")

    # 11) 同类超限：条目数受限，但位置不丢（extra_lines）+ 片段仍覆盖
    # 样本须足够长：短文件会被收益闸门正确挡下（返回 None），测不到本用例。
    # 三处 IDOR 分散在 72 行中，片段合计约 35 行（≈49%）→ 定向有收益。
    many = "\n".join(sum([
        [f"def handler{i}(request):",
         f"    oid{i} = request.args.get('id')",
         f"    rec{i} = Order.query.get(oid{i})",
         f"    return rec{i}"]
        # 填充行须有真实长度：闸门按**字符**占比判定，全用短行会让
        # "覆盖 49% 行数" 折算成 66% 字符，反而被正确挡下（测不到本用例）
        + [f"    # pad line {j} " + "-" * 40 for j in range(20)]
        for i in range(1, 4)], []))
    rep11 = scan_blind_spots(many, per_category_cap=2)
    auth11 = [s for s in rep11.spots if s.category == AUTHORIZATION]
    covered11 = sorted({ln for s in auth11 for ln in s.all_lines})
    ok11 = (len(auth11) <= 2 and any(s.extra_lines for s in auth11)
            and len(covered11) >= 3)
    ctx11 = build_review_context(many, rep11)
    # 片段行形如 "4: rec1 = ..."，须按行号前缀匹配而非整行相等
    ctx_lines = {ln.split(":", 1)[0].strip()
                 for ln in (ctx11 or "").split("\n") if ":" in ln}
    ok11 = ok11 and ctx11 is not None and all(
        str(n) in ctx_lines for n in covered11)
    print(f"[{'PASS' if ok11 else 'FAIL'}] 同类超限不丢位置: "
          f"条目={len(auth11)}(cap2), 覆盖行={covered11}, 片段含全部={ok11}")

    # 12) 收益闸门：短文件/压缩产物定向无收益 → 回退整文件（None）
    tiny = "src = 'http://a.com/x.js'\nval = request.args.get('v')\nrec = M.query.get(val)"
    rep12 = scan_blind_spots(tiny)
    ctx12 = build_review_context(tiny, rep12)
    ok12 = rep12.count > 0 and ctx12 is None
    print(f"[{'PASS' if ok12 else 'FAIL'}] 收益闸门(短文件回退): "
          f"盲区={rep12.count}, ctx={'None(回退整文件)' if ctx12 is None else '片段'}")

    # 13) 第八波·盲区层收口（会话固定/写方法路由/Spring POJO 绑定/密码明文/
    #     http 明文服务）——指导文档 §9.20.2 / §8.5 复核后补入的 5 条提醒
    wave8_py = "\n".join([
        "@app.route('/transfer', methods=['POST'])",   # 写方法路由
        "def transfer():",
        "    session['user_id'] = username",            # 会话固定形态
        "    return 'ok'",
    ])
    rep13a = scan_blind_spots(wave8_py)
    cats13a = {(s.category, s.line_start) for s in rep13a.spots}
    ok13a = (any(c == 'authorization' and l == 1 for c, l in cats13a)
             and any(c == 'authorization' and l == 3 for c, l in cats13a))
    wave8_java = "\n".join([
        "class UserController {",
        "    @PostMapping(\"/users/add\")",
        "    public String addUser(UserForm form) { return form.getName(); }",
        "}",
    ])
    rep13b = scan_blind_spots(wave8_java)
    ok13b = any(s.category == 'framework' for s in rep13b.spots)
    wave8_js = "\n".join([
        "const usersCol = db.collection('users');",
        "this.addUser = (userName, password, cb) => {",
        "    const user = { password, //received from request param",
        "    };",
        "    http.createServer(app).listen(4000);",
        "    cb(null);",
        "};",
    ])
    rep13c = scan_blind_spots(wave8_js)
    cats13c = {s.category for s in rep13c.spots}
    ok13c = 'crypto' in cats13c and 'config' in cats13c
    # 负样本：String 标量形参不是 POJO 绑定；https 服务不是明文
    neg_spring = "\n".join([
        "@PostMapping(\"/ok\")",
        "public String ok(String name) { return name; }",
    ])
    ok13d = not any(s.category == 'framework'
                    for s in scan_blind_spots(neg_spring).spots)
    ok13 = ok13a and ok13b and ok13c and ok13d
    print(f"[{'PASS' if ok13 else 'FAIL'}] 第八波收口提醒: "
          f"py授权={sorted(cats13a)}, java绑定={ok13b}, js密码+http={ok13c}, "
          f"String负样本={ok13d}")

    all_ok = all([ok1, ok2, ok3, ok4, ok5, ok6, ok7, ok8,
                  ok9, ok10, ok11, ok12, ok13])
    print(f"\n{'=== 自检通过 ===' if all_ok else '!!! 自检失败 !!!'}")
    sys.exit(0 if all_ok else 1)
