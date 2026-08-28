# -*- coding: utf-8 -*-
"""覆盖缺口检查：漏洞类型 / 语言 / 框架 / 场景"""
import json, re, sys, collections
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SRC = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_alpha06_v2_12.jsonl")
OUT = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\audit\a9_coverage_out.txt")

rows = []
with SRC.open("r", encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if line: rows.append((i, json.loads(line)))
def get(msgs, role):
    for m in msgs:
        if m.get("role") == role: return m.get("content", "")
    return ""

blob = []
for i, r in rows:
    blob.append(get(r["messages"],"user") + "\n" + get(r["messages"],"assistant"))
TEXT = "\n".join(blob)
TEXT_LOW = TEXT.lower()

w = OUT.open("w", encoding="utf-8")
def P(*a): print(*a, file=w)

# ---------- 1. 漏洞关键词覆盖 ----------
P("=" * 78); P("[1] 漏洞类型覆盖（在数据集中出现次数，0 = 完全缺失）"); P("=" * 78)
VULN_TERMS = {
    "SQL 注入": ["sql injection", "sql注入", "cwe-89"],
    "NoSQL 注入": ["nosql", "cwe-943", "$where", "mongodb"],
    "LDAP 注入": ["ldap", "cwe-90"],
    "XPath 注入": ["xpath", "cwe-643"],
    "命令注入": ["command injection", "命令注入", "cwe-78", "os.system", "subprocess"],
    "代码注入": ["code injection", "代码注入", "cwe-94", "eval("],
    "模板注入 SSTI": ["ssti", "模板注入", "cwe-1336", "jinja2", "freemarker", "velocity"],
    "表达式注入 SpEL/OGNL": ["spel", "ognl", "cwe-917", "expressionparser"],
    "XSS": ["xss", "cross-site scripting", "cwe-79"],
    "CSRF": ["csrf", "cwe-352", "xsrf"],
    "SSRF": ["ssrf", "cwe-918"],
    "开放重定向": ["open redirect", "开放重定向", "cwe-601"],
    "路径穿越": ["path traversal", "路径穿越", "cwe-22", "../"],
    "文件包含 LFI/RFI": ["local file inclusion", "remote file inclusion", "文件包含", "cwe-98"],
    "文件上传": ["file upload", "文件上传", "cwe-434", "multipart"],
    "反序列化": ["deserial", "反序列化", "cwe-502", "pickle", "readobject"],
    "XXE": ["xxe", "cwe-611", "resolve_entities", "external entity"],
    "硬编码凭证": ["hard-coded", "hardcoded", "硬编码", "cwe-798"],
    "弱随机数": ["weak random", "cwe-330", "math.random", "rand()", "random.random"],
    "弱哈希": ["md5", "sha1", "cwe-916", "cwe-327"],
    "加密强度/ECB/静态IV": ["cwe-326", "cwe-329", "ecb", "static iv"],
    "越权 IDOR": ["idor", "越权", "cwe-639", "cwe-284"],
    "认证绕过": ["auth bypass", "认证绕过", "cwe-287", "cwe-306"],
    "会话固定": ["session fixation", "会话固定", "cwe-384"],
    "JWT 问题": ["jwt", "cwe-347", "jsonwebtoken"],
    "日志注入": ["log injection", "日志注入", "cwe-117"],
    "信息泄露/报错": ["information exposure", "信息泄露", "cwe-209", "cwe-200", "stack trace"],
    "竞态 TOCTOU": ["toctou", "race condition", "竞态", "cwe-367", "cwe-362", "cwe-366"],
    "整数溢出": ["integer overflow", "整数溢出", "cwe-190", "cwe-680"],
    "缓冲区溢出": ["buffer overflow", "缓冲区溢出", "cwe-121", "cwe-122", "cwe-787", "cwe-120"],
    "UAF / 双重释放": ["use after free", "uaf", "cwe-416", "cwe-415", "double free"],
    "空指针解引用": ["null pointer", "空指针", "cwe-476"],
    "格式化字符串": ["format string", "格式化字符串", "cwe-134"],
    "ReDoS": ["redos", "cwe-1333", "catastrophic backtracking", "灾难性回溯"],
    "原型链污染": ["prototype pollution", "原型链", "cwe-1321", "__proto__"],
    "Mass Assignment": ["mass assignment", "cwe-915", "批量赋值"],
    "HTTP 响应头注入/CRLF": ["crlf", "header injection", "cwe-113", "cwe-93"],
    "HTTP 请求走私": ["request smuggling", "请求走私", "cwe-444", "transfer-encoding"],
    "点击劫持": ["clickjacking", "cwe-1021", "x-frame-options"],
    "缓存投毒/Web缓存欺骗": ["cache poisoning", "缓存投毒", "cwe-349", "web cache deception"],
    "DNS 重绑定/子域接管": ["dns rebinding", "subdomain takeover"],
    "依赖混淆/typosquatting": ["dependency confusion", "typosquat"],
    "不安全的 CORS": ["cors", "cwe-942", "access-control-allow-origin"],
    "CSP 缺失": ["content-security-policy", "csp"],
    "二阶/存储型注入": ["second-order", "二阶", "stored xss", "存储型"],
    "WebSocket 安全": ["websocket"],
    "GraphQL 安全": ["graphql"],
    "OAuth/OIDC 问题": ["oauth", "oidc", "openid"],
    "SAML 问题": ["saml"],
    "容器/编排安全": ["dockerfile", "kubernetes", "k8s", "cap_drop", "privileged"],
    "IaC/配置安全": ["terraform", "ansible", "cloudformation", "nginx.conf", "systemd"],
    "CI/CD 安全": ["gitlab-ci", "github actions", "jenkins", ".gitlab-ci"],
    "供应链/构建安全": ["supply chain", "供应链", "npm audit", "maven"],
    "侧信道/时序攻击": ["timing attack", "side channel", "cwe-208"],
    "业务逻辑/支付篡改": ["business logic", "业务逻辑", "price", "amount manipul"],
    "人工智能/LLM 相关": ["prompt injection", "llm", "model poisoning"],
}
res = []
for name, kws in VULN_TERMS.items():
    n = sum(TEXT_LOW.count(k) for k in kws)
    res.append((n, name, kws))
res.sort()
P("  —— 完全缺失或极少（<=5 次）——")
for n, name, kws in res:
    if n <= 5:
        P(f"    {name:24s}: {n:5d} 次   {kws}")
P("\n  —— 覆盖充足（>100 次）——")
for n, name, kws in reversed(res):
    if n > 100:
        P(f"    {name:24s}: {n:6d} 次")

# ---------- 2. 语言 / 框架 ----------
P("\n" + "=" * 78); P("[2] 语言与框架覆盖"); P("=" * 78)
LANGS = ["python","javascript","typescript","java","go","php","c","cpp","csharp","rust",
         "ruby","kotlin","swift","scala","bash","powershell","sql","html","yaml","dockerfile"]
for lg in LANGS:
    n = len(re.findall(r"语言[:：]\s*"+re.escape(lg)+r"\b", TEXT, re.I))
    n2 = len(re.findall(r"```\s*"+re.escape(lg)+r"\b", TEXT, re.I))
    P(f"    {lg:12s}: 语言标签 {n:5d}   代码围栏 {n2:5d}")

P("\n  框架关键词:")
FRAMES = ["flask","django","fastapi","spring","express","koa","nest","laravel","symfony",
          "rails","gin","echo","fiber","react","vue","angular","next.js","asp.net",
          "struts","jquery","axios","hibernate","mybatis","jinja","thymeleaf",
          "tornado","aiohttp","quart","sanic","play","ktor","phoenix","struts2"]
for f_ in FRAMES:
    n = TEXT_LOW.count(f_)
    P(f"    {f_:12s}: {n:5d}")

# ---------- 3. 代码形态 / 场景 ----------
P("\n" + "=" * 78); P("[3] 代码形态与场景覆盖"); P("=" * 78)
FORMS = {
    "多文件/跨文件": ["=== file", "多文件项目", "跨文件"],
    "类/面向对象": ["class "],
    "异步 async/await": ["async ", "await "],
    "装饰器/注解": ["@app.", "@Override", "@GetMapping", "@PostMapping", "@route"],
    "中间件": ["middleware", "app.use(", "@app.before_request"],
    "ORM": ["sqlalchemy", "django.db", "hibernate", "gorm", "entitymanager", "eloquent", "prisma"],
    "原始 SQL": ["execute(", "cursor.execute", "prepareStatement", "query("],
    "微服务/gRPC": ["grpc", "protobuf"],
    "消息队列": ["kafka", "rabbitmq", "celery", "sqs", "amqp"],
    "缓存": ["redis", "memcached"],
    "云原生/K8s": ["kubernetes", "kubectl", "deployment.yaml"],
    "WebAssembly": ["wasm"],
    "移动端": ["android", "ios ", "swiftui"],
    "嵌入式/IoT": ["arduino", "esp32", "embedded"],
    "区块链/合约": ["solidity", "smart contract", "web3"],
}
for k, kws in FORMS.items():
    n = sum(TEXT_LOW.count(x) for x in kws)
    P(f"    {k:16s}: {n:6d}")

# ---------- 4. 难度/对抗形态 ----------
P("\n" + "=" * 78); P("[4] 对抗与干扰形态覆盖"); P("=" * 78)
ADV = {
    "黑名单 vs 白名单对照": ["黑名单", "blacklist"],
    "看似安全实有漏洞": ["看似安全", "看起来安全", "实则", "实际上仍"],
    "看似危险实安全": ["看似危险", "看起来危险", "looks dangerous", "noise"],
    "多层防御": ["纵深防御", "多层", "defense in depth"],
    "第二入口/替代通道": ["第二入口", "替代通道", "另一条路由", "备用通道"],
    "不完整修复/部分防御": ["不完整", "部分防御", "修复不完整", "绕过"],
    "编码/双重编码绕过": ["双重编码", "double encoding", "url 编码", "unicode"],
    "大小写/截断绕过": ["大小写", "截断", "null byte", "%00"],
    "条件竞争": ["race", "竞态", "并发"],
    "上下文相关(框架自动防护)": ["框架自动", "自动转义", "autoescape", "automatic"],
}
for k, kws in ADV.items():
    n = sum(TEXT_LOW.count(x) for x in kws)
    P(f"    {k:24s}: {n:6d}")

w.close()
print("done")
