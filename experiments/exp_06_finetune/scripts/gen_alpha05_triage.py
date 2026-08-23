# -*- coding: utf-8 -*-
"""α0.5 架构适配样本生成器（两阶段裁决格式）。

当前双阶段架构（TwoStageScanner Stage2 裁决）的推理输入与扫描训练格式完全不同：
  - 输入：build_triage_prompt() 构造的「可疑数据流 + 行号代码切片」（封闭判别）
  - 输出：{"is_confirmed": true/false, "vulnerability_type", "reason", "fix_suggestion"}

本生成器复用 build_triage_prompt 构造与推理**字节级一致**的 user prompt，
生成 is_confirmed 格式的 assistant 输出，教模型：
  - 确认真漏洞（含纠正工具错误标注的类型）
  - 拒绝误报（防御有效 / 无用户输入 / helper 仅返回输入）

输出：data/supplement_alpha05_triage.jsonl
"""
import json, re, sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / "experiments" / "exp_06_finetune" / "data"
OUT = DATA / "supplement_alpha05_triage.jsonl"

sys.path.insert(0, str(ROOT))
from graduation_project.prompts import build_triage_prompt, get_eval_system_prompt

# triage 是封闭二分类裁决任务（is_confirmed schema），与主扫描（has_vulnerability）
# 任务不同，system prompt 用 triage 专属版，保证训练/推理一致、不与扫描任务混训。
SYSTEM = get_eval_system_prompt("triage_default")


def numbered(code, start=1):
    return "\n".join(f"{i}| {l}" for i, l in enumerate(code.split("\n"), start=start))


def finding(**kw):
    base = dict(rule_id="demo.rule", category="taint", source="", sink="",
                taint_type="Unknown", source_line=0, sink_line=0, path=[],
                severity="medium", tool="semgrep", evidence="")
    base.update(kw)
    return SimpleNamespace(**base)


def make_record(code: str, lang: str, user_prompt: str, analysis: str, verdict: dict) -> dict:
    asst_content = analysis + "\n\n```json\n" + json.dumps(verdict, ensure_ascii=False) + "\n```"
    return {
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": asst_content},
        ]
    }


records = []


def add(code, lang, fnd, analysis, verdict):
    ctx = numbered(code)
    user = build_triage_prompt(fnd, ctx, language=lang)
    records.append(make_record(code, lang, user, analysis, verdict))


# ============ 1. 真漏洞：确认 + 纠正工具类型 ============
add("""
from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM items WHERE name LIKE '%" + q + "%'")
    return str(cur.fetchall())
""", "python",
    finding(rule_id="python.lang.security.audit.django-sql-injection",
            source="request.args.get('q')", sink="cur.execute(query)",
            taint_type="SQL Injection", source_line=9, sink_line=13,
            path=["q", "query"], severity="high",
            evidence="semgrep: taint source -> sink"),
    "分析过程：\n1. source（line 9 request.args.get('q')）确为外部可控输入。\n"
    "2. sink（line 13 cur.execute）接收字符串拼接的 SQL，无参数化。\n"
    "3. source→sink 无有效防御，可注入。\n"
    "4. 确认该 finding 成立。",
    {"is_confirmed": True, "vulnerability_type": "CWE-89 SQL Injection",
     "reason": "用户可控 q 拼接进 SQL 且无参数化，可注入",
     "fix_suggestion": "line 13: 改用参数化查询 cur.execute('SELECT ... WHERE name LIKE ?', ('%'+q+'%',))"})


# ============ 2. 误报拒绝：SQL 拼接但为常量（noise） ============
add("""
import sqlite3

name = "admin"
query = "SELECT * FROM users WHERE name = '" + name + "'"
conn = sqlite3.connect("users.db")
cur = conn.cursor()
cur.execute(query)
print(cur.fetchone())
""", "python",
    finding(rule_id="python.lang.security.audit.django-sql-injection",
            source="name", sink="cur.execute(query)",
            taint_type="SQL Injection", source_line=4, sink_line=7,
            path=["name", "query"], severity="high",
            evidence="semgrep: string concatenation to execute"),
    "分析过程：\n1. 工具标注 source 为 `name`，但它是**硬编码常量**（line 4），非外部可控输入。\n"
    "2. 无用户可控输入流入 sink，无法利用。\n"
    "3. 该 finding 是模式匹配误报（无真实污染源）。",
    {"is_confirmed": False, "vulnerability_type": "none",
     "reason": "source 为硬编码常量，无用户可控输入，不可注入",
     "fix_suggestion": "no fix needed"})


# ============ 3. 跨文件：helper 仅返回输入 -> 拒绝 ============
add("""
# === file: helper.py ===
def get_user_input(request, param, default=""):
    return request.args.get(param, default)
""", "python",
    finding(rule_id="taint_tracker.source", category="taint",
            source="request.args.get(param, default)", sink="(return)",
            taint_type="Possible XSS", source_line=3, sink_line=3,
            path=[], severity="medium",
            evidence="helper 内 request.args.get 命中 source 规则"),
    "分析过程：\n1. 该文件是 helper：仅读取并返回输入，**没有危险 sink**。\n"
    "2. 工具把它标为 XSS source，但 source 本身不是漏洞——需调用方把返回值传入危险 sink 才成立。\n"
    "3. 该 finding 在 helper 内不成立（无 sink）。",
    {"is_confirmed": False, "vulnerability_type": "none",
     "reason": "helper 仅返回输入，无危险 sink，不构成漏洞",
     "fix_suggestion": "no fix needed"})


# ============ 4. 跨文件：输入经 helper 进 sink -> 确认 ============
add("""
# === file: api.py ===
from flask import Flask, request
from db_helper import run_query

app = Flask(__name__)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return run_query("SELECT * FROM items WHERE name LIKE '%" + q + "%'")
""", "python",
    finding(rule_id="taint_tracker.taint", category="taint",
            source="request.args.get('q')", sink="run_query(...)",
            taint_type="SQL Injection", source_line=11, sink_line=12,
            path=["q"], severity="high",
            evidence="跨文件：q 流入 db_helper.run_query 的字符串拼接"),
    "分析过程：\n1. source（line 11 request.args.get('q')）外部可控。\n"
    "2. 跨文件追踪：q 传入 db_helper.run_query，其内部字符串拼接进 SQL（helper 内无参数化）。\n"
    "3. 用户输入确实到达危险 sink → 该 finding 成立。",
    {"is_confirmed": True, "vulnerability_type": "CWE-89 SQL Injection",
     "reason": "q 经跨文件 helper 流入拼接 SQL，无参数化，可注入",
     "fix_suggestion": "db_helper.run_query 内改为参数化查询"})


# ============ 5. XXE：确认 ============
add("""
from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/parse", methods=["POST"])
def parse_xml():
    raw = request.get_data()
    parser = etree.XMLParser()
    root = etree.fromstring(raw, parser=parser)
    return etree.tostring(root, encoding="unicode")
""", "python",
    finding(rule_id="python.lang.security.audit.xml.xxe",
            source="request.get_data()", sink="etree.fromstring(raw)",
            taint_type="XXE (XML External Entity)", source_line=11, sink_line=12,
            path=["raw"], severity="high",
            evidence="不可信 XML 送入 lxml 解析器"),
    "分析过程：\n1. source（line 11 request.get_data()）为不可信 XML。\n"
    "2. sink（line 12 etree.fromstring）使用 lxml 默认解析器，**启用外部实体解析**。\n"
    "3. 可注入外部实体读本地文件/探测内网 → finding 成立。",
    {"is_confirmed": True, "vulnerability_type": "CWE-611 Improper Restriction of XML External Entity Reference",
     "reason": "不可信 XML 经 lxml 默认解析器，外部实体可展开，存在 XXE",
     "fix_suggestion": "line 12: 使用 defusedxml 或 XMLParser(resolve_entities=False, no_network=True)"})


# ============ 6. CSRF 绕过：确认 ============
add("""
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "dev_key"


@app.route("/change_email", methods=["POST"])
def change_email():
    if "user_id" not in session:
        return "Please login", 401
    referer = request.headers.get("Referer", "")
    if "example.com" not in referer:
        return "CSRF blocked", 403
    return "Email changed"
""", "python",
    finding(rule_id="python.flask.security.csrf-weak-referer",
            source="跨站请求", sink="change_email 修改操作",
            taint_type="CSRF", source_line=13, sink_line=14,
            path=[], severity="medium",
            evidence="Referer 仅做子串包含校验"),
    "分析过程：\n1. 修改邮箱操作仅用 Referer 子串包含校验（'example.com' in referer）。\n"
    "2. 攻击者可用 http://example.com.evil.com 或注入 ? 绕过，或发无 Referer 请求。\n"
    "3. 弱同源校验 → finding 成立（CSRF）。",
    {"is_confirmed": True, "vulnerability_type": "CWE-352 Cross-Site Request Forgery (CSRF)",
     "reason": "Referer 子串包含校验可被前缀/参数绕过，存在 CSRF",
     "fix_suggestion": "line 14: 使用会话绑定 CSRF token + Origin 精确全等校验"})


# ============ 7. 工具类型纠正：工具标 XSS，实为认证缺失 ============
add("""
from flask import Flask, request

app = Flask(__name__)


@app.route("/admin/delete_user", methods=["POST"])
def delete_user():
    user_id = request.args.get("user_id")
    return f"User {user_id} deleted"
""", "python",
    finding(rule_id="python.lang.security.audit.xss-reflected",
            source="request.args.get('user_id')", sink="f-string 响应",
            taint_type="XSS", source_line=10, sink_line=11,
            path=["user_id"], severity="high",
            evidence="用户输入进入响应字符串"),
    "分析过程：\n1. 工具标注 XSS，但响应只是回显字符串（`User {user_id} deleted`），未进入 HTML 脚本执行上下文，XSS 不成立。\n"
    "2. **真正缺陷**：`delete_user()` 执行删除操作但**没有任何身份认证**——匿名请求即可删除任意用户。\n"
    "3. 应纠正类型为认证缺失，并确认该漏洞成立。",
    {"is_confirmed": True, "vulnerability_type": "CWE-306 Missing Authentication for Critical Function",
     "reason": "工具误标 XSS；实为敏感操作无身份认证，匿名可删除任意用户",
     "fix_suggestion": "line 9: 加登录校验（@login_required）"})


# ============ 8. 参数化防护：拒绝（防御有效） ============
add("""
from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return str(cur.fetchone())
""", "python",
    finding(rule_id="python.lang.security.audit.django-sql-injection",
            source="request.args.get('id')", sink="cur.execute(...)",
            taint_type="SQL Injection", source_line=9, sink_line=12,
            path=["uid"], severity="high",
            evidence="execute 命中参数化扫描规则"),
    "分析过程：\n1. sink（line 12 cur.execute）使用**占位符 ? + 参数元组**，是参数化查询。\n"
    "2. source→sink 有有效防御，数据库驱动自动转义。\n"
    "3. 该 finding 是误报（防御有效）。",
    {"is_confirmed": False, "vulnerability_type": "none",
     "reason": "参数化查询已正确防护，无注入",
     "fix_suggestion": "no fix needed"})


# ============ 9. 硬编码凭证：确认 798 ============
add("""
from flask import Flask

app = Flask(__name__)

API_KEY = "sk_live_9f8e7d6c5b4a3210"
""", "python",
    finding(rule_id="gitleaks.apikey", category="sast",
            source="(常量)", sink="API_KEY = 'sk_live_...'",
            taint_type="Hardcoded Secret", source_line=5, sink_line=5,
            path=[], severity="high", tool="gitleaks",
            evidence="字面量 API Key 命中密钥检测规则"),
    "分析过程：\n1. line 5: 源码含字面量 API Key（sk_live_ 前缀）。\n"
    "2. 硬编码凭证本身就是漏洞（无论是否被使用）。\n"
    "3. 该 finding 成立。",
    {"is_confirmed": True, "vulnerability_type": "CWE-798 Use of Hard-coded Credentials",
     "reason": "源码含字面量 API Key，泄露即被滥用",
     "fix_suggestion": "line 5: 从环境变量/KMS 读取凭证"})


# ============ 10. 命令注入 shell=True：确认 ============
add("""
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout
""", "python",
    finding(rule_id="python.lang.security.audit.subprocess-shell-true",
            source="request.args.get('host')", sink="subprocess.run(...shell=True)",
            taint_type="Command Injection", source_line=10, sink_line=11,
            path=["host"], severity="high",
            evidence="shell=True + f-string 拼接"),
    "分析过程：\n1. source（line 10 host）外部可控。\n"
    "2. sink（line 11 subprocess.run shell=True + f-string 拼接）。\n"
    "3. host 可含 ; | $() 元字符 → finding 成立。",
    {"is_confirmed": True, "vulnerability_type": "CWE-78 OS Command Injection",
     "reason": "用户可控 host 在 shell=True 下拼接执行，可注入命令",
     "fix_suggestion": "line 11: subprocess.run(['ping','-c','1',host], shell=False)"})


# ============ 11. shell=True 但常量：拒绝 ============
add("""
import subprocess

result = subprocess.run("echo 'hello world'", shell=True, capture_output=True)
print(result.stdout.decode())
""", "python",
    finding(rule_id="python.lang.security.audit.subprocess-shell-true",
            source="(硬编码字符串)", sink="subprocess.run('echo ...', shell=True)",
            taint_type="Command Injection", source_line=3, sink_line=3,
            path=[], severity="high",
            evidence="subprocess 使用 shell=True"),
    "分析过程：\n1. sink（line 3 subprocess.run shell=True）确实存在，但命令是**硬编码字面量**。\n"
    "2. 无用户可控输入流入命令，无法注入。\n"
    "3. 该 finding 是误报（危险函数但不可利用）。",
    {"is_confirmed": False, "vulnerability_type": "none",
     "reason": "命令为硬编码常量，无用户输入，不可注入",
     "fix_suggestion": "no fix needed"})


# ============ 12. IDOR：确认 639 ============
add("""
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "dev_key"


@app.route("/order")
def view_order():
    if "user_id" not in session:
        return "Please login", 401
    order_id = request.args.get("order_id")
    return f"Order detail for {order_id}"
""", "python",
    finding(rule_id="python.flask.security.idor", category="sast",
            source="request.args.get('order_id')", sink="未校验属主直接返回",
            taint_type="IDOR", source_line=12, sink_line=13,
            path=[], severity="high",
            evidence="已登录但未校验资源属主"),
    "分析过程：\n1. line 12: 仅校验登录，line 13: 直接按 order_id 返回数据，未校验是否属于当前用户。\n"
    "2. 攻击者可枚举他人订单 ID 越权访问。\n"
    "3. finding 成立，类型为 IDOR。",
    {"is_confirmed": True, "vulnerability_type": "CWE-639 Authorization Bypass Through User-Controlled Key",
     "reason": "登录校验存在但未校验资源属主，可越权读取他人订单",
     "fix_suggestion": "line 13: 查询前校验 order.owner_id == session['user_id']"})


# ============ 13. SSRF：确认 918 ============
add("""
from flask import Flask, request
import requests

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    return requests.get(url, timeout=5).text
""", "python",
    finding(rule_id="python.lang.security.audit.ssrf",
            source="request.args.get('url')", sink="requests.get(url)",
            taint_type="SSRF", source_line=9, sink_line=10,
            path=["url"], severity="high",
            evidence="用户 URL 直接服务端请求"),
    "分析过程：\n1. source（line 9 url）外部可控 URL。\n"
    "2. sink（line 10 requests.get(url)）服务端发起请求，无协议/主机白名单。\n"
    "3. 可访问内网/元数据端点 → finding 成立。",
    {"is_confirmed": True, "vulnerability_type": "CWE-918 Server-Side Request Forgery",
     "reason": "用户可控 URL 直接服务端请求，可访问内网/元数据",
     "fix_suggestion": "line 10: URL 协议/主机白名单，禁止内网网段"})


# ============ 14. 路径穿越：确认 22 ============
add("""
from flask import Flask, request

app = Flask(__name__)


@app.route("/download")
def download():
    name = request.args.get("name", "")
    return open("/srv/" + name, "r").read()
""", "python",
    finding(rule_id="python.lang.security.audit.path-traversal",
            source="request.args.get('name')", sink="open('/srv/' + name)",
            taint_type="Path Traversal", source_line=9, sink_line=10,
            path=["name"], severity="high",
            evidence="用户输入拼接文件路径"),
    "分析过程：\n1. source（line 9 name）外部可控。\n"
    "2. sink（line 10 open('/srv/' + name)）无路径白名单，../ 可逃逸 /srv。\n"
    "3. finding 成立。",
    {"is_confirmed": True, "vulnerability_type": "CWE-22 Path Traversal",
     "reason": "name 拼接 open 且无路径校验，../ 可读取任意文件",
     "fix_suggestion": "line 10: os.path.realpath + startswith('/srv/') 白名单"})


# ============ 15. pickle 反序列化：确认 502 ============
add("""
import pickle
from flask import Flask, request

app = Flask(__name__)


@app.route("/restore", methods=["POST"])
def restore():
    raw = request.get_data()
    return pickle.loads(raw)
""", "python",
    finding(rule_id="python.lang.security.audit.pickle-unsafe",
            source="request.get_data()", sink="pickle.loads(raw)",
            taint_type="Insecure Deserialization", source_line=9, sink_line=10,
            path=["raw"], severity="high",
            evidence="不可信输入直接 pickle.loads"),
    "分析过程：\n1. source（line 9 raw）不可信请求体。\n"
    "2. sink（line 10 pickle.loads(raw)）反序列化可执行任意代码。\n"
    "3. finding 成立（RCE）。",
    {"is_confirmed": True, "vulnerability_type": "CWE-502 Deserialization of Untrusted Data",
     "reason": "不可信数据直接 pickle.loads，可构造 __reduce__ 触发 RCE",
     "fix_suggestion": "line 10: 改用 json 等安全格式，禁止反序列化不可信数据"})


# ============ 16. 弱随机：确认 330 ============
add("""
from flask import Flask
import random
import string

app = Flask(__name__)


@app.route("/reset_token")
def reset_token():
    token = "".join(random.choices(string.ascii_letters + string.digits, k=32))
    return token
""", "python",
    finding(rule_id="python.lang.security.audit.weak-random", category="sast",
            source="(无 source 型)", sink="random.choices 生成 token",
            taint_type="Weak Randomness", source_line=9, sink_line=9,
            path=[], severity="medium", tool="bandit",
            evidence="random 模块生成密码重置 token"),
    "分析过程：\n1. line 9: 用 random.choices（Mersenne Twister，可预测）生成密码重置 token。\n"
    "2. 无 source 依赖（弱随机是代码固有缺陷），仍需单独检查。\n"
    "3. token 可被预测 → finding 成立。",
    {"is_confirmed": True, "vulnerability_type": "CWE-330 Use of Insufficiently Random Values",
     "reason": "random 伪随机生成重置 token，可被预测",
     "fix_suggestion": "line 9: 改用 secrets.token_urlsafe(32)"})


# ============ 17. 整数溢出：确认 190（Java） ============
add("""
import org.springframework.web.bind.annotation.*;

@RestController
public class CheckoutController {

    @GetMapping("/checkout")
    public long calc(@RequestParam int price, @RequestParam int qty) {
        int total = price * qty;
        return total;
    }
}
""", "java",
    finding(rule_id="java.lang.security.audit.integer-overflow", category="sast",
            source="@RequestParam int price/qty", sink="int total = price * qty",
            taint_type="Integer Overflow", source_line=7, sink_line=8,
            path=[], severity="medium", tool="semgrep",
            evidence="int 乘法无范围校验"),
    "分析过程：\n1. line 7: price/qty 为用户可控 int。\n"
    "2. line 8: `int total = price * qty` 32 位乘法可溢出，绕过金额上限校验。\n"
    "3. 无范围校验 → finding 成立。",
    {"is_confirmed": True, "vulnerability_type": "CWE-190 Integer Overflow or Wraparound",
     "reason": "用户可控 int 相乘可 32 位溢出，绕过金额上限",
     "fix_suggestion": "line 8: 用 long/BigInteger 或乘法前范围校验"})


# ============ 18. 日志注入：确认 117 ============
add("""
import logging
from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("user", "")
    logger.info("login: " + user)
    return "ok"
""", "python",
    finding(rule_id="python.lang.security.audit.log-injection",
            source="request.form.get('user')", sink="logger.info('login: ' + user)",
            taint_type="Log Injection", source_line=9, sink_line=10,
            path=["user"], severity="medium",
            evidence="用户输入拼接进日志"),
    "分析过程：\n1. source（line 9 user）外部可控。\n"
    "2. sink（line 10 logger.info 拼接）未净化 \\r\\n，可伪造日志条目。\n"
    "3. 无占位符之外更严重的格式串注入，但日志注入成立 → finding 确认。",
    {"is_confirmed": True, "vulnerability_type": "CWE-117 Improper Output Neutralization for Logs",
     "reason": "user 拼接进日志未过滤换行，可伪造审计日志",
     "fix_suggestion": "line 10: 日志前过滤 \\r\\n 或结构化日志"})


# ============ 19. 拒绝：subprocess 列表参数（无 shell） ============
add("""
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, timeout=5)
    return result.stdout
""", "python",
    finding(rule_id="python.lang.security.audit.subprocess-shell-true",
            source="request.args.get('host')", sink="subprocess.run([...], host)",
            taint_type="Command Injection", source_line=9, sink_line=10,
            path=["host"], severity="high",
            evidence="subprocess 命中命令执行规则"),
    "分析过程：\n1. sink（line 10）是**列表参数**形式（无 shell=True），不经 shell 解释。\n"
    "2. 即使 host 含元字符也不会被 shell 执行 → 无命令注入。\n"
    "3. 该 finding 是误报（危险函数但无 shell 语义）。",
    {"is_confirmed": False, "vulnerability_type": "none",
     "reason": "列表参数 + 无 shell=True，不经 shell 解释，不可注入",
     "fix_suggestion": "no fix needed"})


# ============ 20. 拒绝：路径白名单（abspath+startswith 有效） ============
add("""
import os
from flask import Flask, request

app = Flask(__name__)
BASE_DIR = "/var/data"


@app.route("/read")
def read_file():
    fname = request.args.get("name", "")
    full = os.path.abspath(os.path.join(BASE_DIR, fname))
    if full.startswith(BASE_DIR):
        return open(full, "r").read()
    return "forbidden"
""", "python",
    finding(rule_id="python.lang.security.audit.path-traversal",
            source="request.args.get('name')", sink="open(full)",
            taint_type="Path Traversal", source_line=9, sink_line=12,
            path=["fname"], severity="high",
            evidence="用户输入到达 open()"),
    "分析过程：\n1. line 10: os.path.abspath 归一化路径，line 11: startswith(BASE_DIR) 校验前缀。\n"
    "2. ../ 归一化后无法逃逸 BASE_DIR → 防御有效。\n"
    "3. 该 finding 是误报（有有效路径校验）。",
    {"is_confirmed": False, "vulnerability_type": "none",
     "reason": "abspath + startswith 白名单校验有效，../ 无法逃逸",
     "fix_suggestion": "no fix needed"})


# ============ 21. 拒绝：XSS 已转义（html.escape） ============
add("""
from flask import Flask, request
import html

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return "<p>" + html.escape(name) + "</p>"
""", "python",
    finding(rule_id="python.lang.security.audit.xss-reflected",
            source="request.args.get('name')", sink="f-string 响应",
            taint_type="XSS", source_line=7, sink_line=8,
            path=["name"], severity="high",
            evidence="用户输入进入响应字符串"),
    "分析过程：\n1. sink（line 8）用 html.escape(name) 转义后插入 HTML。\n"
    "2. 特殊字符被转义，无法形成脚本执行上下文 → 防御有效。\n"
    "3. 该 finding 是误报。",
    {"is_confirmed": False, "vulnerability_type": "none",
     "reason": "html.escape 已转义输出，无法注入脚本",
     "fix_suggestion": "no fix needed"})


# ============ 22. 拒绝：误导注释（实际参数化） ============
add("""
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # WARNING: this query is injectable!（实际是参数化）
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM items WHERE name LIKE ?", ("%" + q + "%",))
    return str(cur.fetchall())
""", "python",
    finding(rule_id="python.lang.security.audit.django-sql-injection",
            source="request.args.get('q')", sink="cur.execute(...)",
            taint_type="SQL Injection", source_line=9, sink_line=12,
            path=["q"], severity="high",
            evidence="注释声称可注入 + execute 命中规则"),
    "分析过程：\n1. line 12: execute 使用**占位符 ? + 参数元组**，是参数化查询。\n"
    "2. line 10 的注释是误导性的，不能作为漏洞证据——判定须基于代码实际语义。\n"
    "3. 该 finding 是误报（参数化已防护）。",
    {"is_confirmed": False, "vulnerability_type": "none",
     "reason": "查询实为参数化，注释误导；无注入",
     "fix_suggestion": "no fix needed"})


# ============ 23. 拒绝：source 为常量赋值（非用户输入） ============
add("""
from flask import Flask
import sqlite3

app = Flask(__name__)


@app.route("/stats")
def stats():
    q = "SELECT COUNT(*) FROM users"   # 常量，非用户输入
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(q)
    return str(cur.fetchone())
""", "python",
    finding(rule_id="python.lang.security.audit.django-sql-injection",
            source="q", sink="cur.execute(q)",
            taint_type="SQL Injection", source_line=9, sink_line=11,
            path=["q"], severity="high",
            evidence="execute 拼接命中规则"),
    "分析过程：\n1. 工具把 `q` 标为 source，但它（line 9）是**硬编码常量字符串**，无任何用户输入链。\n"
    "2. source 非用户可控 → 无污染源 → 不可利用。\n"
    "3. 该 finding 是误报。",
    {"is_confirmed": False, "vulnerability_type": "none",
     "reason": "source 为硬编码常量，无用户可控输入，不可注入",
     "fix_suggestion": "no fix needed"})


# ============ 24. SSTI：确认 1336 ============
add("""
from flask import Flask, request
from jinja2 import Environment

app = Flask(__name__)
env = Environment()


@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    tpl = env.from_string("<h1>Hello " + name + "</h1>")
    return tpl.render()
""", "python",
    finding(rule_id="python.lang.security.audit.ssti",
            source="request.args.get('name')", sink="env.from_string(...)",
            taint_type="SSTI", source_line=9, sink_line=10,
            path=["name"], severity="high",
            evidence="用户输入拼接到模板字符串并 from_string 渲染"),
    "分析过程：\n1. source（line 9 name）外部可控。\n"
    "2. sink（line 10 env.from_string 拼接 + line 11 render）把用户输入当模板表达式求值。\n"
    "3. 可注入 {{...}} 表达式 → RCE → finding 成立。",
    {"is_confirmed": True, "vulnerability_type": "CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine",
     "reason": "name 拼进模板字符串并 from_string 渲染，可注入模板表达式",
     "fix_suggestion": "line 10: 模板字符串固定，name 作为 render(name=name) 变量注入"})


with OUT.open("w", encoding="utf-8") as fh:
    for rec in records:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"生成 {len(records)} 条架构适配（triage）样本 -> {OUT}")

from collections import Counter
c = Counter()
for rec in records:
    jm = re.search(r"```json\s*(\{.*?\})\s*```", rec["messages"][2]["content"], re.S)
    if jm:
        v = json.loads(jm.group(1))
        c[(v["is_confirmed"], v["vulnerability_type"][:12])] += 1
print("分布:", dict(c))
