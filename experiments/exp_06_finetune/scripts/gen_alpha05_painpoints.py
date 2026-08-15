# -*- coding: utf-8 -*-
"""α0.5 痛点补充样本生成器（结构化 FN/FP 类）。

针对 α0 实测真实痛点（不再按猜测的"误报 CWE"前提）：
  1. 跨文件/helper 判别（FN: 输入经 helper 进 sink 被漏报；FP: helper 本身被误报）
  2. noise 干扰项（FP: 危险 sink + 硬编码常量，模型误判为漏洞）
  3. XXE（FN: lxml/Java/PHP 解析不可信 XML，模型漏报）
  4. CSRF 同源/Referer 绕过（FN: 弱同源校验被当安全）

每条样本：正例（真漏洞）+ 对照（安全），含"干扰项排除"论证。
输出：data/supplement_alpha05_painpoints.jsonl
"""
import json, re, sys
from pathlib import Path

ROOT = Path(r"D:\code\毕业设计\Graduation-Project")
DATA = ROOT / "experiments" / "exp_06_finetune" / "data"
OUT = DATA / "supplement_alpha05_painpoints.jsonl"

try:
    sys.path.insert(0, str(ROOT))
    from graduation_project.prompts import ALPHA05_PROMPT
    SYSTEM = ALPHA05_PROMPT
except Exception:
    SYSTEM = "你是一名安全研究员，负责分析给定代码是否存在安全漏洞。"


def make_record(code: str, lang: str, analysis: str, verdict: dict) -> dict:
    user_content = (
        f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```\n\n"
        "请先给出分析过程，然后在最后给出 JSON 结论。"
    )
    asst_content = analysis + "\n\n```json\n" + json.dumps(verdict, ensure_ascii=False) + "\n```"
    return {
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": asst_content},
        ]
    }


def ln(code, marker):
    for i, l in enumerate(code.splitlines(), 1):
        if marker in l:
            return i
    return 1


records = []

# ============================================================
# 1. 跨文件 / helper 判别
# ============================================================
def gen_crossfile():
    # ---- 正例（FN 型）：输入经 helper 进 sink，未校验 ----
    pos = [
        ("""
# === file: storage.py ===
import os

def read_path(base_dir, filename):
    return os.path.join(base_dir, filename)
""", "python", "read_path", "路径穿越"),
        ("""
# === file: api.py ===
from flask import Flask, request
from db_helper import run_query

app = Flask(__name__)


@app.route("/search")
def search():
    keyword = request.args.get("q", "")
    return run_query("SELECT * FROM items WHERE name LIKE '%" + keyword + "%'")
""", "python", "search", "SQL 注入（helper 执行拼接 SQL）"),
        ("""
# === file: shell.py ===
import subprocess

def exec_cmd(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True).stdout
""", "python", "exec_cmd", "命令注入（shell=True 拼接）"),
        ("""
# === file: api.py ===
from flask import Flask, request
from shell import exec_cmd

app = Flask(__name__)


@app.route("/resolve")
def resolve():
    domain = request.args.get("domain", "")
    return exec_cmd("nslookup " + domain)
""", "python", "resolve", "命令注入（domain 进 helper 的 shell 拼接）"),
        ("""
# === file: net.py ===
import requests

def fetch(url):
    return requests.get(url, timeout=5).text
""", "python", "fetch", "SSRF（helper 请求用户 URL）"),
        ("""
# === file: api.py ===
from flask import Flask, request
from net import fetch

app = Flask(__name__)


@app.route("/proxy")
def proxy():
    target = request.args.get("url", "")
    return fetch(target)
""", "python", "proxy", "SSRF（url 进 helper 的 requests.get）"),
        ("""
# === file: ldap.py ===
def ldap_search(base_dn, query):
    conn = ldap.initialize("ldap://internal:389")
    return conn.search_s(base_dn, ldap.SCOPE_SUBTREE, query)
""", "python", "ldap_search", "LDAP 注入（helper 拼接过滤器）"),
        ("""
# === file: api.py ===
from flask import Flask, request
from ldap import ldap_search

app = Flask(__name__)


@app.route("/users")
def users():
    name = request.args.get("name", "")
    return ldap_search("ou=people,dc=x", "(cn=" + name + ")")
""", "python", "users", "LDAP 注入（name 进 helper 的过滤器拼接）"),
        ("""
# === file: store.py ===
def save_upload(upload_dir, filename, content):
    with open(upload_dir + "/" + filename, "wb") as f:
        f.write(content)
""", "python", "save_upload", "路径穿越（helper 拼接文件名）"),
        ("""
# === file: api.py ===
from flask import Flask, request
from store import save_upload

app = Flask(__name__)


@app.route("/upload")
def upload():
    filename = request.args.get("name", "")
    save_upload("/var/uploads", filename, request.get_data())
    return "ok"
""", "python", "upload", "路径穿越（filename 进 helper 的文件路径拼接）"),
    ]
    # 正例 CWE（按 fn 名显式标注，避免派生逻辑误判）
    POS_CWE = {
        "read_path": "CWE-22 Path Traversal",
        "search": "CWE-89 SQL Injection",
        "exec_cmd": "CWE-78 OS Command Injection",
        "ping": "CWE-78 OS Command Injection",
        "fetch": "CWE-918 Server-Side Request Forgery (SSRF)",
        "proxy": "CWE-918 Server-Side Request Forgery (SSRF)",
        "ldap_search": "CWE-90 Improper Neutralization of Special Elements in an LDAP Query",
        "users": "CWE-90 Improper Neutralization of Special Elements in an LDAP Query",
        "save_upload": "CWE-22 Path Traversal",
        "upload": "CWE-22 Path Traversal",
    }
    for code, lang, fn, flaw in pos:
        sink_ln = ln(code, "execute") or ln(code, "subprocess.run") or ln(code, "os.path.join") or ln(code, "os.system") or ln(code, "requests.get") or ln(code, "search_s") or ln(code, "open(")
        src_ln = ln(code, "request.") or ln(code, "args.get")
        analysis = (
            f"分析过程：\n"
            f"1. line {src_ln}: `request` 参数（用户可控）作为输入。\n"
            f"2. 数据流：外部输入 → 传入跨文件 helper → helper 内到达危险 sink"
            f"（execute/subprocess.run(shell=True)/open 路径拼接/requests.get/search_s）。\n"
            f"3. 防御检查：source→sink 之间**没有任何校验/参数化**，危险调用直接使用用户输入。\n"
            f"4. 干扰项排除：helper 文件本身可能看起来安全（没有 request），但**跨文件追踪后**"
            f"用户输入确实流入了危险 sink——这是真实漏洞，不能因为「输入在别的文件」就漏报。\n"
            f"5. 结论：{flaw}，风险 High。"
        )
        verdict = {
            "has_vulnerability": True,
            "vulnerability_type": POS_CWE.get(fn, "CWE-79 Cross-site Scripting (XSS)"),
            "risk_level": "High",
            "source": f"line {src_ln}: request 参数（用户可控）",
            "sink": f"line {sink_ln}: helper 内危险调用未校验",
            "explanation": f"外部输入 -> 跨文件 helper -> 危险 sink（{flaw}）",
            "fix_suggestion": f"line {sink_ln}: 在 sink 前参数化/校验/白名单，禁止直接使用用户输入",
        }
        records.append(make_record(code, lang, analysis, verdict))

    # ---- 反例（FP 型）：helper 只返回输入 / 安全查找，本身安全 ----
    neg = [
        ("""
# === file: params.py ===
class ParamSource:
    # 请求参数读取器（helper：只取输入，不含任何 sink）
    def __init__(self, request):
        self._req = request

    def get(self, name, default=""):
        return self._req.args.get(name, default)

    def form(self, field, default=""):
        return self._req.form.get(field, default)
""", "python", "ParamSource", "helper 只读取并返回输入，无危险 sink"),
        ("""
# === file: user_dao.py ===
def get_user_by_id(user_id):
    return {"id": user_id, "name": "user_" + str(user_id)}
""", "python", "get_user_by_id", "数据访问 helper，只构造返回字典"),
        ("""
# === file: db.py ===
import sqlite3

def query_param(sql, args):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(sql, args)
    return cur.fetchall()
""", "python", "query_param", "helper 内部使用参数化查询"),
        ("""
# === file: io.py ===
import os

def read_whitelisted(base_dir, filename):
    allowed = {"a.txt", "b.txt", "c.txt"}
    if filename not in allowed:
        return None
    with open(os.path.join(base_dir, filename), "r") as f:
        return f.read()
""", "python", "read_whitelisted", "helper 内含白名单校验"),
        ("""
# === file: settings.py ===
def get_timeout():
    return 30


def get_max_retries():
    return 3
""", "python", "get_timeout", "helper 返回配置常量，无外部输入"),
        ("""
# === file: deser.py ===
import json

def parse_payload(raw):
    return json.loads(raw)
""", "python", "parse_payload", "helper 用 json.loads 安全反序列化"),
        ("""
# === file: cmdsafe.py ===
import subprocess, shlex

def run_safe(cmd, *args):
    return subprocess.run([cmd] + list(args), shell=False)
""", "python", "run_safe", "helper 用列表参数 + shell=False，安全"),
    ]
    for code, lang, fn, reason in neg:
        analysis = (
            f"分析过程：\n"
            f"1. 该文件是 **helper 工具模块**：只负责读取/返回输入、构造数据或执行已带防御的操作。\n"
            f"2. 数据流：`{fn}()` 内部**没有用户可控输入到达危险 sink 的路径**"
            f"（要么只返回输入、要么在 sink 前已参数化/白名单校验）。\n"
            f"3. 干扰项排除：函数名/参数可能让人联想到漏洞（如 `get_user_input`、`query_param`），"
            f"但**helper 本身不是漏洞**——它没有不可信的 source→sink 链。漏洞应出现在调用方"
            f"把未校验输入传入危险 sink 的地方。\n"
            f"4. 结论：无漏洞，has_vulnerability=false（{reason}）。"
        )
        verdict = {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": f"helper 仅返回输入/已防御，无 source→sink 漏洞链（{reason}）",
            "fix_suggestion": "no fix needed",
        }
        records.append(make_record(code, lang, analysis, verdict))


# ============================================================
# 2. noise 干扰项（危险 sink + 硬编码常量 = 安全）
# ============================================================
def gen_noise():
    neg = [
        ("""
import sqlite3


def fetch_admin():
    # 查询固定账号，name 为硬编码常量，无任何外部输入
    name = "admin"
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchone()
""", "python", "cur.execute", "SQL 拼接但 name 是硬编码常量", "CWE-89 SQL Injection"),
        ("""
import subprocess


def cleanup_temp():
    # 定时清理脚本：命令为硬编码字符串，无任何外部输入
    return subprocess.run("rm -rf /var/tmp/scratch && touch /var/tmp/clean", shell=True)
""", "python", "subprocess.run", "shell=True 但命令是硬编码字符串", "CWE-78 OS Command Injection"),
        ("""
import os

os.system("df -h /var/log")
""", "python", "os.system", "os.system 但参数是常量", "CWE-78 OS Command Injection"),
        ("""
def render_welcome():
    # 欢迎页：html 为静态模板拼接，无用户输入进入
    html = "<h1>Welcome back!</h1><p>Your session is active.</p>"
    return html.replace("Welcome", "Hello")
""", "python", "replace", "字符串拼接/替换但无用户输入", "CWE-79 Cross-site Scripting (XSS)"),
        ("""
import pickle

data = b"\\x80\\x05\\x95\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
obj = pickle.loads(data)
""", "python", "pickle.loads", "反序列化但输入是硬编码字节", "CWE-502 Deserialization of Untrusted Data"),
        ("""
import yaml

config = yaml.load("key: value", Loader=yaml.Loader)
""", "python", "yaml.load", "yaml.load 但内容是硬编码字符串", "CWE-502 Deserialization of Untrusted Data"),
        ("""
import os

os.remove("/var/tmp/old_backup.tmp")
""", "python", "os.remove", "删除固定路径文件，路径无用户输入", "CWE-22 Path Traversal"),
        ("""
from flask import Flask, request
import ldap

app = Flask(__name__)

filter_str = "(cn=admin)"
conn = ldap.initialize("ldap://internal:389")
conn.search_s("ou=people,dc=x", ldap.SCOPE_SUBTREE, filter_str)
""", "python", "search_s", "LDAP 过滤器是常量，无用户输入", "CWE-90 LDAP Injection"),
        ("""
from flask import Flask, request

app = Flask(__name__)

TARGET = "https://internal.example.com/api"
""", "python", "TARGET", "常量 URL，无用户输入", "CWE-918 SSRF"),
        ("""
import os
import subprocess


class RepoOps:
    # 仓库工具：所有命令都用列表参数 + shell=False，不经过 shell 解释
    def __init__(self, workdir):
        self._wd = workdir

    def current_branch(self):
        return subprocess.Popen(
            ["git", "symbolic-ref", "--short", "HEAD"],
            cwd=self._wd, shell=False,
            stdout=subprocess.PIPE,
        ).communicate()[0]

    def latest_commit(self):
        return subprocess.run(
            ["git", "log", "-1", "--oneline"],
            cwd=self._wd, shell=False, capture_output=True,
        ).stdout

    def is_clean(self):
        proc = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=self._wd, shell=False, capture_output=True,
        )
        return proc.stdout.strip() == b""
""", "python", "subprocess.Popen", "列表参数 + shell=False，即使命令拼接也不可注入", "CWE-78 OS Command Injection"),
    ]
    for code, lang, marker, reason, false_cwe in neg:
        sink_ln = ln(code, marker)
        analysis = (
            f"分析过程：\n"
            f"1. line {sink_ln}: 确实调用了危险 sink（`{marker}()`），且看起来像{false_cwe}。\n"
            f"2. **关键判断**：流入 sink 的数据是**硬编码常量/字面量**，不是任何用户可控输入"
            f"（没有 request/参数/文件/环境变量流入）。攻击者无法控制该数据。\n"
            f"3. 结论：危险函数 ≠ 漏洞。**没有用户可控输入到达 sink，无法利用**，"
            f"应判 has_vulnerability=false。\n"
            f"4. 干扰项排除：不要因为看到 `{marker}()` + 拼接/shell 就报{false_cwe}；"
            f"必须确认污染源（source）存在且可控（{reason}）。"
        )
        verdict = {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": f"line {sink_ln}: {marker}()（但输入为常量，不可控）",
            "explanation": f"危险 sink 存在但无用户可控输入流入，不可利用（{reason}）",
            "fix_suggestion": "no fix needed",
        }
        records.append(make_record(code, lang, analysis, verdict))

    # 对照正例：同一 sink + 用户输入 = 漏洞
    pos = [
        ("""
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    name = request.args.get("name", "")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute(query)
    return str(cur.fetchone())
""", "python", "cur.execute", "CWE-89", "SQL 注入"),
        ("""
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/backup")
def backup():
    dir_name = request.args.get("dir", "")
    script = "tar czf /backup/out.tar " + dir_name
    result = subprocess.run(script, shell=True, capture_output=True)
    return result.stdout
""", "python", "subprocess.run", "CWE-78", "命令注入"),
        ("""
import pickle
from flask import Flask, request

app = Flask(__name__)


@app.route("/load")
def load():
    data = request.get_data()
    obj = pickle.loads(data)
    return "ok"
""", "python", "pickle.loads", "CWE-502", "反序列化"),
    ]
    for code, lang, marker, cwe, flaw in pos:
        src_ln = ln(code, "request.")
        sink_ln = ln(code, marker)
        analysis = (
            f"分析过程：\n"
            f"1. line {src_ln}: `request` 参数/请求体（用户可控）作为 source。\n"
            f"2. line {sink_ln}: 用户输入**直接流入危险 sink** `{marker}()`，且无任何校验/参数化。\n"
            f"3. 与\"常量\"场景的关键区别：这里是**用户可控输入**，攻击者可构造恶意数据触发漏洞。\n"
            f"4. 结论：{cwe} {flaw}，风险 High（{flaw}）。"
        )
        verdict = {
            "has_vulnerability": True,
            "vulnerability_type": cwe,
            "risk_level": "High",
            "source": f"line {src_ln}: request 用户可控输入",
            "sink": f"line {sink_ln}: {marker}() 使用未校验用户输入",
            "explanation": f"request 输入 -> {marker}() 无防御 -> {flaw}",
            "fix_suggestion": f"line {sink_ln}: 参数化/白名单/禁用危险函数",
        }
        records.append(make_record(code, lang, analysis, verdict))


# ============================================================
# 3. XXE（FN）
# ============================================================
def gen_xxe():
    pos = [
        ("""
from flask import Flask, request
from lxml import etree
import io

app = Flask(__name__)


@app.route("/import_catalog", methods=["POST"])
def import_catalog():
    payload = request.data
    parser = etree.XMLParser(load_dtd=True, resolve_entities=True)
    doc = etree.parse(io.BytesIO(payload), parser)
    return etree.tostring(doc, encoding="unicode")
""", "python", "etree.parse", "CWE-611", "lxml 显式启用 DTD/外部实体解析不可信 XML（XXE）"),
        ("""
import javax.xml.parsers.*;
import org.w3c.dom.*;
import java.io.*;
import javax.servlet.http.*;

public class XmlServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(req.getInputStream());
        resp.getWriter().write(doc.getDocumentElement().getTextContent());
    }
}
""", "java", "db.parse", "CWE-611", "DocumentBuilderFactory 未禁用 DTD/外部实体，解析不可信 XML（XXE）"),
        ("""
<?php
$xml = file_get_contents("php://input");
$doc = simplexml_load_string($xml, "SimpleXMLElement", LIBXML_NOENT);
echo $doc->name;
?>
""", "php", "simplexml_load_string", "CWE-611", "simplexml 启用 LIBXML_NOENT 解析不可信 XML（XXE）"),
        ("""
from flask import Flask, request
import xml.dom.minidom

app = Flask(__name__)


@app.route("/parse", methods=["POST"])
def parse_xml():
    raw = request.get_data()
    dom = xml.dom.minidom.parseString(raw)
    return dom.toxml()
""", "python", "parseString", "CWE-611", "minidom 解析不可信 XML，未禁用外部实体（XXE）"),
        ("""
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.xml.sax.helpers.*;
import java.io.*;

public class SaxHandler extends DefaultHandler {
    public void process(InputStream in) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        SAXParser parser = spf.newSAXParser();
        parser.parse(in, this);   // 默认解析外部实体
    }
    public void characters(char[] ch, int s, int l) {}
}
""", "java", "parser.parse", "CWE-611", "SAXParser 默认解析外部实体，处理不可信 XML（XXE）"),
        ("""
<?php
$filename = $_GET['file'];
$doc = new DOMDocument();
$doc->load($filename);
echo $doc->textContent;
?>
""", "php", "->load(", "CWE-611", "DOMDocument 加载外部文件/不可信 XML，默认可解析实体（XXE）"),
    ]
    for code, lang, marker, cwe, flaw in pos:
        sink_ln = ln(code, marker)
        analysis = (
            f"分析过程：\n"
            f"1. 输入：外部传入的**不可信 XML**（POST 请求体/流）。\n"
            f"2. line {sink_ln}: 用 `{marker}()` 解析该 XML，且解析器**启用了外部实体解析**"
            f"（lxml 默认 / DocumentBuilderFactory 默认 / LIBXML_NOENT）。\n"
            f"3. 攻击者可在 XML 中注入 <!DOCTYPE ... SYSTEM \"file:///etc/passwd\"> 或内网 URL，"
            f"解析器会展开外部实体 → 读取本地文件或探测内网（XXE）。\n"
            f"4. 结论：CWE-611 Improper Restriction of XML External Entity Reference，风险 High（{flaw}）。"
        )
        verdict = {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-611 Improper Restriction of XML External Entity Reference",
            "risk_level": "High",
            "source": f"line {ln(code,'get_data') or ln(code,'getInputStream') or ln(code,'php://input')}: 不可信 XML 输入",
            "sink": f"line {sink_ln}: {marker}() 启用外部实体解析",
            "explanation": f"不可信 XML -> {marker}() 外部实体展开 -> 读文件/内网探测 -> XXE CWE-611",
            "fix_suggestion": f"line {sink_ln}: 禁用外部实体/DTD（如 defusedxml、FEATURE_SECURE_PROCESSING、禁用 LIBXML_NOENT）",
        }
        records.append(make_record(code, lang, analysis, verdict))

    neg = [
        ("""
from flask import Flask, request
from defusedxml import ElementTree as DET

app = Flask(__name__)


@app.route("/parse", methods=["POST"])
def parse_xml():
    raw = request.get_data()
    root = DET.fromstring(raw)
    return DET.tostring(root, encoding="unicode")
""", "python", "DET.fromstring", "defusedxml 已禁用外部实体，安全"),
        ("""
import xml.etree.ElementTree as ET

def parse(xml_bytes):
    root = ET.fromstring(xml_bytes)
    return root.findtext("name")
""", "python", "ET.fromstring", "Python ElementTree 默认不解析外部实体，安全"),
        ("""
import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import java.io.*;

public class SafeXml {
    public static Document parse(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        return dbf.newDocumentBuilder().parse(in);
    }
}
""", "java", "disallow-doctype-decl", "显式禁用 DTD 与外部实体，安全"),
        ("""
# lxml 安全配置：显式关闭外部实体与网络加载
from flask import Flask, request
from lxml import etree
import io

app = Flask(__name__)
SECURE_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)


@app.route("/settings/import", methods=["POST"])
def import_settings():
    blob = request.data
    tree = etree.parse(io.BytesIO(blob), SECURE_PARSER)
    return etree.tostring(tree)
""", "python", "resolve_entities=False", "lxml 显式禁用实体解析与网络，安全"),
        ("""
<?php
$xml = file_get_contents("php://input");
$doc = simplexml_load_string($xml);
echo $doc->name;
?>
""", "php", "simplexml_load_string", "simplexml 未启用 LIBXML_NOENT，不解析实体，安全"),
    ]
    for code, lang, marker, reason in neg:
        analysis = (
            f"分析过程：\n"
            f"1. 虽然解析了外部 XML，但 line {ln(code, marker)}: 解析器**已禁用外部实体/DTD**"
            f"（`{marker}`）。\n"
            f"2. 攻击者注入的外部实体不会被展开，无法读取本地文件/探测内网。\n"
            f"3. 结论：无 XXE 漏洞，has_vulnerability=false（{reason}）。"
        )
        verdict = {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": f"解析器已禁用外部实体/DTD（{reason}）",
            "fix_suggestion": "no fix needed",
        }
        records.append(make_record(code, lang, analysis, verdict))


# ============================================================
# 4. CSRF 同源 / Referer 绕过（FN）
# ============================================================
def gen_csrf():
    pos = [
        # Django：Referer 前缀校验可被域名前缀绕过
        ("""
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.contrib import messages


@require_POST
def update_profile(request):
    if not request.session.get("uid"):
        return JsonResponse({"error": "login"}, status=401)
    referer = request.META.get("HTTP_REFERER", "")
    if not referer.startswith("https://profile.example.com"):
        return JsonResponse({"error": "csrf"}, status=403)
    email = request.POST.get("email")
    request.user.email = email
    return JsonResponse({"ok": True})
""", "python", "HTTP_REFERER", "CWE-352", "Referer 前缀校验可用 https://profile.example.com.evil 绕过"),
        # Express：Origin 缺失时放行（非浏览器请求）
        ("""
const express = require('express');
const session = require('express-session');
const app = express();
app.use(express.json());
app.use(session({ secret: 'dev', resave: false, saveUninitialized: true }));

app.post('/api/change_password', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ e: 'login' });
    }
    const origin = req.headers.origin;
    if (origin && origin !== 'https://portal.example.com') {
        return res.status(403).json({ e: 'origin' });
    }
    // Origin 缺失（如 curl / 部分跨站场景）时直接放行
    req.session.passwd = req.body.newpass;
    res.json({ ok: true });
});
""", "javascript", "req.headers.origin", "CWE-352", "Origin 缺失时直接放行，可绕过"),
        # FastAPI：仅登录校验，无任何 CSRF 防护
        ("""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()


@app.post("/admin/wipe_logs")
def wipe_logs(request: Request):
    if not request.session.get("user"):
        return JSONResponse({"error": "login"}, status_code=401)
    log_store.clear()
    return {"ok": True}
""", "python", "wipe_logs", "CWE-352", "有登录但无任何 CSRF token / SameSite / 同源校验"),
        # Flask：双提交 Cookie 允许空 token 恒真绕过
        ("""
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "dev_key"


@app.route("/account/deactivate", methods=["POST"])
def deactivate_account():
    if "user_id" not in session:
        return "Please login", 401
    cookie_token = request.cookies.get("_csrf")
    form_token = request.form.get("_csrf", "")
    if form_token != cookie_token:
        return "blocked", 403
    account.set_active(False)
    return "deactivated"
""", "python", "cookie_token", "CWE-352", "cookie 与 form 都缺失时空串相等恒真，绕过"),
        # Express：Referer 子串校验可被前缀绕过（改邮箱）
        ("""
const express = require('express');
const session = require('express-session');
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: 'dev', resave: false, saveUninitialized: true }));

app.post('/account/email', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ e: 'login' });
    }
    const referer = req.headers.referer || '';
    if (!referer.includes('mail.example.com')) {
        return res.status(403).json({ e: 'csrf' });
    }
    users.updateEmail(req.session.userId, req.body.email);
    res.json({ ok: true });
});
""", "javascript", "referer.includes", "CWE-352", "Referer 子串包含校验可被 mail.example.com.evil 前缀/参数绕过"),
    ]
    for code, lang, marker, cwe, flaw in pos:
        sink_ln = ln(code, marker) or ln(code, "def ")
        analysis = (
            f"分析过程：\n"
            f"1. line {sink_ln}: 修改状态的操作仅做了**登录校验**，其 CSRF 防护是**弱校验**"
            f"（Referer/Origin 子串包含、或缺失时回退、或完全没有）。\n"
            f"2. 攻击面：攻击者可构造恶意页面自动提交跨站请求——若防护是\"example.com\"子串包含，"
            f"攻击者用 `http://example.com.evil.com` 或注入 `?` 即可绕过；若 Origin 缺失时回退，"
            f"可发无 Origin 的请求绕过。\n"
            f"3. 结论：存在 CSRF（CWE-352 Cross-Site Request Forgery），风险 High（{flaw}）。"
        )
        verdict = {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-352 Cross-Site Request Forgery (CSRF)",
            "risk_level": "High",
            "source": f"line {sink_ln}: 跨站请求（弱同源校验可绕过）",
            "sink": f"line {sink_ln}: 修改状态操作无有效 CSRF 防护",
            "explanation": f"弱 Referer/Origin 校验或缺失 -> 跨站请求可伪造 -> CWE-352 CSRF（{flaw}）",
            "fix_suggestion": f"line {sink_ln}: 使用会话绑定 CSRF token + 精确 Origin 白名单（全等比较）或 SameSite=Strict",
        }
        records.append(make_record(code, lang, analysis, verdict))

    neg = [
        # Express：会话绑定 CSRF token + 恒定时间比对
        ("""
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: 'dev', resave: false, saveUninitialized: true }));

app.post('/account/email', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ e: 'login' });
    }
    const expected = req.session.csrf;
    const got = req.body.csrf_token || '';
    if (!expected || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(got))) {
        return res.status(403).json({ e: 'csrf' });
    }
    res.json({ ok: true });
});
""", "javascript", "timingSafeEqual", "会话绑定 token + 恒定时间比对，有效防护"),
        # FastAPI：SameSite=Strict + Secure
        ("""
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="dev",
                   same_site="strict", https_only=True)
""", "python", "same_site", "SameSite=Strict + https_only，阻止跨站携带 Cookie，有效防护"),
        # Django：Origin 精确全等白名单
        ("""
from django.http import JsonResponse
from django.views.decorators.http import require_POST

ALLOWED_ORIGIN = "https://portal.example.com"


@require_POST
def transfer(request):
    if not request.session.get("uid"):
        return JsonResponse({"error": "login"}, status=401)
    origin = request.headers.get("Origin")
    if origin != ALLOWED_ORIGIN:
        return JsonResponse({"error": "csrf"}, status=403)
    return JsonResponse({"ok": True})
""", "python", "origin != ALLOWED_ORIGIN", "Origin 精确全等比较，有效防护"),
        # Django：会话绑定 token 比对
        ("""
from django.http import JsonResponse
from django.views.decorators.http import require_POST


@require_POST
def change_email(request):
    if not request.session.get("uid"):
        return JsonResponse({"error": "login"}, status=401)
    expected = request.session.get("csrf_token")
    got = request.POST.get("csrf_token", "")
    if not expected or expected != got:
        return JsonResponse({"error": "csrf"}, status=403)
    return JsonResponse({"ok": True})
""", "python", "csrf_token", "会话绑定 CSRF token 比对，有效防护"),
    ]
    for code, lang, marker, reason in neg:
        analysis = (
            f"分析过程：\n"
            f"1. 修改状态操作有**有效的 CSRF 防护**（line {ln(code, marker)}: `{marker}`）。\n"
            f"2. 防护手段能阻止跨站请求伪造：会话绑定 token 比对 / SameSite=Strict / Origin 精确白名单。\n"
            f"3. 结论：无 CSRF 漏洞，has_vulnerability=false（{reason}）。"
        )
        verdict = {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": f"有有效 CSRF 防护（{reason}）",
            "fix_suggestion": "no fix needed",
        }
        records.append(make_record(code, lang, analysis, verdict))


gen_crossfile()
gen_noise()
gen_xxe()
gen_csrf()

with OUT.open("w", encoding="utf-8") as fh:
    for rec in records:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"生成 {len(records)} 条痛点补充样本 -> {OUT}")

from collections import Counter
c = Counter()
for rec in records:
    jm = re.search(r"```json\s*(\{.*?\})\s*```", rec["messages"][2]["content"], re.S)
    if jm:
        v = json.loads(jm.group(1))
        c[(v["has_vulnerability"], v["vulnerability_type"][:14])] += 1
print("分布:", dict(c))
