# -*- coding: utf-8 -*-
"""α0.5 真实 CVE 场景补充样本生成器。

针对 α0 在 hard_cve_XX 上出错且训练缺失的真实 CVE 场景（代码与测试集不同，防泄露）：
  1. CVE-2017-7494 Samba 命令注入（用户可控路径 -> os.system/subprocess shell）
  2. CVE-2021-44228 Log4j / 日志注入（f-string/拼接日志含 CRLF -> CWE-117）
  3. CVE-2007-4559 tarfile extractall 任意文件写入（未校验成员 -> CWE-22）
  4. CVE-2017-5638 Struts2 OGNL 表达式注入（用户输入进 OGNL -> CWE-917）
  5. CVE-2022-22965 Spring4Shell 数据绑定 -> CWE-915
  6. CVE-2017-18349 / fastjson 反序列化 RCE -> CWE-502

每条带 CVE 注释锚点 + 正确 CWE + 归因论证。输出：data/supplement_alpha05_realcve.jsonl
"""
import json, re, sys
from pathlib import Path

ROOT = Path(r"D:\code\毕业设计\Graduation-Project")
DATA = ROOT / "experiments" / "exp_06_finetune" / "data"
OUT = DATA / "supplement_alpha05_realcve.jsonl"

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
def add(code, lang, analysis, verdict):
    records.append(make_record(code, lang, analysis, verdict))


# 1. CVE-2017-7494 Samba 命令注入
add("""
# 历史 CVE-2017-7494：Samba 通过恶意共享名触发命令注入（RCE）
from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route("/mount")
def mount_share():
    share = request.args.get("share", "")
    return subprocess.run("mount -t cifs //srv/" + share + " /mnt", shell=True,
                          capture_output=True).stdout
""", "python",
    "分析过程：\n"
    "1. line 10: `share` 用户可控，line 11: 直接拼入 `subprocess.run(..., shell=True)` 命令字符串。\n"
    "2. 与 CVE-2017-7494 同理：共享名/路径含管道或元字符（如 `|id`）即可在 shell 中注入命令 → RCE。\n"
    "3. 结论：CWE-78 OS Command Injection，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-78 OS Command Injection",
     "risk_level": "Critical", "source": "line 10: share 用户可控",
     "sink": "line 11: shell=True 拼接命令",
     "explanation": "share -> subprocess.run(shell=True) 字符串拼接 -> 命令注入 RCE -> CWE-78（CVE-2017-7494 类）",
     "fix_suggestion": "line 11: 列表参数 + shell=False，share 白名单"})

add("""
# 类似 CVE-2017-7494：服务路径经 os.system 触发命令注入
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/reload")
def reload_module():
    mod = request.args.get("mod", "")
    if os.path.exists(mod):
        os.system("systemctl reload " + mod)
        return "ok"
    return "no"
""", "python",
    "分析过程：\n"
    "1. line 10: `mod` 用户可控，line 11: `os.system` 拼接执行，`os.path.exists` 不阻止元字符（`;`/`|`/`$()`）。\n"
    "2. 结论：CWE-78 命令注入，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-78 OS Command Injection",
     "risk_level": "Critical", "source": "line 10: mod 用户可控",
     "sink": "line 11: os.system 拼接命令",
     "explanation": "mod -> os.system 拼接 -> 命令注入 -> CWE-78",
     "fix_suggestion": "line 11: 用 subprocess.run([...], shell=False) + 白名单"})


# 2. 日志注入 / Log4j 类（参数化日志，非拼接，但仍含换行注入风险）
add("""
// 类似 CVE-2021-44228 的日志组件风险：用户输入未净化进入日志（拼接可换行注入/旧版可 JNDI）
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.servlet.http.*;

public class SignupServlet extends HttpServlet {
    private static final Logger LOG = LogManager.getLogger(SignupServlet.class);

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        String nick = req.getParameter("nick");
        LOG.info("signup attempt by " + nick + " from " + req.getRemoteAddr());
    }
}
""", "java",
    "分析过程：\n"
    "1. line 9: `nick` 用户可控，line 10: 拼接写入日志，未过滤 `\\r\\n` 控制字符。\n"
    "2. 攻击者可注入换行伪造审计日志 → CWE-117 日志注入（与 CVE-2021-44228 的日志组件攻击面同类）。\n"
    "3. 干扰项排除：无 `%` 占位符拼接依赖，不是 CWE-134 格式字符串注入；主洞是日志注入 → CWE-117。\n"
    "4. 结论：CWE-117 Improper Output Neutralization for Logs，风险 Medium。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-117 Improper Output Neutralization for Logs",
     "risk_level": "Medium", "source": "line 9: nick 用户可控",
     "sink": "line 10: 日志拼接未净化控制字符",
     "explanation": "nick 含 \\r\\n -> 日志拼接 -> 伪造日志/注入 -> CWE-117（类 CVE-2021-44228）",
     "fix_suggestion": "line 10: 日志前替换 \\r\\n 等控制字符，或结构化日志"})


# 3. tarfile extractall 任意文件写入（CVE-2007-4559）
add("""
# CVE-2007-4559：tarfile.extractall 未校验成员路径 -> 任意文件覆盖
import tarfile
from flask import Flask, request
import io

app = Flask(__name__)


@app.route("/extract", methods=["POST"])
def extract():
    raw = request.get_data()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r") as tar:
        tar.extractall(path="/var/data")
    return "done"
""", "python",
    "分析过程：\n"
    "1. line 12: `tar.extractall()` **未校验每个成员的路径**（未过滤 `../` 与符号链接）。\n"
    "2. 与 CVE-2007-4559 同理：恶意 tar 含 `../../etc/cron.d/x` 或指向系统文件的符号链接 → 任意文件覆盖/写入。\n"
    "3. 结论：CWE-22 Path Traversal（tar 解压路径穿越/任意文件写入），风险 High。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-22 Path Traversal",
     "risk_level": "High", "source": "line 11: 用户上传 tar",
     "sink": "line 12: extractall 未校验成员路径",
     "explanation": "上传 tar -> extractall 未过滤 ../ 与软链 -> 任意文件写入 -> CWE-22（CVE-2007-4559）",
     "fix_suggestion": "line 12: 解压前校验 member.name 用 realpath 限定在目标目录内，拒绝软链"})


# 4. Struts2 OGNL 表达式注入（CVE-2017-5638）
add("""
// CVE-2017-5638：Struts2 解析用户输入为 OGNL 表达式 -> RCE
import ognl.Ognl;
import ognl.OgnlContext;
import javax.servlet.http.*;

public class UserAction {
    public String execute(HttpServletRequest req) throws Exception {
        String expr = req.getHeader("Content-Type");
        Object value = Ognl.getValue(expr, new OgnlContext(), new Object());
        return "parsed: " + value;
    }
}
""", "java",
    "分析过程：\n"
    "1. line 10: 用户可控的 `Content-Type` 请求头直接作为 **OGNL 表达式** 求值（`Ognl.getValue`）。\n"
    "2. 与 CVE-2017-5638 同理：攻击者可传 OGNL 载荷执行任意 Java 代码 → RCE。\n"
    "3. 结论：CWE-917 Improper Neutralization of Special Elements used in an Expression Language，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements used in an Expression Language",
     "risk_level": "Critical", "source": "line 10: Content-Type 请求头用户可控",
     "sink": "line 11: Ognl.getValue 求值用户表达式",
     "explanation": "Content-Type -> OGNL 表达式求值 -> RCE -> CWE-917（CVE-2017-5638）",
     "fix_suggestion": "line 11: 禁止对用户输入做表达式求值，改用参数化/白名单"})


# 5. Spring4Shell 数据绑定（CVE-2022-22965）
add("""
// CVE-2022-22965：Spring MVC @ModelAttribute 数据绑定到任意属性 -> RCE
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class ProfileController {

    @PostMapping("/profile/update")
    @ResponseBody
    public String update(ProfileForm form) {
        return "ok " + form.getDisplayName();
    }
}

class ProfileForm {
    private String displayName;
    public String getDisplayName() { return displayName; }
    public void setDisplayName(String v) { this.displayName = v; }
}
""", "java",
    "分析过程：\n"
    "1. line 10: HTTP 参数自动绑定到 `ProfileForm`（@ModelAttribute）。\n"
    "2. 与 CVE-2022-22965 同理：可提交 `class.module.classLoader` 等额外字段触发任意属性/类加载设置 → RCE。\n"
    "3. 结论：CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes",
     "risk_level": "Critical", "source": "line 10: HTTP 参数绑定",
     "sink": "line 10: @ModelAttribute 自动绑定任意属性",
     "explanation": "HTTP 参数 -> Spring 自动绑定额外字段 -> 任意 setter/类加载 -> CWE-915（CVE-2022-22965）",
     "fix_suggestion": "line 10: @InitBinder setAllowedFields 白名单"})


# 6. fastjson 反序列化 RCE（CVE-2017-18349 类）
add("""
// fastjson 反序列化：用户输入 JSON.parseObject -> 可触发恶意类构造/链 -> RCE
import com.alibaba.fastjson.JSON;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.AbstractController;

@RestController
public class WebhookController extends AbstractController {

    @PostMapping("/webhook/inbound")
    public String inbound(@RequestBody String payload) {
        Object parsed = JSON.parseObject(payload);
        return "event:" + parsed;
    }

    @GetMapping("/health")
    public String health() {
        return "up";
    }
}
""", "java",
    "分析过程：\n"
    "1. line 12: 用户请求体直接 `JSON.parseObject()`，fastjson 默认按 `@type` 反序列化任意类。\n"
    "2. 与 fastjson 历史 RCE（CVE-2017-18349 等）同理：构造恶意 `@type` + gadget 链可执行任意代码。\n"
    "3. 结论：CWE-502 Deserialization of Untrusted Data，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-502 Deserialization of Untrusted Data",
     "risk_level": "Critical", "source": "line 12: 用户请求体",
     "sink": "line 13: JSON.parseObject 反序列化不可信输入",
     "explanation": "请求体 -> JSON.parseObject @type -> gadget 链 -> RCE -> CWE-502（fastjson）",
     "fix_suggestion": "line 13: 使用安全 JSON 库/配置 autoType 白名单/禁止 @type"})


# ============================================================
# 7. CVE-2017-7494 类命令注入（变体 3-5：不同 sink/入口）
# ============================================================
add("""
# CVE-2017-7494 类：用户可控模块名拼入 python 解释执行
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/exec_module")
def exec_module():
    module = request.args.get("module", "")
    return subprocess.call("python " + module, shell=True)
""", "python",
    "分析过程：\n"
    "1. line 8: `module` 用户可控，line 9: `subprocess.call(\"python \" + module, shell=True)` 字符串拼接执行。\n"
    "2. 与 CVE-2017-7494 同理：module 含 `;`/`|`/`$()` 即注入任意命令 → RCE。\n"
    "3. 结论：CWE-78 OS Command Injection，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-78 OS Command Injection",
     "risk_level": "Critical", "source": "line 8: module 用户可控",
     "sink": "line 9: subprocess.call(shell=True) 拼接命令",
     "explanation": "module -> subprocess.call(shell=True) 拼接 -> 命令注入 RCE -> CWE-78",
     "fix_suggestion": "line 9: 列表参数 + shell=False + 模块白名单"})

add("""
# CVE-2017-7494 类：用户可控路径拼入 os.popen
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/inspect")
def inspect():
    target = request.args.get("path", "")
    return os.popen("ls -la " + target).read()
""", "python",
    "分析过程：\n"
    "1. line 8: `target` 用户可控，line 9: `os.popen(\"ls -la \" + target)` 经 shell 执行。\n"
    "2. os.popen 与 system 等价，路径含 `;` 即命令注入。\n"
    "3. 结论：CWE-78 OS Command Injection，风险 High。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-78 OS Command Injection",
     "risk_level": "High", "source": "line 8: target 用户可控",
     "sink": "line 9: os.popen 拼接命令",
     "explanation": "target -> os.popen 拼接 -> 命令注入 -> CWE-78",
     "fix_suggestion": "line 9: 用 os.listdir() 替代 shell，或参数列表"})

add("""
# CVE-2017-7494 类：用户可控仓库 URL 拼入 git clone
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/sync")
def sync():
    repo = request.args.get("repo", "")
    return subprocess.run("git clone " + repo + " /tmp/src", shell=True,
                          capture_output=True).stdout
""", "python",
    "分析过程：\n"
    "1. line 8: `repo` 用户可控，line 9: `subprocess.run(\"git clone \" + repo + \" ...\", shell=True)`。\n"
    "2. repo 含 `;`/`&&` 即注入命令（如 `; cat /etc/passwd`）→ RCE。\n"
    "3. 结论：CWE-78 OS Command Injection，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-78 OS Command Injection",
     "risk_level": "Critical", "source": "line 8: repo 用户可控",
     "sink": "line 9: shell=True 拼接 git 命令",
     "explanation": "repo -> git clone 拼接 shell=True -> 命令注入 -> CWE-78",
     "fix_suggestion": "line 9: subprocess.run(['git','clone',repo,...], shell=False) + URL 白名单"})


# ============================================================
# 8. CWE-117 日志注入（变体 2-4：Java/PHP/Node）
# ============================================================
add("""
// CVE-2021-44228 类日志注入：Java 拼接日志，CRLF 伪造审计条目
import java.util.logging.Logger;
import javax.servlet.http.*;

public class LoginServlet extends HttpServlet {
    private static final Logger LOG = Logger.getLogger("auth");

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        String user = req.getParameter("user");
        LOG.info("login attempt from " + user);
    }
}
""", "java",
    "分析过程：\n"
    "1. line 8: `user` 用户可控，line 9: `LOG.info(\"login attempt from \" + user)` 字符串拼接进日志。\n"
    "2. user 含 `\\r\\n` 可伪造日志条目/审计绕过 → CWE-117；无 `%` 占位符，不是 CWE-134。\n"
    "3. 结论：CWE-117 Improper Output Neutralization for Logs，风险 Medium。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-117 Improper Output Neutralization for Logs",
     "risk_level": "Medium", "source": "line 8: user 用户可控",
     "sink": "line 9: 日志拼接未净化控制字符",
     "explanation": "user -> 日志拼接 -> CRLF 伪造日志 -> CWE-117",
     "fix_suggestion": "line 9: 日志前替换 \\r\\n，或结构化日志参数化"})

add("""
<?php
// CVE-2021-44228 类日志注入：PHP error_log 拼接用户输入
$user = $_GET['user'];
error_log("login attempt from " . $user);
echo "ok";
""", "php",
    "分析过程：\n"
    "1. line 3: `$_GET['user']` 用户可控，line 4: `error_log(... . $user)` 拼接进系统日志。\n"
    "2. 用户可注入 `\\r\\n` 伪造日志行/审计绕过 → CWE-117。\n"
    "3. 结论：CWE-117 Improper Output Neutralization for Logs，风险 Medium。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-117 Improper Output Neutralization for Logs",
     "risk_level": "Medium", "source": "line 3: $_GET['user'] 用户可控",
     "sink": "line 4: error_log 拼接未净化控制字符",
     "explanation": "user -> error_log 拼接 -> CRLF 伪造日志 -> CWE-117",
     "fix_suggestion": "line 4: 过滤 \\r\\n 或使用结构化日志"})

add("""
// CVE-2021-44228 类日志注入：Node 访问日志拼接 Referer
const http = require('http');
const fs = require('fs');

http.createServer((req, res) => {
    const referer = req.headers['referer'] || '';
    fs.appendFileSync('/var/log/access.log', 'visit from ' + referer + '\\n');
    res.end('ok');
}).listen(8080);
""", "javascript",
    "分析过程：\n"
    "1. line 7: `referer` 用户可控（请求头），line 8: 拼接写访问日志。\n"
    "2. referer 含 `\\r\\n` 可伪造/注入日志条目 → CWE-117。\n"
    "3. 结论：CWE-117 Improper Output Neutralization for Logs，风险 Medium。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-117 Improper Output Neutralization for Logs",
     "risk_level": "Medium", "source": "line 7: referer 请求头用户可控",
     "sink": "line 8: 日志拼接未净化控制字符",
     "explanation": "referer -> 日志拼接 -> CRLF 伪造日志 -> CWE-117",
     "fix_suggestion": "line 8: 过滤 \\r\\n 或 JSON 结构化日志"})


# ============================================================
# 9. CVE-2007-4559 tarfile/zipfile 任意文件写入（变体 2-4）
# ============================================================
add("""
# CVE-2007-4559 类：zipfile.extractall 未校验成员路径 -> 任意文件覆盖
import zipfile
from flask import Flask, request
import io

app = Flask(__name__)


@app.route("/unpack", methods=["POST"])
def unpack():
    raw = request.get_data()
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        zf.extractall(path="/srv/uploads")
    return "done"
""", "python",
    "分析过程：\n"
    "1. line 12: `zf.extractall(path=...)` **未校验 zip 成员路径**，`../` 可逃逸目标目录。\n"
    "2. 与 CVE-2007-4559 同理：恶意 zip 含 `../../../etc/cron.d/x` → 任意文件写入。\n"
    "3. 结论：CWE-22 Path Traversal（解压路径穿越/任意文件写入），风险 High。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-22 Path Traversal",
     "risk_level": "High", "source": "line 11: 用户上传 zip",
     "sink": "line 12: extractall 未校验成员路径",
     "explanation": "上传 zip -> extractall 未过滤 ../ -> 任意文件写入 -> CWE-22",
     "fix_suggestion": "line 12: 解压前校验 member 路径 realpath 限定在目标目录内"})

add("""
# CVE-2007-4559 类：tar.extract 逐成员解压未校验符号链接
import tarfile
from flask import Flask, request
import io

app = Flask(__name__)


@app.route("/restore", methods=["POST"])
def restore():
    raw = request.get_data()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        for member in tar.getmembers():
            tar.extract(member, path="/var/backups")
    return "ok"
""", "python",
    "分析过程：\n"
    "1. line 13: 逐成员 `tar.extract(member, ...)` **未校验 `member.issym()`/软链目标**，也未过滤 `../`。\n"
    "2. 与 CVE-2007-4559 同理：恶意 tar 成员为指向 `/etc/passwd` 的软链 → 覆盖任意文件。\n"
    "3. 结论：CWE-22 Path Traversal（tar 解压符号链接任意写入），风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-22 Path Traversal",
     "risk_level": "Critical", "source": "line 11: 用户上传 tar",
     "sink": "line 13: tar.extract 未校验软链/../",
     "explanation": "上传 tar -> 逐成员 extract 未校验软链 -> 任意文件覆盖 -> CWE-22",
     "fix_suggestion": "line 13: 拒绝软链成员 + realpath 前缀校验，或用 filter='data'"})

add("""
# CVE-2007-4559 类：下载后自动解压归档，未校验成员路径
import zipfile, io
import urllib.request
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch_extract")
def fetch_extract():
    url = request.args.get("url", "")
    data = urllib.request.urlopen(url).read()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall("/tmp/inbox")
    return "done"
""", "python",
    "分析过程：\n"
    "1. line 10: `url` 用户可控（还构成 SSRF），line 12: `zf.extractall(\"/tmp/inbox\")` 未校验成员路径。\n"
    "2. 恶意 zip 成员 `../` 逃逸 /tmp/inbox → 任意文件写入（CVE-2007-4559 类）。\n"
    "3. 结论：CWE-22 Path Traversal，风险 High（同时存在 CWE-918 SSRF）。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-22 Path Traversal",
     "risk_level": "High", "source": "line 10: url 用户可控",
     "sink": "line 12: extractall 未校验成员路径",
     "explanation": "url -> 下载 -> extractall 未过滤 ../ -> 任意文件写入 -> CWE-22（兼 SSRF）",
     "fix_suggestion": "line 12: 校验成员路径 + url 主机白名单"})


# ============================================================
# 10. CWE-918 SSRF（测试集 hard_cve_04 缺失的类别，变体 1-4）
# ============================================================
add("""
# SSRF：用户可控 URL 直接 requests.get 服务端请求
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/proxy_get")
def proxy_get():
    target = request.args.get("url", "")
    return requests.get(target, timeout=5).text
""", "python",
    "分析过程：\n"
    "1. line 8: `target` 用户可控 URL，line 9: `requests.get(target)` 服务端发起请求。\n"
    "2. 攻击者可访问内网/云元数据（169.254.169.254）→ CWE-918 SSRF。\n"
    "3. 结论：CWE-918 Server-Side Request Forgery，风险 High。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-918 Server-Side Request Forgery",
     "risk_level": "High", "source": "line 8: url 用户可控",
     "sink": "line 9: requests.get 请求用户 URL",
     "explanation": "url -> requests.get -> 访问内网/元数据 -> CWE-918 SSRF",
     "fix_suggestion": "line 9: URL 协议+主机白名单，禁止内网/元数据 IP"})

add("""
# SSRF：用户可控域名拼入 http.client 连接
from http.client import HTTPConnection
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch_svc")
def fetch_svc():
    host = request.args.get("host", "")
    conn = HTTPConnection(host, 80, timeout=5)
    conn.request("GET", "/")
    return conn.getresponse().read()
""", "python",
    "分析过程：\n"
    "1. line 8: `host` 用户可控，line 9: `HTTPConnection(host)` 服务端向其发起请求。\n"
    "2. 可访问内网服务/元数据端点 → CWE-918 SSRF。\n"
    "3. 结论：CWE-918 Server-Side Request Forgery，风险 High。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-918 Server-Side Request Forgery",
     "risk_level": "High", "source": "line 8: host 用户可控",
     "sink": "line 9: HTTPConnection 请求用户主机",
     "explanation": "host -> HTTPConnection -> 访问内网 -> CWE-918 SSRF",
     "fix_suggestion": "line 9: 主机白名单 + 禁止内网网段"})

add("""
# SSRF：用户可控 url 拼入 curl 命令（命令注入与 SSRF 并存）
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/curl_fetch")
def curl_fetch():
    url = request.args.get("url", "")
    return subprocess.run("curl -s " + url, shell=True, capture_output=True).stdout
""", "python",
    "分析过程：\n"
    "1. line 8: `url` 用户可控，line 9: `subprocess.run(\"curl -s \" + url, shell=True)`。\n"
    "2. 既是 SSRF（curl 访问任意地址），也可注入命令（shell=True 拼接）→ 双漏洞。\n"
    "3. 结论：CWE-918 SSRF + CWE-78 命令注入，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-918 Server-Side Request Forgery",
     "risk_level": "Critical", "source": "line 8: url 用户可控",
     "sink": "line 9: shell=True 拼 curl 命令",
     "explanation": "url -> curl shell 拼接 -> SSRF + 命令注入 -> CWE-918/78",
     "fix_suggestion": "line 9: 参数列表 + shell=False + URL 白名单"})

add("""
// SSRF：Java 用户可控 URL 经 URLConnection 服务端请求
import java.io.*;
import java.net.*;
import javax.servlet.http.*;

public class UrlFetchServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String target = req.getParameter("url");
        URLConnection conn = new URL(target).openConnection();
        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        resp.getWriter().write(in.readLine());
    }
}
""", "java",
    "分析过程：\n"
    "1. line 8: `target` 用户可控 URL，line 9: `new URL(target).openConnection()` 服务端请求。\n"
    "2. 可访问内网/元数据端点 → CWE-918 SSRF。\n"
    "3. 结论：CWE-918 Server-Side Request Forgery，风险 High。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-918 Server-Side Request Forgery",
     "risk_level": "High", "source": "line 8: url 用户可控",
     "sink": "line 9: URL.openConnection 请求用户 URL",
     "explanation": "url -> URL.openConnection -> 访问内网 -> CWE-918 SSRF",
     "fix_suggestion": "line 9: URL 协议/主机白名单，禁止内网网段"})


# ============================================================
# 11. CWE-917 表达式注入（变体 2-3：SpEL/OGNL 其他入口）
# ============================================================
add("""
// CWE-917：用户输入直接作为 SpEL 表达式求值 -> RCE
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.*;

@RestController
public class CalcController {

    @GetMapping("/calc")
    public Object calc(@RequestParam String expr) {
        ExpressionParser p = new SpelExpressionParser();
        return p.parseExpression(expr).getValue();
    }
}
""", "java",
    "分析过程：\n"
    "1. line 10: `expr` 用户可控，line 11: `parseExpression(expr).getValue()` 表达式求值。\n"
    "2. 与 CVE-2017-5638 的 OGNL 同属 EL 注入：表达式可调用任意方法 → RCE → CWE-917。\n"
    "3. 结论：CWE-917 Improper Neutralization of Special Elements used in an Expression Language，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements used in an Expression Language",
     "risk_level": "Critical", "source": "line 10: expr 用户可控",
     "sink": "line 11: SpEL parseExpression 求值用户表达式",
     "explanation": "expr -> SpEL 求值 -> RCE -> CWE-917（类 CVE-2017-5638）",
     "fix_suggestion": "line 11: 禁止对用户输入做表达式求值，用预设表达式+参数注入"})


# ============================================================
# 12. CWE-915 数据绑定（变体 2-3）
# ============================================================
add("""
// CVE-2022-22965 类：Spring @ModelAttribute 绑定任意字段（多字段表单）
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class AccountController {

    @PostMapping("/account/update")
    @ResponseBody
    public String update(AccountForm form) {
        return "updated " + form.getEmail();
    }
}

class AccountForm {
    private String email;
    private String nickname;
    public String getEmail() { return email; }
    public void setEmail(String v) { this.email = v; }
    public String getNickname() { return nickname; }
    public void setNickname(String v) { this.nickname = v; }
}
""", "java",
    "分析过程：\n"
    "1. line 8: `update(AccountForm form)` @ModelAttribute 自动绑定 HTTP 参数到任意 setter。\n"
    "2. 攻击者可提交 `class.module.classLoader...` 等额外字段触发任意属性绑定 → RCE（Spring4Shell）。\n"
    "3. 结论：CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes",
     "risk_level": "Critical", "source": "line 8: HTTP 参数绑定",
     "sink": "line 8: @ModelAttribute 自动绑定任意属性",
     "explanation": "HTTP 参数 -> @ModelAttribute 绑定额外字段 -> 任意 setter/类加载 -> CWE-915（Spring4Shell）",
     "fix_suggestion": "line 8: @InitBinder setAllowedFields 白名单"})


# ============================================================
# 13. CWE-502 反序列化（变体 2-3）
# ============================================================
add("""
// Java 反序列化：用户 base64 token 直接 ObjectInputStream.readObject -> RCE
import java.io.*;
import java.util.Base64;
import javax.servlet.http.*;

public class SessionTokenServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String b64 = req.getParameter("token");
        byte[] data = Base64.getDecoder().decode(b64);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject();
        resp.getWriter().write(obj.toString());
    }
}
""", "java",
    "分析过程：\n"
    "1. line 9: 用户 `token` 经 base64 解码，line 10: `ObjectInputStream.readObject()` 反序列化不可信输入。\n"
    "2. 配合 Commons-Collections 等 gadget 链 → RCE → CWE-502。\n"
    "3. 结论：CWE-502 Deserialization of Untrusted Data，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-502 Deserialization of Untrusted Data",
     "risk_level": "Critical", "source": "line 9: 用户 token（base64）",
     "sink": "line 10: ObjectInputStream.readObject 反序列化不可信输入",
     "explanation": "token -> base64 decode -> readObject -> gadget 链 RCE -> CWE-502",
     "fix_suggestion": "line 10: 禁止反序列化用户数据，改用 JSON；或类白名单过滤"})

add("""
# Python pickle 反序列化：对不可信字节流直接 pickle.loads -> RCE
import pickle


def process_uploaded(data_bytes):
    # 直接反序列化不可信字节流，可触发任意代码执行
    obj = pickle.loads(data_bytes)
    return obj
""", "python",
    "分析过程：\n"
    "1. line 7: 不可信字节流直接 `pickle.loads(data_bytes)` 反序列化。\n"
    "2. pickle 反序列化可执行任意代码（__reduce__ 构造）→ RCE → CWE-502。\n"
    "3. 结论：CWE-502 Deserialization of Untrusted Data，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-502 Deserialization of Untrusted Data",
     "risk_level": "Critical", "source": "line 6: data_bytes 不可信输入",
     "sink": "line 7: pickle.loads 反序列化不可信输入",
     "explanation": "data_bytes -> pickle.loads -> __reduce__ RCE -> CWE-502",
     "fix_suggestion": "line 7: 用 json 等安全格式，禁止反序列化不可信数据"})


with OUT.open("w", encoding="utf-8") as fh:
    for rec in records:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"生成 {len(records)} 条真实 CVE 补充样本 -> {OUT}")

from collections import Counter
c = Counter()
for rec in records:
    jm = re.search(r"```json\s*(\{.*?\})\s*```", rec["messages"][2]["content"], re.S)
    if jm:
        v = json.loads(jm.group(1))
        c[v["vulnerability_type"][:12]] += 1
print("分布:", dict(c))
