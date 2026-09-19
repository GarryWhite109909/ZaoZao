# -*- coding: utf-8 -*-
"""wave2 手写代码对：CWE-78-safe 15 对（78-S-01..15，成对同码，vuln 骨架 + 同码 safe 化）。

规格：wave2_441_95_SPEC.md §2026-09-09 增补。锚句契约：
  - 镜像对 78-S-01 ↔ 78-S-09（列表形式安全因为 argv 无解释器语义 / 同为列表形式但 argv
    含 sh -c、-exec、--upload-pack 故仍 78）；
  - vuln 锚句：非 22（无路径穿越）/ 非 95（无 eval 求值）/ 非 74（注入目标是 OS 命令）；
  - safe 侧防御链逐条答"为何不可旁路"。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from wave2_pairlib import emit, write_index

VULN_ANCHOR = ("非 22 因为无路径穿越语义；非 95 因为无 eval/表达式求值；非 74 抽象层按 MITRE 落 78："
               "注入目标是 OS 命令解释器。")
MIRROR_NOTE = "（镜像对：78-S-01 教『列表形式安全因为 argv 无解释器语义』；本对教『同为列表形式但 argv 含解释器/语义参数，故仍 78』）"

P = []

# ---------------- 78-S-01a Python：列表形式（镜像 A） ----------------
_code = '''import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/diag/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # 故意写成 shell 字符串拼接
    r = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, timeout=5)
    return r.stdout.decode(errors="replace")
'''
P.append({
    "pid": "78-S-01", "lang": "Python", "cwe": "CWE-78",
    "anchor": VULN_ANCHOR,
    "safe_anchor": "防御为何不可旁路：argv 列表不经 shell 解释（shell=False 默认），host 即便含 "
                   "`; rm -rf /` 也只是字面第 4 个参数传给 ping，无第二个解释层可逃逸。" + MIRROR_NOTE,
    "oracle_vuln": [
        (r'host = request\.args\.get\("host"', "source：请求参数"),
        (r'subprocess\.run\(f"ping -c 1 \{host\}", shell=True', "sink：f-string 拼 shell 串"),
        (r'shell=True', "启用 /bin/sh 解释层"),
    ],
    "oracle_safe": [
        (r'subprocess\.run\(\["ping", "-c", "1", host\]', "防御：argv 列表，无 shell 解释层"),
    ],
    "vuln_code": _code,
    "safe_code": _code.replace(
        '    # 故意写成 shell 字符串拼接\n    r = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, timeout=5)',
        '    r = subprocess.run(["ping", "-c", "1", host], capture_output=True, timeout=5)'),
})

# ---------------- 78-S-02a Python：shlex.quote ----------------
_code = '''import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/nslookup")
def nslookup():
    host = request.args.get("host", "example.com")
    cmd = "nslookup " + host
    r = subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
    return r.stdout.decode(errors="replace")
'''
P.append({
    "pid": "78-S-02", "lang": "Python", "cwe": "CWE-78",
    "anchor": VULN_ANCHOR,
    "safe_anchor": "防御为何不可旁路：shlex.quote 对 host 做完整 shell 引号转义，`;`/`&&`/`$()` "
                   "等元字符被包裹成字面参数——注入文本永远是 nslookup 的一个参数，不能开启新语句。",
    "oracle_vuln": [
        (r'cmd = "nslookup " \+ host', "拼接进 shell 串"),
        (r'subprocess\.run\(cmd, shell=True', "sink：shell 解释整串"),
    ],
    "oracle_safe": [
        (r'shlex\.quote\(host\)', "防御：完整 shell 转义，元字符失去语句分隔语义"),
        (r'cmd = "nslookup " \+ shlex\.quote\(host\)', "受控拼接仍经 quote"),
    ],
    "vuln_code": _code,
    "safe_code": _code.replace(
        '    cmd = "nslookup " + host',
        '    import shlex\n    cmd = "nslookup " + shlex.quote(host)'),
})

# ---------------- 78-S-03a Node：命令名白名单 ----------------
_code = '''const express = require("express");
const { exec } = require("child_process");
const app = express();

app.get("/tools/run", (req, res) => {
  const tool = req.query.tool || "uptime";   // 工具名由用户决定
  const arg = req.query.arg || "";
  exec(`${tool} ${arg}`, { timeout: 5000 }, (err, stdout) => {
    if (err) return res.status(400).json({ error: "failed" });
    res.type("text").send(stdout);
  });
});

app.listen(8080);
'''
P.append({
    "pid": "78-S-03", "lang": "JavaScript", "cwe": "CWE-78",
    "anchor": VULN_ANCHOR,
    "safe_anchor": "防御为何不可旁路：工具名只能取 ALLOWED_TOOLS 白名单的 key，arg 经 execFile 以独立 argv 传入且"
                   "默认无 shell——用户永远只能『选择』预置命令，不能构造命令行。",
    "oracle_vuln": [
        (r'req\.query\.tool', "source：工具名用户可控"),
        (r'exec\(`\$\{tool\} \$\{arg\}`', "sink：模板串进 shell"),
    ],
    "oracle_safe": [
        (r'ALLOWED_TOOLS', "防御：工具白名单"),
        (r'execFile\(entry\.bin', "argv 独立传参，无 shell"),
        (r'if \(!entry\)', "白名单外直接拒绝"),
    ],
    "vuln_code": _code,
    "safe_code": '''const express = require("express");
const { execFile } = require("child_process");
const app = express();

const ALLOWED_TOOLS = {
  uptime: { bin: "uptime" },
  diskfree: { bin: "df", args: ["-h"] },
};

app.get("/tools/run", (req, res) => {
  const tool = req.query.tool || "uptime";
  const arg = req.query.arg || "";
  const entry = ALLOWED_TOOLS[tool];
  if (!entry) return res.status(400).json({ error: "tool not allowed" });
  execFile(entry.bin, [...(entry.args || []), arg], { timeout: 5000 }, (err, stdout) => {
    if (err) return res.status(400).json({ error: "failed" });
    res.type("text").send(stdout);
  });
});

app.listen(8080);
''',
})

# ---------------- 78-S-04a Python：模板派发 ----------------
_code = '''import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/report/build")
def build():
    choice = request.args.get("kind", "weekly")
    date = request.args.get("date", "1970-01-01")
    # 由输入拼出整条命令
    cmd = f"/usr/bin/report --kind {choice} --date {date}"
    r = subprocess.run(cmd, shell=True, capture_output=True, timeout=30)
    return r.stdout.decode(errors="replace")
'''
P.append({
    "pid": "78-S-04", "lang": "Python", "cwe": "CWE-78",
    "anchor": VULN_ANCHOR,
    "safe_anchor": "防御为何不可旁路：命令只能从 CMD_TEMPLATES 固定模板字典派发，choice 仅作 key 选择；"
                   "date 参数以独立 argv 传入无 shell 层，`--kind` 的取值空间被枚举封闭。",
    "oracle_vuln": [
        (r'cmd = f"/usr/bin/report', "sink：输入拼出整条命令"),
        (r'subprocess\.run\(cmd, shell=True', "shell 解释执行"),
    ],
    "oracle_safe": [
        (r'CMD_TEMPLATES', "防御：固定模板字典"),
        (r'KeyError', "模板外 key 直接失败"),
        (r'argv = CMD_TEMPLATES\[choice\] \+ \["--date", date\]', "argv 独立传参"),
    ],
    "vuln_code": _code,
    "safe_code": '''import subprocess
from flask import Flask, request

app = Flask(__name__)
CMD_TEMPLATES = {
    "weekly": ["/usr/bin/report", "--kind", "weekly"],
    "daily": ["/usr/bin/report", "--kind", "daily"],
}

@app.route("/report/build")
def build():
    choice = request.args.get("kind", "weekly")
    date = request.args.get("date", "1970-01-01")
    try:
        argv = CMD_TEMPLATES[choice] + ["--date", date]
    except KeyError:
        return "bad kind", 400
    r = subprocess.run(argv, capture_output=True, timeout=30)
    return r.stdout.decode(errors="replace")
''',
})

# ---------------- 78-S-05a Java：ProcessBuilder 列表 ----------------
_code = '''package tools;

public class Unzip {
    public String extract(String archive) throws Exception {
        // 数组形式 sh -c：脚本位整体可控，archive 含 `; rm -rf /` 即执行第二命令
        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "unzip -o " + archive + " -d /srv/tmp"});
        return new String(p.getInputStream().readAllBytes());
    }
}
'''
P.append({
    "pid": "78-S-05", "lang": "Java", "cwe": "CWE-78",
    "anchor": VULN_ANCHOR,
    "safe_anchor": "防御为何不可旁路：ProcessBuilder 以 argv 列表构造进程且不经 shell，archive 只是 unzip 的"
                   "一个参数；引号/分号/反引号在 argv 层全部失义。",
    "oracle_vuln": [
        (r'new String\[\]\{"sh", "-c", "unzip -o " \+ archive', "sink：sh -c 脚本位整体可控（数组形式仍注入）"),
    ],
    "oracle_safe": [
        (r'new ProcessBuilder\(List\.of\("unzip", "-o", archive', "防御：argv 列表无 shell"),
    ],
    "vuln_code": _code,
    "safe_code": '''package tools;

import java.util.List;

public class Unzip {
    public String extract(String archive) throws Exception {
        Process p = new ProcessBuilder(List.of("unzip", "-o", archive, "-d", "/srv/tmp"))
                .start();
        return new String(p.getInputStream().readAllBytes());
    }
}
''',
})

# ---------------- 78-S-06a Go：分片参数 ----------------
_code = '''package tools

import (
	"os/exec"
)

func Resolve(host string) (string, error) {
	// 经 shell 中转
	cmd := exec.Command("sh", "-c", "dig +short "+host)
	out, err := cmd.Output()
	return string(out), err
}
'''
P.append({
    "pid": "78-S-06", "lang": "Go", "cwe": "CWE-78",
    "anchor": VULN_ANCHOR,
    "safe_anchor": "防御为何不可旁路：exec.Command 直接收 argv 分片且 Go 的实现不经任何 shell，"
                   "host 作为 dig 的最后一个参数传入，`;`/反引号无解释层可作用。",
    "oracle_vuln": [
        (r'exec\.Command\("sh", "-c", "dig \+short "\+host\)', "sink：sh -c 中转拼接"),
    ],
    "oracle_safe": [
        (r'exec\.Command\("dig", "\+short", host\)', "防御：argv 分片直传，无 shell"),
    ],
    "vuln_code": _code,
    "safe_code": _code.replace(
        '\tcmd := exec.Command("sh", "-c", "dig +short "+host)',
        '\tcmd := exec.Command("dig", "+short", host)'),
})

# ---------------- 78-S-07a Node：execFile ----------------
_code = '''const express = require("express");
const { exec } = require("child_process");
const app = express();

app.get("/whois", (req, res) => {
  const domain = req.query.domain || "example.com";
  exec(`whois ${domain}`, { timeout: 5000 }, (err, stdout) => {
    if (err) return res.status(400).json({ error: "failed" });
    res.type("text").send(stdout);
  });
});

app.listen(8080);
'''
P.append({
    "pid": "78-S-07", "lang": "JavaScript", "cwe": "CWE-78",
    "anchor": VULN_ANCHOR,
    "safe_anchor": "防御为何不可旁路：execFile 默认不走 shell，domain 作为独立 argv 元素传给 whois，"
                   "`$(...)`/反引号/管道符只是字面字符。",
    "oracle_vuln": [
        (r'req\.query\.domain', "source：请求参数"),
        (r'exec\(`whois \$\{domain\}`', "sink：模板串进默认 shell"),
    ],
    "oracle_safe": [
        (r'execFile\("whois", \[domain\]', "防御：execFile 默认无 shell，argv 独立"),
    ],
    "vuln_code": _code,
    "safe_code": _code.replace(
        'const { exec } = require("child_process");',
        'const { execFile } = require("child_process");').replace(
        '  exec(`whois ${domain}`, { timeout: 5000 }, (err, stdout) => {',
        '  execFile("whois", [domain], { timeout: 5000 }, (err, stdout) => {'),
})

# ---------------- 78-S-08a PHP：escapeshellarg ----------------
_code = '''<?php
// api/ping.php
$host = $_GET['host'] ?? '127.0.0.1';
$out = shell_exec("ping -c 1 " . $host);
header('Content-Type: text/plain');
echo $out;
'''
P.append({
    "pid": "78-S-08", "lang": "PHP", "cwe": "CWE-78",
    "anchor": VULN_ANCHOR,
    "safe_anchor": "防御为何不可旁路：escapeshellarg 把 host 包成单引号字面量并转义内部引号（参数级转义），"
                   "注入文本只能作为 ping 的单个 argv 参数存在——注意与 escapeshellcmd（命令级，防多命令分隔）"
                   "的区别，此处需要的是参数级语义。",
    "oracle_vuln": [
        (r"\$_GET\['host'\]", "source：请求参数"),
        (r'shell_exec\("ping -c 1 " \. \$host\)', "sink：拼接进 shell 串"),
    ],
    "oracle_safe": [
        (r'escapeshellarg\(\$host\)', "防御：参数级转义，元字符字面化"),
    ],
    "vuln_code": _code,
    "safe_code": _code.replace(
        '$out = shell_exec("ping -c 1 " . $host);',
        '$out = shell_exec("ping -c 1 " . escapeshellarg($host));'),
})

# ---------------- 78-S-09a Python：列表形式仍注入（镜像 B） ----------------
_code = '''import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/ops/run")
def run():
    user_cmd = request.args.get("cmd", "echo hi")
    # 以为用了列表形式就安全
    r = subprocess.run(["sh", "-c", user_cmd], capture_output=True, timeout=5)
    return r.stdout.decode(errors="replace")
'''
P.append({
    "pid": "78-S-09", "lang": "Python", "cwe": "CWE-78",
    "anchor": "同为列表形式但 argv 含 `sh -c` 解释器语义参数，user_cmd 仍被 /bin/sh 完整解释——列表形式不豁免，"
              "仍归 78。" + MIRROR_NOTE + " 非 22（无路径穿越）/ 非 95（无 eval 求值）/ 非 74（目标 OS 命令）。",
    "safe_anchor": "防御为何不可旁路：argv 不再含任何解释器/语义参数（去 sh -c），指令以固定枚举映射为"
                   "预定义 argv；user_cmd 只作白名单 key，任何 shell 语法都进不了解释器（本来就没有解释器）。",
    "oracle_vuln": [
        (r'user_cmd = request\.args\.get\("cmd"', "source：请求参数"),
        (r'\["sh", "-c", user_cmd\]', "sink：列表形式但含 sh -c 解释器语义"),
    ],
    "oracle_safe": [
        (r'ALLOWED_COMMANDS', "防御：命令枚举白名单"),
        (r'ALLOWED_COMMANDS\[user_cmd\]', "输入仅作 key 选择"),
        (r'KeyError', "白名单外失败"),
    ],
    "vuln_code": _code,
    "safe_code": '''import subprocess
from flask import Flask, request

app = Flask(__name__)
ALLOWED_COMMANDS = {
    "echo": ["echo", "hi"],
    "date": ["date", "-u"],
}

@app.route("/ops/run")
def run():
    user_cmd = request.args.get("cmd", "date")
    try:
        argv = ALLOWED_COMMANDS[user_cmd]
    except KeyError:
        return "cmd not allowed", 400
    r = subprocess.run(argv, capture_output=True, timeout=5)
    return r.stdout.decode(errors="replace")
''',
})

# ---------------- 78-S-09b Go：git --upload-pack 语义参数 ----------------
_code = '''package gitapi

import (
	"os/exec"
)

func Fetch(userRepo string) ([]byte, error) {
	// userRepo 直达 --upload-pack 语义位：可携带 shell 元字符与任意子命令
	cmd := exec.Command("git", "clone", "--upload-pack="+userRepo, "example/repo")
	return cmd.Output()
}
'''
P.append({
    "pid": "78-S-09b", "lang": "Go", "cwe": "CWE-78",
    "anchor": "argv 虽为列表，但 --upload-pack 的参数会被 git 当作待执行程序（解释器语义参数位），"
              "userRepo 可指向 `/bin/sh -c ...` 形态实现命令执行——列表形式不豁免，归 78。"
              " 非 22/95/74 边界同 78 主锚句。",
    "safe_anchor": "防御为何不可旁路：去掉语义参数位，userRepo 只能是 clone 的 URL 参数位，且以域名白名单"
                   "前缀校验封闭取值空间；不存在任何'被 git 转交执行'的参数位。",
    "oracle_vuln": [
        (r'"--upload-pack="\+userRepo', "sink：用户数据占据程序执行语义参数位"),
        (r'userRepo string', "source：请求侧传入仓库名"),
    ],
    "oracle_safe": [
        (r'ALLOWED_GIT_HOSTS', "防御：域名白名单"),
        (r'exec\.Command\("git", "clone", repoURL\)', "argv 仅数据位，无语义参数"),
    ],
    "vuln_code": _code,
    "safe_code": '''package gitapi

import (
	"fmt"
	"os/exec"
	"strings"
)

var ALLOWED_GIT_HOSTS = []string{"github.com/example/", "git.example.com/mirror/"}

func Fetch(userRepo string) ([]byte, error) {
	ok := false
	for _, p := range ALLOWED_GIT_HOSTS {
		if strings.HasPrefix(userRepo, p) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("repo not allowed")
	}
	repoURL := "https://" + userRepo
	cmd := exec.Command("git", "clone", repoURL)
	return cmd.Output()
}
''',
})

# ---------------- 78-S-10a Python：sudo 子命令 ----------------
_code = '''import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/admin/svc")
def svc():
    action = request.args.get("action", "status")
    # sudo 后接用户可控子命令
    r = subprocess.run(f"sudo systemctl {action} order-service", shell=True,
                       capture_output=True, timeout=10)
    return r.stdout.decode(errors="replace")
'''
P.append({
    "pid": "78-S-10", "lang": "Python", "cwe": "CWE-78",
    "anchor": "sudo 提权面 + 用户可控子命令：action 拼进 shell 串且继承 root 身份，注入即 root RCE，归 78。"
              " 非 22/95/74 边界同主锚句；非 862 因为缺陷不是授权检查缺失而是提权执行链可控。",
    "safe_anchor": "防御为何不可旁路：action 只能选 ACTIONS 白名单内的受控 argv；sudoers 侧约定固定身份，"
                   "即便注入也不存在可写变量/拼接位；argv 无 shell 层。",
    "oracle_vuln": [
        (r'action = request\.args\.get\("action"', "source：请求参数"),
        (r'f"sudo systemctl \{action\} order-service", shell=True', "sink：提权命令拼接"),
    ],
    "oracle_safe": [
        (r'ACTIONS', "防御：动作白名单"),
        (r'\["sudo", "-n", "/usr/bin/systemctl', "固定提权程序 + argv 无 shell"),
        (r'KeyError', "白名单外失败"),
    ],
    "vuln_code": _code,
    "safe_code": '''import subprocess
from flask import Flask, request

app = Flask(__name__)
ACTIONS = {
    "status": ["sudo", "-n", "/usr/bin/systemctl", "status", "order-service"],
    "restart": ["sudo", "-n", "/usr/bin/systemctl", "restart", "order-service"],
}

@app.route("/admin/svc")
def svc():
    action = request.args.get("action", "status")
    try:
        argv = ACTIONS[action]
    except KeyError:
        return "action not allowed", 400
    r = subprocess.run(argv, capture_output=True, timeout=10)
    return r.stdout.decode(errors="replace")
''',
})

# ---------------- 78-S-10b Java：sudo -u 变体 ----------------
_code = '''package admin;

public class BatchRunner {
    public String runAs(String user, String job) throws Exception {
        // sudo -u 后接可控 user 与 job
        Process p = Runtime.getRuntime().exec("sudo -u " + user + " /usr/bin/batch-run " + job);
        return new String(p.getInputStream().readAllBytes());
    }
}
'''
P.append({
    "pid": "78-S-10b", "lang": "Java", "cwe": "CWE-78",
    "anchor": "sudo -u 提权 + user/job 双可控位拼接（exec 单串按空格拆分且经默认 shell 语义），注入即越权执行，"
              "归 78；非 22/95/74 边界同主锚句。",
    "safe_anchor": "防御为何不可旁路：user 只能选 RUN_USERS 枚举，job 只能选 JOBS 枚举；ProcessBuilder argv "
                   "列表不经 shell，两个可控输入都退化为『从枚举中选择』。",
    "oracle_vuln": [
        (r'"sudo -u " \+ user \+ " /usr/bin/batch-run " \+ job', "sink：提权串拼接（双可控位）"),
        (r'Runtime\.getRuntime\(\)\.exec\(', "单串 exec"),
    ],
    "oracle_safe": [
        (r'RUN_USERS', "防御：身份枚举"),
        (r'JOBS', "任务枚举"),
        (r'new ProcessBuilder\(', "argv 列表无 shell"),
    ],
    "vuln_code": _code,
    "safe_code": '''package admin;

import java.util.List;
import java.util.Map;

public class BatchRunner {
    private static final List<String> RUN_USERS = List.of("batch");
    private static final Map<String, String> JOBS = Map.of("nightly", "/opt/jobs/nightly.sh",
                                                           "reindex", "/opt/jobs/reindex.sh");

    public String runAs(String user, String job) throws Exception {
        if (!RUN_USERS.contains(user) || !JOBS.containsKey(job)) {
            throw new IllegalArgumentException("not allowed");
        }
        Process p = new ProcessBuilder(List.of("sudo", "-n", "-u", user,
                "/usr/bin/batch-run", JOBS.get(job))).start();
        return new String(p.getInputStream().readAllBytes());
    }
}
''',
})

# ---------------- 78-S-02b Java：单串 exec → 列表 ----------------
_code = '''package diag;

public class Ping {
    public String ping(String host) throws Exception {
        // 数组形式 sh -c：脚本位整体可控，host 含 `; rm -rf /` 即成第二命令
        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping -c 1 " + host});
        return new String(p.getInputStream().readAllBytes());
    }
}
'''
P.append({
    "pid": "78-S-02b", "lang": "Java", "cwe": "CWE-78",
    "anchor": "数组形式但 argv 含 sh -c 解释器语义参数：脚本位整体可控，归 78（镜像 S-09 同轴）；"
              "非 22（无路径穿越）/ 非 95（无 eval 求值）/ 非 74（目标 OS 命令）。预审修订版 20260913。",
    "safe_anchor": "防御为何不可旁路：ProcessBuilder argv 列表逐元素传给 execve，无 shell、无再分词，"
                   "host 即便含空格/分号也只是单个参数的组成部分。",
    "oracle_vuln": [
        (r'new String\[\]\{"sh", "-c", "ping -c 1 " \+ host\}', "sink：sh -c 脚本位整体可控（数组形式仍注入）"),
        (r'host\)', "source：请求侧传入 host"),
    ],
    "oracle_safe": [
        (r'new ProcessBuilder\("ping", "-c", "1", host\)', "防御：argv 列表无 shell"),
    ],
    "vuln_code": _code,
    "safe_code": '''package diag;

public class Ping {
    public String ping(String host) throws Exception {
        Process p = new ProcessBuilder("ping", "-c", "1", host).start();
        return new String(p.getInputStream().readAllBytes());
    }
}
''',
})

# ---------------- 78-S-04b Go：模板派发 ----------------
_code = '''package report

import (
	"fmt"
	"os/exec"
)

func Build(kind, date string) ([]byte, error) {
	cmd := fmt.Sprintf("/usr/bin/report --kind %s --date %s", kind, date)
	return exec.Command("sh", "-c", cmd).Output()
}
'''
P.append({
    "pid": "78-S-04b", "lang": "Go", "cwe": "CWE-78",
    "anchor": VULN_ANCHOR + " kind/date 拼出整条命令后经 sh -c 解释，双可控位。",
    "safe_anchor": "防御为何不可旁路：kind 只能命中 reportArgs 白名单表的 key，date 走日期格式硬校验；"
                   "argv 分片不经 shell，模板字典的取值空间被枚举封闭。",
    "oracle_vuln": [
        (r'cmd := fmt\.Sprintf\("/usr/bin/report', "sink：Sprintf 拼出整条命令"),
        (r'exec\.Command\("sh", "-c", cmd\)', "sh -c 解释"),
    ],
    "oracle_safe": [
        (r'reportArgs = map\[string\]\[\]string', "防御：模板字典"),
        (r'dateRE\.MatchString\(date\)', "date 格式硬校验"),
        (r'exec\.Command\(argv\[0\], argv\[1:\]\.\.\.\)', "argv 分片无 shell"),
    ],
    "vuln_code": _code,
    "safe_code": '''package report

import (
	"os/exec"
	"regexp"
)

var reportArgs = map[string][]string{
	"weekly": {"/usr/bin/report", "--kind", "weekly"},
	"daily":  {"/usr/bin/report", "--kind", "daily"},
}

var dateRE = regexp.MustCompile(`^\\d{4}-\\d{2}-\\d{2}$`)

func Build(kind, date string) ([]byte, error) {
	argv, ok := reportArgs[kind]
	if !ok {
		return nil, fmt.Errorf("kind not allowed")
	}
	if !dateRE.MatchString(date) {
		return nil, fmt.Errorf("bad date")
	}
	argv = append(append([]string{}, argv...), "--date", date)
	return exec.Command(argv[0], argv[1:]...).Output()
}
'''.replace("import (\n\t\"os/exec\"",
            "import (\n\t\"fmt\"\n\t\"os/exec\""),
})

# ---------------- 78-S-01b Python：os.system → 列表 ----------------
_code = '''import os
from flask import Flask, request

app = Flask(__name__)

@app.route("/diag/traceroute")
def traceroute():
    host = request.args.get("host", "127.0.0.1")
    os.system(f"traceroute -m 5 {host} > /tmp/trace.txt")
    with open("/tmp/trace.txt", encoding="utf-8", errors="replace") as f:
        return f.read()
'''
P.append({
    "pid": "78-S-01b", "lang": "Python", "cwe": "CWE-78",
    "anchor": VULN_ANCHOR + " os.system 恒经 /bin/sh，f-string 注入位在 root/服务身份下执行。",
    "safe_anchor": "防御为何不可旁路：subprocess.run argv 列表无 shell 解释层，host 只能是 traceroute 的"
                   "单个参数；重定向改由 capture_output 在进程内完成，`>` 元字符失义。",
    "oracle_vuln": [
        (r'os\.system\(f"traceroute -m 5 \{host\} > /tmp/trace\.txt"\)', "sink：os.system 恒经 shell"),
        (r'host = request\.args\.get\("host"', "source：请求参数"),
    ],
    "oracle_safe": [
        (r'subprocess\.run\(\["traceroute", "-m", "5", host\]', "防御：argv 列表无 shell"),
        (r'capture_output=True', "重定向由进程管道完成"),
    ],
    "vuln_code": _code,
    "safe_code": '''import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/diag/traceroute")
def traceroute():
    host = request.args.get("host", "127.0.0.1")
    r = subprocess.run(["traceroute", "-m", "5", host], capture_output=True, timeout=30)
    return r.stdout.decode(errors="replace")
''',
})

# ---------------- 78-S-15 Go：find -exec 语义参数 ----------------
_code = '''package cleaner

import (
	"os/exec"
)

func Purge(name string) ([]byte, error) {
	// -exec 执行体位直接由外部传入：name 即被执行的程序
	return exec.Command("find", "/var/tmp", "-type", "f", "-exec", name, "{}", ";").Output()
}
'''
P.append({
    "pid": "78-S-15", "lang": "Go", "cwe": "CWE-78",
    "anchor": "argv 为列表但 `-exec` 的执行体位（程序名）直接由外部 name 占据，find 将以当前进程权限执行 name 指定程序"
              "——列表形式不豁免，归 78。非 22（无路径穿越主叙事）/ 非 95（无 eval 求值）/ 非 74 抽象层同 78 主锚句。预审修订版 20260913。",
    "safe_anchor": "防御为何不可旁路：name 经 basename 化 + 白名单字符校验，删除动作由固定 argv 集合完成且"
                   "限定在 PURGE_ROOT 目录内；不存在可注入的解释器或执行语义参数位。",
    "oracle_vuln": [
        (r'"-exec", name, "\{\}", ";"', "sink：-exec 执行体位由外部 name 占据"),
        (r'func Purge\(name string\)', "source：name 外部传入"),
    ],
    "oracle_safe": [
        (r'nameRE = regexp', "防御：文件名白名单（首字符限字母数字，封死 ..）"),
        (r'filepath\.Join\("/var/tmp", filepath\.Base\(name\)\)', "Join 结果被 Base 化输入约束在上跳之外"),
        (r'filepath\.Base\(name\)', "basename 化，防路径成分"),
        (r'exec\.Command\("rm", append\(\[\]string\{"-rf"\}, target\)', "固定删除动作，目标经校验"),
    ],
    "vuln_code": _code,
    "safe_code": '''package cleaner

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
)

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`) // 首字符限字母数字，封死 ".."

func Purge(name string) ([]byte, error) {
	if !nameRE.MatchString(name) {
		return nil, fmt.Errorf("name not allowed")
	}
	target := filepath.Join("/var/tmp", filepath.Base(name))
	return exec.Command("rm", append([]string{"-rf"}, target)...).Output()
}
''',
})

if __name__ == "__main__":
    made, failed = emit("CWE-78-safe", P, max_diff=10)
    print(f"78-safe: made {len(made)} failed {len(failed)}")
    for pid, errs in failed:
        print("  FAIL", pid, errs)
    (Path(__file__).resolve().parents[1] / "corpus/diffpair_wave1/wave2_pairs" / "_index_78safe.md") \
        .write_text("\n".join(write_index("CWE-78-safe", made)) + "\n", encoding="utf-8")
