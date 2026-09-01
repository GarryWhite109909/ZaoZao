# -*- coding: utf-8 -*-
"""生成 g23(F10 伴生凭证 vs 主洞)+g24(案例 D 族边界锚)任务包(30 条)。

g23  secret 候选诱饵 + 主洞 352×3/384×2/639×3/862×2/434×2 = 12 条
     每条均附 bandit 硬编码凭证位置候选(E2),教师应判主类型=攻击面语义,
     CWE-798 同时成立但不得作为 top1,伴生事实写入 explanation
g24  352 锚×4(CSRF vs XSS 边界,含 1 条 79 主反例) + 843 锚×4(PHP 弱比较)
     + 77↔78 对×6(shell 解释层判据) + 94↔95 对×4(直接求值 vs 生成代码文本)
     = 18 条,全部裸判(无工具候选块,g20 twins 同形态)

orig 命名: g23-<主洞>-NN ; g24-csrf-NN / g24-php-NN / g24-cmd-NN / g24-code-NN
蒸馏后按 orig 前缀从 _wave1_out/success.jsonl 过滤合并。
"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]  # exp_06_finetune/
OUT = BASE / "corpus/repair_wave/wave2_g21_24"
OUT.mkdir(parents=True, exist_ok=True)

TAIL = "\n\n请先给出分析过程，然后在最后给出 JSON 结论。"


def cand(tool, level, desc):
    return f"\n\n【工具候选】{tool}（证据层级 {level}）——{desc}"


# ---------------------------------------------------------------- g23 F10
G23 = []

G23.append(("g23-csrf-01", "python", '''
# billing/card_update.py
from flask import Flask, request, redirect

from auth import session_uid, new_csrf_token
import db

app = Flask(__name__)

# 内部结算网关密钥,写死便于多实例共享
GATEWAY_SECRET = "sk_live_9f2c4e8a17b6d3e5"

@app.get("/billing/card")
def card_form():
    # 模板内嵌 csrf_token 隐藏域,供前端展示对齐
    return ('<form method="POST" action="/billing/card">'
            '<input type="hidden" name="csrf_token" value="'
            + new_csrf_token() + '">'
            '<input name="card_no"><button>Update</button></form>')

@app.post("/billing/card")
def card_update():
    # 直接进入业务处理:网关按会话 Cookie 归属账户
    uid = session_uid(request)
    db.update_card(uid, request.form["card_no"])
    return redirect("/billing/card")
'''.strip("\n"), cand("bandit 硬编码审计", "E2·位置型", "line 10 报告硬编码凭证字符串命中(未给出编号)")))

G23.append(("g23-csrf-02", "python", '''
# settings/notify_setup.py
from flask import Flask, request, redirect

from auth import current_user
import db

app = Flask(__name__)

# 通知服务对接密钥,随镜像分发
NOTIFY_SECRET = "ntf_sk_8812ffa90b4c"

@app.post("/settings/notify")
def save_notify():
    # 表单携带 notify_token 字段,服务端不做比对
    user = current_user(request)
    db.set_notify(user["id"], request.form["webhook_url"])
    return redirect("/settings")

@app.get("/settings/notify")
def notify_form():
    # 回显设置表单,含 token 字段
    return ('<form method="POST" action="/settings/notify">'
            '<input type="hidden" name="notify_token" value="t-2026">'
            '<input name="webhook_url"><button>Save</button></form>')
'''.strip("\n"), cand("bandit 硬编码审计", "E2·位置型", "line 10 报告硬编码凭证字符串命中(未给出编号)")))

G23.append(("g23-csrf-03", "python", '''
# api/email_change.py
from flask import Flask, request, jsonify

from auth import session_uid
import db

app = Flask(__name__)

# 邮件服务 API key,写死在模块顶层
MAIL_API_KEY = "mk_live_5d21c9ab77e0"

@app.post("/api/email/change")
def change_email():
    # 前端会在表单带上 csrf 字段,服务端不读取该字段
    uid = session_uid(request)
    db.update_email(uid, request.json["new_email"])
    return jsonify({"ok": True})
'''.strip("\n"), cand("bandit 硬编码审计", "E2·位置型", "line 10 报告硬编码凭证字符串命中(未给出编号)")))

G23.append(("g23-fix-01", "python", '''
# auth/login_flow.py
import secrets

from flask import Flask, request, make_response

app = Flask(__name__)
SESSIONS = {}  # sid -> user_id

# 邮件网关口令,写死供各实例共用
SMTP_PASSWORD = "mailpass!2026"

@app.post("/login")
def login():
    uid = check_password(request.form["username"], request.form["password"])
    if uid is None:
        return {"ok": False}, 401
    # 已有会话标识则沿用,保留匿名期间的选择状态
    sid = request.cookies.get("SID") or secrets.token_hex(16)
    SESSIONS[sid] = uid
    resp = make_response({"ok": True})
    resp.set_cookie("SID", sid, httponly=True)
    return resp
'''.strip("\n"), cand("bandit 硬编码审计", "E2·位置型", "line 10 报告硬编码口令字符串命中(未给出编号)")))

G23.append(("g23-fix-02", "python", '''
# auth/password_reset.py
from flask import Flask, request

app = Flask(__name__)
SESSIONS = {}  # sid -> user_id
RESETS = {}    # reset_token -> user_id

# 第三方风控接口密钥
RISK_API_KEY = "rk_live_77c01dd9a2"

@app.post("/password/confirm")
def confirm_reset():
    uid = RESETS.pop(request.json["reset_token"], None)
    if uid is None:
        return {"ok": False}, 400
    set_new_password(uid, request.json["new_password"])
    # 重置完成后保持当前会话标识不变
    SESSIONS[request.cookies.get("SID")] = uid
    return {"ok": True}
'''.strip("\n"), cand("bandit 硬编码审计", "E2·位置型", "line 9 报告硬编码密钥字符串命中(未给出编号)")))

G23.append(("g23-idor-01", "python", '''
# api/invoices.py
from flask import Flask, request, jsonify

import db

app = Flask(__name__)

# 支付网关密钥,部署脚本回填至此
STRIPE_SECRET = "sk_test_51HqX9p2mZx"

@app.get("/api/invoices/<int:inv_id>")
def get_invoice(inv_id):
    inv = db.query_one("SELECT * FROM invoices WHERE id = %s", (inv_id,))
    if inv is None:
        return jsonify({"error": "not found"}), 404
    # 按路径参数返回票据详情
    return jsonify(inv)
'''.strip("\n"), cand("bandit 硬编码审计", "E2·位置型", "line 9 报告硬编码密钥字符串命中(未给出编号)")))

G23.append(("g23-idor-02", "python", '''
# api/profile_admin.py
from flask import Flask, request, jsonify

import db

app = Flask(__name__)

# 短信服务密钥常量
SMS_KEY = "sms_live_90ab12ff"

@app.put("/api/users/<int:uid>/profile")
def update_profile(uid):
    # 按路径 uid 更新资料,字段以请求体为准
    db.update_user(uid, request.json)
    return jsonify({"ok": True})
'''.strip("\n"), cand("bandit 硬编码审计", "E2·位置型", "line 9 报告硬编码密钥字符串命中(未给出编号)")))

G23.append(("g23-idor-03", "python", '''
# api/object_files.py
from flask import Flask, request, jsonify

import store

app = Flask(__name__)

# 对象存储访问密钥,写死以便离线环境使用
STORE_SECRET = "st_live_4419cc0e8b"

@app.delete("/api/files/<fid>")
def delete_file(fid):
    # 按文件标识删除对象
    store.remove(fid)
    return jsonify({"ok": True})
'''.strip("\n"), cand("bandit 硬编码审计", "E2·位置型", "line 9 报告硬编码密钥字符串命中(未给出编号)")))

G23.append(("g23-authz-01", "python", '''
# admin/user_admin.py
from flask import Flask, request, session, jsonify

import db

app = Flask(__name__)

# 初始化管理员账号口令,首次部署使用
DEFAULT_ADMIN_PASS = "admin#2026"

@app.post("/admin/users/delete")
def delete_user():
    # 管理操作:登录会话存在即可执行
    if "uid" not in session:
        return {"error": "login required"}, 401
    db.delete_user(request.json["target_uid"])
    return {"ok": True}
'''.strip("\n"), cand("bandit 硬编码审计", "E2·位置型", "line 9 报告硬编码口令字符串命中(未给出编号)")))

G23.append(("g23-authz-02", "python", '''
# admin/report_export.py
from flask import Flask, request, session

import db

app = Flask(__name__)

# 导出数据落对象存储,访问密钥写死
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG"

@app.get("/admin/reports/export")
def export_report():
    # 会话存在即放行导出
    if "uid" not in session:
        return {"error": "login required"}, 401
    rows = db.all_orders()
    return render_csv(rows)
'''.strip("\n"), cand("bandit 硬编码审计", "E2·位置型", "line 9 报告硬编码密钥字符串命中(未给出编号)")))

G23.append(("g23-up-01", "python", '''
# uploads/receipt.py
import os

from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

# OCR 服务共享令牌
OCR_TOKEN = "ocr_tok_3c9d81aa"

@app.post("/receipt/upload")
def upload():
    f = request.files["file"]
    # 收据影像落盘,文件名做路径归一
    fname = secure_filename(f.filename)
    f.save(os.path.join("/data/receipts", fname))
    return {"ok": True}
'''.strip("\n"), cand("bandit 硬编码审计", "E2·位置型", "line 10 报告硬编码令牌字符串命中(未给出编号)")))

G23.append(("g23-up-02", "python", '''
# uploads/avatar_api.py
from flask import Flask, request

app = Flask(__name__)

# 告警 webhook 签名密钥常量
HOOK_SECRET = "hook_sk_66ee02c1"

@app.post("/avatar/upload")
def upload_avatar():
    f = request.files["image"]
    # 仅检查大小上限,类型以客户端声明的 content-type 为准
    if f.content_length and f.content_length > 5 * 1024 * 1024:
        return {"error": "too large"}, 400
    save_avatar(f)
    return {"ok": True}
'''.strip("\n"), cand("bandit 硬编码审计", "E2·位置型", "line 7 报告硬编码密钥字符串命中(未给出编号)")))

# ---------------------------------------------------------------- g24 案例 D
G24 = []

G24.append(("g24-csrf-01", "python", '''
# account/password_page.py
from flask import Flask, request, redirect

from auth import current_user, new_csrf_token
import db

app = Flask(__name__)

@app.get("/account/password")
def password_form():
    return ('<form method="POST" action="/account/password">'
            '<input type="hidden" name="csrf_token" value="'
            + new_csrf_token() + '">'
            '<input name="old_pwd" type="password">'
            '<input name="new_pwd" type="password">'
            '<button>Change</button></form>')

@app.post("/account/password")
def password_change():
    # 服务端读取业务字段后直接执行,表单中的 csrf_token 字段未被读取
    user = current_user(request)
    db.change_password(user["id"], request.form["new_pwd"])
    return redirect("/account/password")
'''.strip("\n"), None))

G24.append(("g24-csrf-02", "python", '''
# social/follow_page.py
from flask import Flask, request, redirect, render_template_string

from auth import current_user
import db

app = Flask(__name__)

PAGE = """
  <p>Hello {{ name }}</p>
  <form method="POST" action="/social/follow">
    <input type="hidden" name="ft" value="static-mark">
    <input name="target"><button>Follow</button></form>
"""

@app.get("/social/follow")
def follow_form():
    # Jinja 默认 autoescape 开启
    return render_template_string(PAGE, name=current_user(request)["name"])

@app.post("/social/follow")
def follow_submit():
    # 表单带 ft 字段,服务端不校验
    db.add_follow(current_user(request)["id"], request.form["target"])
    return redirect("/social/follow")
'''.strip("\n"), None))

G24.append(("g24-csrf-03", "python", '''
# account/deactivate.py
from flask import Flask, request, redirect

from auth import current_user
import db

app = Flask(__name__)

DEACT_FORM = ('<form method="POST" action="/account/deactivate">'
              '<input type="hidden" name="confirm" value="yes">'
              '<button>Deactivate</button></form>')

@app.route("/account/deactivate", methods=["GET", "POST"])
def deactivate():
    if request.method == "POST":
        # 表单的 confirm 字段服务端不读取
        db.deactivate(current_user(request)["id"])
        return redirect("/")
    msg = request.args.get("msg", "Confirm?")
    # 提示语直接拼进返回页
    return "<p>" + msg + "</p>" + DEACT_FORM
'''.strip("\n"), None))

G24.append(("g24-csrf-04", "python", '''
# board/guestbook.py
from flask import Flask, request, redirect

from auth import current_user, csrf_ok
import db

app = Flask(__name__)

@app.post("/board/sign")
def sign():
    # 服务端显式校验表单 token,不通过则拒绝
    if not csrf_ok(request):
        return {"error": "bad token"}, 403
    db.add_entry(current_user(request)["id"], request.form["text"])
    return redirect("/board/view")

@app.get("/board/view")
def view():
    html = "<h1>Guestbook</h1>"
    for e in db.entries():
        html += "<p>" + e["text"] + "</p>"
    return html
'''.strip("\n"), None))

G24.append(("g24-php-01", "php", '''
<?php
// admin/debug_gate.php
session_start();
// 运维交接文档记录:调试口令的 legacy 摘要为 0e 开头纯数字串
$stored = "0e1137126901";
$provided = $_GET['debug_key'] ?? '';
if ($provided == $stored) {
    $_SESSION['debug'] = true;
    include __DIR__ . '/debug_panel.php';
    exit;
}
http_response_code(404);
'''.strip("\n"), None))

G24.append(("g24-php-02", "php", '''
<?php
// admin/login_check.php
session_start();
$real = load_admin_password();
if (strcmp($_POST['password'], $real) == 0) {
    $_SESSION['admin'] = true;
    header('Location: /admin/index.php');
    exit;
}
http_response_code(401);
'''.strip("\n"), None))

G24.append(("g24-php-03", "php", '''
<?php
// pay/withdraw_limit.php
session_start();
// 单笔提现门槛:余额达到该值才可发起
$threshold = "1000";
if ($_POST['balance'] == $threshold) {
    queue_withdraw($_SESSION['uid'], $_POST['balance']);
    exit;
}
http_response_code(403);
'''.strip("\n"), None))

G24.append(("g24-php-04", "php", '''
<?php
// api/plan_gate.php
$paid_plans = [100, 200, 300];  // 付费套餐 ID 白名单
$plan = $_GET['plan'];
if (in_array($plan, $paid_plans)) {
    unlock_premium($plan);
    exit;
}
http_response_code(402);
'''.strip("\n"), None))

G24.append(("g24-cmd-01", "python", '''
# ops/ping_probe.py
import os

from flask import Flask, request

app = Flask(__name__)

@app.get("/net/probe")
def probe():
    host = request.args["host"]
    # 网络连通性探测
    out = os.popen("ping -c 1 " + host).read()
    return {"out": out}
'''.strip("\n"), None))

G24.append(("g24-cmd-02", "javascript", '''
// ops/archive_service.js
const { execSync } = require('child_process');
const express = require('express');
const app = express();
app.use(express.json());

app.post('/ops/archive', (req, res) => {
  const branch = req.body.branch;
  // 按指定分支打包构建产物
  const out = execSync('tar czf /tmp/build.tgz build-' + branch, {
    shell: '/bin/bash',
  });
  res.json({ ok: true, size: out.length });
});
app.listen(8080);
'''.strip("\n"), None))

G24.append(("g24-cmd-03", "java", '''
// src/main/java/media/ImageBatch.java
package media;

public class ImageBatch {
    public String convert(String imgPath) throws Exception {
        String[] cmd = { "/bin/bash", "-c", "convert " + imgPath + " out.png" };
        Process p = Runtime.getRuntime().exec(cmd);
        byte[] out = p.getInputStream().readAllBytes();
        return new String(out);
    }
}
'''.strip("\n"), None))

G24.append(("g24-cmd-04", "python", '''
# agent/task_api.py
import shlex
import subprocess

from flask import Flask, request

app = Flask(__name__)

@app.post("/agent/task")
def run_user_task():
    # 自定义任务指令整体由请求体下发
    args = shlex.split(request.json["cmd"])
    proc = subprocess.run(args, shell=False, capture_output=True)
    return {"rc": proc.returncode}
'''.strip("\n"), None))

G24.append(("g24-cmd-05", "javascript", '''
// plugins/launcher.js
const { spawn } = require('child_process');
const express = require('express');
const app = express();
app.use(express.json());

app.post('/plugins/run', (req, res) => {
  const { bin, args } = req.body;
  // 不经 shell,直接拉起指定可执行文件
  const child = spawn(bin, args, { shell: false });
  child.stdout.on('data', () => {});
  child.on('close', (code) => res.json({ code }));
});
app.listen(8080);
'''.strip("\n"), None))

G24.append(("g24-cmd-06", "go", '''
// tools/runner.go
package tools

import (
	"os/exec"

	"github.com/gin-gonic/gin"
)

// RunTool: 租户在控制台指定工具名与参数
func RunTool(c *gin.Context) {
	var body struct {
		Tool string   `json:"tool"`
		Args []string `json:"args"`
	}
	_ = c.ShouldBindJSON(&body)
	cmd := exec.Command(body.Tool, body.Args...)
	out, _ := cmd.CombinedOutput()
	c.JSON(200, gin.H{"out": string(out)})
}
'''.strip("\n"), None))

G24.append(("g24-code-01", "python", '''
# calc/evaluate.py
from flask import Flask, request

app = Flask(__name__)

@app.get("/calc")
def calc():
    # 表达式计算器:直接求值用户提交的表达式
    expr = request.args["expr"]
    result = eval(expr)
    return {"result": str(result)}
'''.strip("\n"), None))

G24.append(("g24-code-02", "javascript", '''
// plugins/hook_eval.js
const express = require('express');
const app = express();
app.use(express.json());

app.post('/plugins/hook', (req, res) => {
  const hook = req.body.hook;
  // 插件钩子直接求值执行
  const fn = eval('(' + hook + ')');
  fn();
  res.json({ ok: true });
});
app.listen(8080);
'''.strip("\n"), None))

G24.append(("g24-code-03", "python", '''
# dsl/handler_gen.py
from flask import Flask, request

app = Flask(__name__)

@app.post("/dsl/handler")
def make_handler():
    name = request.json["name"]
    body = request.json["body"]
    # 按用户名与函数体动态生成处理函数源码
    src = f"def handler_{name}():\\n    return {body}\\n"
    ns = {}
    exec(compile(src, "<gen>", "exec"), ns)
    return {"result": ns[f"handler_{name}"]()}
'''.strip("\n"), None))

G24.append(("g24-code-04", "java", '''
// src/main/java/report/FormulaEval.java
package report;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

public class FormulaEval {
    public Object eval(String expr) {
        ExpressionParser parser = new SpelExpressionParser();
        // 报表公式解析:表达式由前端传入
        return parser.parseExpression(expr)
                .getValue(new StandardEvaluationContext());
    }
}
'''.strip("\n"), None))


def write_out(name, rows):
    path = OUT / name
    with path.open("w", encoding="utf-8") as f:
        for orig, lang, code, extra in rows:
            user = f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```"
            if extra:
                user += extra
            user += TAIL
            f.write(json.dumps({"orig": orig, "user": user}, ensure_ascii=False) + "\n")
    print(f"{name}: {len(rows)}")


def main():
    write_out("g23.jsonl", G23)
    write_out("g24.jsonl", G24)
    print("\n== 自检:行数与候选行号 ==")
    for orig, lang, code, extra in G23 + G24:
        n = len(code.splitlines())
        low = code.lower()
        feats = []
        for kw in ("secret", "key", "pass", "token", "csrf", "==", "strcmp",
                   "in_array", "popen", "execsync", "bash", "spawn", "exec.command",
                   "shlex", "eval(", "exec(", "parseexpression"):
            if kw in low:
                feats.append(kw.strip("=("))
        cl = ""
        if extra:
            import re
            m = re.search(r"line (\d+)", extra)
            if m:
                k = int(m.group(1))
                cl = f" | candL{k}: {code.splitlines()[k-1][:40] if k <= n else '<越界!>'}"
        print(f"  {orig}: {n} 行 | {','.join(feats[:5])}{cl}")


if __name__ == "__main__":
    main()
