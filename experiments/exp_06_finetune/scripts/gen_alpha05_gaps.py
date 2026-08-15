# -*- coding: utf-8 -*-
"""α0.5 覆盖短板补充生成器。

针对审计发现的覆盖缺口：
  1. CWE-20  Improper Input Validation（Top25，训练 0 条）
  2. CWE-119  Buffer Errors（Top25，训练 0 条，C/C++）
  3. CWE-269  Improper Privilege Management（Top25，训练 0 条）
  4. CWE-863  Incorrect Authorization（Top25，训练 0 条）
  5. CWE-287  Authentication Bypass（训练仅 6 条，α0 认证类错标重灾区，扩量）
  6. CWE-434  Unrestricted Upload（训练 29 条/16 骨架，扩量）
  7. CWE-1333 ReDoS（训练 21 条/14 骨架，扩量）
  8. A06      易受攻击组件（依赖漏洞：log4j/fastjson/lodash 等真实 CVE 场景）

每条：正例 + CoT（含必要归因/干扰项排除）+ 标准 JSON。输出：data/supplement_alpha05_gaps.jsonl
"""
import json, re, sys
from pathlib import Path

ROOT = Path(r"D:\code\毕业设计\Graduation-Project")
DATA = ROOT / "experiments" / "exp_06_finetune" / "data"
OUT = DATA / "supplement_alpha05_gaps.jsonl"

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


records = []


def add(code, lang, analysis, verdict):
    records.append(make_record(code, lang, analysis, verdict))


# ============================================================
# 1. CWE-20 输入验证缺失（0 → +7）
# ============================================================
add("""
import struct
from flask import Flask, request

app = Flask(__name__)


@app.route("/pack", methods=["POST"])
def pack():
    raw = request.get_data()
    # 未校验 raw 长度是否 >= 4 字节
    n = struct.unpack("<I", raw[:4])[0]
    return f"count={n}"
""", "python",
    "分析过程：\n"
    "1. line 11: `request.get_data()` 用户可控，直接 `struct.unpack(\"<I\", raw[:4])` 解析。\n"
    "2. **未校验长度**：raw 不足 4 字节时 unpack 抛异常（信息泄露/DoS）；同时 n 来自不可信输入未做范围校验。\n"
    "3. 核心缺陷是**缺少输入验证**（边界/长度/范围都未检查）→ CWE-20。\n"
    "4. 结论：CWE-20 Improper Input Validation，风险 Medium。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-20 Improper Input Validation",
     "risk_level": "Medium", "source": "line 10: request.get_data() 用户可控",
     "sink": "line 11: 未校验长度直接 unpack/解析",
     "explanation": "raw 未验证长度/范围 -> 解析异常/越界 -> CWE-20 输入验证缺失",
     "fix_suggestion": "line 11: 先校验 len(raw)>=4 且对解析值做范围检查"})

add("""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()


@app.post("/order/amount")
async def order_amount(request: Request):
    body = await request.json()
    qty = int(body.get("qty", "0"))
    price = int(body.get("price", "0"))
    total = qty * price
    return JSONResponse({"total": total})
""", "python",
    "分析过程：\n"
    "1. line 8-9: `int(body.get(...))` 解析用户输入，但**未做数值范围校验**。\n"
    "2. 超大 qty/price（如 10^18）相乘可溢出；负数可绕过业务约束。\n"
    "3. 核心缺陷是**输入验证缺失**（无范围/类型约束）→ CWE-20。\n"
    "4. 结论：CWE-20 Improper Input Validation，风险 Low-Medium。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-20 Improper Input Validation",
     "risk_level": "Low", "source": "line 8: body qty 用户可控",
     "sink": "line 10: 未校验范围的数值运算",
     "explanation": "qty/price 未做范围校验 -> 溢出/绕过业务约束 -> CWE-20",
     "fix_suggestion": "line 8-9: 校验数值范围（如 0<=n<=MAX）后再运算"})


# ============================================================
# 2. CWE-119 缓冲区溢出（C/C++，0 → +5）
# ============================================================
add("""
#include <stdio.h>
#include <string.h>

void greet(char *user) {
    char buf[16];
    strcpy(buf, user);   // 无边界复制
    printf("Hello %s\\n", buf);
}

int main(int argc, char **argv) {
    greet(argv[1]);
    return 0;
}
""", "c",
    "分析过程：\n"
    "1. line 5: `strcpy(buf, user)` 把用户可控字符串复制到固定 16 字节缓冲区，**无边界检查**。\n"
    "2. 超长输入直接溢出栈上 buf，覆盖返回地址 → 任意代码执行。\n"
    "3. 核心缺陷是**缓冲区边界错误** → CWE-119（CWE-121 栈溢出子类）。\n"
    "4. 结论：CWE-119 Buffer Errors，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-119 Buffer Errors (CWE-121 Stack-based Overflow)",
     "risk_level": "Critical", "source": "line 9: argv[1] 用户可控",
     "sink": "line 5: strcpy 无边界复制到固定缓冲区",
     "explanation": "argv[1] -> strcpy 到 16 字节 buf 无边界 -> 栈溢出 -> CWE-119",
     "fix_suggestion": "line 5: 改用 strncpy 并限定长度，或先用 strlen 校验"})

add("""
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char out[8];
    sprintf(out, "id=%s", argv[1]);   // 无界格式化写入
    puts(out);
    return 0;
}
""", "c",
    "分析过程：\n"
    "1. line 5: `sprintf(out, \"id=%s\", argv[1])` 把用户输入写入 8 字节缓冲区，无长度限制。\n"
    "2. 超长 argv[1] 溢出 → 栈破坏/RCE。\n"
    "3. 结论：CWE-119 Buffer Errors，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-119 Buffer Errors",
     "risk_level": "Critical", "source": "line 5: argv[1] 用户可控",
     "sink": "line 5: sprintf 无界写入固定缓冲区",
     "explanation": "argv[1] -> sprintf 无界写入 out[8] -> 溢出 -> CWE-119",
     "fix_suggestion": "line 5: 改用 snprintf(out, sizeof(out), ...)"})

add("""
#include <stdio.h>

int main(int argc, char **argv) {
    char buf[32];
    printf("Enter name: ");
    gets(buf);            // gets 无边界读取
    printf("Hi %s\\n", buf);
    return 0;
}
""", "c",
    "分析过程：\n"
    "1. line 5: `gets(buf)` 从 stdin 读取到 32 字节缓冲区，**无边界**。\n"
    "2. 任意超长输入溢出栈 → RCE。gets 本身就被 CWE-119 族收录。\n"
    "3. 结论：CWE-119 Buffer Errors，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-119 Buffer Errors",
     "risk_level": "Critical", "source": "line 5: stdin 用户可控",
     "sink": "line 5: gets 无边界读取到固定缓冲区",
     "explanation": "stdin -> gets 无边界 -> 栈溢出 -> CWE-119",
     "fix_suggestion": "line 5: 用 fgets(buf, sizeof(buf), stdin)"})


# ============================================================
# 3. CWE-269 权限管理不当（0 → +4）
# ============================================================
add("""
import os

def run_as_privileged():
    # 进程以 root 运行，执行后未降权
    os.system("make install")
    # 忘记 os.setuid(1000) / os.seteuid 降权
    return "done"
""", "python",
    "分析过程：\n"
    "1. 代码在**特权上下文**（root）执行敏感操作（make install / 系统管理），但**未降权**。\n"
    "2. 一旦被注入或代码缺陷触发，攻击者获得 root 级执行。\n"
    "3. 核心缺陷是**权限管理不当**（特权操作后未 drop privilege）→ CWE-269。\n"
    "4. 结论：CWE-269 Improper Privilege Management，风险 High。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-269 Improper Privilege Management",
     "risk_level": "High", "source": "line 4: root 上下文",
     "sink": "line 4: 特权操作后未降权",
     "explanation": "root 执行敏感操作 -> 未降权 -> 越权风险 -> CWE-269",
     "fix_suggestion": "特权操作后立即 os.seteuid(非特权 uid)"})

add("""
#include <stdio.h>
#include <unistd.h>

int main() {
    // 以 root 打开敏感文件后未 drop
    FILE *f = fopen("/etc/shadow", "r");
    // 未调用 setuid(getuid()) 降权
    char line[256];
    fgets(line, sizeof(line), f);
    puts(line);
    return 0;
}
""", "c",
    "分析过程：\n"
    "1. 以 root 读取 /etc/shadow 等敏感文件，**未降权**（setuid 未调用）。\n"
    "2. 后续任何代码漏洞（如 CWE-119）都可利用 root 权限。\n"
    "3. 结论：CWE-269，风险 High。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-269 Improper Privilege Management",
     "risk_level": "High", "source": "line 6: root 上下文读敏感文件",
     "sink": "line 6: 特权操作未降权",
     "explanation": "root 读 /etc/shadow 未降权 -> 越权风险 -> CWE-269",
     "fix_suggestion": "读取前 setuid(getuid()) 降权或避免以 root 运行"})


# ============================================================
# 4. CWE-863 授权校验错误（0 → +5）
# ============================================================
add("""
const express = require('express');
const app = express();
app.use(express.json());

app.post('/admin/action', (req, res) => {
    // 授权判断写反：非管理员才被放行
    if (req.user.role !== 'admin') {
        // 放行！逻辑错误：非 admin 也能执行
        doAdminAction(req.body);
        return res.json({ ok: true });
    }
    return res.status(403).json({ err: 'blocked' });
});
""", "javascript",
    "分析过程：\n"
    "1. line 7: 授权判断逻辑**写反**——`role !== 'admin'` 时反而执行管理操作并放行。\n"
    "2. 真正管理员被拦，非管理员任意执行敏感操作 → 授权校验错误。\n"
    "3. 核心缺陷是**授权逻辑错误**（条件反转）→ CWE-863（而非 862 缺失授权，这里*有*授权逻辑但错了）。\n"
    "4. 结论：CWE-863 Incorrect Authorization，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-863 Incorrect Authorization",
     "risk_level": "Critical", "source": "line 7: req.user.role 用户可控角色",
     "sink": "line 7: 授权条件写反导致越权放行",
     "explanation": "role!=='admin' 反而放行 -> 非管理员执行管理操作 -> CWE-863（授权逻辑错误）",
     "fix_suggestion": "line 7: 改为 if (req.user.role === 'admin') { 执行 } else { 403 }"})

add("""
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "dev_key"


@app.route("/admin/export")
def admin_export():
    # 授权判断顺序错误：先执行后校验，且校验条件恒为假
    if session.get("role") == "nobody":
        return "forbidden", 403
    # role 为 'admin'/'user' 都到这里，任意角色都能导出
    return export_all_users()
""", "python",
    "分析过程：\n"
    "1. line 10: 授权条件 `role == 'nobody'` 恒为假（不存在该角色），任何真实角色（含普通 user）都绕过。\n"
    "2. 普通用户可导出全量用户数据 → 授权校验错误。\n"
    "3. 结论：CWE-863 Incorrect Authorization，风险 High。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-863 Incorrect Authorization",
     "risk_level": "High", "source": "line 10: session role 可控",
     "sink": "line 13: 授权条件恒假导致越权执行",
     "explanation": "role=='nobody' 恒假 -> 任意角色通过 -> 越权导出 -> CWE-863",
     "fix_suggestion": "line 10: 改为 if session.get('role') != 'admin': return 403"})


# ============================================================
# 5. CWE-287 认证绕过（扩量 +6）
# ============================================================
add("""
const express = require('express');
const app = express();
app.use(express.json());

app.post('/login', (req, res) => {
    const { user, pass } = req.body;
    // 认证逻辑短路：用户名存在即通过，忽略密码
    if (user === 'admin' || pass === 'secret') {
        req.session.role = 'admin';
        return res.json({ ok: true });
    }
    return res.status(401).json({ err: 'bad' });
});
""", "javascript",
    "分析过程：\n"
    "1. line 8: 认证条件用 `||` 短路——只要**用户名匹配**或密码碰巧匹配就通过。\n"
    "2. 攻击者知道 admin 用户名即可免密登录 → 认证绕过。\n"
    "3. 结论：CWE-287 Improper Authentication，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-287 Improper Authentication",
     "risk_level": "Critical", "source": "line 8: user/pass 用户可控",
     "sink": "line 8: || 短路导致用户名即通过",
     "explanation": "user=='admin' || 密码匹配 -> 用户名即登录成功 -> 认证绕过 -> CWE-287",
     "fix_suggestion": "line 8: 必须同时校验用户名与密码（用 &&）"})

add("""
from django.http import JsonResponse
from django.views.decorators.http import require_POST


@require_POST
def login(request):
    uid = request.POST.get("uid")
    if uid:
        # 任意 uid 直接写入会话，无密码/凭证校验
        request.session["user_id"] = uid
        return JsonResponse({"ok": True})
    return JsonResponse({"err": "no uid"}, status=400)
""", "python",
    "分析过程：\n"
    "1. line 8: 只要提交 uid 就直接写入会话并视为登录成功，**无密码/凭证校验**。\n"
    "2. 攻击者可提交任意 uid 冒充他人 → 认证绕过。\n"
    "3. 结论：CWE-287 Improper Authentication，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-287 Improper Authentication",
     "risk_level": "Critical", "source": "line 8: uid 用户可控",
     "sink": "line 9: 无密码校验直接写会话",
     "explanation": "任意 uid -> 直接登录 -> 认证绕过 -> CWE-287",
     "fix_suggestion": "line 9: 先验证 uid 对应密码/凭证"})

add("""
const express = require('express');
const app = express();

app.get('/admin', (req, res) => {
    // 认证形同虚设：仅空 key 被拒，任何非空 key 都放行
    if (req.headers['x-api-key'] === '') {
        return res.status(401).json({ err: 'denied' });
    }
    res.json({ panel: true });
});

app.listen(3000);
""", "javascript",
    "分析过程：\n"
    "1. line 6: 认证条件 `x-api-key === ''` 只拒绝空值——攻击者随便填任何非空 key（如 'x'）即通过。\n"
    "2. 认证校验无效（条件恒不满足于真实攻击）→ 认证绕过。\n"
    "3. 结论：CWE-287 Improper Authentication，风险 High。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-287 Improper Authentication",
     "risk_level": "High", "source": "line 6: x-api-key 请求头用户可控",
     "sink": "line 6: 仅拒绝空 key，任意非空 key 放行",
     "explanation": "非空 key 即放行 -> 认证形同虚设 -> CWE-287 认证绕过",
     "fix_suggestion": "line 6: 与服务端存根 key 恒定时间比较（timingSafeEqual）"})

add("""
import hmac
from flask import Flask, request

app = Flask(__name__)


@app.route("/webhook", methods=["POST"])
def webhook():
    sig = request.headers.get("X-Sig", "")
    payload = request.get_data()
    # 比较逻辑写反：不匹配才通过（认证判断取反）
    if hmac.compare_digest(sig, compute_expected(payload)):
        return "rejected", 403
    return process_webhook(payload)
""", "python",
    "分析过程：\n"
    "1. line 11: 签名校验条件**写反**——签名*匹配*时拒绝，不匹配时反而处理。\n"
    "2. 攻击者随便发个错误签名即可触发 webhook 处理 → 认证绕过（校验逻辑错误）。\n"
    "3. 结论：CWE-287 Improper Authentication，风险 High。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-287 Improper Authentication",
     "risk_level": "High", "source": "line 11: X-Sig 请求头用户可控",
     "sink": "line 11: 签名校验条件取反导致错误放行",
     "explanation": "签名匹配被拒、不匹配放行 -> 认证绕过 -> CWE-287",
     "fix_suggestion": "line 11: 改为 if not compare_digest(...): return 403"})


# ============================================================
# 6. CWE-434 文件上传（扩量 +5）
# ============================================================
add("""
from flask import Flask, request, os

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    name = f.filename
    # 未校验扩展名，直接保存可执行文件
    f.save(os.path.join("/srv/uploads", name))
    return "uploaded"
""", "python",
    "分析过程：\n"
    "1. line 11: 上传文件 `f.save` 直接保存，**未校验扩展名**（可上传 .php/.py/.jsp）。\n"
    "2. 攻击者上传 webshell → 服务端代码执行。\n"
    "3. 结论：CWE-434 Unrestricted Upload of File with Dangerous Type，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-434 Unrestricted Upload of File with Dangerous Type",
     "risk_level": "Critical", "source": "line 9: 上传文件用户可控",
     "sink": "line 11: 未校验扩展名直接保存",
     "explanation": "上传 .php/.py -> 保存到可执行目录 -> webshell -> CWE-434",
     "fix_suggestion": "line 11: 扩展名白名单 + 随机文件名 + 禁可执行目录"})

add("""
const express = require('express');
const multer = require('multer');
const path = require('path');
const app = express();

const upload = multer({ dest: '/var/www/uploads/' });

app.post('/upload', upload.single('file'), (req, res) => {
    // 只信客户端 Content-Type，未校验扩展名
    const ext = path.extname(req.file.originalname);
    if (!['.png', '.jpg'].includes(ext)) {
        // 校验只拦"非图片"，未考虑 .php 双扩展名绕过
        return res.status(400).json({ err: 'bad type' });
    }
    res.json({ ok: true, path: req.file.path });
});
""", "javascript",
    "分析过程：\n"
    "1. line 13: 只检查扩展名是否是图片，但未考虑 `shell.php.png` 双扩展名/大小写绕过。\n"
    "2. 上传目录 /var/www/uploads 可被 Web 服务器解析 → webshell。\n"
    "3. 结论：CWE-434，风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-434 Unrestricted Upload of File with Dangerous Type",
     "risk_level": "Critical", "source": "line 13: 上传文件用户可控",
     "sink": "line 13: 扩展名校验可被双扩展名绕过",
     "explanation": "shell.php.png -> 扩展名校验绕过 -> webshell -> CWE-434",
     "fix_suggestion": "校验真实内容魔数 + 随机文件名 + 非可执行目录"})


# ============================================================
# 7. CWE-1333 ReDoS（扩量 +4）
# ============================================================
add("""
import re
from flask import Flask, request

app = Flask(__name__)


@app.route("/check")
def check():
    name = request.args.get("name", "")
    # 嵌套量词 (a+)+ 在长输入上呈指数级回溯
    if re.match(r"^(a+)+$", name):
        return "valid"
    return "invalid"
""", "python",
    "分析过程：\n"
    "1. line 9: 正则 `^(a+)+$` 含**嵌套量词**，对 `a`×N + 一个非 `a` 的输入呈指数回溯。\n"
    "2. 攻击者传大量 'a' + '!' 可耗尽 CPU → ReDoS。\n"
    "3. 结论：CWE-1333 Inefficient Regular Expression Complexity，风险 Medium-High。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-1333 Inefficient Regular Expression Complexity",
     "risk_level": "High", "source": "line 8: name 用户可控",
     "sink": "line 9: 嵌套量词正则匹配长输入",
     "explanation": "name -> (a+)+ 指数回溯 -> CPU 耗尽 -> CWE-1333 ReDoS",
     "fix_suggestion": "line 9: 改用 a+ 单层量词，避免嵌套/叠加量词"})

add("""
const express = require('express');
const app = express();
app.use(express.json());

app.post('/validate', (req, res) => {
    const email = req.body.email || '';
    // (.*)* 在长输入上指数回溯
    if (/^([a-z]+\\.)*[a-z]+$/.test(email)) {
        return res.json({ ok: true });
    }
    return res.status(400).json({ err: 'bad' });
});
""", "javascript",
    "分析过程：\n"
    "1. line 8: 正则含 `([a-z]+\\.)*` 与 `[a-z]+` 的叠加匹配，超长输入可指数回溯。\n"
    "2. 攻击者提交长字符串耗尽事件循环 → ReDoS。\n"
    "3. 结论：CWE-1333，风险 High。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-1333 Inefficient Regular Expression Complexity",
     "risk_level": "High", "source": "line 7: email 用户可控",
     "sink": "line 8: 叠加量词正则回溯",
     "explanation": "email -> ([a-z]+.)*[a-z]+ 回溯 -> 阻塞事件循环 -> CWE-1333",
     "fix_suggestion": "line 8: 拆分量词/加长度上限/用无回溯写法"})


# ============================================================
# 8. A06 易受攻击组件（依赖漏洞，真实 CVE 场景）
# ============================================================
add("""
// 旧版 log4j 依赖（CVE-2021-44228 受影响版本）：对用户输入做日志 lookup
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.servlet.http.*;

public class OrderServlet extends HttpServlet {
    private static final Logger LOG = LogManager.getLogger(OrderServlet.class);

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        String item = req.getParameter("item");
        LOG.info("view item: {}", item);   // item 可含 ${jndi:...} 触发 JNDI
    }
}
""", "java",
    "分析过程：\n"
    "1. line 10: `item` 用户可控进入 log4j 日志；若依赖为受 CVE-2021-44228 影响的旧版，`${jndi:ldap://...}` 会触发 JNDI 注入 → RCE。\n"
    "2. 核心是**引入了易受攻击的组件**（旧版 log4j），漏洞由依赖引入 → A06 / CWE-20 类供应链风险。\n"
    "3. 结论：易受攻击组件（log4j CVE-2021-44228），风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-506 / A06 易受攻击组件 (log4j CVE-2021-44228)",
     "risk_level": "Critical", "source": "line 10: item 用户可控",
     "sink": "line 10: 旧版 log4j lookup 用户输入",
     "explanation": "item 含 ${jndi:} -> 旧版 log4j JNDI 注入 -> RCE -> A06 易受攻击组件",
     "fix_suggestion": "升级 log4j>=2.17.1 并配置 JndiLookup 禁用"})

add("""
// 旧版 fastjson 依赖（CVE-2017-18349 受影响版本）：默认开启 autoType 反序列化
import com.alibaba.fastjson.JSON;
import org.springframework.web.bind.annotation.*;

@RestController
public class ImportController {

    @PostMapping("/import")
    public Object parse(@RequestBody String body) {
        return JSON.parseObject(body);   // 依赖自动带入的旧版 fastjson
    }
}
""", "java",
    "分析过程：\n"
    "1. line 10: 对用户输入 `JSON.parseObject`，依赖是受 CVE-2017-18349 影响的旧版 fastjson（autoType 默认开）。\n"
    "2. 攻击者构造 `@type` gadget 链 → RCE。\n"
    "3. 核心是**引入旧版 fastjson**（依赖漏洞）→ A06；同时是 CWE-502。\n"
    "4. 结论：A06 易受攻击组件（fastjson CVE-2017-18349），风险 Critical。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-502 / A06 易受攻击组件 (fastjson CVE-2017-18349)",
     "risk_level": "Critical", "source": "line 10: body 用户可控",
     "sink": "line 10: 旧版 fastjson 反序列化",
     "explanation": "body @type -> 旧版 fastjson autoType -> gadget RCE -> A06",
     "fix_suggestion": "升级 fastjson>=1.2.83 或启用 SafeMode，关闭 autoType"})

add("""
// 旧版 lodash 依赖（CVE-2021-23337 / CVE-2019-10744）：merge 原型污染
const _ = require('lodash');
const express = require('express');
const app = express();
app.use(express.json());

app.post('/settings', (req, res) => {
    const base = { theme: 'light' };
    _.merge(base, req.body);   // 旧版 lodash merge 未过滤 __proto__
    res.json(base);
});
""", "javascript",
    "分析过程：\n"
    "1. line 8: `_.merge(base, req.body)` 用依赖带入的旧版 lodash；受 CVE-2019-10744 影响的版本 merge 未过滤 `__proto__`。\n"
    "2. 攻击者传 `{\"__proto__\":{...}}` 污染原型链 → 逻辑绕过。\n"
    "3. 核心是**引入旧版 lodash**（依赖漏洞）→ A06；兼 CWE-1321。\n"
    "4. 结论：A06 易受攻击组件（lodash CVE-2019-10744），风险 High。",
    {"has_vulnerability": True, "vulnerability_type": "CWE-1321 / A06 易受攻击组件 (lodash CVE-2019-10744)",
     "risk_level": "High", "source": "line 8: req.body 用户可控",
     "sink": "line 8: 旧版 lodash merge 原型污染",
     "explanation": "req.body __proto__ -> 旧版 lodash merge -> 原型污染 -> A06",
     "fix_suggestion": "升级 lodash>=4.17.21 或改用不污染的合并实现"})


with OUT.open("w", encoding="utf-8") as fh:
    for rec in records:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"生成 {len(records)} 条覆盖短板补充样本 -> {OUT}")

from collections import Counter
c = Counter()
for rec in records:
    jm = re.search(r"```json\s*(\{.*?\})\s*```", rec["messages"][2]["content"], re.S)
    if jm:
        v = json.loads(jm.group(1))
        c[v["vulnerability_type"][:14]] += 1
print("分布:", dict(c))
