# -*- coding: utf-8 -*-
"""α0.5 归因错误对比样本生成器。

前提来自 α0 实测归因错误（真实错误方向，非猜测）：
  306 认证缺失 -> 误报 352(CSRF) / 79(XSS)
  639 IDOR     -> 误报 643(XPath) / 79
  209 信息泄露 -> 误报 89(SQL)
  1321 原型污染-> 误报 502(反序列化) / 400(DoS)
  208 时序比较 -> 误报 798(硬编码凭证)
  915 数据绑定 -> 误报 943(NoSQL) / 94
  384 会话固定 -> 误报 312(明文存储)
  843 类型混淆 -> 误报 89(SQL)
  943 NoSQL 注入-> 误报 89(SQL)
  117 日志注入 -> 误报 134(格式化字符串)
  295 弱 TLS   -> 误报 798 / 漏报

每类：正例（教"为什么是 X 不是 Y"）+ 安全对照/干扰项。
输出：data/supplement_alpha05_attribution.jsonl
"""
import json, re, sys
from pathlib import Path

ROOT = Path(r"D:\code\毕业设计\Graduation-Project")
DATA = ROOT / "experiments" / "exp_06_finetune" / "data"
OUT = DATA / "supplement_alpha05_attribution.jsonl"

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


# ============================================================
# 1. CWE-306 认证缺失（误报 352/79）
# ============================================================
def gen_306():
    add("""
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "dev_key"


@app.route("/admin/deactivate", methods=["POST"])
def deactivate():
    # 没有任何身份认证：无登录校验、无 token、无拦截器
    uid = request.form.get("uid")
    return f"deactivated {uid}"
""", "python",
        "分析过程：\n"
        "1. line 9: `deactivate()` 执行敏感操作（停用账户），但函数体**没有任何认证**——没有登录校验、没有 CSRF token、没有拦截器。\n"
        "2. 干扰项排除：**有 CSRF token 校验 ≠ 有认证**。这里连 token 都没有；即便有 token，token 只是防跨站伪造，不替代身份认证。\n"
        "3. 干扰项排除：把 uid 回显进响应可能被误判为 XSS（CWE-79），但**核心缺陷是认证缺失**——任意匿名请求都能停用任意账户。\n"
        "4. 结论：CWE-306 Missing Authentication for Critical Function，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-306 Missing Authentication for Critical Function",
         "risk_level": "High", "source": "line 9: 任意匿名请求", "sink": "line 9: 敏感操作无认证执行",
         "explanation": "匿名请求 -> deactivate() 无认证 -> 停用账户 -> CWE-306（不是 352：无 token 也无从谈 CSRF）",
         "fix_suggestion": "line 9: 加登录校验（如 @login_required / 检查 session['user_id']）"})
    add("""
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "dev_key"


@app.route("/admin/grant", methods=["POST"])
def grant_admin():
    # 有 CSRF token 校验，但没有身份认证！
    if request.form.get("csrf_token") != session.get("csrf"):
        return "CSRF failed", 403
    uid = request.form.get("uid")
    return f"granted admin to {uid}"
""", "python",
        "分析过程：\n"
        "1. line 11: 有 CSRF token 校验，但 line 9 起的 `grant_admin()` **没有任何身份认证**——任意匿名请求只要带上正确 token 即可提权他人。\n"
        "2. 干扰项排除：看到 CSRF 校验容易误判为\"有防护所以安全\"或误报 CWE-352；但 **CSRF 防护只防跨站请求伪造，不防直接构造的匿名请求**。\n"
        "3. 核心缺陷：敏感操作缺认证 → CWE-306，风险 Critical（任意用户提权任意账户为 admin）。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-306 Missing Authentication for Critical Function",
         "risk_level": "Critical", "source": "line 9: 匿名请求 + 任意 uid", "sink": "line 12: 提权操作无认证执行",
         "explanation": "匿名请求 -> grant_admin() 有 CSRF 但无认证 -> 提权任意账户 -> CWE-306（不是 352：CSRF 防护 ≠ 认证）",
         "fix_suggestion": "line 9: 在函数入口加身份认证（登录 + 角色校验）"})


# ============================================================
# 2. CWE-639 IDOR（误报 643/79）
# ============================================================
def gen_639():
    add("""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()


@app.get("/invoice/{inv_id}")
def get_invoice(inv_id: str, request: Request):
    if request.session.get("user_id") is None:
        return JSONResponse({"error": "login required"}, status_code=401)
    return invoice_repo.fetch(inv_id)
""", "python",
        "分析过程：\n"
        "1. line 9: 只校验了**是否登录**，line 10: 直接按 `inv_id` 返回发票数据，**没有校验该发票是否属于当前用户**。\n"
        "2. 攻击者枚举其他用户的发票 ID 即可越权读取 → 越权访问。\n"
        "3. 干扰项排除：`inv_id` 进函数不是 XPath 注入（CWE-643）；它作为**资源键**被直接使用且未校验属主 → CWE-639。\n"
        "4. 结论：CWE-639 Authorization Bypass Through User-Controlled Key，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-639 Authorization Bypass Through User-Controlled Key",
         "risk_level": "High", "source": "line 8: 用户可控 inv_id", "sink": "line 10: 未校验属主返回数据",
         "explanation": "登录（不够）-> inv_id 未校验属主 -> 越权读取 -> CWE-639（不是 643：无 XPath 注入，是资源键越权）",
         "fix_suggestion": "line 10: 查询前校验 invoice.owner_id == 当前登录用户"})
    add("""
# 资源访问 helper：返回数据库中的记录
def load_record(table, rid):
    return db.execute("SELECT * FROM " + table + " WHERE id = ?", (rid,)).fetchone()
""", "python",
        "分析过程：\n"
        "1. 这是**数据访问 helper**：`load_record(table, rid)` 返回指定记录，本身无 HTTP 入口。\n"
        "2. 注意：`table` 直接拼接进 SQL（若 table 由外部控制则是 SQL 注入），但**当前样本中 table 是调用方传入的常量**，\n"
        "   且本文件没有外部输入入口——helper 本身不构成可利用漏洞。\n"
        "3. 越权（IDOR）发生在**调用方**把用户可控的 rid 传入而未校验属主时；helper 只是执行层。\n"
        "4. 结论：helper 本身无漏洞（若调用方传用户 rid 未校验属主，则该调用点是 CWE-639）。",
        {"has_vulnerability": False, "vulnerability_type": "none",
         "risk_level": "None", "source": "N/A", "sink": "N/A",
         "explanation": "数据访问 helper 无外部输入入口，本身不构成漏洞；越权在调用方",
         "fix_suggestion": "no fix needed"})
    add("""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()


@app.get("/records/{rid}")
def get_record(rid: str, request: Request):
    user = request.session.get("user")
    if user is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return medical.fetch(rid)
""", "python",
        "分析过程：\n"
        "1. line 9: 仅校验登录，line 12: 直接按 `rid` 返回病历，未校验病历归属。\n"
        "2. 干扰项排除：`rid` 只是查询键，不构成注入；漏洞是**越权访问他人病历**（IDOR）。\n"
        "3. 结论：CWE-639，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-639 Authorization Bypass Through User-Controlled Key",
         "risk_level": "High", "source": "line 8: 用户可控 rid", "sink": "line 12: 未校验属主返回病历",
         "explanation": "登录（不够）-> rid 未校验属主 -> 越权读病历 -> CWE-639",
         "fix_suggestion": "line 12: 校验 record.owner_id == user"})
    add("""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()


@app.get("/files/{name}")
def get_file(name: str, request: Request):
    if request.session.get("uid") is None:
        return JSONResponse({"error": "login required"}, status_code=401)
    full_path = "/exports/" + name
    return open(full_path, "r").read()
""", "python",
        "分析过程：\n"
        "1. line 10: 用户可控 `name` 拼入文件路径，未校验属主/未校验路径 → 越权读文件。\n"
        "2. 双视角：这是 **CWE-639 越权**（读取他人资源）且同时是 **CWE-22 路径穿越**（可 ../ 逃逸）。\n"
        "3. 主洞选择：文件按名直接读取且无任何白名单 → 优先判 CWE-22 Path Traversal（sink 是 open 路径拼接），越权是其后果。\n"
        "4. 结论：CWE-22 Path Traversal，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-22 Path Traversal",
         "risk_level": "Critical", "source": "line 9: name 用户可控", "sink": "line 11: open 路径拼接无校验",
         "explanation": "name -> open('/exports/'+name) 无白名单/无属主校验 -> 路径穿越 + 越权 -> CWE-22",
         "fix_suggestion": "line 11: realpath + startswith('/exports/') 白名单校验"})


# ============================================================
# 3. CWE-209 信息泄露（误报 89）
# ============================================================
def gen_209():
    add("""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import sqlite3

app = FastAPI()


@app.get("/profile/{uid}")
def profile(uid: str):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    try:
        cur.execute("SELECT email FROM profiles WHERE id = ?", (uid,))
        return str(cur.fetchone())
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": str(e)})
""", "python",
        "分析过程：\n"
        "1. line 12: 查询是**参数化**的（`WHERE id = ?`），**不是 SQL 注入**——不能把 89 当主洞。\n"
        "2. line 15: 真正的漏洞：异常处理把**数据库错误详情直接回显给客户端**（`detail: str(e)`），泄露表结构/库类型。\n"
        "3. 干扰项排除：看到 execute + 字符串容易误报 CWE-89，但参数化已防注入；**主洞是异常信息泄露**。\n"
        "4. 结论：CWE-209 Generation of Error Message Containing Sensitive Information，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-209 Generation of Error Message Containing Sensitive Information",
         "risk_level": "Medium", "source": "line 15: 异常处理分支", "sink": "line 15: 错误详情回显给客户端",
         "explanation": "查询异常 -> 错误详情拼入响应 -> 信息泄露 -> CWE-209（不是 89：查询已参数化）",
         "fix_suggestion": "line 15: 返回通用错误，详情写日志"})
    add("""
from flask import Flask, request
import traceback

app = Flask(__name__)


@app.route("/report")
def report():
    try:
        rows = run_report()
        return str(rows)
    except Exception:
        tb = traceback.format_exc()
        return f"<pre>{tb}</pre>", 500
""", "python",
        "分析过程：\n"
        "1. line 12: `traceback.format_exc()` 把完整堆栈拼进响应返回客户端，泄露路径/库/依赖信息。\n"
        "2. 干扰项排除：`run_report()` 内部可能是安全的（无注入）；**本样本唯一可确认漏洞是堆栈泄露**。\n"
        "3. 结论：CWE-209，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-209 Generation of Error Message Containing Sensitive Information",
         "risk_level": "Medium", "source": "line 12: 异常处理分支", "sink": "line 12: 堆栈回显到响应",
         "explanation": "异常 -> 堆栈回显 -> 敏感信息泄露 -> CWE-209",
         "fix_suggestion": "line 12: 记录日志，响应只给通用错误"})


# ============================================================
# 4. CWE-1321 原型污染（误报 502/400）
# ============================================================
def gen_1321():
    add("""
const express = require('express');
const app = express();
app.use(express.json());

function assign(target, source) {
    for (const key in source) {
        target[key] = source[key];
    }
    return target;
}

app.post('/config', (req, res) => {
    const cfg = { debug: false };
    assign(cfg, req.body);
    res.json({ ok: true });
});

app.listen(3000);
""", "javascript",
        "分析过程：\n"
        "1. line 16: `req.body`（攻击者可控）作为 source 合并进对象，`for...in` **未过滤 `__proto__`/`constructor`**。\n"
        "2. 攻击者传 `{\"__proto__\": {\"debug\": true}}` 可污染 Object.prototype → 全局对象继承恶意属性（绕过逻辑）。\n"
        "3. 干扰项排除：这不是反序列化（CWE-502，无 pickle/yaml），也不是递归 DoS（CWE-400，这是扁平合并）；\n"
        "   核心是**未过滤特殊键的原型链污染**。\n"
        "4. 结论：CWE-1321 Improperly Controlled Modification of Object Prototype Attributes，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-1321 Improperly Controlled Modification of Object Prototype Attributes",
         "risk_level": "Critical", "source": "line 16: req.body 用户可控", "sink": "line 6-10: assign 未过滤 __proto__",
         "explanation": "req.body -> assign() 未过滤特殊键 -> __proto__ 污染 Object.prototype -> CWE-1321（不是 502/400）",
         "fix_suggestion": "line 6: 跳过 __proto__/constructor/prototype，或用 Object.create(null)"})
    add("""
const express = require('express');
const app = express();
app.use(express.json());

function deepMerge(target, src) {
    for (const k of Object.keys(src)) {
        if (src[k] && typeof src[k] === 'object') {
            target[k] = deepMerge(target[k] || {}, src[k]);
        } else {
            target[k] = src[k];
        }
    }
    return target;
}

app.post('/profile', (req, res) => {
    const profile = { name: '' };
    deepMerge(profile, req.body);
    res.json(profile);
});
""", "javascript",
        "分析过程：\n"
        "1. line 16: `req.body` 递归合并，未过滤 `constructor`/`prototype` 键 → 可污染。\n"
        "2. 干扰项排除：递归可能是 DoS 诱因（CWE-400），但攻击面核心是**原型链污染**（注入属性/逻辑绕过），且 JSON 深度可控。\n"
        "3. 结论：CWE-1321，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-1321 Improperly Controlled Modification of Object Prototype Attributes",
         "risk_level": "Critical", "source": "line 16: req.body 用户可控", "sink": "line 5-14: deepMerge 未过滤特殊键",
         "explanation": "req.body -> deepMerge 未过滤 constructor/prototype -> 原型污染 -> CWE-1321（不是 400 DoS）",
         "fix_suggestion": "line 5: 过滤特殊键，或使用 Object.create(null)"})


# ============================================================
# 5. CWE-208 时序比较（误报 798）
# ============================================================
def gen_208():
    add("""
from django.http import JsonResponse
from django.views.decorators.http import require_GET

API_GATEWAY_KEY = "k-9f8e7d6c5b4a3210"


@require_GET
def verify(request):
    supplied = request.headers.get("X-Gateway-Key", "")
    if supplied == API_GATEWAY_KEY:
        return JsonResponse({"granted": True})
    return JsonResponse({"granted": False}, status=403)
""", "python",
        "分析过程：\n"
        "1. line 10: 用 `==` 比较外部 key 与期望值——**非恒定时间比较**，逐字符在第一个不匹配处提前返回，\n"
        "   攻击者可利用响应时间差异逐字符爆破 key。\n"
        "2. 干扰项排除：`API_GATEWAY_KEY` 是硬编码凭证（可误判 CWE-798 主洞），但**本样本核心可利用缺陷是时序比较**——\n"
        "   凭证硬编码是次要问题，真正可利用的是 `==` 的时序侧信道（可爆破出完整 key）。\n"
        "3. 结论：CWE-208 Observable Timing Discrepancy，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-208 Observable Timing Discrepancy",
         "risk_level": "Medium", "source": "line 8: 外部可控 X-Gateway-Key", "sink": "line 10: == 非恒定时间比较",
         "explanation": "外部 key -> == 比较逐字符提前退出 -> 时序侧信道 -> CWE-208（不是 798：主洞是时序比较）",
         "fix_suggestion": "line 10: 用 hmac.compare_digest() 恒定时间比较"})
    add("""
from django.http import JsonResponse
from django.views.decorators.http import require_POST
import hmac

SIGNING_KEY = "whsec_abc123"


@require_POST
def webhook(request):
    sig = request.headers.get("X-Signature", "")
    payload = request.body
    expect = hmac.new(SIGNING_KEY.encode(), payload, "sha256").hexdigest()
    if hmac.compare_digest(sig, expect):
        return JsonResponse({"ok": True})
    return JsonResponse({"bad": True}, status=401)
""", "python",
        "分析过程：\n"
        "1. line 15: 用 `hmac.compare_digest()` **恒定时间比较**，无时序侧信道。\n"
        "2. 干扰项排除：`SIGNING_KEY` 是硬编码凭证（CWE-798），但**该凭证存在不等于可利用的时序漏洞**——\n"
        "   这里比较是恒定时间的，`==` 时序问题不存在。本样本有硬编码凭证问题（798 可另报），\n"
        "   但**没有 CWE-208 时序比较漏洞**。\n"
        "3. 结论：无 CWE-208（时序比较已用恒定时间函数）；若按凭证论可报 798，但 208 不成立。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-798 Use of Hard-coded Credentials",
         "risk_level": "Medium", "source": "line 7: 硬编码 SIGNING_KEY", "sink": "line 7: 凭证字面量",
         "explanation": "SIGNING_KEY 硬编码 -> CWE-798；比较已用 compare_digest 恒定时间，无 CWE-208",
         "fix_suggestion": "line 7: 从环境变量读取凭证"})


# ============================================================
# 6. CWE-915 数据绑定（误报 943/94）
# ============================================================
def gen_915():
    add("""
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class OrderController {

    @PostMapping("/orders/checkout")
    @ResponseBody
    public String checkout(CheckoutForm form) {
        return "total=" + form.getTotal();
    }
}

class CheckoutForm {
    private String coupon;
    private double total;
    public String getCoupon() { return coupon; }
    public void setCoupon(String c) { this.coupon = c; }
    public double getTotal() { return total; }
    public void setTotal(double t) { this.total = t; }
}
""", "java",
        "分析过程：\n"
        "1. line 10: HTTP 参数直接绑定到 `CheckoutForm`（@ModelAttribute 自动绑定）。\n"
        "2. 攻击者可提交 `coupon`/`total` 之外的字段（如 `class.module.classLoader...`）触发任意 setter → 数据绑定注入（Spring4Shell 类，可达 RCE）。\n"
        "3. 干扰项排除：这不是 NoSQL 注入（CWE-943），也不是表达式注入（CWE-94）——\n"
        "   攻击面是**把不可信数据绑定到对象的任意属性** → CWE-915。\n"
        "4. 结论：CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes",
         "risk_level": "Critical", "source": "line 10: HTTP 参数绑定", "sink": "line 10: @ModelAttribute 自动绑定任意属性",
         "explanation": "HTTP 参数 -> Spring 自动绑定 -> 触发任意 setter -> CWE-915（不是 943/94）",
         "fix_suggestion": "line 10: @InitBinder setAllowedFields 白名单或手工 DTO 绑定"})
    add("""
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class SearchController {

    @PostMapping("/search")
    @ResponseBody
    public String search(@RequestParam("q") String q) {
        return "result for " + q;
    }
}
""", "java",
        "分析过程：\n"
        "1. line 9: 用 `@RequestParam` 显式绑定单个参数，**不是 @ModelAttribute 对象绑定**——攻击者无法触发任意 setter。\n"
        "2. 干扰项排除：有对象形参才构成 CWE-915；这里只有标量参数，无数据绑定注入。\n"
        "3. 结论：无 CWE-915（`q` 仅回显，无脚本执行上下文则非 XSS 主洞）。",
        {"has_vulnerability": False, "vulnerability_type": "none",
         "risk_level": "None", "source": "N/A", "sink": "N/A",
         "explanation": "@RequestParam 标量绑定，无对象属性注入，无 CWE-915",
         "fix_suggestion": "no fix needed"})


# ============================================================
# 7. CWE-384 会话固定（误报 312）
# ============================================================
def gen_384():
    add("""
from flask import Flask, request, session, make_response

app = Flask(__name__)
app.secret_key = "dev_key"


@app.route("/login", methods=["POST"])
def login():
    uid = request.form.get("uid")
    pwd = request.form.get("pwd")
    # 接受客户端指定的 session_id，登录成功后不更换
    sid = request.args.get("sid")
    if sid:
        resp = make_response("ok")
        resp.set_cookie("session", sid)
        session["user_id"] = uid
        return resp
    session["user_id"] = uid
    return "ok"
""", "python",
        "分析过程：\n"
        "1. line 12-16: **接受客户端传入的 session_id（sid）**，登录成功后**不轮换会话 ID** → 攻击者可预置 sid 并诱导受害者登录 → 会话固定（session fixation）。\n"
        "2. 干扰项排除：这里没有把密码明文存储（不是 CWE-312）；核心缺陷是**登录后不重新生成会话 ID 且接受外部指定 ID** → CWE-384。\n"
        "3. 结论：CWE-384 Session Fixation，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-384 Session Fixation",
         "risk_level": "High", "source": "line 13: 外部 sid 指定会话 ID", "sink": "line 15: 登录成功未轮换会话",
         "explanation": "外部 sid -> 登录后会话未轮换 -> 会话固定 -> CWE-384（不是 312：非明文存储）",
         "fix_suggestion": "line 15: 登录成功后 session.clear() + 重新生成新会话 ID"})


# ============================================================
# 8. CWE-843 类型混淆（误报 89）
# ============================================================
def gen_843():
    add("""
<?php
$username = $_POST['username'];
$password = $_POST['password'];

$row = mysqli_fetch_assoc(mysqli_query($conn,
    "SELECT * FROM users WHERE username = '$username'"));

if ($row['password'] == $password) {   // 松散比较 ==
    echo "login ok";
} else {
    echo "fail";
}
?>
""", "php",
        "分析过程：\n"
        "1. line 8: 密码校验用**松散比较 `==`**：若 `$password` 为 `0` 且库中密码哈希以非数字开头，`==` 判定为真（PHP 类型混淆）。\n"
        "2. 干扰项排除：SQL 拼接是真实存在的注入风险，但**本样本教学重点是类型混淆**——\n"
        "   攻击者提交 `password=0` 可绕过哈希比较。若 SQL 也拼接，两者并存时优先报更可利用的注入；\n"
        "   但此处演示的是 `==` 导致的认证绕过 → CWE-843 Type Confusion。\n"
        "3. 结论：CWE-843，风险 High（认证绕过）。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-843 Access of Resource Using Incompatible Type (Type Confusion)",
         "risk_level": "High", "source": "line 8: $password 用户可控", "sink": "line 8: == 松散比较",
         "explanation": "password=0 -> == 松散比较绕过哈希 -> 认证绕过 -> CWE-843",
         "fix_suggestion": "line 8: 用 password_verify() 严格比较"})


# ============================================================
# 9. CWE-943 NoSQL 注入（误报 89）
# ============================================================
def gen_943():
    add("""
const express = require('express');
const { MongoClient } = require('mongodb');
const app = express();
app.use(express.json());

app.post('/login', async (req, res) => {
    const { user, pass } = req.body;
    const db = await MongoClient.connect('mongodb://localhost/app');
    const col = db.collection('users');
    const doc = await col.findOne({ username: user, password: pass });
    res.json({ ok: !!doc });
});
""", "javascript",
        "分析过程：\n"
        "1. line 10: `user`/`pass` 直接作为**对象**传入 `findOne` 查询条件。\n"
        "2. 攻击者提交 `{\"user\": {\"$ne\": null}}` 等操作符对象 → MongoDB 解析为操作符查询，绕过认证 → NoSQL 注入。\n"
        "3. 干扰项排除：这不是 SQL 注入（CWE-89，无 SQL 语句）；是**数据查询逻辑注入（MongoDB 操作符注入）** → CWE-943。\n"
        "4. 结论：CWE-943 Improper Neutralization of Special Elements in Data Query Logic，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-943 Improper Neutralization of Special Elements in Data Query Logic",
         "risk_level": "High", "source": "line 7: req.body user/pass 可控", "sink": "line 10: findOne 未过滤操作符对象",
         "explanation": "user/pass -> findOne 操作符注入 -> 认证绕过 -> CWE-943（不是 89：非 SQL）",
         "fix_suggestion": "line 10: 只取标量（如 user: String(user)），过滤 $ 开头键"})


# ============================================================
# 10. CWE-117 日志注入（误报 134）
# ============================================================
def gen_117():
    add("""
import logging

logging.basicConfig(filename="/var/log/app.log", level=logging.INFO)


def handle_request(user_name):
    logging.info("login attempt by %s", user_name)
    return "ok"
""", "python",
        "分析过程：\n"
        "1. line 7: 用户可控 `user_name` 直接写入日志，`%s` 是**占位符（参数化）**，不是格式字符串注入（不是 CWE-134）。\n"
        "2. 真正漏洞：`user_name` 可含 `\\r\\n` 换行，伪造日志条目/注入假日志 → **日志注入** CWE-117。\n"
        "3. 干扰项排除：`%s` 参数化排除了 CWE-134；攻击者是**注入换行伪造日志** → CWE-117。\n"
        "4. 结论：CWE-117 Improper Output Neutralization for Logs，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-117 Improper Output Neutralization for Logs",
         "risk_level": "Medium", "source": "line 5: user_name 用户可控", "sink": "line 6: logging.info 未净化换行",
         "explanation": "user_name 含 \\r\\n -> 写入日志 -> 伪造日志/注入 -> CWE-117（不是 134：%s 参数化）",
         "fix_suggestion": "line 6: 日志前替换 \\r\\n 等控制字符"})


# ============================================================
# 11. CWE-295 弱 TLS（漏报/误报）
# ============================================================
def gen_295():
    add("""
import ssl
import urllib.request
from flask import Flask, request

app = Flask(__name__)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    resp = urllib.request.urlopen(url, context=ctx)
    return resp.read()
""", "python",
        "分析过程：\n"
        "1. line 9-10: 关闭了证书校验（`check_hostname=False` + `verify_mode=CERT_NONE`）→ 中间人可伪造证书窃取数据。\n"
        "2. 干扰项排除：`url` 来自用户参数也有 SSRF（CWE-918），但**本样本核心确认缺陷是 TLS 证书校验关闭** → CWE-295。\n"
        "3. 结论：CWE-295 Improper Certificate Validation，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-295 Improper Certificate Validation",
         "risk_level": "High", "source": "line 9: 关闭校验的 SSL 上下文", "sink": "line 14: 使用不校验证书的 context",
         "explanation": "verify_mode=CERT_NONE -> HTTPS 不校验证书 -> MITM -> CWE-295",
         "fix_suggestion": "line 9: 使用 create_default_context() 默认校验，不关闭 verify_mode"})


gen_306()
gen_639()
gen_209()
gen_1321()
gen_208()
gen_915()
gen_384()
gen_843()
gen_943()
gen_117()
gen_295()


# ============================================================
# 追加变体（薄弱方向补量，保持"为什么是 X 不是 Y"教学）
# ============================================================

# ---- 306 补 2：Express / Java Servlet 无认证 ----
add("""
const express = require('express');
const app = express();
app.use(express.json());

app.post('/api/users/delete', (req, res) => {
    // 无任何认证：无登录校验、无 token、无拦截器
    const uid = req.body.uid;
    userRepo.remove(uid);
    res.json({ deleted: uid });
});
""", "javascript",
        "分析过程：\n"
        "1. line 7: `/api/users/delete` 执行敏感操作（删除用户）但**没有任何身份认证**。\n"
        "2. 干扰项排除：`deleted: uid` 回显可能被误判为 XSS（CWE-79），但未进入 HTML 脚本上下文；\n"
        "   核心缺陷是匿名请求即可删任意用户 → CWE-306。\n"
        "3. 结论：CWE-306 Missing Authentication for Critical Function，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-306 Missing Authentication for Critical Function",
         "risk_level": "High", "source": "line 7: 匿名请求", "sink": "line 8: 删除操作无认证执行",
         "explanation": "匿名请求 -> 删除用户无认证 -> CWE-306（不是 79：回显非 XSS 主洞）",
         "fix_suggestion": "line 7: 入口加登录/角色校验（如 auth middleware）"})
add("""
import javax.servlet.http.*;

public class AdminDeleteServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        String uid = req.getParameter("uid");
        userService.delete(uid);   // 无任何认证/授权
        resp.getWriter().write("deleted " + uid);
    }
}
""", "java",
        "分析过程：\n"
        "1. line 5: `AdminDeleteServlet` 的 `doPost` 直接执行删除操作，**无登录校验、无角色校验**。\n"
        "2. 干扰项排除：回显 uid 非 XSS 主洞；核心是**敏感操作缺认证** → CWE-306。\n"
        "3. 结论：CWE-306，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-306 Missing Authentication for Critical Function",
         "risk_level": "High", "source": "line 5: 匿名请求", "sink": "line 5: 删除操作无认证执行",
         "explanation": "匿名请求 -> delete 无认证 -> CWE-306",
         "fix_suggestion": "line 5: 入口加登录/角色校验"})

# ---- 209 补 1：Spring 异常消息回显 ----
add("""
import org.springframework.web.bind.annotation.*;

@RestController
public class SearchController {

    @GetMapping("/search")
    public String search(@RequestParam String q) {
        try {
            return runQuery(q);
        } catch (Exception e) {
            return "error: " + e.getMessage();   // 异常详情回显
        }
    }
}
""", "java",
        "分析过程：\n"
        "1. line 10: `e.getMessage()` 把异常详情（可能含 SQL/路径/库信息）直接返回客户端。\n"
        "2. 干扰项排除：`runQuery(q)` 内部若参数化则无 SQL 注入（不是 89）；本样本**可确认漏洞是异常信息泄露** → CWE-209。\n"
        "3. 结论：CWE-209，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-209 Generation of Error Message Containing Sensitive Information",
         "risk_level": "Medium", "source": "line 10: 异常处理分支", "sink": "line 10: 异常详情回显",
         "explanation": "异常 -> e.getMessage 回显 -> 信息泄露 -> CWE-209（不是 89）",
         "fix_suggestion": "line 10: 只返回通用错误，详情写日志"})

# ---- 1321 补 1：Object.assign 合并 ----
add("""
const express = require('express');
const app = express();
app.use(express.json());

function mergeOptions(base, extra) {
    return Object.assign(base, extra);
}

app.post('/options', (req, res) => {
    const opts = { verbose: false };
    mergeOptions(opts, req.body);
    res.json(opts);
});
""", "javascript",
        "分析过程：\n"
        "1. line 10: `req.body` 经 `Object.assign` 合并，**未过滤 `__proto__`/`constructor` 键**。\n"
        "2. 攻击者传 `{\"__proto__\": {\"polluted\": 1}}` 污染原型链 → 逻辑绕过 → CWE-1321。\n"
        "3. 干扰项排除：非反序列化（502）、非递归 DoS（400）；核心是**原型链污染**。\n"
        "4. 结论：CWE-1321，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-1321 Improperly Controlled Modification of Object Prototype Attributes",
         "risk_level": "Critical", "source": "line 10: req.body 用户可控", "sink": "line 5: Object.assign 未过滤特殊键",
         "explanation": "req.body -> Object.assign 未过滤 __proto__ -> 原型污染 -> CWE-1321",
         "fix_suggestion": "line 5: 合并前过滤特殊键或 Object.create(null)"})

# ---- 208 补 1：Node === 时序比较 ----
add("""
const crypto = require('crypto');
const express = require('express');
const app = express();
app.use(express.json());

const SECRET = 'svc_secret_2026';

app.post('/verify', (req, res) => {
    const tok = req.headers['x-token'] || '';
    const expect = crypto.createHmac('sha256', SECRET).update(req.body).digest('hex');
    if (tok === expect) {
        res.json({ ok: true });
    } else {
        res.status(401).json({ err: 'bad' });
    }
});
""", "javascript",
        "分析过程：\n"
        "1. line 11: `tok === expect` 用 `===` 逐字符比较 HMAC，非恒定时间 → 时序侧信道可爆破。\n"
        "2. 干扰项排除：`SECRET` 是硬编码凭证（可报 798 次洞），但**本样本核心可利用缺陷是时序比较** → CWE-208。\n"
        "3. 结论：CWE-208，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-208 Observable Timing Discrepancy",
         "risk_level": "Medium", "source": "line 11: 外部可控 x-token", "sink": "line 11: === 非恒定时间比较",
         "explanation": "x-token -> === 逐字符比较 -> 时序侧信道 -> CWE-208（主洞非 798）",
         "fix_suggestion": "line 11: 用 crypto.timingSafeEqual 恒定时间比较"})

# ---- 384 补 2：PHP / Node 会话固定 ----
add("""
<?php
session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $uid = $_POST['uid'];
    // 登录成功但未 session_regenerate_id()，沿用攻击者预置的 PHPSESSID
    $_SESSION['user_id'] = $uid;
    echo "logged in";
}
""", "php",
        "分析过程：\n"
        "1. line 5: 登录成功后未调用 `session_regenerate_id()`，沿用客户端已有会话 ID → 会话固定。\n"
        "2. 干扰项排除：无明文密码存储（不是 312）；核心是**登录后会话不轮换** → CWE-384。\n"
        "3. 结论：CWE-384 Session Fixation，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-384 Session Fixation",
         "risk_level": "High", "source": "line 5: 攻击者预置 PHPSESSID", "sink": "line 5: 登录成功未轮换会话",
         "explanation": "预置会话 ID -> 登录成功未 regenerate -> 会话固定 -> CWE-384",
         "fix_suggestion": "line 5: session_regenerate_id(true) 后写入 session"})
add("""
const express = require('express');
const session = require('express-session');
const app = express();
app.use(session({ secret: 'x', resave: true, saveUninitialized: true }));

app.post('/login', (req, res) => {
    req.session.userId = req.body.uid;
    res.send('ok');   // 未重新生成 session，未轮换 sessionId
});
""", "javascript",
        "分析过程：\n"
        "1. line 8: 登录成功后未 `req.session.regenerate()`，沿用攻击者可预置的会话 → 会话固定。\n"
        "2. 干扰项排除：非明文存储（312）；核心是**登录后会话不轮换** → CWE-384。\n"
        "3. 结论：CWE-384，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-384 Session Fixation",
         "risk_level": "High", "source": "line 8: 攻击者预置会话", "sink": "line 8: 登录成功未轮换会话",
         "explanation": "预置会话 -> 登录成功未 regenerate -> 会话固定 -> CWE-384",
         "fix_suggestion": "line 8: 登录成功后 session.regenerate()"})

# ---- 843 补 2：PHP 松散比较 / strcmp 绕过 ----
add("""
<?php
$token = $_GET['token'];
$stored = '7a2f...';
if (strcmp($token, $stored) == 0) {   // strcmp 返回 0 时 == 也判真
    echo "granted";
} else {
    echo "denied";
}
""", "php",
        "分析过程：\n"
        "1. line 5: `strcmp($token, $stored) == 0` 使用**松散比较**：strcmp 在参数异常/数组时返回 0，`0 == 0` 判真 → 认证绕过。\n"
        "2. 干扰项排除：非 SQL 注入（89）；核心是**比较运算的类型混淆** → CWE-843。\n"
        "3. 结论：CWE-843，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-843 Access of Resource Using Incompatible Type (Type Confusion)",
         "risk_level": "High", "source": "line 5: $token 用户可控", "sink": "line 5: strcmp()==0 松散比较",
         "explanation": "token 数组/异常 -> strcmp 返回 0 -> == 判真 -> 认证绕过 -> CWE-843",
         "fix_suggestion": "line 5: 用 hash_equals() 严格比较"})
add("""
<?php
$hash = '0e462097431906509019562988736854';
if ($_GET['password'] == $hash) {   // 0e 开头字符串 == 转 float 为 0
    echo "admin access";
}
""", "php",
        "分析过程：\n"
        "1. line 3: `$_GET['password'] == $hash`：`$hash` 是 `0e` 开头的 magic hash，PHP 松散比较时把 `'0'` 与 `0e...` 都转 float 0 → 判真。\n"
        "2. 干扰项排除：非注入（89/78）；核心是**字符串到数值的类型混淆比较** → CWE-843。\n"
        "3. 结论：CWE-843，风险 High（认证绕过）。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-843 Access of Resource Using Incompatible Type (Type Confusion)",
         "risk_level": "High", "source": "line 3: $_GET['password'] 用户可控", "sink": "line 3: == 类型混淆比较",
         "explanation": "password=0 -> == 0e 哈希转 float 0 -> 认证绕过 -> CWE-843",
         "fix_suggestion": "line 3: 用 === 严格比较或 hash_equals"})

# ---- 943 补 2：PyMongo / 另一个 JS 操作符注入 ----
add("""
from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient("mongodb://localhost/app").app

@app.route("/login", methods=["POST"])
def login():
    body = request.get_json()
    doc = db.users.find_one({"username": body["user"], "password": body["pass"]})
    return "ok" if doc else "fail"
""", "python",
        "分析过程：\n"
        "1. line 10: `body['user']/body['pass']` 直接作为**对象**传入 `find_one`，未过滤 `$` 操作符。\n"
        "2. 攻击者传 `{\"user\": {\"$ne\": null}}` → 操作符注入绕过认证 → CWE-943。\n"
        "3. 干扰项排除：非 SQL 注入（89）；是 **MongoDB 查询逻辑注入** → CWE-943。\n"
        "4. 结论：CWE-943，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-943 Improper Neutralization of Special Elements in Data Query Logic",
         "risk_level": "High", "source": "line 10: body user/pass 可控", "sink": "line 10: find_one 未过滤操作符",
         "explanation": "user/pass -> find_one 操作符注入 -> 认证绕过 -> CWE-943（不是 89）",
         "fix_suggestion": "line 10: 只取标量 String(user) 并拒绝 $ 键"})
add("""
const express = require('express');
const mongodb = require('mongodb');
const app = express();
app.use(express.json());

app.post('/find', async (req, res) => {
    const crit = req.body.criteria;          // 用户传入整个查询条件
    const col = await mongodb.connect('mongodb://localhost/db').then(c => c.db().collection('docs'));
    res.json(await col.find(crit).toArray());
});
""", "javascript",
        "分析过程：\n"
        "1. line 9: `req.body.criteria` 整个查询条件由用户控制，直接交给 `find`。\n"
        "2. 攻击者传 `{\"criteria\": {\"$where\": \"...\"}}` 或 `$ne` → 查询逻辑注入 → CWE-943。\n"
        "3. 干扰项排除：非 SQL（89）；是 **NoSQL 查询逻辑注入** → CWE-943。\n"
        "4. 结论：CWE-943，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-943 Improper Neutralization of Special Elements in Data Query Logic",
         "risk_level": "High", "source": "line 9: criteria 用户可控", "sink": "line 10: find 接受操作符对象",
         "explanation": "criteria -> find 操作符/$where 注入 -> 越权查询 -> CWE-943",
         "fix_suggestion": "line 9: 不接收完整条件对象，只允许白名单字段标量"})

# ---- 117 补 2：Java %s 日志 / Python 访问日志 ----
add("""
import java.util.logging.Logger;
import javax.servlet.http.*;

public class AuthServlet extends HttpServlet {
    private static final Logger LOG = Logger.getLogger("auth");

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        String user = req.getParameter("user");
        LOG.info(String.format("login from %s", user));   // 参数化但可 CRLF
    }
}
""", "java",
        "分析过程：\n"
        "1. line 8: `user` 可控，line 9: `String.format` 是参数化日志（非 CWE-134 格式串注入）。\n"
        "2. 真正漏洞：user 含 `\\r\\n` 伪造日志条目 → CWE-117。\n"
        "3. 结论：CWE-117，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-117 Improper Output Neutralization for Logs",
         "risk_level": "Medium", "source": "line 8: user 用户可控", "sink": "line 9: 日志参数化但未净化换行",
         "explanation": "user 含 \\r\\n -> 日志 -> 伪造条目 -> CWE-117（不是 134）",
         "fix_suggestion": "line 9: 日志前过滤 \\r\\n 控制字符"})
add("""
import sys
from flask import Flask, request

app = Flask(__name__)

@app.route("/track")
def track():
    ip = request.args.get("ip", "")
    print("access from " + ip, file=sys.stderr)   # 拼接写入 stderr 日志
    return "ok"
""", "python",
        "分析过程：\n"
        "1. line 8: `ip` 用户可控，line 9: `print(\"access from \" + ip, file=sys.stderr)` 拼接写入日志。\n"
        "2. ip 含 `\\r\\n` 可伪造日志条目 → CWE-117（无占位符，但拼接同样未净化控制字符）。\n"
        "3. 结论：CWE-117，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-117 Improper Output Neutralization for Logs",
         "risk_level": "Medium", "source": "line 8: ip 用户可控", "sink": "line 9: 日志拼接未净化换行",
         "explanation": "ip 含 \\r\\n -> stderr 日志 -> 伪造条目 -> CWE-117",
         "fix_suggestion": "line 9: 日志前过滤 \\r\\n 或结构化日志"})

# ---- 295 补 2：requests verify=False / Java 信任所有 ----
add("""
import urllib.request
import ssl

ssl_context = ssl._create_unverified_context()


def fetch_remote(url):
    resp = urllib.request.urlopen(url, context=ssl_context)
    return resp.read()
""", "python",
        "分析过程：\n"
        "1. line 4: `ssl._create_unverified_context()` 创建**不校验证书**的 SSL 上下文，line 8: 用于 urlopen。\n"
        "2. HTTPS 请求不校验证书链 → 中间人可伪造证书窃取数据 → CWE-295。\n"
        "3. 干扰项排除：url 用户可控兼有 SSRF（918），但**本样本核心确认缺陷是证书校验关闭** → CWE-295。\n"
        "4. 结论：CWE-295，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-295 Improper Certificate Validation",
         "risk_level": "High", "source": "line 4: 不校验证书的 SSL 上下文", "sink": "line 8: urlopen 使用不校验证书 context",
         "explanation": "_create_unverified_context -> HTTPS 不校验证书 -> MITM -> CWE-295",
         "fix_suggestion": "line 4: 使用 create_default_context() 默认校验，不关闭验证"})
add("""
import javax.net.ssl.*;
import java.security.cert.X509Certificate;

public class TrustAllClient {
    public static void main(String[] args) throws Exception {
        TrustManager[] trustAll = { new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return null; }
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}   // 不校验任何证书
        } };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, new java.security.SecureRandom());
    }
}
""", "java",
        "分析过程：\n"
        "1. line 7: `checkServerTrusted` 空实现（不校验任何服务端证书）→ 任何自签/伪造证书都通过 → MITM。\n"
        "2. 干扰项排除：非弱随机（SecureRandom 已用）；核心是**信任所有证书** → CWE-295。\n"
        "3. 结论：CWE-295，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-295 Improper Certificate Validation",
         "risk_level": "High", "source": "line 7: TrustManager 空实现", "sink": "line 7: 不校验服务端证书",
         "explanation": "trust-all TrustManager -> 不校验证书 -> MITM -> CWE-295",
         "fix_suggestion": "line 7: 使用标准 TrustManagerFactory 校验证书链"})

# ---- 915 补 1：WebFlux/Map 绑定 ----
add("""
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class ImportController {

    @PostMapping("/import/settings")
    @ResponseBody
    public String apply(Map<String, String> params) {
        return "applied " + params;
    }
}
""", "java",
        "分析过程：\n"
        "1. line 8: `Map<String, String> params` 直接绑定所有请求参数（Spring 数据绑定到 Map）。\n"
        "2. 攻击者可提交任意字段（含 class 相关路径）触发绑定 → 数据绑定注入 → CWE-915。\n"
        "3. 干扰项排除：非 NoSQL（943）非表达式（94）；核心是**不可信数据绑定到动态对象/属性** → CWE-915。\n"
        "4. 结论：CWE-915，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes",
         "risk_level": "Critical", "source": "line 8: 全部请求参数", "sink": "line 8: Map 自动绑定任意字段",
         "explanation": "请求参数 -> Map 自动绑定 -> 任意属性注入 -> CWE-915（不是 943/94）",
         "fix_suggestion": "line 8: 白名单字段手工绑定，避免整个 Map/对象自动绑定"})


with OUT.open("w", encoding="utf-8") as fh:
    for rec in records:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"生成 {len(records)} 条归因对比样本 -> {OUT}")

from collections import Counter
c = Counter()
for rec in records:
    jm = re.search(r"```json\s*(\{.*?\})\s*```", rec["messages"][2]["content"], re.S)
    if jm:
        v = json.loads(jm.group(1))
        c[v["vulnerability_type"][:12]] += 1
print("分布:", dict(c))
