# -*- coding: utf-8 -*-
"""α0.5 盲区补充样本生成器（v2：防测试集泄露版）。

目标：针对 α0 no-merge 全 87 段真实盲区（7 蒙对 + 1 漏报），生成"带干扰项的归因对比样本"，
教模型识别主洞 vs 干扰项，并显式论证"为什么是 X 不是 Y"。

v2 变更：v1 直接复用了测试集样本的代码结构（typical_13/14/15/28、hard_bypass_06、
hard_cve_05 等），Jaccard 0.5~1.0，构成训练→测试泄露，会虚高评测分（记忆而非泛化）。
v2 全部改为**结构迥异**的代码：换框架（Flask→FastAPI/Django/Express/Java Servlet）、
换业务场景、换注入点，保留"同 CWE + 干扰项排除论证"的教学内容。

盲区清单（期望 CWE -> 模型误报 CWE）：
  1. CWE-306 认证缺失   <- 误报 CWE-79（把回显当 XSS）
  2. CWE-639 IDOR       <- 误报 CWE-79
  3. CWE-862 缺授权     <- 误报 CWE-798（被 secret_key 干扰）
  4. CWE-209 信息泄露   <- 误报 CWE-89（把异常 SQL 当主洞）
  5. CWE-1321 原型污染  <- 误报 CWE-400（把递归当 DoS）
  6. CWE-208 时序比较   <- 误报 CWE-798（被硬编码凭证干扰）
  7. CWE-915 数据绑定   <- 误报 CWE-79（Spring4Shell 把输出当 XSS）
  8. CWE-89  隐藏 SQL   <- 漏报（长文件 + 非 WHERE 注入点被淹没）

输出：data/supplement_alpha05_blindspot.jsonl（ChatML 格式，与训练集一致）
"""
import json, re
from pathlib import Path

ROOT = Path(r"D:\code\毕业设计\Graduation-Project")
DATA = ROOT / "experiments" / "exp_06_finetune" / "data"
OUT = DATA / "supplement_alpha05_blindspot.jsonl"

# 统一 system prompt：α0.5 精简版（角色+要求+schema+简短CoT+few-shot）。
# 训练/推理统一候选，与 data 最终统一版本一致。
try:
    import sys
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


def line_no(code: str, marker: str) -> int:
    for i, ln in enumerate(code.splitlines(), 1):
        if marker in ln:
            return i
    return 1


records = []

# ============================================================
# 1. CWE-306 认证缺失（干扰项：回显 → 误判 XSS）  [FastAPI / Django]
# ============================================================
def gen_auth_missing():
    specs = [
        # 变体 A：FastAPI 取消订阅，无任何认证
        ("""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()


@app.post("/billing/cancel_subscription")
def cancel_subscription(req: Request):
    sub_id = req.query_params.get("subscription_id")
    billing_db.cancel(sub_id)
    return JSONResponse({"status": "cancelled", "subscription": sub_id})
""", "python", "cancel_subscription", "未校验调用者身份，任何请求即可取消任意订阅"),
        # 变体 B：Django 吊销 API token，无认证
        ("""
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from .models import ApiToken


@require_POST
def revoke_token(request):
    token_id = request.POST.get("token_id")
    ApiToken.objects.filter(id=token_id).delete()
    return JsonResponse({"revoked": token_id})
""", "python", "revoke_token", "未校验调用者身份，可吊销任意 API token"),
    ]
    for code, lang, fn, flaw in specs:
        ln = line_no(code, f"def {fn}")
        analysis = (
            f"分析过程：\n"
            f"1. line {ln}: `{fn}()` 处理敏感操作（取消订阅/吊销 token），但函数体**没有任何身份认证**——"
            f"没有登录校验、没有 API key 校验、没有拦截器/装饰器，任何匿名请求都能到达。\n"
            f"2. 数据流：外部请求 → `{fn}()` → 直接执行敏感操作 → 全程无认证门。\n"
            f"3. 干扰项排除：虽然函数把 `subscription_id`/`token_id` 回显到 JSON 响应（可能被误判为 XSS），"
            f"但**核心缺陷是认证缺失**——回显只是次要问题，且未进入 HTML 脚本执行上下文。\n"
            f"4. 结论：CWE-306 Missing Authentication for Critical Function，风险 High（{flaw}）。"
        )
        verdict = {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-306 Missing Authentication for Critical Function",
            "risk_level": "High",
            "source": f"line {ln}: {fn}() 入口未做任何认证",
            "sink": f"line {ln}: 敏感操作在无认证下执行",
            "explanation": f"外部请求 → {fn}() 无认证校验 → 执行敏感操作（{flaw}）→ CWE-306 认证缺失",
            "fix_suggestion": f"line {ln}: 在 {fn}() 前加登录/API key 校验（如 @login_required 或拦截器）",
        }
        records.append(make_record(code, lang, analysis, verdict))


# ============================================================
# 2. CWE-639 IDOR（干扰项：回显 → 误判 XSS）  [Express / FastAPI]
# ============================================================
def gen_idor():
    specs = [
        # 变体 A：Express 发票下载，仅校验登录不校验属主
        ("""
const express = require('express');
const app = express();
app.use(express.json());

app.get('/api/invoices/:id', (req, res) => {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'login required' });
    }
    const invoice = invoiceRepo.findByPk(req.params.id);
    res.json(invoice);
});
""", "javascript", "GET /api/invoices/:id", "已登录但未校验发票是否属于当前用户"),
        # 变体 B：FastAPI 病历查看，仅校验登录不校验属主
        ("""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()


@app.get("/medical/record/{record_id}")
def get_medical_record(record_id: str, request: Request):
    user = request.session.get("user")
    if user is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    record = health_db.fetch_record(record_id)
    return record
""", "python", "get_medical_record", "已登录但未校验病历是否属于当前用户"),
    ]
    for code, lang, fn, flaw in specs:
        ln = line_no(code, "req.session") if "req.session" in code else line_no(code, 'def get_medical_record')
        check_ln = line_no(code, "status_code=401") if "status_code=401" in code else ln
        analysis = (
            f"分析过程：\n"
            f"1. line {ln}: 函数**只校验了是否登录**（session 存在/`user` 非空），"
            f"但没有校验请求的资源（发票/病历）**是否属于当前登录用户**。\n"
            f"2. 数据流：登录用户 → 传入任意资源 ID（`req.params.id`/`record_id`）→ 直接返回该资源数据 → "
            f"攻击者可枚举他人资源 ID 越权访问。\n"
            f"3. 干扰项排除：`req.params.id`/`record_id` 回显/返回可能被误判为 XSS，但这里用户输入"
            f"未进入 HTML 脚本执行上下文，**核心缺陷是越权访问（IDOR）**。\n"
            f"4. 结论：CWE-639 Authorization Bypass Through User-Controlled Key，风险 High（{flaw}）。"
        )
        verdict = {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-639 Authorization Bypass Through User-Controlled Key",
            "risk_level": "High",
            "source": f"line {ln}: 用户可控的资源 ID",
            "sink": f"line {ln}: 未校验属主即返回资源数据",
            "explanation": f"登录校验（不够）→ 用户传入任意资源 ID → 未校验属主直接返回 → CWE-639 IDOR（{flaw}）",
            "fix_suggestion": f"line {ln}: 查询前校验 resource.owner_id == 当前登录用户",
        }
        records.append(make_record(code, lang, analysis, verdict))


# ============================================================
# 3. CWE-862 缺授权（干扰项：登录校验让模型以为安全）  [FastAPI / Django]
# ============================================================
def gen_missing_authz():
    specs = [
        # 变体 A：FastAPI 清空全库，仅校验登录不校验角色
        ("""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()


@app.post("/admin/purge_all_users")
def purge_all_users(request: Request):
    user = request.session.get("user")
    if user is None:
        return JSONResponse({"error": "login required"}, status_code=401)
    user_store.truncate_all()
    return {"ok": True}
""", "python", "purge_all_users", "仅校验登录、未校验管理员角色"),
        # 变体 B：Django 提升任意用户为编辑，仅校验登录不校验角色
        ("""
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from .models import User


@require_POST
def promote_to_editor(request):
    if not request.session.get("user_id"):
        return JsonResponse({"error": "login required"}, status=401)
    uid = request.POST.get("uid")
    User.objects.filter(id=uid).update(role="editor")
    return JsonResponse({"ok": True})
""", "python", "promote_to_editor", "任意登录用户即可提权他人"),
        # 变体 C：Express 导出全量用户，仅校验登录不校验 admin
        ("""
const express = require('express');
const app = express();
app.use(express.json());

app.get('/admin/export', (req, res) => {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'login required' });
    }
    res.json(userRepo.findAll());
});
""", "javascript", "GET /admin/export", "任意登录用户即可导出全量用户数据"),
        # 变体 D：FastAPI 关闭审计，仅校验登录不校验角色
        ("""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()
active_audits = {}


@app.post("/admin/close_audit")
def close_audit(request: Request):
    user = request.session.get("user")
    if user is None:
        return JSONResponse({"error": "auth required"}, status_code=401)
    audit_id = request.query_params.get("audit_id")
    active_audits.pop(audit_id, None)
    audit_log.record(user, "close", audit_id)
    return {"closed": audit_id}
""", "python", "close_audit", "任意登录用户可关闭任意审计任务"),
        # 变体 E：Java Servlet 管理操作，仅校验登录不校验角色
        ("""
import javax.servlet.http.*;

public class GrantAdminServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        if (req.getSession().getAttribute("user") == null) {
            resp.setStatus(401);
            return;
        }
        String uid = req.getParameter("uid");
        userDao.setRole(uid, "admin");
    }
}
""", "java", "GrantAdminServlet", "任意登录用户可提权任意账户为 admin"),
    ]
    for code, lang, fn, flaw in specs:
        ln = line_no(code, f"def {fn}") if f"def {fn}" in code else line_no(code, fn)
        if "session.userId" in code:
            login_ln = line_no(code, "session.userId")
        elif "user is None" in code:
            login_ln = line_no(code, "user is None")
        elif "user_id" in code:
            login_ln = line_no(code, "user_id")
        elif "getAttribute(\"user\")" in code:
            login_ln = line_no(code, "getAttribute(\"user\")")
        else:
            login_ln = ln
        analysis = (
            f"分析过程：\n"
            f"1. line {login_ln}: 只校验了**是否登录**，但 line {ln}: 的管理操作**没有校验角色**（是否 admin）。\n"
            f"2. 数据流：任意登录用户 → 调用 `{fn}()` → 执行管理操作 → 普通用户越权。\n"
            f"3. 干扰项排除：有登录校验容易让模型误判为安全，但**这是登录而非授权**——"
            f"真正缺陷是**缺少功能级授权检查**（有登录、无角色校验）。\n"
            f"4. 结论：CWE-862 Missing Authorization，风险 High（{flaw}）。"
        )
        verdict = {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-862 Missing Authorization",
            "risk_level": "High",
            "source": f"line {login_ln}: 仅校验登录未校验角色",
            "sink": f"line {ln}: 管理操作在无授权下执行",
            "explanation": f"登录校验（不够）→ {fn}() 管理操作 → 无角色校验 → 普通用户越权 → CWE-862 缺授权",
            "fix_suggestion": f"line {ln}: 增加角色校验，如 request.user.is_staff / session 中的 role 检查",
        }
        records.append(make_record(code, lang, analysis, verdict))


# ============================================================
# 4. CWE-209 信息泄露（干扰项：SQL 拼接 → 误判 CWE-89）  [Java Servlet / Node.js]
# ============================================================
def gen_info_disclosure():
    specs = [
        # 变体 A：Java Servlet 用 e.printStackTrace(out) 把堆栈输出到响应
        ("""
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.*;
import javax.servlet.http.*;

public class OrderServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("text/html;charset=UTF-8");
        PrintWriter out = resp.getWriter();
        String id = req.getParameter("id");
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/shop", "root", "root");
            PreparedStatement ps = conn.prepareStatement("SELECT amount FROM orders WHERE id = ?");
            ps.setString(1, id);
            ResultSet rs = ps.executeQuery();
            out.println(rs.getLong("amount"));
        } catch (SQLException e) {
            e.printStackTrace(out);
        }
    }
}
""", "java", "OrderServlet", "异常堆栈直接输出到 HTTP 响应，泄露库类型/连接串/路径"),
        # 变体 B：Node.js 把 err.stack 放进 JSON 响应
        ("""
const express = require('express');
const app = express();

app.get('/api/profile', (req, res) => {
    try {
        const row = userRepo.findByUid(req.query.uid);
        res.json(row);
    } catch (err) {
        res.status(500).json({ error: err.stack });
    }
});
""", "javascript", "GET /api/profile", "完整堆栈 err.stack 回显给客户端"),
    ]
    for code, lang, fn, flaw in specs:
        ln = line_no(code, "catch") if "catch" in code else line_no(code, "catch (SQLException")
        analysis = (
            f"分析过程：\n"
            f"1. line {ln}: 异常处理把**数据库/运行时堆栈详情直接返回给客户端**（`e.printStackTrace(out)` / "
            f"`err.stack`），泄露表结构、连接串、路径、依赖版本等敏感信息。\n"
            f"2. 数据流：异常 → 堆栈拼入响应 → 返回给外部用户 → 攻击者可利用错误信息枚举/探测。\n"
            f"3. 干扰项排除：`findByUid(req.query.uid)`/`PreparedStatement` 是参数化查询（不是 SQL 注入），"
            f"**本样本核心可确认漏洞是异常信息泄露**，不要误判为 CWE-89。\n"
            f"4. 结论：CWE-209 Generation of Error Message Containing Sensitive Information，风险 Medium（{flaw}）。"
        )
        verdict = {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-209 Generation of Error Message Containing Sensitive Information",
            "risk_level": "Medium",
            "source": f"line {ln}: 异常处理分支",
            "sink": f"line {ln}: 堆栈详情拼入响应返回客户端",
            "explanation": f"查询异常 → 堆栈回显给用户 → 敏感信息泄露 → CWE-209 信息泄露",
            "fix_suggestion": f"line {ln}: 仅返回通用错误消息，堆栈写日志不下发客户端",
        }
        records.append(make_record(code, lang, analysis, verdict))


# ============================================================
# 5. CWE-1321 原型污染（干扰项：递归/合并 → 误判 DoS）  [JS 两种合并写法]
# ============================================================
def gen_proto_pollution():
    specs = [
        # 变体 A：扁平 for...in 合并也污染 __proto__（设置合并）
        ("""
const express = require('express');
const app = express();
app.use(express.json());

function assignInto(target, source) {
    for (const key in source) {
        target[key] = source[key];
    }
    return target;
}

app.post('/settings/apply', (req, res) => {
    const settings = { theme: 'dark', locale: 'en' };
    assignInto(settings, req.body);
    res.json({ applied: true });
});

app.listen(8080);
""", "javascript", "assignInto", "扁平 for...in 合并，__proto__ 键仍会污染原型"),
        # 变体 B：深度克隆助手未过滤 constructor/prototype（表单预处理）
        ("""
const express = require('express');
const app = express();
app.use(express.json());

function cloneDeep(input, out) {
    for (const key of Object.keys(input)) {
        if (input[key] && typeof input[key] === 'object' && !Array.isArray(input[key])) {
            out[key] = cloneDeep(input[key], out[key] || {});
        } else {
            out[key] = input[key];
        }
    }
    return out;
}

app.post('/form/preprocess', (req, res) => {
    const clean = {};
    cloneDeep(req.body, clean);
    res.json({ size: Object.keys(clean).length });
});

app.listen(9090);
""", "javascript", "cloneDeep", "__proto__/constructor 键未过滤，污染 Object.prototype"),
    ]
    for code, lang, fn, flaw in specs:
        ln = line_no(code, f"function {fn}")
        sink_ln = line_no(code, "req.body")
        analysis = (
            f"分析过程：\n"
            f"1. line {ln}: `{fn}()` 把攻击者可控对象合并/克隆进目标对象，`for...in`/`Object.keys` "
            f"**未过滤 `__proto__`、`constructor`、`prototype` 特殊键**。\n"
            f"2. line {sink_ln}: `req.body`（攻击者可控 JSON）直接作为 source → 攻击者可构造 "
            f"`{{'__proto__': {{'polluted': true}}}}` 污染 Object.prototype → 全对象继承恶意属性。\n"
            f"3. 干扰项排除：对象合并/递归可能被误判为**深度递归 DoS（CWE-400）**，但这里攻击面是"
            f"**原型链污染**——污染全局原型导致属性注入/逻辑绕过，且 JSON 深度可控，"
            f"核心缺陷不是栈溢出而是原型污染。\n"
            f"4. 结论：CWE-1321 Improperly Controlled Modification of Object Prototype Attributes，"
            f"风险 Critical（{flaw}）。"
        )
        verdict = {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-1321 Improperly Controlled Modification of Object Prototype Attributes",
            "risk_level": "Critical",
            "source": f"line {sink_ln}: req.body 用户可控 JSON",
            "sink": f"line {ln}: {fn}() 未过滤 __proto__ 合并/克隆",
            "explanation": f"req.body → {fn}() 未过滤特殊键 → __proto__ 污染 Object.prototype → CWE-1321 原型污染",
            "fix_suggestion": f"line {ln}: 合并时跳过 __proto__/constructor/prototype，或用 Object.create(null)",
        }
        records.append(make_record(code, lang, analysis, verdict))


# ============================================================
# 6. CWE-208 时序比较（干扰项：硬编码凭证 → 误判 CWE-798）  [Node webhook / Django]
# ============================================================
def gen_timing_compare():
    specs = [
        # 变体 A：Node.js webhook 签名用 === 比较（非恒定时间）
        ("""
const crypto = require('crypto');
const express = require('express');
const app = express();
app.use(express.json());

const WEBHOOK_SHARED_SECRET = 'whsec_7f3a9c2e5b8d1f4a6c0e';

app.post('/webhooks/payment', (req, res) => {
    const sig = req.headers['x-webhook-signature'] || '';
    const payload = JSON.stringify(req.body);
    const expected = crypto.createHmac('sha256', WEBHOOK_SHARED_SECRET).update(payload).digest('hex');
    if (sig === expected) {
        res.json({ received: true });
    } else {
        res.status(401).json({ error: 'bad signature' });
    }
});
""", "javascript", "webhook 签名校验", "用 === 比较 HMAC 摘要，可被时序攻击逐字符爆破"),
        # 变体 B：Django 网关 token 用 == 比较
        ("""
from django.http import JsonResponse
from django.views.decorators.http import require_GET

GATEWAY_SHARED_KEY = "c0nf1g_s3rv3r_k3y_2026"


@require_GET
def verify_gateway(request):
    supplied = request.headers.get("X-Gateway-Token", "")
    if supplied == GATEWAY_SHARED_KEY:
        return JsonResponse({"granted": True})
    return JsonResponse({"granted": False}, status=403)
""", "python", "verify_gateway", "用 == 比较网关 token，可被时序攻击爆破"),
    ]
    for code, lang, fn, flaw in specs:
        ln = line_no(code, "===") if "===" in code else line_no(code, "==")
        analysis = (
            f"分析过程：\n"
            f"1. line {ln}: 用 `===`/`==` 直接比较签名/token 与期望值——这是**非恒定时间比较**，"
            f"逐字符比较会在第一个不匹配处提前退出，攻击者可利用响应时间差异**逐字符爆破凭证**。\n"
            f"2. 数据流：外部请求头/签名 → 比较 → 认证结果（时间差异泄露）。\n"
            f"3. 干扰项排除：`WEBHOOK_SHARED_SECRET`/`GATEWAY_SHARED_KEY` 是硬编码凭证（可被误判为 CWE-798 主洞），"
            f"但**本样本的核心安全缺陷是时序比较**——凭证硬编码是次要问题，"
            f"真正可利用的是 `===`/`==` 的时序侧信道。\n"
            f"4. 结论：CWE-208 Observable Timing Discrepancy，风险 Medium（{flaw}）。"
        )
        verdict = {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-208 Observable Timing Discrepancy",
            "risk_level": "Medium",
            "source": f"line {ln}: 外部可控的签名/token",
            "sink": f"line {ln}: ===/== 非恒定时间比较",
            "explanation": f"外部签名/token → ===/== 比较（逐字符提前退出）→ 时间侧信道 → 可爆破 → CWE-208 时序比较",
            "fix_suggestion": f"line {ln}: 改用恒定时间比较（crypto.timingSafeEqual / hmac.compare_digest）",
        }
        records.append(make_record(code, lang, analysis, verdict))


# ============================================================
# 7. CWE-915 数据绑定（Spring4Shell，干扰项：输出 → 误判 XSS）  [@Controller + @ResponseBody]
# ============================================================
def gen_spring_binding():
    specs = [
        ("""
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class OrderController {

    @PostMapping("/orders/checkout")
    @ResponseBody
    public String checkout(CheckoutForm form) {
        return "Checkout coupon=" + form.getCoupon() + " total=" + form.getTotal();
    }
}

class CheckoutForm {
    private String coupon;
    private double total;
    public String getCoupon() { return coupon; }
    public void setCoupon(String coupon) { this.coupon = coupon; }
    public double getTotal() { return total; }
    public void setTotal(double total) { this.total = total; }
}
""", "java", "checkout", "Spring MVC 数据绑定到 class，攻击者可提交额外字段触发 setter"),
    ]
    for code, lang, fn, flaw in specs:
        ln = line_no(code, f"public String {fn}")
        analysis = (
            f"分析过程：\n"
            f"1. line {ln}: `{fn}(CheckoutForm form)` 使用 Spring MVC 的 **@ModelAttribute 自动绑定**——"
            f"HTTP 请求参数直接映射到 `CheckoutForm` 的 setter（`setCoupon`/`setTotal` 等）。\n"
            f"2. 攻击者可提交**非 coupon/total 字段**（如 `class.module.classLoader...` 或额外属性）触发任意 setter/"
            f"属性绑定，造成**数据绑定注入**（Spring4Shell 类攻击，可达 RCE）。\n"
            f"3. 干扰项排除：`form.getCoupon()` 拼入响应可能被误判为 XSS（CWE-79），但**核心缺陷是"
            f"不可信数据绑定到对象的任意属性**——攻击面在绑定层而非输出层。\n"
            f"4. 结论：CWE-915 Improperly Controlled Modification of Dynamically-Determined Object "
            f"Attributes，风险 Critical（{flaw}）。"
        )
        verdict = {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes",
            "risk_level": "Critical",
            "source": f"line {ln}: HTTP 请求体直接绑定到 CheckoutForm",
            "sink": f"line {ln}: @ModelAttribute 自动绑定任意属性",
            "explanation": f"HTTP 参数 → Spring @ModelAttribute 绑定 → 可触发任意 setter/属性 → CWE-915 数据绑定注入（{flaw}）",
            "fix_suggestion": f"line {ln}: 使用 @InitBinder setAllowedFields 白名单，或改用 DTO 手工绑定",
        }
        records.append(make_record(code, lang, analysis, verdict))


# ============================================================
# 8. CWE-89 隐藏 SQL（漏报：ORDER BY/排序列注入，非 WHERE 注入）  [Flask]
# ============================================================
def gen_hidden_sql():
    specs = [
        # 变体 A：Python ORDER BY 注入（其他查询都参数化）
        ("""
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)


def fetch_users():
    conn = sqlite3.connect("shop.db")
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM users WHERE active = ?", (1,))
    return cur.fetchall()


def fetch_product(id_val):
    conn = sqlite3.connect("shop.db")
    cur = conn.cursor()
    cur.execute("SELECT id, name, price FROM products WHERE id = ?", (id_val,))
    return cur.fetchone()


@app.route("/api/products/list")
def list_products():
    sort_col = request.args.get("sort", "price")
    order = request.args.get("order", "asc")
    # 排序字段/方向直接拼接（危险）：sort/order 用户可控
    query = "SELECT id, name, price FROM products ORDER BY " + sort_col + " " + order
    cur = sqlite3.connect("shop.db").cursor()
    cur.execute(query)
    rows = cur.fetchall()
    return jsonify({"count": len(rows), "rows": rows[:5]})
""", "python", "list_products", "其他查询都参数化，唯独 ORDER BY 排序列拼接导致 SQL 注入"),
        # 变体 B：Java PreparedStatement 参数化 WHERE + ORDER BY 注入
        ("""
import java.sql.*;
import javax.servlet.http.*;

public class ProductServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String sort = req.getParameter("sort");
        String query = "SELECT id, name, price FROM products WHERE active = ? ORDER BY " + sort;
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/shop", "root", "root")) {
            PreparedStatement ps = conn.prepareStatement(query);
            ps.setInt(1, 1);
            ResultSet rs = ps.executeQuery();
        }
    }
}
""", "java", "ProductServlet", "WHERE 用参数化，但 ORDER BY 列名字符串拼接导致 SQL 注入"),
        # 变体 C：Python LIMIT 注入（隐藏 SQL）
        ("""
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)


@app.route("/api/search")
def search():
    q = request.args.get("q", "")
    limit = request.args.get("limit", "10")
    query = "SELECT id, name FROM items WHERE name LIKE '%" + q + "%' LIMIT " + limit
    cur = sqlite3.connect("db.db").cursor()
    cur.execute(query)
    return jsonify(cur.fetchall())
""", "python", "search", "WHERE LIKE 拼接 SQL 注入 + LIMIT 拼接，双重注入"),
    ]
    for code, lang, fn, flaw in specs:
        # 定位拼接行（不同变体的拼接特征不同）
        if 'ORDER BY " + sort_col' in code:
            ln = line_no(code, 'ORDER BY " + sort_col')
            src_expr, src_desc = 'request.args.get("sort")', "sort/order 参数"
        elif '"ORDER BY " + sort' in code:
            ln = line_no(code, '"ORDER BY " + sort')
            src_expr, src_desc = 'req.getParameter("sort")', "sort 参数"
        else:
            ln = line_no(code, 'LIMIT " + limit')
            src_expr, src_desc = 'request.args.get("limit")', "limit 参数"
        analysis = (
            f"分析过程：\n"
            f"1. 文件里多数查询用参数化（`WHERE active = ?`、`WHERE id = ?`），但 line {ln}: "
            f"**`{src_expr}` 被直接拼进 SQL**——这是非 WHERE 位置的隐藏 SQL 注入（CWE-89）。\n"
            f"2. 数据流：`{src_expr}` → 字符串拼接进 SQL 语句（ORDER BY/LIMIT/LIKE）→ `execute` → "
            f"可用 `sort=price,(SELECT...)` / `limit=10;DROP...` 等从数据库提取数据。\n"
            f"3. 干扰项排除：WHERE 都参数化会让人误判为「全安全」，需**逐行找非参数化拼接**——"
            f"ORDER BY/LIMIT/LIKE 这类位置常被忽略，正是漏网之鱼。\n"
            f"4. 结论：CWE-89 SQL Injection，风险 High（{flaw}）。"
        )
        verdict = {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-89 SQL Injection",
            "risk_level": "High",
            "source": f"line {ln-1}: {src_expr} 用户可控",
            "sink": f"line {ln}: {src_expr} 字符串拼接进 SQL",
            "explanation": f"{src_desc} → 字符串拼接进 SQL（ORDER BY/LIMIT/LIKE）→ execute → 可注入 → CWE-89 SQL 注入（{flaw}）",
            "fix_suggestion": f"line {ln}: {src_expr} 用白名单/整型校验，禁止直接拼接 SQL 元素",
        }
        records.append(make_record(code, lang, analysis, verdict))


gen_auth_missing()
gen_idor()
gen_missing_authz()
gen_info_disclosure()
gen_proto_pollution()
gen_timing_compare()
gen_spring_binding()
gen_hidden_sql()

with OUT.open("w", encoding="utf-8") as fh:
    for rec in records:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"生成 {len(records)} 条盲区补充样本 -> {OUT}")

from collections import Counter
c = Counter()
for rec in records:
    jm = re.search(r"```json\s*(\{.*?\})\s*```", rec["messages"][2]["content"], re.S)
    if jm:
        c[json.loads(jm.group(1)).get("vulnerability_type", "?")[:20]] += 1
print("分布:", dict(c))
