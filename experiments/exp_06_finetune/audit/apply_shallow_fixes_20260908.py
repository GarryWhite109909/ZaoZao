# -*- coding: utf-8 -*-
"""敷衍修复·执行者自修批 1（20260908）：638 / 886 / 2108 / 1868。

638：全模板重写（全入口枚举+污点链+防御双向核验+互斥锚句），锚按码重排；
886：锚漂移修正（6→2-3/12→3/15→20/18→23/22-23→30-31），叙事保留；
2108：327→347（本项目 JWT 锚：alg=none=签名验证禁用），全模板重写；
1868：补行锚+互斥锚句+防御核验（352）。
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(Path(__file__).resolve().parents[1])
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"

ROWS = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]


def R(t, x, y):
    assert t.count(x) == 1, f"不唯一({t.count(x)}): {x[:50]}"
    return t.replace(x, y)


def put_json(a, obj):
    m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
    return a[: m.start()] + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```\n"


def mk(n, obj):
    """全量重写用：新叙事 + 程序化 JSON 块。"""
    return n + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```\n"


def log(fid, line, note, basis):
    with CHANGELOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"date": "2026-09-08", "step": "2_敷衍修复_自修", "action": "FIX",
                            "fix_id": fid, "row_line_before": line, "note": note,
                            "basis": basis}, ensure_ascii=False) + "\n")


N89 = "CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
N347 = "CWE-347 Improper Verification of Cryptographic Signature"

# ================= 638（CWE-89，全模板重写） =================
r = ROWS[638 - 1]
assert "LoginController" in r["messages"][1]["content"]
n = (
    "**分析过程**\n\n"
    "1. **全入口枚举**：本文件为 Spring Boot 认证端点。外部入口一：`/api/auth/login` 的 "
    "`@RequestBody LoginRequest`（第 14-15 行取 username/password）；外部入口二：`/user/{id}` "
    "的 `@PathVariable id`（第 49 行）。无文件、环境变量等其他通道。\n\n"
    "2. **污点链（核心）**：第 15 行 `password` 取自请求体（外部可控）→ 第 21 行直接字符串拼接进 SQL"
    "（`... AND password = '\" + password + \"'`）→ 第 24 行 `jdbcTemplate.queryForList(sql)` 执行。"
    "逐跳无净化断点。\n\n"
    "3. **防御逐段核验**：\n"
    "   - 第 18 行 `username.replace(\"'\", \"''\")`：单引号翻倍对 username 而言尚属合法转义，"
    "但**第 15 行的 `password` 完全未处理**即进第 21 行拼接——单点转义救不了整条链；"
    "且该 replace 不处理反斜杠，MySQL 反斜杠语义下仍可逃逸——属\"防御迷惑 1\"（伪防御）。\n"
    "   - 第 36-38 行 catch `DataAccessException` 返回通用 500：仅抑制错误回显（信息泄露面），"
    "对注入本身无防御——\"防御迷惑 2\"。\n"
    "   - 对照组：第 50-52 行 `/user/{id}` 用 `?` 占位符参数化查询——同文件已示范正确写法，"
    "登录接口未采用。\n\n"
    "4. **利用**：`password = ' OR '1'='1` → SQL 变为 `... AND password = '' OR '1'='1'`，"
    "恒真返回全部用户，第 30-32 行签发 token；第 44 行 token 仅为 `Base64(username:role)`"
    "——**无签名**，可离线伪造，加重后果（认证绕过 → 会话劫持）。\n\n"
    "5. **结论与辨析**：CWE-89 SQL Injection，Critical。非 CWE-639/862——鉴权失效是注入的"
    "**后果**而非缺失授权；非 CWE-94/78——执行的是 SQL 语句而非代码/命令。\n"
)
a = mk(n, {
    "has_vulnerability": True,
    "vulnerability_type": N89,
    "risk_level": "Critical",
    "source": "line 15: password 取自 @RequestBody（外部可控，未做任何处理）",
    "sink": "line 24: jdbcTemplate.queryForList(sql) 执行第 21 行拼接的 SQL",
    "explanation": "line 15 password → line 21 字符串拼接（line 18 的 replace 只覆盖 username 且不处理反斜杠，属伪防御）"
                   "→ line 24 执行 → ' OR '1'='1 认证绕过；非 639/862（鉴权失效是后果）；非 94/78（SQL 语句非代码/命令）",
    "fix_suggestion": "line 21: 改为参数化查询 SELECT * FROM users WHERE username = ? AND password = ? 并传参"
                      "（与第 51 行正确写法一致）；line 44: token 改用签名 JWT，不用裸 Base64",
})
r["messages"][2]["content"] = a
log(638, 638, "敷衍修复：全模板重写（全入口枚举/污点链/防御双向核验/利用链/互斥锚句），锚按码重排",
    "敷衍修复队列 R1 + 代码级复核")

# ================= 886（CWE-611，锚漂移修正） =================
r = ROWS[886 - 1]
a = r["messages"][2]["content"]
a = R(a, "1. 第6行和第12行：`DOMParser` 和 `parse` 来自 `xmldom` 和 `xpath` 库",
        "1. 第2-3行：`DOMParser` 和 `parse` 来自 `xmldom` 和 `xpath` 库")
a = R(a, "2. 第15行：`replace(/<!DOCTYPE[^>]*>/g, '')`",
        "2. 第20行：`replace(/<!DOCTYPE[^>]*>/g, '')`")
a = R(a, "3. 第18行：`startsWith('<reset>')`", "3. 第23行：`startsWith('<reset>')`")
a = R(a, "4. 第22-23行：`parse` 提取", "4. 第30-31行：`parse` 提取")
r["messages"][2]["content"] = a
log(886, 886, "敷衍修复：锚漂移修正 6→2-3/12→3/15→20/18→23/22-23→30-31（复查确认=锚漂移而非浅薄，叙事防御核验已有）",
    "敷衍修复队列（复查）")

# ================= 2108（327→347，全模板重写） =================
r = ROWS[2108 - 1]
assert "jwt.verify" in r["messages"][1]["content"]
n = (
    "分析过程：\n"
    "1. **入口与唯一安全边界**：`verifyToken(token)` 接收外部传入 JWT，第 5 行 "
    "`jwt.verify(token, null, {algorithms: ['none']})` 是该 token 的唯一校验点。\n"
    "2. **缺陷核验**：`algorithms: ['none']` 显式把\"无签名算法\"列入白名单——alg=none 的 JWT "
    "没有第三段签名，库会跳过签名校验；secret 传 `null` 进一步坐实无密钥验证。攻击者自造 "
    "`base64url(header).base64url(payload).` 形式 token（header 的 alg=none），payload 填任意身份"
    "声明（如 {\"sub\":\"admin\",\"role\":\"admin\"}），verifyToken 直接放行 → **认证完全绕过**。\n"
    "3. **互斥辨析**：非 CWE-327——327 针对弱/过时**算法选择**（MD5、ECB、TLS1.0 等），"
    "本样本不是算法弱而是**签名验证被显式禁用**，按本项目 JWT 锚（alg=none/签名不校验 → 347）"
    "归 CWE-347；非 CWE-798——无硬编码凭证；非 CWE-287 泛化——缺陷点精确落在签名验证缺失。\n"
    "4. **结论**：CWE-347 Improper Verification of Cryptographic Signature，风险 Critical"
    "（未认证 → 全功能接管）。\n"
)
a = mk(n, {
    "has_vulnerability": True,
    "vulnerability_type": N347,
    "risk_level": "Critical",
    "source": "line 4: token 参数（外部传入的 JWT）",
    "sink": "line 5: jwt.verify(token, null, {algorithms: ['none']}) 显式禁用签名校验",
    "explanation": "alg=none 白名单 + secret=null → 攻击者伪造无签名 token（header.payload.）→ verify 直接通过"
                   " → 任意身份声明被接受 → 认证绕过；非 327：不是算法选择弱，是签名验证被禁用"
                   "（本项目 JWT 锚：alg=none → 347）；非 798：无硬编码凭证",
    "fix_suggestion": "line 5: 从 algorithms 白名单移除 'none'，使用强密钥并显式指定 "
                      "algorithms: ['HS256']（或 RS256），校验失败必须拒绝",
})
r["messages"][2]["content"] = a
log(2108, 2108, "敷衍修复+改标：327→347（JWT alg=none=签名验证禁用，项目锚表/NVD 惯例）；全模板重写",
    "敷衍修复队列 + 项目 JWT 锚（deferred_queue §3.2），label_basis=audit")

# ================= 1868（352，补锚+核验+锚句） =================
r = ROWS[1868 - 1]
assert "bank_transfer" in r["messages"][1]["content"]
n = (
    "分析过程：\n"
    "1. **入口与操作定性**：第 4-5 行 `/bank/transfer` POST 路由执行资金转账（敏感状态变更）；"
    "第 7-8 行 `request.form['to_account']`/`amount` 是跨站表单中攻击者可完整预填的参数。\n"
    "2. **防御逐段核验**：第 6 行注释自认\"未校验 CSRF token\"——第 7-13 行全文件无 token/一次性 "
    "nonce 校验、无 Origin/Referer 校验、无二次确认；第 12 行 `session['user_id']` 只证明\"发起"
    "请求的浏览器有登录态\"——**登录态 Cookie 随跨站请求自动附带，恰是 CSRF 的攻击前提而非防御**"
    "（伪防御：把身份认证当请求来源校验）。\n"
    "3. **利用**：攻击者页面构造自动提交表单 "
    "`<form action=https://bank/bank/transfer method=POST><input name=to_account value=attacker>"
    "<input name=amount value=10000></form>` → 已登录受害者访问即完成转账。\n"
    "4. **互斥辨析**：非 CWE-862/639——授权存在（session 用户身份），缺的是**请求来源**校验；"
    "非 CWE-79——无 HTML 回显；非 CWE-284 泛化——缺陷精确落在跨站伪造面。\n"
    "5. **结论**：CWE-352 Cross-Site Request Forgery (CSRF)，风险 High（直接资金损失）。\n"
)
a = mk(n, {
    "has_vulnerability": True,
    "vulnerability_type": "CWE-352 Cross-Site Request Forgery (CSRF)",
    "risk_level": "High",
    "source": "line 7-8: request.form 的 to_account/amount（跨站表单可预填）",
    "sink": "line 11: db.execute 执行转账（全程无 token/Origin 校验）",
    "explanation": "line 4 敏感状态变更 → line 7-8 攻击者可预填参数 → line 11 落库；登录态 Cookie 自动附带"
                   "使攻击者借受害者会话发起请求（第 12 行 session 是攻击前提非防御）→ CSRF；"
                   "非 862/639（授权存在，缺来源校验）；非 79（无回显）",
    "fix_suggestion": "line 6 后: 增加 CSRF token 校验（session 预存随机 token + 表单回传比对），"
                      "或校验 Origin/Referer 白名单；金额类操作建议二次确认",
})
r["messages"][2]["content"] = a
log(1868, 1868, "敷衍修复：补行锚（原叙事零行引用）+伪防御辨析（session≠来源校验）+利用链+互斥锚句；Medium→High（资金操作）",
    "敷衍修复队列 R1 + 代码级复核")

with DATA.open("w", encoding="utf-8", newline="\n") as f:
    for row in ROWS:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")

for idx in (638, 886, 2108, 1868):
    a2 = ROWS[idx - 1]["messages"][2]["content"]
    m = re.search(r"\n```json\n(\{.*?\})\n```", a2, re.S)
    json.loads(m.group(1))
print("PASS: 638/886/2108/1868 已修复落盘")
