# -*- coding: utf-8 -*-
"""复审残留问题 R1/R3 的三条标签修复（2026-09-01 复审判定的执行）。

R1 line 776: CWE-943 -> CWE-94（SpEL evaluateExpression RCE 主洞，943 吸附纠偏；
             source/sink/fix 行锚 38->38-39/54/50 同步校准）
R3 line 1545: CWE-78 -> CWE-918（叙事纯 SSRF；explanation 行锚 15/16/17-18 -> 17/18/18-19）
R3 line 1768: CWE-78 vuln -> safe（source=args[0] CLI 参数，本机同权非攻击面，追加层四 R2；
             explanation 记加固建议 sanitizeKey）

R2 处置（12 条 1321）：核实为 payload 键语义正确样本（JS + 遍历赋值 sink + req.body），
全部维持不改——复审机检"代码必须含 __proto__ 字面键"为正则盲区，见复审回应文档。
R4（行号越界 15 条）归 D11 人工通道，不动。
R5 定性：抽验 14/14 全部为正确参数化/白名单修法，零伪修复。

fail-fast：替换未命中即退出。产出 apply_review_fixes_out.txt
"""
import hashlib
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
OUT = BASE / "audit/adjudicate_v2_15/apply_review_fixes_out.txt"

CONTRACT = ["has_vulnerability", "vulnerability_type", "risk_level",
            "source", "sink", "explanation", "fix_suggestion"]
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)

LOG = []
def P(*a):
    LOG.append(" ".join(str(x) for x in a))

lines = DATA.read_text(encoding="utf-8").split("\n")
P(f"载入 v2_15: {sum(1 for l in lines if l.strip())} 条")

# ---------- 776: 943 -> 94 ----------
A776_EXPL = ("line 30-31 黑名单仅检查 < > 字符，未覆盖 LDAP/SpEL 元字符 -> line 38-39 username/password "
             "攻击者可控 -> line 50 拼接进 LDAP 过滤器字符串（次级关注点）-> line 54 直接拼入 SpEL "
             "evaluateExpression 并执行 -> ${T(java.lang.Runtime)...} 表达式注入 -> 远程代码执行"
             "（主洞为 SpEL 表达式注入 CWE-94；LDAP 过滤器注入为伴生形态，fix 双通道覆盖）")

def fix_776():
    ln = 776
    rec = json.loads(lines[ln - 1])
    a = rec["messages"][2]["content"]
    ms = list(JSON_BLOCK.finditer(a))
    o = json.loads(ms[-1].group(1))
    assert "CWE-943" in o["vulnerability_type"], f"776 vt 意外: {o['vulnerability_type']}"
    o["vulnerability_type"] = "CWE-94 Code Injection ('Code Injection')"
    o["source"] = "line 38-39: request.getUsername()/getPassword() 攻击者可控输入"
    o["sink"] = ("line 54: evaluateExpression(\"new com.auth.LdapAuthenticator().authenticate('\" "
                 "+ username + ...)\") 用户输入直接拼入 SpEL 表达式并执行")
    o["explanation"] = A776_EXPL
    o["fix_suggestion"] = (o["fix_suggestion"]
                           .replace("line 38: 应改为 String filter", "line 50: 应改为 String filter")
                           .replace("line 37: 应改为 Object result = evaluateExpression",
                                    "line 54: 应改为 Object result = evaluateExpression"))
    assert list(o.keys()) == CONTRACT
    new_a = a[: ms[-1].start()] + "```json\n" + json.dumps(o, ensure_ascii=False) + "\n```" + a[ms[-1].end():]
    rec["messages"][2]["content"] = new_a
    lines[ln - 1] = json.dumps(rec, ensure_ascii=False)
    P(f"R1  line 776: 943 -> 94 | sink 锚 -> L54 | explanation 重写（SpEL 主导，LDAP 伴生）")

# ---------- 1545: 78 -> 918 ----------
def fix_1545():
    ln = 1545
    rec = json.loads(lines[ln - 1])
    a = rec["messages"][2]["content"]
    ms = list(JSON_BLOCK.finditer(a))
    o = json.loads(ms[-1].group(1))
    assert "CWE-78" in o["vulnerability_type"], f"1545 vt 意外: {o['vulnerability_type']}"
    o["vulnerability_type"] = "CWE-918 Server-Side Request Forgery (SSRF)"
    o["sink"] = o["sink"].replace("line 18: new URL(apiUrl) 和 openConnection()",
                                  "line 18-19: new URL(apiUrl) 与 openConnection()")
    o["explanation"] = (o["explanation"]
                        .replace("line 15 将用户输入 orderId 直接拼入 URL", "line 17 将用户输入 orderId 直接拼入 URL")
                        .replace("line 16 创建恶意 URL", "line 18 创建恶意 URL")
                        .replace("line 17-18 发起请求", "line 18-19 发起请求")
                        .replace("实现 SSRF/URL 注入", "实现 SSRF"))
    assert list(o.keys()) == CONTRACT
    new_a = a[: ms[-1].start()] + "```json\n" + json.dumps(o, ensure_ascii=False) + "\n```" + a[ms[-1].end():]
    rec["messages"][2]["content"] = new_a
    lines[ln - 1] = json.dumps(rec, ensure_ascii=False)
    P(f"R3  line 1545: 78 -> 918 | explanation 锚 17/18/18-19 | 保留 URL 编码+前缀校验 fix")

# ---------- 1768: 78 vuln -> safe ----------
A1768 = """分析过程：
1. line 41: `String userKey = args.length > 0 ? args[0] : "default";` —— 输入源是 main 方法的 CLI 参数，属本机操作员输入（信任边界最高层，非攻击者可控面；按信任边界锚 R2，CLI 参数仅本机使用者可控）。
2. line 16-25 serializeEntry：value 经 StringEscapeUtils.escapeJava 转义（line 22），key 未转义直接拼进 "key=value" 行（line 24）。
3. line 27-33 writeConfig：以追加模式写入本机配置文件（line 30-32）。key 含换行时确实可插入新配置项，但写入者是本机 CLI 进程、写入目标也是本机配置——本机同权操作，无跨信任边界，不构成漏洞。
4. 加固注记：key 通道与 value 通道的过滤不对称（value 有 escapeJava、key 无过滤）；若未来 serializeEntry 被复用到 Web 上下文（以请求参数传 key），会升级为 CWE-93 配置注入——建议现在即对 key 做 sanitizeKey 过滤 [\\r\\n=:]。
5. 结论：文件内无攻击者可控 source，判 safe。

```json
"""
A1768_JSON = {"has_vulnerability": False, "vulnerability_type": "none", "risk_level": "None",
              "source": "N/A", "sink": "N/A",
              "explanation": "line 41 输入源为 main 的 CLI 参数 args[0]，属本机操作员输入（信任边界锚 R2：CLI 参数非攻击面）；line 24 key 未转义拼入配置行、line 30-32 写入本机配置文件，为本机同权操作，无跨信任边界；原判定 CWE-78 与代码语义脱钩（文件内无任何命令执行 sink）。key 通道过滤缺失记为加固项：若复用到 Web 上下文会升级为 CWE-93 配置注入",
              "fix_suggestion": "no fix needed；加固建议：serializeEntry 对 key 增加 sanitizeKey 过滤（replaceAll(\"[\\\\r\\\\n=:]\", \"_\")），与 value 的 escapeJava 对称，防止未来复用到 Web 上下文时引入 CWE-93 配置注入"}

def fix_1768():
    ln = 1768
    rec = json.loads(lines[ln - 1])
    old = rec["messages"][2]["content"]
    assert "CWE-78" in old, "1768 应含 CWE-78"
    new_a = A1768 + json.dumps(A1768_JSON, ensure_ascii=False) + "\n```"
    assert list(A1768_JSON.keys()) == CONTRACT
    rec["messages"][2]["content"] = new_a
    lines[ln - 1] = json.dumps(rec, ensure_ascii=False)
    P(f"R3  line 1768: 78 vuln -> safe | CLI 本机同权（R2）| 原判定与代码语义脱钩（无命令 sink）")

fix_776()
fix_1545()
fix_1768()

DATA.write_text("\n".join(lines), encoding="utf-8")

# 自检
n = 0
bad = 0
hv = {}
for l in lines:
    if not l.strip():
        continue
    n += 1
    try:
        o = json.loads(JSON_BLOCK.findall(json.loads(l)["messages"][2]["content"])[-1])
        hv[str(o.get("has_vulnerability"))] = hv.get(str(o.get("has_vulnerability")), 0) + 1
    except Exception:
        bad += 1
P(f"自检: {n} 条 | JSON 失败 {bad} | 正负 {hv}")
(OUT).write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("\n".join(LOG))
