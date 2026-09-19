# -*- coding: utf-8 -*-
"""FIX 队列·本体论决策 C 配套改标（20260908）：7322（补报295）/ 7325（补报184）/ 1449（326→327）。"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(Path(__file__).resolve().parents[1])
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"

N295 = "CWE-295 Improper Certificate Validation"
N184 = "CWE-184 Incomplete List of Disallowed Inputs"
N327 = "CWE-327 Use of a Broken or Risky Cryptographic Algorithm"

ROWS = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]


def R(t, x, y):
    assert t.count(x) == 1, f"不唯一({t.count(x)}): {x[:60]}"
    return t.replace(x, y)


def get_json(a):
    m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
    return m, json.loads(m.group(1))


def put_json(a, obj):
    m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
    return a[: m.start()] + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```\n"


def log(fid, line, note, basis="fix_queue_20260907 spec + 9/7 本体论决策 C（配置类封闭清单）"):
    with CHANGELOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"date": "2026-09-08", "step": "1.4_fix_queue_ontologyC",
                            "action": "FIX", "fix_id": fid, "row_line_before": line,
                            "note": note, "basis": basis}, ensure_ascii=False) + "\n")


# ================= 7322（safe → 295） =================
r = ROWS[7250 - 1]
a = r["messages"][2]["content"]
a = R(a, "3. 第 64-68 行的 `InsecureSkipVerify: true` 表面上是危险配置，但该分支仅在 `viper.GetBool(\"auth.ldap.use_tls\")` 显式开启时可达，且连接目标（第 55 行）来自服务器端配置文件而非用户输入，属于部署方对内网",
        "3. 第 64-68 行的 `InsecureSkipVerify: true` 且**无任何补偿控制**（无证书固定、无对端 allowlist、无带外校验）——按 2026-09-07 规则书扩容后的配置类封闭清单（295 在列）判 **CWE-295 Improper Certificate Validation**：威胁模型核的是\"LDAP 连接对端能否被中间人\"，该分支由服务端配置触发、目标非用户输入**不中和**中间人风险（配置来源 ≠ 信任对端的理由）；教师的注入面分析（EscapeFilter/二次 Bind）仍成立，见第 1-2 点。原 \"属于部署方对内网")
m, obj = get_json(a)
obj["explanation"] = obj["explanation"].replace(
    "InsecureSkipVerify 分支仅由服务器端配置触发、目标非用户输入，不可被外部输入利用。",
    "InsecureSkipVerify=true 无补偿控制——按扩容后规则书（配置类封闭清单含 295）判 CWE-295："
    "威胁模型核 LDAP 连接对端能否被中间人，配置来源为服务端不中和该风险；教师\"非外部输入\"论证"
    "仅覆盖注入面，不覆盖传输安全面。")
obj["has_vulnerability"] = True
obj["vulnerability_type"] = N295
obj["risk_level"] = "Medium"
obj["fix_suggestion"] = ("line 64-68: 移除 InsecureSkipVerify 或改为加载私有 CA + 主机名校验"
                         "（ldap.EscapeFilter 与二次 Bind 的注入防御分析保留不变）")
a = put_json(a, obj)
r["messages"][2]["content"] = a
log(7322, 7250, "safe→CWE-295（InsecureSkipVerify=true 无补偿控制，配置类封闭清单）；LDAP 注入防御分析保留")

# ================= 7325（safe → 184） =================
r = ROWS[7253 - 1]
a = r["messages"][2]["content"]
m0 = re.search(r"\n```json\n", a)
a = a[: m0.start()] + (
    "\n【新口径判定】第 28–35 行的 `BLOCKED_CLASSES` 黑名单（6 类）作为**类访问的防线**属"
    "不完整禁用列表（CWE-184 Incomplete List of Disallowed Inputs）：黑名单外可触达敏感层的类"
    "（其他 ORM/DBAL 门面、容器/服务定位器、文件系统门面等）不在列表中即可直达；"
    "checkMethodAllowed 对类侧是黑名单语义而非白名单——黑名单是必要而非充分防御，"
    "教师\"完整覆盖\"的结论按官方字面不成立。tags/filters/functions 侧为白名单，不受此判定影响。\n"
) + a[m0.start():]
m, obj = get_json(a)
obj["explanation"] += ("；【新口径判定】类侧防线为 6 类黑名单（BLOCKED_CLASSES，第 28-35 行），"
                       "属不完整禁用列表（CWE-184）——黑名单外的敏感层类不拦截；"
                       "tags/filters/functions 侧为白名单，不受影响")
obj["has_vulnerability"] = True
obj["vulnerability_type"] = N184
obj["risk_level"] = "Medium"
obj["fix_suggestion"] = ("line 28-35: 类访问改为白名单（allowed_classes 语义），或补齐全部可触达"
                         "敏感层的类并建立增补流程；黑名单仅作纵深")
a = put_json(a, obj)
r["messages"][2]["content"] = a
log(7325, 7253, "safe→CWE-184（6 类黑名单当防线=不完整禁用列表）；教师锚与原判分析保留")

# ================= 1449（326→327，High→Medium，删无操作 fix） =================
r = ROWS[1405 - 1]
a = r["messages"][2]["content"]
a = R(a, "1. 第11行注释揭示了定时任务使用 `curl -k` 访问该服务", "1. 第13行注释揭示了定时任务使用 `curl -k` 访问该服务")
a = R(a, "2. 第23-24行配置 `ssl_protocols TLSv1 TLSv1.1`，明确启用了已被废弃的TLS 1.0/1.1协议，不符合PCI DSS等合规要求，属于CWE-326 Inadequate Encryption Strength",
        "2. 第25行配置 `ssl_protocols TLSv1 TLSv1.1`，明确启用了已被废弃的TLS 1.0/1.1协议，"
        "不符合PCI DSS等合规要求，属于CWE-327 Use of a Broken or Risky Cryptographic Algorithm"
        "（官方字面含协议/算法选择；326 针对加密强度量级，本样本为协议族整体废弃，按本库口径归 327）")
a = R(a, "3. 第25行 `ssl_ciphers HIGH:!aNULL:!MD5`", "3. 第26行 `ssl_ciphers HIGH:!aNULL:!MD5`")
a = R(a, "4. 第26行 `ssl_prefer_server_ciphers on`", "4. 第27行 `ssl_prefer_server_ciphers on`")
m, obj = get_json(a)
obj["vulnerability_type"] = N327
obj["risk_level"] = "Medium"
obj["source"] = "line 25: ssl_protocols TLSv1 TLSv1.1 启用不安全的旧版TLS协议"
obj["sink"] = "line 21: listen 443 ssl 将弱TLS配置暴露于生产环境HTTPS端口"
obj["explanation"] = ("line 25:启用TLS 1.0/1.1（CWE-327，官方字面含协议/算法选择）→ 结合 line 13 定时任务 "
                      "curl -k 跳过验证 → line 21:暴露于 443 端口 → 中间人可降级/窃听；"
                      "评级 High→Medium（内网健康检查场景，机密性影响有限）")
obj["fix_suggestion"] = ("line 25: 应改为 ssl_protocols TLSv1.2 TLSv1.3;；line 26: 应改为 "
                         "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                         "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                         "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;"
                         "（勘误：原 fix 的 line 27 ssl_prefer_server_ciphers on 为现状配置、无操作，已删；"
                         "自签名证书问题见 line 28-29，需换 CA 签发证书并去掉 curl -k）")
a = put_json(a, obj)
r["messages"][2]["content"] = a
log(1449, 1405, "326→327（官方字面含协议）；High→Medium；删无操作 fix（line 27 现状）；锚 11→13/23-24→25/sink 26→21")

with DATA.open("w", encoding="utf-8", newline="\n") as f:
    for row in ROWS:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")

for idx in (7250 - 1, 7253 - 1, 1405 - 1):
    a2 = ROWS[idx]["messages"][2]["content"]
    m = re.search(r"\n```json\n(\{.*?\})\n```", a2, re.S)
    o = json.loads(m.group(1))
    assert o["has_vulnerability"] is True
print("PASS: 7322→295 / 7325→184 / 1449→327 已落盘")
