# -*- coding: utf-8 -*-
"""FIX 队列 P0×3 落盘（20260908）。

- 7271（今日行 10150，9/7 从 pack_24 重建）：教师判 safe 实为 SSRF。翻正 true/CWE-918：
  ① requests.get 默认 allow_redirects=True 且逐跳不过 is_safe_url
  ② BLOCKED_RANGES 缺 0.0.0.0/8  ③ 缺 IPv4-mapped IPv6（::ffff:0:0/96）。
- 7455（今日行 10151，9/7 从 pack_27 重建）：CWE-1336→915；影响改写为翻译投毒 +
  深键 DoS；删"__class__ 属性链"虚构（Python dict 无原型链，dunder 段为字面键）；
  锚修正 22→20 / 33→32 / 6-14→8-16 / 37→12-16 / fix 9→10。
- 7341（重建后今日行 7336，7455 的同码孪生，9/7 注记"建议家族合并处置"）：
  L2 改标已到 915，本脚本同步纠偏其 __class__ 链叙事与 JSON explanation。

定位：内容锚 + 唯一性断言（不依赖行号缓存）。
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"

N918 = "CWE-918 Server-Side Request Forgery (SSRF)"
N915 = "CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes"

rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]


def find_one(anchor, extra=None):
    hits = [i for i, r in enumerate(rows) if anchor in r["messages"][1]["content"]
            and (extra is None or extra in r["messages"][2]["content"])]
    assert len(hits) == 1, f"锚不唯一({len(hits)}): {anchor[:50]}"
    return hits[0]


def set_assistant(idx, new_text, fid, note, basis):
    rows[idx]["messages"][2]["content"] = new_text
    with CHANGELOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps({
            "date": "2026-09-08", "step": "1.4_fix_queue_P0", "action": "FIX",
            "fix_id": fid, "row_line_before": idx + 1, "note": note, "basis": basis,
        }, ensure_ascii=False) + "\n")


# ---------- 7271 ----------
i = find_one("BLOCKED_RANGES", "is_safe_url")
old = rows[i]["messages"][2]["content"]
assert '"has_vulnerability": false' in old, "7271 现状应为判 safe"
new = (
    "1. **第 31-38 行** BLOCKED_RANGES 黑名单覆盖回环（127.0.0.0/8、::1/128）、内网段"
    "（10/8、172.16/12、192.168/16）与链路本地段（169.254.0.0/16），但**缺 0.0.0.0/8**"
    "（Linux 上 0.0.0.0 路由到本机）与 **IPv4-mapped IPv6 段 ::ffff:0:0/96**"
    "（::ffff:127.0.0.1 等价于 127.0.0.1 却不被任何条目拦截）——黑名单不完整。\n"
    "2. **第 40-42 行** _is_ip_blocked 与 **第 45-50 行** _hostname_resolves_to_blocked_ip "
    "的比对逻辑本身正确（含 DNS 失败 fail-closed），但只在**首次请求前**被调用一次。\n"
    "3. **第 53-60 行** is_safe_url：scheme 白名单（http/https）+ hostname 直接 IP 比对 / "
    "域名全量解析比对。**第 62-66 行** fetchHTML 通过校验后执行 "
    "`requests.get(url, timeout=10)`——未禁用重定向（默认 allow_redirects=True），"
    "且每一跳不再经过 is_safe_url。\n"
    "4. **三重绕过链（外部输入 → 内网）**：攻击者提交指向自己服务器的 URL，服务器返回 "
    "302 → `http://0.0.0.0:8080/...`（缺口①）或 `http://[::ffff:127.0.0.1]:9200/`（缺口②）"
    "或直接 `http://127.0.0.1:6379/`（重定向后不复检，缺口③）——requests 自动跟随并在内网"
    "目标上以服务器身份发起请求，`r.text`（第 66 行）把内网响应带回模块输出（第 95 行）归还"
    "攻击者。SSRF 成立。\n"
    "5. **结论**：入口的一次性校验 ≠ 全程防护；has_vulnerability = true，"
    f"{N918}，风险 High。\n"
    "```json\n" + json.dumps({
        "has_vulnerability": True,
        "vulnerability_type": N918,
        "risk_level": "High",
        "source": "line 88: url = request['url']（外部可控）",
        "sink": "line 65: requests.get(url, timeout=10) 默认跟随重定向且逐跳不复检",
        "explanation": "入口校验(第53-64行 scheme 白名单 + IP/DNS 黑名单)通过后 -> 第65行 requests.get "
                       "默认 allow_redirects=True 且每一跳不再经过 is_safe_url -> 302 跳至 0.0.0.0/8"
                       "（黑名单缺口）、::ffff:127.0.0.1（IPv4-mapped IPv6 缺口）或直接 127.0.0.1 -> "
                       "内网响应经 r.text 返回攻击者 -> SSRF；非 safe：入口一次校验不等于全程防护",
        "fix_suggestion": "line 65: 改为 allow_redirects=False 的手动循环，每一跳对新 URL 重新执行 "
                          "is_safe_url（并以解析出的 IP 直连+Host 头固定 DNS，消 TOCTOU）；"
                          "line 31-38: BLOCKED_RANGES 增加 0.0.0.0/8 与 ::ffff:0:0/96",
    }, ensure_ascii=False) + "\n```\n"
)
set_assistant(i, new, 7271, "safe→SSRF 翻正：补三重绕过（重定向逐跳/0.0.0.0-8/::ffff:0:0-96）+新 fix+锚修正",
              "fix_queue_20260907 P0 spec + 9/7 重裁决（R1a 实测链）")

# ---------- 7455 ----------
i = find_one("TRANSLATIONS", "deep_assign")
# 10151 应为 has_vuln true 且已带 915（L2 曾按独立样本改过标签）
old = rows[i]["messages"][2]["content"]
assert '"has_vulnerability": true' in old, "7455 现状应为判 vuln"
new = (
    "1. **第 20 行** `payload = request.get_json(force=True) or {}` 是唯一外部输入入口，"
    "`payload['translations']` 中每条 `entry['key']` 与 `entry['value']` 完全由攻击者控制，"
    "**第 32 行**直接传入 `deep_assign`，可达性成立。\n"
    "2. **第 8-16 行** `deep_assign` 按分隔符 `##` 切分后逐段 `node[seg] = {}` / "
    "`node[segments[-1]] = value` 动态写键；全程无任何对段名的白名单、正则或替换过滤"
    "（第 21 行仅取分隔符），防御缺失。\n"
    "3. **危害（按真实语义）**：攻击者可将任意嵌套键写入全局 `TRANSLATIONS`（第 6 行）——"
    "**翻译投毒**：`/config/<name>`（第 36-38 行）读取的任意键值均可被攻击者预置，下游任何"
    "使用该翻译/配置字典的渲染路径将输出攻击者内容（存储型注入面）；同时超深/超宽键结构造成"
    "**深键 DoS**。勘误：`__class__##__init__##__globals__` 类 dunder 段在 Python dict 中只是"
    "**字面键**（dict 无原型链，不产生属性链污染）——教师原\"类污染链\"叙事为虚构，已删除。\n"
    "4. **第二入口确认**：`get_config` 路由只读不写，无替代污染通道；但污染一旦发生即影响"
    "进程内所有共享该字典的代码路径，且 `/import` 本身就是唯一也是充分的写入口。\n"
    "5. **结论**：存在 " + N915 + "（用户可控动态键写入共享字典：翻译投毒/深键 DoS），"
    "风险 High。\n"
    "```json\n" + json.dumps({
        "has_vulnerability": True,
        "vulnerability_type": N915,
        "risk_level": "High",
        "source": "line 20: request.get_json(force=True) 中 translations[].key 攻击者可控",
        "sink": "line 16: deep_assign 内 node[segments[-1]] = value 动态键写入",
        "explanation": "主链: line 20 JSON body -> line 27:entry.key -> line 32:deep_assign -> "
                       "line 12-16:逐段动态赋值写入全局 TRANSLATIONS; 危害: 翻译投毒(/config/<name> "
                       "第36-38行读取被预置内容, 下游渲染输出攻击者内容)+深键 DoS; 防御分析: 全程无键名"
                       "白名单/黑名单/正则过滤, 分隔符默认 ## 可构造任意深度路径; 勘误: __class__ 等 "
                       "dunder 段在 dict 中为字面键、无属性链污染(原叙事虚构已删); 非 1336: 无模板引擎",
        "fix_suggestion": "line 10: 对每个 segment 校验仅允许 [A-Za-z0-9_-]（拒绝空段与超长/超深路径）"
                          "后再赋值；line 36: /config/<name> 的 name 加白名单",
    }, ensure_ascii=False) + "\n```\n"
)
set_assistant(i, new, 7455, "1336→915 确认；影响改写为翻译投毒+深键 DoS；删 __class__ 链虚构；锚 22→20/33→32/6-14→8-16/37→12-16/fix 9→10",
              "fix_queue_20260907 P0 spec + 9/7 重裁决（dict 无原型链）")

# ---------- 7341 孪生纠偏（今日行 ≈7336） ----------
i = find_one("def deep_assign", "非 1336：无模板引擎，sink 是动态键赋值（对象属性污染）")
old = rows[i]["messages"][2]["content"]
A = "未过滤 `__class__`、`__init__`、`__globals__` 等危险键名——Python 中污染对象属性可通过 `__class__.__init__.__globals__` 链触及全局命名空间，语义上等价于 JS 原型污染（官方 1321 一族）；本样本是 Python 对象/字典的动态属性污染，按本库口径标 CWE-915（动态决定的对象属性未受控修改）。"
B = ("键名无任何白名单/黑名单过滤。危害按真实语义：任意嵌套键写入共享翻译/配置字典"
     "（下游读取被预置内容＝存储型投毒面）与深键 DoS；勘误：dunder 段（`__class__` 等）在 "
     "Python dict 中只是字面键、无属性链可达（dict 无原型链），教师原\"经 __globals__ 触及"
     "全局命名空间\"的说法为虚构，已删。按本库口径标 CWE-915（动态决定的对象属性未受控修改）。")
assert old.count(A) == 1, "孪生行 point3 原文未命中"
new = old.replace(A, B)
import re as _re
m = _re.search(r"\n```json\n(\{.*?\})\n```", new, _re.S)
obj = json.loads(m.group(1))
obj["explanation"] = obj["explanation"].replace(
    "污染模块级 globals 或敏感配置对象",
    "写入共享字典任意嵌套键，污染下游读取方（翻译/配置投毒）与深键 DoS；"
    "dunder 段为字面键无属性链（原叙事虚构已删）")
new = new[: m.start()] + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```\n"
set_assistant(i, new, 7341, "孪生行纠偏：删 __class__ 链虚构，影响改为翻译投毒/深键 DoS（与 7455 家族裁定一致）",
              "fix_queue 7455 家族裁定（9/7 重裁决）+ 9/7 注记'建议家族合并处置'")

# ---------- 落盘 + 自检 ----------
with DATA.open("w", encoding="utf-8", newline="\n") as f:
    for r in rows:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
bad = 0
for r in rows:
    a = r["messages"][2]["content"]
    m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
    if m:
        try:
            json.loads(m.group(1))
        except Exception:
            bad += 1
print(f"自检: 行数 {len(rows)}, JSON 结论块解析失败 {bad}（存量 2 除外应为 0）")
print("PASS")
