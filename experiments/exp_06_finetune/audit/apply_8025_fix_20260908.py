# -*- coding: utf-8 -*-
"""FIX 队列 P0-8025 落盘（20260908）：开放重定向翻案（R1a 实测链）。

urlparse('////evil.com') → netloc='' / path='//evil.com'（protocol-relative 落入 path）
→ 防御"只取 path"原样放行 → RedirectResponse 发 Location: //evil.com → 浏览器按
protocol-relative 解析跳转外域。未认证 /logout（149-150）可达。
锚修正：206→222 / 215→230 / 15-18→17-20 / 26-27→38 / 97→119 / 204-215→219-230。
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"

N601 = "CWE-601 Uniform Resource Locator Redirection to Untrusted Site ('Open Redirect')"

rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
hits = [i for i, r in enumerate(rows)
        if "_redirect_to_target" in r["messages"][2]["content"]
        and "safe_target = parsed.path" in r["messages"][1]["content"]]
assert len(hits) == 1, f"8025 锚不唯一: {hits}"
r = rows[hits[0]]
a = r["messages"][2]["content"]
assert '"has_vulnerability": false' in a, "8025 现状应为判 safe"


def R(t, x, y):
    assert t.count(x) == 1, f"替换源不唯一({t.count(x)}): {x[:60]}"
    return t.replace(x, y)


a = R(a, "**1. 环境变量读取（第 15–18 行）**", "**1. 环境变量读取（第 17–20 行）**")
a = R(a, "- 第 26–27 行：根据 `get_space()` 选择真实或 mock 路由。",
        "- 第 38 行：根据 `get_space()` 选择真实或 mock 路由。")
a = R(a, "`_nb_redirects` 经 `int()` 转换（第 97 行）", "`_nb_redirects` 经 `int()` 转换（第 119 行）")

OLD6 = """**6. `_redirect_to_target`（第 204–215 行）——关键 sink 分析**
- source：`request.query_params.get('_target_url')`（第 206 行），完全用户可控。
- sink：`RedirectResponse(safe_target)`（第 215 行）。
- 防御验证：第 207–214 行使用 `urllib.parse.urlparse(target)` 解析后**只保留 `parsed.path`**，scheme 与 netloc 被丢弃，因此 `//evil.com`、`https://evil.com`、`javascript:` 等开放重定向 payload 均被剥离为纯路径；path 以 `/` 开头时不会跳离当前域。query/fragment 虽被保留，但它们附着在同源路径之后，不能构成跨域重定向。该防御是结构性的（白名单式只取 path），非黑名单/正则，视为有效。
- 边界情况：若 path 为空则回退到 `/`（第 208 行 `or '/'`），无绕过空间。"""
NEW6 = """**6. `_redirect_to_target`（第 219–230 行）——关键 sink 分析（实测翻案）**
- source：`target = request.query_params.get('_target_url', default_target)`（第 222 行），完全用户可控；`/logout`（第 149-150 行）未认证可达。
- sink：`return RedirectResponse(safe_target)`（第 230 行）。
- 防御缺陷（实测验证）：第 223-225 行 `urllib.parse.urlparse(target)` 后**只保留 `parsed.path`**——但对 `////evil.com` 这类输入，urlparse 给出 `netloc=''`、`path='//evil.com'`（前两个斜杠被解析为空 authority，其余 `//evil.com` 全部落入 path）。"只取 path" 于是原样放行 `//evil.com`；第 230 行发出 `Location: //evil.com`，浏览器按 protocol-relative 语义解析为 `https://evil.com/`（当前 scheme 下任意域）——开放重定向成立。实测链：`urlparse('////evil.com')` → `netloc=''` / `path='//evil.com'` → `safe_target='//evil.com'` → `Location: //evil.com`。
- 边界情况：path 为空回退 `/`（第 225 行 `or '/'`）本身无碍；但**以 `//` 开头的 path 正是绕过体**——"path 以 / 开头不会跳离当前域"仅对单斜杠成立，protocol-relative URL 是标准浏览器语义。"""
a = R(a, OLD6, NEW6)

a = R(a, "- 全部三个路由（login、callback、logout）的出站重定向最终都收敛到 `_redirect_to_target` 或固定 SPACE_HOST 前缀，无遗漏的 raw `RedirectResponse(request.query_params[...])`。",
        "- 全部三个路由（login、callback、logout）的出站重定向中，callback 与 logout 均经 `_redirect_to_target`——正是上述缺陷 sink；收敛到固定 SPACE_HOST 的只是无 `_target_url` 时的默认分支。")
a = R(a, "**结论**：唯一的用户可控 source→sink 流（`_target_url` → RedirectResponse）已被结构性防御（urlparse 后仅取 path）有效阻断；其余重定向目标均锚定环境变量中的 SPACE_HOST。未发现可利用漏洞。",
        f"**结论**：唯一的用户可控 source→sink 流（`_target_url` → RedirectResponse）的防御可被 protocol-relative path（`////evil.com`）绕过，未认证 `/logout` 即可达，构成开放重定向（CWE-601），可用于钓鱼跳转/OAuth 回落劫持。")

m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
obj = json.loads(m.group(1))
obj["has_vulnerability"] = True
obj["vulnerability_type"] = N601
obj["risk_level"] = "High"
obj["source"] = "line 222: target = request.query_params.get('_target_url', default_target)（未认证 /logout 可达，第149-150行）"
obj["sink"] = "line 230: return RedirectResponse(safe_target)"
obj["explanation"] = ("line 222 用户可控 _target_url -> line 223-225 urlparse 仅取 path，但 ////evil.com "
                      "经 urlparse 得 netloc='' 且 path='//evil.com'（protocol-relative 落入 path）-> "
                      "line 230 发出 Location: //evil.com -> 浏览器按 protocol-relative 解析跳转外域 -> "
                      "开放重定向；防御只对单斜杠 path 成立，未覆盖 // 前缀")
obj["fix_suggestion"] = ("line 225: 对 parsed.path 做多斜杠归一（re.sub('^/+', '/', path)）或直接拒绝以 "
                          "// 开头的 path（归一化或 400）；line 230: 出站前断言最终重定向串不以 // 开头")
a = a[: m.start()] + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```\n"
r["messages"][2]["content"] = a

with DATA.open("w", encoding="utf-8", newline="\n") as f:
    for row in rows:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
with CHANGELOG.open("a", encoding="utf-8") as f:
    f.write(json.dumps({
        "date": "2026-09-08", "step": "1.4_fix_queue_P0", "action": "FIX",
        "fix_id": 8025, "row_line_before": hits[0] + 1,
        "note": "safe→CWE-601 翻案：////evil.com protocol-relative 绕过只取 path 防御；未认证 /logout 可达；锚 206→222/215→230/97→119/204-215→219-230",
        "basis": "fix_queue_20260907 P0 spec + R1a 审计员实测链（对账记录 附4/附5）",
    }, ensure_ascii=False) + "\n")

# 自检
a2 = json.loads(DATA.open(encoding="utf-8").readlines()[hits[0]])["messages"][2]["content"]
assert '"has_vulnerability": true' in a2 and "CWE-601" in a2
print(f"PASS: 8025 已翻正为 CWE-601（行 {hits[0]+1}）")
