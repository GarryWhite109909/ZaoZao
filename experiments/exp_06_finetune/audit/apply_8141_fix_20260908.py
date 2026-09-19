# -*- coding: utf-8 -*-
"""FIX 队列：8141（safe→CWE-184，删两样本外断言，系统性锚修正）。"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(Path(__file__).resolve().parents[1])
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"

N184 = "CWE-184 Incomplete List of Disallowed Inputs"

ROWS = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]


def R(t, x, y):
    assert t.count(x) == 1, f"不唯一({t.count(x)}): {x[:60]}"
    return t.replace(x, y)


def anchor_patterns(tok_old, tok_new):
    o = re.escape(tok_old).replace(r"\-", "[-–—]")
    return [
        (rf"第\s*{o}\s*行", f"第 {tok_new} 行"),
        (rf"第{o}行", f"第{tok_new}行"),
        (rf"line\s*{o}(?=[::\s，,)）])", f"line {tok_new}"),
    ]


r = ROWS[8049 - 1]
a = r["messages"][2]["content"]
assert "Grav" in a

# 1) 系统性锚修正
n_sub = 0
for old, new in [("148-215", "181-253"), ("226-246", "267-292"), ("46-58", "50-62"), ("63-91", "70-90")]:
    for pat, rep in anchor_patterns(old, new):
        a, k = re.subn(pat, rep, a)
        n_sub += k
print(f"8141 reline 替换 {n_sub}")

# 2) 删 chr-DoS 断言（chr 取低 8 位，php.net 实证）
a = R(a, "   - 另外第 170 行 `chr(hexdec(...))` 对超长十六进制会产生 >255 值，PHP 8 下抛错，可被用于 DoS/异常中断检测流程。",
        "   - （勘误：原\"chr-DoS\"断言删除——chr 对超长十六进制取低 8 位，php.net 实证，不产生 >255 值异常。）")

# 3) quarantine 第二入口 → 部署假设
a = R(a, "隔离目录在 web 可达路径下（Grav 的 log 位于站点根），且保存的是**未经净化的原始内容**，构成第二入口：攻击者可诱导写入后直接访问 `log/quarantine/xxx.svg` 触发存储型 XSS。",
        "隔离目录的可达性属**部署假设**：上游根 .htaccess 对 logs/ 默认 403（该事实经上游实测成立，但不在本样本代码内，不能作为样本内防御引用）；若部署未保留该规则，隔离保存的**未经净化原始内容**即构成第二入口（`log/quarantine/xxx.svg` 存储型 XSS）。")

# 4) cleanDangerousTwig 主洞 → 184
a = R(a, "均可绕过该名单执行任意函数——典型 CWE-1336/CWE-94。",
        "均可绕过该名单执行任意函数。**新口径判定**：`$bad_twig` 黑名单（第 273-283 行，9 项）不含 "
        "system/exec/include/constant 等危险函数——**不完整禁用列表即 CWE-184**，为本样本主洞"
        "（原 High XSS/79 标签撤销：本文件无输出汇点，CWE-79 的 source/sink 均不在样本内）。")

m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
obj = json.loads(m.group(1))
obj["has_vulnerability"] = True
obj["vulnerability_type"] = N184
obj["risk_level"] = "Medium"
obj["source"] = "line 267-292: cleanDangerousTwig 以 $bad_twig 黑名单过滤 Twig 危险调用，名单（第 273-283 行，9 项）不含 system/exec/include/constant 等"
obj["sink"] = "line 273-283: 黑名单放行名单外任意 Twig 函数/过滤器调用"
obj["explanation"] = ("cleanDangerousTwig 对 Twig 注入做纯黑名单过滤：$bad_twig 仅 9 项且不含 "
                      "system/exec/include/constant——不完整禁用列表（CWE-184），attribute()/高阶函数/"
                      "拼接边界等替代通道可达名单外危险函数；原 High XSS（79）撤销：本文件无输出汇点；"
                      "quarantine 存储链可达性属部署假设（上游 .htaccess 实测 403 但不在样本内，"
                      "不作为样本内防御引用）；chr-DoS 断言删除（chr 取低 8 位，php.net 实证）；"
                      "detectXss 黑名单可绕过的批评按新口径归入 184 防线不完整，调用侧误用部分降为备注")
obj["fix_suggestion"] = ("line 273-283: $bad_twig 改为白名单（allowed Twig functions/filters），至少补齐 "
                         "system/exec/include/constant/attribute/map/filter/sort/reduce；检测器建议调用侧"
                         "改用 HTMLPurifier 类白名单净化并多轮迭代解码")
a = a[: m.start()] + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```\n"
r["messages"][2]["content"] = a

with DATA.open("w", encoding="utf-8", newline="\n") as f:
    for row in ROWS:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
with CHANGELOG.open("a", encoding="utf-8") as f:
    f.write(json.dumps({
        "date": "2026-09-08", "step": "1.4_fix_queue_ontologyC", "action": "FIX",
        "fix_id": 8141, "row_line_before": 8049,
        "note": "safe→CWE-184（$bad_twig 9 项黑名单不完整）；删根 .htaccess 样本外断言（改部署假设）+ chr-DoS 断言；锚 148-215→181-253/226-246→267-292/46-58→50-62/63-91→70-90",
        "basis": "fix_queue_20260907 spec + 9/7 本体论决策 C",
    }, ensure_ascii=False) + "\n")

a2 = ROWS[8049 - 1]["messages"][2]["content"]
m2 = re.search(r"\n```json\n(\{.*?\})\n```", a2, re.S)
o2 = json.loads(m2.group(1))
assert o2["has_vulnerability"] is True and "CWE-184" in o2["vulnerability_type"]
print("PASS: 8141 → 184 已落盘")
