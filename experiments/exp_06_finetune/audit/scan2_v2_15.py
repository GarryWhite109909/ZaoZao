# -*- coding: utf-8 -*-
"""v2_15 第二轮扫描：按文档机检断言口径精确化。

1. P0-A 真断言：explanation 关键词 ↔ 标签一致性（117/134/532/312/1321/1336 六族）
2. P0-C 收紧版：negation 守卫 + 主体限定，只留疑似真命中（供逐条人工裁定）
3. P1-B 第三类抽样：SQLi×参数化 fix 的完整 fix 文本（决定是否为真混淆）
4. P1-A ldap 系完整 fix 文本
输出：audit/scan2_v2_15_out.txt
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[1]
SRC = BASE / "data/final_train_chatml_alpha06_v2_14.jsonl"
OUT = Path(__file__).with_name("scan2_v2_15_out.txt")

LOG = []


def P(*a):
    LOG.append(" ".join(str(x) for x in a))


JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)


def last_json(a):
    m = JSON_BLOCK.findall(a)
    if not m:
        return None
    try:
        return json.loads(m[-1])
    except Exception:
        return None


rows = []
with SRC.open(encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        if line.strip():
            rows.append((i, json.loads(line)))

parsed = []
for i, rec in rows:
    a = rec["messages"][2]["content"]
    o = last_json(a)
    u = rec["messages"][1]["content"]
    kind = (rec.get("meta") or {}).get("kind", "")
    parsed.append((i, rec, u, a, o or {}, kind))

# ------------------------------------------------ P0-A 关键词↔标签一致性
P("=" * 74)
P("[1] P0-A 机检断言：explanation 关键词与标签一致性")
P("=" * 74)
pa_hits = []
for i, rec, u, a, o, kind in parsed:
    if o.get("has_vulnerability") is not True:
        continue
    vt = str(o.get("vulnerability_type", ""))
    expl = str(o.get("explanation", ""))
    body = a.split("```json")[0] if "```json" in a else a
    text = expl + " " + body[-600:]
    nums = re.findall(r"CWE-(\d+)", vt)
    if not nums:
        continue
    primary = nums[0]
    hit = None
    if primary == "117":
        bad_narr = re.search(r"(敏感信息|敏感数据)[^。\n]{0,15}(泄露|泄漏)", text)
        good_anchor = re.search(r"(伪造|换行|\\n|\\r|控制符|日志条目|日志注入)", text)
        if bad_narr and not good_anchor:
            hit = "117 组出现'敏感信息泄露'叙事且无 117 锚点"
    elif primary == "1336":
        bad_narr = re.search(r"(未转义|XSS)", text)
        good_anchor = re.search(r"(模板语法|模板源码|模板执行|当作模板|模板编译|from_string|Template\(|注入模板|模板引擎)", text)
        if bad_narr and not good_anchor:
            hit = "1336 组出现'未转义/XSS'叙事且无模板执行锚点"
    elif primary == "134":
        if not re.search(r"(格式串|格式化字符串|格式字符串|%n|%s|%d|格式符|printf|format)", text):
            hit = "134 组无格式串锚点"
    elif primary == "532":
        if not re.search(r"(敏感|密码|口令|token|令牌|密钥|secret|credential|凭据)", text):
            hit = "532 组无敏感字面值锚点"
    elif primary == "312":
        if re.search(r"(写入?日志|落日志|日志文件)", text) and not re.search(r"(数据库|DB|数据库文件|明文存储|缓存|cookie|Cookie|配置文件|非日志)", text):
            hit = "312 组叙事指向日志介质（疑应 532）"
    elif primary == "1321":
        if not re.search(r"(原型|prototype|__proto__|污染|键名)", text):
            hit = "1321 组无原型链锚点"
    if hit:
        pa_hits.append((i, hit, vt[:60], expl[:110]))
P(f"命中 {len(pa_hits)} 条:")
for i, hit, vt, expl in pa_hits:
    P(f"  line {i} [{hit}] vt={vt}")
    P(f"      expl: {expl}")

# ------------------------------------------------ P0-C 收紧版
P("")
P("=" * 74)
P("[2] P0-C 收紧版（negation 守卫 + 主体限定）")
P("=" * 74)
NEG = r"(?<!不)(?<!非)(?<!并非)(?<!不是)(?<!区别于)(?<!不同于)(?<!无意)"


def sent_around(text, m, back=60, fwd=80):
    s = max(0, m.start() - back)
    return text[s:m.end() + fwd].replace("\n", " ")


pc_hits = []
PC2 = [
    ("P0C-1a", re.compile(r"from_string[^。\n]{0,60}按字面量|按字面量[^。\n]{0,30}(执行|处理|解析)")),
    ("P0C-1b", re.compile(r"from_string[^。\n]{0,60}(不会?执行|无法执行|不(进行)?模板(编译|渲染))")),
    ("P0C-2a", re.compile(r"(==|字符串比较|字符串\s*==|str 比较)[^。\n]{0,25}(是|为)(?:(?!compare_digest|hmac)[^。\n]){0,8}(恒定时间|常数时间|常量时间)")),
    ("P0C-2b", re.compile(r"==[^。\n]{0,25}比较[^。\n]{0,20}不会?(泄露|泄漏)")),
    ("P0C-3a", re.compile(r"extractall[^。\n]{0,120}(path[^。\n]{0,25}常量|常量[^。\n]{0,25}path|无法(通过|被)[^。\n]{0,25}(控制|影响|操纵))")),
    ("P0C-3b", re.compile(r"(extractall|tar)[^。\n]{0,90}(等效|等同|相当)[^。\n]{0,15}(os\.system|命令)|os\.system[^。\n]{0,15}级别")),
    ("P0C-3c", re.compile(r"(extractall|tar\.)[^。\n]{0,80}(就是|属于|构成|是)[^。\n]{0,10}(命令注入|命令执行|系统命令)")),
    ("P0C-4a", re.compile(r"(未调用|没有调用|不调用)[^。\n]{0,25}render_template[^。\n]{0,50}(不涉及|不构成|不(是|存在|属于|算))")),
    ("P0C-4b", re.compile(r"autoescape[^。\n]{0,60}(即可|就能|可以|从而|因此|得以)[^。\n]{0,10}(防|阻止|避免|杜绝|阻断)")),
]
for i, rec, u, a, o, kind in parsed:
    o = o if isinstance(o, dict) else {}
    expl = str(o.get("explanation", ""))
    body = a.split("```json")[0] if "```json" in a else a
    for field, text in (("expl", expl), ("body", body)):
        if not text:
            continue
        for pid, pat in PC2:
            m = pat.search(text)
            if m:
                pc_hits.append((i, pid, field, sent_around(text, m)))
P(f"命中 {len(pc_hits)} 条:")
for i, pid, field, ctx in pc_hits:
    P(f"  line {i} {pid}({field}): …{ctx}…")

# ------------------------------------------------ P1-B 第三类抽样
P("")
P("=" * 74)
P("[3] P1-B 第三类：SQLi×参数化 fix 抽样（前 12 条全文本）")
P("=" * 74)
n = 0
for i, rec, u, a, o, kind in parsed:
    if not isinstance(o, dict) or o.get("has_vulnerability") is not True:
        continue
    vt = str(o.get("vulnerability_type", ""))
    fix = str(o.get("fix_suggestion", ""))
    if "CWE-89" in vt and re.search(r"参数化", fix):
        n += 1
        if n <= 12:
            sink = str(o.get("sink", ""))[:80]
            P(f"  line {i} kind={kind}")
            P(f"    vt: {vt[:70]}")
            P(f"    sink: {sink}")
            P(f"    fix: {fix[:200]}")
P(f"  SQLi×参数化 命中共 {n} 条")

# ------------------------------------------------ P1-A ldap 全文
P("")
P("=" * 74)
P("[4] P1-A ldap.escape 系完整 fix")
P("=" * 74)
for i, rec, u, a, o, kind in parsed:
    if i not in (880, 949, 1011, 1209):
        continue
    o = o if isinstance(o, dict) else {}
    P(f"  line {i} kind={kind} vt={str(o.get('vulnerability_type',''))[:50]}")
    P(f"    fix: {str(o.get('fix_suggestion',''))[:300]}")

Path(OUT).write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("scan2 done ->", OUT.name)
