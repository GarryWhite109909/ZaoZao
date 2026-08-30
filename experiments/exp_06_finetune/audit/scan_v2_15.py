# -*- coding: utf-8 -*-
"""v2_15 行动清单机检扫描 —— 对 v2_14 全库执行 P0-C / P1-A / P1-B / F8 / P0-A。

依据：audit/优化建议_alpha06_日志类CWE归因辨析_v2_15.md（= v2_14 文档全文，含
2026-08-29 新增 F7/F8）。本脚本只扫描输出命中清单供逐条裁定，不做任何修改。

扫描项：
  P0-C  硬性知识错误词表（from_string 语义 / == 恒定时间 / tarfile 语义 /
        autoescape·render_template 语义）
  P1-A  捏造 API（fix_suggestion 中的 API 调用按模块白名单核对 + isalnum 置空）
  P1-B  伪修复（Object.prototype 值比较；SQLi×参数化 fix 矛盾）
  F8    幻觉类型数据侧校验（vulnerability_type 的 sink 特征必须出现在单文件
        代码中；多文件样本跳过，跨文件族不误伤）
  P0-A  形态指纹标签冲突组（log+fmt / 原型键 / 模板编译 三组跨类别并存）

输出：audit/scan_v2_15_out.txt + audit/scan_v2_15_flags.json
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
SRC = BASE / "data/final_train_chatml_alpha06_v2_14.jsonl"
OUT_LOG = Path(__file__).with_name("scan_v2_15_out.txt")
OUT_FLAGS = Path(__file__).with_name("scan_v2_15_flags.json")

LOG = []


def P(*a):
    LOG.append(" ".join(str(x) for x in a))


JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)
CODE_BLOCK = re.compile(r"```[\w+#-]*\s*\n(.*?)```", re.S)


def last_json(assistant: str):
    m = JSON_BLOCK.findall(assistant)
    if not m:
        return None
    try:
        return json.loads(m[-1])
    except Exception:
        return None


def analysis_body(assistant: str) -> str:
    return assistant.split("```json")[0] if "```json" in assistant else assistant


# ---------------------------------------------------------------- 读入
rows = []
with SRC.open(encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        if line.strip():
            rows.append((i, json.loads(line)))
P(f"读入 {len(rows)} 条（v2_14）")

flags = defaultdict(list)   # category -> [ {line, ...} ]


def add(cat, line, **kw):
    flags[cat].append({"line": line, **kw})


# ---------------------------------------------------------------- 代码/多文件识别
FILE_SEP = re.compile(r"^(?:={3,}\s*(?:文件|File)|#{1,3}\s*(?:文件|File)\s*[:# ]|//\s*====\s*File|【文件\s*\d|File\s*\d+\s*[:：])", re.M)


def code_and_multi(user: str):
    blocks = CODE_BLOCK.findall(user)
    multi = len(blocks) >= 2 or bool(FILE_SEP.search(user))
    return "\n".join(blocks), multi, len(blocks)


# ---------------------------------------------------------------- P0-C 词表
P0C_PATTERNS = [
    ("P0C-1a from_string按字面量", re.compile(r"from_string[^。\n]{0,60}按字面量|按字面量[^。\n]{0,30}(执行|处理|解析)")),
    ("P0C-1b from_string不执行", re.compile(r"from_string[^。\n]{0,60}(不会?执行|无法执行|不(进行)?模板(编译|渲染))")),
    ("P0C-1c 字符串当模板字面量", re.compile(r"(模板|template)[^。\n]{0,30}(按|当|作为)(普通)?(字符串|字面量)[^。\n]{0,20}(处理|使用|返回|输出)")),
    ("P0C-2a ==恒定时间", re.compile(r"(是|为|属于)(恒定时间|常数时间|常量时间)比较|字符串比较[^。\n]{0,10}(恒定|常数|常量)时间|==[^。\n]{0,40}(恒定时间|常数时间|常量时间)")),
    ("P0C-2b ==不泄露", re.compile(r"==[^。\n]{0,25}比较[^。\n]{0,20}不会?(泄露|泄漏|泄露信息)|比较操作[^。\n]{0,20}(恒定|常数|常量)时间")),
    ("P0C-2c 无时序攻击", re.compile(r"(不存在|没有|无)[^。\n]{0,10}(Timing|时序)(攻击|侧信道)")),
    ("P0C-3a extractall常量path", re.compile(r"extractall[^。\n]{0,120}(常量|无法(通过|被)[^。\n]{0,25}(控制|影响|操纵))")),
    ("P0C-3b extractall系统级", re.compile(r"(等效(于)?|等同(于)?|相当于)[^。\n]{0,12}os\.system|os\.system[^。\n]{0,12}级别|tar[^。\n]{0,60}(命令注入|命令执行)")),
    ("P0C-4a 未调render_template即非模板", re.compile(r"(未调用|没有调用|不调用)[^。\n]{0,25}render_template[^。\n]{0,50}(不涉及|不构成|不(是|存在|属于|算))")),
    ("P0C-4b autoescape防SSTI", re.compile(r"autoescape[^。\n]{0,60}(即可|就能|可以|从而|因此|得以)[^。\n]{0,10}(防|阻止|避免|杜绝|阻断)")),
    ("P0C-5 模板串硬编码", re.compile(r"(模板串|template_str)[^。\n]{0,40}硬编码[^。\n]{0,60}(不涉及|不构成|不(是|存在|算))")),
]
for i, rec in rows:
    a = rec["messages"][2]["content"]
    body = analysis_body(a)
    o = last_json(a) or {}
    texts = {"body": body, "explanation": str(o.get("explanation", "")),
             "fix": str(o.get("fix_suggestion", ""))}
    for pid, pat in P0C_PATTERNS:
        for field, t in texts.items():
            m = pat.search(t)
            if m:
                s = max(0, m.start() - 40)
                add("P0C", i, pid=pid, field=field,
                    ctx=t[s:m.end() + 60].replace("\n", " "))

# ---------------------------------------------------------------- P1-A 捏造 API
API_CALL = re.compile(r"\b([A-Za-z_][\w.]*)\.(escape|sanitize|neutralize|secure|desanitize)\s*\(")
API_TRUSTED = {"html", "markupsafe", "jinja2", "xml.sax.saxutils", "cgi", "flask",
               "django.utils.html", "bleach", "werkzeug", "saxutils", "utils",
               "codecs", "re", "stringslice"}
for i, rec in rows:
    a = rec["messages"][2]["content"]
    o = last_json(a) or {}
    fix = str(o.get("fix_suggestion", ""))
    for m in API_CALL.finditer(fix):
        mod = m.group(1)
        if mod.lower() not in API_TRUSTED:
            add("P1A_api", i, call=m.group(0), fix=fix[:160])
    if "isalnum" in fix and re.search(r"置空|清空|替换为空|''|\"\"|空串", fix):
        add("P1A_isalnum", i, fix=fix[:160])

# ---------------------------------------------------------------- P1-B 伪修复
VAL_CMP = re.compile(r"(!==?|===?)\s*Object\.prototype|Object\.prototype\s*(!==?|===?)")
for i, rec in rows:
    a = rec["messages"][2]["content"]
    o = last_json(a) or {}
    if not isinstance(o, dict):
        continue
    fix = str(o.get("fix_suggestion", ""))
    vt = str(o.get("vulnerability_type", ""))
    if VAL_CMP.search(fix):
        add("P1B_valcmp", i, vt=vt[:60], fix=fix[:160])
    if "CWE-89" in vt and re.search(r"参数化", fix):
        add("P1B_sqli_param", i, vt=vt[:60], fix=fix[:160])

# ---------------------------------------------------------------- F8 sink 特征
RECHECK_SINK = {
    "CWE-78": r"subprocess\.(?:run|Popen|call|check_output|check_call)\(|os\.system\(|os\.popen\(|Runtime\.getRuntime\(|ProcessBuilder|child_process",
    "CWE-77": r"subprocess\.(?:run|Popen|call|check_output|check_call)\(|os\.system\(|os\.popen\(|Runtime\.getRuntime\(|ProcessBuilder|child_process",
    "CWE-94": r"\beval\(|\bexec\(|SpelExpressionParser|ExpressionParser|Ognl|\.fromString\(",
    "CWE-89": r"\.execute(?:Query|Update|Many)?\(|executemany\(|raw\(|session\.execute\(",
    "CWE-79": r"innerHTML|document\.write\(|insertAdjacentHTML|\.html\(|render(?:\(|_template)|dangerouslySetInnerHTML|innerText\s*=|\{\{.*\}\}|<%=|\|safe|Markup\(",
    "CWE-80": r"innerHTML|document\.write\(|insertAdjacentHTML|\.html\(|render(?:\(|_template)|dangerouslySetInnerHTML",
    "CWE-22": r"open\(|\.save\(|extractall\(|\.extract\(|os\.path\.join|os\.path\.realpath|readFile|createReadStream|File\(|getResource\(|Files\.",
    "CWE-502": r"pickle\.loads\(|yaml\.load\(|readObject\(|ObjectInputStream|json\.loads\(|parseObject\(|defineClass\(|unserialize| deserialize",
    "CWE-117": r"\blog\b|\blogger\b|\blogging\b|console\.|printf|println|\bprint\(|\becho\b|syslog|error_log|appendFile|winston|monolog|\.info\(|\.warn\(|\.error\(|\.debug\(|\.fatal\(|Log\.|LOG\.",
    "CWE-532": r"\blog\b|\blogger\b|\blogging\b|console\.|printf|println|\bprint\(|\becho\b|syslog|error_log|appendFile|winston|monolog|\.info\(|\.warn\(|\.error\(|Log\.",
    "CWE-312": r"open\(|writeFile|writeFileSync|INSERT\s|insert\(|save\(|localStorage|sessionStorage|database|cursor\.|execute\(|File\(|\.write\(|store\(|put\(",
    "CWE-1321": r"__proto__|constructor|prototype",
    "CWE-915": r"setattr\(|__setattr__|\.setAttribute\(|Object\.defineProperty|Object\.assign|\w+\[[^\]\n]+\]\s*=|instance\[|properties\[|attrs\[|Reflect\.set|\.put\(|field\.set\(",
    "CWE-1336": r"from_string\(|Template\(|render_template|Environment\(|Jinja|jinja|ejs\.render|_\.template|Handlebars|createTemplate|freemarker|velocity|text/template|html/template|Mustache|Twig",
    "CWE-134": r"printf|sprintf|fprintf|String\.format|fmt\.Sprintf|%[sdfnx]|NSLog|String\.format",
    "CWE-208": r"==|!=|memcmp|compare",
    "CWE-798": r"(?i)(password|passwd|secret|api_?key|token|credential|access_?key)\s*[:=]\s*['\"][^'\"]{6,}",
}
RECHECK_CWE = {k: re.compile(v) for k, v in RECHECK_SINK.items()}
f8_checked = f8_hit = 0
for i, rec in rows:
    a = rec["messages"][2]["content"]
    o = last_json(a) or {}
    if not isinstance(o, dict) or o.get("has_vulnerability") is not True:
        continue
    vt = str(o.get("vulnerability_type", ""))
    nums = re.findall(r"CWE-(\d+)", vt)
    if not nums:
        continue
    primary = f"CWE-{nums[0]}"
    if primary not in RECHECK_CWE:
        continue
    u = rec["messages"][1]["content"]
    code, multi, nblk = code_and_multi(u)
    if multi or not code.strip():
        continue
    f8_checked += 1
    if not RECHECK_CWE[primary].search(code):
        f8_hit += 1
        add("F8_sink_absent", i, primary=primary, vt=vt[:70],
            code_head=code[:120].replace("\n", " "))

# ---------------------------------------------------------------- P0-A 冲突组
LOG_SINK = re.compile(r"\blog\b|\blogger\b|\blogging\b|console\.|printf|println|\bprint\(|syslog|error_log|appendFile|\.info\(|\.warn\(|\.error\(")
PROTO_KEY = re.compile(r"__proto__|constructor|prototype")
TPL_COMPILE = re.compile(r"from_string\(|Template\(|render_template|Environment\(|Jinja|jinja|ejs\.render|_\.template|Handlebars|createTemplate|freemarker|velocity")
GROUPS = {
    "G_logfmt": (lambda u: bool(LOG_SINK.search(u)), {"117", "134", "532", "312"}),
    "G_proto": (lambda u: bool(PROTO_KEY.search(u)), {"1321", "915", "912"}),
    "G_tpl": (lambda u: bool(TPL_COMPILE.search(u)), {"1336", "79", "94"}),
}
g_members = defaultdict(lambda: defaultdict(list))
for i, rec in rows:
    a = rec["messages"][2]["content"]
    o = last_json(a) or {}
    if not isinstance(o, dict) or o.get("has_vulnerability") is not True:
        continue
    vt = str(o.get("vulnerability_type", ""))
    nums = {n for n in re.findall(r"CWE-(\d+)", vt)}
    if not nums:
        continue
    u = rec["messages"][1]["content"]
    for gname, (test, family) in GROUPS.items():
        if test(u):
            inter = nums & family
            if inter:
                g_members[gname][frozenset(nums)].append(i)
for gname, combos in g_members.items():
    if len(combos) > 1:
        P(f"[P0-A] {gname} 组存在跨类别并存:")
        for combo, lines in sorted(combos.items(), key=lambda x: -len(x[1])):
            P(f"    {sorted('CWE-'+c for c in combo)}: {len(lines)} 条 {lines[:12]}{'...' if len(lines)>12 else ''}")
        for combo, lines in combos.items():
            for ln in lines:
                add("P0A_conflict", ln, group=gname, labels=sorted(combo))

P("")
P("=" * 70)
P("汇总")
P("=" * 70)
for cat in sorted(flags):
    P(f"  {cat}: {len(flags[cat])} 条")
P(f"  F8 实际检查（单文件+漏洞+主类型在表内）: {f8_checked} 条，命中 {f8_hit}")

OUT_LOG.write_text("\n".join(LOG) + "\n", encoding="utf-8")
with OUT_FLAGS.open("w", encoding="utf-8") as f:
    json.dump({k: v for k, v in flags.items()}, f, ensure_ascii=False, indent=1)
print(f"scan done -> {OUT_LOG.name} / {OUT_FLAGS.name}")
