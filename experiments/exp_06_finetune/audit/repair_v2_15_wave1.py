# -*- coding: utf-8 -*-
"""alpha06 v2_14 -> v2_15 wave1 修复脚本。

依据 audit/数据修复方案_v2_14审计x工具层实测_20260831.md §1.1 + §1.2（第 1 天项）：
  1.1  执行 out/manifest_DELETE.jsonl 全部 72 条
       + 8288（8187 同码孪生：8187 经批 004 裁 DELETE/false_positive critical
         —— 纯类型声明文件 + 虚构 SSRF 叙事；8288 同代码且未审，证据直接迁移）
       + 8968（S7 纯重复组 8966/8968 冗余去 1，保留 8966）
  1.2a fix 转义强污染批量修复（解码级反双转义，逐条 before/after 落盘供字节级复验）
  1.2b R1 bash 双引号族全库签名扫描（只出候选，不改写）
  1.2c R7 数据位族全库签名扫描（render_template_string/ejs/Twig 常量模板位）
  1.2d R8 误导注释族全库签名扫描
  1.2e N29 悬挂 CWE 标签修复（safe 样本 explanation 尾部裸编号 -> 删除）
  1.2f N26 PoC 路径层数核查（窄口径自动比对，命中即报）
  1.2g 杂项单点修：7851 零宽字符 / 8030 user fence(4 反引号) / 8280 悬挂 fence /
       156+401+549 元数据孤立 cwe 键
另产出 redistill_manifest_v2_15_wave1.jsonl（13 条 FN 重蒸馏队列，供 1.4 使用）。

转义修复信号口径（对应审计报告 S4「强污染」）：
  SQ  字段内所有双引号均被反斜杠转义（plain==0 且 escaped>=1）——教师代码的字符串
      定位符被整体双转义，唯一无歧义的强信号；域内偶数反斜杠串统一对半。
  BT  同 SQ，对象为反引号（JS 模板字面量定位符伪影）。
  CH  C 族语言单引号字符字面量内 '\\n'/'\\0'/'\\r'/'\\t' 反斜杠翻倍（审计点名的
      「C 族语言字面 \\\\n/\\\\0」形态）；仅限 '...' 包裹，避免误伤 go/json 的合法
      "\\\\n"（字面反斜杠-n 替换）。
无信号但 S4 阳性的字段（CRLF 叙述、正则 \\\\d、python 原始串等合法/歧义形态）不改动，
落盘 escape_queue 供 1.3 逐条处理。

输出：
  data/final_train_chatml_alpha06_v2_15.jsonl
  audit/repair_v2_15_wave1_out.txt
  audit/repair_v2_15_wave1_escape_review.jsonl   （每个修复字段的 before/after）
  audit/repair_v2_15_wave1_escape_queue.jsonl    （S4 阳性但未自动修的弱/歧义项）
  audit/agent_audit_v2_14/out/repair_v2_15_wave1_scan_candidates.jsonl （R1/R7/R8/N26）
  audit/redistill_manifest_v2_15_wave1.jsonl
"""
import json
import posixpath
import re
import sys
from collections import Counter
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent / "agent_audit_v2_14"
sys.path.insert(0, str(AGENT_DIR))
from acommon import (BASE, OUT, load_rows, asst_text, user_text, last_json,
                     write_jsonl)

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SRC = BASE / "data/final_train_chatml_alpha06_v2_14.jsonl"
OUT_DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
AUDIT_DIR = Path(__file__).resolve().parent
OUT_LOG = AUDIT_DIR / "repair_v2_15_wave1_out.txt"
OUT_ESC_REVIEW = AUDIT_DIR / "repair_v2_15_wave1_escape_review.jsonl"
OUT_ESC_QUEUE = AUDIT_DIR / "repair_v2_15_wave1_escape_queue.jsonl"
OUT_SCAN = OUT / "repair_v2_15_wave1_scan_candidates.jsonl"
OUT_REDISTILL = AUDIT_DIR / "redistill_manifest_v2_15_wave1.jsonl"

LOG = []


def P(*a):
    LOG.append(" ".join(str(x) for x in a))


def rewrite_json_block(rec, o):
    """将 assistant 最后一个 ```json 块整体替换为重新序列化的 o。"""
    a = rec["messages"][2]["content"]
    ms = list(re.finditer(r"```json\s*(.*?)```", a, re.S))
    m = ms[-1]
    rec["messages"][2]["content"] = (a[: m.start()] + "```json\n"
                                     + json.dumps(o, ensure_ascii=False) + "\n```"
                                     + a[m.end():])


rows, _ = load_rows()
R = {r["id"]: r["rec"] for r in rows}
P(f"读入 {len(rows)} 条（v2_14, id=源文件行号）")

man_delete = [json.loads(l) for l in (OUT / "manifest_DELETE.jsonl").open(encoding="utf-8") if l.strip()]
man_fix_ids = {json.loads(l)["id"] for l in (OUT / "manifest_FIX.jsonl").open(encoding="utf-8") if l.strip()}
del_ids = {m["id"] for m in man_delete}

LANG = {}
for rid, r in R.items():
    m = re.search(r"```([\w+#.\-/]*)", user_text(r))
    LANG[rid] = m.group(1).lower() if m else ""

# =================================================================
# 步骤 1 [1.1] 删除
# =================================================================
P("=" * 78)
P("[步骤1] 1.1 DELETE：manifest 72 条 + 8288(同码孪生) + 8968(纯重复)")
P("=" * 78)
EXTRA_DELETE = {
    8288: "8187 同码孪生（S7 同码组）；8187 经批 004 裁 DELETE（false_positive critical："
          "纯 TypedDict 声明文件 + 虚构 SSRF 叙事），8288 未审（kit 031 未派发），同码证据直接迁移",
    8968: "S7 纯重复组 8966/8968（同码同结论），冗余去 1，保留 8966",
}
drop = set(del_ids) | set(EXTRA_DELETE)
FN13 = [4378, 6345, 8965, 4771, 5576, 7456, 7877, 8028, 8210, 9067, 9170, 9750, 8081]
missing_fn = [i for i in FN13 if i not in drop]
if missing_fn:
    P(f"  FN 中 {missing_fn} 不在删除集：reviews 裁决为 FIX（manifest 口径权威），样本保留待 1.3 逐条改写；"
      f"仍列入重蒸馏队列供 1.4 取舍")
else:
    P("  13 条 FN 全部在删除集中: 已核")
REDISTILL = []
for i in FN13:
    rec = R[i]
    m = next((x for x in man_delete if x["id"] == i), None)
    REDISTILL.append({
        "orig_line": i,
        "reason": "false_negative_redistill",
        "note": (m["note"] if m else "") + " —— 教师漏判，无法局部修，整条重蒸馏（方案 §1.4）",
        "user": user_text(rec),
    })
P(f"  重蒸馏队列(FN): {len(REDISTILL)} 条 -> redistill_manifest_v2_15_wave1.jsonl")
P(f"  删除合计: {len(drop)} 条（manifest {len(del_ids)} + 附加 {len(EXTRA_DELETE)}）")

# =================================================================
# 步骤 2 [1.2a] 转义强污染修复
# =================================================================
P("")
P("=" * 78)
P("[步骤2] 1.2a 转义强污染修复（SQ=引号伪影 / BT=反引号伪影 / CH=C族字符字面翻倍）")
P("=" * 78)

CFAM = {"c", "cpp", "c++", "java", "javascript", "js", "ts", "typescript", "go", "php",
        "csharp", "c#", "rust", "swift", "kotlin", "scala", "dart",
        "bash", "sh", "shell", "yaml", "dockerfile"}

def scan_units(t):
    """扫描反斜杠极大游程；返回 (units, plain_q, esc_q, plain_bt, esc_bt)。

    units = [(start, run_len, next_char_or_'')]；escaped 引号 = 紧跟奇数游程的引号。
    """
    units = []
    plain_q = esc_q = plain_bt = esc_bt = 0
    i, n = 0, len(t)
    while i < n:
        if t[i] == "\\":
            j = i
            while j < n and t[j] == "\\":
                j += 1
            units.append((i, j - i, t[j] if j < n else ""))
            i = j
            continue
        if t[i] in ('"', "`"):
            prev_odd = bool(units) and units[-1][1] % 2 == 1 and units[-1][0] + units[-1][1] == i
            if t[i] == '"':
                if prev_odd:
                    esc_q += 1
                else:
                    plain_q += 1
            else:
                if prev_odd:
                    esc_bt += 1
                else:
                    plain_bt += 1
        i += 1
    return units, plain_q, esc_q, plain_bt, esc_bt


CHAR_LIT = re.compile(r"[n0tr][0-7]{0,2}'")   # '\0' '\00' '\n' '\r' '\t' '\012' 的尾部


def repair_escape(t, lg):
    """反双转义。返回 (new_text, signals, residual_flags)。

    分支只决定反斜杠输出数量，跟随字符 c 一律由主循环正常追加（避免重复）。
    """
    units, plain_q, esc_q, plain_bt, esc_bt = scan_units(t)
    SQ = esc_q >= 1 and plain_q == 0
    BT = esc_bt >= 1 and plain_bt == 0
    CH = (lg in CFAM and any(
        l >= 2 and l % 2 == 0 and _ > 0 and t[_ - 1] == "'" and _ + l < len(t)
        and CHAR_LIT.match(t, _ + l)
        for _, l, _c in units))
    signals = {"SQ": SQ, "BT": BT, "CH": CH}
    if not any(signals.values()):
        return t, signals, []
    out = []
    flags = []
    i, n = 0, len(t)
    while i < n:
        if t[i] == "\\":
            j = i
            while j < n and t[j] == "\\":
                j += 1
            L = j - i
            c = t[j] if j < n else ""
            if c == '"' and SQ:
                out.append("\\" * (L // 2))
            elif c == "'" and SQ and not (i > 0 and t[i - 1] == "'") \
                    and not (j + 1 < n and t[j + 1] == "'"):
                out.append("\\" * (L // 2))   # 避开 bash '\'' 惯用法
            elif c == "`" and BT:
                out.append("\\" * (L // 2))
            elif SQ and L >= 2 and L % 2 == 0:
                out.append("\\" * (L // 2))   # SQ 域内偶数串统一对半
            elif CH and not SQ and L >= 2 and L % 2 == 0 \
                    and i > 0 and t[i - 1] == "'" and CHAR_LIT.match(t, j):
                out.append("\\" * (L // 2))   # '\\n' -> '\n'
            else:
                out.append("\\" * L)
                if L % 2 == 1 and L > 1:
                    flags.append(f"odd_run{L}@{i}")
            i = j   # c 留给主循环下一轮正常追加
        else:
            out.append(t[i])
            i += 1
    new = "".join(out)
    if SQ and re.search(r'\\"', new):
        flags.append("residual_escaped_quote")
    if "``" in new and "``" not in t:
        flags.append("introduced_double_backtick")
    if '""' in new and '""' not in t:
        flags.append("introduced_double_quote")
    return new, signals, flags


def prev_is(t, i, ch):
    return i > 0 and t[i - 1] == ch


# ---- 单元测试：roundtrip（dq=再双转义一层后必须能复原）+ 不动组（合法形态） ----
def dq(s):
    """模拟教师端双重转义：反斜杠翻倍 + 双引号加反斜杠。"""
    return s.replace("\\", "\\\\").replace('"', '\\"')

ROUNDTRIP = [
    ('printf("Invalid index\\n"); return 1;', "c"),
    ("drv_buf[copy_len] = '\\0';", "c"),
    ('replace("\\\\", "\\\\5c")', "java"),
    ('username.replace("*", "\\\\2a")', "java"),
    ('f.write(f"# Build script"\\n)', "python"),
    ("printf '%s\\n' \"${alert_msg}\"", "bash"),
    ("tr -d '\\r' > file", "yaml"),
    ('strings.ReplaceAll(s, "\\n", "\\\\n")', "go"),
    ('const cmd = `ping ${host}`;', "javascript"),
    ("out->data[copy_len] = '\\0'; out->len = copy_len;", "c"),
    ('v.replace(/[^a-z0-9_\\/-]/g, "")', "javascript"),   # 正则 \\/ + SQ 引号伪影同域
]
for _x, _lg in ROUNDTRIP:
    _got, _sig, _fl = repair_escape(dq(_x), _lg)
    assert _got == _x, f"roundtrip 失败 [{_lg}] 原始={_x!r} 还原={_got!r} flags={_fl}"

UNTOUCHED = [
    ("strings.ReplaceAll(s, \"\\n\", \"\\\\n\")", "go"),     # 合法 go 字面 \\n（plain 引号）
    ("按 '/' 和 '\\\\' 以及 Base 清洗", "go"),                # 合法 go rune '\\'（无 SQ）
    ("仅替换 \\n 未处理 \\r 但未处理 \\r\\n 组合", "java"),   # 合法 CRLF 叙述
    ("re.fullmatch(r'[A-Za-z0-9_\\-]+', branch)", "python"),  # python 原始串（歧义，不动）
    ("/[^a-zA-Z0-9_\\\\/-]/g.test(x)", "javascript"),         # 无引号上下文的 JS 正则 \\/（歧义，不动）
]
for _x, _lg in UNTOUCHED:
    _got, _sig, _fl = repair_escape(_x, _lg)
    assert _got == _x, f"误伤合法形态 [{_lg}] {_x!r} -> {_got!r}"

# bash '\'' 惯用法在 SQ 域内：dq 后必须还原回单反斜杠惯用法
_bash_in = dq("x = \"a '\\' b\"")
_got, _sig, _fl = repair_escape(_bash_in, "bash")
assert _got == "x = \"a '\\' b\"", f"bash 惯用法还原失败: {_got!r}"
P(f"  转义修复单元测试: roundtrip {len(ROUNDTRIP)} + untouched {len(UNTOUCHED)} + bash 惯用法 全部通过")


esc_review, esc_queue = [], []
esc_stats = Counter()
esc_ids = set()
for rid, rec in R.items():
    if rid in drop:
        continue
    o, _, err = last_json(asst_text(rec))
    if not isinstance(o, dict):
        continue
    lg = LANG[rid]
    changed = False
    for fld in ("fix_suggestion", "explanation", "source", "sink"):
        t = str(o.get(fld, ""))
        if not t:
            continue
        runs = re.findall(r"\\{2,}", t)
        lit_n = len(re.findall(r"\\n", t))
        if not runs and lit_n < 2:
            continue  # S4 阴性
        new_t, signals, flags = repair_escape(t, lg)
        if new_t != t:
            o[fld] = new_t
            changed = True
            esc_ids.add(rid)
            esc_stats[fld] += 1
            esc_review.append({
                "id": rid, "field": fld, "lang": lg,
                "signals": {k: bool(v) for k, v in signals.items()},
                "flags": flags,
                "before": t, "after": new_t,
                "in_fix_manifest": rid in man_fix_ids,
            })
            if flags:
                esc_stats["with_flags"] += 1
        else:
            esc_queue.append({
                "id": rid, "field": fld, "lang": lg,
                "signals": {k: bool(v) for k, v in signals.items()},
                "reason": "S4阳性但无确认信号(弱/合法/歧义)",
                "text": t[:400],
                "in_fix_manifest": rid in man_fix_ids,
            })
    if changed:
        rewrite_json_block(rec, o)

P(f"  修复样本数: {len(esc_ids)}（字段级: {dict(esc_stats)}）")
P(f"  S4 阳性未自动修（弱/合法/歧义）字段: {len(esc_queue)} -> escape_queue.jsonl")
P(f"  before/after 全量落盘: {len(esc_review)} 处 -> escape_review.jsonl（字节级复验用）")

# =================================================================
# 步骤 3 [1.2e] N29 悬挂 CWE 标签
# =================================================================
P("")
P("=" * 78)
P("[步骤3] 1.2e N29 悬挂 CWE 标签（safe 样本 explanation 尾部裸 CWE 编号 -> 删除编号）")
P("=" * 78)
DANGLING = re.compile(r"([。；;！！？?.\s])\s*(CWE-\d{1,4})\s*$")
n29_fixed = []
for rid, rec in R.items():
    if rid in drop:
        continue
    o, _, err = last_json(asst_text(rec))
    if not isinstance(o, dict) or o.get("has_vulnerability") is not False:
        continue
    t = str(o.get("explanation", ""))
    if not t:
        continue
    m = DANGLING.search(t)
    if not m:
        continue
    new_t = (t[: m.start(1)] + m.group(1)).rstrip()
    o["explanation"] = new_t
    rewrite_json_block(rec, o)
    n29_fixed.append({"id": rid, "before": t[-80:], "after": new_t[-80:]})
P(f"  修复 {len(n29_fixed)} 处:")
for x in n29_fixed:
    P(f"    id={x['id']}: …{x['before']!r} -> …{x['after']!r}")

# =================================================================
# 步骤 4 [1.2g] 杂项单点修
# =================================================================
P("")
P("=" * 78)
P("[步骤4] 1.2g 杂项单点修（7851 零宽 / 8030 fence / 8280 悬挂 fence / 元数据 cwe 键）")
P("=" * 78)
ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]")

rec = R[7851]
a = asst_text(rec)
zw = ZERO_WIDTH.findall(a)
if zw:
    rec["messages"][2]["content"] = ZERO_WIDTH.sub("", a)
    P(f"  7851: 移除零宽字符 {len(zw)} 处 {[hex(ord(c)) for c in set(zw)]}")
else:
    P("  7851: 未发现零宽字符（异常）")

rec = R[8030]
u = user_text(rec)
assert u.count("```") == 3, "8030 fence 计数异常"
u2 = u.replace("```javascript\n", "````javascript\n", 1)
assert u2.rstrip().endswith("```")
u2 = u2.rstrip()[:-3] + "````"
rec["messages"][1]["content"] = u2
P(f"  8030: user 围栏升级 4 反引号（```` x{u2.count('````')}；代码内字面 ``` 保留）")

rec = R[8280]
u = user_text(rec)
assert u.count("```") == 3 and u.rstrip().endswith("```"), "8280 fence 形态异常"
u2 = u.rstrip()[:-3].rstrip()
rec["messages"][1]["content"] = u2
P(f"  8280: 删除尾部悬挂 ```（3 反引号剩余 {u2.count('```')} 处 = 代码块开+闭）")

cwe_key_rows = []
for rid, rec in R.items():
    fd = rec.get("fix_distill")
    if isinstance(fd, dict) and "cwe" in fd:
        cwe_key_rows.append(rid)
        fd.pop("cwe")
P(f"  元数据孤立 cwe 键清理: 行 {sorted(cwe_key_rows)}（仅 fix_distill 噪声，不进 tokenizer）")

# =================================================================
# 步骤 5 [1.2b/c/d/f] 签名扫描（只出候选，不改写）
# =================================================================
P("")
P("=" * 78)
P("[步骤5] 1.2b/c/d/f 签名扫描 -> 候选清单（R1/R7/R8/N26，不改写）")
P("=" * 78)
candidates = []

def json_of(rid):
    o, _, _ = last_json(asst_text(R[rid]))
    return o if isinstance(o, dict) else {}

def analysis_of(rid):
    a = asst_text(R[rid])
    return a.split("```json")[0] if "```json" in a else a

def code_of(rid):
    return "\n".join(b for _, b in re.findall(r"```([\w+#.\-/]*)[ \t]*\r?\n(.*?)(?:```|\Z)",
                                              user_text(R[rid]), re.S))

# ---- R1 bash 双引号族 ----
R1_PATS = [
    (r"双引号[^。\n]{0,40}(?:分号|;|；)[^。\n]{0,30}(?:解释|分隔|截断|执行|注入|生效)", "双引号内分号被解释"),
    (r"[;；][^。\n]{0,25}双引号[^。\n]{0,25}(?:内|中)", "分号于双引号内"),
    (r"double.?quotes?[^.\n]{0,50}(?:semicolon|;|command\s+separat|interpreted|executed)", "en: double-quote semicolon"),
    (r"\$\([^)\n]{0,60}\)[^。\n]{0,30}(?:双引号|展开|执行|注入)|双引号[^。\n]{0,40}\$\(", "双引号 $() 展开"),
    (r"(?:词切分|word\s?split)[^。\n]{0,40}(?:注入|命令执行|rce)", "词切分=注入(R1 误判形态)"),
]
r1_seen = set()
n_r1 = 0
for rid in R:
    if rid in drop or rid in man_fix_ids:
        continue
    o = json_of(rid)
    if o.get("has_vulnerability") is not True:
        continue
    if LANG[rid] not in ("bash", "sh", "shell", "python", "go", "javascript", "js",
                         "yaml", "dockerfile", ""):
        continue
    text = analysis_of(rid)[:6000] + str(o.get("explanation", "")) + str(o.get("sink", ""))
    for pat, name in R1_PATS:
        if re.search(pat, text, re.I):
            if name not in r1_seen:
                r1_seen.add(name)
                n_r1 += 1
                candidates.append({
                    "family": "R1_bash_doublequote", "id": rid, "lang": LANG[rid],
                    "trigger": name, "vt": o.get("vulnerability_type"),
                    "action_hint": "按 R1 规则复核叙事链：双引号内 ;|\\ 不被解释、词切分不产生新命令；洞因不成立则改判/删除"})
            break
P(f"  R1 bash 双引号族候选: {n_r1}")

# ---- R7 数据位族 ----
TPL_CALLS = [
    (r"render_template_string\s*\(\s*(['\"])", "flask render_template_string(常量"),
    (r"\bTemplate\s*\(\s*(['\"])", "jinja2 Template(常量"),
    (r"ejs\.render\s*\(\s*(['\"])", "ejs.render(常量"),
    (r"renderString\s*\(\s*['\"]", "twig renderString(常量"),
    (r"nunjucks\.renderString\s*\(\s*(['\"])", "nunjucks renderString(常量"),
    (r"mustache\.render\s*\(\s*(['\"])", "mustache.render(常量"),
    (r"Handlebars\.compile\s*\(\s*(['\"])", "handlebars.compile(常量"),
]
n_r7 = 0
for rid in R:
    if rid in drop or rid in man_fix_ids:
        continue
    o = json_of(rid)
    if o.get("has_vulnerability") is not True:
        continue
    code = code_of(rid)
    hit_call = None
    for pat, name in TPL_CALLS:
        if re.search(pat, code):
            hit_call = name
            break
    if not hit_call:
        continue
    text = (str(o.get("vulnerability_type", "")) + str(o.get("explanation", ""))
            + analysis_of(rid)[:4000])
    if re.search(r"1336|SSTI|模板注入|template\s?injection|服务端模板", text, re.I):
        n_r7 += 1
        candidates.append({
            "family": "R7_data_position_ssti", "id": rid, "lang": LANG[rid],
            "trigger": hit_call, "vt": o.get("vulnerability_type"),
            "action_hint": "区分模板位/数据位：常量模板+输入走上下文形参=数据位，SSTI 不成立（须先核实输入是否拼入模板源码串）"})
P(f"  R7 数据位族候选: {n_r7}")

# ---- R8 误导注释族（两层信号：T1 欺骗性自述=高信号；T2 泛化标记=线索）----
DECOY_T1 = re.compile(r"(?:真正(?:的)?漏洞|迷惑|诱饵|decoy|mislead|假漏洞|伪装"
                      r"|看起来(?:危险|有漏洞)|实则(?:安全|无害)|fake\s*(?:vuln|defense)?)", re.I)
DECOY_T2 = re.compile(r"(?:漏洞点|注入点|此处触发|dangerous|vulnerable)", re.I)
COMMENTS = re.compile(r"^\s*(?://|#|/\*|\*|--|<!--).*$", re.M)
r8_t1, r8_t2 = {}, {}
for rid in R:
    if rid in drop or rid in man_fix_ids:
        continue
    o = json_of(rid)
    if o.get("has_vulnerability") is not True:
        continue
    code = code_of(rid)
    hits1 = [ln.strip() for ln in COMMENTS.findall(code) if DECOY_T1.search(ln)]
    hits2 = [ln.strip() for ln in COMMENTS.findall(code) if DECOY_T2.search(ln)]
    if hits1:
        r8_t1[rid] = hits1[:3]
    if hits2:
        r8_t2[rid] = hits2[:3]
for rid in sorted(r8_t1):
    o = json_of(rid)
    candidates.append({
        "family": "R8_decoy_comment_T1", "id": rid, "lang": LANG[rid],
        "trigger": "注释欺骗性自述（真正漏洞/迷惑/诱饵/伪装）× 判洞结论",
        "comments": r8_t1[rid], "vt": o.get("vulnerability_type"),
        "action_hint": "注释断言与代码逐行核对（R2 注释不可信）；结论若沿注释叙事需重审"})
for rid in sorted(set(r8_t2) - set(r8_t1)):
    o = json_of(rid)
    candidates.append({
        "family": "R8_decoy_comment_T2", "id": rid, "lang": LANG[rid],
        "trigger": "泛化漏洞标记注释 × 判洞结论（低信号线索）",
        "comments": r8_t2[rid], "vt": o.get("vulnerability_type"),
        "action_hint": "存档线索：漏洞样本常带漏洞点注释，仅当结论明显照抄注释时重审"})
P(f"  R8 误导注释族候选: T1 高信号 {len(r8_t1)} / T2 泛化 {len(set(r8_t2) - set(r8_t1))}")

# ---- N26 PoC 路径层数（窄口径）----
N26_PAY = re.compile(r"(?:\.\./){1,}([\w.\-]+)")
N26_CLAIM = re.compile(r"(?:读取|读到|访问|解析|读出|read|access|resolve)[^。\n]{0,60}(/(?:[\w.\-]+/){0,3}[\w.\-]+)")
n26_hit = set()
for rid in R:
    if rid in drop or rid in man_fix_ids:
        continue
    o = json_of(rid)
    if o.get("has_vulnerability") is not True:
        continue
    if "CWE-22" not in str(o.get("vulnerability_type", "")):
        continue
    text = analysis_of(rid)
    for para in text.split("。"):
        for m in N26_PAY.finditer(para):
            fname = m.group(1)
            depth = para[: m.start()].count("../")
            for cm in N26_CLAIM.finditer(para):
                claimed = cm.group(1)
                if not (claimed.startswith("/etc/") or claimed.startswith("/root/")):
                    continue
                resolved = posixpath.normpath("/app/" + "../" * depth + fname)
                if claimed != resolved and resolved.split("/")[-1] == claimed.split("/")[-1]:
                    n26_hit.add(rid)
for rid in sorted(n26_hit):
    o = json_of(rid)
    candidates.append({
        "family": "N26_poc_path_depth", "id": rid, "lang": LANG[rid],
        "trigger": "CWE-22 声称根级路径与 ../ 层数不符", "vt": o.get("vulnerability_type"),
        "action_hint": "按 posixpath.normpath(前缀+payload) 逐句核对 resolved path，层数少算则改写 PoC"})
P(f"  N26 PoC 路径层数候选: {len(n26_hit)}")
write_jsonl(OUT_SCAN, candidates)
P(f"  候选合计 {len(candidates)} -> {OUT_SCAN.name}")

# =================================================================
# 写出
# =================================================================
kept = [(r["id"], r["rec"]) for r in rows if r["id"] not in drop]
with OUT_DATA.open("w", encoding="utf-8") as f:
    for i, rec in kept:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
for path, data in ((OUT_ESC_REVIEW, esc_review), (OUT_ESC_QUEUE, esc_queue),
                   (OUT_REDISTILL, REDISTILL)):
    with path.open("w", encoding="utf-8") as f:
        for x in data:
            f.write(json.dumps(x, ensure_ascii=False) + "\n")

P("")
P("=" * 78)
P("[输出]")
P("=" * 78)
P(f"  {OUT_DATA.name}: {len(kept)} 条（v2_14 {len(rows)} - 删除 {len(drop)}）")
P(f"  escape_review.jsonl: {len(esc_review)} 处修复明细（字节级复验）")
P(f"  escape_queue.jsonl: {len(esc_queue)} 处弱/歧义待审")
P(f"  redistill_manifest_v2_15_wave1.jsonl: {len(REDISTILL)} 条（FN 重蒸馏队列）")
P(f"  scan_candidates.jsonl: {len(candidates)} 条（R1/R7/R8/N26 候选）")

# =================================================================
# 自检
# =================================================================
P("")
P("=" * 78)
P("[自检] 对 v2_15 复跑关键检查")
P("=" * 78)
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)
kept_ids = {i for i, _ in kept}
leak = sorted(drop & kept_ids)
P(f"  删除集残留: {leak if leak else '无'}")
P(f"  8030 保留且含 4 反引号围栏: {8030 in kept_ids and user_text(R[8030]).count('````') >= 2}")
P(f"  8280 保留且无悬挂 fence: {8280 in kept_ids and not user_text(R[8280]).rstrip().endswith('```')}")
P(f"  7851 零宽字符已清: {not ZERO_WIDTH.search(asst_text(R[7851]))}")
P(f"  元数据 cwe 键已清: {all('cwe' not in (R[i].get('fix_distill') or {}) for i in cwe_key_rows)}")

bad_json2, strong_left, s4_weak = [], [], 0
for i, rec in kept:
    a = asst_text(rec)
    ms = list(JSON_BLOCK.finditer(a))
    if not ms:
        bad_json2.append(i)
        continue
    try:
        o = json.loads(ms[-1].group(1))
    except Exception:
        bad_json2.append(i)
        continue
    if not isinstance(o, dict):
        bad_json2.append(i)
        continue
    lg = LANG.get(i, "")
    for fld in ("fix_suggestion", "explanation", "source", "sink"):
        t = str(o.get(fld, ""))
        if not t:
            continue
        runs = re.findall(r"\\{2,}", t)
        lit_n = len(re.findall(r"\\n", t))
        if not runs and lit_n < 2:
            continue
        if '\\"' in t or (lg in CFAM and re.search(r"\\\\[n0]", t)):
            strong_left.append((i, fld, t[:100]))
        else:
            s4_weak += 1
P(f"  条数: {len(kept)}  JSON 解析失败: {len(bad_json2)} {bad_json2[:5]}")
resid_detail = []
for i, rec in kept:
    a = asst_text(rec)
    ms = list(JSON_BLOCK.finditer(a))
    if not ms:
        continue
    try:
        o = json.loads(ms[-1].group(1))
    except Exception:
        continue
    if not isinstance(o, dict):
        continue
    lg = LANG.get(i, "")
    for fld in ("fix_suggestion", "explanation", "source", "sink"):
        t = str(o.get(fld, ""))
        if not t:
            continue
        runs = re.findall(r"\\{2,}", t)
        lit_n = len(re.findall(r"\\n", t))
        if not runs and lit_n < 2:
            continue
        if '\\"' in t or (lg in CFAM and re.search(r"\\\\[n0]", t)):
            ctxs = [t[max(0, m.start() - 30):m.end() + 10]
                    for m in re.finditer(r"\\{1,2}[\"n0]", t)][:3]
            resid_detail.append({"id": i, "field": fld, "lang": lg, "ctx": ctxs, "text": t[:400]})
PLAIN_Q_RE = re.compile(r'(?<!\\)"')
mix_n, lit_n_cnt = 0, 0
for x in resid_detail:
    t = x["text"]
    has_esc_q = '\\"' in t
    has_plain_q = bool(PLAIN_Q_RE.search(t.replace('\\"', "")))
    if has_esc_q and has_plain_q:
        x["class"] = "mixed_legit_or_ambiguous"
        mix_n += 1
    elif has_esc_q:
        x["class"] = "escaped_quote_only"
    else:
        x["class"] = "c_family_lit_escapes"
        lit_n_cnt += 1
P(f"  复扫强污染口径命中残留: {len(resid_detail)}（应为 0；逐条明细如下供归类）")
P(f"    其中 plain+escaped 引号共存（转义引号作字符串内容的合法形态，强口径误报）: {mix_n}")
P(f"    其中 C 族 \\\\n/\\\\r 字面（Java replaceAll 合法源码 / JS 正则类污染两可，留 1.3 逐条）: {lit_n_cnt}")
for x in resid_detail[:60]:
    P(f"    !! id={x['id']} {x['field']} {x['lang']} [{x.get('class')}]: {x['ctx']}")
(OUT_LOG.parent / "repair_v2_15_wave1_residue.json").write_text(
    json.dumps(resid_detail, ensure_ascii=False, indent=1), encoding="utf-8")
P(f"  复扫弱标记残留: {s4_weak}（弱/合法形态，明细见 escape_queue.jsonl）")

# fence 奇偶复查（按"恰好 3 反引号"记号法；4 反引号围栏不算记号）
odd_fence = []
for i, rec in kept:
    for role, txt in (("user", user_text(rec)), ("asst", asst_text(rec))):
        n_tok = len(re.findall(r"(?<!`)```(?!`)", txt))
        if n_tok % 2 == 1 and i != 8030:  # 8030: 内容含 1 处字面 ```，围栏为 4 反引号
            odd_fence.append((role, i, n_tok))
P(f"  fence 奇数残留: {odd_fence if odd_fence else '无'}")

OUT_LOG.write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("repair wave1 done ->", OUT_DATA.name)
