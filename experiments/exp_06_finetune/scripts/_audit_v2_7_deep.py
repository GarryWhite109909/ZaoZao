#!/usr/bin/env python3
"""v2.7 深度审计：格式契约 / 行号 / 长度 / 分布 / 语言卫生 / 模板口头禅。
一次性脚本，输出统计到 stdout。"""
import collections
import hashlib
import json
import re
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))
from graduation_project.prompts import ALPHA05_PROMPT

DATA = PROJECT / "experiments/exp_06_finetune/data/final_train_chatml_alpha06_v2_7.jsonl"
CODE_RE = re.compile(r"```([\w+#-]*)\n(.*?)\n```", re.S)
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
CANON = ["has_vulnerability", "vulnerability_type", "risk_level", "source", "sink", "explanation", "fix_suggestion"]
FILLERS = ["综上所述", "总而言之", "总的来说", "首先", "其次", "再次", "接下来", "让我们", "值得注意的是", "需要注意的是", "简而言之", "由此可见", "因此可以", "我们可以"]

rows = []
parse_err = 0
for i, line in enumerate(DATA.read_text(encoding="utf-8").splitlines()):
    if not line.strip():
        continue
    try:
        rows.append((i, json.loads(line)))
    except json.JSONDecodeError:
        parse_err += 1

print(f"总行 {len(rows)+parse_err} | JSON 解析失败 {parse_err}")

# ---- 1. 消息结构 ----
bad_struct = []
sys_mismatch = []
for i, r in rows:
    msgs = r.get("messages")
    if not isinstance(msgs, list) or len(msgs) != 3 or [m["role"] for m in msgs] != ["system", "user", "assistant"]:
        bad_struct.append(i)
    elif msgs[0]["content"] != ALPHA05_PROMPT:
        sys_mismatch.append(i)
print(f"结构异常(非3条/角色错序): {len(bad_struct)} {bad_struct[:10]}")
print(f"system != ALPHA05_PROMPT: {len(sys_mismatch)} {sys_mismatch[:10]}")

# ---- 2. assistant JSON 契约 ----
c = collections.Counter()
json_fail, no_json, missing_fields, order_bad, hv_bad, vt_bad, risk_bad = [], [], [], [], [], [], []
safe_field_bad = collections.Counter()
lang_counter = collections.Counter()
cwe_counter = collections.Counter()
kind_counter = collections.Counter()
code_lines_hist = collections.Counter()
asst_char_hist = collections.Counter()
user_char_hist = collections.Counter()
line_oob = []
filler_counter = collections.Counter()
filler_rows = collections.Counter()
cot_json_conflict = []
fix_no_anchor = []
fix_has_codeblock = []
multi_json_blocks = []
vt_names = collections.Counter()
long_asst = []
records = []
for i, r in rows:
    msgs = r["messages"]
    u, a = msgs[1]["content"], msgs[2]["content"]
    meta = r.get("meta") or {}
    kind_counter[meta.get("kind", "-")] += 1
    m = JSON_RE.search(a)
    if not m:
        no_json.append(i)
        continue
    if len(JSON_RE.findall(a)) > 1:
        multi_json_blocks.append(i)
    try:
        obj = json.loads(m.group(1))
    except json.JSONDecodeError:
        json_fail.append(i)
        continue
    keys = list(obj.keys())
    if any(k not in obj for k in CANON):
        missing_fields.append((i, [k for k in CANON if k not in obj]))
    if keys[:7] != CANON:
        order_bad.append(i)
    hv = obj.get("has_vulnerability")
    if hv not in (True, False):
        hv_bad.append((i, hv))
    vt = obj.get("vulnerability_type")
    rl = obj.get("risk_level")
    if hv is True:
        if not (isinstance(vt, str) and re.match(r"^CWE-\d+ ", vt)):
            vt_bad.append((i, vt))
        else:
            cwe_counter[vt.split()[0]] += 1
            vt_names[vt] += 1
        if rl not in ("Critical", "High", "Medium", "Low"):
            risk_bad.append((i, rl))
    else:
        if vt != "none":
            vt_bad.append((i, vt))
        if rl != "none":
            risk_bad.append((i, rl))
        for f, want in (("source", "N/A"), ("sink", "N/A"), ("fix_suggestion", "no fix needed")):
            if obj.get(f) != want:
                safe_field_bad[f] += 1
    # 代码块与行号
    cm = CODE_RE.search(u)
    lang = (cm.group(1) if cm else "?").lower()
    lang_counter[lang or "none"] += 1
    code = cm.group(2) if cm else u
    n_lines = code.count("\n") + 1
    lb = 10 if n_lines < 10 else (50 if n_lines < 50 else (100 if n_lines < 100 else (200 if n_lines < 200 else (400 if n_lines < 400 else 999))))
    code_lines_hist[lb] += 1
    ac = len(a)
    ab = 500 if ac < 500 else (1000 if ac < 1000 else (2000 if ac < 2000 else (4000 if ac < 4000 else 9999)))
    asst_char_hist[ab] += 1
    user_char_hist[min(len(u)//1000*1000, 15000)] += 1
    if ac > 6000:
        long_asst.append((i, ac))
    # 行号越界（source/sink/fix_suggestion 中的 line N）
    bad_nums = []
    for fld in ("source", "sink", "fix_suggestion", "explanation"):
        v = obj.get(fld) or ""
        for n in re.findall(r"[Ll]ine\s*(\d+)", str(v)):
            if not (1 <= int(n) <= n_lines):
                bad_nums.append((fld, int(n), n_lines))
    if bad_nums:
        line_oob.append((i, bad_nums[:3], n_lines))
    # fix 质量代理
    if hv is True:
        fx = obj.get("fix_suggestion") or ""
        if not re.search(r"[Ll]ine\s*\d+", fx):
            fix_no_anchor.append(i)
        if "```" in fx or "\n" in fx.strip() and fx.count("\n") > 1:
            fix_has_codeblock.append(i)
    # CoT 口头禅
    for f in FILLERS:
        if f in a:
            filler_counter[f] += 1
            filler_rows[i] += 1
    # CoT-结论一致性（启发式：JSON 后无正文 + json 前 300 字含"无漏洞/安全"表述且 hv=True）
    pre = a[: m.start()]
    if hv is True and re.search(r"(不存在漏洞|没有漏洞|无漏洞|代码是安全|可判定安全|不存在安全问题)", pre[-500:]):
        cot_json_conflict.append(i)
    records.append((i, hv, obj, meta, lang, n_lines, len(a)))

print(f"无 json 块: {len(no_json)} {no_json[:10]}")
print(f"json 解析失败: {len(json_fail)} {json_fail[:10]}")
print(f"多 json 块: {len(multi_json_blocks)} {multi_json_blocks[:10]}")
print(f"缺字段: {len(missing_fields)} {missing_fields[:5]}")
print(f"字段顺序非规范: {len(order_bad)} {order_bad[:10]}")
print(f"has_vulnerability 非布尔: {len(hv_bad)} {hv_bad[:5]}")
print(f"vulnerability_type 违规: {len(vt_bad)} {vt_bad[:10]}")
print(f"risk_level 违规: {len(risk_bad)} {risk_bad[:10]}")
print(f"safe 侧字段违规: {dict(safe_field_bad)}")
print(f"行号越界(含 explanation): {len(line_oob)} {line_oob[:8]}")
print(f"vuln fix 无行号锚: {len(fix_no_anchor)}")
print(f"fix 疑似代码块/多行: {len(fix_has_codeblock)}")
print(f"CoT 终判疑似矛盾: {len(cot_json_conflict)} {cot_json_conflict[:10]}")

hv_c = collections.Counter(hv for _, hv, *_ in records)
print(f"方向: vuln {hv_c[True]} / safe {hv_c[False]}")
print("kind 分布:", dict(kind_counter.most_common(30)))
print("语言分布:", dict(lang_counter.most_common(25)))
print("CWE Top20:", cwe_counter.most_common(20))
print(f"CWE 覆盖类数: {len(cwe_counter)}; <10 条的类: {[x for x in cwe_counter.items() if x[1] < 10]}")
print("代码行数分桶(<10/50/100/200/400/999+):", dict(sorted(code_lines_hist.items())))
print("assistant 字符分桶(<500/1k/2k/4k/4k+):", dict(sorted(asst_char_hist.items())))
print(f"assistant >6000 字符: {len(long_asst)} {long_asst[:10]}")
print("口头禅出现次数:", dict(filler_counter.most_common()))
print(f"含口头禅样本数: {len(filler_rows)}")

# ---- 3. 用户内容重复 / 同码异判 ----
def fp(u):
    cm = CODE_RE.search(u)
    body = cm.group(2) if cm else u
    return hashlib.md5("\n".join(l.rstrip() for l in body.split("\n") if l.strip()).encode()).hexdigest()

fp_map = collections.defaultdict(set)
user_exact = collections.Counter()
for i, r in rows:
    u = r["messages"][1]["content"]
    user_exact[u] += 1
    m = JSON_RE.search(r["messages"][2]["content"])
    hv = None
    if m:
        try:
            hv = json.loads(m.group(1)).get("has_vulnerability")
        except Exception:
            pass
    fp_map[fp(u)].add((i, hv))
dup_users = sum(v - 1 for v in user_exact.values() if v > 1)
print(f"user 全文完全重复: {dup_users} 条 / {sum(1 for v in user_exact.values() if v > 1)} 组")
conflict = [(k, v) for k, v in fp_map.items() if len({hv for _, hv in v}) > 1]
print(f"同代码指纹不同判定: {len(conflict)} 组")
for k, v in conflict[:8]:
    print("   冲突组:", sorted(v)[:6])

# ---- 4. CoT 语言混杂 ----
zh = re.compile(r"[\u4e00-\u9fff]")
en_only = 0
for i, r in rows:
    a = r["messages"][2]["content"]
    body_no_json = JSON_RE.sub("", a)
    if not zh.search(body_no_json[:800]):
        en_only += 1
print(f"CoT 前 800 字符纯英文(无中文)样本: {en_only}")

# ---- 5. 头部模板化: json 块前的固定开场白 ----
openers = collections.Counter()
for i, r in rows:
    a = r["messages"][2]["content"]
    m = JSON_RE.search(a)
    pre = a[: m.start()] if m else a
    first = pre.strip().split("\n")[0][:30]
    openers[first] += 1
print("开场白 Top15:")
for k, v in openers.most_common(15):
    print(f"   {v:5d}  {k!r}")
