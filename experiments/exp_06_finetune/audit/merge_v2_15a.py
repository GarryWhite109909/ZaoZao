# -*- coding: utf-8 -*-
"""合并 v2_15a 数据集：v2_14 基底 + P0-A 改标 + P0-B 余量辨析组 + 裁决双版本。

依据：audit/优化建议_alpha06_日志类CWE归因辨析_v2_15.md 行动清单（v2_15_a 批次）。
  1. v2_14 为基底（10021 条）。
  2. P0-A 标签边界改标（scan2 裁定 3 条；body 与新标签不一致者改走剔除+重蒸馏清单）。
  3. 追加 g9_1321 / g10_915 / g11_1336 / g12_1336_79 / g13_1336_134 / g14_priority /
     g15_fromstring / g16_adjud_15a（GLM-5.3-flash 教师产出，已过 dual 一致性门 +
     F8 入库门禁 + 锚句必含）。
  4. 终检：system 单一版本 / 七字段契约 / JSON 可解析 / vt 规范 / 全库 assistant 与
     user md5 重复 / 正负比 / 关键词↔标签一致性复扫 / F8 复核。

输出：
  data/final_train_chatml_alpha06_v2_15_a.jsonl
  audit/merge_v2_15a_report.txt
  audit/redistill_manifest_v2_15a.jsonl   （如有改标失败/剔除）
"""
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
V2_14 = BASE / "data/final_train_chatml_alpha06_v2_14.jsonl"
OUT = BASE / "data/final_train_chatml_alpha06_v2_15_a.jsonl"
REPORT = Path(__file__).with_name("merge_v2_15a_report.txt")
MANIFEST_OUT = Path(__file__).with_name("redistill_manifest_v2_15a.jsonl")
CORPUS = BASE / "corpus/repair_wave"

APPEND_PACKS = ["g9_1321", "g10_915", "g11_1336", "g12_1336_79", "g13_1336_134",
                "g14_priority", "g15_fromstring", "g17_priority_authz",
                "g18_authz_family", "g19_134_boundary", "g16_adjud_15a"]

# P0-A 改标（scan2_v2_15 裁定）：old-family 词表用于 body 一致性门
RELABELS = {
    509:  {"new_cwe": "CWE-78", "old_guard": re.compile(r"CWE-134|格式串"),
           "why": "shell=True 拼接用户输入进 subprocess → 命令注入；134 标签与正文叙事（命令注入）矛盾"},
    932:  {"new_cwe": "CWE-89", "old_guard": re.compile(r"CWE-1336|模板引擎|模板注入"),
           "why": "JS 模板字面量拼接的是 SQL 文本，sink=pool.query → SQL 注入；1336 标签错位"},
    7547: {"new_cwe": "CWE-79", "old_guard": re.compile(r"CWE-1336|SSTI|模板引擎"),
           "why": "用户输入仅进入 href 属性输出位（mark_safe 关转义）→ XSS；未进入模板源码，1336 错位"},
}

CONTRACT = ["has_vulnerability", "vulnerability_type", "risk_level",
            "source", "sink", "explanation", "fix_suggestion"]
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)
VT_BAD = (re.compile(r"^CWE-\d+$"), re.compile(r"^CWE-\d+\s*[:：]"),
          re.compile(r"CWE-\d+\s*/\s*(?:CWE-)?\d+"))

LOG = []


def P(*a):
    LOG.append(" ".join(str(x) for x in a))


def last_json(a):
    m = JSON_BLOCK.findall(a)
    return m[-1] if m else None


def replace_last_json(a, new_text):
    m = list(JSON_BLOCK.finditer(a))[-1]
    return a[:m.start()] + "```json\n" + new_text + "\n```" + a[m.end():]


def norm_md5(s):
    return hashlib.md5(re.sub(r"\s+", "", s).encode()).hexdigest()


def load_jsonl(p):
    out = []
    if p.exists():
        for l in p.open(encoding="utf-8"):
            if l.strip():
                out.append(json.loads(l))
    return out


# ---------------------------------------------------------------- 1) 基底
rows = load_jsonl(V2_14)
P(f"基底 v2_14: {len(rows)} 条")
MAIN_SYSTEM = rows[0]["messages"][0]["content"]
assist_md5 = set()
user_md5 = set()
for r in rows:
    msgs = r["messages"]
    assist_md5.add(norm_md5(msgs[2]["content"]))
    user_md5.add(norm_md5(msgs[1]["content"]))

# ---------------------------------------------------------------- 2) P0-A 改标
manifest = []
relabel_done, relabel_to_manifest = [], []
# 收集每种 CWE 的规范全名（取库内最常见写法）
full_names = defaultdict(Counter)
for r in rows:
    blk = last_json(r["messages"][2]["content"])
    if not blk:
        continue
    try:
        o = json.loads(blk)
    except Exception:
        continue
    vt = str(o.get("vulnerability_type", ""))
    m = re.match(r"(CWE-\d+)\s+(.+)", vt)
    if m and ";" not in vt:
        full_names[m.group(1)][vt] += 1
CANON = {cwe: c.most_common(1)[0][0] for cwe, c in full_names.items() if c}

for ln, spec in RELABELS.items():
    r = rows[ln - 1]
    a = r["messages"][2]["content"]
    blk = last_json(a)
    if not blk:
        P(f"  !! line {ln}: 无 JSON，跳过")
        continue
    o = json.loads(blk)
    body = a.split("```json")[0]
    if spec["old_guard"].search(body):
        relabel_to_manifest.append(ln)
        manifest.append({"orig_line": ln, "reason": "relabel_body_inconsistent",
                         "note": f"改标目标 {spec['new_cwe']}，但正文含旧标签叙事"
                                 f"（{spec['old_guard'].pattern}），需教师重蒸馏。{spec['why']}",
                         "user": r["messages"][1]["content"]})
        continue
    old_vt = str(o.get("vulnerability_type", ""))
    new_vt = CANON.get(spec["new_cwe"], spec["new_cwe"])
    o["vulnerability_type"] = new_vt
    r["messages"][2]["content"] = replace_last_json(a, json.dumps(o, ensure_ascii=False))
    relabel_done.append((ln, old_vt[:50], new_vt))
P(f"P0-A 改标 {len(relabel_done)} 条：")
for ln, old, new in relabel_done:
    P(f"    line {ln}: {old!r} -> {new!r}")
P(f"  改标失败进重蒸馏清单 {len(relabel_to_manifest)} 条: {relabel_to_manifest}")

# ---------------------------------------------------------------- 3) 追加包
appended = Counter()
for pack in APPEND_PACKS:
    recs = load_jsonl(CORPUS / f"{pack}.jsonl")
    for rec in recs:
        msgs = rec["messages"]
        am, um = norm_md5(msgs[2]["content"]), norm_md5(msgs[1]["content"])
        if am in assist_md5 or um in user_md5:
            manifest.append({"orig_line": None, "reason": "duplicate_of_existing",
                             "note": f"{pack}:{rec.get('meta', {}).get('task_key')} 与现有库重复，不入库",
                             "user": msgs[1]["content"][:200]})
            continue
        assist_md5.add(am)
        user_md5.add(um)
        rows.append(rec)
        appended[pack] += 1
P(f"追加: {dict(appended)} 合计 {sum(appended.values())}；"
  f"跳过重复 {sum(1 for m in manifest if m['reason'] == 'duplicate_of_existing')}")
P(f"合并后: {len(rows)} 条")

# ---------------------------------------------------------------- 4) 终检
P("")
P("=" * 60)
P("终检审计")
P("=" * 60)
sys_kinds = Counter()
risk_cnt = Counter()
hv_cnt = Counter()
extra_cnt = Counter()
vt_bad = []
parse_fail = []
dup2 = defaultdict(int)
no_anchor = 0
vuln_n = 0
na_expl = 0
for r in rows:
    msgs = r["messages"]
    sys_kinds[hashlib.md5(msgs[0]["content"].encode()).hexdigest()[:10]] += 1
    a = msgs[2]["content"]
    dup2[norm_md5(a)] += 1
    blk = last_json(a)
    if not blk:
        parse_fail.append(1)
        continue
    try:
        o = json.loads(blk)
    except Exception:
        parse_fail.append(1)
        continue
    hv_cnt[str(o.get("has_vulnerability"))] += 1
    risk_cnt[str(o.get("risk_level"))] += 1
    for k in o:
        if k not in CONTRACT:
            extra_cnt[k] += 1
    vt = str(o.get("vulnerability_type", ""))
    if vt != "none" and any(p.search(vt) for p in VT_BAD):
        vt_bad.append(vt[:40])
    if o.get("has_vulnerability") is True:
        vuln_n += 1
        for fld in ("source", "sink"):
            if not re.search(r"line\s*\d+", str(o.get(fld, ""))):
                no_anchor += 1
    if str(o.get("explanation", "")).strip() in ("N/A", "", "n/a"):
        na_expl += 1
dup_groups = sum(1 for v in dup2.values() if v > 1)
P(f"条数: {len(rows)}")
P(f"system 版本数: {len(sys_kinds)} {dict(sys_kinds)}")
P(f"risk_level: {dict(risk_cnt)}")
P(f"正负: {dict(hv_cnt)} 漏洞样本 {vuln_n}")
P(f"七字段契约多余字段: {dict(extra_cnt) if extra_cnt else '无'}")
P(f"JSON 解析失败: {len(parse_fail)}")
P(f"vt 非规范: {len(vt_bad)} {vt_bad[:5]}")
P(f"assistant 全文重复组: {dup_groups}")
P(f"漏洞样本 source/sink 无 line 锚点: {no_anchor}")
P(f"explanation=N/A 残余: {na_expl}")

# 新增包锚句/F8 复核（入库门禁二次核验）
SINK_GATE = {
    "1321": re.compile(r"__proto__|constructor|prototype"),
    "915": re.compile(r"Object\.assign|\.\.\.\s*\w|defineProperty"),
    "1336": re.compile(r"from_string\(|Template\(|render_template_string|ejs\.render|ejs\.compile|_\.template|nunjucks\.renderString|Handlebars\.compile|createTemplate|new Template\(|VelocityEngine|\.evaluate\(|text/template|html/template|\.compile\("),
    "208": re.compile(r"==|!=|\.equals\("),
    "209": re.compile(r"str\(e|printStackTrace|getMessage\(|\.message|traceback|Exception|\.Error\(\)|String\(e|\$\{e\}|http\.Error"),
    "79": re.compile(r"\|safe|Markup\(|mark_safe|<%-|innerHTML|render_template|document\.write"),
    "89": re.compile(r"execute\(|\.query\(|raw\(|raw_query"),
    "78": re.compile(r"subprocess|os\.system|shell=True|exec\(|child_process|system\("),
    "94": re.compile(r"eval\(|exec\(|Function\("),
    "798": re.compile(r"(?i)((password|secret|token|api_?key|access_?key)\s*=\s*['\"][^'\"]{6,}['\"]|://[^'\"@\s]+:[^'\"@\s]{4,}@)"),
    "22": re.compile(r"open\(|extractall\(|\.extract\(|os\.path\.join|readFile|createReadStream|Files\.|send_file|shutil"),
}
f8_bad = []
for r in rows:
    if (r.get("meta") or {}).get("gen") is not True:
        continue
    blk = last_json(r["messages"][2]["content"])
    if not blk:
        continue
    try:
        o = json.loads(blk)
    except Exception:
        continue
    if o.get("has_vulnerability") is not True:
        continue
    vt = str(o.get("vulnerability_type", ""))
    m = re.match(r"CWE-(\d+)", vt)
    if not m or m.group(1) not in SINK_GATE:
        continue
    code = "\n".join(re.findall(r"```[\w+#-]*\n(.*?)```", r["messages"][1]["content"], re.S))
    if not SINK_GATE[m.group(1)].search(code):
        f8_bad.append((r["meta"].get("task_key"), vt[:40]))
P(f"新增样本 F8 复核（主类型 sink 特征在代码中）: 失败 {len(f8_bad)} {f8_bad[:5]}")

# 关键词↔标签一致性复扫（scan2 口径，全库）
pa_new = 0
for idx, r in enumerate(rows, 1):
    blk = last_json(r["messages"][2]["content"])
    if not blk:
        continue
    try:
        o = json.loads(blk)
    except Exception:
        continue
    if o.get("has_vulnerability") is not True:
        continue
    vt = str(o.get("vulnerability_type", ""))
    expl = str(o.get("explanation", ""))
    body = r["messages"][2]["content"].split("```json")[0]
    text = expl + " " + body[-600:]
    nums = re.findall(r"CWE-(\d+)", vt)
    if not nums:
        continue
    p = nums[0]
    hit = False
    if p == "117":
        hit = (re.search(r"(敏感信息|敏感数据)[^。\n]{0,15}(泄露|泄漏)", text)
               and not re.search(r"(伪造|换行|\\n|\\r|控制符|日志条目|日志注入)", text))
    elif p == "1336":
        hit = (re.search(r"(未转义|XSS)", text)
               and not re.search(r"(模板语法|模板源码|模板执行|当作模板|模板编译|from_string|Template\(|注入模板|模板引擎)", text))
    elif p == "134":
        hit = not re.search(r"(格式串|格式化字符串|格式字符串|%n|%s|%d|格式符|printf|format)", text)
    elif p == "532":
        hit = not re.search(r"(敏感|密码|口令|token|令牌|密钥|secret|credential|凭据)", text)
    elif p == "312":
        hit = (re.search(r"(写入?日志|落日志|日志文件)", text)
               and not re.search(r"(数据库|DB|明文存储|缓存|cookie|Cookie|配置文件|非日志)", text))
    elif p == "1321":
        hit = not re.search(r"(原型|prototype|__proto__|污染|键名)", text)
    if hit:
        pa_new += 1
        if pa_new <= 8:
            P(f"  !! 一致性命中 line {idx}: vt={vt[:50]} expl={expl[:80]}")
P(f"关键词↔标签一致性复扫命中: {pa_new} 条（v2_14 已知 FP 6981/7333 属叙事含次要视角，非标签错误）")

ok = (len(sys_kinds) == 1 and not parse_fail and not vt_bad and not extra_cnt
      and not f8_bad and na_expl == 0)
P("")
P(f"结论: {'✅ 通过，落盘 v2_15_a' if ok else '❌ 未通过（见上）'}")

# ---------------------------------------------------------------- 5) 落盘
if ok:
    with OUT.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    P(f"已写出 {OUT.name}")
if manifest:
    with MANIFEST_OUT.open("w", encoding="utf-8") as f:
        for m in manifest:
            f.write(json.dumps(m, ensure_ascii=False) + "\n")
    P(f"重蒸馏清单 {MANIFEST_OUT.name}: {len(manifest)} 条")

REPORT.write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("merge done ->", OUT.name if ok else "FAILED (see report)")
