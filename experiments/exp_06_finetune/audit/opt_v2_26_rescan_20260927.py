# -*- coding: utf-8 -*-
"""v2_26 存量错误面清点（2026-09-27）。

对 v2_26 候选重跑 0914 版 `_opt_v2_19_manifests_20260914.py` 的同一套检测逻辑
（逐类逐字节沿用原词表/正则），产出 `audit/v2_26_opt_manifests/`，并对照 v2_19
清单做存活率对账：v2_19 已标记行在 v2_26 的三种去向——
  survived  digest 仍在且仍被标记（未清洗）
  cleared   digest 已不存在（被清洗或整行删除，含改写导致 digest 变化）
  new       v2_26 新被标记、且该 digest 在 v2_19 全库不存在（改写后复阳或新波次带入）
只读，不写数据集。
"""
import json, os, re, sys, hashlib, collections

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune"
SRC = os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_26_candidate_20260914.jsonl")
SRC19 = os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_19_candidate_20260914.jsonl")
OUT = os.path.join(ROOT, "audit", "v2_26_opt_manifests")
os.makedirs(OUT, exist_ok=True)

rows = [json.loads(l) for l in open(SRC, encoding="utf-8") if l.strip()]
rows19 = [json.loads(l) for l in open(SRC19, encoding="utf-8") if l.strip()]
N = len(rows)
print("TOTAL v2_26", N, " v2_19", len(rows19))

CODE_RE = re.compile(r"```([a-zA-Z0-9_+#\-\.]*)[ \t]*\n(.*?)```", re.S)
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
LINE_REF_RE = re.compile(r"(?:line\s*(\d+)|第\s*(\d+)\s*行|(?<![A-Za-z0-9_])L(\d+))", re.I)
CWE_RE = re.compile(r"CWE-(\d+)")
COMMENT_RX = re.compile(r"^\s*(?://|#|--|/\*|\*|<!--|;)")


def write_jsonl(name, recs):
    p = os.path.join(OUT, name)
    with open(p, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"  -> {name}: {len(recs)}")


def code_blocks(u):
    return [(m.group(1).lower(), m.group(2)) for m in CODE_RE.finditer(u)]


def verdict_of(a):
    ms = list(JSON_RE.finditer(a))
    if not ms:
        return None
    try:
        return json.loads(ms[-1].group(1))
    except Exception:
        return None


def digest(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()[:10]


# ---------------------------------------------------------------- P0-2 答案性注释
ANN_RULES = [
    ("CWE编号", re.compile(r"CWE[-\s]?\d{1,4}", re.I)),
    ("防御迷惑", re.compile(r"防御迷惑|迷惑防御")),
    ("看似", re.compile(r"看似|表面上|假装")),
    ("漏洞点", re.compile(r"漏洞点|漏洞位置|漏洞所在")),
    ("漏洞行", re.compile(r"漏洞行|vulnerable\s*line", re.I)),
    ("方向泄漏", re.compile(r"存在漏洞|有漏洞|无漏洞|安全样本|不安全样本|insecure|vulnerable|unsafe\b", re.I)),
]
SYNTH_RULES = [("合成标记", re.compile(r"模拟|simulate|场景|业务逻辑|示例数据|demo", re.I))]
ANSWER_CATS = {c for c, _ in ANN_RULES}

p0_2 = []
cat_occ = collections.Counter()
cat_row = collections.defaultdict(set)
synth_rows = set()
whole_line_rows = set()
inline_rows = set()
for i, r in enumerate(rows):
    u = r["messages"][1]["content"]
    hits = []
    for lang, body in code_blocks(u):
        for ln, text in enumerate(body.split("\n"), 1):
            for cat, rx in ANN_RULES:
                if rx.search(text):
                    hits.append(dict(cat=cat, line=ln, kind="whole_line" if COMMENT_RX.match(text) else "inline",
                                     text=text.strip()[:170]))
                    cat_occ[cat] += 1
                    cat_row[cat].add(i)
                    break
            else:
                for cat, rx in SYNTH_RULES:
                    if rx.search(text):
                        synth_rows.add(i)
                        break
    if hits:
        cats = sorted({h["cat"] for h in hits})
        if any(h["kind"] == "whole_line" for h in hits):
            whole_line_rows.add(i)
        if any(h["kind"] == "inline" for h in hits):
            inline_rows.add(i)
        p0_2.append(dict(row=i, cats=cats, n=len(hits),
                         n_whole=sum(1 for h in hits if h["kind"] == "whole_line"),
                         n_inline=sum(1 for h in hits if h["kind"] == "inline"),
                         hits=hits[:12], digest=digest(u)))

print("\n[P0-2 答案性注释] 命中行", len(p0_2), " 处", sum(cat_occ.values()))
for k, v in cat_occ.most_common():
    print(f"    {k}: 处={v} 行={len(cat_row[k])}")
print(f"    仅合成标记(非答案性)额外行: {len(synth_rows - set(x['row'] for x in p0_2))}")
print(f"    整行注释行={len(whole_line_rows)} 行尾内联行={len(inline_rows)} 交集={len(whole_line_rows & inline_rows)}")
write_jsonl("p0_2_answer_annotations.jsonl", p0_2)

# ---------------------------------------------------------------- P0-1 答案键泄漏
LEAK_RX = re.compile(
    r"题目明确要求|题目要求|按题目|题目给定|明确要求[^。；\n]{0,14}(?:是否有漏洞|漏洞[:：]否|判为|标注|输出)"
    r"|调整防御|给定的?(?:标签|真值)|为符合[^。；\n]{0,10}(?:标签|要求)")
p0_1 = []
for i, r in enumerate(rows):
    a = r["messages"][2]["content"]
    ms = list(LEAK_RX.finditer(a))
    if ms:
        p0_1.append(dict(row=i, n=len(ms), hits=[m.group(0) for m in ms[:5]],
                         ctx=[a[max(0, m.start() - 140): m.end() + 200] for m in ms[:3]]))
print("\n[P0-1 答案键泄漏]", len(p0_1), [x["row"] for x in p0_1])
write_jsonl("p0_1_answer_key_leak.jsonl", p0_1)

# ---------------------------------------------------------------- P0-3 弱防御当有效
WEAK_CORE = re.compile(r"HasPrefix|startsWith|starts_with|str_starts_with|黑名单|blacklist|"
                       r"str_replace|strings\.Replace|\.replace\(|正则替换|黑名单式|前缀白名单|前缀匹配|前缀判断")
WEAK_LOOSE = re.compile(r"HasPrefix|startsWith|starts_with|str_starts_with|黑名单|blacklist|"
                        r"str_replace|strings\.Replace|\.replace\(|前缀|prefix|白名单|whitelist|"
                        r"转义|escape|过滤敏感|strip", re.I)
BYPASS_RX = re.compile(r"绕过|bypass|可被利用|会被执行|仍可|仍然可以|不完全|不够充分")
WASH_RX = re.compile(r"样本外|沙箱|容器|宿主机|通常|生产环境|外层|上游|调用方|框架|额外假设")

p0_3_hi, p0_3_all = [], []
for i, r in enumerate(rows):
    a = r["messages"][2]["content"]
    v = verdict_of(a)
    if not v or str(v.get("has_vulnerability")).lower() != "false":
        continue
    if not BYPASS_RX.search(a):
        continue
    rec = dict(row=i, cwe=str(v.get("vulnerability_type", "")),
               weak_def=sorted(set(WEAK_LOOSE.findall(a)))[:8],
               bypass=sorted(set(BYPASS_RX.findall(a)))[:6],
               wash=sorted(set(WASH_RX.findall(a)))[:6], digest=digest(a))
    if WEAK_CORE.search(a):
        p0_3_hi.append(rec)
    p0_3_all.append(rec)
print("\n[P0-3 弱防御当有效] 宽口径", len(p0_3_all), " 窄口径(核心弱防御词)", len(p0_3_hi))
write_jsonl("p0_3_weak_defense_neg_all.jsonl", p0_3_all)
write_jsonl("p0_3_weak_defense_neg_hiprec.jsonl", p0_3_hi)

# ---------------------------------------------------------------- P0-4 内部术语
TERM_CORE = [
    ("M族实验代号", re.compile(r"(?<![A-Za-z0-9_])M[0-9]{1,2}(?![0-9%])")),
    ("教师", re.compile(r"教师(?:第|的|判|标注|输出|原话|认为|给出|立场)")),
    ("真值", re.compile(r"真值|ground\s*truth", re.I)),
    ("应判为", re.compile(r"应判为|应当判为")),
    ("why标注", re.compile(r"why\s*标注|已在\s*why|标注过|已标注")),
    ("蒸馏/门禁术语", re.compile(r"kit\b|manifest|redistill|蒸馏|批次|探针|消融|实测证伪|六道门|门禁|分诊|"
                                  r"负样本集|伪造样本|本批")),
]
TERM_LOOSE = [("英文探针原样输出", re.compile(r"breaks out of|attr\s*上下文|[a-z_]{3,}\s*实测"))]
p0_4, p0_4_loose_rows = [], set()
for i, r in enumerate(rows):
    a = r["messages"][2]["content"]
    hits = [dict(cat=c, t=m.group(0)[:60]) for c, rx in TERM_CORE for m in rx.finditer(a)]
    lo = [dict(cat=c, t=m.group(0)[:60]) for c, rx in TERM_LOOSE for m in rx.finditer(a)]
    if hits:
        p0_4.append(dict(row=i, cats=sorted({h["cat"] for h in hits}), n=len(hits), hits=hits[:10]))
    if lo:
        p0_4_loose_rows.add(i)
print("\n[P0-4 内部术语] 核心口径行", len(p0_4), " 另含英文探针原样行", len(p0_4_loose_rows))
c = collections.Counter(x for y in p0_4 for x in y["cats"])
for k, v in c.most_common():
    print(f"    {k}: {v}")
write_jsonl("p0_4_internal_terms.jsonl", p0_4)
write_jsonl("p0_4_english_probe.jsonl", [dict(row=i) for i in sorted(p0_4_loose_rows)])

# ---------------------------------------------------------------- P1-5 叙事 vs JSON
POS_STANCE = re.compile(r"存在漏洞|是漏洞|属于漏洞|构成漏洞|漏洞成立|可被利用|存在安全风险|"
                        r"可导致|能够读取|可以读取|可被读取|能够执行|可以执行|造成注入|可注入|可越权")
NEG_STANCE = re.compile(r"不存在漏洞|未发现漏洞|不是漏洞|不构成漏洞|代码安全|无安全风险|"
                        r"未发现安全问题|是安全的|判定为无漏洞|不存在安全风险|无漏洞")
CONCL_MARK = re.compile(r"结论|综上|因此|判定|最终|总体|综上所|是否|判定为|应为")
p1_5_stance, p1_5_cwe = [], []
for i, r in enumerate(rows):
    a = r["messages"][2]["content"]
    v = verdict_of(a)
    if not v:
        continue
    hv = str(v.get("has_vulnerability")).lower() == "true"
    body = JSON_RE.sub("", a)
    pos = [m.group(0) for m in POS_STANCE.finditer(body)]
    neg = [m.group(0) for m in NEG_STANCE.finditer(body)]
    if hv and len(neg) > len(pos):
        p1_5_stance.append(dict(row=i, direction="JSON=有洞 / 叙事偏无洞", n_neg=len(neg), n_pos=len(pos),
                                ev=neg[:5], ev_pos=pos[:5], digest=digest(body)))
    elif (not hv) and len(pos) > len(neg):
        p1_5_stance.append(dict(row=i, direction="JSON=无洞 / 叙事偏有洞", n_pos=len(pos), n_neg=len(neg),
                                ev=pos[:5], ev_neg=neg[:5], digest=digest(body)))
    jc = CWE_RE.search(str(v.get("vulnerability_type", "")))
    narr = sorted({int(x) for x in CWE_RE.findall(body)})
    if jc and narr and int(jc.group(1)) not in narr:
        p1_5_cwe.append(dict(row=i, json_cwe="CWE-" + jc.group(1),
                             narr_cwe=["CWE-" + str(x) for x in narr][:8], digest=digest(body)))
print("\n[P1-5] 立场互斥", len(p1_5_stance), " CWE 互斥", len(p1_5_cwe))
print("     立场分向:", collections.Counter(x["direction"] for x in p1_5_stance))
write_jsonl("p1_5_stance_conflict.jsonl", p1_5_stance)
write_jsonl("p1_5_cwe_conflict.jsonl", p1_5_cwe)

# ---------------------------------------------------------------- P1-6 行号锚定
p1_6_embed, p1_6_mix = [], []
n_embed = n_bad = 0
for i, r in enumerate(rows):
    u = r["messages"][1]["content"]; a = r["messages"][2]["content"]
    bl = code_blocks(u)
    cl = sum(len(b[1].strip("\n").split("\n")) for b in bl) if len(bl) > 1 else \
         (len(bl[0][1].strip("\n").split("\n")) if bl else 0)
    bad = []
    for lang, body in bl:
        for ln, text in enumerate(body.split("\n"), 1):
            m = re.search(r"(?:#|//|--|/\*|<!--)\s*line\s*(\d+)", text, re.I)
            if m:
                n_embed += 1
                if int(m.group(1)) != ln:
                    n_bad += 1
                    bad.append(dict(declared=int(m.group(1)), actual=ln, text=text.strip()[:130]))
    v = verdict_of(a)
    refs = [int(x[0] or x[1] or x[2]) for x in LINE_REF_RE.findall(a) if (x[0] or x[1] or x[2])]
    oob = sorted({x for x in refs if cl and x > cl})
    mixed = bool(re.search(r"line\s*\d+", a, re.I)) and bool(re.search(r"(?<![A-Za-z0-9_])L\d{1,3}(?![0-9])", a))
    if bad or oob or mixed:
        p1_6_mix.append(dict(row=i, code_lines=cl, embed_bad=bad[:8], n_embed_bad=len(bad),
                             narr_oob=oob[:8], mixed_style=mixed, digest=digest(a)))
        if bad:
            p1_6_embed.append(dict(row=i, n_bad=len(bad), bad=bad[:8]))
print("\n[P1-6] 内嵌 line N 注释", n_embed, " 错", n_bad, f"({100*n_bad/max(n_embed,1):.1f}%)",
      " 含错注释行", len(p1_6_embed), " 含错/越界/混用行", len(p1_6_mix))
write_jsonl("p1_6_lineno_bad.jsonl", p1_6_embed)
write_jsonl("p1_6_lineno_oob_mix.jsonl", p1_6_mix)

# ---------------------------------------------------------------- P1-7 fix 契约
p1_7 = []
for i, r in enumerate(rows):
    a = r["messages"][2]["content"]; v = verdict_of(a)
    if not v:
        continue
    fx = str(v.get("fix_suggestion", ""))
    hv = str(v.get("has_vulnerability")).lower() == "true"
    reasons = []
    if len(fx.strip().split("\n")) > 1:
        reasons.append("多行")
    if re.search(r"\{|\}|=>|;\s|def\s|\bfunction\b|\$[A-Za-z_]|\breturn\b|if\s*\(", fx):
        reasons.append("含代码")
    if len(fx) > 220:
        reasons.append("过长")
    if (not hv) and not fx.strip().lower().startswith("no fix needed"):
        reasons.append("无洞非no-fix")
    if reasons:
        p1_7.append(dict(row=i, reasons=reasons, len=len(fx), fx=fx[:200]))
print("\n[P1-7 fix 契约] 违约行", len(p1_7),
      dict(collections.Counter(c for x in p1_7 for c in x["reasons"])))
write_jsonl("p1_7_fix_contract.jsonl", p1_7)

# ------------------------------------------------------------------ P1-6a 可自动重编号清单
p1_6_fix = []
for i, r in enumerate(rows):
    u = r["messages"][1]["content"]
    for lang, body in code_blocks(u):
        for ln, text in enumerate(body.split("\n"), 1):
            m = re.search(r"((?:#|//|--|/\*|<!--)\s*line\s*)(\d+)", text, re.I)
            if m and int(m.group(2)) != ln:
                p1_6_fix.append(dict(row=i, decl=int(m.group(2)), actual=ln,
                                     before=text.strip()[:140],
                                     after=(text.strip()[:140].replace(m.group(0), m.group(1) + str(ln)))))
print("  [P1-6a 可自动重编号] 处", len(p1_6_fix))
write_jsonl("p1_6a_lineno_autofix.jsonl", p1_6_fix)

# ------------------------------------------------------------------ P1-7b 无洞行 fix 归一清单
p1_7b = []
for i, r in enumerate(rows):
    v = verdict_of(r["messages"][2]["content"])
    if not v:
        continue
    if str(v.get("has_vulnerability")).lower() != "false":
        continue
    fx = str(v.get("fix_suggestion", ""))
    if not fx.strip().lower().startswith("no fix needed"):
        p1_7b.append(dict(row=i, before=fx[:220], after="no fix needed"))
print("  [P1-7b 无洞行 fix 归一] 行", len(p1_7b))
write_jsonl("p1_7b_nofix_normalize.jsonl", p1_7b)

# ---------------------------------------------------------------- P2-9 同码重复（代码块级）
JSCHEMA = re.compile(r"\`\`\`json\s*(\{.*?\})\s*\`\`\`", re.S)


def verdict_of_row(i):
    ms = list(JSCHEMA.finditer(rows[i]["messages"][2]["content"]))
    if not ms:
        return {}
    try:
        return json.loads(ms[-1].group(1))
    except Exception:
        return {}


seen = collections.defaultdict(set)
for i, r in enumerate(rows):
    for lang, body in code_blocks(r["messages"][1]["content"]):
        t = body.strip()
        if len(t) < 120:                     # 排除零碎片段/围栏噪声
            continue
        if "has_vulnerability" in t and len(t) < 400:   # 排除 user 里回显的输出 JSON 模板
            continue
        seen[hashlib.md5(t.encode("utf-8")).hexdigest()].add(i)
p2_9 = []
for h, ix in seen.items():
    if len(ix) > 1:
        ix = sorted(ix)
        vs = [(i, str(verdict_of_row(i).get("vulnerability_type", "")),
               str(verdict_of_row(i).get("has_vulnerability"))) for i in ix]
        p2_9.append(dict(group=len(p2_9) + 1, rows=ix, verdicts=vs,
                         same_verdict=len({x[1:] for x in vs}) == 1))
rows_in = sum(len(x["rows"]) for x in p2_9)
print("\n[P2-9 同码重复(代码块级≥120字符)] 组", len(p2_9), " 行", rows_in,
      " 同结论组", sum(1 for x in p2_9 if x["same_verdict"]))
print("     CWE 集中:", collections.Counter(x["verdicts"][0][1][:24] for x in p2_9).most_common(8))
write_jsonl("p2_9_duplicate_groups.jsonl", p2_9)

# ================================================================ 存活率对账（v2_19 → v2_26）
print("\n== 存活率对账（v2_19 标记行 → v2_26 去向）==")
# v2_19 全库 digest 基线（用于区分"改写后复阳/新波次"与"本来就干净"）
u19 = set(digest(r["messages"][1]["content"]) for r in rows19)
a19 = set(digest(r["messages"][2]["content"]) for r in rows19)


def survival(manifest_name, digest_key, base19, cur_flagged):
    """manifest_name: v2_19 清单文件；digest_key: 记录里的 digest 字段；
    base19: v2_19 对应侧的全量 digest 集；cur_flagged: v2_26 本类被标记 digest 集。"""
    old = [json.loads(l) for l in
           open(os.path.join(ROOT, "audit", "v2_19_opt_manifests", manifest_name), encoding="utf-8") if l.strip()]
    old_d = {x[digest_key] for x in old if digest_key in x}
    surv = old_d & cur_flagged
    gone = old_d - set(digest(r["messages"][1 if digest_key == "ud" else 2]["content"]) for r in rows) \
        if False else None
    # gone：旧 digest 在 v2_26 任何行都找不到 => 清洗/删除/改写
    cur_all = {digest(r["messages"][1 if digest_key == "ud" else 2]["content"]) for r in rows}
    gone = {d for d in old_d if d not in cur_all}
    new = cur_flagged - old_d - (base19 - old_d)  # 新被标记且非"v2_19 未标记的旧行"
    # 更准确的 new：cur_flagged 中 digest 完全不在 v2_19 全库对应侧基线中的
    new_true = {d for d in cur_flagged if d not in base19}
    res = dict(old_flagged=len(old_d), survived=len(surv), cleared_or_rewritten=len(gone),
               new_flagged_vs19_unflagged=len(new), new_rows_not_in_19=len(new_true))
    print(f"  {manifest_name}: {res}")
    return res


surv = {}
surv["p0_2"] = survival("p0_2_answer_annotations.jsonl", "digest", u19,
                        {x["digest"] for x in p0_2})
surv["p0_3_hi"] = survival("p0_3_weak_defense_neg_hiprec.jsonl", "digest", a19,
                           {x["digest"] for x in p0_3_hi})
surv["p1_5_stance"] = survival("p1_5_stance_conflict.jsonl", "digest", a19,
                               {x["digest"] for x in p1_5_stance})
surv["p1_6_mix"] = survival("p1_6_lineno_oob_mix.jsonl", "digest", a19,
                            {x["digest"] for x in p1_6_mix})

# ---------------------------------------------------------------- 汇总
answer_row_set = {x["row"] for x in p0_2}
any_anno_rows = answer_row_set | synth_rows
summary = dict(
    source=SRC, n_rows=N,
    p0_1_answer_key_leak=len(p0_1), p0_1_rows=[x["row"] for x in p0_1],
    p0_2_rows=len(p0_2), p0_2_occ=sum(cat_occ.values()),
    p0_2_occ_by_cat=dict(cat_occ), p0_2_rows_by_cat={k: len(v) for k, v in cat_row.items()},
    p0_2_extra_synth_only_rows=len(synth_rows - answer_row_set),
    p0_2_any_annotation_rows=len(any_anno_rows),
    p0_2_whole_line_rows=len(whole_line_rows), p0_2_inline_rows=len(inline_rows),
    p0_3_wide=len(p0_3_all), p0_3_narrow=len(p0_3_hi),
    p0_4_rows=len(p0_4), p0_4_english_probe_rows=len(p0_4_loose_rows),
    p1_5_stance=len(p1_5_stance), p1_5_cwe=len(p1_5_cwe),
    p1_6_embed_total=n_embed, p1_6_embed_bad=n_bad, p1_6_flagged_rows=len(p1_6_mix),
    p1_6a_autofix=len(p1_6_fix),
    p1_7_fix_contract=len(p1_7), p1_7b_nofix=len(p1_7b),
    p2_9_groups=len(p2_9), p2_9_rows=rows_in,
    p2_9_same_verdict_groups=sum(1 for x in p2_9 if x["same_verdict"]),
    survival_vs_v2_19=surv,
)
with open(os.path.join(OUT, "summary.json"), "w", encoding="utf-8") as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)
print("\n== SUMMARY ==")
print(json.dumps(summary, ensure_ascii=False, indent=2))
