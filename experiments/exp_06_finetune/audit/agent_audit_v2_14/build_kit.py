# -*- coding: utf-8 -*-
"""审查包（review kit）构建：汇总全部脚本标记 → 风险分层 → 30 条/批 → kit jsonl。

分层：
  T1 = 高风险（bad_json / 结构违规 / 矛盾簇 / 转义强污染 / 锚定全脱靶 / 教师独白 /
        身份泄漏 / vt 冲突 / 越界行号 / S5 污染 / 往轮 scan 命中且未裁决）
  T2 = 中风险（锚定部分脱靶 / 行号大偏移 / 转义弱污染 / 关键词捷径命中且结论存疑）
  T3 = 分层随机（language × has_vuln 分层，覆盖尾部语言与 CWE）
输出：out/kits/batch_XXX.jsonl + out/kit_index.json + out/flag_summary.json
"""
import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acommon import OUT, load_rows, code_blocks, last_json, is_multi_file, hash01

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
random.seed(20260830)

LOG = []
def P(*a):
    LOG.append(" ".join(str(x) for x in a))

rows, _ = load_rows()
rows_by_id = {r["id"]: r for r in rows}

def flags_of(fn):
    p = OUT / fn
    if not p.exists():
        return []
    return [json.loads(l) for l in p.open(encoding="utf-8")]

risk = defaultdict(lambda: {"t1": [], "t2": []})

def mark(level, rid, tag):
    risk[rid][level].append(tag)

# --- S1 ---
for v in flags_of("s1_violations.jsonl"):
    mark("t1", v["id"], "s1:" + v["type"])

# --- S2：cwe_in_safe_expl —— 否定/反证式剔除，残余随机 60 条进 T1 语义裁决 ---
NEG_WIN = re.compile(r"(不构成|不适用|不属于|并非|不是|非该|假设[^\n]{0,20}(利用|尝试|构造|提交|降级|注入|篡改|伪造|执行|发起|通过)|尝试利用|防御|阻断|拒绝|误报|排除|防止|免受|不涉及|用于|即被|在解析阶段|以防止|的利用|攻击路径|攻击面)[^\n]{0,26}$")
cwe_safe_ids = []
for v in flags_of("s2_field_flags.jsonl"):
    if v["type"] == "cwe_in_safe_expl":
        r = rows_by_id[v["id"]]
        o, _, _ = last_json(r["rec"]["messages"][2]["content"])
        expl = str(o.get("explanation", "")) if isinstance(o, dict) else ""
        mentions = [m for m in re.finditer(r"CWE-\d+", expl)]
        unrefuted = [m for m in mentions if not NEG_WIN.search(expl[:m.start()][-46:])]
        if unrefuted:
            cwe_safe_ids.append(v["id"])
        continue
    mark("t1", v["id"], "s2:" + v["type"])
for v in flags_of("s2_bad_json.jsonl"):
    mark("t1", v["id"], "s2:bad_json")
random.shuffle(cwe_safe_ids)
for rid in cwe_safe_ids[:60]:
    mark("t1", rid, "s2:cwe_in_safe_semantic_check")
for rid in cwe_safe_ids[60:]:
    mark("t2", rid, "s2:cwe_in_safe_unrefuted_mention")

# --- S3 ---
for v in flags_of("s3_flags.jsonl"):
    mark("t1", v["id"], "s3:" + v["type"])

# --- S4 转义：强 = 含 \" 或 \\n 且语言为 c/cpp/java/js；弱 = 其他 ---
lang_of = {}
for r in rows:
    m = re.search(r"```([\w+#./-]*)", r["rec"]["messages"][1]["content"])
    lang_of[r["id"]] = (m.group(1).lower() if m else "?")
CFAM = {"c", "cpp", "java", "javascript", "go", "php", "rust", "typescript", "csharp"}
for x in flags_of("s4_escape.jsonl"):
    s = x["sample"]
    strong = '\\"' in s or (lang_of.get(x["id"], "?") in CFAM and "\\n" in s) or "\\0" in s
    mark("t1" if strong else "t2", x["id"], f"s4:escape_{'strong' if strong else 'weak'}_{x['field']}")

# --- S5 ---
for x in flags_of("s5_contam.jsonl"):
    for i in x["issues"]:
        if i["type"] == "json_unclosed_brace":
            continue  # 已归因为字符串内花括号，非缺陷
        mark("t1", x["id"], "s5:" + i["type"])

# --- S6：全部教学凭证 → t2 观察而非缺陷 ---
for x in flags_of("s6_creds.jsonl"):
    mark("t2", x["id"], "s6:" + x["kind"])

# --- S7 矛盾簇：只把代码几乎全同（Jaccard≥0.95）的 hv 矛盾留 T1，其余边界对 T2 ---
def shing(code):
    toks = re.findall(r"\w+", code.lower())
    return {" ".join(toks[i:i + 5]) for i in range(max(0, len(toks) - 4))}

code_of = {}
for r in rows:
    blocks = code_blocks(r["rec"]["messages"][1]["content"])
    code_of[r["id"]] = "\n\n".join(c for _, c in blocks)
SH_CACHE = {}
def sh_of(i):
    if i not in SH_CACHE:
        SH_CACHE[i] = shing(code_of.get(i, ""))
    return SH_CACHE[i]

def jac_ids(a, b):
    sa, sb = sh_of(a), sh_of(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / (len(sa) + len(sb) - len(sa & sb))

for ln in (OUT / "s7_conflict_clusters.jsonl").read_text(encoding="utf-8").splitlines():
    cl = json.loads(ln)
    ids = [m["id"] for m in cl["members"]]
    hvs = {m["hv"] for m in cl["members"]}
    cwes = {m["cwe"] for m in cl["members"]}
    mx = max((jac_ids(a, b) for ai, a in enumerate(ids) for b in ids[ai + 1:]), default=0.0)
    if True in hvs and False in hvs:
        for i in ids:
            mark("t1" if mx >= 0.95 else "t2", i, f"s7:contradiction_hv_jac{mx:.2f}")
    elif len(cwes) > 1 and None not in cwes:
        for i in ids:
            mark("t2" if mx < 0.95 else "t1", i, f"s7:boundary_cwe_pair_jac{mx:.2f}")

# --- 教师独白 / 元话语 / 身份泄漏（已剔除 await 误伤与 CWE-1427 合法术语） ---
MONO = re.compile(
    r"(Actually[ ,]|Hmm[,.]|Let me |For this training data|as a large language model"
    r"|作为一个大语言模型|作为AI|作为 AI|训练数据|生成数据|本数据集|系统提示词)", re.I)
for r in rows:
    a = r["rec"]["messages"][2]["content"]
    m = MONO.search(a)
    if m:
        tag = "mono:" + m.group(0)[:20]
        strong = re.search(r"(大语言模型|large language model|训练数据|For this training data|系统提示词)", a, re.I)
        mark("t1" if strong else "t2", r["id"], tag)

# --- 往轮 scan_v2_15 命中（已被裁决的记录仅作 t2 复核线索） ---
scan = json.load(open(Path(__file__).resolve().parents[1] / "scan_v2_15_flags.json", encoding="utf-8"))
ADJUDICATED = {509, 932, 7547, 6981, 7333}
for cat, items in scan.items():
    if cat == "P1B_sqli_param":
        continue  # 已裁定为契约内正确形态
    for it in items:
        ln = it.get("line")
        if ln in ADJUDICATED:
            continue
        lvl = "t2" if cat in ("P0C", "F8_sink_absent") else "t2"
        mark(lvl, ln, f"scan:{cat}")

# --- 往轮行号大偏移 ---
big_delta = 0
for p in [Path(__file__).resolve().parents[1] / "lineno_review_v2_15a.jsonl"]:
    if p.exists():
        for line in p.open(encoding="utf-8"):
            it = json.loads(line)
            md = it.get("max_delta", 0)
            cat = it.get("category", "")
            if md and md >= 8 and not cat.startswith("embed"):
                mark("t2", it["orig_line"], f"lineno:delta{md}")
                big_delta += 1

# --- 汇总分层 ---
t1_ids = sorted(i for i, v in risk.items() if v["t1"])
t2_ids = sorted(i for i, v in risk.items() if v["t1"] or v["t2"])
P(f"T1 高风险: {len(t1_ids)} 条")
P(f"T1+T2: {len(t2_ids)} 条")
tag_counter = Counter(t for i in t1_ids for t in risk[i]["t1"])
P("T1 标签分布 top20:")
for t, n in tag_counter.most_common(20):
    P(f"  {t}: {n}")

# --- T3 分层随机 ---
strata = defaultdict(list)
for r in rows:
    rid = r["id"]
    if rid in t2_ids:
        continue
    o, _, _ = last_json(r["rec"]["messages"][2]["content"])
    hv = bool(o.get("has_vulnerability")) if isinstance(o, dict) else None
    lang = lang_of.get(rid, "?")
    lang_group = lang if lang not in ("python", "javascript", "java") else lang
    strata[(lang_group, hv)].append(rid)
P("")
P("T3 分层数: " + str(len(strata)))
for k, v in sorted(strata.items(), key=lambda x: -len(x[1]))[:8]:
    P(f"  {k}: {len(v)}")

t3_sample = []
for k, v in sorted(strata.items()):
    take = random.sample(v, min(len(v), max(3, len(v) // 25)))  # ~4% 起步，尾部语言保底 3 条
    t3_sample += take
P(f"T3 抽样: {len(t3_sample)} 条")

review_ids = t1_ids + [i for i in t2_ids if i not in t1_ids] + t3_sample
random.shuffle(review_ids)

# --- 批切分（30/批） ---
BATCH = 30
batches = [review_ids[i:i + BATCH] for i in range(0, len(review_ids), BATCH)]
P(f"总审查条数: {len(review_ids)} → {len(batches)} 批")

kit_dir = OUT / "kits"
kit_dir.mkdir(exist_ok=True)
# 载入 S3 逐样本 refs
s3_refs = {}
p3 = OUT / "s3_refs.jsonl"
if p3.exists():
    for line in p3.open(encoding="utf-8"):
        it = json.loads(line)
        s3_refs[it["id"]] = it["refs"]

index = []
for bi, ids in enumerate(batches, 1):
    recs = []
    for rid in ids:
        r = rows_by_id[rid]
        u = r["rec"]["messages"][1]["content"]
        a = r["rec"]["messages"][2]["content"]
        blocks = code_blocks(u)
        code_lines = []
        for bi2, (lang, code) in enumerate(blocks, 1):
            ls = code.rstrip("\n").split("\n")
            code_lines.append({"block": bi2, "lang": lang,
                               "lines": [f"{j+1:4d}| {l}" for j, l in enumerate(ls)]})
        o, raw, err = last_json(a)
        recs.append({
            "id": rid,
            "lang": lang_of.get(rid, "?"),
            "multi_file": is_multi_file(u),
            "user": u,
            "code_numbered": code_lines,
            "assistant": a,
            "json": o if isinstance(o, dict) else None,
            "json_error": err,
            "s3_refs": s3_refs.get(rid, []),
            "flags": risk[rid]["t1"] + risk[rid]["t2"],
        })
    fn = kit_dir / f"batch_{bi:03d}.jsonl"
    with fn.open("w", encoding="utf-8") as f:
        for rec in recs:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    index.append({"batch": bi, "file": str(fn), "ids": ids,
                  "t1": sum(1 for i in ids if risk[i]["t1"])})

(OUT / "kit_index.json").write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
flag_summary = {str(i): risk[i] for i in sorted(risk)}
(OUT / "flag_summary.json").write_text(json.dumps(flag_summary, ensure_ascii=False, indent=1), encoding="utf-8")
print("\n".join(LOG))
print(f"kits -> {kit_dir}")
