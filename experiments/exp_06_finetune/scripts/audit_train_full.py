# -*- coding: utf-8 -*-
"""训练集全量数据质量审计（2026-08-15）。

覆盖：
  老部分  final_train_chatml_quality_final_fix.jsonl (7692)
  新增部分 supplement_*.jsonl (924, 6 个文件)

检测项：
  A. verdict JSON 解析健康 / 字段完整性
  B. 归一化代码重复 + 同码不同标签冲突
  C. 测试集泄露（vs exp_04_hard_samples/samples，归一化行集合 Jaccard，倒排索引加速）
  D. CoT 元注释（题目要求/本题要求等）
  E. CoT 犹豫表述（分 label 统计）
  F. 归因自相矛盾（CoT 提及的 CWE vs verdict CWE）
  G. 归因错误规则模式（JWT/MD5/eval/open+exec 四类 + 扩展）
  H. 骨架模板化（标识符归一化骨架分组）
  I. safe 样本疑似实为漏洞（CoT 强漏洞表述 / fix_suggestion 给出具体修复）
  J. 无 source 型漏洞（source 空 / 硬编码来源 却 vuln=true）

输出: experiments/exp_06_finetune/data/audit_full_20260815.json
"""
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(r"D:\code\毕业设计\Graduation-Project")
DATA = ROOT / "experiments" / "exp_06_finetune" / "data"
TESTSET = ROOT / "experiments" / "exp_04_hard_samples" / "samples"

OLD_FILE = "final_train_chatml_quality_final_fix.jsonl"
SUPP_FILES = [
    "supplement_samples.jsonl", "supplement_ssti_auth.jsonl",
    "supplement_mode_a.jsonl", "supplement_mode_b.jsonl",
    "supplement_mode_d.jsonl", "supplement_low_cwe.jsonl",
]

# ---------------------------------------------------------------- 解析工具

CODE_RE = re.compile(r"```(?:\w+)?\n(.*?)```", re.S)
JSON_RE = re.compile(r"```json\s*(.*?)```", re.S)
CWE_RE = re.compile(r"CWE-(\d+)")


def parse_sample(obj, source, idx):
    msgs = obj["messages"]
    user = msgs[1]["content"]
    asst = msgs[2]["content"]
    lm = re.search(r"语言:\s*([\w+#-]+)", user)
    cm = CODE_RE.search(user)
    jm = JSON_RE.search(asst)
    code = cm.group(1) if cm else ""
    verdict = None
    verdict_err = ""
    if jm:
        try:
            verdict = json.loads(jm.group(1))
        except Exception as e:
            verdict_err = str(e)[:80]
    else:
        verdict_err = "no json block"
    cot = asst[: jm.start()] if jm else asst
    return {
        "source": source, "line": idx + 1, "lang": lm.group(1) if lm else "?",
        "code": code, "cot": cot, "verdict": verdict, "verdict_err": verdict_err,
    }


# ---------------------------------------------------------------- 归一化

COMMENT_RE = re.compile(r"(#[^\n]*|//[^\n]*|/\*.*?\*/)", re.S)
STR_RE = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`")
NUM_RE = re.compile(r"\b\d+\b")

# 保留关键词/常见安全 API 的标识符，其余归一化为 ID（骨架模板化检测）
_KEEP = set("""if elif else for while def return class import from as try except finally with
lambda pass break continue raise yield async await const let var function new this self
none true false null nil undefined and or not in is
eval exec compile pickle marshal yaml json load loads dumps parse open read write send
request response args form cookies query body get post route render template
os sys subprocess popen system shell curl socket recv connect bind
flask django fastapi express app cursor execute query sql select insert update delete where
document window innerhtml html dom cookie localstorage fetch ajax axios
jwt token md5 sha1 sha256 hmac base64 secret key password user admin
hashlib crypto random uuid venv strip replace format join encode decode headers
int str list dict set tuple len range print
map filter reduce sort foreach instanceof typeof delete void enum struct public private static void
string integer boolean double float char
caasaa""".split())
ID_RE = re.compile(r"\b[A-Za-z_]\w*\b")


def norm_lines(code: str):
    """归一化代码行列表（去注释/空行，字符串/数字占位）。"""
    code = COMMENT_RE.sub(" ", code)
    code = STR_RE.sub("S", code)
    code = NUM_RE.sub("N", code)
    out = []
    for ln in code.splitlines():
        t = ln.strip()
        if t and len(t) >= 4:
            out.append(t)
    return out


def skeleton(code: str) -> str:
    """骨架归一化：非保留标识符 → ID。"""
    code = COMMENT_RE.sub(" ", code)
    code = STR_RE.sub("S", code)
    code = NUM_RE.sub("N", code)
    return "\n".join(
        ID_RE.sub(lambda m: m.group(0) if m.group(0).lower() in _KEEP else "ID", ln.strip())
        for ln in code.splitlines() if ln.strip()
    )


# ---------------------------------------------------------------- 加载数据

samples = []
with open(DATA / OLD_FILE, encoding="utf-8") as fh:
    for i, ln in enumerate(fh):
        samples.append(parse_sample(json.loads(ln), "old", i))
for f in SUPP_FILES:
    with open(DATA / f, encoding="utf-8") as fh:
        for i, ln in enumerate(fh):
            samples.append(parse_sample(json.loads(ln), f.replace("supplement_", "").replace(".jsonl", ""), i))

print(f"loaded {len(samples)} samples")

report = {"n_total": len(samples), "per_source": Counter(s["source"] for s in samples)}

# ---------------------------------------------------------------- A. 解析健康

bad_parse = [{"source": s["source"], "line": s["line"], "err": s["verdict_err"]}
             for s in samples if not s["verdict"]]
REQ_FIELDS = ["has_vulnerability", "vulnerability_type", "source", "sink", "explanation"]
missing_fields = [{"source": s["source"], "line": s["line"],
                   "missing": [f for f in REQ_FIELDS if f not in s["verdict"]]}
                  for s in samples if s["verdict"] and any(f not in s["verdict"] for f in REQ_FIELDS)]
report["A_parse"] = {"bad_json": bad_parse, "n_bad": len(bad_parse),
                     "missing_fields": missing_fields, "n_missing": len(missing_fields)}
print(f"A: bad_json={len(bad_parse)} missing_fields={len(missing_fields)}")

# ---------------------------------------------------------------- B. 重复与标签冲突

by_normcode = defaultdict(list)
for s in samples:
    key = "\n".join(norm_lines(s["code"]))
    by_normcode[key].append(s)

dup_groups = [g for g in by_normcode.values() if len(g) > 1]
conflict_groups = []
for g in dup_groups:
    labels = {(s["verdict"] or {}).get("has_vulnerability") for s in g}
    cwes = {CWE_RE.search((s["verdict"] or {}).get("vulnerability_type", "") or "").group(0)
            if CWE_RE.search((s["verdict"] or {}).get("vulnerability_type", "") or "") else ""
            for s in g}
    if len(labels) > 1 or len(cwes) > 1:
        conflict_groups.append({
            "sources": [f"{s['source']}:{s['line']}" for s in g],
            "labels": sorted(str(x) for x in labels), "cwes": sorted(cwes)})
report["B_dup"] = {
    "n_dup_groups": len(dup_groups),
    "n_dup_samples": sum(len(g) - 1 for g in dup_groups),
    "n_conflict_groups": len(conflict_groups), "conflicts": conflict_groups[:50],
    "dup_by_source": dict(Counter(f"{s['source']}" for g in dup_groups for s in g[1:]))}
print(f"B: dup_groups={len(dup_groups)} dup_samples={sum(len(g)-1 for g in dup_groups)} "
      f"conflicts={len(conflict_groups)}")

# ---------------------------------------------------------------- C. 测试集泄露

test_files = sorted(TESTSET.glob("*.py")) + sorted(TESTSET.glob("*.java"))
line_index = defaultdict(set)   # norm_line -> set(test_idx)
test_sets = []
for ti, tf in enumerate(test_files):
    ls = set(norm_lines(tf.read_text(encoding="utf-8", errors="replace")))
    test_sets.append((tf.name, ls))
    for l in ls:
        line_index[l].add(ti)

leaks = []
for s in samples:
    ls = set(norm_lines(s["code"]))
    if not ls:
        continue
    hits = Counter()
    for l in ls:
        if l in line_index:
            for ti in line_index[l]:
                hits[ti] += 1
    for ti, inter in hits.items():
        name, tls = test_sets[ti]
        union = len(ls) + len(tls) - inter
        j = inter / union if union else 0.0
        if j >= 0.40:
            vt = (s["verdict"] or {}).get("vulnerability_type", "")
            leaks.append({"source": s["source"], "line": s["line"],
                          "test": name, "jaccard": round(j, 3),
                          "verdict_type": vt})
print(f"C: leaks>=0.40: {len(leaks)}, >=0.70: {sum(1 for l in leaks if l['jaccard']>=0.7)}")
leaks.sort(key=lambda x: -x["jaccard"])
report["C_leak"] = {"n_ge40": len(leaks), "n_ge70": sum(1 for l in leaks if l["jaccard"] >= 0.7),
                    "all": leaks, "top": leaks[:40]}
for l in leaks[:12]:
    print("   ", l)

# ---------------------------------------------------------------- D. CoT 元注释

META_RE = re.compile(r"题目要求|本题要求|根据题目|题目设定|按题目|题目中")
meta = [{"source": s["source"], "line": s["line"],
         "ctx": META_RE.search(s["cot"]).group(0)} for s in samples if META_RE.search(s["cot"])]
report["D_meta"] = {"n": len(meta), "items": meta}
print(f"D: meta-comment samples={len(meta)}")
by_src = Counter(m["source"] for m in meta)
print("   by source:", dict(by_src))

# ---------------------------------------------------------------- E. CoT 犹豫

HEDGE_WORDS = ["可能", "似乎", "或许", "大概", "貌似", "有可能是", "看起来", "推测",
               "不一定", "难以确定", "无法确定", "可能是", "疑似"]
hedge = []
for s in samples:
    hit = [w for w in HEDGE_WORDS if w in s["cot"]]
    if hit:
        hedge.append({"source": s["source"], "line": s["line"],
                      "label": (s["verdict"] or {}).get("has_vulnerability"),
                      "words": sorted(set(hit))})
hedge_by_label = defaultdict(int)
label_cnt = defaultdict(int)
for s in samples:
    lb = (s["verdict"] or {}).get("has_vulnerability")
    label_cnt[str(lb)] += 1
for h in hedge:
    hedge_by_label[str(h["label"])] += 1
report["E_hedge"] = {
    "n": len(hedge), "pct": round(len(hedge) / len(samples) * 100, 1),
    "by_label": {k: {"hedge": hedge_by_label[k], "total": label_cnt[k],
                     "pct": round(hedge_by_label[k] / label_cnt[k] * 100, 1)}
                 for k in label_cnt},
    "by_source": dict(Counter(h["source"] for h in hedge)),
    "items": hedge[:200]}
print(f"E: hedge={len(hedge)} ({len(hedge)/len(samples)*100:.1f}%), by_label:",
      {k: v for k, v in report['E_hedge']['by_label'].items()})

# ---------------------------------------------------------------- F. 归因自相矛盾

contradict = []
for s in samples:
    v = s["verdict"] or {}
    vt = v.get("vulnerability_type", "") or ""
    m = CWE_RE.search(vt)
    if not m:
        continue
    vcwe = "CWE-" + m.group(1)
    mentions = Counter("CWE-" + c for c in CWE_RE.findall(s["cot"]))
    # verdict CWE 在 CoT 中从未出现，且 CoT 论证了其他 CWE ≥2 次
    if vcwe not in mentions and sum(mentions.values()) >= 2:
        contradict.append({"source": s["source"], "line": s["line"], "verdict": vcwe,
                           "cot_mentions": dict(mentions)})
report["F_contradict"] = {"n": len(contradict), "items": contradict[:80]}
print(f"F: attribution contradiction candidates={len(contradict)}")
for c in contradict[:15]:
    print("   ", c)

# ---------------------------------------------------------------- G. 归因错误规则模式

def vt_cwe(v):
    m = CWE_RE.search((v or {}).get("vulnerability_type", "") or "")
    return int(m.group(1)) if m else 0

misattr = []
for s in samples:
    v = s["verdict"] or {}
    cwe = vt_cwe(v)
    code_l = s["code"].lower()
    cot_l = s["cot"].lower()
    item = {"source": s["source"], "line": s["line"], "verdict_cwe": f"CWE-{cwe}"}
    tagged = False
    if cwe == 287 and ("jwt" in code_l or "jwt" in cot_l):
        # JWT 类问题标 287：无过期 → 613；硬编码密钥 → 321/798；alg=none → 347
        if re.search(r"expire|exp\b|过期", cot_l) or "过期" in s["cot"]:
            item["rule"] = "JWT 标 CWE-287 → 应 CWE-613（过期缺失）"
            tagged = True
    if cwe == 287 and ("md5" in code_l or "md5" in cot_l):
        item["rule"] = "MD5 标 CWE-287 → 应 CWE-327/798"
        tagged = True
    if cwe == 917 and re.search(r"\beval\s*\(|\bexec\s*\(", s["code"]):
        item["rule"] = "eval/exec 标 CWE-917 → 应 CWE-94/95"
        tagged = True
    if cwe == 610 and re.search(r"\bopen\s*\(", s["code"]) and re.search(r"\bexec\s*\(", s["code"]):
        item["rule"] = "open+exec 标 CWE-610 → 应 CWE-98/94"
        tagged = True
    if tagged:
        misattr.append(item)
report["G_misattr"] = {"n": len(misattr),
                       "by_rule": dict(Counter(i["rule"] for i in misattr)),
                       "items": misattr}
print(f"G: rule-based misattribution={len(misattr)}", report["G_misattr"]["by_rule"])

# ---------------------------------------------------------------- H. 骨架模板化

sk_groups_by_src = defaultdict(lambda: defaultdict(list))
for s in samples:
    sk_groups_by_src[s["source"]][skeleton(s["code"])].append(s["line"])

sk_stat = {}
sk_detail = {}
for src, groups in sk_groups_by_src.items():
    n = sum(len(v) for v in groups.values())
    multi = {k: v for k, v in groups.items() if len(v) >= 2}
    g5 = {k: v for k, v in groups.items() if len(v) >= 5}
    sk_stat[src] = {
        "n_samples": n, "unique_skeletons": len(groups),
        "n_groups_ge2": len(multi),
        "n_in_groups": sum(len(v) for v in multi.values()),
        "pct_in_groups": round(sum(len(v) for v in multi.values()) / n * 100, 1),
        "n_groups_ge5": len(g5), "max_group": max((len(v) for v in groups.values()), default=0),
    }
    sk_detail[src] = sorted(
        ({"size": len(v), "lines": [f"{src}:{l}" for l in v[:12]]} for v in multi.values()),
        key=lambda x: -x["size"])[:15]
report["H_skeleton"] = {"stat": sk_stat, "top_groups": sk_detail}
for src, st in sk_stat.items():
    print(f"H: {src}: n={st['n_samples']} uniq={st['unique_skeletons']} "
          f"ge2={st['n_groups_ge2']} in_groups={st['pct_in_groups']}% "
          f"ge5={st['n_groups_ge5']} max={st['max_group']}")

# ---------------------------------------------------------------- I. safe 疑似实为漏洞

SAFE_STRONG = re.compile(r"确实存在漏洞|确实有漏洞|存在(明显)?的?漏洞|该漏洞|可被攻击者利用|攻击者(可|可以|能够)")
NEG = re.compile(r"不构成|不存在|没有漏洞|并非漏洞|不会导致|安全(的|无)|无风险")
safe_sus = []
for s in samples:
    v = s["verdict"] or {}
    if v.get("has_vulnerability") is not False:
        continue
    reasons = []
    m = SAFE_STRONG.search(s["cot"])
    if m and not NEG.search(s["cot"][:m.start()][-60:]):
        reasons.append(f"CoT 强漏洞表述: ...{m.group(0)}...")
    fix = v.get("fix_suggestion", "") or ""
    if re.search(r"应改为|应该|建议.{0,12}(改|加|过滤|校验|替换)", fix):
        reasons.append(f"safe 但 fix_suggestion 给出具体修复: {fix[:80]}")
    if reasons:
        safe_sus.append({"source": s["source"], "line": s["line"], "reasons": reasons})
report["I_safe_suspect"] = {"n": len(safe_sus), "items": safe_sus[:400]}
# I-hard: safe 却明确断言漏洞（CoT "结论：CWE-xxx" / verdict_type 含 CWE / "确实存在漏洞"）
HARD1 = re.compile(r"结论[：:].{0,30}CWE-\d+")
HARD3 = "确实存在漏洞"
hard_list = []
for s in samples:
    v = s["verdict"] or {}
    if v.get("has_vulnerability") is not False:
        continue
    vt = v.get("vulnerability_type", "") or ""
    h1, h2, h3 = HARD1.search(s["cot"]), CWE_RE.search(vt), HARD3 in s["cot"]
    if h1 or h2 or h3:
        hard_list.append({"source": s["source"], "line": s["line"],
                          "why": (CWE_RE.search(h1.group(0)).group(0) if h1 else "") or vt or "确实存在漏洞"})
report["I_safe_hard"] = {"n": len(hard_list), "items": hard_list}
print(f"I: safe-hard={len(hard_list)}, soft-candidates={len(safe_sus)}")
for x in hard_list[:15]:
    print("   ", x)

# ---------------------------------------------------------------- J. 无 source 型漏洞

nosrc = []
for s in samples:
    v = s["verdict"] or {}
    if v.get("has_vulnerability") is not True:
        continue
    src_f = (v.get("source", "") or "").strip()
    if not src_f:
        nosrc.append({"source": s["source"], "line": s["line"], "why": "source 字段为空",
                      "verdict_type": v.get("vulnerability_type", "")})
    elif re.search(r"硬编码|字面量|常量|固定值|无(外部|用户)输入|内置", src_f):
        nosrc.append({"source": s["source"], "line": s["line"],
                      "why": f"source 声明为非外部输入: {src_f[:80]}",
                      "verdict_type": v.get("vulnerability_type", "")})
# J2: 排除本就无外部污点源的类型（硬编码凭证/权限/加密配置类），剩余为可疑牵强
NO_SOURCE_OK = re.compile(r"CWE-(798|732|276|327|321|326|759|1188|250|693|1284|16|73|328|916|1243|1242|732)")
nosrc_suspect = [x for x in nosrc
                 if not (x.get("verdict_type") and NO_SOURCE_OK.search(x["verdict_type"]))]
report["J_nosource"] = {"n": len(nosrc),
                        "n_suspect": len(nosrc_suspect),
                        "by_source": dict(Counter(x["source"] for x in nosrc)),
                        "by_type": dict(Counter(x["verdict_type"][:20] for x in nosrc)),
                        "suspects": nosrc_suspect[:120]}
print(f"J: no-source vuln={len(nosrc)} (排除无源合理类型后可疑={len(nosrc_suspect)})")
print(f"J: no-source vuln={len(nosrc)}", report["J_nosource"]["by_source"])

# ---------------------------------------------------------------- 保存

out = DATA / "audit_full_20260815.json"
def _clean(o):
    if isinstance(o, Counter):
        return dict(o)
    if isinstance(o, defaultdict):
        return dict(o)
    if isinstance(o, Path):
        return str(o)
    raise TypeError(str(type(o)))
out.write_text(json.dumps(report, ensure_ascii=False, indent=1, default=_clean), encoding="utf-8")
print(f"\nsaved -> {out}")
