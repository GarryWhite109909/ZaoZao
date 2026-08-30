# -*- coding: utf-8 -*-
"""S8 分布统计：长度、配比、risk、CWE×语言、开头 n-gram、注释捷径、safe 形态、分片漂移。

输出：out/s8_out.txt + out/s8_matrix.json
"""
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acommon import BASE, OUT, load_rows, code_blocks, last_json, token_est, write_jsonl, pct, hash01

LOG = []


def P(*a):
    LOG.append(" ".join(str(x) for x in a))


rows, _ = load_rows()

# ---- 分片映射：user 指纹在旧版本文件中的最早出现 ----
shard_files = sorted(BASE.glob("data/final_train_chatml_alpha06_v2_*.jsonl"))
shard_files = [p for p in shard_files if "long_overflow" not in p.name and "v2_14" not in p.name and "v2_15" not in p.name]
shard_order = ["final_train_chatml_alpha06.jsonl"] + [p.name for p in shard_files]
hash2shard = {}
for name in shard_order:
    p = BASE / "data" / name
    if not p.exists():
        continue
    with p.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            u = o["messages"][1]["content"]
            h = hash01(u)
            if h not in hash2shard:
                hash2shard[h] = name

lens = []
openings = Counter()
cwe_lang = defaultdict(Counter)
risk_dist = Counter()
kv_ratio = Counter()
comment_kw = Counter()      # (kw_hit, hv)
safe_morph = Counter()
teacher_stats = defaultdict(lambda: Counter())
shard_stats = defaultdict(lambda: Counter())

KW = re.compile(r"(漏洞|危险|故意|vulnerable|insecure|malicious|attack|unsafe|NOT Safe|存在安全)")

DEFENSE_MARKS = re.compile(
    r"(parameteriz|\?\s*,|\?\s*\)|execute\(sql|\b%s\b|placeholders?|白名单|whitelist|allowlist|"
    r"html\.escape|markupsafe|escape_html|htmlspecialchars|DOMPurify|textContent|"
    r"htmlsafe|json\.dumps|shlex\.quote|subprocess\.\w+\[[^\]]*shell\s*=\s*False|"
    r"sanitize|validator|validate_|escape\(|startswith\(ALLOW|in ALLOWED|allowlist)", re.I)

for r in rows:
    rid = r["id"]
    u = r["rec"]["messages"][1]["content"]
    a = r["rec"]["messages"][2]["content"]
    blocks = code_blocks(r["rec"]["messages"][1]["content"])
    code = "\n\n".join(c for _, c in blocks)
    o, _, _ = last_json(a)
    hv = o.get("has_vulnerability") if isinstance(o, dict) else None
    vt = str(o.get("vulnerability_type", "")) if isinstance(o, dict) else ""
    risk = str(o.get("risk_level", "")) if isinstance(o, dict) else ""
    cwe = re.findall(r"CWE-(\d+)", vt)
    lang_m = re.search(r"语言[:：]\s*([\w+#./]+)", u)
    lang = lang_m.group(1).lower() if lang_m else ("多文件" if "多文件" in u else "?")

    t = token_est(u) + token_est(a) + 908
    lens.append(t)
    opening = re.sub(r"\s+", "", a[:24])
    openings[opening] += 1
    risk_dist[risk] += 1
    kv_ratio[bool(hv)] += 1
    if hv and cwe:
        cwe_lang[f"CWE-{cwe[0]}"][lang] += 1
    kw_hit = bool(KW.search(code))
    comment_kw[(kw_hit, hv)] += 1
    if hv is False:
        has_defense = bool(DEFENSE_MARKS.search(code)) or bool(DEFENSE_MARKS.search(a))
        n_lines = code.count("\n") + 1 if code else 0
        if has_defense and "N/A" not in str(o.get("explanation", ""))[:6]:
            safe_morph["重防御型"] += 1
        elif n_lines <= 12:
            safe_morph["短小无特征型"] += 1
        else:
            safe_morph["其他安全型"] += 1
    fd = r["rec"].get("fix_distill") or {}
    teacher = str(fd.get("teacher", "<none>"))
    teacher_stats[teacher]["n"] += 1
    # 分片
    shard = hash2shard.get(hash01(u), "<new_in_v2_14>")
    shard_stats[shard]["n"] += 1
    if hv:
        shard_stats[shard]["vuln"] += 1
        shard_stats[shard]["tok_sum"] += t
        shard_stats[shard]["cwe_len"] += len(cwe)

def pctl(xs, q):
    xs = sorted(xs)
    if not xs:
        return 0
    i = max(0, min(len(xs) - 1, int(q * (len(xs) - 1) + 0.5) - 1))
    return xs[i]

P("== 长度（token 估算，含 system 908） ==")
P(f"  min={min(lens)} p50={pctl(lens,0.5)} p90={pctl(lens,0.9)} p95={pctl(lens,0.95)} p99={pctl(lens,0.99)} max={max(lens)}")
P(f"  >12288: {sum(1 for x in lens if x > 12288)} 条")
P("")
P("== 有洞:安全 ==")
P(f"  有洞 {kv_ratio[True]} / 安全 {kv_ratio[False]} = 1 : {kv_ratio[False]/max(1,kv_ratio[True]):.2f}")
P("")
P("== risk_level ==")
for v, n in risk_dist.most_common():
    P(f"  {v}: {n} ({pct(n, len(rows))})")
P("")
P("== CWE×语言矩阵（前 18 行 CWE，按总量） ==")
cwe_tot = sorted(cwe_lang.items(), key=lambda x: -sum(x[1].values()))
matrix = {c: dict(vs) for c, vs in cwe_lang.items()}
for c, vs in cwe_tot[:18]:
    langs = ", ".join(f"{k}:{v}" for k, v in sorted(vs.items(), key=lambda x: -x[1])[:5])
    P(f"  {c} (共{sum(vs.values())}): {langs}")
P(f"  CWE 种类数: {len(cwe_lang)}；1-shot CWE 数: {sum(1 for c, vs in cwe_lang.items() if sum(vs.values()) == 1)}")
P("")
P("== assistant 开头 24 字（归一空白）重复 top10 ==")
for o, n in openings.most_common(10):
    P(f"  {n:5d}  {o}")
P("")
P("== 注释/叙事关键词 × 结论 列联 ==")
for (kw, hv), n in sorted(comment_kw.items(), key=lambda x: str(x[0])):
    P(f"  kw_hit={kw}, has_vuln={hv}: {n}")
tot_kw = comment_kw[(True, True)] + comment_kw[(True, False)]
if tot_kw:
    P(f"  关键词命中样本中有洞率: {pct(comment_kw[(True,True)], tot_kw)}")
tot_nokw = comment_kw[(False, True)] + comment_kw[(False, False)]
P(f"  关键词未命中样本中有洞率: {pct(comment_kw[(False,True)], tot_nokw)}")
P("")
P("== 安全样本形态 ==")
for k, n in safe_morph.most_common():
    P(f"  {k}: {n}")
P("")
P("== teacher 桶 ==")
for t, c in sorted(teacher_stats.items(), key=lambda x: -x[1]["n"]):
    P(f"  {t}: {c['n']}")
P("")
P("== 分片漂移（origin shard 映射） ==")
for s, c in sorted(shard_stats.items(), key=lambda x: -x[1]["n"]):
    vuln_rate = pct(c["vuln"], c["n"])
    avg_tok = c["tok_sum"] // max(1, c["vuln"])
    cwe_per = c["cwe_len"] / max(1, c["vuln"])
    P(f"  {s}: n={c['n']} 有洞率={vuln_rate} 漏洞样本均长={avg_tok} cwe引用/漏洞样本={cwe_per:.2f}")

(OUT / "s8_matrix.json").write_text(json.dumps(
    {"cwe_lang": matrix, "risk": dict(risk_dist), "openings": dict(openings.most_common(30)),
     "safe_morph": dict(safe_morph), "shards": {k: dict(v) for k, v in shard_stats.items()}},
    ensure_ascii=False, indent=1), encoding="utf-8")
(OUT / "s8_out.txt").write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("\n".join(LOG))
