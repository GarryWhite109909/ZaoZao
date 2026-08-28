# -*- coding: utf-8 -*-
"""行号真实性全量校验：assistant 引用的行号是否落在 user 代码块的真实行数内"""
import json, re, sys, collections, statistics
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SRC = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_alpha06_v2_12.jsonl")
OUT = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\audit\a7_lineno_out.txt")

rows = []
with SRC.open("r", encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if line:
            rows.append((i, json.loads(line)))
R = dict(rows)
def get(msgs, role):
    for m in msgs:
        if m.get("role") == role: return m.get("content", "")
    return ""
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)
CODE_BLOCK = re.compile(r"```[a-zA-Z0-9_+#\-\.]*[ \t]*\r?\n(.*?)```", re.S)

w = OUT.open("w", encoding="utf-8")
def P(*a): print(*a, file=w)

def code_lines(u):
    """返回 (代码块行数, 代码块文本)。取最大的代码块。"""
    cbs = CODE_BLOCK.findall(u)
    if not cbs: return 0, ""
    cb = max(cbs, key=len)
    # 去掉尾部单个换行再分行
    txt = cb[:-1] if cb.endswith("\n") else cb
    return len(txt.split("\n")), txt

stats = collections.Counter()
oor_json = []      # JSON 字段行号越界
oor_anal = []      # 分析部分行号越界
inconsist = []     # 分析行号 vs JSON 行号 不一致
zero_ref = 0       # 分析完全没提行号
samples = []
n_vuln = 0

for i, r in rows:
    msgs = r["messages"]
    u, a = get(msgs,"user"), get(msgs,"assistant")
    blocks = list(JSON_BLOCK.finditer(a))
    if not blocks: continue
    try: o = json.loads(blocks[-1].group(1))
    except Exception: continue
    analysis = a[:blocks[-1].start()]
    N, cbtxt = code_lines(u)
    if N == 0:
        stats["no_code"] += 1
        continue
    hv = o.get("has_vulnerability")
    if hv is not True:
        continue
    n_vuln += 1

    jnums = {}
    for fld in ("source", "sink", "fix_suggestion"):
        for m in re.finditer(r"line\s*~?\s*(\d+)", str(o.get(fld, ""))):
            jnums.setdefault(fld, []).append(int(m.group(1)))
    bad = {f: [x for x in v if x > N] for f, v in jnums.items()}
    bad = {f: v for f, v in bad.items() if v}
    if bad:
        stats["json_oor"] += 1
        oor_json.append((i, N, bad))
    if not jnums:
        stats["json_no_line"] += 1

    # 分析部分的 第N行
    anums = [int(x) for x in re.findall(r"第\s*(\d+)\s*行", analysis)]
    anums += [int(x) for x in re.findall(r"(?<![\w])L(\d+)(?![\w])", analysis)]
    if not anums:
        zero_ref += 1
    else:
        abad = [x for x in anums if x > N]
        if abad:
            stats["anal_oor"] += 1
            oor_anal.append((i, N, sorted(set(abad))[:6], len(anums)))
    samples.append((i, N, jnums, anums))

P("=" * 78); P("行号真实性全量校验（仅 has_vulnerability=true 的样本）"); P("=" * 78)
P(f"  漏洞样本数: {n_vuln}")
P(f"  统计: {dict(stats)}")
P(f"  JSON 行号越界样本: {len(oor_json)} 条 ({len(oor_json)/max(n_vuln,1)*100:.2f}%)")
P(f"  分析行号越界样本: {len(oor_anal)} 条 ({len(oor_anal)/max(n_vuln,1)*100:.2f}%)")
P(f"  分析中完全未提行号: {zero_ref} 条 ({zero_ref/max(n_vuln,1)*100:.2f}%)")

P("\n" + "-" * 78)
P("JSON 行号越界样例（前 30）")
P("-" * 78)
for i, N, bad in oor_json[:30]:
    P(f"  line {i}: 代码 {N} 行，越界 {bad}")

P("\n" + "-" * 78)
P("分析行号越界样例（前 30）")
P("-" * 78)
for i, N, abad, tot in oor_anal[:30]:
    P(f"  line {i}: 代码 {N} 行，越界行号 {abad}（该样本分析共引用 {tot} 处行号）")

# ---- 分析与 JSON 行号一致性 ----
P("\n" + "-" * 78)
P("分析里提到的行号 vs JSON 结论里的行号 —— 是否说的是同一处")
P("-" * 78)
mismatch = 0
mm_ex = []
for i, N, jnums, anums in samples:
    jall = sorted(set(x for v in jnums.values() for x in v))
    aall = sorted(set(anums))
    if not jall or not aall: continue
    # 若 JSON 的行号集合与分析的行号集合完全无交集 → 严重不一致
    if not (set(jall) & set(aall)):
        mismatch += 1
        if len(mm_ex) < 25:
            mm_ex.append((i, N, jall, aall[:12]))
P(f"  JSON 行号与分行号无交集样本: {mismatch} 条 ({mismatch/max(n_vuln,1)*100:.2f}%)")
for i, N, j, a_ in mm_ex:
    P(f"    line {i} (代码{N}行): JSON行号{j}  分析行号{a_}")

# ---- 代码行数分布 & 行号引用位置分布 ----
P("\n" + "-" * 78)
P("行号引用的相对位置分布（row / 代码总行数）")
P("-" * 78)
relpos = []
for i, N, jnums, anums in samples:
    for v in jnums.values():
        for x in v:
            if N: relpos.append(x/N)
if relpos:
    relpos.sort()
    q = lambda p: relpos[int(p*(len(relpos)-1))]
    P(f"  n={len(relpos)} p5={q(.05):.2f} p25={q(.25):.2f} med={q(.50):.2f} "
      f"p75={q(.75):.2f} p95={q(.95):.2f} max={relpos[-1]:.2f}")
    P(f"  >1.0（越界）占比: {sum(1 for x in relpos if x>1.0)/len(relpos)*100:.2f}%")

w.close()
print("done")
