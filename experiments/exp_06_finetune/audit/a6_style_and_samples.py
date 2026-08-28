# -*- coding: utf-8 -*-
"""文风/啰嗦度量化 + 分层抽样导出（供人工判读）"""
import json, re, sys, random, collections, statistics
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SRC = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_alpha06_v2_12.jsonl")
OUT = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\audit\a6_style_out.txt")
DUMP = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\audit\a6_samples_dump.txt")

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

recs = []
for i, r in rows:
    msgs = r["messages"]
    a = get(msgs, "assistant")
    blocks = list(JSON_BLOCK.finditer(a))
    o = None
    if blocks:
        try: o = json.loads(blocks[-1].group(1))
        except Exception: pass
    recs.append(dict(i=i, u=get(msgs,"user"), a=a, o=o,
                     meta=r.get("meta"), kind=(r.get("meta") or {}).get("kind","none"),
                     analysis=(a[:blocks[-1].start()] if blocks else a)))

w = OUT.open("w", encoding="utf-8")
def P(*a): print(*a, file=w)

# ---------- A. 啰嗦度指标 ----------
P("=" * 78); P("[A] 蒸馏话语啰嗦度量化"); P("=" * 78)
FILLER = {
    "填充词": r"(需要注意的?是|值得一提|总而言之|综上所述|总的来说|换句话说|也就是说|"
              r"显而易见|毫无疑问|众所周知|值得注意的是|由此可见|与此同时|另一方面|"
              r"首先|其次|再次|最后|此外|另外|同时|因此|所以|但是|然而|不过)",
    "自我确认": r"(确认了?|验证了?|检查了?|分析表明|结果表明|可以看出|可以发现|"
                r"我们可以|我们需要|我们应该|让我们|下面|接下来)",
    "冗余限定": r"(实际上|事实上|本质上|基本上|严格来说|一般来说|通常情况下|"
                r"从安全角度|在安全上|安全角度|就安全而言)",
    "套话开场": r"^(作为|这是一个|该代码|这段代码|本代码)",
}
cnt_all = collections.Counter()
per_sample = collections.defaultdict(dict)
for r in recs:
    an = r["analysis"]
    for k, pat in FILLER.items():
        n = len(re.findall(pat, an))
        cnt_all[k] += n
        per_sample[r["i"]][k] = n

lens = [len(re.sub(r"\s+","",r["analysis"])) for r in recs]
P(f"  分析部分长度(去空白): min={min(lens)} p25={sorted(lens)[len(lens)//4]} "
  f"med={statistics.median(lens):.0f} p75={sorted(lens)[3*len(lens)//4]} "
  f"p95={sorted(lens)[int(.95*len(lens))]} max={max(lens)} mean={statistics.mean(lens):.0f}")
P(f"  全库填充词命中总数: {dict(cnt_all)}")
P(f"  平均每样本填充词数: { {k: round(v/len(recs),2) for k,v in cnt_all.items()} }")

# 分析步骤数分布
steps = collections.Counter()
for r in recs:
    steps[len(re.findall(r"^\s*\d+[\.、]\s*", r["analysis"], re.M))] += 1
P(f"\n  分析步骤条数分布: {dict(sorted(steps.items()))}")

# 分析中的代码符号密度（专业性代理指标：是否引用了代码里的真实符号）
P("\n  【专业性代理】分析中是否引用代码实体（标识符/行号）:")
no_symbol = 0
for r in recs:
    an = r["analysis"]
    if not re.search(r"[A-Za-z_][A-Za-z0-9_]{2,}", an):
        no_symbol += 1
P(f"    分析中零代码标识符引用的样本: {no_symbol} ({no_symbol/len(recs)*100:.1f}%)")
no_line_ref = sum(1 for r in recs if not re.search(r"(line\s*\d+|第\s*\d+\s*行)", r["analysis"]))
P(f"    分析中零行号引用的样本: {no_line_ref} ({no_line_ref/len(recs)*100:.1f}%)")

# 极短分析（<80字符）
short = [r["i"] for r in recs if len(re.sub(r"\s+","",r["analysis"])) < 80]
P(f"    分析部分 <80 字符的样本: {len(short)} 条")

# ---------- B. 变体丰富性 ----------
P("\n" + "=" * 78); P("[B] 变体丰富性：代码层面的多样性"); P("=" * 78)
codeblocks = []
for r in recs:
    cb = re.findall(r"```[a-zA-Z0-9_+-]*\s*\n(.*?)```", r["u"], re.S)
    codeblocks.append("".join(cb))
clens = [len(c) for c in codeblocks]
P(f"  代码长度(字符): min={min(clens)} p25={sorted(clens)[len(clens)//4]} "
  f"med={statistics.median(clens)} p75={sorted(clens)[3*len(clens)//4]} "
  f"p95={sorted(clens)[int(.95*len(clens))]} max={max(clens)}")
P(f"  代码行数分布:")
clines = [c.count("\n")+1 for c in codeblocks]
P(f"    <=10 行: {sum(1 for x in clines if x<=10)}")
P(f"    11-30 行: {sum(1 for x in clines if 10<x<=30)}")
P(f"    31-60 行: {sum(1 for x in clines if 30<x<=60)}")
P(f"    61-120 行: {sum(1 for x in clines if 60<x<=120)}")
P(f"    >120 行: {sum(1 for x in clines if x>120)}")

# 代码去重后的近似重复（shingle Jaccard 抽样）
P("\n  代码近似重复（对 1500 条随机样本做 5-gram shingle 抽样比对）:")
random.seed(7)
sample_idx = random.sample(range(len(codeblocks)), 1500)
def shingles(s, k=5):
    s = re.sub(r"\s+", " ", s)
    return set(s[i:i+k] for i in range(0, max(0, len(s)-k+1), 3))
sh = {j: shingles(codeblocks[j]) for j in sample_idx}
near = 0
keys = list(sh.keys())
for a_ in range(len(keys)):
    for b_ in range(a_+1, min(a_+40, len(keys))):
        A, B = sh[keys[a_]], sh[keys[b_]]
        if not A or not B: continue
        j_ = len(A & B)/len(A | B)
        if j_ > 0.6:
            near += 1
P(f"    抽样比对命中 Jaccard>0.6 的近似对: {near} 组")

# ---------- C. 难度梯度 ----------
P("\n" + "=" * 78); P("[C] 难度梯度代理指标"); P("=" * 78)
# 用 "分析步骤数 × 代码行数 × 是否有防御" 粗分
def diff_bucket(r, cl):
    st = len(re.findall(r"^\s*\d+[\.、]\s*", r["analysis"], re.M))
    score = 0
    score += min(cl//20, 5)          # 代码长度
    score += min(st, 5)              # 推理步数
    if re.search(r"(黑名单|正则|过滤|sanitiz|replace|escape)", r["u"]): score += 2  # 有伪装防御
    if re.search(r"(跨文件|多文件|=== file)", r["u"]): score += 3
    o = r["o"] or {}
    if o.get("has_vulnerability") is False: score += 1
    return score
buckets = collections.Counter()
for r, cl in zip(recs, clines):
    buckets[diff_bucket(r, cl)] += 1
P("  难度分桶（0=最简单 … 16=最难）:")
for k in sorted(buckets):
    P(f"    score {k:2d}: {buckets[k]:5d} 条  {'█'*(buckets[k]//80)}")

# ---------- D. 抽样 dump ----------
P("\n" + "=" * 78); P("[D] 分层抽样（导出至 a6_samples_dump.txt）"); P("=" * 78)
random.seed(2026)
groups = collections.defaultdict(list)
for r in recs:
    groups[r["kind"]].append(r)
P(f"  kind 分组: { {k: len(v) for k,v in sorted(groups.items(), key=lambda x:-len(x[1]))} }")

d = DUMP.open("w", encoding="utf-8")
def D(*a): print(*a, file=d)

picked = []
for kind, lst in sorted(groups.items(), key=lambda x: -len(x[1])):
    random.shuffle(lst)
    n_pick = 3 if kind != "none" else 14
    for r in lst[:n_pick]:
        picked.append(r)
D(f"共抽取 {len(picked)} 条样本\n")
for r in sorted(picked, key=lambda x: x["i"]):
    i = r["i"]
    obj = R[i]
    D("=" * 90)
    D(f"### line {i}  kind={r['kind']}  meta={obj.get('meta')}")
    D("-" * 90)
    D(f"[USER]\n{r['u']}")
    D("-" * 90)
    D(f"[ASSISTANT]\n{r['a']}")
    D("")

w.close(); d.close()
print("done")
