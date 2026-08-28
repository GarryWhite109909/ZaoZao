# -*- coding: utf-8 -*-
"""长度核算（快速版）：极值精确分词 + 中段线性拟合
策略：
  1) 全量只算字符长度（O(1)/条）
  2) 对「按字符长度分层抽样」的样本 + 「最长/最短各 N 条」做精确 Qwen3 分词
  3) 用样本拟合  tokens = a*user_chars + b*asst_chars + c
  4) 用拟合式外推全量；极值段用精确值覆盖
"""
import json, re, sys, random, statistics, collections
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from transformers import AutoTokenizer

TOK = r"D:\code\毕业设计\Graduation-Project\models\transformers\Qwen3-8B"
SRC = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_alpha06_v2_12.jsonl")
OUT = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\audit\a4b_tokenlen_fast_out.txt")

tok = AutoTokenizer.from_pretrained(TOK, trust_remote_code=True)
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)

rows = []
with SRC.open("r", encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if line:
            rows.append((i, json.loads(line)))

def get(msgs, role):
    for m in msgs:
        if m.get("role") == role:
            return m.get("content", "")
    return ""

# ---- 1. 全量字符长度（中文 / 非中文分开统计：两者 token 密度差 2-3 倍）----
ZH = re.compile(r"[\u4e00-\u9fff]")
def zh_n(s): return len(ZH.findall(s))
def as_n(s): return len(s) - zh_n(s)

meta = []
for i, r in rows:
    msgs = r["messages"]
    s, u, a = get(msgs,"system"), get(msgs,"user"), get(msgs,"assistant")
    blocks = list(JSON_BLOCK.finditer(a))
    prefix = a[:blocks[-1].start()] if blocks else a
    meta.append(dict(i=i, sc=len(s), uc=len(u), ac=len(a), pc=len(prefix),
                     has_json=bool(blocks),
                     uz=zh_n(u), ua=as_n(u), az=zh_n(a), aa=as_n(a),
                     pz=zh_n(prefix), pa=as_n(prefix)))

n = len(meta)
order_by_total = sorted(range(n), key=lambda k: meta[k]["uc"] + meta[k]["ac"])

# ---- 2. 选精确分词样本 ----
random.seed(42)
N_EXTREME = 120          # 最长/最短各 120 条
N_STRAT = 900            # 分层抽样
extreme = set(order_by_total[:N_EXTREME]) | set(order_by_total[-N_EXTREME:])
step = max(1, n // N_STRAT)
strat = set(order_by_total[::step][:N_STRAT])
exact_idx = sorted(extreme | strat)
print(f"精确分词样本数: {len(exact_idx)} / {n}")

def chat_len_ids(s, u, a):
    msgs = [{"role":"system","content":s},{"role":"user","content":u},{"role":"assistant","content":a}]
    enc = tok.apply_chat_template(msgs, tokenize=True, add_generation_prompt=False)
    # 注意：BatchEncoding 不是 dict 子类，isinstance(x, dict) 为 False，必须取 ["input_ids"]
    ids = enc["input_ids"] if hasattr(enc, "__getitem__") and "input_ids" in enc.keys() else enc
    return len(ids)

X, Y, XP, YP = [], [], [], []
exact = {}
import time
t0 = time.time()
for cnt, k in enumerate(exact_idx, 1):
    i = meta[k]["i"]
    r = dict(rows)[i]
    msgs = r["messages"]
    s, u, a = get(msgs,"system"), get(msgs,"user"), get(msgs,"assistant")
    blocks = list(JSON_BLOCK.finditer(a))
    prefix = a[:blocks[-1].start()] if blocks else a
    T = chat_len_ids(s, u, a)
    assert T > 100, f"chat_len 异常: line {i} -> {T}"
    TP = chat_len_ids(s, u, prefix)
    exact[k] = (T, TP)
    X.append((meta[k]["uz"], meta[k]["ua"], meta[k]["az"], meta[k]["aa"]));   Y.append(T)
    XP.append((meta[k]["uz"], meta[k]["ua"], meta[k]["pz"], meta[k]["pa"]));  YP.append(TP)
    if cnt % 200 == 0:
        print(f"  ...{cnt}/{len(exact_idx)} ({time.time()-t0:.0f}s)")
print(f"精确分词耗时 {time.time()-t0:.0f}s")

# ---- 3. 拟合  T = a*uc + b*ac + c  （最小二乘，闭式解）----
def ols(Xs, Ys):
    """通用最小二乘：Xs 为特征向量列表，Ys 为目标；返回系数 [w1..wk, bias]"""
    m = len(Xs); k = len(Xs[0])
    A = [[sum(x[i]*x[j] for x in Xs) for j in range(k)] + [sum(x[i] for x in Xs)] for i in range(k)]
    A.append([sum(x[j] for x in Xs) for j in range(k)] + [m])
    b = [sum(x[i]*y for x, y in zip(Xs, Ys)) for i in range(k)] + [sum(Ys)]
    sz = k + 1
    for c in range(sz):                      # 高斯消元（部分主元）
        p = max(range(c, sz), key=lambda r_: abs(A[r_][c]))
        A[c], A[p] = A[p], A[c]; b[c], b[p] = b[p], b[c]
        for r_ in range(c+1, sz):
            f = A[r_][c]/A[c][c]
            for cc in range(c, sz): A[r_][cc] -= f*A[c][cc]
            b[r_] -= f*b[c]
    x = [0]*sz
    for r_ in range(sz-1, -1, -1):
        x[r_] = (b[r_] - sum(A[r_][cc]*x[cc] for cc in range(r_+1, sz)))/A[r_][r_]
    return x

def apply_w(w, feats):
    return sum(wi*fi for wi, fi in zip(w[:-1], feats)) + w[-1]

wT = ols(X, Y)
wP = ols(XP, YP)
resid = [y - apply_w(wT, x) for x, y in zip(X, Y)]
rel = [abs(r_)/max(y, 1) for r_, y in zip(resid, Y)]
print(f"拟合 total = {wT[0]:.4f}*u_zh + {wT[1]:.4f}*u_ascii + {wT[2]:.4f}*a_zh + {wT[3]:.4f}*a_ascii + {wT[4]:.2f}")
print(f"拟合残差(总长): mean={statistics.mean(resid):.1f} sd={statistics.pstdev(resid):.1f} "
      f"max|e|={max(abs(r_) for r_ in resid):.0f}")
print(f"相对误差: mean={statistics.mean(rel)*100:.2f}% "
      f"p95={sorted(rel)[int(.95*len(rel))]*100:.2f}% max={max(rel)*100:.1f}%")

# ---- 4. 全量估算（极值段用精确值覆盖）----
tot_tok = [0.0]*n
js_tok = [0.0]*n
for k in range(n):
    if k in exact:
        tot_tok[k], js_tok[k] = exact[k]
    else:
        m_ = meta[k]
        tot_tok[k] = apply_w(wT, (m_["uz"], m_["ua"], m_["az"], m_["aa"]))
        js_tok[k] = apply_w(wP, (m_["uz"], m_["ua"], m_["pz"], m_["pa"]))

w = OUT.open("w", encoding="utf-8")
def P(*a): print(*a, file=w)

P("=" * 78)
P("Qwen3-8B 长度核算（快速版：极值精确 + 中段拟合）")
P("=" * 78)
P(f"总样本 {n}；精确分词 {len(exact_idx)} 条")
P(f"拟合式 total = {wT[0]:.4f}*user中文 + {wT[1]:.4f}*user非中 + {wT[2]:.4f}*asst中文 "
  f"+ {wT[3]:.4f}*asst非中 + {wT[4]:.2f}")
P(f"拟合平均相对误差 {statistics.mean(rel)*100:.2f}%，残差 sd={statistics.pstdev(resid):.1f} token")
P(f"（极值 {N_EXTREME*2} 条为精确值，故长尾结论不受拟合误差影响）")

def dist(name, arr):
    a2 = sorted(arr); m_ = len(a2)
    q = lambda p: a2[int(p*(m_-1))]
    P(f"  {name}: min={a2[0]:.0f} p5={q(.05):.0f} p25={q(.25):.0f} med={q(.50):.0f} "
      f"p75={q(.75):.0f} p90={q(.90):.0f} p95={q(.95):.0f} p99={q(.99):.0f} max={a2[-1]:.0f} mean={statistics.mean(arr):.0f}")

P("\n[1] 全样本 token 长度分布")
dist("total tokens", tot_tok)

P("\n[2] 截断影响（云端脚本 max_seq_length=12288；本地旧脚本默认 2048）")
for ml in [2048, 3072, 4096, 6144, 8192, 10240, 12288, 16384]:
    over = sum(1 for t in tot_tok if t > ml)
    P(f"  max_len={ml:6d}: 超长 {over:5d} 条 = {over/n*100:5.2f}%")

P("\n[3] 【关键】JSON 结论块起点位置 —— 决定监督信号是否被截断")
dist("json_start tokens", js_tok)
P("")
for ml in [2048, 3072, 4096, 6144, 8192, 10240, 12288]:
    cut = sum(1 for t in js_tok if t > ml)
    P(f"  max_len={ml:6d}: JSON 被截断 {cut:5d} 条 = {cut/n*100:5.2f}%  （完整率 {100-cut/n*100:.2f}%）")

P("\n[4] 超长样本明细（精确分词，total > 12288）")
overs = sorted([(tot_tok[k], js_tok[k], meta[k]["i"], meta[k]["uc"], meta[k]["ac"])
                for k in range(n)], reverse=True)
shown = 0
for T, J, i, uc, ac in overs:
    if T <= 12288: break
    P(f"  line {i}: total={T:.0f} json_start={J:.0f} user_chars={uc} asst_chars={ac}")
    shown += 1
P(f"  （共 {shown} 条超过 12288）")

P("\n[5] user / assistant 分段 token 分布（精确样本上统计，样本数 %d）" % len(exact_idx))
uc_tok, ac_tok = [], []
for k in exact_idx:
    i = meta[k]["i"]; r = dict(rows)[i]
    uc_tok.append(len(tok(get(r["messages"],"user"))["input_ids"]))
    ac_tok.append(len(tok(get(r["messages"],"assistant"))["input_ids"]))
dist("user tokens", uc_tok)
dist("assistant tokens", ac_tok)
P(f"  system prompt token = 908（8960 条共用）；另一套 system = "
  f"{len(tok(get(dict(rows)[8069]['messages'],'system'))['input_ids'])}")

w.close()
print("done ->", OUT)
