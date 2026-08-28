# -*- coding: utf-8 -*-
"""用 Qwen3-8B 真实分词器核算长度分布 + 在 max_len 下的截断影响"""
import json, re, sys, collections, statistics
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from transformers import AutoTokenizer

TOK = r"D:\code\毕业设计\Graduation-Project\models\transformers\Qwen3-8B"
SRC = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_alpha06_v2_12.jsonl")
OUT = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\audit\a4_tokenlen_out.txt")

tok = AutoTokenizer.from_pretrained(TOK, trust_remote_code=True)
print("tokenizer loaded, vocab:", len(tok))

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

w = OUT.open("w", encoding="utf-8")
def P(*a): print(*a, file=w)

# 用 chat template 计算完整 prompt 长度（含 special tokens）
lens = []
sys_lens, user_lens, asst_lens = [], [], []
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)

# 抽样：全量 8984 条 tokenize 较慢，先全量跑（8B 分词器速度还行）
import time
t0 = time.time()
for i, r in rows:
    msgs = r["messages"]
    s, u, a = get(msgs,"system"), get(msgs,"user"), get(msgs,"assistant")
    try:
        enc = tok.apply_chat_template(msgs, tokenize=True, add_generation_prompt=False)
        full = enc["input_ids"] if isinstance(enc, dict) else enc
    except Exception:
        full = tok(s + u + a)["input_ids"]
    lens.append(len(full))
    sys_lens.append(len(tok(s)["input_ids"]))
    user_lens.append(len(tok(u)["input_ids"]))
    asst_lens.append(len(tok(a)["input_ids"]))
    if i % 2000 == 0:
        print(f"  ...{i} ({time.time()-t0:.0f}s)")

P("=" * 78)
P("Qwen3-8B 真实分词长度核算（apply_chat_template 全量）")
P("=" * 78)

def dist(name, arr):
    a2 = sorted(arr); n = len(a2)
    q = lambda p: a2[int(p*(n-1))]
    P(f"  {name}: n={n} min={a2[0]} p5={q(.05)} p10={q(.10)} p25={q(.25)} med={q(.50)} "
      f"p75={q(.75)} p90={q(.90)} p95={q(.95)} p99={q(.99)} max={a2[-1]} mean={statistics.mean(arr):.0f}")

dist("system token", sys_lens)
dist("user token", user_lens)
dist("assistant token", asst_lens)
dist("**全样本 token**", lens)

P("\n" + "-" * 78)
P("截断影响（不同 max_seq_length 下被完整保留的样本比例）")
P("-" * 78)
n = len(lens)
for ml in [1024, 1536, 2048, 2560, 3072, 4096, 5120, 6144, 8192]:
    keep = sum(1 for x in lens if x <= ml)
    P(f"  max_len={ml:5d}: 完整保留 {keep:5d}/{n} = {keep/n*100:5.1f}%   被截断 {n-keep:5d} = {(n-keep)/n*100:5.1f}%")

P("\n" + "-" * 78)
P("【致命项】max_len=2048 下，JSON 结论块是否被切掉")
P("-" * 78)
# 计算每条样本：assistant 中最后一个 ```json 块起点距末尾的 token 数
# 若 (total_len - json_start_token) > max_len 则 JSON 被截断
def chat_len(s, u, a):
    msgs = [{"role":"system","content":s},{"role":"user","content":u},{"role":"assistant","content":a}]
    try:
        enc = tok.apply_chat_template(msgs, tokenize=True, add_generation_prompt=False)
        ids = enc["input_ids"] if isinstance(enc, dict) else enc
    except Exception:
        ids = tok(s+u+a)["input_ids"]
    return len(ids)

trunc_json = collections.Counter()
trunc_lines = []
json_start = {}
for (i, r), L in zip(rows, lens):
    a = get(r["messages"], "assistant")
    blocks = list(JSON_BLOCK.finditer(a))
    if not blocks:
        trunc_json["no_json"] += 1
        continue
    last = blocks[-1]
    prefix = a[:last.start()]
    start_pos = chat_len(get(r["messages"],"system"), get(r["messages"],"user"), prefix)
    json_start[i] = start_pos
    if start_pos > 2048:
        trunc_json["json_截断@2048"] += 1
        trunc_lines.append((i, L, start_pos))
    else:
        trunc_json["json_完整@2048"] += 1
P(f"  {dict(trunc_json)}")
P(f"  JSON 被截断的样本占比: {trunc_json['json_截断@2048']/n*100:.1f}%")
P(f"  样例（行号, 总长, json起点token）: {trunc_lines[:15]}")

P("\n" + "-" * 78)
P("各 max_len 下 JSON 结论完整率")
P("-" * 78)
for ml in [2048, 2560, 3072, 4096, 6144, 8192]:
    ok = sum(1 for v in json_start.values() if v <= ml)
    P(f"  max_len={ml}: JSON 完整 {ok}/{n} = {ok/n*100:.1f}%")

P("\n" + "-" * 78)
P("JSON 起点 token 位置分布")
P("-" * 78)
dist("json_start token", list(json_start.values()))

w.close()
print("done")
