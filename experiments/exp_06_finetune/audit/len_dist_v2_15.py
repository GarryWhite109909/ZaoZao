# -*- coding: utf-8 -*-
"""V2_15 数据集 token 长度分布统计（Qwen3 tokenizer，含 chat 模板与纯拼接两种口径）"""
import sys, json
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from tokenizers import Tokenizer
import numpy as np

TK = r"D:\code\毕业设计\Graduation-Project\models\transformers\Qwen3-8B\tokenizer.json"
DATA = r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_alpha06_v2_15.jsonl"

tok = Tokenizer.from_file(TK)

def render(sample):
    # ChatML 手工渲染（与训练口径一致）
    parts = []
    for m in sample["messages"]:
        role = m["role"]
        if role == "system":
            parts.append("<|im_start|>system\n" + m["content"] + "<|im_end|>\n")
        elif role == "user":
            parts.append("<|im_start|>user\n" + m["content"] + "<|im_end|>\n")
        else:
            parts.append("<|im_start|>assistant\n" + m["content"] + "<|im_end|>")
    return "".join(parts)

def render_target_only(sample):
    # 仅 assistant 回复（loss 部分）
    for m in sample["messages"]:
        if m["role"] == "assistant":
            return "<|im_start|>assistant\n" + m["content"] + "<|im_end|>"
    return ""

total_lens, tgt_lens = [], []
max_total, max_tgt = 0, 0
max_idx = -1
with open(DATA, encoding="utf-8") as f:
    for i, line in enumerate(f):
        s = json.loads(line)
        t_full = len(tok.encode(render(s)).ids)
        t_tgt = len(tok.encode(render_target_only(s)).ids)
        total_lens.append(t_full); tgt_lens.append(t_tgt)
        if t_full > max_total:
            max_total, max_idx = t_full, i
        max_tgt = max(max_tgt, t_tgt)

a = np.array(total_lens); b = np.array(tgt_lens)
def q(x, p): return int(np.percentile(x, p))
print(f"样本数: {len(a)}")
print(f"全长(prompt+completion, 含ChatML): min={a.min()} p50={q(a,50)} p90={q(a,90)} p95={q(a,95)} p99={q(a,99)} max={a.max()}")
print(f"均值={a.mean():.0f}  >8192: {(a>8192).sum()}  >16384: {(a>16384).sum()}  >32768: {(a>32768).sum()}  >65536: {(a>65536).sum()}")
print(f"completion(loss部分): min={b.min()} p50={q(b,50)} p95={q(b,95)} max={b.max()}")
print(f"最长样本行号: {max_idx} (0-based), 长度={max_total}")
# top5
idx = np.argsort(a)[-5:][::-1]
print("Top5 最长样本:")
lines = open(DATA, encoding="utf-8").readlines()
for j in idx:
    s = json.loads(lines[j])
    src = s.get("source", s.get("meta", {}).get("source", "?"))
    print(f"  行{j}: {a[j]} tokens, source={src}")
