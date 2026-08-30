# -*- coding: utf-8 -*-
"""从 final_train_chatml_alpha06_v2_14.jsonl 分 5 部分（按行位置均分）抽取 30 条人工抽查样本。
每部分 6 条，独立输出 + 汇总输出，附行号回溯清单。"""
import json
import random
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "data" / "final_train_chatml_alpha06_v2_14.jsonl"
OUT_DIR = Path(__file__).resolve().parents[1] / "audit" / "sample_v2_14_review30"
N_PARTS = 5
PER_PART = 6
SEED = 20260830

OUT_DIR.mkdir(parents=True, exist_ok=True)

with SRC.open(encoding="utf-8") as f:
    lines = f.readlines()

total = len(lines)
part_bounds = []
step = total // N_PARTS
for i in range(N_PARTS):
    lo = i * step
    hi = (i + 1) * step if i < N_PARTS - 1 else total
    part_bounds.append((lo, hi))

rng = random.Random(SEED)
picked = []  # (lineno_1based, record_json_str)

for i, (lo, hi) in enumerate(part_bounds, 1):
    idx_pool = list(range(lo, hi))
    chosen = sorted(rng.sample(idx_pool, PER_PART))
    part_out = OUT_DIR / f"sample_v2_14_part{i}_lines{lo + 1}-{hi}.jsonl"
    with part_out.open("w", encoding="utf-8") as fo:
        for idx in chosen:
            fo.write(lines[idx])
            picked.append((idx + 1, lines[idx]))

merged = OUT_DIR / "sample_v2_14_review30_all.jsonl"
with merged.open("w", encoding="utf-8") as fo:
    for _, s in picked:
        fo.write(s)

manifest = OUT_DIR / "MANIFEST.md"
with manifest.open("w", encoding="utf-8") as fo:
    fo.write(f"# v2_14 人工抽查样本（30 条，分 {N_PARTS} 部分 × 每部分 {PER_PART} 条）\n\n")
    fo.write(f"- 源文件: {SRC.name}（共 {total} 条）\n- 随机种子: {SEED}（可复现）\n\n")
    for i, (lo, hi) in enumerate(part_bounds, 1):
        rows = [(ln, s) for ln, s in picked if lo + 1 <= ln <= hi]
        fo.write(f"## Part {i}（源行 {lo + 1}-{hi}）\n\n")
        fo.write("| 源行号 | 预览（user 内容前 60 字符） |\n|---|---|\n")
        for ln, s in rows:
            rec = json.loads(s)
            user = next((m["content"] for m in rec["messages"] if m["role"] == "user"), "")
            preview = user.replace("\n", " ")[:60]
            fo.write(f"| {ln} | {preview} |\n")
        fo.write("\n")

print(f"total={total}, parts={[(lo + 1, hi) for lo, hi in part_bounds]}")
print("输出目录:", OUT_DIR)
for ln, _ in picked:
    print(ln)
