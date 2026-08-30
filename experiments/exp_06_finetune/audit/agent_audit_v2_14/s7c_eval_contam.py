# -*- coding: utf-8 -*-
"""S7c 评测集污染：app/backend/static/samples/**（演示/评测样例）与训练集代码指纹比对。"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acommon import BASE, load_rows, code_blocks, hash01

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
rows, _ = load_rows()

def sig(c):
    lines = [l.rstrip() for l in c.strip().splitlines() if l.strip()]
    return hash01("|".join(lines)) if lines else None

train_exact = set()
train_sig = set()
for r in rows:
    for _, c in code_blocks(r["rec"]["messages"][1]["content"]):
        train_exact.add(hash01(c.strip()))
        s = sig(c)
        if s:
            train_sig.add(s)
        # 去掉行首空白后比较（防缩进差异）
        train_exact.add(hash01("\n".join(l.strip() for l in c.strip().splitlines())))

sample_dir = BASE.parents[1] / "app/backend/static/samples"
files = sorted(sample_dir.rglob("*.py")) + sorted(sample_dir.rglob("*.js")) + \
        sorted(sample_dir.rglob("*.java")) + sorted(sample_dir.rglob("*.go")) + \
        sorted(sample_dir.rglob("*.ts"))
hit_e = hit_s = 0
for p in files:
    try:
        c = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        continue
    e = hash01(c.strip()) in train_exact or hash01("\n".join(l.strip() for l in c.strip().splitlines())) in train_exact
    s = sig(c) in train_sig
    if e or s:
        hit_e += 1 if e else 0
        hit_s += 1 if s else 0
        print(f"  命中: {p.name} exact={e} sig={s}")
print(f"评测/演示样本 {len(files)} 个，精确命中 {hit_e}，签名命中 {hit_s}")
