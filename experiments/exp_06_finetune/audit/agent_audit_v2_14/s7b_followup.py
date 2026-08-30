# -*- coding: utf-8 -*-
"""S7 后续：4 组同代码指纹组的结论一致性 + 评测样本集（exp_01~07 与两阶段评测）污染检查。"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acommon import BASE, OUT, load_rows, code_blocks, last_json, hash01

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
rows, _ = load_rows()

# ---- 4 组同代码指纹 ----
print("=== 精确同代码组的结论 ===")
bycode = defaultdict(list)
for r in rows:
    blocks = code_blocks(r["rec"]["messages"][1]["content"])
    code = "\n\n".join(c for _, c in blocks)
    o, _, _ = last_json(r["rec"]["messages"][2]["content"])
    hv = o.get("has_vulnerability") if isinstance(o, dict) else None
    vt = str(o.get("vulnerability_type", ""))[:44] if isinstance(o, dict) else ""
    bycode[hash01(code)].append((r["id"], hv, vt))
for h, grp in sorted(bycode.items(), key=lambda x: -len(x[1])):
    if len(grp) > 1:
        conflict = len({(g[1], g[2]) for g in grp}) > 1
        print(("  [结论冲突] " if conflict else "  [结论一致] "), grp)

# ---- 评测集污染 ----
print()
print("=== 评测样本集污染检查 ===")
train_user = set()
train_code = set()
for r in rows:
    u = r["rec"]["messages"][1]["content"]
    train_user.add(hash01(u))
    blocks = code_blocks(r["rec"]["messages"][1]["content"])
    for _, c in blocks:
        train_code.add(hash01(c))
    train_code.add(hash01("\n\n".join(c for _, c in blocks)))

eval_files = []
for p in (BASE.parent / "experiments").rglob("*.json"):
    n = p.name.lower()
    if any(k in n for k in ("sample", "hard_samples", "triage", "eval", "testset", "signal_registry")) and "result" not in n and "report" not in n and "candidates" not in n:
        eval_files.append(p)
for p in (BASE.parent / "data").rglob("*.json*"):
    eval_files.append(p)
for p in (BASE.parent / "experiments" / "exp_07_two_stage_eval").rglob("*.json"):
    if "result" not in p.name.lower():
        eval_files.append(p)
eval_files = sorted(set(eval_files))
print(f"候选评测文件 {len(eval_files)} 个")

for p in eval_files:
    try:
        txt = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        continue
    # 抽取所有 fence 代码
    codes = re.findall(r"```[\w+#.\-]*\r?\n(.*?)(?:```|\Z)", txt, re.S)
    if not codes:
        continue
    hit_user = sum(1 for c in codes if hash01(c.strip()) in train_user)
    hit_code = sum(1 for c in codes if hash01(c.strip()) in train_code or hash01("\n\n".join([c.strip()])) in train_code)
    # 代码行模糊指纹：前3行+行数
    def sig(c):
        lines = [l.strip() for l in c.strip().splitlines() if l.strip()]
        return hash01("|".join(lines[:3]) + f"#{len(lines)}") if lines else None
    sigs_train = set()
    for r in rows:
        blocks = code_blocks(r["rec"]["messages"][1]["content"])
        for _, c in blocks:
            sigs_train.add(sig(c))
    hit_sig = sum(1 for c in codes if sig(c) in sigs_train)
    if hit_code or hit_user or hit_sig:
        print(f"  {p.relative_to(BASE.parent)}: fence代码 {len(codes)} 段，user指纹命中 {hit_user}，代码指纹命中 {hit_code}，前3行签名命中 {hit_sig}")
