# -*- coding: utf-8 -*-
"""解析 alpha0.5.txt：按 epoch 去重提取 eval_loss 与 train loss 趋势"""
import json, re, sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LOG = Path(r"D:\code\yunduan\alpha0.5.txt")

evals = []      # (epoch, eval_loss)
train = []      # (epoch, loss)
phase = 1
with LOG.open(encoding="utf-8") as f:
    for ln in f:
        if "[阶段2/回收dev]" in ln:
            phase = 2
        m = re.search(r"\{.*\}", ln)
        if not m:
            continue
        try:
            d = json.loads(m.group(0))
        except Exception:
            continue
        ep = float(d.get("epoch", -1))
        if "eval_loss" in d:
            evals.append((phase, ep, float(d["eval_loss"])))
        elif "loss" in d:
            train.append((phase, ep, float(d["loss"])))

# 按 (phase, epoch) 去重，保留最后一次出现
def dedup(items):
    seen = {}
    for it in items:
        seen[(it[0], round(it[1], 4))] = it
    return [seen[k] for k in sorted(seen)]

evals_d = dedup(evals)
print("=== 阶段1 eval_loss（按 epoch 去重后的真实序列） ===")
p1_evals = [e for e in evals_d if e[0] == 1]
for ph, ep, el in p1_evals:
    print(f"  epoch {ep:6.3f}: eval_loss {el:.4f}")
print(f"\n阶段1 eval 次数: {len(p1_evals)}")
print(f"起点 {p1_evals[0][2]:.4f} → 终点 {p1_evals[-1][2]:.4f}")
print(f"最低点: {min(p1_evals, key=lambda x: x[2])}")

# 回升检查：是否单调下降
vals = [e[2] for e in p1_evals]
ups = [(p1_evals[i][1], vals[i], vals[i+1]) for i in range(len(vals)-1) if vals[i+1] > vals[i] + 1e-4]
print(f"回升次数(相邻eval差>0.0001): {len(ups)}", ups[:5] if ups else "")

print("\n=== 阶段2（回收dev）轨迹 ===")
p2_train = [t for t in train if t[0] == 2]
if p2_train:
    print(f"阶段2 已记录 train 步数: {len(p2_train)}")
    for ph, ep, loss in p2_train[:8]:
        print(f"  epoch {ep:6.3f}: loss {loss:.4f}")
    print(f"  最后一条: epoch {p2_train[-1][1]:.3f} loss {p2_train[-1][2]:.4f}")
else:
    print("  无阶段2 train 记录")

# 阶段1 train loss 尾段（真实终值）
print("\n=== 阶段1 train loss 尾段 ===")
p1_train = [t for t in train if t[0] == 1]
tail = [t for t in p1_train if t[1] > 1.9]
for ph, ep, loss in tail:
    print(f"  epoch {ep:.3f}: loss {loss:.4f}")
