# -*- coding: utf-8 -*-
"""fixed 系列收敛阶梯图（2026-08-20）。

数据来源：素材库 8.2 fixed 系列收敛。
重跑：AI 环境 python gen_fixed_convergence.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

versions = ["fixed1", "fixed2\n(中断)", "fixed3\n(带污染)", "fixed4\n(弃用)", "fixed5\n(干净)"]
recall = [0.949, None, 0.982, None, 1.000]
fpr = [0.217, None, 0.167, None, 0.043]

fig, ax = plt.subplots(figsize=(12, 6.5))

# 阶梯线：recall 蓝色，fpr 红色
# 注意：fixed2/fixed4 无数据，须断开连线（不能让 step 把 None 点贯穿，误导成有数据）。
x = list(range(len(versions)))
# 有数据的索引
recall_pts = [(i, v) for i, v in enumerate(recall) if v is not None]
fpr_pts = [(i, v) for i, v in enumerate(fpr) if v is not None]

# 分段画实线：仅连相邻都有数据的点
def draw_segmented(pts, color, marker, label):
    for (x1, y1), (x2, y2) in zip(pts[:-1], pts[1:]):
        if x2 - x1 > 1:
            # 中间隔着缺失点，不连线（断开）
            continue
        ax.plot([x1, x2], [y1, y2], color=color, linewidth=2.5, zorder=2)
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    ax.plot(xs, ys, linestyle="", color=color, marker=marker, markersize=8, zorder=3, label=label)

draw_segmented(recall_pts, "#1f77b4", "o", "recall")
draw_segmented(fpr_pts, "#d62728", "s", "FPR")

# 标注数据点
for i, (r, f) in enumerate(zip(recall, fpr)):
    if r is not None:
        ax.text(i, r + 0.03, f"{r:.3f}", ha="center", va="bottom", fontsize=9, color="#1f77b4", fontweight="bold", zorder=4)
    if f is not None:
        ax.text(i, f - 0.03, f"{f:.3f}", ha="center", va="top", fontsize=9, color="#d62728", fontweight="bold", zorder=4)

# fixed2 / fixed4 标注
ax.text(1, 0.55, "fixed2 中断\n（21/87，无有效指标）", ha="center", va="center", fontsize=9,
        color="#888888", fontweight="bold",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="#f5f5f5", edgecolor="#888888"))
ax.text(3, 0.55, "fixed4 弃用\n（抑制池跨跑污染）", ha="center", va="center", fontsize=9,
        color="#d62728", fontweight="bold",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="#ffeeee", edgecolor="#d62728"))

ax.set_xticks(x)
ax.set_xticklabels(versions, fontsize=10)
ax.set_ylabel("指标值")
ax.set_ylim(0, 1.15)
ax.set_title("fixed 系列收敛：从带污染到干净评估", fontsize=15, fontweight="bold")
ax.legend(loc="upper right")
ax.grid(axis="y", alpha=0.25)

# 底部说明
ax.text(2, -0.15, "污染阶段（fixed3）", ha="center", va="top", fontsize=9, color="#d62728")
ax.text(4, -0.15, "干净阶段（fixed5）\nrecall 1.000 / FPR 0.043", ha="center", va="top", fontsize=9,
        color="#2ca02c", fontweight="bold")

fig.tight_layout()
OUT = Path(__file__).resolve().parent / "fixed_convergence.png"
fig.savefig(OUT, dpi=170)
print(f"已生成: {OUT}")
