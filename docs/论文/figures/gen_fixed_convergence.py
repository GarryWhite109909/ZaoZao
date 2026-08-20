# -*- coding: utf-8 -*-
"""fixed 系列收敛阶梯图（2026-08-20）。

数据来源：素材库 8.2 fixed 系列收敛。
重跑：AI 环境 python gen_fixed_convergence.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

versions = ["fixed1", "fixed2", "fixed3\n(带污染)", "fixed4\n(弃用)", "fixed5\n(干净)"]
recall = [0.949, 0.949, 0.982, None, 1.000]
fpr = [0.217, 0.154, 0.167, None, 0.043]

fig, ax = plt.subplots(figsize=(12, 6.5))

# 阶梯线：recall 蓝色，fpr 红色
x = list(range(len(versions)))
ax.step(x, recall, where="mid", color="#1f77b4", linewidth=2.5, marker="o", markersize=8, label="recall")
ax.step(x, fpr, where="mid", color="#d62728", linewidth=2.5, marker="s", markersize=8, label="FPR")

# 标注数据点
for i, (r, f) in enumerate(zip(recall, fpr)):
    if r is not None:
        ax.text(i, r + 0.03, f"{r:.3f}", ha="center", va="bottom", fontsize=9, color="#1f77b4", fontweight="bold")
    if f is not None:
        ax.text(i, f - 0.03, f"{f:.3f}", ha="center", va="top", fontsize=9, color="#d62728", fontweight="bold")

# fixed4 标注
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
fig.savefig("fixed_convergence.png", dpi=170)
print("已生成: fixed_convergence.png")
