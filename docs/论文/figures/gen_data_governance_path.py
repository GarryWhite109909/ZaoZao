# -*- coding: utf-8 -*-
"""数据治理路径图：fixed3 污染 → 隔离修复 → fixed5 干净（2026-08-20）。

重跑：AI 环境 python gen_data_governance_path.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, ax = plt.subplots(figsize=(14, 5))
ax.set_xlim(0, 14)
ax.set_ylim(0, 5)
ax.axis("off")

stages = [
    ("fixed3\n带污染", "recall 0.982\nFPR 0.167", "#d62728", 1.5),
    ("定位污染源", "CWE 口径泄漏\n抑制池跨跑\nin-sample 校准", "#ff7f0e", 5.0),
    ("隔离修复", "--no-signal-feedback\n独立校准集\nJaccard 审计", "#1f77b4", 8.5),
    ("fixed5\n干净", "recall 1.000\nFPR 0.043", "#2ca02c", 12.0),
]

for title, sub, color, x in stages:
    ax.add_patch(FancyBboxPatch((x - 1.1, 1.5), 2.2, 1.6, boxstyle="round,pad=0.05,rounding_size=0.12",
                                facecolor=color, edgecolor="white", linewidth=2, alpha=0.92))
    ax.text(x, 2.7, title, ha="center", va="center", fontsize=11,
            fontweight="bold", color="white")
    ax.text(x, 2.05, sub, ha="center", va="center", fontsize=8.5,
            color="white", linespacing=1.2)

# 箭头
for x in [2.6, 6.1, 9.6]:
    ax.add_patch(FancyArrowPatch((x, 2.3), (x + 1.3, 2.3),
                                 arrowstyle="->,head_width=0.25,head_length=0.15",
                                 color="#555555", linewidth=2))

ax.text(7, 0.6, "数据治理不是一次性清洗，而是「定位污染源 → 隔离机制 → 干净重评」的闭环",
        ha="center", va="center", fontsize=10, color="#555555")

ax.set_title("数据治理路径：从 fixed3 污染到 fixed5 干净评估", fontsize=15, fontweight="bold", pad=20)

fig.tight_layout()
fig.savefig("data_governance_path.png", dpi=170)
print("已生成: data_governance_path.png")
