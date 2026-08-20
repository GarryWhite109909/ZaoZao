# -*- coding: utf-8 -*-
"""信任分级回填门控图（2026-08-20）。

重跑：AI 环境 python gen_trust_graded_feedback.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, ax = plt.subplots(figsize=(14, 6))
ax.set_xlim(0, 14)
ax.set_ylim(0, 6)
ax.axis("off")

# 输入
ax.text(1.0, 4.8, "LLM 裁决输出", ha="center", va="center", fontsize=11,
        fontweight="bold", color="white",
        bbox=dict(boxstyle="round,pad=0.35", facecolor="#1f77b4", edgecolor="white", linewidth=2))

# A-E 分级
grades = [
    ("A", "判定正确\n编号正确", "#2ca02c", 2.4, 4.8),
    ("B", "判定正确\n编号错", "#7fbf7f", 4.4, 4.8),
    ("C", "低置信", "#ffbb78", 2.4, 3.0),
    ("D", "误报", "#ff7f0e", 4.4, 3.0),
    ("E", "无法判断", "#d62728", 3.4, 1.2),
]
for g, desc, color, x, y in grades:
    ax.add_patch(FancyBboxPatch((x - 0.7, y - 0.5), 1.4, 1.0, boxstyle="round,pad=0.05,rounding_size=0.08",
                                facecolor=color, edgecolor="white", linewidth=1.5, alpha=0.92))
    ax.text(x, y + 0.2, g, ha="center", va="center", fontsize=12,
            fontweight="bold", color="white")
    ax.text(x, y - 0.15, desc, ha="center", va="center", fontsize=8, color="white")

# 门控
ax.text(7.5, 4.8, "四重门控", ha="center", va="center", fontsize=11,
        fontweight="bold", color="#333333")
gates = [
    "全票门槛 votes==N",
    "跨样本聚合 ≥2 文件",
    "双向可撤销",
    "验证集门控",
]
for i, text in enumerate(gates):
    y = 4.2 - i * 0.65
    ax.add_patch(FancyBboxPatch((6.3, y), 2.4, 0.5, boxstyle="round,pad=0.03,rounding_size=0.06",
                                facecolor="#9467bd", edgecolor="white", linewidth=1.5, alpha=0.9))
    ax.text(7.5, y + 0.25, text, ha="center", va="center", fontsize=8.5,
            fontweight="bold", color="white")

# 输出
ax.text(11.5, 4.8, "回填工具记忆", ha="center", va="center", fontsize=11,
        fontweight="bold", color="white",
        bbox=dict(boxstyle="round,pad=0.35", facecolor="#2ca02c", edgecolor="white", linewidth=2))
ax.text(11.5, 2.5, "进抑制池", ha="center", va="center", fontsize=11,
        fontweight="bold", color="white",
        bbox=dict(boxstyle="round,pad=0.35", facecolor="#d62728", edgecolor="white", linewidth=2))
ax.text(11.5, 1.0, "Review\n人工复核", ha="center", va="center", fontsize=11,
        fontweight="bold", color="white",
        bbox=dict(boxstyle="round,pad=0.35", facecolor="#ff7f0e", edgecolor="white", linewidth=2))

# 箭头
ax.add_patch(FancyArrowPatch((1.8, 4.8), (3.2, 4.8),
                             arrowstyle="->,head_width=0.25,head_length=0.15",
                             color="#555555", linewidth=1.8))
ax.add_patch(FancyArrowPatch((5.1, 4.8), (6.3, 4.8),
                             arrowstyle="->,head_width=0.25,head_length=0.15",
                             color="#555555", linewidth=1.8))
ax.add_patch(FancyArrowPatch((8.7, 4.8), (10.3, 4.8),
                             arrowstyle="->,head_width=0.25,head_length=0.15",
                             color="#555555", linewidth=1.8))
ax.add_patch(FancyArrowPatch((5.1, 3.0), (10.3, 2.5),
                             arrowstyle="->,head_width=0.25,head_length=0.15",
                             color="#555555", linewidth=1.8))
ax.add_patch(FancyArrowPatch((5.1, 1.2), (10.3, 1.0),
                             arrowstyle="->,head_width=0.25,head_length=0.15",
                             color="#555555", linewidth=1.8))

ax.text(7, 0.3, "核心原则：模型输出必须分层设门槛；A/B 才回填，D 进抑制池，未达门槛保留 review——宁可不改，不教坏工具",
        ha="center", va="center", fontsize=9.5, color="#555555")

ax.set_title("信任分级回填：四层门控防止模型「教坏」工具", fontsize=15, fontweight="bold", pad=20)

fig.tight_layout()
fig.savefig("trust_graded_feedback.png", dpi=170)
print("已生成: trust_graded_feedback.png")
