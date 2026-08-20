# -*- coding: utf-8 -*-
"""信任分级回填门控图（2026-08-20 第二版，正式比赛风格）。

重跑：AI 环境 python gen_trust_graded_feedback.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, ax = plt.subplots(figsize=(14, 7.5))
ax.set_xlim(0, 14)
ax.set_ylim(0, 7.5)
ax.axis("off")

ax.set_title("信任分级回填：防止低质量模型输出污染工具记忆", fontsize=15,
             fontweight="bold", pad=18, color="#1a1a1a")


def grade_box(ax, x, y, w, h, grade, desc, facecolor):
    patch = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.1",
                           facecolor=facecolor, edgecolor=facecolor, linewidth=1.3, alpha=0.95)
    ax.add_patch(patch)
    ax.text(x + w / 2, y + h - 0.28, grade, ha="center", va="center",
            fontsize=12, fontweight="bold", color="white")
    ax.text(x + w / 2, y + h - 0.72, desc, ha="center", va="center",
            fontsize=8.5, color="white", linespacing=1.15)
    return x, y, w, h


def gate_box(ax, x, y, w, h, text, facecolor="#5e35b1"):
    patch = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                           facecolor=facecolor, edgecolor=facecolor, linewidth=1.2, alpha=0.95)
    ax.add_patch(patch)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=9, fontweight="bold", color="white", linespacing=1.1)
    return x, y, w, h


def out_box(ax, x, y, w, h, title, sub, facecolor):
    patch = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12",
                           facecolor=facecolor, edgecolor=facecolor, linewidth=1.5, alpha=0.95)
    ax.add_patch(patch)
    ax.text(x + w / 2, y + h - 0.35, title, ha="center", va="center",
            fontsize=11, fontweight="bold", color="white")
    ax.text(x + w / 2, y + h - 0.80, sub, ha="center", va="center",
            fontsize=8.5, color="white", linespacing=1.15)
    return x, y, w, h


def arr(ax, x1, y1, x2, y2, color="#4a4a4a"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                                 arrowstyle="->,head_width=0.22,head_length=0.14",
                                 color=color, linewidth=1.4,
                                 connectionstyle="arc3,rad=0"))


# 输入
in_patch = FancyBboxPatch((0.4, 5.9), 2.2, 0.8, boxstyle="round,pad=0.03,rounding_size=0.12",
                          facecolor="#1565c0", edgecolor="#1565c0", linewidth=1.5, alpha=0.95)
ax.add_patch(in_patch)
ax.text(1.5, 6.55, "LLM 裁决输出", ha="center", va="center",
        fontsize=10, fontweight="bold", color="white")
ax.text(1.5, 6.20, "含 A-E 质量分级", ha="center", va="center",
        fontsize=8.5, color="white")

# 左侧分级
grade_box(ax, 3.3, 5.85, 1.6, 1.0, "A", "判定正确\n编号正确", "#2e7d32")
grade_box(ax, 5.3, 5.85, 1.6, 1.0, "B", "判定正确\n编号错误", "#7cb342")
grade_box(ax, 3.3, 4.45, 1.6, 1.0, "C", "低置信", "#ef6c00")
grade_box(ax, 5.3, 4.45, 1.6, 1.0, "D", "误报", "#c62828")
grade_box(ax, 4.3, 3.05, 1.6, 1.0, "E", "无法判断", "#757575")

# 箭头：输入 → 分级
arr(ax, 2.6, 6.3, 3.3, 6.3)

# 中间门控
gate_box(ax, 7.6, 5.85, 2.4, 0.55, "全票门槛\nvotes == N")
gate_box(ax, 7.6, 5.10, 2.4, 0.55, "跨样本聚合\n≥2 独立文件")
gate_box(ax, 7.6, 4.35, 2.4, 0.55, "双向可撤销\n高置信否定清零")
gate_box(ax, 7.6, 3.60, 2.4, 0.55, "独立验证集\n复验门控")

# 门控标题
ax.text(8.8, 6.65, "四重回填门控", ha="center", va="center",
        fontsize=11, fontweight="bold", color="#333333")

# 箭头：A/B → 门控
arr(ax, 6.9, 6.35, 7.6, 6.10)
arr(ax, 6.9, 6.35, 7.6, 5.35)
# D 不进门控，直接进抑制池
# C/E 直接 review

# 右侧输出
out_box(ax, 11.0, 5.80, 2.4, 1.0, "回填工具记忆", "A / B 全部门控通过", "#2e7d32")
out_box(ax, 11.0, 4.40, 2.4, 1.0, "进入抑制池", "D / 高置信否定", "#c62828")
out_box(ax, 11.0, 3.00, 2.4, 1.0, "人工复核", "C / E / 未达门槛", "#ef6c00")

# 箭头：门控 → 回填
arr(ax, 10.0, 5.50, 11.0, 6.30)
# D → 抑制池
arr(ax, 6.9, 4.95, 11.0, 4.90)
# C/E → review
arr(ax, 4.3, 4.45, 4.3, 3.50)
arr(ax, 5.9, 4.45, 5.9, 3.50)
arr(ax, 4.3, 3.05, 5.3, 3.50)
arr(ax, 5.9, 3.50, 11.0, 3.50)

# 底部原则
ax.text(7.0, 1.5, "核心原则", ha="center", va="center",
        fontsize=12, fontweight="bold", color="#333333")
ax.text(7.0, 1.05, "A / B 级输出经四重门控后才允许回填；误报与无法判断进入抑制池或人工复核。",
        ha="center", va="center", fontsize=10, color="#4a4a4a")
ax.text(7.0, 0.65, "宁可不修改工具规则，也不让错误模型输出教坏确定性工具。",
        ha="center", va="center", fontsize=10, fontweight="bold", color="#4a4a4a")

fig.tight_layout()
fig.savefig("trust_graded_feedback.png", dpi=170)
print("已生成: trust_graded_feedback.png")
