# -*- coding: utf-8 -*-
"""2.5 代信任层架构图（2026-08-20）。

重跑：AI 环境 python gen_trust_layer_25.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, ax = plt.subplots(figsize=(15, 8.5))
ax.set_xlim(0, 15)
ax.set_ylim(0, 8.5)
ax.axis("off")

# 顶层：两阶段骨架输出
ax.text(7.5, 8.0, "Stage 2 LLM 裁决输出（N 次采样 + source/sink 证据链）",
        ha="center", va="center", fontsize=12, fontweight="bold", color="white",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#1f77b4", edgecolor="white", linewidth=2))

# 三层门控
layers = [
    ("Layer 1\n共形预测", "统计门控\n标签条件分位数\n{漏洞}/{安全}/{不确定}", "#2ca02c", 6.0),
    ("Layer 2\n反事实验证", "因果门控\nsink 行内注入防御\n裁决翻转判定", "#ff7f0e", 4.5),
    ("Layer 3\n确定性证据门", "零 LLM 成本\nsink 邻域防御签名\n无外部输入入口拦截", "#9467bd", 3.0),
]

for title, sub, color, y in layers:
    box = FancyBboxPatch((2.0, y), 5.5, 1.1, boxstyle="round,pad=0.05,rounding_size=0.12",
                         facecolor=color, edgecolor="white", linewidth=2, alpha=0.92)
    ax.add_patch(box)
    ax.text(4.75, y + 0.7, title, ha="center", va="center",
            fontsize=11, fontweight="bold", color="white")
    ax.text(4.75, y + 0.28, sub, ha="center", va="center",
            fontsize=8.5, color="white", linespacing=1.25)

# 右侧：信任分级回填
ax.text(11.5, 6.5, "信任分级", ha="center", va="center", fontsize=12,
        fontweight="bold", color="#333333")
grades = [
    ("A", "判定正确且编号正确", "#2ca02c", 5.7),
    ("B", "判定正确但编号错", "#7fbf7f", 5.0),
    ("C/D", "低置信/误报", "#d62728", 4.3),
    ("Review", "未达门槛", "#ff7f0e", 3.6),
]
for g, desc, c, y in grades:
    ax.add_patch(FancyBboxPatch((9.5, y), 4.0, 0.55, boxstyle="round,pad=0.03,rounding_size=0.08",
                                facecolor=c, edgecolor="white", linewidth=1.5, alpha=0.9))
    ax.text(10.0, y + 0.28, g, ha="center", va="center", fontsize=10,
            fontweight="bold", color="white")
    ax.text(11.5, y + 0.28, desc, ha="center", va="center", fontsize=8.5, color="white")

# 门控到分级的箭头
arrow1 = FancyArrowPatch((7.5, 6.55), (9.5, 5.7),
                         arrowstyle="->,head_width=0.25,head_length=0.15",
                         color="#555555", linewidth=1.5, connectionstyle="arc3,rad=0")
ax.add_patch(arrow1)

# 底部：信号回填
ax.text(7.5, 1.8, "信号回填 / 抑制池", ha="center", va="center", fontsize=12,
        fontweight="bold", color="white",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#17becf", edgecolor="white", linewidth=2))

# 门控到底部回填
arrow2 = FancyArrowPatch((4.75, 3.0), (4.75, 2.2),
                         arrowstyle="->,head_width=0.3,head_length=0.2",
                         color="#555555", linewidth=2)
ax.add_patch(arrow2)
arrow3 = FancyArrowPatch((11.5, 3.6), (11.5, 2.2),
                         arrowstyle="->,head_width=0.3,head_length=0.2",
                         color="#555555", linewidth=2)
ax.add_patch(arrow3)

# 说明
ax.text(7.5, 0.7, "为什么叫 2.5 代：统计门控 + 因果门控互补，后端过度自信时确定性证据门兜底；\n所有「谨慎」都是门槛参数写入代码，不是口头原则。",
        ha="center", va="center", fontsize=9.5, color="#555555", linespacing=1.4)

ax.set_title("2.5 代信任层：共形 + 反事实 + 确定性证据门 + 信任分级回填", fontsize=15, fontweight="bold", pad=20)

fig.tight_layout()
fig.savefig("trust_layer_25.png", dpi=170)
print("已生成: trust_layer_25.png")
