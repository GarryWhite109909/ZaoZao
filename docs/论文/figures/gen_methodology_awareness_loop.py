# -*- coding: utf-8 -*-
"""方法论自觉闭环图（2026-08-20）。

重跑：AI 环境 python gen_methodology_awareness_loop.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, ax = plt.subplots(figsize=(14, 7))
ax.set_xlim(0, 14)
ax.set_ylim(0, 7)
ax.axis("off")

# 五个阶段
stages = [
    ("漂亮数字\n100% 准确率", "样本注释泄露", "#ff7f0e"),
    ("诚实修正", "删除 47 个泄露文件\n重跑后 89.7%→78.2%", "#2ca02c"),
    ("再次推翻", "v4 训练-测试泄漏\n整版废弃", "#d62728"),
    ("反思架构", "LLM 不该做'发现'\n该做'裁决'", "#1f77b4"),
    ("新方法", "工具召回 + LLM 裁决\n两阶段架构", "#9467bd"),
]

boxes = []
for i, (title, sub, color) in enumerate(stages):
    x = 1.0 + i * 2.55
    y = 3.0
    box = FancyBboxPatch(
        (x, y), 2.0, 1.6, boxstyle="round,pad=0.05,rounding_size=0.15",
        facecolor=color, edgecolor="white", linewidth=2, alpha=0.92
    )
    ax.add_patch(box)
    ax.text(x + 1.0, y + 1.05, title, ha="center", va="center",
            fontsize=11, fontweight="bold", color="white")
    ax.text(x + 1.0, y + 0.45, sub, ha="center", va="center",
            fontsize=8.5, color="white", linespacing=1.3)
    boxes.append((x, y, 2.0, 1.6))

# 箭头
for i in range(len(boxes) - 1):
    x1 = boxes[i][0] + boxes[i][2]
    y1 = boxes[i][1] + boxes[i][3] / 2
    x2 = boxes[i + 1][0]
    y2 = boxes[i + 1][1] + boxes[i + 1][3] / 2
    arrow = FancyArrowPatch((x1, y1), (x2, y2),
                            arrowstyle="->,head_width=0.3,head_length=0.2",
                            color="#555555", linewidth=2,
                            connectionstyle="arc3,rad=0")
    ax.add_patch(arrow)

# 底部总结
ax.text(7, 1.2, "核心结论：数据可信度是前提，推翻自己是方法论的常态",
        ha="center", va="center", fontsize=13, fontweight="bold", color="#333333")
ax.text(7, 0.7, "最可贵的不是最终指标，而是每次发现「数字在骗我」后敢于重来的判断力",
        ha="center", va="center", fontsize=10, color="#555555")

ax.set_title("方法论自觉闭环：从 100% 准确率假象到两阶段架构", fontsize=15, fontweight="bold", pad=20)

fig.tight_layout()
fig.savefig("methodology_awareness_loop.png", dpi=170)
print("已生成: methodology_awareness_loop.png")
