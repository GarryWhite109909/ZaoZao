# -*- coding: utf-8 -*-
"""方法论自觉闭环图（2026-08-20 第三版，紧凑布局，消除顶部留白）。

vs 第二版：五个阶段框整体居中上移（不再挤在下方），
底部闭环 + 结论区保留，顶部标题下不再大片空白。
重跑：AI 环境 python gen_methodology_awareness_loop.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, ax = plt.subplots(figsize=(14, 7))
ax.set_xlim(0, 14)
ax.set_ylim(0, 7)
ax.axis("off")

# 五个阶段（配色语义化：橙=假象 / 绿=修正 / 红=推翻 / 蓝=反思 / 紫=新方法）
stages = [
    ("100% 准确率假象", "样本注释泄露\n表面完美", "#e65100"),
    ("第一次修正", "删除 47 个泄露文件\n准确率 89.7%→78.2%", "#2e7d32"),
    ("再次推翻", "v4 训练-测试泄漏\n整版数据废弃", "#c62828"),
    ("反思架构", "LLM 不应做'发现'\n应做'裁决'", "#1565c0"),
    ("建立新方法", "工具召回 + LLM 裁决\n两阶段架构", "#6a1b9a"),
]

box_w, box_h = 2.15, 1.7
# 五个框居中：5 框 × 2.15 + 4 间隔 × 0.45 = 10.75 + 1.8 = 12.55，起点 x=0.72
start_x, y = 0.72, 3.5
boxes = []
for i, (title, sub, color) in enumerate(stages):
    x = start_x + i * 2.6
    box = FancyBboxPatch(
        (x, y), box_w, box_h, boxstyle="round,pad=0.05,rounding_size=0.15",
        facecolor=color, edgecolor="white", linewidth=2, alpha=0.94
    )
    ax.add_patch(box)
    ax.text(x + box_w / 2, y + box_h - 0.38, title, ha="center", va="center",
            fontsize=10.5, fontweight="bold", color="white")
    ax.text(x + box_w / 2, y + box_h - 0.9, sub, ha="center", va="center",
            fontsize=8.5, color="white", linespacing=1.25)
    boxes.append((x, y, box_w, box_h))

# 阶段编号
for i, (x, y, w, h) in enumerate(boxes):
    ax.text(x + w / 2, y + h + 0.22, f"Step {i + 1}", ha="center", va="center",
            fontsize=9, fontweight="bold", color="#555555")


# 前向箭头（水平直线）
def harrow(ax, x1, y1, x2, y2, color="#4a4a4a"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                                 arrowstyle="->,head_width=0.25,head_length=0.15",
                                 color=color, linewidth=1.6,
                                 connectionstyle="arc3,rad=0"))


for i in range(len(boxes) - 1):
    x1 = boxes[i][0] + boxes[i][2]
    y1 = boxes[i][1] + boxes[i][3] / 2
    x2 = boxes[i + 1][0]
    y2 = boxes[i + 1][1] + boxes[i + 1][3] / 2
    harrow(ax, x1, y1, x2, y2)

# 闭环反馈箭头：从最后一个回到第一个，走下方弧线
last_x = boxes[-1][0] + boxes[-1][2] / 2
last_y = boxes[-1][1]
first_x = boxes[0][0] + boxes[0][2] / 2
first_y = boxes[0][1]
ax.annotate("", xy=(first_x, first_y - 0.15), xytext=(last_x, last_y - 0.15),
            arrowprops=dict(arrowstyle="->", color="#6a1b9a", lw=1.8,
                            connectionstyle="arc3,rad=-0.30"))
ax.text(7.0, 2.0, "新一轮迭代：新数据 / 新问题触发下一轮自我审查", ha="center", va="center",
        fontsize=9.5, color="#6a1b9a", fontweight="bold")

# 底部结论（紧贴闭环下方，不再有大留白）
ax.text(7.0, 1.35, "核心结论：数据可信度是前提，推翻自己是方法论的常态",
        ha="center", va="center", fontsize=13, fontweight="bold", color="#1a1a1a")
ax.text(7.0, 0.85, "最可贵的不是最终指标，而是发现数据不可信后敢于重来、修正体系的能力",
        ha="center", va="center", fontsize=10, color="#4a4a4a")

ax.set_title("方法论自觉闭环：从 100% 准确率假象到两阶段架构", fontsize=15,
             fontweight="bold", pad=14, color="#1a1a1a")

fig.tight_layout()
from pathlib import Path
OUT = Path(__file__).resolve().parent / "methodology_awareness_loop.png"
fig.savefig(OUT, dpi=170)
print(f"已生成: {OUT}")
