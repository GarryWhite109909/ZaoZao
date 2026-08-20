# -*- coding: utf-8 -*-
"""2.5 代信任层架构图（2026-08-20 第二版，正式比赛风格）。

重跑：AI 环境 python gen_trust_layer_25.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, ax = plt.subplots(figsize=(14, 9))
ax.set_xlim(0, 14)
ax.set_ylim(0, 9)
ax.axis("off")

ax.set_title("2.5 代信任层：统计门控 + 因果门控 + 确定性证据门 + 信任分级回填",
             fontsize=15, fontweight="bold", pad=18, color="#1a1a1a")


def layer_box(ax, x, y, w, h, title, lines, facecolor, edgecolor):
    patch = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12",
                           facecolor=facecolor, edgecolor=edgecolor, linewidth=1.6, alpha=0.96)
    ax.add_patch(patch)
    ax.text(x + w / 2, y + h - 0.30, title, ha="center", va="center",
            fontsize=11, fontweight="bold", color="white")
    for i, line in enumerate(lines):
        ax.text(x + w / 2, y + h - 0.68 - i * 0.32, line, ha="center", va="center",
                fontsize=8.5, color="white", linespacing=1.2)
    return x, y, w, h


def small_box(ax, x, y, w, h, text, facecolor, text_color="white", fs=9):
    patch = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                           facecolor=facecolor, edgecolor=facecolor, linewidth=1.2, alpha=0.95)
    ax.add_patch(patch)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fs, fontweight="bold", color=text_color, linespacing=1.15)
    return x, y, w, h


def arr(ax, x1, y1, x2, y2, color="#4a4a4a"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                                 arrowstyle="->,head_width=0.22,head_length=0.14",
                                 color=color, linewidth=1.4,
                                 connectionstyle="arc3,rad=0"))


# 输入
small_box(ax, 4.8, 8.05, 4.4, 0.55, "Stage 2 LLM 裁决输出\nN 次采样 + source/sink 证据链", "#1565c0", fs=9)

# 三层门控（垂直堆叠，左列）
layer_box(ax, 2.0, 5.75, 5.0, 1.35, "Layer 1  共形预测（统计门控）", [
    "标签条件分位数",
    "输出：{漏洞} / {安全} / {不确定}"
], "#2e7d32", "#2e7d32")

layer_box(ax, 2.0, 3.95, 5.0, 1.35, "Layer 2  反事实验证（因果门控）", [
    "sink 行内注入防御，观察裁决是否翻转",
    "过滤过度自信的伪真"
], "#ef6c00", "#ef6c00")

layer_box(ax, 2.0, 2.15, 5.0, 1.35, "Layer 3  确定性证据门（零 LLM 成本兜底）", [
    "sink 邻域防御签名 / 无外部输入入口拦截",
    "无 LLM 调用即可否决"
], "#6a1b9a", "#6a1b9a")

# 门控之间垂直箭头
arr(ax, 4.5, 7.95, 4.5, 7.15)
arr(ax, 4.5, 5.75, 4.5, 5.35)
arr(ax, 4.5, 3.95, 4.5, 3.55)

# 右侧：信任分级
ax.text(10.5, 6.95, "信任分级", ha="center", va="center", fontsize=12,
        fontweight="bold", color="#333333")
small_box(ax, 8.8, 6.15, 3.4, 0.55, "A  判定正确且编号正确", "#2e7d32")
small_box(ax, 8.8, 5.40, 3.4, 0.55, "B  判定正确但编号错误", "#7cb342")
small_box(ax, 8.8, 4.65, 3.4, 0.55, "C/D  低置信 / 误报", "#c62828")
small_box(ax, 8.8, 3.90, 3.4, 0.55, "Review  未达门槛", "#ef6c00")

# 从门控到分级
arr(ax, 7.0, 6.15, 8.8, 6.42)
arr(ax, 7.0, 4.35, 8.8, 4.92)

# 四重门控（A/B 回填前必须通过）
ax.text(10.5, 3.15, "四重回填门控", ha="center", va="center", fontsize=12,
        fontweight="bold", color="#333333")
small_box(ax, 8.8, 2.45, 3.4, 0.45, "全票门槛  votes == N", "#5e35b1", fs=8.5)
small_box(ax, 8.8, 1.90, 3.4, 0.45, "跨样本聚合  ≥2 独立文件", "#5e35b1", fs=8.5)
small_box(ax, 8.8, 1.35, 3.4, 0.45, "双向可撤销", "#5e35b1", fs=8.5)
small_box(ax, 8.8, 0.80, 3.4, 0.45, "独立验证集门控", "#5e35b1", fs=8.5)

# 从 A/B 到门控
arr(ax, 10.5, 6.15, 10.5, 2.95)

# 底部输出
small_box(ax, 2.0, 0.45, 3.0, 0.75, "信号回填\nA/B 通过门控 → 工具记忆", "#00838f", fs=9)
small_box(ax, 5.5, 0.45, 3.0, 0.75, "抑制池\nD / 高置信否定", "#c62828", fs=9)
small_box(ax, 9.0, 0.45, 3.2, 0.75, "人工复核\nReview / 未达门槛", "#ef6c00", fs=9)

# 从门控到底部
arr(ax, 8.8, 2.00, 7.1, 1.25)
arr(ax, 10.5, 0.75, 10.5, 1.25)
# 从 Layer 3 到回填
arr(ax, 4.5, 2.15, 4.5, 1.25)

# 说明
ax.text(7.0, 0.12, "2.5 代含义：统计门控与因果门控互补，后端过度自信时由确定性证据门兜底；所有门槛均为代码参数，非口头原则。",
        ha="center", va="center", fontsize=9, color="#4a4a4a")

fig.tight_layout()
fig.savefig("trust_layer_25.png", dpi=170)
print("已生成: trust_layer_25.png")
