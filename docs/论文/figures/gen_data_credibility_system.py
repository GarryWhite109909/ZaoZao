# -*- coding: utf-8 -*-
"""数据可信度保障体系图（2026-08-20 修复截断与重叠版）。

修复：
- 第三个红色框 line1 被截断：hbox 文字位置调整，确保所有 line 在框内
- 紫色结果框与蓝色 parse_fail 框重叠：紫色框下移 + 压缩中列间距

重跑：AI 环境 cd figures && python gen_data_credibility_system.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, ax = plt.subplots(figsize=(14, 8))
ax.set_xlim(0, 14)
ax.set_ylim(0, 8)
ax.axis("off")

ax.set_title("数据可信度保障体系", fontsize=16, fontweight="bold", pad=20, color="#1a1a1a")

# ---------- 辅助函数 ----------
def hbox(ax, x, y, w, h, title, lines, facecolor, edgecolor, title_fs=10, text_fs=8.5):
    patch = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.1",
                           facecolor=facecolor, edgecolor=edgecolor, linewidth=1.5, alpha=0.95)
    ax.add_patch(patch)
    # 文字位置收紧，确保所有行在框内（title 顶格、sub 紧贴上/下）
    ax.text(x + w / 2, y + h - 0.26, title, ha="center", va="center",
            fontsize=title_fs, fontweight="bold", color="white")
    for i, line in enumerate(lines):
        ax.text(x + w / 2, y + h - 0.52 - i * 0.26, line, ha="center", va="center",
                fontsize=text_fs, color="white", linespacing=1.2)
    return {"x": x, "y": y, "w": w, "h": h,
            "cx": x + w / 2, "cy": y + h / 2,
            "top": y + h, "bottom": y}


def make_arrow(ax, x1, y1, x2, y2, color="#4a4a4a", lw=1.4):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                                 arrowstyle="->,head_width=0.22,head_length=0.14",
                                 color=color, linewidth=lw,
                                 connectionstyle="arc3,rad=0"))


# ---------- 三列标题 ----------
ax.text(2.3, 7.35, "问题发现", ha="center", va="center", fontsize=12,
        fontweight="bold", color="#c62828")
ax.text(7.0, 7.35, "审计与验证机制", ha="center", va="center", fontsize=12,
        fontweight="bold", color="#1565c0")
ax.text(11.7, 7.35, "评估隔离", ha="center", va="center", fontsize=12,
        fontweight="bold", color="#2e7d32")

# ---------- 三列 box（每列从同一顶部起，等距分布，底部对齐，文字不溢出） ----------
BOX_W = 3.6
BOX_H = 0.85        # 需容纳 title + 2 行 sub
COL_TOP = 6.1       # 三列顶部统一
COL_BOTTOM = 1.7    # 三列底部统一（等分区间，避免文字溢出）

# 左列：3 项
left_x = 0.5
left_boxes = [
    ("样本注释泄露", ["100% 准确率假象", "删除 47 个文件"]),
    ("训练-测试 Jaccard 泄漏", ["v4 整版废弃", "63 个样本重叠 30%+"]),
    ("反向拟合规则", ["类型白名单对着测试集推", "建立独立推导铁律"]),
]
left_ys = [COL_TOP - i * (COL_TOP - COL_BOTTOM - BOX_H) / 2 for i in range(3)]
left_objs = []
for (title, lines), y in zip(left_boxes, left_ys):
    left_objs.append(hbox(ax, left_x, y, BOX_W, BOX_H, title, lines, "#c62828", "#c62828"))

# 中列：5 项
center_x = 5.2
center_boxes = [
    ("Jaccard 行级重叠审计", ["30% 相似阈值触发复核"]),
    ("合成集 vs CVE-fix 双测试集", ["合成集虚高 59.2pp 实证"]),
    ("Bootstrap 显著性检验", ["v7 vs v5 无显著差异"]),
    ("CWE 纠正口径", ["关键词归一 + evidence 守卫 + 父子族"]),
    ("parse_fail 计入漏报", ["避免解析失败被分母剔除"]),
]
center_ys = [COL_TOP - i * (COL_TOP - COL_BOTTOM - BOX_H) / 4 for i in range(5)]
center_objs = []
for (title, lines), y in zip(center_boxes, center_ys):
    center_objs.append(hbox(ax, center_x, y, BOX_W, BOX_H, title, lines, "#1565c0", "#1565c0"))

# 右列：4 项
right_x = 9.9
right_boxes = [
    ("抑制池跨跑隔离", ["--no-signal-feedback 干净评估"]),
    ("共形校准独立集", ["禁用 in-sample 校准泄漏"]),
    ("答案泄漏零容忍", ["文件名标签 / 反向规则审计"]),
    ("归因分流再修复", ["工具/模型责任分离"]),
]
right_ys = [COL_TOP - i * (COL_TOP - COL_BOTTOM - BOX_H) / 3 for i in range(4)]
right_objs = []
for (title, lines), y in zip(right_boxes, right_ys):
    right_objs.append(hbox(ax, right_x, y, BOX_W, BOX_H, title, lines, "#2e7d32", "#2e7d32"))

# ---------- 底部结果框（下移消除重叠） ----------
RB_X = 3.8
RB_Y = 0.25
RB_W = 6.4
RB_H = 0.85
result_box = FancyBboxPatch((RB_X, RB_Y), RB_W, RB_H, boxstyle="round,pad=0.03,rounding_size=0.12",
                            facecolor="#5e35b1", edgecolor="#5e35b1", linewidth=1.5, alpha=0.95)
ax.add_patch(result_box)
ax.text(7.0, 0.68, "fixed5 干净评估结果", ha="center", va="center",
        fontsize=11, fontweight="bold", color="white")
ax.text(7.0, 0.42, "recall 1.000  /  FPR 0.043  /  strict_recall 0.811", ha="center", va="center",
        fontsize=9.5, color="white")

rb_top = RB_Y + RB_H        # = 1.10
rb_left = RB_X              # = 3.8
rb_right = RB_X + RB_W      # = 10.2
rb_cx = RB_X + RB_W / 2     # = 7.0

# ---------- 汇聚线（直角折线） ----------
make_arrow(ax, left_objs[-1]["cx"], left_objs[-1]["bottom"], left_objs[-1]["cx"], rb_top, color="#999999", lw=1.2)
make_arrow(ax, left_objs[-1]["cx"], rb_top, rb_left, rb_top, color="#999999", lw=1.2)

make_arrow(ax, center_objs[-1]["cx"], center_objs[-1]["bottom"], center_objs[-1]["cx"], rb_top, color="#999999", lw=1.2)

make_arrow(ax, right_objs[-1]["cx"], right_objs[-1]["bottom"], right_objs[-1]["cx"], rb_top, color="#999999", lw=1.2)
make_arrow(ax, right_objs[-1]["cx"], rb_top, rb_right, rb_top, color="#999999", lw=1.2)

# ---------- 底部说明 ----------
ax.text(7.0, 0.08, "核心原则：任何指标提升须先经「删除泄露后重跑」验证；数据可信度优先于指标绝对值。",
        ha="center", va="center", fontsize=9.5, color="#4a4a4a")

fig.tight_layout()
fig.savefig("data_credibility_system.png", dpi=170)
print("已生成: data_credibility_system.png")
