# -*- coding: utf-8 -*-
"""信任分级回填门控图（2026-08-20 第四版：排版平衡，修正文字压制卡片等问题）。

修复：
- 左栏加浅色容器面板，分级头(LLM 裁决输出/按质量分级 A-E)放在面板顶部净空区，
  与 A 卡片之间留足间距，不再压到 A 卡片上
- 卡片内文字改为垂直居中（不再顶格/贴边），大卡片按内容排版，不再"框很大字很小"
- 中栏门控文本在框内均匀排布（标题置顶、门控条件居中、提示置底），消除大块空白
- 所有连线保持横平竖直、互不交叉

重跑：AI 环境 cd figures && python gen_trust_graded_feedback.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, ax = plt.subplots(figsize=(14, 8))
ax.set_xlim(0, 14)
ax.set_ylim(0, 8)
ax.axis("off")

ax.set_title("信任分级回填：防止低质量模型输出污染工具记忆",
             fontsize=15, fontweight="bold", pad=14, color="#1a1a1a")


# ---------- 辅助函数 ----------
def chip(ax, x, y, w, h, text, facecolor, fs=10.5):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.10",
                                facecolor=facecolor, edgecolor=facecolor, linewidth=1.3, alpha=0.95))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fs, fontweight="bold", color="white")
    return {"x": x, "y": y, "w": w, "h": h,
            "cx": x + w / 2, "cy": y + h / 2, "left": x, "right": x + w,
            "top": y + h, "bottom": y}


def gate_box(ax, x, y, w, h, title, lines, note):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.14",
                                facecolor="#5e35b1", edgecolor="#5e35b1", linewidth=1.5, alpha=0.96))
    cx = x + w / 2
    ax.text(cx, y + h - 0.34, title, ha="center", va="center",
            fontsize=12, fontweight="bold", color="white")
    # 4 条条件在框内垂直均匀分布（顶部标题、底部提示之外）
    bot = y + h - 0.60
    step = (h - 1.85) / (len(lines) - 1) if len(lines) > 1 else 0
    for i, line in enumerate(lines):
        ax.text(cx, bot - i * step, line, ha="center", va="center",
                fontsize=9, color="white")
    ax.text(cx, y + 0.36, note, ha="center", va="center",
            fontsize=9.5, fontweight="bold", color="#ffe082")
    return {"x": x, "y": y, "w": w, "h": h,
            "cx": cx, "cy": y + h / 2, "left": x, "right": x + w,
            "top": y + h, "bottom": y}


def out_box(ax, x, y, w, h, title, sub, facecolor, title_fs=11.5, sub_fs=9):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12",
                                facecolor=facecolor, edgecolor=facecolor, linewidth=1.5, alpha=0.96))
    cx, cy = x + w / 2, y + h / 2
    ax.text(cx, cy + 0.18, title, ha="center", va="center",
            fontsize=title_fs, fontweight="bold", color="white")
    ax.text(cx, cy - 0.20, sub, ha="center", va="center",
            fontsize=sub_fs, color="white")
    return {"x": x, "y": y, "w": w, "h": h,
            "cx": cx, "cy": cy, "left": x, "right": x + w,
            "top": y + h, "bottom": y}


def arr(ax, x1, y1, x2, y2, color="#4a4a4a", lw=1.7):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                                 arrowstyle="->,head_width=0.24,head_length=0.15",
                                 color=color, linewidth=lw,
                                 connectionstyle="arc3,rad=0"))


# ---------- 左栏：容器面板 + 分级头部 + 5 行卡片 ----------
PANEL_X, PANEL_W = 0.5, 3.9
PANEL_Y, PANEL_H = 1.7, 5.55
ax.add_patch(Rectangle((PANEL_X, PANEL_Y), PANEL_W, PANEL_H,
                       facecolor="#f2f5fb", edgecolor="#c8d2ea", linewidth=1.2, zorder=0))
# 面板内分级头部（置于顶部净空区，A 卡片之下留足间距）
ax.text(PANEL_X + 0.15, 6.92, "LLM 裁决输出", ha="left", va="center",
        fontsize=13, fontweight="bold", color="#1a1a1a", zorder=2)
ax.text(PANEL_X + 0.15, 6.55, "按判定质量分级 A–E", ha="left", va="center",
        fontsize=10, color="#555555", zorder=2)

# 5 张分级卡片（columns）
CX0, CW = PANEL_X + 0.35, 3.2
chip_y = [5.62, 4.80, 3.98, 3.16, 2.34]      # 各卡底边 y，高 0.68，垂直均匀分布
grade_rows = [
    ("A", "判定正确 · 编号正确", "#2e7d32"),
    ("B", "判定正确 · 编号错误", "#7cb342"),
    ("C", "低置信",             "#ef6c00"),
    ("D", "误报",               "#c62828"),
    ("E", "无法判断",           "#757575"),
]
grades = []
for (g, desc, color), y in zip(grade_rows, chip_y):
    c = chip(ax, CX0, y, CW, 0.68, f"{g}   {desc}", color)
    grades.append((g, c, color))

# ---------- 中栏：四重回填门控 ----------
GATE = gate_box(ax, 5.3, 2.55, 3.0, 4.35, "四重回填门控",
                ["全票门槛  votes == N",
                 "跨样本聚合  ≥2 独立文件",
                 "双向可撤销",
                 "独立验证集门控"],
                "仅 A / B 放行 → 回填")

# ---------- 右栏：三个出口（文字垂直居中） ----------
fb = out_box(ax, 9.0, 5.72, 4.0, 1.05, "回填工具记忆", "A / B · 全部门控通过", "#00838f")
po = out_box(ax, 9.0, 4.22, 4.0, 1.05, "进入抑制池", "D · 高置信否定", "#c62828")
rw = out_box(ax, 9.0, 2.72, 4.0, 1.05, "人工复核", "C / E · 未达门槛", "#ef6c00")

# ---------- 连线（横平竖直，互不交叉） ----------
for (_g, c, _col) in grades:
    arr(ax, c["right"], c["cy"], GATE["left"], c["cy"])
arr(ax, GATE["right"], fb["cy"], fb["left"], fb["cy"], color="#00838f")
arr(ax, GATE["right"], po["cy"], po["left"], po["cy"], color="#c62828")
arr(ax, GATE["right"], rw["cy"], rw["left"], rw["cy"], color="#ef6c00")

# ---------- 底部说明 ----------
ax.text(7.0, 1.02, "核心原则", ha="center", va="center",
        fontsize=12, fontweight="bold", color="#333333")
ax.text(7.0, 0.62, "仅 A / B 级输出经四重门控后允许回填；误报与无法判断进入抑制池或人工复核。",
        ha="center", va="center", fontsize=10, color="#4a4a4a")
ax.text(7.0, 0.28, "宁可不修改工具规则，绝不让低质量模型信号污染确定性工具。",
        ha="center", va="center", fontsize=10, fontweight="bold", color="#575757")

fig.tight_layout()
fig.savefig("trust_graded_feedback.png", dpi=170)
print("已生成: trust_graded_feedback.png")