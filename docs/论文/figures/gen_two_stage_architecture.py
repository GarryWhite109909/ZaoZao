# -*- coding: utf-8 -*-
"""两阶段扫描架构图（2026-08-20 按 fixed5 代码重绘）。

重跑：AI 环境 python gen_two_stage_architecture.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, ax = plt.subplots(figsize=(16, 10))
ax.set_xlim(0, 16)
ax.set_ylim(0, 10)
ax.axis("off")


def box(ax, x, y, w, h, title, lines, facecolor, edgecolor="#333333", title_color="white", text_color="#333333"):
    """绘制带标题的圆角矩形框。"""
    patch = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.02,rounding_size=0.12",
        facecolor=facecolor, edgecolor=edgecolor, linewidth=1.5, alpha=0.95
    )
    ax.add_patch(patch)
    ax.text(x + w / 2, y + h - 0.28, title, ha="center", va="center",
            fontsize=10, fontweight="bold", color=title_color)
    for i, line in enumerate(lines):
        ax.text(x + w / 2, y + h - 0.65 - i * 0.32, line, ha="center", va="center",
                fontsize=8.5, color=text_color, linespacing=1.2)
    return x, y, w, h


def arrow(ax, x1, y1, x2, y2, color="#555555"):
    """绘制箭头。"""
    arr = FancyArrowPatch((x1, y1), (x2, y2),
                          arrowstyle="->,head_width=0.25,head_length=0.15",
                          color=color, linewidth=1.5,
                          connectionstyle="arc3,rad=0")
    ax.add_patch(arr)


def label(ax, x, y, text, color="#555555", fontsize=8.5):
    ax.text(x, y, text, ha="center", va="center", fontsize=fontsize, color=color)


# Stage 1 工具召回
b1 = box(ax, 1.0, 6.2, 3.6, 2.6, "Stage 1：工具召回", [
    "Semgrep taint 模式",
    "TaintTracker（自研 AST 污点）",
    "Prefilter（自研正则预筛）",
    "↓ 合并去重 + CWE 归一"
], "#e8f4fd", edgecolor="#1f77b4", title_color="#1f77b4", text_color="#1f77b4")

# 源代码输入
ax.text(2.8, 9.3, "源代码输入", ha="center", va="center", fontsize=11, fontweight="bold", color="#333333")
arrow(ax, 2.8, 9.0, 2.8, 8.85)

# 候选 findings 列表
label(ax, 2.8, 5.85, "候选 finding 列表")

# 决策菱形：有候选？
diamond_x, diamond_y = 2.8, 4.6
from matplotlib.patches import RegularPolygon
diamond = RegularPolygon((diamond_x, diamond_y), numVertices=4, radius=0.55,
                         orientation=0, facecolor="#fff3cd", edgecolor="#f0ad4e", linewidth=2)
ax.add_patch(diamond)
ax.text(diamond_x, diamond_y, "有\n候选？", ha="center", va="center", fontsize=9, fontweight="bold", color="#856404")

arrow(ax, 2.8, 6.15, 2.8, 5.2)
arrow(ax, 2.8, 4.0, 2.8, 3.5)
label(ax, 3.4, 4.0, "是", color="#333333")

# 无候选分支：判安全 + 复核
b_no = box(ax, 0.4, 1.4, 3.6, 1.8, "无候选分支", [
    "默认判安全，按 no_candidate_mode",
    "sampled 10% 抽样 / full_recheck 全量",
    "LLM 全文件复核 → 全票判真才采信"
], "#d4edda", edgecolor="#28a745", title_color="#155724", text_color="#155724")

arrow(ax, 2.25, 4.1, 0.8, 3.25, color="#28a745")
label(ax, 1.2, 3.7, "否", color="#333333")

# Stage 2 LLM 裁决
b2 = box(ax, 6.0, 5.6, 4.2, 3.2, "Stage 2：LLM 裁决", [
    "triage_train_aligned（与训练对齐）",
    "has_vulnerability schema + 双格式解析",
    "N=5 次采样 → 自一致率置信度",
    "上下文：CodeSlicer 切片 + 污点链"
], "#fff3e0", edgecolor="#ff7f0e", title_color="#e65100", text_color="#bf360c")

arrow(ax, 3.35, 4.6, 5.95, 6.5)

# 2.5 代信任层
b_trust = box(ax, 11.0, 5.6, 4.2, 3.2, "2.5 代信任层（由廉价到昂贵）", [
    "① 确定性证据门：sink 已防御 / 无输入入口",
    "② 共形预测：{漏洞}/{安全}/{不确定}",
    "③ 反事实验证：sink 注入防御后是否翻转",
    "④ 信任分级：A-E 级 → 回填 / 抑制池 / Review"
], "#f3e5f5", edgecolor="#7b1fa2", title_color="#4a148c", text_color="#4a148c")

arrow(ax, 10.25, 7.2, 10.95, 7.2)

# 聚合最终结论
b_agg = box(ax, 7.4, 2.6, 5.4, 2.0, "聚合最终结论", [
    "confirmed_vulnerability：确认漏洞（带 source/sink/修复建议）",
    "confirmed_review / dismissed_review：低置信 → 人工复核",
    "dismissed_safe：确认安全"
], "#e3f2fd", edgecolor="#1565c0", title_color="#0d47a1", text_color="#0d47a1")

arrow(ax, 13.1, 5.55, 13.1, 4.0, color="#7b1fa2")
arrow(ax, 13.1, 4.0, 12.85, 4.0, color="#7b1fa2")

# 兜底复核
b_fallback = box(ax, 7.4, 0.4, 5.4, 1.4, "兜底复核（防工具盲区静默放行）", [
    "全部候选被裁决否决后，强制全文件 LLM 复核",
    "全票判真 + 代码形态匹配 → 采信为漏洞"
], "#ffebee", edgecolor="#c62828", title_color="#b71c1c", text_color="#b71c1c")

arrow(ax, 10.1, 2.55, 10.1, 1.85)

# 无候选复核结果也汇入聚合
arrow(ax, 4.05, 2.3, 7.35, 3.0, color="#28a745")

# 输出
ax.text(13.4, 1.1, "输出：漏洞判定 + CWE + 修复建议\n（或 review / safe）",
        ha="center", va="center", fontsize=10, fontweight="bold", color="#333333",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="#ffffff", edgecolor="#333333", linewidth=1.5))
arrow(ax, 12.85, 1.1, 13.05, 1.1)

# 顶部说明
ax.text(8, 9.5, "当前 fixed5 实际架构：两阶段骨架 + 2.5 代信任层 + 复核兜底",
        ha="center", va="center", fontsize=14, fontweight="bold", color="#333333")
ax.text(8, 9.05, "不再标称'80% 文件不调用 LLM'——两阶段未做实测统计；复核/兜底路径保证工具盲区不被静默放行",
        ha="center", va="center", fontsize=9, color="#d32f2f")

fig.tight_layout()
fig.savefig("two_stage_architecture.png", dpi=170)
print("已生成: two_stage_architecture.png")
