# -*- coding: utf-8 -*-
"""数据可信度保障体系图（2026-08-20 第二版，正式比赛风格）。

重跑：AI 环境 python gen_data_credibility_system.py
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


def hbox(ax, x, y, w, h, title, lines, facecolor, edgecolor, title_fs=10, text_fs=8.5):
    patch = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.1",
                           facecolor=facecolor, edgecolor=edgecolor, linewidth=1.5, alpha=0.95)
    ax.add_patch(patch)
    ax.text(x + w / 2, y + h - 0.28, title, ha="center", va="center",
            fontsize=title_fs, fontweight="bold", color="white")
    for i, line in enumerate(lines):
        ax.text(x + w / 2, y + h - 0.62 - i * 0.30, line, ha="center", va="center",
                fontsize=text_fs, color="white", linespacing=1.2)
    return x, y, w, h


def varr(ax, x1, y1, x2, y2, color="#4a4a4a"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                                 arrowstyle="->,head_width=0.22,head_length=0.14",
                                 color=color, linewidth=1.4,
                                 connectionstyle="arc3,rad=0"))


def harr(ax, x1, y1, x2, y2, color="#4a4a4a"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                                 arrowstyle="->,head_width=0.22,head_length=0.14",
                                 color=color, linewidth=1.4,
                                 connectionstyle="arc3,rad=0"))


# 三列标题
col_titles = [
    ("问题发现", 2.3, "#c62828"),
    ("审计与验证机制", 7.0, "#1565c0"),
    ("评估隔离", 11.7, "#2e7d32"),
]
for title, x, color in col_titles:
    ax.text(x, 7.35, title, ha="center", va="center", fontsize=12,
            fontweight="bold", color=color)

# 问题发现列
hbox(ax, 0.5, 5.65, 3.6, 1.15, "样本注释泄露", ["100% 准确率假象", "删除 47 个文件"], "#c62828", "#c62828")
hbox(ax, 0.5, 4.25, 3.6, 1.15, "训练-测试 Jaccard 泄漏", ["v4 整版废弃", "63 个样本重叠 30%+"], "#c62828", "#c62828")
hbox(ax, 0.5, 2.85, 3.6, 1.15, "反向拟合规则", ["类型白名单对着测试集推", "建立独立推导铁律"], "#c62828", "#c62828")

# 审计机制列
hbox(ax, 5.2, 5.95, 3.6, 0.85, "Jaccard 行级重叠审计", ["30% 相似阈值触发复核"], "#1565c0", "#1565c0")
hbox(ax, 5.2, 4.90, 3.6, 0.85, "合成集 vs CVE-fix 双测试集", ["合成集虚高 59.2pp 实证"], "#1565c0", "#1565c0")
hbox(ax, 5.2, 3.85, 3.6, 0.85, "Bootstrap 显著性检验", ["v7 vs v5 无显著差异"], "#1565c0", "#1565c0")
hbox(ax, 5.2, 2.80, 3.6, 0.85, "CWE 纠正口径", ["关键词归一 + evidence 守卫 + 父子族"], "#1565c0", "#1565c0")
hbox(ax, 5.2, 1.75, 3.6, 0.85, "parse_fail 计入漏报", ["避免解析失败被分母剔除"], "#1565c0", "#1565c0")

# 评估隔离列
hbox(ax, 9.9, 5.95, 3.6, 0.85, "抑制池跨跑隔离", ["--no-signal-feedback 干净评估"], "#2e7d32", "#2e7d32")
hbox(ax, 9.9, 4.90, 3.6, 0.85, "共形校准独立集", ["禁用 in-sample 校准泄漏"], "#2e7d32", "#2e7d32")
hbox(ax, 9.9, 3.85, 3.6, 0.85, "答案泄漏零容忍", ["文件名标签 / 反向规则审计"], "#2e7d32", "#2e7d32")
hbox(ax, 9.9, 2.80, 3.6, 0.85, "归因分流再修复", ["工具/模型责任分离"], "#2e7d32", "#2e7d32")

# 横向箭头：问题 → 审计 → 隔离
for y in [6.22, 5.17, 4.12]:
    harr(ax, 4.1, y, 5.2, y)
for y in [6.22, 5.17, 4.12, 3.07, 2.02]:
    harr(ax, 8.8, y, 9.9, y)

# 底部结果
result_box = FancyBboxPatch((3.8, 0.55), 6.4, 0.85, boxstyle="round,pad=0.03,rounding_size=0.12",
                            facecolor="#5e35b1", edgecolor="#5e35b1", linewidth=1.5, alpha=0.95)
ax.add_patch(result_box)
ax.text(7.0, 0.98, "fixed5 干净评估结果", ha="center", va="center",
        fontsize=11, fontweight="bold", color="white")
ax.text(7.0, 0.72, "recall 1.000  /  FPR 0.043  /  strict_recall 0.811", ha="center", va="center",
        fontsize=9.5, color="white")

# 从隔离列底部指向结果
varr(ax, 11.7, 2.75, 11.7, 1.45)
harr(ax, 9.9, 1.45, 10.2, 1.45)

# 底部说明
ax.text(7.0, 0.18, '核心原则：任何指标提升须先经「删除泄露后重跑」验证；数据可信度优先于指标绝对值。',
        ha="center", va="center", fontsize=9.5, color="#4a4a4a")

fig.tight_layout()
fig.savefig("data_credibility_system.png", dpi=170)
print("已生成: data_credibility_system.png")
