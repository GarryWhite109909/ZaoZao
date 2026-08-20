# -*- coding: utf-8 -*-
"""数据可信度保障体系图（2026-08-20）。

重跑：AI 环境 python gen_data_credibility_system.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, ax = plt.subplots(figsize=(15, 8))
ax.set_xlim(0, 15)
ax.set_ylim(0, 8)
ax.axis("off")

# 标题
ax.set_title("数据可信度保障体系：漂亮数字不等于真能力", fontsize=15, fontweight="bold", pad=20)

# 左侧：三次泄漏发现
leaks = [
    ("样本注释泄露", "100% 准确率是假象\n删除 47 个文件", "#d62728", 6.5),
    ("训练-测试 Jaccard 泄漏", "v4 整版废弃\n63 个样本重叠 30%+", "#d62728", 5.2),
    ("反向拟合规则", "类型白名单对着测试集推\n建立「不看结果能推吗」铁律", "#d62728", 3.9),
]
ax.text(2.5, 7.3, "三次「数字骗我」", ha="center", va="center", fontsize=12,
        fontweight="bold", color="#333333")
for title, sub, color, y in leaks:
    ax.add_patch(FancyBboxPatch((0.5, y), 4.0, 0.9, boxstyle="round,pad=0.05,rounding_size=0.1",
                                facecolor=color, edgecolor="white", linewidth=2, alpha=0.9))
    ax.text(2.5, y + 0.6, title, ha="center", va="center", fontsize=10,
            fontweight="bold", color="white")
    ax.text(2.5, y + 0.22, sub, ha="center", va="center", fontsize=8, color="white", linespacing=1.2)

# 中间：审计机制
audits = [
    "Jaccard 行级重叠审计",
    "合成集 vs CVE-fix 双测试集",
    "Bootstrap 显著性检验",
    "CWE 纠正口径 + parse_fail 计入",
]
ax.text(7.5, 7.3, "审计与验证机制", ha="center", va="center", fontsize=12,
        fontweight="bold", color="#333333")
for i, text in enumerate(audits):
    y = 6.3 - i * 0.95
    ax.add_patch(FancyBboxPatch((5.5, y), 4.0, 0.7, boxstyle="round,pad=0.03,rounding_size=0.08",
                                facecolor="#1f77b4", edgecolor="white", linewidth=1.5, alpha=0.9))
    ax.text(7.5, y + 0.35, text, ha="center", va="center", fontsize=9.5,
            fontweight="bold", color="white")

# 右侧：评估隔离
ax.text(12.5, 7.3, "评估隔离铁律", ha="center", va="center", fontsize=12,
        fontweight="bold", color="#333333")
rules = [
    "抑制池跨跑隔离",
    "共形校准独立集",
    "答案泄漏零容忍",
    "归因分流再修复",
]
for i, text in enumerate(rules):
    y = 6.3 - i * 0.95
    ax.add_patch(FancyBboxPatch((10.5, y), 4.0, 0.7, boxstyle="round,pad=0.03,rounding_size=0.08",
                                facecolor="#2ca02c", edgecolor="white", linewidth=1.5, alpha=0.9))
    ax.text(12.5, y + 0.35, text, ha="center", va="center", fontsize=9.5,
            fontweight="bold", color="white")

# 底部结论
ax.text(7.5, 1.5, "结果：fixed5 干净评估 recall 1.000 / FPR 0.043",
        ha="center", va="center", fontsize=13, fontweight="bold", color="white",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#9467bd", edgecolor="white", linewidth=2))
ax.text(7.5, 0.6, "任何指标提升须先用「删除泄露后重跑」验证；数据可信度比指标绝对值更重要。",
        ha="center", va="center", fontsize=9.5, color="#555555")

# 箭头：三次泄漏 → 审计机制
for y in [6.95, 5.65, 4.35]:
    ax.add_patch(FancyArrowPatch((4.5, y + 0.45), (5.5, 6.0),
                                 arrowstyle="->,head_width=0.2,head_length=0.12",
                                 color="#888888", linewidth=1.2, connectionstyle="arc3,rad=0.1"))

# 箭头：审计机制 → 评估隔离
for y in [6.65, 5.7, 4.75, 3.8]:
    ax.add_patch(FancyArrowPatch((9.5, y), (10.5, y),
                                 arrowstyle="->,head_width=0.2,head_length=0.12",
                                 color="#888888", linewidth=1.2))

fig.tight_layout()
fig.savefig("data_credibility_system.png", dpi=170)
print("已生成: data_credibility_system.png")
