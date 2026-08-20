# -*- coding: utf-8 -*-
"""自研工具链关系图（2026-08-20）。

重跑：AI 环境 python gen_self_developed_tools.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, ax = plt.subplots(figsize=(15, 5.5))
ax.set_xlim(0, 15)
ax.set_ylim(0, 5.5)
ax.axis("off")

# 输入
ax.text(0.8, 3.0, "代码输入", ha="center", va="center", fontsize=11,
        fontweight="bold", color="#333333",
        bbox=dict(boxstyle="round,pad=0.35", facecolor="#e8e8e8", edgecolor="#999999", linewidth=1.5))

# 工具节点（横向流程）
tools = [
    ("TaintTracker", "污点分析\nsource→sink", "#1f77b4", 2.8),
    ("Prefilter", "预筛候选\n安全/漏洞特征", "#ff7f0e", 5.1),
    ("CodeSlicer", "长文件切片\n≥150 行按函数切", "#2ca02c", 7.4),
    ("LLM", "封闭裁决\n自一致率置信度", "#9467bd", 9.7),
]

for name, sub, color, x in tools:
    ax.add_patch(FancyBboxPatch((x, 2.5), 1.9, 1.0, boxstyle="round,pad=0.05,rounding_size=0.1",
                                facecolor=color, edgecolor="white", linewidth=2, alpha=0.92))
    ax.text(x + 0.95, 3.15, name, ha="center", va="center", fontsize=10,
            fontweight="bold", color="white")
    ax.text(x + 0.95, 2.78, sub, ha="center", va="center", fontsize=7.5,
            color="white", linespacing=1.1)

# 箭头
for x in [1.7, 4.0, 6.3, 8.6]:
    ax.add_patch(FancyArrowPatch((x, 3.0), (x + 0.9, 3.0),
                                 arrowstyle="->,head_width=0.25,head_length=0.15",
                                 color="#555555", linewidth=1.8))

# 后处理工具
post_tools = [
    ("CWE Normalizer", "编号纠正\n零 token", 10.3, 4.3),
    ("LineNormalizer", "行号锚定\n内容反向定位", 12.2, 4.3),
    ("FixVerifier", "修复建议\n语法校验", 11.25, 1.6),
]
for name, sub, x, y in post_tools:
    ax.add_patch(FancyBboxPatch((x, y), 1.7, 0.75, boxstyle="round,pad=0.03,rounding_size=0.08",
                                facecolor="#17becf", edgecolor="white", linewidth=1.5, alpha=0.9))
    ax.text(x + 0.85, y + 0.5, name, ha="center", va="center", fontsize=9,
            fontweight="bold", color="white")
    ax.text(x + 0.85, y + 0.2, sub, ha="center", va="center", fontsize=6.5, color="white")

# 箭头：LLM → 后处理
ax.add_patch(FancyArrowPatch((11.6, 3.5), (11.15, 4.3),
                             arrowstyle="->,head_width=0.2,head_length=0.12",
                             color="#888888", linewidth=1.2))
ax.add_patch(FancyArrowPatch((11.6, 3.5), (12.05, 4.3),
                             arrowstyle="->,head_width=0.2,head_length=0.12",
                             color="#888888", linewidth=1.2))
ax.add_patch(FancyArrowPatch((11.6, 2.5), (12.1, 2.35),
                             arrowstyle="->,head_width=0.2,head_length=0.12",
                             color="#888888", linewidth=1.2))

# 输出
ax.text(14.0, 3.0, "SARIF\n导出", ha="center", va="center", fontsize=10,
        fontweight="bold", color="white",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="#8c564b", edgecolor="white", linewidth=1.5))
ax.add_patch(FancyArrowPatch((13.9, 4.65), (14.0, 3.5),
                             arrowstyle="->,head_width=0.2,head_length=0.12",
                             color="#888888", linewidth=1.2))
ax.add_patch(FancyArrowPatch((13.9, 1.95), (14.0, 2.5),
                             arrowstyle="->,head_width=0.2,head_length=0.12",
                             color="#888888", linewidth=1.2))

ax.text(7.5, 0.7, "7 个自研工具全部零依赖实现（tree-sitter / 标准库 / 手写状态机）",
        ha="center", va="center", fontsize=10, color="#555555")

ax.set_title("自研工具链：从代码输入到 SARIF 导出的完整流水线", fontsize=15, fontweight="bold", pad=20)

fig.tight_layout()
fig.savefig("self_developed_tools.png", dpi=170)
print("已生成: self_developed_tools.png")
