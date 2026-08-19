# -*- coding: utf-8 -*-
"""数据版本血缘图（2026-08-20 重绘，补 α0.5）。

数据来源：素材库 1.1.2 各版本数据量 + 8.2 数据血缘时间轴。
重跑：AI 环境 python gen_data_lineage.py

图注要点：
  - 数据链：v2→v3→v4(废弃)→v5→v6(失败)→v7→v8(失败)→v9→v9max→α0→α0.5
  - 绿色柱 = 云端蒸馏突破（v9max），紫色柱 = α0 系列（α0.5 为当前训练主线）
  - v4/v6/v8 红色标记（失败/废弃）
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

# (版本, 数据量, 是否失败/废弃)
VERSIONS = [
    ("v2", 823, False),
    ("v3", 832, False),
    ("v4", 839, True),   # 训练-测试泄漏废弃
    ("v5", 749, False),
    ("v6", 755, True),   # 负迁移失败
    ("v7", 799, False),
    ("v8", 819, True),   # FP 激增失败
    ("v9", 914, False),
    ("v9max", 7692, False),   # 云端蒸馏突破（绿色）
    ("α0", 8616, False),
    ("α0.5", 7972, False),    # 当前训练主线（紫色）
]

fig, ax = plt.subplots(figsize=(15, 6.2))

labels = [v[0] for v in VERSIONS]
sizes = [v[1] for v in VERSIONS]
colors = []
for name, size, bad in VERSIONS:
    if bad:
        colors.append("#d62728")          # 失败/废弃：红
    elif name == "v9max":
        colors.append("#2ca02c")          # 云端蒸馏突破：绿
    elif name in ("α0", "α0.5"):
        colors.append("#9467bd")          # α0 系列：紫
    else:
        colors.append("#1f77b4")          # 本地迭代：蓝

bars = ax.bar(labels, sizes, color=colors, width=0.62, edgecolor="white", linewidth=0.6)

# 柱顶标注数据量
for bar, size in zip(bars, sizes):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 80,
            f"{size}", ha="center", va="bottom", fontsize=10, fontweight="bold")

# 标注
ax.annotate("云端蒸馏突破\n（双模型 API，约 100 元）", xy=(8, 7692), xytext=(8, 8000),
            ha="center", fontsize=10, color="#2ca02c", fontweight="bold")
ax.annotate("当前训练主线\n（两阶段）", xy=(10, 7972), xytext=(10, 9100),
            ha="center", fontsize=10, color="#9467bd", fontweight="bold",
            arrowprops=dict(arrowstyle="->", color="#9467bd"))

ax.set_ylabel("训练数据量（条）")
ax.set_title("数据版本血缘：914 条手写 → 蒸馏 7692 条 → α0.5 两阶段 7972 条", fontsize=14, fontweight="bold")
ax.set_ylim(0, 10500)
ax.grid(axis="y", alpha=0.25)

# 图例
from matplotlib.patches import Patch
legend = [
    Patch(color="#1f77b4", label="本地手写迭代（v2~v9）"),
    Patch(color="#2ca02c", label="云端蒸馏突破（v9max）"),
    Patch(color="#9467bd", label="α0 系列（α0 / α0.5）"),
    Patch(color="#d62728", label="失败 / 废弃（v4 泄漏 / v6 负迁移 / v8 FP 激增）"),
]
ax.legend(handles=legend, loc="upper left", fontsize=9, framealpha=0.9)

fig.tight_layout()
fig.savefig(__file__.rsplit("/", 1)[0] + "/data_lineage.png", dpi=170)
print("已生成: data_lineage.png")
