# -*- coding: utf-8 -*-
"""数据版本血缘图（2026-09-03 更新，补 α0.6 冻结节点）。

数据来源：素材库 1.1 层 2 各版本数据量 + 8.2 数据血缘时间轴 + PPT价值话语库纠偏表。
重跑：python gen_data_lineage.py

图注要点：
  - 数据链：v2→v3→v4(废弃)→v5→v6(失败)→v7→v8(失败)→v9→v9max→α0→α0.5→α0.6(冻结待训)
  - 绿色柱 = 云端蒸馏突破（v9max），紫色柱 = α0 系列已训（α0.5 为当前已训主线），
    浅紫柱 = α0.6（v2_15，10167 条，2026-09-02 冻结，数据就绪待训）
  - v4/v6/v8 红色标记（失败/废弃）
"""

from pathlib import Path

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
    ("α0.5", 7972, False),    # 当前已训主线（紫色）
    ("α0.6", 10167, False),   # v2_15 已冻结待训（浅紫）
]

fig, ax = plt.subplots(figsize=(15, 6.2))

labels = [v[0] for v in VERSIONS]
sizes = [v[1] for v in VERSIONS]
colors = []
for name, size, bad in VERSIONS:
    if bad:
        colors.append("#B8524A")          # 失败/废弃：红
    elif name == "v9max":
        colors.append("#6FA39B")          # 云端蒸馏突破：绿
    elif name in ("α0", "α0.5"):
        colors.append("#35608A")          # α0 系列已训：紫
    elif name == "α0.6":
        colors.append("#A8C0D8")          # 数据就绪待训：浅紫
    else:
        colors.append("#4A7FA5")          # 本地迭代：蓝

bars = ax.bar(labels, sizes, color=colors, width=0.62, edgecolor="white", linewidth=0.6)

# 柱顶标注数据量
for bar, size in zip(bars, sizes):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 90,
            f"{size}", ha="center", va="bottom", fontsize=10, fontweight="bold")

# 标注——放在空白区，避免遮挡柱顶数字
ax.annotate("云端蒸馏突破\n（双模型 API，约 100 元）", xy=(8, 7692), xytext=(7.2, 9400),
            ha="center", fontsize=10, color="#4E7A72", fontweight="bold",
            arrowprops=dict(arrowstyle="->", color="#6FA39B"))
ax.annotate("α0.5 两阶段（当前已训主线）", xy=(10, 7972), xytext=(9.2, 10400),
            ha="center", fontsize=10, color="#35608A", fontweight="bold",
            arrowprops=dict(arrowstyle="->", color="#35608A"))
ax.annotate("α0.6 已冻结待训（v2_15，09-02）", xy=(11, 10167), xytext=(10.1, 11200),
            ha="center", fontsize=10, color="#4A7FA5", fontweight="bold",
            arrowprops=dict(arrowstyle="->", color="#A8C0D8"))

ax.set_ylabel("训练数据量（条）")
ax.set_title("数据版本血缘：914 手写 → 蒸馏 7692 → α0.5 两阶段 7972 → α0.6 10167（冻结待训）",
             fontsize=14, fontweight="bold")
ax.set_ylim(0, 11800)
ax.grid(axis="y", alpha=0.25)

# 图例
from matplotlib.patches import Patch
legend = [
    Patch(color="#4A7FA5", label="本地手写迭代（v2~v9）"),
    Patch(color="#6FA39B", label="云端蒸馏突破（v9max）"),
    Patch(color="#35608A", label="α0 系列已训（α0 / α0.5）"),
    Patch(color="#A8C0D8", label="α0.6（数据冻结待训）"),
    Patch(color="#B8524A", label="失败 / 废弃（v4 泄漏 / v6 负迁移 / v8 FP 激增）"),
]
ax.legend(handles=legend, loc="upper left", fontsize=9, framealpha=0.9)

fig.tight_layout()
fig.savefig(Path(__file__).with_name("data_lineage.png"), dpi=170)
print("已生成: data_lineage.png")
