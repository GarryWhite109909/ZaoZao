# -*- coding: utf-8 -*-
"""SFT strict_recall 与 CVE-fix recall 演进图（2026-09-03 统一重算口径）。

数据来源：素材库 1.1 层 2 / unified_score_table_20260903.md
（scripts/score_batch.py 按 2026-09-02 修正后答案统一重算）。
CVE-fix 答案未受 9/2 修正影响，该线与 8/18 口径一致。
重跑：python gen_sft_strict_evolution.py
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

VERSIONS = ["baseline", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9max"]
# 合成集 87 段 strict_recall（2026-09-03 统一重算，CWE 纠正口径）
STRICT_SYN = [0.848, 0.864, 0.833, 0.852, 0.836, 0.800, 0.767, 0.848, 0.754]
# CVE-fix recall（HF 管道；样本数 8/8/8/7/7/7/20/20/20）
CVE_RECALL = [0.375, 0.625, 0.500, 0.429, 0.571, 0.429, 0.800, 0.750, 0.950]
FAILED = {"v4", "v6", "v8"}

x = range(len(VERSIONS))

fig, ax = plt.subplots(figsize=(10, 5.4), dpi=200)

ax.plot(x, STRICT_SYN, "-o", color="#4A7FA5", lw=2, ms=7, zorder=3,
        label="合成集 strict_recall（CWE 纠正口径）")
ax.plot(x, CVE_RECALL, "-s", color="#6FA39B", lw=2, ms=7, zorder=3,
        label="CVE-fix recall（HF 管道）")

for i, v in enumerate(VERSIONS):
    failed = v in FAILED
    face = "#B8524A" if failed else "white"
    ax.plot(i, STRICT_SYN[i], "o", ms=7, mfc=face, mec="#4A7FA5", mew=1.6, zorder=4)
    ax.plot(i, CVE_RECALL[i], "s", ms=7, mfc=face, mec="#6FA39B", mew=1.6, zorder=4)
    # v7 两条线数值接近（0.767 vs 0.800），两枚标签分别让位避让
    s_off = (0, -16) if v == "v7" else (0, 9)
    c_off = (15, 5) if v == "v7" else (0, -14)
    ax.annotate(f"{STRICT_SYN[i]:.3f}", (i, STRICT_SYN[i]),
                textcoords="offset points", xytext=s_off, ha="center",
                fontsize=8.5, color="#3A6A8C")
    ax.annotate(f"{CVE_RECALL[i]:.3f}", (i, CVE_RECALL[i]),
                textcoords="offset points", xytext=c_off, ha="center",
                fontsize=8.5, color="#4E7A72")

# 失败版本标注：放在 v4 正下方，短箭头，不穿越图表
ax.annotate("v4/v6/v8 失败版本\n（泄漏/负迁移/FP 激增）",
            xy=(3, 0.429), xytext=(3, 0.28),
            fontsize=9, color="#B8524A", ha="center", va="top",
            arrowprops=dict(arrowstyle="->", color="#B8524A", lw=1.2,
                            connectionstyle="arc3,rad=0.1"))

# 在 v6 和 v8 加小标记，保持视觉一致性
ax.annotate("", xy=(5, 0.429), xytext=(5, 0.32),
            arrowprops=dict(arrowstyle="->", color="#B8524A", lw=1.2,
                            connectionstyle="arc3,rad=0.1"))
ax.annotate("", xy=(7, 0.750), xytext=(7, 0.64),
            arrowprops=dict(arrowstyle="->", color="#B8524A", lw=1.2,
                            connectionstyle="arc3,rad=0.1"))

ax.annotate("SFT 收益集中在判别与格式：\nCVE-fix recall 0.375→0.950",
            xy=(8, 0.950), xytext=(5.4, 0.925),
            fontsize=9.5, color="#A67214", ha="left",
            arrowprops=dict(arrowstyle="->", color="#D9962E", lw=1.2))
ax.annotate("归因编号未注入：strict 不升（0.848→0.754）",
            xy=(8, 0.754), xytext=(5.0, 0.55),
            fontsize=9.5, color="#3A6A8C", ha="left",
            arrowprops=dict(arrowstyle="->", color="#4A7FA5", lw=1.2))

ax.set_xticks(list(x))
ax.set_xticklabels(VERSIONS)
ax.set_ylim(0, 1.02)
ax.set_ylabel("recall")
ax.set_title("SFT 迭代演进：合成集 strict_recall（纠正口径）与 CVE-fix recall", fontsize=12)
ax.grid(axis="y", ls="--", alpha=0.35)
ax.legend(loc="lower left", fontsize=9.5, framealpha=0.9)

fig.text(0.12, 0.015,
         "口径：strict_recall = CWE 纠正口径（normalizer + evidence 守卫 + 父子族匹配），分母 tp+fn；"
         "CVE-fix 样本数 8→7（v4~v6 清洗）→20（v7 扩集）；数据 2026-09-03 统一重算（score_batch.py）",
         fontsize=8, color="#7C8B96")

fig.tight_layout(rect=(0, 0.045, 1, 1))
out = Path(__file__).with_name("sft_strict_recall_evolution.png")
fig.savefig(out)
print(f"saved: {out}")
