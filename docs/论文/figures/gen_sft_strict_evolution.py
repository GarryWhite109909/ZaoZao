# -*- coding: utf-8 -*-
"""SFT strict_recall 与 CVE-fix recall 演进图（2026-08-18 CWE 纠正口径）。

数据来源：素材库 1.1.2 / 1.1.4（recompute_strict_metrics.py 重算值）。
重跑：python gen_sft_strict_evolution.py
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

VERSIONS = ["baseline", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9max"]
# 合成集 87 段 strict_recall（CWE 纠正口径）
STRICT_SYN = [0.705, 0.738, 0.738, 0.656, 0.754, 0.689, 0.667, 0.770, 0.656]
# CVE-fix recall（HF 管道；样本数 8/8/8/7/7/7/20/20/20）
CVE_RECALL = [0.375, 0.625, 0.500, 0.429, 0.571, 0.429, 0.800, 0.750, 0.950]
FAILED = {"v4", "v6", "v8"}

x = range(len(VERSIONS))

fig, ax = plt.subplots(figsize=(10, 5.4), dpi=200)

ax.plot(x, STRICT_SYN, "-o", color="#1f6feb", lw=2, ms=7, zorder=3,
        label="合成集 strict_recall（CWE 纠正口径）")
ax.plot(x, CVE_RECALL, "-s", color="#d29922", lw=2, ms=7, zorder=3,
        label="CVE-fix recall（HF 管道）")

for i, v in enumerate(VERSIONS):
    failed = v in FAILED
    face = "#d64545" if failed else "white"
    ax.plot(i, STRICT_SYN[i], "o", ms=7, mfc=face, mec="#1f6feb", mew=1.6, zorder=4)
    ax.plot(i, CVE_RECALL[i], "s", ms=7, mfc=face, mec="#d29922", mew=1.6, zorder=4)
    ax.annotate(f"{STRICT_SYN[i]:.3f}", (i, STRICT_SYN[i]),
                textcoords="offset points", xytext=(0, 9), ha="center",
                fontsize=8.5, color="#1f6feb")
    ax.annotate(f"{CVE_RECALL[i]:.3f}", (i, CVE_RECALL[i]),
                textcoords="offset points", xytext=(0, -14), ha="center",
                fontsize=8.5, color="#9a6700")

ax.annotate("v4/v6/v8 失败版本（泄漏/负迁移/FP 激增）",
            xy=(3, 0.429), xytext=(1.2, 0.14),
            fontsize=9, color="#d64545",
            arrowprops=dict(arrowstyle="->", color="#d64545", lw=1.2))

ax.annotate("SFT 收益集中在判别与格式：\nCVE-fix recall 0.375→0.950",
            xy=(8, 0.950), xytext=(5.6, 0.90),
            fontsize=9.5, color="#9a6700", ha="left",
            arrowprops=dict(arrowstyle="->", color="#9a6700", lw=1.2))
ax.annotate("归因编号未注入：strict 持平（0.705→0.656）",
            xy=(8, 0.656), xytext=(5.2, 0.50),
            fontsize=9.5, color="#1f6feb", ha="left",
            arrowprops=dict(arrowstyle="->", color="#1f6feb", lw=1.2))

ax.set_xticks(list(x))
ax.set_xticklabels(VERSIONS)
ax.set_ylim(0, 1.02)
ax.set_ylabel("recall")
ax.set_title("SFT 迭代演进：合成集 strict_recall（纠正口径）与 CVE-fix recall", fontsize=12)
ax.grid(axis="y", ls="--", alpha=0.35)
ax.legend(loc="upper left", fontsize=9.5, framealpha=0.9)

fig.text(0.12, 0.015,
         "口径：strict_recall = CWE 纠正口径（normalizer + evidence 守卫 + 父子族匹配），分母 tp+fn；"
         "CVE-fix 样本数 8→7（v4~v6 清洗）→20（v7 扩集）；数据 2026-08-18 统一重算",
         fontsize=8, color="#666")

fig.tight_layout(rect=(0, 0.045, 1, 1))
out = Path(__file__).with_name("sft_strict_recall_evolution.png")
fig.savefig(out)
print(f"saved: {out}")
