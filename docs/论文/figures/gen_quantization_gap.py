# -*- coding: utf-8 -*-
"""量化缺口对比图（2026-08-20 重绘，修正 Ollama 未标注 combined 的问题）。

数据来源：素材库 1.1.3 量化缺口诊断表（v9max，CWE 纠正口径）：
  - 合成集 87：HF NF4+FP16 LoRA recall 1.000 / FPR 0.423 / acc 0.874
               Ollama Q4_K_M combined recall 0.951 / FPR 0.077 / acc 0.943
  - CVE-fix 20：HF 0.950；Ollama base 0.789；Ollama combined 0.750
重跑：AI 环境 python gen_quantization_gap.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

# ============ 左图：合成集 87（recall + FPR，HF vs Ollama combined） ============
x = np.arange(3)
width = 0.35

# 左图柱状：HF 与 Ollama 的 recall / FPR
left_pipes = ["HF NF4+FP16\nLoRA", "Ollama Q4_K_M\ncombined"]
left_recall = [1.000, 0.951]
left_fpr = [0.423, 0.077]

bars1 = ax1.bar(x[:2] - width / 2, left_recall, width, label="recall",
                color="#1f77b4", edgecolor="#333333", linewidth=0.8)
bars2 = ax1.bar(x[:2] + width / 2, left_fpr, width, label="FPR",
                color="#d62728", edgecolor="#333333", linewidth=0.8)

for b, v in zip(bars1, left_recall):
    ax1.text(b.get_x() + b.get_width() / 2, v + 0.02, f"{v:.3f}", ha="center",
             va="bottom", fontsize=10, fontweight="bold", color="#1f77b4")
for b, v in zip(bars2, left_fpr):
    ax1.text(b.get_x() + b.get_width() / 2, v + 0.02, f"{v:.3f}", ha="center",
             va="bottom", fontsize=10, fontweight="bold", color="#d62728")

ax1.set_xticks(x[:2])
ax1.set_xticklabels(left_pipes, fontsize=11)
ax1.set_ylim(0, 1.2)
ax1.set_title("合成集 87 段：两种 4-bit 管道", fontsize=14, fontweight="bold")
ax1.set_ylabel("指标值")
ax1.legend(loc="upper right")
ax1.grid(axis="y", alpha=0.25)
# 关键结论标注
ax1.text(1, 1.05, "recall 1.000→0.951\n（量化噪声影响存在性判别）", ha="center", va="bottom",
         fontsize=9, color="#1f77b4")
ax1.text(1, 0.45, "FPR 42.3%→7.7%\n（合并量化抹平过度敏感模式）", ha="center", va="bottom",
         fontsize=9, color="#d62728")

# ============ 右图：CVE-fix 20（recall，HF vs Ollama base vs combined） ============
right_pipes = ["HF NF4+FP16\nLoRA", "Ollama Q4_K_M\nbase", "Ollama Q4_K_M\ncombined"]
right_recall = [0.950, 0.789, 0.750]

bars3 = ax2.bar(np.arange(3), right_recall, width=0.5,
                color=["#2ca02c", "#ff7f0e", "#9467bd"], edgecolor="#333333", linewidth=0.8)
for b, v in zip(bars3, right_recall):
    ax2.text(b.get_x() + b.get_width() / 2, v + 0.02, f"{v:.3f}", ha="center",
             va="bottom", fontsize=10, fontweight="bold", color="#333333")

ax2.set_xticks(np.arange(3))
ax2.set_xticklabels(right_pipes, fontsize=11)
ax2.set_ylim(0, 1.15)
ax2.set_title("CVE-fix 20 段：量化缺口", fontsize=14, fontweight="bold")
ax2.set_ylabel("recall")
ax2.grid(axis="y", alpha=0.25)
ax2.text(0.5, 1.0, "HF 95% vs Ollama 75~79%\nLoRA 信号被整体量化抹平", ha="center", va="bottom",
         fontsize=9, color="#2ca02c", fontweight="bold")

# 总标题与结论
fig.suptitle("量化缺口：HF（NF4+FP16 LoRA 增量叠加）vs Ollama（Q4_K_M 合并后整体量化）",
             fontsize=15, fontweight="bold", y=1.0)
fig.text(0.5, -0.02,
         "两种 4-bit 量化管道的差异，不是“量化 vs 未量化”。CVE-fix 上 combined（0.750）优势不迁移到真实 CVE（低于 base 0.789）。",
         ha="center", va="top", fontsize=10, color="#555555")

fig.tight_layout()
OUT = Path(__file__).resolve().parent / "quantization_gap.png"
fig.savefig(OUT, dpi=170, bbox_inches="tight")
print(f"已生成: {OUT}")
