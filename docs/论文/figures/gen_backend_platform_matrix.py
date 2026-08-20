# -*- coding: utf-8 -*-
"""后端平台支持矩阵图（2026-08-20）。

重跑：AI 环境 python gen_backend_platform_matrix.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

from pathlib import Path

# 行：后端-平台组合；列：纯硬件能力
backends = ["Ollama", "Transformers\n(Windows)", "Transformers\n(Linux)", "LlamaCPP\n(Linux)", "LlamaCPP\n(Windows)", "vLLM"]
columns = ["NVIDIA CUDA", "RTX 50 系", "AMD ROCm", "Apple Silicon", "CPU only"]

# 编码：2=原生支持，1=需额外配置，0=不支持，-1=不适用（该平台无此硬件）
matrix = np.array([
    [ 2,  2,  2,  2,  2],  # Ollama
    [ 2,  1,  0, -1,  2],  # Transformers Windows
    [ 2,  2,  1,  1,  2],  # Transformers Linux
    [ 2,  2,  2,  2,  2],  # LlamaCPP Linux
    [ 2,  0,  0, -1,  2],  # LlamaCPP Windows
    [ 2,  2,  0,  0,  0],  # vLLM
])

fig, ax = plt.subplots(figsize=(11, 6.5))

# 自定义颜色：-1 用浅灰，0 红，1 橙，2 绿
cmap = plt.cm.colors.ListedColormap(["#e0e0e0", "#d62728", "#ffbb78", "#2ca02c"])
# imshow 需要把 -1,0,1,2 映射到 0,1,2,3
im = ax.imshow(matrix + 1, cmap=cmap, aspect="auto", vmin=0, vmax=3)

ax.set_xticks(np.arange(len(columns)))
ax.set_yticks(np.arange(len(backends)))
ax.set_xticklabels(columns, fontsize=10)
ax.set_yticklabels(backends, fontsize=10)

# 单元格文字
labels = {2: "支持", 1: "需配置", 0: "不支持", -1: "N/A"}
for i in range(len(backends)):
    for j in range(len(columns)):
        val = matrix[i, j]
        if val == -1:
            color = "#888888"
        elif val == 1:
            color = "#333333"
        else:
            color = "white"
        ax.text(j, i, labels[val], ha="center", va="center", fontsize=11, color=color, fontweight="bold")

ax.set_title("多后端 × 多平台支持矩阵（按后端-平台组合 × 硬件能力）",
             fontsize=14, fontweight="bold", pad=15)

from matplotlib.patches import Patch
legend = [
    Patch(color="#2ca02c", label="原生支持"),
    Patch(color="#ffbb78", label="需额外配置"),
    Patch(color="#d62728", label="不支持"),
    Patch(color="#e0e0e0", label="不适用（该平台无此硬件）"),
]
ax.legend(handles=legend, loc="upper right", bbox_to_anchor=(1.32, 1))

fig.tight_layout()
OUT = Path(__file__).resolve().parent / "backend_platform_matrix.png"
fig.savefig(OUT, dpi=170)
print(f"已生成: {OUT}")
