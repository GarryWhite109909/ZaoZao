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

# 行：后端；列：平台/硬件
backends = ["Ollama", "Transformers\n(Win)", "Transformers\n(Linux)", "LlamaCPP\n(Linux)", "LlamaCPP\n(Win)", "vLLM"]
columns = ["Win CUDA", "Win RTX50", "Linux CUDA", "Linux RTX50", "AMD ROCm", "Apple", "CPU"]

# 编码：2=原生支持，1=需额外配置，0=不支持
matrix = np.array([
    [2, 2, 2, 2, 2, 2, 2],  # Ollama
    [2, 1, 2, 2, 0, 1, 2],  # Transformers Win
    [0, 0, 2, 2, 1, 1, 2],  # Transformers Linux
    [0, 0, 2, 2, 2, 2, 2],  # LlamaCPP Linux
    [2, 0, 0, 0, 0, 0, 2],  # LlamaCPP Win
    [0, 0, 2, 2, 0, 0, 0],  # vLLM
])

fig, ax = plt.subplots(figsize=(12, 6))
cmap = plt.cm.colors.ListedColormap(["#d62728", "#ffbb78", "#2ca02c"])
im = ax.imshow(matrix, cmap=cmap, aspect="auto", vmin=0, vmax=2)

ax.set_xticks(np.arange(len(columns)))
ax.set_yticks(np.arange(len(backends)))
ax.set_xticklabels(columns, fontsize=10)
ax.set_yticklabels(backends, fontsize=10)

# 单元格文字
labels = {2: "支持", 1: "需配置", 0: "不支持"}
for i in range(len(backends)):
    for j in range(len(columns)):
        val = matrix[i, j]
        color = "white" if val != 1 else "#333333"
        ax.text(j, i, labels[val], ha="center", va="center", fontsize=11, color=color, fontweight="bold")

ax.set_title("多后端 × 多平台支持矩阵", fontsize=15, fontweight="bold", pad=15)

from matplotlib.patches import Patch
legend = [
    Patch(color="#2ca02c", label="原生支持"),
    Patch(color="#ffbb78", label="需额外配置"),
    Patch(color="#d62728", label="不支持"),
]
ax.legend(handles=legend, loc="upper right", bbox_to_anchor=(1.25, 1))

fig.tight_layout()
fig.savefig("backend_platform_matrix.png", dpi=170)
print("已生成: backend_platform_matrix.png")
