# -*- coding: utf-8 -*-
"""自研工具链关系图（2026-08-20 重构版：消除扇出扇入交叉线）。

重构要点（解决"线条、构图混乱"）：
- 主流程一排等高横向流水：代码输入 → TaintTracker → Prefilter → CodeSlicer → LLM
- 三个后处理工具（CWE Normalizer / LineNormalizer / FixVerifier）排在 LLM 右下方一列，
  左边缘对齐，用一根公共竖直母线实现"1 入 3 出"，不再多条斜线扇出交叉
- SARIF 设为覆盖后处理三行高度的竖向终端框，三条短横线分别从各自 cy 进入 → 无汇聚交叉
- 所有连线横平竖直，无斜线、无穿过无关框体

重跑：AI 环境 cd figures && python gen_self_developed_tools.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from pathlib import Path

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, ax = plt.subplots(figsize=(14, 6))
ax.set_xlim(0, 14)
ax.set_ylim(0, 6)
ax.axis("off")

ax.set_title("自研工具链：从代码输入到 SARIF 导出的完整流水线",
             fontsize=15, fontweight="bold", pad=16, color="#1a1a1a")


# ---------- 辅助函数 ----------
def make_box(ax, x, y, w, h, title, subtitle, facecolor, title_fs=11, sub_fs=7.5):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.05,rounding_size=0.12",
                                facecolor=facecolor, edgecolor=facecolor, linewidth=1.4, alpha=0.95))
    cx, cy = x + w / 2, y + h / 2
    ax.text(cx, cy + 0.10, title, ha="center", va="center",
            fontsize=title_fs, fontweight="bold", color="white")
    ax.text(cx, cy - 0.18, subtitle, ha="center", va="center",
            fontsize=sub_fs, color="white", linespacing=1.12)
    return {"x": x, "y": y, "w": w, "h": h,
            "cx": cx, "cy": cy, "left": x, "right": x + w,
            "top": y + h, "bottom": y}


def arr(ax, x1, y1, x2, y2, color="#555555", lw=1.8, head=True):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                                 arrowstyle="->,head_width=0.25,head_length=0.15" if head
                                            else "-",
                                 color=color, linewidth=lw,
                                 connectionstyle="arc3,rad=0"))


# ---------- 主流程（同一横排，等高） ----------
MAIN_Y, MAIN_H = 3.6, 1.4
inp = make_box(ax, 0.3, MAIN_Y, 1.1, MAIN_H, "代码输入", "", "#8e8e93")
tt  = make_box(ax, 1.8, MAIN_Y, 1.6, MAIN_H, "TaintTracker", "污点分析\nsource→sink", "#1f77b4")
pf  = make_box(ax, 3.8, MAIN_Y, 1.6, MAIN_H, "Prefilter", "预筛候选\n安全/漏洞特征", "#ff7f0e")
cs  = make_box(ax, 5.8, MAIN_Y, 1.6, MAIN_H, "CodeSlicer", "长文件切片\n≥150 行按函数切", "#2ca02c")
llm = make_box(ax, 7.8, MAIN_Y, 1.6, MAIN_H, "LLM", "封闭裁决\n自一致率置信度", "#9467bd")

# 主流程箭头（水平平行）
for src, dst in [(inp, tt), (tt, pf), (pf, cs), (cs, llm)]:
    arr(ax, src["right"], src["cy"], dst["left"], dst["cy"])

# ---------- 后处理工具（LLM 右下方一列，左边缘对齐 = x0） ----------
POST_X, POST_LEFT = 9.6, 9.8
p_boxes = [
    make_box(ax, POST_LEFT, 3.8, 2.2, 0.9, "CWE Normalizer", "编号纠正 · 零 token", "#17becf", 9, 6.5),
    make_box(ax, POST_LEFT, 2.6, 2.2, 0.9, "LineNormalizer", "行号锚定 · 反向定位", "#17becf", 9, 6.5),
    make_box(ax, POST_LEFT, 1.4, 2.2, 0.9, "FixVerifier", "修复建议 · 语法校验", "#17becf", 9, 6.5),
]
# 公共竖直母线（x=POST_X），上端接 LLM，向下分到三个工具
bus_top = p_boxes[0]["cy"]      # 4.25
bus_bottom = p_boxes[2]["cy"]   # 1.85
# LLM → 母线顶端
arr(ax, llm["right"], bus_top, POST_X, bus_top, color="#888888", lw=1.5)
# 母线竖直段（无箭头）
arr(ax, POST_X, bus_top, POST_X, bus_bottom, color="#888888", lw=1.5, head=False)
# 母线 → 各工具（右向短箭头）
for pb in p_boxes:
    arr(ax, POST_X, pb["cy"], POST_LEFT, pb["cy"], color="#888888", lw=1.5)

# ---------- ExternalScanner（唯一第三方工具封装层，并行预筛） ----------
ext = make_box(ax, 1.8, 1.6, 5.6, 1.0, "ExternalScanner",
               "封装 Bandit / Semgrep / Gitleaks / Trivy 等第三方工具\n作为 LLM 并行预筛输入（唯一非零依赖）",
               "#bcbd22", 10, 6.5)
# ExternalScanner → LLM（虚线，表示辅助输入）
ax.add_patch(FancyArrowPatch((ext["right"], ext["cy"]), (llm["left"], llm["bottom"]),
                             arrowstyle="->,head_width=0.25,head_length=0.15",
                             color="#888888", linewidth=1.5, ls="--",
                             connectionstyle="arc3,rad=0"))

# ---------- SARIF 终端（竖向，覆盖三个工具行高，三条短横线进入，不汇聚） ----------
out = make_box(ax, 12.6, 1.4, 1.1, 3.5, "SARIF", "导出", "#8c564b", 12, 8)
for pb in p_boxes:
    arr(ax, pb["right"], pb["cy"], out["left"], pb["cy"], color="#888888", lw=1.5)

# ---------- 底部说明 ----------
ax.text(7.0, 0.55, "8 个工具：7 个零依赖自研（tree-sitter / 标准库 / 手写状态机）+ ExternalScanner（第三方工具封装层）",
        ha="center", va="center", fontsize=10, color="#555555")

fig.tight_layout()
OUT = Path(__file__).resolve().parent / "self_developed_tools.png"
fig.savefig(OUT, dpi=170)
print(f"已生成: {OUT}")