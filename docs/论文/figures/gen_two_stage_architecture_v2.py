# -*- coding: utf-8 -*-
"""两阶段架构图 v2.1：大字号 + 自动缩字（文字永不超出盒子）。

画布 11.5×7.2in，与 PPT 相框 7.94×4.97 同比例；正文目标有效 ≈10pt。
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, RegularPolygon
from pathlib import Path

matplotlib.use("Agg")
plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

W, H = 11.5, 7.2
DPI = 200
fig, ax = plt.subplots(figsize=(W, H), dpi=DPI)
ax.set_xlim(0, W)
ax.set_ylim(0, H)
ax.set_position([0, 0, 1, 1])
ax.axis("off")
renderer = fig.canvas.get_renderer()

T, TT = 16, 19
PXU = DPI  # 1 数据单位 = 1 英寸 = DPI 像素


def _fit(t, inner_units):
    """按盒子内宽缩字号。"""
    max_px = inner_units * PXU
    ext = t.get_window_extent(renderer=renderer)
    if ext.width > max_px:
        t.set_fontsize(max(9, t.get_fontsize() * max_px / ext.width * 0.98))


def box(x, y, w, h, title, lines, face, edge, tcolor, fs=T, title_fs=TT, pitch=0.30,
        t_off=0.36, l_off=0.74):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.10",
                                facecolor=face, edgecolor=edge, linewidth=1.8, alpha=0.97))
    inner = w - 0.22
    t = ax.text(x + w / 2, y + h - t_off, title, ha="center", va="center",
                fontsize=title_fs, fontweight="bold", color=tcolor)
    _fit(t, inner)
    for i, line in enumerate(lines):
        t = ax.text(x + w / 2, y + h - l_off - i * pitch, line, ha="center", va="center",
                    fontsize=fs, color=tcolor)
        _fit(t, inner)


def arrow(x1, y1, x2, y2, color="#555555", lw=1.8):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                                 arrowstyle="->,head_width=0.22,head_length=0.14",
                                 color=color, linewidth=lw))


def label(x, y, text, color="#444444", fs=15, bold=False):
    ax.text(x, y, text, ha="center", va="center", fontsize=fs, color=color,
            fontweight="bold" if bold else "normal")


ax.text(W / 2, 6.88, "当前 wave8 实际架构：两阶段骨架 + 2.5 代信任层 + 复核兜底",
        ha="center", va="center", fontsize=23, fontweight="bold", color="#222222")
label(9.62, 6.50, "wave8 = signal-feedback on · ctx16384", color="#7b1fa2", fs=13)

box(0.15, 4.0, 3.75, 2.15, "Stage 1：工具召回", [
    "Semgrep taint 模式（整文件）",
    "TaintTracker（自研 AST 污点）",
    "Prefilter（自研正则预筛）",
    "ExternalScanner（外部四类）",
    "↓ 合并去重 + CWE 归一",
], "#e8f4fd", "#1f77b4", "#1f77b4")

box(4.12, 4.0, 3.75, 2.15, "Stage 2：LLM 裁决", [
    "triage_train_aligned（训练对齐）",
    "has_vulnerability schema",
    "双格式解析 + 容错重试",
    "N=3 采样 → 自一致率置信度",
    "上下文：CodeSlicer 切片+污点链",
], "#fff3e0", "#ff7f0e", "#bf360c")

box(8.09, 4.0, 3.26, 2.15, "2.5 代信任层（廉价→昂贵）", [
    "① 确定性证据门：已防御/无入口",
    "② 共形预测：漏洞/安全/不确定",
    "③ 反事实验证：注入防御看翻转",
    "④ 信任分级 A–E → 回填/抑制",
], "#f3e5f5", "#7b1fa2", "#4a148c")

label(2.03, 6.55, "源代码输入", fs=16, bold=True)
arrow(2.03, 6.38, 2.03, 6.18)

dx, dy = 2.03, 3.3
ax.add_patch(RegularPolygon((dx, dy), numVertices=4, radius=0.52, orientation=0,
                            facecolor="#fff3cd", edgecolor="#f0ad4e", linewidth=2))
t = ax.text(dx, dy, "有候选？", ha="center", va="center", fontsize=15,
            fontweight="bold", color="#856404")
arrow(2.03, 4.0, 2.03, 3.84)

box(0.15, 1.15, 3.75, 1.5, "无候选分支（不直接放行）", [
    "默认 full_recheck 全量复核",
    "sampled 10% 抽样可配",
    "LLM 复核 → 全票判真才采信",
], "#d4edda", "#28a745", "#155724", fs=14, title_fs=16, pitch=0.30)
arrow(2.03, 2.78, 2.03, 2.67, color="#28a745")
label(4.30, 3.46, "是", fs=15)
label(1.42, 3.15, "否", fs=15)
arrow(2.52, 3.30, 5.99, 3.30)
arrow(5.99, 3.30, 5.99, 3.96)

box(4.12, 1.15, 3.75, 1.5, "聚合最终结论", [
    "confirmed_vulnerability → 漏洞",
    "review → 低置信转人工复核",
    "dismissed_safe → 确认安全",
], "#e3f2fd", "#1565c0", "#0d47a1", fs=14, title_fs=16, pitch=0.30)

arrow(7.87, 5.08, 8.06, 5.08)
arrow(9.72, 4.0, 9.72, 1.9, color="#7b1fa2")
arrow(9.72, 1.9, 7.90, 1.9, color="#7b1fa2")
arrow(3.90, 1.9, 4.09, 1.9, color="#28a745")

box(4.12, 0.10, 3.75, 0.95, "兜底复核（防盲区静默放行）", [
    "全部候选否决 → 强制全文件 LLM 复核",
], "#ffebee", "#c62828", "#b71c1c", fs=13, title_fs=15, pitch=0.24, t_off=0.28, l_off=0.56)
arrow(5.99, 1.15, 5.99, 1.07)

box(8.09, 0.10, 3.26, 0.95, "输出", [
    "漏洞判定 + CWE + 修复建议",
    "（或 review / safe）",
], "#ffffff", "#333333", "#333333", fs=13, title_fs=15, pitch=0.24, t_off=0.28, l_off=0.56)
arrow(7.90, 0.575, 8.06, 0.575)

OUT = Path(__file__).resolve().parent / "two_stage_architecture_v2.png"
fig.savefig(OUT, dpi=DPI)
print(f"已生成: {OUT}")
