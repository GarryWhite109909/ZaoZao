# -*- coding: utf-8 -*-
"""2.5 代信任层图 v2.1：大字号 + 自动缩字。

画布 12.45×8.0in，与 PPT 相框 7.78×5.00 同比例；正文有效 ≈10pt。
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

W, H = 12.45, 8.0
DPI = 200
fig, ax = plt.subplots(figsize=(W, H), dpi=DPI)
ax.set_xlim(0, W)
ax.set_ylim(0, H)
ax.set_position([0, 0, 1, 1])
ax.axis("off")
renderer = fig.canvas.get_renderer()
PXU = DPI


def _fit(t, inner_units):
    max_px = inner_units * PXU
    ext = t.get_window_extent(renderer=renderer)
    if ext.width > max_px:
        t.set_fontsize(max(9, t.get_fontsize() * max_px / ext.width * 0.98))


ax.set_title("2.5 代信任层：统计门控 + 因果门控 + 确定性证据门 + 信任分级回填",
             fontsize=23, fontweight="bold", pad=14, color="#1a1a1a")


def layer_box(x, y, w, h, title, lines, color, fs=15, title_fs=17, pitch=0.34):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.10",
                                facecolor=color, edgecolor=color, linewidth=1.6, alpha=0.96))
    inner = w - 0.2
    t = ax.text(x + w / 2, y + h - 0.36, title, ha="center", va="center",
                fontsize=title_fs, fontweight="bold", color="white")
    _fit(t, inner)
    for i, line in enumerate(lines):
        t = ax.text(x + w / 2, y + h - 0.80 - i * pitch, line, ha="center", va="center",
                    fontsize=fs, color="white")
        _fit(t, inner)


def small_box(x, y, w, h, text, color, fs=16):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                                facecolor=color, edgecolor=color, linewidth=1.2, alpha=0.95))
    t = ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
                fontsize=fs, fontweight="bold", color="white", linespacing=1.25)
    _fit(t, w - 0.2)


def arr(x1, y1, x2, y2, color="#4a4a4a", lw=1.8):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                                 arrowstyle="->,head_width=0.22,head_length=0.14",
                                 color=color, linewidth=lw))


small_box(0.15, 6.85, 3.55, 0.85,
          "Stage 2 LLM 裁决输出\nN 次采样 + source/sink 证据链", "#1565c0", fs=14.5)

layer_box(0.15, 5.20, 3.55, 1.40, "Layer 1 共形预测（统计门控）", [
    "标签条件分位数",
    "输出：{漏洞} / {安全} / {不确定}",
], "#2e7d32", fs=14.5, title_fs=16)

layer_box(0.15, 3.50, 3.55, 1.40, "Layer 2 反事实（因果门控）", [
    "sink 行内注入防御看是否翻转",
    "过滤过度自信的伪真",
], "#ef6c00", fs=14.5, title_fs=16)

layer_box(0.15, 1.80, 3.55, 1.40, "Layer 3 确定性证据门", [
    "sink 邻域防御签名 / 无入口拦截",
    "零 LLM 成本兜底：无证据不采信",
], "#6a1b9a", fs=14.5, title_fs=16)

small_box(4.15, 4.55, 4.05, 2.75,
          "信任分级 A–E（判定质量）\n"
          "━━━━━━━━━━\n"
          "A  判对且归因对 → 回填\n"
          "B  判对但归因错 → 只回填判定\n"
          "C  碰巧对 → 拦截不入池\n"
          "D  误报 → 抑制池\n"
          "E  漏报 → 无输出可回填\n"
          "置信门槛以下 → Review 转人工",
          "#1565c0", fs=14.5)

small_box(4.15, 1.30, 4.05, 2.35,
          "四重回填门控\n━━━━━━━━━━\n"
          "全票门槛  votes == N\n"
          "跨样本聚合  ≥2 独立文件\n"
          "双向可撤销 · 独立验证集",
          "#5e35b1", fs=15.5)

small_box(8.80, 5.30, 3.50, 1.05, "抑制池\nD / 高置信否定", "#c62828", fs=16)
small_box(8.80, 3.80, 3.55, 1.05, "人工复核\n低置信 Review（未达门槛）", "#ef6c00", fs=15)

small_box(4.15, 0.15, 4.05, 0.85, "信号回填\nA/B 通过门控 → 工具记忆", "#00838f", fs=15)

ax.text(10.55, 1.85,
        "2.5 代含义：\n统计门控与因果门控互补，\n后端过度自信时由确定性\n证据门兜底；所有门槛均\n为代码参数，非口头原则。",
        ha="center", va="center", fontsize=13, color="#4a4a4a", linespacing=1.5)

arr(1.93, 6.85, 1.93, 6.62)
arr(1.93, 5.20, 1.93, 4.92)
arr(1.93, 3.50, 1.93, 3.22)
arr(1.93, 1.80, 1.93, 1.52)
arr(1.93, 1.52, 3.88, 1.52)
arr(3.88, 1.52, 3.88, 6.00)
arr(3.88, 6.00, 4.13, 6.00)
arr(6.18, 4.55, 6.18, 3.67)
arr(8.22, 5.83, 8.78, 5.83, color="#c62828")
arr(8.22, 5.28, 8.50, 5.28)
arr(8.50, 5.28, 8.50, 4.33)
arr(8.50, 4.33, 8.78, 4.33, color="#ef6c00")
arr(6.18, 1.30, 6.18, 1.02)

OUT = Path(__file__).resolve().parent / "trust_layer_25_v2.png"
fig.savefig(OUT, dpi=DPI)
print(f"已生成: {OUT}")
