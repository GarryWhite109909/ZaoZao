# -*- coding: utf-8 -*-
"""2.5 代信任层架构图（2026-08-20 彻底重排版）。

修复：
- 删除从信任分级向右再向左横穿全图到抑制池的荒谬路径
- 底部输出框与上层框在 x 方向严格错开，消除重叠
- D 从信任分级内正确行高引出，走直角折线到同侧抑制池
- 所有连线横平竖直，不穿过无关框体

重跑：AI 环境 cd figures && python gen_trust_layer_25.py
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, ax = plt.subplots(figsize=(14, 9))
ax.set_xlim(0, 14)
ax.set_ylim(0, 9)
ax.axis("off")

ax.set_title("2.5 代信任层：统计门控 + 因果门控 + 确定性证据门 + 信任分级回填",
             fontsize=15, fontweight="bold", pad=18, color="#1a1a1a")


# ---------- 辅助函数 ----------
def layer_box(ax, x, y, w, h, title, lines, facecolor, edgecolor, title_fs=11, text_fs=8.5):
    patch = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12",
                           facecolor=facecolor, edgecolor=edgecolor, linewidth=1.6, alpha=0.96)
    ax.add_patch(patch)
    ax.text(x + w / 2, y + h - 0.32, title, ha="center", va="center",
            fontsize=title_fs, fontweight="bold", color="white")
    for i, line in enumerate(lines):
        ax.text(x + w / 2, y + h - 0.72 - i * 0.32, line, ha="center", va="center",
                fontsize=text_fs, color="white", linespacing=1.2)
    return {"x": x, "y": y, "w": w, "h": h,
            "cx": x + w / 2, "cy": y + h / 2,
            "left": x, "right": x + w,
            "top": y + h, "bottom": y}


def small_box(ax, x, y, w, h, text, facecolor, text_color="white", fs=9):
    patch = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                           facecolor=facecolor, edgecolor=facecolor, linewidth=1.2, alpha=0.95)
    ax.add_patch(patch)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fs, fontweight="bold", color=text_color, linespacing=1.15)
    return {"x": x, "y": y, "w": w, "h": h,
            "cx": x + w / 2, "cy": y + h / 2,
            "left": x, "right": x + w,
            "top": y + h, "bottom": y}


def arr(ax, x1, y1, x2, y2, color="#4a4a4a", lw=1.4):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                                 arrowstyle="->,head_width=0.22,head_length=0.14",
                                 color=color, linewidth=lw,
                                 connectionstyle="arc3,rad=0"))


# ---------- 输入（与左栏 L1 对齐） ----------
inp = small_box(ax, 0.8, 8.0, 3.5, 0.6,
                "Stage 2 LLM 裁决输出\nN 次采样 + source/sink 证据链", "#1565c0", fs=9)

# ---------- 左栏：三层门控（垂直等距） ----------
l1 = layer_box(ax, 0.8, 6.3, 3.5, 1.2, "Layer 1  共形预测（统计门控）", [
    "标签条件分位数",
    "输出：{漏洞} / {安全} / {不确定}"
], "#2e7d32", "#2e7d32")

l2 = layer_box(ax, 0.8, 4.7, 3.5, 1.2, "Layer 2  反事实验证（因果门控）", [
    "sink 行内注入防御，观察裁决是否翻转",
    "过滤过度自信的伪真"
], "#ef6c00", "#ef6c00")

l3 = layer_box(ax, 0.8, 3.1, 3.5, 1.2, "Layer 3  确定性证据门（零 LLM 成本兜底）", [
    "sink 邻域防御签名 / 无外部输入入口拦截",
    "无 LLM 调用即可否决"
], "#6a1b9a", "#6a1b9a")

# ---------- 中间栏：信任分级（上） + 四重回填门控（下） ----------
# 信任分级内四行文字，从 top 向下排，行高约 0.32
# 行1(A) y≈7.48, 行2(B) y≈7.16, 行3(C/D) y≈6.84, 行4(Review) y≈6.52
tr = small_box(ax, 5.5, 5.8, 3.5, 2.0,
               "信任分级\n━━━━━━━━━━━━\n"
               "A  判定正确且编号正确\n"
               "B  判定正确但编号错误\n"
               "C/D  低置信 / 误报\n"
               "Review  未达门槛",
               "#1565c0", fs=9)

# 四重回填门控放在信任分级正下方，x 对齐
gt = small_box(ax, 5.5, 2.8, 3.5, 1.8,
               "四重回填门控\n━━━━━━━━━━━━\n"
               "全票门槛  votes == N\n"
               "跨样本聚合  ≥2 独立文件\n"
               "双向可撤销\n"
               "独立验证集门控",
               "#5e35b1", fs=9)

# ---------- 右侧输出框（与中间栏/左栏严格不重叠） ----------
# 抑制池接收 D，放在信任分级右侧同高处，避免长距离横穿
po = small_box(ax, 10.0, 6.2, 3.0, 0.8, "抑制池\nD / 高置信否定", "#c62828", fs=9)

# 人工复核接收 C/E/Review，放在抑制池下方，x 对齐
rw = small_box(ax, 10.0, 4.5, 3.0, 0.8, "人工复核\nC/E/Review", "#ef6c00", fs=9)

# 信号回填接收 A/B 经四重后的输出，放在四重正下方，x 对齐
fb = small_box(ax, 5.5, 0.3, 3.5, 0.7, "信号回填\nA/B 通过门控 → 工具记忆", "#00838f", fs=9)

# ---------- 连线（全部横平竖直） ----------
# 1. 输入 → L1（垂直）
arr(ax, inp["cx"], inp["bottom"], l1["cx"], l1["top"])

# 2. L1 → L2 → L3（垂直）
arr(ax, l1["cx"], l1["bottom"], l2["cx"], l2["top"])
arr(ax, l2["cx"], l2["bottom"], l3["cx"], l3["top"])

# 3. L3 → 信任分级（直角折线：右 → 中 → 上 → 左）
arr(ax, l3["right"], l3["cy"], 5.0, l3["cy"])       # 水平到中间栏左侧间隙
arr(ax, 5.0, l3["cy"], 5.0, tr["cy"])                # 垂直上升到信任分级 cy
arr(ax, 5.0, tr["cy"], tr["left"], tr["cy"])         # 水平进入信任分级

# 4. 信任分级 → 四重（垂直）
arr(ax, tr["cx"], tr["bottom"], gt["cx"], gt["top"])

# 5. 信任分级(D) → 抑制池（直角折线：右 → 同高 → 左进入）
# D 在信任分级内第三行，约 y = tr.top - 0.80 ≈ 6.80
d_y = tr["top"] - 0.80
arr(ax, tr["right"], d_y, po["left"], d_y)           # 水平直接进入抑制池左侧（同高）

# 6. 信任分级(C/E/Review) → 复核（直角折线：右 → 同高 → 左进入）
# C/E/Review 在第四行，约 y = tr.top - 1.12 ≈ 6.48
cer_y = tr["top"] - 1.12
arr(ax, tr["right"], cer_y, 9.5, cer_y)              # 水平向右到复核左侧间隙
arr(ax, 9.5, cer_y, 9.5, rw["cy"])                   # 垂直下降到复核 cy
arr(ax, 9.5, rw["cy"], rw["left"], rw["cy"])         # 水平进入复核左侧

# 7. 四重 → 回填（垂直）
arr(ax, gt["cx"], gt["bottom"], fb["cx"], fb["top"])

# ---------- 说明 ----------
ax.text(7.0, 0.08, "2.5 代含义：统计门控与因果门控互补，后端过度自信时由确定性证据门兜底；所有门槛均为代码参数，非口头原则。",
        ha="center", va="center", fontsize=9, color="#4a4a4a")

fig.tight_layout()
fig.savefig("trust_layer_25.png", dpi=170)
print("已生成: trust_layer_25.png")
