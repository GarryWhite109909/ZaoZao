#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HNCPC 比赛答辩 PPT 精简重建脚本（v2）
=====================================
输入原版：docs/论文/码安管家 —— LLM驱动的漏洞分析站.pptx（28 页）
输出精简：docs/论文/码安管家 —— LLM驱动的漏洞分析站_精简版19页.pptx

改造原则（2026-09-20）：
  1. 换轴：从"毕设答辩·方法论发现链"改为"比赛答辩·分类能力 + 硬结果"
  2. 分类总结：用「四层能力」做骨架（数据 / 工程 / 训练 / 实验），
     章节页明确宣告"本章讲第几层"，评委任何一页都知道进度
  3. 文字减量：每页一个主张句（主标题），页面最多 3 个支撑点，其余进口播稿
  4. 10 分钟节奏：19 页 = 封面 + 目录 + 4 层能力 + 结果 + 演示 + 收尾

实现方式：直接操作原 pptx 的 OOXML，**全量保留原有主题、母版、字体、配色**。
"""

import os
import re
import shutil
import sys

from pptx import Presentation

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pptutil import iter_shapes, replace_cross_run  # noqa: E402

# --------------------------------------------------------------------------
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DOCS = os.path.join(ROOT, "docs", "论文")
SRC = os.path.join(DOCS, "码安管家 —— LLM驱动的漏洞分析站.pptx")
DST = os.path.join(DOCS, "码安管家 —— LLM驱动的漏洞分析站_精简版19页.pptx")
BACKUP_DIR = os.path.join(DOCS, "_ppt_backup")

NS_R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"

# --------------------------------------------------------------------------
# 最终 19 页 = 原页码按此顺序
# --------------------------------------------------------------------------
KEEP_ORDER = [
    1,    # 1  封面
    2,    # 2  目录
    3,    # 3  章节页 01 · 研究背景
    4,    # 4  背景：漏洞量 7.4 倍
    6,    # 5  背景：四路线实测 ★"工具+模型都不够"的硬证据
    9,    # 6  章节页 · 四层能力（原 03 章）
    10,   # 7  ★分类总览：四层能力 + 元能力（全场支点）
    11,   # 8  第一层 · 数据可信
    14,   # 9  章节页 · 工程实现（原 04 章）
    15,   # 10 第二层 · 工程：总体架构
    16,   # 11 第二层 · 工程：Stage 1 四路召回
    17,   # 12 第二层 · 工程：Stage 2 封闭裁决
    18,   # 13 第二层 · 工程：2.5 代信任层
    20,   # 14 ★核心结果（8 指标 × 4 组态打分表）
    12,   # 15 第三层 · 训练策略
    13,   # 16 第四层 · 实验严谨
    19,   # 17 工程实现：自研工具链
    23,   # 18 章节页 · 系统演示
    25,   # 19 演示视频
]
DROP_PAGES = [5, 7, 8, 21, 22, 24, 26, 27, 28]   # 物理摘除
TOTAL = len(KEEP_ORDER)

# --------------------------------------------------------------------------
# 文字覆盖：(原页码, 原文本片段, 新文本)  支持跨 run 匹配
# 空字符串 new_text = 清空该段文字（用于删掉冗余副标题）
# --------------------------------------------------------------------------
# 队员署名（2026-09-20 定：新增谭依晴；署名顺序报名成功后不可更改）
TEAM = "白明耀、易卓玥、谭依晴"
TEAM_OLD = "白明耀、易卓玥"

OVERRIDES = [
    # ------ 封面：主张句换成三项硬指标 ------
    (1, "工具召回 × LLM 裁决的两阶段架构，",
        "工具召回 × LLM 裁决的两阶段架构"),
    (1, "与一套被六轮审计反复验证过的评估方法论",
        "召回率 100%（0 漏报）· 误报率 4.35% · 严格归因 0.923"),

    # ------ 目录：6 章压成 5 章，每章副标题给"分类" ------
    # 精简版已删「研究目标」与「未来规划」，目录对应两格改写为能力层与工程层
    (2, "研究目标", "能力总览"),
    (2, "从安全专用模型出发，探索、实践出演进路线",
        "数据 / 工程 / 训练 / 实验：四层可迁移能力，每层都有证据"),
    (2, "未来规划", "工程实现"),
    (2, "α0.6 开训、α1 偏好对齐、数据飞轮与发布",
        "全栈交付 · 跨平台 · 自研工具链 · 成本治理"),
    (2, "项目界面实拍与系统演示视频", "产品界面实拍与系统演示视频"),
    (2, "数据 · 训练 · 实验：三层可迁移能力",
        "数据 / 训练 / 实验三层，每层都有可复现的证据"),

    # ------ 章节页页脚导航条：把旧六章名改成精简版口径 ------
    # 导航条保留 6 格（改形状数量风险大），只改第 2、6 格的名称；
    # 第 2 格承 03 章「我们的价值」（三层能力），第 6 格承 04 章「项目的价值」（工程实现）
    (3, "02 研究目标", "02 能力总览"),
    (3, "06 未来规划", "06 工程实现"),
    (9, "02 研究目标", "02 能力总览"),
    (9, "06 未来规划", "06 工程实现"),
    (14, "02 研究目标", "02 能力总览"),
    (14, "06 未来规划", "06 工程实现"),
    (23, "02 研究目标", "02 能力总览"),
    (23, "06 未来规划", "06 工程实现"),

    # ------ P3 章节页 01 ------
    (3, "年披露漏洞逼近 5 万，人工审计追不上增长速度，单一工具也追不上漏洞的语义复杂度。",
        "年披露漏洞逼近 5 万，而现有工具在真实 CVE 上语焉不详——这就是我们的出发点。"),

    # ------ P6 四路线实测：把长句结论压短 ------
    (6, "工具负责找全 × 模型负责判准 | ——这正是本项目选择两阶段架构的直接实验依据",
        "工具负责找全 × 模型负责判准 —— 两阶段架构的直接实验依据"),

    # ------ P9 章节页：宣告"分类总览"是本章第一件事 ------
    (9, "比最终系统更可迁移的，是三层能力：数据 · 训练 · 实验",
        "比最终系统更可迁移的，是三层能力：数据 · 训练 · 实验\n"
        "本章先给全览，再逐层展开证据"),

    # ------ P10 总览页：口径是"三层"（页面只有数据/训练/实验三列），
    #       保持"三层"不动，标题也保持原长度，避免超宽溢出 ------
    (10, "三层可迁移能力：一套让“不可靠”变“可靠”的方法论",
         "三层可迁移能力：让「不可靠」变「可靠」的方法论"),

    # ------ P14 章节页：副标题压缩，避免文字溢出版心 ------
    (14, "上一章的三层能力，在本章物化成可运行的系统——",
         "三层能力，在本章物化成可运行的系统"),
    (14, "架构 · 结果 · 工程 · 成本：每一个结论背后，都有可运行的代码与可复现的实验",
         "架构 · 结果 · 工程 · 成本：每个结论背后都有可运行的代码与实验"),

    # ------ P15 架构页：标题给出主张 ------
    (15, "总体架构：工具召回 × LLM 裁决，信任层兜底",
         "总体架构 · 确定性工具召回 × LLM 封闭裁决，2.5 代信任层兜底"),

    # ------ P20 结果页：标题直接给结论（评委最想看的一页） ------
    (20, "核心结果：双口径下，两阶段+信任层全面优于纯 LLM",
         "核心结果 · 误报 -72%、召回升到 1.000、严格归因 0.774→0.923"),

    # ------ P23 章节页 05：给出演示时长，控场 ------
    (23, "软件「凿凿」实机运行：从粘贴代码到 SARIF 报告，每一个界面背后，都是刚才那套引擎在真实运行。",
         "软件「凿凿」实机运行（2 分 54 秒）：从粘贴代码到 SARIF 报告，每一个界面背后，都是刚才那套引擎在真实运行。"),
]

PAGE_NO_RE = re.compile(r"^\s*\d+\s*/\s*\d+\s*$")


def fit_team_author_box(prs):
    """
    封面「报告人」格：队员从 2 人变 3 人后，原文本框宽度只够放两个名字，
    会与右侧「指导教师」的姓名重叠。按实际字数把该框加宽、必要时缩字号。
    仅动报告人一栏，其余三栏不动。
    """
    from pptx.util import Pt

    slide = prs.slides[0]
    TITLES = {"报告人", "指导教师", "所在学院", "报告日期"}
    NAMES = ["白明耀", "易卓玥", "谭依晴", "陈纪友"]
    boxes = []
    for sh in iter_shapes(slide.shapes):
        if not sh.has_text_frame:
            continue
        t = sh.text_frame.text.strip()
        if t in TITLES:
            boxes.append((sh, t, sh.top))
        elif t and any(m in t for m in NAMES):
            boxes.append((sh, "VALUE", sh.top))

    # 找报告人那一栏（title=报告人 的 top，对应的 VALUE 框）
    title_top = next((top for _, t, top in boxes if t == "报告人"), None)
    if title_top is None:
        return "skip: 未找到报告人栏"
    name_sh = next((sh for sh, t, top in boxes
                    if t == "VALUE" and abs(top - title_top) < 600000), None)
    if name_sh is None:
        return "skip: 未找到报告人姓名框"

    txt = name_sh.text_frame.text.strip()
    n = len([c for c in txt if c == "、"]) + 1        # 人数

    right_limit = None
    for sh, t, top in boxes:
        if t == "指导教师":
            right_limit = sh.left

    # 优先保证字号不小于 11pt（与其余三栏接近）；放不下才逐级缩小
    avail = (right_limit - name_sh.left - 60000) if right_limit else None
    need_pt = 12
    est_emu = 0
    for pt in (12, 11, 10):
        # 每个中文名按 5 个全角宽估算，顿号 1 个全角；全角宽 ≈ 字号 * 12700
        est_emu = int((5 * n + (n - 1)) * pt * 12700 * 1.10)
        need_pt = pt
        if avail is None or est_emu <= avail:
            break

    new_w = max(name_sh.width, est_emu)
    if avail is not None:
        new_w = min(new_w, avail)

    name_sh.width = new_w
    for para in name_sh.text_frame.paragraphs:
        for run in para.runs:
            run.font.size = Pt(need_pt)
    return (f"报告人框 {n} 人：宽 {name_sh.width}，字号 {need_pt}pt，"
            f"右边距剩余 {right_limit - (name_sh.left + new_w) if right_limit else '?'}")


def renumber(prs, keep_order):
    mapping = {old: new for new, old in enumerate(keep_order, 1)}
    cnt = 0
    for old_no, new_no in mapping.items():
        slide = prs.slides[old_no - 1]
        for sh in iter_shapes(slide.shapes):
            if not sh.has_text_frame:
                continue
            if not PAGE_NO_RE.match(sh.text_frame.text):
                continue
            for para in sh.text_frame.paragraphs:
                for run in para.runs:
                    if "/" in run.text:
                        run.text = f"{new_no:02d} / {TOTAL}"
                        cnt += 1
    return cnt


def append_notes(prs, notes_map):
    for old_no, extra in notes_map.items():
        slide = prs.slides[old_no - 1]
        _ = slide.notes_slide
        tf = slide.notes_slide.notes_text_frame
        base = tf.text.rstrip()
        marker = "【10 分钟精简版 · 口播与计时】"
        if marker in base:
            continue
        tf.text = (base + "\n\n" + marker + "\n" + extra).strip()


NOTES = {
    4: "主张：漏洞量十年 7.4 倍；更麻烦的是真实 CVE 与正常代码几乎一样，规则工具已到极限。30 秒。",
    6: "主张：四条路线实测——纯规则工具在多语言真实 CVE 上召回只有 6%，纯基座 35%，"
       "微调后 59.5%，叠加两阶段 64.5%。结论：工具负责找全、模型负责判准。45 秒。",
    10: "【全场支点】讲 60 秒：四层能力各一句，讲完让评委知道后面在看什么。"
        "收尾金句：终点不是训出一个模型，而是知道怎样走才更接近真理。",
    15: "架构总览 60 秒。主动交代已知边界：大仓库下无候选全量复核成本高，"
        "下一代已预留「先由 API 模型产出候选再注入 Stage 2」。",
    20: "结果页 60 秒，只说三个数：误报 0.154→0.0435、召回 0.967→1.000、strict 0.774→0.923。"
        "强调「不靠漏报换误报」；主动交代未决率上升是信任层保守设计的代价，不是判错。",
    25: "现场播放 2 分 54 秒视频。务必提前在本机预跑一遍，确认 Ollama 模型已就位。",
}


def reorder_and_drop(prs, keep_order, drop_pages):
    sldIdLst = prs.slides._sldIdLst
    ids = list(sldIdLst)
    n = len(ids)
    assert n == 28, f"原 PPT 应为 28 页，实际 {n}"

    kept = [ids[p - 1] for p in keep_order]
    drops = [ids[p - 1] for p in sorted(drop_pages)]

    for el in ids:
        sldIdLst.remove(el)
    for el in kept:
        sldIdLst.append(el)
    for el in drops:
        rId = el.get(NS_R + "id")
        try:
            prs.part.drop_rel(rId)
        except Exception as exc:
            print(f"[warn] drop_rel({rId}) 失败: {exc}")
    return len(kept), len(drops)


def main():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    b = os.path.join(BACKUP_DIR, "码安管家_28页原版_20260920.pptx")
    if not os.path.exists(b):
        shutil.copy2(SRC, b)
        print(f"[backup] {b}")

    prs = Presentation(SRC)
    print(f"[load] {SRC}  ({len(prs.slides)} 页)")

    ok = miss = 0
    for old_no, old_sub, new_text in OVERRIDES:
        slide = prs.slides[old_no - 1]
        n = replace_cross_run(slide, old_sub, new_text)
        if n:
            ok += 1
            print(f"  [text] P{old_no:2d} OK   {old_sub[:34]}")
        else:
            miss += 1
            print(f"  [text] P{old_no:2d} MISS {old_sub[:34]}")
    print(f"[text] 命中 {ok} / 未命中 {miss}")

    append_notes(prs, NOTES)
    print(f"[notes] 写入 {len(NOTES)} 页口播备注")

    print(f"[fit] 封面署名框：{fit_team_author_box(prs)}")

    print(f"[page-no] 重编 {renumber(prs, KEEP_ORDER)} 处 -> NN / {TOTAL}")

    kept, dropped = reorder_and_drop(prs, KEEP_ORDER, DROP_PAGES)
    print(f"[order] 保留 {kept} 页，摘除 {dropped} 页")

    prs.save(DST)
    print(f"[save] {DST}  ({len(Presentation(DST).slides)} 页)")


if __name__ == "__main__":
    main()
