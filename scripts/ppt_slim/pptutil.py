#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pptx 文本改写工具：支持跨 run 匹配、组合递归、保留原格式。"""

import copy
import re

from pptx.util import Pt

NS_A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"


def iter_shapes(shapes):
    """递归遍历形状（含组合内），组合本身也产出。"""
    for sh in shapes:
        yield sh
        if sh.shape_type == 6:  # GROUP
            yield from iter_shapes(sh.shapes)


def iter_text_frames(slide):
    for sh in iter_shapes(slide.shapes):
        if sh.has_text_frame:
            yield sh, sh.text_frame


def _make_br():
    br = NS_A and None
    from lxml import etree
    br = etree.SubElement  # placeholder, replaced below
    return br


def replace_in_textframe(tf, old_sub, new_text, first_only=True):
    """
    在 text_frame 内查找 old_sub（可跨 run / 跨段落），替换为 new_text。
    返回替换次数。格式取自被替换区域的**首个 run**；多行用 <a:br/> 软换行实现，
    保证字号与颜色一致。
    """
    from lxml import etree

    # 1) 收集所有 run 及其在"拼接文本"中的区间
    runs = []
    for para in tf.paragraphs:
        for run in para.runs:
            runs.append(run)
    if not runs:
        return 0

    joined = "".join(r.text or "" for r in runs)
    idx = joined.find(old_sub)
    if idx < 0:
        return 0

    # 2) 定位起止 run 与 run 内偏移
    pos = 0
    start_run_i = end_run_i = -1
    start_off = end_off = 0
    for i, r in enumerate(runs):
        t = r.text or ""
        if start_run_i < 0 and pos + len(t) > idx:
            start_run_i = i
            start_off = idx - pos
        if pos + len(t) >= idx + len(old_sub):
            end_run_i = i
            end_off = idx + len(old_sub) - pos
            break
        pos += len(t)
    if start_run_i < 0 or end_run_i < 0:
        return 0

    sr = runs[start_run_i]
    er = runs[end_run_i]
    sr_text = sr.text or ""
    er_text = er.text or ""

    head = sr_text[:start_off]
    tail = er_text[end_off:]

    # 3) 首个 run 写入 head + 新文本第一行
    lines = new_text.split("\n")
    sr.text = head + lines[0]

    # 4) 清空/删除中间 run
    if start_run_i == end_run_i:
        # 同一 run：补回 tail
        sr.text = head + lines[0]
        if tail:
            # 在同一段落尾部追加 tail（作为新 run，继承格式）
            new_r = copy.deepcopy(sr._r)
            for child in list(new_r):
                if child.tag != NS_A + "rPr":
                    new_r.remove(child)
            t = etree.SubElement(new_r, NS_A + "t")
            t.text = tail
            sr._r.addnext(new_r)
    else:
        for i in range(start_run_i + 1, end_run_i):
            runs[i].text = ""
        er.text = tail
        # 若 end run 已空且非首 run，删掉它
        if not tail and end_run_i != start_run_i:
            er._r.getparent().remove(er._r)

    # 5) 多行：用 <a:br/> 插入软换行
    if len(lines) > 1:
        prev_el = sr._r
        for line in lines[1:]:
            br = etree.SubElement(prev_el, NS_A + "br")
            # br 必须跟在 run 之后：move 到 next
            prev_el.addnext(br)
            new_r = copy.deepcopy(sr._r)
            for child in list(new_r):
                if child.tag != NS_A + "rPr":
                    new_r.remove(child)
            t = etree.SubElement(new_r, NS_A + "t")
            t.text = line
            br.addnext(new_r)
            prev_el = new_r
            sr = type(sr)(new_r, sr._parent) if False else sr

    return 1


def replace_cross_run(slide, old_sub, new_text):
    """在整页范围内尝试替换（逐 text_frame）"""
    hits = 0
    for _, tf in iter_text_frames(slide):
        n = replace_in_textframe(tf, old_sub, new_text)
        hits += n
    return hits


def set_font_size_on_text(tf, size_pt):
    """把 text_frame 内所有 run 的字号统一设为 size_pt"""
    for para in tf.paragraphs:
        for run in para.runs:
            run.font.size = Pt(size_pt)
