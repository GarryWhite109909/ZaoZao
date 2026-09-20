#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
按「最终演示顺序」重排 pptx，并**保留**未入选的页（不物理删除）。

背景：python-pptx 没有公开的"删除幻灯片"API。直接对 sldIdLst 做 append/remove
会破坏 part 的 rels 顺序，导致 PowerPoint 报"需要修复"。本脚本采用标准做法：

  1. 把 sldIdLst 里所有 sldId 摘下来；
  2. 按目标顺序重新 append；
  3. 未入选页的 sldId 也 append 在最后（不丢弃数据、不静默删除），
     调用方可用 --drop-tail N 把它们从演示顺序中摘掉并清理 rels。

用法：
  python reorder_slides.py in.pptx out.pptx --order 1,2,3,4,6,9,10,11,...
"""

import argparse
import sys

from pptx import Presentation

NS_R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"


def reorder(src, dst, order, drop_tail=0):
    prs = Presentation(src)
    sldIdLst = prs.slides._sldIdLst
    ids = list(sldIdLst)
    n = len(ids)

    bad = [p for p in order if not (1 <= p <= n)]
    if bad:
        raise SystemExit(f"[fatal] 越界页码: {bad}（共 {n} 页）")
    dup = {p for p in order if order.count(p) > 1}
    if dup:
        raise SystemExit(f"[fatal] 重复页码: {sorted(dup)}")

    selected = [ids[p - 1] for p in order]
    rest = [ids[p - 1] for p in range(1, n + 1) if p not in set(order)]

    for el in ids:
        sldIdLst.remove(el)
    for el in selected:
        sldIdLst.append(el)

    dropped = []
    if drop_tail:
        tail = rest[-drop_tail:] if drop_tail <= len(rest) else rest
        rest = rest[: len(rest) - len(tail)]
        for el in tail:
            rId = el.get(NS_R + "id")
            try:
                prs.part.drop_rel(rId)
            except Exception as exc:  # pragma: no cover
                print(f"[warn] drop_rel {rId} 失败: {exc}")
            dropped.append(rId)
    for el in rest:
        sldIdLst.append(el)

    prs.save(dst)
    print(f"[ok] 选中 {len(selected)} 页，尾部保留 {len(rest)} 页，摘除 {len(dropped)} 页")
    print(f"[ok] 输出 {dst}（共 {len(Presentation(dst).slides)} 页）")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--order", required=True, help="逗号分隔的 1-based 原页码，按目标顺序")
    ap.add_argument("--drop-tail", type=int, default=0, help="从尾部摘除 N 页（清理 rels）")
    a = ap.parse_args()
    order = [int(x) for x in a.order.replace(" ", "").split(",") if x]
    reorder(a.src, a.dst, order, a.drop_tail)


if __name__ == "__main__":
    sys.exit(main())
