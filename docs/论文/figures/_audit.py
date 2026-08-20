# -*- coding: utf-8 -*-
"""几何审计：检测两张图的文字重叠、连线交叉、连线穿框。"""
import matplotlib

matplotlib.use("Agg")
import importlib.util
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def seg_intersect(p1, p2, p3, p4):
    """判断线段 p1p2 与 p3p4 是否相交（含端点相接返回 False）。"""
    d1x, d1y = p2[0] - p1[0], p2[1] - p1[1]
    d2x, d2y = p4[0] - p3[0], p4[1] - p3[1]
    r = d1x * d2y - d1y * d2x
    if abs(r) < 1e-9:
        return False  # 平行
    t = ((p3[0] - p1[0]) * d2y - (p3[1] - p1[1]) * d2x) / r
    u = ((p3[0] - p1[0]) * d1y - (p3[1] - p1[1]) * d1x) / r
    if 0 < t < 1 and 0 < u < 1:
        ix, iy = p1[0] + t * d1x, p1[1] + t * d1y
        return (ix, iy)
    return False


def audit(name, path):
    print("=" * 60)
    print("AUDIT:", name)
    mod = load_module(name, path)
    fig = plt.gcf()
    ax = fig.axes[0]
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    inv = ax.transData.inverted()

    # 1) 文字 bbox（数据坐标）
    texts = []
    for t in ax.texts:
        bb = t.get_window_extent(renderer)
        p0 = inv.transform((bb.x0, bb.y0))
        p1 = inv.transform((bb.x1, bb.y1))
        texts.append({
            "txt": t.get_text().replace("\n", " ")[:18],
            "x0": p0[0], "y0": p0[1], "x1": p1[0], "y1": p1[1],
            "cx": (p0[0] + p1[0]) / 2, "cy": (p0[1] + p1[1]) / 2,
        })

    # 2) 框体 bbox（数据坐标，仅取 FancyBboxPatch 的外接矩形）
    boxes = []
    for p in ax.patches:
        if isinstance(p, FancyArrowPatch):
            continue
        bb = p.get_window_extent(renderer)
        p0 = inv.transform((bb.x0, bb.y0))
        p1 = inv.transform((bb.x1, bb.y1))
        boxes.append({
            "x0": p0[0], "y0": p0[1], "x1": p1[0], "y1": p1[1],
        })

    # 3) 连线折线段
    segs = []
    for p in ax.patches:
        if not isinstance(p, FancyArrowPatch):
            continue
        path = p.get_path()
        verts = path.vertices
        codes = path.codes
        pts = [ax.transData.inverted().transform(p.get_transform().transform(v))
               for v in verts]
        for a, b in zip(pts[:-1], pts[1:]):
            if (a[0] != b[0] or a[1] != b[1]):
                segs.append((a, b))

    # 文字-文字重叠
    print("\n[文字重叠]")
    any_t = False
    for i in range(len(texts)):
        for j in range(i + 1, len(texts)):
            a, b = texts[i], texts[j]
            if a["x0"] < b["x1"] and b["x0"] < a["x1"] and a["y0"] < b["y1"] and b["y0"] < a["y1"]:
                print(f"  OVERLAP: '{a['txt']}' vs '{b['txt']}'")
                any_t = True
    if not any_t:
        print("  (无)")

    # 文字中心落在框内（可能串框）
    print("\n[文字中心落入框体]")
    any_b = False
    for t in texts:
        inside = []
        for b in boxes:
            if b["x0"] < t["cx"] < b["x1"] and b["y0"] < t["cy"] < b["y1"]:
                inside.append((round(b["x0"], 2), round(b["y0"], 2), round(b["x1"], 2), round(b["y1"], 2)))
        if inside:
            print(f"  '{t['txt']}' center {t['cx']:.2f},{t['cy']:.2f} -> {inside}")
            any_b = True
    if not any_b:
        print("  (无)")

    # 连线交叉
    print("\n[连线交叉]")
    any_c = False
    for i in range(len(segs)):
        for j in range(i + 1, len(segs)):
            pt = seg_intersect(segs[i][0], segs[i][1], segs[j][0], segs[j][1])
            if pt:
                print(f"  CROSS: seg{i} {segs[i]} × seg{j} {segs[j]} at ({pt[0]:.2f},{pt[1]:.2f})")
                any_c = True
    if not any_c:
        print("  (无)")

    # 连线穿过框体（线段中点或端点位于框内，且线段不短于 0.3）
    print("\n[连线穿框]")
    any_p = False
    for k, (a, b) in enumerate(segs):
        mx, my = (a[0] + b[0]) / 2, (a[1] + b[1]) / 2
        ln = ((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2) ** 0.5
        if ln < 0.3:
            continue
        for bi, bx in enumerate(boxes):
            if bx["x0"] < mx < bx["x1"] and bx["y0"] < my < bx["y1"]:
                print(f"  THRU seg{k} {(round(a[0],2),round(a[1],2))}->{(round(b[0],2),round(b[1],2))} midpoint inside box{bi} {bx}")
                any_p = True
    if not any_p:
        print("  (无)")

    print()
    plt.close(fig)


base = r"D:\code\毕业设计\Graduation-Project\docs\论文\figures"
audit("trust_graded_feedback", base + r"\gen_trust_graded_feedback.py")
audit("self_developed_tools", base + r"\gen_self_developed_tools.py")
