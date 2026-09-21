# -*- coding: utf-8 -*-
"""typst 通道排版打磨：在 pandoc 产出的 .typ 上做五类修复，然后由 typst 重新编译。

用法：D:/miniconda/python.exe polish_typ_for_pdf.py [build/说明书正文.typ]
典型链路（接 build_pdf.sh 的 pandoc 产物之后）：
  1) pandoc 说明书合并.md -t typst -s -o build/说明书正文.typ（既有四步后处理：../assets 前缀、
     目录标题「目录」、篇级 H1 前 #pagebreak()，详见 修订记录_代码对齐_20260921.md §五之三）
  2) 本脚本（幂等，可重复跑）
  3) typst compile --root . build/说明书正文.typ build/说明书正文.pdf
  4) pymupdf 合并 封面_已填写.pdf + 说明书正文.pdf -> 说明书_最终_待编号.pdf

修复清单（对应 2026-09-21 终检发现的四类排版缺陷）：
  A. 表格全框线：pandoc 模板默认 #set table(stroke: none) 导致 95 张表无线条 → 改 0.5pt 深灰全框线，
     表头加粗 + 浅灰底（跨页时 typst 自动重复表头）。
  B. 表格/图片可跨页：pandoc 把 123 个表/图全部包进不可跨页的 #figure → 大表整体跳页留下大面积
     空白、超页高的表溢出叠印（文字重叠）→ show figure: set block(breakable: true) 等三条规则。
  C. 图片双标题：pandoc 对带 alt 的图片自动生成英文编号「Figure N: …」，与正文手写「图 X-N」图注
     重复 → 删除 figure 的 caption 参数（保留 alt 供无障碍）。
  D. 表格列宽：pandoc 对宽表输出等宽百分比列（如 33.33%×3），术语表首列大片留白 → 改 auto 整数列
     按内容自适应；同时去掉 align(center) 包裹，恢复单元格左对齐（居中包裹会把 auto 对齐传染成居中）。
  E. 字体：标题黑体（SimHei）、代码 Consolas，正文仍 SimSun，贴近 docx 通道（generate.js）的字体口径。
"""
import re
import sys

MARK = "// ---- 排版打磨（polish_typ_for_pdf.py 注入，幂等）----"

PREAMBLE_OLD = """#set table(
  inset: 6pt,
  stroke: none
)"""

PREAMBLE_NEW = """// ---- 排版打磨（polish_typ_for_pdf.py 注入，幂等）----
// A. 表格全框线 + 表头样式（跨页自动重复表头）
#set table(
  inset: (x: 7pt, y: 5.5pt),
  stroke: 0.5pt + luma(60),
)
#show table.cell.where(y: 0): set text(weight: "bold")
#show table.cell.where(y: 0): set table.cell(fill: luma(242))
// 表格行原子化：行内文字不得跨页拆断（否则出现半行残片 + 大空洞）
#show table.cell: it => block(breakable: false, it)
// B. 表格/图片可跨页：消除大表跳页留白与超页溢出叠印
#show figure: set block(breakable: true)
#set block(breakable: true)
// E. 标题黑体；代码 Consolas 且可跨页
#show heading: set text(font: ("SimHei", "Microsoft YaHei"))
#show raw: set text(font: ("Consolas", "Courier New"), size: 0.92em)
#show raw.where(block: true): set block(breakable: true)
// F. 禁用英文断词：中文文档中 Apple Silicon / Transformers 等词在表格窄列被
//    软断词切成 Sili-con / Transform-ers，观感差且无必要（2026-09-21 终验遗留）
#set text(hyphenate: false)"""


def main(path):
    with open(path, encoding="utf-8") as f:
        typ = f.read()

    # A+B+E：替换模板默认的 table 设置块（幂等：已打磨过则跳过）
    if MARK in typ:
        print("[skip] 前缀已注入（幂等），仅重跑 C/D 内容级替换")
    elif PREAMBLE_OLD in typ:
        typ = typ.replace(PREAMBLE_OLD, PREAMBLE_NEW, 1)
        print("[ok] A/B/E 前缀注入：全框线表 + breakable + 字体规则")
    else:
        sys.exit("[error] 找不到 pandoc 默认 #set table 块，模板可能已变，请人工核对")

    # C. 删除图片 figure 的英文 caption（保留 alt）
    #    注意 group 内的 \)：要消费 image(...) 自己的收尾括号，否则下一位是 ) 而非逗号，永不匹配
    typ, n_cap = re.subn(
        r'#figure\(\s*(image\("[^"]+", alt: "[^"]*"\))\s*,\s*\n?\s*caption:\s*\[[^\]]*\]\s*\n?\s*\)',
        r"#figure(\1)",
        typ, flags=re.S)
    print(f"[ok] C 去除图片英文双标题：{n_cap} 处")

    # C2. 图片按宽高比单边约束（横图限宽 82% 版心；竖图限高 66% 页高）：
    #     单边约束不会预留多余盒子；切忌宽高同时约束——contain 会把图缩得很小、
    #     盒子却照预留，页面中央一片留白（实测 p67 图 6-1 教训）。
    #     竖图限高的目的：标题 + 整图 + 图注能同页放下，消除「标题孤悬 + 大空白」。
    from PIL import Image
    import os

    def img_constraint(m):
        path, alt = m.group(1), m.group(2)
        fn = path.replace("../assets/", "assets/")  # 脚本按说明书稿/ 为 cwd 运行
        try:
            w, h = Image.open(fn).size
            aspect = h / w
        except Exception:
            aspect = 1.0
        if aspect > 1.15:
            return 'image("%s", alt: "%s", height: 66%%, fit: "contain")' % (path, alt)
        return 'image("%s", alt: "%s", width: 82%%, fit: "contain")' % (path, alt)

    typ, n_img = re.subn(r'image\("([^"]+)", alt: "([^"]*)"\)', img_constraint, typ)
    print(f"[ok] C2 图片按宽高比单边约束：{n_img} 处")

    # D1. 表格去掉 align(center)[...] 包裹（居中包裹会把单元格 auto 对齐传染成居中）
    #     匹配 align(center)[#table( BODY )] , kind: table；G1 = "table(BODY)"（含收尾括号）
    #     替换为 "table(BODY), kind: table"：# 随模式去掉（figure 参数是代码模式，不能带 #）
    typ, n_wrap = re.subn(
        r"align\(center\)\[#(table\(.*?\))\]\s*,\s*kind: table",
        r"\1, kind: table",
        typ, flags=re.S)
    print(f"[ok] D1 去除表格 align(center) 包裹：{n_wrap} 处")

    # D2. 等宽百分比列 -> auto 整数列（按内容自适应）
    def cols_to_auto(m):
        return "columns: %d," % m.group(0).count("%")
    typ, n_col = re.subn(r"columns: \((?:\s*[\d.]+%\s*,?)+\),", cols_to_auto, typ)
    print(f"[ok] D2 百分比列宽改 auto：{n_col} 处")

    # D3. 删掉表内 align: (auto,auto,...) 行（注意 pandoc 会写尾逗号 (auto,auto,)）
    typ, n_al = re.subn(r"\n\s*align: \(auto(?:,\s*auto)*,?\),", "", typ)
    print(f"[ok] D3 清理冗余 align 行：{n_al} 处")

    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(typ)
    print(f"[done] {path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "build/说明书正文.typ")
