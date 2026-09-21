# -*- coding: utf-8 -*-
"""typst 通道一键构建：md 章节稿 -> 说明书_最终_待编号_v3.pdf

流水线（详见 00_排版手册与制作流水线.md 与 修订记录_代码对齐_20260921.md §五之三）：
  1) 合并 02_*~11_* 章节稿 -> build/说明书合并.md（篇间 \\newpage）
  2) pandoc -t typst -s -> build/说明书正文.typ
  3) typst 化后处理（本脚本内）：\\newpage -> #pagebreak()、outline 标题「目录」、
     图片路径加 ../ 前缀
  4) polish_typ_for_pdf.py（表格框线/跨页/字体/图片单边约束，幂等）
  5) 图题绑定（2026-09-21 新增）：仅含「图 + 图注」的 quote 块设为不可跨页，
     消除图与题注分居两页的分页事故（v2 的图 6-7a / 图 7-2）
  6) typst compile --root .
  7) pymupdf 合并封面（封面元数据：title/subject/creator）

用法：D:/miniconda/python.exe build_typst_channel.py
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build"
PANDOC = r"C:/Users/zane/AppData/Local/Pandoc/pandoc.exe"
TYPST = r"C:/Users/zane/.workbuddy/binaries/tools/typst-x86_64-pc-windows-msvc/typst.exe"

BODY_TYPPATH = BUILD / "说明书正文.typ"
BODY_PDF = BUILD / "说明书正文_new.pdf"
COVER_PDF = BUILD / "封面_已填写.pdf"
FINAL_PDF = BUILD / "说明书_最终_待编号_v3.pdf"


def step_merge():
    files = sorted(ROOT.glob("0[2-9]_*.md")) + sorted(ROOT.glob("1[01]_*.md"))
    assert files, "未找到章节稿"
    parts = []
    for f in files:
        print("  追加", f.name)
        parts.append(f.read_text(encoding="utf-8").rstrip() + "\n\n\\newpage\n\n")
    (BUILD / "说明书合并.md").write_text("".join(parts), encoding="utf-8", newline="\n")
    # 匿名化截图覆盖（与 build_pdf.sh §1.5 同一约定）：assets_src_anon/ 优先
    anon = ROOT / "assets_src_anon"
    if anon.is_dir():
        import shutil
        n = 0
        for f in anon.glob("*.png"):
            shutil.copy(f, ROOT / "assets" / f.name)
            n += 1
        print(f"  匿名截图覆盖 {n} 张 <- assets_src_anon/")


def step_pandoc():
    subprocess.run(
        [PANDOC, str(BUILD / "说明书合并.md"), "-t", "typst", "-s",
         "-o", str(BODY_TYPPATH)],
        check=True,
    )


def step_typstify():
    typ = BODY_TYPPATH.read_text(encoding="utf-8")
    # 1) 篇级 H1 前插 #pagebreak()（pandoc 会丢弃合并稿里的 \newpage 原始 LaTeX）
    typ, n_pb = re.subn(r"^(= )", r"#pagebreak()\n\1", typ, flags=re.M)
    # 2) 目录：在第一个篇级标题前插 #outline（等价 pandoc --toc 的 title: auto，
    #    英文语境下会渲染成 Contents，故直接写死「目录」）
    typ, n_out = re.subn(
        r"#pagebreak\(\)\n= ",
        "#outline(\n  title: [目录],\n  depth: 3\n)\n\n#pagebreak()\n= ",
        typ, count=1,
    )
    # 3) 图片路径 ../ 前缀（相对 .typ 所在 build/ 目录解析；compile 需 --root .）
    typ, n_img = re.subn(r'image\("assets/', 'image("../assets/', typ)
    print(f"  pagebreak {n_pb} / outline {n_out} / imgprefix {n_img}")
    BODY_TYPPATH.write_text(typ, encoding="utf-8", newline="\n")


def step_bind_figure_caption():
    """仅含「figure(image) + #strong[图 ...] 图注」的 quote 块 -> block(breakable: false)。"""
    typ = BODY_TYPPATH.read_text(encoding="utf-8")
    out, pos, n = [], 0, 0
    marker = "#quote(block: true)["
    while True:
        i = typ.find(marker, pos)
        if i == -1:
            out.append(typ[pos:])
            break
        j = i + len(marker)
        depth = 1
        while j < len(typ) and depth:
            if typ[j] == "[":
                depth += 1
            elif typ[j] == "]":
                depth -= 1
            j += 1
        body = typ[i + len(marker):j - 1]
        # 条件：图开头，且含手写图注（#strong[图），不含会超页的表格
        if body.lstrip().startswith("#figure(image(") and "#strong[图" in body and "table(" not in body:
            out.append(typ[pos:i])
            out.append("#quote(block: true)[#block(breakable: false)[" + body + "]]")
            n += 1
        else:
            out.append(typ[pos:j])
        pos = j
    BODY_TYPPATH.write_text("".join(out), encoding="utf-8", newline="\n")
    print(f"  图题绑定 {n} 处")


def step_compile():
    subprocess.run(
        [TYPST, "compile", "--root", ".", str(BODY_TYPPATH), str(BODY_PDF)],
        check=True, cwd=str(ROOT),
    )


def step_merge_cover():
    import pymupdf
    import time
    import os

    cover = pymupdf.open(str(COVER_PDF))
    body = pymupdf.open(str(BODY_PDF))
    final = pymupdf.open()
    final.insert_pdf(cover)
    final.insert_pdf(body)
    final.set_metadata({
        "title": "系统设计说明书",
        "author": "",
        "subject": "第22届湖南省大学生程序设计竞赛 应用开发类竞赛（2026）",
        "creator": "Typst 0.15",
        "producer": "",
    })
    # Windows 下 PDF 可能被阅读器占用：先写临时名，再尝试替换；被锁则保留临时名并提示
    tmp = FINAL_PDF.with_suffix(".tmp.pdf")
    final.save(str(tmp), deflate=True, garbage=3)
    for attempt in range(3):
        try:
            os.replace(str(tmp), str(FINAL_PDF))
            break
        except PermissionError:
            if attempt == 2:
                print(f"  [warn] {FINAL_PDF.name} 被其他程序占用，产物暂存为 {tmp.name}")
                print("         关闭占用程序后手动改名即可。")
                break
            time.sleep(2)
    print("  产物:", FINAL_PDF.name, final.page_count, "页")


if __name__ == "__main__":
    print("[1/6] 合并章节稿")
    step_merge()
    print("[2/6] pandoc -> typ")
    step_pandoc()
    print("[3/6] typst 化后处理")
    step_typstify()
    print("[4/6] polish 排版打磨")
    subprocess.run([sys.executable, str(ROOT / "polish_typ_for_pdf.py"), str(BODY_TYPPATH)], check=True, cwd=str(ROOT))
    print("[5/6] 图题绑定")
    step_bind_figure_caption()
    print("[6/6] typst compile + 合并封面")
    step_compile()
    step_merge_cover()
    print("[done]")
