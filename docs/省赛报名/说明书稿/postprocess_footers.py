# 页脚域后处理：目录节 PAGE -> ROMAN，正文节 PAGE -> arabic；移除封面节空 pgNumType（WPS 兼容）
import re, shutil, sys, zipfile, os

src = sys.argv[1]
tmp = src + ".tmp"
shutil.copy(src, tmp)

zin = zipfile.ZipFile(tmp, "r")
doc = zin.read("word/document.xml").decode("utf-8")
rels = zin.read("word/_rels/document.xml.rels").decode("utf-8")

# 节顺序 = sectPr 出现顺序：[封面, 目录, 正文]
sects = re.findall(r"<w:sectPr.*?</w:sectPr>", doc, re.S)
assert len(sects) == 3, "expect 3 sections, got %d" % len(sects)

def footer_of(sect_xml):
    m = re.search(r'<w:footerReference w:type="default" r:id="(rId\d+)"', sect_xml)
    if not m:
        return None
    rid = m.group(1)
    m2 = re.search(r'<Relationship[^>]*Id="%s"[^>]*Target="([^"]+)"' % rid, rels)
    return "word/" + m2.group(1) if m2 else None

toc_footer = footer_of(sects[1])
body_footer = footer_of(sects[2])
print("toc footer:", toc_footer, "| body footer:", body_footer)

# 移除空 pgNumType（docx-js 在未设页码的节也会输出）
doc2 = doc.replace("<w:pgNumType/>", "")

out = zipfile.ZipFile(src, "w", zipfile.ZIP_DEFLATED)
for item in zin.infolist():
    data = zin.read(item.filename)
    if item.filename == "word/document.xml":
        data = doc2.encode("utf-8")
    elif toc_footer and item.filename == toc_footer:
        x = data.decode("utf-8")
        x = re.sub(r"(<w:instrText[^>]*>)\s*PAGE\s*(</w:instrText>)", r"\1 PAGE \\* ROMAN \\* MERGEFORMAT \2", x)
        data = x.encode("utf-8")
    elif body_footer and item.filename == body_footer:
        x = data.decode("utf-8")
        x = re.sub(r"(<w:instrText[^>]*>)\s*PAGE\s*(</w:instrText>)", r"\1 PAGE \\* arabic \\* MERGEFORMAT \2", x)
        data = x.encode("utf-8")
    out.writestr(item, data)
out.close()
zin.close()
os.remove(tmp)
print("footers patched OK")
