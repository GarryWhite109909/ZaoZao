# -*- coding: utf-8 -*-
"""L1 冲突单条处置：CVE-2025-66371（SaxonC 默认允许外部协议 → XXE）。

NVD 官方 = CWE-611；同 CVE 的 checklist 样本（7456）已标 611；
evidence_adjudication_pos 行（7637）标 94/Critical —— 按 L1 纪律对齐官方：
改标 611/High，叙事按"外部引用解析"语义重写，label_basis=nvd。
定位用 meta.cve 指纹（行号已漂移）。
"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"

C611 = "CWE-611 Improper Restriction of XML External Entity References (XXE)"

rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
hits = [i for i, r in enumerate(rows)
        if (r.get("meta") or {}).get("cve") == "CVE-2025-66371"
        and (r.get("meta") or {}).get("kind") == "evidence_adjudication_pos"]
assert len(hits) == 1, f"指纹不唯一: {hits}"
r = rows[hits[0]]
old = r["messages"][2]["content"]

def R(t, a, b):
    assert t.count(a) == 1, f"不唯一: {a[:40]}"
    return t.replace(a, b)

new = old
# 第3跳：把 "exec( 即 executable. 前缀误配 → 语义 sink 是代码求值" 改为 611 语义
new = R(new,
    "第81行 `executable.transform_to_string(xdm_node=document)` 对污点文档执行样式表——工具所报 `exec(` 即 `executable.` 前缀对应的语义 sink，攻击者可在 .sch 的 test/断言中内嵌 XPath/XSLT 构造，由引擎直接求值。",
    "第81行 `executable.transform_to_string(xdm_node=document)` 对污点内容执行 XSLT 转换——.sch（Schematron/XSLT 2.0）中的 `document()`、`xsl:include`、`unparsed-text()` 等外部引用由 SaxonC 解析执行，可指向 `file://`/`http://` 读取本地文件或发起内网请求（工具所报 `exec(` 是 `executable.` 标识符前缀误配，真实 sink 是 XML 外部引用解析）。")
# 第4步：RCE 故事 → XXE 危害
new = R(new,
    "**危害落地**：第83-84行将含污点的 `output_text` 写回 `.xsl` 文件，成为后续 `compile_stylesheet`（与第37行同一使用模式）加载执行的代码，构成“污点数据变可执行代码”的代码生成注入，可达 RCE。",
    "**危害落地**：外部引用解析即任意文件读取/SSRF（XXE 族危害面）；第83-84行将转换产物写回 `.xsl` 还可污染后续构建链。")
# 第5步：结论改 611
new = R(new,
    "漏洞类型按实际语义判定为 CWE-94 代码注入（XSLT 注入致任意代码执行），风险 Critical。",
    "官方归类按 XML 外部实体/引用限制缺失定 CWE-611（与同 CVE 的 checklist 样本及 NVD 官方标签一致；"
    "非 94：XSLT/文档引用解析的官方语义落在 611，代码执行仅是潜在放大后果），风险 High。")
# JSON patch
import re
m = re.search(r"\n```json\n(\{.*?\})\n```", new, re.S)
obj = json.loads(m.group(1))
obj["vulnerability_type"] = C611
obj["risk_level"] = "High"
obj["explanation"] = R(obj["explanation"],
    "第81行 transform 执行时内嵌 XPath/XSLT 被引擎求值 -> 第83-84行污点输出写回 .xsl 成为可执行代码 -> 代码注入RCE",
    "第81行 transform 执行时 .sch 内的 document()/xsl:include/unparsed-text() 外部引用被 SaxonC 解析 -> "
    "任意文件读取/SSRF（XXE 族）-> 第83-84行产物写回 .xsl 污染后续构建；官方归类 CWE-611，非 94")
obj["fix_suggestion"] = ("line 79: 在 parse_xml/compile_stylesheet 之前设置 "
    "proc.set_configuration_property('http://saxon.sf.net/feature/allowedProtocols', '') 禁止外部协议"
    "（与同 CVE 修复版一致），并对 input_sch_file 做精确白名单校验，仅允许内置发行版 .sch 内容")
new = new[: m.start()] + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```\n"

r["messages"][2]["content"] = new
with DATA.open("w", encoding="utf-8", newline="\n") as f:
    for row in rows:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
with CHANGELOG.open("a", encoding="utf-8") as f:
    f.write(json.dumps({
        "date": "2026-09-08", "step": "1.2_L1_nvd_full", "action": "FIX",
        "locator": {"meta.cve": "CVE-2025-66371", "meta.kind": "evidence_adjudication_pos"},
        "note": "94/Critical → 611/High：NVD 官方=611，同 CVE checklist 行（7456）=611，对齐官方并统一严重度",
        "label_basis": "nvd",
    }, ensure_ascii=False) + "\n")

# 自检
rows2 = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
a2 = rows2[hits[0]]["messages"][2]["content"]
assert "CWE-611" in a2 and "CWE-94 Code Injection" not in a2
print(f"PASS: 行 {hits[0]+1} 已改标 611/High")
