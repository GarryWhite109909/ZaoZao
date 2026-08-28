#!/usr/bin/env python3
"""v2.7 审计第四段：新增层(8639-8777)质量 + CWE 覆盖全表 + 元话语样本终验。"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))
DATA = PROJECT / "experiments/exp_06_finetune/data/final_train_chatml_alpha06_v2_7.jsonl"
OUT = PROJECT / "experiments/exp_06_finetune/scripts/_audit_v2_7_probe4_out.txt"
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
CODE_RE = re.compile(r"```([\w+#-]*)\n(.*?)\n```", re.S)

rows = [json.loads(l) for l in DATA.read_text(encoding="utf-8").splitlines() if l.strip()]
buf = []
def w(s=""):
    buf.append(str(s))

# 1) #8058 嵌入行号注解核验：块内 L 注解最大值
r = rows[8058]
blocks = CODE_RE.findall(r["messages"][1]["content"])
body = blocks[0][1]
anns = [int(x) for x in re.findall(r"\bL(\d+)\b", body)]
w(f"#8058 块内 L 注解: 数量={len(anns)} 最小={min(anns) if anns else '-'} 最大={max(anns) if anns else '-'}")
w(f"   助手引用越界集合中 L246 是否在注解内: {246 in anns}, L202: {202 in anns}, L237: {237 in anns}")
for i in (8065, 8071, 8073, 8086, 8089, 8090):
    rr = rows[i]
    bb = CODE_RE.findall(rr["messages"][1]["content"])[0][1]
    aa = [int(x) for x in re.findall(r"\bL(\d+)\b", bb)]
    if aa:
        w(f"#{i} 块 L 注解 min={min(aa)} max={max(aa)} | 物理行数={bb.count(chr(10))+1}")

# 2) 新增层统计
INC = range(8639, 8778)
kind_c, vt_c, lang_c, dir_c, opener_c, len_c = Counter(), Counter(), Counter(), Counter(), Counter(), []
for i in INC:
    r = rows[i]
    meta = r.get("meta") or {}
    kind_c[meta.get("kind", "-")] += 1
    a = r["messages"][2]["content"]
    m = JSON_RE.search(a)
    obj = json.loads(m.group(1)) if m else {}
    hv = obj.get("has_vulnerability")
    dir_c[hv] += 1
    if hv:
        vt_c[obj.get("vulnerability_type")] += 1
    cm = CODE_RE.search(r["messages"][1]["content"])
    lang_c[(cm.group(1) if cm else "?").lower()] += 1
    opener_c[a.strip().split("\n")[0][:24]] += 1
    len_c.append((len(a), (cm.group(2) if cm else "").count("\n") + 1))
w(f"\n新增层 kind: {dict(kind_c)}")
w(f"新增层方向: {dict(dir_c)}")
w(f"新增层语言: {dict(lang_c)}")
w(f"新增层 opener: {dict(opener_c.most_common(10))}")
als = sorted(x[0] for x in len_c)
cls = sorted(x[1] for x in len_c)
w(f"新增层 assistant 字符: min={als[0]} p50={als[len(als)//2]} max={als[-1]}")
w(f"新增层 代码行数: min={cls[0]} p50={cls[len(cls)//2]} p90={cls[int(len(cls)*0.9)]} max={cls[-1]}")
w(f"新增层 vt(前25): {vt_c.most_common(25)}")
multi = [v for v, n in vt_c.items() if "/" in str(v) or "与" in str(v) or "次要" in str(v)]
w(f"新增层 多 CWE 混写 vt 形态数: {len(multi)} 总条数: {sum(vt_c[v] for v in multi)}")

# 3) 全库 vt 单串格式再查（限 hv=True 且排除 triage 4 字段）
bad_vt_new = []
for i in INC:
    r = rows[i]
    m = JSON_RE.search(r["messages"][2]["content"])
    if not m:
        continue
    obj = json.loads(m.group(1))
    if obj.get("has_vulnerability") is True:
        vt = str(obj.get("vulnerability_type"))
        if not re.match(r"^CWE-\d+ [A-Za-z][^/:]*$", vt) or "/" in vt:
            bad_vt_new.append((i, vt))
w(f"\n新增层 vt 非单串规范: {len(bad_vt_new)}")
for i, vt in bad_vt_new[:15]:
    w(f"   #{i} {vt!r}")

# 4) 元话语样本终验（#203 #243 #1382 #1752 + hv=False 组）
for i in (203, 243, 1382, 1752, 3319, 4902, 8326, 8391):
    r = rows[i]
    a = r["messages"][2]["content"]
    m = JSON_RE.search(a)
    obj = json.loads(m.group(1)) if m else {}
    meta = r.get("meta") or {}
    cm = CODE_RE.search(r["messages"][1]["content"])
    lg = (cm.group(1) if cm else "?")
    w(f"\n#{i} lang={lg} kind={meta.get('kind')} hv={obj.get('has_vulnerability')} vt={obj.get('vulnerability_type')}")
    w("  JSON前 300: " + (a[: m.start()][-300:].replace("\n", "\\n") if m else a[:300]))

# 5) CWE 全覆盖表
all_cwe = Counter()
for i, r in enumerate(rows):
    m = JSON_RE.search(r["messages"][2]["content"])
    if not m:
        continue
    try:
        obj = json.loads(m.group(1))
    except Exception:
        continue
    if obj.get("has_vulnerability") is True and "is_confirmed" not in obj:
        vt = str(obj.get("vulnerability_type") or "")
        mm = re.match(r"CWE-(\d+)", vt)
        if mm:
            all_cwe[f"CWE-{mm.group(1)}"] += 1
w(f"\nCWE 总类数 {len(all_cwe)}")
common = ["CWE-125", "CWE-476", "CWE-120", "CWE-121", "CWE-122", "CWE-787", "CWE-134", "CWE-190", "CWE-191",
          "CWE-200", "CWE-209", "CWE-256", "CWE-259", "CWE-284", "CWE-287", "CWE-295", "CWE-311", "CWE-319",
          "CWE-321", "CWE-322", "CWE-323", "CWE-327", "CWE-328", "CWE-330", "CWE-347", "CWE-359", "CWE-377",
          "CWE-384", "CWE-404", "CWE-434", "CWE-451", "CWE-471", "CWE-565", "CWE-598", "CWE-601", "CWE-614",
          "CWE-639", "CWE-643", "CWE-645", "CWE-650", "CWE-668", "CWE-672", "CWE-680", "CWE-681", "CWE-693",
          "CWE-703", "CWE-732", "CWE-749", "CWE-754", "CWE-755", "CWE-770", "CWE-776", "CWE-789", "CWE-79",
          "CWE-798", "CWE-807", "CWE-840", "CWE-843", "CWE-909", "CWE-912", "CWE-915", "CWE-917", "CWE-94",
          "CWE-940", "CWE-941", "CWE-943", "CWE-1004", "CWE-1104", "CWE-116", "CWE-117", "CWE-1188", "CWE-1192",
          "CWE-1204", "CWE-1220", "CWE-1275", "CWE-1284", "CWE-1312", "CWE-1321", "CWE-1333", "CWE-1336",
          "CWE-1357", "CWE-1427", "CWE-20", "CWE-22", "CWE-23", "CWE-24", "CWE-27", "CWE-35", "CWE-36", "CWE-37",
          "CWE-38", "CWE-39", "CWE-40", "CWE-42", "CWE-44", "CWE-45", "CWE-46", "CWE-47", "CWE-49", "CWE-50",
          "CWE-52", "CWE-53", "CWE-59", "CWE-61", "CWE-62", "CWE-64", "CWE-65", "CWE-66", "CWE-67", "CWE-68",
          "CWE-69", "CWE-72", "CWE-73", "CWE-74", "CWE-75", "CWE-76", "CWE-77", "CWE-78", "CWE-79", "CWE-80",
          "CWE-81", "CWE-82", "CWE-83", "CWE-84", "CWE-86", "CWE-87", "CWE-88", "CWE-89", "CWE-90", "CWE-91",
          "CWE-92", "CWE-93", "CWE-94", "CWE-95"]
missing = [c for c in sorted(set(common)) if c not in all_cwe]
w(f"未覆盖的常见 CWE（抽样清单内）: {missing}")
w(f"覆盖但 <10 条: {sorted([(k, v) for k, v in all_cwe.items() if v < 10], key=lambda x: x[1])}")

OUT.write_text("\n".join(buf), encoding="utf-8")
print("written")
