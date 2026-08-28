#!/usr/bin/env python3
"""v2.7 审计第五段：新增层全文抽样 + 残留矛盾核验 + 补充 CWE 检查。"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))
DATA = PROJECT / "experiments/exp_06_finetune/data/final_train_chatml_alpha06_v2_7.jsonl"
OUT = PROJECT / "experiments/exp_06_finetune/scripts/_audit_v2_7_probe5_out.txt"
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
CODE_RE = re.compile(r"```([\w+#-]*)\n(.*?)\n```", re.S)

rows = [json.loads(l) for l in DATA.read_text(encoding="utf-8").splitlines() if l.strip()]
buf = []
def w(s=""):
    buf.append(str(s))

# 1) #8058 块前缀编号核验
body = CODE_RE.findall(rows[8058]["messages"][1]["content"])[0][1]
prefixes = [int(x) for x in re.findall(r"^\s*(\d+)\s*\|", body, re.M)]
w(f"#8058 行前缀编号: 数量={len(prefixes)} 范围={min(prefixes) if prefixes else '-'}~{max(prefixes) if prefixes else '-'}")
w(f"   L202 在前缀? {202 in prefixes} L246? {246 in prefixes}")

# 2) 残留终判矛盾核验（无元话语的）
for i in (566, 629, 836, 1180, 1283, 8224):
    r = rows[i]
    a = r["messages"][2]["content"]
    m = JSON_RE.search(a)
    obj = json.loads(m.group(1)) if m else {}
    pre = a[: m.start()] if m else a
    w(f"\n--- #{i} hv={obj.get('has_vulnerability')} vt={obj.get('vulnerability_type')}")
    w("JSON前 250: " + pre[-250:].replace("\n", "\\n"))

# 3) 新增层全文抽样（crossfile 2 + framework 1 + checklist 1）
def dump(i):
    r = rows[i]
    meta = r.get("meta") or {}
    w(f"\n{'='*70}\n样本 #{i} kind={meta.get('kind')} meta={json.dumps({k: v for k, v in meta.items() if k != 'kind'}, ensure_ascii=False)[:200]}")
    w("--- USER ---")
    w(r["messages"][1]["content"][:3500])
    w("--- ASSISTANT ---")
    w(r["messages"][2]["content"][:3500])

crossfile_idx = [i for i in range(8639, 8778) if (rows[i].get("meta") or {}).get("kind") == "variant_crossfile"]
fw_idx = [i for i in range(8639, 8778) if (rows[i].get("meta") or {}).get("kind") == "variant_framework"]
ck_idx = [i for i in range(8639, 8778) if (rows[i].get("meta") or {}).get("kind") == "checklist_cot"]
dump(crossfile_idx[3])
dump(crossfile_idx[50])
dump(fw_idx[0])
dump(ck_idx[0])

# 4) 补充 CWE 存在性
all_cwe = set()
for r in rows:
    m = JSON_RE.search(r["messages"][2]["content"])
    if not m:
        continue
    try:
        obj = json.loads(m.group(1))
    except Exception:
        continue
    if obj.get("has_vulnerability") is True:
        mm = re.match(r"CWE-(\d+)", str(obj.get("vulnerability_type") or ""))
        if mm:
            all_cwe.add(f"CWE-{mm.group(1)}")
extra = ["CWE-476", "CWE-786", "CWE-829", "CWE-1021", "CWE-1022", "CWE-1023", "CWE-347", "CWE-320",
         "CWE-915", "CWE-917", "CWE-942", "CWE-613", "CWE-525", "CWE-522", "CWE-548", "CWE-345",
         "CWE-434", "CWE-476", "CWE-362", "CWE-367", "CWE-369", "CWE-453", "CWE-1284", "CWE-1321", "CWE-1333"]
w("\n补充 CWE 检查: " + str({c: (c in all_cwe) for c in sorted(set(extra))}))

# 5) 口头禅在新增层的分布
FILLERS = ["首先", "其次", "再次", "综上所述", "总而言之"]
n = Counter()
for i in range(8639, 8778):
    a = rows[i]["messages"][2]["content"]
    for f in FILLERS:
        if f in a:
            n[f] += 1
w(f"新增层口头禅: {dict(n)}")

# 6) 新增层 crossfile 用户内容形态：几个代码块（是否真的多文件）
nb = Counter()
for i in crossfile_idx:
    blocks = CODE_RE.findall(rows[i]["messages"][1]["content"])
    nb[len(blocks)] += 1
w(f"crossfile 代码块数分布: {dict(nb)}")

OUT.write_text("\n".join(buf), encoding="utf-8")
print("written")
