# -*- coding: utf-8 -*-
"""复核 S4/S5/S6 信号：字节级转义验证 + 括号不平衡归因 + 凭证上下文。"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acommon import OUT, SRC, load_rows, asst_text, user_text

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

rows = {r["id"]: r for r in load_rows()[0]}

# ---------- S4 字节级验证 ----------
print("=== S4 字节级验证（raw JSON 行片段 vs 解码后） ===")
s4 = [json.loads(l) for l in open(OUT / "s4_escape.jsonl", encoding="utf-8")]
for sid in (10, 13):
    with SRC.open(encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            if i == sid:
                m = re.search(r'"fix_suggestion":\s*"((?:[^"\\]|\\.){0,400})', line)
                print(f"id={sid} RAW: {m.group(1)[:220] if m else '?'}")
                break
o10 = None
a = asst_text(rows[10])
m = re.search(r"```json\s*(.*?)```", a, re.S)
o10 = json.loads(m.group(1))
print(f"id=10 DECODED: {o10['fix_suggestion'][:200]!r}")

# 分类：修复串属 C/类 C 语言样本？
lang_of = {}
for r in rows.values():
    u = r["rec"]["messages"][1]["content"]
    m = re.search(r"```([\w+#.\-]*)", u)
    lang_of[r["id"]] = (m.group(1).lower() if m else "?")
lang_dist = Counter(lang_of.get(x["id"], "?") for x in s4)
print("S4 污染候选按语言 top:", dict(lang_dist.most_common(12)))

# ---------- S5 括号不平衡归因 ----------
print()
print("=== S5 json_unclosed_brace 归因 ===")
s5 = [json.loads(l) for l in open(OUT / "s5_contam.jsonl", encoding="utf-8")]
brace_ids = [x["id"] for x in s5 if any(i["type"] == "json_unclosed_brace" for i in x["issues"])]
reason = Counter()
examples = {}
for sid in brace_ids:
    a = asst_text(rows[sid])
    m = re.search(r"```json\s*(.*?)```", a, re.S)
    frag = m.group(1) if m else ""
    o = None
    try:
        o = json.loads(frag)
    except Exception:
        reason["json_parse_fail"] += 1
        continue
    # 解析成功 → 括号在字符串值内部（如 ${VAR}、代码片段）
    vals = " ".join(str(v) for v in o.values() if isinstance(v, str))
    if "${" in vals or "{" in vals:
        reason["brace_inside_string_value"] += 1
        examples.setdefault("brace_inside_string_value", (sid, vals[:110]))
    else:
        reason["brace_other"] += 1
        examples.setdefault("brace_other", (sid, vals[:110]))
print("归因:", dict(reason))
for k, (sid, v) in examples.items():
    print(f"  例 id={sid}: {v}")
other5 = Counter()
for x in s5:
    for i in x["issues"]:
        if i["type"] != "json_unclosed_brace":
            other5[i["type"]] += 1
            if other5[i["type"]] <= 3:
                print(f"  [{i['type']}] id={x['id']}: {json.dumps(i, ensure_ascii=False)[:160]}")

# ---------- S6 凭证上下文 ----------
print()
print("=== S6 疑似真实格式凭证上下文 ===")
s6 = [json.loads(l) for l in open(OUT / "s6_creds.jsonl", encoding="utf-8")]
for x in s6:
    if not x["dummy_hint"]:
        print(f"id={x['id']} [{x['kind']}] {x['ctx'][:130]}")
