#!/usr/bin/env python3
"""v2.7 审计第二段：定点深挖问题样本。"""
import json
import re
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))
DATA = PROJECT / "experiments/exp_06_finetune/data/final_train_chatml_alpha06_v2_7.jsonl"
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
CODE_RE = re.compile(r"```([\w+#-]*)\n(.*?)\n```", re.S)

rows = [json.loads(l) for l in DATA.read_text(encoding="utf-8").splitlines() if l.strip()]


def show(i, label, max_u=900, max_a=1500):
    r = rows[i]
    msgs = r["messages"]
    meta = r.get("meta") or {}
    print(f"\n===== [{label}] #{i} kind={meta.get('kind')} meta={ {k: v for k, v in meta.items() if k != 'kind'} }")
    u = msgs[1]["content"]
    blocks = CODE_RE.findall(msgs[1]["content"])
    print(f"  user 总长 {len(u)} | 代码块数 {len(blocks)} | 各块行数 {[b[1].count(chr(10))+1 for b in blocks]}")
    print("  user 开头:", u[:300].replace("\n", "\\n"))
    print("  user 结尾:", u[-200:].replace("\n", "\\n"))
    a = msgs[2]["content"]
    print("  assistant 开头 400:", a[:400].replace("\n", "\\n"))
    print("  assistant 结尾 600:", a[-600:].replace("\n", "\\n"))


# 1) 24 条缺字段（8093-8116）
show(8093, "缺字段-首条")
show(8105, "缺字段-中位")

# 2) vt 无名称
for i in (3255, 3521, 3554, 7493, 7494, 7790):
    r = rows[i]
    m = JSON_RE.search(r["messages"][2]["content"])
    obj = json.loads(m.group(1)) if m else {}
    print(f"\n#{i} vt={obj.get('vulnerability_type')!r} hv={obj.get('has_vulnerability')} kind={(r.get('meta') or {}).get('kind')}")

# 3) safe 侧字段违规样本
n = 0
for i, r in enumerate(rows):
    m = JSON_RE.search(r["messages"][2]["content"])
    if not m:
        continue
    try:
        obj = json.loads(m.group(1))
    except Exception:
        continue
    if obj.get("has_vulnerability") is False and (obj.get("source") != "N/A" or obj.get("sink") != "N/A" or obj.get("fix_suggestion") != "no fix needed"):
        n += 1
        if n <= 6:
            print(f"\n[safe字段违规 #{i}] source={obj.get('source')!r} sink={obj.get('sink')!r} fix={obj.get('fix_suggestion')!r} kind={(r.get('meta') or {}).get('kind')}")
print(f"\nsafe 字段违规合计 {n}")

# 4) 行号越界 3 条
show(8058, "行号越界A")
show(8068, "行号越界B")
show(8085, "行号越界C")

# 5) 冲突对
show(8060, "冲突True")
show(8076, "冲突False")

# 6) CoT 矛盾疑似
for i in (38, 161, 208, 566, 8133):
    r = rows[i]
    m = JSON_RE.search(r["messages"][2]["content"])
    obj = json.loads(m.group(1)) if m else {}
    pre = r["messages"][2]["content"][: m.start()] if m else ""
    print(f"\n[CoT矛盾? #{i}] hv={obj.get('has_vulnerability')} vt={obj.get('vulnerability_type')}")
    print("  json前500:", pre[-500:].replace("\n", "\\n"))

# 7) 纯英文 CoT 分布
zh = re.compile(r"[\u4e00-\u9fff]")
en_rows = []
for i, r in enumerate(rows):
    a = r["messages"][2]["content"]
    m = JSON_RE.search(a)
    pre = a[: m.start()] if m else a
    if not zh.search(pre[:800]):
        en_rows.append((i, (r.get("meta") or {}).get("kind")))
print(f"\n纯英文 CoT: {len(en_rows)} 条; kind分布:", {k: sum(1 for _, kk in en_rows if kk == k) for k in {kk for _, kk in en_rows}})
print("样例:", en_rows[:10])

# 8) user 全文重复组
seen = {}
for i, r in enumerate(rows):
    u = r["messages"][1]["content"]
    if u in seen:
        print(f"\nuser 重复: #{seen[u]} 与 #{i}")
    seen[u] = i

# 9) fix 无行号锚样例
n = 0
for i, r in enumerate(rows):
    m = JSON_RE.search(r["messages"][2]["content"])
    if not m:
        continue
    try:
        obj = json.loads(m.group(1))
    except Exception:
        continue
    if obj.get("has_vulnerability") is True and not re.search(r"[Ll]ine\s*\d+", str(obj.get("fix_suggestion"))):
        n += 1
        if n <= 8:
            print(f"\n[fix无锚 #{i}] {obj.get('fix_suggestion')!r}")
print(f"\nfix 无行号锚合计 {n}")
