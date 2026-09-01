# -*- coding: utf-8 -*-
"""Pass1:FIX 清单 234 条的行号重锚 —— 产出 ops 决策日志(不直接改数据)。

ops schema:
  {"id", "op": "reline", "field", "moves": [[old_n, new_n], ...], "method": "evidence|identifier", "why"}
  {"id", "op": "manual", "field", "why"}   # 无法确定性重锚,留人工/2.1
策略:
  1) evidence 优先:review evidence 中「X ... 实际(在)? L/Y」映射对
  2) identifier 回退:字段描述中的标识符在 code_lines 全文唯一命中且当前锚不含它
  3) 当前锚已命中(宽松) → 不动;多候选 → manual
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
OUT = Path(__file__).resolve().parent / "agent_audit_v2_14" / "out"

wb = [json.loads(l) for l in (OUT / "fix13_workbench.jsonl").open(encoding="utf-8")]
ops = []

STOP = {"line", "none", "null", "true", "false", "http", "https", "user", "input",
        "attack", "attacker", "line.", "this", "that", "with", "from", "into"}

def norm(s):
    return re.sub(r"\s+", " ", s).strip().lower()

def extract_ids(desc):
    toks = re.findall(r"[A-Za-z_][A-Za-z0-9_.\-]{3,}", desc)
    toks = [t.rstrip(".-") for t in toks if t.lower() not in STOP]
    toks.sort(key=len, reverse=True)
    return toks

def find_lines(ids, code_lines, exclude=None):
    """返回按命中标识符数排序的候选行。"""
    hits = {}
    for n, content in code_lines.items():
        if exclude and n == exclude:
            continue
        c = norm(content)
        score = sum(1 for t in ids[:5] if t.lower() in c or t.split(".")[-1].lower() in c)
        if score:
            hits[n] = score
    return sorted(hits.items(), key=lambda kv: -kv[1])

def anchored_hit(desc, content):
    ids = extract_ids(desc)
    c = norm(content)
    return any(t.lower() in c or t.split(".")[-1].lower() in c for t in ids[:5])

# evidence 中的行号修正映射:「line X ... 实际 L Y」「实为 Y」「实际在 line Y」
EV_MAP = re.compile(r"[「`\"]?line\s*(\d{1,4})[」`\":：][^。|\n]{0,60}?实际(?:在|为)?\s*(?:line\s*)?L?(\d{1,4})")
EV_MAP2 = re.compile(r"(?:source|sink|fix[^。]{0,6}|explanation)[^。|\n]{0,40}?实际(?:在|为)?\s*(?:line\s*)?L?(\d{1,4})[^。|\n]{0,10}?(?:[（(]实际|[，,;；]|\))")

for it in wb:
    rid = it["id"]
    code_lines = {int(k): v for k, v in it["code_lines"].items()}
    ev = "；".join(e["evidence"] for e in it["review_errors"]) + "；" + it["review_note"]
    ev_pairs = {}   # field-agnostic: old->new
    for m in EV_MAP.finditer(ev):
        ev_pairs.setdefault(int(m.group(1)), int(m.group(2)))
    tj = it["teacher_json"] or {}
    for fld in ("source", "sink"):
        v = str(tj.get(fld, "") or "")
        if not v:
            continue
        m = re.search(r"line\s*(\d{1,4})", v)
        if not m:
            continue
        old_n = int(m.group(1))
        desc = v[m.end():]
        # 1) 当前锚命中 → 不动
        if 0 < old_n <= len(code_lines) and anchored_hit(desc, code_lines.get(old_n, "")):
            continue
        # 2) evidence 映射
        if old_n in ev_pairs and 0 < ev_pairs[old_n] <= len(code_lines):
            ops.append({"id": rid, "op": "reline", "field": fld, "moves": [[old_n, ev_pairs[old_n]]],
                        "method": "evidence", "why": f"evidence 指认实际行 {ev_pairs[old_n]}"})
            continue
        # 3) 标识符唯一命中
        ids = extract_ids(desc)
        if not ids:
            ops.append({"id": rid, "op": "manual", "field": fld, "why": f"锚 line {old_n} 脱靶且无可提取标识符"})
            continue
        cands = find_lines(ids, code_lines, exclude=old_n)
        # 当前内容部分命中主标识符的次级词也视为命中(保守:不动)
        top = ids[0]
        cand = [n for n, s in cands if s >= 2] or [n for n, s in cands if s >= 1]
        uniq = None
        if len(cand) == 1:
            uniq = cand[0]
        elif len(cand) > 1:
            # 多候选:若最高分严格唯一,取之
            best = cands[0][1]
            tops = [n for n, s in cands if s == best]
            if len(tops) == 1 and best >= 2:
                uniq = tops[0]
        if uniq:
            ops.append({"id": rid, "op": "reline", "field": fld, "moves": [[old_n, uniq]],
                        "method": "identifier", "why": f"标识符 {top!r} 唯一/最高分命中 line {uniq}"})
        else:
            ops.append({"id": rid, "op": "manual", "field": fld,
                        "why": f"锚 line {old_n} 脱靶;候选 {[n for n,_ in cands[:4]]} 不唯一"})

from collections import Counter
c = Counter(o["op"] for o in ops)
c2 = Counter(o.get("method") for o in ops if o["op"] == "reline")
print("ops 统计:", dict(c), "| reline 方法:", dict(c2))
with (OUT / "fix13_ops_pass1.jsonl").open("w", encoding="utf-8") as f:
    for o in ops:
        f.write(json.dumps(o, ensure_ascii=False) + "\n")
print("-> fix13_ops_pass1.jsonl")
