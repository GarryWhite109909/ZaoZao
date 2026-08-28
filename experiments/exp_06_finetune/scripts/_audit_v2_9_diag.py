#!/usr/bin/env python3
"""v2.9 诊断：吸附未命中原因 / ±5 窗口收益 / 残留泄漏注释形态 / 两条'为满足'裁定。"""
import json
import re
from collections import Counter
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data/final_train_chatml_alpha06_v2_9.jsonl"
OUT = Path(__file__).resolve().parent / "_audit_v2_9_diag_out.txt"
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
CODE_RE = re.compile(r"```([\w+#./-]*)\n(.*?)\n```", re.S)

rows = [json.loads(l) for l in DATA.read_text(encoding="utf-8").splitlines() if l.strip()]
buf = []
def w(s=""):
    buf.append(str(s))

def get_obj(r):
    m = JSON_RE.search(r["messages"][2]["content"])
    if not m:
        return None, None
    try:
        return json.loads(m.group(1)), m
    except Exception:
        return None, None

# 1) #1 吸附未命中调试
for idx in (0, 1, 5):
    r = rows[idx]
    obj, _ = get_obj(r)
    blocks = [(t, b) for t, b in CODE_RE.findall(r["messages"][1]["content"]) if t != "json"]
    _, code = max(blocks, key=lambda x: len(x[1]))
    cl = code.split("\n")
    w(f"\n--- #{idx} sink={obj.get('sink')!r}")
    for fld in ("source", "sink"):
        v = str(obj.get(fld) or "")
        mm = re.match(r"line\s*(\d+)\s*:\s*(.+)", v)
        if not mm:
            continue
        toks = re.findall(r"[A-Za-z_][A-Za-z0-9_.]{2,}", mm.group(2))
        w(f"  {fld} tokens={toks[:4]}")
        for t in toks[:2]:
            hits = [j + 1 for j, ln in enumerate(cl) if t.lower() in ln.lower()]
            w(f"    '{t}' 出现行: {hits[:12]}")

# 2) ±5 窗口收益预估（sink，与 verify 同口径）
for WIN in (3, 5, 8):
    snap_n = 0
    tot = 0
    for i, r in enumerate(rows):
        obj, _ = get_obj(r)
        if obj is None or obj.get("has_vulnerability") is not True:
            continue
        sk = str(obj.get("sink") or "")
        mm = re.match(r"line\s*(\d+)\s*:\s*(.+)", sk)
        if not mm or sk.startswith("L"):
            continue
        u = r["messages"][1]["content"]
        if "# === file:" in u:
            continue
        blocks = [(t, b) for t, b in CODE_RE.findall(u) if t != "json"]
        if not blocks:
            continue
        _, code = max(blocks, key=lambda x: len(x[1]))
        if len(re.findall(r"^\s*\d+\s*\|", code, re.M)) >= 5:
            continue
        cl = code.split("\n")
        n = int(mm.group(1))
        if not (1 <= n <= len(cl)):
            continue
        toks = [t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_.]{2,}", mm.group(2))
                if t.lower() not in ("the", "this", "and", "into", "from", "with", "line")]
        if not toks:
            continue
        tot += 1
        if any(t.lower() in cl[n - 1].lower() for t in toks[:3]):
            continue
        tok = max(toks, key=len).lower()
        cand = [j + 1 for j, ln in enumerate(cl) if tok in ln.lower()]
        near = [c for c in cand if abs(c - n) <= WIN]
        if len(near) == 1 and near[0] != n:
            snap_n += 1
    w(f"\n[2] ±{WIN} 窗口：sink 可吸附 {snap_n}/{tot}（v2.9 已修过一轮后的残余口径）")

# 3) 残留泄漏注释形态
SRC_SINK_HINT = re.compile(r"(//|#|\*|--|<!--)\s*.{0,50}(source[:：]|sink[:：]|attacker[- ]controlled)", re.I)
w("\n[3] 残留泄漏注释:")
for i, r in enumerate(rows):
    for lg, body in CODE_RE.findall(r["messages"][1]["content"]):
        for m in SRC_SINK_HINT.finditer(body):
            ln_start = body.rfind("\n", 0, m.start()) + 1
            ln_end = body.find("\n", m.end())
            w(f"  #{i} [{lg}] ...{body[ln_start:ln_end][:100]!r}...")
            break
        else:
            continue
        break

# 4) #8308/#8373 '为满足' 裁定
for i in (8308, 8373):
    r = rows[i]
    a = r["messages"][2]["content"]
    p = a.find("为满足")
    w(f"\n[4] #{i} kind={(r.get('meta') or {}).get('kind')} hv={get_obj(r)[0].get('has_vulnerability') if get_obj(r)[0] else '?'}")
    w("  " + a[max(0, p - 150): p + 150].replace("\n", " "))

OUT.write_text("\n".join(buf), encoding="utf-8")
print("written")
