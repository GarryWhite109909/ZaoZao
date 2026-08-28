#!/usr/bin/env python3
"""v2.8 补充审计 III：定点核实 #4692/#7778 + 分层偏移分布 + 残余无锚 fix。"""
import json
import re
from collections import Counter
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data/final_train_chatml_alpha06_v2_8.jsonl"
OUT = Path(__file__).resolve().parent / "_audit_v2_8_extra3_out.txt"
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

# 1) #4692 全文终验
r = rows[4692]
obj, m = get_obj(r)
w(f"#4692 hv={obj.get('has_vulnerability')} vt={obj.get('vulnerability_type')} kind={(r.get('meta') or {}).get('kind')}")
a = r["messages"][2]["content"]
w("  CoT 结尾 800 字:")
w("  " + a[: m.start()][-800:].replace("\n", "\n  "))
w("  JSON: " + json.dumps(obj, ensure_ascii=False)[:400])

# 2) #7778 全文终验
r = rows[7778]
obj, m = get_obj(r)
w(f"\n#7778 hv={obj.get('has_vulnerability')} vt={obj.get('vulnerability_type')} kind={(r.get('meta') or {}).get('kind')}")
w("  obj=" + json.dumps(obj, ensure_ascii=False)[:500])
w("  CoT 结尾 500 字: " + r["messages"][2]["content"][: m.start()][-500:].replace("\n", " "))

# 3) [B] 60 条里再抓高嫌疑模式（结论句含"代码含 N 个漏洞/存在漏洞"类断言）
HARD = re.compile(r"代码含\s*\d+\s*个|共\s*\d+\s*处|存在\s*\d+\s*个(漏洞|注入)|上述漏洞|以上漏洞|漏洞综上|确认.{0,4}漏洞.{0,6}(成立|存在)")
hard_hits = []
for i, r in enumerate(rows):
    obj, m = get_obj(r)
    if obj is None or obj.get("has_vulnerability") is not False:
        continue
    pre = r["messages"][2]["content"][: m.start()]
    mm = HARD.search(pre[-350:])
    if mm and not re.search(r"(不|无|未|阻断|拒绝|排除)", pre[max(0, mm.start()-20): mm.start()]):
        hard_hits.append((i, pre[max(0, mm.start()-60): mm.end()+60].replace("\n", " ")))
w(f"\n高嫌疑反向断言: {len(hard_hits)} 条")
for i, ctx in hard_hits[:20]:
    w(f"  #{i}: ...{ctx}...")

# 4) 分层偏移分布
def seg(i):
    kind = (rows[i].get("meta") or {}).get("kind") or ""
    return kind if kind else ("old" if i < 7600 else "mid")

seg_off = {}
for i, r in enumerate(rows):
    obj, m = get_obj(r)
    if obj is None or obj.get("has_vulnerability") is not True:
        continue
    sk = str(obj.get("sink") or "")
    if sk.startswith("L"):
        continue
    mm = re.match(r"line\s*(\d+)\s*:\s*(.+)", sk)
    if not mm:
        continue
    cm = CODE_RE.search(r["messages"][1]["content"])
    if not cm:
        continue
    code_lines = cm.group(2).split("\n")
    n = int(mm.group(1))
    if not (1 <= n <= len(code_lines)):
        continue
    toks = [t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_.]{2,}", mm.group(2))
            if t.lower() not in ("the", "this", "and", "into", "from", "with", "line")]
    if not toks:
        continue
    tok = max(toks, key=len).split(".")[0].lower()
    actual = [j + 1 for j, ln in enumerate(code_lines) if tok in ln.lower()]
    if not actual:
        seg_off.setdefault(seg(i), []).append(None)
        continue
    best = min(actual, key=lambda x: abs(x - n))
    seg_off.setdefault(seg(i), []).append(best - n)

w("\n分层偏移分布 (|off|<=2 视为近似命中):")
for s, offs in sorted(seg_off.items(), key=lambda x: -len(x[1])):
    vals = [o for o in offs if o is not None]
    exact = sum(1 for o in vals if o == 0)
    near = sum(1 for o in vals if abs(o) <= 2)
    none = sum(1 for o in offs if o is None)
    w(f"  {s}: n={len(offs)} 精确={exact}({exact/len(offs):.0%}) ±2内={near}({near/len(offs):.0%}) 找不到token={none}")

# 5) 残余无锚 fix 计数
n_noanchor = 0
for i, r in enumerate(rows):
    obj, m = get_obj(r)
    if obj is None or obj.get("has_vulnerability") is not True:
        continue
    if not re.search(r"[Ll]ine\s*\d+", str(obj.get("fix_suggestion"))):
        n_noanchor += 1
w(f"\n残余无行号锚 fix: {n_noanchor} 条")

OUT.write_text("\n".join(buf), encoding="utf-8")
print("written")
