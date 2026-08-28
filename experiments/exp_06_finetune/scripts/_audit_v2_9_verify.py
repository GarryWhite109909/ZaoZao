#!/usr/bin/env python3
"""v2.9 复审：毒样本/泄漏/锚定命中率/契约 + 吸附与剥离的定点人工核验。"""
import json
import re
from collections import Counter
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data/final_train_chatml_alpha06_v2_9.jsonl"
OUT = Path(__file__).resolve().parent / "_audit_v2_9_verify_out.txt"
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

w(f"v2.9 总条数 {len(rows)}")

# 1) 毒样本/自白扫描
CONFESS = ["根据指令", "指令要求", "应标记为", "标注为有漏洞", "标注为无漏洞", "实际不安全",
           "实际无漏洞", "被要求", "要求为 false", "要求为 true", "此处结论为", "但标注为",
           "本应标记", "按题目要求", "为满足", "需假设", "需修正", "已生成", "生成要求"]
hits = []
for i, r in enumerate(rows):
    a = r["messages"][2]["content"]
    f = [t for t in CONFESS if t in a]
    if f:
        hits.append((i, f))
w(f"\n[1] 毒词/自白扫描: {len(hits)} 条")
for i, f in hits[:20]:
    w(f"  #{i} {f}")

# 2) 泄漏注释复查（与审计同口径）
SRC_SINK_HINT = re.compile(r"(//|#|\*|--|<!--)\s*.{0,50}(source[:：]|sink[:：]|attacker[- ]controlled)", re.I)
n_leak = 0
for i, r in enumerate(rows):
    for lg, body in CODE_RE.findall(r["messages"][1]["content"]):
        if SRC_SINK_HINT.search(body):
            n_leak += 1
            break
w(f"\n[2] EN source/sink 泄漏注释残留: {n_leak} 条")

# 3) sink 锚定命中率（与上轮同口径对比：v2.8 精确 32% / ±2 67%）
offsets = Counter()
checked = 0
not_found = 0
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
    blocks = [(t, b) for t, b in CODE_RE.findall(r["messages"][1]["content"]) if t != "json"]
    if not blocks or "# === file:" in r["messages"][1]["content"]:
        continue
    _, code = max(blocks, key=lambda x: len(x[1]))
    if len(re.findall(r"^\s*\d+\s*\|", code, re.M)) >= 5:
        continue
    code_lines = code.split("\n")
    n = int(mm.group(1))
    if not (1 <= n <= len(code_lines)):
        continue
    toks = [t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_.]{2,}", mm.group(2))
            if t.lower() not in ("the", "this", "and", "into", "from", "with", "line")]
    if not toks:
        continue
    tok = max(toks, key=len).lower()
    actual = [j + 1 for j, ln in enumerate(code_lines) if tok in ln.lower()]
    if not actual:
        not_found += 1
        continue
    checked += 1
    best = min(actual, key=lambda x: abs(x - n))
    offsets[best - n] += 1
exact = offsets[0]
near = sum(v for k, v in offsets.items() if abs(k) <= 2)
w(f"\n[3] sink 锚定（同口径）: 核验 {checked} | 精确 {exact}({exact/max(checked,1):.0%}) | ±2内 {near}({near/max(checked,1):.0%}) | token找不到 {not_found}")

# 4) 契约终态
rl, vt_bad, ph = Counter(), 0, 0
PH_KW = ["用 -> 描述", "CWE-编号", "最小局部改正", "true/false"]
for i, r in enumerate(rows):
    obj, m = get_obj(r)
    if obj is None:
        continue
    if obj.get("has_vulnerability") is True and "is_confirmed" not in obj:
        rl[obj.get("risk_level")] += 1
        vt = str(obj.get("vulnerability_type") or "")
        if re.match(r"^CWE-\d+$", vt):
            vt_bad += 1
    for k, v in obj.items():
        if isinstance(v, str) and any(p in v for p in PH_KW):
            ph += 1
w(f"\n[4] 契约: risk={dict(rl)} | 裸编号vt={vt_bad} | 占位符={ph}")

# 5) 剥离正确性抽查：找 3 条被剥离样本，看代码语法是否破坏
stripped = []
for i, r in enumerate(rows):
    u = r["messages"][1]["content"]
    for lg, body in CODE_RE.findall(u):
        # 曾有泄漏注释的样本：现应无注释但行内有代码被截断的痕迹（行尾突然以 ( 或 , 结尾）
        if re.search(r"[\(,]\s*$", body, re.M) and re.search(r"query|request|req\b", body):
            pass
    stripped.append(i)
# 直接抽 3 条 old 层 py 样本展示代码头部
w("\n[5] 剥离样本抽查（代码完整性目测）:")
import random
random.seed(42)
cand = [i for i, r in enumerate(rows) if (r.get("meta") or {}).get("kind") in (None, "-")]
for i in random.sample(cand, 2):
    r = rows[i]
    blocks = CODE_RE.findall(r["messages"][1]["content"])
    if not blocks:
        continue
    body = max(blocks, key=lambda x: len(x[1]))[1]
    w(f"--- #{i} 代码前 500 字符:")
    w(body[:500])

# 6) 吸附定点核验：抽报告日志中 5 组，核对吸附后行是否含 token
w("\n[6] 吸附后字段-代码一致性抽验（全量）:")
bad_snap = 0
tot_snap = 0
for i, r in enumerate(rows):
    obj, m = get_obj(r)
    if obj is None or obj.get("has_vulnerability") is not True:
        continue
    blocks = [(t, b) for t, b in CODE_RE.findall(r["messages"][1]["content"]) if t != "json"]
    if not blocks or "# === file:" in r["messages"][1]["content"]:
        continue
    _, code = max(blocks, key=lambda x: len(x[1]))
    if len(re.findall(r"^\s*\d+\s*\|", code, re.M)) >= 5:
        continue
    code_lines = code.split("\n")
    for fld in ("source", "sink"):
        v = str(obj.get(fld) or "")
        mm = re.match(r"line\s*(\d+)\s*:\s*(.+)", v)
        if not mm:
            continue
        toks = [t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_.]{2,}", mm.group(2))
                if t.lower() not in ("the", "this", "and", "into", "from", "with", "line")]
        if not toks:
            continue
        tok = max(toks, key=len).lower()
        n = int(mm.group(1))
        tot_snap += 1
        if 1 <= n <= len(code_lines) and tok not in code_lines[n - 1].lower():
            bad_snap += 1
            if bad_snap <= 8:
                w(f"  #{i} {fld} line {n} 含 '{tok}'? 实际: {code_lines[n-1].strip()[:60]!r}")
w(f"核验 {tot_snap} 字段锚 | 不一致 {bad_snap} ({bad_snap/max(tot_snap,1):.1%})")

OUT.write_text("\n".join(buf), encoding="utf-8")
print("written")
