#!/usr/bin/env python3
"""v2.8 补充审计 II：诊断 sink 锚定 66% 失配的真因 + 精化各项。"""
import json
import re
from collections import Counter
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data/final_train_chatml_alpha06_v2_8.jsonl"
OUT = Path(__file__).resolve().parent / "_audit_v2_8_extra2_out.txt"
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

# ---------- A. 锚定失配诊断：计算偏移分布 ----------
offsets = Counter()
found_at = 0
not_found = 0
examples = []
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
    rest = mm.group(2)
    toks = re.findall(r"[A-Za-z_][A-Za-z0-9_.]{2,}", rest)
    toks = [t for t in toks if t.lower() not in ("the", "this", "and", "into", "from", "with", "line")]
    if not toks:
        continue
    tok = max(toks, key=len).split(".")[0].lower()
    # 在全代码块中找 token 实际所在行
    actual = [j + 1 for j, ln in enumerate(code_lines) if tok in ln.lower()]
    if not actual:
        not_found += 1
        continue
    # 找距声称行号最近的实际行
    best = min(actual, key=lambda x: abs(x - n))
    off = best - n
    offsets[off] += 1
    if off != 0:
        found_at += 1
        if len(examples) < 12:
            examples.append((i, n, best, tok, code_lines[n - 1].strip()[:50], code_lines[best - 1].strip()[:50]))
    else:
        found_at += 1

w(f"[A] 锚定诊断: token 在代码中找到 {found_at} 条, 完全找不到 {not_found} 条")
w(f"偏移分布 (实际行-声称行): {dict(sorted(offsets.items(), key=lambda x: -x[1])[:15])}")
w("非零偏移示例:")
for i, n, best, tok, ln_n, ln_b in examples:
    w(f"  #{i} 声称 L{n} 实际 L{best} tok={tok} | L{n}: {ln_n!r} | L{best}: {ln_b!r}")

# 按区段统计失配率（老层 vs 新层）
def seg(i):
    kind = (rows[i].get("meta") or {}).get("kind") or ""
    return kind if kind else ("old" if i < 7600 else "wave/distill 区段")

seg_total, seg_bad = Counter(), Counter()
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
    s = seg(i)
    seg_total[s] += 1
    if tok not in code_lines[n - 1].lower():
        seg_bad[s] += 1
w("\n[A2] 按 kind 的失配率:")
for s in seg_total:
    w(f"  {s}: {seg_bad[s]}/{seg_total[s]} = {seg_bad[s]/seg_total[s]:.0%}")

# ---------- B. 精化反向矛盾（否定词感知） ----------
NEG_BEFORE = re.compile(r"(不|无|非|未|无法|不能|阻断|拒绝|不存在|没有)[^。\n]{0,12}$")
REV = re.compile(r"(存在|构成|确认|判定|属于|触发|成立)[^。\n]{0,10}(漏洞|注入|越权|穿越|XSS|SSRF|溢出)|攻击者可(注入|读取|执行|访问|越权|构造)|任意文件(读取|写入|执行)")
refined = []
for i, r in enumerate(rows):
    obj, m = get_obj(r)
    if obj is None or obj.get("has_vulnerability") is not False:
        continue
    pre = r["messages"][2]["content"][: m.start()]
    tail = pre[-300:]
    hit = None
    for mm in REV.finditer(tail):
        before = tail[: mm.start()]
        if NEG_BEFORE.search(before[-30:]) or re.search(r"(不|无|未|无法|阻断)", before[-8:]):
            continue
        # 结论句里还要排除假设语气
        s = max(0, mm.start() - 40)
        ctx = tail[s: mm.end() + 40].replace("\n", " ")
        if re.search(r"(即使|若|如果|假设|一旦|就算|除非)", ctx):
            continue
        hit = ctx
        break
    if hit:
        refined.append((i, hit))
w(f"\n[B] 精化反向矛盾: {len(refined)} 条")
for i, ctx in refined[:25]:
    w(f"  #{i}: ...{ctx}...")

# ---------- C. safe 侧 fix_suggestion 违规（排除 triage 4字段） ----------
c_bad = []
for i, r in enumerate(rows):
    obj, m = get_obj(r)
    if obj is None or obj.get("has_vulnerability") is not False or "is_confirmed" in obj:
        continue
    fx = obj.get("fix_suggestion")
    if fx != "no fix needed":
        c_bad.append((i, str(fx)[:60]))
w(f"\n[C] safe 侧 fix 非 no-fix-needed: {len(c_bad)} 条")
for i, fx in c_bad[:12]:
    w(f"  #{i} {fx!r}")

# ---------- D. 泄漏注释分类 ----------
SRC_SINK_HINT = re.compile(r"(//|#|\*|--|<!--)\s*.{0,50}(source[:：]|sink[:：]|attacker[- ]controlled)", re.I)
CN_HINT = re.compile(r"(//|#|\*|--|<!--).{0,40}(攻击者可控|用户可控|不可信)", re.I)
BUG_HINT = re.compile(r"(//|#|\*|--|<!--).{0,30}(注意.{0,8}未|故意|漏洞在此|VULN|BUG:|不安全|未校验|未净化|未转义)", re.I)
tax = Counter()
for i, r in enumerate(rows):
    for lg, body in CODE_RE.findall(r["messages"][1]["content"]):
        s = SRC_SINK_HINT.search(body)
        c = CN_HINT.search(body)
        b = BUG_HINT.search(body)
        if s:
            tax["EN source/sink 标注"] += 1
        elif c:
            tax["中文可控性注释"] += 1
        elif b:
            tax["bug 揭示注释"] += 1
        if s or c or b:
            break
w(f"\n[D] 泄漏注释分类: {dict(tax)}")

# ---------- E. 元话语残留 triage ----------
for i in (3311, 3480, 920, 3143, 25):
    r = rows[i]
    a = r["messages"][2]["content"]
    w(f"\n[E] #{i}:")
    for kw in ("已生成", "假设存在", "本应"):
        p = a.find(kw)
        if p >= 0:
            w(f"  {kw!r} @ {p}: ...{a[max(0,p-60):p+80]}...".replace("\n", " "))
            break

# ---------- F. 7 条 cwe 漂移的 explanation 首句 ----------
w("\n[F] 漂移样本裁定材料:")
for i in (8043, 8044, 8045, 8046, 8048):
    obj, m = get_obj(rows[i])
    meta = rows[i].get("meta") or {}
    w(f"  #{i} seed={meta.get('seed_file')} cve={meta.get('cve')} 种子CWE={meta.get('cwe')} → 输出={obj.get('vulnerability_type')}")
    w(f"     expl: {str(obj.get('explanation'))[:150]}")

OUT.write_text("\n".join(buf), encoding="utf-8")
print("written")
