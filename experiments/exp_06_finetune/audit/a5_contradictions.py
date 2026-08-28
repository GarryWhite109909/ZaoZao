# -*- coding: utf-8 -*-
"""标签矛盾检测 + 分层抽样（供人工判读）"""
import json, re, sys, collections, random
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SRC = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_alpha06_v2_12.jsonl")
OUT = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\audit\a5_contradictions_out.txt")

rows = []
with SRC.open("r", encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if line:
            rows.append((i, json.loads(line)))
R = dict(rows)
def get(msgs, role):
    for m in msgs:
        if m.get("role") == role:
            return m.get("content", "")
    return ""
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)

recs = []
for i, r in rows:
    msgs = r["messages"]
    a = get(msgs, "assistant")
    blocks = list(JSON_BLOCK.finditer(a))
    o = None
    if blocks:
        try: o = json.loads(blocks[-1].group(1))
        except Exception: pass
    recs.append(dict(i=i, u=get(msgs,"user"), a=a, o=o, meta=r.get("meta"),
                     sysshort=len(get(msgs,"system")) < 1500))

w = OUT.open("w", encoding="utf-8")
def P(*a): print(*a, file=w)

# ---------- 1. 漏洞样本但 source/sink 说"无" ----------
P("=" * 78); P("[1] has_vulnerability=true 但 source/sink 自述'无/未发现'（标签矛盾）"); P("=" * 78)
NEG = re.compile(r"(无|未发现|不存在|没有|N/A|n/a)", re.I)
bad = []
for r in recs:
    o = r["o"]
    if not o or o.get("has_vulnerability") is not True: continue
    s, k = str(o.get("source","")), str(o.get("sink",""))
    if NEG.fullmatch(s.strip()) or NEG.search(s[:8]) or NEG.fullmatch(k.strip()) or NEG.search(k[:8]):
        bad.append(r)
P(f"  共 {len(bad)} 条")
for r in bad[:25]:
    o = r["o"]
    P(f"\n  ---- line {r['i']} ----")
    P(f"    vt={o.get('vulnerability_type')} risk={o.get('risk_level')}")
    P(f"    source={o.get('source')!r}")
    P(f"    sink={o.get('sink')!r}")
    P(f"    expl={str(o.get('explanation'))[:200]!r}")
    P(f"    USER: {r['u'][:400]}")

# ---------- 2. 漏洞样本但 explanation 说安全 ----------
P("\n" + "=" * 78); P("[2] has_vulnerability=true 但 explanation 出现否定/安全措辞"); P("=" * 78)
SAFEWORD = re.compile(r"(未发现漏洞|无漏洞|不构成漏洞|是安全的|代码安全|不存在安全|无需修复|误报|不可利用|无法利用)")
cnt = 0
for r in recs:
    o = r["o"]
    if not o or o.get("has_vulnerability") is not True: continue
    e = str(o.get("explanation",""))
    if SAFEWORD.search(e):
        cnt += 1
        if cnt <= 20:
            P(f"\n  line {r['i']}: expl={e[:260]!r}")
            P(f"    vt={o.get('vulnerability_type')}")
P(f"  共 {cnt} 条")

# ---------- 3. 安全样本但 explanation 说有风险 ----------
P("\n" + "=" * 78); P("[3] has_vulnerability=false 但 explanation/source/sink 出现漏洞措辞"); P("=" * 78)
RISKW = re.compile(r"(可注入|可被利用|存在漏洞|攻击者可以|可导致|危险|可绕过|CWE-\d+.*注入)")
cnt2 = 0
for r in recs:
    o = r["o"]
    if not o or o.get("has_vulnerability") is not False: continue
    e = str(o.get("explanation","")) + " " + str(o.get("sink",""))
    if RISKW.search(e):
        cnt2 += 1
        if cnt2 <= 20:
            P(f"\n  line {r['i']}: sink={str(o.get('sink'))[:120]!r}")
            P(f"    expl={str(o.get('explanation'))[:220]!r}")
P(f"  共 {cnt2} 条")

# ---------- 4. 安全样本却给了具体 source/sink 行号（与规范 N/A 冲突）----------
P("\n" + "=" * 78); P("[4] 安全样本 source/sink/fix 未按规范填 N/A"); P("=" * 78)
c = collections.Counter()
ex = collections.defaultdict(list)
for r in recs:
    o = r["o"]
    if not o or o.get("has_vulnerability") is not False: continue
    if str(o.get("source","")).strip() != "N/A":
        c["source非N/A"] += 1; ex["source非N/A"].append((r["i"], str(o.get("source"))[:80]))
    if str(o.get("sink","")).strip() != "N/A":
        c["sink非N/A"] += 1; ex["sink非N/A"].append((r["i"], str(o.get("sink"))[:80]))
    if str(o.get("fix_suggestion","")).strip() != "no fix needed":
        c["fix非no-fix-needed"] += 1; ex["fix非no-fix-needed"].append((r["i"], str(o.get("fix_suggestion"))[:80]))
P(f"  {dict(c)}")
for k, v in ex.items():
    P(f"  {k} 样例:")
    for i, s in v[:8]:
        P(f"    line {i}: {s!r}")

# ---------- 5. 规范：漏洞样本 source/sink 是否都带 line ----------
P("\n" + "=" * 78); P("[5] 漏洞样本 source/sink 行号锚点覆盖率"); P("=" * 78)
tot_v = 0; src_ok = 0; snk_ok = 0; fx_ok = 0
no_line = []
for r in recs:
    o = r["o"]
    if not o or o.get("has_vulnerability") is not True: continue
    tot_v += 1
    if re.search(r"line\s*\d+", str(o.get("source",""))): src_ok += 1
    else: no_line.append((r["i"], "source", str(o.get("source"))[:60]))
    if re.search(r"line\s*\d+", str(o.get("sink",""))): snk_ok += 1
    else: no_line.append((r["i"], "sink", str(o.get("sink"))[:60]))
    if re.search(r"line\s*\d+", str(o.get("fix_suggestion",""))): fx_ok += 1
P(f"  漏洞样本 {tot_v}: source 有行号 {src_ok} ({src_ok/tot_v*100:.1f}%), "
  f"sink 有行号 {snk_ok} ({snk_ok/tot_v*100:.1f}%), fix 有行号 {fx_ok} ({fx_ok/tot_v*100:.1f}%)")
P("  无行号样例:")
for x in no_line[:20]:
    P(f"    {x}")

# ---------- 6. 用户代码带行号时，校验标注行号处是否真是所述 API ----------
P("\n" + "=" * 78); P("[6] source/sink 标注行与代码该行内容是否对得上（抽样校验）"); P("=" * 78)
mismatch = []
checked = 0
for r in recs:
    o = r["o"]
    if not o or o.get("has_vulnerability") is not True: continue
    u = r["u"]
    lines = {}
    for m in re.finditer(r"^\s*(\d+)\|(.*)$", u, re.M):
        lines[int(m.group(1))] = m.group(2)
    if not lines: continue
    for fld in ("source", "sink"):
        v = str(o.get(fld, ""))
        mm = re.search(r"line\s*(\d+)", v)
        if not mm: continue
        ln = int(mm.group(1))
        if ln not in lines: continue
        checked += 1
        code = lines[ln]
        # 从标注文本里抽取可能的标识符
        ids = re.findall(r"[A-Za-z_][A-Za-z0-9_\.]{3,}", v)
        ids = [x for x in ids if x.lower() not in ("line", "http", "https")]
        if ids:
            if not any(x.split(".")[-1] in code or x in code for x in ids):
                mismatch.append((r["i"], fld, ln, v[:70], code.strip()[:70]))
P(f"  校验了 {checked} 处标注；疑似对不上 {len(mismatch)} 处")
for x in mismatch[:25]:
    P(f"    line {x[0]} {x[1]}@{x[2]}: 标注={x[3]!r} 代码={x[4]!r}")

w.close()
print("done")
