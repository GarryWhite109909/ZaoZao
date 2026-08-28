# -*- coding: utf-8 -*-
"""风格双峰检测：按 kind 统计分析长度 / explanation 长度 / 步骤数"""
import json, re, sys, collections, statistics
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SRC = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_alpha06_v2_12.jsonl")
OUT = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\audit\a10_bimodal_out.txt")

rows = []
with SRC.open("r", encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if line: rows.append((i, json.loads(line)))
def get(msgs, role):
    for m in msgs:
        if m.get("role") == role: return m.get("content", "")
    return ""
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)

by_kind = collections.defaultdict(lambda: dict(anal=[], expl=[], steps=[], n=0, hv=collections.Counter()))
for i, r in rows:
    msgs = r["messages"]
    a = get(msgs, "assistant")
    kind = (r.get("meta") or {}).get("kind", "none")
    blocks = list(JSON_BLOCK.finditer(a))
    o = None
    if blocks:
        try: o = json.loads(blocks[-1].group(1))
        except Exception: pass
    anal = a[:blocks[-1].start()] if blocks else a
    d = by_kind[kind]
    d["n"] += 1
    d["anal"].append(len(re.sub(r"\s+","",anal)))
    d["steps"].append(len(re.findall(r"^\s*\d+[\.、]\s*", anal, re.M)))
    if o:
        d["expl"].append(len(str(o.get("explanation",""))))
        d["hv"][o.get("has_vulnerability")] += 1

w = OUT.open("w", encoding="utf-8")
def P(*a): print(*a, file=w)
med = lambda x: statistics.median(x) if x else 0

P("=" * 100)
P("风格双峰检测：各 kind 的分析长度 / explanation 长度 / 步骤数（中位数）")
P("=" * 100)
P(f"{'kind':28s} {'条数':>6s} {'分析中位':>9s} {'分析p90':>8s} {'expl中位':>9s} {'步骤中位':>8s} {'正/负':>12s}")
P("-" * 100)
items = sorted(by_kind.items(), key=lambda x: -x[1]["n"])
for kind, d in items:
    a_sorted = sorted(d["anal"])
    p90 = a_sorted[int(.9*(len(a_sorted)-1))] if a_sorted else 0
    hv = d["hv"]
    P(f"{kind:28s} {d['n']:6d} {med(d['anal']):9.0f} {p90:8.0f} {med(d['expl']):9.0f} "
      f"{med(d['steps']):8.0f}   {hv[True]:5d}/{hv[False]:<5d}")

base = by_kind["none"]
new_anal = []
new_expl = []
for kind, d in by_kind.items():
    if kind == "none": continue
    new_anal += d["anal"]; new_expl += d["expl"]
P("\n" + "-" * 100)
P("基础库 vs 新增针对性数据")
P("-" * 100)
P(f"  基础库 (kind=none, {base['n']} 条): 分析中位 {med(base['anal']):.0f} 字符, "
  f"explanation 中位 {med(base['expl']):.0f} 字符")
P(f"  新增   (有 kind,  {sum(d['n'] for k,d in items if k!='none')} 条): 分析中位 {med(new_anal):.0f} 字符, "
  f"explanation 中位 {med(new_expl):.0f} 字符")
P(f"  >> 分析长度倍数: {med(new_anal)/max(med(base['anal']),1):.2f}x   "
  f"explanation 倍数: {med(new_expl)/max(med(base['expl']),1):.2f}x")

# explanation 长度总分布
all_expl = []
for kind, d in by_kind.items():
    all_expl += d["expl"]
all_expl.sort()
P(f"\n  explanation 长度分布: n={len(all_expl)} p25={all_expl[len(all_expl)//4]} "
  f"med={statistics.median(all_expl):.0f} p75={all_expl[3*len(all_expl)//4]} "
  f"p90={all_expl[int(.9*len(all_expl))]} p99={all_expl[int(.99*len(all_expl))]} max={all_expl[-1]}")
for th in [100, 200, 400, 800, 1500]:
    c = sum(1 for x in all_expl if x > th)
    P(f"    > {th} 字符: {c} ({c/len(all_expl)*100:.1f}%)")
P(f"    <= 20 字符(=N/A 等): {sum(1 for x in all_expl if x<=20)} "
  f"({sum(1 for x in all_expl if x<=20)/len(all_expl)*100:.1f}%)")

w.close()
print("done")
