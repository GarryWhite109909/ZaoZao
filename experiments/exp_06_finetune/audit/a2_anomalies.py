# -*- coding: utf-8 -*-
"""异常点深挖：异种system / 重复assistant / 解析失败 / 超长样本 / meta分布"""
import json, re, sys, hashlib, collections
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SRC = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_alpha06_v2_12.jsonl")
OUT = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\audit\a2_anomalies_out.txt")
rows = []
with SRC.open("r", encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if line:
            rows.append((i, json.loads(line)))

w = OUT.open("w", encoding="utf-8")
def P(*a): print(*a, file=w)

def get(msgs, role):
    for m in msgs:
        if m.get("role") == role:
            return m.get("content", "")
    return ""

# ---------- meta / kind 分布 ----------
P("=" * 78); P("[A] meta 与 kind 分布"); P("=" * 78)
metakeys = collections.Counter()
kinds = collections.Counter()
kind_without_meta = 0
for i, r in rows:
    meta = r.get("meta")
    if meta is None:
        kind_without_meta += 1
        continue
    if isinstance(meta, dict):
        metakeys[tuple(sorted(meta.keys()))] += 1
        kinds[meta.get("kind", "<no-kind>")] += 1
    else:
        metakeys[("<<non-dict>>",)] += 1
P(f"  无 meta 字段: {kind_without_meta} 条；有 meta: {len(rows)-kind_without_meta} 条")
P(f"  meta 的 key 组合: {dict(metakeys)}")
P("  kind 分布:")
for k, v in kinds.most_common():
    P(f"    {k}: {v}")

# ---------- 异种 system 的 24 条 ----------
P("\n" + "=" * 78); P("[B] 异种 system prompt 的 24 条（行 8069+）"); P("=" * 78)
odd = []
for i, r in rows:
    s = get(r["messages"], "system")
    if len(s) < 1500:
        odd.append(i)
P(f"  行号: {odd}")
for i in odd[:3]:
    r = dict(rows)[i]
    P(f"\n  ---- line {i} ----")
    P(f"  [SYSTEM] {get(r['messages'],'system')[:900]}")
    P(f"  [USER] {get(r['messages'],'user')[:600]}")
    P(f"  [ASSISTANT] {get(r['messages'],'assistant')[:1200]}")
# 这 24 条的 JSON 字段集合
P("\n  这 24 条的 assistant JSON 字段集合:")
for i in odd:
    r = dict(rows)[i]
    a = get(r["messages"], "assistant")
    blocks = re.findall(r"```json\s*(.*?)```", a, re.S)
    if blocks:
        try:
            o = json.loads(blocks[-1])
            P(f"    line {i}: {list(o.keys())}")
        except Exception as e:
            P(f"    line {i}: PARSE FAIL {e}")

# ---------- 解析失败的 2 条 ----------
P("\n" + "=" * 78); P("[C] JSON 解析失败的样本全文"); P("=" * 78)
for i in [8797, 8826]:
    r = dict(rows)[i]
    P(f"\n  ---- line {i} ----")
    P(f"  [USER] {get(r['messages'],'user')[:400]}")
    P(f"  [ASSISTANT 全文] {get(r['messages'],'assistant')[:3000]}")

# ---------- 超长样本 ----------
P("\n" + "=" * 78); P("[D] 超长样本（assistant > 8000 字符）"); P("=" * 78)
longs = []
for i, r in rows:
    a = get(r["messages"], "assistant")
    u = get(r["messages"], "user")
    if len(a) > 8000:
        longs.append((len(a), i, len(u)))
longs.sort(reverse=True)
P(f"  共 {len(longs)} 条")
for L, i, ul in longs[:25]:
    P(f"    line {i}: assistant={L} user={ul}")
# 看最长的一条结构
if longs:
    i = longs[0][1]
    r = dict(rows)[i]
    a = get(r["messages"], "assistant")
    P(f"\n  ---- line {i} assistant 前 2500 字符 ----")
    P(a[:2500])
    P(f"\n  ---- line {i} assistant 后 1500 字符 ----")
    P(a[-1500:])

# ---------- assistant 重复大组 ----------
P("\n" + "=" * 78); P("[E] assistant 全文重复大组（x72 / x52）"); P("=" * 78)
dup = collections.defaultdict(list)
for i, r in rows:
    a = get(r["messages"], "assistant")
    dup[hashlib.md5(re.sub(r"\s+", "", a).encode()).hexdigest()].append(i)
big = sorted([v for v in dup.values() if len(v) > 1], key=lambda x: -len(x))
for grp in big[:2]:
    P(f"\n  === 重复 {len(grp)} 条, 行 {grp[:6]}...{grp[-3:]} ===")
    r0 = dict(rows)[grp[0]]
    P(f"  [USER-0 全文] {get(r0['messages'],'user')[:1500]}")
    P(f"  [ASSISTANT 共享全文] {get(r0['messages'],'assistant')[:1500]}")
    # 对比第二条 user
    r1 = dict(rows)[grp[1]]
    P(f"  [USER-1 全文] {get(r1['messages'],'user')[:1500]}")
    P("-" * 60)

# ---------- risk_level 小写 none 的来源 ----------
P("\n" + "=" * 78); P("[F] risk_level='none'（小写）样本分布"); P("=" * 78)
lowsys = collections.Counter()
line_ranges = []
low_lines = []
for i, r in rows:
    a = get(r["messages"], "assistant")
    blocks = re.findall(r"```json\s*(.*?)```", a, re.S)
    if not blocks: continue
    try:
        o = json.loads(blocks[-1])
    except Exception:
        continue
    if o.get("risk_level") == "none":
        low_lines.append(i)
        lowsys["short" if len(get(r["messages"], "system")) < 1500 else "long"] += 1
P(f"  小写 none 总数: {len(low_lines)}  按 system 类型: {dict(lowsys)}")
P(f"  行号区间: min={min(low_lines)} max={max(low_lines)}")
# 分段统计
buckets = collections.Counter()
for i in low_lines:
    buckets[(i // 1000) * 1000] += 1
P(f"  按行号千位分段: {dict(sorted(buckets.items()))}")
# 大写 None 的样本
up_lines = []
for i, r in rows:
    a = get(r["messages"], "assistant")
    blocks = re.findall(r"```json\s*(.*?)```", a, re.S)
    if not blocks: continue
    try:
        o = json.loads(blocks[-1])
    except Exception:
        continue
    if o.get("risk_level") == "None":
        up_lines.append(i)
P(f"  大写 None 总数: {len(up_lines)} 行号样例: {up_lines[:20]}")
P(f"  大写 None 行号区间: min={min(up_lines)} max={max(up_lines)}")

# ---------- cvss 多余字段 ----------
P("\n" + "=" * 78); P("[G] 多余字段来源"); P("=" * 78)
extra_stat = collections.Counter()
extra_lines = collections.defaultdict(list)
for i, r in rows:
    a = get(r["messages"], "assistant")
    blocks = re.findall(r"```json\s*(.*?)```", a, re.S)
    if not blocks: continue
    try:
        o = json.loads(blocks[-1])
    except Exception:
        continue
    ex = [k for k in o.keys() if k not in ["has_vulnerability","vulnerability_type","risk_level","source","sink","explanation","fix_suggestion"]]
    if ex:
        extra_stat[tuple(ex)] += 1
        extra_lines[tuple(ex)].append(i)
for k, v in extra_stat.most_common():
    P(f"  {k}: {v} 条, 行号区间 {min(extra_lines[k])}-{max(extra_lines[k])}, 样例 {extra_lines[k][:5]}")

w.close()
print("done")
