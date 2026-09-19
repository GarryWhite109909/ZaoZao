# -*- coding: utf-8 -*-
"""
变体质量诊断 + 毒样本队列（2026-09-09 晚）

用户问题：「多变体教一个方面知识」的策略导致重复多，是不是变体设计不优秀？
方法：把 917 个近重复簇按**信息增量**分类——
  差分对簇      ：同簇含 vuln+safe（刻意设计，保留）
  有信息量变体  ：同标签但代码差异大 / CWE 多样（策略在起作用，保留）
  近全同冗余    ：同标签 + 同 CWE + 成对 containment≥0.92（只改变量名的懒变体，重复元凶）
同时产出毒样本 purge 队列（在 build 层执行，不动行号）：
  A 同码反标    B 示意代码HIGH（占位行压在 sink 上=毒；外围=备案）C 空代码/残片
  D 结论JSON损坏 E 围栏未闭合 F 实测坐实真破损
"""
import json, re, sys, os, collections, hashlib
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_16.jsonl"
CLUSTER = BASE / "audit/scan_v2_16_l3_cluster_flags.json"
SCAN = BASE / "audit/示意代码扫描_v2_16_20260909.jsonl"
OUTQ = BASE / "audit/毒样本与冗余治理队列_20260909.jsonl"

rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
ga = lambda r: [m["content"] for m in r["messages"] if m["role"] == "assistant"][-1]
gu = lambda r: [m["content"] for m in r["messages"] if m["role"] == "user"][0]


def code_of(u):
    fs = re.findall(r"```[A-Za-z0-9_+\-]*\n(.*?)```", u, re.S)
    return max(fs, key=len) if fs else ""


def verd(a):
    m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
    if not m:
        return None
    try:
        v = json.loads(m.group(1))
        hv = v.get("has_vulnerability")
        if isinstance(hv, str):
            hv = hv.strip().lower() == "true"
        c = re.search(r"CWE-(\d+)", str(v.get("vulnerability_type") or ""))
        return (hv, "CWE-" + c.group(1) if c else "", v)
    except Exception:
        return None


codes, verds = {}, {}
for i, r in enumerate(rows, 1):
    codes[i] = code_of(gu(r))
    verds[i] = verd(ga(r))


def nlines(code):
    out = []
    for l in code.split("\n"):
        s = l.strip()
        if not s or s.startswith(("//", "#", "/*", "*", "--")):
            continue
        out.append(re.sub(r"\s+", " ", s))
    return out


def containment(a, b):
    A, B = set(a), set(b)
    if not A or not B:
        return 0.0
    inter = len(A & B)
    return inter / min(len(A), len(B))


# ---------- 1. 簇分类 ----------
cl = json.load(open(CLUSTER, encoding="utf-8"))
tax = collections.Counter()
tax_rows = collections.defaultdict(list)
redundant_samples = []
quota3_removed = 0
for c in cl.get("clusters", []):
    rr = [int(x) for x in c.get("rows_1based", [])]
    if len(rr) < 2:
        continue
    hvs = {verds[x][0] for x in rr if verds[x]}
    cwes = {verds[x][1] for x in rr if verds[x] and verds[x][0]}
    mx, near = 0.0, 0
    for i in range(len(rr)):
        for j in range(i + 1, len(rr)):
            ct = containment(nlines(codes[rr[i]]), nlines(codes[rr[j]]))
            mx = max(mx, ct)
            near += ct >= 0.92
    if True in hvs and False in hvs:
        t = "差分对"
    elif mx >= 0.92 and len(cwes) <= 1:
        t = "近全同冗余"
    else:
        t = "有信息量变体"
    tax[t] += 1
    tax_rows[t].extend(rr)
    if t == "近全同冗余":
        if len(redundant_samples) < 8:
            redundant_samples.append({"rows": rr, "max_containment": round(mx, 3), "cwes": sorted(cwes)})
        quota3_removed += max(0, len(rr) - 3)

print("=== 917 簇按信息增量分类 ===")
for t, n in tax.most_common():
    print(f"  {t:<10} {n:>4} 簇 / {len(tax_rows[t]):>4} 行")
print(f"  近全同冗余簇按簇内配额 3 可裁: ~{quota3_removed} 行")
print("  冗余样例:", json.dumps(redundant_samples[:3], ensure_ascii=False)[:300])

# ---------- 2. 毒样本队列 ----------
queue = []


def add(kind, ln, reason, disp):
    queue.append({"kind": kind, "line": ln, "reason": reason, "disposition": disp})


# A 同码反标
h = collections.defaultdict(list)
for i in range(1, len(rows) + 1):
    if codes[i]:
        h[hashlib.md5(codes[i].strip().encode("utf-8", "replace")).hexdigest()].append(i)
for k, lst in h.items():
    if len(lst) > 1:
        vs = {verds[x][0] for x in lst if verds[x]}
        if len(vs) > 1:
            for x in lst:
                add("A_同码反标", x, f"同码多标签: {[(y, str(verds[y][:2])) for y in lst]}", "终裁: 逐行裁决或全组删除")

# B 示意代码 HIGH：占位行是否压在 sink 引用上
scan = [json.loads(l) for l in SCAN.open(encoding="utf-8") if json.loads(l)["top_tier"] == "HIGH"]
for s in scan:
    ln = s["line"]
    v = verds[ln]
    if not v or not v[2]:
        add("B_示意HIGH", ln, "无结论JSON", "删除候选")
        continue
    sink = str(v[2].get("sink") or "")
    src = str(v[2].get("source") or "")
    cited_sink = set(int(x) for x in re.findall(r"(?:line|行|第)\s*(\d{1,3})", sink + " " + src))
    poison = False
    for hit in s["hits"]:
        lic = hit["line_in_code"]
        exact = lic in cited_sink
        if re.search(r"伪代码|不可运行|无法运行", hit["text"]):
            poison = True
        if exact and "省略" in hit["text"]:
            poison = True
    if poison:
        add("B_示意HIGH_压sink", ln, f"占位/伪代码行压在结论引用行附近: {[h2['text'][:40] for h2 in s['hits']][:2]}", "删除候选（教的是不存在的 sink）")
    else:
        add("B_示意HIGH_外围", ln, f"占位注释在外围: {[h2['text'][:40] for h2 in s['hits']][:1]}", "备案保留（sink 真实存在）")

# C 空代码 / D JSON损坏 / E 围栏
for i in range(1, len(rows) + 1):
    if len(codes[i]) < 30:
        add("C_空代码残片", i, f"代码 {len(codes[i])} 字符", "删除候选")
    if verds[i] is None:
        add("D_结论JSON损坏", i, "结论块解析失败", "修复或删除")
# E 围栏未闭合（复用体检口径）
FENCE_ALL = re.compile(r"```")
for i, r in enumerate(rows, 1):
    if gu(r).count("```") % 2:
        add("E_围栏未闭合", i, "代码块未闭合（切片不完整）", "删除候选")

# F 实测坐实真破损（L0 优先队列）
for l in (BASE / "audit/实测门_优先队列_L0_20260909.jsonl").open(encoding="utf-8"):
    o = json.loads(l)
    if o["l0"] in ("SYNTAX_FAIL", "LINT_FAIL") or (o["l0"] == "COMPILE_FAIL" and o["lang"] in ("python", "go", "javascript")):
        add("F_实测真破损", o["line"], f"{o['lang']} {o['l0']}: {str(o.get('l0_detail'))[:70]}", "删除候选或重蒸馏")

seen = set()
dedup = []
for q in queue:
    k = (q["kind"], q["line"])
    if k in seen:
        continue
    seen.add(k)
    dedup.append(q)
with OUTQ.open("w", encoding="utf-8") as f:
    for q in dedup:
        f.write(json.dumps(q, ensure_ascii=False) + "\n")

kc = collections.Counter(q["kind"] for q in dedup)
print("\n=== 毒样本/脏样本队列 ===")
for k, n in kc.most_common():
    print(f"  {k:<20} {n:>4}")
print(f"  合计 {len(dedup)} 条 → {OUTQ.name}（build 层执行，不动行号）")
