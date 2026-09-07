# -*- coding: utf-8 -*-
"""v2_15 训练集 vs rolling_dev(50) 测试集：类型/长度/难度分布 + 覆盖度对照"""
import json, re, sys, io
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ROOT = Path(r"D:/code/毕业设计/Graduation-Project/experiments/exp_06_finetune")
TRAIN = ROOT / "data" / "final_train_chatml_alpha06_v2_15.jsonl"
RD_DIR = ROOT / "corpus" / "rolling_dev"

# ---------- 训练集 ----------
def lang_of_code(code):
    if re.search(r"\bdef \w+\(|import \w+\n|from \w+ import", code): 
        if re.search(r"\bdef |\bimport\b|elif |self\.|lambda", code) and not re.search(r"\bfunction\b|\bconst \w+ =|=>|\blet \w+ =", code[:400]):
            return "python"
    if re.search(r"\bfunction\b|=>|\bconst \b|\blet \b|\bvar \b|require\(|module\.exports", code): return "javascript"
    if re.search(r"\bpublic class\b|\bprivate \w+ \w+;|System\.out|@Override|import java\.", code): return "java"
    if re.search(r"\bfunc \w+\(|fmt\.|package main", code): return "go"
    if re.search(r"<\?php|\$\w+\s*=", code): return "php"
    if re.search(r"#include\s*<|printf\(|int main\(", code): return "c"
    if re.search(r"\busing System\b|namespace \w+|Console\.", code): return "csharp"
    if re.search(r"\bruby\b|puts |end\n\s*def", code): return "ruby"
    return "other"

def extract_json_block(text):
    m = re.findall(r"```json\s*(\{.*?\})\s*```", text, re.S)
    if m: return m[-1]
    m = re.findall(r"(\{[^\n]*\"has_vulnerability\"[^\n]*\})", text)
    return m[-1] if m else None

rows = []
with open(TRAIN, encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        try: d = json.loads(line)
        except Exception: continue
        msgs = d.get("messages", [])
        sysm = next((m for m in msgs if m["role"]=="system"), None)
        usr = next((m for m in msgs if m["role"]=="user"), None)
        ast = next((m for m in msgs if m["role"]=="assistant"), None)
        if not usr or not ast: continue
        u, a = usr["content"], ast["content"]
        # 提取用户代码（[CODE] 段或代码块）
        code = ""
        cm = re.search(r"\[CODE\](.*?)(?:\[ANALYSIS\]|\[JSON\]|\Z)", u, re.S)
        if cm: code = cm.group(1)
        else:
            cb = re.findall(r"```\w*\n(.*?)```", u, re.S)
            code = cb[0] if cb else u
        code_lines = code.count("\n") + 1 if code.strip() else 0
        jl = extract_json_block(a)
        j = {}
        if jl:
            try: j = json.loads(jl)
            except Exception:
                j2 = re.sub(r",\s*}", "}", jl)
                try: j = json.loads(j2)
                except Exception: j = {}
        cwe = str(j.get("vulnerability_type", "none") or "none")
        cm2 = re.match(r"(CWE-\d+)", cwe)
        cwe_id = cm2.group(1) if cm2 else ("none" if cwe=="none" else cwe[:20])
        has_v = j.get("has_vulnerability")
        rows.append(dict(line=i, lang=lang_of_code(code), cwe=cwe_id,
                         has_vuln=has_v, code_lines=code_lines,
                         usr_chars=len(u), ast_chars=len(a), sample_id=d.get("sample_id") or d.get("id")))

print(f"=== 训练集 v2_15 总览 ===")
print(f"样本总数: {len(rows)}")
print(f"JSON 解析成功: {sum(1 for r in rows if r['cwe'] != '')}/{len(rows)}")
hv = Counter(str(r['has_vuln']) for r in rows)
print(f"has_vulnerability 分布: {dict(hv)}")

print(f"\n--- 语言分布 ---")
for k, v in Counter(r['lang'] for r in rows).most_common(): print(f"  {k:12s} {v:5d}  ({v/len(rows)*100:.1f}%)")

print(f"\n--- CWE Top 30（有漏洞样本） ---")
cw = Counter(r['cwe'] for r in rows if r['has_vuln'] is True)
for k, v in cw.most_common(30): print(f"  {k:28s} {v:5d}  ({v/max(1,sum(cw.values()))*100:.1f}%)")
print(f"  有漏洞样本 CWE 类别数: {len(cw)}")

print(f"\n--- 代码长度（行数）分布 ---")
ls = sorted(r['code_lines'] for r in rows)
import statistics
def pct(p): 
    idx = min(int(len(ls)*p), len(ls)-1); return ls[idx]
print(f"  min={ls[0]} p10={pct(.1)} p25={pct(.25)} p50={pct(.5)} p75={pct(.75)} p90={pct(.9)} p99={pct(.99)} max={ls[-1]} mean={statistics.mean(ls):.0f}")
buckets = [(0,20),(21,50),(51,100),(101,200),(201,400),(401,10**9)]
for lo,hi in buckets:
    n = sum(1 for x in ls if lo<=x<=hi)
    print(f"  {lo}-{min(hi,999)}行: {n} ({n/len(ls)*100:.1f}%)")

print(f"\n--- 助手输出长度（字符） ---")
al = sorted(r['ast_chars'] for r in rows)
print(f"  p10={al[int(len(al)*.1)]} p50={al[int(len(al)*.5)]} p90={al[int(len(al)*.9)]} p99={al[int(len(al)*.99)]} max={al[-1]}")

# ---------- 测试集 ----------
mf = json.loads((RD_DIR/"manifest.json").read_text(encoding="utf-8"))
tests = []
for s in mf["samples"]:
    f = RD_DIR / s["file"]
    n = len(f.read_text(encoding="utf-8", errors="replace").splitlines()) if f.exists() else 0
    cwes = re.findall(r"CWE-\d+", s.get("expected_cwe","") or "")
    tests.append(dict(file=s["file"], lang=s.get("language","?"), diff=s.get("difficulty","?"),
                      cwes=cwes, present=s.get("expected_present"), lines=n))
print(f"\n=== rolling_dev 测试集（{len(tests)} 条） ===")
print(f"--- 语言分布 ---")
for k,v in Counter(t['lang'] for t in tests).most_common(): print(f"  {k:12s} {v:3d}")
print(f"--- 难度分布 ---")
for k,v in Counter(t['diff'] for t in tests).most_common(): print(f"  {k:12s} {v:3d}")
print(f"--- 有/无漏洞 ---")
for k,v in Counter(str(t['present']) for t in tests).most_common(): print(f"  {k:12s} {v:3d}")
print(f"--- CWE 分布（标签可多值） ---")
tc = Counter(c for t in tests for c in t['cwes'])
for k,v in tc.most_common(): print(f"  {k:10s} {v:3d}")
tls = sorted(t['lines'] for t in tests)
print(f"--- 代码行数 p50={tls[len(tls)//2]} min={tls[0]} max={tls[-1]} ---")

# ---------- 覆盖度 ----------
print(f"\n=== 训练集→测试集 CWE 覆盖 ===")
train_cwe = Counter(r['cwe'] for r in rows if r['has_vuln'] is True)
train_cwe_nov = Counter(r['cwe'] for r in rows if r['has_vuln'] is not True)
miss = []
for c, n in sorted(tc.items()):
    tr = train_cwe.get(c, 0)
    print(f"  {c:10s} 测试{n}条  训练(有漏洞标签){tr}条" + ("  ⚠️零覆盖" if tr==0 else ""))
    if tr < max(3, n): miss.append((c, tr, n))
print(f"低覆盖(训练<3条 或 <测试数): {miss}")

# 无漏洞覆盖
nov_test = sum(1 for t in tests if not t['present'])
print(f"\n无漏洞测试条数: {nov_test}; 训练集 has_vuln=false: {hv.get('False',0)+hv.get('false',0)}")
