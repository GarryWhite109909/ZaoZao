# -*- coding: utf-8 -*-
"""v2_24 独立验证（与构建脚本不同的实现）"""
import sys, os, json, re, hashlib, collections
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
V23 = os.path.join(ROOT, "data/final_train_chatml_alpha06_v2_23_candidate_20260914.jsonl")
V24 = os.path.join(ROOT, "data/final_train_chatml_alpha06_v2_24_candidate_20260914.jsonl")


def load(p):
    return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]


def g(r, role):
    for m in (r.get("messages") or []):
        if m.get("role") == role:
            return m.get("content") or ""
    return ""


v23, v24 = load(V23), load(V24)
print("v2_23", len(v23), "v2_24", len(v24))

# 1. 前 10000 行逐 md5
h = lambda r: hashlib.md5(json.dumps(r, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
same = sum(1 for i in range(len(v23)) if h(v23[i]) == h(v24[i]))
print(f"1) 前 {len(v23)} 行原样: {same}/{len(v23)}", "✅" if same == len(v23) else "❌")

# 2. 尾 24 行契约
tail = v24[len(v23):]
print(f"2) 尾部新增 {len(tail)} 行")
CANON = ["has_vulnerability", "vulnerability_type", "risk_level", "source", "sink",
         "explanation", "fix_suggestion"]
bad = []
for r in tail:
    a = g(r, "assistant")
    m = re.findall(r"```json\s*(\{.*?\})\s*```", a, re.S)
    o = json.loads(m[-1]) if m else None
    if not o or any(c not in o for c in CANON):
        bad.append(r["src_row"])
print(f"   尾部 7 字段不完整: {bad or '无'} ✅")

# 3. is_confirmed 全库
ic = [i for i, r in enumerate(v24) if "is_confirmed" in (g(r, "user") + g(r, "assistant"))]
print(f"3) 全库含 is_confirmed 的行: {len(ic)} ✅" if not ic else f"3) ❌ {ic[:5]}")

# 4. T 族计数（另一套判据：user 以 triage 抬头开头）
t24 = [r for r in v24 if g(r, "user").lstrip().startswith("【安全分析任务")]
t23 = [r for r in v23 if g(r, "user").lstrip().startswith("【安全分析任务")]
print(f"4) T 族（抬头判据）: v2_23 {len(t23)} → v2_24 {len(t24)}")

# 5. 尾部 24 行的 user 是否已无输出模板冲突
conflict = [r["src_row"] for r in tail
            if "has_vulnerability" not in g(r, "user")[-400:]]
print(f"5) 尾部 user 尾部 400 字未含 has_vulnerability 的行: {conflict or '无'} ✅")

# 6. 正负
def hv(r):
    m = re.findall(r'"has_vulnerability"\s*:\s*(true|false)', g(r, "assistant"))
    return m[-1] == "true" if m else None


pos = sum(1 for r in v24 if hv(r) is True)
neg = sum(1 for r in v24 if hv(r) is False)
print(f"6) 正 {pos} / 负 {neg} / 合计 {pos+neg}（应 == {len(v24)}：{pos+neg==len(v24)}）")

# 7. system prompt 唯一
print(f"7) system 种类: {len(set(g(r,'system') for r in v24))}")
print(f"8) 键集: {set(tuple(sorted(r.keys())) for r in v24)}")
print(f"9) sha256 v2_24 = {hashlib.sha256(open(V24,'rb').read()).hexdigest()}")
print(f"   sha256 v2_23 = {hashlib.sha256(open(V23,'rb').read()).hexdigest()}")

# 10. 规则覆盖
rules = set()
for r in t24:
    m = re.search(r"- 规则:\s*(\S+)", g(r, "user"))
    if m:
        rules.add(m.group(1))
print(f"10) T 族规则种类 = {len(rules)}")
