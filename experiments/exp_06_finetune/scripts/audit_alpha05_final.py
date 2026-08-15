# -*- coding: utf-8 -*-
"""α0.5 最终训练集审计验证。

对 data/final_train_chatml_alpha05.jsonl 复跑关键检查（与 GLM audit_train_full 口径一致）：
  A. 解析健康：所有记录 JSON 可解析、含必需字段
  B. 完全重复：归一化后同码同标签 → 应为 0
  C. 测试集泄露：Jaccard>=0.50 → 必须为 0；0.40~0.50 仅报告（低于阈值，保留）
  D. 元注释：CoT 含"题目要求/本题要求..." → 应为 0
  G. 归因错误：JWT/MD5/eval/open+exec 误标规则 → 必须为 0
  I. safe 硬矛盾：verdict=False 但 CoT 明确写 CWE-xxx → 应为 0（手动复核命中）
  Z. 盲区样本：14 条格式合法 + CWE 归属正确
"""
import json, re, sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(r"D:\code\毕业设计\Graduation-Project")
DATA = ROOT / "experiments" / "exp_06_finetune" / "data"
FINAL = DATA / "final_train_chatml_alpha05.jsonl"
TESTSET = ROOT / "experiments" / "exp_04_hard_samples" / "samples"

CODE_RE = re.compile(r"```(?:\w+)?\n(.*?)```", re.S)
JSON_RE = re.compile(r"```json\s*(.*?)```", re.S)
CWE_RE = re.compile(r"CWE-(\d+)")
COMMENT_RE = re.compile(r"(#[^\n]*|//[^\n]*|/\*.*?\*/)", re.S)
STR_RE = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`")
NUM_RE = re.compile(r"\b\d+\b")
META_RE = re.compile(r"题目要求|本题要求|根据题目|题目设定|按题目|题目中")

def norm_lines(code):
    code = COMMENT_RE.sub(" ", code)
    code = STR_RE.sub("S", code)
    code = NUM_RE.sub("N", code)
    return [t for ln in code.splitlines() if (t := ln.strip()) and len(t) >= 4]

def misattr_hit(verdict, code_l, cot_l):
    """命中 = 存在待修正的归因错误（与 fix_alpha05_data 同规则）。"""
    m = CWE_RE.search(verdict.get("vulnerability_type", "") or "")
    cwe = int(m.group(1)) if m else 0
    if cwe == 287 and ("jwt" in code_l or "jwt" in cot_l) and re.search(r"过期|expire|exp\b", cot_l):
        return "JWT 287→613"
    if cwe == 287 and ("md5" in code_l or "md5" in cot_l):
        return "MD5 287→327"
    if cwe == 917 and re.search(r"\beval\s*\(|\bexec\s*\(", code_l):
        return "eval/exec 917→94"
    if cwe == 610 and re.search(r"\bopen\s*\(", code_l) and re.search(r"\bexec\s*\(", code_l):
        return "open+exec 610→98"
    return None

# ---------------- 载入 ----------------
samples = []
with FINAL.open(encoding="utf-8") as fh:
    for i, ln in enumerate(fh):
        ln = ln.strip()
        if not ln:
            continue
        rec = json.loads(ln)
        user, asst = rec["messages"][1]["content"], rec["messages"][2]["content"]
        cm, jm = CODE_RE.search(user), JSON_RE.search(asst)
        code = cm.group(1) if cm else ""
        verdict = None
        if jm:
            try:
                verdict = json.loads(jm.group(1))
            except Exception:
                verdict = None
        cot = asst[: jm.start()] if jm else asst
        samples.append({"i": i, "code": code, "verdict": verdict, "cot": cot, "asst": asst})
print(f"载入 {len(samples)} 条")

ok = True

# A. 解析健康
bad = [s["i"] for s in samples if not s["verdict"]]
REQ = ["has_vulnerability", "vulnerability_type", "source", "sink", "explanation"]
_REQ_TRIAGE = ["is_confirmed", "vulnerability_type", "reason", "fix_suggestion"]
missing = []
for s in samples:
    if not s["verdict"]:
        continue
    v = s["verdict"]
    # 兼容 triage 格式（is_confirmed 而非 has_vulnerability）
    if "is_confirmed" in v:
        mf = [f for f in _REQ_TRIAGE if f not in v]
    else:
        mf = [f for f in REQ if f not in v]
    if mf:
        missing.append((s["i"], mf))
print(f"A. 解析失败: {len(bad)}  缺字段: {len(missing)}")
if bad or missing:
    ok = False
    print("   坏记录:", bad[:10], missing[:10])

# B. 完全重复（同码同标签）
seen = {}
dups = 0
for s in samples:
    nk = "\n".join(norm_lines(s["code"]))
    label = (s["verdict"] or {}).get("has_vulnerability")
    if nk and (nk, label) in seen:
        dups += 1
    else:
        seen[(nk, label)] = s["i"]
print(f"B. 归一化完全重复: {dups}")
if dups:
    ok = False

# C. 泄露（Jaccard）
# 覆盖测试集全部代码语言（不限于 py/java，含 php/js/c/cpp 等，避免历史盲区）
_CODE_SUFFIXES = {".py", ".java", ".php", ".js", ".c", ".cpp", ".cc", ".go", ".rb", ".sh", ".rs", ".ts"}
test_files = sorted(
    p for p in TESTSET.glob("*") if p.is_file() and p.suffix in _CODE_SUFFIXES
)
line_index = defaultdict(set)
test_sets = []
for ti, tf in enumerate(test_files):
    ls = set(norm_lines(tf.read_text(encoding="utf-8", errors="replace")))
    test_sets.append((tf.name, ls))
    for l in ls:
        line_index[l].add(ti)

leak_ge50, leak_40_50 = [], []
for s in samples:
    ls = set(norm_lines(s["code"]))
    if not ls:
        continue
    hits = Counter()
    for l in ls:
        if l in line_index:
            for ti in line_index[l]:
                hits[ti] += 1
    for ti, inter in hits.items():
        name, tls = test_sets[ti]
        union = len(ls) + len(tls) - inter
        j = inter / union if union else 0.0
        if j >= 0.50:
            leak_ge50.append((s["i"], name, round(j, 3)))
        elif j >= 0.40:
            leak_40_50.append((s["i"], name, round(j, 3)))
print(f"C. 泄露>=0.50: {len(leak_ge50)}  (0.40~0.50 仅报告: {len(leak_40_50)})")
if leak_ge50:
    ok = False
    for x in leak_ge50[:15]:
        print("   ", x)
for x in leak_40_50[:10]:
    print("   [info]", x)

# D. 元注释
meta = [(s["i"], META_RE.search(s["cot"]).group(0)) for s in samples if META_RE.search(s["cot"])]
print(f"D. 元注释残留: {len(meta)}")
if meta:
    ok = False
    print("   ", meta[:15])

# G. 归因错误
misattr = []
for s in samples:
    if not s["verdict"]:
        continue
    why = misattr_hit(s["verdict"], s["code"].lower(), s["cot"].lower())
    if why:
        misattr.append((s["i"], why))
print(f"G. 归因错误残留: {len(misattr)}")
if misattr:
    ok = False
    print("   ", misattr[:15])

# I. safe 硬矛盾：False 但 CoT 明确标 CWE
safe_hard = []
for s in samples:
    if not s["verdict"]:
        continue
    if s["verdict"].get("has_vulnerability") is False:
        m = CWE_RE.search(s["cot"])
        if m:
            safe_hard.append((s["i"], m.group(0)))
print(f"I. safe 但 CoT 标 CWE 候选: {len(safe_hard)}（需复核是否「干扰项论证」）")
for x in safe_hard[:20]:
    print("   ", x)

# Z. 盲区样本（按内容定位，位置无关）：CWE 归属正确
# 从 supplement_alpha05_blindspot.jsonl 读取盲区样本代码，在 final 中按
# 归一化行集匹配定位（不依赖硬编码行号——删除/增补样本后位置会漂移）
EXPECT = {"306": 2, "639": 2, "862": 5, "209": 2, "1321": 2, "208": 2, "915": 1, "89": 3}
blindspot_file = DATA / "supplement_alpha05_blindspot.jsonl"
blind_codes = []
if blindspot_file.exists():
    with blindspot_file.open(encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            rec = json.loads(ln)
            cm = CODE_RE.search(rec["messages"][1]["content"])
            blind_codes.append(cm.group(1) if cm else "")
print(f"Z. 盲区源文件样本数: {len(blind_codes)}（期望 19）")
blind_set = [set(norm_lines(c)) for c in blind_codes if c.strip()]
blind = []
for s in samples:
    ls = set(norm_lines(s["code"]))
    if not ls:
        continue
    for bs in blind_set:
        # 训练样本覆盖盲区源代码的 95%+ 行才视为同一样本（盲区样本在 final
        # 中为内容级复制，覆盖率≈1.0；阈值 0.8 会把 base 中结构相似的
        # 同 CWE 样本（如 CWE-915 Spring 属性操纵）误收进来）
        if len(ls & bs) / max(len(bs), 1) >= 0.95:
            blind.append(s)
            break
blind_cwe = Counter()
blind_bad = []
for s in blind:
    if not s["verdict"]:
        blind_bad.append((s["i"], "no verdict"))
        continue
    m = CWE_RE.search(s["verdict"].get("vulnerability_type", "") or "")
    cwe = m.group(1) if m else "?"
    blind_cwe[cwe] += 1
    # 论证中必须出现"干扰项"排除表述
    if "干扰项" not in s["cot"]:
        blind_bad.append((s["i"], "缺干扰项排除论证"))
print(f"Z. 定位到盲区样本: {len(blind)}  CWE 分布: {dict(blind_cwe)}  期望: {EXPECT}")
if len(blind) != len(blind_codes) or dict(blind_cwe) != EXPECT or blind_bad:
    ok = False
    print("   异常:", blind_bad, "定位数:", len(blind))

print("\n======== 审计结论: " + ("PASS ✓ 最终训练集干净" if ok else "FAIL ✗ 存在残留，需处理") + " ========")
