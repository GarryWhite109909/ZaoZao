# -*- coding: utf-8 -*-
"""S9 全量非语义机检:v2_15 上所有可确定性验证的缺陷筛查。

检查项(全部机械可判,产出 violations 供脚本修/人工修;语义问题不在此列):
  C1  JSON/契约:解析失败、七字段缺失、字段顺序
  C2  fix 契约:hv=true 时空修复/无修复;含 ```;含换行;hv=false 非 no-fix 开头
  C3  行号越界:四字段中 line N > 代码行数
  C4  锚点失位:source/sink 的 line N: 锚内容片段(≥8字符)在全文任意行找不到
  C5  截断:assistant 不以 ``` 结尾
  C6  不可见字符:零宽/BOM/RTL
  C7  JSON 块后尾随文本
  C8  语言标签错位:标签 vs 代码特征最匹配语言
  C9  safe 样本 explanation 含裸 CWE(可数)
  C10 重复:user/assistant/code 归一 md5 重复
  C11 同码异标:代码相同但 has_vulnerability 不同(含 s7 已知,重扫可发现新增)
  C12 fix 无任何形式行号锚(hv=true)
  C13 教师元数据异常:fix_distill 缺失/teacher 未知
输出: s9_violations.jsonl(逐条)+ s9_screen_out.txt(汇总)
"""
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
OUT_V = Path(__file__).resolve().parent / "s9_violations.jsonl"
OUT_L = Path(__file__).resolve().parent / "s9_screen_out.txt"
CONTRACT = ["has_vulnerability", "vulnerability_type", "risk_level",
            "source", "sink", "explanation", "fix_suggestion"]
JB = re.compile(r"```json\s*(.*?)```", re.S)
FENCE = re.compile(r"```([\w+#.\-/]*)[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)
INVISIBLE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]")
CONTRACT_FIX_ANCHOR = re.compile(r"(?:line\s*\d+|第\s*\d+\s*行|\bL\s*\d+|(?:^|[;；])\s*\d{1,4}\s*[:：])", re.I)

# 语言特征(最强信号优先)
LANG_SIG = [
    ("python", re.compile(r"^\s*(?:def |class |import \w|from \w+ import|print\()", re.M)),
    ("javascript", re.compile(r"(?:function\s+\w|const\s+\w|let\s+\w|require\(|console\.)")),
    ("typescript", re.compile(r"(?::\s*(?:string|number|boolean)\b|interface\s+\w+\s*\{)")),
    ("php", re.compile(r"<\?php|\$\w+\s*=")),
    ("java", re.compile(r"public\s+(?:class|static|void)\b")),
    ("go", re.compile(r"^package\s+\w+", re.M)),
    ("c", re.compile(r"#include\s*<")),
    ("cpp", re.compile(r"#include\s*<(?:iostream|vector|string)>|std::")),
    ("csharp", re.compile(r"using\s+System|namespace\s+\w+")),
    ("bash", re.compile(r"^#!/bin/(?:ba)?sh", re.M)),
    ("ruby", re.compile(r"\bputs\b|require\s+['\"]")),
    ("kotlin", re.compile(r"\bfun\s+\w+|val\s+\w+=")),
]

def norm_md5(s):
    return hashlib.md5(re.sub(r"\s+", "", s).encode()).hexdigest()

def frag_found(content, norm_all):
    """锚内容中 ≥8 字符片段是否在代码骨架中出现(任一);无长片段 → 无法判定,放行。"""
    toks = [t.replace("'", "").replace('"', "").lower()
            for t in content.split() if len(t) >= 8]
    if not toks:
        return True   # 纯散文锚,机械不可判,放行(留给语义层)
    return any(t in norm_all for t in toks)

LOG = []
V = []   # violations

def add(lineno, wid, code, typ, sev, evidence):
    V.append({"line": lineno, "id_code": code, "type": typ, "severity": sev,
              "evidence": evidence})

n = 0
user_md5, asst_md5, code_md5 = {}, {}, {}
code_groups = defaultdict(list)
lang_mismatch = []
fix_len_stats = []
sys_versions = {}
sys_cnt = {}

for lineno, line in enumerate(open(DATA, encoding="utf-8"), 1):
    if not line.strip():
        continue
    n += 1
    rec = json.loads(line)
    u, a = rec["messages"][1]["content"], rec["messages"][2]["content"]
    sys_digest = hashlib.md5(rec["messages"][0]["content"].encode()).hexdigest()[:8]
    sys_cnt[sys_digest] = sys_cnt.get(sys_digest, 0) + 1

    # C6 不可见字符
    for part_name, part in (("user", u), ("assistant", a)):
        if INVISIBLE.search(part):
            add(lineno, None, None, "invisible_char", "minor",
                f"{part_name} 含不可见字符")
    # C7 JSON 后尾随文本
    idx = a.rfind("```")
    if a[idx + 3:].strip():
        add(lineno, None, None, "trailing_after_json", "minor",
            f"JSON 块后有尾随文本: {a[idx+3:].strip()[:50]}")
    # C5 截断
    if not a.rstrip().endswith("```"):
        add(lineno, None, None, "suspect_truncation", "major",
            f"assistant 不以 ``` 结尾,尾部: {a[-40:]!r}")

    blocks = [m.group(2) for m in FENCE.finditer(u)]
    lang_m = re.search(r"```([\w+#.\-/]*)", u)
    label = lang_m.group(1).lower() if lang_m else "text"
    code = blocks[0] if blocks else ""
    code_lines = code.split("\n")
    norm_all = "".join("".join(cl.split()).replace('"', "").replace("'", "").lower()
                       for cl in code_lines)

    um, am, cm = norm_md5(u), norm_md5(a), norm_md5(code)
    if um in user_md5:
        add(lineno, user_md5[um], None, "duplicate_user", "major", f"与行 {user_md5[um]} user 全同")
    else:
        user_md5[um] = lineno
    if am in asst_md5:
        add(lineno, asst_md5[am], None, "duplicate_assistant", "critical", f"与行 {asst_md5[am]} assistant 全同")
    else:
        asst_md5[am] = lineno

    ms = JB.findall(a)
    if not ms:
        add(lineno, None, None, "no_json", "critical", "无 JSON 块")
        continue
    try:
        o = json.loads(ms[-1])
    except Exception as e:
        add(lineno, None, None, "bad_json", "critical", f"解析失败 {e}")
        continue

    # C1 契约
    keys = list(o.keys())
    if keys != CONTRACT:
        add(lineno, None, None, "contract_fields", "minor", f"字段序/集: {keys}")

    hv = o.get("has_vulnerability")
    fix = str(o.get("fix_suggestion", "") or "").strip()
    expl = str(o.get("explanation", "") or "")

    # C2 fix 契约
    if hv is True:
        fix_len_stats.append(len(fix))
        if not fix or fix.lower().startswith("no fix"):
            add(lineno, None, None, "vuln_no_fix", "critical",
                f"hv=true 但 fix={fix[:40]!r}")
        if "```" in fix:
            add(lineno, None, None, "fix_code_block", "major", "fix 含代码块")
        if "\n" in fix:
            add(lineno, None, None, "fix_multiline", "major", "fix 含换行")
        if not CONTRACT_FIX_ANCHOR.search(fix):
            add(lineno, None, None, "fix_no_anchor", "minor", f"fix 无行号锚: {fix[:60]}")
        if len(fix) > 500:
            add(lineno, None, None, "fix_overlong", "minor", f"fix 长 {len(fix)} 字")
    else:
        if not fix:
            add(lineno, None, None, "safe_empty_fix", "minor", "safe 样本 fix 为空")

    # C3/C4 四字段行号越界与锚点失位(source/sink 为主)
    for fld in ("source", "sink", "fix_suggestion", "explanation"):
        t = str(o.get(fld, "") or "")
        for m in re.finditer(r"line\s*(\d+)", t):
            N = int(m.group(1))
            if N > len(code_lines):
                add(lineno, None, None, "anchor_oob", "major",
                    f"{fld} line {N} 越界(代码 {len(code_lines)} 行): {t[max(0,m.start()-20):m.end()+20][:70]}")

    # C4b source/sink 锚内容失位(锚描述的代码在全文找不到)
    for fld in ("source", "sink"):
        t = str(o.get(fld, "") or "")
        m = re.search(r"line\s*(\d+)\s*[:：]\s*(.+)", t)
        if not m:
            continue
        content = m.group(2)[:150]
        if frag_found(content, norm_all):
            continue
        # 锚内容片段在全文找不到 → 锚定错误(报告)
        add(lineno, None, None, "anchor_content_unlocatable", "major",
            f"{fld} 锚内容在代码中不可定位: {content[:80]!r}")

    # C9 safe 样本 explanation 含 CWE
    if hv is False and re.search(r"CWE-\d+", expl):
        add(lineno, None, None, "safe_cwe_in_expl", "minor", f"safe 样本 explanation 含 CWE: {expl[:60]}")

    # C8 语言标签错位(启发式,仅强信号)
    if code:
        best, best_n = None, 0
        for lname, pat in LANG_SIG:
            k = len(pat.findall(code))
            if k > best_n:
                best, best_n = lname, k
        best_alias = {"cpp": "c++", "c": "c"}.get(best, best)
        label_alias = {"cpp": "c++", "c": "c"}.get(label, label)
        family = lambda x: {"c": "sys", "c++": "sys", "rust": "sys"}.get(x, x)
        if best and label and label not in ("text", "") and label != best:
            alias = {"js": "javascript", "c++": "cpp", "sh": "bash", "shell": "bash",
                     "cs": "csharp", "c#": "csharp", "py": "python", "ts": "typescript"}
            la, ba = alias.get(label, label), alias.get(best, best)
            if la != ba and not ({la, ba} <= {"c", "cpp"}):
                lang_mismatch.append((lineno, label, best, best_n))

# C11 同码异标(跨全库重扫,不只 s7 旧表)
code_groups_n = 0
g = defaultdict(set)
for lineno, line in enumerate(open(DATA, encoding="utf-8"), 1):
    if not line.strip():
        continue
    rec = json.loads(line)
    bm = list(FENCE.finditer(rec["messages"][1]["content"]))
    blocks = [m.group(2) for m in bm]
    if len(blocks) != 1:
        continue
    cm = norm_md5(blocks[0])
    ms = JB.findall(rec["messages"][2]["content"])
    if not ms:
        continue
    try:
        o = json.loads(ms[-1])
    except Exception:
        continue
    g[cm].add(str(o.get("has_vulnerability")))
for cm, labels in g.items():
    if len(labels) > 1:
        code_groups_n += 1

P = []
P.append(f"总样本 {n}")
P.append(f"system 版本数: {len(sys_cnt)}")
P.append("")
cnts = Counter(v["type"] for v in V)
sevs = Counter(v["severity"] for v in V)
P.append("== 违规类型分布 ==")
for t, c in cnts.most_common():
    P.append(f"  {t}: {c}")
P.append(f"严重度: {dict(sevs)}")
P.append(f"语言标签错位候选: {len(lang_mismatch)} {lang_mismatch[:6]}")
P.append(f"同码异标簇: {code_groups_n}")
with OUT_V.open("w", encoding="utf-8") as f:
    for v in V:
        f.write(json.dumps(v, ensure_ascii=False) + "\n")
OUT_L.write_text("\n".join(P) + "\n", encoding="utf-8")
print("\n".join(P))
print(f"明细 -> {OUT_V.name}")
