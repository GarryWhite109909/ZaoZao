# -*- coding: utf-8 -*-
"""对 α0 训练数据相对 v9max 新增的 924 条补充样本做质量审计。
输入：exp_06_finetune/data/supplement_*.jsonl
输出：终端摘要 + _audit_supplements_report.txt 详细报告
"""
import json, os, re, sys, io
from collections import Counter, defaultdict

sys.stdout.reconfigure(encoding="utf-8")

DATA = r"d:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data"
HARD = r"d:\code\毕业设计\Graduation-Project\experiments\exp_04_hard_samples\samples"
TSET = r"d:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\testset_cve_fix"
REPORT_PATH = r"d:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\_audit_supplements_report.txt"

FILES = ["supplement_samples.jsonl", "supplement_ssti_auth.jsonl", "supplement_mode_a.jsonl",
         "supplement_mode_b.jsonl", "supplement_mode_d.jsonl", "supplement_low_cwe.jsonl"]

RE_VERDICT = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
RE_CWE = re.compile(r"CWE[\s-]?(\d+)", re.IGNORECASE)
RE_CODEBLOCK = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.DOTALL)

HESITATE = re.compile(r"可能|也许|或许|不确定|疑似|边界|需要进一步|有待|尚不|难以判断|无法确定|不够确定|倾向|大概|应该可以|或许存在|模糊")

RE_HARDCRED = re.compile(r"(password|passwd|pwd|secret|api_?key|auth_?key|access_?key|token|credential|private_?key|client_?secret)\s*[=:]\s*[\"'][^\"']{2,}[\"']", re.IGNORECASE)
RE_WEAKCRYPTO = re.compile(r"\b(md5|sha1|des\b|rc4|blowfish|ecb|rot13)\b|\bpassword_?hash\s*\(\s*[\"'](?!\$2[aby]\$)", re.IGNORECASE)
# 真正的代码执行（eval 注入）：Python eval()/exec()，JS eval()/Function()，PHP eval()/assert()。
# 排除命令执行：child_process.exec / Runtime.exec / os.popen / os.system / subprocess / exec.Command
RE_EVAL_TRUE = re.compile(r"(?<!\.)\beval\s*\(|(?<!\.)\bexec\s*\(|preg_replace\s*\([^)]*?/e|\bFunction\s*\(|execScript|assert\s*\((?![^)]*\))", re.IGNORECASE)
# 命令执行特征（判断标 CWE-78 是否成立）
RE_CMD = re.compile(r"os\.system|os\.popen|subprocess|Popen|check_output|check_call|system\s*\(|Runtime\.getRuntime|ProcessBuilder|child_process|execFile|exec\s*\(|execSync|exec.Command|/bin/sh|/bin/bash|shell\s*=\s*True|cmd\.(Output|Run|Start)", re.IGNORECASE)
RE_JWT = re.compile(r"\bjwt\b|\bJWT\b|pyjwt|jsonwebtoken|jose\b", re.IGNORECASE)
RE_NOSQL = re.compile(r"mongo|pymongo|MongoClient|\.find\s*\(\s*\{\$|\\\$where|\\\$ne|\\\$gt|\\\$regex|\$where|\$ne\b|db\.\w+\.(find|insert|update|remove)", re.IGNORECASE)
RE_TEMPLATE = re.compile(r"render_template_string|render_template|\{\{|\{%|Template\s*\(|Environment\s*\(|jade|pug\b|ejs\b|twig|thymeleaf|velocity|freemarker|markupsafe|Templating", re.IGNORECASE)

NO_SOURCE_CWES = {"338", "330", "190", "362", "367", "798", "327", "312", "311", "20", "835"}

report_lines = []
def R(s=""):
    report_lines.append(str(s))

def print_report():
    for ln in report_lines:
        print(ln)

# ---------- 读取所有样本 ----------
def load_samples(fn):
    p = os.path.join(DATA, fn)
    out = []
    with open(p, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception as e:
                out.append({"file": fn, "row": i, "error": f"json parse: {e}"})
                continue
            msgs = rec.get("messages", [])
            user = next((m["content"] for m in msgs if m.get("role") == "user"), "")
            assistant = next((m["content"] for m in msgs if m.get("role") == "assistant"), "")
            codeblocks = RE_CODEBLOCK.findall(user)
            code = max(codeblocks, key=len, default="")
            # verdict
            verdict = None
            v_err = None
            blocks = RE_VERDICT.findall(assistant)
            if blocks:
                try:
                    verdict = json.loads(blocks[-1])
                except Exception as e:
                    v_err = f"verdict json parse: {e}"
            else:
                v_err = "no json block"
            # CoT = assistant 中 ```json 之前的部分
            cot = assistant
            m = RE_VERDICT.search(assistant)
            if m:
                cot = assistant[: m.start()].strip()
            # 代码首行（非空）
            first_line = next((l.strip() for l in code.splitlines() if l.strip()), "")
            cwe = None
            vt = verdict.get("vulnerability_type", "") if isinstance(verdict, dict) else ""
            if vt:
                mm = RE_CWE.search(vt)
                if mm:
                    cwe = mm.group(1)
            out.append({
                "file": fn, "row": i,
                "user": user, "assistant": assistant, "cot": cot,
                "code": code, "first_line": first_line,
                "verdict": verdict, "v_err": v_err, "cwe": cwe,
                "has_vuln": isinstance(verdict, dict) and verdict.get("has_vulnerability") is True,
                "source": verdict.get("source", "") if isinstance(verdict, dict) else "",
                "sink": verdict.get("sink", "") if isinstance(verdict, dict) else "",
                "risk": verdict.get("risk_level", "") if isinstance(verdict, dict) else "",
            })
    return out

all_samples = []
for fn in FILES:
    all_samples.extend(load_samples(fn))

R("#" * 90)
R("# 补充样本质量审计报告 (924 条)")
R("#" * 90)

# ---------- 1. 各文件标签分布 ----------
R("\n## 1. 各文件标签分布")
for fn in FILES:
    rows = [s for s in all_samples if s["file"] == fn]
    vuln = sum(1 for s in rows if s["has_vuln"])
    safe = sum(1 for s in rows if s["has_vuln"] is False)
    err = sum(1 for s in rows if s["has_vuln"] is None or s["v_err"])
    R(f"- {fn}: 总 {len(rows)} | 漏洞 {vuln} | 安全 {safe} | 解析失败/无verdict {err}")

# ---------- 2. 各文件 CWE 分布 ----------
R("\n## 2. 各文件 CWE 分布")
for fn in FILES:
    rows = [s for s in all_samples if s["file"] == fn]
    cnt = Counter(s["cwe"] if s["cwe"] else ("(无CWE)" if s["has_vuln"] else "(安全)") for s in rows)
    R(f"- {fn}:")
    for cwe, n in cnt.most_common():
        R(f"    CWE-{cwe}: {n}")

# ---------- 3. CWE 归因错误审计 ----------
R("\n## 3. CWE 归因错误审计")
R("\n### 3.1 硬编码凭证/弱密码学被标 CWE-287 (应 CWE-798/327)")
for s in all_samples:
    if s["cwe"] == "287":
        code = s["code"]
        hard = bool(RE_HARDCRED.search(code))
        weak = bool(RE_WEAKCRYPTO.search(code))
        # 硬编码 hash 直接 == 比较（MD5/SHA1 固定摘要作为唯一凭证）
        hardhash = bool(re.search(r"==\s*['\"][0-9a-fA-F]{32}['\"]", code)) or bool(re.search(r"md5\([^)]*\)\.hexdigest\(\).*==|hashlib\.md5|['\"]5f4dcc3b5aa765d61d8327deb882cf99['\"]", code, re.IGNORECASE))
        if hard or weak or hardhash:
            R(f"- {s['file']}:{s['row']} | 标签 {s['verdict'].get('vulnerability_type')} | 硬编码凭证={hard} 弱密码学={weak} 硬编码hash比较={hardhash}")
            R(f"    代码首行: {s['first_line']}")
            R(f"    source: {s['source'][:160]}")
            R(f"    sink: {s['sink'][:160]}")

R("\n### 3.2 eval/exec 代码注入标 CWE-78 (应 CWE-94/95) —— 且无 os.system/subprocess")
for s in all_samples:
    if s["cwe"] == "78":
        code = s["code"]
        if RE_EVAL_TRUE.search(code) and not RE_CMD.search(code):
            R(f"- {s['file']}:{s['row']} | 标签 {s['verdict'].get('vulnerability_type')}")
            R(f"    代码首行: {s['first_line']}")
            R(f"    sink: {s['sink'][:160]}")

R("\n### 3.3 标 CWE-78 且含 eval，同时也有 os.system/subprocess (需人工确认 sink 指向)")
for s in all_samples:
    if s["cwe"] == "78":
        code = s["code"]
        if RE_EVAL_TRUE.search(code) and RE_CMD.search(code):
            R(f"- {s['file']}:{s['row']} | {s['verdict'].get('vulnerability_type')}")
            R(f"    代码首行: {s['first_line']}")
            R(f"    sink: {s['sink'][:160]}")

R("\n### 3.2b 补充: 含 eval()/exec() 代码注入但标签为 CWE-917 (应 CWE-94/95)")
for s in all_samples:
    if s["cwe"] == "917":
        code = s["code"]
        # 仅 Python/JS 原生 eval 型，排除 SpEL/OGNL 表达式引擎（CWE-917 合理）
        if re.search(r"(?<!\.)\beval\s*\(|(?<!\.)\bexec\s*\(|execScript", code, re.IGNORECASE) and not re.search(r"parseExpression|Ognl\.|SpelExpression", code):
            R(f"- {s['file']}:{s['row']} | 标签 {s['verdict'].get('vulnerability_type')} (eval/exec 代码注入, 应 CWE-94/95)")
            R(f"    代码首行: {s['first_line']}")
            R(f"    sink: {s['sink'][:160]}")

R("\n### 3.2c 补充: CWE-610 但含 exec(code)/eval 代码执行 (应 CWE-94/98)")
for s in all_samples:
    if s["cwe"] == "610":
        code = s["code"]
        if re.search(r"(?<!\.)\bexec\s*\(|(?<!\.)\beval\s*\(|__import__", code, re.IGNORECASE):
            R(f"- {s['file']}:{s['row']} | 标签 {s['verdict'].get('vulnerability_type')} (open+exec 代码执行)")
            R(f"    代码首行: {s['first_line']}")
            R(f"    sink: {s['sink'][:160]}")

R("\n### 3.4 标 CWE-1336 (SSTI) 但代码无模板语法")
for s in all_samples:
    if s["cwe"] == "1336":
        code = s["code"]
        if not RE_TEMPLATE.search(code):
            # 排除 Thymeleaf 视图名拼接 (return "xxx :: " + fragment) —— 这是真实 Thymeleaf view-name 注入向量
            is_thymeleaf_viewname = bool(re.search(r"return\s+[\"'][\w/]+ :: [\"']?\s*\+|\"\s*::\s*\"\s*\+", code))
            R(f"- {s['file']}:{s['row']} | 标签 {s['verdict'].get('vulnerability_type')} | Thymeleaf视图名拼接={is_thymeleaf_viewname}")
            R(f"    代码首行: {s['first_line']}")
            R(f"    sink: {s['sink'][:160]}")

R("\n### 3.5 无过期时间 JWT 标 CWE-287 (应 CWE-613/347)")
for s in all_samples:
    if s["cwe"] in ("287", "613", "347"):
        code = s["code"]
        if RE_JWT.search(code) and not re.search(r"\bexp\b", code, re.IGNORECASE):
            R(f"- {s['file']}:{s['row']} | 标签 {s['verdict'].get('vulnerability_type')}")
            R(f"    代码首行: {s['first_line']}")
            R(f"    sink: {s['sink'][:160]}")

R("\n### 3.6 NoSQL 注入标 CWE-89 (应 CWE-943)")
for s in all_samples:
    if s["cwe"] == "89":
        code = s["code"]
        if RE_NOSQL.search(code):
            R(f"- {s['file']}:{s['row']} | 标签 {s['verdict'].get('vulnerability_type')}")
            R(f"    代码首行: {s['first_line']}")
            R(f"    sink: {s['sink'][:160]}")

# ---------- 4. 模板化程度聚类 ----------
R("\n## 4. 模板化程度 (变量名替换后骨架聚类, 同骨架>=5 的组)")
def skeleton(code):
    s = code
    s = re.sub(r'""".*?"""', "STR", s, flags=re.DOTALL)
    s = re.sub(r"'''.*?'''", "STR", s, flags=re.DOTALL)
    s = re.sub(r'"[^"\n]*"', "STR", s)
    s = re.sub(r"'[^'\n]*'", "STR", s)
    s = re.sub(r"\b\d+(?:\.\d+)?\b", "NUM", s)
    s = re.sub(r"\b[A-Za-z_]\w*\b", "ID", s)
    lines = [ln.strip() for ln in s.splitlines()]
    return "\n".join(ln for ln in lines if ln)

for fn in FILES:
    rows = [s for s in all_samples if s["file"] == fn]
    grp = defaultdict(list)
    for s in rows:
        sk = skeleton(s["code"])
        if sk:
            grp[sk].append(s["row"])
    groups = sorted(grp.values(), key=len, reverse=True)
    big = [g for g in groups if len(g) >= 5]
    R(f"- {fn}: 样本 {len(rows)} | 唯一骨架 {len(grp)} | 同骨架>=5 的组数 {len(big)}")
    # 打印最大几组
    for g in big[:5]:
        sk = None
        for s in rows:
            if s["row"] == g[0]:
                sk = skeleton(s["code"])
                break
        R(f"    组 (n={len(g)}) 行号 {g[:8]}{'...' if len(g)>8 else ''}:")
        for ln in sk.splitlines()[:6]:
            R(f"        {ln}")
        R(f"        ...")

# ---------- 5. CoT 质量 ----------
R("\n## 5. CoT 质量 (犹豫表述比例)")
tot_hes = 0
tot = 0
for fn in FILES:
    rows = [s for s in all_samples if s["file"] == fn]
    hes = sum(1 for s in rows if HESITATE.search(s["cot"]))
    tot_hes += hes
    tot += len(rows)
    R(f"- {fn}: {hes}/{len(rows)} = {hes/len(rows)*100:.1f}%")
R(f"- 合计: {tot_hes}/{tot} = {tot_hes/tot*100:.1f}%")
R("\n含犹豫表述的样本明细:")
for s in all_samples:
    if HESITATE.search(s["cot"]):
        R(f"  - {s['file']}:{s['row']} | {s['verdict'].get('vulnerability_type','?') if isinstance(s['verdict'],dict) else '?'} | 首行: {s['first_line'][:70]}")

# ---------- 6. 测试集泄漏 ----------
R("\n## 6. 测试集泄漏 (行级 Jaccard > 0.5)")
test_files = {}
for d in (HARD, TSET):
    if not os.path.isdir(d):
        R(f"  [警告] 目录不存在: {d}")
        continue
    for fname in os.listdir(d):
        if fname.startswith("manifest"):
            continue
        if fname.endswith((".py", ".java", ".js", ".php")):
            p = os.path.join(d, fname)
            with open(p, encoding="utf-8", errors="replace") as f:
                lines = [l.strip() for l in f if l.strip()]
            test_files[fname] = set(lines)

R(f"  测试文件数: {len(test_files)}")
leak_rows = []
for s in all_samples:
    code_lines = set(l.strip() for l in s["code"].splitlines() if l.strip())
    if not code_lines:
        continue
    best = (0.0, None)
    for tf, tset in test_files.items():
        inter = len(code_lines & tset)
        union = len(code_lines | tset)
        if union == 0:
            continue
        j = inter / union
        if j > best[0]:
            best = (j, tf)
    if best[0] > 0.5:
        leak_rows.append((best[0], s, best[1]))
leak_rows.sort(key=lambda x: -x[0])
if leak_rows:
    for j, s, tf in leak_rows:
        R(f"  - J={j:.2f} | {s['file']}:{s['row']} | 测试文件 {tf} | 首行: {s['first_line'][:60]}")
else:
    R("  (无泄漏)")

# ---------- 7. 安全样本检查 ----------
R("\n## 7. 安全样本 (supplement_mode_d 中 has_vulnerability=false) CoT 坚定度/标签可信度")
safe_rows = [s for s in all_samples if s["has_vuln"] is False]
R(f"  安全样本总数: {len(safe_rows)}")
for s in safe_rows:
    hes = bool(HESITATE.search(s["cot"]))
    verdict_txt = s["verdict"] if isinstance(s["verdict"], dict) else s["v_err"]
    R(f"- {s['file']}:{s['row']} | CoT犹豫={hes}")
    R(f"    代码首行: {s['first_line']}")
    R(f"    结论: {verdict_txt}")
    R(f"    CoT: {s['cot'][:300].replace(chr(10),' / ')}")

# ---------- 8. 无 source 型漏洞 ----------
R("\n## 8. 无 source 型漏洞样本 (弱随机数/整数溢出/竞态/硬编码凭证/弱加密)")
for s in all_samples:
    if s["cwe"] in NO_SOURCE_CWES and s["has_vuln"]:
        src = s["source"]
        R(f"- {s['file']}:{s['row']} | CWE-{s['cwe']} | {s['verdict'].get('vulnerability_type')}")
        R(f"    代码首行: {s['first_line']}")
        R(f"    source: {src[:150]}")
        R(f"    sink: {s['sink'][:150]}")

# ---------- 附: 抽样 30 条代码首行 + vulnerability_type ----------
R("\n## 附. 抽样 30 条 (代码首行 + vulnerability_type)")
# 抽样策略: 每文件均匀抽, 用固定 seed 保证可复现
import random
random.seed(42)
sampled = []
for fn in FILES:
    rows = [s for s in all_samples if s["file"] == fn]
    k = max(1, round(len(rows) * 30 / 924))
    sampled.extend(random.sample(rows, min(k, len(rows))))
sampled = sampled[:30]
for s in sampled:
    R(f"- {s['file']}:{s['row']} | {s['verdict'].get('vulnerability_type','?') if isinstance(s['verdict'],dict) else s['v_err']} | {s['first_line'][:90]}")

with open(REPORT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(report_lines) + "\n")
print_report()
print("\n[详细报告已写入]", REPORT_PATH)
