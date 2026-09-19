# -*- coding: utf-8 -*-
"""
v2_16 全量体检 + 实测门覆盖率记账（2026-09-09）

目的：在继续扩大「实测门」（编译/运行）投入之前，先把**零边际成本的全量确定性信号**跑完，
      并用它回答两个决策问题：
        Q1 实测门理论上最多能覆盖数据集的百分之多少？（覆盖率天花板）
        Q2 在实测门够不到的那部分里，还有没有便宜且可靠的清洗抓手？

产出：
  实测门_全量体检_v2_16_20260909.json   —— 机器可读全量指标
  实测门_覆盖率与全量体检报告_20260909.md —— 人读报告（含分级清洗队列）
"""
import json, re, sys, collections, hashlib, os

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.normpath(os.path.join(ROOT, "..", "data", "final_train_chatml_alpha06_v2_16.jsonl"))
CLUSTER = os.path.join(ROOT, "scan_v2_16_l3_cluster_flags.json")

FENCE = re.compile(r"```([A-Za-z0-9_+\-]*)\n(.*?)```", re.S)
LANG_HINT = re.compile(r"语言[:：]\s*([^\s）)]+)")

C_MAIN = re.compile(r"\b(?:int|void)\s+main\s*\(")
PY_MAIN = re.compile(r"if\s+__name__\s*==\s*[\"']__main__[\"']")
PY_TOP = re.compile(r"^(?!\s*(?:#|import|from|def|class|@|if|try|with))\S", re.M)
JS_SVC = re.compile(r"\.listen\s*\(|createServer\s*\(|app\.(?:get|post|use)\s*\(")
GO_MAIN = re.compile(r"func\s+main\s*\(")
JAVA_MAIN = re.compile(r"public\s+static\s+void\s+main\s*\(")
JAVA_FW = re.compile(r"@(?:RequestMapping|GetMapping|PostMapping|Controller|RestController|SpringBootApplication)|extends\s+HttpServlet|javax\.servlet|jakarta\.servlet|org\.springframework")
PHP_TOP = re.compile(r"^(?!\s*(?:<\?php|//|#|\*/|namespace|use\s|require|include|function|class|declare))", re.M)

# 框架依赖（Java 实测层的主要障碍）
JAVA_FW_ONLY = JAVA_FW


def norm_lang(hint, fence_lang):
    h = (hint or "").strip().lower()
    f = (fence_lang or "").strip().lower()
    m = {"c": "c", "cpp": "cpp", "c++": "cpp", "c#": "csharp", "csharp": "csharp", "cs": "csharp",
         "python": "python", "py": "python", "javascript": "javascript", "js": "javascript",
         "node": "javascript", "typescript": "javascript", "ts": "javascript",
         "go": "go", "golang": "go", "java": "java", "php": "php",
         "bash": "bash", "sh": "bash", "shell": "bash", "ruby": "ruby",
         "yaml": "yaml", "yml": "yaml", "dockerfile": "dockerfile", "sql": "sql"}
    if h in m:
        return m[h]
    if f in m:
        return m[f]
    for k in m:
        if h.startswith(k):
            return m[k]
    return "other"


def is_self_runnable(lang, code):
    """该样本能否在本地不经改造直接跑起来（实测门可达性的必要条件）"""
    if lang in ("c", "cpp"):
        return bool(C_MAIN.search(code))
    if lang == "python":
        return bool(PY_MAIN.search(code)) or bool(PY_TOP.search(code))
    if lang == "javascript":
        return bool(JS_SVC.search(code)) or bool(PY_TOP.search(code))
    if lang == "go":
        return bool(GO_MAIN.search(code))
    if lang == "php":
        return bool(PHP_TOP.search(code))
    if lang == "java":
        return bool(JAVA_MAIN.search(code)) and not bool(JAVA_FW_ONLY.search(code))
    if lang == "bash":
        return True
    return False


def parse_row(i, row):
    msgs = row.get("messages", [])
    user = ""
    asst = ""
    for m in msgs:
        if m.get("role") == "user":
            user = m.get("content", "")
        elif m.get("role") == "assistant":
            asst = m.get("content", "")
    hint = LANG_HINT.search(user)
    fences = FENCE.findall(user)
    lang = "other"
    code = ""
    if fences:
        # 取最长的一个代码围栏当主体代码
        fl, fc = max(fences, key=lambda x: len(x[1]))
        code = fc
        lang = norm_lang(hint.group(1) if hint else "", fl)
    else:
        lang = norm_lang(hint.group(1) if hint else "", "")

    # 结论 JSON
    v = None
    blocks = re.findall(r"```json\s*(.*?)```", asst, re.S)
    if blocks:
        try:
            v = json.loads(blocks[-1].strip())
        except Exception:
            v = None
    hv = None
    cwe = ""
    fix = None
    if isinstance(v, dict):
        hv = v.get("has_vulnerability")
        if isinstance(hv, str):
            hv = hv.strip().lower() in ("true", "yes", "1")
        vt = str(v.get("vulnerability_type") or "")
        m = re.search(r"CWE-(\d+)", vt)
        cwe = "CWE-" + m.group(1) if m else ""
        fix = v.get("fix_suggestion")

    closed = user.count("```") % 2 == 0
    return {
        "line": i + 1,
        "lang": lang,
        "code": code,
        "code_len": len(code),
        "has_vuln": hv,
        "cwe": cwe,
        "fix_present": bool(fix and str(fix).strip() and str(fix).strip().lower() not in ("null", "none", "无", "n/a")),
        "verdict_parsed": v is not None,
        "fence_closed": closed,
        "self_runnable": is_self_runnable(lang, code) if code else False,
        "code_hash": hashlib.md5(code.encode("utf-8", "replace")).hexdigest() if code else "",
    }


def main():
    rows = []
    with open(DATA, encoding="utf-8") as f:
        for i, l in enumerate(f):
            l = l.strip()
            if not l:
                continue
            try:
                rows.append(parse_row(i, json.loads(l)))
            except Exception as e:
                rows.append({"line": i + 1, "lang": "?", "code": "", "code_len": 0, "has_vuln": None,
                             "cwe": "", "fix_present": False, "verdict_parsed": False,
                             "fence_closed": False, "self_runnable": False,
                             "code_hash": "", "err": str(e)})
    n = len(rows)
    out = {"dataset": os.path.basename(DATA), "n_rows": n}

    # ---------- 1. 语言分布 ----------
    by_lang = collections.Counter(r["lang"] for r in rows)
    out["by_lang"] = by_lang.most_common()

    # ---------- 2. 实测门可达性（覆盖率天花板） ----------
    # 实测层工具链：c/cpp(gcc) python go node php bash(shellcheck) dockerfile(hadolint/checkov) yaml(checkov)
    TOOLCHAIN = {"c", "cpp", "python", "go", "javascript", "php", "bash", "dockerfile", "yaml"}
    reachable = [r for r in rows if r["lang"] in TOOLCHAIN and r["self_runnable"]]
    runnable_by_lang = collections.Counter(r["lang"] for r in rows if r["self_runnable"])
    out["reachable_n"] = len(reachable)
    out["reachable_pct"] = round(100.0 * len(reachable) / n, 2)
    out["self_runnable_by_lang"] = runnable_by_lang.most_common()
    out["unreachable_by_lang"] = collections.Counter(
        r["lang"] for r in rows if not (r["lang"] in TOOLCHAIN and r["self_runnable"])).most_common()
    # 语言在工具链内但样本不自运行（需合成 harness，成本 ×3~5）
    out["in_toolchain_not_runnable"] = collections.Counter(
        r["lang"] for r in rows if r["lang"] in TOOLCHAIN and not r["self_runnable"]).most_common()

    # ---------- 3. 全量免费信号：结构完整性 ----------
    out["verdict_parse_fail"] = sum(1 for r in rows if not r["verdict_parsed"])
    out["fence_unclosed"] = sum(1 for r in rows if not r["fence_closed"])
    out["empty_code"] = sum(1 for r in rows if r["code_len"] < 30)
    out["fix_missing"] = sum(1 for r in rows if r["has_vuln"] and not r["fix_present"])
    out["fix_missing_pct_of_vuln"] = round(
        100.0 * out["fix_missing"] / max(1, sum(1 for r in rows if r["has_vuln"])), 2)

    # ---------- 4. 全量免费信号：精确重复代码 ----------
    h = collections.defaultdict(list)
    for r in rows:
        if r["code_hash"]:
            h[r["code_hash"]].append(r["line"])
    dup_groups = {k: v for k, v in h.items() if len(v) > 1}
    dup_rows = sorted(sum(dup_groups.values(), []))
    out["exact_dup_groups"] = len(dup_groups)
    out["exact_dup_rows"] = len(dup_rows)
    out["exact_dup_rows_pct"] = round(100.0 * len(dup_rows) / n, 2)
    out["exact_dup_top"] = sorted(dup_groups.values(), key=len, reverse=True)[:15]

    # ---------- 5. 全量免费信号：同码反标（相同代码、相反标签）----------
    hv_by_hash = collections.defaultdict(list)
    for r in rows:
        if r["code_hash"] and r["has_vuln"] is not None:
            hv_by_hash[r["code_hash"]].append((r["line"], r["has_vuln"], r["cwe"]))
    contra = []
    for k, lst in hv_by_hash.items():
        vals = set(x[1] for x in lst)
        if len(vals) > 1:
            contra.append(sorted(lst))
    out["same_code_conflict_groups"] = len(contra)
    out["same_code_conflict_rows"] = sum(len(g) for g in contra)
    out["same_code_conflict_samples"] = contra[:20]

    # ---------- 6. 近重复簇（复用既有 L3 结果） ----------
    if os.path.exists(CLUSTER):
        try:
            cl = json.load(open(CLUSTER, encoding="utf-8"))
            cl_rows = set()
            sizes = []
            for c in cl.get("clusters", []):
                rr = c.get("rows_1based", [])
                if len(rr) > 1:
                    cl_rows.update(rr)
                    sizes.append(len(rr))
            out["cluster_multi_groups"] = len(sizes)
            out["cluster_rows_in_multi"] = len(cl_rows)
            out["cluster_rows_pct"] = round(100.0 * len(cl_rows) / n, 2)
            out["cluster_max_size"] = max(sizes) if sizes else 0
            out["cluster_size_hist"] = dict(sorted(collections.Counter(sizes).items()))
        except Exception as e:
            out["cluster_err"] = str(e)

    # ---------- 7. 语言 × 标签 交叉（为分层抽样做准备）----------
    ct = collections.Counter((r["lang"], r["has_vuln"]) for r in rows)
    out["lang_x_label"] = {f"{k[0]}|{k[1]}": v for k, v in sorted(ct.items(), key=lambda x: (str(x[0][0]), str(x[0][1])))}

    with open(os.path.join(ROOT, "实测门_全量体检_v2_16_20260909.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(json.dumps({k: v for k, v in out.items()
                      if k not in ("exact_dup_top", "same_code_conflict_samples", "lang_x_label")},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
