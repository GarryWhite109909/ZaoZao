"""Stage 1 候选审计工具——快速提升工具层能力的主战脚本（exp_08）。

方法论（2026-08-30 用户确立）：让工具扫多个样本/仓库/URL，逐条审计候选：
  A) 该产出候选却没产出的 —— 规则盲区（最能快速提升召回）
  B) 产出了但类型/证据误导的 —— 类型推断与映射错（污染裁决）
  C) 产出了但无关的 —— 噪声（挤占裁决注意力）
  D) 产出了却被剔除/抑制的 —— 剔除规则误杀（或确认剔除规则价值）

用法（对单文件/整仓批量）：
  python audit_stage1.py --file repos/dvna/core/appHandler.js --lang javascript \
      --expect manifest_dvna.json
  python audit_stage1.py --repo-dir repos/dvna --manifest manifest_dvna.json

输出：候选审计清单（Markdown），每条候选含「去向」（进裁决/被剔除/被抑制），
每条 expected finding 标注「覆盖情况」（有候选且类型对 / 有候选类型错 / 零候选=盲区）。
零 LLM 依赖：Stage 1 是纯确定性工具，秒级出全部结果。
"""
import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

_CWE_RE = re.compile(r"CWE-(\d+)")

# 语义类型名 → CWE 编号（工具层 taint_type 多为语义名，expected 用编号，两者都要能匹配）
_SEMANTIC_TO_CWE = {
    "sql injection": "89", "sqli": "89", "sequelize": "89",
    "command injection": "78", "cmdi": "78", "os command injection": "77",
    "code injection": "94", "eval injection": "95",
    "path traversal": "22", "path": "22",
    "open redirect": "601", "redirect": "601",
    "deserialization": "502", "insecure deserialization": "502",
    "xxe": "611", "xml external": "611",
    "xss": "79", "cross-site scripting": "79",
    "ssrf": "918", "server-side request forgery": "918",
    "template injection": "1336", "ssti": "1336",
    "timing attack": "208",
    "open redirect": "601",
    # 2026-08-31 补（VFlask 审计实锤缺口）：推断分支已能产出这些语义名，
    # 但本表缺映射 → 候选明明类型正确却被判 B。补的都是"语义名↔CWE 一对一
    # 无歧义"的项；有歧义的（如 weak cryptography 在 327/326/916 间）按项目
    # 标准答案口径取一个，并在下方注明。
    "hardcoded credentials": "798",      # 硬编码凭证，无歧义
    "insecure tls": "295",               # 禁用证书校验，无歧义
    # 弱密码学：327（弱/被破解算法，工具粒度）与 916（密码哈希强度不足，精确分类）
    # 同组。依据：CWE-916 官方定义 + CodeQL js/insufficient-password-hash 均将
    # md5(password) 归 916；而 bandit B324 / semgrep 只能到"用了弱算法"这一粒度
    # （327）。标准答案按精确分类记 916，此处双编号以对齐工具能力。
    "weak cryptography": "327|916",
}


def _types_to_cwes(text: str) -> set:
    """从类型/规则文本提取 CWE 编号：显式编号 + 语义名映射。

    语义名可映射**多个** CWE（"|" 分隔，2026-08-31）：标准答案的精确分类与
    工具的能力粒度常常不是同一个编号，但语义等价。例如密码用 md5 哈希，
    CWE 官方/CodeQL 的精确分类是 **916**（密码哈希计算强度不足），而 bandit
    B324 只能产出"弱哈希算法"这一粒度（327）。两者是同一个缺陷的不同粒度表述，
    不应判成"类型错标"——故归入同一语义组，任一命中即算对齐。
    """
    out = set(_CWE_RE.findall(text or ""))
    low = (text or "").lower()
    for name, cwe in _SEMANTIC_TO_CWE.items():
        if name in low:
            out.update(c for c in str(cwe).split("|") if c)
    return out


def collect_raw_candidates(ts, code: str, lang: str, fname: str) -> tuple[list, list, list]:
    """复刻 _stage1_recall 内部流程但保留中间态：原始候选 / 剔除+抑制后 / 最终去重。

    返回 (raw, after_drop, final)。after_drop 相对 raw 的差集 = 剔除/抑制的贡献。
    """
    from concurrent.futures import ThreadPoolExecutor

    def _semgrep():
        if ts.use_semgrep:
            return ts._semgrep_recall(code, lang, fname)
        return []

    def _taint():
        if ts._taint_tracker_enabled():
            return ts._taint_recall(code, lang, fname)
        return []

    def _prefilter():
        if ts._prefilter is not None:
            return ts._prefilter_recall(code, lang)
        return []

    def _external():
        if ts.use_external:
            return ts._external_positional_recall(code, lang, fname)
        return []

    raw = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        for fut in [pool.submit(fn) for fn in (_semgrep, _taint, _prefilter, _external)]:
            try:
                raw.extend(fut.result())
            except Exception as e:
                print(f"  [召回维度失败] {e}")

    dropped = ts._drop_irrelevant_positional(list(raw))
    final = ts._dedupe(ts._apply_signal_registry(dropped))

    def key(f):
        return (f.rule_id, f.sink_line or f.source_line, f.taint_type)

    after_drop = dropped
    return raw, after_drop, final


def candidate_rows(raw, after_drop, final) -> list[dict]:
    """每条原始候选标注去向：kept(final) / dropped(剔除) / deduped(合并进另一条)。

    同时记录 **推断后类型**（2026-08-31 修正）：候选的 taint_type 字段常是工具
    内部标识（bandit 的 B608/B324、semgrep 的规则文件路径），而生产链路里
    `_dedupe` 的语义族归并**走的是 _infer_taint_type 推断后的语义名**
    （two_stage_scanner 2218 行）。审计判定若只看原始 taint_type，就会把"类型
    其实正确、只是没写回字段"的候选误判成 B 类型错标（VFlask 实锤：B608 明明
    能推断出 SQL Injection，却被算成错标）。故此处同步计算并供判定使用。
    """
    from graduation_project.two_stage_scanner import TwoStageScanner
    final_keys = {(f.rule_id, f.sink_line or f.source_line, f.taint_type) for f in final}
    drop_keys = {(f.rule_id, f.sink_line or f.source_line, f.taint_type) for f in after_drop}
    rows = []
    for f in raw:
        k = (f.rule_id, f.sink_line or f.source_line, f.taint_type)
        if k in final_keys:
            fate = "进裁决"
        elif k in drop_keys:
            fate = "去重合并"
        else:
            fate = "被剔除/抑制"
        try:
            inferred = TwoStageScanner._infer_taint_type(f.to_dict())
        except Exception:
            inferred = f.taint_type
        rows.append({"rule_id": f.rule_id, "tool": f.tool, "taint_type": f.taint_type,
                     "inferred_type": inferred,
                     "line": f.sink_line or f.source_line, "severity": f.severity,
                     "evidence": (f.evidence or "")[:80], "fate": fate})
    return rows


def audit_expected(rec: dict, rows: list[dict], final) -> list[dict]:
    """对每条 expected finding：查候选覆盖情况与类型对齐（语义名+编号双口径）。"""
    out = []
    for exp in rec.get("expected_findings") or []:
        exp_cwe = exp.get("cwe", "")
        exp_num = exp_cwe.replace("CWE-", "")
        exp_line = exp.get("line", 0)
        covering = [r for r in rows
                    if r["fate"] != "被剔除/抑制"
                    and abs(r["line"] - exp_line) <= 2]
        # 判定口径：原始类型 + 推断后类型 + 规则号（2026-08-31）。
        # 只看原始 taint_type 会把"字段未写回但推断正确"的候选误判为 B，
        # 与生产 _dedupe 的语义族口径不一致（详见 candidate_rows 文档）。
        type_match = [r for r in covering
                      if exp_num in _types_to_cwes(" ".join(
                          [r["taint_type"], r["rule_id"],
                           r.get("inferred_type") or ""]))]
        if not covering:
            verdict = "A 盲区（零候选）"
        elif type_match:
            verdict = "OK（候选覆盖且类型对）"
        else:
            verdict = "B 候选在但类型错标"
        out.append({"cwe": exp_cwe, "line": exp_line, "note": exp.get("note", ""),
                    "verdict": verdict,
                    "covering": covering,
                    "dropped_covering": [r for r in rows
                                         if r["fate"] == "被剔除/抑制"
                                         and abs(r["line"] - exp_line) <= 2]})
    # C 类：与任何 expected 行不沾边的进裁决候选 = 无关候选（人工定性）
    exp_lines = [e.get("line", 0) for e in rec.get("expected_findings") or []]
    unrelated = [r for r in rows
                 if r["fate"] == "进裁决" and r["line"]
                 and not any(abs(r["line"] - l) <= 2 for l in exp_lines)]
    return out, unrelated


# ============================================================
# C 类候选合理性核验（确定性规则，零模型）——2026-08-30 用户确立：
# "候选是否合理"不该问模型。每条无关候选跑四问：
#   1) 行号处真的有污点传播形态吗（source→sink 同函数可见）？
#   2) 类型标签与行内代码形态匹配吗（判 Path Traversal 的行有 open/read 吗）？
#   3) 规则触发是否泛匹配（无行号 / 行号在注释/字符串里）？
#   4) 同位置同类型是否重复报告（去重失败信号）？
# ============================================================
_COMMENT_RE = re.compile(r"^\s*(//|/\*|\*|#|--)")
_STR_TOKEN_RE = re.compile(r"['\"`][^'\"`]{0,120}['\"`]")

_TYPE_REQUIRE = {
    # 类型关键词 → 行内必须出现的形态词（大小写不敏感，任一命中即算形态匹配）
    "path traversal": ("open(", "readfile", "writefile", "readdir", "unlink",
                       "createReadStream", "fs.", "path.join", "filepath",
                       "sendfile", "download", "require("),
    "command injection": ("exec(", "system(", "popen", "spawn", "subprocess"),
    "sql injection": ("query(", "execute(", "select", "insert", "update ", "delete from", "sequelize", "cursor"),
    "server-side template injection": ("render", "template", "jinja", "eval"),
    "code injection": ("eval(", "exec(", "new function", "compile("),
    "open redirect": ("redirect(", "location", "res.redirect", "window.location"),
    "deserialization": ("unserialize", "loads(", "readobject", "yaml.load", "pickle"),
    "xxe": ("parsexml", "xml", "documentbuilder", "libxml"),
    "xss": ("innerhtml", "document.write", "send(", "echo", "res.", "outerhtml"),
    "ssrf": ("requests.get", "urlopen", "fetch(", "axios", "http.get", "request("),
    "timing attack": ("===", "==", "compare_digest", "verify("),
    "mass assignment": ("req.body", "params[", "form", "update_attributes", "assign"),
    "idor": ("find(", "findby", "where:", "query", "select"),
    "missing authorization": ("route", "post(", "get(", "@app", "@controller", "handler"),
}


def _line_text(code: str, line: int) -> str:
    lines = code.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1].lower()
    return ""


def check_candidate_reasonable(cand: dict, code: str) -> dict:
    """确定性核验单条候选的合理性，返回四问结果与结论。"""
    line = cand.get("line") or 0
    ttype = (cand.get("taint_type") or "").lower()
    rule = (cand.get("rule_id") or "").lower()
    text = _line_text(code, line)

    checks = {}
    # 问 3：无行号 / 行落在注释或纯字符串里
    if not line:
        checks["Q3_无行号"] = True
    elif _COMMENT_RE.match(_line_text(code, line)):
        checks["Q3_注释行"] = True
    # 问 2：类型 → 行内形态匹配
    need = None
    for k, v in _TYPE_REQUIRE.items():
        if k in ttype or k in rule:
            need = v
            break
    if need is not None:
        hit = any(w in text for w in need)
        checks["Q2_形态匹配"] = hit
        if not hit:
            # 上下文放宽一行，仍不中才算错标
            around = (_line_text(code, line - 1) + " " + text + " " + _line_text(code, line + 1))
            checks["Q2_邻行形态匹配"] = any(w in around for w in need)
    # 问 4：同位置同类型重复（由调用方聚合后标注，此处单条无法判断，占位 False）
    checks["Q4_重复"] = False

    unreasonable = [k for k, v in checks.items() if v is True]
    return {"unreasonable": unreasonable,
            "verdict": ("疑不合理：" + "、".join(unreasonable)) if unreasonable else "形态核验通过"}


def dedupe_check(rows: list[dict]) -> list[dict]:
    """问 4 聚合版：同文件内 规则+类型+行 完全相同的重复候选。"""
    seen = {}
    dup = []
    for r in rows:
        k = (r["rule_id"], r["taint_type"], r["line"])
        seen[k] = seen.get(k, 0) + 1
        if seen[k] == 2:
            dup.append(r)
    return dup


def audit_file(ts, path: Path, rec: dict) -> dict:
    code = path.read_text(encoding="utf-8", errors="replace")
    lang = rec.get("language", "python").lower()
    raw, after, final = collect_raw_candidates(ts, code, lang, path.name)
    rows = candidate_rows(raw, after, final)
    audits, unrelated = audit_expected(rec, rows, final)
    # C 类候选逐条确定性核验（零模型）
    for r in unrelated:
        r["reasonableness"] = check_candidate_reasonable(r, code)["verdict"]
    dups = dedupe_check(rows)
    return {"file": rec["file"], "raw_count": len(raw), "final_count": len(final),
            "candidates": rows, "expected_audit": audits,
            "unrelated_confirmed_candidates": unrelated,
            "duplicate_candidates": dups}


def render_md(all_audits: list[dict], manifest: dict) -> str:
    lines = [f"# Stage 1 候选审计清单 —— {manifest['repo']}", "",
             "四类问题：A 盲区（该产出没产出）/ B 类型错标 / C 无关候选 / D 剔除存疑", ""]
    counts = {"A": 0, "B": 0, "OK": 0}
    for a in all_audits:
        lines.append(f"## {a['file']}（原始候选 {a['raw_count']} → 最终 {a['final_count']}）\n")
        lines.append("### expected finding 覆盖情况\n")
        lines.append("| CWE | 行 | 判定 | 覆盖候选（工具/类型/行）| 被剔除的相关候选 |")
        lines.append("|---|---|---|---|---|")
        for e in a["expected_audit"]:
            counts["A" if e["verdict"].startswith("A") else
                   ("B" if e["verdict"].startswith("B") else "OK")] += 1
            cov_parts = []
            for c in e["covering"]:
                shown = c["inferred_type"]
                if shown != c["taint_type"]:
                    shown += "(原:%s)" % c["taint_type"][:12]
                cov_parts.append("%s·%s·L%s" % (c["tool"], shown, c["line"]))
            cov = "<br>".join(cov_parts) or "—"
            drop = "<br>".join(f"{c['tool']}·{c['taint_type']}·L{c['line']}"
                               for c in e["dropped_covering"]) or "—"
            lines.append(f"| {e['cwe']} | {e['line']} | {e['verdict']} | {cov} | {drop} |")
        lines.append("")
        if a["unrelated_confirmed_candidates"]:
            lines.append("### C 无关候选（进裁决但与 expected 无关；合理性为**确定性核验**结论，零模型）\n")
            lines.append("| 工具 | 规则 | 类型 | 行 | 证据 | 确定性核验 |")
            lines.append("|---|---|---|---|---|---|")
            for r in a["unrelated_confirmed_candidates"]:
                lines.append(f"| {r['tool']} | {r['rule_id'][:40]} | {r['taint_type']} | "
                             f"{r['line']} | {r['evidence'][:40]} | {r.get('reasonableness','—')} |")
            lines.append("")
        if a.get("duplicate_candidates"):
            lines.append("### 重复候选（同规则+同类型+同行多报，去重失败信号）\n")
            for r in a["duplicate_candidates"]:
                lines.append(f"- {r['tool']}·{r['taint_type']}·L{r['line']}")
            lines.append("")
        lines.append("### 全部原始候选去向\n")
        lines.append("| 去向 | 工具 | 规则 | 类型 | 行 | 严重度 |")
        lines.append("|---|---|---|---|---|---|")
        for r in a["candidates"]:
            lines.append(f"| {r['fate']} | {r['tool']} | {r['rule_id'][:40]} | "
                         f"{r['taint_type']} | {r['line']} | {r['severity']} |")
        lines.append("")
    lines.insert(1, f"\n**审计统计**：OK {counts['OK']} · A 盲区 {counts['A']} · "
                     f"B 类型错标 {counts['B']}（A/B 逐条归因后写入工具层文档修复）\n")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--repo-dir", required=True)
    ap.add_argument("--file", default=None, help="只审计单个文件（调试用）")
    ap.add_argument("--output", default=None)
    args = ap.parse_args()

    from graduation_project.two_stage_scanner import TwoStageScanner
    from graduation_project.external_scanner import ExternalScanner
    ts = TwoStageScanner.__new__(TwoStageScanner)   # Stage 1 纯工具，无需 LLM client
    ts.use_semgrep = True
    ts.use_external = True
    ts.use_taint_tracker = True
    ts._external = ExternalScanner()
    ts._taint_tracker = None          # _taint_tracker_enabled 内惰性加载
    ts.n_samples = 3
    ts._signal_registry = None
    # §五之四 留痕容器（2026-08-30）：本脚本为跑纯 Stage 1 用 __new__ 绕过
    # __init__（不接 LLM client），而留痕字段在 __init__ 内初始化 —— 未补这两个
    # 字段时，命中"无主告警剔除/抑制池跳过"的文件会 AttributeError，整仓审计中断。
    ts._last_suppressed = False
    ts._last_suppressed_rules = []
    ts._dropped_unowned_rules = []
    from graduation_project.prefilter import Prefilter
    ts._prefilter = Prefilter()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    repo = Path(args.repo_dir)
    targets = [r for r in manifest["files"]
               if not args.file or r["file"] == args.file]
    print(f"审计 {len(targets)} 个文件（零 LLM，纯工具层）")

    all_audits = []
    for rec in targets:
        path = repo / rec["file"]
        if not path.exists():
            print(f"[skip] {rec['file']}")
            continue
        a = audit_file(ts, path, rec)
        all_audits.append(a)
        for e in a["expected_audit"]:
            mark = {"OK（候选覆盖且类型对）": "OK"}.get(e["verdict"], e["verdict"])
            print(f"  {rec['file']} L{e['line']} {e['cwe']}: {mark}")

    fname_tag = (args.file or "all").replace("/", "_")
    out = Path(args.output) if args.output else (
        HERE / "results" / f"stage1_audit.{manifest['repo'].split('/')[-1]}.{fname_tag}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_md(all_audits, manifest), encoding="utf-8")
    print(f"审计清单已写入: {out}")


if __name__ == "__main__":
    main()
