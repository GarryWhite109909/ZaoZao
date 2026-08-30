"""全量评估结果四口径排查脚本（离线，秒级完成，不碰 GPU）。

对 eval_two_stage.py 产出的逐样本 JSON 做：
  1. 判定 + 类型 strict hit 比对（vs manifest expected，含多标注 `;` 分隔）
  2. 行号锚逐条核对（explanation / fix_suggestion / 裁决 reason 中的
     "line N:" 锚 vs 源码真实行内容）
  3. 伪修复检测（F5 启发式：判定与修复矛盾、值比较挡注入、防御措辞矛盾）
  4. 多漏洞共现清单（≥2 个不同 CWE 语义族的候选均被确认，供标注治理）

输出：Markdown 报告（results/triage_report_<ts>.md）+ 控制台摘要。
仅做启发式标记，"可疑"不等于"错误"，最终定性靠人工复核。

用法：
  python triage_report.py [--result results/exp_07_full87...json]
"""
import argparse
import json
import re
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_RESULT = HERE / "results" / "exp_07_full87.nivis-alpha0.combined_nosource.20260830.json"
SAMPLES_DIR = HERE.parent / "exp_04_hard_samples" / "samples"

# 行号锚：line_normalizer 输出恒为 "line N: 内容"；兼容 "第 N 行" 叙述
_LINE_RE = re.compile(r"line\s*(\d+)\s*[:：]?\s*(.*)", re.IGNORECASE)
_CN_LINE_RE = re.compile(r"第\s*(\d+)\s*行")
_CWE_RE = re.compile(r"CWE-(\d+)")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip()).lower()


def _src_lines(code: str) -> list[str]:
    return code.splitlines()


def _anchor_issues(text: str, code: str, is_fix: bool = False) -> list[dict]:
    """检查文本中 "line N: 内容" 锚：N 越界或内容与源码第 N 行不符 → 可疑。

    容忍两类固有形态（非错误）：
      - 多锚文本：内容在下一个 "line M" 处截断（"line 9: xxx, line 10: yyy"）
      - 修复建议描述目标态：fix 里 "应改为 requests.get(url, verify=true)" 与
        源码行（verify=false）必然不同——退化为只验证该行含锚中关键 token
    """
    issues = []
    lines = _src_lines(code)
    matches = list(_LINE_RE.finditer(text))
    for i, m in enumerate(matches):
        n = int(m.group(1))
        # 内容截断到下一个锚（或文本末尾），避免贪婪吞并相邻锚
        seg_end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        content = _norm(text[m.end():seg_end].lstrip(":： "))
        if n < 1 or n > len(lines):
            issues.append({"n": n, "why": "越界", "content": content[:50],
                           "actual": f"共 {len(lines)} 行"})
            continue
        actual = _norm(lines[n - 1])
        if not content or len(content) < 6:
            continue
        # 修复建议目标态：只查该行含锚中任一关键 token（≥4 字符）
        if is_fix and re.search(r"(应改为|改为|修改为|应使用|替换为|replace)", content):
            tokens = [w for w in re.split(r"[^\w.]+", content) if len(w) >= 4]
            if tokens and any(t in actual for t in tokens):
                continue
        probe = content[:12].strip(":： ")
        if probe and probe not in actual and actual[:12] not in content:
            issues.append({"n": n, "why": "内容不符", "content": content[:50],
                           "actual": actual[:50]})
    return issues


def _check_verdict(s: dict) -> dict:
    """口径 1：判定 + 类型 strict hit。"""
    exp_present = bool(s.get("expected_present"))
    pred = s.get("predicted")  # True/False/None(复核)
    pred_str = s.get("predicted_str") or ""
    exp_cwes = set(_CWE_RE.findall(s.get("expected_cwe") or ""))
    got_type = s.get("vulnerability_type") or ""
    got_cwes = set(_CWE_RE.findall(got_type))
    r = {"file": s.get("file"), "kind": "ok", "detail": ""}
    if pred is None:
        r["kind"] = "review"
        r["detail"] = f"predicted=None（需人工复核，decision={s.get('decision')}）"
        return r
    if exp_present and not pred:
        r["kind"] = "FN"
        # 归因：stage1 是否有候选
        st = s.get("stage1") or {}
        n_cand = st.get("candidates", st.get("n_candidates", -1))
        r["detail"] = f"漏报。stage1 候选数={n_cand}（0=工具层未召回，>0=裁决层否决）"
        return r
    if not exp_present and pred:
        r["kind"] = "FP"
        r["detail"] = f"误报。predicted 类型={got_type or '(空)'}"
        return r
    # 判定方向正确 → 类型核对（仅漏洞样本）
    if exp_present:
        if not got_cwes:
            r["kind"] = "type_miss"
            r["detail"] = f"判定对但无 CWE 编号：{got_type!r}（expected {sorted(exp_cwes)}）"
        elif not (got_cwes & exp_cwes):
            r["kind"] = "type_miss"
            r["detail"] = (f"类型不符：predicted {sorted(got_cwes)} vs "
                           f"expected {sorted(exp_cwes)}")
    return r


def _check_fix(s: dict) -> list[dict]:
    """口径 3：伪修复启发式（F5）。"""
    issues = []
    if not s.get("predicted"):
        return issues
    fix = (s.get("fix_suggestion") or "").strip()
    low = fix.lower()
    ft = _norm(got_type := (s.get("vulnerability_type") or ""))
    if fix in ("N/A", "no fix needed", ""):
        issues.append({"rule": "F5-判定修复矛盾",
                       "detail": f"判真但 fix_suggestion={fix!r}"})
    elif any(k in low for k in ("不存在漏洞", "误报", "已正确防御", "无漏洞", "不需要修复")):
        issues.append({"rule": "F5-防御措辞矛盾",
                       "detail": f"判真但修复建议称无漏洞：{fix[:60]}"})
    # 值比较挡注入：SQL/命令族且 fix 无参数化/预编译/转义关键词，却出现值白名单特征
    inj_family = any(k in ft for k in ("sql", "command", "inject", "cwe-89", "cwe-78", "cwe-77"))
    has_param = any(k in low for k in ("parameter", "prepared", "占位", "placeholder",
                                       "execute(", "?", "%s", "escape", "shlex",
                                       "literal_eval", "白名单", "allowlist"))
    if inj_family and not has_param and re.search(r"(==|\bin\s+\[|startswith)", fix):
        issues.append({"rule": "F5-值比较挡不住注入",
                       "detail": f"注入类修复仅含值比较，无参数化/预编译：{fix[:60]}"})
    return issues


def _family_set(s: dict) -> set[str]:
    """口径 4：已确认裁决的 CWE 语义族集合。"""
    fams = set()
    for a in s.get("adjudications") or []:
        if not a.get("confirmed"):
            continue
        cwes = _CWE_RE.findall(a.get("vulnerability_type") or "")
        if cwes:
            fams.update(cwes)
        else:
            t = _norm(a.get("taint_type") or "")
            if t and t not in ("none", "unknown"):
                fams.add(t)
    return fams


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--result", type=str, default=str(DEFAULT_RESULT))
    args = ap.parse_args()

    data = json.loads(Path(args.result).read_text(encoding="utf-8"))
    samples = data.get("samples", [])
    verdicts, anchors, fixes, cooccur = [], [], [], []
    for s in samples:
        fname = s.get("file", "")
        code = ""
        code_path = SAMPLES_DIR / fname
        if code_path.exists():
            code = code_path.read_text(encoding="utf-8")

        v = _check_verdict(s)
        verdicts.append(v)

        if code and s.get("predicted"):
            for field in ("explanation", "fix_suggestion"):
                for iss in _anchor_issues(s.get(field) or "", code,
                                          is_fix=(field == "fix_suggestion")):
                    anchors.append({"file": fname, "field": field, **iss})
            for a in s.get("adjudications") or []:
                if a.get("confirmed") and a.get("reason"):
                    for iss in _anchor_issues(a["reason"], code):
                        anchors.append({"file": fname, "field": f"reason({a.get('rule_id')})",
                                        **iss})

        for iss in _check_fix(s):
            fixes.append({"file": fname, **iss})

        fams = _family_set(s)
        if len(fams) >= 2:
            cooccur.append({"file": fname, "families": sorted(fams),
                            "expected_cwe": s.get("expected_cwe")})

    # ---- 汇总 ----
    vc = Counter(v["kind"] for v in verdicts)
    n = len(samples)
    hit = vc.get("ok", 0)
    print(f"总样本 {n} | 判定+类型全对 {hit} | 复核 {vc.get('review',0)} | "
          f"FN {vc.get('FN',0)} | FP {vc.get('FP',0)} | 类型错 {vc.get('type_miss',0)}")
    print(f"可疑行号锚 {len(anchors)} | 可疑修复 {len(fixes)} | 多漏洞共现 {len(cooccur)}")

    # ---- 报告 ----
    ts = time.strftime("%Y%m%d_%H%M%S")
    out = HERE / "results" / f"triage_report_{ts}.md"
    lines = [f"# 全量评估四口径排查报告（{ts}）",
             f"- 结果文件：`{args.result}`",
             f"- 样本：{n}；判定+类型全对 {hit}；复核 {vc.get('review',0)}；"
             f"FN {vc.get('FN',0)}；FP {vc.get('FP',0)}；类型错 {vc.get('type_miss',0)}",
             ""]
    def _sec(title: str, rows: list[dict], cols: list[str]) -> None:
        lines.append(f"## {title}（{len(rows)}）\n")
        if not rows:
            lines.append("（无）\n")
            return
        lines.append("| " + " | ".join(cols) + " |")
        lines.append("|" + "---|" * len(cols))
        for r in rows:
            lines.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")
        lines.append("")
    _sec("一、漏报 FN（含归因）", [v for v in verdicts if v["kind"] == "FN"],
         ["file", "detail"])
    _sec("二、误报 FP", [v for v in verdicts if v["kind"] == "FP"], ["file", "detail"])
    _sec("三、类型不符 type_miss", [v for v in verdicts if v["kind"] == "type_miss"],
         ["file", "detail"])
    _sec("四、需人工复核（predicted=None）", [v for v in verdicts if v["kind"] == "review"],
         ["file", "detail"])
    _sec("五、可疑行号锚（启发式，需人工确认）", anchors,
         ["file", "field", "n", "why", "content", "actual"])
    _sec("六、可疑修复（F5 启发式）", fixes, ["file", "rule", "detail"])
    _sec("七、多漏洞共现（≥2 语义族确认，供标注治理）", cooccur,
         ["file", "families", "expected_cwe"])
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"报告已写入: {out}")

    # 明细打印 FN/类型错（排查优先级最高）
    for v in verdicts:
        if v["kind"] in ("FN", "type_miss"):
            print(f"  [{v['kind']}] {v['file']}: {v['detail']}")


if __name__ == "__main__":
    main()
