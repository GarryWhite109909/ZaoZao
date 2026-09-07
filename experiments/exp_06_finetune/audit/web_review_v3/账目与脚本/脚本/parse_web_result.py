# -*- coding: utf-8 -*-
"""网页端审计结果解析器：纯文本字段行 → 结构化 JSONL。

用法:
  python parse_web_result.py results_r2/result_pack_081.txt
  python parse_web_result.py results_r2/*.txt            # 批量, 输出到 parsed/ 同名 .jsonl
  python parse_web_result.py --stdin                     # 直接粘贴后 Ctrl+Z 回车结束(Windows)

容错: 自动剥离 ``` 代码块包裹/散文行/智能引号(仅映射回 ASCII 引号用于 enum 匹配,
evidence 原样保留)。字段缺省=无; 解析失败样本会在 stderr 报告行号, 不中断。
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HEADER = re.compile(r"^#{3,6}\s*id=(\d+)", re.M)
SUMMARY = re.compile(r"^#{3,6}\s*batch_summary\s*$", re.M)
FIELD = re.compile(r"^(\w+)\s*:\s*(.*)$")
LISTY = {"error", "evidence", "verify", "conditional", "unsure_reason", "note", "novel"}

def norm_quotes(s):
    return (s.replace("\u201c", '"').replace("\u201d", '"')
             .replace("\u2018", "'").replace("\u2019", "'"))

def parse_block(body, rec_id):
    rec = {"id": rec_id, "verdict": None, "tier": None, "independent": {},
           "errors": [], "verify": [], "verdict_conditionals": [],
           "unsure_reason": None, "note": None}
    cur_err = None
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("```"):
            continue
        m = FIELD.match(line)
        if not m:
            if cur_err is not None and line.startswith(("—", "-", "·")):
                rec["errors"][-1]["evidence"] += " " + line.lstrip("—-· ")
            continue
        k, v = m.group(1).lower(), m.group(2).strip()
        if k == "verdict":
            vv = norm_quotes(v).strip("\"' ")
            rec["verdict"] = vv if vv in {"DELETE", "FIX", "KEEP", "UNSURE"} else vv
        elif k == "tier":
            m2 = re.search(r"\d", v)
            rec["tier"] = int(m2.group(0)) if m2 else None
        elif k == "independent":
            for kv in norm_quotes(v).split(";"):
                if "=" in kv:
                    kk, _, val = kv.partition("=")
                    rec["independent"][kk.strip()] = val.strip()
            sl = rec["independent"].get("source_line", "")
            sk = rec["independent"].get("sink_line", "")
            rec["independent"]["source_line"] = None if sl.lower() in ("none", "null", "") else int(re.sub(r"\D", "", sl) or 0) or None
            rec["independent"]["sink_line"] = None if sk.lower() in ("none", "null", "") else int(re.sub(r"\D", "", sk) or 0) or None
        elif k == "error":
            seg = dict(x.strip().split("=", 1) for x in v.split(";") if "=" in x)
            cur_err = {"type": seg.get("type", "other"), "severity": seg.get("severity", "minor"), "evidence": ""}
            rec["errors"].append(cur_err)
        elif k == "evidence":
            if cur_err is not None:
                cur_err["evidence"] = v
        elif k == "verify":
            rec["verify"].append(v)
        elif k in ("conditional", "verdict_conditionals"):
            rec["verdict_conditionals"].append(v)
        elif k == "unsure_reason":
            rec["unsure_reason"] = norm_quotes(v).strip("\"' ")
        elif k == "note":
            rec["note"] = v
    rec["_complete"] = bool(rec["verdict"])
    return rec

def parse_summary(body):
    s = {"batch": None, "counts": {}, "top_errors": None, "worst_ids": [],
         "novel_error_count": 0, "novel_errors": []}
    cur_novel = None
    for raw in body.splitlines():
        line = raw.strip()
        m = FIELD.match(line)
        if not m:
            continue
        k, v = m.group(1).lower(), m.group(2).strip()
        if k == "batch":
            s["batch"] = v
        elif k == "counts":
            for kv in v.split():
                if "=" in kv:
                    a, _, b = kv.partition("=")
                    s["counts"][a] = int(re.sub(r"\D", "", b) or 0)
        elif k in ("top_errors",):
            s["top_errors"] = v
        elif k == "worst_ids":
            s["worst_ids"] = [int(x) for x in re.findall(r"\d+", v)]
        elif k == "novel_error_count":
            s["novel_error_count"] = int(re.sub(r"\D", "", v) or 0)
        elif k == "novel":
            if v.strip().lower() != "none":
                cur_novel = v
                s["novel_errors"].append(cur_novel)
    return s

def parse_text(text):
    text = text.replace("\r\n", "\n")
    # 剥离代码块围栏(网页端若包了 ```)
    text = re.sub(r"^```[a-z]*\n", "", text, flags=re.M)
    text = text.replace("```", "")
    out, summaries = [], []
    marks = [(m.start(), m.group(1), False) for m in HEADER.finditer(text)]
    marks += [(m.start(), "batch_summary", True) for m in SUMMARY.finditer(text)]
    marks.sort()
    for n, (start, rid, is_sum) in enumerate(marks):
        end = marks[n + 1][0] if n + 1 < len(marks) else len(text)
        body = text[start:end]
        if is_sum:
            summaries.append(parse_summary(body))
        else:
            out.append(parse_block(body, int(rid)))
    return out, summaries

def main():
    args = sys.argv[1:]
    outdir = None
    if args and args[0] == "--stdin":
        text = sys.stdin.read()
        recs, sums = parse_text(text)
        for r in recs:
            print(json.dumps(r, ensure_ascii=False))
        for s in sums:
            print(json.dumps({"batch_summary": s}, ensure_ascii=False))
        print(f"// 解析 {len(recs)} 条记录, {len(sums)} 个汇总; 不完整 {sum(1 for r in recs if not r['_complete'])}",
              file=sys.stderr)
        return
    for a in args:
        p = Path(a)
        outdir = p.parent / "parsed"
        outdir.mkdir(exist_ok=True)
        recs, sums = parse_text(p.read_text(encoding="utf-8", errors="replace"))
        dst = outdir / (p.stem + ".jsonl")
        with dst.open("w", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
            for s in sums:
                f.write(json.dumps({"batch_summary": s}, ensure_ascii=False) + "\n")
        bad = [r["id"] for r in recs if not r["_complete"]]
        print(f"{p.name}: {len(recs)} 条 -> {dst.name}; 无verdict: {bad if bad else '无'}")

if __name__ == "__main__":
    main()
