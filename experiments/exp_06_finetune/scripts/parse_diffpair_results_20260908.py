# -*- coding: utf-8 -*-
"""差分对蒸馏：网页结果解析（纯文本字段行协议 → 结构化 jsonl）。

用法：python scripts/parse_diffpair_results_20260908.py corpus/diffpair_wave1/results/*.txt
输出：corpus/diffpair_wave1/parsed/<包名>.jsonl（每行一条记录：id + 字段 dict）

容错（对账 9/7 附2 精神）：智能引号/代码围栏/多行值/中文冒号/散文前缀均无害；
已知字段键开启新值，未知行并入当前字段（分析过程的多行支持）。
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FIELDS = ["分析过程", "has_vulnerability", "vulnerability_type", "risk_level",
          "source", "sink", "行级归因", "explanation", "fix_suggestion"]
BLOCK = re.compile(r"^#{3,5}\s*(.+?)\s*$")
FIELD = re.compile(r"^(" + "|".join(re.escape(f) for f in FIELDS) + r")\s*[:：]\s?(.*)$")


def parse_text(text: str):
    records = []
    cur_id, cur_field, rec = None, None, None

    def flush():
        nonlocal rec
        if rec and rec.get("id"):
            rec["fields"] = {k: "\n".join(v).strip() for k, v in rec["_raw"].items() if v}
            del rec["_raw"]
            records.append(rec)
        rec = None

    for raw in text.splitlines():
        line = raw.rstrip()
        bm = BLOCK.match(line)
        bare = re.match(r"^((?:redistill-line-\d+)|(?:diffpair-\S+?)(?:-PRE|-POST)?)\s*$", line)
        if (bm and ("PRE" in bm.group(1) or "POST" in bm.group(1) or "diffpair-" in bm.group(1)
                    or "redistill" in bm.group(1))) or bare:
            flush()
            cur_id = (bm.group(1) if bm else bare.group(1)).strip().lstrip("#").strip()
            rec = {"id": cur_id, "_raw": {}}
            cur_field = None
            continue
        if rec is None:
            continue
        fm = FIELD.match(line)
        if fm:
            cur_field = fm.group(1)
            rec["_raw"].setdefault(cur_field, []).append(fm.group(2))
        elif line.startswith("#####") or (line.startswith("#") and not line.startswith("#!")):
            # 未知标题：视为块结束（防串块）
            flush()
            cur_field = None
        elif line.strip() and cur_field:
            rec["_raw"][cur_field].append(line)
    flush()
    return records


def main(argv):
    total = 0
    for arg in argv:
        p = Path(arg)
        if not p.exists() or p.suffix != ".txt":
            print(f"[skip] {p}")
            continue
        outdir = p.parent.parent / "parsed"   # results 的同级 parsed（wave 目录自包含）
        outdir.mkdir(parents=True, exist_ok=True)
        recs = parse_text(p.read_text(encoding="utf-8", errors="replace"))
        out = outdir / (p.stem + ".jsonl")
        with out.open("w", encoding="utf-8", newline="\n") as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        total += len(recs)
        print(f"{p.name}: {len(recs)} records → {out.name}")
    print(f"TOTAL {total}")


if __name__ == "__main__":
    main(sys.argv[1:])
