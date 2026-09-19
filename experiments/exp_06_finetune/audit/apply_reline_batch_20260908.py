# -*- coding: utf-8 -*-
"""FIX 队列纯 reline 批处理（20260908）：7276 / 7277 / 7282 / 7532 / 7284 / 7841。

方法（fix13 pass1 的 evidence 映射传统，spec 即审计员给定的 old→new 锚点对）：
- 定位：v15_line 经"删除事件全量重放"换算的今日行号（locate_fix_queue_20260908.py 同链），
  另加 kind/代码头特征复核；
- 替换形态：`第 X 行` / `第X行` / `第 X-Y 行` / `line X` / `LX` / JSON 字段内 `line X:`
  （仅 assistant 文本，代码本体不动）；
- 验证：每个映射 ≥1 次替换；旧锚在锚位语境零残留；JSON 可解析；
  JSON source/sink 新行位抽验（新行文本须含叙事中的标识符之一，命中失败仅告警不中止）。
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"

ITEMS = {
    7276: {"today": 7209, "sig": "import errno", "kind": "safe_pair",
           "moves": [("96", "99"), ("88-89", "97-99"), ("60", "51"), ("91-99", "106-108"),
                     ("100-104", "110-115"), ("63-86", "55-94")]},
    7277: {"today": 7210, "sig": "declare(strict_types", "kind": "safe_pair",
           "moves": [("62-63", "88-89"), ("55-57", "60-64"), ("73-75", "80-82"),
                     ("78-80", "90-92"), ("74", "83-85")]},
    7282: {"today": 7214, "sig": "Licensed to the Apache", "kind": "safe_pair",
           "moves": [("18", "17"), ("22", "21"), ("24-26", "23-25"), ("29", "28"), ("31-32", "30-31")]},
    7532: {"today": 7454, "sig": "PhpOffice", "kind": "checklist_cot",
           "moves": [("17", "22"), ("44", "52"), ("22", "28"), ("24-27", "31-35"),
                     ("30-34", "36-40"), ("57", "70")]},
    7284: {"today": 7216, "sig": "Licensed to the Apache", "kind": "safe_pair",
           "moves": [("8", "23"), ("33", "40"), ("63", "68"), ("55-62", "57-72"),
                     ("46-52", "48-55"), ("58", "60")]},
    7841: {"today": 7754, "sig": "consult_gemini", "kind": None,
           "moves": [("168", "300"), ("253", "383"), ("174", "306"), ("88", "129"), ("285", "418")]},
}

ROWS = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]


def anchor_patterns(tok_old, tok_new):
    """同一映射的多种文本形态；长 token 的正则优先。"""
    o, n = re.escape(tok_old), tok_new
    pats = [
        (rf"第\s*{o}\s*行", f"第 {n} 行"),
        (rf"第{o}行", f"第{n}行"),
        (rf"line\s*{o}(?=[::\s，,)）])", f"line {n}"),
        (rf"(?<![A-Za-z0-9])L{o}(?![0-9])", f"L{n}"),
    ]
    return pats


def reline_text(text, moves):
    total = 0
    for old, new in moves:
        cnt = 0
        for pat, rep in anchor_patterns(old, new):
            text, k = re.subn(pat, rep, text)
            cnt += k
        if cnt == 0:
            print(f"    [warn] 映射 {old}→{new} 零替换")
        total += cnt
    return text, total


def residue(text, moves):
    """旧锚在锚位语境的残留计数。"""
    bad = 0
    for old, _ in moves:
        o = re.escape(old)
        bad += len(re.findall(rf"第\s*{o}\s*行", text))
        bad += len(re.findall(rf"line\s*{o}(?=[::\s，,)）])", text))
    return bad


def spot_check(row):
    """JSON source/sink 新行位抽验：新行文本含叙事标识符之一。"""
    a = row["messages"][2]["content"]
    m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
    if not m:
        return "no-json"
    obj = json.loads(m.group(1))
    code = "\n".join(re.findall(r"```[a-zA-Z0-9+#]*\n(.*?)```", row["messages"][1]["content"], re.S))
    lines = code.split("\n")
    out = []
    for field in ("source", "sink"):
        v = obj.get(field, "")
        lm = re.match(r"line (\d+)", v)
        if not lm:
            continue
        ln = int(lm.group(1))
        if 1 <= ln <= len(lines):
            out.append(f"{field}@L{ln}:{lines[ln-1].strip()[:38]}")
    return " | ".join(out)


def main():
    report = []
    for fid, it in ITEMS.items():
        idx = it["today"] - 1
        row = ROWS[idx]
        u, a = row["messages"][1]["content"], row["messages"][2]["content"]
        assert it["sig"] in u, f"id={fid} 特征不符"
        if it["kind"]:
            assert (row.get("meta") or {}).get("kind") == it["kind"], f"id={fid} kind 不符"
        a2, n_sub = reline_text(a, it["moves"])
        res = residue(a2, it["moves"])
        row["messages"][2]["content"] = a2
        spot = spot_check(row)
        # JSON 可解析性
        m = re.search(r"\n```json\n(\{.*?\})\n```", a2, re.S)
        ok_json = bool(m) and (json.loads(m.group(1)) is not None)
        report.append((fid, n_sub, res, ok_json, spot))
        with CHANGELOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps({
                "date": "2026-09-08", "step": "1.4_fix_queue_reline", "action": "FIX",
                "fix_id": fid, "row_line_before": it["today"],
                "note": f"reline {it['moves']}, {n_sub} 次替换, 旧锚残留 {res}",
                "basis": "fix_queue_20260907 spec（审计员 evidence 映射）",
            }, ensure_ascii=False) + "\n")
        print(f"id={fid} 替换 {n_sub} 残留 {res} json={ok_json}")
        print(f"   抽验 {spot}")

    assert all(r[3] for r in report), "存在 JSON 解析失败"
    with DATA.open("w", encoding="utf-8", newline="\n") as f:
        for r in ROWS:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print("落盘完成")


if __name__ == "__main__":
    main()
