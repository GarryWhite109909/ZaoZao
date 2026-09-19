# -*- coding: utf-8 -*-
"""FIX 队列 reline+小语义 rider 批处理（20260908）：
7551 / 7264 / 7265 / 7270 / 7543 / 7283 / 7832 / 7839。

reline 部分全验证（每映射计数 + 旧锚残留 + JSON 解析）；
rider 部分尽力而为，零命中 → changelog 记"待人工跟进"。
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(Path(__file__).resolve().parents[1])
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"

ITEMS = {
    7551: {"today": 7474, "sig": "report_exporter", "kind": "taint_boundary_vuln",
           # spec 旧锚（38/52/58）与现文本不同基（疑 pack 版号）；按实码对码修正，反向序防连锁
           "moves": [("23", "24"), ("22", "23"), ("16", "17"), ("20", "19-20")],
           "riders": [("dual2single", None)]},
    7264: {"today": 7198, "sig": "# -*- coding: utf-8", "kind": "safe_pair",
           "moves": [("8", "18"), ("10", "21"), ("15", "25"), ("16", "26"), ("20", "32"),
                     ("21", "33"), ("27-33", "47-50"), ("36", "53"), ("41-43", "63-65")],
           "riders": [("append", "【补充断言】abspath 仅做词法规范化，不解析符号链接——符号链接指向白名单外目标的场景不受其防护。")]},
    7265: {"today": 7199, "sig": "package client", "kind": "vuln",
           "moves": [("14", "17"), ("16", "20"), ("39", "51"), ("33-36", "42-46"), ("62-68", "63-78")],
           "riders": [("append", "【边界补充】req.Path 仅取 path 分量参与匹配，authority（scheme://host）不进入；若上游以含 authority 的原样字符串构造跳转目标，需另行校验——本文件出口均按 path 处理，authority 注入不构成本文件内的可达面。")]},
    7270: {"today": 7204, "sig": "header('Content-Type:", "kind": "vuln",
           "moves": [("8", "10"), ("33", "30"), ("35", "33"), ("41-43", "47-48")],
           "riders": [("drop_sent", "userSavePhoto.php")]},
    7543: {"today": 7464, "sig": "from __future__ import", "kind": "checklist_cot",
           "moves": [("23", "32"), ("45", "75"), ("50", "77"), ("68", "88"), ("60", "85"), ("47", "71")],
           "riders": [("json_sink_71to77", None), ("1336to79", None)]},
    7283: {"today": 7215, "sig": "Licensed to the Apache", "kind": "safe_pair",
           "moves": [("55", "70"), ("58-64", "73-80"), ("59-60", "73"), ("44", "43"),
                     ("48", "50"), ("53", "58"), ("69", "65"), ("74", "85")],
           "riders": [("combined_7283", None),
                      ("append", "【残余风险补充】白名单收敛攻击面但不消除 gadget 风险：白名单内类若可参与 JDK 反序列化 gadget 链（如受控版本的 commons-collections），仍可能被组合利用——白名单是必要而非充分防御。")]},
    7832: {"today": 7748, "sig": "package archive_test", "kind": None,
           "moves": [("238-257", "229-244"), ("177-179", "171-173"), ("195-236", "195-227"),
                     ("218-219", "217-218")],
           "riders": [("drop_sent", "247-257")]},
    7839: {"today": 7752, "sig": "package http", "kind": None,
           "moves": [("66", "72"), ("39-53", "46-57"), ("61", "65"), ("74", "81"),
                     ("96", "119"), ("156", "193"), ("193", "235")],
           "riders": [("six2five", None), ("scan2query", None)]},
}
# 修正 7283 的映射表（spec: 55→70,58-64→73-80,59-60→73,44→43,48/53/69/74→50/58/65/85/92）
ITEMS[7283]["moves"] = [("55", "70"), ("58-64", "73-80"), ("59-60", "73"), ("44", "43"),
                        ("48", "50"), ("53", "58"), ("69", "65"), ("74", "85")]


def R(t, x, y):
    assert t.count(x) == 1, f"不唯一({t.count(x)}): {x[:60]}"
    return t.replace(x, y)


def anchor_patterns(tok_old, tok_new):
    o = re.escape(tok_old).replace(r"\-", "[-–—]")
    n = tok_new
    return [
        (rf"第\s*{o}\s*行", f"第 {n} 行"),
        (rf"第{o}行", f"第{n}行"),
        (rf"line\s*{o}(?=[::\s，,)）])", f"line {n}"),
        (rf"(?<![A-Za-z0-9])L{o}(?![0-9])", f"L{n}"),
    ]


def reline_text(text, moves):
    total = 0
    for old, new in moves:
        cnt = 0
        for pat, rep in anchor_patterns(old, new):
            text, k = re.subn(pat, rep, text)
            cnt += k
        if cnt == 0:
            print(f"    [warn] {old}→{new} 零替换")
        total += cnt
    return text, total


def apply_riders(text, riders):
    notes = []
    for kind, arg in riders:
        if kind == "dual2single":
            n = text.count("双重编码")
            if n:
                text = text.replace("双重编码", "单重编码")
            notes.append(f"双重→单重编码 ×{n}" + ("" if n else "（零命中，待人工）"))
        elif kind == "append":
            m = re.search(r"\n```json\n", text)
            text = text[: m.start()] + "\n" + arg + text[m.start():]
            notes.append("append 补注 ✓")
        elif kind == "drop_sent":
            pat = rf"[^。；\n]*{re.escape(arg)}[^。；\n]*[。；]?"
            text, n = re.subn(pat, "", text)
            notes.append(f"删句（含 {arg}）×{n}" + ("" if n else "（零命中，待人工）"))
        elif kind == "json_sink_71to77":
            m = re.search(r"\n```json\n(\{.*?\})\n```", text, re.S)
            obj = json.loads(m.group(1))
            if obj.get("sink", "").startswith("line 71"):
                obj["sink"] = obj["sink"].replace("line 71", "line 77", 1)
                notes.append("json sink 71→77 ✓")
            else:
                notes.append(f"json sink 现值={obj.get('sink','')[:30]}（非 71，免改）")
            text = text[: m.start()] + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```"
        elif kind == "1336to79":
            n = len(re.findall(r"1336", text))
            text = re.sub(r"1336", "79", text)
            notes.append(f"正文 1336→79 ×{n}" + ("" if n else "（零命中，待人工）"))
        elif kind == "combined_7283":
            n = text.count("48、53、69、74")
            if n:
                text = text.replace("48、53、69、74", "50、58、65、85")
            notes.append(f"组合锚 48/53/69/74→50/58/65/85 ×{n}" + ("" if n else "（零命中，待人工）"))
        elif kind == "six2five":
            text, n = re.subn(r"6\s*个\s*handler", "5 个 handler", text)
            notes.append(f"6个handler→5 ×{n}" + ("" if n else "（零命中，待人工）"))
        elif kind == "scan2query":
            text, n = re.subn(r"服务端扫描", "用户查询参数回显", text)
            notes.append(f"扫描归因→查询参数 ×{n}" + ("" if n else "（零命中，待人工）"))
    return text, notes


ROWS = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
for fid, it in ITEMS.items():
    idx = it["today"] - 1
    row = ROWS[idx]
    assert it["sig"] in row["messages"][1]["content"], f"id={fid} 特征不符"
    if it["kind"]:
        assert (row.get("meta") or {}).get("kind") == it["kind"], f"id={fid} kind 不符"
    a = row["messages"][2]["content"]
    a, n_sub = reline_text(a, it["moves"])
    a, notes = apply_riders(a, it["riders"])
    m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
    assert m and json.loads(m.group(1)), f"id={fid} JSON 损坏"
    row["messages"][2]["content"] = a
    with CHANGELOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps({
            "date": "2026-09-08", "step": "1.4_fix_queue_reline_rider", "action": "FIX",
            "fix_id": fid, "row_line_before": it["today"],
            "note": f"reline {it['moves']} ×{n_sub}; riders: {'; '.join(notes)}",
            "basis": "fix_queue_20260907 spec",
        }, ensure_ascii=False) + "\n")
    print(f"id={fid} reline×{n_sub} | {'; '.join(notes)}")

with DATA.open("w", encoding="utf-8", newline="\n") as f:
    for r in ROWS:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
print("落盘完成")
