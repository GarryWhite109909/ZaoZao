# -*- coding: utf-8 -*-
"""容错解析 result.txt: 修复字符串内部未转义引号, 输出全量 verdict 清单。

上一批 apply_web_review_delete.py 用 json.loads 解析 result.txt, 68 行因
evidence 内含未转义 ASCII 引号而解析失败被静默跳过 —— 本次全量容错重析,
核对 DELETE 漏删与 FIX 实际规模, 结果落盘 _result_tolparse_20260902.json。
"""
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[2]
RESULT = BASE / "audit/web_review/result.txt"
MAP = BASE / "audit/result_id_map.json"
OUT = BASE / "audit/web_review/_result_tolparse_20260902.json"


def _fix_bad_escapes(s):
    """裸反斜杠后跟非法转义字符(\d \e \. 等) -> 双写。"""
    return re.sub(r'\\(?!["\\/bfnrtu])', r"\\\\", s)


def tolparse(line):
    """json.loads 失败时, 逐字符扫描: 字符串内部的裸引号转义之。"""
    try:
        return json.loads(line)
    except Exception:
        pass
    try:
        return json.loads(_fix_bad_escapes(line))
    except Exception:
        pass
    out, i, n, instr = [], 0, len(line), False
    while i < n:
        c = line[i]
        if not instr:
            if c == '"':
                instr = True
            out.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < n and line[i + 1] in '"\\/bfnrtu':
            out.append(line[i:i + 2])  # 合法转义序列原样保留
            i += 2
            continue
        if c == '"':
            j = i + 1
            while j < n and line[j] in " \t":
                j += 1
            nxt = line[j] if j < n else ""
            if nxt in ",}]:":  # 边界引号
                instr = False
                out.append(c)
            else:  # 字符串内部引号 -> 转义
                out.append('\\"')
            i += 1
            continue
        out.append(c)
        i += 1
    try:
        return json.loads("".join(out))
    except Exception:
        return None


recs, still_fail = {}, 0
for l in RESULT.open(encoding="utf-8"):
    l = l.strip()
    if not l.startswith("{"):
        continue
    o = tolparse(l)
    if o is None:
        still_fail += 1
        print("仍失败:", l[:100])
        continue
    if o.get("id") is not None:
        recs[o["id"]] = o

print("容错解析成功:", len(recs), " 仍失败:", still_fail)
print(Counter(v["verdict"] for v in recs.values()))

mp = json.loads(MAP.read_text(encoding="utf-8"))
print("map 条目:", len(mp))
k0 = next(iter(mp))
print("map 样例:", k0, mp[k0])
nomatch = sorted(i for i in recs if str(i) not in mp)
print("result.txt id 不在 map 中的:", len(nomatch))
d = defaultdict(list)
for i in nomatch:
    d[recs[i]["verdict"]].append(i)
print("no_match 按 verdict:", dict(d))

OUT.write_text(json.dumps({str(k): v for k, v in recs.items()},
                          ensure_ascii=False, indent=1), encoding="utf-8")
print("已写入", OUT.name)
