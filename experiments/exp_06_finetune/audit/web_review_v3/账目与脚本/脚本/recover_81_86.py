# -*- coding: utf-8 -*-
"""恢复 81-240/result.txt 的编码事故（cp936→GBK 链）并容错解析。"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
SRC = Path(__file__).resolve().parents[2] / "81-240/result.txt"
DST = SRC.parent / "result_recovered.jsonl"

# 恢复: 文件文本 --cp936 编码--> 字节 --GBK 解码--> 原文
t = SRC.read_text(encoding="utf-8")
fixed = t.encode("cp936").decode("gbk")
print('质量: 含"教师"', "教师" in fixed, '| 含"漏洞"', "漏洞" in fixed,
      "| FFFD", fixed.count("\ufffd"))
DST.write_text(fixed, encoding="utf-8")

# 容错 JSON: 修复非法反斜杠转义（BSL = 单个反斜杠字符，避开 heredoc 转义问题）
BSL = chr(92)
VALID = set('"\\/bfnrtu')
fix_pat = re.compile(BSL + BSL + "(?!" + "[" + BSL + BSL + "/bfnrtu" + "])")

def toljson(s):
    for cand in (s, fix_pat.sub(BSL + BSL, s),
                 re.sub(r",(\s*[}\]])", r"\1", fix_pat.sub(BSL + BSL, s))):
        try:
            return json.loads(cand, strict=False)
        except Exception:
            pass
    raise ValueError(s[:80])

recs, sums, fails = [], [], []
BSL = chr(92)
depth = 0; in_str = False; esc = False; start = None
for i, ch in enumerate(fixed):
    if in_str:
        if esc: esc = False
        elif ch == BSL: esc = True
        elif ch == chr(34): in_str = False
        continue
    if ch == chr(34): in_str = True; continue
    if ch == chr(123):
        if depth == 0: start = i
        depth += 1
    elif ch == chr(125):
        depth -= 1
        if depth == 0 and start is not None:
            obj_txt = fixed[start:i+1]
            start = None
            try:
                d = toljson(obj_txt)
            except Exception as e:
                fails.append((str(e)[:60], obj_txt[:60])); continue
            if isinstance(d, dict) and d.get("id") is not None and "verdict" in d: recs.append(d)
            elif isinstance(d, dict) and "batch" in d: sums.append(d)
            else: fails.append(("orphan", obj_txt[:60]))
print(f"记录 {len(recs)}, 汇总 {len(sums)}, 解析失败 {len(fails)}")
for f in fails:
    print("  失败:", f)
out = SRC.parent / "parsed.jsonl"
with out.open("w", encoding="utf-8") as f:
    for r in recs:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
    for s in sums:
        f.write(json.dumps({"batch_summary": s}, ensure_ascii=False) + "\n")
print("结构化 ->", out.name)
for r in recs:
    et = [f"{e['type']}({e['severity'][0]})" for e in r.get("errors", [])]
    ind = r.get("independent", {})
    vc = len(r.get("verdict_conditionals", []) or [])
    ur = r.get("unsure_reason") or ""
    print(f"id={r['id']} {r['verdict']}/T{r.get('tier')} {ind.get('cwe')} "
          f"conf={ind.get('confidence')} cond={vc} {ur} | {' '.join(et[:5])}{'…' if len(et) > 5 else ''}")
for s in sums:
    print("汇总 batch=", s.get("batch"), s.get("counts"))
