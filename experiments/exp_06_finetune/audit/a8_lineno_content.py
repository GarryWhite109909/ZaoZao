# -*- coding: utf-8 -*-
"""行号-内容一致性：JSON 标注的 line N 处，代码内容是否真的匹配描述中的 API/符号"""
import json, re, sys, collections, statistics, random
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SRC = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_alpha06_v2_12.jsonl")
OUT = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\audit\a8_lineno_content_out.txt")

rows = []
with SRC.open("r", encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if line: rows.append((i, json.loads(line)))
R = dict(rows)
def get(msgs, role):
    for m in msgs:
        if m.get("role") == role: return m.get("content", "")
    return ""
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)
CODE_BLOCK = re.compile(r"```[a-zA-Z0-9_+#\-\.]*[ \t]*\r?\n(.*?)```", re.S)

w = OUT.open("w", encoding="utf-8")
def P(*a): print(*a, file=w)

# 从描述文本中抽取"像 API/变量"的符号
STOP = {"line","http","https","the","and","for","with","that","this","from","into",
        "user","input","data","name","value","code","file","path","param","args",
        "true","false","none","null","request","response","error","string","int",
        "函数","参数","变量","用户","输入","行","注入","漏洞","攻击","防御","执行"}
IDENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,}(?:\.[A-Za-z_][A-Za-z0-9_]{1,})*)\b")

def symbols(text):
    out = []
    for m in IDENT.finditer(text):
        s = m.group(1)
        low = s.lower()
        if low in STOP: continue
        if s.startswith("CWE"): continue
        parts = s.split(".")
        # 取最后一段（方法名）和整体
        last = parts[-1]
        if len(last) < 3: continue
        out.append(last)
        if len(parts) > 1 and len(parts[0]) >= 3:
            out.append(parts[0])
    return list(dict.fromkeys(out))

checked = collections.Counter()
hit1 = collections.Counter()   # 精确行命中
hit3 = collections.Counter()   # ±1 行命中
hit5 = collections.Counter()   # ±2 行命中
samples_bad = collections.defaultdict(list)
samples_good = collections.defaultdict(list)
per_sample_rate = []

for i, r in rows:
    msgs = r["messages"]
    u, a = get(msgs,"user"), get(msgs,"assistant")
    blocks = list(JSON_BLOCK.finditer(a))
    if not blocks: continue
    try: o = json.loads(blocks[-1].group(1))
    except Exception: continue
    if o.get("has_vulnerability") is not True: continue
    cbs = CODE_BLOCK.findall(u)
    if not cbs: continue
    cbtxt = max(cbs, key=len)
    cbtxt = cbtxt[:-1] if cbtxt.endswith("\n") else cbtxt
    lines = cbtxt.split("\n")
    N = len(lines)

    for fld in ("source", "sink", "fix_suggestion"):
        v = str(o.get(fld, ""))
        m = re.search(r"line\s*(\d+)\s*[:：]\s*(.*)$", v)
        if not m: continue
        ln = int(m.group(1)); desc = m.group(2)
        if ln < 1 or ln > N: continue
        syms = symbols(desc)
        if not syms: continue
        checked[fld] += 1
        cur = lines[ln-1]
        win3 = "\n".join(lines[max(0,ln-2):ln+1])
        win5 = "\n".join(lines[max(0,ln-3):ln+2])
        ok1 = any(s in cur for s in syms)
        ok3 = any(s in win3 for s in syms)
        ok5 = any(s in win5 for s in syms)
        if ok1: hit1[fld] += 1
        if ok3: hit3[fld] += 1
        if ok5: hit5[fld] += 1
        if not ok5:
            if len(samples_bad[fld]) < 18:
                samples_bad[fld].append((i, ln, N, desc[:70], cur.strip()[:70]))
        else:
            if len(samples_good[fld]) < 5:
                samples_good[fld].append((i, ln, desc[:60], cur.strip()[:60]))

P("=" * 78); P("行号-内容一致性校验（漏洞样本，JSON 中 line N: 描述）"); P("=" * 78)
P("  命中率定义：描述里的 API/变量名是否出现在标称行（±0 / ±1 / ±2 行窗口）")
for fld in ("source", "sink", "fix_suggestion"):
    c = checked[fld]
    if not c: continue
    P(f"\n  [{fld}] 可校验 {c} 处")
    P(f"    精确行命中      : {hit1[fld]:5d} = {hit1[fld]/c*100:5.1f}%")
    P(f"    ±1 行窗口命中   : {hit3[fld]:5d} = {hit3[fld]/c*100:5.1f}%")
    P(f"    ±2 行窗口命中   : {hit5[fld]:5d} = {hit5[fld]/c*100:5.1f}%")
    P(f"    完全对不上(±2外): {c-hit5[fld]:5d} = {(c-hit5[fld])/c*100:5.1f}%")

P("\n" + "-" * 78)
P("对不上的样例（field / line号 / 代码总行 / 描述 / 该行实际代码）")
P("-" * 78)
for fld in ("source", "sink", "fix_suggestion"):
    P(f"\n  === {fld} ===")
    for i, ln, N, desc, cur in samples_bad[fld]:
        P(f"    line {i} @{ln}/{N}: 描述={desc!r}")
        P(f"                        实际={cur!r}")

P("\n" + "-" * 78)
P("命中样例（确认校验逻辑没写反）")
P("-" * 78)
for fld in ("source", "sink", "fix_suggestion"):
    P(f"\n  === {fld} ===")
    for i, ln, desc, cur in samples_good[fld]:
        P(f"    line {i} @{ln}: 描述={desc!r}")
        P(f"                   实际={cur!r}")

w.close()
print("done")
