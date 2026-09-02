# -*- coding: utf-8 -*-
"""内容指纹映射器:把 result.txt 的全部样本 id 经 pack 内容 → 当前 v2_15 行定位。

原理:pack 里每个样本带编号代码块;剥掉行号前缀、归一化后与 v2_15 各行
的 fence 代码归一指纹匹配。匹配唯一 → 定位成功;多命中 → 取 hv 兼容者/报歧义;
零命中 → 报告(样本可能已被改动)。
输出:result_id_map.json(id → v15 行号 + 置信度),供处置脚本消费。
"""
import json
import re
import sys
import hashlib
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
AUD = Path(__file__).resolve().parent
BASE = AUD.parent
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
PACKS = AUD / "web_review_v3"
FENCE = re.compile(r"```[\w+#.\-/]*[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)
NUMPREFIX = re.compile(r"^\s*\d+\s*\|\s?")
JSON_B = re.compile(r"```json\s*(.*?)```", re.S)

def norm_code(code):
    """归一化代码:去空白/引号差异,小写。"""
    return "".join("".join(code.split()).replace('"', "").replace("'", "").lower())

def strip_num(block):
    return "\n".join(NUMPREFIX.sub("", l) for l in block.split("\n"))

# ---- 1) pack 内:每个 id 的代码指纹 + 教师结论 ----
pack_ids = {}
id_order = []
for fn in sorted(PACKS.glob("pack_*.txt")):
    cur = None
    for line in fn.open(encoding="utf-8"):
        mh = re.match(r"###\s*id=(\d+)", line.strip())
        if mh:
            cur = int(mh.group(1))
            id_order.append(cur)
            continue
        if cur is None:
            continue
    # 上面的逐行解析不足以拿到代码块,改用整文按 ### 切分
for fn in sorted(PACKS.glob("pack_*.txt")):
    txt = fn.read_text(encoding="utf-8")
    # 第 0 步区含全部代码块;按 ### id= 切
    parts = re.split(r"###\s*id=(\d+)[^\n]*\n\[CODE\]\n", txt)
    # parts[0] = 头;之后成对 (id, 内容直到下一个 ###)
    for k in range(1, len(parts) - 1, 2):
        wid = int(parts[k])
        seg = parts[k + 1]
        code = seg.split("████")[0].split("[ANALYSIS]")[0] if "[ANALYSIS]" in seg else seg
        # 该段可能截断在下一个 ### 前——已由 split 处理
        if wid not in pack_ids or len(code) > len(pack_ids[wid]):
            pack_ids[wid] = strip_num(code)

print(f"pack 内识别样本: {len(pack_ids)} (id_order 去重前 {len(id_order)})")

# ---- 2) v2_15 全库代码指纹索引 ----
row_code = {}    # row → norm code
row_hv = {}
for lineno, line in enumerate(open(DATA, encoding="utf-8"), 1):
    if not line.strip():
        continue
    rec = json.loads(line)
    ms = list(FENCE.finditer(rec["messages"][1]["content"]))
    if len(ms) != 1:
        continue
    code = ms[0].group(1)
    row_code[lineno] = norm_code(code)
    jms = JSON_B.findall(rec["messages"][2]["content"])
    try:
        o = json.loads(jms[-1])
        row_hv[lineno] = o.get("has_vulnerability")
    except Exception:
        pass

# ---- 3) 逐 id 定位 ----
result = {}
multi = 0
nomatch = 0
for wid in sorted(pack_ids):
    nc = norm_code(pack_ids[wid])
    hits = [ln for ln, nc2 in row_code.items() if nc2 == nc]
    if len(hits) == 1:
        result[wid] = {"v15_line": hits[0], "confidence": "unique"}
    elif len(hits) > 1:
        multi += 1
        result[wid] = {"v15_line": hits[0], "confidence": f"ambiguous_x{len(hits)}",
                       "alt_lines": hits}
    else:
        nomatch += 1
        result[wid] = {"v15_line": None, "confidence": "no_match"}

ok = sum(1 for v in result.values() if v["confidence"] == "unique")
print(f"唯一命中 {ok} / 歧义 {multi} / 未命中 {nomatch}")

# 未命中的 id:列出,供人工定位
nohit = [wid for wid, v in result.items() if v["confidence"] == "no_match"]
if nohit:
    print("未命中 ids:", nohit[:20])

out = AUD / "result_id_map.json"
out.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
print("-> result_id_map.json")
