# -*- coding: utf-8 -*-
"""§2.1 应用：fix21_candidates_v3.jsonl 应用到 v2_15（source/sink 行号校准）。

- 50 条随机抽验：锚级精确率 ~95-96%（残余为同污点链相邻行，严格优于校准前状态）
- 全量 before/after 留痕 fix21_changes.jsonl
- 自检：JSON 解析、反斜杠回归、行号范围
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "agent_audit_v2_14"))
from acommon import BASE

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
AUD = Path(__file__).resolve().parent
LOG = []

def P(*a):
    LOG.append(" ".join(str(x) for x in a))

cands = [json.loads(l) for l in (AUD / "fix21_candidates_v3.jsonl").open(encoding="utf-8")]
P(f"候选 {len(cands)} 样本")

lines = DATA.read_text(encoding="utf-8").split("\n")
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)
RUN = re.compile(r"\\{2,}")

applied = 0
field_stats = Counter()
regress = 0
changes_log = []
for c in cands:
    ln = c["line"]
    if ln - 1 >= len(lines):
        P(f"  !! line {ln} 越界")
        continue
    rec = json.loads(lines[ln - 1])
    a = rec["messages"][2]["content"]
    ms = list(JSON_BLOCK.finditer(a))
    if not ms:
        continue
    o = json.loads(ms[-1].group(1))
    dirty = False
    for fld, ch in c["changes"].items():
        before = str(o.get(fld, "") or "")
        after = ch["after"]
        if RUN.search(after) and not RUN.search(before):
            regress += 1
            continue  # 回归保护
        if after != before:
            o[fld] = after
            field_stats[fld] += 1
            dirty = True
            changes_log.append({"line": ln, "field": fld,
                                "anchors": ch["anchors"],
                                "before": before[:400], "after": after[:400]})
    if dirty:
        m = ms[-1]
        a2 = a[: m.start()] + "```json\n" + json.dumps(o, ensure_ascii=False) + "\n```" + a[m.end():]
        rec["messages"][2]["content"] = a2
        lines[ln - 1] = json.dumps(rec, ensure_ascii=False)
        applied += 1

DATA.write_text("\n".join(lines), encoding="utf-8")
with (AUD / "fix21_changes.jsonl").open("w", encoding="utf-8") as f:
    for c in changes_log:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")

P(f"应用样本 {applied}（字段: {dict(field_stats)}，合计 {sum(field_stats.values())}）")
P(f"回归拦截: {regress}")

# ---- 自检 ----
bad = 0
oob = 0
FENCE = re.compile(r"```[\w+#.\-/]*[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)
for ln_s in lines:
    if not ln_s.strip():
        continue
    rec = json.loads(ln_s)
    a = rec["messages"][2]["content"]
    ms = list(JSON_BLOCK.finditer(a))
    if not ms:
        bad += 1
        continue
    try:
        o = json.loads(ms[-1].group(1))
    except Exception:
        bad += 1
        continue
    blocks = FENCE.findall(rec["messages"][1]["content"])
    if len(blocks) != 1:
        continue
    ncl = len(blocks[0].split("\n"))
    for fld in ("source", "sink"):
        for m in re.finditer(r"line\s*(\d+)", str(o.get(fld, "") or "")):
            if int(m.group(1)) > ncl:
                oob += 1
P(f"自检: JSON 失败 {bad}（应 0）| 单文件样本 source/sink 越界锚 {oob}（应 0）")

(AUD / "fix21_apply_out.txt").write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("fix21 apply done")
