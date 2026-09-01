# -*- coding: utf-8 -*-
"""1.3 ops 统一应用到 data/final_train_chatml_alpha06_v2_15.jsonl。

字段管线（同一 (id, field)）：
  1) set_fields 存在 → 基文本 = 新值（忽略该字段的 reline——reline 是对原文算的）
  2) 否则基文本 = 原值，依序应用 pass1/auto/b* 的 reline moves（两阶段替换防碰撞）
  3) strip_tail（正则去尾）
  4) append_field（句号衔接追加）
写出：字段级 before/after 变更日志 fix13_changes.jsonl + 汇总日志 + 自检。
"""
import json
import re
import sys
import glob as g
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "agent_audit_v2_14"))
from acommon import BASE, OUT

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
AUD = Path(__file__).resolve().parent
LOG = []

def P(*a):
    LOG.append(" ".join(str(x) for x in a))

def load_ops_file(f):
    txt = open(f, encoding="utf-8").read().strip()
    if not txt:
        return []
    return json.loads(txt) if txt.startswith("[") else [json.loads(l) for l in txt.split("\n") if l.strip()]

# ---- 收集 ops ----
op_files = [str(OUT / "fix13_ops_pass1.jsonl"), str(OUT / "fix13_ops_pass2.jsonl"),
            str(OUT / "fix13_ops_pass3.jsonl")]
op_files += sorted(g.glob(str(OUT / "fix13_ops_pass3_b*.json")))
op_files.append(str(OUT / "fix13_ops_pass3_auto_evidence.jsonl"))
all_ops = []
for f in op_files:
    all_ops.extend(load_ops_file(f))
P(f"载入 ops {len(all_ops)} 条（来自 {len(op_files)} 个文件）")

FIELD_SET = {}    # (id, field) -> value      (set_fields / set_vt)
FIELD_REL = {}    # (id, field) -> [moves]   (reline, 按文件顺序)
FIELD_TAIL = {}   # (id, field) -> pattern
FIELD_APPEND = {} # (id, field) -> [text]
DEDOUPLE_IDS = set()  # N1 花括号翻倍伪影修复（user 代码块）
touched_ids = set()
for o in all_ops:
    rid = o["id"]
    touched_ids.add(rid)
    op = o["op"]
    if op == "set_vt":
        FIELD_SET[(rid, "vulnerability_type")] = o["value"]
    elif op == "set_fields":
        for fld, val in o["fields"].items():
            FIELD_SET[(rid, fld)] = val
    elif op == "reline":
        FIELD_REL.setdefault((rid, o["field"]), []).extend(o["moves"])
    elif op == "strip_tail":
        FIELD_TAIL[(rid, o["field"])] = o["pattern"]
    elif op == "append_field":
        FIELD_APPEND.setdefault((rid, o["field"]), []).append(o["text"])
    elif op == "dedouble_braces":
        DEDOUPLE_IDS.add(rid)
    elif op in ("nojson_op", "needs_human", "manual"):
        pass
    else:
        P(f"  !! 未知 op {op} id={rid}")

P(f"涉及样本 {len(touched_ids)}；set {len(FIELD_SET)} 字段 / reline {len(FIELD_REL)} 字段 / "
  f"strip {len(FIELD_TAIL)} / append {len(FIELD_APPEND)}")

# ---- 工作台提供 id -> v15 行号 ----
wb = [json.loads(l) for l in (OUT / "fix13_workbench.jsonl").open(encoding="utf-8")]
id2line = {it["id"]: it["v15_line"] for it in wb}
code_len = {it["id"]: len(it["code_lines"]) for it in wb}

# ---- 读 v2_15 ----
lines = DATA.read_text(encoding="utf-8").split("\n")
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)

# dedouble 样本的 v15 行号（6716 不在 FIX 工作台内，按删除集推算）
del_ids = set()
for l in (OUT / "manifest_DELETE.jsonl").open(encoding="utf-8"):
    if l.strip():
        del_ids.add(json.loads(l)["id"])
del_ids |= {8288, 8968}
extra_line = {}
for rid in DEDOUPLE_IDS:
    if rid not in id2line:
        extra_line[rid] = rid - sum(1 for d in del_ids if d < rid)
        id2line[rid] = extra_line[rid]

for rid in sorted(DEDOUPLE_IDS):
    ln = id2line.get(rid)
    if ln is None or ln - 1 >= len(lines):
        P(f"  !! dedouble id={rid} 无 v15 行映射，跳过")
        continue
    rec = json.loads(lines[ln - 1])
    u = rec["messages"][1]["content"]
    fence = re.compile(r"(```[\w+#.\-/]*[ \t]*\r?\n)(.*?)(```|\Z)", re.S)
    def _dd(m):
        return m.group(1) + m.group(2).replace("{{", "{").replace("}}", "}") + m.group(3)
    u2 = fence.sub(_dd, u)
    if u2 != u:
        rec["messages"][1]["content"] = u2
        lines[ln - 1] = json.dumps(rec, ensure_ascii=False)
        P(f"  dedouble_braces id={rid}: user 代码块花括号去翻倍")
    else:
        P(f"  dedouble_braces id={rid}: 无变化（可能已修复）")

def two_phase(text, moves):
    """行号 token 替换（两阶段防碰撞；区间形式整段替换）。"""
    ph = text
    for i, (old, new) in enumerate(moves):
        for pat, fmt in ((rf"line\s*{old}\s*-\s*\d+", f"line {new}"),
                         (rf"第\s*{old}\s*[-~～]\s*\d+\s*行", f"第{new}行"),
                         (rf"line\s*{old}\b", f"line {new}"),
                         (rf"第\s*{old}\s*行", f"第{new}行"),
                         (rf"(?<![A-Za-z0-9_])L{old}\b", f"L{new}")):
            ph = re.sub(pat, f"__RLP{i}__", ph)
    for i, (old, new) in enumerate(moves):
        ph = ph.replace(f"__RLP{i}__", str(new))
    return ph

changes = []
field_stats = Counter()
for rid in sorted(touched_ids):
    ln = id2line.get(rid)
    if ln is None or ln - 1 >= len(lines):
        P(f"  !! id={rid} 无 v15 行映射，跳过")
        continue
    rec = json.loads(lines[ln - 1])
    a = rec["messages"][2]["content"]
    ms = list(JSON_BLOCK.finditer(a))
    if not ms:
        P(f"  !! id={rid} 无 JSON 块，跳过")
        continue
    o = json.loads(ms[-1].group(1))
    orig_o = dict(o)
    touched_fields = set()
    for (rid2, fld) in list(FIELD_SET) + list(FIELD_REL) + list(FIELD_TAIL) + list(FIELD_APPEND):
        if rid2 == rid:
            touched_fields.add(fld)
    for fld in sorted(touched_fields):
        before = str(o.get(fld, "") or "")
        if (rid, fld) in FIELD_SET:
            base = FIELD_SET[(rid, fld)]
        else:
            base = before
        # reline 仅在基文本为原值时应用（set_fields 文本已含正确行号）
        if (rid, fld) in FIELD_REL and (rid, fld) not in FIELD_SET:
            base = two_phase(base, FIELD_REL[(rid, fld)])
        if (rid, fld) in FIELD_TAIL:
            base = re.sub(FIELD_TAIL[(rid, fld)], "", base).rstrip()
        if (rid, fld) in FIELD_APPEND:
            for tx in FIELD_APPEND[(rid, fld)]:
                if base and not base.endswith("。"):
                    base += "。"
                base += tx
        if base != before:
            o[fld] = base
            field_stats[fld] += 1
            changes.append({"id": rid, "field": fld,
                            "before": str(before)[:600], "after": str(base)[:600]})
    new_block = json.dumps(o, ensure_ascii=False)
    if json.dumps(orig_o, ensure_ascii=False) != new_block:
        m = ms[-1]
        a2 = a[: m.start()] + "```json\n" + new_block + "\n```" + a[m.end():]
        rec["messages"][2]["content"] = a2
        lines[ln - 1] = json.dumps(rec, ensure_ascii=False)

DATA.write_text("\n".join(lines), encoding="utf-8")
with (AUD / "fix13_changes.jsonl").open("w", encoding="utf-8") as f:
    for c in changes:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")

P("")
P("== 应用统计 ==")
P(f"  变更字段: {dict(field_stats)}  合计 {sum(field_stats.values())}")
P(f"  变更样本: {len({c['id'] for c in changes})}")

# ---- 自检 ----
P("")
P("== 自检 ==")
bad = 0
empty_fields = 0
new_pollution = 0
s4_pat = re.compile(r"\\{2,}")
for i, ln2 in enumerate(lines, 1):
    if not ln2.strip():
        continue
    rec = json.loads(ln2)
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
    for fld in ("fix_suggestion", "explanation", "source", "sink"):
        t = str(o.get(fld, "") or "")
        if not t:
            continue
        if not t.strip():
            empty_fields += 1
        if s4_pat.search(t) and "repair" not in t:
            new_pollution += 1
P(f"  JSON 解析失败: {bad}（应为 0）")
P(f"  空字段: {empty_fields}（应为 0）")
P(f"  双反斜杠污染字段: {new_pollution}（应为 0；合法 \\ 转义不计）")

(AUD / "fix13_apply_out.txt").write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("apply done ->", DATA.name)
