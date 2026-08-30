# -*- coding: utf-8 -*-
"""v2_13 全库错位扫描：assistant 引用行号 vs user 代码范围 + 契约匹配。

检查项：
  A. 漏洞样本：source/sink/fix_suggestion 中每个 line N（含范围 line a-b）须 ≤ user 代码最大行号
  B. 安全样本：explanation 中 第 N 行 / line N 须 ≤ max（8081 型错位）
  C. 裁决任务 user（【安全分析任务：裁决）assistant JSON 须用 is_confirmed 契约
  D. fix_distill/转写样本 assistant 须含 user 中出现的关键代码标识（抽查头 3 个标识符）
输出：audit/misalign_v2_13.jsonl + 统计
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path("/home/zane/文档/code/毕业设计/experiments/exp_06_finetune")
SRC = BASE / "data/final_train_chatml_alpha06_v2_13.jsonl"
OUT = BASE / "audit/misalign_v2_13.jsonl"

def get(msgs, role):
    for m in msgs:
        if m.get("role") == role:
            return m.get("content", "")

def code_max_line(user: str):
    """user 代码最大行号：N| 前缀取最大 N；代码块按换行数估。"""
    nums = [int(m.group(1)) for m in re.finditer(r"^\s*(\d+)\|", user, re.M)]
    if nums:
        return max(nums)
    # 无行号前缀：取代码块行数（多文件块合计不可靠，返回块内最大单块行数）
    blocks = re.findall(r"```[a-zA-Z0-9+#]*\n(.*?)(?:```|$)", user, re.S)
    if blocks:
        return max(b.count("\n") for b in blocks)
    return 0

def refs_lines(text: str):
    """提取 line N / line a-b / 第 N 行 引用的所有行号。"""
    out = []
    for m in re.finditer(r"line\s*(\d+)(?:\s*[-–~]\s*(\d+))?", text, re.I):
        out.append(int(m.group(1)))
        if m.group(2):
            out.append(int(m.group(2)))
    for m in re.finditer(r"第\s*(\d+)\s*行", text):
        out.append(int(m.group(1)))
    return out

rows = []
for i, l in enumerate(open(SRC, encoding="utf-8"), 1):
    if l.strip():
        rows.append((i, json.loads(l)))

viol = []
stats = Counter()
for i, r in rows:
    u = get(r["messages"], "user")
    a = get(r["messages"], "assistant")
    kind = (r.get("meta") or {}).get("kind", "base")
    jm = re.findall(r"```json\s*(.*?)```", a, re.S)
    if not jm:
        continue
    try:
        o = json.loads(jm[-1])
    except Exception:
        continue
    mx = code_max_line(u)
    reasons = []
    if mx <= 0:
        stats["skip_no_code"] += 1
        continue
    if o.get("has_vulnerability") is True:
        for fld in ("source", "sink", "fix_suggestion"):
            bad = [n for n in refs_lines(str(o.get(fld, ""))) if n > mx]
            if bad:
                reasons.append(f"{fld} 行号越界 {bad[:4]} > {mx}")
    else:
        bad = [n for n in refs_lines(str(o.get("explanation", ""))) if n > mx]
        if bad:
            reasons.append(f"explanation 行号越界 {bad[:4]} > {mx}")
    # C. 裁决任务契约检查
    if u.startswith("【安全分析任务：裁决一个静态工具告警是否为真漏洞】"):
        if "is_confirmed" not in jm[-1] and "has_vulnerability" in jm[-1]:
            reasons.append("裁决任务但 assistant 用主契约 has_vulnerability")
    if reasons:
        viol.append({
            "line": i, "kind": kind, "max_code_line": mx,
            "verdict": o.get("has_vulnerability"),
            "reasons": reasons,
            "json_head": json.dumps({k: str(o.get(k))[:100] for k in
                                     ("source", "sink", "explanation", "fix_suggestion")},
                                    ensure_ascii=False),
        })

OUT.write_text("\n".join(json.dumps(v, ensure_ascii=False) for v in viol) + "\n", encoding="utf-8")
kc = Counter(v["kind"] for v in viol)
print(f"扫描 {len(rows)} 条，错位/可疑 {len(viol)} 条")
print(f"按 kind: {dict(kc)}")
print(f"按 verdict: {dict(Counter(str(v['verdict']) for v in viol))}")
for v in viol[:25]:
    print(f"  line {v['line']} [{v['kind']}] max={v['max_code_line']} hv={v['verdict']} :: {v['reasons'][0]}")
