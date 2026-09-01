# -*- coding: utf-8 -*-
"""§2.1 行号全量校准 —— 第一阶段：对 v2_15 全库（单文件样本）跑 line_normalizer。

- 4 个 JSON 字段（source/sink/fix_suggestion/explanation）逐字段校准
- 产出候选变更 fix21_candidates.jsonl（供 50 条随机抽验，≥95% 精确率后才应用）
- 顺带产出 N4 幻影锚定候选清单（锚点越界的样本，转 1.4 重蒸馏队列）
- 多文件样本跳过（锚定语义歧义，2.1 专项另行处理）
本脚本只生成候选，不改数据。
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "agent_audit_v2_14"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from acommon import BASE, OUT
from graduation_project.line_normalizer import normalize_line_numbers

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
OUT_CAND = AUD_CAND = Path(__file__).resolve().parent / "fix21_candidates.jsonl"
OUT_PHANTOM = Path(__file__).resolve().parent / "fix21_phantom_candidates.jsonl"

FENCE = re.compile(r"```[\w+#.\-/]*[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)
FILE_SEP = re.compile(
    r"^(?:={3,}\s*(?:文件|File)|#{1,3}\s*(?:文件|File)\s*[:# ]|//\s*====\s*File|【文件\s*\d|File\s*\d+\s*[:：]|###\s*文件\s*[:：])",
    re.M)
FIELDS = ("source", "sink", "fix_suggestion", "explanation")

n_total = n_single = n_multi = 0
cand = []
phantom = []
field_stats = Counter()
id_line = 0

with DATA.open(encoding="utf-8") as f:
    for lineno, line in enumerate(f, 1):
        if not line.strip():
            continue
        n_total += 1
        rec = json.loads(line)
        u = rec["messages"][1]["content"]
        a = rec["messages"][2]["content"]
        blocks = FENCE.findall(u)
        if len(blocks) >= 2 or FILE_SEP.search(u):
            n_multi += 1
            continue
        if not blocks:
            continue
        n_single += 1
        code = blocks[0]
        code_lines = code.splitlines()
        jb = re.findall(r"```json\s*(.*?)```", a, re.S)
        if not jb:
            continue
        try:
            o = json.loads(jb[-1])
        except Exception:
            continue
        # N4 幻影锚定候选：source/sink/fix 的锚点越界
        oob = 0
        for fld in ("source", "sink", "fix_suggestion"):
            t = str(o.get(fld, "") or "")
            for m in re.finditer(r"line\s*(\d+)", t):
                if int(m.group(1)) > len(code_lines):
                    oob += 1
        if oob >= 3:
            phantom.append({"line": lineno, "oob_refs": oob, "code_lines": len(code_lines),
                            "vt": str(o.get("vulnerability_type", ""))[:50]})
        changed = {}
        for fld in FIELDS:
            t = str(o.get(fld, "") or "")
            if not t:
                continue
            new_t, anchors = normalize_line_numbers(t, code, return_anchors=True)
            if anchors and new_t != t:
                changed[fld] = {"before": t, "after": new_t, "anchors": anchors}
                field_stats[fld] += 1
        if changed:
            cand.append({"line": lineno, "changes": changed})

with OUT_CAND.open("w", encoding="utf-8") as f:
    for c in cand:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")
with OUT_PHANTOM.open("w", encoding="utf-8") as f:
    for p in phantom:
        f.write(json.dumps(p, ensure_ascii=False) + "\n")

print(f"全库 {n_total} | 单文件 {n_single} | 多文件跳过 {n_multi}")
print(f"候选变更样本: {len(cand)}（字段级: {dict(field_stats)}）")
print(f"幻影锚定候选(oob>=3): {len(phantom)} -> {OUT_PHANTOM.name}")
