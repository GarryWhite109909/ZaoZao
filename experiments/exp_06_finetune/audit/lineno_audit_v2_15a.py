# -*- coding: utf-8 -*-
"""P1-C 数据侧行号入库审计（v2_15_a 批次，audit-only 不改数据）。

对 v2_14 全库每条漏洞样本的 source / sink / fix_suggestion / explanation 跑
graduation_project.line_normalizer.normalize_line_numbers（推理端同源工具），
输出 ≠ 原文（锚点行号被纠正）→ 记入 lineno_review_v2_15a.jsonl 人工复核清单。

依据 v2_15 文档 P1-C：行号校准入库审计；多文件样本跳过（归一器按单文件定位）。
"""
import json
import re
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from graduation_project.line_normalizer import normalize_line_numbers

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
SRC = BASE / "data/final_train_chatml_alpha06_v2_14.jsonl"
OUT_REVIEW = Path(__file__).with_name("lineno_review_v2_15a.jsonl")

JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)
CODE_BLOCK = re.compile(r"```[\w+#-]*\n(.*?)```", re.S)

stats = {"checked": 0, "skipped_multi": 0, "skipped_nojson": 0, "dirty_samples": 0,
         "dirty_fields": 0}
review = []
with SRC.open(encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        r = json.loads(line)
        blocks = CODE_BLOCK.findall(r["messages"][1]["content"])
        if len(blocks) != 1:
            stats["skipped_multi"] += 1
            continue
        code = blocks[0].rstrip()
        m = JSON_BLOCK.findall(r["messages"][2]["content"])
        if not m:
            stats["skipped_nojson"] += 1
            continue
        try:
            o = json.loads(m[-1])
        except Exception:
            stats["skipped_nojson"] += 1
            continue
        if o.get("has_vulnerability") is not True:
            continue
        stats["checked"] += 1
        dirty = {}
        for fld in ("source", "sink", "fix_suggestion", "explanation"):
            txt = str(o.get(fld, ""))
            if "line " not in txt and "line\u00a0" not in txt:
                continue
            try:
                fixed, anchors = normalize_line_numbers(txt, code, return_anchors=True)
            except Exception:
                continue
            real = [(a, b) for a, b in anchors if a != b]
            if real and fixed != txt:
                dirty[fld] = real
        if dirty:
            stats["dirty_samples"] += 1
            stats["dirty_fields"] += len(dirty)
            review.append({"orig_line": i, "fields": dirty,
                           "vt": str(o.get("vulnerability_type", ""))[:60]})

with OUT_REVIEW.open("w", encoding="utf-8") as f:
    for item in review:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")
print(json.dumps(stats, ensure_ascii=False))
print("fields 分布:", {k: sum(1 for x in review if k in x["fields"])
                     for k in ("source", "sink", "fix_suggestion", "explanation")})
print("->", OUT_REVIEW.name)
