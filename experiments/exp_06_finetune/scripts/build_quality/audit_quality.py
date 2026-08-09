#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""审计：重建后正样本质量 vs 重建前基础数据。"""
import sys, re, json
from collections import Counter
from pathlib import Path
PROJECT_ROOT = Path.home() / "文档/code/毕业设计"
sys.path.insert(0, str(PROJECT_ROOT))
from graduation_project.schema import parse_verdict

BASE = PROJECT_ROOT / "experiments/exp_06_finetune/data/quality/clean_base.jsonl"
REBUILT = PROJECT_ROOT / "experiments/exp_06_finetune/data/quality/positives_rebuilt.jsonl"

def load(p):
    return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]

def audit(recs, label):
    n = len(recs); src=sink=fix=parse=0
    cwes = Counter(); langs = Counter()
    for r in recs:
        j = parse_verdict(r["messages"][2]["content"])
        if not j or j.get("has_vulnerability") is not True:
            continue
        parse += 1
        if re.search(r"line\s*\d+", str(j.get("source","")), re.I): src += 1
        if re.search(r"line\s*\d+", str(j.get("sink","")), re.I): sink += 1
        if re.search(r"```[a-zA-Z0-9_+\-]*\n", str(j.get("fix_suggestion",""))): fix += 1
        cwes[str(j.get("vulnerability_type","?"))[:20]] += 1
        m = re.search(r"```(\w+)", r["messages"][1]["content"])
        langs[m.group(1) if m else "?"] += 1
    print(f"\n===== {label} ({n} 条) =====")
    print(f"  parse_verdict 成功      : {parse}/{n}")
    print(f"  source 含行号(精确定位) : {src}/{n} ({src/n*100:.1f}%)")
    print(f"  sink  含行号(精确定位) : {sink}/{n} ({sink/n*100:.1f}%)")
    print(f"  fix_suggestion 含可运行补丁: {fix}/{n} ({fix/n*100:.1f}%)")
    print(f"  语言分布: {dict(langs)}")
    print(f"  CWE 种类数: {len(cwes)}")
    return cwes

# 重建前：基础数据里所有正样本
base = load(BASE)
base_pos = [r for r in base if parse_verdict(r["messages"][2]["content"]).get("has_vulnerability") is True]
base_cwes = audit(base_pos, "重建前 正样本 (clean_base)")
print(f"  重建前 CWE top8: {base_cwes.most_common(8)}")

# 重建后
rebuilt = load(REBUILT)
rebuilt_cwes = audit(rebuilt, "重建后 正样本 (positives_rebuilt)")
print(f"  重建后 CWE top8: {rebuilt_cwes.most_common(8)}")
