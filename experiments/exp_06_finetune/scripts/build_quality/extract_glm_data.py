#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 v5_fixembed 提取 GLM 蒸馏数据（非 deepseek 部分），并按正负拆分。

用户反馈：v5_fixembed（10575）= deepseek v9max（7698）+ GLM 蒸馏（2913）。
GLM 的 CWE 标号更规范，应保留并重建补行号+补丁，而非摒弃。

用法：
  python3 extract_glm_data.py
"""
import json, re, sys, hashlib
from pathlib import Path
PROJECT_ROOT = Path.home() / "文档/code/毕业设计"
sys.path.insert(0, str(PROJECT_ROOT))
from graduation_project.schema import parse_verdict

DATA = PROJECT_ROOT / "experiments/exp_06_finetune/data"

def code_hash(r):
    m = re.search(r"```\w*\n(.*?)```", r["messages"][1]["content"], re.DOTALL)
    return hashlib.md5((m.group(1) if m else r["messages"][1]["content"]).encode()).hexdigest()

def main():
    v5 = [json.loads(l) for l in open(DATA / "final_train_chatml_v5_fixembed.jsonl", encoding="utf-8") if l.strip()]
    v9 = [json.loads(l) for l in open(DATA / "distill_v2/train_chatml_v9max_clean.jsonl", encoding="utf-8") if l.strip()]
    v9h = {code_hash(r) for r in v9}

    glm_pos, glm_neg = [], []
    for r in v5:
        if code_hash(r) in v9h:
            continue  # 跳过 deepseek 部分
        j = parse_verdict(r["messages"][2]["content"])
        if not j:
            continue
        if j.get("has_vulnerability") is True:
            glm_pos.append(r)
        elif j.get("has_vulnerability") is False:
            glm_neg.append(r)

    print(f"GLM 正样本: {len(glm_pos)} | GLM 负样本: {len(glm_neg)}")
    for name, recs in [("glm_positives.jsonl", glm_pos), ("glm_negatives.jsonl", glm_neg)]:
        p = DATA / "quality" / name
        with open(p, "w", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"输出: {p}")

if __name__ == "__main__":
    main()
