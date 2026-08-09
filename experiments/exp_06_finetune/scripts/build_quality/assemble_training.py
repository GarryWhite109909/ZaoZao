#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""组装最终高质量训练集：deepseek 重建正样本 + GLM 重建正样本 + 清洗负样本。

多源合并：
  正样本：positives_rebuilt.jsonl (deepseek 重建) + glm_positives_rebuilt.jsonl (GLM 重建)
  负样本：clean_base.jsonl (deepseek 清洗) + glm_negatives.jsonl (GLM 清洗)

按代码内容哈希去重（保留先出现的）。

用法：
  python3 assemble_training.py \
      --pos data/quality/positives_rebuilt.jsonl,data/quality/glm_positives_rebuilt.jsonl \
      --neg data/quality/clean_base.jsonl,data/quality/glm_negatives.jsonl \
      --out data/quality/final_train_chatml_quality.jsonl
"""
import argparse, json, re, sys, hashlib
from pathlib import Path
sys.path.insert(0, str(Path.home() / "文档/code/毕业设计"))
from graduation_project.schema import parse_verdict

def code_hash(r):
    m = re.search(r"```\w*\n(.*?)```", r["messages"][1]["content"], re.DOTALL)
    return hashlib.md5((m.group(1) if m else r["messages"][1]["content"]).encode()).hexdigest()

def load_positive(files):
    out, seen = [], set()
    for f in files:
        for r in [json.loads(l) for l in open(f, encoding="utf-8") if l.strip()]:
            h = code_hash(r)
            if h in seen:
                continue
            seen.add(h)
            out.append(r)
    return out

def load_negative(files):
    out, seen = [], set()
    for f in files:
        for r in [json.loads(l) for l in open(f, encoding="utf-8") if l.strip()]:
            if parse_verdict(r["messages"][2]["content"]).get("has_vulnerability") is not False:
                continue
            h = code_hash(r)
            if h in seen:
                continue
            seen.add(h)
            out.append(r)
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pos", default="data/quality/positives_rebuilt.jsonl,data/quality/glm_positives_rebuilt.jsonl")
    ap.add_argument("--neg", default="data/quality/clean_base.jsonl,data/quality/glm_negatives.jsonl")
    ap.add_argument("--out", default="data/quality/final_train_chatml_quality.jsonl")
    args = ap.parse_args()

    pos = load_positive(args.pos.split(","))
    neg = load_negative(args.neg.split(","))
    print(f"正样本 {len(pos)} (deepseek+GLM) | 负样本 {len(neg)} (deepseek+GLM)")

    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for r in pos + neg:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"输出: {out} ({len(pos)+len(neg)} 条, 正:负=1:{len(neg)/max(len(pos),1):.2f})")

if __name__ == "__main__":
    main()
