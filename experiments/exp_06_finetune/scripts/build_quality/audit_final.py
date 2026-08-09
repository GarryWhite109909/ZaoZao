import json, re, sys
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path.home() / "文档/code/毕业设计"))
from graduation_project.schema import parse_verdict

recs = [json.loads(l) for l in open("data/quality/final_train_chatml_quality.jsonl", encoding="utf-8") if l.strip()]
pos = [r for r in recs if parse_verdict(r["messages"][2]["content"]).get("has_vulnerability") is True]
neg = [r for r in recs if parse_verdict(r["messages"][2]["content"]).get("has_vulnerability") is False]
print(f"最终训练集: 总 {len(recs)} | 正 {len(pos)} | 负 {len(neg)} | 正:负=1:{len(neg)/max(len(pos),1):.2f}")

src = sink = fix = 0
cwes = Counter(); langs = Counter()
for r in pos:
    j = parse_verdict(r["messages"][2]["content"])
    if re.search(r"line\s*\d+", str(j.get("source", "")), re.I): src += 1
    if re.search(r"line\s*\d+", str(j.get("sink", "")), re.I): sink += 1
    if re.search(r"```[a-zA-Z0-9_+\-]*\n", str(j.get("fix_suggestion", ""))): fix += 1
    m = re.match(r"(CWE-\d+)", str(j.get("vulnerability_type", "")))
    cwes[m.group(1) if m else "?"] += 1
    lm = re.search(r"```(\w+)", r["messages"][1]["content"])
    l = lm.group(1) if lm else "?"
    if not lm:
        lm2 = re.search(r"语言[：:]\s*(\w+)", r["messages"][1]["content"])
        l = lm2.group(1) if lm2 else "?"
    langs[l] += 1
print(f"正样本定位: source含行号 {src}/{len(pos)} ({src/len(pos)*100:.1f}%) | sink含行号 {sink}/{len(pos)} ({sink/len(pos)*100:.1f}%)")
print(f"正样本补丁: fix_suggestion含可运行补丁 {fix}/{len(pos)} ({fix/len(pos)*100:.1f}%)")
print(f"CWE 种类: {len(cwes)}")
print(f"语言分布: {dict(langs.most_common())}")
print(f"CWE top12: {cwes.most_common(12)}")
