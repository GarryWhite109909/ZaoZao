# -*- coding: utf-8 -*-
"""任务1/3 回填产出盘点。"""
import re
import collections
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = r"d:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\corpus\diffpair_wave1"

for name, path in [("redistill(任务1)", BASE + r"\kits_redistill_truth\result\result.txt"),
                   ("learner续投(任务3)", BASE + r"\kits_learner\result\result.txt")]:
    t = open(path, encoding="utf-8", errors="replace").read()
    ids = re.findall(r"^### (\S+)", t, re.M)
    c = collections.Counter(ids)
    print(f"[{name}] size={len(t)} | ### headers={len(ids)} | unique={len(c)}")
    print("  first:", ids[:4], "| last:", ids[-3:])
    d = {k: v for k, v in c.items() if v > 3}
    print("  headers>3 的 id:", len(d), list(d.items())[:4])
    print("  'disagree' 出现:", t.count("disagree"), "| '存在漏洞=':", t.count("存在漏洞="))
    print()
