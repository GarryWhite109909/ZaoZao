# -*- coding: utf-8 -*-
"""四个投喂目录的非围栏行泄漏终检。"""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
WAVE = Path(__file__).resolve().parents[1] / "corpus" / "diffpair_wave1"
LEAK = ["蒸馏", "修复前", "修复后", "cve=", "seed=", "样本数", "oracle", "anchor",
        "vuln", "safe", "裁定真值", "expected"]

bad = []
for d in ["kits_redistill_truth", "kits_wave2_preaudit", "kits_wave2_formal", "kits_learner"]:
    fence = False
    for p in sorted((WAVE / d).glob("*.txt")):
        fence = False
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if line.startswith("```"):
                fence = not fence
            elif not fence:
                if any(x in line or x in line.lower() for x in LEAK):
                    bad.append((d, p.name, i, line[:60]))
print("非围栏行泄漏命中:", len(bad))
for b in bad[:15]:
    print(" ", b)
