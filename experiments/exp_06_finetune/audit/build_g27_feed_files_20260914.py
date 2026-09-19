# -*- coding: utf-8 -*-
"""g27 投喂文本生成：把 16 条出题包拆成 4 个批次文件（每批 4 条，≤10KB），供网页端逐条粘贴（2026-09-14）"""
import sys, os, json, re
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "corpus/repair_wave/wave2_g27/g27_kits.jsonl"
OUT = ROOT / "corpus/repair_wave/wave2_g27/feed"
OUT.mkdir(parents=True, exist_ok=True)

rows = [json.loads(l) for l in SRC.open(encoding="utf-8") if l.strip()]
assert len(rows) == 16, len(rows)

SEP = "\n\n" + "=" * 70 + "\n\n"
parts = []
for i, r in enumerate(rows, 1):
    body = (r["user"]
            + "\n\n【前期审计已实测的事实(供参考;仍需你在分析中独立核对代码)】\n"
            + r["hint"])
    parts.append(f"### {r['orig']}\n\n{body}")

# 4 批 × 4 条
BATCH = 4
files = []
for b in range(0, len(parts), BATCH):
    chunk = parts[b:b + BATCH]
    p = OUT / f"g27_feed_{b // BATCH + 1:02d}.txt"
    p.write_text(SEP.join(chunk) + "\n", encoding="utf-8", newline="\n")
    files.append(p)
    print(f"{p.name}  {p.stat().st_size / 1024:.1f} KB  ({len(chunk)} 条: "
          f"{rows[b]['orig']} ~ {rows[min(b + BATCH - 1, len(rows) - 1)]['orig']})")

total = sum(p.stat().st_size for p in files)
print(f"\n合计 {len(files)} 个批次文件 / {total / 1024:.1f} KB")
print(f"最大单批 {max(p.stat().st_size for p in files) / 1024:.1f} KB（粘贴红线 48KB）")
