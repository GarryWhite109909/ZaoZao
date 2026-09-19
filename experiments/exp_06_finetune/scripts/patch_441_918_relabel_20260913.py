# -*- coding: utf-8 -*-
"""441-07/08/13/14 主标签改 918（build 脚本源头）+ 重建验证。"""
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
f = Path(__file__).resolve().parents[1] / "scripts" / "build_wave2_pairs_441_20260911.py"
t = f.read_text(encoding="utf-8")
for pid in ["441-07", "441-08", "441-13", "441-14"]:
    m = re.search(r'("pid": "' + pid + r'".*?"cwe": ")(CWE-441)(")', t, re.S)
    assert m, pid
    t = t[:m.start(2)] + "CWE-918" + t[m.end(2):]
f.write_text(t, encoding="utf-8")
print("build 脚本 4 对主标签已改 918")
