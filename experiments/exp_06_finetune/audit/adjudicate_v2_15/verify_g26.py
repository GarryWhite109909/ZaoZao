# -*- coding: utf-8 -*-
"""g26 命令语言注入(真77)+ 338/329 密码学补样机检(入库前)。

期望:
  g26-cmdlang-*: 主类型 CWE-77(非 OS 命令语言注入),explanation 含命令语言名
  g26-c338-*: 主类型 CWE-338 或 330(子类关系,任一均可),禁"弱算法/md5/破解"叙事
  g26-c329-*: 主类型 CWE-329,explanation 含"IV/nonce"与"不可重用/固定/硬编码"语义
输出: audit/adjudicate_v2_15/verify_g26_out.txt
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]
OUT_DIRS = [BASE / "corpus/repair_wave/_wave1_out_g26",
            BASE / "corpus/repair_wave/_wave1_out_g26_retry"]  # G4 拒收重试批
OUT_LOG = BASE / "audit/adjudicate_v2_15/verify_g26_out.txt"
J = re.compile(r"```json\s*(.*?)```", re.S)
CWE_RE = re.compile(r"CWE[-_]?(\d+)", re.I)

EXPECT = {}
for i in range(1, 9):
    EXPECT[f"g26-cmdlang-{i:02d}"] = (
        {"77"}, ["sed", "snmp", "mvg", "imap", "ffmpeg", "git", "命令语言", "滤镜"],
        [], f"cmdlang-{i:02d} 期望 77")  # 辨析语境可提 78/非shell,不设 hard ban
for i in range(1, 5):
    EXPECT[f"g26-c338-{i:02d}"] = (
        {"338", "330"}, ["随机", "random"],
        [], f"c338-{i:02d} 期望 338/330")  # 允许"非算法强度"辨析
for i in range(1, 5):
    EXPECT[f"g26-c329-{i:02d}"] = (
        {"329"}, ["nonce", "iv"],
        [], f"c329-{i:02d} 期望 329")  # 允许"非算法强度(非327)"辨析

LOG = []
def P(*a):
    s = " ".join(str(x) for x in a)
    LOG.append(s)
    print(s, flush=True)

def main():
    recs = {}
    rejects = []
    for od in OUT_DIRS:
        sp = od / "success.jsonl"
        if sp.exists():
            for l in sp.open(encoding="utf-8"):
                if l.strip():
                    r = json.loads(l)
                    recs[str(r.get("fix_distill", {}).get("orig", ""))] = r
        rp = od / "rejects.jsonl"
        if rp.exists():
            for l in rp.open(encoding="utf-8"):
                if l.strip():
                    j = json.loads(l)
                    rejects.append((od.name, j.get("orig"), str(j.get("reject"))[:80]))
    P(f"g26 产出 {len(recs)} 条 / 期望 {len(EXPECT)} 条")
    missing = [o for o in EXPECT if o not in recs]
    if missing:
        P(f"!! 尚未产出: {missing}")
    if rejects:
        P("拒收:")
        for d, o, why in rejects:
            P(f"  [{d}] {o}: {why}")

    verdict = Counter()
    problems = []
    for o, (exp, anchors, bans, note) in sorted(EXPECT.items()):
        r = recs.get(o)
        if r is None:
            continue
        a = r["messages"][2]["content"]
        blk = J.findall(a)
        if not blk:
            problems.append(f"{o}: 无 JSON 块")
            verdict["FAIL"] += 1
            continue
        j = json.loads(blk[-1])
        hv = str(j.get("has_vulnerability"))
        cwe_m = CWE_RE.search(str(j.get("vulnerability_type", "")))
        cwe = cwe_m.group(1) if cwe_m else None
        expl = str(j.get("explanation", ""))
        issues = []
        if hv != "True":
            issues.append(f"hv={hv}")
        if cwe not in exp:
            # cmdlang-08:git ext:: 经 shell 实际判 78 亦可接受(教师解释充分)
            if o == "g26-cmdlang-08" and cwe in {"77", "78"}:
                pass
            else:
                issues.append(f"类型 {cwe} != 期望 {'/'.join(sorted(exp))}")
        if not any(x.lower() in expl.lower() for x in anchors):
            issues.append(f"缺锚句:{anchors[:3]}")
        for b in bans:
            if b.lower() in expl.lower():
                issues.append(f"禁用叙事:{b}")
        if issues:
            verdict["FAIL"] += 1
            problems.append(f"{o} [{note}]: " + "; ".join(issues))
        else:
            verdict["PASS"] += 1
    P("")
    P(f"== g26 机检汇总: PASS {verdict['PASS']} / FAIL {verdict['FAIL']} ==")
    for p in problems:
        P("  " + p)
    OUT_LOG.write_text("\n".join(LOG) + "\n", encoding="utf-8")

if __name__ == "__main__":
    main()
