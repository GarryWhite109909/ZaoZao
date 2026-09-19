# -*- coding: utf-8 -*-
"""
待办核实现状（2026-09-10）
对照 v2_17_known_issues_20260909.md 的 A~F 各项，用内容锚（代码 md5）把
v2_15 行号映射到 v2_17 行号，核实现价标签/叙事/同码关系。
只读，不改任何数据。
"""
import json, re, sys, hashlib, collections
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[1]
V15 = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
V17 = BASE / "data/final_train_chatml_alpha06_v2_17.jsonl"
# 可选后缀：python 待办核实现状_20260910.py _落库后  →  待办核实现状_20260910_落库后.json
# （无参数时保持原文件名，便于留存在不同治理波次下的两份快照）
_SUFFIX = sys.argv[1] if len(sys.argv) > 1 else ""
OUT = BASE / f"audit/待办核实现状_20260910{_SUFFIX}.json"

ga = lambda r: [m["content"] for m in r["messages"] if m["role"] == "assistant"][-1]
gu = lambda r: [m["content"] for m in r["messages"] if m["role"] == "user"][0]


def code_of(u):
    fs = re.findall(r"```[A-Za-z0-9_+\-]*\n(.*?)```", u, re.S)
    return max(fs, key=len) if fs else ""


def verd(a):
    m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
    if not m:
        return None
    v = json.loads(m.group(1))
    hv = v.get("has_vulnerability")
    if isinstance(hv, str):
        hv = hv.strip().lower() == "true"
    c = re.search(r"CWE-(\d+)", str(v.get("vulnerability_type") or ""))
    return (hv, "CWE-" + c.group(1) if c else "")


def md5(s):
    return hashlib.md5(s.strip().encode("utf-8", "replace")).hexdigest()


rows15 = [json.loads(l) for l in V15.open(encoding="utf-8") if l.strip()]
rows17 = [json.loads(l) for l in V17.open(encoding="utf-8") if l.strip()]
print(f"v2_15 行数={len(rows15)}  v2_17 行数={len(rows17)}")

# v2_17 索引：代码 md5 -> 行号（1-based）；同码可能多行
idx17 = collections.defaultdict(list)
for i, r in enumerate(rows17, 1):
    c = code_of(gu(r))
    if c.strip():
        idx17[md5(c)].append(i)

# 待核对目标（v2_15 行号 → 说明）
TARGETS = {
    113: "终裁A-推荐safe(实测敌意调用可崩)", 153: "终裁A-推荐safe", 218: "终裁A-推荐safe",
    1665: "终裁A-推荐safe", 7968: "终裁B-推荐vuln(litellm判例)",
    3489: "补投待回收", 3900: "补投待回收", 8055: "补投待回收(purge吸收?)", 7996: "补投待回收",
    3575: "safe硬崩-堆越界写", 3807: "safe硬崩-UAF+double free", 5119: "safe硬崩-已翻CWE-416?",
    5613: "编译失败47中唯一真缺陷(示意代码)",
    7662: "取证落库True/CWE-601", 7725: "purge撤销恢复safe", 9334: "取证落库True/CWE-306",
    7152: "7494五标签族-915", 7153: "7494五标签族-502", 7159: "7494五标签族-117",
    7160: "7494五标签族-22", 7161: "7494五标签族-918",
    7816: "CVE-2019-10909 标22", 2094: "CVE-2021-22555 标798?", 7191: "CVE-2021-23337 none?",
    8056: "Jinja2 1336双CVE", 7444: "CVE-2026-44364 标200", 7641: "CVE-2026-47117 neg=89",
}

out = {}
for ln, note in TARGETS.items():
    r = rows15[ln - 1] if ln - 1 < len(rows15) else None
    if r is None:
        out[ln] = {"note": note, "error": "v2_15 无此行"}
        continue
    code = code_of(gu(r))
    h = md5(code) if code.strip() else ""
    hits = idx17.get(h, [])
    v15v = verd(ga(r))
    rec = {"note": note, "code_md5": h[:12], "v2_15_verdict": list(v15v) if v15v else None,
           "v2_17_lines": hits, "v2_17_verdicts": [], "v2_17_narr_head": []}
    for h2 in hits:
        v17v = verd(ga(rows17[h2 - 1]))
        rec["v2_17_verdicts"].append(list(v17v) if v17v else None)
        rec["v2_17_narr_head"].append(ga(rows17[h2 - 1])[:120].replace("\n", " "))
    out[ln] = rec
    vv = rec["v2_17_verdicts"]
    print(f"行{ln:>5} {note[:26]:<28} v15={rec['v2_15_verdict']} -> v17行{hits} 判定={vv}")

# 7725 vs 7662 vs 9334 同码核对（v2_17 内三行互比）
print("\n--- 7725/7662/9334 同码核对（按 v2_17 内容锚） ---")
fam = {}
for ln in (7662, 7725, 9334):
    code = code_of(gu(rows15[ln - 1]))
    fam[ln] = md5(code) if code.strip() else ""
h662, h725, h334 = fam[7662], fam[7725], fam[9334]
print(f"7662 md5={h662[:12]} 7725 md5={h725[:12]} 9334 md5={h334[:12]}")
print(f"7725 与 7662 同码: {h725 == h662} | 7725 与 9334 同码: {h725 == h334} | 7662 与 9334 同码: {h662 == h334}")
# 相似度兜底（前12位不同但可能空格差异）：字符级 dice
def dice(a, b):
    if not a or not b:
        return 0.0
    from collections import Counter as Ct
    ca, cb = Ct(a), Ct(b)
    inter = sum((ca & cb).values())
    return 2 * inter / (len(a) + len(b))
c662 = code_of(gu(rows15[7662 - 1])); c725 = code_of(gu(rows15[7725 - 1])); c334 = code_of(gu(rows15[9334 - 1]))
print(f"dice(7725,7662)={dice(c725, c662):.3f}  dice(7725,9334)={dice(c725, c334):.3f}  dice(7662,9334)={dice(c662, c334):.3f}")

# v2_17 语言分布（为 L0/配置族跑批做底册）
def lang_of(u):
    m = re.search(r"语言[:：]\s*([^\s）)，,]+)", u)
    l = (m.group(1) if m else "?").lower()
    return {"c++": "cpp", "py": "python", "js": "javascript", "node": "javascript", "ts": "javascript",
            "typescript": "javascript", "golang": "go", "sh": "bash", "shell": "bash",
            "node.js": "javascript"}.get(re.split(r"[，,、/（(]", l)[0].strip(), l)
dist = collections.Counter()
codefmt = collections.Counter()
for r in rows17:
    u = gu(r)
    dist[lang_of(u)] += 1
    if "```dockerfile" in u or "FROM " in code_of(u)[:400]:
        codefmt["dockerfile_有FROM"] += 1
print("\nv2_17 语言分布 top:", dist.most_common(15))

with OUT.open("w", encoding="utf-8") as f:
    json.dump({"rows17": len(rows17), "targets": out, "samecode": {
        "7662": h662[:12], "7725": h725[:12], "9334": h334[:12],
        "7725==7662": h725 == h662, "7725==9334": h725 == h334}, "lang_dist": dict(dist)}, f, ensure_ascii=False, indent=1)
print(f"\n落盘: {OUT}")
