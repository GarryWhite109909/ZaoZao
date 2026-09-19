# -*- coding: utf-8 -*-
"""
v2_17 懒变体治理（2026-09-09 晚）

对象：变体质量诊断判定的「近全同冗余」簇（containment≥0.92、同 verdict、同 CWE，非差分对）
规则：每簇保留 **2** 条（按叙事质量优先：行引用数多 → explanation 长），其余删除。
      差分对簇与有信息量变体不动。
实现：原簇文件行号是 v2_16 的 → 用 purge 集合重建 old→v2_17 映射 → 簇内存活者重算 containment
      → 配额删减 → 重写 v2_17 → changelog → 重映射表 + 459 清单再生。
"""
import json, re, sys, hashlib, collections
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_17.jsonl"
CLUSTER = BASE / "audit/scan_v2_16_l3_cluster_flags.json"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"
REMAP = BASE / "audit/治理后行号重映射_20260909.json"

rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
ga = lambda r: [m["content"] for m in r["messages"] if m["role"] == "assistant"][-1]


def code_of(u):
    fs = re.findall(r"```[A-Za-z0-9_+\-]*\n(.*?)```", u, re.S)
    return max(fs, key=len) if fs else ""


def verd(a):
    m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
    if not m:
        return None
    try:
        v = json.loads(m.group(1))
        hv = v.get("has_vulnerability")
        if isinstance(hv, str):
            hv = hv.strip().lower() == "true"
        c = re.search(r"CWE-(\d+)", str(v.get("vulnerability_type") or ""))
        return (hv, "CWE-" + c.group(1) if c else "", v)
    except Exception:
        return None


# 实际被 build 删除的是 86 行（27 条外围备案保留未删）——映射必须按实际删除集
purge = {json.loads(l)["line"] for l in (BASE / "audit/purge_queue_v2_17_20260909.jsonl").open(encoding="utf-8")
         if json.loads(l)["kind"] != "B_示意HIGH_外围"}
assert len(purge) == 86, f"实际删除集应为 86，得到 {len(purge)}"
old2new = {}
n = 0
for i in range(1, 10152):
    if i in purge:
        continue
    n += 1
    old2new[i] = n

# 簇成员映射到 v2_17 行
codes, verds = {}, {}
for i, r in enumerate(rows, 1):
    codes[i] = code_of([m["content"] for m in r["messages"] if m["role"] == "user"][0])
    verds[i] = verd(ga(r))


def nlines(c):
    return set(re.sub(r"\s+", " ", l.strip()) for l in c.split("\n")
               if l.strip() and not l.strip().startswith(("//", "#", "/*", "*", "--")))


def containment(A, B):
    A, B = set(A), set(B)
    return len(A & B) / min(len(A), len(B)) if A and B else 0.0


cl = json.load(open(CLUSTER, encoding="utf-8"))
remove = []
kc = collections.Counter()
kept_examples = []
for c in cl.get("clusters", []):
    rr = sorted(old2new[int(x)] for x in c.get("rows_1based", []) if int(x) in old2new)
    if len(rr) < 2:
        continue
    hvs = {verds[x][0] for x in rr if verds[x]}
    cwes = {verds[x][1] for x in rr if verds[x] and verds[x][0]}
    if True in hvs and False in hvs:
        continue
    mx = 0.0
    for i in range(len(rr)):
        for j in range(i + 1, len(rr)):
            mx = max(mx, containment(nlines(codes[rr[i]]), nlines(codes[rr[j]])))
    if mx < 0.92 or len(cwes) > 1:
        continue
    # 懒变体簇：保留 2 条（行引用数多 → explanation 长者优先）
    def quality(x):
        v = verds[x]
        if not v or not v[2]:
            return (0, 0)
        exp = str(v[2].get("explanation") or "")
        cites = len(set(re.findall(r"(?:line|行|第)\s*(\d{1,3})", exp)))
        return (cites, len(exp))
    keep = sorted(rr, key=lambda x: (-quality(x)[0], -quality(x)[1], x))[:2]
    for x in rr:
        if x not in keep:
            remove.append(x)
    kc[f"簇{len(rr)}裁{len(rr)-2}"] += 1
    if len(kept_examples) < 5:
        kept_examples.append({"keep": keep, "remove": [x for x in rr if x not in keep][:6],
                              "max_containment": round(mx, 3), "cwe": sorted(cwes)})

remove = sorted(set(remove))
assert all(verds[x] is not None for x in remove), "待删行结论异常"
new_rows = [r for i, r in enumerate(rows, 1) if i not in set(remove)]
with DATA.open("w", encoding="utf-8", newline="\n") as f:
    for r in new_rows:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
with CHANGELOG.open("a", encoding="utf-8") as f:
    for x in remove:
        v = verds[x]
        f.write(json.dumps({"date": "2026-09-09", "step": "3.2_lazy_variant_quota",
                            "action": "DELETE", "row_line_before": x,
                            "kind": "L_近全同冗余配额", "reason": f"懒变体簇配额裁剪（保留2，删{len(remove)}中之一）",
                            "verdict_kept": "同簇保留2条更优叙事",
                            "basis": "变体质量诊断 containment>=0.92 同verdict同CWE；build 层治理",
                            "label_basis": "n/a"}, ensure_ascii=False) + "\n")

# 重映射表再生（FLIP/终裁）
purge2 = purge | set(remove)
o2n = {}
n = 0
for i in range(1, 10152):
    if i in purge2:
        continue
    n += 1
    o2n[i] = n
FLAGS = {}
for l in (BASE / "corpus/redistill_wave/verify_report.jsonl").open(encoding="utf-8"):
    r = json.loads(l)
    if r.get("line"):
        FLAGS[r["line"]] = r.get("flags", [])
flip_old = sorted(ln for ln, fl in FLAGS.items() if any(f.startswith("FLIP") for f in fl))
final_old = [113, 153, 218, 1542, 1665, 3489, 3900, 7996, 8055]
remap = {"flip": {str(ln): o2n[ln] for ln in flip_old if ln in o2n},
         "final": {str(ln): o2n[ln] for ln in final_old if ln in o2n},
         "dropped": {"flip": [ln for ln in flip_old if ln not in o2n],
                     "final": [ln for ln in final_old if ln not in o2n]}}
json.dump(remap, REMAP.open("w", encoding="utf-8"), ensure_ascii=False, indent=1)
sha = hashlib.sha256(DATA.read_bytes()).hexdigest()
print(f"懒变体治理: 删 {len(remove)} 行 → v2_17 现 {len(new_rows)} 行")
print("簇裁剪分布:", dict(sorted(kc.items(), key=lambda x: -int(x[0].split('簇')[1].split('裁')[0]))[:6]))
print("保留样例:", json.dumps(kept_examples[:2], ensure_ascii=False)[:260])
print(f"FLIP 存活 {len(remap['flip'])} / 终裁存活 {len(remap['final'])}；sha256 {sha[:32]}…")
print(f"changelog +{len(remove)}；重映射表已再生")
