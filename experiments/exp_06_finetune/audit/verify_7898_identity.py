# -*- coding: utf-8 -*-
"""7898 同一性验证:快照指纹 vs 当前 v2_15 公式行/全文定位。"""
import json, re, sys, hashlib, os
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
FENCE = re.compile(r"```[\w+#.\-/]*[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)
JSON_B = re.compile(r"```json\s*(.*?)```", re.S)
del_ids = {json.loads(l)["id"] for l in
           open("agent_audit_v2_14/out/manifest_DELETE.jsonl", encoding="utf-8")} | {8288, 8968}
def v15(v14): return v14 - sum(1 for d in del_ids if d < v14)
def umd5(s): return hashlib.md5("".join(s.split()).encode()).hexdigest()

rb = r"D:\$RECYCLE.BIN\S-1-5-21-2018009969-3916152638-467293194-1001"
snap = os.path.join(rb, "$RO28S3R", "data", "final_train_chatml_alpha06_v2_15.jsonl")
snap_um = None
with open(snap, encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        if i == 7898:
            u = json.loads(line)["messages"][1]["content"]
            snap_um = umd5(u)
            head = u.splitlines()
            print(f"快照 7898 行: umd5={snap_um[:12]} 代码头: {head[2][:60]!r}")
            break

cur = open("../data/final_train_chatml_alpha06_v2_15.jsonl", encoding="utf-8").read().split("\n")
formula_ln = v15(7898)
u_formula = json.loads(cur[formula_ln - 1])["messages"][1]["content"]
print(f"公式行({formula_ln}): umd5={umd5(u_formula)[:12]} | 同一性: {umd5(u_formula) == snap_um}")

found = None
for i, line in enumerate(cur, 1):
    if not line.strip():
        continue
    if umd5(json.loads(line)["messages"][1]["content"]) == snap_um:
        found = i
        break
print("快照样本 7898 实际位于当前 v2_15 行:", found, "(公式预测", formula_ln, ")")
if found:
    o = json.loads(JSON_B.findall(json.loads(cur[found - 1])["messages"][2]["content"])[-1])
    print("该行实际 hv:", o.get("has_vulnerability"), "| s7 聚类记录: False")
