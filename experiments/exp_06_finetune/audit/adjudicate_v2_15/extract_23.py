# -*- coding: utf-8 -*-
"""重建 v2_14 行号(id) -> v2_15 行号映射，抽取 23 条待裁决样本。

映射原理：v2_15 前 9947 条 = v2_14 按 DELETE 集合(74 条)删除后的剩余序列（顺序不变，
1.2/1.3 全部为原位字段修改），148 条新样本追加在尾部。v15_line = id - |deleted < id|。
用 workbench 的 v15_line 字段交叉验证（4 条升级项在 workbench 内）。
"""
import json
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

AUDIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # audit/
ROOT = os.path.dirname(AUDIT)  # exp_06_finetune/
OUT = os.path.join(AUDIT, "adjudicate_v2_15", "samples")
os.makedirs(OUT, exist_ok=True)

IDS = [524, 1108, 8199, 1667, 8196, 2833, 7899, 7218, 8037, 7862, 8025, 8176,
       8141, 1289, 1724, 1449, 7980, 7531, 1717, 2559, 7301, 8184, 6347]

# 1. DELETE 集合（manifest 72 + 附加 8288/8968）
deleted = set()
mpath = os.path.join(AUDIT, "agent_audit_v2_14", "out", "manifest_DELETE.jsonl")
with open(mpath, encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            deleted.add(json.loads(line)["id"])
deleted |= {8288, 8968}
print(f"deleted count = {len(deleted)}")

# 2. workbench v15_line 交叉验证基准
wb = {}
wpath = os.path.join(AUDIT, "agent_audit_v2_14", "out", "fix13_workbench.jsonl")
with open(wpath, encoding="utf-8") as f:
    for line in f:
        r = json.loads(line)
        wb[r["id"]] = r.get("v15_line")

def map_id(i):
    if i in deleted:
        return None
    return i - sum(1 for d in deleted if d < i)

# 3. 抽取
v15 = os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_15.jsonl")
want_lines = {}
mismatch = []
for i in IDS:
    ln = map_id(i)
    if ln is None:
        print(f"id={i} 已删除?!")
        continue
    want_lines[ln] = i
    if i in wb and wb[i] not in (None, ln):
        mismatch.append((i, ln, wb[i]))
print(f"workbench 交叉验证: {'一致' if not mismatch else mismatch}")

found = {}
with open(v15, encoding="utf-8") as f:
    for lineno, line in enumerate(f, 1):
        if lineno in want_lines:
            found[want_lines[lineno]] = json.loads(line)

missing = [i for i in IDS if i not in found]
print(f"found {len(found)}/23; missing: {missing}")

# 4. 落盘 + 摘要（含身份校验信息：语言指纹）
for i in IDS:
    if i not in found:
        continue
    rec = found[i]
    with open(os.path.join(OUT, f"id{i}.json"), "w", encoding="utf-8") as f:
        json.dump(rec, f, ensure_ascii=False, indent=2)
    msgs = rec.get("messages", [])
    user = next((m["content"] for m in msgs if m.get("role") == "user"), "")
    asst = next((m["content"] for m in msgs if m.get("role") == "assistant"), "")
    # 语言指纹：代码围栏
    import re
    m = re.search(r"```(\w+)", user)
    lang = m.group(1) if m else "?"
    # 教师 JSON 关键判定
    try:
        j = json.loads(asst)
        hv = j.get("has_vulnerability")
        vt = j.get("vulnerability_type")
        sev = j.get("severity")
    except Exception as e:
        hv, vt, sev = f"parse_err:{e}", None, None
    print(f"id={i} v15_line={map_id(i)} lang={lang} len(code)={len(user)} "
          f"hv={hv} vt={vt} sev={sev}")
