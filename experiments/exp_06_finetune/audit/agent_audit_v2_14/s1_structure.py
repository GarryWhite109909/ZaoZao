# -*- coding: utf-8 -*-
"""S1 结构与管线：roles 严格性、system 一致性、元数据盘点、空内容。

输出：out/s1_out.txt + out/s1_violations.json + out/s1_systems.json
"""
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acommon import BASE, SRC, OUT, load_rows, sys_text, user_text, asst_text, hash01, write_jsonl, pct

LOG = []


def P(*a):
    LOG.append(" ".join(str(x) for x in a))


rows, bad_parse = load_rows()
P(f"读入 {len(rows)} 条；行级 JSON 解析失败 {len(bad_parse)} 条")
for b in bad_parse:
    P(f"  bad line json: id={b['id']} {b['error']}")

viol = []
sys_counter = Counter()
fd_key_counter = Counter()
fd_teacher = Counter()
fd_time = []
role_seqs = Counter()
empty_content = []

for r in rows:
    rid = r["id"]
    rec = r["rec"]
    msgs = rec.get("messages")
    if not isinstance(msgs, list):
        viol.append({"id": rid, "type": "messages_not_list"})
        continue
    roles = tuple(m.get("role") for m in msgs)
    role_seqs[roles] += 1
    if roles != ("system", "user", "assistant"):
        viol.append({"id": rid, "type": "role_seq", "roles": roles})
    for idx, m in enumerate(msgs):
        c = m.get("content")
        if not isinstance(c, str) or not c.strip():
            empty_content.append({"id": rid, "idx": idx})
            viol.append({"id": rid, "type": "empty_content", "role": m.get("role")})
    if roles and roles[0] == "system":
        sys_counter[hash01(sys_text(r))] += 1
    fd = rec.get("fix_distill")
    if fd is None:
        fd_key_counter["<absent>"] += 1
    elif isinstance(fd, dict):
        for k in fd:
            fd_key_counter[k] += 1
        t = fd.get("teacher")
        fd_teacher[str(t)] += 1
        g = fd.get("generated_at")
        if g:
            fd_time.append(str(g)[:10])
    else:
        fd_key_counter[f"<{type(fd).__name__}>"] += 1

P("")
P("== role 序列分布 ==")
for seq, n in role_seqs.most_common(10):
    P(f"  {seq}: {n}")

P("")
P("== system 一致性 ==")
P(f"  不同 system 指纹数: {len(sys_counter)}")
for h, n in sys_counter.most_common(10):
    P(f"  {h}: {n} 条")
# 找出少数派 system 的样本 id（供内容比对）
major_h, major_n = sys_counter.most_common(1)[0]
minor_ids = []
if len(sys_counter) > 1:
    for r in rows:
        if hash01(sys_text(r)) != major_h:
            minor_ids.append(r["id"])
    P(f"  少数派 system 样本 id（前 30）: {minor_ids[:30]}")

P("")
P("== fix_distill 元数据 ==")
P(f"  键分布: {dict(fd_key_counter)}")
P(f"  teacher 分布: {dict(fd_teacher.most_common(20))}")
if fd_time:
    fd_time.sort()
    P(f"  generated_at 范围: {fd_time[0]} ~ {fd_time[-1]}")

P("")
P("== 违规汇总 ==")
vc = Counter(v["type"] for v in viol)
for t, n in vc.most_common():
    P(f"  {t}: {n} ({pct(n, len(rows))})")

# ---- 管线级检查：训练脚本对字段的消费（静态证据，写进报告） ----
P("")
P("== 管线级检查（静态证据） ==")
tp = BASE / "cloud_train/train_qlora_cloud.py"
if tp.exists():
    src = tp.read_text(encoding="utf-8", errors="replace")
    hits = [f"L{i+1}: {ln.strip()}" for i, ln in enumerate(src.splitlines())
            if ("messages" in ln or "fix_distill" in ln or "remove_columns" in ln.replace(" ", "")) and not ln.strip().startswith("#")]
    for h in hits:
        P(f"  {tp.name} {h}")

write_jsonl(OUT / "s1_violations.jsonl", viol)
(OUT / "s1_systems.json").write_text(json.dumps(
    {"fingerprints": dict(sys_counter), "major": major_h,
     "minor_ids": minor_ids}, ensure_ascii=False, indent=1), encoding="utf-8")
(OUT / "s1_out.txt").write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("\n".join(LOG[-25:]))
print("->", OUT / "s1_out.txt")
