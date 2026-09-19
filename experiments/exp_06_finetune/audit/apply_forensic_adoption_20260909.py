# -*- coding: utf-8 -*-
"""
取证行落库（2026-09-09 晚）：7662 / 9334 / 7725 采纳 staging 叙事

背景（另一执行者取证 + 用户授权采纳）：
  - 三行此前因代码哈希不匹配被列为"疑似 teacher 换血"——取证结论：代码未被重写，
    哈希不匹配源于 staging 重建 user 内容时围栏归一化（抽取器假阳性）
  - teacher 引文可对码（7662 双模型 4/4 引文命中、9334 双模型一致且引用不越界、
    7725 真引文 class Craft extends Yii 在码）→ 按"引文可对码=叙事重写采纳"政策落库
  - 7667 已由 NVD CVE-2026-59821 官方 CWE-94 复核，与已落库判定一致（VERIFY 留痕）
映射：v2_16 行 → v2_17 行需过两段位移（purge86 + lazy44），两段行号空间不同，分开计数。
"""
import json, re, sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_17.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"
WAVE = BASE / "corpus/redistill_wave"

TARGETS = {7662: "取证：双模型 4/4 引文对码，最大行引用=代码行数",
           9334: "取证：双模型一致 CWE-306，引用不越界",
           7725: "取证：真引文 class Craft extends Yii 在码（未命中为抽取器误判散文）"}

rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
ga = lambda r: [m["content"] for m in r["messages"] if m["role"] == "assistant"][-1]

purge86 = {q["line"] for q in (BASE / "audit/purge_queue_v2_17_20260909.jsonl").open(encoding="utf-8")
           if json.loads(q if isinstance(q, str) else json.dumps(q))["kind"] != "B_示意HIGH_外围"} \
    if False else {json.loads(l)["line"] for l in (BASE / "audit/purge_queue_v2_17_20260909.jsonl").open(encoding="utf-8")
                   if json.loads(l)["kind"] != "B_示意HIGH_外围"}
lazy44 = [c["row_line_before"] for c in map(json.loads, CHANGELOG.open(encoding="utf-8"))
          if c.get("step") == "3.2_lazy_variant_quota"]
assert len(purge86) == 86 and len(lazy44) == 44, (len(purge86), len(lazy44))

o2t = {}
n = 0
for i in range(1, 10152):
    if i in purge86:
        continue
    n += 1
    o2t[i] = n
t2f = {}
n = 0
for t in range(1, len(o2t) + 2):
    if t in lazy44:
        continue
    n += 1
    t2f[t] = n


def v17_line(old):
    t = o2t.get(old)
    return t2f.get(t) if t else None


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


stg = {}
for l in (WAVE / "merged_stage.jsonl").open(encoding="utf-8"):
    r = json.loads(l)
    stg[r["meta"]["orig_line"]] = r

for old, why in TARGETS.items():
    f = v17_line(old)
    assert f, f"行{old} 映射失败"
    r = rows[f - 1]
    srow = stg[old]
    new_a = [m["content"] for m in srow["messages"] if m["role"] == "assistant"][-1]
    v_new = verd(new_a)
    assert v_new, f"行{old} staging 内容无 JSON"
    old_a = ga(r)
    v_old = verd(old_a)
    same = old_a.strip() == new_a.strip()
    [m.__setitem__("content", new_a) for m in r["messages"] if m["role"] == "assistant"]
    kind = "叙事升级" if v_old == v_new else f"结论变更 {v_old} → {v_new}"
    print(f"  行{old}(v2_17 行{f}): {v_old} → {v_new}  [{kind}]")
    changelog = {"date": "2026-09-09", "step": "2.8_staging_forensic_adoption", "action": "FIX",
                 "row_line_before": f, "old_verdict": list(v_old) if v_old else None,
                 "new_verdict": list(v_new), "note": f"取证采纳 staging 叙事：{why}；结论{kind}",
                 "basis": "引文对码取证（引文可对码=叙事重写采纳政策）+ 用户授权", "label_basis": "teacher_retake"}
    with CHANGELOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(changelog, ensure_ascii=False) + "\n")

# 7667 NVD 复核留痕
with CHANGELOG.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps({"date": "2026-09-09", "step": "2.9_nvd_verify", "action": "VERIFY",
                         "row_line_before": v17_line(7667), "note":
                         "CVE-2026-59821 官方 CWE-94（GitHub security advisory，litellm <1.82.0-stable），"
                         "描述原文 production paths did not apply the same sandboxing and validation —— "
                         "与已落库 vuln/CWE-94 一致；驳回部署边界抗辩",
                         "basis": "NVD API 独立复核", "label_basis": "nvd"}, ensure_ascii=False) + "\n")

with DATA.open("w", encoding="utf-8", newline="\n") as f:
    for r in rows:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
rows2 = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
assert len(rows2) == len(rows)
print(f"落库完成：3 行采纳 + 1 条 VERIFY 留痕；行数不变 {len(rows2)}")
