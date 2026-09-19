# -*- coding: utf-8 -*-
"""
v2_17 修复：恢复 7725 + 落 7662/9334 取证叙事（2026-09-09 深夜）

背景：上一脚本在 7725 映射处断言崩溃——DATA 未写盘（7662/9334 内容未持久化），
      但 changelog 已写入 2 条提前条目；且 7725 在 v2_17 构建时被 A2 同码反标整组 purge，
      而取证结论是"7725 引文可对码、safe 判定成立"→ 应恢复（7724 spurious vuln 维持 PURGE）。
本脚本（对当前 v2_17 做外科手术，不改其他行）：
  1. 按正确映射（purge86 + lazy44，两段行号空间）重建最终行序，把 7725 插回原位
  2. 7725 行 = v2_16 用户内容 + staging 叙事（safe）；7662/9334 = 现 v2_17 行 + staging 叙事
  3. changelog 只补缺失条目（7725 取证 + RESTORE + 7667 VERIFY）
"""
import json, re, sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_17.jsonl"
V16 = BASE / "data/final_train_chatml_alpha06_v2_16.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"
WAVE = BASE / "corpus/redistill_wave"

cur = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
v16 = [json.loads(l) for l in V16.open(encoding="utf-8") if l.strip()]
chlog = [json.loads(l) for l in CHANGELOG.open(encoding="utf-8") if l.strip()]

purge86 = {q["line"] for q in map(json.loads, (BASE / "audit/purge_queue_v2_17_20260909.jsonl").open(encoding="utf-8"))
           if q["kind"] != "B_示意HIGH_外围"}
assert len(purge86) == 86
lazy44 = [c["row_line_before"] for c in chlog if c.get("step") == "3.2_lazy_variant_quota"]
assert len(lazy44) == 44

S = [i for i in range(1, 10152) if i not in purge86]          # 10065，purge 后旧行序
L44old = {S[t - 1] for t in lazy44}                            # lazy 删的旧行
final_old = sorted((set(S) - L44old) | {7725})                 # 10022，含恢复的 7725
assert len(final_old) == 10022, len(final_old)

ga = lambda r: [m["content"] for m in r["messages"] if m["role"] == "assistant"][-1]
stg = {}
for l in (WAVE / "merged_stage.jsonl").open(encoding="utf-8"):
    r = json.loads(l)
    stg[r["meta"]["orig_line"]] = [m["content"] for m in r["messages"] if m["role"] == "assistant"][-1]


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


new_rows, ci = [], 0
report = []
for old in final_old:
    if old == 7725:
        r = json.loads(json.dumps(v16[old - 1]))
        sa = stg[old]
        v_new = verd(sa)
        assert v_new and v_new[0] is False, f"7725 staging 判定异常 {v_new}"
        [m.__setitem__("content", sa) for m in r["messages"] if m["role"] == "assistant"]
        new_rows.append(r)
        report.append(f"7725 恢复（v2_16 行7725 + staging 叙事，verdict={v_new}）")
        continue
    r = cur[ci]
    ci += 1
    if old in (7662, 9334):
        old_a = ga(r)
        sa = stg[old]
        v_old, v_new = verd(old_a), verd(sa)
        assert v_new, f"行{old} staging 无 JSON"
        [m.__setitem__("content", sa) for m in r["messages"] if m["role"] == "assistant"]
        report.append(f"{old}（v2_17 行{ci}）: {v_old} → {v_new}")
    new_rows.append(r)
assert ci == len(cur), (ci, len(cur))

with DATA.open("w", encoding="utf-8", newline="\n") as f:
    for r in new_rows:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

have = {(c.get("step"), c.get("row_line_before")) for c in chlog}
add = []
for old, why in {7725: "取证：真引文 class Craft extends Yii 在码（未命中为抽取器误判散文）；safe 判定成立"}.items():
    if ("2.8_staging_forensic_adoption", old) not in have:
        add.append({"date": "2026-09-09", "step": "2.8_staging_forensic_adoption", "action": "RESTORE",
                    "row_line_before": old, "new_verdict": ["False", ""],
                    "note": f"{why}；A2 purge 撤销（7724 spurious vuln 维持 PURGE）",
                    "basis": "引文对码取证 + 用户授权采纳", "label_basis": "teacher_retake"})
f7725 = final_old.index(7725) + 1
f7667 = final_old.index(7667) + 1
if ("2.9_nvd_verify", f7667) not in have:
    add.append({"date": "2026-09-09", "step": "2.9_nvd_verify", "action": "VERIFY", "row_line_before": f7667,
                "note": "CVE-2026-59821 官方 CWE-94（litellm <1.82.0-stable），描述 production paths did not "
                        "apply the same sandboxing and validation —— 与已落库 vuln/CWE-94 一致；驳回部署边界抗辩",
                "basis": "NVD API 独立复核", "label_basis": "nvd"})
for old in (7662, 9334):
    if ("2.8_staging_forensic_adoption", final_old.index(old) + 1) not in have:
        add.append({"date": "2026-09-09", "step": "2.8_staging_forensic_adoption", "action": "FIX",
                    "row_line_before": final_old.index(old) + 1, "note": "取证采纳 staging 叙事（见前次条目内容）",
                    "basis": "引文对码取证 + 用户授权", "label_basis": "teacher_retake"})
with CHANGELOG.open("a", encoding="utf-8") as fh:
    for c in add:
        fh.write(json.dumps(c, ensure_ascii=False) + "\n")

for x in report:
    print(" ", x)
print(f"v2_17 终版: {len(new_rows)} 行（7725 恢复 +1）；changelog +{len(add)}")
