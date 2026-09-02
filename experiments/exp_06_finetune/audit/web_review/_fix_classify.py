# -*- coding: utf-8 -*-
"""FIX 全量分类工作清单: 机械行号类 / CWE 标签类 / 深度重写类, 附定位抽查。"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE / "audit/web_review"))
from _fix_tool import locate, asst_of, code_of  # noqa: E402

TOL = json.loads((BASE / "audit/web_review/_result_tolparse_20260902.json").read_text(encoding="utf-8"))

# json.loads/tolparse 均失败的 9 个 FIX, 手工从 result.txt 原行转录错误类型
UNPARSED_FIX = {
    4771: [("hallucinated_behavior", "critical"), ("poc_invalid", "major"), ("missed_vulnerability", "major"), ("line_number_error", "major"), ("other", "minor"), ("label_leak_shortcut", "minor")],
    7838: [("line_number_error", "major")],
    524: [("wrong_cwe", "major"), ("analysis_json_mismatch", "major"), ("line_number_error", "major"), ("risk_miscalibrated", "minor"), ("fix_half_measure", "minor"), ("label_leak_shortcut", "minor")],
    1667: [("line_number_error", "major"), ("fix_invalid", "minor"), ("verbosity", "minor"), ("label_leak_shortcut", "minor")],
    8196: [("verbosity", "major"), ("wrong_cwe", "minor"), ("risk_miscalibrated", "minor"), ("line_number_error", "minor"), ("fix_format_violation", "minor"), ("vocabulary_inconsistency", "minor")],
    7218: [("line_number_error", "major"), ("analysis_json_mismatch", "minor"), ("missed_vulnerability", "minor"), ("fix_half_measure", "minor"), ("label_leak_shortcut", "minor")],
    6923: [("hallucinated_behavior", "critical"), ("missed_vulnerability", "major"), ("risk_miscalibrated", "major"), ("fix_context_broken", "major"), ("line_number_error", "major"), ("analysis_json_mismatch", "minor")],
    7480: [("hallucinated_artifact", "major"), ("poc_invalid", "major"), ("line_number_error", "major"), ("label_leak_shortcut", "minor")],
    7823: [("false_negative", "critical"), ("analysis_json_mismatch", "major"), ("line_number_error", "major")],
}

def errs_of(wid):
    if str(wid) in TOL:
        o = TOL[str(wid)]
        return o.get("tier"), [(e["type"], e["severity"]) for e in o.get("errors", [])], o.get("note", "")
    t = UNPARSED_FIX[wid]
    return {4771: 2, 7838: 2, 524: 2, 1667: 2, 8196: 2, 7218: 2, 6923: 3, 7480: 2, 7823: 1}[wid], t, ""

fix_ids = sorted([int(i) for i, o in TOL.items() if o.get("verdict") == "FIX"] + list(UNPARSED_FIX))
MECH_OK = {"line_number_error", "label_leak_shortcut"}
CWE_ONLY = {"wrong_cwe", "analysis_json_mismatch", "vocabulary_inconsistency", "risk_miscalibrated"}

worklist, mech, cwe, deep = [], [], [], []
for wid in fix_ids:
    tier, errs, note = errs_of(wid)
    types = {t for t, _ in errs}
    if types <= MECH_OK:
        cls = "MECH"
        mech.append(wid)
    elif types - MECH_OK <= CWE_ONLY and "risk_miscalibrated" not in (types - CWE_ONLY):
        cls = "CWE"
        cwe.append(wid)
    else:
        cls = "DEEP"
        deep.append(wid)
    cur, rec = locate(wid)
    worklist.append({"id": wid, "class": cls, "tier": tier, "cur_line": cur,
                     "errors": errs, "note": note[:150]})

print(f"FIX 总数: {len(fix_ids)}  MECH: {len(mech)}  CWE: {len(cwe)}  DEEP: {len(deep)}")
print("MECH:", mech)
print("CWE :", cwe)
print("DEEP:", deep)
(BASE / "audit/web_review/_fix_worklist_20260902.json").write_text(
    json.dumps(worklist, ensure_ascii=False, indent=1), encoding="utf-8")
print("工作清单已存 _fix_worklist_20260902.json")

# 定位抽查: 每类抽 2 个, 用审计 note 关键词对 assistant 内容
print("\n--- 定位抽查 ---")
import random
random.seed(2)
for cls, ids in (("MECH", mech), ("CWE", cwe), ("DEEP", deep)):
    for wid in random.sample(ids, min(2, len(ids))):
        cur, rec = locate(wid)
        a = asst_of(rec)
        wl = next(w for w in worklist if w["id"] == wid)
        print(f"[{cls}] id={wid} 行{cur} note={wl['note'][:60]}")
        print("   assistant 开头:", a[:80].replace(chr(10), " "))
