# -*- coding: utf-8 -*-
"""S2 JSON 结论块：提取、解析、字段齐全/顺序/取值域。

输出：out/s2_out.txt + out/s2_bad_json.jsonl(DELETE 候选) + out/s2_field_flags.jsonl
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acommon import OUT, load_rows, asst_text, last_json, write_jsonl, pct

LOG = []


def P(*a):
    LOG.append(" ".join(str(x) for x in a))


EXPECT_ORDER = ["has_vulnerability", "vulnerability_type", "risk_level",
                "source", "sink", "explanation", "fix_suggestion"]
RISK_DOMAIN = {"Critical", "High", "Medium", "Low", "None"}
VT_RE = re.compile(r"^CWE-\d+\s+\S.*$")

rows, _ = load_rows()
bad_json = []
flags = []
stat = Counter()
vt_values = Counter()
risk_values = Counter()
extra_fields = Counter()
key_order_dev = []

for r in rows:
    rid = r["id"]
    a = asst_text(r)
    o, raw, err = last_json(a)
    if o is None:
        bad_json.append({"id": rid, "error": err,
                         "tail": a[-160:].replace("\n", "\\n")})
        stat["bad_json"] += 1
        continue
    if not isinstance(o, dict):
        bad_json.append({"id": rid, "error": "json_not_object"})
        stat["bad_json"] += 1
        continue
    keys = list(o.keys())
    # 字段顺序（允许前缀匹配期望序列的子集序）
    idxs = [keys.index(k) if k in keys else -1 for k in EXPECT_ORDER]
    present = [i for i in idxs if i >= 0]
    if present != sorted(present):
        key_order_dev.append({"id": rid, "keys": keys})
        stat["key_order_dev"] += 1
    missing = [k for k in EXPECT_ORDER if k not in o]
    if missing:
        flags.append({"id": rid, "type": "missing_fields", "missing": missing})
        stat["missing_fields"] += 1
    for k in keys:
        if k not in EXPECT_ORDER:
            extra_fields[k] += 1
            flags.append({"id": rid, "type": "extra_field", "field": k})
            stat["extra_field"] += 1

    hv = o.get("has_vulnerability")
    vt = str(o.get("vulnerability_type", ""))
    risk = str(o.get("risk_level", ""))
    src_ = str(o.get("source", ""))
    snk = str(o.get("sink", ""))
    expl = str(o.get("explanation", ""))
    fix = str(o.get("fix_suggestion", ""))

    if not isinstance(hv, bool):
        flags.append({"id": rid, "type": "hv_not_bool", "val": repr(hv)})
        stat["hv_not_bool"] += 1
    risk_values[risk] += 1
    if risk not in RISK_DOMAIN:
        flags.append({"id": rid, "type": "risk_domain", "val": risk})
        stat["risk_domain"] += 1
    if hv is True:
        vt_values[vt] += 1
        if not VT_RE.match(vt):
            flags.append({"id": rid, "type": "vt_format", "val": vt[:90]})
            stat["vt_format"] += 1
        if "N/A" == expl.strip() or not expl.strip():
            flags.append({"id": rid, "type": "explanation_na_vuln"})
            stat["explanation_na_vuln"] += 1
        if fix.strip() == "no fix needed":
            flags.append({"id": rid, "type": "fix_noop_vuln"})
            stat["fix_noop_vuln"] += 1
    else:
        if hv is False:
            vt_values["<false:" + vt[:40] + ">"] += 1
        if vt.strip() not in ("none", ""):
            flags.append({"id": rid, "type": "vt_not_none_safe", "val": vt[:60]})
            stat["vt_not_none_safe"] += 1
        if re.search(r"CWE-\d+", expl) or re.search(r"CWE-\d+", vt):
            flags.append({"id": rid, "type": "cwe_in_safe_expl"})
            stat["cwe_in_safe_expl"] += 1
        if risk not in ("None", "none", ""):
            flags.append({"id": rid, "type": "risk_not_none_safe", "val": risk})
            stat["risk_not_none_safe"] += 1
    # fix 单行约束（解码后不应含换行/代码块）
    if "```" in fix or "\n" in fix:
        flags.append({"id": rid, "type": "fix_multiline_or_block"})
        stat["fix_multiline_or_block"] += 1
    # 结论一致：正文最后一个"结论"句 vs JSON
    body = a.split("```json")[0] if "```json" in a else a
    body_has_cwe = re.findall(r"CWE-(\d+)", body)
    json_cwe = re.findall(r"CWE-(\d+)", vt)
    if hv is True and not json_cwe:
        flags.append({"id": rid, "type": "vuln_no_cwe_in_json"})
        stat["vuln_no_cwe_in_json"] += 1

P(f"读入 {len(rows)} 条")
P(f"bad_json(DELETE 候选): {len(bad_json)}")
P(f"key_order_dev: {stat['key_order_dev']}")
P("")
P("== risk_level 取值分布 ==")
for v, n in risk_values.most_common(15):
    P(f"  {v!r}: {n}")
P("")
P("== 常见违规 ==")
for t, n in sorted(stat.items(), key=lambda x: -x[1]):
    if t != "bad_json":
        P(f"  {t}: {n} ({pct(n, len(rows))})")
P("")
P("== extra field 明细 ==")
for k, n in extra_fields.most_common(10):
    P(f"  {k}: {n}")
P("")
P("== safe 样本 vt 取值 top ==")
safe_vt = [(v, n) for v, n in vt_values.most_common() if v.startswith("<false")]
for v, n in safe_vt[:10]:
    P(f"  {v}: {n}")
P("")
P("== bad_json 样本（前 10） ==")
for b in bad_json[:10]:
    P(f"  id={b['id']} err={b['error']} tail={b.get('tail','')[:120]}")

write_jsonl(OUT / "s2_bad_json.jsonl", bad_json)
write_jsonl(OUT / "s2_field_flags.jsonl", flags)
(OUT / "s2_out.txt").write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("\n".join(LOG))
