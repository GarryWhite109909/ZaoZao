# -*- coding: utf-8 -*-
"""差分对蒸馏：契约验证门（方法论 §2.2 生成契约 → 机检）。

检查项（每对）：
  C1 配对完整：PRE+POST 两记录均在；
  C2 配对一致性：PRE 判真（或 unknown 标注）且 POST 判安——POST 判真=修复无效（高价值信号，FLAG 人工复核）；
  C3 类型族 oracle：PRE.vulnerability_type 与 expected_cwe 同族（族表容忍近邻）；
  C4 行号边界：source/sink/行级归因引用的行号 ≤ 对应版本代码行数；
  C5 归因锚定：POST 行级归因引用的行号须命中真实 diff 变更行 ±2（归因幻觉检测）；
  C6 互斥锚句：近邻族的 explanation/分析过程 须含"非 CWE-"；
  C7 行级归因须含代码片段（反引号或引号包裹）。

输出：corpus/diffpair_wave1/verify_report.jsonl + 终端统计。FLAG 不落库，进人工/2v1。
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(Path(__file__).resolve().parents[1])
WAVE = BASE / "corpus/diffpair_wave1"

FAMILY = {
    "77": {"77", "78"}, "78": {"78", "77"},
    "94": {"94", "95", "1336"}, "95": {"95", "94"}, "1336": {"1336", "94"},
    "89": {"89", "943"}, "943": {"943", "89", "643"}, "643": {"643", "91", "943"},
    "601": {"601", "918", "441"}, "918": {"918", "601", "441"}, "441": {"441", "918", "601"},
    "22": {"22", "73"}, "73": {"73", "22"},
    "611": {"611", "776", "611"}, "502": {"502"}, "798": {"798", "321", "259", "798"},
    "184": {"184"}, "295": {"295"}, "327": {"327", "326", "327"},
    "862": {"862", "639", "306"}, "639": {"639", "862", "306"}, "306": {"306", "862", "639"},
    "79": {"79"}, "352": {"352"}, "915": {"915", "1321"}, "1321": {"1321", "915"},
    "384": {"384"}, "117": {"117"}, "125": {"125"},
}
NEIGHBOR_FAMILIES = {"77", "78", "94", "95", "1336", "89", "943", "601", "918", "441", "22", "73"}

LINE_REF = re.compile(r"(?:line|第)\s*(\d{1,4})(?:[-–]\d{1,4})?\s*(?:行|[:：])?|L(\d{1,4})\b")


def refs(text):
    out = []
    for m in LINE_REF.finditer(text or ""):
        out.append(int(m.group(1) or m.group(2)))
    return out


def cwe_of(vt: str):
    m = re.match(r"CWE-(\d+)", (vt or "").strip())
    return m.group(1) if m else None


def verify_pair(kid, meta, parsed_map):
    flags = []
    pre = parsed_map.get(f"{kid}-PRE")
    post = parsed_map.get(f"{kid}-POST")
    if not pre or not post:
        return None, [f"C1 缺记录: {'PRE' if not pre else ''}{'POST' if not post else ''}"]

    def fget(rec, k):
        return rec.get("fields", {}).get(k, "")

    # C2 一致性
    pre_v = fget(pre, "has_vulnerability").strip().lower()
    post_v = fget(post, "has_vulnerability").strip().lower()
    if pre_v == "unknown" or "truncated" in pre_v:
        flags.append("C2 PRE 标注截断/unknown → 重投喂")
    if post_v == "true":
        flags.append("C2 POST 判真=修复无效或引入新洞 → 高价值，人工复核")
    if pre_v not in ("true", "false", "unknown"):
        flags.append(f"C2 PRE has_vulnerability 不可解析: {pre_v[:20]}")

    # C3 类型族
    pre_cwe = cwe_of(fget(pre, "vulnerability_type"))
    exp = (meta.get("expected_cwe") or "").replace("CWE-", "")
    if pre_cwe and exp and pre_v == "true":
        fam = FAMILY.get(exp, {exp})
        if pre_cwe not in fam:
            flags.append(f"C3 类型族偏差: 教师CWE-{pre_cwe} vs oracle CWE-{exp}（族{sorted(fam)}）")

    # C4 行号边界
    post_code = json.loads((WAVE / "manifest_PRIVATE.json").read_text(encoding="utf-8"))[kid]
    pre_n, post_n = post_code["pre_lines"], post_code["post_lines"]
    for rec, n, tag in ((pre, pre_n, "PRE"), (post, post_n, "POST")):
        for field in ("source", "sink", "行级归因"):
            for ln in refs(fget(rec, field)):
                if ln > n:
                    flags.append(f"C4 {tag}.{field} 引用行 {ln} > 代码 {n} 行（行号幻觉）")
                    break

    # C5 归因锚定（POST 行级归因须命中真实变更行 ±2）
    changed = set(post_code["changed_post"])
    attr = fget(post, "行级归因")
    cited = refs(attr)
    if attr:
        if not any(ln in changed or any(abs(ln - c) <= 2 for c in changed) for ln in cited):
            flags.append(f"C5 归因行 {cited[:6]} 未命中真实变更行 {sorted(changed)[:8]}（归因幻觉）")
        if "`" not in attr and "\"" not in attr and "'" not in attr:
            flags.append("C7 归因无代码片段（须引用片段）")
    else:
        flags.append("C5 POST 缺行级归因字段")

    # C6 互斥锚句（近邻族）
    if pre_cwe in NEIGHBOR_FAMILIES:
        blob = fget(pre, "explanation") + fget(pre, "分析过程")
        if "非 CWE" not in blob and "非CWE" not in blob:
            flags.append(f"C6 近邻族 CWE-{pre_cwe} 缺互斥锚句")

    return {"pre_v": pre_v, "post_v": post_v, "pre_cwe": pre_cwe}, flags


def main():
    manifest = json.loads((WAVE / "manifest_PRIVATE.json").read_text(encoding="utf-8"))
    parsed_dir = WAVE / "parsed"
    out = []
    done = 0
    for kit_file in sorted((WAVE / "results").glob("*.txt")):
        parsed = parsed_dir / (kit_file.stem + ".jsonl")
        kid = kit_file.stem
        meta = manifest.get(kid)
        if not meta:
            continue
        if not parsed.exists():
            continue
        recs = [json.loads(l) for l in parsed.open(encoding="utf-8") if l.strip()]
        pmap = {r["id"]: r for r in recs}
        pair, flags = verify_pair(kid, meta, pmap)
        out.append({"kit": kid, "cve": meta["cve"], "pair": pair, "flags": flags})
        done += 1
    (WAVE / "verify_report.jsonl").write_text(
        "\n".join(json.dumps(o, ensure_ascii=False) for o in out) + "\n", encoding="utf-8")
    hard = [o for o in out if o["flags"] and any(f.startswith(("C2 POST", "C5", "C4", "C1")) for f in o["flags"])]
    soft = [o for o in out if o["flags"] and o not in hard]
    clean = [o for o in out if not o["flags"]]
    print(f"验证 {done} 对：PASS {len(clean)} / 软FLAG {len(soft)} / 硬FLAG {len(hard)}")
    print(f"→ {WAVE / 'verify_report.jsonl'}")


if __name__ == "__main__":
    main()
