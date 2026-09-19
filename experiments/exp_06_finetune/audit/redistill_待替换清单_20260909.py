# -*- coding: utf-8 -*-
"""
redistill 待替换清单生成器（2026-09-09）

背景：redistill wave（manifest 231 id → glm5.3 241 段 + qwen_flip 52 + retake 4 → parsed 297
      → merged_stage 220）已蒸馏并 parse 完，但 merged_stage 与 v2_16 比对发现
      **79 条新旧结论不同 = 蒸馏完没来得及替换**，另有 6 条代码定位不到。

本脚本把 79+6 条与 verify_report 的 flag（FLIP 翻转 / C6 缺锚句 / 干净）做 join，
按处置难度分三档输出，供分批拍板：
  A_直接替换   —— verify 干净且仅 CWE 重归类（has_vuln 不变）
  B_补锚句后换 —— C6 近邻族缺互斥锚句
  C_人工终裁   —— FLIP 翻转（has_vuln 变化）或执行证据与重投冲突
产出：redistill_待替换清单_20260909.csv / .md
"""
import json, re, sys, os, hashlib, collections

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.normpath(os.path.join(ROOT, "..", "data", "final_train_chatml_alpha06_v2_16.jsonl"))
WAVE = os.path.join(ROOT, "..", "corpus", "redistill_wave")
OUT_CSV = os.path.join(ROOT, "redistill_待替换清单_20260909.csv")
OUT_MD = os.path.join(ROOT, "redistill_待替换清单_20260909.md")


def code_of(u):
    fs = re.findall(r"```[A-Za-z]*\n(.*?)```", u, re.S)
    return hashlib.md5(max(fs, key=len).strip().encode("utf-8", "replace")).hexdigest() if fs else None


def verd(a):
    b = re.findall(r"```json\s*(.*?)```", a, re.S)
    if not b:
        return None
    try:
        v = json.loads(b[-1].strip())
        m = re.search(r"CWE-(\d+)", str(v.get("vulnerability_type") or ""))
        return (v.get("has_vulnerability"), "CWE-" + m.group(1) if m else "")
    except Exception:
        return None


def main():
    rows16 = [json.loads(l) for l in open(DATA, encoding="utf-8")]
    idx16 = {}
    for i, r in enumerate(rows16, 1):
        u = [m["content"] for m in r["messages"] if m["role"] == "user"][0]
        h = code_of(u)
        if h:
            idx16[h] = i

    flags = {}
    for l in open(os.path.join(WAVE, "verify_report.jsonl"), encoding="utf-8"):
        r = json.loads(l)
        flags[str(r.get("id"))] = r.get("flags", [])
        if r.get("line"):
            flags[str(r["line"])] = r.get("flags", [])

    pending, nofind = [], []
    for l in open(os.path.join(WAVE, "merged_stage.jsonl"), encoding="utf-8"):
        r = json.loads(l)
        u = [m["content"] for m in r["messages"] if m["role"] == "user"][0]
        a = [m["content"] for m in r["messages"] if m["role"] == "assistant"][-1]
        rid = ""
        for m in r.get("messages", []):
            pass
        rid = str(r.get("id") or r.get("meta", {}).get("id") or "")
        h = code_of(u)
        ln = idx16.get(h)
        if not ln:
            nofind.append({"rid": rid, "flags": flags.get(rid, flags.get(rid.split("-")[-1], [])), "row": r})
            continue
        vnew, vold = verd(a), verd([m["content"] for m in rows16[ln - 1]["messages"] if m["role"] == "assistant"][-1])
        if vnew == vold:
            continue
        fl = flags.get(rid, flags.get(str(ln), []))
        is_flip = any("FLIP" in x for x in fl)
        is_c6 = any("C6" in x for x in fl)
        if is_flip or (vold and vnew and vold[0] != vnew[0]):
            tier = "C_人工终裁"
        elif is_c6:
            tier = "B_补锚句后换"
        else:
            tier = "A_直接替换"
        pending.append({"line": ln, "rid": rid, "old": vold, "new": vnew,
                        "flags": fl, "tier": tier})

    pending.sort(key=lambda x: x["tier"])
    with open(OUT_CSV, "w", encoding="utf-8-sig", newline="") as f:
        f.write("line,redistill_id,tier,old_has_vuln,old_cwe,new_has_vuln,new_cwe,flags,决定\n")
        for p in pending:
            o, n = p["old"] or ("", ""), p["new"] or ("", "")
            f.write(f'{p["line"]},{p["rid"]},{p["tier"]},{o[0]},{o[1]},{n[0]},{n[1]},"{"; ".join(p["flags"])}",\n')

    cnt = collections.Counter(p["tier"] for p in pending)
    md = ["# redistill 待替换清单（2026-09-09）", "",
          f"merged_stage 220 条：结论一致 {135 + (220 - len(pending) - len(nofind) - 79) if False else ''}"
          f"待替换 **{len(pending)}** 条，代码定位不到 **{len(nofind)}** 条", "",
          "| 档 | 数量 | 含义 |", "|---|---:|---|",
          f"| A_直接替换 | {cnt.get('A_直接替换',0)} | verify 干净，仅 CWE 重归类（has_vuln 不变）|",
          f"| B_补锚句后换 | {cnt.get('B_补锚句后换',0)} | C6 近邻族缺互斥锚句，补锚句后可换 |",
          f"| C_人工终裁 | {cnt.get('C_人工终裁',0)} | FLIP 翻转（has_vuln 变化），且部分与执行证据冲突 |", ""]
    for tier in ("C_人工终裁", "B_补锚句后换", "A_直接替换"):
        md.append(f"## {tier}")
        md.append("| 行号 | redistill id | 旧结论 | 新结论 | flags |")
        md.append("|---|---|---|---|---|")
        for p in [x for x in pending if x["tier"] == tier]:
            o, n = p["old"] or ("", ""), p["new"] or ("", "")
            md.append(f'| {p["line"]} | {p["rid"]} | {o[0]}/{o[1]} | {n[0]}/{n[1]} | {"; ".join(p["flags"])} |')
        md.append("")
    if nofind:
        md.append(f"## 代码定位不到（{len(nofind)} 条，需人工核对是新样本还是代码被改）")
        for x in nofind:
            md.append(f"- {x['rid']} flags={x['flags']}")
    open(OUT_MD, "w", encoding="utf-8").write("\n".join(md))

    print(f"待替换 {len(pending)} 条 / 定位不到 {len(nofind)} 条")
    for k, v in cnt.most_common():
        print(f"  {k}: {v}")
    print("CSV:", OUT_CSV)
    print("MD :", OUT_MD)


if __name__ == "__main__":
    main()
