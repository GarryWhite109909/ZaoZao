# -*- coding: utf-8 -*-
"""
近重复簇 × 标签一致性分析（2026-09-09）

原理：同一「近重复簇」内的样本是同源代码的不同化身（同文件/同叙事/同 CVE 的变体）。
      按簇不变量约束，同簇样本**应当**持有相同的 has_vuln 与相近的 CWE 归类。
      一旦簇内出现 has_vuln 相反、或 CWE 分叉，就不可能是"两个都对的独立判断"——
      必然至少有一方错标。这是**零人工、全量、可解释**的错标挖掘机，
      比逐条实测（覆盖率 <60%）便宜两个数量级。

产出：实测门_簇内标签冲突_20260909.jsonl + 控制台摘要
"""
import json, re, sys, os, collections

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.normpath(os.path.join(ROOT, "..", "data", "final_train_chatml_alpha06_v2_16.jsonl"))
CLUSTER = os.path.join(ROOT, "scan_v2_16_l3_cluster_flags.json")
OUT = os.path.join(ROOT, "实测门_簇内标签冲突_20260909.jsonl")


def load_labels():
    lab = {}
    with open(DATA, encoding="utf-8") as f:
        for i, l in enumerate(f):
            l = l.strip()
            if not l:
                continue
            ln = i + 1
            try:
                row = json.loads(l)
            except Exception:
                lab[ln] = (None, "")
                continue
            asst = ""
            user = ""
            for m in row.get("messages", []):
                if m.get("role") == "assistant":
                    asst = m.get("content", "")
                elif m.get("role") == "user":
                    user = m.get("content", "")
            hv, cwe = None, ""
            blocks = re.findall(r"```json\s*(.*?)```", asst, re.S)
            if blocks:
                try:
                    v = json.loads(blocks[-1].strip())
                    hv = v.get("has_vulnerability")
                    if isinstance(hv, str):
                        hv = hv.strip().lower() in ("true", "yes", "1")
                    m = re.search(r"CWE-(\d+)", str(v.get("vulnerability_type") or ""))
                    cwe = "CWE-" + m.group(1) if m else ""
                except Exception:
                    pass
            lhm = re.search(r"语言[:：]\s*([^\s）)]+)", user)
            lab[ln] = (hv, cwe, lhm.group(1) if lhm else "")
    return lab


def main():
    lab = load_labels()
    cl = json.load(open(CLUSTER, encoding="utf-8"))
    hv_conf, cwe_conf, stats = [], [], {"clusters": 0, "rows": 0}
    for c in cl.get("clusters", []):
        rr = [int(x) for x in c.get("rows_1based", [])]
        if len(rr) < 2:
            continue
        stats["clusters"] += 1
        stats["rows"] += len(rr)
        rows = [(r, lab.get(r, (None, "", ""))) for r in rr if r in lab]
        hvs = [x[1][0] for x in rows if x[1][0] is not None]
        cwes = [x[1][1] for x in rows if x[1][1]]
        langs = [x[1][2] for x in rows if x[1][2]]
        if len(set(hvs)) > 1:
            hv_conf.append({
                "cluster_rows": rr,
                "size": len(rr),
                "lang": collections.Counter(langs).most_common(1)[0][0] if langs else "",
                "detail": [{"line": r, "has_vuln": v[0], "cwe": v[1]} for r, v in rows],
                "n_true": sum(1 for x in hvs if x), "n_false": sum(1 for x in hvs if not x),
            })
        # CWE 分叉只在同为 vuln 的样本间比较（safe 样本无 CWE）
        vuln_cwes = [x[1][1] for x in rows if x[1][0] is True and x[1][1]]
        if len(set(vuln_cwes)) > 1:
            cwe_conf.append({
                "cluster_rows": rr,
                "size": len(rr),
                "lang": collections.Counter(langs).most_common(1)[0][0] if langs else "",
                "cwe_dist": collections.Counter(vuln_cwes).most_common(),
                "detail": [{"line": r, "has_vuln": v[0], "cwe": v[1]} for r, v in rows],
            })

    hv_conf.sort(key=lambda x: -x["size"])
    cwe_conf.sort(key=lambda x: -x["size"])
    with open(OUT, "w", encoding="utf-8") as f:
        for x in hv_conf:
            x["conflict"] = "has_vuln"
        for x in cwe_conf:
            x["conflict"] = "cwe"
        for x in hv_conf + cwe_conf:
            f.write(json.dumps(x, ensure_ascii=False) + "\n")

    print("=== 近重复簇标签一致性 ===")
    print(f"多成员簇        : {stats['clusters']} 组 / {stats['rows']} 行")
    print(f"簇内 has_vuln 冲突: {len(hv_conf)} 组 / {sum(len(x['cluster_rows']) for x in hv_conf)} 行")
    print(f"簇内 CWE 分叉     : {len(cwe_conf)} 组 / {sum(len(x['cluster_rows']) for x in cwe_conf)} 行")
    print()
    print("--- has_vuln 冲突（前 12 组，按簇规模）---")
    for x in hv_conf[:12]:
        print(f"  簇{x['size']:>2} 行 {x['lang']:>10}  T={x['n_true']} F={x['n_false']}  rows={x['cluster_rows'][:8]}{'...' if x['size']>8 else ''}")
    print()
    print("--- CWE 分叉（前 12 组）---")
    for x in cwe_conf[:12]:
        print(f"  簇{x['size']:>2} 行 {x['lang']:>10}  {x['cwe_dist']}  rows={x['cluster_rows'][:8]}{'...' if x['size']>8 else ''}")
    print(f"\n明细已落盘: {os.path.basename(OUT)}")


if __name__ == "__main__":
    main()
