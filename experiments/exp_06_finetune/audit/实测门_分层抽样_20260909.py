# -*- coding: utf-8 -*-
"""
实测门分层抽样清单（2026-09-09）

用途：把实测门从「逐条清洗工具」改成「总体错标率测量工具」。
      按 (语言 × has_vuln) 分层，在 CWE 头部族上加密，抽 N 条作为人工/L1 精审样本。
      在这批样本上得到的错标率，可带权回推全库，给出**带置信区间的标签噪声估计**——
      这比多修几十条样本对论文和方法论的价值大得多。

产出：实测门_分层抽样清单_20260909.jsonl / .csv
"""
import json, re, sys, os, random, collections

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.normpath(os.path.join(ROOT, "..", "data", "final_train_chatml_alpha06_v2_17.jsonl"))
OUT_J = os.path.join(ROOT, "实测门_分层抽样清单_20260909.jsonl")
OUT_C = os.path.join(ROOT, "实测门_分层抽样清单_20260909.csv")

TOTAL_N = 340          # 目标样本量（C 层已跑 340，保持同量级可比）
HEAD_CWE = {"CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-22", "CWE-327",
            "CWE-798", "CWE-416", "CWE-125", "CWE-787", "CWE-502", "CWE-918"}
OVERSAMPLE = 1.6       # 头部 CWE 加密倍率
SEED = 20260909


def main():
    random.seed(SEED)
    rows = []
    with open(DATA, encoding="utf-8") as f:
        for i, l in enumerate(f):
            l = l.strip()
            if not l:
                continue
            ln = i + 1
            try:
                r = json.loads(l)
            except Exception:
                continue
            u = a = ""
            for m in r.get("messages", []):
                if m.get("role") == "user":
                    u = m.get("content", "")
                elif m.get("role") == "assistant":
                    a = m.get("content", "")
            lhm = re.search(r"语言[:：]\s*([^\s）)]+)", u)
            lang = (lhm.group(1) if lhm else "?").lower()
            hv = None
            cwe = ""
            b = re.findall(r"```json\s*(.*?)```", a, re.S)
            if b:
                try:
                    v = json.loads(b[-1].strip())
                    hv = v.get("has_vulnerability")
                    if isinstance(hv, str):
                        hv = hv.strip().lower() in ("true", "yes", "1")
                    m = re.search(r"CWE-(\d+)", str(v.get("vulnerability_type") or ""))
                    cwe = "CWE-" + m.group(1) if m else ""
                except Exception:
                    pass
            # 语言归一化：先剥"X，多文件项目"后缀，再映射别名
            lang = re.split(r"[，,、/（(]", lang)[0].strip()
            lang = {"c++": "cpp", "cpp": "cpp", "c#": "csharp", "cs": "csharp",
                    "py": "python", "js": "javascript", "node": "javascript",
                    "node.js": "javascript", "ts": "javascript", "typescript": "javascript",
                    "golang": "go", "sh": "bash", "shell": "bash", "yml": "yaml",
                    "docker": "dockerfile", "conf": "ini", "properties": "ini"}.get(lang, lang)
            rows.append({"line": ln, "lang": lang, "has_vuln": hv, "cwe": cwe})

    n = len(rows)
    strata = collections.defaultdict(list)
    for r in rows:
        strata[(r["lang"], bool(r["has_vuln"]))].append(r)

    # 按比例分配，头部 CWE 层（vuln 侧）加密
    out = []
    for (lang, hv), items in sorted(strata.items(), key=lambda x: -len(x[1])):
        share = len(items) / n
        k = max(4, round(TOTAL_N * share))
        if hv and lang in ("python", "javascript", "go", "c", "cpp", "php", "java"):
            k = round(k * OVERSAMPLE)
        k = min(k, len(items))
        picked = random.sample(items, k)
        for p in picked:
            p["stratum"] = f"{lang}|{'vuln' if hv else 'safe'}"
            p["stratum_n"] = len(items)
            p["oversampled"] = bool(hv and lang in ("python", "javascript", "go", "c", "cpp", "php", "java"))
            out.append(p)
    out.sort(key=lambda x: x["line"])

    with open(OUT_J, "w", encoding="utf-8") as f:
        for o in out:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    with open(OUT_C, "w", encoding="utf-8-sig", newline="") as f:
        f.write("line,lang,has_vuln,cwe,stratum,stratum_n,oversampled,verdict,verdict_basis\n")
        for o in out:
            f.write(f"{o['line']},{o['lang']},{o['has_vuln']},{o['cwe']},{o['stratum']},"
                    f"{o['stratum_n']},{int(o['oversampled'])},,\n")

    cnt = collections.Counter(o["stratum"] for o in out)
    print(f"总体 {n} 行 → 抽样 {len(out)} 条（{100.0*len(out)/n:.2f}%）")
    print("分层分布（层规模 → 抽样数）:")
    for (lang, hv), items in sorted(strata.items(), key=lambda x: -len(x[1])):
        k = f"{lang}|{'vuln' if hv else 'safe'}"
        print(f"  {k:<22} {len(items):>5} → {cnt.get(k,0):>4}")
    print(f"\n落盘: {os.path.basename(OUT_J)} / {os.path.basename(OUT_C)}")


if __name__ == "__main__":
    main()
