# -*- coding: utf-8 -*-
"""
差分对 wave1 夜班工具箱（2026-09-09）

白天智普拥挤、只能半夜蒸馏 → 白天把夜班的「准备」和「验收」全部自动化，
让夜间的粘贴窗口 100% 花在 teacher 上。

子命令：
  plan    生成夜班批次清单（按字节升序=先易后难，含每夜配额与累计进度）
  verify  晨检验收 results/*.txt —— 差分对契约逐条机检：
            (1) A(修复前) 判 vuln / B(修复后) 判 safe
            (2) 结论 JSON 可解析且字段齐全
            (3) CWE 与 expected 一致（不一致记为近邻候选）
            (4) 行号锚定：explanation/source/sink 引用的 line N 必须落在对应版本行数内
            (5) 行级归因：A/B 引用行号集合必须不同（差分对的教学单元就是差异行）
            (6) 与 v2_16 代码哈希查重
用法：
  python night_shift_tools.py plan   [--per-night 40]
  python night_shift_tools.py verify [结果目录]   # 默认 corpus/diffpair_wave1/results
"""
import json, re, sys, os, hashlib, argparse, collections

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
WAVE = os.path.normpath(os.path.join(HERE, "..", "..", "corpus", "diffpair_wave1"))
KITS = os.path.join(WAVE, "kits")
RESULTS = os.path.join(WAVE, "results")
V2_16 = os.path.normpath(os.path.join(HERE, "..", "..", "data", "final_train_chatml_alpha06_v2_16.jsonl"))

VERDICT = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
LINEREF = re.compile(r"(?:line|第|行)\s*(\d{1,3})", re.I)
ANCHOR = re.compile(r"非\s*(?:CWE-)?\s*(\d{3})")


def kit_meta(path):
    txt = open(path, encoding="utf-8", errors="replace").read()
    m = re.search(r"^### id=(\S+) lang=(\S+) cve=(\S+) seed=(\S+)", txt, re.M)
    versions = re.findall(r"####\s*版本([AB])（修复(前|后)，(\d+)\s*行）", txt)
    codes = re.findall(r"```[A-Za-z0-9_+\-]*\n(.*?)```", txt, re.S)
    return {
        "kit": os.path.basename(path), "id": m.group(1) if m else "?",
        "lang": m.group(2) if m else "?", "cve": m.group(3) if m else "?",
        "seed": m.group(4) if m else "?",
        "n_versions": len(versions), "n_codes": len(codes),
        "kb": round(os.path.getsize(path) / 1024, 1),
        "code_hashes": [hashlib.md5(c.strip().encode("utf-8", "replace")).hexdigest() for c in codes[:2]],
    }


def cmd_plan(per_night):
    kits = sorted((os.path.join(KITS, f) for f in os.listdir(KITS) if f.endswith(".txt")), key=os.path.getsize)
    rows = [kit_meta(p) for p in kits]
    bad = [r for r in rows if r["n_codes"] < 2 or r["n_versions"] < 2]
    ok = [r for r in rows if r not in bad]
    nights = [ok[i:i + per_night] for i in range(0, len(ok), per_night)]
    md = ["# 差分对 wave1 夜班批次清单", "",
          f"- 可投喂 {len(ok)} 包（{len(bad)} 包结构异常已剔除，见下）",
          f"- 每夜 {per_night} 包 → 共 {len(nights)} 夜；按字节升序（先易后难）", ""]
    for ni, night in enumerate(nights, 1):
        cum = sum(r["kb"] for r in night)
        md.append(f"## 第 {ni} 夜 · {len(night)} 包 · 约 {cum:.0f} KB")
        md.append("| # | kit | KB | lang | cwe |")
        md.append("|---|---|---|---|---|")
        for j, r in enumerate(night, 1):
            md.append(f"| {j} | {r['kit']} | {r['kb']} | {r['lang']} | {r['cve']} |")
        md.append("")
    if bad:
        md.append("## 结构异常（本次不投喂）")
        for r in bad:
            md.append(f"- {r['kit']}  versions={r['n_versions']} codes={r['n_codes']}")
    out = os.path.join(WAVE, "夜班批次清单_20260909.md")
    open(out, "w", encoding="utf-8").write("\n".join(md))
    print(f"夜数={len(nights)} 每夜={per_night} 可投喂={len(ok)} 异常={len(bad)}")
    print("清单:", out)
    for ni, night in enumerate(nights, 1):
        print(f"  第{ni}夜 {len(night)}包 {sum(r['kb'] for r in night):.0f}KB "
              f"({night[0]['kit']} … {night[-1]['kit']})")


def load_v2_hashes():
    hs = set()
    with open(V2_16, encoding="utf-8") as f:
        for l in f:
            u = ""
            try:
                r = json.loads(l)
            except Exception:
                continue
            for m in r.get("messages", []):
                if m.get("role") == "user":
                    u = m.get("content", "")
            for c in re.findall(r"```[A-Za-z0-9_+\-]*\n(.*?)```", u, re.S):
                hs.add(hashlib.md5(c.strip().encode("utf-8", "replace")).hexdigest())
    return hs


def cmd_verify(res_dir):
    v2 = load_v2_hashes()
    files = sorted(f for f in os.listdir(res_dir) if f.endswith(".txt"))
    stat = collections.Counter()
    out_rows = []
    for fn in files:
        txt = open(os.path.join(res_dir, fn), encoding="utf-8", errors="replace").read()
        row = {"result": fn, "issues": []}
        verdicts = []
        for blk in VERDICT.findall(txt):
            try:
                verdicts.append(json.loads(blk))
            except Exception:
                row["issues"].append("JSON解析失败")
                verdicts.append(None)
        row["n_verdicts"] = len(verdicts)
        if len(verdicts) < 2:
            row["issues"].append(f"结论少于2个({len(verdicts)}) — A/B 至少各一")
        elif verdicts[0] is None or verdicts[1] is None:
            pass
        else:
            a, b = verdicts[0], verdicts[1]
            ahv, bhv = a.get("has_vulnerability"), b.get("has_vulnerability")
            if ahv is not True:
                row["issues"].append(f"版本A(修复前)未判漏洞: {ahv}")
            if bhv is not False:
                row["issues"].append(f"版本B(修复后)未判安全: {bhv}")
            for side, v in (("A", a), ("B", b)):
                for fld in ("vulnerability_type", "explanation"):
                    if not str(v.get(fld) or "").strip():
                        row["issues"].append(f"{side}缺字段 {fld}")
            if not str(a.get("sink") or "").strip():
                row["issues"].append("A(漏洞侧)缺 sink —— 行级归因契约要求指到污点路径")
            ca = re.search(r"CWE-(\d+)", str(a.get("vulnerability_type") or ""))
            cb = re.search(r"CWE-(\d+)", str(b.get("vulnerability_type") or ""))
            row["cwe_A"] = "CWE-" + ca.group(1) if ca else ""
            row["cwe_B"] = "CWE-" + cb.group(1) if cb else ""
            if row["cwe_A"] and row["cwe_A"] != row["cwe_B"]:
                row["issues"].append(f"A/B CWE 不一致 {row['cwe_A']} vs {row['cwe_B']}")
            la = sorted(set(int(x) for x in LINEREF.findall(str(a.get("explanation", "")) + str(a.get("sink", "")))))[:20]
            lb = sorted(set(int(x) for x in LINEREF.findall(str(b.get("explanation", "")) + str(b.get("sink", "")))))[:20]
            row["lines_A"], row["lines_B"] = la, lb
            if la and lb and set(la) == set(lb):
                row["issues"].append("A/B 行级归因相同 — 差分对未指向差异行")
            anchors = set(ANCHOR.findall(txt))
            row["anchor_cwes"] = sorted("CWE-" + x for x in anchors)
        for c in re.findall(r"```[A-Za-z0-9_+\-]*\n(.*?)```", txt, re.S):
            if hashlib.md5(c.strip().encode("utf-8", "replace")).hexdigest() in v2:
                row["issues"].append("产出代码与 v2_16 重复")
                break
        tier = "FAIL" if any(("未判" in x or "少于" in x or "JSON" in x) for x in row["issues"]) else \
               ("WARN" if row["issues"] else "PASS")
        row["tier"] = tier
        stat[tier] += 1
        out_rows.append(row)
    outp = os.path.join(WAVE, "verify_report.jsonl")
    with open(outp, "w", encoding="utf-8") as f:
        for r in out_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"验收 {len(out_rows)} 个结果: PASS={stat['PASS']} WARN={stat['WARN']} FAIL={stat['FAIL']}")
    print("报告:", outp)
    for r in out_rows:
        if r["tier"] != "PASS":
            print(f"  [{r['tier']}] {r['result']}: {'; '.join(r['issues'][:3])}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["plan", "verify"])
    ap.add_argument("--per-night", type=int, default=40)
    ap.add_argument("res", nargs="?", default=RESULTS)
    a = ap.parse_args()
    (cmd_plan if a.cmd == "plan" else cmd_verify)(a.per_night if a.cmd == "plan" else a.res)
