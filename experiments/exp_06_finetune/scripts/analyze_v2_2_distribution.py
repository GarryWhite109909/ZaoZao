#!/usr/bin/env python3
"""alpha06-v2.2 训练集全量分布审计：CWE 分布 / 变体形态分布 / 难度代理分布。

用途：回答"类型/变体/难度分布是否合理、长尾是否伤害泛化、是否需要难度梯度"。
来源分段依据 build_alpha06_final_v2_2.py 的合并顺序（保序写出）：
  old -> distill(wave1) -> wave2+checklist -> taint -> blacklist -> evidence -> triage
"""
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DATA = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_alpha06_v2_2.jsonl")
TOK = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\cloud_train\tokenizer.json")

# 保序来源分段（行号区间，右开）
SEGS = [
    ("old", 0, 7599),
    ("wave1蒸馏", 7599, 8173),
    ("wave2+checklist", 8173, 8472),
    ("taint边界", 8472, 8611),
    ("blacklist对", 8611, 8635),
    ("evidence", 8635, 8672),
    ("triage", 8672, 8696),
]

STRONG_DEF = re.compile(r"参数化|白名单|转义|escape|占位符|\?\"|\?'|%s|autoescape|prepareStatement|placeholder|PreparedStatement|escapeshellarg|realpath|sanitize|Sanitized|Encode|encodeURI|ENT_QUOTES", re.I)
WEAK_DEF = re.compile(r"黑名单|blacklist|blocklist|re\.(?:search|match|sub)|\.replace\(|str_replace|过滤|filter\(|\bbanned\b|forbidden", re.I)


def seg_of(i):
    for name, lo, hi in SEGS:
        if lo <= i < hi:
            return name
    return "?"


def main():
    tok = None
    try:
        from tokenizers import Tokenizer
        tok = Tokenizer.from_file(str(TOK))
    except Exception as e:
        print(f"[警告] tokenizer 不可用（{e}），token 数按 chars/3 估算")

    rows = []
    with open(DATA, encoding="utf-8") as f:
        for i, line in enumerate(f):
            d = json.loads(line)
            msgs = d["messages"]
            user = next(m["content"] for m in msgs if m["role"] == "user")
            asst = next(m["content"] for m in msgs if m["role"] == "assistant")
            meta = d.get("meta") or {}
            # verdict JSON：取最后一个 json 块
            blocks = re.findall(r"```json\s*(\{.*?\})\s*```", asst, re.S)
            obj = None
            if blocks:
                try:
                    obj = json.loads(blocks[-1])
                except json.JSONDecodeError:
                    obj = None
            lang_m = re.search(r"语言[:：]\s*(\w+)", user)
            lang = lang_m.group(1).lower() if lang_m else None
            cm = re.search(r"```[\w+-]*\n(.*?)\n```", user, re.S)
            code = cm.group(1) if cm else user
            n_lines = code.count("\n") + 1
            hv = obj.get("has_vulnerability") if obj else None
            vt = obj.get("vulnerability_type") if obj else None
            risk = obj.get("risk_level") if obj else None
            cwe = None
            if isinstance(vt, str):
                m2 = re.match(r"(CWE-\d+)", vt)
                if m2:
                    cwe = m2.group(1)
            if tok:
                n_tok = len(tok.encode("".join(m["content"] for m in msgs)).ids)
            else:
                n_tok = len("".join(m["content"] for m in msgs)) // 3
            rows.append({
                "i": i, "seg": seg_of(i), "meta": meta, "lang": lang,
                "lines": n_lines, "tok": n_tok, "hv": hv, "vt": vt, "cwe": cwe,
                "risk": risk, "code": code, "obj": obj,
            })

    print(f"总行数: {len(rows)}")
    bad_json = [r for r in rows if r["obj"] is None]
    print(f"verdict JSON 不可解析: {len(bad_json)}（seg 分布 {Counter(r['seg'] for r in bad_json)}）")

    scan = [r for r in rows if r["seg"] not in ("evidence", "triage")]
    special = [r for r in rows if r["seg"] in ("evidence", "triage")]

    # ---------- 1. 方向分布 ----------
    print("\n===== 1. 方向分布（扫描类样本）=====")
    hv_c = Counter(str(r["hv"]) for r in scan)
    print(hv_c)
    for seg, lo, hi in SEGS:
        sub = [r for r in scan if r["seg"] == seg]
        if sub:
            c = Counter(str(r["hv"]) for r in sub)
            print(f"  {seg}: {dict(c)}")

    vuln = [r for r in scan if r["hv"] is True]
    safe = [r for r in scan if r["hv"] is False]

    # ---------- 2. CWE 分布 ----------
    print("\n===== 2. 漏洞类型（CWE）分布（vuln 样本）=====")
    cwe_c = Counter(r["cwe"] for r in vuln)
    n_v = len(vuln)
    print(f"vuln 样本 {n_v}，覆盖 CWE 类别 {len([k for k in cwe_c if k])} 个；无 CWE 编号: {cwe_c.get(None, 0)}")
    print(f"{'CWE':<12}{'条数':>6}{'占比':>9}{'安全侧同类':>10}")
    # 每类 CWE 的 safe 配对：安全样本 vt=none 无法配……看 meta.cwe
    safe_meta_cwe = Counter((r["meta"].get("cwe") or "").upper().replace(" ", "") for r in safe if r["meta"].get("cwe"))
    for k, v in cwe_c.most_common():
        if k is None:
            continue
        pct = v / n_v * 100
        print(f"{k:<12}{v:>6}{pct:>8.1f}%{safe_meta_cwe.get(k, 0):>10}")
    if None in cwe_c:
        print(f"{'(无编号)':<12}{cwe_c[None]:>6}{cwe_c[None]/n_v*100:>8.1f}%")

    # 长尾
    print("\n-- 长尾（vuln<30 条的 CWE）--")
    tail = [(k, v) for k, v in cwe_c.most_common() if k and v < 30]
    print(f"共 {len(tail)} 类、合计 {sum(v for _, v in tail)} 条（占 vuln {sum(v for _, v in tail)/n_v*100:.1f}%）")
    for k, v in sorted(tail, key=lambda x: x[1]):
        print(f"  {k}: {v}")

    # ---------- 3. 变体形态分布 ----------
    print("\n===== 3. 变体形态分布 =====")
    print("-- wave1 蒸馏 meta.kind --")
    print(Counter(r["meta"].get("kind") for r in rows if r["seg"] == "wave1蒸馏"))
    print("-- wave2+checklist meta.kind / form --")
    print(Counter(r["meta"].get("kind") for r in rows if r["seg"] == "wave2+checklist"))
    print(Counter(r["meta"].get("form") for r in rows if r["seg"] == "wave2+checklist"))
    print("-- taint 边界 form×kind --")
    tk = Counter((r["meta"].get("form"), r["meta"].get("kind")) for r in rows if r["seg"] == "taint边界")
    for k, v in sorted(tk.items(), key=lambda x: str(x[0])):
        print(f"  {k}: {v}")
    print("-- taint CWE 分布 --")
    print(Counter(r["meta"].get("cwe") for r in rows if r["seg"] == "taint边界").most_common())
    print("-- blacklist pair CWE --")
    print(Counter(r["meta"].get("cwe") for r in rows if r["seg"] == "blacklist对"))
    print("-- blacklist kind --")
    print(Counter(r["meta"].get("kind") for r in rows if r["seg"] == "blacklist对"))
    print("-- evidence/triage 结论字段 --")
    print(Counter("is_confirmed" if (r["obj"] and "is_confirmed" in r["obj"]) else ("has_vulnerability" if r["obj"] else "unparsable") for r in special))

    # ---------- 4. 语言分布 ----------
    print("\n===== 4. 语言分布（扫描类）=====")
    lang_c = Counter(r["lang"] for r in scan)
    print(lang_c)
    print("-- 语言 × 方向 --")
    cross = Counter((r["lang"], str(r["hv"])) for r in scan)
    langs = sorted(k for k in lang_c if k)
    print(f"{'lang':<12}{'vuln':>7}{'safe':>7}{'合计':>7}")
    for lg in langs:
        v = cross.get((lg, "True"), 0)
        s = cross.get((lg, "False"), 0)
        print(f"{lg:<12}{v:>7}{s:>7}{v+s:>7}")

    # ---------- 5. 难度代理 ----------
    print("\n===== 5. 难度代理分布 =====")
    def bucket(n):
        if n < 20: return "<20"
        if n < 50: return "20-49"
        if n < 100: return "50-99"
        if n < 200: return "100-199"
        if n < 400: return "200-399"
        return ">=400"
    print("-- 代码行数分桶（vuln / safe）--")
    lb_v = Counter(bucket(r["lines"]) for r in vuln)
    lb_s = Counter(bucket(r["lines"]) for r in safe)
    for b in ["<20", "20-49", "50-99", "100-199", "200-399", ">=400"]:
        print(f"  {b:<9} vuln {lb_v.get(b,0):>5} | safe {lb_s.get(b,0):>5}")

    def tbucket(n):
        if n < 512: return "<512"
        if n < 1024: return "512-1k"
        if n < 2048: return "1k-2k"
        if n < 4096: return "2k-4k"
        if n < 8192: return "4k-8k"
        return ">=8k"
    print("-- 总 token 分桶 --")
    tb = Counter((tbucket(r["tok"]), str(r["hv"])) for r in scan)
    for b in ["<512", "512-1k", "1k-2k", "2k-4k", "4k-8k", ">=8k"]:
        print(f"  {b:<9} vuln {tb.get((b,'True'),0):>5} | safe {tb.get((b,'False'),0):>5}")
    import statistics
    toks = [r["tok"] for r in scan]
    print(f"  token 中位数 {statistics.median(toks):.0f} / 均值 {statistics.mean(toks):.0f} / p90 {sorted(toks)[int(len(toks)*0.9)]} / max {max(toks)}")

    print("-- safe 样本防御形态（代码内正则探测）--")
    dsafe = Counter()
    for r in safe:
        st = bool(STRONG_DEF.search(r["code"]))
        wk = bool(WEAK_DEF.search(r["code"]))
        dsafe["strong" if st else ("weak" if wk else "none")] += 1
    print(dsafe)
    print("-- vuln 样本含强防御形态（= 绕过型 hard 样本）--")
    dv = Counter()
    for r in vuln:
        st = bool(STRONG_DEF.search(r["code"]))
        wk = bool(WEAK_DEF.search(r["code"]))
        dv[("strong" if st else "") + ("+" if st and wk else "") + ("weak" if wk and not st else "") or "none"] += 1
    print(dv)

    print("-- risk_level 分布（vuln）--")
    print(Counter(r["risk"] for r in vuln))

    # ---------- 6. CWE × 语言 稀疏矩阵 ----------
    print("\n===== 6. CWE × 语言（vuln 样本，仅头部 15 类 + 长尾汇总）=====")
    top = [k for k, _ in cwe_c.most_common(15) if k]
    langset = sorted(k for k in lang_c if k)
    hdr = f"{'CWE':<10}" + "".join(f"{l[:6]:>8}" for l in langset) + f"{'合计':>8}"
    print(hdr)
    mat = Counter((r["cwe"], r["lang"]) for r in vuln)
    for cw in top:
        line = f"{cw:<10}" + "".join(f"{mat.get((cw, l), 0):>8}" for l in langset) + f"{cwe_c[cw]:>8}"
        print(line)
    tailset = set(k for k, v in cwe_c.items() if k and v < 30)
    line = f"{'长尾合计':<10}" + "".join(f"{sum(mat.get((c, l), 0) for c in tailset):>8}" for l in langset) + f"{sum(v for k, v in cwe_c.items() if k in tailset):>8}"
    print(line)
    # 单语言单 CWE 覆盖率
    cells = sum(1 for c in cwe_c if c for l in langset if mat.get((c, l), 0) > 0)
    total_cells = len([c for c in cwe_c if c]) * len(langset)
    print(f"CWE×语言 非空格子: {cells}/{total_cells} = {cells/total_cells*100:.0f}%")

    # ---------- 7. safe 侧的 CWE 多样性（safe 样本教什么防御）----------
    print("\n===== 7. safe 样本来源与 meta.cwe 覆盖 =====")
    safe_by_seg = Counter(r["seg"] for r in safe)
    print(safe_by_seg)
    safe_old = [r for r in safe if r["seg"] == "old"]
    print(f"old safe {len(safe_old)} 条无 meta（CWE 覆盖不可考，按代码形态分布）")

    print("\n===== 8. evidence/triage 方向 =====")
    for r in special:
        o = r["obj"] or {}
        conf = o.get("is_confirmed")
        if conf is None and "has_vulnerability" in o:
            conf = o.get("has_vulnerability")
        print(f"  #{r['i']} {r['seg']}: is_confirmed={conf}", end="")
        if r["seg"] == "evidence":
            print(f" fix_applied={o.get('fix_applied', o.get('verified'))}", end="")
        print()


if __name__ == "__main__":
    main()
