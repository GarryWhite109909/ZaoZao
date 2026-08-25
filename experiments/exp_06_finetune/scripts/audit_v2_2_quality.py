#!/usr/bin/env python3
"""alpha06-v2.2 补充审计：CoT-结论一致性 / 近重复 / fix_suggestion 质量 / safe 侧 CWE-77 粒度。

支撑《数据分布审计》第七节之外的数据质量维度检查。
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DATA = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_alpha06_v2_2.jsonl")
SEGS = [
    ("old", 0, 7599), ("wave1", 7599, 8173), ("wave2+checklist", 8173, 8472),
    ("taint", 8472, 8611), ("blacklist", 8611, 8635), ("evidence", 8635, 8672),
    ("triage", 8672, 8696),
]


def seg_of(i):
    for name, lo, hi in SEGS:
        if lo <= i < hi:
            return name
    return "?"


def shingle_sig(code: str, n=8, k=40):
    """8-gram 词级 shingle 签名，取 hash 前 k 个，用于近重复粗筛。"""
    words = re.sub(r"\s+", " ", code.lower()).split()
    if len(words) < n:
        return set()
    return {hash(" ".join(words[i:i+n])) for i in range(len(words) - n + 1)}


def main():
    rows = []
    with open(DATA, encoding="utf-8") as f:
        for i, line in enumerate(f):
            d = json.loads(line)
            user = next(m["content"] for m in d["messages"] if m["role"] == "user")
            asst = next(m["content"] for m in d["messages"] if m["role"] == "assistant")
            meta = d.get("meta") or {}
            blocks = re.findall(r"```json\s*(\{.*?\})\s*```", asst, re.S)
            obj = json.loads(blocks[-1]) if blocks else {}
            cm = re.search(r"```[\w+-]*\n(.*?)\n```", user, re.S)
            code = cm.group(1) if cm else user
            rows.append({"i": i, "seg": seg_of(i), "user": user, "asst": asst,
                         "meta": meta, "obj": obj, "code": code})

    scan = [r for r in rows if r["seg"] not in ("evidence", "triage")]

    # ---------- 1. CoT 与结论方向一致性 ----------
    print("===== 1. CoT-结论方向自相矛盾检测 =====")
    # 启发式：分析段（json 块之前）出现明确的"安全/无漏洞/不构成"结论句，
    # 但 verdict 报 vuln；或反之出现"存在漏洞/可被注入"但 verdict 报 safe。
    SAFE_CLAIM = re.compile(r"(代码?(是安全|不存在|无)漏洞|不构成漏洞|可以?判定为安全|没有安全风险|无风险)")
    VULN_CLAIM = re.compile(r"(存在(安全)?漏洞|构成(安全)?漏洞|确实?(存在|可被).{0,12}(注入|溢出|穿越|执行|泄露)|是(一个)?漏洞)")
    contra = []
    for r in scan:
        hv = r["obj"].get("has_vulnerability")
        if hv is None:
            continue
        cot = r["asst"].split("```json")[0]
        s_claim = SAFE_CLAIM.search(cot)
        v_claim = VULN_CLAIM.search(cot)
        if hv is True and s_claim and not v_claim:
            contra.append((r["i"], r["seg"], "CoT说安全/结论报漏洞", s_claim.group(0)[:30]))
        elif hv is False and v_claim and not s_claim:
            contra.append((r["i"], r["seg"], "CoT说有漏洞/结论报安全", v_claim.group(0)[:30]))
    print(f"疑似自相矛盾: {len(contra)} 条（启发式，需人工复核）")
    for c in contra[:15]:
        print(f"  #{c[0]}[{c[1]}] {c[2]}: 「{c[3]}」")
    print(Counter(c[1] for c in contra))

    # ---------- 2. 近重复（改写型） ----------
    print("\n===== 2. 近重复检测（shingle Jaccard，粗筛）=====")
    sigs = []
    for r in scan:
        sigs.append((r["i"], r["seg"], shingle_sig(r["code"])))
    # 分段两两比太贵：用倒排（每个 shingle -> 行列表），只比对共享 shingle 多的对
    from collections import defaultdict
    inv = defaultdict(list)
    for i, seg, sig in sigs:
        for s in sig:
            inv[s].append(i)
    pair_count = Counter()
    for s, lst in inv.items():
        if 1 < len(lst) <= 5:  # 高频 shingle 跳过（模板/习语）
            for a in range(len(lst)):
                for b in range(a + 1, len(lst)):
                    pair_count[(lst[a], lst[b])] += 1
    cand = [(p, c) for p, c in pair_count.items() if c >= 60]
    near_dup = []
    seen_pair = set()
    for (a, b), c in sorted(cand, key=lambda x: -x[1]):
        if (a, b) in seen_pair:
            continue
        seen_pair.add((a, b))
        sa = dict(sigs)[a] if False else None
        sig_a = next(s for i, _, s in sigs if i == a)
        sig_b = next(s for i, _, s in sigs if i == b)
        j = len(sig_a & sig_b) / len(sig_a | sig_b) if sig_a | sig_b else 0
        if j >= 0.7:
            near_dup.append((a, b, round(j, 3)))
    print(f"Jaccard>=0.7 的近重复对: {len(near_dup)}（构建去重门用 md5 尾部哈希，改写型可漏检）")
    for a, b, j in near_dup[:20]:
        print(f"  #{a} ~ #{b} J={j} seg={seg_of(a)}/{seg_of(b)}")

    # ---------- 3. fix_suggestion 可执行性 ----------
    print("\n===== 3. fix_suggestion 字段质量（vuln 样本）=====")
    vuln = [r for r in scan if r["obj"].get("has_vulnerability") is True]
    miss = [r for r in vuln if not str(r["obj"].get("fix_suggestion") or "").strip()]
    empty_like = [r for r in vuln if str(r["obj"].get("fix_suggestion") or "").strip() in
                  ("无", "N/A", "none", "None", "-", "暂无")]
    print(f"vuln {len(vuln)} 条中 fix_suggestion 缺失: {len(miss)}，空值占位: {len(empty_like)}")
    print("缺失分布:", Counter(r["seg"] for r in miss))
    # 行号锚定率：fix_suggestion 是否引用具体行号（可执行性的代理）
    anchored = [r for r in vuln if re.search(r"line\s*\d+|第\s*\d+\s*行|L\d+", str(r["obj"].get("fix_suggestion")))]
    print(f"fix_suggestion 带行号锚定: {len(anchored)}/{len(vuln)} = {len(anchored)/len(vuln)*100:.0f}%")
    # 代码引用率：是否给出改后代码形态（应改为/改为/替换）
    codefix = [r for r in vuln if re.search(r"应改为|改为|替换|修改为|使用\s*`|改用", str(r["obj"].get("fix_suggestion")))]
    print(f"fix_suggestion 含改法指令（应改为/替换/改用）: {len(codefix)}/{len(vuln)} = {len(codefix)/len(vuln)*100:.0f}%")
    by_seg = Counter(r["seg"] for r in miss)
    if miss:
        print("缺失样例:")
        for r in miss[:5]:
            print(f"  #{r['i']}[{r['seg']}] vt={r['obj'].get('vulnerability_type')}")

    # ---------- 4. safe 侧 meta.cwe=CWE-77 的 13 条 ----------
    print("\n===== 4. safe 侧 meta.cwe=CWE-77 粒度核查 =====")
    for r in scan:
        mc = (r["meta"].get("cwe") or "").strip()
        if mc == "CWE-77":
            print(f"  #{r['i']}[{r['seg']}] kind={r['meta'].get('kind')} seed={r['meta'].get('seed_file')}")

    # ---------- 5. 极长尾争议归并清单 ----------
    print("\n===== 5. 极长尾（<10 条）逐条盘点（供 v2.3 人工归并复核）=====")
    cwe_c = Counter()
    for r in scan:
        if r["obj"].get("has_vulnerability") is True:
            m = re.match(r"(CWE-\d+)", str(r["obj"].get("vulnerability_type") or ""))
            if m:
                cwe_c[m.group(1)] += 1
    for cw, n in cwe_c.most_common():
        if n < 10:
            idxs = [r["i"] for r in scan
                    if r["obj"].get("has_vulnerability") is True
                    and str(r["obj"].get("vulnerability_type") or "").startswith(cw)]
            print(f"  {cw} ({n}): rows {idxs}")


if __name__ == "__main__":
    main()
