#!/usr/bin/env python3
"""alpha06-v2.10 行号吸附二段升级（v2.9 残余 38% 的两类病灶，2026-08-28）。

v2.9 吸附（±5 窗口唯一 token 命中）之后的残余不吸附分两类：
  A. 老 C 层整记录系统性偏移（10+ 行）：教师数行口径整体错位，窗口放多宽都够不着，
     且跨行独立吸附会互相打架 → 记录级常数偏移投票（k 从无歧义引用中估计，
     ≥3 票且过半数才生效），逐条引用再做"目标行确含 token"证据校验后才改写；
  B. 同 token 多候选：唯一命中约束直接放弃 → 多 token 计分消歧（token 池 3→5、
     ±5 内按命中 token 数打分，最高分 ≥2 且领先第二名 ≥1 才吸附）。

度量口径与 v2.9 报告一致：精确命中=声称行含任一 token（top-3）。
只动 source/sink/fix_suggestion 契约字段；多文件（# === file:）与 N| 注解记录跳过。
单一 obj 权威：两段都只改结构化对象，最后一次性回写 JSON 块，杜绝文本手术错位。
"""
import json
import re
from collections import Counter
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SRC = BASE / "data/final_train_chatml_alpha06_v2_9.jsonl"
OUT = BASE / "data/final_train_chatml_alpha06_v2_10.jsonl"
REPORT = BASE / "data/build_alpha06_v2_10_report.md"
FIELDS = ("source", "sink", "fix_suggestion")
STOP = {"the", "this", "and", "into", "from", "with", "line", "via", "then",
        "when", "after", "before", "not", "are", "was", "参数", "漏洞"}

REF_RE = re.compile(r"([Ll]ine\s+)(\d+)")


def tokens_after(val: str, pos: int, n: int = 5):
    desc = val[pos: pos + 110]
    toks = [t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_.]{2,}", desc)
            if t.lower().split(".")[0] not in STOP]
    return toks[:n]


def refs_of(obj):
    out = []
    for f in FIELDS:
        v = str(obj.get(f, ""))
        for m in REF_RE.finditer(v):
            out.append((f, int(m.group(2)), tokens_after(v, m.end())))
    return out


def single_file_code(user: str):
    m = re.search(r"```[\w+-]*\n(.*?)\n```", user, re.S)
    if not m:
        return None
    code = m.group(1)
    if "# === file:" in code or re.search(r"^\s*\d+\|", code, re.M):
        return None
    return code.splitlines()


def tok_hit(code, line_no, toks, need=1):
    if not (1 <= line_no <= len(code)):
        return 0
    low = code[line_no - 1].lower()
    return sum(1 for t in toks if t.lower() in low) >= need


def main():
    rows = [json.loads(l) for l in SRC.read_text(encoding="utf-8").splitlines() if l.strip()]
    pre_exact = pre_tot = post_exact = 0
    a_fixed = b_fixed = a_recs = 0
    samples_a, samples_b = [], []
    out_rows = []

    for i, r in enumerate(rows):
        code = single_file_code(r["messages"][1]["content"])
        a = r["messages"][2]["content"]
        m = re.search(r"```json\s*(\{.*?\})\s*```", a, re.S)
        if not code or not m:
            out_rows.append(r)
            continue
        try:
            obj = json.loads(m.group(1))
        except json.JSONDecodeError:
            out_rows.append(r)
            continue
        refs0 = refs_of(obj)
        for _, c, t in refs0:
            if 1 <= c <= len(code) and t:
                pre_tot += 1
                pre_exact += 1 if tok_hit(code, c, t[:3]) else 0
        changed = False

        # ---- Stage A：记录级系统性偏移投票 ----
        votes = Counter()
        for _, claimed, toks in refs0:
            if not toks:
                continue
            tl = [t.lower() for t in toks]
            cands_all = [j + 1 for j, ln in enumerate(code) if any(x in ln.lower() for x in tl)]
            strong = [c for c in cands_all
                      if sum(x in code[c - 1].lower() for x in tl) >= min(2, len(tl))]
            pool = strong if len(strong) == 1 else (cands_all if len(cands_all) == 1 else [])
            if len(pool) == 1 and pool[0] != claimed:
                votes[pool[0] - claimed] += 1
        k = 0
        if votes:
            cand_k, cnt = votes.most_common(1)[0]
            uniq = len({c for _, c, _ in refs0})
            if cand_k != 0 and cnt >= 3 and cnt >= (uniq + 1) // 2:
                k = cand_k
        if k:
            n_a = 0
            for f, claimed, toks in refs0:
                target = claimed + k
                if not tok_hit(code, target, toks[:3]):
                    continue                      # 目标行须确含 token
                if tok_hit(code, claimed, toks[:3], need=2):
                    continue                      # 声称行双 token 强证据在位，不动
                v = str(obj.get(f, ""))
                mm = list(REF_RE.finditer(v))
                hit = [x for x in mm if int(x.group(2)) == claimed]
                if not hit:
                    continue
                x = hit[0]
                obj[f] = v[:x.start()] + x.group(1) + str(target) + v[x.end():]
                n_a += 1
                a_fixed += 1
                if len(samples_a) < 40:
                    samples_a.append(f"#{i} {f} line {claimed}→{target} (k={k})")
            if n_a:
                a_recs += 1
                changed = True

        # ---- Stage B：多 token 计分消歧（±5 内） ----
        for f in FIELDS:
            v = str(obj.get(f, ""))
            chs = []

            def repl(mm):
                claimed = int(mm.group(2))
                toks = tokens_after(v, mm.end())
                if not toks or not (1 <= claimed <= len(code)):
                    return mm.group(0)
                if tok_hit(code, claimed, toks[:3]):
                    return mm.group(0)
                scored = []
                for c in range(max(1, claimed - 5), min(len(code), claimed + 5) + 1):
                    s = sum(1 for t in toks if t.lower() in code[c - 1].lower())
                    if s:
                        scored.append((s, c))
                scored.sort(reverse=True)
                if scored and scored[0][0] >= 2 and \
                        (len(scored) == 1 or scored[0][0] - scored[1][0] >= 1):
                    best = scored[0][1]
                    chs.append((claimed, best))
                    return mm.group(1) + str(best)
                return mm.group(0)

            nv = REF_RE.sub(repl, v)
            if nv != v:
                obj[f] = nv
                b_fixed += len(chs)
                changed = True
                for c0, c1 in chs:
                    if len(samples_b) < 40:
                        samples_b.append(f"#{i} {f} line {c0}→{c1}")

        if changed:
            r["messages"][2]["content"] = a[:m.start()] + "```json\n" + \
                json.dumps(obj, ensure_ascii=False) + "\n```" + a[m.end():]
        for _, c, t in refs_of(obj):
            if 1 <= c <= len(code) and t:
                post_exact += 1 if tok_hit(code, c, t[:3]) else 0
        out_rows.append(r)

    with open(OUT, "w", encoding="utf-8") as f:
        for r in out_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    pct = lambda x: f"{x}/{pre_tot} = {x/max(pre_tot,1):.1%}"
    lines = [
        "# alpha06-v2.10 行号吸附二段升级报告\n",
        f"- 输入 v2.9 {len(rows)} → 输出 {len(out_rows)}（行数不变）",
        f"- Stage A 系统性偏移：{a_recs} 条记录 / {a_fixed} 处改写",
        f"- Stage B 计分消歧：{b_fixed} 处改写",
        f"- source/sink 精确命中：{pct(pre_exact)} → {pct(post_exact)}",
        "",
        "## Stage A 抽样", *samples_a,
        "", "## Stage B 抽样", *samples_b,
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines[:6]))


if __name__ == "__main__":
    main()
