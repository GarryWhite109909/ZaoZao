#!/usr/bin/env python3
"""alpha06-v2.9 清洗构建 v2（2026-08-29 二轮深挖后重写）。

基底：final_train_chatml_alpha06_v2_8.jsonl（8762 条）。相对初版 v2.9 的变更：
1. 剔除名单 3 → 9 条（初版 3 条自白毒 + 二轮逐条裁定新增 6 条）；
2. 吸附算法升级：
   - 唯一命中不限距离（|off|≤60 上限）——修老 C 层大偏移；
   - 多候选时共现评分（该行含描述 token 数 ≥2 且唯一最高 → 吸附）；
   - 评分并列全 1 时取距声称唯一最近行（dist≤20）；
   - "声称行已含 token"判定收紧：含主 token，或含 ≥2 个描述 token。

毒样本指纹（v2.8 索引，剔前断言命中防错位）：
  #207  T毒 为演示 CWE-415      #649  T毒 但按照要求必须标记为有漏洞
  #3064 F毒 但根据要求，负样本必须  #3691 F毒 该代码片段实际存在 CWE-862
  #3996 F毒 整体不安全，需修复email  #4692 F毒 根据指令要求 has_vulnerability 必须为 false
  #4728 矛盾 CoT断言XPath漏洞成立但代码无XPath执行（标签safe，教学信号自相矛盾）
  #5147 F毒 本样本要求输出has_vulnerability=false
  #5274 F毒 但根据要求，本样本标记为无漏洞
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
BASE_DIR = PROJECT / "experiments/exp_06_finetune"
BASE = BASE_DIR / "data/final_train_chatml_alpha06_v2_8.jsonl"
OUT = BASE_DIR / "data/final_train_chatml_alpha06_v2_9.jsonl"
REPORT = BASE_DIR / "data/build_alpha06_v2_9_report.md"

JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
CODE_BLOCK_RE = re.compile(r"```([\w+#./-]*)\n(.*?)\n```", re.S)
FILE_SEG = "# === file:"
ANN_PREFIX = re.compile(r"^\s*(\d+)\s*\|", re.M)

REMOVE = {
    207: ("T", "为演示 CWE-415"),
    649: ("T", "但按照要求必须标记为有漏洞"),
    3064: ("F", "但根据要求，负样本必须"),
    3574: ("F", "has_vulnerability 应为 true"),
    3691: ("F", "该代码片段实际存在 CWE-862"),
    3996: ("F", "整体不安全，需修复email输入处理"),
    4692: ("F", "根据指令要求 has_vulnerability 必须为 false"),
    4728: ("X", "XPath 注入漏洞成立"),
    5147: ("F", "本样本要求输出has_vulnerability=false"),
    5274: ("F", "但根据要求，本样本标记为无漏洞"),
}

LEAK_KW = re.compile(r"source\s*[:：]|sink\s*[:：]|attacker[- ]controlled", re.I)


def find_comment_start(ln: str, kw_start: int):
    in_str = None
    cands = []
    i, n = 0, len(ln)
    while i < n:
        ch = ln[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in "\"'":
            in_str = ch
            i += 1
            continue
        if ch == "/" and i + 1 < n:
            if ln[i + 1] == "/" and (i == 0 or ln[i - 1] in " \t(*"):
                cands.append(i)
            elif ln[i + 1] == "*":
                cands.append(i)
        elif ch == "#":
            cands.append(i)
        elif ch == "-" and i + 1 < n and ln[i + 1] == "-" and (i == 0 or ln[i - 1] in " \t"):
            cands.append(i)
        i += 1
    valid = [c for c in cands if c <= kw_start]
    return valid[-1] if valid else None


def strip_leak_comments(code: str):
    lines = code.split("\n")
    n_changed = 0
    for i, ln in enumerate(lines):
        m = LEAK_KW.search(ln)
        if not m:
            continue
        start = find_comment_start(ln, m.start())
        if start is None:
            if re.match(r"^\s*\*\s", ln):
                lines[i] = re.match(r"^\s*", ln).group(0) + "*"
                n_changed += 1
            continue
        if ln[start: start + 2] == "/*":
            close = ln.find("*/", m.end())
            lines[i] = (ln[:start] + ln[close + 2:]).rstrip() if close != -1 else ln[:start].rstrip()
        else:
            lines[i] = ln[:start].rstrip()
        n_changed += 1
    return "\n".join(lines), n_changed


STOP = {"the", "this", "and", "into", "from", "with", "line", "via", "then",
        "when", "after", "before", "not", "are", "was", "attacker", "user",
        "call", "calls", "data", "flag", "value"}


def snap_field(val: str, code_lines):
    """行号吸附 v2：唯一命中不限距离；多候选共现评分 + 最近邻兜底。"""
    changes = []

    def repl(m):
        claimed = int(m.group(2))
        desc = val[m.end(): m.end() + 120]
        toks = [t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_.]{2,}", desc)
                if t.lower().split(".")[0] not in STOP]
        if not toks:
            return m.group(0)
        primary = toks[0].lower()
        # 声称行已含主 token 或 ≥2 个描述 token → 视为正确，不动
        if 1 <= claimed <= len(code_lines):
            ln_txt = code_lines[claimed - 1].lower()
            n_hit = sum(1 for t in toks[:5] if t.lower() in ln_txt)
            if primary in ln_txt or n_hit >= 2:
                return m.group(0)
        # 找主 token 的候选行；主 token 无命中则依次降级
        cand = []
        for t in toks:
            tl = t.lower()
            keys = [tl] + ([tl.split(".")[0]] if "." in tl else [])
            for k in keys:
                cand = [j + 1 for j, ln in enumerate(code_lines) if k in ln.lower()]
                if cand:
                    break
            if cand:
                break
        if not cand:
            return m.group(0)

        def snap_to(target):
            changes.append((claimed, target))
            return m.group(1) + str(target)

        if len(cand) == 1:
            if cand[0] != claimed and abs(cand[0] - claimed) <= 60:
                return snap_to(cand[0])
            return m.group(0)
        # 多候选：共现评分
        tokset = [t.lower() for t in toks[:5]]
        scored = [(c, sum(1 for t in tokset if t in code_lines[c - 1].lower())) for c in cand]
        max_score = max(s for _, s in scored)
        best = [c for c, s in scored if s == max_score]
        if max_score >= 2 and len(best) == 1 and best[0] != claimed:
            if abs(best[0] - claimed) <= 60:
                return snap_to(best[0])
            return m.group(0)
        # 全 1 分或并列：距声称唯一最近行
        dist = {c: abs(c - claimed) for c in cand}
        min_d = min(dist.values())
        nearest = [c for c, d in dist.items() if d == min_d]
        if len(nearest) == 1 and nearest[0] != claimed and min_d <= 20:
            return snap_to(nearest[0])
        return m.group(0)

    return re.sub(r"([Ll]ine\s+)(\d+)", repl, val), changes


def main():
    rows = [json.loads(l) for l in BASE.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(rows) == 8762, f"基底条数异常: {len(rows)}"

    drop_log = []
    for idx, (typ, fp) in sorted(REMOVE.items(), reverse=True):
        a = rows[idx]["messages"][2]["content"]
        assert fp in a, f"#{idx} 指纹未命中（索引错位?）: {fp!r}"
        drop_log.append(f"#{idx}[{typ}]: {fp}")
        del rows[idx]

    stats = Counter()
    strip_samples, strip_spans = 0, 0
    snap_samples, snap_fixes = 0, 0
    snap_log = []

    for r in rows:
        msgs = r["messages"]
        u, a = msgs[1]["content"], msgs[2]["content"]

        def strip_in_user(m):
            nonlocal strip_spans
            new_body, k = strip_leak_comments(m.group(2))
            if k:
                strip_spans += k
                return f"```{m.group(1)}\n{new_body}\n```"
            return m.group(0)

        new_u = CODE_BLOCK_RE.sub(strip_in_user, u)
        if new_u != u:
            msgs[1]["content"] = new_u
            strip_samples += 1

        m = JSON_RE.search(a)
        if not m:
            continue
        try:
            obj = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
        if "is_confirmed" in obj:
            continue
        blocks = [(t, b) for t, b in CODE_BLOCK_RE.findall(new_u) if t != "json"]
        if not blocks or FILE_SEG in new_u:
            continue
        _, code = max(blocks, key=lambda x: len(x[1]))
        code_lines = code.split("\n")
        if len(ANN_PREFIX.findall(code)) >= 5:
            continue

        touched = False
        for fld in ("source", "sink", "fix_suggestion"):
            v = obj.get(fld)
            if not isinstance(v, str) or "line" not in v.lower():
                continue
            nv, ch = snap_field(v, code_lines)
            if ch:
                obj[fld] = nv
                touched = True
                snap_fixes += len(ch)
                if len(snap_log) < 60:
                    for c, s in ch:
                        snap_log.append(f"{fld} line {c}→{s}: {nv[:60]!r}")
        if touched:
            snap_samples += 1
            msgs[2]["content"] = a[: m.start()] + "```json\n" + \
                json.dumps(obj, ensure_ascii=False) + "\n```" + a[m.end():]

    # 终态断言
    def bounds_of(u):
        blocks = [(t, b) for t, b in CODE_BLOCK_RE.findall(u) if t != "json"]
        if not blocks:
            return None
        _, code = max(blocks, key=lambda x: len(x[1]))
        n = code.count("\n") + 1
        ann = [int(x) for x in ANN_PREFIX.findall(code)]
        return max([n] + ann) if len(ann) >= 5 else n

    oob = []
    parse_fail = 0
    hv_c = Counter()
    for i, r in enumerate(rows):
        a = r["messages"][2]["content"]
        m = JSON_RE.search(a)
        if not m:
            parse_fail += 1
            continue
        try:
            obj = json.loads(m.group(1))
        except json.JSONDecodeError:
            parse_fail += 1
            continue
        hv_c[obj.get("has_vulnerability")] += 1
        if "is_confirmed" in obj:
            continue
        bnd = bounds_of(r["messages"][1]["content"])
        if bnd is None:
            continue
        contract_txt = " ".join(str(obj.get(f) or "") for f in ("source", "sink", "fix_suggestion"))
        for ln in {int(n) for n in re.findall(r"[Ll]ine\s+(\d+)", contract_txt)}:
            if not (1 <= ln <= bnd):
                oob.append((i, ln, bnd))

    assert parse_fail == 0, "存在不可解析样本"
    assert len(oob) == 0, f"行号越界残留 {len(oob)}: {oob[:5]}"

    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    lines = [
        "# alpha06-v2.9 清洗构建报告（二轮重写版）",
        "",
        f"- 基底：v2.8（8762 条） → 输出 **{len(rows)} 条**",
        f"- 剔除毒样本 10 条（T=硬标漏洞 / F=硬标安全 / X=自相矛盾）：",
        *[f"  - {x}" for x in drop_log],
        f"- 泄漏注释剥离：{strip_samples} 条样本 / {strip_spans} 处注释段（行数不变，行号零漂移）",
        f"- 行号吸附 v2：{snap_samples} 条样本 / {snap_fixes} 处修正",
        "  （唯一命中不限距离≤60；多候选共现评分≥2 唯一最高；并列全 1 取唯一最近≤20；",
        "   声称行含主 token 或 ≥2 token 则不动）",
        f"- 终态断言：JSON 解析失败 0 | 契约字段行号越界 0",
        f"- 方向：vuln {hv_c[True]} / safe {hv_c[False]}",
        "",
        "## 吸附修正抽样（前 60，供人工复核）",
        *[f"- {x}" for x in snap_log],
        "",
        "## 二轮裁定增补说明（相对初版 v2.9）",
        "- 新增剔除 6 条来自三类扫描的逐条人工裁定：",
        "  explanation 强断言扫描（#3996 整体不安全需修复）、",
        "  供词句式补漏（'根据要求/按照要求'变体：#3064 #5274 #649）、",
        "  CoT 末句断言漏洞（#3691 #4727——后者经代码核验无 XPath 执行 sink，",
        "  标签 safe 数据流上正确但 CoT/注释/标签三方矛盾，教学信号自相矛盾故剔除）；",
        "- 裁定保留的边界形态：#8560/#8565 修复版说明（'原漏洞…修复后闭合'）为合法 safe 教学；",
        "  #8164/#8447/#8499 '证据不足不确认'为合法裁决语气；",
        "- CoT 散文行号不重写（仅修契约字段），老 C 层 CoT 内行号漂移属已知局限。",
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines[:16]))
    print(f"\n输出: {OUT}")


if __name__ == "__main__":
    main()
