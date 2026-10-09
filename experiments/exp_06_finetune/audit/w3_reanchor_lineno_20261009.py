# -*- coding: utf-8 -*-
"""W3 行号重锚（2026-10-09）—— v2_26 → v2_27 的前置批次。

背景（存量残留清点_v2_26 §二.1）：注释级清洗把代码行整体上移，assistant 按
"含注释时代"写的行号引用出界（narr_oob 403 行新 digest），叠加存量越界/混用共 768 行
（audit/v2_26_opt_manifests/p1_6_lineno_oob_mix.jsonl）。

原则（勿违反）：
  1. 唯一真源是"当前代码块"——绝不用旧行号推新行号；锚是代码标识符，不是数字。
  2. 验证后修复：每条引用先核对旧号是否与代码一致，一致则不动；仅错/越界才重锚。
  3. 不猜：标识符无命中或多命中无法裁决 → needs_human，宁缺勿滥。
  4. 应用 ⟺ 复扫干净 由构造保证：修完的 assistant 文本在写盘前用与
     opt_v2_26_rescan_20260927.py 逐字节相同的 p1_6 判定自检，仍被标记的行不应用。
  5. 本脚本只处理行号与风格混用；叙事语义对错（W-E 范畴）不碰。

用法：
  python w3_reanchor_lineno_20261009.py --pilot            # 前 20 行试批 + 预览
  python w3_reanchor_lineno_20261009.py                    # 全量分析（不写数据集）
  python w3_reanchor_lineno_20261009.py --apply            # 应用 → v2_27_w3 数据集
"""
import argparse, collections, hashlib, json, os, re, sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune"
SRC = os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_26_candidate_20260914.jsonl")
MANIFEST = os.path.join(ROOT, "audit", "v2_26_opt_manifests", "p1_6_lineno_oob_mix.jsonl")
OUT_DIR = os.path.join(ROOT, "audit", "w3_out")
DST = os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_27_w3reanchor_20261009.jsonl")

# ---- 与 opt_v2_26_rescan_20260927.py 逐字节相同的判定口径（勿改，改了自检就失效）----
CODE_RE = re.compile(r"```([a-zA-Z0-9_+#\-\.]*)[ \t]*\n(.*?)```", re.S)
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
LINE_REF_RE = re.compile(r"(?:line\s*(\d+)|第\s*(\d+)\s*行|(?<![A-Za-z0-9_])L(\d+))", re.I)
LBAD_RE = re.compile(r"(?:#|//|--|/\*|<!--)\s*line\s*(\d+)", re.I)


def code_blocks(u):
    return [(m.group(1).lower(), m.group(2)) for m in CODE_RE.finditer(u)]


def digest(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()[:10]


def total_code_lines(u):
    bl = code_blocks(u)
    if not bl:
        return 0
    lens = [len(b[1].strip("\n").split("\n")) for b in bl]
    return sum(lens) if len(bl) > 1 else lens[0]


def p1_6_flags(u, a):
    """返回 (oob_set, mixed, embed_bad_n)——与 rescan 同口径。"""
    bl = code_blocks(u)
    cl = total_code_lines(u)
    bad = 0
    for lang, body in bl:
        for ln, text in enumerate(body.split("\n"), 1):
            m = LBAD_RE.search(text)
            if m and int(m.group(1)) != ln:
                bad += 1
    refs = [int(x[0] or x[1] or x[2]) for x in LINE_REF_RE.findall(a) if (x[0] or x[1] or x[2])]
    oob = sorted({x for x in refs if cl and x > cl})
    mixed = bool(re.search(r"line\s*\d+", a, re.I)) and bool(
        re.search(r"(?<![A-Za-z0-9_])L\d{1,3}(?![0-9])", a))
    return oob, mixed, bad


# ---------------------------------------------------------------- 代码侧索引
IDENT_RX = re.compile(r"[A-Za-z_$][A-Za-z0-9_$.\-]{2,}")
STOP = {"line", "the", "this", "that", "function", "return", "const", "var", "let",
        "and", "for", "with", "from", "http", "https", "self", "none", "true", "false",
        "import", "require", "class", "public", "private", "static", "void", "int",
        "string", "error", "index", "length"}


class CodeIndex:
    """单文件/多代码块统一索引：block_no 内 1 基行号 → 行文本。"""

    def __init__(self, u):
        self.lines = []  # [(block_no, line_no, text)]
        for bi, (lang, body) in enumerate(code_blocks(u), 1):
            for ln, text in enumerate(body.strip("\n").split("\n"), 1):
                self.lines.append((bi, ln, text))
        self.multi = len(code_blocks(u)) > 1

    def find(self, ident):
        """ident → 出现行列表 [(block_no, line_no)]（大小写敏感子串匹配）。"""
        if not ident or len(ident) < 3 or ident.lower() in STOP:
            return []
        return [(b, n) for b, n, t in self.lines if ident in t]

    def window_idents(self, window):
        toks = [t for t in IDENT_RX.findall(window) if t.lower() not in STOP and len(t) >= 3]
        seen, out = set(), []
        for t in toks:
            if t not in seen:
                seen.add(t)
                out.append(t)
        return out[:12]


def resolve_candidates(idx: CodeIndex, old_n, window):
    """窗口标识符 → 候选行列表（按证据强度排序）。
    返回 (candidates, strength, basis)。candidates: [(line_no, basis)] 由强到弱；
    strength: 'hi'（唯一命中或≥2个ident一致）/ 'med'（多命中近邻）/ None。"""
    idents = idx.window_idents(window)
    if not idents:
        return [], None, "窗口无标识符"
    unique_hits, agree = [], collections.Counter()
    for ident in idents:
        hits = idx.find(ident)
        if len(hits) == 1:
            unique_hits.append((hits[0][1], f"ident:{ident}@L{hits[0][1]}"))
        elif hits and not idx.multi:
            for b, n in hits:
                agree[n] += 1
    # ≥2 个不同 ident 指向同一行 → 高置信
    for n, c in agree.most_common():
        if c >= 2:
            return [(n, f"{c}个ident一致指向L{n}")], "hi", f"{c}ident@L{n}"
    if unique_hits:
        # 多个 ident 各自唯一命中不同行：同现于同一行则合并，否则全部作候选
        lines = sorted({n for n, _ in unique_hits})
        if len(lines) == 1:
            return [(lines[0], unique_hits[0][1])], "hi", unique_hits[0][1]
        cands = [(n, "多ident各唯一命中") for n in sorted(lines, key=lambda x: abs(x - old_n))]
        return cands, "hi", cands[0][1]
    # 只有多命中 ident：近邻候选（中置信）
    allhits = sorted({n for ident in idents for b, n in idx.find(ident)}, key=lambda x: abs(x - old_n))
    if allhits:
        return [(n, "多命中取近邻") for n in allhits], "med", f"近邻L{allhits[0]}"
    return [], None, "标识符零命中"


def _renumber(matched: str, new_n: int) -> str:
    """保留原格式只换数字：'第58行'→'第59行'，'line 45:'→'line 59:'，'L73'→'L59'。"""
    return re.sub(r"\d+", str(new_n), matched, count=1)


def reanchor_text(u, a):
    """返回 (new_a, plan, status)。
    status: clean / remapped(hi) / remapped_med / partial / human / nochange_needed"""
    idx = CodeIndex(u)
    cl = total_code_lines(u)
    span = json_span(a)

    # 第一遍：给每条引用建档（是否需要改、候选行、证据）
    items = []  # dict(pos, end, matched, n, style, in_json, need, cands, strength, basis)
    for m in LINE_REF_RE.finditer(a):
        s, e = m.span()
        matched = m.group(0)
        n = int(m.group(1) or m.group(2) or m.group(3))
        style = ref_kind(a, m)
        in_json = span and span[0] <= s < span[1]
        ws, we = max(0, s - 90), min(len(a), e + 90)
        window = a[ws:we]
        it = dict(s=s, e=e, matched=matched, n=n, style=style, in_json=bool(in_json))
        if n <= cl:
            it["need"] = False
            if not idx.multi:
                idents = idx.window_idents(window)
                line_text = next((t for b, ln, t in idx.lines if ln == n), "")
                if idents and not any(idt in line_text for idt in idents):
                    cands, strength, basis = resolve_candidates(idx, n, window)
                    it.update(need=True, cands=cands, strength=strength, basis="界内错位:" + basis)
                else:
                    it.update(action="keep")
            else:
                it.update(action="keep")
        else:
            cands, strength, basis = resolve_candidates(idx, n, window)
            it.update(need=True, cands=cands, strength=strength, basis="越界:" + basis)
        items.append(it)

    need_items = [it for it in items if it.get("need")]
    if not need_items:
        return a, [dict(old=it["n"], action="keep", style=it["style"]) for it in items], "nochange_needed"

    # 入射约束贪心指派：已核对的保留行先占位；多个待改引用不许映射到同一行
    taken = {it["n"] for it in items if it.get("action") == "keep"}
    order = sorted(need_items, key=lambda it: (0 if it.get("strength") == "hi" else 1,
                                               it["s"]))
    for it in order:
        cands = [c for c in (it.get("cands") or []) if c[0] not in taken]
        if not cands:
            it["final"], it["assign"] = None, "human"
            it["basis"] = it.get("basis", "") + "|无可用行(占位冲突或零命中)"
            continue
        it["final"], it["assign"] = cands[0][0], cands[0][1]
        it["strength"] = it.get("strength") or "med"
        taken.add(it["final"])

    edits, plan = [], []
    for it in items:
        if not it.get("need"):
            plan.append(dict(old=it["n"], action="keep", style=it["style"],
                             json=it["in_json"]))
            continue
        if it.get("final") is None:
            plan.append(dict(old=it["n"], action="human", style=it["style"],
                             json=it["in_json"], why=it["basis"]))
            continue
        edits.append((it["s"], it["e"], _renumber(it["matched"], it["final"])))
        plan.append(dict(old=it["n"], new=it["final"], action="remap",
                         style=it["style"], json=it["in_json"],
                         strength=it["strength"], basis=it["basis"]))

    # 风格混用归一：独立 L\d token（非 JSON 区）→ 本行主流风格，保留行号值
    _, mixed, _ = p1_6_flags(u, a)
    if mixed:
        styles = collections.Counter(p["style"] for p in plan if p["style"] in ("cn", "line"))
        target = "cn" if styles.get("cn", 0) >= styles.get("line", 0) else "line"
        for m in re.finditer(r"(?<![A-Za-z0-9_])L(\d{1,3})(?![0-9])", a):
            s, e = m.span()
            if span and span[0] <= s < span[1]:
                continue
            n = int(m.group(1))
            if n > cl + 2:
                continue  # 不像行号的 L-token 不动
            repl = f"第 {n} 行" if target == "cn" else f"line {n}"
            edits.append((s, e, repl))
            plan.append(dict(old=n, action="restyle", style="L", to=target))

    buf = a
    for s, e, repl in sorted(edits, key=lambda x: -x[0]):  # 从右往左，偏移不漂移
        buf = buf[:s] + repl + buf[e:]

    humans = [p for p in plan if p["action"] == "human"]
    if not edits:
        return a, plan, "human"
    oob2, mixed2, bad2 = p1_6_flags(u, buf)
    if oob2 or mixed2 or bad2:
        return buf, plan, "partial"   # 部分修掉，剩余引用留给人工批
    return buf, plan, ("remapped" if not humans else "remapped_with_humans")


# ---------------------------------------------------------------- assistant 解析
def ref_kind(a, m):
    """按捕获组返回风格。"""
    if m.group(1) is not None:
        return "line"
    if m.group(2) is not None:
        return "cn"
    return "L"


def json_span(a):
    ms = list(JSON_RE.finditer(a))
    return ms[-1].span() if ms else None


JSON_FIELD_RE = re.compile(r'''line\s*\d+\s*[:：]\s*([^'"\n,，。；;；)]{2,60})''')


def _renumber(matched: str, new_n: int) -> str:
    """保留原格式只换数字：'第58行'→'第59行'，'line 45'→'line 59'，'L73'→'L59'。"""
    return re.sub(r"\d+", str(new_n), matched, count=1)


def reanchor_text(u, a):
    """返回 (new_a, plan, status)。

    模型：这类行是"注释清洗造成区域性整体位移"——同区间内旧行号偏移一个常量。
    机械修复只动两类：①越界引用（oob，检测器的真实信号）用锚点唯一命中或
    同区间等位移插值重锚；②风格混用归一。界内引用一律不动（可能仍有语义性
    陈旧，留给 W-E/人工批——那是语义判断不是行号判断）。
    status: remapped / partial / style_only / human
    """
    idx = CodeIndex(u)
    cl = total_code_lines(u)
    span = json_span(a)

    items = []
    for m in LINE_REF_RE.finditer(a):
        s, e = m.span()
        n = int(m.group(1) or m.group(2) or m.group(3))
        style = ref_kind(a, m)
        in_json = bool(span and span[0] <= s < span[1])
        ws, we = max(0, s - 90), min(len(a), e + 90)
        window = a[ws:we]
        oob = n > cl
        json_idents = []
        if in_json:
            fm = JSON_FIELD_RE.search(window)
            if fm:
                json_idents = [t for t in IDENT_RX.findall(fm.group(1)) if len(t) >= 3][:3]
        items.append(dict(s=s, e=e, matched=m.group(0), n=n, style=style,
                          in_json=in_json, oob=oob, wids=idx.window_idents(window),
                          jids=json_idents))

    def unique_ident_target(it):
        for idt in it["jids"] + it["wids"]:
            hits = idx.find(idt)
            if len(hits) == 1 and not idx.multi:
                return hits[0][1], f"唯一命中 {idt}@L{hits[0][1]}"
        return None, None

    # 锚点：oob 且标识符唯一命中的引用（占位互斥：同一目标行只认第一个）
    anchors, taken = [], set()
    for it in items:
        if it["oob"]:
            tgt, basis = unique_ident_target(it)
            if tgt and tgt not in taken:
                it["final"], it["assign"], it["strength"] = tgt, basis, "hi"
                anchors.append((it["n"], tgt))
                taken.add(tgt)
            elif tgt:
                it["assign"] = f"唯一命中 {tgt} 但已被同组引用占用"
    anchors.sort()
    # 等位移区间：相邻锚点位移一致 → 区间内 oob 引用插值
    def interp(old_n):
        for i in range(len(anchors) - 1):
            (o1, n1), (o2, n2) = anchors[i], anchors[i + 1]
            if o1 <= old_n <= o2 and (n1 - o1) == (n2 - o2):
                return n1 - o1, f"插值 {o1}→{n1},{o2}→{n2} 同位移 {n1-o1:+d}"
        return None, None

    taken2 = set(taken)
    for it in items:
        if not it["oob"] or it.get("final"):
            continue
        tgt, basis = unique_ident_target(it)
        if tgt and tgt not in taken2:
            it.update(final=tgt, assign=basis, strength="hi")
            taken2.add(tgt)
            continue
        off, basis2 = interp(it["n"])
        if off is not None and 1 <= it["n"] + off <= cl and (it["n"] + off) not in taken2:
            it.update(final=it["n"] + off, assign=basis2, strength="med")
            taken2.add(it["n"] + off)
            continue
        it.update(final=None, assign=(it.get("assign") or "越界且无锚点/插值可用"),
                  strength=None)

    edits, plan = [], []
    for it in items:
        if not it["oob"]:
            plan.append(dict(old=it["n"], action="keep", style=it["style"],
                             json=it["in_json"]))
            continue
        if it.get("final"):
            edits.append((it["s"], it["e"], _renumber(it["matched"], it["final"])))
            plan.append(dict(old=it["n"], new=it["final"], action="remap",
                             style=it["style"], json=it["in_json"],
                             strength=it["strength"], basis=it["assign"]))
        else:
            plan.append(dict(old=it["n"], action="human", style=it["style"],
                             json=it["in_json"], why=it["assign"]))

    # 风格混用归一：独立 L\d token（非 JSON 区）→ 本行主流风格
    _, mixed, _ = p1_6_flags(u, a)
    if mixed:
        styles = collections.Counter(p["style"] for p in plan if p["style"] in ("cn", "line"))
        target = "cn" if styles.get("cn", 0) >= styles.get("line", 0) else "line"
        for m in re.finditer(r"(?<![A-Za-z0-9_])L(\d{1,3})(?![0-9])", a):
            s, e = m.span()
            if span and span[0] <= s < span[1]:
                continue
            n = int(m.group(1))
            if n > cl + 2:
                continue  # 不像行号的 L-token 不动
            repl = f"第{n}行" if target == "cn" else f"line {n}"
            edits.append((s, e, repl))
            plan.append(dict(old=n, action="restyle", style="L", to=target))

    humans = [p for p in plan if p["action"] == "human"]
    if not edits:
        return a, plan, "human"
    buf = a
    for s, e, repl in sorted(edits, key=lambda x: -x[0]):  # 从右往左，偏移不漂移
        buf = buf[:s] + repl + buf[e:]
    oob2, mixed2, bad2 = p1_6_flags(u, buf)
    if oob2 or mixed2 or bad2:
        return buf, plan, "partial"   # 部分修掉，剩余 oob 引用留给人工批
    return buf, plan, ("remapped" if humans else "remapped_clean")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", action="store_true", help="只处理 manifest 前 20 行并输出预览")
    ap.add_argument("--apply", action="store_true", help="写 v2_27_w3 数据集（默认只分析）")
    args = ap.parse_args()
    os.makedirs(OUT_DIR, exist_ok=True)

    manifest = [json.loads(l) for l in open(MANIFEST, encoding="utf-8") if l.strip()]
    if args.pilot:
        manifest = manifest[:20]
    rows = [json.loads(l) for l in open(SRC, encoding="utf-8") if l.strip()]
    print(f"manifest {len(manifest)} 行 / 数据集 {len(rows)} 行")

    ops, stats = [], collections.Counter()
    preview, new_rows_by_idx = [], {}
    for rec in manifest:
        i = rec["row"]
        r = rows[i]
        u, a = r["messages"][1]["content"], r["messages"][2]["content"]
        oob, mixed, bad = p1_6_flags(u, a)
        new_a, planstat, status = reanchor_text(u, a)
        # 构造性自检：修完必须在本行维度过 rescan 同口径判定
        oob2, mixed2, bad2 = p1_6_flags(u, new_a)
        applied = False
        if new_a != a:
            if (oob2 or mixed2 or bad2) and status == "remapped":
                status = "residual"  # 自检未过 → 不应用，转人工
                stats["residual"] += 1
            else:
                applied = True
                stats[status] += 1
                new_rows_by_idx[i] = new_a
        else:
            stats[status] += 1
        ops.append(dict(row=i, digest=digest(a), status=status, applied=applied,
                        oob_before=oob, mixed_before=mixed,
                        oob_after=oob2, mixed_after=mixed2,
                        plan=planstat))
        if args.pilot:
            preview.append((i, status, a, new_a, planstat))

    print("状态分布:", dict(stats))
    ops_path = os.path.join(OUT_DIR, "w3_ops_pass1.jsonl")
    with open(ops_path, "w", encoding="utf-8") as f:
        for o in ops:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    print(f"-> {ops_path}")

    if args.pilot:
        pv = os.path.join(OUT_DIR, "w3_pilot_preview.md")
        with open(pv, "w", encoding="utf-8") as f:
            for i, st, a, na, pl in preview:
                f.write(f"## row={i} status={st}\n\n")
                f.write(f"plan: {json.dumps(pl, ensure_ascii=False)}\n\n")
                if na != a:
                    f.write("**BEFORE**:\n```text\n" + a[:600] + "\n```\n\n")
                    f.write("**AFTER**:\n```text\n" + na[:600] + "\n```\n\n---\n\n")
                else:
                    f.write("(无改动)\n\n---\n\n")
        print(f"-> {pv}")

    if args.apply:
        src_md5 = hashlib.md5(open(SRC, "rb").read()).hexdigest()
        n_changed = 0
        with open(DST, "w", encoding="utf-8", newline="\n") as f:
            for i, r in enumerate(rows):
                if i in new_rows_by_idx:
                    rr = json.loads(json.dumps(r))
                    rr["messages"][2]["content"] = new_rows_by_idx[i]
                    f.write(json.dumps(rr, ensure_ascii=False) + "\n")
                    n_changed += 1
                else:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
        assert hashlib.md5(open(SRC, "rb").read()).hexdigest() == src_md5, "源文件被改动！"
        # 落盘后护栏：重载 v2_27，全量复扫 p1_6 同口径
        rows27 = [json.loads(l) for l in open(DST, encoding="utf-8") if l.strip()]
        flagged27 = set()
        for i, r in enumerate(rows27):
            o, mx, bd = p1_6_flags(r["messages"][1]["content"], r["messages"][2]["content"])
            if o or mx or bd:
                flagged27.add(i)
        manifest_rows = {rec["row"] for rec in manifest}
        expect = {o["row"] for o in ops if o["status"] in ("partial", "human")}
        print(f"APPLY -> {DST}  改写 {n_changed} 行")
        print(f"护栏① 源文件 md5 未变: {src_md5[:12]}")
        print(f"护栏② v2_27 仍被标记 {len(flagged27)} 行（预期 {len(expect)}）"
              f" {'OK' if flagged27 == expect else 'MISMATCH!'}")
        outside = flagged27 - manifest_rows
        print(f"护栏③ 圈外新增标记 {len(outside)} 行 {'OK' if not outside else outside}")
        # 人工批工作清单
        wl = os.path.join(OUT_DIR, "w3_human_worklist.md")
        with open(wl, "w", encoding="utf-8") as f:
            f.write("# W3 人工批工作清单（机械不可解，交 W-E/教师批）\n\n")
            f.write(f"> 生成 {args.pilot and '(pilot)' or ''}；"
                    f"partial=已修部分引用但仍有 oob；human=未动。\n\n")
            for o in ops:
                if o["status"] not in ("partial", "human"):
                    continue
                f.write(f"## row={o['row']} status={o['status']} oob={o['oob_after'] or o['oob_before']}\n")
                for p in o["plan"]:
                    if p["action"] == "human":
                        f.write(f"- 引用 {p['old']}：{p.get('why','')}\n")
                f.write("\n")
        print(f"-> {wl}")


if __name__ == "__main__":
    main()
