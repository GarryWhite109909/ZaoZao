#!/usr/bin/env python3
"""alpha06-v2.9 清洗构建（2026-08-28，补充审计落地）。

基底：final_train_chatml_alpha06_v2_8.jsonl（8762 条），原样保留 v2.8 的全部
修复层（12 条 P0 剔除 / 724 类型归一 / 15 risk 归一）。本轮只做三件确定性手术：

1. 剔除自白式错标 3 条（补充审计 P0-NEW，v2.8 行索引）：
   - #207  T 毒：'实际无漏洞。为演示 CWE-415 Double Free'（教师自述硬标）
   - #4692 F 毒：'根据指令要求 has_vulnerability 必须为 false……实际不安全，但标注为无漏洞'
   - #5147 F 毒：'实际存在CWE-117漏洞。但根据指令，本样本要求输出has_vulnerability=false'
   （剔前断言命中词存在，防索引错位误删）

2. 剥离代码内答案泄漏注释（EN source:/sink:/attacker-controlled 标注，161 条样本）：
   行数保持不变（只删注释段不删行），行号引用零漂移；字符串感知（不碰字符串字面量）。

3. 行号吸附修正（sink 锚定审计：精确命中仅 32%，±2 内 67%，教师数行系统性偏移）：
   对 source/sink/fix_suggestion 中每个 "line N"，取描述里最长 API token，
   在代码块 ±3 行窗口内唯一命中时吸附到真实行；声称行已含 token 则不动。
   跳过：多文件格式（L<n>:line）、含 N| 行号注解的 evidence 块、无代码块样本。
   CoT 散文里的行号不重写（避免大面积文本手术），仅修结构化契约字段。

输出：data/final_train_chatml_alpha06_v2_9.jsonl + data/build_alpha06_v2_9_report.md
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

# ---- 剔除断言（v2.8 索引 → 必须命中的指纹） ----
REMOVE = {
    207: "为演示 CWE-415",
    4692: "根据指令要求 has_vulnerability 必须为 false",
    5147: "本样本要求输出has_vulnerability=false",
}

# ---- 2) 泄漏注释剥离 ----
LEAK_KW = re.compile(r"source\s*[:：]|sink\s*[:：]|attacker[- ]controlled", re.I)


def find_comment_start(ln: str, kw_start: int):
    """字符串感知扫描：返回 kw_start 左侧最近的合法注释起点（不在字符串内）。
    支持 // # /* -- 四种行注释起点；URL 的 :// 与黏着标识符的 # 已排除。"""
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
    """剥离含 source:/sink:/attacker-controlled 的注释段，行数不变。
    覆盖行注释（// # -- /* ... */）与 C 风格文档注释续行（' * ... '）。"""
    lines = code.split("\n")
    n_changed = 0
    for i, ln in enumerate(lines):
        m = LEAK_KW.search(ln)
        if not m:
            continue
        start = find_comment_start(ln, m.start())
        if start is None:
            # 文档注释续行：" * source: ..."——行首星号后跟空白
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


# ---- 3) 行号吸附 ----
STOP = {"the", "this", "and", "into", "from", "with", "line", "via", "then",
        "when", "after", "before", "not", "are", "was", "参数", "漏洞"}


def snap_field(val: str, code_lines):
    """对字段内每个 line N 尝试吸附；返回 (新值, [(声称,吸附),...])。"""
    changes = []

    def repl(m):
        claimed = int(m.group(2))
        desc = val[m.end(): m.end() + 90]
        toks = [t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_.]{2,}", desc)
                if t.lower().split(".")[0] not in STOP]
        if 1 <= claimed <= len(code_lines):
            line_txt = code_lines[claimed - 1].lower()
            if any(t.lower() in line_txt for t in toks[:3]):
                return m.group(0)  # 声称行已含 token，不动
        snapped = None
        for t in toks[:3]:
            tl = t.lower()
            keys = [tl] + ([tl.split(".")[0]] if "." in tl else [])
            for k in keys:
                cand = [j + 1 for j, ln in enumerate(code_lines) if k in ln.lower()]
                near = [c for c in cand if abs(c - claimed) <= 5]
                if len(near) == 1 and near[0] != claimed:
                    snapped = near[0]
                    break
            if snapped is not None:
                break
        if snapped is not None:
            changes.append((claimed, snapped))
            return m.group(1) + str(snapped)
        return m.group(0)

    new_val = re.sub(r"([Ll]ine\s+)(\d+)", repl, val)
    return new_val, changes


def main():
    rows = [json.loads(l) for l in BASE.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(rows) == 8762, f"基底条数异常: {len(rows)}"

    # ---- 1) 剔除（先验指纹再删） ----
    drop_log = []
    for idx, fp in sorted(REMOVE.items(), reverse=True):
        a = rows[idx]["messages"][2]["content"]
        assert fp in a, f"#{idx} 指纹未命中，索引可能错位: {fp!r}"
        drop_log.append(f"#{idx}: {fp}")
        del rows[idx]

    stats = Counter()
    strip_samples, strip_spans = 0, 0
    snap_samples, snap_fixes = 0, 0
    snap_log = []

    for r in rows:
        msgs = r["messages"]
        u, a = msgs[1]["content"], msgs[2]["content"]

        # ---- 2) 泄漏注释剥离（user 侧所有代码块） ----
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

        # ---- 3) 行号吸附（assistant 结构化字段） ----
        m = JSON_RE.search(a)
        if not m:
            continue
        try:
            obj = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
        if "is_confirmed" in obj:  # triage 独立 schema
            continue
        # 代码块选择：最大的非 json 块
        blocks = [(t, b) for t, b in CODE_BLOCK_RE.findall(new_u) if t != "json"]
        if not blocks:
            continue
        if FILE_SEG in new_u:  # 多文件 crossfile：行号语义按文件分段，跳过
            continue
        _, code = max(blocks, key=lambda x: len(x[1]))
        code_lines = code.split("\n")
        if len(ANN_PREFIX.findall(code)) >= 5:  # N| 注解行号格式（evidence），跳过
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

    # ---- 终态断言 ----
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
        # 只检查锚定契约字段（source/sink/fix_suggestion）；
        # explanation 是散文，可引用工具输出的空链（如 "L0 line 0"），不在此约束内
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
        "# alpha06-v2.9 清洗构建报告",
        "",
        f"- 基底：v2.8（8762 条） → 输出 **{len(rows)} 条**",
        f"- 剔除自白式错标 3 条：{' | '.join(drop_log)}",
        f"- 泄漏注释剥离：{strip_samples} 条样本 / {strip_spans} 处注释段（行数不变，行号零漂移）",
        f"- 行号吸附：{snap_samples} 条样本 / {snap_fixes} 处修正（±5 窗口唯一命中）",
        f"- 终态断言：JSON 解析失败 0 | 行号越界（含 evidence 注解口径）0",
        f"- 方向：vuln {hv_c[True]} / safe {hv_c[False]}",
        "",
        "## 吸附修正抽样（前 60，供人工复核）",
        *[f"- {x}" for x in snap_log],
        "",
        "## 设计说明",
        "- CoT 散文中的行号不做重写（避免大面积文本手术引入新错），仅修 source/sink/fix_suggestion 契约字段；",
        "- 多文件（# === file:）与 N| 注解行号格式（evidence）跳过吸附，属已知局限；",
        "- 断言门口径修正：以代码块内嵌行号注解最大值为界（evidence 层物理行数≠真实行号），",
        "  后续 delta 构建与生成器（gen_crossfile_safe 等）应沿用本口径。",
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines[:12]))
    print(f"\n输出: {OUT}")


if __name__ == "__main__":
    main()
