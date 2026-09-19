# -*- coding: utf-8 -*-
"""统一 diff 解析与应用（hunk-only 或带 ---/+++ 头均可）。

应用策略（容错）：
- 按 hunk 的 old_start 定位，上下文行失配时在 ±offset 窗口内重找（应对行号漂移）；
- 上下文行做右.strip 宽松匹配（容忍行尾空白差异）；
- 返回 (post_code_lines, changed: {pre_lines:[...], post_lines:[...]}, ok, msg)。
"""
import re

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_patch(text: str):
    """返回 [{old_start, old_count, new_start, new_count, lines:[(tag, line)]}]，tag∈' ','-','+'。"""
    hunks = []
    cur = None
    for ln in text.splitlines():
        m = HUNK.match(ln)
        if m:
            if cur:
                hunks.append(cur)
            cur = {"old_start": int(m.group(1)), "old_count": int(m.group(2) or 1),
                   "new_start": int(m.group(3)), "new_count": int(m.group(4) or 1),
                   "lines": []}
            continue
        if cur is None:
            continue
        if ln.startswith("\\"):            # \ No newline at end of file
            continue
        if ln.startswith("---") or ln.startswith("+++") or ln.startswith("diff "):
            continue
        if ln.startswith("+"):
            cur["lines"].append(("+", ln[1:]))
        elif ln.startswith("-"):
            cur["lines"].append(("-", ln[1:]))
        elif ln.startswith(" "):
            cur["lines"].append((" ", ln[1:]))
        elif ln == "":
            cur["lines"].append((" ", ""))
    if cur:
        hunks.append(cur)
    return hunks


def apply_patch(pre_lines, hunks, window=200):
    """pre_lines: list[str]。返回 (post_lines, info) 或 (None, err)。"""
    out = []
    pos = 0            # 0-based 已消费行数
    changed = {"pre": [], "post": []}
    for h in hunks:
        ctx = [(t, l) for (t, l) in h["lines"]]
        old_start = h["old_start"] - 1
        # 在窗口内寻找失配平移
        base = max(0, min(old_start, len(pre_lines)) - window)
        matched_at = None
        for delta in range(0, window + 1):
            for off in ({0} if delta == 0 else (delta, -delta)):
                start = old_start + off
                if start < 0:
                    continue
                # 校验该 hunk 的上下文与删除行是否吻合
                cur_pre = start
                ok = True
                for t, l in ctx:
                    if t in (" ", "-"):
                        if cur_pre >= len(pre_lines) or pre_lines[cur_pre].rstrip() != l.rstrip():
                            ok = False
                            break
                        cur_pre += 1
                if ok:
                    matched_at = start
                    break
            if matched_at is not None:
                break
        if matched_at is None:
            return None, f"hunk@{h['old_start']} 无法锚定"
        start = matched_at
        # 复制 hunk 前的未变更行
        out.extend(pre_lines[pos:start])
        pos = start
        new_i = 0
        for t, l in ctx:
            if t in (" ", "-"):
                if t == "-":
                    changed["pre"].append(pos + 1)      # 1-based pre 行号
                pos += 1
            if t in (" ", "+"):
                if t == "+":
                    changed["post"].append(len(out) + 1)  # 1-based post 行号
                out.append(l)
            new_i += 1
    out.extend(pre_lines[pos:])
    return out, changed
