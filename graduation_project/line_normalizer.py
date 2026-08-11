"""
行号纠正工具（与 cwe_normalizer 同思路：确定性查表/匹配，纠正模型输出）。

背景：模型输出的 source / sink / fix_suggestion 采用"行号锚定"格式
（如 "line 7: request.args.get('file') 用户可控路径参数"）。行号是纯
"数行"任务，模型容易数错（多算/漏算 import、装饰器、空行，或切片后按
chunk 相对行号输出），但 `line N:` 后面的**行文本内容**通常是可靠的。
本工具在模型输出之后做确定性纠正：用行文本内容在源文件中定位真实行号，
覆盖掉错误的 N（纠正后的锚点统一输出为 `line N:` 格式，便于下游
VS Code / FixVerifier 等解析）。

支持锚点形态：`line 7:` / `L7:` / `第 7 行:`（含无冒号的 `第7行`）。

与 cwe_normalizer.py 的设计原则保持一致：
- 纯 Python 内容匹配，**不进模型上下文、不增加任何 token/资源消耗**；
- 只纠正能可靠定位的行号；匹配不到无语义锚点时**原样返回，不做破坏性覆盖**；
- 幂等：输入行号已正确（内容能定位到同一行）时输出不变；
- 适用于所有 "LLM 直接输出 source/sink/fix_suggestion" 的场景
  （/api/analyze、batch、url、github、vllm、multi-model、两阶段扫描）。
"""

from __future__ import annotations

import difflib

# 行号锚点前缀：支持 "line 7:" / "L7:" / "第7行:" 等常见形态。
# `line N:` 后紧跟的行文本是我们用于定位的内容锚。
_LINE_ANCHOR_RE = None  # 惰性编译，避免 import 时开销
_CJK_RE = None


def _anchor_re():
    global _LINE_ANCHOR_RE
    if _LINE_ANCHOR_RE is None:
        import re
        # 匹配 "line 7:" / "line7:" / "L7:" / "第 7 行:" / "第7行" 等，
        # 捕获行号与后续文本。
        # content 用非贪婪 + lookahead：在下一个锚点或结尾处截断，避免 `. *`
        # 贪婪吞掉同一文本里的后续锚点；content 保留冒号后的首个空格。
        _LINE_ANCHOR_RE = re.compile(
            r"(?:"
            r"\b(?:line|L)\s*(?P<num_line>\d+)\s*[:：]"
            r"|第\s*(?P<num_cn>\d+)\s*行\s*[:：]?"
            r")"
            r"(?P<content>.*?)"
            r"(?=\s*(?:\b(?:line|L)\s*\d+\s*[:：]|第\s*\d+\s*行\s*[:：]?)|\Z)",
            re.IGNORECASE | re.DOTALL,
        )
    return _LINE_ANCHOR_RE


def _strip_cjk(text: str) -> str:
    """去掉中文字符，保留代码/英文骨架（用于相似度比较）。"""
    global _CJK_RE
    if _CJK_RE is None:
        import re as _re
        _CJK_RE = _re.compile(r"[\u4e00-\u9fff]+")
    return _CJK_RE.sub("", text)


def _norm_frag(frag: str) -> str:
    """归一化单个无空白代码片段（去引号 + 小写）。"""
    return frag.replace("'", "").replace('"', "").lower()


def _code_fragments(text: str) -> list[str]:
    """提取锚点内容中最长的无空白代码片段（≥8 字符，最多 2 个）。

    模型的描述尾缀（中文/英文自由文本）会稀释整串相似度，但代码片段本身
    通常是一个连续无空白 token（如 `request.args.get('file')`），且会
    原样出现在真实源码行中——用它做"包含关系"匹配最稳。
    """
    pieces = sorted(
        (_norm_frag(p) for p in text.split() if len(p) >= 8),
        key=len, reverse=True,
    )
    return pieces[:2]


def _norm(text: str) -> str:
    """归一化行文本用于模糊匹配：去空白/引号大小写差异，保留语义骨架。"""
    if not text:
        return ""
    s = text.strip()
    # 去掉行尾的状态描述（如 "用户可控路径参数"、"直接打开拼接后的路径"），
    # 只保留代码片段本身。以代码关键字/符号特征截断到第一个明显的代码片段结束点。
    s = s.split("（")[0].split("，")[0].split("。")[0]
    # 归一化空白与引号差异
    return "".join(s.split()).replace('"', "").replace("'", "").lower()


def _line_score(
    target_full: str,
    target_cjk: str,
    frags: list[str],
    norm_line: str,
    line_cjk: str,
) -> float:
    """计算锚点内容与单行源码的匹配分（1.0 最强，0 表示无信号）。

    评分：
    1. 整串相等 / 去中文后的代码骨架包含在行内（长片段才可信）→ 1.0；
    2. 最长无空白代码片段包含在行内 → 0.95（容忍中英文自由描述尾缀）；
    3. 退化：取「整串去中文相似度」与「最长代码片段相似度」的较大者——
       片段相似度能覆盖模型省略参数等"内容不完全一致但代码锚清晰"的情况
       （如锚写 `request.args.get('file')`，真实行为 `request.args.get('file', '')`）。
    """
    if target_full == norm_line:
        return 1.0
    if len(target_full) >= 8 and target_full in norm_line:
        return 1.0
    if len(target_cjk) >= 8 and target_cjk in line_cjk:
        return 1.0
    best_frag = 0.0
    for f in frags:
        if f in norm_line:
            return 0.95
        frag_ratio = difflib.SequenceMatcher(None, f, norm_line).ratio()
        if frag_ratio > best_frag:
            best_frag = frag_ratio
    whole_ratio = (
        difflib.SequenceMatcher(None, target_cjk, line_cjk).ratio()
        if target_cjk and line_cjk else 0.0
    )
    return max(whole_ratio, best_frag)


def _find_line(content_anchor: str, code_lines: list[str], orig: int | None = None) -> int | None:
    """在源文件行列表中按内容锚定位真实行号（1-indexed）。

    策略：
    - 高分优先；同分时优先靠近模型原始行号（行号幻觉通常是"差几行"，
      而非跨文件乱跳），重复内容行也能保持幂等；
    - 命中 1.0 且恰为原始行号时立即返回（内容完全吻合时信任原行号）；
    - 低于阈值（0.6）返回 None，不做破坏性覆盖。
    """
    # 去掉锚点内容末尾的分隔符（多锚点场景 content 会残留 "; " 等），
    # 提高整串包含/相等的命中率；输出仍保留原始 content 文本。
    content_anchor = content_anchor.strip().rstrip(";；，,。")
    target_full = _norm(content_anchor)
    if not target_full:
        return None
    target_cjk = _norm(_strip_cjk(content_anchor))
    frags = _code_fragments(content_anchor)
    best_idx: int | None = None
    best_score = 0.0
    for i, line in enumerate(code_lines):
        norm_line = _norm(line)
        score = _line_score(target_full, target_cjk, frags, norm_line, _norm(_strip_cjk(line)))
        if score <= 0:
            continue
        if score == 1.0 and i + 1 == orig:
            return orig  # 幂等快路径：内容完全吻合且行号已正确
        if score > best_score or (
            score == best_score
            and best_idx is not None
            and orig is not None
            and abs((i + 1) - orig) < abs((best_idx + 1) - orig)
        ):
            best_score, best_idx = score, i
    if best_idx is not None and best_score >= 0.6:
        return best_idx + 1  # 0-indexed → 1-indexed
    return None


def normalize_line_numbers(
    text: str,
    code: str,
    return_anchors: bool = False,
) -> str | tuple[str, list[tuple[int, int]]]:
    """纠正文本中的行号锚点（`line N:`）为源文件中的真实行号。

    Args:
        text: 模型输出文本（source / sink / fix_suggestion / explanation）。
        code: 源文件全文（用于内容定位）。
        return_anchors: 为 True 时额外返回 (原行号, 纠正后行号) 列表，供
            需要原值/新值对照的调用方使用；默认只返回纠正后的文本。

    Returns:
        return_anchors=False：纠正后的文本（匹配不到的内容段原样保留）。
        return_anchors=True：(纠正后文本, [(orig_line, fixed_line), ...])。
    """
    if not text or not code:
        return (text, []) if return_anchors else text

    code_lines = code.splitlines()
    if not code_lines:
        return (text, []) if return_anchors else text

    re_anchor = _anchor_re()
    out: list[str] = []
    anchors: list[tuple[int, int]] = []
    last_end = 0
    for m in re_anchor.finditer(text):
        # 锚点之前的普通文本原样保留
        out.append(text[last_end:m.start()])
        num_s = m.group("num_line") or m.group("num_cn")
        content = m.group("content")
        try:
            orig = int(num_s)
        except ValueError:
            out.append(m.group(0))
            last_end = m.end()
            continue
        fixed = _find_line(content, code_lines, orig=orig)
        if fixed is not None and fixed != orig:
            # 纠正后的锚点统一输出为 `line N:` 格式（下游解析器只认该形态）
            out.append(f"line {fixed}:{content}")
            anchors.append((orig, fixed))
        else:
            out.append(m.group(0))
        last_end = m.end()
    out.append(text[last_end:])

    corrected = "".join(out)
    return (corrected, anchors) if return_anchors else corrected


if __name__ == "__main__":
    print("=== 行号纠正自检（离线） ===\n")
    sample = (
        "import os\n"
        "from flask import Flask, request\n"
        "\n"
        "app = Flask(__name__)\n"
        "BASE_DIR = '/var/www/uploads'\n"
        "\n"
        "\n"
        "@app.route('/view')\n"
        "def view():\n"
        "    filename = request.args.get('file', '')\n"
        "    full_path = os.path.join(BASE_DIR, filename)\n"
        "    with open(full_path, 'r') as f:\n"
        "        return f.read()\n"
    )
    cases = [
        # (输入文本, 期望输出)
        ("line 7: request.args.get('file') 用户可控路径参数",
         "line 10: request.args.get('file') 用户可控路径参数"),
        ("line 10: open(full_path) 直接打开拼接后的路径",
         "line 12: open(full_path) 直接打开拼接后的路径"),
        # 已经是正确行号 → 幂等
        ("line 10: request.args.get('file', '') 用户可控路径参数",
         "line 10: request.args.get('file', '') 用户可控路径参数"),
        # 无行号前缀 → 原样返回
        ("无行号锚定的普通文本", "无行号锚定的普通文本"),
        # 匹配不到语义锚 → 原样保留（不破坏）
        ("line 3: 这段代码在源码里不存在", "line 3: 这段代码在源码里不存在"),
        # 多个行号锚
        ("line 7: request.args.get('file'); line 8: os.path.join(BASE_DIR, filename)",
         "line 10: request.args.get('file'); line 11: os.path.join(BASE_DIR, filename)"),
    ]
    ok = True
    for text, exp in cases:
        got = normalize_line_numbers(text, sample)
        passed = got == exp
        ok = ok and passed
        print(f"[{'PASS' if passed else 'FAIL'}] {text!r}\n     -> {got!r}\n     期望 {exp!r}")

    # 边界补充：第N行格式、长中文/英文描述（描述不应稀释代码锚）、
    # 重复内容行（幂等：原行号正确时不得被纠到另一处同内容行）
    extra = [
        ("第 7 行: request.args.get('file') 用户可控路径参数",
         "line 10: request.args.get('file') 用户可控路径参数"),
        ("line 7: request.args.get('file') 这是一个非常非常长的中文说明文字用来测试匹配阈值会不会被稀释掉",
         "line 10: request.args.get('file') 这是一个非常非常长的中文说明文字用来测试匹配阈值会不会被稀释掉"),
        ("line 7: request.args.get('file') user-controlled path param",
         "line 10: request.args.get('file') user-controlled path param"),
    ]
    for text, exp in extra:
        got = normalize_line_numbers(text, sample)
        passed = got == exp
        ok = ok and passed
        print(f"[{'PASS' if passed else 'FAIL'}] 边界: {text[:42]!r}...\n     -> {got!r}\n     期望 {exp!r}")

    dup_code = (
        "x = 1\n"
        "q = 'select * from t'\n"
        "cursor.execute(q)\n"
        "y = 2\nz = 3\nw = 4\nv = 5\nu = 6\ns = 7\nt = 8\nr = 9\n"
        "cursor.execute(q)\n"
        "print('done')\n"
    )
    dup_near = normalize_line_numbers("line 2: cursor.execute(q)", dup_code)
    dup_idem = normalize_line_numbers("line 12: cursor.execute(q)", dup_code)
    ok_dup_near = dup_near == "line 3: cursor.execute(q)"
    ok_dup_idem = dup_idem == "line 12: cursor.execute(q)"
    ok = ok and ok_dup_near and ok_dup_idem
    print(f"[{'PASS' if ok_dup_near else 'FAIL'}] 重复行就近: {dup_near!r} (期望 'line 3: cursor.execute(q)')")
    print(f"[{'PASS' if ok_dup_idem else 'FAIL'}] 重复行幂等: {dup_idem!r} (期望 'line 12: cursor.execute(q)')")

    print(f"\n{'全部通过' if ok else '存在失败'}")
