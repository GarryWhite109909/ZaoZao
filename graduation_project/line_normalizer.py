"""
行号纠正工具（与 cwe_normalizer 同思路：确定性查表/匹配，纠正模型输出）。

背景：模型输出的 source / sink / fix_suggestion 采用"行号锚定"格式
（如 "line 7: request.args.get('file') 用户可控路径参数"）。行号是纯
"数行"任务，模型容易数错（多算/漏算 import、装饰器、空行，或切片后按
chunk 相对行号输出），但 `line N:` 后面的**行文本内容**通常是可靠的。
本工具在模型输出之后做确定性纠正：用行文本内容在源文件中定位真实行号，
覆盖掉错误的 N。

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


def _anchor_re():
    global _LINE_ANCHOR_RE
    if _LINE_ANCHOR_RE is None:
        import re
        # 匹配 "line 7:" / "line7:" / "L7:" / "第 7 行:" 等，捕获行号与后续文本。
        # content 用非贪婪 + lookahead：在下一个锚点或结尾处截断，避免 `. *`
        # 贪婪吞掉同一文本里的后续锚点；content 保留冒号后的首个空格。
        _LINE_ANCHOR_RE = re.compile(
            r"(?P<pre>\b(?:line|L)\s*)(?P<num>\d+)\s*[:：]"
            r"(?P<content>.*?)(?=\s*\b(?:line|L)\s*\d+\s*[:：]|\Z)",
            re.IGNORECASE | re.DOTALL,
        )
    return _LINE_ANCHOR_RE


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


def _find_line(content_anchor: str, code_lines: list[str]) -> int | None:
    """在源文件行列表中按内容锚定位真实行号（1-indexed）。

    用 difflib 的 SequenceMatcher 对每个候选行做相似度匹配，命中最高且
    超过阈值者返回其真实行号；低于阈值返回 None（不做破坏性覆盖）。
    """
    target = _norm(content_anchor)
    if not target:
        return None
    best_idx, best_ratio = None, 0.0
    for i, line in enumerate(code_lines):
        ratio = difflib.SequenceMatcher(None, target, _norm(line)).ratio()
        if ratio > best_ratio:
            best_ratio, best_idx = ratio, i
    # 阈值：>=0.6 视为可靠锚定（内容片段较短时容忍更多差异）
    if best_idx is not None and best_ratio >= 0.6:
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
        pre, num_s, content = m.group("pre"), m.group("num"), m.group("content")
        try:
            orig = int(num_s)
        except ValueError:
            out.append(m.group(0))
            last_end = m.end()
            continue
        fixed = _find_line(content, code_lines)
        if fixed is not None and fixed != orig:
            out.append(f"{pre}{fixed}:{content}")
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
    print(f"\n{'全部通过' if ok else '存在失败'}")