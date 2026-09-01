# -*- coding: utf-8 -*-
"""§2.1 第三阶段：精确片段包含规则（v2 基础上追加）。

追加规则（依据第二轮抽验残余错误）：
  6. 每个锚的新落点行必须【精确包含】锚内容中至少一个 ≥8 字符代码片段
     （复用 line_normalizer 的 _code_fragments/_norm 归一）——纯散文锚与
     相似度匹配全部拒绝（如 'router.post' 锚匹配到 require 行、
     'base64 回显' 匹配到 'B64.' 垃圾行均被此规则杀掉）。
产出 fix21_candidates_v3.jsonl。
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "agent_audit_v2_14"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from acommon import BASE
from graduation_project.line_normalizer import normalize_line_numbers, _code_fragments, _norm

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
OUT_CAND = Path(__file__).resolve().parent / "fix21_candidates_v3.jsonl"

FENCE = re.compile(r"```[\w+#.\-/]*[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)
FILE_SEP = re.compile(
    r"^(?:={3,}\s*(?:文件|File)|#{1,3}\s*(?:文件|File)\s*[:# ]|//\s*====\s*File|【文件\s*\d|File\s*\d+\s*[:：]|###\s*文件\s*[:：])",
    re.M)
FILE_SEP2 = re.compile(r"^\s*(?:#|//|--|<!--)\s*===?\s*file\s*[:=]?.*$", re.I | re.M)
COMMENT_RE = re.compile(r"^\s*(?:#|//|/\*|\*|--|<!--)")
FIELDS = ("source", "sink")

# 锚内容截取：line_normalizer 的锚正则（简化复刻：取 line N: 后到下一锚/句末）
ANCHOR_CONTENT = re.compile(
    r"(?:\b(?:lines?|L)\s*(\d+)(?:\s*[-–~]\s*\d+)?(?:\s*[:：]|\s(?=\S))|第\s*(\d+)\s*(?:[-–~]\s*\d+\s*)?行\s*[:：]?)"
    r"(.*?)(?=\s*(?:\b(?:lines?|L)\s*\d+(?:\s*[-–~]\s*\d+)?(?:\s*[:：]|\s(?=\S))|第\s*\d+\s*(?:[-–~]\s*\d+\s*)?行\s*[:：]?)|\Z)",
    re.IGNORECASE | re.DOTALL)

def anchor_passes(t_after, old, new, code_lines):
    """单个锚是否满足全部严格规则。"""
    if new > len(code_lines) or new < 1:
        return False
    new_l = code_lines[new - 1].strip()
    old_l = code_lines[old - 1].strip() if 0 < old <= len(code_lines) else ""
    if not new_l:
        return False
    old_is_code = bool(old_l) and not COMMENT_RE.match(old_l)
    if old_is_code and COMMENT_RE.match(new_l):
        return False
    # 锚内容（取 after 中该锚的描述段）
    m = re.search(rf"(?:line\s*{new}\b|第\s*{new}\s*行)\s*[:：]?\s*(.*?)(?=(?:\b(?:lines?|L)\s*\d+|第\s*\d+\s*行)|$)",
                  t_after, re.IGNORECASE | re.DOTALL)
    content = m.group(1) if m else ""
    frags = [f for f in _code_fragments(content) if len(f) >= 8]
    if not frags:
        return False  # 纯散文锚拒绝
    norm_new = _norm(new_l)
    return any(f in norm_new for f in frags)  # 精确包含

n_total = n_single = n_multi = 0
cand = []
field_stats = Counter()

with DATA.open(encoding="utf-8") as f:
    for lineno, line in enumerate(f, 1):
        if not line.strip():
            continue
        n_total += 1
        rec = json.loads(line)
        u = rec["messages"][1]["content"]
        a = rec["messages"][2]["content"]
        blocks = FENCE.findall(u)
        if len(blocks) >= 2 or FILE_SEP.search(u) or FILE_SEP2.search(u):
            n_multi += 1
            continue
        if not blocks:
            continue
        n_single += 1
        code = blocks[0]
        code_lines = code.split("\n")
        jb = re.findall(r"```json\s*(.*?)```", a, re.S)
        if not jb:
            continue
        try:
            o = json.loads(jb[-1])
        except Exception:
            continue
        changed = {}
        for fld in FIELDS:
            t = str(o.get(fld, "") or "")
            if not t:
                continue
            new_t, anchors = normalize_line_numbers(t, code, return_anchors=True)
            if not anchors or new_t == t:
                continue
            kept = [(old, new) for (old, new) in anchors
                    if anchor_passes(new_t, old, new, code_lines)]
            if kept and len(kept) == len(anchors):
                changed[fld] = {"before": t, "after": new_t, "anchors": anchors}
                field_stats[fld] += 1
        if changed:
            cand.append({"line": lineno, "changes": changed})

with OUT_CAND.open("w", encoding="utf-8") as f:
    for c in cand:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")
print(f"全库 {n_total} | 单文件 {n_single} | 多文件跳过 {n_multi}")
print(f"候选(全锚通过严格规则): {len(cand)}（字段级: {dict(field_stats)}）")
