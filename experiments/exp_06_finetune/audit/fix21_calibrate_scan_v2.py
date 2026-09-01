# -*- coding: utf-8 -*-
"""§2.1 行号全量校准 —— 第二阶段：收紧后的 source/sink 专用扫描。

相对第一版的过滤（依据 25 条抽验的失败模式）：
  1. 只校准 source / sink（fix 锚语义是"待改行"、explanation 是散文叙事，
     内容匹配的失败模式均不可接受，退出自动校准范围）
  2. 多文件识别加强：识别 `=== file:` / `-- file:` 等嵌入分隔
  3. 注释落点拒绝：新行是注释而旧行是代码 → 放弃该锚
  4. 越界拒绝：新行号 > 代码行数 → 放弃（库内 delta 传播上界 bug 已修，
     此处双保险）
  5. 空行落点拒绝
产出 fix21_candidates_v2.jsonl 供第二轮 50 条抽验。
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "agent_audit_v2_14"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from acommon import BASE
from graduation_project.line_normalizer import normalize_line_numbers

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
OUT_CAND = Path(__file__).resolve().parent / "fix21_candidates_v2.jsonl"

FENCE = re.compile(r"```[\w+#.\-/]*[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)
FILE_SEP = re.compile(
    r"^(?:={3,}\s*(?:文件|File)|#{1,3}\s*(?:文件|File)\s*[:# ]|//\s*====\s*File|【文件\s*\d|File\s*\d+\s*[:：]|###\s*文件\s*[:：])",
    re.M)
FILE_SEP2 = re.compile(r"^\s*(?:#|//|--|<!--)\s*===?\s*file\s*[:=]?.*$", re.I | re.M)
COMMENT_RE = re.compile(r"^\s*(?:#|//|/\*|\*|--|<!--|<!---)")
FIELDS = ("source", "sink")

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
            kept = []
            for (old, new) in anchors:
                if new > len(code_lines) or new < 1:
                    continue  # 越界拒绝
                old_l = code_lines[old - 1].strip() if 0 < old <= len(code_lines) else ""
                new_l = code_lines[new - 1].strip()
                if not new_l:
                    continue  # 空行落点拒绝
                old_is_code = bool(old_l) and not COMMENT_RE.match(old_l)
                if old_is_code and COMMENT_RE.match(new_l):
                    continue  # 注释落点拒绝（代码→注释 = 恶化）
                kept.append((old, new))
            if kept and new_t != t:
                # 仅应用保留的锚：以 kept 为准重放（简单法：整文本已被
                # normalizer 改写，若存在被拒锚则放弃整字段，保守优先）
                all_kept = len(kept) == len(anchors)
                changed[fld] = {"before": t, "after": new_t,
                                "anchors": anchors, "kept": kept,
                                "all_kept": all_kept}
                if all_kept:
                    field_stats[fld] += 1
        kept_only = {k: v for k, v in changed.items() if v["all_kept"]}
        if kept_only:
            cand.append({"line": lineno, "changes": kept_only})

with OUT_CAND.open("w", encoding="utf-8") as f:
    for c in cand:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")
print(f"全库 {n_total} | 单文件 {n_single} | 多文件跳过 {n_multi}")
print(f"候选(全锚保留): {len(cand)}（字段级: {dict(field_stats)}）")
