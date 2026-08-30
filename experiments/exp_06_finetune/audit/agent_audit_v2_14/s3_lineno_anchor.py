# -*- coding: utf-8 -*-
"""S3 行号锚定表（核心基建）：教师引用行号 → 实际行内容 → 引用摘录 → 命中判定。

坐标：单文件 = fence 内 1-based 行号；多文件 = 各 fence 块内独立 1-based，
命中判定跨块取最优。输出逐样本 refs + 全库统计；miss/near 样本进 flags。

输出：out/s3_refs.jsonl（全量）、out/s3_out.txt、out/s3_flags.jsonl
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acommon import OUT, load_rows, code_blocks, last_json, write_jsonl, pct, is_multi_file

LOG = []


def P(*a):
    LOG.append(" ".join(str(x) for x in a))


STOP_ID = {"line", "return", "function", "const", "string", "value", "data",
           "input", "output", "error", "param", "self", "this", "true", "false",
           "none", "null", "int", "str", "def", "var", "let", "len", "print",
           "file", "name", "user", "index", "https", "http", "com", "www"}


def quote_identifiers(quote):
    ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", quote)
    return [i for i in ids if i.lower() not in STOP_ID]


def field_refs(text):
    """从字段文本抽 (n, quote)。锚定式 'line N: xxx' 取冒号后描述；叙事式 '第N行' 取前后文。"""
    refs = []
    for m in re.finditer(r"line\s*(\d{1,4})\s*[:：]?\s*([^\n]{0,80})", text, re.I):
        n = int(m.group(1))
        q = (m.group(2) or "").strip()
        if not q:
            pre = text[max(0, m.start() - 40):m.start()]
            q = pre.strip()[-60:]
        refs.append((n, q, m.group(0)[:40]))
    for m in re.finditer(r"第\s*(\d{1,4})\s*行([^\n]{0,60})", text):
        n = int(m.group(1))
        refs.append((n, (m.group(2) or "").strip(), m.group(0)[:40]))
    return refs


rows, _ = load_rows()
stat = Counter()
flags = []
out_f = open(OUT / "s3_refs.jsonl", "w", encoding="utf-8")

for r in rows:
    rid = r["id"]
    user = r["rec"]["messages"][1]["content"]
    blocks = code_blocks(user)
    if not blocks:
        stat["no_code_block"] += 1
        continue
    multi = len(blocks) >= 2 or is_multi_file(user)
    # 每块行表
    block_lines = [b.rstrip("\n").split("\n") for _, b in blocks]
    a = r["rec"]["messages"][2]["content"]
    o, raw, err = last_json(a)
    body = a.split("```json")[0] if "```json" in a else a
    fields = {}
    if isinstance(o, dict):
        for k in ("source", "sink", "fix_suggestion", "explanation"):
            fields[k] = str(o.get(k, ""))
    fields["body"] = body

    refs_out = []
    per_field_hit = Counter()
    for fld, text in fields.items():
        for n, quote, anchor in field_refs(text):
            stat["refs_total"] += 1
            stat[f"field_{fld}"] += 1
            # 命中判定：跨所有块
            best = None  # (status, block_idx, actual)
            ids = quote_identifiers(quote)
            candidates = []
            for bi, lines in enumerate(block_lines):
                if 1 <= n <= len(lines):
                    actual = lines[n - 1].strip()
                    if ids and any(i in actual for i in ids):
                        candidates.append(("hit", bi, actual))
                    elif not ids:
                        candidates.append(("no_ids", bi, actual))
            if candidates:
                status, bi, actual = candidates[0]
            else:
                # near：±2 行
                near = []
                for bi, lines in enumerate(block_lines):
                    for dn in (-2, -1, 1, 2):
                        j = n + dn
                        if 1 <= j <= len(lines) and ids and any(i in lines[j - 1] for i in ids):
                            near.append((bi, j, lines[j - 1].strip()))
                if near:
                    bi, j, actual = near[0]
                    status, n_eff = "near", j
                else:
                    inrange = any(1 <= n <= len(lines) for lines in block_lines)
                    status = "out_of_range" if not inrange else "miss"
                    bi = 0
                    actual = block_lines[0][n - 1].strip() if (block_lines and 1 <= n <= len(block_lines[0])) else ""
                    n_eff = n
            refs_out.append({"f": fld, "n": n, "q": quote[:80], "s": status,
                             "a": actual[:100]})
            per_field_hit[fld] += 1 if status == "hit" else 0
            stat[f"status_{status}"] += 1
            stat[f"{fld}_{status}"] += 1

    if refs_out:
        n_refs = len(refs_out)
        n_hit = sum(1 for x in refs_out if x["s"] == "hit")
        # source/sink 是必须精确锚定的字段（fix/explanation/body 语义上允许改写/跨行叙事）
        anchor_refs = [x for x in refs_out if x["f"] in ("source", "sink")]
        anchor_miss = [x for x in anchor_refs if x["s"] in ("miss", "out_of_range")]
        if anchor_refs and len(anchor_miss) == len(anchor_refs) and not multi:
            flags.append({"id": rid, "type": "anchor_all_miss",
                          "refs": anchor_miss[:4]})
        elif len(anchor_miss) >= 2 and len(anchor_miss) >= len(anchor_refs) - 0 and not multi and len(anchor_refs) >= 2:
            flags.append({"id": rid, "type": "anchor_majority_miss",
                          "miss": len(anchor_miss), "total": len(anchor_refs),
                          "refs": anchor_miss[:3]})
    out_f.write(json.dumps({"id": rid, "multi": multi, "refs": refs_out},
                           ensure_ascii=False) + "\n")

out_f.close()
P(f"读入 {len(rows)} 条")
P(f"refs_total: {stat['refs_total']}")
for k in ("hit", "near", "miss", "out_of_range", "no_ids"):
    P(f"  {k}: {stat['status_' + k]} ({pct(stat['status_' + k], stat['refs_total'])})")
P("")
P("== 按字段 × 状态 ==")
for fld in ("source", "sink", "fix_suggestion", "explanation", "body"):
    tot = stat[f"field_{fld}"]
    parts = " ".join(f"{s}={stat[fld + '_' + s]}({pct(stat[fld + '_' + s], tot)})" if tot else f"{s}=0"
                     for s in ("hit", "near", "miss", "out_of_range", "no_ids"))
    P(f"  {fld}: n={tot} | {parts}")
P("")
P(f"no_code_block: {stat['no_code_block']}")
P(f"flags: {len(flags)}")

write_jsonl(OUT / "s3_flags.jsonl", flags)
(OUT / "s3_out.txt").write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("\n".join(LOG))
