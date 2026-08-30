# -*- coding: utf-8 -*-
"""S4 转义污染 / S5 截断与污染 / S6 凭证扫描。

输出：out/s4s5s6_out.txt + out/s4_escape.jsonl + out/s5_contam.jsonl + out/s6_creds.jsonl
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acommon import OUT, load_rows, asst_text, user_text, last_json, write_jsonl, pct

LOG = []


def P(*a):
    LOG.append(" ".join(str(x) for x in a))


rows, _ = load_rows()

# ---------------- S4 转义污染 ----------------
s4 = []
for r in rows:
    o, raw, err = last_json(asst_text(r))
    if not isinstance(o, dict):
        continue
    for fld in ("fix_suggestion", "explanation", "source", "sink"):
        t = str(o.get(fld, ""))
        if not t:
            continue
        # JSON 解码后仍出现连续反斜杠（≥2）= 双重转义污染
        runs = re.findall(r"\\{2,}", t)
        # 字面 \n 序列（反斜杠+n 可见）也是典型污染
        lit_n = len(re.findall(r"\\n", t))
        if runs or lit_n >= 2:
            s4.append({"id": r["id"], "field": fld,
                       "max_bs": max((len(x) for x in runs), default=0),
                       "lit_n": lit_n,
                       "sample": t[:120]})
P(f"S4 转义污染样本: {len(s4)} ({pct(len(s4), len(rows))})")
bs_dist = Counter(x["max_bs"] for x in s4)
P(f"  最大连续反斜杠分布: {dict(sorted(bs_dist.items()))}")

# ---------------- S5 截断与污染 ----------------
SPECIAL_TOKENS = ["<|im_start|>", "<|im_end|>", "<|endoftext|>", "<|object_ref_start|>",
                  "<|user|>", "<|assistant|>", "<|system|>"]
ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]")
s5 = []
think_cnt = 0
end_stats = Counter()
for r in rows:
    rid = r["id"]
    a = asst_text(r)
    u = user_text(r)
    issues = []
    # 截断：assistant 结尾形态
    t = a.rstrip()
    if t.endswith("```"):
        end_stats["ends_fence_closed"] += 1
    elif "```json" in a and t.endswith("}"):
        end_stats["ends_json_brace_no_fence"] += 1
    elif t.endswith("。") or t.endswith("）") or t.endswith(")"):
        end_stats["ends_sentence"] += 1
    else:
        end_stats["ends_other"] += 1
        issues.append({"type": "suspect_truncation", "tail": t[-80:]})
    # 未闭合 fence 计数（assistant 与 user）
    for name, txt in (("assistant", a), ("user", u)):
        n_fence = len(re.findall(r"```", txt))
        if n_fence % 2 == 1:
            issues.append({"type": f"unclosed_fence_{name}", "count": n_fence})
    # JSON 块未闭合（有 ```json 开头但 brace 不闭合）
    if "```json" in a:
        m = re.search(r"```json\s*(.*)\Z", a, re.S)
        if m and m.group(1).count("{") > m.group(1).count("}"):
            issues.append({"type": "json_unclosed_brace"})
    # 特殊 token 字面量
    for name, txt in (("assistant", a), ("user", u)):
        for tok in SPECIAL_TOKENS:
            if tok in txt:
                issues.append({"type": f"special_token_{name}", "tok": tok})
    # 零宽/RTL
    for name, txt in (("assistant", a), ("user", u)):
        zw = ZERO_WIDTH.findall(txt)
        if zw:
            issues.append({"type": f"zero_width_{name}",
                           "chars": [hex(ord(c)) for c in set(zw)]})
    if "<think>" in a or "</think>" in a or "<think>" in u:
        think_cnt += 1
        issues.append({"type": "think_block"})
    if issues:
        s5.append({"id": rid, "issues": issues})

P("")
P(f"S5 截断/污染样本: {len(s5)}")
P(f"  assistant 结尾形态: {dict(end_stats)}")
P(f"  think 块样本: {think_cnt}")
cat = Counter()
for x in s5:
    for i in x["issues"]:
        cat[i["type"]] += 1
for t, n in cat.most_common():
    P(f"  {t}: {n}")

# ---------------- S6 凭证扫描 ----------------
CRED_PATTERNS = [
    ("sk_live_prefix", re.compile(r"\bsk-(?:live|proj|svcacct|ant)?-?[A-Za-z0-9_\-]{20,}")),
    ("AKIA", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("ghp_", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("google_api", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("jwt_ey", re.compile(r"\beyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\b")),
]
DUMMY_HINT = re.compile(r"(?i)(xxxx|x{4,}|\*\*\*|example|your[_-]|placeholder|<[^>]*>| dummy |sample[_-]|test[_-]?key|redacted|场景|演示|虚构|模拟|假设)", )
s6 = []
for r in rows:
    rid = r["id"]
    a = asst_text(r)
    u = user_text(r)
    for name, pat in CRED_PATTERNS:
        for m in pat.finditer(a):
            ctx = a[max(0, m.start() - 60):m.end() + 40].replace("\n", " ")
            dummy = bool(DUMMY_HINT.search(ctx))
            s6.append({"id": rid, "where": "assistant", "kind": name,
                       "match": m.group(0)[:50], "dummy_hint": dummy, "ctx": ctx[:140]})
        for m in pat.finditer(u):
            ctx = u[max(0, m.start() - 60):m.end() + 40].replace("\n", " ")
            dummy = bool(DUMMY_HINT.search(ctx))
            s6.append({"id": rid, "where": "user", "kind": name,
                       "match": m.group(0)[:50], "dummy_hint": dummy, "ctx": ctx[:140]})
real_like = [x for x in s6 if not x["dummy_hint"]]
P("")
P(f"S6 凭证格式命中: {len(s6)} 处（其中疑似虚构/占位 {len(s6) - len(real_like)}，疑似真实格式 {len(real_like)}）")
kind_real = Counter(x["kind"] for x in real_like)
P(f"  疑似真实格式按类型: {dict(kind_real)}")

write_jsonl(OUT / "s4_escape.jsonl", s4)
write_jsonl(OUT / "s5_contam.jsonl", s5)
write_jsonl(OUT / "s6_creds.jsonl", s6)
(OUT / "s4s5s6_out.txt").write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("\n".join(LOG))
