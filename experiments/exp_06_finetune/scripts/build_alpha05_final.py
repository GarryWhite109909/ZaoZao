# -*- coding: utf-8 -*-
"""α0.5 最终训练集组装脚本。

输入：
  - data/final_train_chatml_alpha05_raw.jsonl   （修正+骨架去重后的 base，7825 条）
  - data/supplement_alpha05_*.jsonl             （盲区/痛点/归因/真实CVE/架构适配补充）
输出：
  - data/final_train_chatml_alpha05.jsonl       （α0.5 最终训练集）

步骤：
  1. 载入 base + 全部补充；
  2. 泄露门禁：所有补充样本对测试集 Jaccard 必须 < LEAK_GATE（防训练→测试泄露）；
  3. 统一 system prompt 为 ALPHA05_PROMPT；
  4. 组装写出并打印统计。
"""
import json, re, sys, hashlib, os
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# 仓库根 = 本脚本（experiments/exp_06_finetune/scripts/）向上三级；
# 可用环境变量 GRAD_ROOT 覆盖（脚本被拷到别处运行时）。原先硬编码
# D:\code\... Windows 绝对路径，Linux 上无法运行
ROOT = Path(os.environ.get("GRAD_ROOT") or Path(__file__).resolve().parents[3])
sys.path.insert(0, str(ROOT))
from graduation_project.prompts import ALPHA05_PROMPT

DATA = ROOT / "experiments" / "exp_06_finetune" / "data"
BASE = DATA / "final_train_chatml_alpha05_raw.jsonl"
# 注意：triage（架构适配裁决样本）不并入本文件——它的输出 schema 是 is_confirmed，
# 与主扫描的 has_vulnerability schema 不同，混训会互相污染。triage 独立成
# supplement_alpha05_triage.jsonl，配 triage 专属 system prompt，供裁决任务单独微调。
SUPP_FILES = [
    "supplement_alpha05_blindspot.jsonl",
    "supplement_alpha05_painpoints.jsonl",
    "supplement_alpha05_attribution.jsonl",
    "supplement_alpha05_realcve.jsonl",
    "supplement_alpha05_gaps.jsonl",
]
OUT = DATA / "final_train_chatml_alpha05.jsonl"
TESTSET = ROOT / "experiments" / "exp_04_hard_samples" / "samples"
LEAK_GATE = 0.50   # 补充样本对测试集 Jaccard 上限；>= 则判定泄露（与项目数据审计阈值一致），阻断构建

CODE_RE = re.compile(r"```(?:\w+)?\n(.*?)```", re.S)
JSON_RE = re.compile(r"```json\s*(.*?)```", re.S)
COMMENT_RE = re.compile(r"(#[^\n]*|//[^\n]*|/\*.*?\*/)", re.S)
STR_RE = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`")
NUM_RE = re.compile(r"\b\d+\b")

def norm_lines(code):
    code = COMMENT_RE.sub(" ", code)
    code = STR_RE.sub("S", code)
    code = NUM_RE.sub("N", code)
    return [t for ln in code.splitlines() if (t := ln.strip()) and len(t) >= 4]

def load(path):
    recs, codes = [], []
    with path.open(encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            rec = json.loads(ln)
            user = rec["messages"][1]["content"]
            cm = CODE_RE.search(user)
            codes.append(cm.group(1) if cm else "")
            recs.append(rec)
    return recs, codes

base, base_codes = load(BASE)
print(f"base={len(base)}")
sups = []   # (src_name, recs, codes)
for fn in SUPP_FILES:
    p = DATA / fn
    if p.exists():
        recs, codes = load(p)
        sups.append((fn, recs, codes))
        print(f"  {fn}: {len(recs)} 条")

# ---- 泄露门禁：所有补充样本对测试集 Jaccard 必须 < LEAK_GATE ----
test_files = sorted(TESTSET.glob("*.py")) + sorted(TESTSET.glob("*.java"))
test_sets = []
for tf in test_files:
    test_sets.append((tf.name, set(norm_lines(tf.read_text(encoding="utf-8", errors="replace")))))

leaky = []
for src, recs, codes in sups:
    for i, c in enumerate(codes):
        ls = set(norm_lines(c))
        if not ls:
            continue
        for name, tls in test_sets:
            inter = len(ls & tls)
            union = len(ls) + len(tls) - inter
            j = inter / union if union else 0.0
            if j >= LEAK_GATE:
                leaky.append((src, i + 1, name, round(j, 3)))
if leaky:
    print(f"[FATAL] 补充样本与测试集泄露（>= {LEAK_GATE}）：")
    for x in leaky:
        print("   ", x)
    sys.exit(2)
print(f"[OK] 全部补充样本对测试集最大 Jaccard < {LEAK_GATE}，无泄露")

# 组装
final = base + [r for _, recs, _ in sups for r in recs]

# 统一 system prompt 为 α0.5 精简版
unified = 0
for rec in final:
    if rec["messages"][0].get("content") != ALPHA05_PROMPT:
        rec["messages"][0]["content"] = ALPHA05_PROMPT
        unified += 1
print(f"system prompt 统一: {unified} 条替换为 ALPHA05_PROMPT")

# 统一后校验：只有一种 system prompt
sp_hashes = set(hashlib.md5(rec["messages"][0]["content"].encode()).hexdigest()[:8] for rec in final)
print(f"system prompt 变体数: {len(sp_hashes)}（期望 1）")

with OUT.open("w", encoding="utf-8") as fh:
    for rec in final:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"写出 -> {OUT} ({len(final)} 条)")

# 标签 + CWE 分布（兼容 verdict has_vulnerability 与 triage is_confirmed）
lab = Counter()
cwe = Counter()
for rec in final:
    asst = rec["messages"][2]["content"]
    jm = JSON_RE.search(asst)
    if jm:
        try:
            v = json.loads(jm.group(1))
            h = v.get("has_vulnerability", v.get("is_confirmed"))
            lab[h] += 1
            m = re.search(r"CWE-(\d+)", v.get("vulnerability_type", "") or "")
            if m:
                cwe[m.group(1)] += 1
        except Exception:
            lab["parse"] += 1
    else:
        lab["no_json"] += 1
print("标签分布(has_vulnerability/is_confirmed):", dict(lab))
print("Top CWE:", dict(cwe.most_common(20)))
