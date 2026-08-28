#!/usr/bin/env python3
"""v2.7 审计第三段：毒化样本清点 / 缺字段段 / 行号锚定核验。结果写文件。"""
import json
import re
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))
DATA = PROJECT / "experiments/exp_06_finetune/data/final_train_chatml_alpha06_v2_7.jsonl"
OUT = PROJECT / "experiments/exp_06_finetune/scripts/_audit_v2_7_probe3_out.txt"
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
CODE_RE = re.compile(r"```([\w+#-]*)\n(.*?)\n```", re.S)

rows = [json.loads(l) for l in DATA.read_text(encoding="utf-8").splitlines() if l.strip()]
buf = []
def w(s=""):
    buf.append(s)

# 1) 生成元话语毒化清点
META_TALK = ["为满足", "要求是", "需修正", "已生成", "为达到", "生成要求", "任务要求", "为了构造", "构造漏洞", "需修改第", "改为漏洞", "标注实际漏洞"]
hits = []
for i, r in enumerate(rows):
    a = r["messages"][2]["content"]
    found = [t for t in META_TALK if t in a]
    if found:
        m = JSON_RE.search(a)
        hv = None
        if m:
            try:
                hv = json.loads(m.group(1)).get("has_vulnerability")
            except Exception:
                pass
        hits.append((i, found, hv))
w(f"生成元话语命中: {len(hits)} 条")
for i, f, hv in hits[:40]:
    w(f"  #{i} hv={hv} 命中={f}")
lang_of = {}
for i, r in enumerate(rows):
    cm = CODE_RE.search(r["messages"][1]["content"])
    lang_of[i] = (cm.group(1) if cm else "?")
w("元话语样本语言分布: " + str({l: sum(1 for i, _, _ in hits if lang_of.get(i) == l) for l in {lang_of.get(i) for i, _, _ in hits}}))
w(f"元话语样本行号范围: {hits[0][0] if hits else '-'} ~ {hits[-1][0] if hits else '-'}")

# 2) CoT-终判矛盾 18 条全量
CONCL = re.compile(r"(不存在漏洞|没有漏洞|无漏洞|代码是安全|可判定安全|不存在安全问题|实际无漏洞)")
suspects = []
for i, r in enumerate(rows):
    a = r["messages"][2]["content"]
    m = JSON_RE.search(a)
    if not m:
        continue
    try:
        obj = json.loads(m.group(1))
    except Exception:
        continue
    pre = a[: m.start()]
    if obj.get("has_vulnerability") is True and CONCL.search(pre[-600:]):
        suspects.append((i, obj.get("vulnerability_type")))
w(f"\n终判矛盾候选: {len(suspects)} 条")
for i, vt in suspects:
    in_meta = i in {h[0] for h in hits}
    w(f"  #{i} vt={vt} 元话语={'是' if in_meta else '否'}")

# 3) 8093-8116 段详情
w("\n--- 8093-8116 段（24 条缺字段）---")
for i in (8093, 8096, 8105, 8116):
    r = rows[i]
    meta = r.get("meta") or {}
    m = JSON_RE.search(r["messages"][2]["content"])
    obj = json.loads(m.group(1)) if m else {}
    w(f"#{i} kind={meta.get('kind')} keys={list(obj.keys())}")
    w(f"   obj={json.dumps(obj, ensure_ascii=False)[:300]}")
    w(f"   user 开头: {r['messages'][1]['content'][:150]!r}")

# 4) #8058 行号锚定核验：代码块内是否含行号前缀/实际行数
w("\n--- #8058 代码块核验 ---")
r = rows[8058]
blocks = CODE_RE.findall(r["messages"][1]["content"])
for j, (lg, body) in enumerate(blocks):
    lines = body.split("\n")
    w(f"块{j} 语言={lg} 行数={len(lines)}")
    w(f"  首3行: {lines[:3]}")
    w(f"  末2行: {lines[-2:]}")
    numbered = sum(1 for ln in lines if re.match(r"^\s*\d+[\s|:]", ln))
    w(f"  行号前缀行数: {numbered}")
# 检查 assistant 引用的行在块里对应什么
code = blocks[0][1].split("\n")
for ln in (201, 202, 218, 223, 237, 246):
    if ln <= len(code):
        w(f"  L{ln}: {code[ln-1][:80]!r}")
    else:
        w(f"  L{ln}: 超出块行数 {len(code)}")

# 5) evidence 段所有样本的行号引用 vs 块行数（判断是否系统性行号错位）
w("\n--- evidence 段行号锚定全查 ---")
bad_ev = 0
tot_ev = 0
for i, r in enumerate(rows):
    meta = r.get("meta") or {}
    if not str(meta.get("kind", "")).startswith("evidence"):
        continue
    tot_ev += 1
    blocks = CODE_RE.findall(r["messages"][1]["content"])
    n = max((b[1].count("\n") + 1 for b in blocks), default=0)
    m = JSON_RE.search(r["messages"][2]["content"])
    if not m:
        continue
    txt = r["messages"][2]["content"]
    flat = []
    for a, b in re.findall(r"\b[Ll]ine\s*(\d+)|\bL(\d+)\b", txt):
        flat.append(int(a or b))
    oob = [x for x in flat if x > n]
    if oob:
        bad_ev += 1
        if bad_ev <= 10:
            w(f"  #{i} 块最大行数={n} 越界引用={sorted(set(oob))[:8]}")
w(f"evidence 总数 {tot_ev}，行号引用越界 {bad_ev}")

# 6) vt 违规全量清点（格式）
w("\n--- vt 格式违规清点 ---")
from collections import Counter
pat = Counter()
for i, r in enumerate(rows):
    m = JSON_RE.search(r["messages"][2]["content"])
    if not m:
        continue
    try:
        obj = json.loads(m.group(1))
    except Exception:
        continue
    hv = obj.get("has_vulnerability")
    vt = obj.get("vulnerability_type")
    if hv is True:
        if vt == "none" or vt is None:
            pat["vuln但vt=none/None"] += 1
        elif re.match(r"^CWE-\d+$", str(vt)):
            pat["裸编号无名称"] += 1
        elif not re.match(r"^CWE-\d+ [^:]+$", str(vt)):
            pat["其他格式"] += 1
            if pat["其他格式"] <= 15:
                w(f"  #{i} {vt!r}")
    elif hv is False:
        if vt != "none":
            pat["safe但vt非none"] += 1
            if pat["safe但vt非none"] <= 10:
                w(f"  #{i} {vt!r}")
w(f"vt 格式分布: {dict(pat)}")

# 7) #3255 3521 3554 7493 7494 详情（hv 与 fix）
w("\n--- 裸编号样本详情 ---")
for i in (3255, 3521, 3554, 7493, 7494, 7790):
    r = rows[i]
    m = JSON_RE.search(r["messages"][2]["content"])
    obj = json.loads(m.group(1)) if m else {}
    meta = r.get("meta") or {}
    w(f"#{i} kind={meta.get('kind')} hv={obj.get('has_vulnerability')} vt={obj.get('vulnerability_type')!r} fix={obj.get('fix_suggestion')!r} risk={obj.get('risk_level')!r}")

# 8) 纯英文 CoT 的行号范围与来源猜测
w("\n--- 纯英文 CoT 样本区间 ---")
zh = re.compile(r"[\u4e00-\u9fff]")
en = []
for i, r in enumerate(rows):
    a = r["messages"][2]["content"]
    m = JSON_RE.search(a)
    pre = a[: m.start()] if m else a
    if not zh.search(pre[:800]):
        en.append(i)
if en:
    w(f"{len(en)} 条, 区间 {en[0]}~{en[-1]}, 语言={Counter(lang_of.get(i) for i in en).most_common(8)}")

OUT.write_text("\n".join(buf), encoding="utf-8")
print("written", OUT)
