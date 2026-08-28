# -*- coding: utf-8 -*-
"""教学质量审计：模板坍塌 / 教师独白泄漏 / 元话语 / 空壳分析 / 语言与 CWE 分布"""
import json, re, sys, collections, statistics
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SRC = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_alpha06_v2_12.jsonl")
OUT = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\audit\a3_quality_out.txt")

rows = []
with SRC.open("r", encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if line:
            rows.append((i, json.loads(line)))

w = OUT.open("w", encoding="utf-8")
def P(*a): print(*a, file=w)

def get(msgs, role):
    for m in msgs:
        if m.get("role") == role:
            return m.get("content", "")
    return ""

recs = []
for i, r in rows:
    msgs = r["messages"]
    recs.append(dict(
        i=i, obj=r, sys=get(msgs,"system"), user=get(msgs,"user"), asst=get(msgs,"assistant"),
        meta=r.get("meta"), fixd=r.get("fix_distill"),
    ))

# ---------- 1. 教师独白 / 元话语泄漏 ----------
P("=" * 78); P("[1] 教师思维泄漏（assistant 中出现元话语/英文独白）"); P("=" * 78)
LEAK_PAT = re.compile(
    r"(Actually|Hmm,|Let me |Wait,|I think|I need to|I should|Option [ABC]:|"
    r"For this training data|the training data|synthetic (project|example)|"
    r"the prompt asks|the prompt says|Let me reconsider|I'?ll |we don'?t need to|"
    r"Let me think|Now, about|But wait|Good\.|✓|Let me also|"
    r"I remember|I could|To be safe|I want to|A common pattern|"
    r"The safest fix|Design of the fix|So the fix should|Now, format)",
    re.I)
leak_hits = []
for r in recs:
    # 只看 JSON 块之前的分析部分
    a = r["asst"]
    body = a.split("```json")[0] if "```json" in a else a
    hits = LEAK_PAT.findall(body)
    if hits:
        leak_hits.append((r["i"], len(hits), collections.Counter(hits).most_common(5), len(a)))
P(f"  命中元话语泄漏的样本: {len(leak_hits)} 条")
leak_hits.sort(key=lambda x: -x[1])
for i, n, top, L in leak_hits[:30]:
    P(f"    line {i}: 命中{n}次, 长度{L}, 高频词 {top}")
P(f"  >> 泄漏样本的长度中位数: {statistics.median([x[3] for x in leak_hits]) if leak_hits else 0}")

# 英文占比
P("\n  assistant 分析部分以英文为主的样本:")
en_dominant = []
for r in recs:
    a = r["asst"]
    body = a.split("```json")[0] if "```json" in a else a
    if len(body) < 50: continue
    zh = len(re.findall(r"[\u4e00-\u9fff]", body))
    en = len(re.findall(r"[A-Za-z]{2,}", body))
    if en > zh * 1.5 and en > 100:
        en_dominant.append((r["i"], en, zh, len(a)))
en_dominant.sort(key=lambda x: -x[3])
P(f"    共 {len(en_dominant)} 条")
for i, en, zh, L in en_dominant[:25]:
    P(f"      line {i}: en={en} zh={zh} total_len={L}")

# ---------- 2. 空壳分析 / 模板坍塌 ----------
P("\n" + "=" * 78); P("[2] 空壳分析（分析步骤只复述步骤名、无实质结论）"); P("=" * 78)
SHELL_PAT = re.compile(r"^\s*\d+\.\s*(污染源|输入检查|危险 sink|sink 评估|数据流|防御检查|防御确认|综合判定|结论)[：:]\s*(.{0,60})$", re.M)
def shell_score(body):
    """返回 (步骤条数, 空壳条数)"""
    lines = [l for l in body.split("\n") if re.match(r"^\s*\d+\.\s*", l)]
    if not lines:
        return 0, 0
    shell = 0
    for l in lines:
        m = re.match(r"^\s*\d+\.\s*([^：:]{2,20})[：:]\s*(.*)$", l)
        if not m: continue
        head, tail = m.group(1).strip(), m.group(2).strip()
        # 空壳判据：tail 是泛泛而谈、没有具体代码符号/行号
        vague = [
            r"^检查用户可控输入点", r"^追踪输入到 sink 的路径", r"^N/A[，,]?\s*需判断",
            r"^识别代码中的用户输入点与处理逻辑", r"^N/A$", r"^未发现漏洞",
            r"^代码是安全的", r"^无$",
        ]
        if any(re.search(p, tail) for p in vague):
            shell += 1
    return len(lines), shell

shell_recs = []
for r in recs:
    a = r["asst"]
    body = a.split("```json")[0] if "```json" in a else a
    tot, sh = shell_score(body)
    if tot and sh >= 2:
        shell_recs.append((r["i"], tot, sh))
P(f"  >=2 条空壳步骤的样本: {len(shell_recs)} 条（占 {len(shell_recs)/len(recs)*100:.1f}%）")
P(f"  行号区间样例: {[x[0] for x in shell_recs[:20]]}")
buckets = collections.Counter()
for i, t, s in shell_recs:
    buckets[(i // 500) * 500] += 1
P(f"  按行号 500 分段: {dict(sorted(buckets.items()))}")

# 典型空壳模板（去代码符号后聚合）
P("\n  典型空壳分析模板 Top15（归一化后聚合）:")
tmpl = collections.Counter()
for i, t, s in shell_recs:
    r = dict(rows)[i]
    a = get(r["messages"], "assistant")
    body = a.split("```json")[0].strip()
    norm = re.sub(r"\d+", "#", body)
    norm = re.sub(r"\s+", "", norm)
    tmpl[norm] += 1
for k, v in tmpl.most_common(15):
    P(f"    x{v}: {k[:200]}")

# ---------- 3. explanation = N/A ----------
P("\n" + "=" * 78); P("[3] 结论字段取值的规范性"); P("=" * 78)
expl_na = []
src_na_on_vuln = []
for r in recs:
    a = r["asst"]
    blocks = re.findall(r"```json\s*(.*?)```", a, re.S)
    if not blocks: continue
    try:
        o = json.loads(blocks[-1])
    except Exception:
        continue
    if str(o.get("explanation", "")).strip() in ("N/A", "n/a", ""):
        expl_na.append(r["i"])
P(f"  explanation = 'N/A'/空 的样本: {len(expl_na)} 条")
if expl_na:
    P(f"    行号区间 {min(expl_na)}-{max(expl_na)}, 样例 {expl_na[:15]}")
    bk = collections.Counter(((i // 500) * 500) for i in expl_na)
    P(f"    分段: {dict(sorted(bk.items()))}")

# ---------- 4. 语言 / CWE 分布 ----------
P("\n" + "=" * 78); P("[4] 代码语言与 CWE 分布"); P("=" * 78)
langs = collections.Counter()
for r in recs:
    u = r["user"]
    m = re.search(r"语言[:：]\s*([a-zA-Z0-9+#]+)", u)
    if m:
        langs[m.group(1).lower()] += 1
    else:
        m2 = re.search(r"```\s*([a-zA-Z0-9+#]+)", u)
        langs[(m2.group(1).lower() if m2 else "<unknown>")] += 1
P("  代码语言分布:")
for k, v in langs.most_common(25):
    P(f"    {k}: {v}")

cwes = collections.Counter()
for r in recs:
    a = r["asst"]
    blocks = re.findall(r"```json\s*(.*?)```", a, re.S)
    if not blocks: continue
    try:
        o = json.loads(blocks[-1])
    except Exception:
        continue
    vt = str(o.get("vulnerability_type", ""))
    m = re.findall(r"CWE-(\d+)", vt)
    for c in m:
        cwes["CWE-" + c] += 1
P(f"\n  CWE 种类数: {len(cwes)}")
P("  CWE 分布（Top40）:")
for k, v in cwes.most_common(40):
    P(f"    {k}: {v}")
rest = cwes.most_common()[40:]
P(f"  （其余 {len(rest)} 种，共 {sum(v for _, v in rest)} 条）: {rest}")

# 正负样本比
P("\n" + "=" * 78); P("[5] 正负样本与难度分布"); P("=" * 78)
hv = collections.Counter()
for r in recs:
    a = r["asst"]
    blocks = re.findall(r"```json\s*(.*?)```", a, re.S)
    if not blocks: continue
    try:
        o = json.loads(blocks[-1])
    except Exception:
        continue
    hv[o.get("has_vulnerability")] += 1
P(f"  has_vulnerability 分布: {dict(hv)}")
tot = sum(hv.values())
for k, v in hv.items():
    P(f"    {k}: {v} ({v/tot*100:.1f}%)")

# ---------- 6. user prompt 模板种类 ----------
P("\n" + "=" * 78); P("[6] user 侧任务模板种类"); P("=" * 78)
utpl = collections.Counter()
for r in recs:
    u = r["user"]
    # 取第一行或第一个【】标记
    m = re.search(r"【([^】]{0,40})】", u)
    head = m.group(1) if m else u.strip().split("\n")[0][:40]
    utpl[head] += 1
P(f"  user 开头模板种类: {len(utpl)}")
for k, v in utpl.most_common(30):
    P(f"    x{v}: {k}")

# ---------- 7. fix_suggestion 规范性 ----------
P("\n" + "=" * 78); P("[7] fix_suggestion 规范性"); P("=" * 78)
fx_issue = collections.Counter()
fx_samples = collections.defaultdict(list)
for r in recs:
    a = r["asst"]
    blocks = re.findall(r"```json\s*(.*?)```", a, re.S)
    if not blocks: continue
    try:
        o = json.loads(blocks[-1])
    except Exception:
        continue
    if o.get("has_vulnerability") is not True: continue
    fx = str(o.get("fix_suggestion", ""))
    if "```" in fx:
        fx_issue["含代码块"] += 1; fx_samples["含代码块"].append(r["i"])
    if not re.search(r"line\s*\d+", fx):
        fx_issue["无 line 锚点"] += 1; fx_samples["无 line 锚点"].append(r["i"])
    if len(fx) > 300:
        fx_issue["过长>300字符"] += 1; fx_samples["过长>300字符"].append(r["i"])
    if re.search(r"\n", fx.strip()):
        fx_issue["含换行(多行)"] += 1; fx_samples["含换行(多行)"].append(r["i"])
P(f"  漏洞样本 fix_suggestion 问题统计: {dict(fx_issue)}")
for k, v in fx_samples.items():
    P(f"    {k} 样例: {v[:10]}")

# ---------- 8. source/sink 行号真实性 ----------
P("\n" + "=" * 78); P("[8] source/sink 行号 vs 代码真实行数"); P("=" * 78)
oor = []
no_anchor = []
n_vuln = 0
for r in recs:
    a = r["asst"]
    blocks = re.findall(r"```json\s*(.*?)```", a, re.S)
    if not blocks: continue
    try:
        o = json.loads(blocks[-1])
    except Exception:
        continue
    if o.get("has_vulnerability") is not True: continue
    n_vuln += 1
    # 代码行数：user 里若带 "N| " 行号前缀
    u = r["user"]
    numbered = re.findall(r"^\s*(\d+)\|", u, re.M)
    maxline = max(int(x) for x in numbered) if numbered else None
    for fld in ("source", "sink"):
        v = str(o.get(fld, ""))
        m = re.search(r"line\s*(\d+)", v)
        if not m:
            no_anchor.append((r["i"], fld, v[:50]))
            continue
        if maxline and int(m.group(1)) > maxline:
            oor.append((r["i"], fld, m.group(1), maxline))
P(f"  漏洞样本数: {n_vuln}")
P(f"  source/sink 无 line 锚点: {len(no_anchor)}")
for x in no_anchor[:15]:
    P(f"    {x}")
P(f"  source/sink 行号越界（超出代码最大行）: {len(oor)}")
for x in oor[:25]:
    P(f"    line {x[0]} {x[1]}: 标注{x[2]} > 代码最大{x[3]}")

w.close()
print("done")
