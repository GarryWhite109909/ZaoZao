# -*- coding: utf-8 -*-
"""alpha06_v2_12 全库结构与格式审计（Stage 1）"""
import json, re, sys, hashlib, collections, statistics
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SRC = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_alpha06_v2_12.jsonl")
OUT = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\audit\a1_structure_out.txt")

rows = []
bad_json_lines = []
with SRC.open("r", encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append((i, json.loads(line)))
        except Exception as e:
            bad_json_lines.append((i, str(e)[:120]))

OUT.parent.mkdir(parents=True, exist_ok=True)
w = OUT.open("w", encoding="utf-8")
def P(*a):
    print(*a, file=w)

P("=" * 78)
P("alpha06_v2_12 结构审计报告")
P("=" * 78)
P(f"总条数: {len(rows)}   解析失败行: {len(bad_json_lines)}")
for i, e in bad_json_lines[:20]:
    P(f"  [BADJSON] line {i}: {e}")

# ---------- 1. 顶层结构 ----------
P("\n" + "-" * 78)
P("[1] 顶层结构 / 消息骨架")
P("-" * 78)
topkeys = collections.Counter()
role_seqs = collections.Counter()
nmsg = collections.Counter()
for i, r in rows:
    topkeys[tuple(sorted(r.keys()))] += 1
    msgs = r.get("messages", [])
    nmsg[len(msgs)] += 1
    role_seqs[tuple(m.get("role") for m in msgs)] += 1
for k, v in topkeys.most_common():
    P(f"  top-level keys {k}: {v}")
for k, v in nmsg.most_common():
    P(f"  messages 数量 {k}: {v}")
for k, v in role_seqs.most_common():
    P(f"  role 序列 {k}: {v}")

# ---------- 2. system prompt 一致性 ----------
P("\n" + "-" * 78)
P("[2] system prompt 一致性")
P("-" * 78)
sysmap = collections.defaultdict(list)
for i, r in rows:
    msgs = r.get("messages", [])
    s = ""
    for m in msgs:
        if m.get("role") == "system":
            s = m.get("content", "")
            break
    h = hashlib.md5(s.encode("utf-8")).hexdigest()[:10]
    sysmap[h].append(i)
P(f"  system prompt 去重后种类数: {len(sysmap)}")
for h, idxs in sorted(sysmap.items(), key=lambda x: -len(x[1])):
    P(f"    {h}: {len(idxs)} 条  样例行号 {idxs[:5]}")
# 保存每种 system 的全文到单独文件
for h, idxs in sysmap.items():
    msgs = dict(rows)[idxs[0]].get("messages", [])
    s = next((m.get("content","") for m in msgs if m.get("role")=="system"), "")
    p = OUT.parent / f"system_variants/{h}.txt"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s, encoding="utf-8")
    P(f"    -> 全文已存 {p.name} (len={len(s)})")

# ---------- 3. assistant JSON 块解析 ----------
P("\n" + "-" * 78)
P("[3] assistant 输出结构")
P("-" * 78)
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)
FIELDS = ["has_vulnerability", "vulnerability_type", "risk_level",
          "source", "sink", "explanation", "fix_suggestion"]

no_block = []
multi_block = []
unparsable = []
missing_fields = collections.Counter()
extra_fields = collections.Counter()
field_order_bad = []
type_bad = collections.Counter()
recs = []   # (lineno, obj, assistant_text, json_obj, user_text)

for i, r in rows:
    msgs = r.get("messages", [])
    asst = None
    user = None
    for m in msgs:
        if m.get("role") == "assistant":
            asst = m.get("content", "")
        if m.get("role") == "user":
            user = m.get("content", "")
    if asst is None:
        no_block.append(i)
        continue
    blocks = JSON_BLOCK.findall(asst)
    if len(blocks) == 0:
        no_block.append(i)
        continue
    if len(blocks) > 1:
        multi_block.append(i)
    raw = blocks[-1]
    try:
        obj = json.loads(raw)
    except Exception as e:
        unparsable.append((i, str(e)[:100], raw[:200]))
        continue
    keys = list(obj.keys())
    miss = [f for f in FIELDS if f not in obj]
    if miss:
        for m_ in miss:
            missing_fields[m_] += 1
    ext = [k for k in keys if k not in FIELDS]
    for e_ in ext:
        extra_fields[e_] += 1
    present = [k for k in keys if k in FIELDS]
    if present != [k for k in FIELDS if k in obj]:
        field_order_bad.append(i)
    if "has_vulnerability" in obj and not isinstance(obj["has_vulnerability"], bool):
        type_bad["has_vulnerability"] += 1
    for f in ["vulnerability_type", "risk_level", "source", "sink", "explanation", "fix_suggestion"]:
        if f in obj and not isinstance(obj[f], str):
            type_bad[f] += 1
    recs.append((i, r, asst, obj, user or ""))

P(f"  assistant 缺 JSON 块: {len(no_block)}" + (f"  样例 {no_block[:10]}" if no_block else ""))
P(f"  assistant 多 JSON 块: {len(multi_block)}" + (f"  样例 {multi_block[:10]}" if multi_block else ""))
P(f"  JSON 解析失败: {len(unparsable)}")
for i, e, raw in unparsable[:10]:
    P(f"    line {i}: {e} | {raw[:150]}")
P(f"  可解析记录数: {len(recs)}")
P(f"  缺字段统计: {dict(missing_fields)}")
P(f"  多余字段统计: {dict(extra_fields)}")
P(f"  字段顺序非规范: {len(field_order_bad)}")
P(f"  类型错误统计: {dict(type_bad)}")

# ---------- 4. 枚举值合法性 + 一致性 ----------
P("\n" + "-" * 78)
P("[4] 枚举值与标签自洽性")
P("-" * 78)
lvl_bad = collections.Counter()
lvl_dist = collections.Counter()
vt_bad = []
consist_issues = collections.Counter()
na_usage = collections.Counter()
consist_examples = collections.defaultdict(list)

for i, r, asst, obj, user in recs:
    hv = obj.get("has_vulnerability")
    vt = obj.get("vulnerability_type", "")
    rl = obj.get("risk_level", "")
    src = obj.get("source", "")
    snk = obj.get("sink", "")
    fx = obj.get("fix_suggestion", "")
    expl = obj.get("explanation", "")
    lvl_dist[rl] += 1
    if rl not in ("Critical", "High", "Medium", "Low", "None"):
        lvl_bad[rl] += 1
    if hv is True:
        if not re.match(r"^CWE-\d+\s+\S.*$", str(vt)):
            vt_bad.append((i, vt))
        if rl == "None":
            consist_issues["true_but_risk_None"] += 1
            consist_examples["true_but_risk_None"].append(i)
        if str(src).strip() in ("", "N/A", "n/a"):
            consist_issues["true_but_source_NA"] += 1
            consist_examples["true_but_source_NA"].append(i)
        if str(snk).strip() in ("", "N/A", "n/a"):
            consist_issues["true_but_sink_NA"] += 1
            consist_examples["true_but_sink_NA"].append(i)
        if str(fx).strip() in ("", "no fix needed", "N/A"):
            consist_issues["true_but_fix_none"] += 1
            consist_examples["true_but_fix_none"].append(i)
    elif hv is False:
        if str(vt).strip().lower() not in ("none",):
            consist_issues["false_but_vt_not_none"] += 1
            consist_examples["false_but_vt_not_none"].append((i, vt))
        if rl != "None":
            consist_issues["false_but_risk_not_None"] += 1
            consist_examples["false_but_risk_not_None"].append((i, rl))
        if str(src).strip() not in ("N/A",):
            na_usage["safe_source_" + str(src)[:20]] += 1
        if str(snk).strip() not in ("N/A",):
            na_usage["safe_sink_" + str(snk)[:20]] += 1
        if str(fx).strip() not in ("no fix needed",):
            na_usage["safe_fix_" + str(fx)[:30]] += 1
    if str(expl).strip() == "":
        consist_issues["empty_explanation"] += 1

P(f"  risk_level 分布: {dict(lvl_dist.most_common())}")
P(f"  risk_level 非法值: {dict(lvl_bad)}")
P(f"  vulnerability_type 非 'CWE-xxx name' 格式: {len(vt_bad)}")
for i, vt in vt_bad[:15]:
    P(f"    line {i}: {vt!r}")
P(f"  标签自洽问题: {dict(consist_issues)}")
for k, v in consist_examples.items():
    P(f"    {k} 样例: {v[:8]}")
P(f"  安全样本的 N/A 变体（前 15）: ")
for k, v in na_usage.most_common(15):
    P(f"    {k!r}: {v}")

# ---------- 5. 重复检测 ----------
P("\n" + "-" * 78)
P("[5] 重复与近似重复")
P("-" * 78)
full_user = collections.defaultdict(list)
full_asst = collections.defaultdict(list)
pair = collections.defaultdict(list)
code_hash = collections.defaultdict(list)
for i, r, asst, obj, user in recs:
    h = hashlib.md5(user.encode()).hexdigest()
    full_user[h].append(i)
    ha = hashlib.md5(re.sub(r"\s+", "", asst).encode()).hexdigest()
    full_asst[ha].append(i)
    hp = hashlib.md5((user + "||" + asst).encode()).hexdigest()
    pair[hp].append(i)
    # 提取 user 中的代码块
    cb = re.findall(r"```[a-zA-Z0-9_+-]*\s*\n(.*?)```", user, re.S)
    if cb:
        code_hash[hashlib.md5(re.sub(r"\s+", "", "".join(cb)).encode())].append(i)

def dup_report(name, d):
    dups = {k: v for k, v in d.items() if len(v) > 1}
    P(f"  {name}: 唯一 {len(d)} 组，重复组 {len(dups)}，涉及样本 {sum(len(v) for v in dups.values())}")
    tot = 0
    for k, v in sorted(dups.items(), key=lambda x: -len(x[1]))[:12]:
        P(f"    x{len(v)}: 行 {v[:10]}")
        tot += 1
    return dups

dup_report("user 全文指纹", full_user)
dup_report("assistant 全文指纹(去空白)", full_asst)
dup_report("(user,assistant) 对指纹", pair)
dup_report("user 代码块指纹", code_hash)

# ---------- 6. 长度分布 ----------
P("\n" + "-" * 78)
P("[6] 长度分布（字符数 / 近似 token）")
P("-" * 78)
def approx_token(s):
    # 中文按 1 字≈1.5token 粗估，英文按 4 字符 1 token
    zh = len(re.findall(r"[\u4e00-\u9fff]", s))
    rest = len(s) - zh
    return zh * 1.5 + rest / 4.0

ulen, alen, slen, tlen = [], [], [], []
for i, r, asst, obj, user in recs:
    msgs = r.get("messages", [])
    s = next((m.get("content","") for m in msgs if m.get("role")=="system"), "")
    ulen.append(len(user)); alen.append(len(asst)); slen.append(len(s))
    tlen.append(approx_token(s + user + asst))

def dist(name, arr):
    arr2 = sorted(arr)
    n = len(arr2)
    q = lambda p: arr2[int(p * (n - 1))]
    P(f"  {name}: n={n} min={arr2[0]} p10={q(.10)} p25={q(.25)} med={q(.50)} "
      f"p75={q(.75)} p90={q(.90)} p95={q(.95)} p99={q(.99)} max={arr2[-1]} mean={statistics.mean(arr):.0f}")

dist("system 字符", slen)
dist("user 字符", ulen)
dist("assistant 字符", alen)
dist("总近似 token", tlen)

for th in [512, 1024, 2048, 3072, 4096, 6144, 8192]:
    c = sum(1 for t in tlen if t > th)
    P(f"  > {th} token: {c} ({c/len(tlen)*100:.1f}%)")

# 长尾样本
longs = sorted(zip(tlen, [r[0] for r in recs]), reverse=True)[:15]
P("  最长 15 条: " + ", ".join(f"#{i}:{t:.0f}" for t, i in longs))

w.close()
print("done, wrote", OUT)
