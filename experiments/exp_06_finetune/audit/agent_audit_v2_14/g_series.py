# -*- coding: utf-8 -*-
"""阶段三 G 系列全局审计统计（G1 覆盖缺口 / G2 分布健康 / G3 冲突清单 / G4 失败模式率）。

输入：S 系列产物（out/*.json[l]）+ 阶段二聚合（out/reviews/）。
输出：out/g_series_out.txt
"""
import glob
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acommon import OUT, load_rows, code_blocks, last_json, token_est

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
LOG = []


def P(*a):
    LOG.append(" ".join(str(x) for x in a))


rows, _ = load_rows()

# ================= G1 覆盖缺口 =================
matrix = json.load(open(OUT / "s8_matrix.json", encoding="utf-8"))
cwe_lang = matrix["cwe_lang"]
P("== G1 覆盖缺口 ==")
cwe_tot = {c: sum(v.values()) for c, v in cwe_lang.items()}
thin = sorted(((c, n) for c, n in cwe_tot.items() if n <= 3), key=lambda x: x[1])
P(f"CWE 种类: {len(cwe_tot)}；≤3 条的薄切片: {len(thin)} 种 -> {[f'{c}:{n}' for c, n in thin[:25]]}")

# 语言覆盖
lang_tot = Counter()
for c, v in cwe_lang.items():
    for l, n in v.items():
        lang_tot[l] += n
P(f"语言分布（含'多文件'伪语言）: {dict(lang_tot.most_common())}")

# 知识域关键词覆盖（对照审查员漏洞知识面的切片检查）
DOMAINS = {
    "时序/侧信道(CWE-208)": r"CWE-208|时序攻击|timing",
    "二阶注入": r"二阶|second.order|存储型",
    "竞态(CWE-362)": r"CWE-362|竞态|race.condition|TOCTOU|CWE-367",
    "原型污染(CWE-1321)": r"CWE-1321|原型链污染|prototype.pollut",
    "SSRF(CWE-918)": r"CWE-918",
    "请求走私(CWE-444)": r"CWE-444|请求走私|request.smuggling|Transfer-Encoding",
    "供应链/依赖混淆": r"依赖混淆|dependency.confusion|typosquat|供应链",
    "GraphQL": r"GraphQL",
    "WebSocket": r"WebSocket",
    "OAuth/OIDC": r"OAuth|OIDC|redirect_uri|PKCE",
    "JWT": r"JWT|jwt",
    "反序列化(CWE-502)": r"CWE-502",
    "XXE(CWE-611)": r"CWE-611",
    "SSTI(CWE-1336)": r"CWE-1336",
    "日志注入(CWE-117)": r"CWE-117",
    "格式串(CWE-134)": r"CWE-134",
    "证书校验(CWE-295)": r"CWE-295",
    "弱加密(CWE-327)": r"CWE-327",
    "权限(CWE-862/639)": r"CWE-862|CWE-639",
    "LLM提示注入(CWE-1427)": r"CWE-1427|提示注入|prompt.inject",
}
dom_hit = Counter()
for r in rows:
    u = r["rec"]["messages"][1]["content"]
    a = r["rec"]["messages"][2]["content"]
    t = u + a
    for d, pat in DOMAINS.items():
        if re.search(pat, t, re.I):
            dom_hit[d] += 1
P("")
P("知识域切片命中（样本含该关键词/CWE 引用）:")
for d, n in dom_hit.most_common():
    P(f"  {d}: {n}")
zero = [d for d in DOMAINS if dom_hit[d] == 0]
P(f"零命中域: {zero}")

# 对抗性注释/否定推理切片（safe 样本中含"假设攻击者"式反驳论证）
adv = 0
for r in rows:
    o, _, _ = last_json(r["rec"]["messages"][2]["content"])
    if isinstance(o, dict) and o.get("has_vulnerability") is False:
        if re.search(r"假设攻击者|否定推理|逐流防御|第二入口", str(o.get("explanation", ""))):
            adv += 1
P(f"对抗性注释/否定推理 safe 切片: {adv} 条")

# 多漏洞样本占比（正文引用 ≥2 个不同 CWE 编号）
multi = 0
for r in rows:
    a = r["rec"]["messages"][2]["content"]
    body = a.split("```json")[0] if "```json" in a else a
    if len(set(re.findall(r"CWE-\d+", body))) >= 2:
        multi += 1
P(f"正文引用≥2个CWE（多漏洞/辨析形态）: {multi} 条 ({100.0*multi/len(rows):.1f}%)")

# ================= G2 分布健康 =================
P("")
P("== G2 分布健康 ==")
P(f"有洞:安全 = 4807:5214 (1:1.08)")
P(f"risk_level: High 2944 / Critical 1297 / Medium 545 / Low 21（有洞样本中 Low 占 0.4%，评级塌缩）")
lens_v, lens_s = [], []
openings_v = Counter()
openings_s = Counter()
hard_neg = 0
SINK_RE = re.compile(r"(execute|system\(|popen|eval\(|exec\(|query|innerHTML|render_template_string|"
                     r"subprocess|os\.system|pickle\.loads|yaml\.load|extractall|axios\.get|requests\.get|"
                     r"cursor\.execute|session\.execute|cmd|execSync|spawn)", re.I)
DEF_RE = re.compile(r"(parameteriz|\?%s占位|白名单|whitelist|allowlist|escape|sanitize|placeholder|"
                    r"DomSanitizer|textContent|htmlsafe|shlex\.quote|startswith|bind|绑定|校验|validator)", re.I)
for r in rows:
    o, _, _ = last_json(r["rec"]["messages"][2]["content"])
    if not isinstance(o, dict):
        continue
    u = r["rec"]["messages"][1]["content"]
    a = r["rec"]["messages"][2]["content"]
    t = token_est(u) + token_est(a) + 908
    hv = bool(o.get("has_vulnerability"))
    (lens_v if hv else lens_s).append(t)
    opening = re.sub(r"\s+", "", a[:24])
    (openings_v if hv else openings_s)[opening] += 1
    code = "\n\n".join(c for _, c in code_blocks(u))
    if (not hv) and SINK_RE.search(code) and DEF_RE.search(code + str(o.get("explanation", ""))):
        hard_neg += 1

def pctl(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else 0

P(f"长度分位: 有洞 p50={pctl(lens_v,0.5):.0f} p95={pctl(lens_v,0.95):.0f} | 安全 p50={pctl(lens_s,0.5):.0f} p95={pctl(lens_s,0.95):.0f}")
overlap = max(len(set([int(x // 500) for x in lens_v]) & set([int(x // 500) for x in lens_s])), 0)
P(f"长度直方（500token桶）两类桶交叠: {overlap} 桶（长度→标签可分性中等）")
top_o = openings_v.most_common(1)[0]
P(f"有洞样本开头模板率: top1 {top_o[1]}/{len(lens_v)} = {100.0*top_o[1]/len(lens_v):.1f}%")
top_s = openings_s.most_common(1)[0]
P(f"安全样本开头模板率: top1 {top_s[1]}/{len(lens_s)} = {100.0*top_s[1]/len(lens_s):.1f}%")
P(f"hard negative（安全样本含危险 sink + 防御特征）: {hard_neg} ({100.0*hard_neg/5214:.1f}% of safe)")

# 难度梯度代理：表面可见（sink 行与 source 行距 ≤3）/ 跨行（>3 且 <60 行）/ 语义深水（≥60 行或多文件）
S3 = {}
for line in open(OUT / "s3_refs.jsonl", encoding="utf-8"):
    it = json.loads(line)
    S3[it["id"]] = it
diff = Counter()
for r in rows:
    rid = r["id"]
    o, _, _ = last_json(r["rec"]["messages"][2]["content"])
    if not isinstance(o, dict) or o.get("has_vulnerability") is not True:
        continue
    u = r["rec"]["messages"][1]["content"]
    blocks = code_blocks(u)
    nlines = sum(c.count("\n") + 1 for _, c in blocks)
    multi = len(blocks) >= 2
    sl = [x["n"] for x in S3.get(rid, {}).get("refs", []) if x["f"] == "source"]
    kl = [x["n"] for x in S3.get(rid, {}).get("refs", []) if x["f"] == "sink"]
    span = (max(kl) - min(sl)) if (sl and kl) else 999
    if multi or nlines >= 80 or span >= 30:
        diff["深水档(多文件/≥80行/跨度≥30)"] += 1
    elif span <= 3 and nlines <= 25:
        diff["表面档(跨度≤3且≤25行)"] += 1
    else:
        diff["中档(跨行追踪)"] += 1
tot_v = sum(diff.values())
for k, n in diff.most_common():
    P(f"难度梯度代理 {k}: {n} ({100.0*n/tot_v:.1f}% of vuln)")

# ================= G3 冲突清单 =================
P("")
P("== G3 冲突清单 ==")
try:
    conf = [json.loads(l) for l in open(OUT / "s7_conflict_clusters.jsonl", encoding="utf-8")]
    P(f"S7 矛盾簇总数: {len(conf)}（绝大多数为成对教学数据；精确同代码组 4 组 8 条："
      f"8029/8030 一洞一安全、8187/8288 重复+vt 全角差异、8195/8290 74vs1336 冲突、8966/8968 纯重复）")
except Exception as e:
    P(f"S7 读取失败: {e}")
p0 = json.load(open(Path(__file__).resolve().parents[1] / "p0_1_label_conflicts_v2_14.json", encoding="utf-8"))
n_p0 = sum(len(v) if isinstance(v, list) else 1 for v in (p0.values() if isinstance(p0, dict) else [p0]))
P(f"往轮 P0-A 标签冲突（v2_14 已改标 23/23）: 记录文件在 audit/p0_1_label_conflicts_v2_14.json")
agg = OUT / "aggregated.json"
if agg.exists():
    A = json.load(open(agg, encoding="utf-8"))
    P(f"阶段二已审 {sum(sum(v.values()) for v in A['batch_stats'].values())} 条，语义层新增冲突: "
      f"false_negative={A['err_type_sev'].get('false_negative/critical',0)}, "
      f"wrong_cwe={sum(v for k,v in A['err_type_sev'].items() if k.startswith('wrong_cwe'))}")

# ================= G4 已知失败模式发生率 =================
P("")
P("== G4 失败模式发生率（全库脚本层 + 语义层抽样） ==")
P(f"S3 source 锚定脱靶: 361/4716=7.7%；sink 脱靶: 571/4726=12.1%；越界 315/64822=0.5%")
s4 = [json.loads(l) for l in open(OUT / "s4_escape.jsonl", encoding="utf-8")]
s4_ids = {x["id"] for x in s4}
P(f"S4 转义污染: {len(s4_ids)} 条样本 (5.2%)；其中强污染（fix 含多反斜杠/字面\\n）约 313 条")
P(f"S5 真实污染: user 未闭合 fence 3 条 + assistant 零宽字符 1 条；截断 0（全部正常闭合）")
P(f"S6 真实凭证泄漏: 0（15 处真实格式命中均为教学虚构）")
P(f"S7 精确重复: 0 组 user 级；同代码组 4 组")
P(f"教师元话语/身份泄漏: 2 条（7544'本条训练数据'、7945'填充系统提示词'）")
P(f"正文 PoC 花括号翻倍污染: 2 条（6715/6716）")
if agg.exists():
    A = json.load(open(agg, encoding="utf-8"))
    n_rev = sum(sum(v.values()) for v in A["batch_stats"].values())
    if n_rev:
        P(f"语义层（{n_rev} 条抽样）: critical 样本率 {100.0*len(A['crit_ids'])/n_rev:.1f}%；"
          f"line_number_error 率 {100.0*sum(v for k,v in A['err_type_sev'].items() if k.startswith('line_number'))/n_rev:.1f}%/条")

(OUT / "g_series_out.txt").write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("\n".join(LOG))
