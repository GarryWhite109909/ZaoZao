# -*- coding: utf-8 -*-
"""探测②：构建人工复核包（2026-09-27）。

产出 audit/复核包_存量语义_20260927/：
  1. 弱防御复核包_50行.md   —— 从 v2_26 p0_3 窄口径 1199 行按 CWE 分层抽 50，
     每行附三问复核表（防御真实有效？叙事与代码一致？标签 false 正确？）
  2. MT族抽查包_40行.md     —— 多文件（M）族 / 工具裁决（T）族各 20 行结构化抽查
只读 v2_26，不写数据集。
"""
import json, os, re, sys, random, collections

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune"
SRC = os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_26_candidate_20260914.jsonl")
MAN = os.path.join(ROOT, "audit", "v2_26_opt_manifests")
OUT = os.path.join(ROOT, "audit", "复核包_存量语义_20260927")
os.makedirs(OUT, exist_ok=True)

rows = [json.loads(l) for l in open(SRC, encoding="utf-8") if l.strip()]
CODE_RE = re.compile(r"```([a-zA-Z0-9_+#\-\.]*)[ \t]*\n(.*?)```", re.S)
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)


def code_blocks(u):
    return [(m.group(1).lower(), m.group(2)) for m in CODE_RE.finditer(u)]


def verdict_of(a):
    ms = list(JSON_RE.finditer(a))
    if not ms:
        return None
    try:
        return json.loads(ms[-1].group(1))
    except Exception:
        return None


# ================================================================ 1. 弱防御复核包
hi = [json.loads(l) for l in open(os.path.join(MAN, "p0_3_weak_defense_neg_hiprec.jsonl"), encoding="utf-8") if l.strip()]
print("p0_3 窄口径总数", len(hi))

# 负样本行的 vulnerability_type 恒为 "none"（无号），CWE 族分层无意义 →
# 简单随机抽样（seed 固定可复现）。
by_fam = collections.defaultdict(list)
for rec in hi:
    by_fam["all"].append(rec["row"])
print("抽样池（单一层）:", len(by_fam["all"]))

random.seed(20260927)
# 分层：每族配额 ∝ 族大小（上限=族容量），再从最大族调整到目标总数。
# 注意：不能把单族上限写死为 6 再做迭代补齐——族数少时总容量 < 50 会死循环。
fams_sorted = sorted(by_fam.items(), key=lambda kv: (-len(kv[1]), kv[0]))
target_total = min(50, len(hi))
quota = {k: min(len(v), max(1, int(round(target_total * len(v) / len(hi)))))
         for k, v in fams_sorted}


def _quota_total():
    return sum(quota.values())


while _quota_total() > target_total:
    big = max(quota, key=lambda k: (quota[k], k))
    quota[big] -= 1
while _quota_total() < target_total:
    for k, v in fams_sorted:
        if quota[k] < len(v):
            quota[k] += 1
            if _quota_total() >= target_total:
                break
picked = []
for k, v in fams_sorted:
    cand = sorted(by_fam[k])
    picked.extend(random.sample(cand, min(quota[k], len(cand))))
picked = sorted(set(picked))[:target_total]
print("抽样行数", len(picked), " 族覆盖", sum(1 for k in quota if quota[k] > 0))

pack = ["# 弱防御当有效 · 人工复核包（50 行，2026-09-27）", "",
        "> 总体：v2_26 p0_3 窄口径 1199 行（`audit/v2_26_opt_manifests/p0_3_weak_defense_neg_hiprec.jsonl`）。",
        "> 抽样：seed=20260927 简单随机（负样本行 vulnerability_type 恒为 none，无族可分层）。逐行回答三问：",
        "> - Q1 代码中的防御机制**真实且有效**吗？（真实有效 / 弱但叙事如实承认其弱 / 完全编造）",
        "> - Q2 叙事声称的防御与代码实际一致吗？（一致 / 夸大 / 张冠李戴）",
        "> - Q3 标签 has_vulnerability=false 正确吗？（正确 / 错误应改 true）",
        "> 判定口径：Q1=编造或 Q3=错误 → 该行进入清洗/删除队列；仅 Q2=夸大 → 重写队列。",
        ""]
for n, i in enumerate(picked, 1):
    r = rows[i]
    u = r["messages"][1]["content"]
    a = r["messages"][2]["content"]
    v = verdict_of(a) or {}
    rec = next(x for x in hi if x["row"] == i)
    pack.append(f"---\n\n## #{n} row={i}  CWE标注={rec['cwe']}  src_row={r.get('src_row')}")
    pack.append(f"- 词表命中：weak_def={rec['weak_def']} bypass={rec['bypass']} wash={rec['wash']}")
    pack.append(f"- JSON 判定：has_vulnerability={v.get('has_vulnerability')} type={v.get('vulnerability_type')}")
    pack.append(f"- **Q1 防御真实有效？** ______（真实有效/弱但如实/编造）  **Q2 叙事一致？** ______  **Q3 标签正确？** ______")
    pack.append("")
    pack.append("<details><summary>user（代码）</summary>\n")
    pack.append("```\n" + u[:6000] + "\n```")
    pack.append("\n</details>")
    pack.append("<details><summary>assistant（分析）</summary>\n")
    pack.append("```\n" + a[:8000] + "\n```")
    pack.append("\n</details>")
    pack.append("")
with open(os.path.join(OUT, "弱防御复核包_50行.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(pack))
print("  -> 弱防御复核包_50行.md")

json.dump({"pack": "weak_defense", "seed": 20260927, "rows": picked,
           "strata": {k: quota[k] for k in quota}},
          open(os.path.join(OUT, "weak_defense_sample.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=2)

# ================================================================ 2. M/T 族抽查包
# M 族：user 含 ≥2 个 ≥120 字符代码块
# T 族：user 含工具告警/裁决形态标记
T_MARK = re.compile(r"is_confirmed|rule_id|工具(?:告警|输出|检测结果)|扫描器(?:报告|输出)|告警(?:列表|条目)")
m_rows, t_rows = [], []
for i, r in enumerate(rows):
    u = r["messages"][1]["content"]
    bl = [b for _, b in code_blocks(u) if len(b.strip()) >= 120]
    if len(bl) >= 2:
        m_rows.append(i)
    if T_MARK.search(u):
        t_rows.append(i)
print(f"\nM 族(≥2 代码块) {len(m_rows)} 行   T 族(裁决标记) {len(t_rows)} 行")

random.seed(20260927)
m_pick = sorted(random.sample(m_rows, min(20, len(m_rows))))
t_pick = sorted(random.sample(t_rows, min(20, len(t_rows))))

pack2 = ["# M/T 族结构抽查包（40 行，2026-09-27）", "",
         f"> M 族总体 {len(m_rows)} 行（user 含 ≥2 个 ≥120 字符代码块）；T 族总体 {len(t_rows)} 行（user 含裁决标记）。",
         "> 抽查关注：① 代码块间数据流是否自洽（跨文件流可追踪）；② 裁决形态是否复现生产多候选场景；",
         "> ③ 行号引用是否与代码块对齐；④ 9967 式泄漏（与考卷同源）目检。",
         ""]
for tag, picks in (("M", m_pick), ("T", t_pick)):
    pack2.append(f"---\n\n# {tag} 族抽查（{len(picks)} 行）")
    for n, i in enumerate(picks, 1):
        r = rows[i]
        u = r["messages"][1]["content"]
        a = r["messages"][2]["content"]
        v = verdict_of(a) or {}
        nblk = len([b for _, b in code_blocks(u) if len(b.strip()) >= 120])
        pack2.append(f"\n## {tag}#{n} row={i}  src_row={r.get('src_row')}  代码块数={nblk}")
        pack2.append(f"- JSON 判定：has_vulnerability={v.get('has_vulnerability')} type={v.get('vulnerability_type')}")
        pack2.append(f"- 抽查记录：数据流自洽?____ 叙事块对齐?____ 泄漏嫌疑?____")
        pack2.append("")
        pack2.append("<details><summary>user</summary>\n")
        pack2.append("```\n" + u[:7000] + "\n```")
        pack2.append("\n</details>")
        pack2.append("<details><summary>assistant（截断 4000 字）</summary>\n")
        pack2.append("```\n" + a[:4000] + "\n```")
        pack2.append("\n</details>")
with open(os.path.join(OUT, "MT族抽查包_40行.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(pack2))
print("  -> MT族抽查包_40行.md")

json.dump({"m_total": len(m_rows), "t_total": len(t_rows),
           "m_pick": m_pick, "t_pick": t_pick},
          open(os.path.join(OUT, "mt_sample.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=2)
print("\nDONE ->", OUT)
