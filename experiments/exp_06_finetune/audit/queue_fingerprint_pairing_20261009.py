# -*- coding: utf-8 -*-
"""判定 E：敷衍修复队列 235 行在 v2_27 的存活上下界（2026-10-09，v2 纯指纹版）。

问题（存量残留清点 §二.3）：队列行号是 v2_15/16 口径且无内容指纹入库，处置链
不透明。v1 的行号对位失败（基座代际无法确证 + ana_len 百分比容差被 JSON 块长度
击穿），v2 改为纯结构指纹匹配 + 叙事充实度对比：

  指纹      = (cwe, lang, code_len±3, ana_len±160)——绝对容差吸收 JSON 块/清洗漂移
  存活      = v2_27 中指纹匹配的行（上界；多个候选取总距离最小者，歧义计数）
  敷衍未修  = 存活 且 现叙事行号引用数 ≈ 队列 ana_refs（±1）→ 下界（大概率没修过）
  已充实    = 存活 但 行号引用数显著增多（>ana_refs+1）→ 大概率被 0908 修复波/
              后续清洗/W 系列改写
  无法对位  = 指纹零命中（已删或深度改写）

只读；输出 audit/判定E_敷衍队列存活对账_20261009.{md,jsonl}
"""
import hashlib
import json
import os
import re
import sys
from collections import Counter

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune"
QUEUE = os.path.join(ROOT, "audit", "敷衍修复队列_20260908.jsonl")
TARGETS = {
    "v2_27": os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_27_w3reanchor_20261009.jsonl"),
    "v2_26": os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_26_candidate_20260914.jsonl"),
}
OUT_MD = os.path.join(ROOT, "audit", "判定E_敷衍队列存活对账_20261009.md")
OUT_JSONL = os.path.join(ROOT, "audit", "判定E_敷衍队列存活对账_20261009.jsonl")

CODE_RE = re.compile(r"```([a-zA-Z0-9_+#\-\.]*)[ \t]*\n(.*?)```", re.S)
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
REF_RE = re.compile(r"(?:line\s*\d+|第\s*\d+\s*行)", re.I)


def digest(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()[:10]


def features(row):
    u = row["messages"][1]["content"]
    a = row["messages"][2]["content"]
    bl = CODE_RE.findall(u)
    lang = next((l.lower() for l, b in bl if l), "")
    code_len = sum(len(b.strip("\n").split("\n")) for l, b in bl)
    m = re.search(r"CWE[- ]?(\d+)", str((JSON_RE.findall(a) or [""])[-1]))
    cwe = m.group(1) if m else ""
    return dict(cwe=cwe, lang=lang, code_len=code_len, ana_len=len(a),
                refs=len(REF_RE.findall(a)), digest=digest(a))


def fp_dist(fq, fr):
    """指纹距离（None=不匹配）。"""
    if fq["cwe"] and fr["cwe"] and fq["cwe"] != fr["cwe"]:
        return None
    if fq["lang"] and fr["lang"] and fq["lang"] != fr["lang"]:
        return None
    dc = abs(fq["code_len"] - fr["code_len"])
    da = abs(fq["ana_len"] - fr["ana_len"])
    if dc > 3 or da > 160:
        return None
    return dc * 2 + da


def main():
    queue = [json.loads(l) for l in open(QUEUE, encoding="utf-8") if l.strip()]
    print(f"队列 {len(queue)} 条")
    idx = {}
    for k, p in TARGETS.items():
        if not os.path.exists(p):
            continue
        trs = [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
        idx[k] = [(i, features(r)) for i, r in enumerate(trs)]
        print(f"  {k}: {len(trs)} 行已索引")

    out, cnt = [], Counter()
    for q in queue:
        best = None
        for k, feats in idx.items():
            for i, fr in feats:
                d = fp_dist(q, fr)
                if d is not None and (best is None or d < best[0]):
                    best = (d, k, i, fr)
        rec = dict(line=q["line"], cwe=q["cwe"], lang=q["lang"],
                   reasons=q.get("reasons", [])[:1])
        if best is None:
            rec["status"] = "无法对位"
        else:
            d, k, i, fr = best
            ties = sum(1 for j, f2 in idx[k] if fp_dist(q, f2) is not None)
            if abs(fr["refs"] - q.get("ana_refs", 0)) <= 1:
                rec["status"] = f"存活·敷衍未修@{k}"
            elif fr["refs"] > q.get("ana_refs", 0) + 1:
                rec["status"] = f"存活·已充实@{k}"
            else:
                rec["status"] = f"存活·refs减少@{k}"
            rec.update(v27_row=i + 1, dist=d, ties=ties - 1,
                       refs_now=fr["refs"], refs_queue=q.get("ana_refs"))
        out.append(rec)
        cnt[rec["status"].split("@")[0]] += 1

    alive = cnt.get("存活·敷衍未修", 0) + cnt.get("存活·已充实", 0) + cnt.get("存活·refs减少", 0)
    print("\n对账:", dict(cnt))
    print(f"存活上界 = {alive}/235；敷衍未修下界 = {cnt.get('存活·敷衍未修', 0)}/235")

    with open(OUT_JSONL, "w", encoding="utf-8") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    md = ["# 判定 E：敷衍队列 235 行存活对账（2026-10-09，纯结构指纹版）\n",
          "> 指纹 (cwe, lang, code_len±3, ana_len±160)；存活区分：现叙事行号引用数 "
          "≈队列 ana_refs → 大概率敷衍未修；引用数显著增多 → 已被改写充实。\n",
          f"> **存活上界 {alive}/235；敷衍未修下界 {cnt.get('存活·敷衍未修', 0)}/235**\n",
          "| 状态 | 行数 |\n|---|---|"]
    for k, v in cnt.most_common():
        md.append(f"| {k} | {v} |")
    multi = sum(1 for r in out if r.get("ties", 0) > 0)
    md.append(f"\n指纹歧义（≥2 候选）：{multi} 行（取总距离最小者）")
    md.append("\n<details><summary>逐行明细</summary>\n")
    for r in out:
        md.append(f"- line={r['line']} cwe={r['cwe']} {r['lang']} → {r['status']}"
                  + (f" (v27_row={r.get('v27_row')}, refs {r.get('refs_queue')}→{r.get('refs_now')}, ties={r.get('ties')})"
                     if "v27_row" in r else ""))
    md.append("\n</details>")
    open(OUT_MD, "w", encoding="utf-8").write("\n".join(md))
    print(f"-> {OUT_MD}")


if __name__ == "__main__":
    main()
