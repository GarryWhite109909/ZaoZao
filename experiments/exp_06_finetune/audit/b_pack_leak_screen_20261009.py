# -*- coding: utf-8 -*-
"""判定卡 B 泄漏嫌疑同源比对（2026-10-09）。

对 MT 族抽查包 40 行的代码文本，与三套评测考卷（87 合成集 / cve_fix20 /
rolling_dev50 + safe47）做词集 Jaccard 同源筛查——9967 泄漏簇同款检测手法。
阈值沿用簇审计现行口径的分档提示：≥0.5 高嫌疑 / 0.3~0.5 中嫌疑 / <0.3 无信号。
只读，输出 MD 报告。
"""
import json, os, re, sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune"
SRC = os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_26_candidate_20260914.jsonl")
RESULT = os.path.join(ROOT, "audit", "复核包_存量语义_20260927", "判定B_MT族_结果_20261009.jsonl")
OUT = os.path.join(ROOT, "audit", "复核包_存量语义_20260927", "判定B_同源比对_20261009.md")

CORPORA = {
    "87": os.path.join(ROOT, "..", "exp_04_hard_samples", "samples"),
    "cvefix": os.path.join(ROOT, "testset_cve_fix"),
    "rolling": os.path.join(ROOT, "corpus", "rolling_dev"),
    "rolling_safe": os.path.join(ROOT, "corpus", "rolling_dev_safe"),
}
CODE_RE = re.compile(r"```[a-zA-Z0-9_+#\-\.]*[ \t]*\n(.*?)```", re.S)
TOK_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")


def words(text):
    return {t.lower() for t in TOK_RE.findall(text)}


def jac(a, b):
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def main():
    corpus = {}  # name -> [(fname, words)]
    for name, d in CORPORA.items():
        d = os.path.normpath(d)
        items = []
        for f in sorted(os.listdir(d)):
            if f.endswith((".json", ".md")) or f.startswith("."):
                continue
            p = os.path.join(d, f)
            if os.path.isfile(p) and os.path.getsize(p) < 2_000_000:
                items.append((f, words(open(p, encoding="utf-8", errors="replace").read())))
        corpus[name] = items
        print(f"corpus {name}: {len(items)} files")

    rows = [json.loads(l) for l in open(SRC, encoding="utf-8") if l.strip()]
    judged = [json.loads(l) for l in open(RESULT, encoding="utf-8") if l.strip()]

    lines = ["# 判定卡 B 同源比对（词集 Jaccard，9967 手法）\n",
             "> 阈值：≥0.5 高嫌疑 / 0.3~0.5 中嫌疑 / <0.3 无信号。代码 token 取 ≥4 字符标识符。\n"]
    n_hit = 0
    for j in judged:
        rn = int(j["row"])
        u = rows[rn]["messages"][1]["content"]
        blocks = CODE_RE.findall(u)
        text = "\n".join(blocks) if blocks else u
        w = words(text)
        best = []
        for cname, items in corpus.items():
            for fname, cw in items:
                v = jac(w, cw)
                if v >= 0.2:
                    best.append((v, cname, fname))
        best.sort(reverse=True)
        top = best[:3]
        flag = "高嫌疑" if top and top[0][0] >= 0.5 else ("中嫌疑" if top and top[0][0] >= 0.3 else "无信号")
        if flag != "无信号":
            n_hit += 1
        lines.append(f"## {j['no']} row={rn} verdict={j.get('verdict','')} 泄漏判定={flag}")
        for v, cname, fname in top:
            lines.append(f"- {v:.3f} {cname}/{fname}")
        if not top:
            lines.append("- （全部 <0.2）")
        lines.append("")
    lines.insert(2, f"**有信号行数：{n_hit}/40**\n")
    open(OUT, "w", encoding="utf-8").write("\n".join(lines))
    print(f"-> {OUT}  有信号 {n_hit}/40")
    # 控制台直接打高/中嫌疑行
    for ln in lines:
        if "高嫌疑" in ln or "中嫌疑" in ln:
            print(ln)


if __name__ == "__main__":
    main()
