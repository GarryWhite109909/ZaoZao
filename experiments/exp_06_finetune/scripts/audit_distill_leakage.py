#!/usr/bin/env python3
"""蒸馏产出审计：泄漏检查（P0.2）+ alpha05 格式核验。

泄漏：distill 样本的用户代码 vs 三测试集（87段 / cve_fix20 / rolling_dev）
      归一化行集 Jaccard，阈值 0.3 剔除、0.5 红线。
格式：system 与 ALPHA05_PROMPT 逐字一致；user 头格式；assistant 七字段与判定方向。
输出报告到 corpus/distill_audit_report.md。
"""
import json
import re
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
CORPUS = PROJECT / "experiments/exp_06_finetune/corpus"
DISTILL = CORPUS / "distill_alpha_pairs.jsonl"
REPORT = CORPUS / "distill_audit_report.md"

sys.path.insert(0, str(PROJECT))
from graduation_project.prompts import ALPHA05_PROMPT

REQUIRED_FIELDS = ["has_vulnerability", "vulnerability_type", "risk_level",
                   "source", "sink", "explanation", "fix_suggestion"]


def norm_lines(code: str) -> set:
    out = set()
    for ln in code.splitlines():
        s = ln.strip()
        if not s or s.startswith(("#", "//")):
            continue
        s = re.sub(r'"""[\s\S]*?"""', "", s)
        s = re.sub(r"\s+", " ", s).lower()
        if len(s) >= 8:
            out.add(s)
    return out


def jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def load_testsets():
    sets = {}
    e04 = PROJECT / "experiments/exp_04_hard_samples/samples"
    for f in e04.glob("*"):
        if f.suffix in (".py", ".java", ".js", ".php", ".go", ".ts"):
            sets[f"87seg/{f.name}"] = f.read_text(errors="replace")
    cf = PROJECT / "experiments/exp_06_finetune/testset_cve_fix"
    for f in cf.glob("cve_fix_*"):
        if f.is_file():
            sets[f"cve20/{f.name}"] = f.read_text(errors="replace")
    rd = PROJECT / "experiments/exp_06_finetune/corpus/rolling_dev"
    for f in rd.glob("corpus_*"):
        if f.is_file():
            sets[f"rollingdev/{f.name}"] = f.read_text(errors="replace")
    return sets


def main():
    testsets = load_testsets()
    test_norm = {k: norm_lines(v) for k, v in testsets.items()}

    records = []
    fmt_bad = []
    for i, line in enumerate(DISTILL.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError as e:
            fmt_bad.append(f"L{i}: json 解析失败 {e}")
            continue
        msgs = r.get("messages", [])
        meta = r.get("meta", {})
        # 格式核验
        if msgs[0]["content"] != ALPHA05_PROMPT:
            fmt_bad.append(f"L{i}: system 与 ALPHA05_PROMPT 不一致")
        if not msgs[1]["content"].startswith("代码片段（语言"):
            fmt_bad.append(f"L{i}: user 头格式不符")
        m = re.search(r"```json\s*(\{.*?\})\s*```", msgs[2]["content"], re.S)
        if not m:
            fmt_bad.append(f"L{i}: 无 json 结论块")
        else:
            try:
                obj = json.loads(m.group(1))
                miss = [k for k in REQUIRED_FIELDS if k not in obj]
                if miss:
                    fmt_bad.append(f"L{i}: 缺字段 {miss}")
                hv = obj.get("has_vulnerability")
                want = meta.get("kind") == "vuln"
                if hv is not want:
                    fmt_bad.append(f"L{i}: 判定方向与 kind 矛盾")
            except json.JSONDecodeError as e:
                fmt_bad.append(f"L{i}: json 解析失败 {e}")
        records.append((i, r, norm_lines(msgs[1]["content"])))

    # 泄漏比对
    hits = []
    for i, r, norm in records:
        best_k, best_v = "", 0.0
        for k, tn in test_norm.items():
            j = jaccard(norm, tn)
            if j > best_v:
                best_k, best_v = k, j
        if best_v >= 0.3:
            hits.append((best_v, best_k, r["meta"].get("seed_file"),
                         r["meta"].get("cve_id"), r["meta"].get("kind")))

    hits.sort(reverse=True)
    n = len(records)
    over03 = sum(1 for h in hits if h[0] >= 0.3)
    over05 = sum(1 if h[0] >= 0.5 else 0 for h in hits)
    vuln_n = sum(1 for _, r, _ in records if r["meta"]["kind"] == "vuln")
    safe_n = n - vuln_n

    lines = [
        "# 蒸馏产出审计报告（P0.2）\n",
        f"- 样本总数：{n}（漏洞侧 {vuln_n} / 安全对 {safe_n}）",
        f"- 格式核验不通过：{len(fmt_bad)} 条",
        f"- 泄漏门 0.3~0.5：{over03 - over05} 条（需剔除/改写）",
        f"- 泄漏红线 ≥0.5：{over05} 条",
        "",
        "## 泄漏命中明细（≥0.3）",
    ]
    if hits:
        lines.append("| Jaccard | 测试集文件 | 种子样本 | CVE | 类别 |")
        lines.append("|---|---|---|---|---|")
        for v, k, seed, cve, kind in hits[:40]:
            lines.append(f"| {v:.3f} | {k} | {seed} | {cve} | {kind} |")
    else:
        lines.append("（无命中）")
    if fmt_bad:
        lines += ["", "## 格式问题明细", *[f"- {x}" for x in fmt_bad[:30]]]

    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines[:12]))
    print(f"\n完整报告: {REPORT}")
    sys.exit(1 if (over05 or len(fmt_bad) > n * 0.01) else 0)


if __name__ == "__main__":
    main()
