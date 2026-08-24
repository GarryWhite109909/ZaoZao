#!/usr/bin/env python3
"""挖掘跑结果分析：把 evaluate.py 结果 JSON 归档成按知识点组织的弱点报告。

失败四分类（模型层口径，无工具层参与）：
  parse_fail_truncated —— 输出顶到 max_new_tokens 上限被切断（无 ```json）
  parse_fail_format    —— 输出完整但没有可解析 JSON（格式失败）
  FN_wrong_direction   —— 判了安全（真漏洞被放行）
  FN_cwe_mismatch      —— 方向对但 CWE 标错（strict 口径失败）
real-safe 侧对应 FP 分类复用同脚本（expected_present=false 时 FN_* 变 FP_*）。

用法：python analyze_mining_run.py <result.json> [--out report.md]
"""
import argparse
import json
import re
import sys


def classify(rec):
    outcome = rec["outcome"]
    raw = rec.get("raw_output") or ""
    has_json = bool(re.search(r"```json", raw))
    if outcome == "parse_fail":
        # 无 json 块 + 长度贴近 2048 token 截断带 → 输出超长被切
        near_cap = len(raw) > 1800  # 中文≈1字/token，2048 上限的经验带
        return "parse_fail_truncated" if (not has_json and near_cap) else "parse_fail_format"
    if outcome == "FN":
        return "FN_cwe_mismatch" if rec.get("model_vulnerability_type") else "FN_wrong_direction"
    return outcome


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("result_json")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    data = json.loads(open(args.result_json).read())
    samples = data["samples"] if isinstance(data, dict) and "samples" in data else data
    if isinstance(samples, dict):
        samples = list(samples.values())

    rows = []
    for rec in samples:
        rows.append({
            "file": rec["file"], "lang": rec.get("language", "?"),
            "cwe": rec.get("expected_cwe", "?"), "outcome": rec["outcome"],
            "cls": classify(rec), "model_type": rec.get("model_vulnerability_type", ""),
        })

    n = len(rows)
    cnt = {}
    for r in rows:
        cnt[r["cls"]] = cnt.get(r["cls"], 0) + 1
    print(f"总数 {n}")
    for k, v in sorted(cnt.items(), key=lambda x: -x[1]):
        print(f"  {k}: {v} ({v/n:.0%})")

    by_cwe = {}
    for r in rows:
        if r["cls"].startswith(("FN", "parse")) or r["cls"] == "FP":
            by_cwe.setdefault(r["cwe"], []).append(r)
    print("\n失败按 CWE 归档：")
    for cwe, lst in sorted(by_cwe.items(), key=lambda x: -len(x[1])):
        langs = sorted(set(x["lang"] for x in lst))
        print(f"  {cwe}: {len(lst)} 条 {[x['file'] for x in lst]} ({','.join(langs)})")

    if args.out:
        with open(args.out, "w") as f:
            f.write("# 挖掘跑弱点归档（模型层）\n\n")
            f.write(f"来源: {args.result_json}\n\n## 汇总\n\n")
            for k, v in sorted(cnt.items(), key=lambda x: -x[1]):
                f.write(f"- {k}: {v}\n")
            f.write("\n## 明细\n\n")
            for r in rows:
                if r["cls"] in ("TP", "TN"):
                    continue
                f.write(f"### {r['file']} [{r['cls']}] {r['cwe']} ({r['lang']})\n\n")
                rec = next(s for s in samples if s["file"] == r["file"])
                raw = rec.get("raw_output") or ""
                f.write("结论尾部:\n```\n" + raw[-300:] + "\n```\n\n")
        print(f"\n报告: {args.out}")


if __name__ == "__main__":
    main()
