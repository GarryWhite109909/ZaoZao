# -*- coding: utf-8 -*-
"""
示意代码 / 占位代码全量扫描（2026-09-09）

背景：line 5613 发现「自认占位的示意代码」——`memset(env_key_copy, ...)` 变量未声明，
      且自带注释 `/* 注意：此处为示意，实际应操作 buf */`。这是网页蒸馏的真风险：
      教的不是漏洞判别，而是"编一段看起来对的代码"。

本脚本只扫**代码块内部**（叙事里的"示例"不算），按置信度分三档：
  HIGH 自认非真实 —— 明说"示意/伪代码/省略/不可运行"
  MED  完成度存疑 —— stub/placeholder/not implemented/后续补充
  LOW  需人工看一眼 —— "实际应/生产环境应/真实场景"类免责注释

产出：示意代码扫描_v2_16_20260909.jsonl + 控制台摘要（按 label / CWE 交叉）
"""
import json, re, sys, os, collections

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.normpath(os.path.join(ROOT, "..", "data", "final_train_chatml_alpha06_v2_16.jsonl"))
OUT = os.path.join(ROOT, "示意代码扫描_v2_16_20260909.jsonl")

HIGH = re.compile(
    r"此处为示意|仅为示意|示意代码|示意性的|伪代码|pseudocode|不可运行|无法运行|"
    r"此处省略|省略了|省略其余|其余省略|略去|此处略|（略）|\(略\)|同上|"
    r"由于篇幅|篇幅所限|为简洁|为简单起见|省略错误处理|省略了错误")
MED = re.compile(
    r"placeholder|not implemented|未实现|待实现|待补充|TODO|FIXME|"
    r"stub|dummy|\bfake\b|mock(?!up)|假设已|假定已|假设存在|假定存在")
LOW = re.compile(
    r"实际应(?!用)|实际中应|真实场景应|生产环境应|实际部署应|应替换为|应改为|"
    r"此处简化|做了简化|简化处理|示意性地|为演示|仅为演示|demo only|for brevity")

FENCE = re.compile(r"```[A-Za-z0-9_+\-]*\n(.*?)```", re.S)


def main():
    rows = []
    with open(DATA, encoding="utf-8") as f:
        for i, l in enumerate(f):
            l = l.strip()
            if not l:
                continue
            try:
                r = json.loads(l)
            except Exception:
                continue
            u = a = ""
            for m in r.get("messages", []):
                if m.get("role") == "user":
                    u = m.get("content", "")
                elif m.get("role") == "assistant":
                    a = m.get("content", "")
            fences = FENCE.findall(u)
            if not fences:
                continue
            code = max(fences, key=len)
            lines = code.split("\n")
            hits = []
            for ln, text in enumerate(lines, 1):
                tier = "HIGH" if HIGH.search(text) else ("MED" if MED.search(text) else ("LOW" if LOW.search(text) else None))
                if tier:
                    hits.append({"tier": tier, "line_in_code": ln, "text": text.strip()[:120]})
            if not hits:
                continue
            hv = None
            cwe = ""
            b = re.findall(r"```json\s*(.*?)```", a, re.S)
            if b:
                try:
                    v = json.loads(b[-1].strip())
                    hv = v.get("has_vulnerability")
                    if isinstance(hv, str):
                        hv = hv.strip().lower() in ("true", "yes", "1")
                    mm = re.search(r"CWE-(\d+)", str(v.get("vulnerability_type") or ""))
                    cwe = "CWE-" + mm.group(1) if mm else ""
                except Exception:
                    pass
            rows.append({"line": i + 1, "has_vuln": hv, "cwe": cwe,
                         "top_tier": min((h["tier"] for h in hits), key=lambda t: ["HIGH", "MED", "LOW"].index(t)),
                         "n_hits": len(hits), "hits": hits[:4]})

    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    by_tier = collections.Counter(r["top_tier"] for r in rows)
    by_label = collections.Counter((r["top_tier"], r["has_vuln"]) for r in rows)
    top_cwe = collections.Counter(r["cwe"] for r in rows if r["top_tier"] == "HIGH" and r["cwe"])

    print(f"命中样本: {len(rows)} / 10151")
    for t in ("HIGH", "MED", "LOW"):
        print(f"  {t:<5} {by_tier.get(t,0):>4}")
    print("  分档 × 标签:", dict(sorted(by_label.items(), key=lambda x: str(x[0]))))
    print("  HIGH 档 CWE top:", top_cwe.most_common(8))
    print()
    print("--- HIGH 档示例（前 8）---")
    for r in [x for x in rows if x["top_tier"] == "HIGH"][:8]:
        h = r["hits"][0]
        print(f"  行{r['line']:>5} label={str(r['has_vuln']):<5} {r['cwe']:<9} | {h['text'][:70]}")
    print(f"\n明细: {os.path.basename(OUT)}")


if __name__ == "__main__":
    main()
