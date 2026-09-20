#!/usr/bin/env python
"""工具层召回审计（2026-09-20）：只跑 Stage 1（零 LLM），按通道归因候选来源。

语料：
  1. exp_04 演示样本 87 段（带 expected_present 标签，safe_control/noise 为误报面）
  2. exp_08 四仓库真实代码（dvna/nodegoat/php-goof/vflask，带 manifest 标签）

指标（泛化性能）：
  - 漏召回：漏洞样本（expected_present=true）0 候选的比例，按类别/语言分解
  - 误报种子：safe_control / noise 样本产生 ≥1 裁决档候选的比例
  - 通道归因：taint_tracker / prefilter / semgrep / external 各自贡献

用法：python scripts/recall_audit.py [--corpus demo|repos|all]
"""
from __future__ import annotations

import argparse
import io
import contextlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.backend.services.scanner import Scanner  # noqa: E402
from graduation_project.two_stage_scanner import TwoStageScanner  # noqa: E402


def build_scanner():
    sc = Scanner(model="dummy")
    ts = TwoStageScanner(
        client=sc.client, system_prompt=sc.system_prompt,
        keep_alive=0, num_ctx=8192, triage_aligned=True,
        no_candidate_mode="targeted", n_samples=1,
    )
    return ts


def recall_one(ts, code: str, language: str, filename: str):
    """单文件 Stage 1 召回（静默），返回 findings 列表。"""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            findings = ts._stage1_recall(code, language, filename)
        except Exception as e:  # noqa: BLE001
            print(f"  [audit] {filename} 召回异常: {e}", file=sys.stderr)
            findings = []
    return findings


def audit_demo(ts, verbose=False):
    manifest = json.load(open(PROJECT_ROOT / "app/backend/static/samples/demo/manifest.json", encoding="utf-8"))
    items = manifest if isinstance(manifest, list) else manifest.get("samples", manifest.get("items", []))
    rows = []
    for s in items:
        path = PROJECT_ROOT / "app/backend/static/samples/demo" / s["file"]
        if not path.is_file():
            continue
        code = path.read_text(encoding="utf-8", errors="replace")
        lang = {"Python": "python", "JavaScript": "javascript", "Java": "java", "PHP": "php"}.get(s["language"], s["language"].lower())
        findings = recall_one(ts, code, lang, s["file"])
        adjud = [f for f in findings if f.category not in ("secret", "sca")]
        rows.append({
            "file": s["file"], "lang": lang, "category": s["category"],
            "difficulty": s.get("difficulty", ""),
            "expected": s["expected_present"],
            "n_findings": len(findings), "n_adjud": len(adjud),
            "tools": Counter(f.tool for f in findings),
            "types": sorted({f.taint_type for f in findings}),
        })
    return rows


def audit_repos(ts):
    rows = []
    base = PROJECT_ROOT / "experiments/exp_08_repo_benchmark"
    for mf in sorted(base.glob("manifest_*.json")):
        m = json.load(open(mf, encoding="utf-8"))
        if m.get("repo", "").startswith("local/"):
            continue
        for fspec in m.get("files", []):
            rel = fspec["file"]
            for repo_dir in (base / "repos").iterdir():
                p = repo_dir / rel
                if p.is_file():
                    break
            else:
                continue
            code = p.read_text(encoding="utf-8", errors="replace")
            lang = {"javascript": "javascript", "python": "python", "php": "php", "java": "java"}.get(fspec["language"], fspec["language"])
            findings = recall_one(ts, code, lang, rel)
            adjud = [f for f in findings if f.category not in ("secret", "sca")]
            rows.append({
                "file": f"{m['repo'].split('/')[-1]}/{rel}", "lang": lang,
                "category": "repo", "difficulty": "",
                "expected": fspec.get("expected_present"),
                "n_findings": len(findings), "n_adjud": len(adjud),
                "tools": Counter(f.tool for f in findings),
                "types": sorted({f.taint_type for f in findings}),
            })
    return rows


def summarize(rows, title):
    print("=" * 78)
    print(f"{title}（{len(rows)} 文件）")
    vuln = [r for r in rows if r["expected"] is True]
    safe = [r for r in rows if r["expected"] is False]
    missed = [r for r in vuln if r["n_adjud"] == 0 and r["n_findings"] == 0]
    fp_seeds = [r for r in safe if r["n_adjud"] > 0]
    print(f"  漏召回: {len(missed)}/{len(vuln)} 漏洞文件零候选 "
          f"({100 * len(missed) / max(len(vuln), 1):.0f}% 漏)")
    by_cat = Counter(r["category"] for r in missed)
    print(f"    漏召回按类别: {dict(by_cat)}")
    by_lang_missed = Counter(r["lang"] for r in missed)
    by_lang_all = Counter(r["lang"] for r in vuln)
    print(f"    漏召回按语言: { {k: f'{v}/{by_lang_all.get(k, v)}' for k, v in by_lang_missed.items()} }")
    print(f"  误报种子: {len(fp_seeds)}/{len(safe)} 安全文件产生裁决候选 "
          f"({100 * len(fp_seeds) / max(len(safe), 1):.0f}%)")
    for r in fp_seeds[:10]:
        print(f"    [FP种子] {r['file']} ({r['category']}): {r['types'][:3]} via {dict(r['tools'])}")
    tool_total = Counter()
    for r in rows:
        tool_total.update(r["tools"])
    print(f"  通道贡献（全部文件）: {dict(tool_total)}")
    return missed, fp_seeds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", choices=["demo", "repos", "all"], default="all")
    ap.add_argument("--missed-detail", action="store_true", help="打印全部漏召回明细")
    args = ap.parse_args()

    ts = build_scanner()
    all_rows = []
    if args.corpus in ("demo", "all"):
        rows = audit_demo(ts)
        all_rows += rows
        missed, _ = summarize(rows, "演示样本 87 段（exp_04 测试集）")
        if args.missed_detail:
            for r in missed:
                print(f"    [漏] {r['file']} ({r['category']}/{r['difficulty']}/{r['lang']})")
    if args.corpus in ("repos", "all"):
        rows = audit_repos(ts)
        all_rows += rows
        summarize(rows, "exp_08 四仓库真实代码")
    # 语言覆盖总表
    print("=" * 78)
    lang_agg = defaultdict(lambda: {"files": 0, "with_cand": 0})
    for r in all_rows:
        lang_agg[r["lang"]]["files"] += 1
        if r["n_findings"]:
            lang_agg[r["lang"]]["with_cand"] += 1
    print("语言覆盖（有候选文件数/文件数）:")
    for lang, agg in sorted(lang_agg.items()):
        print(f"  {lang:<12} {agg['with_cand']}/{agg['files']}")


if __name__ == "__main__":
    main()
