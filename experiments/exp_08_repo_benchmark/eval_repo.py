"""仓库级基准评估：真实教学仓库全文件扫描 vs 已知答案清单（exp_08）。

与 exp_07（单漏洞样本测引擎）的分工：
  - exp_07：单文件、单 expected_cwe，测"判定+类型"的引擎能力；
  - 本脚本：整仓多文件、单文件多发现（expected_findings），测"仓库形态"下的
    文件级判定、类型命中、发现级召回（漏了文件里第几个洞）、误报（标 false 文件
    判真）与吞吐（工程化指标）。

三列对照（论文"工具层为 LLM 减负"仓库级数据）：
  A 列 = 外部工具原始输出（bandit/semgrep 对该文件的 finding）
  B 列 = 本系统最终判定（confirmed 且过证据门的类型）
  C 列 = 已知答案（manifest.expected_findings）

用法：
  python eval_repo.py --manifest manifest_dvna.json \
      --repo-dir repos/dvna --backend transformers [--resume] [--output ...]

输出：results/repo_eval.<repo>.<ts>.json（逐文件明细 + 汇总指标 + 三列对照）
"""
import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

_CWE_RE = re.compile(r"CWE-(\d+)")


def load_manifest(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def scan_external_tools(code: str, lang: str, tmp: Path) -> list[dict]:
    """A 列：外部工具原始 finding（不进裁决，仅对照）。"""
    from graduation_project.external_scanner import ExternalScanner
    p = tmp / "target_file"
    p.write_text(code, encoding="utf-8")
    try:
        hits = ExternalScanner().scan_sast(str(p), lang) or []
    except Exception as e:
        print(f"  [external] 失败（跳过 A 列）: {e}")
        return []
    return [{"tool": h.tool, "rule": h.rule_id, "line": h.line,
             "cwe_hint": (re.findall(r"CWE-(\d+)", h.message or "") or [None])[0]}
            for h in hits]


def judge_file(ts, code: str, lang: str, fname: str) -> dict:
    r = ts.scan_code(code, lang, fname)
    card = r.to_dict()
    confirmed = []
    for a in card.get("adjudications") or []:
        if not a.get("confirmed") or a.get("evidence_gate"):
            continue
        vt = a.get("vulnerability_type") or a.get("taint_type") or ""
        confirmed.append({"cwe": (_CWE_RE.findall(vt) or [vt])[0] if vt else None,
                          "votes": f"{a.get('votes_true')}/{a.get('votes_false')}",
                          "type": vt})
    return {"card": card, "confirmed": confirmed,
            "hv": card.get("has_vulnerability"),
            "vtype": card.get("vulnerability_type") or ""}


def compare(rec: dict, judged: dict) -> dict:
    """发现级比对：expected_findings vs 系统确认的类型集合（行号放宽为文件级命中）。"""
    exp = rec.get("expected_findings") or []
    exp_cwes = {f["cwe"] for f in exp if f.get("cwe")}
    got_cwes = {f.get("cwe") for f in judged["confirmed"] if f.get("cwe")}
    hit = exp_cwes & got_cwes
    return {"expected_cwes": sorted(exp_cwes),
            "got_cwes": sorted(got_cwes),
            "hit": sorted(hit),
            "missed": sorted(exp_cwes - got_cwes),
            "extra": sorted(got_cwes - exp_cwes),   # 系统多报的（可能是真发现/误报，人工判）
            "discovery_recall": (len(hit) / len(exp_cwes)) if exp_cwes else None}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--repo-dir", required=True, help="已 clone 的仓库根目录")
    ap.add_argument("--backend", default="transformers")
    ap.add_argument("--num-ctx", type=int, default=16384)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--output", default=None)
    args = ap.parse_args()

    manifest = load_manifest(Path(args.manifest))
    repo_root = Path(args.repo_dir)
    ts_out = time.strftime("%Y%m%d_%H%M%S")
    out = Path(args.output) if args.output else (
        HERE / "results" / f"repo_eval.{manifest['repo'].split('/')[-1]}.{ts_out}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists() and not args.resume:
        out.unlink()

    prev = {"files": []}
    if args.resume and out.exists():
        prev = json.loads(out.read_text(encoding="utf-8"))
    done = {f["file"] for f in prev.get("files", [])}
    rows = list(prev.get("files", []))

    # 生产组态（与 mock_frontend_card 对齐检查表同款）
    from graduation_project.two_stage_scanner import TwoStageScanner
    from graduation_project.transformers_client import create_llm_client
    from graduation_project.paths import resolve_base_model_path, resolve_adapter_path
    from graduation_project.prompts import ALPHA05_PROMPT

    client = create_llm_client(
        "transformers",
        model_id=resolve_base_model_path(),
        adapter=resolve_adapter_path(),
        num_ctx=args.num_ctx,
    )
    ts = TwoStageScanner(client=client, system_prompt=ALPHA05_PROMPT, n_samples=3,
                         triage_aligned=True, no_candidate_mode="full_recheck")
    print("=== 生产组态（同 mock_frontend_card 对齐检查表）===")

    import tempfile
    stats = {"tp_files": 0, "tn_files": 0, "fp_files": 0, "review_files": 0,
             "findings_hit": 0, "findings_total": 0, "extra": 0, "durations": []}
    for rec in manifest["files"]:
        fname = rec["file"]
        if fname in done:
            continue
        path = repo_root / fname
        if not path.exists():
            print(f"[skip] {fname} 不存在")
            continue
        code = path.read_text(encoding="utf-8", errors="replace")
        lang = rec.get("language", "python").lower()
        if lang == "javascript":
            lang = "javascript"

        t0 = time.time()
        judged = judge_file(ts, code, lang, fname)
        dur = round(time.time() - t0, 1)
        with tempfile.TemporaryDirectory() as td:
            ext = scan_external_tools(code, lang, Path(td))
        cmp_res = compare(rec, judged)

        exp_present = rec.get("expected_present")
        hv = judged["hv"]
        if hv is True and exp_present:
            stats["tp_files"] += 1
        elif hv is False and not exp_present:
            stats["tn_files"] += 1
        elif hv is True and not exp_present:
            stats["fp_files"] += 1
        else:
            stats["review_files"] += 1
        stats["findings_hit"] += len(cmp_res["hit"])
        stats["findings_total"] += len(cmp_res["expected_cwes"])
        stats["extra"] += len(cmp_res["extra"])
        stats["durations"].append(dur)

        row = {"file": fname, "expected_present": exp_present,
               "hv": hv, "vtype": judged["vtype"],
               "expected_findings": rec.get("expected_findings"),
               "confirmed": judged["confirmed"],
               "compare": cmp_res, "external": ext,
               "duration": dur}
        rows.append(row)
        print(f"[{fname}] {dur}s hv={hv} 类型={judged['vtype']!r} "
              f"发现命中 {len(cmp_res['hit'])}/{len(cmp_res['expected_cwes'])} "
              f"多报={len(cmp_res['extra'])}")
        # 边跑边落盘
        out.write_text(json.dumps(
            {"meta": {"repo": manifest["repo"], "ts": ts_out}, "stats": stats,
             "files": rows}, ensure_ascii=False, indent=2), encoding="utf-8")

    n = len(rows)
    avg = round(sum(stats["durations"]) / max(1, len(stats["durations"])), 1)
    print(f"\n===== 仓库基准汇总 {manifest['repo']} =====")
    print(f"文件级: TP={stats['tp_files']} TN={stats['tn_files']} "
          f"FP={stats['fp_files']} 复核={stats['review_files']}")
    print(f"发现级 recall: {stats['findings_hit']}/{stats['findings_total']}"
          f"={round(stats['findings_hit']/max(1,stats['findings_total']),3)}")
    print(f"多报（人工定性）: {stats['extra']} | 平均耗时: {avg}s/文件")
    print(f"结果: {out}")


if __name__ == "__main__":
    main()
