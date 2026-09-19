# -*- coding: utf-8 -*-
"""存量语料回填（20260913）：给已有 patch 补 `diff --git` 头 + 落 commit 文件清单台账。

背景（`_gap_disposition_20260913.md` §6）：
  实测 corpus/patches/*.patch **291/291 全部缺失 `diff --git` 头**，
  导致无法从 patch 得知"这个 CVE 还改了哪几个文件"，门 A 失去文件级输入。

本脚本用 manifest 里完好的元数据（source_repo / source_path / source_sha /
source_parent_sha / cve_id）就地重建头部与台账：

  1. 给每个 patch 补 `diff --git a/<source_path> b/<source_path>` 三行头（幂等）；
  2. 生成 corpus/patch_meta/<CVE>.json，记录该 commit 的已知文件清单
     （离线只能填 source_path；若有网络 + 本地克隆，可用 --resolve 补全同批文件）；
  3. 输出回填报告，供门 A/门B+ 复跑。

用法：
  python backfill_patch_headers_20260913.py --apply
  python backfill_patch_headers_20260913.py --apply --resolve --repo-dir <仓库根>
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
CORPUS = BASE / "corpus"
PATCHES = CORPUS / "patches"
META = CORPUS / "patch_meta"
MANIFEST = CORPUS / "train_pool" / "manifest.json"


def is_header(text: str) -> bool:
    return text.lstrip().startswith("diff --git")


def show_name_only(repo_dir: Path, sha: str):
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_dir), "show", "--name-only", "--format=", sha],
            capture_output=True, text=True, timeout=90)
        if out.returncode != 0:
            return None, out.stderr.strip()[:160]
        return [l.strip() for l in out.stdout.splitlines() if l.strip()], None
    except Exception as e:
        return None, str(e)[:160]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="实际写盘（默认只报告）")
    ap.add_argument("--resolve", action="store_true", help="联网/本地克隆补全同批文件清单")
    ap.add_argument("--repo-dir", default=None)
    a = ap.parse_args()

    samples = json.loads(MANIFEST.read_text(encoding="utf-8"))["samples"]
    print(f"manifest 样本 {len(samples)}")

    report = {"total": 0, "already_have_header": 0, "header_added": 0,
              "missing_patch": 0, "meta_written": 0, "resolved": 0, "resolve_fail": 0}
    META.mkdir(parents=True, exist_ok=True)
    repo_root = Path(a.repo_dir) if a.repo_dir else None

    for s in samples:
        pf = s.get("patch_file")
        if not pf:
            continue
        p = CORPUS / pf
        report["total"] += 1
        if not p.exists():
            report["missing_patch"] += 1
            continue

        text = p.read_text(encoding="utf-8", errors="replace")
        src_path = s.get("source_path") or ""
        if is_header(text):
            report["already_have_header"] += 1
        else:
            report["header_added"] += 1
            if a.apply and src_path:
                header = (f"diff --git a/{src_path} b/{src_path}\n"
                          f"--- a/{src_path}\n"
                          f"+++ b/{src_path}\n")
                p.write_text(header + text, encoding="utf-8")

        # commit 级台账
        cve = s.get("cve_id") or Path(pf).stem
        meta_path = META / f"{cve.replace('/', '_')}.json"
        files = [{"filename": src_path, "from": "manifest.source_path"}]
        if a.resolve and repo_root:
            cand = repo_root / str(s.get("source_repo", "")).replace("/", "__")
            if cand.exists() and s.get("source_parent_sha"):
                listed, err = show_name_only(cand, s["source_parent_sha"])
                if listed:
                    files = [{"filename": f, "from": "git_show_name_only"} for f in listed]
                    report["resolved"] += 1
                else:
                    report["resolve_fail"] += 1
        if a.apply:
            meta_path.write_text(json.dumps({
                "cve_id": cve,
                "repo": s.get("source_repo"),
                "fix_sha": s.get("source_sha"),
                "parent_sha": s.get("source_parent_sha"),
                "sample_file": s.get("file"),
                "files": files,
                "sibling_files": [f["filename"] for f in files if f["filename"] != src_path],
                "_backfilled": "2026-09-13",
            }, ensure_ascii=False, indent=1), encoding="utf-8")
            report["meta_written"] += 1

    out = BASE / "corpus" / "diffpair_wave1" / "results"  
    out.mkdir(parents=True, exist_ok=True)
    (out / "_patch_header_backfill_20260913.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")

    print(json.dumps(report, ensure_ascii=False, indent=1))
    if not a.apply:
        print("\n[干跑] 未写盘。加 --apply 实际执行。")


if __name__ == "__main__":
    main()
