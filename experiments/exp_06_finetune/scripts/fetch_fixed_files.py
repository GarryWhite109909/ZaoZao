#!/usr/bin/env python3
"""拉取语料样本对应修复后版本的文件（minimal pair 的 safe 侧）。

对 train_pool 每个样本：source_sha 即修复 commit，取该 commit 下同路径文件的
内容（修复后）存到 train_pool_fixed/。修复中被重命名/删除的文件跳过并记录。

用法：
  GITHUB_TOKEN=ghp_xxx python3 fetch_fixed_files.py [--resume]
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from prepare_cve_fix_testset import (
    check_token, get_file_content, get_commit_detail,
)

BASE = Path(__file__).resolve().parents[1] / "corpus"
FIXED_DIR = BASE / "train_pool_fixed"
MAP_PATH = BASE / "train_pool_fixed" / "fixed_map.json"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    token = check_token()

    FIXED_DIR.mkdir(parents=True, exist_ok=True)
    mapping = {}
    if args.resume and MAP_PATH.exists():
        mapping = json.loads(MAP_PATH.read_text())

    manifest = json.loads((BASE / "train_pool" / "manifest.json").read_text())
    stats = {"ok": 0, "gone": 0, "fail": 0}

    for s in manifest["samples"]:
        stem = Path(s["file"]).stem
        if stem in mapping:
            continue
        owner, repo = s["source_repo"].split("/", 1)
        ext = Path(s["file"]).suffix
        out_name = f"{stem}_fixed{ext}"
        time.sleep(0.4)
        code = get_file_content(token, owner, repo, s["source_path"], s["source_sha"])
        if code is None:
            # 文件可能在修复 commit 中被改名/删除；查一次 detail 确认状态
            detail = get_commit_detail(token, owner, repo, s["source_sha"])
            gone = False
            if detail:
                for f in detail.get("files", []):
                    if f.get("filename") == s["source_path"] and f.get("status") in ("removed", "renamed"):
                        gone = True
            if gone:
                mapping[stem] = {"status": "removed_or_renamed"}
                stats["gone"] += 1
            else:
                mapping[stem] = {"status": "error"}
                stats["fail"] += 1
        else:
            (FIXED_DIR / out_name).write_text(code, encoding="utf-8")
            mapping[stem] = {
                "status": "ok",
                "fixed_file": out_name,
                "bytes": len(code),
                "cve_id": s.get("cve_id"),
            }
            stats["ok"] += 1
        MAP_PATH.write_text(json.dumps(mapping, ensure_ascii=False, indent=1))
        mark = {"ok": "✓", "gone": "∅", "error": "✗"}[
            mapping[stem]["status"].split("_")[0].replace("removed", "gone").replace("error", "✗")]
        print(f"  {mark} {s['file']} -> {out_name if mapping[stem]['status']=='ok' else mapping[stem]['status']}")

    print(f"\n完成：{json.dumps(stats)}")


if __name__ == "__main__":
    main()
