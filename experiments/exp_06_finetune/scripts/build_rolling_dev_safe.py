#!/usr/bin/env python3
"""离线构建 rolling_dev 的 real-safe 侧（L1-safe，docs/测试集建设方案.md §二）。

不打 GitHub API：rolling_dev 每条自带修复 patch（corpus/patches/CVE-*.patch），
在临时目录重建 source_path 后用 `git apply --include` 只应用目标文件的补丁块，
得到修复后版本。标签即事实（修复 commit parent→fixed），无模型参与。

输出：
  corpus/rolling_dev_safe/corpus_NNNNN.<ext>   修复后代码
  corpus/rolling_dev_safe/manifest.json        expected_present=false 的评估清单
  corpus/rolling_dev_safe/safe_map.json        每条状态（ok / skipped:<原因>）
"""
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
SRC = CORPUS / "rolling_dev"
OUT = CORPUS / "rolling_dev_safe"


def main():
    manifest = json.loads((SRC / "manifest.json").read_text())
    OUT.mkdir(exist_ok=True)
    records, safe_map = [], {}
    ok = skipped = 0
    for s in manifest["samples"]:
        key = s["file"]
        patch = CORPUS / s["patch_file"]  # patch_file 相对 corpus 目录
        src_path = s.get("source_path") or ""
        if not patch.exists():
            safe_map[key] = f"skipped:patch_missing:{s['patch_file']}"
            skipped += 1
            continue
        text = patch.read_text(errors="replace")
        # 文件被删除/改名的补丁无法产出"修复后同路径文件"，按方案 §二.2 跳过
        m = re.search(r"^deleted file mode", text, re.M)
        if m or re.search(r"^rename from ", text, re.M):
            safe_map[key] = "skipped:delete_or_rename"
            skipped += 1
            continue
        vuln_code = (SRC / s["file"]).read_text(errors="replace")
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / src_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(vuln_code)
            # patches/ 里存的是剥掉文件头的纯 hunk，且末尾常缺换行符；
            # 重建 a/ b/ 头并补 \n 后 git apply
            if not text.endswith("\n"):
                text += "\n"
            full_patch = f"--- a/{src_path}\n+++ b/{src_path}\n" + text
            r = subprocess.run(
                ["git", "apply", "--whitespace=nowarn", "-"],
                cwd=td, input=full_patch, capture_output=True, text=True)
            if r.returncode != 0:
                safe_map[key] = f"skipped:apply_fail:{r.stderr.strip()[:120]}"
                skipped += 1
                continue
            fixed = target.read_text(errors="replace")
        if not fixed.strip() or fixed == vuln_code:
            safe_map[key] = "skipped:unchanged_after_patch"
            skipped += 1
            continue
        (OUT / s["file"]).write_text(fixed)
        rec = dict(s)
        rec["expected_present"] = False
        rec["safe_of"] = s.get("cve_id")
        records.append(rec)
        safe_map[key] = "ok"
        ok += 1

    (OUT / "manifest.json").write_text(json.dumps(
        {"experiment": "rolling_dev_safe", "discipline": "eval-only, paired with rolling_dev",
         "samples": records}, ensure_ascii=False, indent=1))
    (OUT / "safe_map.json").write_text(json.dumps(safe_map, ensure_ascii=False, indent=1))
    print(f"ok={ok} skipped={skipped} → {OUT}")
    for k, v in safe_map.items():
        if v != "ok":
            print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
