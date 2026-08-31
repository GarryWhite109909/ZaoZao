"""risk_budget 预算调度 vs 盲目截断——真实标准答案对照实验（2026-08-31）。

验证问题（app/backend/main.py github_scan 路径的 2026-08-31 改动）：
  旧：os.walk 顺序收集、取前 max_files 即 break（盲目截断）；
  新：全量收集 → risk_budget.allocate 按风险分选取（未覆盖者显式回报）。

核心问题：**在同等预算下，风险调度能否保住标准答案里的漏洞文件？**

口径注意（2026-08-31 首轮验证的教训）：exp04_87 的文件名按字母序恰好把
vuln 密集的 hard_* 排在最前——盲目截断在该集上是" alphabet 运气好"，直接对比
会高估旧策略。故本脚本同时给出**随机顺序截断的期望覆盖**（200 次洗牌）作为
公平基线：风险调度的底线是"不差于随机"，在真实仓库上则应显著优于随机。

数据集与标准答案（expected_present=true 且有 expected_findings 的文件）：
  - dvna / Vulnerable-Flask-App：exp_08 manifest（逐行实读的仓库级答案）
  - exp_04 87 段（flat 目录伪仓库）：61 漏洞 / 26 安全，额外给出 precision@N
    （选中的文件里漏洞占比）——验证打分是否真的把漏洞文件排在安全文件前。

口径（与生产一致）：
  - 收集：os.walk + EXT_TO_LANG + 跳过 .git/node_modules/vendor/__pycache__
  - 新路径：_apply_scan_budget(max_files=N, fold_duplicates=True)（生产默认）
  - 旧路径：walk 顺序取前 N（旧代码在收集循环里 break，等价于 collected[:N]）

输出：每个数据集 × 每档预算的 漏洞覆盖数 / 漏洞文件明细（哪个策略漏了谁），
另打印标准答案文件的风险分与排序位置，供归因。
"""

from __future__ import annotations

import json
import os
import random
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.risk_budget import (  # noqa: E402
    allocate, plan_to_files, score_file,
)

EXT_TO_LANG = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript",
    ".java": "java", ".php": "php", ".go": "go",
    ".c": "c", ".cpp": "cpp", ".cs": "csharp", ".rb": "ruby",
    ".html": "html", ".htm": "html",
    ".vue": "html", ".svelte": "html",
}
SKIP_PARTS = {".git", "node_modules", "vendor", "__pycache__"}

EXP08 = PROJECT_ROOT / "experiments/exp_08_repo_benchmark"
DATASETS = [
    ("dvna", EXP08 / "repos/dvna", EXP08 / "manifest_dvna.json", "repo"),
    ("VFlask", EXP08 / "repos/Vulnerable-Flask-App",
     EXP08 / "manifest_vflask.json", "repo"),
    ("exp04_87", PROJECT_ROOT / "experiments/exp_04_hard_samples/samples",
     PROJECT_ROOT / "experiments/exp_04_hard_samples/samples/manifest.json",
     "flat"),
]
BUDGETS = [3, 5, 8, 10, 15, 20, 50]


def collect_repo(repo_dir: Path) -> list[tuple[str, str, str]]:
    """复刻 _clone_and_collect 的收集逻辑（无硬上限场景，仓库远小于 cap）。"""
    files = []
    for root, _dirs, fnames in os.walk(repo_dir):
        if set(Path(root).parts) & SKIP_PARTS:
            continue
        for fname in fnames:
            ext = Path(fname).suffix.lower()
            if ext not in EXT_TO_LANG:
                continue
            fpath = os.path.join(root, fname)
            try:
                content = Path(fpath).read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            files.append((os.path.relpath(fpath, repo_dir), EXT_TO_LANG[ext], content))
    return files


def load_ground_truth(manifest_path: Path, kind: str) -> dict[str, list]:
    """返回 {相对路径: [CWE...]}——expected_present=true 的漏洞文件。"""
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    gt: dict[str, list] = {}
    entries = data["files"] if kind == "repo" else data.get("samples", [])
    for rec in entries:
        if not rec.get("expected_present"):
            continue
        if kind == "repo":
            findings = rec.get("expected_findings") or []
            cwes = [f.get("cwe", "") for f in findings if f.get("cwe")]
        else:
            raw = (rec.get("expected_cwe") or "").strip()
            cwes = [c.strip().upper() for c in raw.split(";") if c.startswith("CWE")]
        if cwes:
            gt[rec["file"]] = cwes
    return gt


def main() -> None:
    out = {}
    for name, data_dir, manifest_path, kind in DATASETS:
        if kind == "repo":
            collected = collect_repo(data_dir)
        else:
            collected = [
                (p.name, EXT_TO_LANG.get(p.suffix.lower(), "python"),
                 p.read_text(encoding="utf-8", errors="replace"))
                for p in sorted(data_dir.iterdir())
                if p.is_file() and p.suffix.lower() in EXT_TO_LANG
            ]
        gt = load_ground_truth(manifest_path, kind)
        collected_paths = {c[0] for c in collected}
        gt_in = {p: c for p, c in gt.items() if p in collected_paths}
        gt_miss_manifest = sorted(set(gt) - collected_paths)

        print(f"\n===== {name}（收集 {len(collected)} 文件，标准答案 "
              f"{len(gt_in)} 个在收集集内）=====")
        if gt_miss_manifest:
            print(f"  （manifest 有但不在收集集: {gt_miss_manifest}）")

        # 标准答案文件的风险分与排序位次（归因用）
        scored = allocate(collected, max_files=None, fold_duplicates=False)
        rank = {fr.path: i for i, fr in enumerate(scored.selected)}
        smap = {fr.path: fr.score for fr in scored.selected}
        print("  标准答案文件的风险分/位次（共 %d 个可打分文件）：" % len(rank))
        for p in sorted(gt_in, key=lambda x: rank.get(x, 10**9)):
            print(f"    rank={rank.get(p, '×'):>3}  score={smap.get(p, 0):>7.1f}  {p}")

        rows = []
        collected_names = [c[0] for c in collected]
        for n in BUDGETS:
            old_sel = [c[0] for c in collected[:n]]          # 旧：walk 顺序截断
            plan = allocate(collected, max_files=n, fold_duplicates=True)
            new_sel = [f.path for f in plan.selected]        # 新：风险预算
            # 随机顺序截断的期望覆盖（200 次洗牌，公平基线——walk 顺序本质任意）
            rnd = 0.0
            for seed in range(200):
                rng = random.Random(seed)
                shuffled = collected_names[:]
                rng.shuffle(shuffled)
                rnd += sum(1 for p in gt_in if p in shuffled[:n])
            rnd /= 200
            old_hit = sum(1 for p in gt_in if p in old_sel)
            new_hit = sum(1 for p in gt_in if p in new_sel)
            # 新路径里标准答案被折叠的情况（fold 掉 = 没有独立扫描）
            folded_gt = [f.path for f in plan.folded if f.path in gt_in]
            rows.append({"budget": n, "old_hit": old_hit, "new_hit": new_hit,
                         "random_expect": round(rnd, 1),
                         "old_missed": sorted(set(gt_in) - set(old_sel)),
                         "new_missed": sorted(set(gt_in) - set(new_sel)),
                         "new_folded_gt": folded_gt})
            print(f"  预算={n:>3}: 旧覆盖 {old_hit}/{len(gt_in)}"
                  f"  新覆盖 {new_hit}/{len(gt_in)}"
                  f"  随机期望 {rnd:.1f}"
                  + (f"  （新路径折叠掉标准答案: {folded_gt}）" if folded_gt else ""))
        out[name] = {"collected": len(collected), "gt": {p: c for p, c in gt_in.items()},
                     "gt_rank": {p: rank.get(p) for p in gt_in},
                     "gt_score": {p: smap.get(p) for p in gt_in},
                     "rows": rows}

        # 87 段额外：precision@N（选中里漏洞占比）——打分排序质量的总信号
        if kind == "flat":
            safe = set()
            for rec in json.loads(
                    manifest_path.read_text(encoding="utf-8")).get("samples", []):
                if not rec.get("expected_present"):
                    safe.add(rec["file"])
            for n in (10, 20, 30):
                sel = [f.path for f in allocate(
                    collected, max_files=n, fold_duplicates=True).selected]
                old_sel = [c[0] for c in collected[:n]]
                print(f"  precision@{n}: 旧 {sum(1 for p in old_sel if p not in safe)}/{n}"
                      f"  新 {sum(1 for p in sel if p not in safe)}/{n}")

    out_path = EXP08 / "results" / "risk_budget_eval.json"
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=1),
                        encoding="utf-8")
    print(f"\n结果已写入 {out_path}")


if __name__ == "__main__":
    main()
