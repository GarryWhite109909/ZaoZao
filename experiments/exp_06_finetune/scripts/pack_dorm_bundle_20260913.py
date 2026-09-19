# -*- coding: utf-8 -*-
"""宿舍工作包打包（20260913）：收集 v2_17 之后的全部新产出 → 单个 zip（UTF-8 文件名）。"""
import sys
import zipfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = Path(r"d:\code\毕业设计\Graduation-Project")
EXP = ROOT / "experiments" / "exp_06_finetune"
WAVE = EXP / "corpus" / "diffpair_wave1"
OUT = ROOT / "wave2_宿舍工作包_20260913_v2.zip"

# (来源基准目录, 相对模式列表, zip 内前缀)
PICKS = [
    (EXP / "scripts", [
        "diffpair_gates_v2_20260911.py", "make_redistill_truth_kits_20260911.py",
        "wave2_pairlib.py", "build_wave2_pairs_441_20260911.py", "build_wave2_pairs_95_20260911.py",
        "build_wave2_pairs_78s_20260911.py", "build_wave2_kits_20260911.py",
        "convert_kits_to_learner_20260911.py", "gateA_fail_triage_20260911.py",
        "gateA_fail_triage_v2_20260911.py", "gateD_adjudication_sheet_20260911.py",
        "gateD_p3_triage_20260911.py", "gateD_nvd_fetch_20260911.py",
        "apply_nvd_relabel_20260911.py", "parse_redistill_truth_20260913.py",
        "parse_part2_20260913.py", "scan_result_caveats_20260913.py",
        "compare_preaudit_20260913.py", "verify_formal_20260913.py",
        "patch_441_relabel_20260913.py", "patch_95_78_revisions_20260913.py",
        "patch_441_918_relabel_20260913.py", "final_leak_scan_20260911.py",
    ], "experiments/exp_06_finetune/scripts"),
    (WAVE, ["wave2_pairs", "kits_redistill_truth", "kits_wave2_preaudit", "kits_wave2_formal",
            "kits_learner", "_quarantine_20260911"], "experiments/exp_06_finetune/corpus/diffpair_wave1"),
    (WAVE, ["learner_framed_prompt_v3.md", "teacher_prompt_session.md", "manifest_PRIVATE.json",
            "manifest_PRIVATE.json.bak-20260911", "index.md",
            "index_redistill_truth.md", "投喂操作单_20260911.md", "wave2_441_95_SPEC.md"],
     "experiments/exp_06_finetune/corpus/diffpair_wave1"),
    (WAVE / "results", None, "experiments/exp_06_finetune/corpus/diffpair_wave1/results"),  # results 全量
    (ROOT / "docs", ["出题流水线_差分对v2_20260911.md"], "docs"),
]

MANIFEST = """宿舍工作包（20260913）— v2_17 之后全部新产出

experiments/exp_06_finetune/scripts/        六道门机检器 + wave2 构建器/补丁 + parse/verify/字眼扫描（23 个脚本）
experiments/exp_06_finetune/corpus/diffpair_wave1/
  wave2_pairs/                              wave2 手写代码对 46 对（含 oracle 头，源头档案；441 批已按教师轴改标）
  kits_redistill_truth/                     复核包 31（learner 格式）+ result/result.txt = 任务1 教师产出
  kits_wave2_preaudit/                      预审包 46（learner 格式）
  kits_wave2_formal/                        正式蒸馏包 46（learner 格式+边界备注）
  _quarantine_20260911/                     8 个毒包（kits 与 kits_learner 各 8，可还原）
  manifest_PRIVATE.json                     最新台账（含 NVD 改标 00160/00270/00333 + 20260911 治理标记）
  learner_framed_prompt_v3.md               会话 prompt（95/94 已改 MITRE sink 轴 + redistill 包类型）
  投喂操作单_20260911.md                    四任务操作单 v2
  results/                                  全部台账与报告：
    _gates_20260911.*                       六道门机检三分清单（246 条）
    _gateA_fail_triage / _gateD_*           门A 分诊 / 门D 裁定单与 NVD 对照
    _redistill_truth_parse_20260913.*       任务1 对照（23 agree/4 qualified/5 disagree）
    _part2_parse_20260913.*                 任务3 对照（123 id/251 块）
    _caveat_scan_20260913.*                 问题字眼全量扫描（571 块三级分级）
    _wave2_preaudit_compare_20260913.*      预审统一比对（29 PASS/17 待处置）
    _formal_verify_20260913.json            任务4 verify（25 PASS/3 B_HOLE）
    wave2_preaudit_results_*.txt            任务2 产出（441/78/95 三族）
    wave2_formal_results_*.txt              任务4 产出（5 批）
    result_blocks.jsonl / _relabel / _adjudication / _quarantine / _weakness_driven_plan 等 9/11 台账
docs/出题流水线_差分对v2_20260911.md        六道门文档（§7 执行记录）

宿舍待办：1) 任务1 的 5 条 disagree 裁决（00147 优先）
         2) 修订过的 17 对重新预审（wave2_pairs 已更新，需重出 preaudit 包→ convert_kits_to_learner）
         3) B_HOLE 3 对 safe 侧修复（78-S-10 补认证门 / 95-11 沙箱 / 95-13 限指数）
         4) v2_18 合并：wave1 治理块 + 任务3 干净块 163 + wave2 A 侧 28，按字眼三级降档
"""

count = 0
with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    z.writestr("README_宿舍工作包.txt", MANIFEST)
    for base, names, prefix in PICKS:
        if names is None:  # 整目录
            for p in sorted(base.rglob("*")):
                if p.is_file():
                    arc = f"{prefix}/{p.relative_to(base).as_posix()}"
                    z.write(p, arc)
                    count += 1
        else:
            for name in names:
                p = base / name
                if not p.exists():
                    print("  [缺] ", p)
                    continue
                if p.is_dir():
                    for q in sorted(p.rglob("*")):
                        if q.is_file():
                            arc = f"{prefix}/{name}/{q.relative_to(p).as_posix()}"
                            z.write(q, arc)
                            count += 1
                else:
                    z.write(p, f"{prefix}/{name}")
                    count += 1

size = OUT.stat().st_size
print(f"打包完成: {OUT}")
print(f"文件数 {count} | 压缩后 {size/1024/1024:.1f} MB")
