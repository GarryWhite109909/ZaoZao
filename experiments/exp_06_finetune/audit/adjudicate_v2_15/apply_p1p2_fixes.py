# -*- coding: utf-8 -*-
"""P1 剩余 + P2 执行(来源: audit/官方口径测试集审查_CWE判别要点_20260902.md §五)

P1 剩余(exp04 manifest):
  typical_08_eval.py:            CWE-94 -> CWE-95   (eval() 一跳求值,统一 eval 口径为95)
  hard_cve_05_spring4shell.java: 915;94;79 -> 94;915;79 (top-1 对齐 NVD 官方 94)
P2(cve_fix 13 条手写样本):
  1. 代码首行 "Inspired by CVE-X (项目) - <漏洞类型>" -> "Pattern reference: CVE-X (模式参考,非该CVE官方归因)"
     —— 原措辞会让人以为标签来自 NVD,而 NVD 官方标签与此处不符(如 0010 标 89 但 NVD=295)
  2. manifest 增加 label_basis 字段: 手写样本=code, 真实 CVE 样本=nvd
幂等, 备份先行; 改代码文件后须重打冻结锁(由调用方执行)。
"""
import json
import re
import shutil
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

E6 = Path(__file__).resolve().parents[2]          # exp_06_finetune/
EXP = Path(__file__).resolve().parents[3]         # experiments/
E4_MANIFEST = EXP / "exp_04_hard_samples/samples/manifest.json"
CV_MANIFEST = E6 / "testset_cve_fix/manifest.json"
CV_EVAL = E6 / "testset_cve_fix/manifest_eval.json"
CV_DIR = E6 / "testset_cve_fix"
DATE = "2026-09-02"

# 手写样本(报告 §三:cve_fix_0009~0021 共 13 条)
HANDWRITTEN = {f"cve_fix_{i:04d}" for i in
               [9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]}


def backup(p):
    b = p.with_suffix(p.suffix + f".bak_{DATE}_p1p2")
    if not b.exists():
        shutil.copy(p, b)


# ---------------- P1 剩余 ----------------
def p1():
    d = json.loads(E4_MANIFEST.read_text(encoding="utf-8"))
    changed = []
    for s in d["samples"]:
        fn = s.get("file", "")
        old = str(s.get("expected_cwe", ""))
        if fn == "typical_08_eval.py":
            if old != "CWE-95":
                backup(E4_MANIFEST)
                s["expected_cwe"] = "CWE-95"
                s["_label_note"] = ("统一 eval 口径:sink 为 eval() 一跳求值 -> CWE-95"
                                    "(与 NVD 对 Xinference CVE 官方标 95 一致)")
                changed.append((fn, old, "CWE-95", "eval 一跳求值"))
        elif fn == "hard_cve_05_spring4shell.java":
            if old != "CWE-94; CWE-915; CWE-79":
                backup(E4_MANIFEST)
                s["expected_cwe"] = "CWE-94; CWE-915; CWE-79"
                s["_label_note"] = ("top-1 对齐 NVD 官方标签 CWE-94(CVE-2022-22965);"
                                    "915/79 保留为伴生")
                changed.append((fn, old, "CWE-94; CWE-915; CWE-79", "top-1 对齐 NVD"))
    if changed:
        d.setdefault("_changelog", []).append({
            "date": DATE,
            "action": "P1 口径统一:eval 归 95;Spring4Shell top-1 对齐 NVD 官方 94",
            "source": "audit/官方口径测试集审查_CWE判别要点_20260902.md §五 P1",
            "changes": [{"file": f, "from": o, "to": n, "why": w} for f, o, n, w in changed],
        })
        E4_MANIFEST.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
        for f, o, n, w in changed:
            print(f"  exp04 {f}: {o} -> {n}  ({w})")
    return len(changed)


# ---------------- P2 ----------------
INSPIRED = re.compile(r"^(//|#)\s*Inspired by CVE-\S+\s*\([^)]*\)\s*-\s*(.*)$", re.M)


def p2():
    # 1) 代码注释降级
    fixed_files = []
    for s in sorted(CV_DIR.glob("cve_fix_*")):
        if s.suffix not in {".py", ".java", ".js", ".php", ".go"}:
            continue
        stem = s.stem
        if stem not in HANDWRITTEN:
            continue
        txt = s.read_text(encoding="utf-8")
        if "Inspired by CVE-" not in txt:
            continue
        m = INSPIRED.search(txt)
        if not m:
            continue
        comment, desc = m.group(1), m.group(2).strip()
        cve = re.search(r"CVE-\S+", m.group(0)).group(0)
        new_line = (f"{comment} Pattern reference: {cve}"
                    f" —— 模式参考(非该 CVE 的官方归因;标签基于代码形态)。原形态:{desc}")
        backup(s)
        new_txt = txt[:m.start()] + new_line + txt[m.end():]
        s.write_text(new_txt, encoding="utf-8")
        fixed_files.append(stem)
        print(f"  {s.name}: 注释降级 -> Pattern reference: {cve}")

    # 2) manifest 加 label_basis
    for mf in (CV_MANIFEST, CV_EVAL):
        if not mf.exists():
            continue
        d = json.loads(mf.read_text(encoding="utf-8"))
        touched = []
        for s in d["samples"]:
            fn = s.get("file", "")
            stem = Path(fn).stem
            basis = "code" if stem in HANDWRITTEN else "nvd"
            if s.get("label_basis") != basis:
                backup(mf)
                s["label_basis"] = basis
                touched.append((stem, basis))
        if touched:
            d.setdefault("_changelog", []).append({
                "date": DATE,
                "action": ("P2 标签依据标注:手写样本 label_basis=code(13条,代码形态即标签,"
                           "CVE 仅作模式参考),真实 CVE 样本=nvd;代码注释由 'Inspired by CVE-X - 类型' "
                           "降级为 'Pattern reference: CVE-X(模式参考,非官方归因)'"),
                "source": "audit/官方口径测试集审查_CWE判别要点_20260902.md §三/§五 P2",
                "changed_files": [f for f, _ in touched],
            })
            mf.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
            ncode = sum(1 for _, b in touched if b == "code")
            print(f"  {mf.name}: label_basis 标注 {len(touched)} 条(code={ncode})")
    return len(fixed_files)


def main():
    print("== P1 剩余 ==")
    n1 = p1()
    print()
    print("== P2 ==")
    n2 = p2()
    print()
    print(f"完成: P1 改标 {n1} 处 / P2 注释降级 {n2} 个文件")


if __name__ == "__main__":
    main()
