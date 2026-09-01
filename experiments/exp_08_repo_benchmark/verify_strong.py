#!/usr/bin/env python3
"""强判别样本可信度重验（2026-09-01，§9.29 触发）。

背景：corpus_00071.go 的漏洞侧与修复侧文件 diff 为空（完全相同），
但 patchpair_diff 报 v>0/f=0（STRONG）。证明差分管道存在非确定性
（semgrep 偶发失败被吞 / ts 状态污染）。本脚本对全部 STRONG 样本做：
  1) 文件对 sha 对比 —— 相同文件对的 STRONG 必为假阳性
  2) 差分重跑 ×3 —— 不稳定的 STRONG 不可信
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from patchpair_diff import build_ts, count_final  # noqa: E402

BASE = "/home/zane/文档/code/毕业设计/experiments/exp_06_finetune/corpus"


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()[:12]


def main():
    d = json.load(open(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "results", "patchpair_diff.train_pool.json")))
    # JSON 的 cls 是旧分类跑出来的；按原始值重算 STRONG（vuln>0 且 fixed=0）
    strong = [r for r in d["rows"]
              if r.get("vuln", -1) > 0 and r.get("fixed", -1) == 0]
    ts = build_ts()
    print(f"STRONG 样本 {len(strong)} 个，重验：")
    print(f"  {'样本':<24}{'sha相同?':<9}{'重跑v(3次)':<14}{'重跑f(3次)':<14}{'结论'}")
    real = fake = unstable = 0
    for r in strong:
        vf, lang = r["file"], r["lang"]
        stem, ext = os.path.splitext(vf)
        vp = os.path.join(BASE, "train_pool", vf)
        fp = os.path.join(BASE, "train_pool_fixed", f"{stem}_fixed{ext}")
        same = os.path.exists(vp) and os.path.exists(fp) and sha(vp) == sha(fp)
        vs, fs = [], []
        for _ in range(3):
            try:
                vs.append(count_final(ts, vp, lang, vf))
            except Exception:
                vs.append(-9)
            try:
                fs.append(count_final(ts, fp, lang, f"{stem}_fixed{ext}"))
            except Exception:
                fs.append(-9)
        if same:
            verdict = "✗✗ 假阳性（文件对相同）"
            fake += 1
        elif len(set(vs)) > 1 or len(set(fs)) > 1:
            verdict = "⚠ 非确定（重跑不稳）"
            unstable += 1
        elif all(v > 0 for v in vs) and all(f == 0 for f in fs):
            verdict = "✓ 真判别（稳定）"
            real += 1
        else:
            verdict = f"✗ 复测不成立({vs}/{fs})"
            fake += 1
        print(f"  {vf:<24}{str(same):<9}{str(vs):<14}{str(fs):<14}{verdict}")
    print(f"\n→ 真判别 {real} / 假阳性 {fake} / 非确定 {unstable}  (共 {len(strong)})")


if __name__ == "__main__":
    main()
