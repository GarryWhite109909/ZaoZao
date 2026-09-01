#!/usr/bin/env python3
"""补丁对差分判别度量（与 CWE 标签无关的工具层召回度量）。

对每对「漏洞侧 / 修复侧」同名文件，比较 Stage 1 最终候选数：
    漏洞侧有候选、修复侧无 → 真判别（真命中该 CVE）
    两侧候选数相同         → 与补丁无关的版本无关噪声
    两侧均无候选           → 漏洞侧零召回，无从判别
    修复侧有、漏洞侧无     → 反向，纯误报

口径与 audit_stage1.py 完全一致（复用 collect_raw_candidates），
不另行实现扫描逻辑，保证与既有报告可横向对比。

用法：
    python patchpair_diff.py <vuln_dir> <fixed_dir> <manifest> [--fixed-pattern *_fixed] [--limit N]
"""
import argparse
import json
import os
import re
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from audit_stage1 import collect_raw_candidates  # noqa: E402

EXT_LANG = {
    ".py": "python", ".js": "javascript", ".ts": "javascript",
    ".go": "go", ".php": "php", ".java": "java",
}


def build_ts():
    """复刻 audit_stage1.py 主流程的 TwoStageScanner 构造（441-458 行）。

    Stage 1 纯工具，__new__ 绕过 __init__（不接 LLM client）；§五之四 留痕
    字段必须补齐，否则命中"无主告警剔除/抑制池跳过"的文件会 AttributeError
    导致整批中断。
    """
    from graduation_project.two_stage_scanner import TwoStageScanner
    from graduation_project.external_scanner import ExternalScanner
    from graduation_project.prefilter import Prefilter
    ts = TwoStageScanner.__new__(TwoStageScanner)
    ts.use_semgrep = True
    ts.use_external = True
    ts.use_taint_tracker = True
    ts._external = ExternalScanner()
    ts._taint_tracker = None
    ts.n_samples = 3
    ts._signal_registry = None
    ts._last_suppressed = False
    ts._last_suppressed_rules = []
    ts._dropped_unowned_rules = []
    ts._prefilter = Prefilter()
    return ts


def count_final(ts, path: str, lang: str, fname: str) -> int:
    """返回 Stage 1 最终候选数（与 audit_stage1 口径一致）。

    collect_raw_candidates(ts, code, lang, fname) -> (raw, after_drop, final)
    """
    code = open(path, encoding="utf-8", errors="replace").read()
    raw, after, final = collect_raw_candidates(ts, code, lang, fname)
    return len(final)


def fixed_name(vuln_file: str, naming: str) -> str:
    """修复侧文件名。

    naming=suffix（默认，train_pool_fixed）: corpus_00003.js -> corpus_00003_fixed.js
    naming=same（rolling_dev_safe）        : corpus_00003.js -> corpus_00003.js
    """
    if naming == "same":
        return vuln_file
    stem, ext = os.path.splitext(vuln_file)
    return f"{stem}_fixed{ext}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("vuln_dir")
    ap.add_argument("fixed_dir")
    ap.add_argument("manifest")
    ap.add_argument("--limit", type=int, default=0, help="只处理前 N 个（调试用）")
    ap.add_argument("--naming", choices=["suffix", "same"], default="suffix",
                    help="修复侧命名：suffix=加 _fixed；same=同名不同目录")
    ap.add_argument("--out", default="", help="结果 JSON 落盘路径")
    args = ap.parse_args()

    samples = json.load(open(args.manifest, encoding="utf-8"))["samples"]
    if args.limit:
        samples = samples[: args.limit]

    ts = build_ts()
    rows = []
    t0 = time.time()
    for i, s in enumerate(samples, 1):
        vf = s["file"]
        lang = (s.get("language") or "").lower()
        if not lang:
            lang = EXT_LANG.get(os.path.splitext(vf)[1].lower(), "")
        if not lang:
            continue
        ff = fixed_name(vf, args.naming)
        vpath = os.path.join(args.vuln_dir, vf)
        fpath = os.path.join(args.fixed_dir, ff)
        if not (os.path.exists(vpath) and os.path.exists(fpath)):
            continue
        cwe = (s.get("expected_cwe") or "").replace("CWE-", "")
        try:
            vn = count_final(ts, vpath, lang, vf)
        except Exception as e:
            vn = -1
            print(f"  ! {vf} vuln ERR {type(e).__name__}: {e}", file=sys.stderr)
        try:
            fn = count_final(ts, fpath, lang, ff)
        except Exception as e:
            fn = -1
            print(f"  ! {ff} fixed ERR {type(e).__name__}: {e}", file=sys.stderr)

        # 分类（2026-09-01 修正）：原实现把 v>f 与 f>v 一并归入 partial，
        # 导致"修复侧候选反而更多"的反向样本被误计为真判别（train_pool 实测
        # 虚高 4 个：6% → 4.8%）。此处严格按方向拆分：
        #   STRONG   v>0 且 f=0  修复侧清零，最强判别
        #   WEAK     v>f>0       漏洞侧多于修复侧（弱判别，可能是噪声抖动）
        #   REVERSE  f>v>0       修复侧候选更多 —— 反向，绝不可计入判别
        if vn == 0 and fn == 0:
            cls = "both_zero"      # 漏洞侧零召回
        elif vn > 0 and fn == 0:
            cls = "STRONG"         # 强判别
        elif vn > fn > 0:
            cls = "WEAK"           # 弱判别
        elif vn == fn:
            cls = "same_count"     # 与补丁无关的噪声
        elif fn > vn > 0:
            cls = "REVERSE"        # 反向：修复侧候选更多
        else:
            cls = "reversed"       # 反向：修复侧有、漏洞侧无
        rows.append({"file": vf, "lang": lang, "cwe": cwe,
                     "vuln": vn, "fixed": fn, "cls": cls})
        if i % 25 == 0:
            el = time.time() - t0
            print(f"  ...{i}/{len(samples)} 用时{el:.0f}s 预计{el/i*len(samples):.0f}s",
                  file=sys.stderr, flush=True)

    # 汇总
    n = len(rows)
    c = Counter(r["cls"] for r in rows)
    by_lang = {}
    for lang in sorted({r["lang"] for r in rows}):
        sub = [r for r in rows if r["lang"] == lang]
        cl = Counter(r["cls"] for r in sub)
        by_lang[lang] = {
            "n": len(sub),
            "strong": cl["STRONG"],
            "rate_strict": cl["STRONG"] * 100 // max(len(sub), 1),
            "weak": cl["WEAK"], "reverse_gt": cl["REVERSE"],
            "same_count": cl["same_count"],
            "both_zero": cl["both_zero"], "reversed": cl["reversed"],
        }

    strong, weak = c["STRONG"], c["WEAK"]
    print(f"\n{'='*66}\n补丁对差分判别  n={n}\n{'='*66}")
    print(f"  强判别   漏洞侧有候选 / 修复侧清零   {strong:>4}")
    print(f"  弱判别   漏洞侧多于修复侧（>0）      {weak:>4}")
    print(f"  反向     修复侧候选更多（**不可计入判别**） {c['REVERSE']:>4}")
    print(f"  噪声     两侧候选数相同              {c['same_count']:>4}")
    print(f"  双零     两侧均无候选（漏洞侧零召回） {c['both_zero']:>4}")
    print(f"  反向     修复侧有 / 漏洞侧无（纯误报） {c['reversed']:>4}")
    print(f"  → 严格判别率（仅强）      {strong}/{n} = {strong*100/max(n,1):.1f}%")
    print(f"  → 宽松判别率（强+弱）     {strong+weak}/{n} = {(strong+weak)*100/max(n,1):.1f}%")
    has = strong + weak + c["same_count"] + c["REVERSE"]
    print(f"  → 漏洞侧有候选比例（含噪声） {has}/{n} = {has*100/max(n,1):.0f}%")
    print(f"\n按语言（严格 = 仅强判别）:")
    print(f"  {'语言':<12}{'n':>5}{'强':>5}{'率':>7}{'弱':>5}{'反向':>5}{'同数':>5}{'双零':>5}")
    for lang, d in sorted(by_lang.items(), key=lambda kv: -kv[1]["n"]):
        print(f"  {lang:<12}{d['n']:>5}{d['strong']:>5}{d['rate_strict']:>6}%"
              f"{d['weak']:>5}{d['reverse_gt']:>5}{d['same_count']:>5}{d['both_zero']:>5}")

    print(f"""
⚠️ 判别成功 ≠ 检测语义正确（2026-09-01 实测教训）：
差分只能证明"候选在修复后消失"，不能证明工具检测到了那个漏洞。
train_pool 实测 11 个强判别中仅 5 个语义正确（1.7%），另 6 个是蹭中或
类型错配——4 个 CWE-1336(SSTI) 全靠 bandit B701(autoescape→XSS) 蹭中：
修复把 Environment() 换成 SandboxedEnvironment() 后 B701 恰好不触发。
**报告判别率时必须抽样追查命中规则与推断类型，给出"语义正确率"。**""")

    if args.out:
        json.dump({"rows": rows, "summary": dict(c), "by_lang": by_lang},
                  open(args.out, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
        print(f"\n明细已写入 {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
