# -*- coding: utf-8 -*-
"""wave2_g21_24 蒸馏进度总账。

不看 stdout(runner 的进度行被 workbuddy 会话收走),改从磁盘还原:
success.jsonl / rejects.jsonl 每条完成即 flush,以此对 kit 清单算覆盖。

用法:
  python scripts/check_distill_progress.py            # 总账 + 各输出目录活性
  python scripts/check_distill_progress.py --pending  # 只列还没有 success 的 orig
"""
import argparse
import glob
import io
import json
import time
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
WAVE = BASE / "corpus/repair_wave/wave2_g21_24"
OUT_ROOT = BASE / "corpus/repair_wave"


def jsonl_ids(p):
    out = []
    if not p.exists():
        return out
    for l in io.open(p, encoding="utf-8"):
        if l.strip():
            try:
                o = json.loads(l)
                # rejects 的 orig 在顶层,success 的在 fix_distill.orig
                i = o.get("orig")
                if i is None:
                    i = (o.get("fix_distill") or {}).get("orig")
                if i is not None:
                    out.append(str(i))
            except Exception:
                pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pending", action="store_true", help="只列缺 success 的 orig")
    args = ap.parse_args()

    kits = {}
    for kf in sorted(WAVE.rglob("*.jsonl")):
        rel = kf.relative_to(WAVE).as_posix()
        for i in jsonl_ids(kf):
            if i not in kits.setdefault(rel, []):
                kits[rel].append(i)

    universe, kit_of = [], {}
    for rel, ids in kits.items():
        for i in ids:
            if i not in kit_of:
                universe.append(i)
                kit_of[i] = rel

    success, reject = {}, {}
    for d in sorted(glob.glob(str(OUT_ROOT / "_wave1_out*"))) + [str(OUT_ROOT / "_smoke_g21")]:
        d = Path(d)
        if not d.is_dir():
            continue
        for i in jsonl_ids(d / "success.jsonl"):
            success.setdefault(i, []).append(d.name)
        for i in jsonl_ids(d / "rejects.jsonl"):
            reject.setdefault(i, []).append(d.name)

    pending = [i for i in universe if i not in success]

    if args.pending:
        for i in pending:
            print(i, kit_of[i], "reject@%s" % ",".join(reject[i]) if i in reject else "")
        return

    print(f"kit 文件 {len(kits)} 个 | 全宇宙 unique orig {len(universe)} 条")
    print(f"已有 success(跨目录并集): {len(success)} | 缺口 {len(pending)} 条")
    if pending:
        print("--- 缺口清单 ---")
        for i in pending:
            tag = " (曾拒: %s)" % ",".join(reject[i]) if i in reject else ""
            print(f"  {i}  [{kit_of[i]}]{tag}")

    print("--- 各输出目录 ---")
    rows = []
    for d in sorted(glob.glob(str(OUT_ROOT / "_wave1_out*"))) + [str(OUT_ROOT / "_smoke_g21")]:
        d = Path(d)
        if not d.is_dir():
            continue
        s, r = d / "success.jsonl", d / "rejects.jsonl"
        ns, nr = len(jsonl_ids(s)), len(jsonl_ids(r))
        latest = max([s, r], key=lambda p: p.stat().st_mtime if p.exists() else 0)
        age = time.time() - latest.stat().st_mtime if latest.exists() else -1
        rows.append((age, d.name, ns, nr))
    for age, name, ns, nr in sorted(rows):
        act = "活跃" if 0 <= age < 600 else ("静止" if age < 3600 * 6 else "久置")
        print(f"  {name:24s} success {ns:3d}  reject {nr:2d}  最近写盘 {age/60:6.1f} 分钟前 [{act}]")


if __name__ == "__main__":
    main()
