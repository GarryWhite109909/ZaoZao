#!/usr/bin/env python3
"""rolling_dev 平衡 + 冻结（一次性脚本，2026-08-22）。

背景：dev 按哈希分池时恰逢首批候选以 CWE-1336 为主，导致 dev 构成偏科
（1336 占 27/50，15 个类别零覆盖）。本脚本在冻结前做一次跨池置换：
  - dev 保留各类少量代表，其余退回 train；
  - 从 train 按每类配额抽调补足 dev 至 50 条、覆盖全部 20 类；
  - 跨池移动的文件重命名到目标池编号段（两池编号独立会冲突），
    patch 文件同步改名并更新 manifest 字段；
  - 最后生成 frozen_lock.json（manifest 哈希 + 文件清单），dev 即冻结。

用法：python3 scripts/rebalance_rolling_dev.py [--apply]
  默认 dry-run 只打印计划；--apply 实际执行。
"""
import hashlib
import json
import re
import shutil
import sys
import time
from pathlib import Path

BASE = Path("/home/zane/文档/code/毕业设计/experiments/exp_06_finetune/corpus")
APPLY = "--apply" in sys.argv

train_m_path = BASE / "train_pool" / "manifest.json"
dev_m_path = BASE / "rolling_dev" / "manifest.json"
train_m = json.loads(train_m_path.read_text())
dev_m = json.loads(dev_m_path.read_text())
train, dev = train_m["samples"], dev_m["samples"]

# ---- 1. dev 保留配额：每类最多 3 条 ----
keep_quota = 3
by_cwe = {}
for s in dev:
    by_cwe.setdefault(s["expected_cwe"], []).append(s)
dev_keep, dev_return = [], []
for cwe, lst in sorted(by_cwe.items()):
    lst.sort(key=lambda x: x["file"])
    dev_keep.extend(lst[:keep_quota])
    dev_return.extend(lst[keep_quota:])

# ---- 2. 从 train 抽调：目标 dev 每类 ≥2 条，总 50 ----
dev_cwe_now = {}
for s in dev_keep:
    dev_cwe_now[s["expected_cwe"]] = dev_cwe_now.get(s["expected_cwe"], 0) + 1
target_per_cwe = 2
need = {}
all_cwes = sorted({s["expected_cwe"] for s in train} | set(dev_cwe_now))
for cwe in all_cwes:
    gap = target_per_cwe - dev_cwe_now.get(cwe, 0)
    if gap > 0:
        need[cwe] = gap

slots = len(dev_return)          # 需要补进 dev 的数量 = 退回 train 的数量
train_by_cwe = {}
for s in sorted(train, key=lambda x: x["file"]):
    train_by_cwe.setdefault(s["expected_cwe"], []).append(s)
dev_cves = {s["cve_id"] for s in dev}
donors = []
for cwe, gap in sorted(need.items()):
    pool = [s for s in train_by_cwe.get(cwe, []) if s["cve_id"] not in dev_cves]
    donors.extend(pool[:gap])
# 配额 2/类不足 38 时，从当前数量最少的类轮流补齐（保持均衡）
if len(donors) < slots:
    chosen = {id(s) for s in donors}
    while len(donors) < slots:
        counts = {}
        for s in dev_keep + donors:
            counts[s["expected_cwe"]] = counts.get(s["expected_cwe"], 0) + 1
        progressed = False
        for cwe in sorted(counts, key=lambda c: counts[c]):
            if len(donors) >= slots:
                break
            for s in train_by_cwe.get(cwe, []):
                if id(s) not in chosen and s["cve_id"] not in dev_cves \
                        and s not in dev_return:
                    donors.append(s)
                    chosen.add(id(s))
                    progressed = True
                    break
        if not progressed:
            break
donors = donors[:slots]

print(f"计划：dev 退回 {len(dev_return)} 条，从 train 抽调 {len(donors)} 条")
print(f"平衡后 dev CWE 预览：", end=" ")
preview = {}
for s in dev_keep:
    preview[s["expected_cwe"]] = preview.get(s["expected_cwe"], 0) + 1
for s in donors:
    preview[s["expected_cwe"]] = preview.get(s["expected_cwe"], 0) + 1
print(dict(sorted(preview.items())))
if not APPLY:
    print("\n(dry-run，加 --apply 执行)")
    sys.exit(0)

# ---- 3. 执行置换（重命名文件 + patch + manifest 字段）----
def next_index(samples):
    idxs = [int(m.group(1)) for s in samples
            if (m := re.match(r"corpus_(\d+)", s["file"]))]
    return (max(idxs) + 1) if idxs else 1

train_idx = next_index(train)
dev_idx = next_index(dev)

def move(sample, src_pool, dst_pool, new_idx):
    """跨池移动：源路径用 src_pool（当前所在池），目标重编号到 dst_pool 号段。"""
    old_name = sample["file"]
    ext = Path(old_name).suffix
    new_name = f"corpus_{new_idx:05d}{ext}"
    shutil.move(BASE / src_pool / old_name, BASE / dst_pool / new_name)
    if sample.get("patch_file"):
        old_p = BASE / sample["patch_file"]
        new_p = BASE / "patches" / f"corpus_{new_idx:05d}.patch"
        if old_p.exists():
            shutil.move(old_p, new_p)
        sample["patch_file"] = f"patches/{new_p.name}"
    sample["file"] = new_name
    sample["pool"] = dst_pool

for s in dev_return:
    move(s, "rolling_dev", "train_pool", train_idx)
    train.append(s)
    train_idx += 1
for s in donors:
    train.remove(s)
    move(s, "train_pool", "rolling_dev", dev_idx)
    dev.append(s)
    dev_idx += 1

dev_m["samples"] = dev
train_m["samples"] = train
train_m_path.write_text(json.dumps(train_m, ensure_ascii=False, indent=1))
dev_m_path.write_text(json.dumps(dev_m, ensure_ascii=False, indent=1))

# ---- 4. 冻结：lock 文件 ----
manifest_hash = hashlib.sha256(dev_m_path.read_bytes()).hexdigest()
files = sorted(f.name for f in (BASE / "rolling_dev").iterdir() if f.is_file())
lock = {
    "frozen_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    "pool": "rolling_dev",
    "n_samples": len(dev),
    "manifest_sha256": manifest_hash,
    "files": files,
    "discipline": "冻结后不得增删改；不参与训练/选型；仅发布前测量一次",
}
(BASE / "rolling_dev" / "frozen_lock.json").write_text(
    json.dumps(lock, ensure_ascii=False, indent=1))

print(f"\n完成：train {len(train)} | dev {len(dev)}（已冻结，lock 写入 frozen_lock.json）")
from collections import Counter
print("dev 最终 CWE:", dict(Counter(s["expected_cwe"] for s in dev).most_common()))
print("dev 语言:", dict(Counter(s["language"] for s in dev).most_common()))
