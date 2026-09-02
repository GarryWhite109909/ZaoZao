# -*- coding: utf-8 -*-
"""重打 rolling_dev 冻结锁(因 2026-09-02 官方口径改标 6 处后 manifest 已变)。
只更新 manifest_sha256 / frozen_at / n_samples,不重排样本、不动文件清单。
"""
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2] / "corpus"
DEV = BASE / "rolling_dev"
MANIFEST = DEV / "manifest.json"
LOCK = DEV / "frozen_lock.json"

# 备份旧锁
bak = LOCK.with_suffix(".json.bak_2026-09-02_officialfix")
if not bak.exists():
    shutil.copy(LOCK, bak)
    print(f"备份旧锁 -> {bak.name}")

old = json.loads(LOCK.read_text(encoding="utf-8"))
print(f"旧锁: frozen_at={old.get('frozen_at')} n_samples={old.get('n_samples')}")

m = json.loads(MANIFEST.read_text(encoding="utf-8"))
new_hash = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()

lock = {
    "frozen_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    "pool": "rolling_dev",
    "n_samples": len(m["samples"]),
    "manifest_sha256": new_hash,
    "files": sorted(f.name for f in DEV.iterdir() if f.is_file()),
    "discipline": "冻结后不得增删改；不参与训练/选型；仅发布前测量一次",
    "_relock_note": ("2026-09-02 按 MITRE v4.20 + NVD/GHSA 官方字段修正 6 处错标"
                     "(00001:89→94, 00002:89→95, 00003:1336→150, 00004:1336→639, "
                     "00005:1336→862, 00053:352→502),清单详见 manifest _changelog"),
}

LOCK.write_text(json.dumps(lock, ensure_ascii=False, indent=1), encoding="utf-8")
print(f"新锁: frozen_at={lock['frozen_at']} n_samples={lock['n_samples']}")
print(f"manifest_sha256: {old.get('manifest_sha256')[:16]}... -> {new_hash[:16]}...")
# 校验
chk = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
print("校验:", "OK" if chk == json.loads(LOCK.read_text(encoding='utf-8'))["manifest_sha256"] else "失配!")
