# -*- coding: utf-8 -*-
"""FIX 队列 id→当前行 定位器（20260908）。

纪律（9/7 对账记录附8 教训：禁止 id±偏移心算）：
- 基线：result_id_map.json（map 快照 = 2026-09-02 19:45 的 10181 行版）；
- 删除事件全量重放（全部有 manifest/账目记录）：
  9/2 wave1 10 条 + missed10 11 条 + 9/7 batch_20_30 7261 + 9/7 R2 1724
  + 9/7 p81-86 7833/7834/7835 + 9/8 purge 68518 裁决对（按位置求解）
  + 9/8 L2 五删（今日行号 739/904/914/978/1093）；
- 输出今日 1-based 行号 + assistant 头部摘要，供逐条人工核对后编辑。
"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
MAP = BASE / "audit/result_id_map.json"
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
DEL1 = BASE / "audit/web_review/web_review_DELETE_manifest_20260902.json"
DEL2 = BASE / "audit/web_review/web_review_DELETE_manifest_20260902_missed10.json"
FIXQ = BASE / "audit/web_review_v3/账目与脚本/账目/fix_queue_20260907.jsonl"

MAP_ROWS = 10181          # map 快照时点行数


def load_deleted_map_lines():
    """返回 map-era（10181 行版）被删除的 1-based 行号集合。"""
    deleted = set()
    for p in (DEL1, DEL2):
        man = json.loads(p.read_text(encoding="utf-8"))
        items = man if isinstance(man, list) else man.get("deleted", man.get("items", []))
        for it in items:
            wid = it.get("id") if isinstance(it, dict) else it
            # 7271/7455 虽在 9/2 误删批次，但 9/7 batch_20_30 已恢复入库（对账记录 §一），排除
            if wid in (7271, 7455):
                continue
            v = mp.get(str(wid), {})
            if v.get("v15_line"):
                deleted.add(v["v15_line"])
            else:
                print(f"[warn] manifest id {wid} 不在 map")
    # batch_20_30: 7261 删（7271/7455 为恢复，非删除）
    for wid in (7261, 1724, 7833, 7834, 7835):
        v = mp.get(str(wid), {})
        if v.get("v15_line"):
            deleted.add(v["v15_line"])
        else:
            print(f"[warn] 记录删除 id {wid} 不在 map")
    return deleted


def solve_purge_lines(deleted):
    """purge 的 68518 对：pre-purge（10158 行版）1-based 7646/7664 → map-era 行号。"""
    out = set()
    base = [x for x in range(1, MAP_ROWS + 1) if x not in deleted]
    for pre in (7646, 7664):
        # map-era x 满足：rank(x) in base == pre
        lo, hi = 1, MAP_ROWS
        while lo <= hi:
            mid = (lo + hi) // 2
            rank = sum(1 for y in base if y <= mid)  # 慢但一次性
            if rank < pre:
                lo = mid + 1
            elif rank > pre:
                hi = mid - 1
            else:
                out.add(mid)
                break
        else:
            raise RuntimeError(f"purge 行 {pre} 无解")
    return out


mp = json.loads(MAP.read_text(encoding="utf-8"))
D = load_deleted_map_lines()
D |= solve_purge_lines(D)
print(f"map-era 已删行数（含 purge 对）: {len(D)}")

# 今日文件 = 上述幸存者 再删 L2 五行
surv = [x for x in range(1, MAP_ROWS + 1) if x not in D]      # 10156 行版顺序
L2_DELETED = {739, 904, 914, 978, 1093}                        # 10156 行版 1-based
pos_of = {}
for idx, v in enumerate(surv, 1):
    if idx in L2_DELETED:
        continue
    # 今日行号 = idx - (#L2 删除位 < idx)
    today = idx - sum(1 for d in L2_DELETED if d < idx)
    pos_of[v] = today

rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
print(f"今日行数: {len(rows)}")

q = [json.loads(l) for l in FIXQ.open(encoding="utf-8") if l.strip()]
for it in q:
    wid = it["id"]
    v = mp.get(str(wid), {}).get("v15_line")
    if not v:
        print(f"id={wid} [{it['priority']}] ✗ map 无记录")
        continue
    today = pos_of.get(v)
    if not today or today > len(rows):
        print(f"id={wid} [{it['priority']}] ✗ 定位失败 v15_line={v}")
        continue
    r = rows[today - 1]
    a = r["messages"][2]["content"]
    u = r["messages"][1]["content"]
    import re
    m = re.search(r'"vulnerability_type": "([^"]{0,46})', a)
    print(f"id={wid} [{it['priority']}] {it['class'][:12]:12s} v15={v} today={today} "
          f"kind={(r.get('meta') or {}).get('kind')} | code={u[:60].strip()[:50]!r}")
