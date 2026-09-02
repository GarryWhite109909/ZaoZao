# -*- coding: utf-8 -*-
"""基于 web_review result.txt 的 DELETE verdict,从 v2_15 删除确认有问题的样本。

- 定位来源: audit/result_id_map.json (result.txt id -> v2_15 1-based v15_line)
- 待删: DELETE verdict 且 v15_line 可定位的样本(no_match 的 7808 本就不在库,跳过)
- 安全: 备份先行;按行号从大到小删防偏移;产出 changelog manifest;删除后自检
"""
import json, re, shutil, sys, time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]   # exp_06_finetune/
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
MAP = BASE / "audit/result_id_map.json"
RESULT = BASE / "audit/web_review/result.txt"
BAK = DATA.with_suffix(DATA.suffix + ".bak_wr_delete_20260902")
OUT_LOGDIR = BASE / "audit/web_review"
DATE = "2026-09-02"

# 1) 收集 result.txt DELETE verdict + 理由
reason = {}
for l in RESULT.open(encoding="utf-8"):
    l = l.strip()
    if not l.startswith("{"):
        continue
    try:
        o = json.loads(l)
    except Exception:
        continue
    if o.get("verdict") == "DELETE" and isinstance(o.get("id"), int):
        reason[o["id"]] = {
            "note": o.get("note", ""),
            "tier": o.get("tier"),
            "audit_cwe": (o.get("independent") or {}).get("cwe", ""),
        }

mp = json.loads(MAP.read_text(encoding="utf-8"))
# 2) 定位可删的: id 在 map 且 v15_line 非 None
del_targets = []
for wid in sorted(reason):
    v = mp.get(str(wid))
    if v and v.get("v15_line"):
        del_targets.append((wid, v["v15_line"], reason[wid]))
    else:
        print(f"  跳过 id={wid}: {v}")

print(f"待删除样本: {len(del_targets)} 个")
lines = DATA.read_text(encoding="utf-8").split("\n")
n_before = sum(1 for l in lines if l.strip())
print(f"删除前 v2_15: {n_before} 条")

# 3) 备份
if not BAK.exists():
    shutil.copy(DATA, BAK)
    print(f"已备份 -> {BAK.name}")
else:
    print("备份已存在")

# 4) 校验每个待删行确实是目标(抽查: 行内容非空 + 记录 id)
#    不做内容强匹配(不同样本内容不同), 但记录删除前该行 JSON 的 teacher/来源
deleted_log = []
remove_lines = set()
for wid, vline, rr in del_targets:
    idx = vline - 1
    if idx >= len(lines) or not lines[idx].strip():
        print(f"  !! id={wid} 行{idx} 为空/越界, 跳过")
        continue
    try:
        rec = json.loads(lines[idx])
    except Exception as e:
        print(f"  !! id={wid} 行{idx} JSON 解析失败, 跳过: {e}")
        continue
    fd = rec.get("fix_distill") or {}
    remove_lines.add(idx)
    deleted_log.append({
        "id": wid, "v15_line": vline, "reason": rr["note"][:120],
        "tier": rr["tier"], "audit_cwe": rr["audit_cwe"],
        "orig_at_line": str(fd.get("orig", "")),
        "source_pack": str(fd.get("source_pack", "-")),
    })

print(f"实际删除行: {len(remove_lines)} 个")

# 5) 从大到小删(防行号偏移) — 用 set 过滤重写
remove_lines_sorted = sorted(remove_lines, reverse=True)
for idx in remove_lines_sorted:
    lines[idx] = ""   # 置空, 末尾统一清理
# 统一去除空行(保留原空行结构可能改变, 但 jsonl 空行无意义)
new_lines = [l for l in lines if l.strip()]
DATA.write_text("\n".join(new_lines), encoding="utf-8")
n_after = sum(1 for l in new_lines if l.strip())
print(f"删除后 v2_15: {n_after} 条 (应删 {n_before - n_after})")

# 6) changelog manifest
manifest = {
    "date": DATE,
    "action": "web_review result.txt DELETE verdict 应用: 删除审计确认有严重问题(假阳性/假阴性/safe失真/不可用)的样本",
    "source": "audit/web_review/result.txt + audit/result_id_map.json",
    "n_deleted": n_before - n_after,
    "deleted": deleted_log,
}
mpath = OUT_LOGDIR / "web_review_DELETE_manifest_20260902.json"
mpath.write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
print(f"manifest 写入: {mpath.name}")
for d in deleted_log:
    print(f"  删 id={d['id']} (行{d['v15_line']}) [{d['audit_cwe'] or '?'}] tier={d['tier']}")
