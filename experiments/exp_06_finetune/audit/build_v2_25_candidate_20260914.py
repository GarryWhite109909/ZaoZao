# -*- coding: utf-8 -*-
"""v2_25 候选构建：v2_24 + g27 真 CWE-77 16 条（2026-09-14）

预期：N 10024 → 10040；CWE-77 9 → 25；77:78 = 0.0176 → 0.0488
"""
import sys, os, json, re, hashlib
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = Path(__file__).resolve().parents[3]
E = ROOT / "experiments/exp_06_finetune"
V24 = E / "data/final_train_chatml_alpha06_v2_24_candidate_20260914.jsonl"
G27 = E / "corpus/repair_wave/g27_command_language.jsonl"
OUT = E / "data/final_train_chatml_alpha06_v2_25_candidate_20260914.jsonl"
CHANGELOG = E / "audit/v2_25_candidate_changelog_20260914.jsonl"

DRY = "--apply" not in sys.argv
log = []


def P(s):
    print(s)
    log.append(s)


def sha(r):
    return hashlib.sha256(json.dumps(r, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


v24 = [json.loads(l) for l in V24.open(encoding="utf-8") if l.strip()]
g27 = [json.loads(l) for l in G27.open(encoding="utf-8") if l.strip()]
P(f"v2_24 = {len(v24)} 行 | g27 新增 = {len(g27)} 条")

new_rows = []
for k, g in enumerate(g27):
    rec = {"messages": g["messages"], "src_row": len(v24) + k}
    new_rows.append(rec)

out_rows = v24 + new_rows


def asst(r):
    return r["messages"][2]["content"]


def user(r):
    return r["messages"][1]["content"]


def cwe(r):
    m = re.findall(r'"vulnerability_type"\s*:\s*"CWE-(\d+)(?!\d)', asst(r))
    return m[-1] if m else None


print("\n门禁")
# G1 键集唯一
ks = set(tuple(sorted(r.keys())) for r in out_rows)
assert ks == {("messages", "src_row")}, ks
P(f"G1 键集全库唯一 = {ks} ✅")

# G2 v2_24 既有行原样
same = all(sha(v24[i]) == sha(out_rows[i]) for i in range(len(v24)))
assert same
P(f"G2 v2_24 既有 {len(v24)} 行逐行 sha 未变 ✅")

# G3 新增 16 行契约
CANON = ["has_vulnerability", "vulnerability_type", "risk_level", "source", "sink",
         "explanation", "fix_suggestion"]
bad = []
for r in new_rows:
    a = asst(r)
    m = re.findall(r"```json\s*(\{.*?\})\s*```", a, re.S)
    o = json.loads(m[-1]) if m else None
    if not o or any(c not in o for c in CANON):
        bad.append(r["src_row"])
    if "is_confirmed" in a or "is_confirmed" in user(r):
        bad.append(f"{r['src_row']}:is_confirmed")
assert not bad, bad
P(f"G3 新增 {len(new_rows)} 行 7 字段完整、无 is_confirmed ✅")

# G4 靶点计数
import collections
cnt = collections.Counter(cwe(r) for r in out_rows)
P(f"G4 CWE-77 = {cnt.get('77')}（9 → {cnt.get('77')}，+{cnt.get('77',0)-9}） | "
  f"CWE-78 = {cnt.get('78')} | 77:78 = {cnt.get('77',0)/cnt.get('78',1):.4f}")
P(f"    N = {len(out_rows)} | system 种类 = {len(set(r['messages'][0]['content'] for r in out_rows))}")

pos = sum(1 for r in out_rows if '"has_vulnerability": true' in asst(r))
P(f"    正样本(粗计) = {pos}")

# 新增 16 行的 user 与出题包一致
kit_map = {json.loads(l)["orig"]: json.loads(l) for l in
           (E / "corpus/repair_wave/wave2_g27/g27_kits.jsonl").open(encoding="utf-8") if l.strip()}
mism = [r["fix_distill"]["orig"] for r in g27
        if r["messages"][1]["content"] != kit_map[r["fix_distill"]["orig"]]["user"]]
assert not mism, mism
P(f"G5 新增行 user 与出题包逐字一致 ✅（{len(g27)} 条）")

if DRY:
    P("\n[DRY-RUN] 未写盘。加 --apply 落库。")
else:
    with OUT.open("w", encoding="utf-8", newline="\n") as f:
        for r in out_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with CHANGELOG.open("w", encoding="utf-8", newline="\n") as f:
        for r, g in zip(new_rows, g27):
            f.write(json.dumps({
                "date": "2026-09-14", "step": "v2_25_g27_cwe77",
                "action": "APPEND", "v2_25_src_row": r["src_row"],
                "orig": g["fix_distill"]["orig"],
                "source_pack": "repair_wave/g27_command_language",
                "note": "真 CWE-77 首批 16 条（8 形态），教师产出过 V-1~V-6 全绿",
            }, ensure_ascii=False) + "\n")
    h = hashlib.sha256(OUT.read_bytes()).hexdigest()
    P(f"\n已写 {OUT.name}  {len(out_rows)} 行")
    P(f"sha256 = {h}")
    P(f"v2_24 sha256 = {hashlib.sha256(V24.read_bytes()).hexdigest()}")

(E / "audit/v2_25_candidate_构建报告_20260914.md").write_text(
    "# v2_25 候选构建报告（g27 真 CWE-77 并入）\n\n```\n" + "\n".join(log) + "\n```\n",
    encoding="utf-8")
