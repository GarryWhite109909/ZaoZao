# -*- coding: utf-8 -*-
"""v2_24 候选构建：恢复 T 族（工具告警裁决）24 条并修掉契约互斥（2026-09-14）

背景
----
`data/supplement_alpha05_triage.jsonl` 24 条是项目史上唯一的「工具告警裁决（T 族）」载体。
它们存活 v2_1 → v2_16，在 v2_17 被 `audit/purge_queue_v2_17_20260909.jsonl` 的
`P_契约模板泄漏`(24 条, disposition=PURGE, 行 7670–7693) 整批删除。

删除原因（队列原文）
    "用户代码字段是蒸馏契约模板而非代码（teacher 对模板幻觉出判定）"

真实成因（本次定位）
    `audit/repair_v2_13.py` L101–L149（步骤1 P0-3）把 assistant 的结论从
    `is_confirmed` 契约转写为 `has_vulnerability` 7 字段（**方向正确**——见
    `graduation_project/prompts.py` L874–878：α0.5 权重内化的是 has_vulnerability，
    is_confirmed 是训练从未见过的格式，是 triage 自一致漂移/recall 0.676 的根因），
    但 **user 消息尾部的 `is_confirmed` 输出模板没有被同步改写**，
    造成 **user 要 is_confirmed / assistant 答 has_vulnerability** 的契约互斥，
    随后被契约一致性扫描判为"用户字段是契约模板"整体删除。

本脚本动作（最小外科手术，只改契约，不动其余）
    A. user: 判定要求段内的 `is_confirmed` → `has_vulnerability`（2 处/条）
    B. user: 尾部 JSON 模板换成部署侧现行 `_TRIAGE_ALIGNED_SCHEMA`（import 自
       graduation_project.prompts，保证与部署一致）
    C. assistant: 行 7685 的 CWE-330 → CWE-338（对齐 BASE_PROMPT 明确口径：
       "可预测随机数（时间种子/math.rand）生成令牌、密钥等安全值 = CWE-338"）
    D. 原样保留：抬头、来源可信度分级标注（sast/位置型 防锚定设计）、工具字段、
       代码切片、判定要求其余条目、assistant 正文与 7 字段

不改的东西
    - 不动 v2_23 的既有 10000 行（逐行 sha 校验）
    - 不改 system prompt（已是全库统一 BASE_PROMPT）
    - 不新增 JSON 键（保持 {messages, src_row} 全库唯一）；溯源另存 sidecar
"""
import sys, os, json, re, hashlib
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve()
ROOT = HERE.parents[3]                     # Graduation-Project
EXP = ROOT / "experiments/exp_06_finetune"
sys.path.insert(0, str(ROOT))
from graduation_project.prompts import _TRIAGE_ALIGNED_SCHEMA  # noqa: E402

V16 = EXP / "data/final_train_chatml_alpha06_v2_16.jsonl"
V23 = EXP / "data/final_train_chatml_alpha06_v2_23_candidate_20260914.jsonl"
OUT = EXP / "data/final_train_chatml_alpha06_v2_24_candidate_20260914.jsonl"
CHANGELOG = EXP / "audit/v2_24_candidate_changelog_20260914.jsonl"
REPORT = EXP / "audit/v2_24_candidate_构建报告_20260914.md"
SIDECAR = EXP / "audit/v2_24_T族溯源_20260914.json"

TRI_START, TRI_END = 7670, 7693           # 1-based 行号（含）
CANON = ["has_vulnerability", "vulnerability_type", "risk_level",
         "source", "sink", "explanation", "fix_suggestion"]
DRY = "--apply" not in sys.argv

log = []


def P(s):
    print(s)
    log.append(s)


def g(rec, role):
    for m in rec.get("messages", []):
        if m.get("role") == role:
            return m.get("content") or ""
    return ""


def last_json(text):
    m = re.findall(r"```json\s*(\{.*?\})\s*```", text, re.S)
    if not m:
        return None, None
    try:
        return m[-1], json.loads(m[-1])
    except Exception:
        return None, None


def rec_sha(rec):
    return hashlib.sha256(json.dumps(rec, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


# ---------------------------------------------------------------- 载入
v16 = [json.loads(l) for l in V16.open(encoding="utf-8") if l.strip()]
v23 = [json.loads(l) for l in V23.open(encoding="utf-8") if l.strip()]
P(f"v2_16 = {len(v16)} 行 | v2_23 = {len(v23)} 行")

tri_src = v16[TRI_START - 1:TRI_END]
assert len(tri_src) == 24, len(tri_src)

# ---------------------------------------------------------------- 转换
NEW_TAIL = ("请先给出简短分析过程，然后在回答最后输出如下 JSON：\n"
            "```json\n" + _TRIAGE_ALIGNED_SCHEMA.strip() + "\n```")

new_rows, sidecar = [], []
for k, rec in enumerate(tri_src):
    src_line = TRI_START + k
    u_old = g(rec, "user")
    a_old = g(rec, "assistant")
    changes = []

    # A. 判定要求段内的 is_confirmed → has_vulnerability
    head, sep, _tail = u_old.partition("请先给出简短分析过程")
    assert sep, f"行 {src_line}: 找不到尾部 schema 分隔串"
    n_is = head.count("is_confirmed")
    head = head.replace("is_confirmed", "has_vulnerability")
    if n_is:
        changes.append(f"user判定要求 is_confirmed→has_vulnerability ×{n_is}")

    # B. 尾部 schema 换为部署侧 aligned schema
    u_new = head + NEW_TAIL
    if "is_confirmed" in _tail:
        changes.append("user尾部schema is_confirmed模板→_TRIAGE_ALIGNED_SCHEMA")
    assert "is_confirmed" not in u_new, f"行 {src_line}: user 仍含 is_confirmed"

    # C. 口径修正：CWE-330 → CWE-338
    a_new = a_old
    if "CWE-330 " in a_new or '"CWE-330' in a_new:
        a_new = a_new.replace("CWE-330 Use of Insufficiently Random Values",
                              "CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)")
        a_new = a_new.replace('"CWE-330', '"CWE-338')
        changes.append("assistant CWE-330→CWE-338（对齐 BASE_PROMPT 口径）")

    rec_new = {"messages": [
        {"role": "system", "content": g(rec, "system")},
        {"role": "user", "content": u_new},
        {"role": "assistant", "content": a_new},
    ], "src_row": len(v23) + k}

    # 契约校验
    _, o = last_json(a_new)
    assert o is not None, f"行 {src_line}: assistant JSON 坏"
    miss = [c for c in CANON if c not in o]
    assert not miss, f"行 {src_line}: 缺字段 {miss}"

    new_rows.append(rec_new)
    sidecar.append({
        "v2_24_src_row": rec_new["src_row"],
        "v2_16_line": src_line,
        "v2_12_line": 8069 + k,
        "source": "data/supplement_alpha05_triage.jsonl",
        "rule_id": (re.search(r"- 规则:\s*(\S+)", u_new) or [None, None])[1],
        "has_vulnerability": o["has_vulnerability"],
        "vulnerability_type": o["vulnerability_type"],
        "changes": changes,
    })
    P(f"  行 {src_line} → src_row {rec_new['src_row']} | hv={o['has_vulnerability']} | "
      f"{o['vulnerability_type'][:38]} | {', '.join(changes)}")

out_rows = v23 + new_rows

# ---------------------------------------------------------------- 门禁
P("\n" + "=" * 78)
P("门禁校验")

# G1 全库 JSON 可解析 + 键集唯一
keysets = set()
for r in out_rows:
    keysets.add(tuple(sorted(r.keys())))
assert keysets == {("messages", "src_row")}, keysets
P(f"G1 键集全库唯一 = {keysets} ✅")

# G2 v2_23 原样（逐行 sha）
same = all(rec_sha(v23[i]) == rec_sha(out_rows[i]) for i in range(len(v23)))
assert same, "v2_23 既有行被改动"
P(f"G2 v2_23 既有 {len(v23)} 行逐行 sha 未变 ✅")

# G3 契约互斥清零
bad_u = sum(1 for r in out_rows if "is_confirmed" in g(r, "user"))
bad_a = sum(1 for r in out_rows if "is_confirmed" in g(r, "assistant"))
assert bad_u == 0 and bad_a == 0, (bad_u, bad_a)
P(f"G3 user/assistant 残留 is_confirmed = {bad_u}/{bad_a} ✅")

# G4 T 族（工具告警裁决）规模与契约
def tri_shaped(u):
    return ('- 污染源:' in u and '- 危险点:' in u and '- 传播链:' in u)


tf_old = [r for r in v23 if tri_shaped(g(r, "user"))]
tf_new = [r for r in new_rows if tri_shaped(g(r, "user"))]
assert len(tf_new) == 24, len(tf_new)
ok = 0
for r in tf_new:
    _, o = last_json(g(r, "assistant"))
    if o and all(c in o for c in CANON):
        ok += 1
assert ok == 24, ok
P(f"G4 T 族：v2_23 {len(tf_old)} 条 → v2_24 {len(tf_old) + len(tf_new)} 条"
  f"（+{len(tf_new)}，7 字段完整 {ok}/24）✅")


def tri_stats(rows):
    pos = neg = 0
    rules = set()
    for r in rows:
        _, o = last_json(g(r, "assistant"))
        if not o or "has_vulnerability" not in o:
            continue
        pos += 1 if o["has_vulnerability"] is True else 0
        neg += 1 if o["has_vulnerability"] is False else 0
        m = re.search(r"- 规则:\s*(\S+)", g(r, "user"))
        if m:
            rules.add(m.group(1))
    return pos, neg, len(rules)


p0, n0, r0 = tri_stats(tf_old)
p1, n1, r1 = tri_stats(tf_new)
P(f"    v2_23 T 族：正 {p0} / 负 {n0} / 规则种类 {r0}")
P(f"    新增 24 条：正 {p1} / 负 {n1} / 规则种类 {r1}")
P(f"    合计：正 {p0+p1} / 负 {n0+n1}")


# G5 正负构成
pos = sum(1 for r in out_rows if last_json(g(r, "assistant"))[1] and
          last_json(g(r, "assistant"))[1].get("has_vulnerability") is True)
neg = sum(1 for r in out_rows if last_json(g(r, "assistant"))[1] and
          last_json(g(r, "assistant"))[1].get("has_vulnerability") is False)
P(f"G5 总 N = {len(out_rows)} | 有洞 {pos} / 无洞 {neg}")
P(f"G6 system prompt 种类 = {len(set(g(r,'system') for r in out_rows))}（应为 1）")

# ---------------------------------------------------------------- 写盘
if DRY:
    P("\n[DRY-RUN] 未写盘。加 --apply 落库。")
else:
    with OUT.open("w", encoding="utf-8", newline="\n") as f:
        for r in out_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with CHANGELOG.open("w", encoding="utf-8", newline="\n") as f:
        for s in sidecar:
            for c in (s["changes"] or ["（无实质变更）"]):
                f.write(json.dumps({
                    "date": "2026-09-14", "step": "v2_24_T族恢复",
                    "action": "RESTORE_AND_FIX_CONTRACT",
                    "v2_24_src_row": s["v2_24_src_row"], "v2_16_line": s["v2_16_line"],
                    "source_pack": "supplement_alpha05_triage",
                    "note": c, "basis": "purge_queue_v2_17 P_契约模板泄漏 反查 + prompts.py L874-878",
                }, ensure_ascii=False) + "\n")
    SIDECAR.write_text(json.dumps(sidecar, ensure_ascii=False, indent=1), encoding="utf-8")
    sha = hashlib.sha256(OUT.read_bytes()).hexdigest()
    P(f"\n已写 {OUT.name}  {len(out_rows)} 行")
    P(f"sha256 = {sha}")
    P(f"v2_23 sha256 = {hashlib.sha256(V23.read_bytes()).hexdigest()}")

REPORT.write_text(
    "# v2_24 候选构建报告（T 族恢复 + 契约修复）\n\n"
    "> 动作：从 v2_16 行 7670–7693 取回 T 族 24 条，修掉 user/assistant 契约互斥后追加到 v2_23。\n\n"
    "```\n" + "\n".join(log) + "\n```\n", encoding="utf-8")
