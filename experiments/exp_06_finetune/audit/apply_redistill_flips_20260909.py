# -*- coding: utf-8 -*-
"""
redistill 产物落库（2026-09-09）——用户已批准的三类替换

批次内容：
  PART1 三条翻案（证据齐一，用户拍板）：
    5119  False → True/CWE-416   basis=实测硬崩(0xC0000005) + 2v1仲裁 + glm5.3重投 三方互证
    7667  False → True/CWE-94    basis=retake 终裁（完整分析+行级归因+辨析锚句）
    7968  False → True/CWE-639   basis=retake 终裁（"非862/非306"锚句规范）
  PART2 1542/61 记录不改：重投判 safe 但实测有洞 → 执行 > 重投，维持现状，CWE 归属待口径终裁
  PART3 A档 36 条 CWE 重归类替换（has_vuln 不变、verify 干净）
  PART4 叙事升级：结论一致且 verify 零 flag 的行，assistant 整体换为 glm5.3 新分析
        （用户指示：旧叙事出自较弱 teacher，新叙事质量更高，结论相同也换）
  跳过：B 档（C6 缺锚句，待 teacher 补）· C 档其余（FLIP 无独立证据，不盲从重投，
        排入实测门 P0 队列以跑代想）· 代码定位不到的 6 条
纪律：备份先行 → 定位断言（旧行号+旧结论必须命中）→ 替换 → changelog → 自检
"""
import json, re, sys, shutil, hashlib, collections
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_16.jsonl"
BAK = BASE / "data/final_train_chatml_alpha06_v2_16.jsonl.bak_20260909_redistill_apply"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"
WAVE = BASE / "corpus/redistill_wave"

FLIPS = {  # line: (expect_old_hv, new_fields_source, basis)
    5119: (False, "glm5.3", "实测硬崩0xC0000005 + 2v1仲裁翻CWE-416 + glm5.3重投翻转，三证据齐一；label_basis=execution"),
    7667: (False, "retake", "retake 终裁：完整污点链+行级归因+辨析锚句（非95/非917/1336/非78）；label_basis=teacher_retake"),
    7968: (False, "retake", "retake 终裁：显式task_id绕过会话作用域绑定，锚句非862/非306规范；label_basis=teacher_retake"),
}
NOCHANGE = {1542: "重投判safe但实测注入实锤——执行>重投，维持True/CWE-798现状，CWE归属待口径终裁",
            61: "重投判safe但实测有实锤——执行>重投，维持True/CWE-416现状"}

parsed = {}
for fn in ("glm5.3.jsonl", "retake.jsonl", "qwen_flip.jsonl"):
    for l in (WAVE / "parsed" / fn).open(encoding="utf-8"):
        r = json.loads(l)
        parsed[(fn, r["id"])] = r["fields"]

flags = {}
for l in (WAVE / "verify_report.jsonl").open(encoding="utf-8"):
    r = json.loads(l)
    if r.get("line"):
        flags[int(r["line"])] = r.get("flags", [])


def code_of(u):
    fs = re.findall(r"```[A-Za-z]*\n(.*?)```", u, re.S)
    return hashlib.md5(max(fs, key=len).strip().encode("utf-8", "replace")).hexdigest() if fs else None


def verd(a):
    m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
    if not m:
        return None
    try:
        v = json.loads(m.group(1))
        hv = v.get("has_vulnerability")
        if isinstance(hv, str):
            hv = hv.strip().lower() == "true"
        c = re.search(r"CWE-(\d+)", str(v.get("vulnerability_type") or ""))
        return (hv, "CWE-" + c.group(1) if c else "")
    except Exception:
        return None


def build_assistant(fl):
    """parsed 8 字段 → 数据集 assistant 格式：分析叙事 + ```json 块```"""
    j = {k: fl[k] for k in ("has_vulnerability", "vulnerability_type", "risk_level",
                            "source", "sink", "explanation", "fix_suggestion")}
    if isinstance(j["has_vulnerability"], str):
        j["has_vulnerability"] = j["has_vulnerability"].strip().lower() == "true"
    for k, v in j.items():
        assert str(v).strip(), f"契约字段为空: {k}"
    return fl["分析过程"].strip() + "\n\n```json\n" + json.dumps(j, ensure_ascii=False) + "\n```\n"


rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
assist = lambda r: [m["content"] for m in r["messages"] if m["role"] == "assistant"][-1]
set_assist = lambda r, t: [m.__setitem__("content", t) for m in r["messages"] if m["role"] == "assistant"][-1]

log = []
changelog = []

# ---------- PART 1: 三条翻案 ----------
for ln, (old_hv, src, basis) in FLIPS.items():
    r = rows[ln - 1]
    v_old = verd(assist(r))
    assert v_old and v_old[0] == old_hv and not v_old[1], f"行{ln} 旧结论不符: {v_old}"
    fl = parsed.get((src + ".jsonl", f"redistill-line-{ln}"))
    assert fl, f"parsed 里找不到 {src}/redistill-line-{ln}"
    new_a = build_assistant(fl)
    v_new = verd(new_a)
    assert v_new and v_new[0] is True, f"行{ln} 新结论异常: {v_new}"
    set_assist(r, new_a)
    log.append((ln, v_old, v_new))
    changelog.append({"date": "2026-09-09", "step": "2.1_redistill_flip_apply", "action": "FIX",
                      "row_line_before": ln, "old_verdict": list(v_old), "new_verdict": list(v_new),
                      "note": f"{v_old[0]}/{v_old[1] or 'none'} → {v_new[0]}/{v_new[1]} 翻案落库",
                      "basis": basis, "label_basis": "execution" if ln == 5119 else "teacher_retake"})

# ---------- PART 2: 1542/61 不改，仅留痕 ----------
for ln, note in NOCHANGE.items():
    changelog.append({"date": "2026-09-09", "step": "2.2_execution_override_nochange", "action": "KEEP",
                      "row_line_before": ln, "note": note,
                      "basis": "实测证据与重投冲突：执行 > 模型重投", "label_basis": "execution"})

# ---------- PART 3/4: merged_stage 的 A 档替换 + 叙事升级 ----------
idx16 = {}
for i, r in enumerate(rows, 1):
    h = code_of([m["content"] for m in r["messages"] if m["role"] == "user"][0])
    if h:
        idx16[h] = i
stat = collections.Counter()
for l in (WAVE / "merged_stage.jsonl").open(encoding="utf-8"):
    r = json.loads(l)
    u = [m["content"] for m in r["messages"] if m["role"] == "user"][0]
    ln = idx16.get(code_of(u))
    if not ln:
        stat["跳过_代码定位不到"] += 1
        continue
    if ln in NOCHANGE or ln in FLIPS:
        stat["跳过_单列处理"] += 1
        continue
    fl = flags.get(ln, [])
    if any(("C6" in x) or ("FLIP" in x) for x in fl):
        stat["跳过_B档C6或FLIP"] += 1
        continue
    new_a = assist(r)
    v_new = verd(new_a)
    if not v_new:
        stat["跳过_新内容无JSON"] += 1
        continue
    old_a = assist(rows[ln - 1])
    v_old = verd(old_a)
    if v_old == v_new:
        if old_a.strip() == new_a.strip():
            stat["叙事已相同"] += 1
            continue
        set_assist(rows[ln - 1], new_a)
        stat["PART4_叙事升级"] += 1
        changelog.append({"date": "2026-09-09", "step": "2.4_narrative_upgrade", "action": "FIX",
                          "row_line_before": ln, "note": "结论不变，assistant 叙事升级为 glm5.3 重蒸馏版",
                          "basis": "teacher 升级（弱teacher→glm5.3），verify 零 flag", "label_basis": "teacher_retake"})
    else:
        if v_old[0] != v_new[0]:
            stat["跳过_has_vuln翻转未批准"] += 1
            continue
        set_assist(rows[ln - 1], new_a)
        stat["PART3_A档CWE重归类"] += 1
        changelog.append({"date": "2026-09-09", "step": "2.3_cwe_reclass_apply", "action": "FIX",
                          "row_line_before": ln, "old_verdict": list(v_old), "new_verdict": list(v_new),
                          "note": f"{v_old[1]} → {v_new[1]} CWE 重归类（has_vuln 不变），verify 干净",
                          "basis": "glm5.3 重蒸馏 + verify 零 flag", "label_basis": "teacher_retake"})

# ---------- 写盘 ----------
shutil.copyfile(DATA, BAK)
with DATA.open("w", encoding="utf-8", newline="\n") as f:
    for row in rows:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
with CHANGELOG.open("a", encoding="utf-8") as f:
    for c in changelog:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")

# ---------- 自检 ----------
rows2 = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
assert len(rows2) == len(rows), "行数变化！"
for ln, v_old, v_new in log:
    v2 = verd(assist(rows2[ln - 1]))
    assert v2 == v_new, f"自检失败 行{ln}: {v2} != {v_new}"
n_diff = sum(1 for a, b in zip(rows, rows2) if assist(a) != assist(b))
print(f"备份: {BAK.name}")
print(f"翻案: {[(ln, f'{v[1]}→{w[1]}') for ln, v, w in log]}")
print("统计:", dict(stat))
print(f"changelog 追加 {len(changelog)} 条；实测 assistant 内容变化 {n_diff} 行；自检 PASS")
