# -*- coding: utf-8 -*-
"""
C6 补锚落库 + v2_15 分歧端口（2026-09-09 晚，用户批准"补锚、实测都开始"）

PART A 端口分歧（4 行）：09-08 敷衍修复队列写的是 v2_15 且在 v2_16 构建（15:46）之后（16:03），
        导致 v2_16 缺 4 行修复 —— 其中 2108 是结论级（327→347 JWT alg=none）。
        以 v2_15 为准端口（changelog 有据）。
PART B C6 补锚落库（45 行）：
        - 锚句来源①：glm5.3 分析过程里已有的"非 <数字>"推理句 → 归一化为"非 CWE-XXX"
          （C6 机检要求分析过程含字面"非 CWE"，glm5.3 有推理但没按格式写）
        - 来源②：finalize 的近邻族模板兜底（修正原 89 模板的重复病句）
        - assistant 用 glm5.3 重蒸馏版整体替换（结论不变或 CWE 重归类；C6-only 不含 FLIP）
PART C 自检：45 行分析过程均含"非 CWE"；行数不变；JSON 契约完整
"""
import json, re, sys, shutil
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_16.jsonl"
V15 = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"
WAVE = BASE / "corpus/redistill_wave"

PORT_ROWS = {638: "敷衍修复全模板重写（锚按码重排）", 886: "敷衍修复锚漂移修正",
             1868: "敷衍修复补行锚+伪防御辨析+利用链", 2108: "敷衍修复改标 327→347（JWT alg=none，label_basis=audit）"}

ANCHORS = {
    "78": "非 CWE-77 因为注入目标是 OS shell 程序执行而非 sed/IMAP 等非 OS 命令语言；非 CWE-88 因为命令名并非固定、输入进入的是完整命令文本而非纯参数位。",
    "22": "非 CWE-73 因为输入被拼入固定目录前缀、核心危害是 .. 序列穿越出受限目录（22 比 73 更精确）；非 CWE-78 因为 sink 是文件/路径操作而非程序执行。",
    "1336": "非 CWE-94/95 因为不存在 eval/exec 求值或生成代码再执行，缺陷在模板引擎把输入当模板源码渲染；非 CWE-79 因为危害在模板语法位而非浏览器输出转义。",
    "89": "非 CWE-943 因为 sink 是 SQL 执行而非 MongoDB 操作符/HQL 等非 SQL 数据查询逻辑；非 CWE-94 因为不存在代码构造与求值。",
    "918": "非 CWE-441 因为请求并非借产品身份/回环信任绕过访问控制；非 CWE-601 因为不存在返回给浏览器的 Location 跳转，缺陷在服务端取回内容。",
    "327": "非 CWE-326 因为问题不是密钥长度不足而是协议/算法整体废弃或破碎；非 CWE-347 因为不涉及签名校验缺失。",
    "94": "非 CWE-95 因为输入不是直接进入 eval() 一跳求值，而是先拼入生成的代码文本再执行；非 CWE-78 因为执行的是代码而非 OS 命令。",
    "601": "非 CWE-918 因为危害是骗浏览器跳转（Location）而非服务端取回内容；非 CWE-441 因为不涉及代理/回环信任语义。",
}

rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
v15 = [json.loads(l) for l in V15.open(encoding="utf-8") if l.strip()]
ga = lambda r: [m["content"] for m in r["messages"] if m["role"] == "assistant"][-1]
sa = lambda r, t: [m.__setitem__("content", t) for m in r["messages"] if m["role"] == "assistant"][-1]


def verd(a):
    m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
    if not m:
        return None
    v = json.loads(m.group(1))
    hv = v.get("has_vulnerability")
    if isinstance(hv, str):
        hv = hv.strip().lower() == "true"
    c = re.search(r"CWE-(\d+)", str(v.get("vulnerability_type") or ""))
    return (hv, "CWE-" + c.group(1) if c else "")


changelog = []
stat = {}

# ---------- PART A 端口 4 行 ----------
for ln, note in PORT_ROWS.items():
    a15, a16 = ga(v15[ln - 1]), ga(rows[ln - 1])
    if a15 == a16:
        stat.setdefault("端口_已一致", []).append(ln)
        continue
    assert verd(a15) is not None, f"行{ln} v2_15 无 JSON"
    sa(rows[ln - 1], a15)
    stat.setdefault("端口_已应用", []).append(ln)
    changelog.append({"date": "2026-09-09", "step": "2.6_port_v2_15_divergence", "action": "FIX",
                      "row_line_before": ln, "old_verdict": list(verd(a16) or ("?", "")),
                      "new_verdict": list(verd(a15)),
                      "note": f"端口 09-08 敷衍修复（写入了 v2_15 但晚于 v2_16 构建未进 v2_16）：{note}",
                      "basis": "清洗changelog_v2_16_20260908 敷衍修复队列", "label_basis": "audit"})

# ---------- PART B C6 补锚 ----------
FLAGS = {}
for l in (WAVE / "verify_report.jsonl").open(encoding="utf-8"):
    r = json.loads(l)
    if r.get("line"):
        FLAGS[r["line"]] = r.get("flags", [])
pm = {}
for fn in ("glm5.3.jsonl", "qwen_flip.jsonl", "retake.jsonl"):
    for l in (WAVE / "parsed" / fn).open(encoding="utf-8"):
        o = json.loads(l)
        pm.setdefault(o["id"], {})["glm5.3"] = o["fields"] if fn == "glm5.3.jsonl" else pm.get(o["id"], {}).get("glm5.3")
        pm[o["id"]][fn.replace(".jsonl", "")] = o["fields"]

SENT = re.compile(r"[^。；\n]*非\s*(?:CWE-?)?\s*(\d{3})[^。；\n]*")


def mine_anchors(ana):
    out = []
    for m in SENT.finditer(ana):
        s = m.group(0).strip()
        s = re.sub(r"非\s*(?:CWE-?)?\s*(\d{3})", lambda x: f"非 CWE-{x.group(1)}", s)
        if len(s) > 12 and ("因为" in s or "而非" in s or "：" in s or ":" in s):
            out.append(s if s.endswith(("。", "；")) else s + "；")
    seen, dedup = set(), []
    for s in out:
        k = re.sub(r"\s", "", s)[:40]
        if k not in seen:
            seen.add(k)
            dedup.append(s)
    return dedup[:3]


for ln, fl in sorted(FLAGS.items()):
    if not (fl and all(f.startswith("C6") for f in fl)):
        continue
    fields = (pm.get(f"redistill-line-{ln}") or {}).get("glm5.3")
    assert fields, f"行{ln} 无 glm5.3 parsed 字段"
    vt = str(fields.get("vulnerability_type") or "")
    mc = re.match(r"CWE-(\d+)", vt)
    assert mc, f"行{ln} 无 CWE"
    fam = mc.group(1)
    anchors = mine_anchors(fields.get("分析过程", ""))
    if not anchors:
        assert fam in ANCHORS, f"行{ln} 族 {fam} 无兜底锚模板"
        anchors = [ANCHORS[fam]]
    anchor_text = " ".join(a.rstrip("；。") + "；" for a in anchors)
    ana = fields["分析过程"].strip()
    assert "非 CWE" in (ana + anchor_text) or "非CWE" in (ana + anchor_text), f"行{ln} 补锚后仍无'非 CWE'"
    j = {k: fields[k] for k in ("has_vulnerability", "vulnerability_type", "risk_level",
                                "source", "sink", "explanation", "fix_suggestion")}
    if isinstance(j["has_vulnerability"], str):
        j["has_vulnerability"] = j["has_vulnerability"].strip().lower() == "true"
    j["explanation"] = j["explanation"].rstrip("。；;") + "。" + anchor_text
    new_a = ana + "\n\n辨析补充：" + anchor_text + "\n\n```json\n" + json.dumps(j, ensure_ascii=False) + "\n```\n"
    cur = rows[ln - 1]
    v_old, v_new = verd(ga(cur)), verd(new_a)
    assert v_new and v_new[0] is not None, f"行{ln} 新结论解析失败"
    if v_old == v_new:
        stat["C6_叙事升级含锚"] = stat.get("C6_叙事升级含锚", 0) + 1
        step = "2.7_c6_anchor_narrative"
    else:
        assert v_old and v_new and v_old[0] == v_new[0], f"行{ln} C6 行出现 has_vuln 翻转（异常，跳过）"
        stat["C6_CWE重归类含锚"] = stat.get("C6_CWE重归类含锚", 0) + 1
        step = "2.7_c6_anchor_cwe_reclass"
    sa(cur, new_a)
    changelog.append({"date": "2026-09-09", "step": step, "action": "FIX", "row_line_before": ln,
                      "old_verdict": list(v_old) if v_old else None, "new_verdict": list(v_new),
                      "note": f"C6 补互斥锚句（族 {fam}，锚{' mined' if anchors and anchors[0] in (fields.get('分析过程') or '') else ' template'}）",
                      "basis": "glm5.3 重蒸馏 + verify C6 规则", "label_basis": "teacher_retake"})

# ---------- 写盘 + 自检 ----------
BAK = BASE / "data/final_train_chatml_alpha06_v2_16.jsonl.bak_20260909_c6_anchor"
shutil.copyfile(DATA, BAK)
with DATA.open("w", encoding="utf-8", newline="\n") as f:
    for row in rows:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
with CHANGELOG.open("a", encoding="utf-8") as f:
    for c in changelog:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")

rows2 = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
assert len(rows2) == len(rows)
remain = 0
for ln, fl in FLAGS.items():
    if fl and all(f.startswith("C6") for f in fl):
        if "非 CWE" not in ga(rows2[ln - 1]) and "非CWE" not in ga(rows2[ln - 1]):
            remain += 1
print(f"备份: {BAK.name}")
print("统计:", {k: (len(v) if isinstance(v, list) else v) for k, v in stat.items()})
print(f"changelog +{len(changelog)}；C6 补锚后仍缺'非 CWE'的行: {remain}（应=0）")
