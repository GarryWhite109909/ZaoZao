#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""合并修复蒸馏波产出 → v2_14 数据集 + 终检审计。

用法：
  python3 scripts/merge_repair_wave.py            # 合并 + 审计，产出 v2_14
  python3 scripts/merge_repair_wave.py --dry-run  # 只审计不落盘

逻辑：
  1. v2_13 为基底（8637 条）。
  2. r1_expl 按 user 内容 md5 对齐回 v2_13 原行，仅替换 assistant（保留原行
     fix_distill/meta 等顶层标记）。
  3. r2_regen / r3_readj / g* 追加到尾部（按包顺序）。
  4. 全量终检：七字段契约 / risk_level / vt 规范 / system 单一版本 /
     重复 md5 / JSON 可解析 / 正负比 / explanation=N/A 残余。
"""
import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from repair_wave_common import BASE, CORPUS, CONTRACT, V2_13, norm_md5

V2_14 = BASE / "data/final_train_chatml_alpha06_v2_14.jsonl"
REPORT = BASE / "audit/merge_v2_14_report.txt"
MANIFEST = BASE / "audit/redistill_manifest_v2_13.jsonl"

# 追加顺序（phase 2 的 g3b/g4b 缺文件时自动跳过）
APPEND_PACKS = ["r2_regen", "r3_readj", "g1_looks_safe", "g2_evidence",
                "g3a_trust", "g3b_trust", "g4a_blacklist", "g4b_blacklist",
                "g5_extreme", "g6a_lang", "g6b_lang", "g7_special", "g8_logfam"]

BAD_KEYS = {"cvss_vector", "cvss_score", "fix_code", "is_confirmed", "reason",
            "label", "cwe_id", "severity", "verdict"}


def load_jsonl(p: Path):
    out = []
    if p.exists():
        for l in p.open(encoding="utf-8"):
            if l.strip():
                out.append(json.loads(l))
    return out


def assistant_json(assistant: str):
    m = re.findall(r"```json\s*(.*?)```", assistant, re.S)
    if not m:
        return None
    try:
        return json.loads(m[-1])
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    rep = []

    def log(s=""):
        print(s)
        rep.append(s)

    rows = load_jsonl(V2_13)
    log(f"基底 v2_13: {len(rows)} 条")

    # ---- 索引：user md5 -> 行号列表 ----
    user_idx = {}
    for i, r in enumerate(rows, 1):
        user_idx.setdefault(norm_md5(r["messages"][1]["content"]), []).append(i)

    # ---- 1) r1_expl 原位替换 ----
    r1 = load_jsonl(CORPUS / "r1_expl.jsonl")
    man = load_jsonl(MANIFEST)
    na_lines = {m["orig_line"] for m in man if m["reason"] == "explanation_na"}
    replaced, unmatched = 0, []
    for rec in r1:
        um = norm_md5(rec["messages"][1]["content"])
        cands = user_idx.get(um, [])
        body_head = rec["messages"][2]["content"].split("```json")[0].strip()[:200]
        target = None
        for li in cands:
            if rows[li - 1]["messages"][2]["content"].strip()[:200] == body_head:
                target = li
                break
        if target is None and len(cands) == 1:
            target = cands[0]
        if target is None:
            unmatched.append(rec["meta"]["task_key"])
            continue
        row = rows[target - 1]
        row["messages"][2] = rec["messages"][2]  # 仅替换 assistant
        replaced += 1
    log(f"r1_expl: 产出 {len(r1)}，原位替换 {replaced}，未匹配 {len(unmatched)} {unmatched[:5]}")
    log(f"  清单内 explanation_na 共 {len(na_lines)}，缺口 {len(na_lines) - replaced} 条"
        f"（如 >0 检查 _failed/ 后重跑 distill_repair_wave.py 补齐）")

    # ---- 1.5) r4_fixes：审计队列定点重蒸馏，r1 式原位替换 assistant ----
    r4 = load_jsonl(CORPUS / "r4_fixes.jsonl")
    user2row = {}
    for idx, r in enumerate(rows):
        user2row[norm_md5(r["messages"][1]["content"])] = idx
    n_r4 = 0
    for rec in r4:
        um = norm_md5(rec["messages"][1]["content"])
        idx = user2row.get(um)
        if idx is None:
            log(f"r4_fixes: 未匹配 {rec['meta']['task_key']}")
            continue
        rows[idx]["messages"][2] = rec["messages"][2]
        n_r4 += 1
    log(f"r4_fixes: 产出 {len(r4)}，原位替换 {n_r4}")

    # ---- 2) 追加包 ----
    exist_user = {norm_md5(r["messages"][1]["content"]) for r in rows}
    exist_assist = {norm_md5(r["messages"][2]["content"]) for r in rows}
    appended = Counter()
    dup_skip = []
    for pack in APPEND_PACKS:
        for rec in load_jsonl(CORPUS / f"{pack}.jsonl"):
            um = norm_md5(rec["messages"][1]["content"])
            am = norm_md5(rec["messages"][2]["content"])
            if am in exist_assist or um in exist_user:
                dup_skip.append(f"{pack}:{rec.get('meta', {}).get('task_key', '?')}")
                continue
            exist_user.add(um)
            exist_assist.add(am)
            rows.append({"messages": rec["messages"],
                         **({"meta": rec["meta"]} if rec.get("meta") else {})})
            appended[pack] += 1
    log(f"追加: {dict(appended)} 合计 {sum(appended.values())}"
        + (f"；跳过重复 {len(dup_skip)}" if dup_skip else ""))
    log(f"合并后: {len(rows)} 条")

    # ---- 2.5) 规范化 pass（审计前置，2026-08-30）----
    # P0-1 标签冲突改标（依据 audit/p0_1_label_conflicts_v2_14.json，判定表口径）
    from graduation_project.line_normalizer import normalize_line_numbers
    P01 = {ln: "CWE-78 OS Command Injection"
           for ln in [242, 250, 262, 290, 298, 312, 318, 319, 375, 378, 432,
                      450, 463, 475, 505, 530, 554, 584, 284, 500]}
    P01[649] = "CWE-1333 Inefficient Regular Expression Complexity"
    P01[2661] = "CWE-117 Improper Output Neutralization for Logs"
    P01[7078] = "CWE-532 Insertion of Sensitive Information into Log File"
    n_p01 = 0
    for ln, new_vt in P01.items():
        row = rows[ln - 1]
        a = row["messages"][2]["content"]
        old = re.search(r'"vulnerability_type":\s*"([^"]*)"', a)
        if old and old.group(1).split()[0] != new_vt.split()[0]:
            a2 = a.replace(f'"vulnerability_type": "{old.group(1)}"',
                           f'"vulnerability_type": "{new_vt}"', 1)
            if ln == 7078:
                a2 = a2.replace("CWE-312 明文存储", "CWE-532 日志文件插入敏感信息")
            row["messages"][2]["content"] = a2
            n_p01 += 1
    log(f"规范化: P0-1 改标 {n_p01}/{len(P01)} 条")

    # safe 行 risk_level 收敛（GLM 会写 N/A；契约要求 None）
    # hv=true vt 规范化：裸编号/缺空格 → 编号 + 官方名（语料库内 harvesting）
    name_map = {}
    for r in rows:
        m = re.match(r"(CWE-\d+)\s+(\S.*)",
                     (re.search(r'"vulnerability_type":\s*"([^"]*)"',
                                r["messages"][2]["content"]).group(1)))
        if m:
            name_map.setdefault(m.group(1), Counter())[m.group(2).strip()] += 1
    canon = {c: names.most_common(1)[0][0] for c, names in name_map.items()}
    EXTRA = {"CWE-250": "Execution with Unnecessary Privileges",
             "CWE-90": "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
             "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"}
    n_risk = n_vt = n_safe_vt = 0
    for r in rows:
        a = r["messages"][2]["content"]
        jm = re.findall(r"```json\s*(.*?)```", a, re.S)
        if not jm:
            continue
        try:
            o = json.loads(jm[-1])
        except Exception:
            continue
        hv = o.get("has_vulnerability")
        mutated = False
        rl = str(o.get("risk_level", "")).strip()
        if hv is False and rl.lower() in ("n/a", "na", "无", "不适用"):
            o["risk_level"] = "None"
            n_risk += 1
            mutated = True
        elif hv is False and rl != "None":
            # 安全样本的任何风险等级都与 has_vulnerability=false 矛盾
            # （GLM 习惯写"Low"表残余风险低，r2_regen 329 条）：统一收敛
            o["risk_level"] = "None"
            n_risk += 1
            mutated = True
        vt = str(o.get("vulnerability_type", ""))
        if hv is True and not re.match(r"^CWE-\d+\s", vt):
            m = re.match(r"(CWE-\d+)", vt)
            if m:
                code = m.group(1)
                name = canon.get(code) or EXTRA.get(code)
                if name:
                    o["vulnerability_type"] = f"{code} {name}"
                    n_vt += 1
                    mutated = True
        if hv is False and vt.lower() != "none" \
                and not re.search(r"CWE-\d+", vt):
            o["vulnerability_type"] = "none"
            n_safe_vt += 1
            mutated = True
        if mutated:
            a2 = a[:a.rfind("```json")] + "```json\n" + \
                json.dumps(o, ensure_ascii=False) + "\n```"
            r["messages"][2]["content"] = a2
    log(f"规范化: risk_level 收敛 {n_risk} 条，vt 规范化 {n_vt} 条，safe vt 收敛 {n_safe_vt} 条")

    # P1-3b explanation 行号校准（生产同源 normalizer）
    n_ln = 0
    for r in rows:
        user, asst = r["messages"][1]["content"], r["messages"][2]["content"]
        m = re.search(r'"explanation":\s*"((?:[^"\\]|\\.)*)"', asst)
        if not m:
            continue
        orig = m.group(1)
        if "line" not in orig.lower():
            continue
        codes = re.findall(r"```\w*\n(.*?)```", user, re.S)
        if not codes:
            continue
        try:
            fixed = normalize_line_numbers(orig, codes[0])
        except Exception:
            continue
        if fixed and fixed != orig:
            r["messages"][2]["content"] = asst.replace(
                f'"explanation": "{orig}"', f'"explanation": "{fixed}"', 1)
            n_ln += 1
    log(f"规范化: P1-3b explanation 行号校准 {n_ln} 条")

    # ---- 3) 终检 ----
    log("\n" + "=" * 60 + "\n终检审计\n" + "=" * 60)
    sys_set = Counter()
    risk = Counter()
    pos = Counter()
    bad_field = []
    vt_bad = []
    json_fail = []
    na_expl = 0
    too_long = 0
    for i, r in enumerate(rows, 1):
        msgs = r["messages"]
        sys_set[norm_md5(msgs[0]["content"])] += 1
        a = msgs[2]["content"]
        if len(a) > 6000:
            too_long += 1
        o = assistant_json(a)
        if o is None:
            json_fail.append(i)
            continue
        risk[str(o.get("risk_level"))] += 1
        pos[bool(o.get("has_vulnerability"))] += 1
        if set(o.keys()) != set(CONTRACT) or (set(o.keys()) & BAD_KEYS):
            bad_field.append(i)
        hv = o.get("has_vulnerability")
        vt = str(o.get("vulnerability_type", ""))
        if hv is True and not re.match(r"^CWE-\d+\s", vt):
            vt_bad.append((i, vt[:40]))
        if hv is False and vt.lower() != "none":
            vt_bad.append((i, vt[:40]))
        if str(o.get("explanation", "")).strip().upper().startswith("N/A"):
            na_expl += 1
    log(f"system 版本数: {len(sys_set)}" + ("" if len(sys_set) == 1
        else f"  ⚠ {sys_set.most_common(3)}"))
    log(f"risk_level: {dict(risk)}")
    log(f"正负: True={pos[True]} False={pos[False]}"
        f"（{pos[True]/len(rows)*100:.1f}% : {pos[False]/len(rows)*100:.1f}%）")
    log(f"七字段契约异常: {len(bad_field)} {bad_field[:10]}")
    log(f"vt 非规范: {len(vt_bad)} {vt_bad[:5]}")
    log(f"JSON 解析失败: {len(json_fail)} {json_fail[:10]}")
    log(f"explanation=N/A 残余: {na_expl}")
    log(f"assistant >6000 字符: {too_long}")

    ok = (len(sys_set) == 1 and not bad_field and not vt_bad
          and not json_fail and risk.get("None", 0) == pos[False]
          and set(risk) <= {"Critical", "High", "Medium", "Low", "None"})
    log(f"\n结论: {'✅ 通过，可落盘 v2_14' if ok else '❌ 存在问题，先修复再合并'}")

    if args.dry_run or not ok:
        return
    REPORT.write_text("\n".join(rep) + "\n", encoding="utf-8")
    with V2_14.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"\n已写出 {V2_14}（{len(rows)} 条）\n报告: {REPORT}")


if __name__ == "__main__":
    main()
