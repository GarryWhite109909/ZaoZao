#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v2_15a 阶段二：为 P0-B 余量辨析组产出 evidence_adjudication 双版本。

依据 v2_15 文档 P0-B「裁决格式对齐：每条产出 evidence_adjudication 版本」+ 机检断言③
「主库/adjudication 双版本标签一致」。

流程：
  1. 读 corpus/repair_wave/{g9..g15}.jsonl 主库记录（阶段一产出）。
  2. 每条记录：从 assistant JSON 取 vt/source/sink/risk，构造模拟工具告警提示，
     让教师独立写【告警 + 裁决分析 + 七字段结论】。
  3. 教师裁决标签 ≠ 主库标签 → 拒绝入 _failed（教师一致性门 ③ 的数据侧落地）。
  4. 校验后装配 evidence_adjudication_pos/neg 记录（system 与主库同版，user=代码+告警+
     判定要求尾注，与库内 g2_evidence 同构）。

用法：
  TEACHER_API_URL=... TEACHER_KEY=... TEACHER_MODEL=... \
    python3 scripts/distill_adjud_v2_15a.py [--workers 6] [--pilot]
断点续传：corpus/repair_wave/_progress/g16_adjud_15a.jsonl
"""
import argparse
import json
import os
import re
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from repair_wave_common import (
    CORPUS, PROGRESS, FAILED, call_teacher, load_context, parse_json_block,
    check_contract, check_style, norm_md5, gen_user, clean_analysis_text,
)
from gen_alpha06_variants import SCHEMA_LOCK

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SRC_PACKS = ["g9_1321", "g10_915", "g11_1336", "g12_1336_79", "g13_1336_134",
             "g14_priority", "g15_fromstring", "g17_priority_authz",
             "g18_authz_family", "g19_134_boundary"]
OUT_PACK = "g16_adjud_15a"

# 各包裁决版需复现的锚句（与主库一致； g15 安全样本走安全口径锚句）
ANCHORS = {
    "g9_1321": "攻击者控制键名污染原型链|不是 912",
    "g10_915": "对象属性修改而非原型键注入|不是 1321",
    "g11_1336": "输入被当作模板语法执行",
    "g12_1336_79": None,   # 逐条取主库正文里的辨析句（非 1336 即非 79 方向）
    "g13_1336_134": "不是 134|printf 格式串语义|模板引擎定义",
    "g14_priority": None,  # 逐条：主类型 NNN + 伴生并列（主库 vt 已含）
    "g15_fromstring": None,
    "g17_priority_authz": "798 同时成立|字面值凭证是伴生发现",
    "g18_authz_family": None,
    "g19_134_boundary": "不是 134",
}

TABLE_AUTHZ_ADJUD = (
    "【授权族判定表——裁决分析必须遵循】\n"
    "有无访问控制机制？无检查+敏感操作=862；有检查但访问对象由用户可控参数决定=639（IDOR）；\n"
    "登录后不重新生成会话标识=384；无 per-request token 的 state-changing 操作=352；\n"
    "JWT alg=none/签名不校验=347；字面值凭证 798 只是伴生发现，判主类型看用户可控数据流到达的危险 sink；\n"
    "306（API 级缺失认证）与 862 同现时以 639>862>306 为主次")

RULE_HINT = {
    "1321": "prefilter:proto_pollution_merge（JS 递归合并三件套）",
    "915": "sast:mass-assignment-object-merge",
    "1336": "taint_tracker:Server-Side Template Injection",
    "79": "taint_tracker:Cross-Site Scripting",
    "208": "prefilter:timing_unsafe_compare",
    "209": "sast:error-disclosure-exception-message",
    "89": "taint_tracker:SQL Injection",
    "798": "gitleaks:generic-api-key",
    "78": "sast:request-data-write",
    "862": "sast:missing-authorization-handler",
    "639": "sast:idor-object-controlled-key",
    "384": "sast:session-fixation-no-regenerate",
    "352": "sast:csrf-no-per-request-token",
    "347": "sast:jwt-signature-not-verified",
    "306": "sast:api-missing-authentication",
}


def parse_rec(rec):
    """主库记录 → (lang, code, obj, source/sink 行号, primary_cwe, expect_hv)。"""
    user = rec["messages"][1]["content"]
    asst = rec["messages"][2]["content"]
    m = re.search(r"语言:\s*(\w+)", user)
    lang = m.group(1) if m else "python"
    blocks = re.findall(r"```[\w+#-]*\n(.*?)```", user, re.S)
    code = "\n".join(blocks).rstrip()
    obj = json.loads(re.findall(r"```json\s*(.*?)```", asst, re.S)[-1])
    vt = str(obj.get("vulnerability_type", ""))
    cwe_m = re.match(r"CWE-(\d+)", vt)
    return lang, code, obj, vt, (cwe_m.group(1) if cwe_m else None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--pilot", action="store_true")
    args = ap.parse_args()

    ctx = load_context()
    adjud_tail = ctx["adjud_tail"] or "判定要求：核实告警传播链每一跳后给出七字段结论。"

    # ---- 断点：已完成的 src_key 集合
    prog_f = PROGRESS / f"{OUT_PACK}.jsonl"
    done = set()
    if prog_f.exists():
        done = {json.loads(l)["key"] for l in prog_f.open(encoding="utf-8") if l.strip()}

    # ---- 已产出（避免重复追加）
    out_f = CORPUS / f"{OUT_PACK}.jsonl"
    produced = set()
    if out_f.exists():
        for l in out_f.open(encoding="utf-8"):
            if l.strip():
                produced.add(json.loads(l)["meta"]["task_key"])

    tasks = []
    for pack in SRC_PACKS:
        pf = CORPUS / f"{pack}.jsonl"
        if not pf.exists():
            print(f"跳过 {pack}（无产出）")
            continue
        for l in pf.open(encoding="utf-8"):
            if not l.strip():
                continue
            rec = json.loads(l)
            key = rec["meta"]["task_key"]
            if key in done or f"{OUT_PACK}:{key}" in produced:
                continue
            lang, code, obj, vt, cwe = parse_rec(rec)
            expect_hv = obj.get("has_vulnerability") is True
            src, snk = str(obj.get("source", "")), str(obj.get("sink", ""))
            risk = str(obj.get("risk_level", "Medium"))
            n_lines = code.count("\n") + 1
            kind = "evidence_adjudication_pos" if expect_hv else "evidence_adjudication_neg"
            verdict_line = (f"vulnerability_type 必须逐字等于「{vt}」（主库/裁决双版本标签一致）"
                            if expect_hv else
                            "has_vulnerability=false，vulnerability_type='none'，risk_level='None'，"
                            "source/sink='N/A'，explanation 说明告警为何是误报（防御有效/输入不可控/链路断裂），"
                            "fix_suggestion='no fix needed'")
            anchor_req = ANCHORS.get(pack)
            if pack == "g12_1336_79":
                anchor_req = ("不是 1336：变量值不进入模板源码，模板语法不执行" if cwe == "79"
                              else "不是 79：输入进入模板源码而非仅输出未转义")
            elif pack == "g15_fromstring":
                anchor_req = ("from_string 将字符串编译为模板并渲染" if expect_hv
                              else "变量值不进入模板源码，模板语法不执行")
            elif pack == "g14_priority":
                anchor_req = "为伴生漏洞同时成立"
            prompt = (f"一段 {lang} 代码如下（禁止改写代码，禁止重排行号）：\n\n"
                      f"```{lang}\n{code}\n```\n\n"
                      f"分两步生成一条【裁决类{'正例' if expect_hv else '负例'}】训练素材：\n\n"
                      f"【第一步】以静态分析工具口吻写一条针对该代码的告警（4~8 行：规则名形如"
                      f"「{RULE_HINT.get(cwe, 'sast:suspicious-flow')}」、污染源入口、2~3 跳传播、"
                      f"sink 行号必须与代码真实行号一致且 ≤ {n_lines}）。"
                      f"可参考事实（不得照抄原文）：source={src[:80]}；sink={snk[:80]}；严重度 {risk}。\n"
                      f"{'若判定为真，须验证告警传播链每一跳真实存在。' if expect_hv else '该告警实际是误报：请从防御有效/输入不可控/链路断裂角度给出否决论证。'}\n\n"
                      f"【第二步】对该告警做独立裁决，{verdict_line}。\n"
                      + (f"裁决分析必须逐字包含以下锚句：{anchor_req}\n" if anchor_req else "")
                      + (f"多漏洞共现按危害可达性取主类型，伴生漏洞以「; CWE-编号 官方名」并列写入"
                         f" vulnerability_type，不得省略。\n" if (pack == "g14_priority" and expect_hv) else "")
                      + (TABLE_AUTHZ_ADJUD + "\n\n"
                         if pack in ("g17_priority_authz", "g18_authz_family") else "")
                      + f"\n【输出格式】\n【模拟工具告警】\n<告警文本，行号必须真实>\n"
                        f"1. <裁决分析 3~5 步，引用真实行号与标识符>\n"
                        f"```json\n<七字段结论>\n```\n"
                        f"JSON 字符串值内严禁英文双引号。严禁使用 label/cwe_id/severity/reason 等旧键名。\n"
                        f"{SCHEMA_LOCK}")
            tasks.append({"pack": OUT_PACK, "key": f"{OUT_PACK}:{key}", "src_pack": pack,
                          "prompt": prompt, "lang": lang, "code": code, "n": n_lines,
                          "expect_hv": expect_hv, "expect_vt": vt, "kind": kind,
                          "anchor_req": anchor_req, "src_key": key})

    if args.pilot:
        cnt, kept = {}, []
        for t in tasks:
            c = cnt.get(t["src_pack"], 0)
            if c < 2:
                kept.append(t)
                cnt[t["src_pack"]] = c + 1
        tasks = kept

    print(f"裁决版任务 {len(tasks)} 条 | workers={args.workers}", flush=True)

    lock = threading.Lock()
    stats = Counter()

    def run_task(t):
        t0 = time.time()
        try:
            text = call_teacher(os.environ["TEACHER_KEY"], t["prompt"])
        except Exception as e:
            with lock:
                stats["api_fail"] += 1
            return f"✗ {t['key']} API: {str(e)[:60]}"
        rec, err = validate_adjud(t, text, ctx, adjud_tail)
        with lock:
            if rec is None:
                stats["reject"] += 1
                with open(FAILED / f"{OUT_PACK}.jsonl", "a", encoding="utf-8") as f:
                    f.write(json.dumps({"key": t["key"], "err": str(err)[:200],
                                        "raw_head": text[:2000]}, ensure_ascii=False) + "\n")
            else:
                with out_f.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                with prog_f.open("a", encoding="utf-8") as f:
                    f.write(json.dumps({"key": t["key"]}) + "\n")
                stats["ok"] += 1
        return (f"✓ {t['key']} ({time.time()-t0:.0f}s)" if rec is not None
                else f"✗ {t['key']} 拒: {str(err)[:80]}")

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(run_task, t) for t in tasks]
        for i, fut in enumerate(as_completed(futs)):
            print(f"  [{i+1}/{len(tasks)}] {fut.result()}", flush=True)

    print(f"\n完成 {json.dumps(stats, ensure_ascii=False)} | 输出 {out_f}", flush=True)


def validate_adjud(t, text, ctx, adjud_tail):
    text = text.strip()
    if "【模拟工具告警】" not in text:
        return None, "缺告警段"
    obj, err = parse_json_block(text)
    if obj is None:
        return None, f"JSON: {err}"
    seg = text.split("【模拟工具告警】")[1]
    jm = seg.find("```json")
    if jm > 0:
        seg = seg[:jm]
    # 告警段与裁决分析切分：分析按约定以 "1. " 开头（不重复进 user，避免 g2 老记录
    # 的"正文双写"瑕疵）
    parts = re.split(r"\n1\. ", seg, maxsplit=1)
    alert = parts[0].strip()
    body = ("1. " + parts[1]) if len(parts) > 1 else ""
    if not body.strip():
        return None, "缺裁决分析（1. 编号正文）"
    bad = [int(x) for x in re.findall(r"line\s*(\d+)", alert, re.I) if int(x) > t["n"]]
    if bad:
        return None, f"告警行号越界 {bad[:3]} > {t['n']}"
    e = check_contract(obj, t["expect_hv"], t["code"])
    if e:
        return None, e
    # ---- 教师一致性门③：裁决标签必须与主库逐字一致
    if t["expect_hv"]:
        if str(obj.get("vulnerability_type", "")).strip() != t["expect_vt"].strip():
            return None, (f"裁决 vt 与主库不一致：{str(obj.get('vulnerability_type'))[:60]}"
                          f" != {t['expect_vt'][:60]}")
    n_ref = max((int(m.group(1)) for m in re.finditer(r"第\s*(\d+)\s*行", body)), default=0)
    if n_ref > t["n"] + 2:
        return None, f"正文引用第 {n_ref} 行 > 代码 {t['n']} 行"
    if t["anchor_req"]:
        for phrase in t["anchor_req"].split("|"):
            phrase = phrase.strip()
            if phrase and phrase not in body:
                return None, f"缺锚句「{phrase}」"
    body = clean_analysis_text(body)
    user = (gen_user(t["lang"], t["code"]) + f"\n\n【静态工具告警】\n{alert}\n\n" + adjud_tail)
    assistant = body + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```"
    e = check_style(assistant)
    if e:
        return None, e
    if norm_md5(assistant) in ctx["assist_md5"] or norm_md5(user) in ctx["user_md5"]:
        return None, "与现有库重复"
    return ({"messages": [{"role": "system", "content": ctx["main_system"]},
                          {"role": "user", "content": user},
                          {"role": "assistant", "content": assistant}],
             "meta": {"kind": t["kind"], "task_key": t["key"], "gen": True,
                      "src_task": t["src_key"]}}, None)


if __name__ == "__main__":
    main()
