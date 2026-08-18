# -*- coding: utf-8 -*-
"""
提示质量审计（Prompt Quality Audit）—— 工具层不只是"过/不过"，要量化
"提示到点、不瞎说、真正帮到模型"。作为工具链评估的固定指标脚本。

背景：工具层（Stage 1）的职责是"找可疑点、给证据提示给模型"，最终裁决权归 LLM。
本脚本衡量工具提示质量，而不是工具对错——它回答三个问题：
  1) 工具找得全吗？（会不会漏提示，把活全甩给 LLM 复核）
  2) 工具给了提示时，点找对了吗？（会不会给错点）
  3) 工具提示真正帮到模型了吗？（提示有没有被采信、还是误导）

用法：
  /home/zane/miniconda3/bin/python prompt_quality_audit.py <result.json>

指标定义（对 expected_present=True 的漏洞样本统计）：
  A. 工具召回覆盖率 Tool-Recall Coverage
       工具产生 >=1 条 confirmed 候选的漏洞样本 / 漏洞样本数
       —— "工具找得全不全"。低=多数漏洞靠 LLM 复核兜底（工具层召回归责）
  B. 提示到点率 Prompt Hit-Rate（在工具召回的子集上）
       存在 >=1 条 confirmed 提示类型与 ground-truth 同族匹配 / 工具召回样本数
       —— "给了提示时，点找对没"。接近 100% 才合格
  C. 噪音提示率 Noisy-Prompt Rate（在工具召回的子集上）
       存在 confirmed 提示类型与 ground-truth 冲突 / 工具召回样本数
       —— "会不会瞎说/给无关点"。注意：噪音 ≠ 误导——仅当噪音类型被模型采信
         （模型最终判型落在噪音类型上）才算真正"误导模型"，本脚本单列 D
  D. 误导率 Misleading-Rate
       模型最终 vulnerability_type 落在"工具噪音提示类型"上的样本 / 工具召回样本数
       —— "提示真带偏模型了"。这是最严重的工具质量问题，必须为 0
  E. 提示-判型一致性 Prompt-Verdict Alignment（在到点子集上）
       模型判型语义 == 工具到点提示语义 / 到点样本数
       —— "工具提示被模型采信了没"（帮到判定）

硬性约束：类型推断表只放通用规则（bandit B 编号语义、semgrep 规则关键词），
不针对具体测试样本拟合——本脚本自身也遵守"不会的不瞎说"，推断不出的类型
保留原串并在明细里可人工复核。
"""
import json
import re
import sys

# ---------------------------------------------------------------------------
# CWE 编号 -> 语义类型（77/78 命令注入同族；80 是 XSS 子类）
# ---------------------------------------------------------------------------
CWE_TYPE = {
    "89": "SQL Injection", "79": "XSS", "80": "XSS",
    "78": "Command Injection", "77": "Command Injection",
    "94": "Code Injection", "95": "Code Injection",
    "22": "Path Traversal", "1336": "Server-Side Template Injection",
    "502": "Insecure Deserialization", "798": "Hardcoded Credentials",
    "918": "SSRF", "352": "CSRF", "611": "XXE", "601": "Open Redirect",
    "862": "Missing Authorization", "327": "Weak Crypto",
    "330": "Weak Random Number", "117": "Log Injection",
    "306": "Missing Authentication", "384": "Session Fixation",
    "347": "JWT Algorithm Confusion", "190": "Integer Overflow",
    "362": "Race Condition", "209": "Information Disclosure",
    "915": "Mass Assignment", "1321": "Prototype Pollution",
    "843": "Type Confusion", "917": "Expression Language Injection",
    "943": "NoSQL Injection", "90": "LDAP Injection",
    "643": "XPath Injection", "797": "LDAP Injection",
    "610": "External Control of Resource", "208": "Timing Attack",
}

# bandit B 规则编号 -> 语义类型（按 bandit 官方规则语义，不臆造）
BANDIT = {
    "b601": "Command Injection", "b602": "Command Injection", "b603": "Command Injection",
    "b605": "Command Injection", "b607": "Command Injection",
    "b608": "SQL Injection", "b609": "SQL Injection",
    "b301": "Insecure Deserialization", "b403": "Insecure Deserialization",
    "b401": "Insecure Deserialization", "b404": "Insecure Deserialization",
    "b701": "Server-Side Template Injection", "b702": "Server-Side Template Injection",
    "b202": "Path Traversal", "b108": "Path Traversal", "b310": "Path Traversal",
    "b105": "Hardcoded Credentials", "b106": "Hardcoded Credentials",
    "b107": "Hardcoded Credentials", "b324": "Weak Crypto",
    "b311": "Weak Random Number",
}

# rule_id / taint_type -> 语义类型 关键词推断（对齐 two_stage_scanner._infer_taint_type）
KEYWORD = [
    (re.compile(r"sql|execute|cursor|query", re.I), "SQL Injection"),
    (re.compile(r"xss|cross.?site|escape|innerhtml|document\.write|echoed|html.?context"
                r"|raw-html|format-string|html-concat", re.I), "XSS"),
    (re.compile(r"command|subprocess|system|popen|shell|runtime|child.?process", re.I), "Command Injection"),
    (re.compile(r"code|eval\(|pickle|yaml\.load|marshal|object.?inject", re.I), "Code Injection"),
    (re.compile(r"path|travers|open\(|join|abspath|symlink|tarfile", re.I), "Path Traversal"),
    (re.compile(r"ssti|jinja|from_string|render_template_string", re.I), "Server-Side Template Injection"),
    (re.compile(r"deserial|pickle|yaml|serialize", re.I), "Insecure Deserialization"),
    (re.compile(r"secret|credential|password|token|api.?key|aws|hashlib", re.I), "Hardcoded Credentials"),
    (re.compile(r"ssrf|urlopen|requests\.|urllib", re.I), "SSRF"),
    (re.compile(r"csrf", re.I), "CSRF"),
    (re.compile(r"xxe|xml|dtd|entity", re.I), "XXE"),
    (re.compile(r"redirect", re.I), "Open Redirect"),
    (re.compile(r"auth|authorization|access.?control|idor", re.I), "Missing Authorization"),
]


def infer_type(text: str) -> str:
    """rule_id/taint_type -> 语义类型。bandit 编号优先，其次语义名，再次关键词，
    兜底保留原串（绝不臆造，留人工复核）。"""
    if not text:
        return ""
    m = re.search(r"\b([Bb]\d{2,3})\b", text)
    if m and m.group(1).lower() in BANDIT:
        return BANDIT[m.group(1).lower()]
    for sem in CWE_TYPE.values():
        if sem.lower() in text.lower():
            return sem
    for rx, sem in KEYWORD:
        if rx.search(text):
            return sem
    return text.lower().split(".")[-1][:40]


def expected_types(expected_cwe: str) -> set:
    """'CWE-89,CWE-79' -> {'SQL Injection', 'XSS'}；未在表的编号保留 'CWE-xxx'。"""
    out = set()
    for cwe in re.findall(r"CWE-(\d+)", expected_cwe or ""):
        out.add(CWE_TYPE.get(cwe, f"CWE-{cwe}"))
    return out


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if not path:
        import glob
        cands = sorted(glob.glob(
            "/home/zane/文档/code/毕业设计/experiments/exp_07_two_stage_eval/results/"
            "*triage_train_aligned*.json"))
        if not cands:
            print("用法: prompt_quality_audit.py <result.json>"); return
        path = cands[-1]
    d = json.load(open(path))
    vuln = [s for s in d["samples"] if s.get("expected_present")]

    recall_cov = hit = hit_tot = noisy = noisy_tot = mislead = mislead_tot = 0
    align = align_tot = 0
    miss_recall, hit_fail, noisy_l, mislead_l, align_fail = [], [], [], [], []

    for s in vuln:
        name = s["file"]
        exp = expected_types(s.get("expected_cwe", ""))
        adj = s.get("adjudications") or []
        # 工具候选全集：全部工具产生的 adjudications（不论模型采信与否）。
        # 2026-08-18 口径修正：B 到点率衡量"工具提示到点上没"= 看工具生成的所有
        # 候选（含被模型否决的）；模型采信与否由 E 指标单独衡量。原实现只看
        # confirmed=True 导致"工具到点但被模型否决"被误判为未到点。
        all_cands = [a for a in adj if not (a.get("rule_id") or "").startswith("llm")]
        confirmed = [a for a in all_cands if a.get("confirmed")]
        tool_types = {infer_type(a.get("taint_type") or a.get("rule_id") or "")
                      for a in all_cands}
        tool_types.discard("")

        if not all_cands:
            miss_recall.append((name, sorted(exp)))
            continue
        recall_cov += 1

        # B：到点 = 存在一条提示与 ground-truth 同族匹配
        onpoint = bool(tool_types & exp)
        hit_tot += 1
        if onpoint:
            hit += 1
        else:
            hit_fail.append((name, sorted(exp), sorted(tool_types)))

        # C：噪音 = 提示类型里与 ground-truth 冲突的（非主漏洞类型的额外提示）
        noise = tool_types - exp
        noisy_tot += 1
        if noise:
            noisy += 1
            noisy_l.append((name, sorted(exp), sorted(noise)))
            # D：误导 = 噪音类型被模型最终判型采信（模型判落在噪音上 = 真带偏）
            final = s.get("vulnerability_type") or ""
            final_sem = infer_type(final)
            if final_sem and final_sem in noise:
                mislead += 1
                mislead_l.append((name, sorted(exp), sorted(noise), final_sem))

        # E：到点子集上模型判型与工具提示一致性
        if onpoint:
            align_tot += 1
            final_sem = infer_type(s.get("vulnerability_type") or "")
            if final_sem and final_sem in tool_types:
                align += 1
            else:
                align_fail.append((name, sorted(exp), sorted(tool_types), final_sem))

    n = len(vuln)
    print(f"=== 提示质量审计（工具层）: {path.split('/')[-1]} ===")
    print(f"漏洞样本 {n} | 工具召回候选 {recall_cov}")
    print(f"\nA. 工具召回覆盖率: {recall_cov}/{n} = {recall_cov/n:.1%}"
          f"（其余 {n-recall_cov} 靠 LLM 复核兜底）")
    print(f"B. 提示到点率(召回子集): {hit}/{hit_tot} = {hit/hit_tot:.1%}")
    print(f"C. 噪音提示率(召回子集): {noisy}/{noisy_tot} = {noisy/noisy_tot:.1%}")
    print(f"D. 误导率(噪音被子集): {mislead}/{noisy} = {mislead/max(noisy,1):.1%}"
          f"（噪音被模型采信=真带偏）")
    if align_tot:
        print(f"E. 提示-判型一致性(到点子集): {align}/{align_tot} = {align/align_tot:.1%}")

    print(f"\n--- A. 工具未召回(靠 LLM 兜底判对)的漏洞样本 {len(miss_recall)} ---")
    for name, exp in miss_recall:
        print(f"  {name[:34]:36s} exp={exp}")
    if hit_fail:
        print(f"\n--- B. 工具召回但提示未到点的样本 {len(hit_fail)} ---")
        for name, exp, got in hit_fail:
            print(f"  {name[:34]:36s} exp={exp} tool={got}")
    if noisy_l:
        print(f"\n--- C. 工具噪音提示(非主漏洞的额外类型)的样本 {len(noisy_l)} ---")
        for name, exp, bad in noisy_l:
            print(f"  {name[:34]:36s} exp={exp} noise={bad}")
    if mislead_l:
        print(f"\n--- D. 工具提示真误导了模型的样本 {len(mislead_l)}（必须归因修复）---")
        for name, exp, bad, final in mislead_l:
            print(f"  {name[:34]:36s} exp={exp} noise={bad} final={final!r}")
    if align_fail:
        print(f"\n--- E. 到点但模型判型未采信提示的样本 {len(align_fail)} ---")
        for name, exp, got, final in align_fail:
            print(f"  {name[:34]:36s} exp={exp} tool={got} final={final!r}")


if __name__ == "__main__":
    main()
