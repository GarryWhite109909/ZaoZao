#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v9max 训练数据 (final_train_chatml_quality_final.jsonl) 全面质量审计。

覆盖 8 项检查：
1. 标签分布统计（漏洞 vs 安全）
2. 标签一致性（has_vulnerability vs vulnerability_type/risk_level）
3. 重复代码块（md5 hash 去重）
4. CWE 归因抽样检查（固定 seed 随机 20 条 + 规则化明显错误扫描）
5. 模板化程度（变量名替换后骨架聚类，>=5 同骨架组数）
6. CoT 质量（犹豫/边缘表述比例）
7. 测试集 Jaccard 泄漏检查（exp_04 samples + testset_cve_fix 共 107 文件）
8. 安全样本 CoT 坚定度（不含矛盾信号）
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

DATA_FILE = Path(r"d:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_quality_final.jsonl")
TEST_DIR_A = Path(r"d:\code\毕业设计\Graduation-Project\experiments\exp_04_hard_samples\samples")
TEST_DIR_B = Path(r"d:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\testset_cve_fix")

_JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)

# 保留的语言关键字（识别骨架时不被替换）
KEYWORDS = set("""
def class return if elif else for while in not and or import from as with try except finally raise lambda pass
break continue None True False is del global assert yield async await struct enum fn impl pub let mut static self
interface package public private protected extends implements new void int float double char boolean string
var const let function this super throw catch do switch case default typeof instanceof delete new using
namespace std using namespace int main include define ifndef endif
""".split())


def extract_code(user_content: str) -> str | None:
    if not user_content:
        return None
    m = re.search(r"```(\w+)\s*\n(.*?)```", user_content, re.DOTALL)
    if m:
        return m.group(2).strip()
    return None


def extract_language(user_content: str) -> str | None:
    if not user_content:
        return None
    m = re.search(r"语言:\s*(\w+)", user_content)
    return m.group(1).lower() if m else None


def extract_verdict(assistant_content: str) -> dict | None:
    """用 _JSON_BLOCK_RE 解析 verdict JSON 块。"""
    if not assistant_content:
        return None
    m = _JSON_BLOCK_RE.search(assistant_content)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    # 兜底：找最后一个含 has_vulnerability 的 JSON 对象
    matches = list(re.finditer(r'\{[^{}]*"has_vulnerability"[^{}]*\}', assistant_content, re.DOTALL))
    for mm in reversed(matches):
        try:
            return json.loads(mm.group(0))
        except json.JSONDecodeError:
            continue
    return None


def extract_cot(assistant_content: str) -> str:
    m = _JSON_BLOCK_RE.search(assistant_content)
    if m:
        return assistant_content[: m.start()].strip()
    return assistant_content.strip()


def skeleton(code: str) -> str:
    """变量名替换后的代码骨架：字符串/数字/关键字/标点保留，标识符替换为 X。"""
    tokens = re.findall(r'"""[^"]*"""|r?"""[^"]*"""|\'\'\'[^\']*\'\'\'|r?\'\'\'[^\']*\'\'\'|"[^"\n]*"|\'[^\'\n]*\'|[A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)?|[^\sA-Za-z0-9_\'"]', code)
    out = []
    for t in tokens:
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", t) and t not in KEYWORDS:
            out.append("X")
        else:
            out.append(t)
    s = " ".join(out)
    s = re.sub(r"\s+", " ", s)
    return s


def jaccard(tokens_a: set, tokens_b: set) -> float:
    inter = len(tokens_a & tokens_b)
    union = len(tokens_a | tokens_b)
    return inter / union if union else 0.0


def tokenize(text: str) -> set:
    return set(re.findall(r"[a-z0-9_]+", text.lower()))


def main():
    # ==================== 加载 ====================
    records = []
    with open(DATA_FILE, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError as e:
                records.append({"_parse_error": str(e), "_line": i})
                continue
            r["_line"] = i
            records.append(r)

    total = len(records)
    parsed_ok = 0
    rows = []
    for r in records:
        msgs = r.get("messages", [])
        user = asst = None
        for m in msgs:
            if m.get("role") == "user":
                user = m.get("content", "")
            elif m.get("role") == "assistant":
                asst = m.get("content", "")
        code = extract_code(user)
        lang = extract_language(user)
        verdict = extract_verdict(asst) if asst else None
        if verdict is not None:
            parsed_ok += 1
        rows.append({
            "line": r.get("_line", 0),
            "user": user or "",
            "asst": asst or "",
            "code": code,
            "lang": lang,
            "verdict": verdict,
            "cot": extract_cot(asst) if asst else "",
        })

    print("=" * 78)
    print(f"v9max 训练数据全面质量审计")
    print(f"文件: {DATA_FILE.name}")
    print(f"总样本数: {total} | 成功解析 verdict: {parsed_ok} ({parsed_ok/total*100:.1f}%)")
    print("=" * 78)

    # ==================== 1. 标签分布 ====================
    print("\n[1] 标签分布")
    hv_true = hv_false = hv_none = 0
    vt_counter = Counter()
    risk_counter = Counter()
    lang_counter = Counter()
    for row in rows:
        v = row["verdict"]
        if v is None:
            hv_none += 1
            continue
        hv = v.get("has_vulnerability")
        if hv is True:
            hv_true += 1
            vt = v.get("vulnerability_type")
            if vt:
                vt_counter[vt] += 1
            rl = v.get("risk_level")
            if rl:
                risk_counter[str(rl)] += 1
        elif hv is False:
            hv_false += 1
        else:
            hv_none += 1
        if row["lang"]:
            lang_counter[row["lang"]] += 1

    print(f"  漏洞样本 (has_vulnerability=true) : {hv_true}  ({hv_true/total*100:.2f}%)")
    print(f"  安全样本 (has_vulnerability=false): {hv_false}  ({hv_false/total*100:.2f}%)")
    print(f"  无法解析/缺失                    : {hv_none}  ({hv_none/total*100:.2f}%)")
    if hv_true > 0:
        print(f"  漏洞:安全比例 ≈ 1 : {hv_false/max(hv_true,1):.2f}")
    print(f"  risk_level 分布: {dict(risk_counter.most_common())}")
    print(f"  distinct vulnerability_type 数量: {len(vt_counter)}")
    print(f"  语言分布: {dict(lang_counter.most_common(15))}")
    print(f"  Top 20 vulnerability_type:")
    for vt, c in vt_counter.most_common(20):
        print(f"    {c:5d}  {vt}")

    # ==================== 2. 标签一致性 ====================
    print("\n[2] 标签一致性检查")
    inconsistency = []
    for row in rows:
        v = row["verdict"]
        if v is None:
            continue
        hv = v.get("has_vulnerability")
        vt = v.get("vulnerability_type")
        rl = v.get("risk_level")
        if hv is True:
            if not vt or str(vt).strip().lower() in ("none", "n/a"):
                inconsistency.append((row["line"], "has_vulnerability=true 但 vulnerability_type 为空/none"))
            elif rl is None or str(rl).strip() in ("None", "N/A", ""):
                inconsistency.append((row["line"], "has_vulnerability=true 但 risk_level 缺失"))
        elif hv is False:
            if vt and str(vt).strip().lower() != "none":
                inconsistency.append((row["line"], f"has_vulnerability=false 但 vulnerability_type='{vt}'"))
            if rl is not None and str(rl).strip() not in ("None", "N/A", ""):
                inconsistency.append((row["line"], f"has_vulnerability=false 但 risk_level='{rl}'"))
    print(f"  标签不一致样本数: {len(inconsistency)} / {total} ({len(inconsistency)/total*100:.2f}%)")
    for ln, desc in inconsistency[:30]:
        print(f"    line {ln}: {desc}")
    if len(inconsistency) > 30:
        print(f"    ... 其余 {len(inconsistency)-30} 条略")

    # ==================== 3. 重复代码块 ====================
    print("\n[3] 重复代码块 (md5 hash 去重)")
    hash_groups = defaultdict(list)
    for row in rows:
        if row["code"]:
            h = hashlib.md5(row["code"].encode("utf-8")).hexdigest()
            hash_groups[h].append(row["line"])
    dup_groups = {h: v for h, v in hash_groups.items() if len(v) > 1}
    dup_lines = sum(len(v) for v in dup_groups.values())
    print(f"  唯一代码 hash 数: {len(hash_groups)}")
    print(f"  重复组数 (出现>=2次): {len(dup_groups)}")
    print(f"  涉及重复的样本行数: {dup_lines} ({dup_lines/total*100:.2f}%)")
    # 最大重复组
    top = sorted(dup_groups.items(), key=lambda kv: -len(kv[1]))[:15]
    for h, lines in top:
        # 找对应代码预览
        preview = ""
        for row in rows:
            if row["line"] == lines[0] and row["code"]:
                preview = row["code"].split("\n")[0][:80]
                break
        print(f"    hash {h[:10]}... 出现 {len(lines)} 次, 行号 {lines}, 首行: {preview!r}")

    # ==================== 4. CWE 归因抽样检查 ====================
    print("\n[4] CWE 归因抽样检查")
    vuln_rows = [row for row in rows if row["verdict"] and row["verdict"].get("has_vulnerability") is True]
    print(f"  漏洞样本总数: {len(vuln_rows)}")
    random.seed(42)
    sample20 = random.sample(vuln_rows, min(20, len(vuln_rows)))
    print("  --- 随机 20 条漏洞样本 (seed=42) ---")
    for i, row in enumerate(sample20, 1):
        vt = row["verdict"].get("vulnerability_type", "")
        first_line = (row["code"] or "").split("\n")[0][:100]
        print(f"    #{i} line {row['line']:<6d} vt={vt}")
        print(f"         代码首行: {first_line!r}")

    # 规则化明显归因错误扫描
    print("\n  --- 规则化 CWE 归因错误扫描 (启发式) ---")
    attribution_issues = []
    patterns = [
        # (正则模式, 问题描述, 期望CWE, 错误CWE集)
        (re.compile(r"\beval\s*\(", re.I), "eval() 调用", {"CWE-94", "CWE-95"}, {"CWE-78", "CWE-89", "CWE-79", "CWE-22"}),
        (re.compile(r"\bexec\s*\(", re.I), "exec() 调用", {"CWE-94", "CWE-95"}, {"CWE-78", "CWE-89"}),
        (re.compile(r"(password|passwd|secret|api[_-]?key|access[_-]?key|token|credential)\s*=\s*['\"][^'\"]+['\"]", re.I), "硬编码凭证", {"CWE-798"}, {"CWE-287", "CWE-306", "CWE-862", "CWE-863"}),
        (re.compile(r"(eval\s*\(|exec\s*\().{0,200}(sql|cursor\.execute|execute\s*\()", re.I), "eval 与 SQL 混用", {"CWE-94", "CWE-95"}, {"CWE-89"}),
    ]
    for row in vuln_rows:
        code = row["code"] or ""
        vt = str(row["verdict"].get("vulnerability_type", ""))
        cwe_ids = set(re.findall(r"CWE-(\d+)", vt))
        cwe_str = {f"CWE-{c}" for c in cwe_ids}
        for pat, desc, expected, wrong in patterns:
            if pat.search(code):
                if expected & cwe_str:
                    continue  # 归因正确
                wrong_hit = wrong & cwe_str
                if wrong_hit:
                    attribution_issues.append((row["line"], desc, vt, code.split("\n")[0][:80]))
    print(f"  命中明显归因错误模式: {len(attribution_issues)} 条")
    for ln, desc, vt, first in attribution_issues[:30]:
        print(f"    line {ln}: [{desc}] vt='{vt}' 首行: {first!r}")
    if len(attribution_issues) > 30:
        print(f"    ... 其余 {len(attribution_issues)-30} 条略")

    # ==================== 5. 模板化程度 ====================
    print("\n[5] 模板化程度 (变量名替换骨架聚类)")
    skel_groups = defaultdict(list)
    for row in rows:
        if row["code"]:
            sk = skeleton(row["code"])
            skel_groups[sk].append(row["line"])
    big_groups = {sk: v for sk, v in skel_groups.items() if len(v) >= 5}
    big_lines = sum(len(v) for v in big_groups.values())
    print(f"  唯一骨架数: {len(skel_groups)}")
    print(f"  同骨架 >=5 的组数: {len(big_groups)}")
    print(f"  这些组覆盖样本数: {big_lines} ({big_lines/total*100:.2f}%)")
    top_sk = sorted(big_groups.items(), key=lambda kv: -len(kv[1]))[:20]
    for sk, lines in top_sk:
        preview = " ".join(sk.split())[:110]
        print(f"    出现 {len(lines):4d} 次: {preview!r}")
        print(f"           行号: {lines[:15]}{'...' if len(lines)>15 else ''}")

    # ==================== 6. CoT 质量 ====================
    print("\n[6] CoT 犹豫/边缘表述统计")
    hedge_patterns = re.compile(r"可能|也许|或许|不确定|疑似|边界|需要进一步|不一定|难以确定|尚不明确|有待|无法确定|无法完全确定|需要更多|需进一步|存在争议")
    hedge_lines = []
    for row in rows:
        cot = row["cot"]
        if cot and hedge_patterns.search(cot):
            hedge_lines.append(row["line"])
    print(f"  含犹豫/边缘表述的样本: {len(hedge_lines)} / {total} ({len(hedge_lines)/total*100:.2f}%)")
    # 按 has_vulnerability 拆分
    hedge_true = sum(1 for r in rows if r["line"] in set(hedge_lines) and r["verdict"] and r["verdict"].get("has_vulnerability") is True)
    hedge_false = sum(1 for r in rows if r["line"] in set(hedge_lines) and r["verdict"] and r["verdict"].get("has_vulnerability") is False)
    print(f"    其中漏洞样本: {hedge_true} | 安全样本: {hedge_false}")

    # ==================== 7. 测试集 Jaccard 泄漏检查 ====================
    print("\n[7] 测试集 Jaccard 泄漏检查")
    test_files = {}
    for d in (TEST_DIR_A, TEST_DIR_B):
        if d.exists():
            for p in sorted(d.glob("*.py")) + sorted(d.glob("*.java")) + sorted(d.glob("*.js")) + sorted(d.glob("*.php")) + sorted(d.glob("*.c")) + sorted(d.glob("*.cpp")) + sorted(d.glob("*.go")) + sorted(d.glob("*.rb")):
                test_files[p.name] = p.read_text(encoding="utf-8", errors="replace")
    print(f"  测试文件数: {len(test_files)} (exp_04={len(list(TEST_DIR_A.glob('*.py'))) if TEST_DIR_A.exists() else 0}+..., 需合计 107)")
    test_tokens = {name: tokenize(code) for name, code in test_files.items()}
    test_lineset = {name: {l.strip() for l in code.splitlines() if l.strip()} for name, code in test_files.items()}

    leak_high = []   # Jaccard >= 0.9
    leak_mid = []    # 0.7 <= Jaccard < 0.9
    exact_match = []
    for row in rows:
        if not row["code"]:
            continue
        code = row["code"]
        code_tok = tokenize(code)
        code_lineset = {l.strip() for l in code.splitlines() if l.strip()}
        best = (0.0, None)
        for name, tt in test_tokens.items():
            j = jaccard(code_tok, tt)
            if j > best[0]:
                best = (j, name)
        j, name = best
        if j >= 0.9:
            leak_high.append((row["line"], name, j))
        elif j >= 0.7:
            leak_mid.append((row["line"], name, j))
        # 整文件行级覆盖（同一测试文件行集是训练代码行集的子集）
        for name, tls in test_lineset.items():
            if tls and tls <= code_lineset and len(tls) >= 5:
                exact_match.append((row["line"], name, len(tls)))
                break
    print(f"  Jaccard >= 0.9 (高度疑似泄露): {len(leak_high)} 条")
    for ln, name, j in leak_high[:40]:
        print(f"    line {ln}: Jaccard={j:.2f} vs {name}")
    print(f"  0.7 <= Jaccard < 0.9 (疑似模板重叠): {len(leak_mid)} 条")
    for ln, name, j in leak_mid[:20]:
        print(f"    line {ln}: Jaccard={j:.2f} vs {name}")
    print(f"  测试文件行集 ⊆ 训练代码行集 (整文件级覆盖): {len(exact_match)} 条")
    for ln, name, n in exact_match[:20]:
        print(f"    line {ln}: 覆盖测试文件 {name} 的 {n} 行")
    if not leak_high and not exact_match:
        print("  ✅ 未发现明显测试集泄露")

    # ==================== 8. 安全样本 CoT 坚定度 ====================
    print("\n[8] 安全样本 CoT 坚定度")
    contradiction_patterns = re.compile(
        r"仍然存在风险|仍有风险|存在风险|潜在风险|可能不安全|不安全|有漏洞|可被利用|存在隐患|隐患|风险仍然|仍然危险|不够安全|并非完全安全|仍可能被|理论上存在|严格来说存在")
    safe_rows = [row for row in rows if row["verdict"] and row["verdict"].get("has_vulnerability") is False]
    weak_lines = []
    for row in safe_rows:
        if contradiction_patterns.search(row["cot"]):
            weak_lines.append(row["line"])
    print(f"  安全样本总数: {len(safe_rows)}")
    print(f"  含矛盾/动摇信号的安全样本: {len(weak_lines)} ({len(weak_lines)/max(len(safe_rows),1)*100:.2f}%)")
    # 展示几条（只截取匹配上下文）
    for row in safe_rows:
        if row["line"] in set(weak_lines):
            m = contradiction_patterns.search(row["cot"])
            ctx = row["cot"][max(0, m.start()-40): m.end()+40].replace("\n", " ")
            print(f"    line {row['line']}: ...{ctx}...")

    print("\n" + "=" * 78)
    print("审计完成")
    print("=" * 78)


if __name__ == "__main__":
    main()
