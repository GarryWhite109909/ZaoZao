#!/usr/bin/env python3
"""P0.3：构建 alpha06 训练集（final_train_chatml_alpha06.jsonl）。

流水线（顺序固定，见 docs/实验路线图.md）：
  1. 清洗旧 alpha05 数据（7972 条）：剔除无语言标记；剔除"仅以黑名单/正则过滤
     为安全理由"的可疑样本（教 FN 的矛盾信号）；
  2. 全部扫描类样本统一 system 为新版 ALPHA05_PROMPT（α0.6 口径）；
  3. 并入蒸馏对（592）与 triage 裁决样本（24，保留其专属 system 不动）；
  4. 扫描类 assistant JSON 七字段按 schema 声明顺序重排；
  5. 全量断言（结构/字段/判定方向/CWE 格式/语言标记）；
  6. 最终泄漏门：合并集 vs 三测试集（87段/cve_fix20/rolling_dev）Jaccard ≥0.3 剔除。
输出：data/final_train_chatml_alpha06.jsonl + data/build_alpha06_report.md
"""
import hashlib
import json
import re
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))
from graduation_project.prompts import ALPHA05_PROMPT

OLD_DATA = Path("/home/zane/下载/final_train_chatml_alpha05.jsonl")
DISTILL = PROJECT / "experiments/exp_06_finetune/corpus/distill_alpha_pairs.jsonl"
WAVE2 = PROJECT / "experiments/exp_06_finetune/corpus/distill_variants_wave2.jsonl"
TRIAGE = PROJECT / "experiments/exp_06_finetune/data/supplement_alpha05_triage.jsonl"
OUT = PROJECT / "experiments/exp_06_finetune/data/final_train_chatml_alpha06.jsonl"
REPORT = PROJECT / "experiments/exp_06_finetune/data/build_alpha06_report.md"

CANONICAL = ["has_vulnerability", "vulnerability_type", "risk_level",
             "source", "sink", "explanation", "fix_suggestion"]
STRONG_DEFENSE = re.compile(r"参数化|白名单|转义|escape|占位符|\?\"|\?'|%s|autoescape|prepareStatement|placeholder", re.I)
WEAK_DEFENSE = re.compile(r"黑名单|正则(?!.*有效)|re\.(?:search|match|sub)|\.replace\(|过滤")


def reorder_json(text: str):
    """把 assistant 里 ```json 七字段按 canonical 序重排。返回 (新文本, 是否成功)。"""
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.S)
    if not m:
        return text, False
    try:
        obj = json.loads(m.group(1))
    except json.JSONDecodeError:
        return text, False
    if "has_vulnerability" not in obj:
        return text, False  # 非 has_vulnerability 格式（如 triage）不动
    ordered = {k: obj[k] for k in CANONICAL if k in obj}
    for k, v in obj.items():
        if k not in ordered:
            ordered[k] = v
    return text[:m.start()] + "```json\n" + \
        json.dumps(ordered, ensure_ascii=False) + "\n```" + text[m.end():], True


def lang_of(user: str):
    lm = re.search(r"语言[:：]\s*(\w+)", user)
    return lm.group(1).lower() if lm else None


def norm_lines(code: str) -> set:
    out = set()
    for ln in code.splitlines():
        s = ln.strip()
        if not s or s.startswith(("#", "//")):
            continue
        s = re.sub(r"\s+", " ", s).lower()
        if len(s) >= 8:
            out.add(s)
    return out


def main():
    stats = {"old_in": 0, "drop_nolang": 0, "drop_weak_defense": 0,
             "distill_in": 0, "triage_in": 0, "final": 0}
    merged = []
    seen_hash = set()

    # ---------- 1) 旧数据清洗 ----------
    for line in OLD_DATA.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        stats["old_in"] += 1
        msgs = r["messages"]
        user = next(m["content"] for m in msgs if m["role"] == "user")
        asst = next(m["content"] for m in msgs if m["role"] == "assistant")
        if lang_of(user) is None:
            stats["drop_nolang"] += 1
            continue
        jm = re.search(r'"has_vulnerability":\s*(true|false)', asst)
        if jm and jm.group(1) == "false":
            reason_part = asst.split("```json")[0]
            # 仅以弱防御（黑名单/正则/replace 过滤）为安全理由、且无强防御词 → 可疑，剔除
            if WEAK_DEFENSE.search(reason_part) and not STRONG_DEFENSE.search(reason_part):
                stats["drop_weak_defense"] += 1
                continue
        merged.append(("old", r))

    # ---------- 2/3/4) 统一 system + 重排（旧数据同样必须过此管道）----------
    def process_scan_record(r, source_tag):
        """统一 system、重排七字段；返回 (r, err)。"""
        msgs = r["messages"]
        msgs[0]["content"] = ALPHA05_PROMPT
        asst_msg = next(m for m in msgs if m["role"] == "assistant")
        new_text, ok = reorder_json(asst_msg["content"])
        if not ok:
            return None, "assistant 无可解析的 has_vulnerability JSON"
        asst_msg["content"] = new_text
        return r, None

    processed = []
    for tag, r in merged:
        if tag == "triage":
            processed.append((tag, r))  # triage 保留专属 system，不统一不重排
            continue
        r2, err = process_scan_record(r, tag)
        if err:
            print(f"[跳过 {tag}] {r['messages'][1]['content'][:40]}...: {err}")
            continue
        processed.append((tag, r2))
    merged = processed

    # 并入蒸馏对与 triage 样本
    for line in DISTILL.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        stats["distill_in"] += 1
        r2, err = process_scan_record(r, "distill")
        if err:
            print(f"[跳过 distill] {r['meta'].get('seed_file')}: {err}")
            continue
        merged.append(("distill", r2))

    # 并入 wave2 语义结构变体（框架习语/无污点硬安全/跨文件）
    stats["wave2_in"] = 0
    for line in WAVE2.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        stats["wave2_in"] += 1
        r2, err = process_scan_record(r, "wave2")
        if err:
            print(f"[跳过 wave2] {r['meta'].get('task_key')}: {err}")
            continue
        merged.append(("wave2", r2))

    for line in TRIAGE.read_text().splitlines():
        if not line.strip():
            continue
        stats["triage_in"] += 1
        merged.append(("triage", json.loads(line)))

    # ---------- 5) 全量断言 ----------
    errors = []
    final_records = []
    code_seen = set()
    for idx, (tag, r) in enumerate(merged):
        msgs = r["messages"]
        if len(msgs) != 3 or [m["role"] for m in msgs] != ["system", "user", "assistant"]:
            errors.append(f"#{idx}[{tag}] 结构错误")
            continue
        is_triage = (tag == "triage")
        user_c = msgs[1]["content"]
        asst_c = msgs[2]["content"]
        if not is_triage and lang_of(user_c) is None:
            errors.append(f"#{idx}[{tag}] 缺语言标记")
            continue
        m = re.search(r"```json\s*(\{.*?\})\s*```", asst_c, re.S)
        if not m:
            errors.append(f"#{idx}[{tag}] 无 json 块")
            continue
        try:
            obj = json.loads(m.group(1))
        except json.JSONDecodeError as e:
            errors.append(f"#{idx}[{tag}] json 解析失败: {e}")
            continue
        if not is_triage:
            hv = obj.get("has_vulnerability")
            if not isinstance(hv, bool):
                errors.append(f"#{idx}[{tag}] has_vulnerability 非布尔")
                continue
        if not is_triage:
            missing = [k for k in CANONICAL if k not in obj]
            if missing:
                errors.append(f"#{idx}[{tag}] 缺字段 {missing}")
                continue
            vt = obj.get("vulnerability_type", "")
            if hv and not str(vt).startswith("CWE-"):
                errors.append(f"#{idx}[{tag}] 漏洞但类型非 CWE: {vt}")
                continue
            if not hv and vt != "none":
                errors.append(f"#{idx}[{tag}] 安全但类型非 none: {vt}")
                continue
            code_body = user_c
            cm = re.search(r"```[\w+-]*\n(.*?)\n```", user_c, re.S)
            if cm:
                code_body = cm.group(1)
            n_lines = code_body.count("\n") + 1
            bad_anchor = [int(n) for n in set(re.findall(r"line (\d+)", json.dumps(obj, ensure_ascii=False)))
                          if not (1 <= int(n) <= n_lines)]
            if bad_anchor:
                errors.append(f"#{idx}[{tag}] 行号越界 {bad_anchor[:3]}")
                continue
        h = hashlib.md5((user_c[-2000:] + asst_c[-500:]).encode()).hexdigest()
        if h in code_seen:
            continue  # 完全重复
        code_seen.add(h)
        final_records.append(r)
    stats["final"] = len(final_records)

    # ---------- 6) 最终泄漏门 ----------
    testsets = {}
    e04 = PROJECT / "experiments/exp_04_hard_samples/samples"
    for f in e04.glob("*"):
        if f.suffix in (".py", ".java", ".js", ".php", ".go", ".ts"):
            testsets[f"87seg/{f.name}"] = f.read_text(errors="replace")
    cf = PROJECT / "experiments/exp_06_finetune/testset_cve_fix"
    for f in cf.glob("cve_fix_*"):
        if f.is_file():
            testsets[f"cve20/{f.name}"] = f.read_text(errors="replace")
    rd = PROJECT / "experiments/exp_06_finetune/corpus/rolling_dev"
    for f in rd.glob("corpus_*"):
        if f.is_file():
            testsets[f"rollingdev/{f.name}"] = f.read_text(errors="replace")
    test_norm = {k: norm_lines(v) for k, v in testsets.items()}

    leaks = []
    for i, r in enumerate(final_records):
        user_c = next(m["content"] for m in r["messages"] if m["role"] == "user")
        norm = norm_lines(user_c)
        best_k, best_j, best_c = "", 0.0, 0.0
        for k, tn in test_norm.items():
            j = len(norm & tn) / len(norm | tn) if norm and tn else 0.0
            c = len(norm & tn) / min(len(norm), len(tn)) if norm and tn else 0.0
            if j > best_j:
                best_j, best_k = j, k
            if c > best_c:
                best_c = c
        # 双口径泄漏门（2026-08-23 正式化）：Jaccard≥0.3 或 包含度≥0.5 均剔除
        if best_j >= 0.3 or best_c >= 0.5:
            leaks.append({"index": i, "file": best_k,
                          "jaccard": round(best_j, 3), "containment": round(best_c, 3)})
    # 剔除泄漏条目
    leak_idx = {x["index"] for x in leaks}
    final_records = [r for i, r in enumerate(final_records) if i not in leak_idx]
    stats["final"] = len(final_records)

    # ---------- 输出 ----------
    with open(OUT, "w", encoding="utf-8") as f:
        for r in final_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    src_dist = {}
    lines = [
        "# alpha06 训练集构建报告\n",
        f"- 输入：旧 {stats['old_in']} | 蒸馏 {stats['distill_in']} | triage {stats['triage_in']}",
        f"- 清洗剔除：无语言 {stats['drop_nolang']} | 弱防御安全理由 {stats['drop_weak_defense']}",
        f"- 泄漏门剔除（≥0.3）：{len(leaks)}",
        f"- **最终：{stats['final']} 条** → `{OUT.name}`",
        f"- 断言错误：{len(errors)}（全部阻断不入集）",
        "",
    ]
    if leaks:
        lines += ["## 泄漏明细"]
        for x in leaks[:30]:
            lines.append(f"- #{x['index']} vs {x['file']} J={x['jaccard']} C={x['containment']}")
    else:
        lines += ["## 泄漏明细", "", "（无命中）"]
    if errors:
        lines += ["", "## 断言错误样例", *[f"- {e}" for e in errors[:30]]]
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines[:10]))
    print(f"来源分布: {json.dumps({k: v for k, v in stats.items()})}")
    print(f"报告: {REPORT}")


if __name__ == "__main__":
    main()
