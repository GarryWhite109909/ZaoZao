#!/usr/bin/env python3
"""构建 alpha06-v2 训练集（final_train_chatml_alpha06_v2.jsonl）。

在 alpha06 基础上并入四类新增量（弱点挖掘报告 第九~十一节）：
  1. 旧 alpha05 清洗集（同 v1：剔除无语言/弱防御安全理由）
  2. wave1 蒸馏对（574）+ wave2 语义结构变体（含本轮 B/D/盲区栈增量，追加同文件）
  3. 检查清单 CoT 重蒸馏（checklist_cot_wave.jsonl，assistant 演示固定清单）
  4. 证据消费裁决演示（evidence_adjudication_demos.jsonl——裁决格式，
     与 triage 同走"保留原样"通道，不做语言标记断言）
  5. triage 裁决样本（24）

断言门与泄漏门同 v1（七字段/方向/CWE 格式/行号范围/Jaccard≥0.3 或包含度≥0.5）。
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
CHECKLIST = PROJECT / "experiments/exp_06_finetune/corpus/checklist_cot_wave.jsonl"
EVIDENCE = PROJECT / "experiments/exp_06_finetune/corpus/evidence_adjudication_demos.jsonl"
TRIAGE = PROJECT / "experiments/exp_06_finetune/data/supplement_alpha05_triage.jsonl"
OUT = PROJECT / "experiments/exp_06_finetune/data/final_train_chatml_alpha06_v2.jsonl"
REPORT = PROJECT / "experiments/exp_06_finetune/data/build_alpha06_v2_report.md"

CANONICAL = ["has_vulnerability", "vulnerability_type", "risk_level",
             "source", "sink", "explanation", "fix_suggestion"]
STRONG_DEFENSE = re.compile(r"参数化|白名单|转义|escape|占位符|\?\"|\?'|%s|autoescape|prepareStatement|placeholder", re.I)
WEAK_DEFENSE = re.compile(r"黑名单|正则(?!.*有效)|re\.(?:search|match|sub)|\.replace\(|过滤")


def reorder_json(text: str):
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.S)
    if not m:
        return text, False
    try:
        obj = json.loads(m.group(1))
    except json.JSONDecodeError:
        return text, False
    if "has_vulnerability" not in obj:
        return text, False
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


def load_jsonl(path: Path):
    for line in path.read_text().splitlines():
        if line.strip():
            yield json.loads(line)


def main():
    stats = {"old_in": 0, "drop_nolang": 0, "drop_weak_defense": 0,
             "distill_in": 0, "wave2_in": 0, "checklist_in": 0,
             "evidence_in": 0, "triage_in": 0, "final": 0}
    merged = []

    # ---------- 1) 旧数据清洗 ----------
    for r in load_jsonl(OLD_DATA):
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
            if WEAK_DEFENSE.search(reason_part) and not STRONG_DEFENSE.search(reason_part):
                stats["drop_weak_defense"] += 1
                continue
        merged.append(("old", r))

    # 扫描类统一 system + 七字段重排
    def process_scan_record(r):
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
        r2, err = process_scan_record(r)
        if err:
            print(f"[跳过 {tag}] {r['messages'][1]['content'][:40]}...: {err}")
            continue
        processed.append((tag, r2))
    merged = processed

    # ---------- 2/3) 各蒸馏源 ----------
    for path, tag, stat_key in ((DISTILL, "distill", "distill_in"),
                                (WAVE2, "wave2", "wave2_in"),
                                (CHECKLIST, "checklist", "checklist_in")):
        if not path.exists():
            print(f"[警告] 缺文件 {path.name}")
            continue
        for r in load_jsonl(path):
            stats[stat_key] += 1
            r2, err = process_scan_record(r)
            if err:
                seed = (r.get("meta") or {}).get("seed_file") or \
                       (r.get("meta") or {}).get("task_key") or "?"
                print(f"[跳过 {tag}] {seed}: {err}")
                continue
            merged.append((tag, r2))

    # ---------- 4) 证据消费演示 + triage：保留原样 ----------
    for r in load_jsonl(EVIDENCE):
        stats["evidence_in"] += 1
        merged.append(("evidence", r))
    for r in load_jsonl(TRIAGE):
        stats["triage_in"] += 1
        merged.append(("triage", r))

    # ---------- 5) 全量断言 ----------
    errors = []
    final_records = []
    code_seen = set()
    for idx, (tag, r) in enumerate(merged):
        msgs = r["messages"]
        if len(msgs) != 3 or [m["role"] for m in msgs] != ["system", "user", "assistant"]:
            errors.append(f"#{idx}[{tag}] 结构错误")
            continue
        keep_as_is = tag in ("triage", "evidence")
        user_c = msgs[1]["content"]
        asst_c = msgs[2]["content"]
        if not keep_as_is and lang_of(user_c) is None:
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
        if not keep_as_is:
            hv = obj.get("has_vulnerability")
            if not isinstance(hv, bool):
                errors.append(f"#{idx}[{tag}] has_vulnerability 非布尔")
                continue
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
            cm = re.search(r"```[\w+-]*\n(.*?)\n```", user_c, re.S)
            code_body = cm.group(1) if cm else user_c
            n_lines = code_body.count("\n") + 1
            bad_anchor = [int(n) for n in set(re.findall(
                r"line (\d+)", json.dumps(obj, ensure_ascii=False)))
                if not (1 <= int(n) <= n_lines)]
            if bad_anchor:
                errors.append(f"#{idx}[{tag}] 行号越界 {bad_anchor[:3]}")
                continue
        else:
            # 裁决/证据演示：至少要求结论 JSON 可解析且方向字段存在
            if "is_confirmed" not in obj and "has_vulnerability" not in obj:
                errors.append(f"#{idx}[{tag}] 结论缺判定字段")
                continue
        h = hashlib.md5((user_c[-2000:] + asst_c[-500:]).encode()).hexdigest()
        if h in code_seen:
            continue
        code_seen.add(h)
        final_records.append(r)
    stats["final"] = len(final_records)

    # ---------- 6) 泄漏门 ----------
    testsets = {}
    for f in (PROJECT / "experiments/exp_04_hard_samples/samples").glob("*"):
        if f.suffix in (".py", ".java", ".js", ".php", ".go", ".ts"):
            testsets[f"87seg/{f.name}"] = f.read_text(errors="replace")
    for f in (PROJECT / "experiments/exp_06_finetune/testset_cve_fix").glob("cve_fix_*"):
        if f.is_file():
            testsets[f"cve20/{f.name}"] = f.read_text(errors="replace")
    rd = PROJECT / "experiments/exp_06_finetune/corpus/rolling_dev"
    if rd.exists():
        for f in rd.glob("corpus_*"):
            if f.is_file():
                testsets[f"rollingdev/{f.name}"] = f.read_text(errors="replace")
    rsd = PROJECT / "experiments/exp_06_finetune/corpus/rolling_dev_safe"
    if rsd.exists():
        for f in rsd.glob("corpus_*"):
            if f.is_file():
                testsets[f"realsafe/{f.name}"] = f.read_text(errors="replace")
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
        if best_j >= 0.3 or best_c >= 0.5:
            leaks.append({"index": i, "file": best_k,
                          "jaccard": round(best_j, 3), "containment": round(best_c, 3)})
    leak_idx = {x["index"] for x in leaks}
    final_records = [r for i, r in enumerate(final_records) if i not in leak_idx]
    stats["final"] = len(final_records)

    # ---------- 输出 ----------
    with open(OUT, "w", encoding="utf-8") as f:
        for r in final_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    src_dist = collections.Counter(tag for tag, _ in [(t, r) for t, r in merged]) \
        if False else {}
    lines = [
        "# alpha06-v2 训练集构建报告\n",
        f"- 输入：旧 {stats['old_in']}（剔无语言 {stats['drop_nolang']} / "
        f"弱防御理由 {stats['drop_weak_defense']}）| wave1 蒸馏 {stats['distill_in']} | "
        f"wave2 变体 {stats['wave2_in']} | **清单 CoT {stats['checklist_in']}** | ",
        f"  **证据消费演示 {stats['evidence_in']}** | triage {stats['triage_in']}",
        f"- 泄漏门剔除（J≥0.3 或 C≥0.5，新增 realsafe 对照）: {len(leaks)}",
        f"- 断言错误：{len(errors)}（全部阻断不入集）",
        f"- **最终：{stats['final']} 条** → `{OUT.name}`",
        "",
    ]
    if leaks:
        lines += ["## 泄漏明细（前30）"]
        for x in leaks[:30]:
            lines.append(f"- #{x['index']} vs {x['file']} J={x['jaccard']} C={x['containment']}")
    if errors:
        lines += ["", "## 断言错误样例（前30）", *[f"- {e}" for e in errors[:30]]]
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"报告: {REPORT}")


if __name__ == "__main__":
    import collections  # noqa: F401 预留分布统计
    main()
