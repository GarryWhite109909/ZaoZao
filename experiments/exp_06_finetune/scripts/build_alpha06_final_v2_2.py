#!/usr/bin/env python3
"""构建 alpha06-v2.2 训练集（final_train_chatml_alpha06_v2_2.jsonl）。

基于 build_alpha06_final_v2_1.py（v2.1 冻结文件与其脚本保持不动），在其基础上并入
两个针对弱点挖掘报告（2026-08-24）根因的定向修复数据源：

  D. 污点边界演示（taint_boundary_wave.jsonl，教师蒸馏）——对应最大 FN 根因
     "库代码/间接输入盲区"（25 条 FN 中 ~11 条）：F1 库函数参数 / F2 文件协议内容 /
     F3 框架回调三形态 × vuln/safe 双方向，教"函数参数即污点边界"；
  E. 黑名单绕过 minimal pair（blacklist_bypass_pairs.jsonl，确定性手写 12 对）——
     对应根因 3"净化过度信任"与 FP 第一根因"防御未识别"（FP 复核 12/25）：
     弱防御可绕过演示 + 强防御覆盖面论证，正反成对。

其余管道（类型白名单改写、none 统一小写、清洗、断言门、泄漏门、去重、长度守门
TRAIN_MAX_LEN=12288 与 train_qlora_cloud.py 默认对齐）与 v2.1 完全一致。
"""
import hashlib
import json
import re
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))
from graduation_project.prompts import ALPHA05_PROMPT
from graduation_project.cwe_normalizer import normalize_cwe_label

_OLD_CANDIDATES = [
    Path("/home/zane/下载/final_train_chatml_alpha05.jsonl"),
    Path("D:/code/yunduan/final_train_chatml_alpha05.jsonl"),
    PROJECT / "experiments/exp_06_finetune/data/final_train_chatml_alpha05.jsonl",
]
OLD_DATA = next((p for p in _OLD_CANDIDATES if p.exists()), _OLD_CANDIDATES[0])
DISTILL = PROJECT / "experiments/exp_06_finetune/corpus/distill_alpha_pairs.jsonl"
WAVE2 = PROJECT / "experiments/exp_06_finetune/corpus/distill_variants_wave2.jsonl"
CHECKLIST = PROJECT / "experiments/exp_06_finetune/corpus/checklist_cot_wave.jsonl"
EVIDENCE = PROJECT / "experiments/exp_06_finetune/corpus/evidence_adjudication_demos.jsonl"
TRIAGE = PROJECT / "experiments/exp_06_finetune/data/supplement_alpha05_triage.jsonl"
TAINT = PROJECT / "experiments/exp_06_finetune/corpus/taint_boundary_wave.jsonl"
BLACKLIST = PROJECT / "experiments/exp_06_finetune/corpus/blacklist_bypass_pairs.jsonl"
OUT = PROJECT / "experiments/exp_06_finetune/data/final_train_chatml_alpha06_v2_2.jsonl"
OVERFLOW = PROJECT / "experiments/exp_06_finetune/data/final_train_chatml_alpha06_v2_2_long_overflow.jsonl"
REPORT = PROJECT / "experiments/exp_06_finetune/data/build_alpha06_v2_2_report.md"
TRAIN_MAX_LEN = 12288  # 与 train_qlora_cloud.py --max-seq-length 默认值保持一致

CANONICAL = ["has_vulnerability", "vulnerability_type", "risk_level",
             "source", "sink", "explanation", "fix_suggestion"]
STRONG_DEFENSE = re.compile(r"参数化|白名单|转义|escape|占位符|\?\"|\?'|%s|autoescape|prepareStatement|placeholder", re.I)
WEAK_DEFENSE = re.compile(r"黑名单|正则(?!.*有效)|re\.(?:search|match|sub)|\.replace\(|过滤")

# 仅放行人工审核过的映射（同 v2.1，复用其复核结论）
ALLOWED_REWRITES = {("77", "78"), ("94", "917"), ("94", "1336"), ("1336", "78")}


def fix_vuln_type(vt: str) -> str:
    fixed = normalize_cwe_label(vt)
    o = re.match(r"CWE-(\d+)", vt)
    n = re.match(r"CWE-(\d+)", fixed)
    if not (o and n) or o.group(1) == n.group(1):
        return vt
    if (o.group(1), n.group(1)) in ALLOWED_REWRITES:
        return fixed
    TYPE_REWRITE_HELD.append((vt, fixed))
    return vt


TYPE_REWRITE_HELD = []
NORMALIZE_STATS = {"type_rewritten": 0, "none_coerced": 0}


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
    hv = obj.get("has_vulnerability")
    vt = obj.get("vulnerability_type")
    if hv is True and isinstance(vt, str) and vt.strip():
        new_vt = fix_vuln_type(vt)
        if new_vt != vt:
            NORMALIZE_STATS["type_rewritten"] += 1
            obj["vulnerability_type"] = new_vt
    elif hv is False:
        if isinstance(vt, str) and vt != "none":
            NORMALIZE_STATS["none_coerced"] += 1
        obj["vulnerability_type"] = "none"
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
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield json.loads(line)


def main():
    stats = {"old_in": 0, "drop_nolang": 0, "drop_weak_defense": 0,
             "distill_in": 0, "wave2_in": 0, "checklist_in": 0,
             "evidence_in": 0, "triage_in": 0, "taint_in": 0, "blacklist_in": 0,
             "final": 0}
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

    # 扫描类统一 system + 七字段重排（含类型规范化）
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

    # ---------- 2/3) 各蒸馏源（含 v2.2 新增两个） ----------
    for path, tag, stat_key in (
            (DISTILL, "distill", "distill_in"),
            (WAVE2, "wave2", "wave2_in"),
            (CHECKLIST, "checklist", "checklist_in"),
            (TAINT, "taint", "taint_in"),
            (BLACKLIST, "blacklist", "blacklist_in")):
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
    final_tags = []
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
            if not hv and str(vt).lower() != "none":
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
        final_tags.append(tag)
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
    kept = [(t, r) for i, (t, r) in enumerate(zip(final_tags, final_records))
            if i not in leak_idx]
    final_tags = [t for t, _ in kept]
    final_records = [r for _, r in kept]
    stats["final"] = len(final_records)

    # ---------- 7) 长度守门 ----------
    tok = None
    try:
        from tokenizers import Tokenizer
        tok_path = PROJECT / "experiments/exp_06_finetune/cloud_train/tokenizer.json"
        if tok_path.exists():
            tok = Tokenizer.from_file(str(tok_path))
    except Exception:
        tok = None
    overflow_rows = []
    if tok is not None:
        kept2 = []
        for tag, r in zip(final_tags, final_records):
            n_tok = len(tok.encode("".join(m["content"] for m in r["messages"])).ids)
            if n_tok > TRAIN_MAX_LEN:
                overflow_rows.append((tag, n_tok, r))
            else:
                kept2.append((tag, r))
        before = len(final_records)
        final_tags = [t for t, _ in kept2]
        final_records = [r for _, r in kept2]
        stats["overflow_dropped"] = before - len(final_records)
    else:
        stats["overflow_dropped"] = 0
    stats["final"] = len(final_records)

    # ---------- 输出 ----------
    with open(OUT, "w", encoding="utf-8") as f:
        for r in final_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(OVERFLOW, "w", encoding="utf-8") as f:
        for tag, n_tok, r in overflow_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    lines = [
        "# alpha06-v2.2 训练集构建报告\n",
        f"- 输入：旧 {stats['old_in']}（剔无语言 {stats['drop_nolang']} / "
        f"弱防御理由 {stats['drop_weak_defense']}）| wave1 蒸馏 {stats['distill_in']} | "
        f"wave2 变体 {stats['wave2_in']} | 清单 CoT {stats['checklist_in']} | ",
        f"  证据消费演示 {stats['evidence_in']} | triage {stats['triage_in']}",
        f"- **v2.2 新增：污点边界演示 {stats['taint_in']}（库参数/文件协议/回调三形态 × vuln/safe）"
        f"| 黑名单绕过 minimal pair {stats['blacklist_in']}（12 对）**",
        f"- 类型编号改写 {NORMALIZE_STATS['type_rewritten']} 条（白名单映射）；"
        f"安全侧 none 统一小写 {NORMALIZE_STATS['none_coerced']} 条",
        f"- 泄漏门剔除（J≥0.3 或 C≥0.5）: {len(leaks)}",
        f"- 超长分流（>{TRAIN_MAX_LEN} token）: {stats.get('overflow_dropped', 0)} 条 → `{OVERFLOW.name}`",
        f"- 断言错误：{len(errors)}（全部阻断不入集）",
        f"- **最终：{stats['final']} 条** → `{OUT.name}`",
        "",
    ]
    if overflow_rows:
        import collections as _c2
        ov_by = _c2.Counter(t for t, _n, _r in overflow_rows)
        lines.append("  超长样本来源：" + "、".join(f"{k} {v}" for k, v in ov_by.most_common()) + "\n")
    if TYPE_REWRITE_HELD:
        held = sorted(set(TYPE_REWRITE_HELD))
        lines += ["## 编号改动未放行清单（人工复核用）"]
        lines += [f"- {a}  →  {b}" for a, b in held]
    if leaks:
        lines += ["## 泄漏明细（前30）"]
        for x in leaks[:30]:
            lines.append(f"- #{x['index']} vs {x['file']} J={x['jaccard']} C={x['containment']}")
    if errors:
        import collections as _c
        by_tag = _c.Counter(e.split("[")[1].split("]")[0] for e in errors)
        lines += ["", f"## 断言错误分布（共 {len(errors)}）",
                  *[f"- {k}: {v}" for k, v in by_tag.most_common()],
                  "", "### 样例（前30）",
                  *[f"- {e}" for e in errors[:30]]]
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"报告: {REPORT}")


if __name__ == "__main__":
    main()
