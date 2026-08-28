#!/usr/bin/env python3
"""增量构建 alpha06-v2.6（v2.5 基底 + 本轮 BigModel 教师增量）。

设计约束（2026-08-27 夜，赶时间版）：
- 以 data/final_train_chatml_alpha06_v2_5.jsonl 为基底原样保留——
  v2.2~v2.5 会话的全部修复层（指纹替换基集/冲突对剔除/14 污染删除/96 修复/
  risk_level 归一）一字不动；
- 只把本轮蒸馏增量并入：checklist_cot_wave / distill_variants_wave2 中
  user 全文不存在于基底的记录，过与 v2.1 相同的断言门 + 泄漏门 + 尾哈希去重；
- 安全侧判定字段统一小写 none（trust 对 "None" 的历史坑在门内就地修正文本）。
"""
import hashlib, json, re, sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
BASE_DIR = PROJECT / "experiments/exp_06_finetune"
sys.path.insert(0, str(PROJECT))
from graduation_project.prompts import ALPHA05_PROMPT
from graduation_project.cwe_normalizer import normalize_cwe_label

BASE = BASE_DIR / "data/final_train_chatml_alpha06_v2_5.jsonl"
OUT = BASE_DIR / "data/final_train_chatml_alpha06_v2_7.jsonl"
REPORT = BASE_DIR / "data/build_alpha06_v2_7_report.md"
SOURCES = {
    "checklist": BASE_DIR / "corpus/checklist_cot_wave.jsonl",
    "wave2": BASE_DIR / "corpus/distill_variants_wave2.jsonl",
}
CANONICAL = ["has_vulnerability", "vulnerability_type", "risk_level",
             "source", "sink", "explanation", "fix_suggestion"]


def load(p):
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def u_of(r): return next(m["content"] for m in r["messages"] if m["role"] == "user")
def a_of(r): return next(m["content"] for m in r["messages"] if m["role"] == "assistant")
def tail_h(r): return hashlib.md5((u_of(r)[-2000:] + a_of(r)[-500:]).encode()).hexdigest()


def norm_lines(code):
    out = set()
    for ln in code.splitlines():
        s = ln.strip()
        if not s or s.startswith(("#", "//")):
            continue
        s = re.sub(r"\s+", " ", s).lower()
        if len(s) >= 8:
            out.add(s)
    return out


def normalize_assistant(rec):
    """七字段重排 + 类型白名单改写 + 安全体 none 统一；失败返回 None。"""
    msgs = rec["messages"]
    msgs[0]["content"] = ALPHA05_PROMPT
    text = a_of(rec)
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.S)
    if not m:
        return None
    try:
        obj = json.loads(m.group(1))
    except json.JSONDecodeError:
        return None
    if "has_vulnerability" not in obj:
        return None
    hv = obj.get("has_vulnerability")
    vt = obj.get("vulnerability_type")
    if hv is True:
        if not isinstance(vt, str) or not str(vt).startswith("CWE-"):
            return None
        fixed = normalize_cwe_label(vt)
        o, n = re.match(r"CWE-(\d+)", vt), re.match(r"CWE-(\d+)", fixed or "")
        if fixed != vt and (not n or not o or o.group(1) == n.group(1)):
            obj["vulnerability_type"] = fixed
    else:
        obj["vulnerability_type"] = "none"
    ordered = {k: obj[k] for k in CANONICAL if k in obj}
    for k, v in obj.items():
        if k not in ordered:
            ordered[k] = v
    new_text = text[:m.start()] + "```json\n" + \
        json.dumps(ordered, ensure_ascii=False) + "\n```" + text[m.end():]
    msgs[2]["content"] = new_text
    return obj


def main():
    base = load(BASE)
    base_users = {u_of(r) for r in base}
    base_tails = {tail_h(r) for r in base}

    testsets = {}
    for f in (PROJECT / "experiments/exp_04_hard_samples/samples").glob("*"):
        if f.suffix in (".py", ".java", ".js", ".php", ".go", ".ts"):
            testsets[f"87seg/{f.name}"] = f.read_text(errors="replace")
    for f in (BASE_DIR / "testset_cve_fix").glob("cve_fix_*"):
        if f.is_file():
            testsets[f"cve20/{f.name}"] = f.read_text(errors="replace")
    rd = BASE_DIR / "corpus/rolling_dev"
    if rd.exists():
        testsets.update({f"rdev/{f.name}": f.read_text(errors="replace")
                         for f in rd.glob("corpus_*") if f.is_file()})
    rsd = BASE_DIR / "corpus/rolling_dev_safe"
    if rsd.exists():
        testsets.update({f"realsafe/{f.name}": f.read_text(errors="replace")
                         for f in rsd.glob("corpus_*") if f.is_file()})
    tn = {k: norm_lines(v) for k, v in testsets.items()}

    stats = {"cand": 0, "dup_base": 0, "assert_fail": 0, "leak": 0,
             "dup_self": 0, "added": 0}
    drop_notes = []
    added = []
    seen_users = set()
    seen_tails = set()
    for tag, path in SOURCES.items():
        for r in load(path):
            stats["cand"] += 1
            u = u_of(r)
            h = tail_h(r)
            if u in base_users:
                stats["dup_base"] += 1
                continue
            if u in seen_users or h in base_tails or h in seen_tails:
                stats["dup_self"] += 1
                continue
            obj = normalize_assistant(r)
            if obj is None or len(r["messages"]) != 3:
                stats["assert_fail"] += 1
                if len(drop_notes) < 40:
                    seed = (r.get("meta") or {}).get("task_key") or "?"
                    drop_notes.append(f"[{tag}] 断言不过: {seed}")
                continue
            cm = re.search(r"```[\w+-]*\n(.*?)\n```", u, re.S)
            code_body = cm.group(1) if cm else u
            n_lines = code_body.count("\n") + 1
            bad = [int(n) for n in set(re.findall(r"line (\d+)",
                   json.dumps(obj, ensure_ascii=False))) if not (1 <= int(n) <= n_lines)]
            if bad:
                stats["assert_fail"] += 1
                continue
            norm = norm_lines(u)
            # 定罪（leak_verdict）与诊断（最像文件）分离：2026-08-27 首版把
            # argmax 赋给 leak_hit，导致与评测文件共享哪怕一行规范化代码的
            # 候选全部误判（97 条"泄漏"里 95 条冤案，重算后真泄漏仅 2 条）
            leak_verdict = ""
            best_k, best_j = "", 0.0
            for k, t in tn.items():
                j = len(norm & t) / len(norm | t) if norm and t else 0.0
                c = len(norm & t) / min(len(norm), len(t)) if norm and t else 0.0
                if j > best_j:
                    best_j, best_k = j, k
                if j >= 0.3 or c >= 0.5:
                    leak_verdict = f"{k}(J={j:.3f},C={c:.3f})"
                    break
            if leak_verdict:
                stats["leak"] += 1
                if len(drop_notes) < 40:
                    drop_notes.append(f"[{tag}] 泄漏 {leak_verdict}（次近 {best_k} J={best_j:.3f}）")
                continue
            added.append((tag, r))
            seen_users.add(u)
            seen_tails.add(h)
            stats["added"] += 1

    final = base + [r for _, r in added]
    with open(OUT, "w", encoding="utf-8") as f:
        for r in final:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    import collections as _c
    by_tag = _c.Counter(t for t, _ in added)
    by_kind = _c.Counter(((r.get("meta") or {}).get("kind") or "-")
                         for _, r in added if r.get("meta"))
    lines = [
        "# alpha06-v2.7 增量构建报告\n",
        f"- 基底：final_train_chatml_alpha06_v2_5.jsonl（{len(base)} 条，原样保留全部修复层）",
        f"- 增量候选 {stats['cand']} → 并入 **{stats['added']}** "
        f"（基底重复 {stats['dup_base']} | 自身/尾哈希重复 {stats['dup_self']} | "
        f"断言拦 {stats['assert_fail']} | 泄漏拦 {stats['leak']}）",
        f"- 按来源：{dict(by_tag)}",
        f"- 按 kind：{dict(by_kind)}",
        f"- **最终：{len(final)} 条** → `{OUT.name}`",
        "",
    ]
    if drop_notes:
        lines += ["## 拦截明细（前40）", *[f"- {x}" for x in drop_notes]]
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
