"""训练集形态 mining——泛化差距图谱（exp_08 工具层进化第二阶段）。

用户确立的战略（2026-08-31）：泛化性能 > 逐仓补规则。训练集 10021 条结构化
污点路径（source→sink→taint_path）是现成的"期望形态频谱"：

  1. 解析训练集全部样本的 taint_path / user 侧代码
  2. 提取 sink API 形态（变量名正则化 → 统一形态签名）
  3. 统计形态频次 → 与工具层 sink/source 覆盖求差集
  4. 差集按频次排序 = 泛化差距图谱：一条形态规则覆盖 N 个实例 + 未来同形态

产出：results/formal_spectrum_<ts>.json + 控制台 Top 表。零 GPU、纯文本解析。
"""
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
ROOT = HERE.parents[1]

TRAIN_FILES = [
    "experiments/exp_06_finetune/data/final_train_chatml_alpha06_v2_13.jsonl",
    "experiments/exp_06_finetune/cloud_train/final_train_chatml_alpha05.jsonl",
]


def normalize_form(text: str) -> str:
    """变量名/字面量正则化 → 可泛化的形态签名。"""
    t = text.strip()
    t = re.sub(r"'[^']*'", "'S'", t)
    t = re.sub(r'"[^"]*"', '"S"', t)
    t = re.sub(r"\b\d+\b", "N", t)
    for var in ("user_input", "userInput", "username", "password", "email",
                "search_term", "searchTerm", "comment", "name", "value",
                "data", "query", "id", "uid", "file", "content", "message",
                "input", "param", "request", "payload", "token", "url", "cmd"):
        t = re.sub(rf"\b{re.escape(var)}\b", "VAR", t, flags=re.IGNORECASE)
    t = re.sub(r"\s+", " ", t)
    return t[:120]


def extract_code(text: str) -> str:
    """取 user 侧最大代码围栏（```lang ... ```），并携带语言标签。"""
    blocks = re.findall(r"```(\w*)\r?\n(.*?)```", text, re.S)
    if not blocks:
        return ""
    lang, code = max(blocks, key=lambda b: len(b[1]))
    return f"__LANG__{lang}\n{code}"


SINK_SIGNATURES = [
    (r"\.execute\(", "89"), (r"cursor\.execute", "89"),
    (r"system\(", "78"), (r"popen\(", "78"),
    (r"subprocess\.\w+\(", "78"), (r"child_process", "78"),
    (r"\beval\(", "94"), (r"\bexec\(", "94/78"),
    (r"pickle\.loads\(", "502"), (r"yaml\.load\(", "502"),
    (r"unserialize\(", "502"), (r"readObject\(", "502"),
    (r"\.innerHTML\s*=", "79"), (r"document\.write", "79"),
    (r"render_template_string\(", "1336"),
    (r"\.from_string\(", "1336"),
    (r"redirect\(", "601"),
    (r"verify\s*=\s*False", "295/347"),
    (r"jwt\.decode\([^)]*verify\s*=\s*False", "347"),
    (r"libxml\w*\.parse\w*\(", "611"),
    (r"md5\(|sha1\(", "327"),
    (r"random\.(?:random|randint|choice)\(", "338"),
    (r"\.query\.filter\(", "89-orm"),
    (r"\.find\(\s*\{", "943-orm"),
    (r"os\.environ\.get\(", "312-src"),
    (r"request\.(?:args|form|json|files|data)", "SRC"),
]


def mine() -> dict:
    seen_forms = Counter()
    examples = defaultdict(list)
    n_samples = 0
    code_hits = 0

    for rel in TRAIN_FILES:
        p = ROOT / rel
        if not p.exists():
            print(f"[skip] {rel} 不存在")
            continue
        with open(p, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                n_samples += 1
                texts = []
                if isinstance(rec.get("messages"), list):
                    texts = [m.get("content", "") for m in rec["messages"]
                             if m.get("role") == "user"]
                elif rec.get("user"):
                    texts = [rec["user"]]
                meta = rec.get("meta") or rec
                taint_paths = meta.get("taint_path") or []
                if isinstance(taint_paths, str):
                    taint_paths = [taint_paths]
                for t in taint_paths:
                    if t and t != "N/A":
                        seen_forms[("TAINT_PATH", normalize_form(t))] += 1
                for text in texts:
                    code = extract_code(text)
                    if not code or len(code) < 40:
                        continue
                    code_hits += 1
                    # 语言标签：第一行 __LANG__xx（挖掘输出按语言分桶，供 sink 语言覆盖核对）
                    mlang = re.match(r"__LANG__(\w*)", code)
                    slang = (mlang.group(1) if mlang else "?").lower() or "?"
                    for i, ln in enumerate(code.splitlines(), 1):
                        if i == 1 and mlang and ln.startswith("__LANG__"):
                            continue
                        ln_s = ln.strip()
                        if not ln_s or ln_s.startswith(("#", "//", "*", "<!--")):
                            continue
                        for pat, cat in SINK_SIGNATURES:
                            if re.search(pat, ln_s):
                                form = normalize_form(ln_s)
                                key = (cat, form)
                                seen_forms[key] += 1
                                if len(examples[key]) < 2:
                                    examples[key].append(f"#{n_samples} L{i}")
                                break

    result = {
        "generated": time.strftime("%Y%m%d_%H%M%S"),
        "samples_parsed": n_samples,
        "code_fields": code_hits,
        "forms": [{"category": c, "form": f, "count": n,
                   "examples": examples.get((c, f), [])}
                  for (c, f), n in seen_forms.most_common()],
    }
    return result


def main() -> None:
    res = mine()
    print(f"解析样本 {res['samples_parsed']} 条（含代码字段 {res['code_fields']} 条）")
    print(f"形态签名总数: {len(res['forms'])}\n")

    by_cat = defaultdict(list)
    for f in res["forms"]:
        by_cat[f["category"]].append(f)
    for cat in sorted(by_cat, key=lambda c: -sum(f["count"] for f in by_cat[c])):
        rows = by_cat[cat][:8]
        total = sum(f["count"] for f in by_cat[cat])
        print(f"== {cat}（{total} 次）==")
        for f in rows:
            print(f"  {f['count']:5d}  {f['form'][:86]}")
        print()

    ts = time.strftime("%Y%m%d_%H%M%S")
    out = HERE / "results" / f"formal_spectrum_{ts}.json"
    out.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"图谱已写入: {out}")


if __name__ == "__main__":
    main()
