#!/usr/bin/env python3
"""补丁驱动词表挖掘：从 train_pool 的修复 diff 反推各 CWE×语言 的漏洞/防御 API 形态。

原理（泛化导向，见 docs/弱点挖掘报告 第九节纪律）：
  - 删除行(-) = 漏洞侧代码形态（污点 API、缺失校验的上下文）
  - 新增行(+) = 防御形态（参数化/白名单/校验的写法）
  - 对每个 CWE 族聚合"API 调用形状"（剥掉字符串字面量与变量名后的调用骨架），
    产出人工筛选新 semgrep/taint 规则用的素材，而不是直接产出规则——
    规则仍须语义命名并登记 P6 表。

输出：
  results/patch_vocab_material.json   结构化素材（每 CWE×语言 top 形状 + 例行）
  results/patch_vocab_material.md     人读版报告
"""
import collections
import json
import re
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
CORPUS = PROJECT / "experiments/exp_06_finetune/corpus"

CALL_RE = re.compile(r"([\w.$\->:\[\]]+)\s*\(")


def normalize(line: str) -> str:
    """剥字符串字面量/数字，压缩空白 → 只留代码骨架。"""
    s = re.sub(r'"[^"]*"|\'[^\']*\'|`[^`]*`', '""', line)
    s = re.sub(r"\b\d+\b", "N", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:160]


def api_shapes(line: str) -> list[str]:
    """提取一行里的调用骨架：receiver.func( → 小写化排序键。"""
    out = []
    for m in CALL_RE.finditer(line):
        shape = m.group(1)
        # 去掉纯小写局部变量的前缀链中明显的标识符噪声（保留 . 方法名）
        parts = shape.split(".")
        tail = ".".join(p for p in parts[-2:]) if len(parts) > 1 else parts[0]
        if len(tail) >= 3:
            out.append(tail.lower())
    return out


def parse_patch(text: str):
    """解析无头 hunk 补丁 → (删除行列表, 新增行列表, hunk 上下文函数名)。"""
    dels, adds, ctx_funcs = [], [], []
    for m in re.finditer(r"^@@.*?@@\s*(.*)$", text, re.M):
        if m.group(1).strip():
            ctx_funcs.append(m.group(1).strip()[:80])
    for ln in text.splitlines():
        if ln.startswith("---") or ln.startswith("+++"):
            continue
        if ln.startswith("-") and not ln.startswith("---"):
            dels.append(ln[1:])
        elif ln.startswith("+") and not ln.startswith("+++"):
            adds.append(ln[1:])
    return dels, adds, ctx_funcs


def main():
    manifest = json.loads((CORPUS / "train_pool" / "manifest.json").read_text())
    # bucket[(cwe, lang)] = {"del_shapes": Counter, "add_shapes": Counter,
    #                        "del_lines": [(file, line)], "add_lines": [...], "ctx": Counter}
    buckets = collections.defaultdict(
        lambda: {"del_shapes": collections.Counter(), "add_shapes": collections.Counter(),
                 "del_lines": [], "add_lines": [], "ctx": collections.Counter()})
    n_ok = n_skip = 0
    for s in manifest["samples"]:
        p = CORPUS / (s.get("patch_file") or "")
        if not p.exists():
            n_skip += 1
            continue
        text = p.read_text(errors="replace")
        dels, adds, ctxs = parse_patch(text)
        key = (s.get("expected_cwe", "?"), s.get("language", "?"))
        b = buckets[key]
        for ln in dels:
            norm = normalize(ln)
            if len(norm) < 8:
                continue
            b["del_lines"].append((s["file"], norm))
            for sh in api_shapes(ln):
                b["del_shapes"][sh] += 1
        for ln in adds:
            norm = normalize(ln)
            if len(norm) < 8:
                continue
            b["add_lines"].append((s["file"], norm))
            for sh in api_shapes(ln):
                b["add_shapes"][sh] += 1
        for c in ctxs:
            b["ctx"][c] += 1
        n_ok += 1

    # 汇总：每桶取 top 形状；过滤过于通用的（if/for/return/print 等）
    GENERIC = {"if", "for", "while", "return", "print", "switch", "else", "def",
               "func", "catch", "try", "new", "throw", "len(", "and", "or"}
    report = {}
    for (cwe, lang), b in buckets.items():
        if not b["del_shapes"] and not b["add_shapes"]:
            continue
        ds = [(k, v) for k, v in b["del_shapes"].most_common(25) if k not in GENERIC]
        as_ = [(k, v) for k, v in b["add_shapes"].most_common(25) if k not in GENERIC]
        # 挑"防御特征形状"：新增里出现、删除里没有或稀少
        del_set = dict(ds)
        defense_only = [(k, v) for k, v in as_ if del_set.get(k, 0) < max(1, v // 3)][:12]
        report[f"{cwe}|{lang}"] = {
            "n_samples_del": len(b["del_lines"]), "n_samples_add": len(b["add_lines"]),
            "top_vuln_shapes": ds[:15], "top_defense_shapes": as_[:15],
            "defense_only_shapes": defense_only,
            "example_vuln_lines": b["del_lines"][:6],
            "example_defense_lines": b["add_lines"][:6],
            "common_contexts": b["ctx"].most_common(5),
        }

    out_json = PROJECT / "experiments/exp_06_finetune/results/patch_vocab_material.json"
    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=1))

    md = ["# 补丁驱动词表素材（train_pool 291 条修复 diff）\n",
          f"- 解析成功 {n_ok} 条 / 跳过 {n_skip} 条\n",
          "> 用法：每格 top_vuln_shapes 是该 CWE×语言 真实漏洞代码的高频调用骨架（新规则候选），",
          "> defense_only_shapes 是只在防御侧出现的骨架（白名单/签名表候选）。\n"]
    for key, r in sorted(report.items(), key=lambda kv: -kv[1]["n_samples_del"])[:24]:
        cwe, lang = key.split("|")
        md.append(f"\n## {cwe} · {lang}\n")
        md.append(f"- 漏洞侧行样本 {r['n_samples_del']} / 防御侧行样本 {r['n_samples_add']}")
        md.append(f"- top 漏洞形状: {[k for k, _ in r['top_vuln_shapes'][:10]]}")
        md.append(f"- 仅防御侧形状: {[k for k, _ in r['defense_only_shapes'][:8]]}")
        if r["example_vuln_lines"]:
            md.append("- 例:")
            for f_, ln in r["example_vuln_lines"][:3]:
                md.append(f"  - `{f_}`: `{ln[:110]}`")
    (PROJECT / "experiments/exp_06_finetune/results/patch_vocab_material.md").write_text(
        "\n".join(md), encoding="utf-8")
    print(f"桶数 {len(report)} | 解析 {n_ok} 跳过 {n_skip}")
    print(f"输出: {out_json.name} + patch_vocab_material.md")


if __name__ == "__main__":
    main()
