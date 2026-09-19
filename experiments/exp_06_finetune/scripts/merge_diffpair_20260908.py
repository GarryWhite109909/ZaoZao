# -*- coding: utf-8 -*-
"""差分对蒸馏：合并（PASS 对 → 训练行 staging）。

- 只取 verify PASS（无 flags）的对；FLAG 对不落库（人工/2v1 后手动放行）。
- JSON 结论块程序化构造（json.dumps），杜绝网页端转义风险。
- system = 全库唯一 stamp 版（corpus/diffpair_wave1/system_prompt_alpha05_stamped.txt）；
  user 格式对齐库内多数派（代码片段围栏 + "请先给出分析过程…"尾）。
- meta: kind=diffpair_pre/diffpair_post, cve, seed_file, pair_id, label_basis=patch。
- 产物：corpus/diffpair_wave1/merged_stage.jsonl —— **staging，不自动并入 v2_15**；
  入库需人工抽验 + G6 簇检查（脚本附带输出每个 seed 的在库化身计数）。
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(Path(__file__).resolve().parents[1])
WAVE = BASE / "corpus/diffpair_wave1"
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
LANG_NORM = {"javascript": "javascript", "python": "python", "php": "php", "go": "go",
             "java": "java", "typescript": "typescript"}


def build_row(system, lang, code, analysis, concl, meta):
    user = (f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```\n\n"
            "请先给出分析过程，然后在最后给出 JSON 结论。")
    asst = (f"{analysis.strip()}\n\n```json\n"
            + json.dumps(concl, ensure_ascii=False) + "\n```")
    return {"messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user},
                         {"role": "assistant", "content": asst}],
            "meta": meta}


def main():
    manifest = json.loads((WAVE / "manifest_PRIVATE.json").read_text(encoding="utf-8"))
    verify = [json.loads(l) for l in (WAVE / "verify_report.jsonl").open(encoding="utf-8") if l.strip()]
    system = (WAVE / "system_prompt_alpha05_stamped.txt").read_text(encoding="utf-8")

    # 在库化身计数（G6 参考）：seed 代码在 v2_15 的出现次数
    seed_names = {v["seed"] for v in manifest.values()}
    incarn = defaultdict(int)
    for line in DATA.open(encoding="utf-8"):
        if not any(s in line for s in seed_names):
            continue
        for s in seed_names:
            if s in line:
                incarn[s] += 1

    rows, report = [], []
    for v in verify:
        if v["flags"]:
            continue
        kid = v["kit"]
        meta = manifest[kid]
        parsed = {r["id"]: r for r in
                  (json.loads(l) for l in (WAVE / "parsed" / f"{kid}.jsonl").open(encoding="utf-8") if l.strip())}
        pre, post = parsed.get(f"{kid}-PRE"), parsed.get(f"{kid}-POST")
        if not pre or not post:
            continue

        def concl(rec, is_post):
            f = rec["fields"]
            c = {
                "has_vulnerability": f.get("has_vulnerability", "").strip().lower() == "true",
                "vulnerability_type": f.get("vulnerability_type", "").strip(),
                "risk_level": f.get("risk_level", "Medium").strip(),
                "source": f.get("source", "N/A").strip(),
                "sink": f.get("sink", "N/A").strip(),
                "explanation": f.get("explanation", "").strip(),
                "fix_suggestion": f.get("fix_suggestion", "no fix needed").strip(),
            }
            return c

        lang = (meta["language"] or "").lower()
        seed_path = BASE / "corpus/train_pool" / meta["seed"]
        pre_lines = seed_path.read_text(encoding="utf-8", errors="replace").splitlines()
        # post 代码 = seed + patch（由 kit 生成时的 same pipeline 重算，保证一致）
        sys.path.insert(0, str(BASE / "scripts"))
        from diffpair_patchlib import parse_patch, apply_patch
        patch_path = BASE / "corpus" / meta.get("_patch_file", f"patches/{meta['seed'].split('.')[0]}.patch")
        if not patch_path.exists():
            continue
        post_lines, _ = apply_patch(pre_lines, parse_patch(patch_path.read_text(encoding="utf-8", errors="replace")))

        common = {"cve": meta["cve"], "seed_file": meta["seed"], "pair_id": kid,
                  "label_basis": "patch", "incarn_in_train": incarn.get(meta["seed"], 0)}
        rows.append(build_row(system, lang, "\n".join(pre_lines),
                              pre["fields"].get("分析过程", ""), concl(pre, False),
                              {"kind": "diffpair_pre", **common}))
        concl_post = concl(post, True)
        if post["fields"].get("行级归因"):
            concl_post["explanation"] = (concl_post["explanation"]
                                         + " 行级归因：" + post["fields"]["行级归因"].strip())
        rows.append(build_row(system, lang, "\n".join(post_lines),
                              post["fields"].get("分析过程", ""), concl_post,
                              {"kind": "diffpair_post", **common}))
        report.append(f"{kid} ok (incarn={incarn.get(meta['seed'], 0)})")

    out = WAVE / "merged_stage.jsonl"
    with out.open("w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"staging 行数: {len(rows)}（=PASS 对数 ×2）→ {out}")
    multi = [r for r in report if "incarn=" in r and int(r.split("incarn=")[1].rstrip(")")) > 0]
    print(f"seed 已有在库化身的对: {len(multi)}（G6 簇配额检查项，入库前过目）")


if __name__ == "__main__":
    main()
