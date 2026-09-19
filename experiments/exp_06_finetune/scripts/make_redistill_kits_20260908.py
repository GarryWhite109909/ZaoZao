# -*- coding: utf-8 -*-
"""敷衍修复·重蒸馏 kit 生成器（20260908）。

输入：audit/敷衍修复队列_20260908.jsonl（排除自修完成的 638/886/2108/1868）。
输出：corpus/redistill_wave/kits/pack_NNN.txt（≤40KB，多样本/包）
      corpus/redistill_wave/manifest_PRIVATE.json
      corpus/redistill_wave/index.md

重蒸馏模式：给代码 + 原分析（仅供对照、禁止沿用结论）+ 重写模板，
教师仅基于代码重写完整分析。verdict 翻转不拦截（可能原判就错），verify 打 FLAG 人工复核。
"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(Path(__file__).resolve().parents[1])
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
QUEUE = BASE / "audit/敷衍修复队列_20260908.jsonl"
OUT = BASE / "corpus/redistill_wave"
LIMIT = 40 * 1024
SELF_FIXED = {638, 886, 2108, 1868}

HEAD = (
    "【蒸馏批次 redistill | 样本数={n}】\n\n"
)

BLOCK_TPL = (
    "\n### id=redistill-line-{line} lang={lang} flags=[{flags}]\n"
    "#### 代码（{clen} 行）\n```{lang}\n{code}\n```\n"
)


def main():
    import re
    queue = [json.loads(l) for l in QUEUE.open(encoding="utf-8") if l.strip()]
    queue = [q for q in queue if q["line"] not in SELF_FIXED]
    rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
    FENCE = re.compile(r"```[a-zA-Z0-9+#]*\n(.*?)```", re.S)

    items = []
    for q in queue:
        row = rows[q["line"] - 1]
        code = "\n".join(FENCE.findall(row["messages"][1]["content"]))
        lang = (q.get("lang") or "text").lower()
        flags = ",".join(sorted({re.match(r"(R\d)", r).group(1) for r in q["reasons"] if re.match(r"(R\d)", r)}))
        items.append({
            "id": f"redistill-line-{q['line']}", "line": q["line"],
            "cwe": q["cwe"], "kind": q["kind"], "has_v": q["has_v"],
            "reasons": q["reasons"], "lang": lang,
            "code": code, "flags": flags,
            "block": BLOCK_TPL.format(line=q["line"], lang=lang, flags=flags,
                                      clen=len(code.splitlines()), code=code),
        })
    # 按体积升序装箱（贪心：每包 ≤ LIMIT 且 ≤10 条——教师单次回复长度有限，审计包 5 条/包的前车之鉴）
    items.sort(key=lambda x: len(x["block"]))
    packs, cur, cur_bytes = [], [], 0
    for it in items:
        b = len(it["block"].encode("utf-8"))
        if cur and (cur_bytes + b > LIMIT or len(cur) >= 10):
            packs.append(cur)
            cur, cur_bytes = [], 0
        cur.append(it)
        cur_bytes += b
    if cur:
        packs.append(cur)

    manifest = {}
    (OUT / "kits").mkdir(parents=True, exist_ok=True)
    for n, pack in enumerate(packs, 1):
        name = f"redistill_pack_{n:03d}"
        head = HEAD.format(n=len(pack))
        body = head + "\n".join(it["block"] for it in pack)
        assert len(body.encode("utf-8")) <= 48 * 1024, f"{name} 超限"
        (OUT / "kits" / f"{name}.txt").write_text(body, encoding="utf-8", newline="\n")
        for it in pack:
            manifest[it["id"]] = {"pack": name, "line": it["line"], "cwe": it["cwe"],
                                  "kind": it["kind"], "has_v_orig": it["has_v"],
                                  "lang": it["lang"], "reasons": it["reasons"],
                                  "code_lines": len(it["code"].splitlines())}
    (OUT / "manifest_PRIVATE.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"重蒸馏包 {len(packs)} 个（覆盖 {len(items)} 条，自修除外）")
    print("每包样本数: min", min(len(p) for p in packs), "max", max(len(p) for p in packs))
    print(f"→ {OUT/'kits'}")


if __name__ == "__main__":
    main()
