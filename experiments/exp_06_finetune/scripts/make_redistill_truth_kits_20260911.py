# -*- coding: utf-8 -*-
"""带真值重蒸馏投喂包生成器（20260911）——门 F 闭环的"错题回流"环节落地。

两类输入：
  G2 = results/_redistill_pack_20260911.jsonl（16 块人审冲突，R4 重构自洽推理）
  G3 = manifest 中 expected_present=false 且未被 G2 覆盖的负样本 id（R5 防御链核验，补门 E）

教师协议：teacher_prompt_session.md 类型三 redistill_truth（真值权威 > 独立结论；
凑不出真值 → disagree 回流人工，禁止硬凑）。

输出：
  corpus/diffpair_wave1/kits_redistill_truth/*.txt（≤48KB 网页投喂包）
  corpus/diffpair_wave1/index_redistill_truth.md（投喂索引）
  corpus/diffpair_wave1/results/_redistill_truth_ledger.json（台账：id→来源/真值/flags）
"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
CORPUS = BASE / "corpus"
WAVE = CORPUS / "diffpair_wave1"
RESULTS = WAVE / "results"
OUT = WAVE / "kits_redistill_truth"
OUT.mkdir(exist_ok=True)

LIMIT = 48 * 1024
LANG_TAG = {"JavaScript": "javascript", "Python": "python", "PHP": "php", "Go": "go",
            "Java": "java", "TypeScript": "typescript", "Ruby": "ruby", "C": "c",
            "C#": "csharp", "Kotlin": "kotlin", "Rust": "rust"}


def build_kit(sid, lang, flags, code, truth_hv, truth_cwe, note):
    hv = "true" if truth_hv else "false"
    cwe = truth_cwe or "none"
    return (
        f"【蒸馏批次 redistill_truth | 样本数=1】\n\n"
        f"### id={sid} lang={lang} flags={flags}\n"
        f"#### 代码\n```{lang}\n{code.rstrip()}\n```\n"
        f"#### 裁定真值\n"
        f"has_vulnerability: {hv}\n"
        f"cwe: {cwe}\n"
        f"note: {note}\n"
        f"（真值依据 = 人工读码 patch 语义裁定，判定权威高于你的独立结论；"
        f"若代码事实无法支撑真值，按协议输出 disagree 记录，禁止硬凑。）\n"
    )


def main():
    wave_manifest = json.loads((WAVE / "manifest_PRIVATE.json").read_text(encoding="utf-8"))
    packs = [json.loads(l) for l in
             (RESULTS / "_redistill_pack_20260911.jsonl").open(encoding="utf-8") if l.strip()]

    ledger, sizes, skipped = [], [], []
    made_ids = set()
    # ---------- G2：16 块人审冲突 ----------
    kid_count = {}
    for p in packs:
        kid8 = p["id"].replace("diffpair-corpus_", "")
        kid_count[kid8] = kid_count.get(kid8, 0) + 1
    for p in packs:
        kid8 = p["id"].replace("diffpair-corpus_", "")
        meta = wave_manifest.get(p["id"])
        lang = LANG_TAG.get(meta.get("language"), "text") if meta else "text"
        flags = ["R4"]
        if not p["truth_has_vulnerability"]:
            flags.append("R5")
        sid = f"redistill-{kid8}-A"
        if kid_count[kid8] > 1:  # 同 id 多块（00007 L56/L68）用 header_line 区分
            sid = f"redistill-{kid8}-A-L{p.get('header_line', 0)}"
        code = p["code_A"] if p.get("version") == "版本A" else p["code_B"]
        note = p.get("truth_note") or "人工读码裁定"
        if p.get("truth_uncertain"):
            note += "（裁定置信度一般，若发现更硬的代码证据以代码为准）"
        text = build_kit(sid, lang, "+".join(flags), code,
                         p["truth_has_vulnerability"], p["truth_cwe"], note)
        if len(text.encode("utf-8")) > LIMIT:
            skipped.append({"id": sid, "why": f"{len(text.encode('utf-8'))//1024}KB 超上限"})
            continue
        (OUT / f"{sid}.txt").write_text(text, encoding="utf-8", newline="\n")
        sizes.append((sid, len(text.encode("utf-8"))))
        made_ids.add(kid8)
        ledger.append({"id": sid, "source": "g2_redistill_pack", "orig_kit": p["id"],
                       "defect": p.get("defect"), "priority": p.get("priority"),
                       "truth_hv": p["truth_has_vulnerability"], "truth_cwe": p.get("truth_cwe"),
                       "flags": flags})

    # ---------- G3：负样本防御链核验（expected_present=false，未被 G2 覆盖） ----------
    for kid, meta in wave_manifest.items():
        if meta.get("expected_present") is not False:
            continue
        kid8 = kid.replace("diffpair-corpus_", "")
        if kid8 in made_ids:
            continue  # 已在 G2 覆盖（误报 5 条），避免重复投喂
        seed_path = CORPUS / "train_pool" / meta["seed"]
        if not seed_path.exists():
            skipped.append({"id": kid, "why": "seed 缺失"})
            continue
        code = seed_path.read_text(encoding="utf-8", errors="replace")
        lang = LANG_TAG.get(meta.get("language"), "text")
        sid = f"redistill-neg-{kid8}"
        text = build_kit(sid, lang, "R5", code, False, "none",
                         "人工读码裁定：无洞。分析必须逐段点名防御行号并论证为何有效/为何不可旁路。")
        if len(text.encode("utf-8")) > LIMIT:
            skipped.append({"id": sid, "why": f"{len(text.encode('utf-8'))//1024}KB 超上限"})
            continue
        (OUT / f"{sid}.txt").write_text(text, encoding="utf-8", newline="\n")
        sizes.append((sid, len(text.encode("utf-8"))))
        ledger.append({"id": sid, "source": "g3_manifest_negative", "orig_kit": kid,
                       "defect": "负样本缺防御证据（门E）", "priority": 2,
                       "truth_hv": False, "truth_cwe": None, "flags": ["R5"]})

    (RESULTS / "_redistill_truth_ledger.json").write_text(
        json.dumps({"made": ledger, "skipped": skipped}, ensure_ascii=False, indent=1),
        encoding="utf-8")

    # ---------- 投喂索引 ----------
    sizes.sort(key=lambda x: x[1])
    g2_n = sum(1 for x in ledger if x["source"] == "g2_redistill_pack")
    g3_n = sum(1 for x in ledger if x["source"] == "g3_manifest_negative")
    L = ["# 带真值重蒸馏投喂索引（2026-09-11，按字节升序）", "",
         f"- 会话协议：`teacher_prompt_session.md`（已含类型三 redistill_truth），一次一包",
         f"- 总 {len(ledger)} 包 = G2 人审冲突 {g2_n}（R4）+ G3 负样本防御链 {g3_n}（R5）"
         f"；跳过 {len(skipped)}", "",
         "| 顺序 | 包 | KB | 来源 | 缺陷类 | 真值 |", "|---|---|---|---|---|---|"]
    by_id = {x["id"]: x for x in ledger}
    for i, (sid, b) in enumerate(sizes, 1):
        e = by_id[sid]
        truth = ("有洞 " + (e["truth_cwe"] or "")) if e["truth_hv"] else "无洞"
        L.append(f"| {i} | {sid} | {b//1024} | {e['source'].split('_')[0]} | {e['defect']} | {truth} |")
    L.append("")
    L.append("回填：教师输出纯文本字段行 → 存 results/redistill_truth_results.txt → "
             "parse → verify（disagree 记录回流人工，不入库）→ merge 进 v2_18。")
    (WAVE / "index_redistill_truth.md").write_text("\n".join(L) + "\n", encoding="utf-8")

    print(f"made {len(ledger)} (G2={g2_n} G3={g3_n}) skipped={len(skipped)}")
    print("最大包:", sizes[-1][0], sizes[-1][1] // 1024, "KB")
    for s in skipped:
        print("  skip:", s["id"], s["why"])


if __name__ == "__main__":
    main()
