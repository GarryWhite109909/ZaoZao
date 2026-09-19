# -*- coding: utf-8 -*-
"""差分对蒸馏 wave1：patch 派生差分对 kit 生成器（方法论 §2.1 差分对生成契约）。

输入：corpus/train_pool/manifest.json（cve_id/patch_file/expected_cwe/...）+
      corpus/train_pool/<seed>（pre-fix 代码）+ corpus/patches/<patch>（ground-truth 修复）。
输出：corpus/diffpair_wave1/kits/kit_NNN_<seed>.txt（网页投喂包，单包单 CVE，≤48KB）
      corpus/diffpair_wave1/manifest_PRIVATE.json（包↔CVE↔种子↔变更行私有映射）
      corpus/diffpair_wave1/index.md（投喂索引：尺寸/语言/CWE 排序）
      corpus/diffpair_wave1/skipped.jsonl（不可应用/超尺寸清单+原因）

纪律：
- 仅 train_pool 种子（exam 侧 rolling_dev/cve20 一律不用——G6 同源簇只许一侧）；
- 教师输出协议=纯文本字段行（9/7 附2 口径，杜绝 JSON 转义事故），merge 阶段程序化构造 JSON 块；
- hint 纪律：包内不含 advisory/expected_cwe——教师结论独立得出，expected_* 只进 verify oracle；
- 粘贴 ≤48KB 实测红线，本生成器硬断言。
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from diffpair_patchlib import parse_patch, apply_patch

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(Path(__file__).resolve().parents[1])
CORPUS = BASE / "corpus"
OUT = CORPUS / "diffpair_wave1"
LIMIT = 48 * 1024
SOFT_LIMIT = 45 * 1024          # 预留余量


def build_kit_text(kid, seed, cve, lang, pre, post, pre_n, post_n):
    """瘦格式：批次标记 + 数据块。教师指令全部在会话 prompt（teacher_prompt_session.md）。"""
    pre_s, post_s = "\n".join(pre), "\n".join(post)
    head = (
        f"【蒸馏批次 diffpair | 样本数=1】\n\n"
        f"### id={kid} lang={lang} cve={cve or 'N/A'} seed={seed}\n"
        f"#### 版本A（修复前，{pre_n} 行）\n```{lang}\n{pre_s}\n```\n"
        f"#### 版本B（修复后，{post_n} 行）\n```{lang}\n{post_s}\n```\n"
    )
    return head


def norm_lang(l):
    return {"JavaScript": "javascript", "Python": "python", "PHP": "php", "Go": "go",
            "Java": "java", "TypeScript": "typescript", "Ruby": "ruby", "C": "c",
            "C#": "csharp", "Kotlin": "kotlin", "Rust": "rust"}.get(l, (l or "text").lower())


def main():
    tp = json.loads((CORPUS / "train_pool/manifest.json").read_text(encoding="utf-8"))["samples"]
    kits, skipped, manifest = [], [], {}
    for s in tp:
        seed_name = s["file"]
        seed_path = CORPUS / "train_pool" / seed_name
        patch_rel = s.get("patch_file")
        if not patch_rel:
            skipped.append({"seed": seed_name, "why": "manifest 无 patch_file"})
            continue
        patch_path = CORPUS / patch_rel
        if not seed_path.exists() or not patch_path.exists():
            skipped.append({"seed": seed_name, "why": f"文件缺失 seed={seed_path.exists()} patch={patch_path.exists()}"})
            continue
        pre_lines = seed_path.read_text(encoding="utf-8", errors="replace").splitlines()
        hunks = parse_patch(patch_path.read_text(encoding="utf-8", errors="replace"))
        post_lines, info = apply_patch(pre_lines, hunks)
        if post_lines is None:
            skipped.append({"seed": seed_name, "why": f"patch 无法应用: {info}"})
            continue
        kid = f"diffpair-{seed_name.split('.')[0]}"
        lang = norm_lang(s.get("language"))
        cve = s.get("cve_id")
        text = build_kit_text(kid, seed_name, cve, lang, pre_lines, post_lines,
                              len(pre_lines), len(post_lines))
        if len(text.encode("utf-8")) > LIMIT:
            skipped.append({"seed": seed_name, "why": f"超粘贴上限 {len(text.encode('utf-8'))//1024}KB"})
            continue
        fname = OUT / "kits" / f"{kid}.txt"
        fname.write_text(text, encoding="utf-8", newline="\n")
        kits.append({
            "kit": fname.name, "bytes": len(text.encode("utf-8")), "seed": seed_name,
            "cve": cve, "language": s.get("language"), "expected_cwe": s.get("expected_cwe"),
            "expected_risk": s.get("expected_risk_level"),
            "patch_file": patch_rel,
            "changed_pre": info["pre"], "changed_post": info["post"],
            "hunks": len(hunks), "pre_lines": len(pre_lines), "post_lines": len(post_lines),
        })
        manifest[kid] = kits[-1]

    (OUT / "manifest_PRIVATE.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    (OUT / "skipped.jsonl").write_text(
        "\n".join(json.dumps(x, ensure_ascii=False) for x in skipped) + "\n", encoding="utf-8")

    kits_sorted = sorted(kits, key=lambda k: k["bytes"])
    idx = ["# 差分对 wave1 投喂索引（按字节升序=先易后难）", "",
           f"可投喂 {len(kits)} 包；跳过 {len(skipped)}（见 skipped.jsonl）；粘贴红线 48KB", "",
           "| 包 | KB | 语言 | CVE | expected_cwe | 变更(pre/post 行) |", "|---|---|---|---|---|---|"]
    for k in kits_sorted:
        idx.append(f"| {k['kit']} | {k['bytes']//1024} | {k['language']} | {k['cve'] or '-'} "
                   f"| {k['expected_cwe']} | {len(k['changed_pre'])}/{len(k['changed_post'])} |")
    (OUT / "index.md").write_text("\n".join(idx) + "\n", encoding="utf-8")

    print(f"kits {len(kits)} skipped {len(skipped)}")
    print("最大包:", kits_sorted[-1]["kit"], kits_sorted[-1]["bytes"] // 1024, "KB")
    from collections import Counter
    print("语言分布:", Counter(k["language"] for k in kits).most_common())
    print("CWE 分布(oracle):", Counter(k["expected_cwe"] for k in kits).most_common(12))


if __name__ == "__main__":
    main()
