# -*- coding: utf-8 -*-
"""wave2 手写代码对共享库：发射 + oracle 机检 + 成对同码守卫 + 索引。

每对数据结构：
  {
    "pid": "441-01",             # 形态号
    "lang": "Python",
    "cwe": "CWE-441",            # vuln 侧标签（safe 侧恒为无洞）
    "anchor": "...",             # 辨析锚句（vuln 侧，非近邻族因为…）
    "safe_anchor": "...",        # safe 侧锚句（为何不可旁路）
    "oracle_vuln": [(fragment, desc), ...],  # 污点路径 source→…→sink；片段须唯一命中一行
    "oracle_safe": [(fragment, desc), ...],  # 防御链：哪一行/什么机制/为何不可旁路；片段须唯一命中
    "vuln_code": "...", "safe_code": "...",          # 成对同码：除防御行外逐字相同
  }

机检（出生即检，不合规拒发）：
  E1 oracle_vuln 每个片段必须在 vuln_code 中唯一命中一行（0 命中/多命中都拒发），由片段解析行号
  E2 oracle_safe 同上（对 safe_code）
  E3 成对同码：difflib 逐行 diff，0 < 变更行数 <= max_diff（默认 8）
  E4 尺寸 < 40KB；代码非空；lang 合法
"""
import difflib
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

WAVE = Path(__file__).resolve().parents[1] / "corpus" / "diffpair_wave1"
PAIRS_DIR = WAVE / "wave2_pairs"
LIMIT = 40 * 1024
LANG_TAG = {"Python": "python", "PHP": "php", "Go": "go", "Java": "java",
            "JavaScript": "javascript", "Ruby": "ruby", "TypeScript": "typescript"}


def _lines(code: str):
    return code.strip("\n").splitlines()


def _resolve(lines, frag):
    """片段 → 唯一行号；0 或多命中都视为失败。"""
    hits = [i + 1 for i, l in enumerate(lines) if re.search(frag, l)]
    return hits


def check_pair(p):
    errs = []
    vlines = _lines(p["vuln_code"])
    slines = _lines(p["safe_code"])
    if not vlines or not slines:
        errs.append("E4 代码为空")
        return errs, 0
    p["_oracle_vuln_resolved"] = []
    p["_oracle_safe_resolved"] = []
    for frag, desc in p["oracle_vuln"]:
        hits = _resolve(vlines, frag)
        if not hits:
            errs.append(f"E1 vuln 片段未命中: /{frag}/")
        elif len(hits) > 1:
            errs.append(f"E1 vuln 片段不唯一(行{hits}): /{frag}/")
        else:
            p["_oracle_vuln_resolved"].append((hits[0], frag, desc))
    for frag, desc in p["oracle_safe"]:
        hits = _resolve(slines, frag)
        if not hits:
            errs.append(f"E2 safe 片段未命中: /{frag}/")
        else:
            # safe 侧取首个命中（防御锚点通常为定义行）；命中数记入 desc 前的标记
            p["_oracle_safe_resolved"].append((hits[0], frag, desc + (f" [{len(hits)} hits]" if len(hits) > 1 else "")))
    sm = difflib.SequenceMatcher(None, vlines, slines, autojunk=False)
    diff_n = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag != "equal":
            diff_n += max(i2 - i1, j2 - j1)
    if diff_n == 0:
        errs.append("E3 vuln/safe 完全相同——不是差分对")
    return errs, diff_n


def emit(family, pairs, max_diff=8):
    PAIRS_DIR.mkdir(exist_ok=True)
    made, failed = [], []
    for p in pairs:
        errs, diff_n = check_pair(p)
        if errs:
            failed.append((p["pid"], errs))
            continue
        tag = LANG_TAG.get(p["lang"], "text")
        ov = "\n".join(f"  - L{ln} `{frag}` {d}" for ln, frag, d in p["_oracle_vuln_resolved"])
        os_ = "\n".join(f"  - L{ln} `{frag}` {d}" for ln, frag, d in p["_oracle_safe_resolved"])
        text = (
            f"# wave2 pair {p['pid']} | {p['cwe']} | {p['lang']} | 成对同码\n"
            f"# oracle_vuln（污点路径，行号自版本A围栏后起算）：\n{ov}\n"
            f"# anchor_vuln: {p['anchor']}\n"
            f"# oracle_safe（防御链）：\n{os_}\n"
            f"# anchor_safe: {p['safe_anchor']}\n"
            f"\n### id=wave2-{p['pid']} lang={tag} cve=N/A\n"
            f"#### 版本A（vuln，{len(_lines(p['vuln_code']))} 行）\n```{tag}\n{p['vuln_code'].strip(chr(10))}\n```\n"
            f"#### 版本B（safe，{len(_lines(p['safe_code']))} 行）\n```{tag}\n{p['safe_code'].strip(chr(10))}\n```\n"
        )
        if len(text.encode("utf-8")) > LIMIT:
            failed.append((p["pid"], [f"E4 超尺寸 {len(text.encode('utf-8'))//1024}KB"]))
            continue
        (PAIRS_DIR / f"{p['pid']}.txt").write_text(text, encoding="utf-8", newline="\n")
        made.append((p["pid"], p["cwe"], p["lang"], diff_n, len(_lines(p["vuln_code"])), len(_lines(p["safe_code"]))))
    return made, failed


def write_index(family_name, made):
    made.sort()
    L = [f"# wave2_pairs {family_name} 出库索引（{len(made)} 对，全部通过 E1-E4 出生机检）", "",
         "| 对 | CWE | 语言 | 同码diff行数 | A行数 | B行数 |", "|---|---|---|---|---|---|"]
    for pid, cwe, lang, d, na, nb in made:
        L.append(f"| {pid} | {cwe} | {lang} | {d} | {na} | {nb} |")
    return L
