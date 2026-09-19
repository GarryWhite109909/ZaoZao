# -*- coding: utf-8 -*-
"""差分对 wave1 → learner 框架脱敏 kit 转换器（20260910 蒸馏前工作）。

背景：新一轮蒸馏改用 learner_framed_prompt_v3.md（不向教师模型暴露蒸馏意图）。
原 kits/（make_diffpair_kits_20260908.py 产物）头部带三类泄漏，本脚本逐一去除后
输出到 kits_learner/，文件名与 kits/ 一一对应：

  L1 【蒸馏批次 diffpair | 样本数=1】  → 【代码审计案例包 | diffpair】（蒸馏字眼）
  L2 id 行的 cve=/seed= 字段          → 删除（CVE 可被联网反查 advisory，seed 是流水线字眼；
                                        id↔CVE↔seed 映射仍在 manifest_PRIVATE.json，可追溯性不丢）
  L3 版本A（修复前）/版本B（修复后）  → 版本A（N 行）/版本B（N 行）（修复方向标签泄漏，
                                        诱发 label_leak_shortcut：从"A 是修复前"直接读出结论）

纪律：
- 只动 4 个头部行，代码围栏体零改动（逐文件断言：行数不变 + 围栏块逐字节一致）；
- 非围栏行零泄漏断言（蒸馏/修复前/修复后/cve=/seed=/样本数）；围栏体内若命中泄漏词
  仅告警不失败（属语料代码自身内容，需人工判断）；
- 严格全行匹配，格式不符即 raise——静默放过泄漏等于没脱敏。
"""
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
SRC = BASE / "corpus/diffpair_wave1/kits"
DST = BASE / "corpus/diffpair_wave1/kits_learner"

RE_ID = re.compile(r"^### id=(\S+) lang=(\S+) cve=(\S+) seed=(\S+)$")
RE_VER_A = re.compile(r"^#### 版本A（修复前，(\d+) 行）$")
RE_VER_B = re.compile(r"^#### 版本B（修复后，(\d+) 行）$")
HEADER_OLD = "【蒸馏批次 diffpair | 样本数=1】"
HEADER_NEW = "【代码审计案例包 | diffpair】"
LEAK_WORDS = ["蒸馏", "修复前", "修复后", "cve=", "seed=", "样本数"]


def sanitize(text, name):
    out, n = [], {"head": 0, "id": 0, "va": 0, "vb": 0}
    for line in text.splitlines():
        if line == HEADER_OLD:
            out.append(HEADER_NEW); n["head"] += 1
        elif (m := RE_ID.match(line)):
            out.append(f"### id={m.group(1)} lang={m.group(2)}"); n["id"] += 1
        elif (m := RE_VER_A.match(line)):
            out.append(f"#### 版本A（{m.group(1)} 行）"); n["va"] += 1
        elif (m := RE_VER_B.match(line)):
            out.append(f"#### 版本B（{m.group(1)} 行）"); n["vb"] += 1
        else:
            out.append(line)
    assert n == {"head": 1, "id": 1, "va": 1, "vb": 1}, f"{name}: 替换计数异常 {n}"
    return "\n".join(out) + "\n"


def fenced_blocks(text):
    blocks, cur = [], None
    for line in text.splitlines():
        if line.startswith("```"):
            if cur is None:
                cur = [line]
            else:
                blocks.append("\n".join(cur + [line])); cur = None
        elif cur is not None:
            cur.append(line)
    assert cur is None, "围栏不闭合"
    return blocks


def prose_leak(text):
    hits, in_fence = [], False
    for i, line in enumerate(text.splitlines(), 1):
        if line.startswith("```"):
            in_fence = not in_fence
        elif not in_fence and any(w in line for w in LEAK_WORDS):
            hits.append((i, line[:80]))
    return hits


def body_leak(text):
    hits, in_fence = [], False
    for i, line in enumerate(text.splitlines(), 1):
        if line.startswith("```"):
            in_fence = not in_fence
        elif in_fence and any(w in line for w in LEAK_WORDS):
            hits.append((i, line[:80]))
    return hits


def main():
    files = sorted(SRC.glob("diffpair-corpus_*.txt"))
    assert files, f"源目录无 kit: {SRC}"
    DST.mkdir(exist_ok=True)
    body_warns = []
    for f in files:
        orig = f.read_text(encoding="utf-8")
        new = sanitize(orig, f.name)
        assert new.count("\n") == orig.count("\n"), f"{f.name}: 行数变了"
        assert fenced_blocks(new) == fenced_blocks(orig), f"{f.name}: 代码围栏体被改动"
        assert not prose_leak(new), f"{f.name}: 非围栏行仍含泄漏词 {prose_leak(new)}"
        if (w := body_leak(orig)):
            body_warns.append((f.name, w))
        (DST / f.name).write_text(new, encoding="utf-8", newline="\n")

    dst_files = sorted(DST.glob("diffpair-corpus_*.txt"))
    assert [p.name for p in dst_files] == [p.name for p in files], "输出文件名集合不一致"
    readme = [
        "# kits_learner — learner 框架脱敏 kit（20260910）",
        "",
        f"- 来源: ../kits/（make_diffpair_kits_20260908.py 产物）共 {len(files)} 包，文件名一一对应",
        "- 脱敏三处: 批次头去蒸馏字眼；id 行删 cve=/seed=；版本A/B 头删（修复前/修复后）",
        "- id↔CVE↔seed↔expected_cwe 映射: ../manifest_PRIVATE.json（喂投与对账照旧）",
        "- 喂投顺序: 沿用 ../index.md（字节升序=先易后难）与 夜班批次清单_20260909.md 的分夜表",
        "- 配套教师侧提示词: ../learner_framed_prompt_v3.md（原稿备份 .bak-20260910）",
        "",
    ]
    (DST / "README.md").write_text("\n".join(readme), encoding="utf-8", newline="\n")

    print(f"转换 {len(files)} 包 → {DST}")
    print("断言全过: 行数不变 / 围栏体逐字节一致 / 非围栏行零泄漏 / 替换计数 1+1+1+1")
    if body_warns:
        print(f"围栏体内命中泄漏词 {len(body_warns)} 包（语料代码自身内容，请人工过目）:")
        for name, w in body_warns[:10]:
            print(f"  {name}: {w}")
    else:
        print("围栏体内零泄漏词命中")


if __name__ == "__main__":
    main()
