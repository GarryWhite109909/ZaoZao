# -*- coding: utf-8 -*-
"""今晚最后一轮投喂打包：主池 12 + wave2 78-S-09/09b（2026-09-14）

口径：
- learner 协议（learner_framed_prompt_v3.md）每个 kit 文件里都内嵌了一份（前 6470 字节），
  会话开头贴一次协议即可；本脚本只抽取案例段（从【代码审计案例包 起到文件尾）。
- 主池 diffpair 单包大（21–50KB），按「一次一包」原纪律；小包两两合并（≤46KB）。
- wave2 两个包是 learner 格式，同法处理。
"""
import sys, os, json, re
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[1]
KL = BASE / "corpus/diffpair_wave1/kits_learner"
W2F = BASE / "corpus/diffpair_wave1/kits_wave2_formal"
OUT = BASE / "corpus/diffpair_wave1/feed_final_20260914"
OUT.mkdir(parents=True, exist_ok=True)

MAIN = ["diffpair-corpus_00159", "diffpair-corpus_00209", "diffpair-corpus_00280",
        "diffpair-corpus_00282", "diffpair-corpus_00283", "diffpair-corpus_00284",
        "diffpair-corpus_00285", "diffpair-corpus_00286", "diffpair-corpus_00297",
        "diffpair-corpus_00298", "diffpair-corpus_00299", "diffpair-corpus_00301"]
W2 = ["78-S-09", "78-S-09b"]
LIMIT = 46 * 1024


def case_only(path):
    """取案例段：协议正文里也会提到【代码审计案例包】字样，所以取**最后一个**行首命中的标记行"""
    t = path.read_text(encoding="utf-8", errors="replace")
    starts = [m.start() for m in re.finditer(r"^【代码审计案例包", t, flags=re.M)]
    assert starts, f"{path.name} 找不到案例段标记行"
    return t[starts[-1]:].strip() + "\n"


def pack(name, items, max_kits=3):
    """items = [(label, case_text)]，贪心装入 ≤LIMIT 且 ≤max_kits 个 kit 的批文件"""
    batches, cur, cur_size = [], [], 0
    for label, txt in items:
        n = len(txt.encode("utf-8"))
        if cur and (cur_size + n > LIMIT or len(cur) >= max_kits):
            batches.append(cur)
            cur, cur_size = [], 0
        cur.append((label, txt))
        cur_size += n
    if cur:
        batches.append(cur)
    outs = []
    for bi, b in enumerate(batches, 1):
        p = OUT / f"{name}_{bi:02d}.txt"
        body = ("\n\n" + "=" * 70 + "\n\n").join(x[1] for x in b)
        p.write_text(body, encoding="utf-8", newline="\n")
        outs.append((p, [x[0] for x in b], p.stat().st_size))
    return outs


# ---- 主池：先按大小排序，贪心配对
main_items = []
for k in MAIN:
    p = KL / f"{k}.txt"
    main_items.append((k, case_only(p)))
main_items.sort(key=lambda x: len(x[1]))
main_outs = pack("main", main_items)

# ---- wave2 两包
w2_items = [(n, case_only(W2F / f"{n}.txt")) for n in W2]
w2_outs = pack("wave2", w2_items)

total = 0
print("=== 主池 12 kit（合并后批次）===")
for p, labels, size in main_outs:
    total += size
    print(f"  {p.name}  {size/1024:.1f} KB  <- {', '.join(labels)}")
print("=== wave2 ===")
for p, labels, size in w2_outs:
    total += size
    print(f"  {p.name}  {size/1024:.1f} KB  <- {', '.join(labels)}")
print(f"\n合计 {len(main_outs)+len(w2_outs)} 个粘贴单元 / {total/1024:.1f} KB / 覆盖 {len(MAIN)+len(W2)} 个 kit")

# 自检：每个批文件含案例标记、不含协议正文
alltxt = [(p, p.read_text(encoding="utf-8")) for p, _, _ in main_outs + w2_outs]
bad = [p.name for p, t in alltxt if "【代码审计案例包" not in t]
dup = [p.name for p, t in alltxt if "## 我的判别笔记" in t]
print("自检-含案例标记:", "✅" if not bad else f"❌ {bad}")
print("自检-无协议正文混入:", "✅" if not dup else f"❌ {dup}")
over = [(p.name, round(p.stat().st_size / 1024, 1)) for p, _, _ in main_outs + w2_outs
        if p.stat().st_size > 48 * 1024]
print("自检-超 48KB 红线:", "✅ 无" if not over else f"⚠️ {over}")
