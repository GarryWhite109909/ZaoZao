# -*- coding: utf-8 -*-
"""wave2 预审 kits + 正式蒸馏 kits 生成器（20260911）。

从 wave2_pairs/*.txt（带 oracle 头）派生两种投喂包：
  1. kits_wave2_preaudit/  找茬任务：剥掉 oracle 头防泄题，措辞与 wave1 一致
     （版本A=修复前 / 版本B=修复后）。教师用普通会话协议（类型一 diffpair）输出
     PRE/POST 两条记录；回填后比对——教师若在 safe 侧报出"断言之外的缺陷"→
     该对带附带洞，退回修订（g25 教训：7/16 带隐蔽洞）。
  2. kits_wave2_formal/    正式蒸馏包：预审通过后再投喂。批量头带判别标准 hint
     （给判别标准不给结论，契约 3），oracle 仍不入包，只在 verify 阶段使用。

附带机检：预审包内不得出现 oracle 头内容（"oracle" / "anchor" 字样）与 vuln/safe 字样。
"""
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

WAVE = Path(__file__).resolve().parents[1] / "corpus" / "diffpair_wave1"
PAIRS = WAVE / "wave2_pairs"
PRE = WAVE / "kits_wave2_preaudit"
FORMAL = WAVE / "kits_wave2_formal"
LIMIT = 48 * 1024

HINT = {
    "441": "判别标准 hint：核验 441 官方判据——『request would appear to be coming from the product』"
           "（借产品网络位置/代理语义发请求）。注意与 918（服务端取回 URL 的目的地未校验）、"
           "601（浏览器跳转）的边界，分析过程必须写互斥锚句。",
    "95": "判别标准 hint：核验 95 官方判据——不可信数据进入动态求值调用的求值位（eval()/Function()/"
          "ScriptEngine 等）。注意：拼接与否不影响 95 定位（sink 是求值器即 95）；"
          "94 指非求值器 sink 的代码生成执行（拼代码写文件再 include 等）；与 78（OS 命令）的边界必须写互斥锚句。",
    "78": "判别标准 hint：核验 78 官方判据——注入目标是 OS 命令解释器（有无 shell 层均算）。"
          "注意：argv 列表形式不豁免——argv 含解释器/执行语义参数（sh -c、-exec、--upload-pack）仍为 78；"
          "必须写非 22/非 95/非 74 互斥锚句。",
}


def leak_check(text, pid):
    bad = []
    for pat in (r"oracle", r"anchor", r"污点路径", r"防御链", r"vuln", r"safe", r"成对同码"):
        if re.search(pat, text, re.I):
            bad.append(pat)
    return bad


def main():
    PRE.mkdir(exist_ok=True)
    FORMAL.mkdir(exist_ok=True)
    made, skipped = [], []
    for f in sorted(PAIRS.glob("*.txt")):
        if f.name.startswith("_"):
            continue
        raw = f.read_text(encoding="utf-8")
        # 拆出正文（从 "### id=" 开始）
        m = re.search(r"^### id=.*$", raw, re.M)
        if not m:
            skipped.append((f.name, "无 ### id 行"))
            continue
        body = raw[m.start():]
        pid = f.stem  # e.g. 441-01 / 78-S-09b
        # 预审：措辞统一为 wave1 口径
        pre = body.replace("#### 版本A（vuln", "#### 版本A（修复前").replace(
            "#### 版本B（safe", "#### 版本B（修复后")
        pre = re.sub(r"#### 版本A（修复前，(\d+) 行）", r"#### 版本A（修复前，\1 行）", pre)
        leaks = leak_check(pre, pid)
        if leaks:
            skipped.append((f.name, f"预审包疑似泄题: {leaks}"))
            continue
        pre_text = f"【蒸馏批次 diffpair | 样本数=1】\n\n{pre}"
        if len(pre_text.encode("utf-8")) > LIMIT:
            skipped.append((f.name, "预审包超尺寸"))
            continue
        (PRE / f.name).write_text(pre_text, encoding="utf-8", newline="\n")
        # 正式：带判别标准 hint（家族 = pid 前缀）
        fam = "441" if pid.startswith("441") else ("95" if pid.startswith("95") else "78")
        formal_text = f"【蒸馏批次 diffpair | 样本数=1】\n【{HINT[fam].split('：')[1]}】\n\n{body}".replace(
            "#### 版本A（vuln", "#### 版本A（修复前").replace("#### 版本B（safe", "#### 版本B（修复后")
        if len(formal_text.encode("utf-8")) > LIMIT:
            skipped.append((f.name, "正式包超尺寸"))
            continue
        (FORMAL / f.name).write_text(formal_text, encoding="utf-8", newline="\n")
        made.append((pid, len(pre_text.encode("utf-8")), len(formal_text.encode("utf-8"))))

    # 索引
    def index(path, title, col_idx):
        L = [f"# {title}（{len(made)} 包，按字节升序=先易后难）", "",
             f"粘贴红线 48KB；一次一包；协议：teacher_prompt_session.md（预审=类型一原样 / 正式=类型一+批量头 hint）", "",
             "| 顺序 | 包 | 预审KB | 正式KB |", "|---|---|---|---|"]
        for i, (pid, pb, fb) in enumerate(sorted(made, key=lambda x: x[1]), 1):
            L.append(f"| {i} | {pid} | {pb//1024} | {fb//1024} |")
        path.write_text("\n".join(L) + "\n", encoding="utf-8")

    index(PRE / "_index_preaudit.md",
          "wave2 预审（找茬）投喂索引——教师独立分析 A/B，回填后比对 oracle 与附带洞", 0)
    index(FORMAL / "_index_formal.md",
          "wave2 正式蒸馏投喂索引——预审全部通过后才可投喂", 0)

    print(f"made {len(made)} preaudit+formal, skipped {len(skipped)}")
    for name, why in skipped:
        print("  SKIP", name, why)


if __name__ == "__main__":
    main()
