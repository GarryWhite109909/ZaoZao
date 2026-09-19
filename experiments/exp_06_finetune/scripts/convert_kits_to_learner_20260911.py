# -*- coding: utf-8 -*-
"""learner 化转换器（20260911）：把我建的 teacher 格式包全部转成 learner 脱敏框架。

背景：实际投喂走 learner 轨（kits_learner/ + learner_framed_prompt_v3.md，不向模型暴露
蒸馏意图）。我此前按 teacher 协议生成的三类包全部泄漏（"蒸馏批次/修复前/修复后/
cve=/裁定真值"），原地重写为 learner 格式：

  1. kits_redistill_truth/（31 包）——头改【代码审计案例包 | redistill】，
     "裁定真值"→"官方结论（待你验证）"（存在漏洞/编号/备注，学习者口吻）；
  2. kits_wave2_preaudit/（46 包）——头改【代码审计案例包 | diffpair】，
     id 行去 cve=，版本头去（修复前/修复后），剥 oracle 头；
  3. kits_wave2_formal/（46 包）——同上 + 学习者口吻边界备注（给判别轴不给结论，契约3）。

统一断言：产物非围栏行零泄漏词（蒸馏|修复前|修复后|cve=|seed=|样本数|oracle|anchor|
vuln|safe|裁定真值|expected）；围栏体内命中仅告警。
"""
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

WAVE = Path(__file__).resolve().parents[1] / "corpus" / "diffpair_wave1"
PAIRS = WAVE / "wave2_pairs"
LEAK = ["蒸馏", "修复前", "修复后", "cve=", "seed=", "样本数", "oracle", "anchor",
        "vuln", "safe", "裁定真值", "expected"]


def leaks(text):
    hits, fence = [], False
    for i, line in enumerate(text.splitlines(), 1):
        if line.startswith("```"):
            fence = not fence
        elif not fence:
            low = line.lower()
            if any(w in line or w in low for w in LEAK):
                hits.append((i, line[:70]))
    return hits


FAMILY_NOTE = {
    "441": "备注：这是我反复判不稳的边界族——借产品身份/网络位置发请求、服务端取回 URL、浏览器跳转三者的轴，判别时严格对照笔记。",
    "95": "备注：这是我反复判不稳的边界族——eval 家族求值器与代码生成、OS 命令的轴，判别时严格对照笔记第 2 条。",
    "78": "备注：这是我反复判不稳的边界族——OS 命令解释器消费输入的形态（含 argv 列表形式带 sh -c/-exec/--upload-pack 语义参数），判别时严格对照笔记。",
}


def convert_redistill(p: Path):
    text = p.read_text(encoding="utf-8")
    if "【代码审计案例包 | redistill】" in text:
        return "skip"  # 已 learner 化
    m_id = re.search(r"^### id=(\S+) lang=(\S+) flags=(.+)$", text, re.M)
    m_code = re.search(r"#### 代码\n```[\w]*\n(.*?)```", text, re.S)
    m_truth = re.search(r"#### 裁定真值\n(.*?)\n（真值依据.*$", text, re.S | re.M)
    assert m_id and m_code and m_truth, f"{p.name}: 结构缺失"
    sid, lang, flags = m_id.group(1), m_id.group(2), m_id.group(3)
    code = m_code.group(1).rstrip()
    truth = m_truth.group(1).strip()
    hv = "true" if "has_vulnerability: true" in truth else "false"
    mm = re.search(r"cwe: (\S+)", truth)
    cwe = mm.group(1) if mm else "none"
    mm = re.search(r"note: (.*?)(?:\n|$)", truth, re.S)
    note = mm.group(1).strip() if mm else ""
    # flags 翻译成学习者口吻备注
    extra = ""
    if "R5" in flags and hv == "false":
        extra = " 这是我判为安全但一直不敢确认的案例，防御链请逐段给行号。"
    out = (
        f"【代码审计案例包 | redistill】\n\n"
        f"### id={sid} lang={lang}\n"
        f"#### 代码\n```{lang}\n{code}\n```\n"
        f"#### 官方结论（待你验证）\n"
        f"- 存在漏洞: {hv}\n"
        f"- 编号: {cwe}\n"
        f"- 备注: {note}{extra}\n"
    )
    assert not leaks(out), f"{p.name}: 泄漏 {leaks(out)[:2]}"
    p.write_text(out, encoding="utf-8", newline="\n")


def learnerize_pair(p: Path, formal: bool):
    raw = p.read_text(encoding="utf-8")
    m = re.search(r"^### id=.*$", raw, re.M)
    body = raw[m.start():]
    pid = p.stem
    fam = "441" if pid.startswith("441") else ("95" if pid.startswith("95") else "78")
    body = re.sub(r"^### id=(\S+) lang=(\S+) cve=\S+$", r"### id=\1 lang=\2", body, flags=re.M)
    body = body.replace("（vuln", "（").replace("（safe", "（")
    body = re.sub(r"^(#### 版本[AB])（，\s*", r"\1（", body, flags=re.M)
    head = "【代码审计案例包 | diffpair】\n"
    if formal:
        head += f"{FAMILY_NOTE[fam]}\n"
    out = head + "\n" + body
    assert not leaks(out), f"{p.name}: 泄漏 {leaks(out)[:2]}"
    (WAVE / ("kits_wave2_formal" if formal else "kits_wave2_preaudit") / p.name).write_text(
        out, encoding="utf-8", newline="\n")


def main():
    rd = sorted((WAVE / "kits_redistill_truth").glob("redistill-*.txt"))
    for p in rd:
        convert_redistill(p)
    print(f"redistill 转换 {len(rd)} 包")

    pairs = [p for p in sorted(PAIRS.glob("*.txt")) if not p.name.startswith("_")]
    for p in pairs:
        learnerize_pair(p, formal=False)
        learnerize_pair(p, formal=True)
    print(f"wave2 预审+正式 各 {len(pairs)} 包")

    # 索引更新
    sizes = sorted(((p.name, p.stat().st_size) for p in (WAVE / "kits_redistill_truth").glob("*.txt")),
                   key=lambda x: x[1])
    idx = ["# 带官方结论复核包投喂索引（learner 框架，20260911，按字节升序）", "",
           "会话 prompt：learner_framed_prompt_v3.md（已含 redistill 包类型说明）；一次一包", "",
           "| 顺序 | 包 | KB |", "|---|---|---|"]
    for i, (n, b) in enumerate(sizes, 1):
        idx.append(f"| {i} | {n} | {b//1024} |")
    (WAVE / "index_redistill_truth.md").write_text("\n".join(idx) + "\n", encoding="utf-8")

    for d in ("kits_wave2_preaudit", "kits_wave2_formal"):
        sizes = sorted(((p.name, p.stat().st_size) for p in (WAVE / d).glob("*.txt")), key=lambda x: x[1])
        idx = [f"# {d} 投喂索引（learner 框架，{len(sizes)} 包，按字节升序）", "",
               "会话 prompt：learner_framed_prompt_v3.md；一次一包", "",
               "| 顺序 | 包 | KB |", "|---|---|---|"]
        for i, (n, b) in enumerate(sizes, 1):
            idx.append(f"| {i} | {n} | {b//1024} |")
        (WAVE / d / ("_index_preaudit.md" if "preaudit" in d else "_index_formal.md")) \
            .write_text("\n".join(idx) + "\n", encoding="utf-8")
    print("索引已更新")


if __name__ == "__main__":
    main()
