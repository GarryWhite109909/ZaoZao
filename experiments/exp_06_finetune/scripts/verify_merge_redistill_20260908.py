# -*- coding: utf-8 -*-
"""重蒸馏结果验证+合并（20260908）。

检查：C4 行号边界；C5' R1 类样本须含防御核验论证；C6 近邻族互斥锚句；
      FLIP verdict 翻转（与原判不同）→ FLAG 人工复核（可能原判就错，高价值）。
合并：PASS → 训练行 staging（程序化 JSON 块；meta.redistilled=true，保留原 kind 与敷衍原因）。
用法：python scripts/verify_merge_redistill_20260908.py
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(Path(__file__).resolve().parents[1])
WAVE = BASE / "corpus/redistill_wave"
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
SYSTEM = (BASE / "corpus/diffpair_wave1/system_prompt_alpha05_stamped.txt").read_text(encoding="utf-8")
FENCE = re.compile(r"```[a-zA-Z0-9+#]*\n(.*?)```", re.S)
LINE_REF = re.compile(r"(?:第|行|line\s|L)\s*\d{1,4}|(?:[\w.\-]+\.(?:ts|js|py|php|go|java|cs|rb))\s*[:：]\s*\d{1,4}", re.I)
FAMILY = {
    "77": {"77", "78"}, "78": {"78", "77"}, "94": {"94", "95", "1336"},
    "95": {"95", "94"}, "1336": {"1336", "94"}, "89": {"89", "943"}, "943": {"943", "89", "643"},
    "601": {"601", "918", "441"}, "918": {"918", "601", "441"}, "441": {"441", "918", "601"},
    "22": {"22", "73"}, "73": {"73", "22"}, "327": {"327", "347"}, "862": {"862", "639", "306"},
    "639": {"639", "862", "306"}, "915": {"915", "1321"},
}
NEIGHBOR = {"77", "78", "94", "95", "1336", "89", "943", "601", "918", "441", "22", "73", "327"}
DEF_MARKS = ["核验", "有效", "可绕过", "伪防御", "无效", "防御"]


def main():
    manifest = json.loads((WAVE / "manifest_PRIVATE.json").read_text(encoding="utf-8"))
    rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
    report, staging = [], []
    n_pass = n_flag = 0
    # 全局 id→record 索引（兼容多包合投单文件 / 分文件两种投喂方式）
    parsed_map = {}
    for pj in sorted((WAVE / "parsed").glob("*.jsonl")):
        for l in pj.open(encoding="utf-8"):
            try:
                o = json.loads(l)
                parsed_map[o.get("id")] = o
            except Exception:
                pass
    for kid, meta in manifest.items():
        rec = parsed_map.get(kid)
        if not rec:
            report.append({"id": kid, "flags": ["缺记录"]})
            n_flag += 1
            continue
        f = rec["fields"]
        flags = []
        row = rows[meta["line"] - 1]
        code = "\n".join(FENCE.findall(row["messages"][1]["content"]))
        n_lines = len(code.splitlines())
        # 嵌入行号兼容：部分样本（文件级上下文切片）代码自带原始文件 "N|" 前缀，
        # 叙事引用原始编号是忠于可见产物的——C4 合法上界 = max(围栏行数, 嵌入编号最大值)
        embedded_max = 0
        for el in code.splitlines():
            em = re.match(r"^\s*(\d{1,4})\|", el)
            if em:
                embedded_max = max(embedded_max, int(em.group(1)))
        n_valid = max(n_lines, embedded_max)
        ana = f.get("分析过程", "")
        # C4 行号边界
        for m in LINE_REF.finditer(ana + " " + f.get("source", "") + " " + f.get("sink", "")):
            n = int(re.search(r"\d{1,4}", m.group(0)).group(0))
            if n > n_valid:
                flags.append(f"C4 行号 {n} > 合法上界 {n_valid}（围栏 {n_lines} 行/嵌入最大 {embedded_max}）")
                break
        # C5' R1 类须含防御核验论证
        if any("R1" in r for r in meta["reasons"]):
            if not any(mk in ana for mk in DEF_MARKS):
                flags.append("C5' R1 类重写缺防御核验论证")
        # C8 深度门（20260908 模型横评教训：标签正确但推理浅的输出可漏过 C5' 关键词门——
        # DeepSeek V4 Pro 横评 10 条中 7 条标签全对但仅 3-4 处行引用，GLM5.3 同批 8-15 处）
        # 20260909 补：单行压缩产物（webpack bundle，n_lines≤3）行号引用无意义，豁免——
        # 该形态下叙事以"line 1 + 多代码片段"表达，7237 实测 2421 字符高质量叙事被误拦
        cited = set()
        for m in re.finditer(r"(?:第|行|line\s|L)\s*(\d{1,4})(?:[-–~](\d{1,4}))?", ana):
            cited.add(int(m.group(1)))
            if m.group(2):
                cited.add(int(m.group(2)))
        need = max(3, min(8, 3 + n_lines // 20))
        if n_lines > 3 and len(cited) < need:
            flags.append(f"C8 深度不足：{len(cited)} 处行引用 < 阈值 {need}（标签可能对但推理浅，抽验优先）")
        # C6 互斥锚句
        vt = f.get("vulnerability_type", "")
        mc = re.match(r"CWE-(\d+)", vt)
        if mc and mc.group(1) in NEIGHBOR:
            if "非 CWE" not in ana and "非CWE" not in ana:
                flags.append(f"C6 近邻族 CWE-{mc.group(1)} 缺互斥锚句")
        # FLIP
        hv_new = f.get("has_vulnerability", "").strip().lower() == "true"
        if hv_new != meta["has_v_orig"]:
            flags.append(f"FLIP 判定翻转（原 {meta['has_v_orig']} → 新 {hv_new}）→ 人工复核")
        if flags:
            n_flag += 1
        else:
            n_pass += 1
        report.append({"id": kid, "line": meta["line"], "flags": flags})
        if not flags:
            concl = {
                "has_vulnerability": hv_new,
                "vulnerability_type": vt or "none",
                "risk_level": f.get("risk_level", "Medium"),
                "source": f.get("source", "N/A"),
                "sink": f.get("sink", "N/A"),
                "explanation": f.get("explanation", ""),
                "fix_suggestion": f.get("fix_suggestion", "no fix needed"),
            }
            lang = (meta["lang"] or "text").lower()
            user = (f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```\n\n"
                    "请先给出分析过程，然后在最后给出 JSON 结论。")
            asst = (f.get("分析过程", "").strip() + "\n\n```json\n"
                    + json.dumps(concl, ensure_ascii=False) + "\n```")
            old_meta = row.get("meta") or {}
            staging.append({"messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": user},
                {"role": "assistant", "content": asst}],
                "meta": {"kind": (old_meta.get("kind") or "") + "_redistilled" if old_meta.get("kind") else "redistilled",
                         "cve": old_meta.get("cve"), "redistilled": True,
                         "orig_line": meta["line"], "orig_reasons": meta["reasons"],
                         "label_basis": "redistill"}})
    (WAVE / "verify_report.jsonl").write_text(
        "\n".join(json.dumps(o, ensure_ascii=False) for o in report) + "\n", encoding="utf-8")
    with (WAVE / "merged_stage.jsonl").open("w", encoding="utf-8", newline="\n") as f:
        for r in staging:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    flips = [o for o in report if any(x.startswith("FLIP") for x in o["flags"])]
    print(f"验证 {len(report)}：PASS {n_pass} / FLAG {n_flag}（其中判定翻转 {len(flips)}）")
    print(f"staging {len(staging)} 行 → {WAVE / 'merged_stage.jsonl'}")


if __name__ == "__main__":
    main()
