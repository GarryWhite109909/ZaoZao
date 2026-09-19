# -*- coding: utf-8 -*-
"""重蒸馏收尾（20260909）：
① C6-only 45 条：按近邻族补互斥锚句（merge 时注入 explanation + 分析过程尾部）；
② C4×2 / C8×2：退重投喂包（redistill_pack_XXX_retake）；
③ FLIP 46 条：打 Qwen 2v1 包（重蒸馏模式，仅代码；会由用户网页投喂）。
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(Path(__file__).resolve().parents[1])
WAVE = BASE / "corpus/redistill_wave"
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"

ANCHORS = {
    "78": "非 CWE-77 因为注入目标是 OS shell 程序执行而非 sed/IMAP 等非 OS 命令语言；非 CWE-88 因为命令名并非固定、输入进入的是完整命令文本而非纯参数位。",
    "22": "非 CWE-73 因为输入被拼入固定目录前缀、核心危害是 .. 序列穿越出受限目录（22 比 73 更精确）；非 CWE-78 因为 sink 是文件/路径操作而非程序执行。",
    "1336": "非 CWE-94/95 因为不存在 eval/exec 求值或生成代码再执行，缺陷在模板引擎把输入当模板源码渲染；非 CWE-79 因为危害在模板语法位而非浏览器输出转义。",
    "89": "非 CWE-943 因为 sink 是 SQL 执行而非 MongoDB 操作符/HQL 等非 SQL 数据查询逻辑；非 CWE-943 的 ORM 表达式面。",
    "918": "非 CWE-441 因为请求并非借产品身份/回环信任绕过访问控制；非 CWE-601 因为不存在返回给浏览器的 Location 跳转，缺陷在服务端取回内容。",
    "327": "非 CWE-326 因为问题不是密钥长度不足而是协议/算法整体废弃或破碎；非 CWE-347 因为不涉及签名校验缺失。",
    "94": "非 CWE-95 因为输入不是直接进入 eval() 一跳求值，而是先拼入生成的代码文本再执行；非 CWE-78 因为执行的是代码而非 OS 命令。",
    "601": "非 CWE-918 因为危害是骗浏览器跳转（Location）而非服务端取回内容；非 CWE-441 因为不涉及代理/回环信任语义。",
}

rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
FENCE = re.compile(r"```[a-zA-Z0-9+#]*\n(.*?)```", re.S)
rep = {json.loads(l)["id"]: json.loads(l) for l in (WAVE / "verify_report.jsonl").open(encoding="utf-8")}
pm = {}
for pj in sorted((WAVE / "parsed").glob("*.jsonl")):
    for l in pj.open(encoding="utf-8"):
        o = json.loads(l)
        pm[o["id"]] = o

# ---------- ① C6-only 补锚句：构造行（带锚）并入 staging ----------
SYSTEM = (BASE / "corpus/diffpair_wave1/system_prompt_alpha05_stamped.txt").read_text(encoding="utf-8")
staging = [json.loads(l) for l in (WAVE / "merged_stage.jsonl").open(encoding="utf-8") if l.strip()]
staged_ids = {f"redistill-line-{r['meta']['orig_line']}" for r in staging}
patched = 0
for kid, flags in sorted(rep.items()):
    if not flags["flags"] or not all(f.startswith("C6") for f in flags["flags"]):
        continue
    if kid in staged_ids:
        continue
    f = pm[kid]["fields"]
    vt = f.get("vulnerability_type", "")
    mcw = re.match(r"CWE-(\d+)", vt)
    if not mcw or mcw.group(1) not in ANCHORS:
        print(f"  [warn] {kid} 无锚模板（族 {vt[:20]}），跳过")
        continue
    anchor = ANCHORS[mcw.group(1)]
    ln = flags["line"]
    row = rows[ln - 1]
    code = "\n".join(FENCE.findall(row["messages"][1]["content"]))
    lm = re.search(r"语言[:：]\s*(\w+)", row["messages"][1]["content"])
    lang = (lm.group(1) if lm else "text").lower()
    concl = {
        "has_vulnerability": f.get("has_vulnerability", "").strip().lower() == "true",
        "vulnerability_type": vt,
        "risk_level": f.get("risk_level", "Medium"),
        "source": f.get("source", "N/A"),
        "sink": f.get("sink", "N/A"),
        "explanation": f.get("explanation", "").rstrip("。；;") + "。" + anchor,
        "fix_suggestion": f.get("fix_suggestion", "no fix needed"),
    }
    ana = f.get("分析过程", "").rstrip() + "\n\n辨析补充：" + anchor
    user = (f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```\n\n"
            "请先给出分析过程，然后在最后给出 JSON 结论。")
    asst = ana + "\n\n```json\n" + json.dumps(concl, ensure_ascii=False) + "\n```"
    old_meta = row.get("meta") or {}
    staging.append({"messages": [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": user},
        {"role": "assistant", "content": asst}],
        "meta": {"kind": ((old_meta.get("kind") or "") + "_redistilled") if old_meta.get("kind") else "redistilled",
                 "cve": old_meta.get("cve"), "redistilled": True,
                 "orig_line": ln, "orig_reasons": ["C6_anchor_patched"],
                 "label_basis": "redistill"}})
    patched += 1
with (WAVE / "merged_stage.jsonl").open("w", encoding="utf-8", newline="\n") as f:
    for r in staging:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
print(f"① C6 补锚句并入 staging: {patched} 条（staging 现共 {len(staging)} 行）")

# ---------- ② C4/C8 退投喂包 ----------
FENCE = re.compile(r"```[a-zA-Z0-9+#]*\n(.*?)```", re.S)
retake = [rid for rid, r in rep.items()
          if any(f.startswith(("C4", "C8")) for f in r["flags"])]
blocks = []
for rid in sorted(retake):
    ln = int(rid.split("-")[-1])
    row = rows[ln - 1]
    code = "\n".join(FENCE.findall(row["messages"][1]["content"]))
    lang = (re.search(r"语言[:：]\s*(\w+)", row["messages"][1]["content"]) or [None, "text"])
    lang = (lang.group(1) if hasattr(lang, "group") else "text").lower()
    blocks.append(f"\n### id={rid} lang={lang} flags=[retake]\n"
                  f"#### 代码（{len(code.splitlines())} 行）\n```{lang}\n{code}\n```\n")
retake_text = ("【蒸馏批次 redistill | 样本数=%d】\n" % len(retake)) + "".join(blocks)
out2 = WAVE / "kits" / "redistill_pack_retake.txt"
out2.write_text(retake_text, encoding="utf-8", newline="\n")
print(f"② 退重投喂包: {len(retake)} 条 → {out2.name}")

# ---------- ③ FLIP 46 条 → Qwen 2v1 包（≤8 条/包） ----------
flip_ids = sorted(rid for rid, r in rep.items()
                  if any(f.startswith("FLIP") for f in r["flags"]))
blocks = []
for rid in flip_ids:
    ln = int(rid.split("-")[-1])
    row = rows[ln - 1]
    code = "\n".join(FENCE.findall(row["messages"][1]["content"]))
    lang = re.search(r"语言[:：]\s*(\w+)", row["messages"][1]["content"])
    lang = (lang.group(1) if lang else "text").lower()
    blocks.append(f"\n### id={rid} lang={lang} flags=[arbitrate]\n"
                  f"#### 代码（{len(code.splitlines())} 行）\n```{lang}\n{code}\n```\n")
packs = [blocks[i:i + 8] for i in range(0, len(blocks), 8)]
mfile = {}
for n, pack in enumerate(packs, 1):
    name = f"flip2v1_pack_{n:03d}"
    body = ("【蒸馏批次 redistill | 样本数=%d】\n" % len(pack)) + "".join(pack)
    (WAVE / "kits" / f"{name}.txt").write_text(body, encoding="utf-8", newline="\n")
    for b in pack:
        rid = re.search(r"### id=(redistill-line-\d+)", b).group(1)
        mfile[rid] = {"pack": name, "line": int(rid.split("-")[-1]),
                      "glm_verdict": pm[rid]["fields"].get("has_vulnerability"),
                      "glm_cwe": pm[rid]["fields"].get("vulnerability_type", "")[:50],
                      "orig_has_v": rep[rid]["flags"] and next(
                          (f for f in rep[rid]["flags"] if f.startswith("FLIP")), "")}
(WAVE / "flip2v1_manifest_PRIVATE.json").write_text(
    json.dumps(mfile, ensure_ascii=False, indent=1), encoding="utf-8")
print(f"③ FLIP 2v1 包: {len(flip_ids)} 条 / {len(packs)} 包 → kits/flip2v1_pack_*.txt")
tv = sum(1 for v in mfile.values() if v["glm_verdict"] is True)
fv = sum(1 for v in mfile.values() if v["glm_verdict"] is False)
print(f"   GLM 判定: safe(原标vuln翻案) {tv} + vuln(原safe翻出洞) {fv}")
