# -*- coding: utf-8 -*-
"""收尾批 14 kit 解析 + 验收 + 并入 v2_26（2026-09-14 深夜）

行格式对齐库内 diffpair 派生行（实测自 v2_25 行 7601/7602）：
  user      = 代码片段（语言: X）：```X\n<该版本代码>\n```\n请先给出分析过程，然后在最后给出 JSON 结论。
  assistant = 入口/链/防御/载荷/组合链 栏位（锚句并入 explanation 尾部；结论/修复 剥入 JSON）+ ```json{7 字段}```
"""
import sys, os, json, re, hashlib, collections
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = Path(__file__).resolve().parents[3]
E = ROOT / "experiments/exp_06_finetune"
BF = E / "corpus/diffpair_wave1/feed_final_20260914/result.txt"
KL = E / "corpus/diffpair_wave1/kits_learner"
W2F = E / "corpus/diffpair_wave1/kits_wave2_formal"
V25 = E / "data/final_train_chatml_alpha06_v2_25_candidate_20260914.jsonl"
OUT = E / "data/final_train_chatml_alpha06_v2_26_candidate_20260914.jsonl"
CHANGELOG = E / "audit/v2_26_candidate_changelog_20260914.jsonl"
DRY = "--apply" not in sys.argv

sys.path.insert(0, str(ROOT))
_v25_first = json.loads(next(l for l in V25.open(encoding="utf-8") if l.strip()))
SYSTEM = _v25_first["messages"][0]["content"]

FAMILY = {"77": {"77", "78"}, "78": {"78", "77"}, "94": {"94", "95", "1336"}, "95": {"95", "94", "1336"},
          "1336": {"1336", "94", "95"}, "89": {"89", "943"}, "918": {"918", "601", "441"},
          "441": {"441", "918", "601"}, "639": {"639", "862", "306"}, "79": {"79"},
          "1336b": {"1336"}, "639b": {"639"}}

FIELDS = ["入口", "链", "防御", "载荷", "组合链", "锚句", "结论", "修复"]


def parse_blocks(text):
    """按 ### <id> 版本X 切块；同 id+版本 重复取第一份"""
    parts = re.split(r"(?m)^### ", text)
    out, seen = [], set()
    for p in parts:
        m = re.match(r"(diffpair-corpus_\d+|wave2-78-S-09b?) (版本[AB])", p)
        if not m:
            continue
        key = (m.group(1), m.group(2))
        if key in seen:
            continue
        seen.add(key)
        out.append((key[0], key[1], p[m.end():].strip()))
    return out


def parse_fields(body):
    """栏位行 = 顶格 `栏位:`，续行 = 缩进行"""
    fields, cur = {}, None
    for line in body.splitlines():
        m = re.match(r"^(入口|链|防御|载荷|组合链|锚句|结论|修复)[:：]\s*(.*)$", line)
        if m:
            cur = m.group(1)
            fields[cur] = m.group(2)
        elif cur and (line.startswith(("  ", "\t", " ")) or (line.strip() and not re.match(r"^(入口|链|防御|载荷|组合链|锚句|结论|修复)[:：]", line) and fields.get(cur) is not None and not line.startswith("###"))):
            if cur == "结论":
                continue
            fields[cur] = fields.get(cur, "") + ("\n" if fields.get(cur) else "") + line.rstrip()
        elif line.strip() == "" and cur in ("防御",):
            continue
    return fields


def parse_verdict(s):
    """结论: 存在漏洞=false | CWE-N/A 无 | Low"""
    m = re.search(r"存在漏洞=(true|false)\s*\|\s*(CWE-[\dNA]+[^|]*?)\s*\|\s*(Critical|High|Medium|Low|None)", s or "")
    if not m:
        m2 = re.search(r"存在漏洞=(true|false)", s or "")
        return (m2.group(1) == "true" if m2 else None), None, None
    hv = m.group(1) == "true"
    cwe_m = re.search(r"CWE-(\d+)(?!\d)", m.group(2))
    risk = m.group(3)
    return hv, (cwe_m.group(1) if cwe_m else None), risk


def kit_versions(kit_id):
    """返回 {版本A: (lang, code), 版本B: (lang, code)}；锚定行首 #### 版本X 标题，避免命中协议模板"""
    base_id = kit_id.split("wave2-")[-1]          # wave2-78-S-09 → 78-S-09
    for base in (KL, W2F):
        for name in (f"{kit_id}.txt", f"{base_id}.txt"):
            p = base / name
            if p.exists():
                t = p.read_text(encoding="utf-8", errors="replace")
                vs = {}
                for ver in ("版本A", "版本B"):
                    m = re.search(r"(?m)^#### " + re.escape(ver) +
                                  r"[^\n]*\n+```([a-zA-Z0-9_+#-]*)\n(.*?)```", t, re.S)
                    if m:
                        vs[ver] = (m.group(1) or "text", m.group(2))
                return vs, p
    return None, None


log = []
backfill = BF.read_text(encoding="utf-8", errors="replace")
blocks = parse_blocks(backfill)
print(f"回填块 {len(blocks)} 个（去重后）")

man = json.loads((E / "corpus/diffpair_wave1/manifest_PRIVATE.json").read_text(encoding="utf-8"))
per_kit = collections.defaultdict(dict)
for kid, ver, body in blocks:
    per_kit[kid][ver] = parse_fields(body)

report, new_rows, rejected = [], [], []
for kid in sorted(per_kit):
    vers = per_kit[kid]
    oracle = man.get(kid, {})
    exp_cwe = re.search(r"CWE-(\d+)", oracle.get("expected_cwe", "") or "")
    exp_cwe = exp_cwe.group(1) if exp_cwe else None
    fam = FAMILY.get(exp_cwe, {exp_cwe})
    vs_code, src = kit_versions(kid)
    if not vs_code or "版本A" not in vers or "版本B" not in vers:
        rejected.append((kid, "缺版本块或 kit 文件"))
        continue
    ok_kit, notes = True, []
    built = []
    for ver in ("版本A", "版本B"):
        f = vers[ver]
        hv, cwe, risk = parse_verdict(f.get("结论", ""))
        lang, code = vs_code[ver]
        if hv is None:
            ok_kit = False; notes.append(f"{ver} 无结论行")
            continue
        # B 侧必须 false
        if ver == "版本B" and hv:
            ok_kit = False; notes.append(f"{ver} B 侧判 true（修复无效）")
        # A 侧 oracle 对照
        if ver == "版本A" and hv:
            if cwe not in fam:
                ok_kit = False; notes.append(f"{ver} A 侧 {cwe} 不在 oracle 族 {sorted(fam)}")
        # 行号范围
        nlines = len(code.rstrip("\n").split("\n"))
        oob = [ln for ln in re.findall(r"L(\d+)", " ".join(
            f.get(k, "") for k in ("入口", "链", "防御", "载荷", "组合链") if k in f))
            if int(ln) > nlines]
        if oob:
            ok_kit = False; notes.append(f"{ver} 行号越界 {sorted(set(oob))[:4]}> {nlines}")
        built.append((ver, f, hv, cwe, risk, lang, code))
    if not ok_kit:
        rejected.append((kid, "; ".join(notes)))
        continue
    # 组行
    for ver, f, hv, cwe, risk, lang, code in built:
        anchor = f.get("锚句", "")
        expl = " ".join(x for x in [f.get("链", ""), f.get("组合链", "")] if x)
        if anchor:
            expl = (expl + " " + anchor).strip()
        obj7 = {
            "has_vulnerability": hv,
            "vulnerability_type": (f"CWE-{cwe}" + ("" if not hv else "")) if cwe else "none",
            "risk_level": risk if hv else "None",
            "source": f.get("入口", "N/A"),
            "sink": f.get("链", "N/A") if hv else "N/A",
            "explanation": expl or "N/A",
            "fix_suggestion": f.get("修复", "no fix needed") if hv else "no fix needed",
        }
        body = "\n".join(f"{k}: {f[k]}" for k in ("入口", "链", "防御", "载荷", "组合链") if k in f)
        assistant = (body + "\n\n```json\n" + json.dumps(obj7, ensure_ascii=False) + "\n```")
        new_rows.append({
            "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"代码片段（语言: {lang}）：\n```{lang}\n{code.strip()}\n```\n请先给出分析过程，然后在最后给出 JSON 结论。"},
                {"role": "assistant", "content": assistant},
            ],
            "src_row": None,
            "_meta": {"orig": kid, "ver": ver, "oracle": exp_cwe},
        })
    report.append((kid, exp_cwe,
                   f"A={'true' if built[0][2] else 'false'}/{built[0][3] or '-'}",
                   f"B={'true' if built[1][2] else 'false'}/{built[1][3] or '-'}", "✅"))

print(f"\n{'kit':<24}{'oracle':<9}{'A 侧':<14}{'B 侧':<14}门")
for r in report:
    print(f"  {r[0]:<24}{str(r[1]):<9}{r[2]:<14}{r[3]:<14}{r[4]}")
if rejected:
    print("\n拒收:")
    for k, why in rejected:
        print(f"  {k}: {why}")
print(f"\n可入库行 = {len(new_rows)}（来自 {len(report)} kit × 2 版本）")

# ---- v2_26
v25 = [json.loads(l) for l in V25.open(encoding="utf-8") if l.strip()]
def sha(r):
    return hashlib.sha256(json.dumps(r, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
fp25 = set()
for r in v25:
    for b in re.findall(r"```[a-zA-Z0-9_+#-]*\n(.*?)```", r["messages"][1]["content"], re.S):
        fp25.add(hashlib.sha256(re.sub(r"\s+", " ", re.sub(r"^\s*(//|#|--).*$", "", b, flags=re.M)).strip().encode()).hexdigest()[:16])

dedup, seen = [], set()
for r in new_rows:
    code = re.findall(r"```[a-zA-Z0-9_+#-]*\n(.*?)```", r["messages"][1]["content"], re.S)[0]
    k = hashlib.sha256(re.sub(r"\s+", " ", re.sub(r"^\s*(//|#|--).*$", "", code, flags=re.M)).strip().encode()).hexdigest()[:16]
    if k in fp25 or k in seen:
        continue
    seen.add(k)
    dedup.append(r)
meta_print = [r.pop("_meta") for r in dedup]
for i, r in enumerate(dedup):
    r["src_row"] = len(v25) + i
print(f"指纹去重后可追加 = {len(dedup)} 行（其余与库内同码，跳过）")
out_rows = v25 + dedup

print("\n门禁")
assert all(tuple(sorted(r.keys())) == ("messages", "src_row") for r in out_rows)
print("G1 键集唯一 ✅")
assert all(sha(v25[i]) == sha(out_rows[i]) for i in range(len(v25)))
print(f"G2 v2_25 既有 {len(v25)} 行逐行 sha 未变 ✅")
bad = [r["src_row"] for r in dedup if "is_confirmed" in r["messages"][1]["content"] + r["messages"][2]["content"]]
print(f"G3 is_confirmed 残留 = {len(bad)} ✅" if not bad else f"G3 ❌ {bad}")
cc = collections.Counter()
for r in out_rows:
    m = re.findall(r'"vulnerability_type"\s*:\s*"CWE-(\d+)(?!\d)', r["messages"][2]["content"])
    cc[m[-1] if m else None] += 1
print(f"G4 N = {len(out_rows)} | CWE-77 = {cc.get('77')} | CWE-78 = {cc.get('78')} | "
      f"77:78 = {cc.get('77',0)/max(cc.get('78',1),1):.4f} | system 种类 = "
      f"{len(set(r['messages'][0]['content'] for r in out_rows))}")
print(f"    新增行 oracle 分布: {collections.Counter(m['oracle'] for m in meta_print)}")

if DRY:
    print("\n[DRY-RUN] 未写盘。加 --apply 落库。")
else:
    with OUT.open("w", encoding="utf-8", newline="\n") as f:
        for r in out_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with CHANGELOG.open("w", encoding="utf-8", newline="\n") as f:
        for r, m in zip(dedup, meta_print):
            f.write(json.dumps({"date": "2026-09-14", "step": "v2_26_final_feed",
                                "action": "APPEND", "v2_26_src_row": r["src_row"],
                                "orig": m["orig"], "ver": m["ver"], "oracle": m["oracle"],
                                "source_pack": "feed_final_20260914"},
                               ensure_ascii=False) + "\n")
    h = hashlib.sha256(OUT.read_bytes()).hexdigest()
    print(f"\n已写 {OUT.name}  {len(out_rows)} 行  sha256 = {h}")
