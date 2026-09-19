# -*- coding: utf-8 -*-
"""g27 教师产出解析 + 验收门 V-1~V-6 + 转入库格式（2026-09-14）

产出：corpus/repair_wave/g27_command_language.jsonl（messages 三元组 + fix_distill 元数据，同 g26 形态）
"""
import sys, os, json, re
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

WAVE = ROOT / "experiments/exp_06_finetune/corpus/repair_wave/wave2_g27"
V24 = ROOT / "experiments/exp_06_finetune/data/final_train_chatml_alpha06_v2_24_candidate_20260914.jsonl"

# system 必须与入库版本一致：取 v2_24 行 1 的主契约（全库唯一），不用 prompts.py 的 BASE_PROMPT
_v24_first = json.loads(next(l for l in V24.open(encoding="utf-8") if l.strip()))
BASE_PROMPT = _v24_first["messages"][0]["content"]
KITS = WAVE / "g27_kits.jsonl"
RESULT = WAVE / "result.txt"
OUT = ROOT / "experiments/exp_06_finetune/corpus/repair_wave/g27_command_language.jsonl"
CANON = ["has_vulnerability", "vulnerability_type", "risk_level", "source", "sink",
         "explanation", "fix_suggestion"]

kits = [json.loads(l) for l in KITS.open(encoding="utf-8") if l.strip()]
kit_by_id = {k["orig"]: k for k in kits}
expected_ids = [k["orig"] for k in kits]
print(f"出题包 {len(kits)} 条")

raw = RESULT.read_text(encoding="utf-8")

# ---- 切块：按 分析过程：
chunks = [c for c in raw.split("分析过程：") if c.strip()]
print(f"分析过程块 {len(chunks)} 个")

objs = []       # (id, obj)
narr = {}       # id -> narrative paragraph
for ci, ch in enumerate(chunks, 1):
    m = re.search(r"```json\s*(\[.*?\])\s*```", ch, re.S)
    if not m:
        print(f"  !! 块 {ci} 无 JSON 数组")
        continue
    arr = json.loads(m.group(1))
    # 抽本块各样本的叙事段
    paras = [p.strip() for p in ch.split("\n\n") if p.strip()]
    for j, o in enumerate(arr):
        oid = o.get("sample_id") or o.get("file") or o.get("file_name")
        if not oid:
            oid = expected_ids[len(objs)]          # 第 4 批无 id，按序补
        objs.append((oid, o))
        # 找包含该 id 的段落
        hit = [p for p in paras if oid in p]
        narr[oid] = hit[0] if hit else (paras[0] if paras else "")

print(f"解析出结论 {len(objs)} 条")
ids = [o for o, _ in objs]
print("V-1 块覆盖:", f"{len(set(ids))}/16", "✅" if len(set(ids)) == 16 else "❌",
      "" if len(set(ids)) == 16 else f"缺 {set(expected_ids)-set(ids)}")

# ---- 归一化 + 门
def norm_cwe(v):
    m = re.search(r"CWE-(\d+)(?!\d)", str(v or ""))
    return int(m.group(1)) if m else None

SINK_HINT = re.compile(r"awk|smtp|mail|rcpt|tex|latex|pdflatex|roff|groff|\blp\b|cups|"
                       r"exiftool|iptables|nft|fluentd|nginx", re.I)

rows, issues = [], []
import collections
gate = collections.Counter()
for oid, o in objs:
    cwe = norm_cwe(o.get("vulnerability_type"))
    hv = cwe is not None and cwe != 0
    risk = o.get("risk_level") or o.get("severity") or ""
    risk = {"high": "High", "medium": "Medium", "low": "Low", "critical": "Critical"}.get(
        str(risk).lower(), str(risk))
    fix = o.get("fix") or o.get("fix_suggestion") or ""
    obj7 = {
        "has_vulnerability": bool(hv),
        "vulnerability_type": f"CWE-{cwe} Command Injection" if cwe == 77 else
                              (f"CWE-{cwe}" if cwe else "none"),
        "risk_level": risk if hv else "None",
        "source": o.get("source", ""),
        "sink": o.get("sink", ""),
        "explanation": o.get("explanation", ""),
        "fix_suggestion": fix,
    }
    # V-3/V-4
    gate["cwe_77" if cwe == 77 else ("cwe_78" if cwe == 78 else "cwe_other")] += 1
    # V-6 行号范围（按物理行数计——教师纪律是"围栏后第 1 行 = 行 1"，含空行）
    kit = kit_by_id[oid]
    code = re.search(r"```[a-zA-Z0-9_+\-]*\n(.*?)```", kit["user"], re.S).group(1)
    nlines = len(code.rstrip("\n").split("\n"))
    oob = []
    for field in ("source", "sink"):
        for ln in re.findall(r"line (\d+)", str(obj7[field])):
            if not (1 <= int(ln) <= max(nlines, 0)):
                oob.append(f"{field}:line {ln}>{nlines}")
    if oob:
        gate["行号越界"] += 1
        issues.append(f"{oid}: {oob}")
    # G2 sink 特征
    if not SINK_HINT.search(str(obj7["sink"])):
        gate["sink无解释器特征"] += 1
        issues.append(f"{oid}: sink 未提及解释器")
    # G4 契约
    if any(not str(obj7[k]).strip() for k in CANON):
        gate["契约空字段"] += 1
        issues.append(f"{oid}: 契约有空字段")
    # 风险等级合法
    if risk not in ("Critical", "High", "Medium", "Low", "None"):
        gate["risk非法"] += 1
        issues.append(f"{oid}: risk={risk!r}")

    narrative = narr.get(oid, "")
    assistant = (f"分析过程：\n{narrative}\n\n"
                 "```json\n" + json.dumps(obj7, ensure_ascii=False) + "\n```")
    rows.append({
        "messages": [
            {"role": "system", "content": BASE_PROMPT},
            {"role": "user", "content": kit["user"]},
            {"role": "assistant", "content": assistant},
        ],
        "fix_distill": {"teacher": "glm-5.3-flash-web(g27)", "generated_at": "2026-09-14",
                        "orig": oid, "gate_note": "web 投喂，人工回填"},
    })

# ---- 汇总
print("\n" + "=" * 78)
print("验收门读数")
c77, c78, c_other = gate["cwe_77"], gate["cwe_78"], gate["cwe_other"]
print(f"V-1 块覆盖 16/16            : {'✅' if len(set(ids))==16 else '❌'}")
print(f"V-2 has_vulnerability=true  : {sum(1 for _,o in objs if norm_cwe(o.get('vulnerability_type')))} / 16")
print(f"V-3 CWE 落在 77/78 族       : {c77+c78} / 16  {'✅' if c77+c78==16 else '❌'}")
print(f"V-4 判 78 的条数            : {c78}  {'✅ (≤2)' if c78<=2 else '❌ (>2，先裁决再入库)'}")
risk_cnt = collections.Counter((o.get('risk_level') or o.get('severity') or '') for _, o in objs)
print(f"V-5 风险分布                : {dict(risk_cnt)}  (Critical={risk_cnt.get('Critical',0)}，未虚高 {'✅' if risk_cnt.get('Critical',0)==0 else '⚠️'})")
print(f"V-6 行号越界                : {gate['行号越界']}  {'✅' if gate['行号越界']==0 else '❌ ' + str(issues[:3])}")
print(f"G2 sink 解释器特征缺失      : {gate['sink无解释器特征']}")
print(f"G4 契约空字段               : {gate['契约空字段']}")
print(f"risk 非法                   : {gate['risk非法']}")
if issues:
    print("\n问题明细（前 8 条）:")
    for x in issues[:8]:
        print("   ", x)

print("\n教师行为抽查（新增追加层七是否被使用）:")
for pat, label in [(r"样本内(无法|非全)可证|理论链", "L1 样本内可证/理论链"),
                   (r"存在完整污点链，可直接确认", "F11 证据层级"),
                   (r"不经 OS shell|列表不经 OS shell|无 OS shell", "77/78 双亚型"),
                   (r"伴生", "F10 主次关系")]:
    n = len(re.findall(pat, raw))
    print(f"   {label:<22} 命中 {n}")

# ---- 写入库格式
if len(set(ids)) == 16 and c78 <= 2 and gate["行号越界"] == 0:
    with OUT.open("w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"\n✅ 已写 {OUT}  {len(rows)} 条（可并入 v2_25）")
else:
    print("\n❌ 未达入库条件，先裁决再入库")
