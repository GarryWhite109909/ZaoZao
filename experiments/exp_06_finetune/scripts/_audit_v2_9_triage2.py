#!/usr/bin/env python3
"""v2.9 深挖 II：explanation 字段（结论性）+ CoT 末句 的严格反向断言扫描。"""
import json
import re
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data/final_train_chatml_alpha06_v2_9.jsonl"
OUT = Path(__file__).resolve().parent / "_audit_v2_9_triage2_out.txt"
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)

rows = [json.loads(l) for l in DATA.read_text(encoding="utf-8").splitlines() if l.strip()]
buf = []
def w(s=""):
    buf.append(str(s))

def get_obj(r):
    m = JSON_RE.search(r["messages"][2]["content"])
    if not m:
        return None, None
    try:
        return json.loads(m.group(1)), m
    except Exception:
        return None, None

# explanation 里的强断言（结论性字段，直接表达教师真实判断）
STRONG = [
    re.compile(r"(整体|实际上?|本质上?)(?<!不)(不安全|存在|构成)", ),
    re.compile(r"需修复|应修复|须修复|需要修复"),
    re.compile(r"(?<![不无未])(存在|构成|属于)(可利用|可注入|真实|实际|成功)"),
    re.compile(r"漏洞(成立|可利用|未被阻断|未被防御|仍然存在|依然存在)"),
    re.compile(r"应标记为有漏洞|应判为漏洞|应判(定)?为不安全|标错|标注错误"),
    re.compile(r"攻击者可(成功|实际|轻易)?(注入|读取|执行|访问|越权|获取|绕过)"),
    re.compile(r"注入(成功|成立|可达|未被阻断)"),
    re.compile(r"(?<![不无未])可被(利用|注入|攻击|绕过)"),
    re.compile(r"因此不安全|故不安全|综上.{0,6}不安全"),
]
hits = []
for i, r in enumerate(rows):
    obj, m = get_obj(r)
    if obj is None or obj.get("has_vulnerability") is not False:
        continue
    expl = str(obj.get("explanation") or "")
    # CoT 最后一行结论句
    pre = r["messages"][2]["content"][: m.start()]
    last = pre.strip().split("\n")[-1] if pre.strip() else ""
    for zone_name, zone in (("expl", expl), ("cot末句", last)):
        for pat in STRONG:
            mm = pat.search(zone)
            if mm:
                # 前置否定再排一次（正则里部分已带，这里兜底）
                s = max(0, mm.start() - 40)
                ctx = zone[s: mm.end() + 120].replace("\n", " ")
                hits.append((i, zone_name, ctx))
                break

w(f"强断言命中: {len(hits)} 条（样本级 {len({h[0] for h in hits})}）")
for i, zn, ctx in hits:
    meta = rows[i].get("meta") or {}
    w(f"\n--- #{i} [{zn}] kind={meta.get('kind') or 'old'}")
    w(f"  ...{ctx}...")

OUT.write_text("\n".join(buf), encoding="utf-8")
print(f"written; 样本级 {len({h[0] for h in hits})}")
