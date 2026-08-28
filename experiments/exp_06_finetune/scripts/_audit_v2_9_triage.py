#!/usr/bin/env python3
"""v2.9 深挖 I：全部反向矛盾候选逐条输出裁定材料 + 补充扫描模式。"""
import json
import re
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data/final_train_chatml_alpha06_v2_9.jsonl"
OUT = Path(__file__).resolve().parent / "_audit_v2_9_triage_out.txt"
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

# 模式集（hv=False 时命中才算候选；每条给 240 字上下文）
PATTERNS = [
    # A. 结论段断言漏洞存在（无前置否定）
    (re.compile(r"(存在|构成|确认|判定|属于|触发|成立)[^。\n]{0,10}(漏洞|注入|越权|穿越|XSS|SSRF|溢出)"), "A"),
    (re.compile(r"攻击者可(注入|读取|执行|访问|越权|构造|获取)"), "A"),
    (re.compile(r"任意文件(读取|写入|执行)"), "A"),
    # B. 供词式变体（无'根据指令'但语义相同）
    (re.compile(r"(实际存在|实际上存在|确实存在)[^。\n]{0,16}漏洞"), "B"),
    (re.compile(r"漏洞(仍然|依然)(成立|存在|可用|可利用)"), "B"),
    (re.compile(r"(本|该)样本(应|应被)标记为"), "B"),
    (re.compile(r"标注(为|错误)"), "B"),
    # C. 洗白式：用代码外假设论证安全
    (re.compile(r"(假设|假定|若|如果)[^。\n]{0,30}(配置|部署|上游|运维|管理员)[^。\n]{0,20}(正确|妥当|合理|已?启用|过滤|校验)"), "C"),
]
NEG_BEFORE = re.compile(r"(不|无|非|未|无法|不能|阻断|拒绝|不存在|没有|排除|防御)[^。\n]{0,12}$")
HYPHO = re.compile(r"(即使|若|如果|假设|一旦|就算|除非|理论上|在.{0,6}场景下|理想)")

cands = {}
for i, r in enumerate(rows):
    obj, m = get_obj(r)
    if obj is None or obj.get("has_vulnerability") is not False:
        continue
    a = r["messages"][2]["content"]
    pre = a[: m.start()]
    # 扫三段：CoT 全文（重点结尾）+ explanation
    for zone_name, zone in (("cot尾", pre[-400:]), ("cot全文", pre),
                             ("expl", str(obj.get("explanation") or ""))):
        for pat, tag in PATTERNS:
            for mm in pat.finditer(zone):
                before = zone[: mm.start()]
                if NEG_BEFORE.search(before[-30:]):
                    continue
                s = max(0, mm.start() - 80)
                ctx = zone[s: mm.end() + 160].replace("\n", " ")
                # 假设语气在紧邻上下文出现 → 降级为 C 类观察项
                hypo = bool(HYPHO.search(ctx))
                key = (i, tag, zone_name)
                if key not in cands:
                    cands[key] = ctx
                break

# 输出：按 tag 分组，B 类最优先
w(f"候选总数（去重后样本级）: {len({i for i, _, _ in cands})}")
by_tag = {}
for (i, tag, zone), ctx in cands.items():
    by_tag.setdefault(tag, {}).setdefault(i, []).append((zone, ctx))

for tag in ("B", "C", "A"):
    w(f"\n{'='*70}\n=== {tag} 类（{len(by_tag.get(tag, {}))} 条）===")
    for i, items in sorted(by_tag.get(tag, {}).items()):
        obj, _ = get_obj(rows[i])
        meta = rows[i].get("meta") or {}
        w(f"\n--- #{i} kind={meta.get('kind') or 'old'} zones={[z for z, _ in items]}")
        for z, ctx in items[:2]:
            w(f"  [{z}] ...{ctx}...")

OUT.write_text("\n".join(buf), encoding="utf-8")
print(f"written; 样本级候选 {len({i for i, _, _ in cands})}")
