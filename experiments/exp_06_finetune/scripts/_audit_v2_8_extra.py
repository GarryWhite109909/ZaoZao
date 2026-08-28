#!/usr/bin/env python3
"""v2.8 补充审计：上轮盲区专项。
1) 反向矛盾扫描（hv=False 但 CoT 论证漏洞存在）
2) 扩展元话语残留
3) assistant 占位符污染（教师没填 schema 模板）
4) sink 行号语义锚定（声明的 API 是否真在该行）
5) 答案泄漏进代码注释（合成代码里写着 source/sink 提示）
6) meta.cwe 与输出 vt 漂移
7) 92 条 safe 语义注记的 explanation 是否已含推理（决定归一是否零损失）
8) v2.8 终态复核
"""
import json
import re
from collections import Counter
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data/final_train_chatml_alpha06_v2_8.jsonl"
OUT = Path(__file__).resolve().parent / "_audit_v2_8_extra_out.txt"
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
CODE_RE = re.compile(r"```([\w+#./-]*)\n(.*?)\n```", re.S)

rows = [json.loads(l) for l in DATA.read_text(encoding="utf-8").splitlines() if l.strip()]
buf = []
def w(s=""):
    buf.append(str(s))

w(f"v2.8 总条数 {len(rows)}")

def get_obj(r):
    m = JSON_RE.search(r["messages"][2]["content"])
    if not m:
        return None, None
    try:
        return json.loads(m.group(1)), m
    except Exception:
        return None, None

# ---------- 1) 反向矛盾：hv=False 但 CoT 断言漏洞存在 ----------
REV = re.compile(r"(存在|构成|确认|判定为|属于|触发|成立)[^。\n]{0,10}(漏洞|注入|越权|穿越|XSS|SSRF|溢出)|(漏洞|注入|越权|穿越)(成立|成功|可达)|攻击者可(注入|读取|执行|访问|越权|构造)|可被(注入|利用|攻击)|任意文件(读取|写入|执行)")
hits = []
for i, r in enumerate(rows):
    obj, m = get_obj(r)
    if obj is None or obj.get("has_vulnerability") is not False:
        continue
    pre = r["messages"][2]["content"][: m.start()]
    # 只看结尾结论段（最后 400 字符）降低误报
    tail = pre[-400:]
    for mm in REV.finditer(tail):
        s = max(0, mm.start() - 30)
        hits.append((i, tail[s: mm.end() + 30].replace("\n", " ")))
        break
w(f"\n[1] 反向矛盾候选（hv=False 且结论段断言漏洞）: {len(hits)} 条")
for i, ctx in hits[:30]:
    w(f"  #{i}: ...{ctx}...")

# ---------- 2) 扩展元话语残留 ----------
META2 = ["需假设", "假设存在", "构造漏洞", "制造漏洞", "标注实际", "为达到",
         "样例要求", "示例要求", "按要求", "硬标", "本应", "改为漏洞",
         "为满足", "已生成", "任务要求", "要求是", "需修正", "生成要求"]
res = []
for i, r in enumerate(rows):
    a = r["messages"][2]["content"]
    f = [t for t in META2 if t in a]
    if f:
        res.append((i, f))
w(f"\n[2] 扩展元话语残留: {len(res)} 条")
for i, f in res[:20]:
    w(f"  #{i} {f}")

# ---------- 3) 占位符污染 ----------
PH = ["用 -> 描述", "CWE-编号", "最小局部改正", "true/false", "污染来源（如", "危险点（如", "数据流/成因"]
ph_hits = []
for i, r in enumerate(rows):
    obj, m = get_obj(r)
    if obj is None:
        continue
    for k, v in obj.items():
        if isinstance(v, str):
            f = [p for p in PH if p in v]
            if f:
                ph_hits.append((i, k, f, v[:80]))
            if k == "has_vulnerability" and not isinstance(v, bool):
                ph_hits.append((i, k, ["非布尔"], str(v)[:40]))
w(f"\n[3] 占位符/类型污染: {len(ph_hits)} 条")
for i, k, f, v in ph_hits[:30]:
    w(f"  #{i} {k} {f} {v!r}")

# ---------- 4) sink 行号语义锚定 ----------
anchor_bad, anchor_oob, checked = [], [], 0
for i, r in enumerate(rows):
    obj, m = get_obj(r)
    if obj is None or obj.get("has_vulnerability") is not True:
        continue
    sk = str(obj.get("sink") or "")
    if sk.startswith("L"):  # crossfile 多文件格式，本轮跳过
        continue
    mm = re.match(r"line\s*(\d+)\s*:\s*(.+)", sk)
    if not mm:
        continue
    cm = CODE_RE.search(r["messages"][1]["content"])
    if not cm:
        continue
    code_lines = cm.group(2).split("\n")
    n = int(mm.group(1))
    if not (1 <= n <= len(code_lines)):
        anchor_oob.append((i, n, len(code_lines)))
        continue
    checked += 1
    rest = mm.group(2)
    toks = re.findall(r"[A-Za-z_][A-Za-z0-9_.]{2,}", rest)
    toks = [t for t in toks if not t.startswith("line")]
    if not toks:
        continue
    tok = max(toks, key=len).split(".")[0].lower()
    if tok in ("the", "this", "and", "into", "from", "with", "sql", "http", "html", "json", "url", "xss", "ssrf", "rce", "api"):
        toks2 = [t for t in toks if t.split(".")[0].lower() not in ("the", "this", "and", "into", "from", "with", "sql", "http", "html", "json", "url", "xss", "ssrf", "rce", "api", "line")]
        if not toks2:
            continue
        tok = max(toks2, key=len).split(".")[0].lower()
    if tok not in code_lines[n - 1].lower():
        anchor_bad.append((i, n, tok, code_lines[n - 1].strip()[:60]))
w(f"\n[4] sink 锚定: 核验 {checked} 条 | 行号越界 {len(anchor_oob)} | 语义不匹配 {len(anchor_bad)}")
for i, n, tok, ln in anchor_bad[:25]:
    w(f"  #{i} sink声称 line {n} 含 '{tok}'，实际该行: {ln!r}")
for i, n, tot in anchor_oob[:10]:
    w(f"  [oob] #{i} sink line {n} > 代码 {tot} 行")

# ---------- 5) 答案泄漏进代码注释 ----------
LEAK = re.compile(r"(//|#|\*|--|<!--)\s*.{0,50}(source[:：]|sink[:：]|attacker[- ]controlled|攻击者可控|漏洞点|vuln point|injection point|exploit)", re.I)
leak_by_kind = Counter()
leak_rows = []
for i, r in enumerate(rows):
    for lg, body in CODE_RE.findall(r["messages"][1]["content"]):
        if LEAK.search(body):
            kind = (r.get("meta") or {}).get("kind") or "old"
            leak_by_kind[kind] += 1
            leak_rows.append((i, kind))
            break
w(f"\n[5] 代码内答案泄漏注释: {len(leak_rows)} 条，按 kind: {dict(leak_by_kind)}")
for i, k in leak_rows[:15]:
    w(f"  #{i} kind={k}")

# ---------- 6) meta.cwe 与 vt 漂移 ----------
drift = []
for i, r in enumerate(rows):
    meta = r.get("meta") or {}
    mc = meta.get("cwe")
    if not mc:
        continue
    obj, m = get_obj(r)
    if obj is None or obj.get("has_vulnerability") is not True:
        continue
    vt = str(obj.get("vulnerability_type") or "")
    mm = re.match(r"CWE-(\d+)", vt)
    mo = re.match(r"CWE-(\d+)", str(mc))
    if mm and mo and mm.group(1) != mo.group(1):
        drift.append((i, mc, vt))
w(f"\n[6] meta.cwe vs vt 漂移: {len(drift)} 条")
for i, mc, vt in drift[:25]:
    w(f"  #{i} 种子={mc} 输出={vt}")

# ---------- 7) 92 条 safe 语义注记：explanation 是否已含推理 ----------
rich, poor = 0, 0
poor_rows = []
for i, r in enumerate(rows):
    obj, m = get_obj(r)
    if obj is None or obj.get("has_vulnerability") is not False:
        continue
    src, sk, exp = str(obj.get("source")), str(obj.get("sink")), str(obj.get("explanation") or "")
    if (src != "N/A" or sk != "N/A") and "line" in (src + sk):
        if len(exp) > 60 and ("->" in exp or "不可控" in exp or "常量" in exp or "可控" in exp):
            rich += 1
        else:
            poor += 1
            poor_rows.append((i, src[:40], sk[:40], exp[:60]))
w(f"\n[7] safe 语义注记样本: 推理已在 explanation {rich} 条 | explanation 缺推理 {poor} 条")
for i, s, k, e in poor_rows[:10]:
    w(f"  #{i} src={s!r} sink={k!r} exp={e!r}")

# ---------- 8) 终态复核 ----------
rl, bare, nofix = Counter(), 0, 0
for i, r in enumerate(rows):
    obj, m = get_obj(r)
    if obj is None:
        continue
    if obj.get("has_vulnerability") is True and "is_confirmed" not in obj:
        rl[obj.get("risk_level")] += 1
        vt = str(obj.get("vulnerability_type") or "")
        if re.match(r"^CWE-\d+$", vt):
            bare += 1
        if obj.get("fix_suggestion") == "no fix needed":
            nofix += 1
w(f"\n[8] 终态: risk_level={dict(rl)} | 裸编号 vt={bare} | vuln但no-fix={nofix}")

OUT.write_text("\n".join(buf), encoding="utf-8")
print("written")
