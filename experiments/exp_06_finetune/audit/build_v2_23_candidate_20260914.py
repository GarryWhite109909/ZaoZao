# -*- coding: utf-8 -*-
"""
build_v2_23_candidate_20260914.py
v2_22 → v2_23：补漏波次（v2_22 已完成的 W-A/B/C/D 不重跑）

新增：
  W-B2  代码区英文答案注释清空（v2_22 的 W-B 词表只有中文）
  W-D2  叙事暴露教师身份清除（「教师原 fix…」「教师完全漏报」）
  W-D3  『防御迷惑』泛形式中性化（不只固定串「防御迷惑样本」）
  W-F2  中文合成占位注释清空（「# FIXME: 需要添加单元测试」）
  W-G   花括号双写解双（整块判定：块内不存在单花括号且存在签名/控制流 `{{`）

约束：保行数（G1）、代码指纹不变（G2''，指纹内已归一花括号）、JSON 7 键（G3）、
      角色结构（G4）。--dry-run 只出清单不写盘。
"""
import json, io, os, re, sys, hashlib, collections

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune"
SRC = os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_22_candidate_20260914.jsonl")
DST = os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_23_candidate_20260914.jsonl")
AUD = os.path.join(ROOT, "audit")
CHANGELOG = os.path.join(AUD, "v2_23_candidate_changelog_20260914.jsonl")
DRY = "--dry-run" in sys.argv
ONLY = [a[2:] for a in sys.argv if a.startswith("--w=")]

KEYS = ["has_vulnerability", "vulnerability_type", "risk_level", "source", "sink",
        "explanation", "fix_suggestion"]
CODE_RE = re.compile(r"```([a-zA-Z0-9_+#\-\.]*)[ \t]*\n(.*?)```", re.S)
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
DOC_RE = re.compile(r'("""|\'\'\')([\s\S]*?)\1')

rows = [json.loads(l) for l in io.open(SRC, encoding="utf-8") if l.strip()]
SRC_SHA = hashlib.sha256(open(SRC, "rb").read()).hexdigest()
print(f"SRC rows={len(rows)} sha256={SRC_SHA[:16]}… dry={DRY} only={ONLY or 'ALL'}")


def on(w):
    return (not ONLY) or (w in ONLY)


def msgs(r):
    return {m["role"]: m["content"] for m in r["messages"]}


# ==================================================== 注释扫描（引号感知）
def _comment_start(line):
    i, n, q = 0, len(line), None
    while i < n:
        c = line[i]
        if q:
            if c == "\\":
                i += 2
                continue
            if c == q:
                q = None
            i += 1
            continue
        if c in "\"'`":
            q = c
            i += 1
            continue
        if line.startswith("//", i) or line.startswith("/*", i):
            return i, line[i:i + 2]
        if line.startswith("<!--", i):
            return i, "<!--"
        if c == "#":
            rest = line[i + 1:].lstrip()
            if not re.match(r"(include|define|ifdef|ifndef|endif|pragma|error|warning|"
                            r"undef|region|endregion)\b", rest):
                return i, "#"
        i += 1
    return None


def iter_units(body):
    lines = body.split("\n")
    units, i = [], 0
    while i < len(lines):
        line = lines[i]
        cs = _comment_start(line)
        if cs is None:
            i += 1
            continue
        pos, marker = cs
        if marker in ("/*", "<!--"):
            em = "*/" if marker == "/*" else "-->"
            tail = line[pos + len(marker):]
            if em in tail:
                units.append((i, i, line[:pos], marker, line[pos:], True))
                i += 1
                continue
            j = i + 1
            while j < len(lines) and em not in lines[j]:
                j += 1
            if j >= len(lines):
                i += 1
                continue
            mp = lines[j].find(em)
            safe = not lines[j][mp + len(em):].strip()
            for k in range(i + 1, j + 1):
                s = lines[k].lstrip()
                if not (s.startswith("*") or s.startswith(em) or s == ""):
                    safe = False
            units.append((i, j, line[:pos], marker, "", safe))
            i = j + 1
            continue
        units.append((i, i, line[:pos], marker, line[pos:], True))
        i += 1
    return units


def skeleton(body):
    lines = body.split("\n")
    keep = list(lines)
    for s, e, pre, marker, ct, safe in iter_units(body):
        keep[s] = pre
        for k in range(s + 1, e + 1):
            keep[k] = ""
        if e > s:
            em = "*/" if marker == "/*" else ("-->" if marker == "<!--" else "")
            if em:
                mp = lines[e].find(em)
                if mp >= 0:
                    keep[e] = lines[e][mp + len(em):]
    return "\n".join(keep)


def fp(body):
    """代码指纹：剥注释 + 剥 docstring 内文 + 连续花括号压成单个（幂等）+ 空白归一。"""
    b = skeleton(body)
    b = DOC_RE.sub(lambda m: m.group(1) + m.group(1), b)
    b = re.sub(r"\{\{+", "{", b)          # 幂等：}}}} → }、{{ → {
    b = re.sub(r"\}+", "}", b)
    return re.sub(r"[ \t]+", " ", b)


# ==================================================== W-B2 英文答案注释
EN_TRIGGER = re.compile(
    r"\b(?:BUG|VULNERABLE|VULN|INSECURE|UNSAFE|DANGEROUS|EXPLOITABLE|EXPLOIT)\b|"
    r"dangling|double\s+free|second\s+free|use[- ]after[- ]free|"
    r"no\s+escap\w*|not\s+escap\w*|without\s+escap\w*|unescap\w*|not\s+escaped|"
    r"(?:command|code|sql|ldap|xpath|template|log|crlf|header)\s+injection|"
    r"(?:buffer|integer|heap|stack|memory)\s+overflow|out[- ]of[- ]bounds|"
    r"path\s+traversal|directory\s+traversal|prototype\s+pollution|"
    r"bypass\w*|unsanitiz\w*|unvalidat\w*|uncheck\w*|unescap\w*|"
    r"missing\s+(?:check|validation|sanitization|bounds|escaping)|"
    r"allows?\s+(?:an?\s+)?attacker|attacker[- ](?:controlled|supplied|can)|"
    r"malicious|crafted|tainted|"
    r"user[- ](?:input|controlled|supplied)|untrusted|raw\s+input|external\s+input|"
    r"(?:no|without|missing|lacks?)\s+(?:validation|sanitization|escaping|checking|"
    r"bounds|verification|authentication|authorization)|"
    r"\b(?:FIXME|XXX|HACK)\b",
    re.I)


def apply_WB2(body, row, events):
    """英文答案注释：触发即整条清空（与 W-B 同策略）。"""
    lines = body.split("\n")
    for s, e, pre, marker, ct, safe in iter_units(body):
        if not ct.strip() or not EN_TRIGGER.search(ct):
            continue
        if not safe:
            events.append(dict(row=row, wave="W-B2", kind="SKIP_UNSAFE", block_line=s + 1,
                               before=ct.strip()[:120]))
            continue
        lines[s] = pre
        for k in range(s + 1, e + 1):
            lines[k] = ""
        events.append(dict(row=row, wave="W-B2", kind="BLANK", block_line=s + 1,
                           before=ct.strip()[:150]))
    return "\n".join(lines)


# ==================================================== W-F2 中文合成占位
PLACEHOLDER = re.compile(
    r"需要(?:添加|补充|优化|完善|实现)|待(?:实现|补充|完善|添加)|"
    r"此处省略|省略若干|示例注释|示例代码|伪代码|TODO:\s*$")
CN_ONLY = re.compile(r"[\u4e00-\u9fff]")


def apply_WF2(body, row, events):
    """中文合成占位注释（蒸馏模板填充）清空；英文原生 TODO 保留。"""
    lines = body.split("\n")
    for s, e, pre, marker, ct, safe in iter_units(body):
        c = ct.strip()
        if not c or not PLACEHOLDER.search(c) or not CN_ONLY.search(c):
            continue
        if not safe:
            continue
        lines[s] = pre
        for k in range(s + 1, e + 1):
            lines[k] = ""
        events.append(dict(row=row, wave="W-F2", kind="BLANK", block_line=s + 1, before=c[:120]))
    return "\n".join(lines)


# ==================================================== W-G 花括号双写解双
SIG_BRACE = re.compile(
    r"(?m)^[^\n]*\)\s*\{\{\s*$|"
    r"^\s*(?:if|else|for|while|do|try|catch|finally|switch)\b[^\n]*\{\{\s*$")


def apply_WG(body, row, events):
    """仅当：① 块内不存在单花括号（100% 双写）② 存在函数签名/控制流 + {{ 。
    两个条件同时满足才整块 {{→{ 、}}→}。"""
    n2, c2 = body.count("{{"), body.count("}}")
    if n2 == 0 or n2 != c2:
        return body
    if (body.count("{") - n2 * 2) != 0 or (body.count("}") - c2 * 2) != 0:
        return body
    if not SIG_BRACE.search(body):
        return body
    events.append(dict(row=row, wave="W-G", kind="DEBRACE",
                       before=f"{{{{×{n2} }}}}×{c2}", sample=SIG_BRACE.search(body).group(0).strip()[:80]))
    return body.replace("{{", "{").replace("}}", "}")


# ==================================================== W-D2 教师身份
TEACHER_SUBS = [
    (re.compile(r"教师原\s*fix"), "原修复思路"),
    (re.compile(r"教师完全漏报"), "此前分析完全漏报"),
    (re.compile(r"教师全文漏报"), "此前分析全文漏报"),
    (re.compile(r"教师完全遗漏"), "此前分析完全遗漏"),
    (re.compile(r"教师漏报"), "此前分析漏报"),
    (re.compile(r"教师未识别"), "此前分析未识别"),
    (re.compile(r"教师未提"), "此前分析未提"),
    (re.compile(r"教师未识别"), "此前分析未识别"),
    (re.compile(r"教师零提及"), "此前分析未提及"),
    (re.compile(r"教师仅称"), "此前分析仅称"),
    (re.compile(r"教师仅把"), "此前分析仅把"),
    (re.compile(r"教师所举"), "原分析所举"),
    (re.compile(r"教师所报"), "原分析所报"),
    (re.compile(r"教师声称"), "原分析声称"),
    (re.compile(r"教师此前依赖"), "此前分析依赖"),
    (re.compile(r"教师跟随"), "此前分析跟随"),
    (re.compile(r"教师沿\s*"), "此前分析沿 "),
    (re.compile(r"教师主判"), "原判定"),
    (re.compile(r"教师裁决"), "原判定"),
    (re.compile(r"教师方案"), "原方案"),
    (re.compile(r"教师正文"), "原分析正文"),
    (re.compile(r"教师行号"), "原分析行号"),
    (re.compile(r"教师\s*PoC"), "原分析 PoC"),
    (re.compile(r"教师(原|的)"), r"原分析\1"),
    (re.compile(r"教师"), "原分析"),
]


def apply_WD2(a, row, events):
    for rx, rep in TEACHER_SUBS:
        h = rx.findall(a)
        if not h:
            continue
        events.append(dict(row=row, wave="W-D2", kind="TEACHER", before=rx.pattern[:40],
                           after=rep, count=len(h)))
        a = rx.sub(rep, a)
    # 中文语序里不留西文空格（「教师原 fix 把…」→「原修复思路 把」的残留空格）
    a = re.sub(r"(原修复思路|原分析|此前分析|原判定|原方案)\s+(?=[\u4e00-\u9fff])", r"\1", a)
    return a


# ==================================================== W-D3 防御迷惑泛形式
DM_SUBS = [
    (re.compile(r"防御迷惑样本|迷惑防御样本"), "该情形"),
    (re.compile(r"防御迷惑(?:点|分析|验证|逻辑|代码|核心|模式|测试|检查|部分|环节|"
                r"体现在|的核心|被绕过|1|2|3)?"), "防御设计"),
    (re.compile(r"迷惑防御(?:分析|验证|点|逻辑|代码)?"), "防御设计"),
]


def apply_WD3(a, row, events):
    for rx, rep in DM_SUBS:
        h = rx.findall(a)
        if not h:
            continue
        events.append(dict(row=row, wave="W-D3", kind="TERM", before=rx.pattern[:40],
                           after=rep, count=len(h)))
        a = rx.sub(rep, a)
    # 仅做标点层清理，**不动空白格式**（全局压空白会波及整个叙事/代码块）
    a = re.sub(r"防御设计\s*[：:]\s*", "防御设计：", a)
    a = re.sub(r"([，,。；;])\s*防御设计\s*(?=[，,。；;])", r"\1", a)
    a = re.sub(r"(?m)^[ \t]*防御设计[ \t]*$", "", a)
    return a


# ==================================================== 主流程
events = []
out = []
stats = collections.Counter()
for i, r in enumerate(rows):
    o = json.loads(json.dumps(r, ensure_ascii=False))
    m = msgs(o)
    u, a = m["user"], m["assistant"]
    if on("B2") or on("F2") or on("G"):
        def code_sub(mt):
            lang, body = mt.group(1), mt.group(2)
            if on("G"):
                b = apply_WG(body, i, events)
                if b != body:
                    stats["WG"] += 1
                    body = b
            if on("B2"):
                b = apply_WB2(body, i, events)
                if b != body:
                    stats["WB2"] += 1
                    body = b
            if on("F2"):
                b = apply_WF2(body, i, events)
                if b != body:
                    stats["WF2"] += 1
                    body = b
            return "```" + lang + "\n" + body + "```"
        u = CODE_RE.sub(code_sub, u)
    if on("D2"):
        b = apply_WD2(a, i, events)
        if b != a:
            stats["WD2"] += 1
        a = b
    if on("D3"):
        b = apply_WD3(a, i, events)
        if b != a:
            stats["WD3"] += 1
        a = b
    for mm in o["messages"]:
        if mm["role"] == "user":
            mm["content"] = u
        elif mm["role"] == "assistant":
            mm["content"] = a
    out.append(o)

print("事件统计:", dict(stats), "| 事件总数:", len(events))
print("事件类型:", dict(collections.Counter(e["kind"] for e in events)))

# ==================================================== 门禁
bad = collections.Counter()
ex = collections.defaultdict(list)
for i, (r0, r1) in enumerate(zip(rows, out)):
    m0, m1 = msgs(r0), msgs(r1)
    c0 = [x.group(2) for x in CODE_RE.finditer(m0["user"])]
    c1 = [x.group(2) for x in CODE_RE.finditer(m1["user"])]
    if len(c0) != len(c1):
        bad["G-块数"] += 1
        ex["G-块数"].append(i)
        continue
    for a0, a1 in zip(c0, c1):
        if len(a0.split("\n")) != len(a1.split("\n")):
            bad["G1-行数"] += 1
            ex["G1-行数"].append(i)
        if fp(a0) != fp(a1):
            bad["G2-指纹"] += 1
            ex["G2-指纹"].append(i)
    if [x["role"] for x in r1["messages"]] != ["system", "user", "assistant"]:
        bad["G4-角色"] += 1
    mt = list(JSON_RE.finditer(m1["assistant"]))
    if not mt:
        bad["G3-缺失"] += 1
    else:
        try:
            o = json.loads(mt[-1].group(1))
            if list(o.keys()) != KEYS:
                bad["G3-键序"] += 1
            if not isinstance(o.get("has_vulnerability"), bool):
                bad["G3-bool"] += 1
        except Exception:
            bad["G3-解析"] += 1
print("门禁违例:", dict(bad) or "0 全通过")
for k, v in ex.items():
    print("   ", k, v[:10])

# ==================================================== 泄漏回扫
g5 = collections.Counter()
for i, r in enumerate(out):
    m = msgs(r)
    for mt in CODE_RE.finditer(m["user"]):
        body = mt.group(2)
        for _, _, _, _, ct, _ in iter_units(body):
            if EN_TRIGGER.search(ct):
                g5["残留 英文答案注释"] += 1
            if PLACEHOLDER.search(ct) and CN_ONLY.search(ct):
                g5["残留 中文占位"] += 1
    if "教师" in m["assistant"]:
        g5["残留 教师"] += 1
    if re.search(r"防御迷惑|迷惑防御", m["assistant"]):
        g5["残留 防御迷惑"] += 1
    for mt in CODE_RE.finditer(m["user"]):
        b = mt.group(2)
        n2, c2 = b.count("{{"), b.count("}}")
        if n2 and n2 == c2 and (b.count("{") - n2 * 2) == 0 and (b.count("}") - c2 * 2) == 0 \
                and SIG_BRACE.search(b):
            g5["残留 花括号双写"] += 1
print("G5 回扫:", dict(g5) or "0 全通过")


# ==================================================== 写盘
if not DRY:
    with io.open(DST, "w", encoding="utf-8", newline="\n") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with io.open(CHANGELOG, "w", encoding="utf-8", newline="\n") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    sha = hashlib.sha256(open(DST, "rb").read()).hexdigest()
    print(f"[WROTE] {DST}\n        sha256={sha}\n        事件 {len(events)} → {CHANGELOG}")
else:
    print("[DRY-RUN] 未写盘")

print("=" * 25, "W-G 解双样例")
for e in [x for x in events if x["wave"] == "W-G"][:10]:
    print("  row %-5d %-12s %s" % (e["row"], e["before"], e["sample"]))
print("=" * 25, "W-B2 样例")
for e in [x for x in events if x["wave"] == "W-B2" and x["kind"] == "BLANK"][:15]:
    print("  row %-5d L%-4d %s" % (e["row"], e["block_line"], e["before"]))
print("=" * 25, "W-D2 教师样例")
for e in [x for x in events if x["wave"] == "W-D2"][:12]:
    print("  row %-5d %-22s → %-14s ×%d" % (e["row"], e["before"], e["after"], e["count"]))
print("=" * 25, "W-D3 防御迷惑样例")
for e in [x for x in events if x["wave"] == "W-D3"][:8]:
    print("  row %-5d %-24s → %-10s ×%d" % (e["row"], e["before"], e["after"], e["count"]))
print("=" * 25, "W-F2 占位样例")
for e in [x for x in events if x["wave"] == "W-F2"][:10]:
    print("  row %-5d L%-4d %s" % (e["row"], e["block_line"], e["before"]))
