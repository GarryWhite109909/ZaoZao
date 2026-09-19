# -*- coding: utf-8 -*-
"""v2_22 独立验证（脱离构建器）：门禁复算 + 逐项对账 + 改动面统计"""
import json, io, re, sys, hashlib, collections
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune"
P21 = ROOT + r"\data\final_train_chatml_alpha06_v2_21_candidate_20260914.jsonl"
P22 = ROOT + r"\data\final_train_chatml_alpha06_v2_22_candidate_20260914.jsonl"
CHG = ROOT + r"\audit\v2_22_candidate_changelog_20260914.jsonl"

r21 = [json.loads(l) for l in io.open(P21, encoding="utf-8") if l.strip()]
r22 = [json.loads(l) for l in io.open(P22, encoding="utf-8") if l.strip()]
print("rows", len(r21), "->", len(r22))
print("sha v2_21", hashlib.sha256(open(P21, "rb").read()).hexdigest()[:16])
print("sha v2_22", hashlib.sha256(open(P22, "rb").read()).hexdigest()[:16])
ev = [json.loads(l) for l in io.open(CHG, encoding="utf-8") if l.strip()]
print("changelog 事件", len(ev), dict(collections.Counter(e["kind"] for e in ev)))


def msgs(r):
    return {m["role"]: m["content"] for m in r["messages"]}


CODE = re.compile(r"```([a-zA-Z0-9_+#\-\.]*)[ \t]*\n(.*?)```", re.S)


def blocks(u):
    return [m.group(2) for m in CODE.finditer(u)]


# ---------- 引号感知骨架（与构建器同源，用于 G2 精判） ----------
def _cs(line):
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


def _units(body):
    lines = body.split("\n")
    units, i = [], 0
    while i < len(lines):
        line = lines[i]
        cs = _cs(line)
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


def strip_comments(body):
    """引号感知：剥掉注释后只留代码文本（不含注释的任何字符）。"""
    lines = body.split("\n")
    keep = list(lines)
    for s, e, pre, marker, ct, safe in _units(body):
        keep[s] = pre
        for k in range(s + 1, e + 1):
            keep[k] = ""
        if e > s:
            em = "*/" if marker == "/*" else ("-->" if marker == "<!--" else "")
            if em:
                mp = lines[e].find(em)
                if mp >= 0:
                    keep[e] = lines[e][mp + len(em):]
    return re.sub(r"[ \t]+", " ", "\n".join(keep)).strip()


DOC_RE = re.compile(r'("""|\'\'\')([\s\S]*?)\1')


def fp(body):
    """代码指纹：剥注释 + 剥 docstring 内文 + 归一空白。"""
    b = strip_comments(body)
    b = DOC_RE.sub(lambda m: m.group(1) + m.group(1), b)
    return re.sub(r"[ \t]+", " ", b).strip()


bad = collections.Counter()
ex = collections.defaultdict(list)
changed_user, changed_asst = [], []
for i, (a, b) in enumerate(zip(r21, r22)):
    ma, mb = msgs(a), msgs(b)
    if ma["user"] != mb["user"]:
        changed_user.append(i)
    if ma["assistant"] != mb["assistant"]:
        changed_asst.append(i)
    if ma["system"] != mb["system"]:
        bad["system被改"] += 1
    ba, bb = blocks(ma["user"]), blocks(mb["user"])
    if len(ba) != len(bb):
        bad["块数"] += 1
        ex["块数"].append(i)
        continue
    for x, y in zip(ba, bb):
        if len(x.split("\n")) != len(y.split("\n")):
            bad["G1行数"] += 1
            ex["G1行数"].append(i)
        if fp(x) != fp(y):
            bad["G2骨架"] += 1
            ex["G2骨架"].append(i)
    if [m["role"] for m in b["messages"]] != ["system", "user", "assistant"]:
        bad["G4角色"] += 1

print("改动行：user", len(changed_user), "| assistant", len(changed_asst))
print("assistant 改动行明细:", changed_asst)
print("门禁违例:", dict(bad) or "0 全通过")
for k, v in ex.items():
    print("   ", k, v[:12])

# G2 差异定位
if ex.get("G2骨架"):
    print("=" * 20, "G2 差异定位（前 5 行）")
    shown = 0
    for i in ex["G2骨架"]:
        ba, bb = blocks(msgs(r21[i])["user"]), blocks(msgs(r22[i])["user"])
        done = False
        for x, y in zip(ba, bb):
            sa, sb = fp(x), fp(y)
            if sa != sb:
                print(f"--- row {i}")
                la, lb = sa.split("\n"), sb.split("\n")
                for k in range(max(len(la), len(lb))):
                    va = la[k] if k < len(la) else "<无>"
                    vb = lb[k] if k < len(lb) else "<无>"
                    if va != vb:
                        print(f"    L{k+1} 21<{va.strip()[:70]}> | 22<{vb.strip()[:70]}>")
                done = True
                break
        if done:
            shown += 1
            if shown >= 5:
                break

# ---------- 泄漏回扫 ----------
HEAD_RE = re.compile(r"^代码片段\s*（\s*文件名\s*[:：]\s*(?P<fn>.+?)\s*[，,]\s*语言\s*[:：]\s*(?P<lang>.+?)\s*）\s*[:：]?\s*$")
LEAK_PFX = re.compile(r"^(?:vuln|safe|noise|distill|supplement|unsafe|weak|strong|bad|good|evil|malicious)[_\-]", re.I)
MAL = re.compile(r"[${}<>\s\"';`|]")
R = collections.Counter()
for i, b in enumerate(r22):
    m = msgs(b)
    first = m["user"].partition("\n")[0]
    mp = HEAD_RE.match(first)
    if mp:
        R["头部有文件名"] += 1
        fn = mp.group("fn").strip()
        if LEAK_PFX.match(fn):
            R["🔴头部泄漏前缀残留"] += 1
        if MAL.search(fn):
            R["🔴头部畸形名残留"] += 1
        if re.match(r"^module_\d{5}\.", fn):
            R["中性名"] += 1
    for body in blocks(m["user"]):
        if re.search(r"distill_glm", body, re.I):
            R["🔴distill_glm 残留"] += 1
        if re.search(r"Defense\s*attempt|防御尝试", body, re.I):
            R["🔴Defense attempt 残留"] += 1
        if re.search(r"漏洞[点：:]|迷惑性|伪装防御|原缺陷", body):
            R["🔴漏洞标记残留"] += 1
        if re.search(r"存在[\w\u4e00-\u9fff]{0,10}漏洞", body):
            R["🔴存在XX漏洞残留"] += 1
        if re.search(r"(?m)^\s*(#|//|/\*)\s*(vuln_|safe_|noise_|distill_)", body, re.I):
            R["🔴代码内泄漏文件名注释"] += 1
print("泄漏回扫:", dict(R))

# 残留明细
print("=" * 20, "残留明细")
for i, b in enumerate(r22):
    m = msgs(b)
    for body in blocks(m["user"]):
        for pat, tag in ((r"存在[\w\u4e00-\u9fff]{0,10}漏洞", "存在XX漏洞"),
                         (r"漏洞[点：:]|迷惑性|伪装防御|原缺陷", "漏洞标记"),
                         (r"(?m)^\s*(#|//|/\*)\s*(vuln_|safe_|noise_|distill_)", "代码内泄漏文件名")):
            mt = re.search(pat, body)
            if mt:
                ln = body[:mt.start()].count("\n") + 1
                print(f"  [{tag}] row {i} L{ln} …{body[max(0,mt.start()-40):mt.start()+60].replace(chr(10),' ')}…")
    first = m["user"].partition("\n")[0]
    if HEAD_RE.match(first) and (LEAK_PFX.match(HEAD_RE.match(first).group("fn").strip()) or MAL.search(HEAD_RE.match(first).group("fn"))):
        print(f"  [头部] row {i} {first[:80]}")
print("  第一行结构样例:", repr(msgs(r22[1770])["user"].partition("\n")[0]))
print("  第一行结构样例2:", repr(msgs(r22[4])["user"].partition("\n")[0]))

# ---------- 正负/契约不变 ----------
def concl(a):
    mt = list(re.finditer(r"```json\s*(\{.*?\})\s*```", a, re.S))
    return json.loads(mt[-1].group(1)) if mt else None


c21 = collections.Counter()
c22 = collections.Counter()
chg_json = 0
for a, b in zip(r21, r22):
    ca, cb = concl(msgs(a)["assistant"]), concl(msgs(b)["assistant"])
    if ca and cb:
        c21[ca["has_vulnerability"]] += 1
        c22[cb["has_vulnerability"]] += 1
        if ca["has_vulnerability"] != cb["has_vulnerability"]:
            bad["🔴has_vulnerability被改"] += 1
        elif ca != cb:
            chg_json += 1
print("正负 v2_21", dict(c21), "v2_22", dict(c22),
      "| 🔴has_vulnerability 被改:", bad["🔴has_vulnerability被改"], "| JSON 内容变化(非正负):", chg_json)

# ---------- 头部泄漏面（v2_21 原始口径复核） ----------
FX = re.compile(r"\b(vuln_|safe_|noise_)[A-Za-z0-9_]*\.(?:py|js|jsx|ts|tsx|go|java|c|cpp|php|rb|sh|json|ya?ml|toml|conf|html|xml|sql|txt|md)\b")
n21 = sum(1 for r in r21 if FX.search(msgs(r)["user"]))
n22 = sum(1 for r in r22 if FX.search(msgs(r)["user"]))
print(f"报告口径（vuln_/safe_/noise_ 文件名）: v2_21 {n21} -> v2_22 {n22}")

# 全部泄漏语义前缀（含 supplement_/distill_/畸形）
LT = re.compile(r"(vuln_|safe_|noise_|distill_|supplement_|unsafe_|weak_|strong_|bad_|good_)", re.I)
h21 = sum(1 for r in r21 if HEAD_RE.match(msgs(r)["user"].partition("\n")[0]) and LT.search(msgs(r)["user"].partition("\n")[0]))
h22 = sum(1 for r in r22 if HEAD_RE.match(msgs(r)["user"].partition("\n")[0]) and LT.search(msgs(r)["user"].partition("\n")[0]))
print(f"全量泄漏语义前缀（头部）: v2_21 {h21} -> v2_22 {h22}")

# ---------- 事件面统计 ----------
print("=" * 20, "changelog 波次")
print(dict(collections.Counter(e["wave"] for e in ev)))
print("W-A1 按前缀归类:")
pfx = collections.Counter()
for e in ev:
    if e["wave"] == "W-A1":
        m = re.match(r"^([A-Za-z]+)", e["before"])
        pfx[m.group(1).lower() if m else "OTHER"] += 1
print("  ", dict(pfx.most_common(20)))
