# -*- coding: utf-8 -*-
"""v2_23 独立验证：门禁复算 + v2_22 已清项不回退 + 本轮补漏项清零"""
import json, io, re, sys, hashlib, collections
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune"
P22 = ROOT + r"\data\final_train_chatml_alpha06_v2_22_candidate_20260914.jsonl"
P23 = ROOT + r"\data\final_train_chatml_alpha06_v2_23_candidate_20260914.jsonl"
CHG = ROOT + r"\audit\v2_23_candidate_changelog_20260914.jsonl"
r22 = [json.loads(l) for l in io.open(P22, encoding="utf-8") if l.strip()]
r23 = [json.loads(l) for l in io.open(P23, encoding="utf-8") if l.strip()]
ev = [json.loads(l) for l in io.open(CHG, encoding="utf-8") if l.strip()]
print("rows", len(r22), "->", len(r23))
print("sha v2_22", hashlib.sha256(open(P22, "rb").read()).hexdigest())
print("sha v2_23", hashlib.sha256(open(P23, "rb").read()).hexdigest())
print("changelog", len(ev), dict(collections.Counter(e["kind"] for e in ev)))

CODE = re.compile(r"```([a-zA-Z0-9_+#\-\.]*)[ \t]*\n(.*?)```", re.S)
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
DOC_RE = re.compile(r'("""|\'\'\')([\s\S]*?)\1')


def M(r):
    return {m["role"]: m["content"] for m in r["messages"]}


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


def units(body):
    lines = body.split("\n")
    out, i = [], 0
    while i < len(lines):
        cs = _cs(lines[i])
        if cs is None:
            i += 1
            continue
        pos, mk = cs
        if mk in ("/*", "<!--"):
            em = "*/" if mk == "/*" else "-->"
            tail = lines[i][pos + len(mk):]
            if em in tail:
                out.append((i, i, lines[i][:pos], mk, lines[i][pos:]))
                i += 1
                continue
            j = i + 1
            while j < len(lines) and em not in lines[j]:
                j += 1
            if j >= len(lines):
                i += 1
                continue
            out.append((i, j, lines[i][:pos], mk, ""))
            i = j + 1
            continue
        out.append((i, i, lines[i][:pos], mk, lines[i][pos:]))
        i += 1
    return out


def fp(body):
    keep = list(body.split("\n"))
    for s, e, pre, mk, ct in units(body):
        keep[s] = pre
        for k in range(s + 1, e + 1):
            keep[k] = ""
    b = DOC_RE.sub(lambda m: m.group(1) + m.group(1), "\n".join(keep))
    b = re.sub(r"\{\{+", "{", b)
    b = re.sub(r"\}+", "}", b)
    return re.sub(r"[ \t]+", " ", b)


bad = collections.Counter()
ex = collections.defaultdict(list)
cu, ca = [], []
for i, (a, b) in enumerate(zip(r22, r23)):
    ma, mb = M(a), M(b)
    if ma["user"] != mb["user"]:
        cu.append(i)
    if ma["assistant"] != mb["assistant"]:
        ca.append(i)
    if ma["system"] != mb["system"]:
        bad["system被改"] += 1
    ba = [m.group(2) for m in CODE.finditer(ma["user"])]
    bb = [m.group(2) for m in CODE.finditer(mb["user"])]
    if len(ba) != len(bb):
        bad["块数"] += 1
        ex["块数"].append(i)
        continue
    for x, y in zip(ba, bb):
        if len(x.split("\n")) != len(y.split("\n")):
            bad["G1行数"] += 1
            ex["G1行数"].append(i)
        if fp(x) != fp(y):
            bad["G2指纹"] += 1
            ex["G2指纹"].append(i)
    if [m["role"] for m in b["messages"]] != ["system", "user", "assistant"]:
        bad["G4角色"] += 1
    mt = list(JSON_RE.finditer(mb["assistant"]))
    if not mt:
        bad["G3缺失"] += 1
    else:
        try:
            o = json.loads(mt[-1].group(1))
            if len(o) != 7:
                bad["G3键数"] += 1
            if not isinstance(o.get("has_vulnerability"), bool):
                bad["G3bool"] += 1
        except Exception:
            bad["G3解析"] += 1
print("改动行：user", len(cu), "| assistant", len(ca))
print("门禁违例:", dict(bad) or "0 全通过")
for k, v in ex.items():
    print("   ", k, v[:10])

# ---------------- 本轮补漏项清零 ----------------
EN = re.compile(
    r"\b(?:BUG|VULNERABLE|VULN|INSECURE|UNSAFE|DANGEROUS|EXPLOITABLE|EXPLOIT)\b|"
    r"dangling|double\s+free|second\s+free|use[- ]after[- ]free|"
    r"no\s+escap\w*|not\s+escap\w*|without\s+escap\w*|unescap\w*|not\s+escaped|"
    r"(?:command|code|sql|ldap|xpath|template|log|crlf|header)\s+injection|"
    r"(?:buffer|integer|heap|stack|memory)\s+overflow|out[- ]of[- ]bounds|"
    r"path\s+traversal|directory\s+traversal|prototype\s+pollution|"
    r"bypass\w*|unsanitiz\w*|unvalidat\w*|uncheck\w*|"
    r"missing\s+(?:check|validation|sanitization|bounds|escaping)|"
    r"allows?\s+(?:an?\s+)?attacker|attacker[- ](?:controlled|supplied|can)|"
    r"malicious|crafted|tainted|"
    r"user[- ](?:input|controlled|supplied)|untrusted|raw\s+input|external\s+input|"
    r"(?:no|without|missing|lacks?)\s+(?:validation|sanitization|escaping|checking|"
    r"bounds|verification|authentication|authorization)|"
    r"\b(?:FIXME|XXX|HACK)\b", re.I)
PLACE = re.compile(r"需要(?:添加|补充|优化|完善|实现)|待(?:实现|补充|完善|添加)|"
                   r"此处省略|省略若干|示例注释|示例代码|伪代码")
SIGB = re.compile(r"(?m)^[^\n]*\)\s*\{\{\s*$|"
                  r"^\s*(?:if|else|for|while|do|try|catch|finally|switch)\b[^\n]*\{\{\s*$")
HEAD = re.compile(r"^代码片段\s*（\s*文件名\s*[:：]\s*(?P<fn>.+?)\s*[，,]\s*语言\s*[:：]\s*(?P<lang>.+?)\s*）\s*[:：]?\s*$")
LEAKPFX = re.compile(r"^(?:vuln|safe|noise|distill|supplement|unsafe|weak|strong|bad|good|evil|malicious)[_\-]", re.I)
R = collections.Counter()
for i, b in enumerate(r23):
    m = M(b)
    a = m["assistant"]
    if "教师" in a:
        R["🔴教师"] += 1
    if re.search(r"防御迷惑|迷惑防御", a):
        R["🔴防御迷惑"] += 1
    if re.search(r"锚句|样本外|防御迷惑样本|流A|流B", a):
        R["🔴旧术语"] += 1
    if re.search(r"(?<![A-Za-z0-9_])F12(?![0-9A-Za-z_])", a):
        R["🔴F12"] += 1
    first = m["user"].partition("\n")[0]
    hp = HEAD.match(first)
    if hp and LEAKPFX.match(hp.group("fn").strip()):
        R["🔴头部泄漏名"] += 1
    for mt in CODE.finditer(m["user"]):
        body = mt.group(2)
        for _, _, _, _, ct in units(body):
            if ct.strip() and EN.search(ct):
                R["🔴英文答案注释"] += 1
            if ct.strip() and PLACE.search(ct) and re.search(r"[\u4e00-\u9fff]", ct):
                R["🔴中文占位"] += 1
            if re.search(r"漏洞[点：:]|迷惑性|伪装防御", ct):
                R["🔴中文答案注释"] += 1
            if re.search(r"distill_glm", ct, re.I):
                R["🔴distill标记"] += 1
        n2, c2 = body.count("{{"), body.count("}}")
        if n2 and n2 == c2 and (body.count("{") - n2 * 2) == 0 and \
                (body.count("}") - c2 * 2) == 0 and SIGB.search(body):
            R["🔴花括号双写"] += 1
print("补漏回扫:", dict(R) or "0 全通过")

# 正负
c22 = collections.Counter()
c23 = collections.Counter()
chg = 0
for a, b in zip(r22, r23):
    ma = list(JSON_RE.finditer(M(a)["assistant"]))
    mb = list(JSON_RE.finditer(M(b)["assistant"]))
    if not (ma and mb):
        continue
    oa, ob = json.loads(ma[-1].group(1)), json.loads(mb[-1].group(1))
    c22[oa["has_vulnerability"]] += 1
    c23[ob["has_vulnerability"]] += 1
    if oa["has_vulnerability"] != ob["has_vulnerability"]:
        bad["🔴正负被改"] += 1
    elif oa != ob:
        chg += 1
print("正负 v2_22", dict(c22), "v2_23", dict(c23),
      "| 🔴has_vulnerability 被改:", bad["🔴正负被改"], "| JSON 内容变化:", chg)

# v2_22 已清项不回退
BACK = collections.Counter()
for b in r23:
    m = M(b)
    for mt in CODE.finditer(m["user"]):
        body = mt.group(2)
        if re.search(r"distill_glm|supplement_", body):
            BACK["distill标记回退"] += 1
        if re.search(r"(?m)^\s*(#|//|/\*)\s*(vuln_|safe_|noise_|distill_)", body):
            BACK["代码内泄漏文件名"] += 1
    hp = HEAD.match(m["user"].partition("\n")[0])
    if hp and not re.match(r"^module_\d{5}\.", hp.group("fn").strip()) and \
            (LEAKPFX.match(hp.group("fn").strip()) or re.search(r"[${}<>\s\"';`|]", hp.group("fn"))):
        BACK["头部泄漏名回退"] += 1
    mt = list(JSON_RE.finditer(m["assistant"]))
    if mt:
        try:
            o = json.loads(mt[-1].group(1))
            if o.get("has_vulnerability") is False:
                if str(o.get("vulnerability_type", "")).strip().lower() not in ("none", "null", ""):
                    BACK["无洞vt非none回退"] += 1
                if str(o.get("risk_level", "")).strip().lower() not in ("none", "null"):
                    BACK["无洞rl非None回退"] += 1
        except Exception:
            pass
print("v2_22 已清项回退检查:", dict(BACK) or "0 全通过")
print("changelog 波次:", dict(collections.Counter(e["wave"] for e in ev)))
