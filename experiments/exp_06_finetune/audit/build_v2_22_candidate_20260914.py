# -*- coding: utf-8 -*-
"""
build_v2_22_candidate_20260914.py
v2_21 → v2_22 治理构建器（P0 泄漏清理 + P1 契约归一）

波次：
  W-A1 头部文件名中性化       —— user 首行「代码片段（文件名: …，语言: …）」中含泄漏 token 的
  W-A2 代码内来源标记清除      —— `# distill_glm_cwe_cvss_001.py` 这类首部蒸馏标记（整行清空）
  W-B  代码区答案性注释清理    —— 复用 v2_20 W2 引擎 + 扩展触发词表
  W-C  无洞契约归一            —— fix_suggestion 清零 / vulnerability_type 归一 / risk_level 归一
  W-D  叙事术语清洗            —— 项目内部行话 → 中性安全分析表述

约束：保行数（G1）、代码骨架字节不变（G2）、JSON 7 键契约（G3）、角色结构（G4）、
      泄漏词回扫为 0（G5）。--dry-run 只出清单不写盘。
"""
import json, io, os, re, sys, hashlib, collections

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune"
SRC = os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_21_candidate_20260914.jsonl")
DST = os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_22_candidate_20260914.jsonl")
AUD = os.path.join(ROOT, "audit")
CHANGELOG = os.path.join(AUD, "v2_22_candidate_changelog_20260914.jsonl")
REPORT = os.path.join(AUD, "v2_22_candidate_构建报告_20260914.md")
DRY = "--dry-run" in sys.argv
ONLY = [a[2:] for a in sys.argv if a.startswith("--w=")]  # 限定波次

KEYS = ["has_vulnerability", "vulnerability_type", "risk_level", "source", "sink",
        "explanation", "fix_suggestion"]
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)

rows = [json.loads(l) for l in io.open(SRC, encoding="utf-8") if l.strip()]
SRC_SHA = hashlib.sha256(open(SRC, "rb").read()).hexdigest()
print(f"SRC rows={len(rows)} sha256={SRC_SHA[:16]}…  dry={DRY}  only={ONLY or 'ALL'}")

def msgs(r):
    return {m["role"]: m["content"] for m in r["messages"]}

def on(w):
    return (not ONLY) or (w in ONLY)


# ==================================================== 注释扫描（引号感知，摘自 v2_20 构建器）
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
            end_marker = "*/" if marker == "/*" else "-->"
            tail = line[pos + len(marker):]
            if end_marker in tail:
                units.append((i, i, line[:pos], marker, line[pos:], True))
                i += 1
                continue
            j = i + 1
            while j < len(lines) and end_marker not in lines[j]:
                j += 1
            if j >= len(lines):
                i += 1
                continue
            mp = lines[j].find(end_marker)
            safe = not lines[j][mp + len(end_marker):].strip()
            for k in range(i + 1, j + 1):
                s = lines[k].lstrip()
                if not (s.startswith("*") or s.startswith(end_marker) or s == ""):
                    safe = False
            ctext = "\n".join([line[pos:]] + lines[i + 1:j] + [lines[j][:mp + len(end_marker)]])
            units.append((i, j, line[:pos], marker, ctext, safe))
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


# ==================================================== W-B 词表（v2_20 口径 + 扩展）
ANN_TRIGGER = re.compile(
    r"CWE[-\s]?\d{1,4}|防御迷惑|迷惑防御|迷惑性|伪装防御|"
    r"看似|表面上|假装|"
    r"漏洞点|漏洞行|漏洞位置|漏洞所在|漏洞锚点|漏洞触发|实际漏洞|真实漏洞|漏洞[：:]|"
    r"存在漏洞|有漏洞|无漏洞|安全样本|不安全样本|不安全|"
    r"存在[\w\u4e00-\u9fff]{0,10}漏洞|"
    r"修复[：:]|原缺陷|"
    r"Defense\s*attempt|防御尝试|防御意图|"
    r"distill_glm|distill_|"
    r"无效|无害|形同虚设|不生效|不起作用|不可靠|不严谨|有缺陷|存在缺陷|"
    r"(?:因此|所以|故|因而)[^。\n]{0,25}(?:安全|无风险|无影响|无害|不可达|无法(?:利用|触发|绕过)|不受影响)|"
    r"(?:是|属于|即为)安全的|即(?:为)?安全|无风险|不可达|"
    r"不(?:会|被执行|实例化|解析外部)|已(?:被)?(?:转义|锁定|白名单|参数化)|"
    r"已(?:被)?(?:阻断|拦截|修复|加固|缓解|消除|规避)|"
    r"安全(?:的)?(?:写法|版本|实现|替代)|unsafe\s+version|safe\s+version|"
    r"无[\w\u4e00-\u9fff]{0,8}(?:保护|防御|校验|验证|检查|过滤)|"
    r"vulnerab\w*|insecure|unsafe\b|"
    r"path\s*traversal|allows?\s+attacker|attacker\s+(?:can|to)|"
    r"bypass\w*|exploit\w*|malicious",
    re.I)

LEAK_SEG = re.compile(
    r"CWE[-\s]?\d{1,4}|防御迷惑|迷惑防御|迷惑性|伪装防御|看似|表面上|假装|"
    r"漏洞点|漏洞行|漏洞位置|漏洞所在|漏洞锚点|漏洞触发|实际漏洞|真实漏洞|漏洞|不安全|"
    r"存在漏洞|有漏洞|无漏洞|安全样本|不安全样本|注入|溢出|越界|穿越|反序列化|越权|绕过|bypass|"
    r"UAF|use-after-free|悬垂|截断|竞态|TOCTOU|后门|触发|攻击者|恶意|payload|"
    r"未(?:校验|验证|检查|过滤|转义|处理|置|做|考虑|规范化|限制|初始化|释放|禁|使用)|"
    r"缺少|不完整|不充分|只替换|仅过滤|实际上|实则|但实际|然而|真正的防御|真防御|正确防御|有效防御|"
    r"无效|无害|形同虚设|不生效|不起作用|不可靠|不严谨|有缺陷|存在缺陷|"
    r"无[\w\u4e00-\u9fff]{0,8}(?:保护|防御|校验|验证|检查|过滤)|"
    r"vulnerab\w*|unsaf\w*|insecure|unchecked|unvalidated|unsanitiz\w*|inject\w*|"
    r"overflow\w*|traversal|deserializ\w*|missing|exploit\w*|malicious|"
    r"Defense\s*attempt|防御尝试|防御意图|"
    r"修复[：:]|原缺陷|"
    r"已(?:被)?(?:阻断|拦截|修复|加固|缓解|消除|规避)|"
    r"安全(?:的)?(?:写法|版本|实现|替代)|unsafe\s+version|safe\s+version|"
    r"not\s+(?:validated|checked|sanitized)|without\s+(?:proper\s+)?bounds|"
    r"\bno\b[^.]{0,30}\b(?:check|valid|sanitiz)|"
    r"应(?:使用|改用|修复)|建议(?:使用|改用|修复)",
    re.I | re.X)

SEP_RE = re.compile(r"(?:[：]|:(?!/)|[；;，,。、【】「」\[\]]+|\s[-—–]\s|\s{2,})")
LINE_REF_IN_COMMENT = re.compile(
    r"(?<![A-Za-z0-9_#/])(?:line|行|L)\s*\d{1,4}(?![0-9A-Za-z_])|第\s*\d{1,4}\s*行", re.I)
PAREN_LEAK = re.compile(r"[（(][^（()）]{0,80}[)）]")
ADVERSATIVE = re.compile(r"^(?:但|却|然而|不过|其实|只是)")


def balance_parens(s):
    res, stack = [], 0
    for ch in s:
        if ch in "（(":
            stack += 1
            res.append(ch)
        elif ch in "）)":
            if stack > 0:
                stack -= 1
                res.append(ch)
        else:
            res.append(ch)
    out = "".join(res)
    if stack:
        chars = list(out)
        for i in range(len(chars) - 1, -1, -1):
            if stack == 0:
                break
            if chars[i] in "（(":
                chars[i] = ""
                stack -= 1
        out = "".join(chars)
    return out


def neutralize(ctext, marker):
    body = ctext
    for m in ("/*", "*/", "<!--", "-->"):
        body = body.replace(m, " ")
    body = re.sub(r"^\s*\*\s?", " ", body, flags=re.M)
    if marker in ("//", "#", ";"):
        body = re.sub(r"^\s*" + re.escape(marker) + r"\s*", "", body)
    body = PAREN_LEAK.sub(lambda m: " " if (LEAK_SEG.search(m.group(0)) or
                                            ANN_TRIGGER.search(m.group(0))) else m.group(0), body)
    body = LINE_REF_IN_COMMENT.sub(" ", body)
    segs = SEP_RE.split(body)
    keep = [s.strip() for s in segs
            if s.strip() and not LEAK_SEG.search(s) and not ADVERSATIVE.match(s.strip())]
    kept = " ".join(keep)
    kept = balance_parens(kept)
    kept = kept.strip(" -—–_:：,，;；")
    kept = re.sub(r"\s{2,}", " ", kept)
    if len(re.sub(r"\s+", "", kept)) < 4:
        return ""
    if re.fullmatch(r"第?\s*\d{1,4}\s*行?", kept):
        return ""
    if ANN_TRIGGER.search(kept) or LINE_REF_IN_COMMENT.search(kept):
        return ""
    return kept


def apply_WB(body, events, row):
    """代码区答案性注释清理：**触发即整条清空**。
    理由：代码区注释一旦含答案词，其技术描述本身就是答案（部分保留仍泄漏机制），
    故不做片段保留。清空不改变代码骨架（G2 保证）、不改变行数（G1 保证）。"""
    lines = body.split("\n")
    for s, e, pre, marker, ct, safe in iter_units(body):
        if not ct.strip():
            continue
        if not (ANN_TRIGGER.search(ct) or LINE_REF_IN_COMMENT.search(ct)):
            continue
        if not safe:
            events.append(dict(row=row, wave="W-B", kind="SKIP_UNSAFE", block_line=s + 1,
                               before=ct.strip()[:120]))
            continue
        lines[s] = pre
        for k in range(s + 1, e + 1):
            lines[k] = ""
        events.append(dict(row=row, wave="W-B", kind="BLANK",
                           block_line=s + 1, before=ct.strip()[:150]))
    return "\n".join(lines)


# ==================================================== W-A 头部文件名 + 来源标记
# 锚定整行，避免跨行误匹配
HEAD_RE = re.compile(
    r"^代码片段\s*（\s*文件名\s*[:：]\s*(?P<fn>.+?)\s*[，,]\s*语言\s*[:：]\s*(?P<lang>.+?)\s*）\s*[:：]?\s*$")
# 泄漏语义前缀（含报告漏报的 supplement_ 批次）
LEAK_PFX = re.compile(
    r"^(?:vuln|safe|noise|distill|supplement|unsafe|weak|strong|bad|good|evil|malicious)"
    r"[_\-]", re.I)
# 畸形名（蒸馏模板变量未替换 / 混入代码片段）
MALFORMED = re.compile(r"[${}<>\s\"';`|]|\.(?:jsp|vue|rs)$", re.I)
LANG_EXT = {
    "python": "py", "javascript": "js", "typescript": "ts", "java": "java", "go": "go",
    "php": "php", "c": "c", "cpp": "cpp", "csharp": "cs", "kotlin": "kt", "rust": "rs",
    "bash": "sh", "shell": "sh", "dockerfile": "dockerfile", "yaml": "yaml", "yml": "yml",
    "nginx": "conf", "ruby": "rb", "html": "html", "sql": "sql", "xml": "xml", "json": "json",
    "perl": "pl", "swift": "swift", "scala": "scala", "lua": "lua", "r": "r",
}
KNOWN_EXT = set("py js jsx ts tsx go java c cc cpp h hpp cs kt kts rs php rb sh bash pl "
                "swift scala lua r jsp vue html htm xml json yaml yml toml conf cfg ini sql "
                "txt md dockerfile".split())


def neut_name(row, fn, lang):
    """生成确定性中性文件名：module_<5位行号>.<ext>"""
    m = re.match(r"^[^.]*\.([A-Za-z0-9_]{1,12})$", (fn or "").strip())
    ext = m.group(1).lower() if m else None
    if not ext or ext not in KNOWN_EXT:
        ext = LANG_EXT.get((lang or "").strip().lower(), "txt")
    return f"module_{row:05d}.{ext}"


def apply_WA1(user, row, events):
    """头部文件名中性化：泄漏前缀 或 畸形名 → 中性名。返回 (新user, 旧名, 新名)。"""
    first, nl, rest = user.partition("\n")
    mp = HEAD_RE.match(first)
    if not mp:
        return user, None, None
    fn, lang = mp.group("fn").strip(), mp.group("lang").strip()
    if re.match(r"^module_\d{5}\.", fn):          # 幂等：已是中性名
        return user, None, None
    if not (LEAK_PFX.match(fn) or MALFORMED.search(fn)):
        return user, None, None
    new = neut_name(row, fn, lang)
    events.append(dict(row=row, wave="W-A1", kind="RENAME", before=fn, after=new, lang=lang))
    # 只替换首行中的文件名片段，保留「代码片段（文件名: …，语言: …）：」结构
    fixed_first = first[:mp.start("fn")] + new + first[mp.end("fn"):]
    return fixed_first + nl + rest, fn, new


# 来源标记 / 泄漏文件名（代码内首行注释）
EXT_ALT = ("py|js|jsx|ts|tsx|go|java|c|cc|cpp|h|hpp|cs|kt|rs|php|rb|sh|bash|pl|jsp|vue|"
           "html|htm|xml|json|ya?ml|toml|conf|cfg|ini|sql|txt|md|dockerfile")
SRC_TAG = re.compile(
    r"(?m)^[ \t]*(?://|#|/\*|\*|--|<!--)[ \t]*"
    r"(?:distill\S*|supplement\S*"
    r"|(?:vuln|safe|noise|unsafe|weak|strong|bad|good)[_\-][\w\-]*\.(?:" + EXT_ALT + r"))"
    r"[ \t]*(?:\*/)?[ \t]*$")


def apply_WA2(body, row, events):
    def rep(m):
        events.append(dict(row=row, wave="W-A2", kind="BLANK_TAG", before=m.group(0).strip()[:120]))
        return ""
    return SRC_TAG.sub(rep, body)


# ---- W-A3：Python docstring 内的答案标注（docstring 不是注释，需单独处理）----
DOC_RE = re.compile(r'("""|\'\'\')([\s\S]*?)\1')


def apply_WA3(body, row, events):
    """只清理 docstring 内文中的答案标注。**逐行处理以保行数**；行数变化则回退不动。
    判定只用 ANN_TRIGGER（窄口径）—— 用宽词表会把「触发 CI/CD 构建」这类中性描述误清。"""
    def rep(m):
        q, txt = m.group(1), m.group(2)
        lines = txt.split("\n")
        if not any(ANN_TRIGGER.search(ln) for ln in lines):
            return m.group(0)
        new_lines = list(lines)
        for k, ln in enumerate(lines):
            if ANN_TRIGGER.search(ln):
                # 与 W-B 同策略：触发即整行清空（任何片段保留都可能残留答案语义）
                new_lines[k] = ""
        new_txt = "\n".join(new_lines)
        if new_txt == txt:
            return m.group(0)
        if len(new_txt.split("\n")) != len(lines):
            events.append(dict(row=row, wave="W-A3", kind="SKIP_LINECOUNT",
                               before=txt.strip()[:120]))
            return m.group(0)
        events.append(dict(row=row, wave="W-A3", kind="REWRITE",
                           before=txt.strip()[:150], after=new_txt.strip()[:150]))
        return q + new_txt + q
    return DOC_RE.sub(rep, body)


# ==================================================== W-C 无洞契约归一
VT_RE = re.compile(r'"vulnerability_type"\s*:\s*"(?:[^"\\]|\\.)*"')
RL_RE = re.compile(r'"risk_level"\s*:\s*"(?:[^"\\]|\\.)*"')
SS_RE = re.compile(r'"(?:source|sink)"\s*:\s*"(?:[^"\\]|\\.)*"')


def apply_WC(a, row, events):
    """无洞样本契约归一：vulnerability_type→'none'、risk_level→'None'（仅改 JSON 内字段值）。"""
    mt = list(JSON_RE.finditer(a))
    if not mt:
        return a
    last = mt[-1]
    raw = last.group(1)
    try:
        o = json.loads(raw)
    except Exception:
        return a
    if o.get("has_vulnerability") is not False:
        return a
    new = raw
    vt = str(o.get("vulnerability_type", "")).strip()
    if vt.lower() not in ("none", "null", ""):
        new = VT_RE.sub('"vulnerability_type": "none"', new)
        events.append(dict(row=row, wave="W-C", kind="VT_NORM", before=vt[:60]))
    rl = str(o.get("risk_level", "")).strip()
    if rl.lower() not in ("none", "null"):
        new = RL_RE.sub('"risk_level": "None"', new)
        events.append(dict(row=row, wave="W-C", kind="RL_NORM", before=rl[:30]))
    if new == raw:
        return a
    return a[:last.start(1)] + new + a[last.end(1):]


# ==================================================== W-D 叙事术语清洗
NB = r"(?<![A-Za-z0-9_])"      # 前界
NA = r"(?![0-9A-Za-z_])"       # 后界
TERM_SUBS_2 = [
    (re.compile(r"近邻互斥锚句"), "近邻排除判据"),
    (re.compile(r"互斥锚句"), "互斥判据"),
    (re.compile(r"锚句"), "判据"),
    (re.compile(r"样本外假设"), "外部前提"),
    (re.compile(r"样本外"), "片段外"),
    (re.compile(r"防御迷惑样本"), "防御不完整处"),
    (re.compile(r"F12\s*密码学族互斥边界"), "密码学族互斥边界"),
    (re.compile(r"F12\s*互斥判据"), "互斥判据"),
    (re.compile(r"F12\s*判据"), "判据"),
    (re.compile(r"按\s*F12\s*"), "按 "),
    (re.compile(r"【\s*F12\s*"), "【"),
    (re.compile(NB + r"F12" + NA), ""),
    (re.compile(r"流A"), "路径A"),
    (re.compile(r"流B"), "路径B"),
    (re.compile(r"信任边界锚\s*R2"), "信任边界"),
    (re.compile(r"信任边界锚\s*R1"), "信任边界"),
    (re.compile(NB + r"R2/N8" + NA), "信任边界规则"),
    (re.compile(r"[（(]\s*R1\s*镜像\s*[)）]"), "（按引号镜像规则）"),
    (re.compile(NB + r"R1" + NA), "引号镜像规则"),
    (re.compile(NB + r"R2" + NA), "信任边界规则"),
]


def apply_WD(a, row, events):
    for rx, rep in TERM_SUBS_2:
        hits = rx.findall(a)
        if not hits:
            continue
        events.append(dict(row=row, wave="W-D", kind="TERM", before=rx.pattern[:40],
                           after=rep, count=len(hits)))
        a = rx.sub(rep, a)
    return a


# ==================================================== 代码指纹（G2'）
def fp(body):
    """剥注释 + 剥 docstring 内文 + 归一空白。W-B 清注释、W-A3 改 docstring 都不应影响它。"""
    b = skeleton(body)
    b = DOC_RE.sub(lambda m: m.group(1) + m.group(1), b)
    return re.sub(r"[ \t]+", " ", b)


# ==================================================== 主流程
events = []
out = []
stats = collections.Counter()
for i, r in enumerate(rows):
    o = json.loads(json.dumps(r, ensure_ascii=False))
    if on("A1") or on("A2") or on("A3") or on("B") or on("C") or on("D"):
        m = msgs(o)
        u, a = m["user"], m["assistant"]
        if on("A1"):
            u2, old_fn, new_fn = apply_WA1(u, i, events)
            if old_fn:
                # 同步 assistant 中的文件名引用（仅合法文件名才替换）
                if re.match(r"^[A-Za-z0-9_./\-]+\.[A-Za-z0-9_]+$", old_fn):
                    a = a.replace(old_fn, new_fn)
                    stem = old_fn.rsplit(".", 1)[0]
                    if len(stem) > 6:
                        a = a.replace(stem, new_fn.rsplit(".", 1)[0])
                u = u2
                stats["WA1"] += 1
        if on("A1") or on("A2") or on("A3") or on("B"):
            # 对每个代码块做 W-A2 / W-A3 / W-B
            def code_sub(mt):
                lang, body = mt.group(1), mt.group(2)
                if on("A2"):
                    b2 = apply_WA2(body, i, events)
                    if b2 != body:
                        stats["WA2"] += 1
                        body = b2
                if on("A3"):
                    b3 = apply_WA3(body, i, events)
                    if b3 != body:
                        stats["WA3"] += 1
                        body = b3
                if on("B"):
                    n0 = len(events)
                    b3 = apply_WB(body, events, i)
                    if b3 != body:
                        stats["WB"] += 1
                    body = b3
                return "```" + lang + "\n" + body + "```"
            u = re.sub(r"```([a-zA-Z0-9_+#\-\.]*)[ \t]*\n(.*?)```", code_sub, u, flags=re.S)
        if on("C"):
            a = apply_WC(a, i, events)
        if on("D"):
            b = apply_WD(a, i, events)
            if b != a:
                stats["WD"] += 1
            a = b
        for mm in o["messages"]:
            if mm["role"] == "user":
                mm["content"] = u
            elif mm["role"] == "assistant":
                mm["content"] = a
    out.append(o)

print("事件统计:", dict(stats), "| 事件总数:", len(events))
kind = collections.Counter(e["kind"] for e in events)
print("事件类型:", dict(kind))

# ==================================================== 门禁
def gate():
    bad = collections.Counter()
    ex = collections.defaultdict(list)
    for i, (r0, r1) in enumerate(zip(rows, out)):
        m0, m1 = msgs(r0), msgs(r1)
        c0 = re.findall(r"```[a-zA-Z0-9_+#\-\.]*[ \t]*\n(.*?)```", m0["user"], re.S)
        c1 = re.findall(r"```[a-zA-Z0-9_+#\-\.]*[ \t]*\n(.*?)```", m1["user"], re.S)
        if len(c0) != len(c1):
            bad["G-块数"] += 1
            ex["G-块数"].append(i)
            continue
        for a0, a1 in zip(c0, c1):
            if len(a0.split("\n")) != len(a1.split("\n")):
                bad["G1-行数"] += 1
                ex["G1-行数"].append(i)
            if fp(a0) != fp(a1):
                bad["G2-骨架"] += 1
                ex["G2-骨架"].append(i)
        if [x["role"] for x in r1["messages"]] != ["system", "user", "assistant"]:
            bad["G4-角色"] += 1
        # G6：首行结构必须保持（有文件名的仍要有，语言字段不得变）
        f0 = m0["user"].partition("\n")[0]
        f1 = m1["user"].partition("\n")[0]
        h0, h1 = HEAD_RE.match(f0), HEAD_RE.match(f1)
        if bool(h0) != bool(h1) or (h0 and h1 and
                                   h0.group("lang").strip() != h1.group("lang").strip()):
            bad["G6-首行结构"] += 1
            ex["G6-首行结构"].append((i, f0[:60], f1[:60]))
        for mm in r1["messages"]:
            if mm["role"] == "assistant":
                mt = list(JSON_RE.finditer(mm["content"]))
                if not mt:
                    bad["G3-JSON缺失"] += 1
                    continue
                try:
                    o = json.loads(mt[-1].group(1))
                except Exception:
                    bad["G3-JSON解析"] += 1
                    continue
                if list(o.keys()) != KEYS:
                    bad["G3-键序"] += 1
                if not isinstance(o.get("has_vulnerability"), bool):
                    bad["G3-bool"] += 1
    return bad, ex


bad, ex = gate()
print("门禁违例:", dict(bad) or "0 全通过")
for k, v in ex.items():
    print("   ", k, v[:12])

# ==================================================== G5 泄漏回扫
g5 = collections.Counter()
for i, r in enumerate(out):
    m = msgs(r)
    for lang, body in re.findall(r"```([a-zA-Z0-9_+#\-\.]*)[ \t]*\n(.*?)```", m["user"], re.S):
        ct = "\n".join(ct for _, _, _, _, ct, _ in iter_units(body))
        if re.search(r"distill_glm", ct, re.I):
            g5["残留 distill_glm"] += 1
        if re.search(r"Defense\s*attempt", ct, re.I):
            g5["残留 Defense attempt"] += 1
        if re.search(r"漏洞[点：:]|迷惑性|伪装防御", ct):
            g5["残留 漏洞标记词"] += 1
        for dm in DOC_RE.finditer(body):
            if re.search(r"迷惑性|伪装防御|存在[\w\u4e00-\u9fff]{0,10}漏洞|看起来.{0,10}实则", dm.group(2)):
                g5["残留 docstring 标记"] += 1
    aa = msgs(r)["assistant"]
    for t in ("锚句", "样本外", "防御迷惑样本", "流A", "流B"):
        if t in aa:
            g5["残留 " + t] += 1
    if re.search(NB + r"F12" + NA, aa):
        g5["残留 F12"] += 1
    mt = list(JSON_RE.finditer(aa))
    if mt:
        try:
            oo = json.loads(mt[-1].group(1))
        except Exception:
            oo = None
        if oo and oo.get("has_vulnerability") is False:
            if str(oo.get("vulnerability_type", "")).strip().lower() not in ("none", "null", ""):
                g5["残留 无洞vt非none"] += 1
            if str(oo.get("risk_level", "")).strip().lower() not in ("none", "null"):
                g5["残留 无洞rl非None"] += 1
    first = m["user"].partition("\n")[0]
    mp = HEAD_RE.match(first)
    if mp:
        fn = mp.group("fn").strip()
        if not re.match(r"^module_\d{5}\.", fn) and (LEAK_PFX.match(fn) or MALFORMED.search(fn)):
            g5["残留 头部泄漏名"] += 1
print("G5 回扫:", dict(g5) or "0 全通过")

# ==================================================== 写盘
def w(p, t):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with io.open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(t)


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

# 样例预览
print("=" * 25, "W-A1 样例")
for e in [x for x in events if x["wave"] == "W-A1"][:8]:
    print("  row %-5d %-34s → %s" % (e["row"], e["before"], e["after"]))
print("=" * 25, "W-A2 样例")
for e in [x for x in events if x["wave"] == "W-A2"][:5]:
    print("  row %-5d %s" % (e["row"], e["before"]))
print("=" * 25, "W-B BLANK 样例")
for e in [x for x in events if x["wave"] == "W-B" and x["kind"] == "BLANK"][:12]:
    print("  row %-5d L%-4d %s" % (e["row"], e["block_line"], e["before"]))
print("=" * 25, "W-B SKIP_UNSAFE")
for e in [x for x in events if x["wave"] == "W-B" and x["kind"] == "SKIP_UNSAFE"][:5]:
    print("  row %-5d L%-4d %s" % (e["row"], e["block_line"], e["before"]))
print("=" * 25, "W-A3 docstring")
for e in [x for x in events if x["wave"] == "W-A3"][:12]:
    print("  row %-5d [%s] %s → %s" % (e["row"], e["kind"], e["before"][:70], e.get("after", "")[:50]))
print("=" * 25, "W-A2 样例后 5 条")
for e in [x for x in events if x["wave"] == "W-A2"][-5:]:
    print("  row %-5d %s" % (e["row"], e["before"]))
