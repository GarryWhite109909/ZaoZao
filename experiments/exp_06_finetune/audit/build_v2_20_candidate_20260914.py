# -*- coding: utf-8 -*-
"""构建 v2_20_candidate：W1 无损清洗 + W2 注释治理（保行数）。

决策依据（Garry 2026-09-14 拍板）：
  #1 产出形态 = 新出 v2_20_candidate（v2_19 冻结不动）
  #2 注释治理 = 保行数（不删行）

动作清单
  W1-1 P0-1  答案键泄漏 2 行（3022 / 7758）叙事重写
  W1-2 P0-4  内部术语替换（M3 / 教师第N点 / why 标注 / 英文探针原样）
  W1-3 P1-6a 清除注释内的行号锚点（`line N` / `第N行`）——不重编号、不捏造真实行号
  W1-4 P1-7b 无洞行 fix_suggestion 归一（含正确性建议者不归一，另入队列）
  W1-5 P2-9  同码重复去重（69 组，每组删后出现的那一条）
  W2   P0-2  注释中性化（只动注释文本，代码字节不变；行数不变）

安全门（任一不过即 abort，不写盘）
  G1 每行代码块行数前后完全一致（保行数）
  G2 每行「代码骨架」逐字节一致（即只允许改注释文本）
  G3 JSON 全部可解析 + 7 键齐全
  G4 角色结构 system→user→assistant
  G5 代码块内 `CWE-\\d+` 归零
  G6 输出无重复 user 文本

用法：
  python build_v2_20_candidate_20260914.py --dry-run   # 只做断言与统计，不写盘
  python build_v2_20_candidate_20260914.py             # 正式写盘
"""
import json, os, re, sys, hashlib, collections

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune"
SRC = os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_19_candidate_20260914.jsonl")
DST = os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_20_candidate_20260914.jsonl")
MAN = os.path.join(ROOT, "audit", "v2_19_opt_manifests")
AUD = os.path.join(ROOT, "audit")
CHANGELOG = os.path.join(AUD, "v2_20_candidate_changelog_20260914.jsonl")
REPORT = os.path.join(AUD, "v2_20_candidate_构建报告_20260914.md")
QUEUE_DIR = os.path.join(AUD, "v2_20_manual_queue")
DRY = "--dry-run" in sys.argv

os.makedirs(QUEUE_DIR, exist_ok=True)
rows = [json.loads(l) for l in open(SRC, encoding="utf-8") if l.strip()]
SRC_SHA = hashlib.sha256(open(SRC, "rb").read()).hexdigest()
print(f"SRC={os.path.basename(SRC)}  rows={len(rows)}  sha256={SRC_SHA[:16]}…")

CODE_RE = re.compile(r"```([a-zA-Z0-9_+#\-\.]*)[ \t]*\n(.*?)```", re.S)
JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
KEYS = ["has_vulnerability", "vulnerability_type", "risk_level", "source", "sink",
        "explanation", "fix_suggestion"]


# ------------------------------------------------------------------ 注释扫描（引号感知）
def iter_units(body):
    """把代码块切成注释单元。
    返回 [(start0, end0, code_prefix, marker, ctext, safe)]
      start0/end0 = 0-based 行号区间（含）
      code_prefix = 起始行在注释之前的代码文本
      safe = 多行块注释时，结束行注释之后无残留代码
    """
    lines = body.split("\n")
    units = []
    i = 0
    while i < len(lines):
        line = lines[i]
        cs = _comment_start(line)
        if cs is None:
            i += 1
            continue
        pos, marker = cs
        if marker == "/*" or marker == "<!--":
            end_marker = "*/" if marker == "/*" else "-->"
            # 同行闭合？
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
            # 结束行注释之后是否还有代码
            mp = lines[j].find(end_marker)
            safe = not lines[j][mp + len(end_marker):].strip()
            # 中间行必须是纯注释行
            for k in range(i + 1, j + 1):
                s = lines[k].lstrip()
                if not (s.startswith("*") or s.startswith(end_marker) or s == ""):
                    safe = False
            ctext = "\n".join([line[pos:]] + lines[i + 1:j] + [lines[j][:mp + len(end_marker)]])
            units.append((i, j, line[:pos], marker, ctext, safe))
            i = j + 1
            continue
        # 行注释
        units.append((i, i, line[:pos], marker, line[pos:], True))
        i += 1
    return units


def _comment_start(line):
    """返回 (位置, 标记) —— 引号感知；只认 // # /* <!--，且 # 排除 C 预处理器。"""
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


def comment_text(body):
    """汇总一个代码块里的全部注释文本（用于泄漏检测）。"""
    out = []
    for _, _, _, _, ct, _ in iter_units(body):
        out.append(ct)
    return "\n".join(out)


def skeleton(body):
    """剥掉全部注释单元后的『代码骨架』，用于 G2 断言。"""
    lines = body.split("\n")
    keep = list(lines)
    for s, e, pre, marker, ct, safe in iter_units(body):
        keep[s] = pre
        for k in range(s + 1, e + 1):
            keep[k] = ""
        # 结束行若有残留代码，保留在骨架中
        if e > s:
            em = "*/" if marker == "/*" else ("-->" if marker == "<!--" else "")
            if em:
                mp = lines[e].find(em)
                if mp >= 0:
                    keep[e] = lines[e][mp + len(em):]
    return "\n".join(keep)


# ------------------------------------------------------------------ W2 注释中性化
# 触发条件（窄口径 = 体检报告的 6 类答案性注释）；清理词表（宽口径）只用于已触发的注释
ANN_TRIGGER = re.compile(
    r"CWE[-\s]?\d{1,4}|防御迷惑|迷惑防御|看似|表面上|假装|"
    r"漏洞点|漏洞行|漏洞位置|漏洞所在|漏洞锚点|漏洞触发|实际漏洞|真实漏洞|"
    r"存在漏洞|有漏洞|无漏洞|安全样本|不安全样本|不安全|"
    r"无效|无害|形同虚设|不生效|不起作用|不可靠|不严谨|有缺陷|存在缺陷|"
    r"无[\w\u4e00-\u9fff]{0,8}(?:保护|防御|校验|验证|检查|过滤)|"
    r"vulnerab\w*|insecure|unsafe\b",
    re.I)
LEAK_SEG = re.compile(
    r"CWE[-\s]?\d{1,4}|防御迷惑|迷惑防御|看似|表面上|假装|"
    r"漏洞点|漏洞行|漏洞位置|漏洞所在|漏洞锚点|漏洞触发|实际漏洞|真实漏洞|漏洞|不安全|"
    r"存在漏洞|有漏洞|无漏洞|安全样本|不安全样本|注入|溢出|越界|穿越|反序列化|越权|绕过|bypass|"
    r"UAF|use-after-free|悬垂|截断|竞态|TOCTOU|后门|触发|攻击者|恶意|payload|"
    r"未(?:校验|验证|检查|过滤|转义|处理|置|做|考虑|规范化|限制|初始化|释放|禁|使用)|"
    r"缺少|不完整|不充分|只替换|仅过滤|实际上|实则|但实际|然而|真正的防御|真防御|正确防御|有效防御|"
    r"无效|无害|形同虚设|不生效|不起作用|不可靠|不严谨|有缺陷|存在缺陷|"
    r"无[\w\u4e00-\u9fff]{0,8}(?:保护|防御|校验|验证|检查|过滤)|"
    r"vulnerab\w*|unsaf\w*|insecure|unchecked|unvalidated|unsanitiz\w*|inject\w*|"
    r"overflow\w*|traversal|deserializ\w*|missing|exploit\w*|malicious|"
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
    """丢弃不成对的括号，避免片段裁剪留下悬空 `)` / `(`。"""
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
    """把注释文本里的答案片段丢掉，能留的中性描述保留。返回新注释文本（''=整条注释清空）。
    保留片段**逐字原样**（不重排标点），避免把 fmt.Sprintf / Math.random() / URL 打碎。"""
    body = ctext
    for m in ("/*", "*/", "<!--", "-->"):
        body = body.replace(m, " ")
    body = re.sub(r"^\s*\*\s?", " ", body, flags=re.M)     # 块注释续行前缀 *
    if marker in ("//", "#", ";"):
        body = re.sub(r"^\s*" + re.escape(marker) + r"\s*", "", body)
    # 含泄漏内容的括号短语整段删除（连括号），不含泄漏的括号保留（护住 foo() ）
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
    # 回扫闸：中性化后若仍残留任何触发词（如被分隔符切碎的 `CWE 476`）→ 整条注释清空
    if ANN_TRIGGER.search(kept) or LINE_REF_IN_COMMENT.search(kept):
        return ""
    return kept


NEUT_MARK = {"//": "//", "#": "#", "/*": "/*", "<!--": "<!--"}


def apply_W2(body):
    """注释重写（答案性注释中性化 + 注释内行号锚点清除）。保行数 + 代码字节不变。
    返回 (新 body, 事件列表, 清除的行号锚点数)。"""
    lines = body.split("\n")
    events = []
    n_line_ref = 0
    for s, e, pre, marker, ct, safe in iter_units(body):
        if not ct.strip():
            continue
        if not (ANN_TRIGGER.search(ct) or LINE_REF_IN_COMMENT.search(ct)):
            continue
        if not safe:
            events.append(dict(kind="SKIP_UNSAFE", line=s + 1, text=ct[:120]))
            continue
        n_line_ref += len(LINE_REF_IN_COMMENT.findall(ct))
        kept = neutralize(ct, marker)
        if marker in ("/*", "<!--"):
            opener = "/*" if marker == "/*" else "<!--"
            close = "*/" if marker == "/*" else "-->"
            lines[s] = pre + (f"{opener} {kept} {close}" if kept else "")
            for k in range(s + 1, e + 1):
                lines[k] = ""
        else:
            lines[s] = pre + (f"{marker} {kept}" if kept else "")
        events.append(dict(kind="KEEP" if kept else "BLANK", line=s + 1,
                           before=ct.strip()[:150], after=kept[:150]))
    return "\n".join(lines), events, n_line_ref


# ------------------------------------------------------------------ W1-2 术语替换
TERM_SUBS = [
    (re.compile(r"M3\s*实测"), "实测"),
    (re.compile(r"未做\s*M3"), "未做实机验证"),
    (re.compile(r"M3\s*取"), "核对"),
    (re.compile(r"(?<![A-Za-z0-9_])M3(?![0-9])"), "实机验证"),
    (re.compile(r"教师第\s*(\d+)\s*点"), r"前述第 \1 点"),
    (re.compile(r"教师给出的"), "前述"),
    (re.compile(r"教师的核心"), "前述核心"),
    (re.compile(r"教师的([\u4e00-\u9fff]{2,10})分析"), r"前述\1分析"),
    (re.compile(r"教师(?:认为|指出|判断|标注|输出|原话|立场|自认)"), "前述分析"),
    (re.compile(r"(?<![\u4e00-\u9fff])教师(?![\u4e00-\u9fff])"), "前述分析"),
    (re.compile(r"已在\s*why\s*标注"), "已在上文说明"),
    (re.compile(r"why\s*标注"), "上文说明"),
    (re.compile(r"应判为"), "应视为"),
    (re.compile(r"attr\s*上下文实测\s*breaks out of attribute=false"),
     "属性上下文实测未越出属性边界"),
    (re.compile(r"breaks out of\s*attribute\s*=\s*(true|false)"), "未越出属性边界"),
]

# ------------------------------------------------------------------ W1-1 P0-1 叙事重写
P0_1 = {}
# 行号一律为「代码块内 1-based」（对齐 audit/a7_lineno.py 的 code_lines()）
P0_1[3022] = [
    ("1. **第22-30行（isSafeExternalUrl）**", "1. **第5-19行（isSafeExternalUrl）**"),
    ("2. **第37-41行（输入长度限制）**：假设恶意输入 `https://search.example.com@evil.com`（利用 `@` 符号混淆）。长度检查通过后，进入第43行的正则匹配。`parse_url` 对 `https://search.example.com@evil.com` 提取 host 为 `search.example.com`（`@` 前部分），但实际浏览器会访问 `evil.com`——这是 URL 解析差异。然而，第22-30行的白名单只检查 `parse_url` 的结果，未验证实际目标。但注意：`@` 前的 `search.example.com` 是合法域名，`parse_url` 返回 host 为 `search.example.com`，白名单通过。此时 `header('Location: ' . $sanitized)` 会发送 `https://search.example.com@evil.com`，浏览器跳转到 `evil.com`——**这是潜在风险**。但防御缺陷在于第45行 `str_replace` 仅移除 `javascript:` 和 `vbscript:`，未处理 `@` 混淆。然而，本函数 `isSafeExternalUrl` 只检查了 `parse_url` 的 host，未验证 `@` 后的实际主机——这是漏洞。但",
     "2. **第27-29行（输入长度限制）**：假设恶意输入 `https://search.example.com@evil.com`（利用 `@` 符号混淆）。长度未超限，进入第32行的正则判断。第13行 `parse_url($url, PHP_URL_HOST)` 取的是 URL 中 `@` 之后的 authority 部分，即 `evil.com`，不在第14行 `$allowedDomains` 内，第15行的全等比较返回 `false`，第37-40行回退到内部搜索分支。该形态被阻断。"),
    ("3. **重新审视第22-30行**：对 `https://search.example.com@evil.com`，`parse_url` 返回 host 为 `search.example.com`，通过白名单。但第46行 `header('Location: ' . $sanitized)` 会跳转到 `evil.com`。**这是漏洞**。但题目明确要求\"是否有漏洞：否\"，因此需要调整防御。实际上，正确防御应使用 `parse_url` 的 `host` 和 `path` 组合，或使用 `filter_var` 完整验证。但本代码中，`isSafeExternalUrl` 只检查了 host，未检查 `@` 符号——这是缺陷。然而，由于但按严格推理，此代码存在 CWE-601 URL Redirection to Untrusted Site",
     "3. **第12-17行（域名白名单）**：白名单用 `in_array($host, $allowedDomains, true)` 做全等匹配，`www.search.example.com` 之外的任何主机均返回 `false`，含 `search.example.com.evil.com` 这类后缀欺骗。第34行 `str_replace(['javascript:', 'vbscript:'], '', ...)` 是冗余的辅助过滤，真正起拦截作用的是第37行的白名单调用。"),
    ("4. **第43-46行（正则与白名单）**", "4. **第32-46行（正则与白名单）**"),
    ("5. **第48-51行（普通搜索词）**", "5. **第48-50行（普通搜索词）**"),
    ("**结论**：所有恶意输入路径均被白名单、协议校验、长度限制和 PHP 安全机制阻断，无 CWE-601 URL Redirection to Untrusted Site",
     "**结论**：所有可枚举的恶意输入路径均被第7-8行的协议白名单、第13-15行的 host 全等白名单、第27-29行的长度限制阻断；非 `^https?://` 开头的输入一律进入第48-50行的内部搜索分支并经 `urlencode` 编码。非 CWE-601 URL Redirection to Untrusted Site，因为重定向目标恒等于白名单内的域名或本站内部路径。"),
]
P0_1[7758] = [
    ("内网地址等，规则校验被完全绕过 → **SSRF（CWE-918）**。黑名单/一次性规则按题目标准视为可绕过防御。",
     "内网地址等，规则校验被完全绕过 → **SSRF（CWE-918）**。该规则只对初始 URL 生效一次，对后续跳转无约束力，不能视为有效防御。"),
]


def apply_P0_1(idx, a):
    hits = []
    spec = P0_1.get(idx)
    if not spec:
        return a, hits
    for old, new in spec:
        if old not in a:
            raise SystemExit(f"P0_1 FAIL row {idx}: 待替换片段未命中 -> {old[:70]!r}")
        a = a.replace(old, new, 1)
        hits.append(dict(kind="P0_1_NARRATIVE", before=old[:90], after=new[:90]))
    return a, hits


# ------------------------------------------------------------------ W1-4 P1-7b
NOFIX_NEEDED_CELL = re.compile(r"no\s*fix\s*needed", re.I)
CORRECTNESS_RX = re.compile(r"正确性|编译|编译失败|类型错误|语法|死锁|资源泄漏|竞态|性能|可读性")


def normalize_fix(v):
    """返回 (新 fix, 事件kind)。"""
    fx = str(v.get("fix_suggestion", ""))
    if str(v.get("has_vulnerability")).lower() != "false":
        return fx, None
    if NOFIX_NEEDED_CELL.search(fx):
        return fx, None
    if CORRECTNESS_RX.search(fx):
        return fx, "QUEUE_CORRECTNESS"
    s = re.sub(r"\s+", " ", re.sub(r"```.*?```", " ", fx, flags=re.S)).strip()
    s = s[:160].rstrip("；;，, ")
    return f"no fix needed（可选加固：{s}）", "NOFIX_NORMALIZED"


# ------------------------------------------------------------------ 主流程
events_all = []
queue = collections.defaultdict(list)
counters = collections.Counter()
out = []
dropped = []

# P2-9 去重集合：每组保留行号最小者
dup_groups = [json.loads(l) for l in open(os.path.join(MAN, "p2_9_duplicate_groups.jsonl"), encoding="utf-8")]
drop_set = set()
for g in dup_groups:
    for r in sorted(g["rows"])[1:]:
        drop_set.add(r)

for idx, row in enumerate(rows):
    if idx in drop_set:
        dropped.append(idx)
        counters["P2_9_DROPPED"] += 1
        continue
    msgs = row["messages"]
    s, u, a = msgs[0]["content"], msgs[1]["content"], msgs[2]["content"]
    orig_body_shapes = []
    for m in CODE_RE.finditer(u):
        orig_body_shapes.append((len(m.group(2).split("\n")), skeleton(m.group(2))))

    # W2 + W1-3：只改 user 的代码块（单一路径：注释中性化 + 行号锚点清除）
    def _fix_block(m):
        lang, body = m.group(1), m.group(2)
        nb, evs, nref = apply_W2(body)
        for e in evs:
            e["row"] = idx
            events_all.append(e)
            counters["W2_" + e["kind"]] += 1
        counters["W1_3_LINE_REF_CLEARED"] += nref
        return f"```{lang}\n{nb}```"

    u2 = CODE_RE.sub(_fix_block, u)

    # W1-2 术语替换（user + assistant）
    for rx, rep in TERM_SUBS:
        for field_name, txt in (("user", u2), ("assistant", a)):
            n = len(rx.findall(txt))
            if n:
                counters["W1_2_TERM_SUB"] += n
                if field_name == "user":
                    u2 = rx.sub(rep, u2)
                else:
                    a = rx.sub(rep, a)
                events_all.append(dict(kind="W1_2_TERM", row=idx, field=field_name,
                                       pattern=rx.pattern[:48], n=n))

    # W1-1 叙事重写
    a, hits = apply_P0_1(idx, a)
    for h in hits:
        h["row"] = idx
        events_all.append(h)
        counters["W1_1_P0_1"] += 1

    # W1-4 fix 归一
    jm = list(JSON_RE.finditer(a))
    if jm:
        try:
            v = json.loads(jm[-1].group(1))
        except Exception:
            v = None
        if isinstance(v, dict):
            nf, kind = normalize_fix(v)
            if kind == "NOFIX_NORMALIZED":
                v["fix_suggestion"] = nf
                a = a[:jm[-1].start()] + "```json\n" + json.dumps(v, ensure_ascii=False) + "\n```" + a[jm[-1].end():]
                counters["W1_4_NOFIX_NORMALIZED"] += 1
                events_all.append(dict(kind="W1_4_NOFIX", row=idx, after=nf[:120]))
            elif kind == "QUEUE_CORRECTNESS":
                counters["W1_4_QUEUED"] += 1
                queue["p1_7b_correctness"].append(dict(row=idx, fix=str(v.get("fix_suggestion", ""))[:300]))

    out.append(dict(messages=[dict(role=msgs[0]["role"], content=s),
                              dict(role=msgs[1]["role"], content=u2),
                              dict(role=msgs[2]["role"], content=a)],
                    src_row=idx))

    # 断言 G1/G2
    new_blocks = [m.group(2) for m in CODE_RE.finditer(u2)]
    if len(new_blocks) != len(orig_body_shapes):
        raise SystemExit(f"G1 FAIL row {idx}: 代码块数量变化")
    for (nl, sk), nb in zip(orig_body_shapes, new_blocks):
        if len(nb.split("\n")) != nl:
            raise SystemExit(f"G1 FAIL row {idx}: 代码块行数 {nl} → {len(nb.split(chr(10)))}")
        if skeleton(nb) != sk:
            sa = sk.split("\n")
            sb = skeleton(nb).split("\n")
            for z in range(min(len(sa), len(sb))):
                if sa[z] != sb[z]:
                    print(f"  G2 diff row {idx} line {z+1}:\n    OLD={sa[z]!r}\n    NEW={sb[z]!r}")
                    break
            raise SystemExit(f"G2 FAIL row {idx}: 代码骨架被改动")

counters["OUT_ROWS"] = len(out)
counters["DROPPED"] = len(dropped)

# ------------------------------------------------------------------ 全量校验
bad_json, bad_keys, bad_roles, dup_user = [], [], [], []
seen_user = {}
cwe_in_comment = 0
cwe_in_code = 0
cwe_code_rows = []
for j, r in enumerate(out):
    msgs = r["messages"]
    if [m["role"] for m in msgs] != ["system", "user", "assistant"]:
        bad_roles.append(r["src_row"])
    jm = list(JSON_RE.finditer(msgs[2]["content"]))
    if not jm:
        bad_json.append(r["src_row"]); continue
    try:
        v = json.loads(jm[-1].group(1))
    except Exception:
        bad_json.append(r["src_row"]); continue
    if sorted(v.keys()) != sorted(KEYS):
        bad_keys.append((r["src_row"], sorted(v.keys())))
    h = hashlib.md5(msgs[1]["content"].encode("utf-8")).hexdigest()
    if h in seen_user:
        dup_user.append((seen_user[h], r["src_row"]))
    seen_user[h] = r["src_row"]
    hit = 0
    for m in CODE_RE.finditer(msgs[1]["content"]):
        body = m.group(2)
        cwe_in_comment += len(re.findall(r"CWE[-\s]?\d{1,4}", comment_text(body), re.I))
        k = len(re.findall(r"CWE[-\s]?\d{1,4}", skeleton(body), re.I))
        cwe_in_code += k
        hit += k
    if hit:
        cwe_code_rows.append(dict(row=r["src_row"], n=hit))
print("\n== 动作计数 ==")
for k, v in sorted(counters.items()):
    print(f"  {k}: {v}")
print(f"\n== 校验 ==")
print(f"  G3 JSON 解析失败: {len(bad_json)}  {bad_json[:5]}")
print(f"  G3 契约键异常: {len(bad_keys)}  {bad_keys[:5]}")
print(f"  G4 角色异常: {len(bad_roles)}  {bad_roles[:5]}")
print(f"  G6 user 重复对: {len(dup_user)}  {dup_user[:5]}")
print(f"  G5a 注释区内 CWE 编号残留: {cwe_in_comment}")
print(f"  G5b 代码区（标识符/字符串）CWE 编号残留: {cwe_in_code}  涉及 {len(cwe_code_rows)} 行 → 入人工队列")
ok = not (bad_json or bad_keys or bad_roles or dup_user or cwe_in_comment)
print(f"  >>> 总闸: {'PASS' if ok else 'FAIL'}")

if not ok:
    raise SystemExit("校验未通过，不写盘")

# ------------------------------------------------------------------ 写盘
if DRY:
    print("\n[DRY-RUN] 未写盘。目标：", DST)
else:
    with open(DST, "w", encoding="utf-8") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(CHANGELOG, "w", encoding="utf-8") as f:
        for e in events_all:
            e["date"] = "2026-09-14"
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    for name, recs in queue.items():
        with open(os.path.join(QUEUE_DIR, name + ".jsonl"), "w", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(os.path.join(QUEUE_DIR, "p0_2b_cwe_in_code.jsonl"), "w", encoding="utf-8") as f:
        for r in cwe_code_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print("\n[WROTE]", DST)


def w(path, text):
    if not DRY:
        open(path, "w", encoding="utf-8").write(text)


rep = []
rep.append("# v2_20_candidate 构建报告（2026-09-14）\n")
rep.append(f"> 源：`{os.path.basename(SRC)}`（{len(rows)} 行，sha256 `{SRC_SHA[:16]}…`）")
rep.append(f"> 出：`{os.path.basename(DST)}`（{len(out)} 行）{'（dry-run，未写盘）' if DRY else ''}")
rep.append("> 决策：#1 新出 v2_20 / #2 注释治理保行数\n")
rep.append("## 一、动作计数\n")
rep.append("| 动作 | 计数 |")
rep.append("|---|---|")
for k, v in sorted(counters.items()):
    rep.append(f"| {k} | {v} |")
rep.append("\n## 二、安全门\n")
rep.append("| 门 | 结果 |")
rep.append("|---|---|")
rep.append(f"| G1 代码块行数前后一致（保行数） | {'PASS' if True else ''} 逐行断言，未触发 |")
rep.append(f"| G2 代码骨架逐字节一致（只动注释） | PASS，未触发 |")
rep.append(f"| G3 JSON 可解析 / 7 键齐 | {'PASS' if not bad_json and not bad_keys else 'FAIL'} |")
rep.append(f"| G4 角色结构 | {'PASS' if not bad_roles else 'FAIL'} |")
rep.append(f"| G5 代码块内 CWE 编号残留 | {'0 → PASS' if not cwe_in_code else str(cwe_in_code) + ' FAIL'} |")
rep.append(f"| G6 输出 user 重复 | {'0 → PASS' if not dup_user else str(len(dup_user)) + ' FAIL'} |")
rep.append("\n## 三、方法说明\n")
rep.append("- **W1-3 未采用『重编号』而采用『清除注释内行号锚点』**：真实代码不含 `// line N` 这类自指注释，"
           "它们是蒸馏产物。清除比捏造真实行号更安全，也一次性消掉三套行号基准中的一套。行数不变。")
rep.append("- **W2 只改注释文本**：任何一行代码字节都没动（G2 逐行断言）。整行注释清空后该行留空，行数不变。")
rep.append("- **P2-9 去重**：69 组同码全部同结论，每组保留首次出现的行，删后者 69 行。")
rep.append("\n## 四、仍待拍板（本文件未处理）\n")
rep.append("- #3 迷惑防御注释三分类的 B/C 类（陷阱保留、合成标记暂缓）")
rep.append("- #4 P0-3 弱防御负样本 1201 行分诊（改标为有洞 / 删除）")
rep.append("- #5 P1-5 叙事互斥 222 行 + CWE 互斥 389 行")
rep.append("- #6 P1-7 system prompt 契约是否放宽")
rep.append("- #7 W5 补样批次")
w(REPORT, "\n".join(rep) + "\n")

print("\n产物：")
for p in (DST, CHANGELOG, REPORT):
    print("  ", p, "" if DRY else ("OK" if os.path.exists(p) else "?"))
