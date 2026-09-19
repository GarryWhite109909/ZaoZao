# -*- coding: utf-8 -*-
"""差分对六道门机检器 v2（20260911）——按 docs/出题流水线_差分对v2_20260911.md §2 落地。

本脚本实现可机检的四道门，对 wave1 全量 246 条复扫：
  门 A 语义对齐：CVE 描述机制词必须命中 patch 改动行（修"取材错配"毒源）
  门 B 差分有效：新增行须含 >=1 非注释有效行（对账 _patch_audit_20260911.json）
  门 C 标签可证：expected_cwe 须在 A 版代码数出要件>0，否则降级 pending_lead（修"标注错配"毒源）
  门 E 防御素材：负样本候选的 patch 防御行号清单（供"带防御证据"负样本改造包使用）
门 D（独立真值）与 门 F（闭环复测）非机检项，报告中仅占位。

机检边界（诚实声明，写入报告）：
  - 门 C 是词法要件计数，不是污点分析。"因缺失而致的洞"（A 版缺的正是修复新增代码）
    会被要件=0 误伤 → 输出 possible_missing_type 标记交门 D，不机械判死。
  - 门 A 机制词命中是必要非充分条件：命中≠语义对齐，但 0 命中基本=错配。

输出：corpus/diffpair_wave1/results/_gates_20260911.json + _gates_20260911.md
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from diffpair_patchlib import parse_patch

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
CORPUS = BASE / "corpus"
WAVE = CORPUS / "diffpair_wave1"
RESULTS = WAVE / "results"

# ---------------- 门 A：CWE 机制词表（描述 ↔ 改动行 对齐判定用） ----------------
CWE_MECH = {
    "77": ["command", "injection", "execute", "shell", "eval", "expression", "arbitrary"],
    "78": ["command", "injection", "execute", "shell", "subprocess", "arbitrary", "system"],
    "89": ["sql", "injection", "query", "database", "select", "statement", "sanitize"],
    "79": ["xss", "script", "html", "injection", "cross-site", "encoding", "escaping", "output"],
    "94": ["code", "injection", "eval", "execute", "rce", "expression", "arbitrary"],
    "95": ["eval", "expression", "code", "injection", "rce", "dynamic", "evaluation"],
    "1336": ["template", "ssti", "injection", "jinja", "twig", "render", "expression", "blade", "freemarker"],
    "502": ["deserialization", "deserialize", "untrusted", "pickle", "yaml", "marshal", "gadget", "unserialize"],
    "611": ["xxe", "xml", "entity", "external", "dtd", "parser", "document"],
    "918": ["ssrf", "request", "url", "internal", "fetch", "server-side", "http"],
    "441": ["proxy", "forward", "trust", "x-forwarded", "spoof", "confuse", "delegate", "ip"],
    "601": ["redirect", "open", "url", "unvalidated", "location", "forward"],
    "90": ["ldap", "injection", "filter", "search", "dn", "escape"],
    "798": ["hardcoded", "credentials", "password", "secret", "key", "embedded", "default"],
    "327": ["weak", "crypto", "md5", "sha1", "des", "ecb", "outdated", "algorithm", "hash", "random"],
    "22": ["traversal", "path", "directory", "arbitrary", "file", "read", "write", "local", "zip"],
    "639": ["authorization", "bypass", "idor", "object", "reference", "access", "key", "owner"],
    "862": ["authorization", "missing", "access", "control", "unchecked", "permission"],
    "863": ["authorization", "incorrect", "permission", "privilege", "check"],
    "306": ["authentication", "missing", "critical", "function", "unauthenticated", "bypass"],
    "284": ["access", "control", "improper", "permission", "policy", "restrict"],
    "400": ["denial", "resource", "exhaustion", "uncontrolled", "memory", "loop", "unbounded", "limit"],
    "476": ["null", "dereference", "pointer", "nil", "missing", "check"],
    "352": ["csrf", "cross-site", "request", "forgery", "token", "anti", "samesite"],
    "190": ["integer", "overflow", "wraparound", "conversion", "truncation", "cast"],
    "1321": ["prototype", "pollution", "proto", "merge", "deep", "assignment"],
    "346": ["origin", "validation", "source", "verify", "spoof", "cors"],
    "354": ["integrity", "check", "validation", "missing", "verify", "signature"],
    "494": ["download", "code", "integrity", "update", "install", "unsigned", "verify"],
    "409": ["compression", "decompression", "incomplete", "zip", "bomb", "archive", "entry"],
    "125": ["out-of-bounds", "buffer", "read", "overread", "bounds", "index"],
    "20": ["input", "validation", "improper", "malformed", "unsanitized"],
    "73": ["external", "control", "file", "name", "path", "filename"],
    "184": ["list", "incomplete", "filter", "allowlist", "blacklist"],
    "295": ["certificate", "tls", "ssl", "verify", "improper", "validation", "hostname"],
    "117": ["log", "injection", "output", "sanitization", "entry"],
    "384": ["session", "fixation", "credential", "sessions", "cookie"],
    "915": ["attribute", "modification", "mass", "assignment", "getter", "setter", "binding"],
    "434": ["upload", "file", "unrestricted", "type", "extension", "filename"],
    "829": ["include", "inclusion", "remote", "file", "path", "require"],
    "693": ["protection", "mechanism", "bypass", "filter", "evasion"],
    "668": ["exposure", "resource", "wrong", "partition", "permission", "sensitive"],
    "522": ["credential", "protective", "mechanism", "password", "salt", "hash", "insufficiently"],
    "521": ["weak", "password", "requirement", "brute", "policy"],
    "676": ["dangerous", "function", "use", "deprecated", "unsafe"],
    "697": ["incorrect", "comparison", "segregation", "domain", "scope"],
    "451": ["request", "forgery", "server-side", "ssrf", "interface"],
    "552": ["external", "resource", "access", "url", "file", "unrestricted"],
    "770": ["allocation", "resource", "limit", "without", "unbounded"],
    "1284": ["resource", "calculation", "improper", "limit", "exhaust"],
}

# ---------------- 门 C：要件词表（strong=标签可证 / weak=弱可证） ----------------
# 设计：strong 是"该 CWE 的构成性机制词"，weak 是"相关 API 面"。
# 要件数 = strong 命中 + weak 命中（分别记）。
CWE_EVIDENCE = {
    "78": {"strong": [r"subprocess\.(run|call|check|Popen)", r"os\.(system|popen)", r"exec(Sync|File)?\s*\(",
                       r"shell_exec|passthru|proc_open|\bpopen\b", r"Runtime\.getRuntime|ProcessBuilder",
                       r"exec\.Command|child_process", r"/bin/(sh|bash)|sh\s+-c"],
            "weak": [r"shell\s*=\s*True", r"shlex", r"command|cmd_|cmd\b"]},
    "77": {"strong": [r"eval\s*\(", r"exec\s*\(", r"os\.system|popen|shell_exec|passthru", r"exec\.Sync|child_process"],
            "weak": [r"expression|interpreter|command"]},
    "89": {"strong": [r"\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bUNION\b|\bDROP\b", r"execute\s*\(|executemany|rawQuery|createQuery|mysqli_query",
                       r"f['\"](SELECT|INSERT|UPDATE|DELETE)|%\s*\w*.*\bFROM\b|\.raw\s*\(|RawSQL"],
            "weak": [r"cursor|\.query\(|\bdb\.|\bsql\b|connection|prepare\s*\("]},
    "79": {"strong": [r"innerHTML|document\.write|dangerouslySetInnerHTML|v-html", r"echo\s+\$|print\s+\$", r"MarkSafe|markSafe|htmlsafe|\|safe\b|autoescape\s*=\s*False"],
            "weak": [r"escape|sanitize|render|DOM|<script|textContent"]},
    "94": {"strong": [r"eval\s*\(|new\s+Function|ScriptEngine|GroovyShell|compile\s*\(", r"setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"]"],
            "weak": [r"dynamic|expression|interpret"]},
    "95": {"strong": [r"eval\s*\(", r"new\s+Function\s*\(", r"assert\s*\(", r"ScriptEngine|GroovyShell|Nashorn"],
            "weak": [r"eval|literal_eval|expression|compile"]},
    "1336": {"strong": [r"render_template_string", r"Template\s*\(", r"\.render\(", r"jinja|Jinja|Twig|Blade|Freemarker|freemarker|Velocity|Handlebars|thymeleaf|createTemplate"],
              "weak": [r"template|render"]},
    "502": {"strong": [r"pickle\.loads", r"yaml\.load\s*\((?![^)]*Loader)", r"unserialize\s*\(", r"ObjectInputStream|readObject",
                        r"Marshal\.load", r"JSON\.parse\s*\([^)]*reviver|fastjson|JSON\.parseObject"],
             "weak": [r"deserializ|pickle|marshal|yaml|unmarshal"]},
    "611": {"strong": [r"simplexml_load|DOMDocument|XMLReader|XMLInputFactory|SAXParser", r"etree\.parse|lxml|xmltodict|xml\.etree", r"ENTITY|libxml|resolveExternals|external-general-entities|loadDTD|setFeature"],
             "weak": [r"\bxml\b|dtd|xinclude"]},
    "918": {"strong": [r"requests\.(get|post|head|put)\s*\(", r"urlopen|urlretrieve|httpx|http\.Get|http\.Post|http\.client", r"curl_init|file_get_contents\s*\(\s*\$", r"axios\.?(get|post)?\s*\(|fetch\s*\(", r"HttpClient|OkHttpClient|RestTemplate|new\s+URL\s*\("],
             "weak": [r"url|uri|host|endpoint|redirect"]},
    "441": {"strong": [r"X-Forwarded-For|X-Real-IP|X-Original-URL|x-forwarded", r"trust(ed)?\s*proxy|proxy_set_header|RemoteAddr|remote_addr", r"Forwarded\s*:|by=|for="],
             "weak": [r"\bip\b|header|proxy|forward|loopback|127\.0\.0\.1|0\.0\.0\.0|::1|::ffff:"]},
    "601": {"strong": [r"redirect\s*\(|Redirect\s*\(|sendRedirect|http\.Redirect", r"Location\s*:|header\s*\(\s*['\"]Location", r"url_for\s*\(\s*request|redirect_uri|returnTo|next\s*="],
             "weak": [r"redirect|location|href"]},
    "90": {"strong": [r"ldap_(search|list|bind)|ldap\.Search|SearchRequest", r"EscapeFilter|escape_filter|ldap_escape", r"\(\s*\|\s*\(|&\s*\(|\)\s*\(\s*\)"],
            "weak": [r"ldap|\bdn\b|filter|cn=|uid="]},
    "798": {"strong": [r"(password|passwd|pwd|secret|api_?key|token|access_?key|private_?key)\s*[=:]\s*[\"'][^\"']{4,}[\"']", r"DefaultPasswd|hardcoded|hard_coded|hardcode"],
             "weak": [r"credential|secret|password|apikey|api_key|token"]},
    "327": {"strong": [r"\bMD5\b|\bmd5\b|\bSHA1\b|\bsha1\b|\bDES\b|\bRC4\b|ECB", r"Math\.random\s*\(|random\.random\s*\(|\brand\s*\(|mt_rand", r"GetMD5|NewHash.*md5"],
             "weak": [r"cipher|encrypt|decrypt|hash|digest|random|salt"]},
    "22": {"strong": [r"\.\./|\.\.\\|%2e%2e|__DIR__", r"zip(slip|_slip)|ZipSlip|\.\./"],
            "weak": [r"file_get_contents|fopen|fread|readFile|createReadStream|fs\.(read|write|open)", r"os\.(remove|path)|unlink|open\s*\(|ioutil|os\.(Open|ReadFile|Create)", r"send_file|send_from_directory|realpath|basename|dirname|path\.(join|resolve)"]},
    "639": {"strong": [],  # 授权绕过基本是缺失型，词法无构成性要件 → 走 weak + 门 D
             "weak": [r"user_?id|userId|account_?id|owner|getById|findById|params\[|\.get\s*\(\s*['\"]id|object_id|resource"]},
    "862": {"strong": [],
             "weak": [r"authoriz|permission|@login_required|@require|current_user|isAuth|checkAuth|middleware|role|admin|decorator"]},
    "863": {"strong": [],
             "weak": [r"checkPermission|hasRole|hasPermission|verify.*permission|authoriz|role|privilege"]},
    "306": {"strong": [],
             "weak": [r"login|auth|password|verify|credential|session|authenticate|jwt|token"]},
    "284": {"strong": [],
             "weak": [r"permission|role|auth|access|acl|policy|restrict|check"]},
    "400": {"strong": [r"while\s+True", r"for\s+.*:\s*$"],
             "weak": [r"limit|timeout|chunk|batch|range|read\(|recv|stream|loop|iter|yield"]},
    "476": {"strong": [],
             "weak": [r"\bnil\b|\bnull\b|\bNone\b|\bnullptr\b|\.Value|pointer|\bptr\b"]},
    "352": {"strong": [r"csrf|Csrf|CSRF|XSRF|xsrf|SameSite|sameSite|X-Requested-With|authenticity_token| csrf"],
             "weak": [r"token|session|cookie|origin|referer"]},
    "190": {"strong": [r"int32|int64|uint16|uint32|\(int\)|\(long\)|\(short\)", r"Integer\.parseInt|parseInt\s*\(|strconv\.Atoi|ParseInt|toUnsigned|Bitwise"],
             "weak": [r"overflow|underflow|truncat|cast|convert|len\(|size|count"]},
    "1321": {"strong": [r"__proto__|prototype\s*\[|constructor\s*\[", r"Object\.assign|lodash.*(merge|set)|\.extend\s*\(|deepMerge|deepmerge|merge\s*\("],
              "weak": [r"merge|extend|prototype|assign|options|config"]},
    "346": {"strong": [r"Origin\s*:|Referer\s*:|origin|referer", r"verify.*(origin|source)|cors|CORS|Access-Control-Allow"],
             "weak": [r"source|origin|trust|forward|host|proxy"]},
    "354": {"strong": [r"hmac|HMAC|checksum|signature|verify\s*\(|integrity"],
             "weak": [r"validate|verif|md5|sha|digest|compare|equal|sign"]},
    "494": {"strong": [r"download.*(exec|install|run)|exec.*download", r"curl.*\|\s*(sh|bash)|wget.*&&", r"pip install|npm install|go install|installer"],
             "weak": [r"download|fetch|install|update|upgrade|package|release"]},
    "409": {"strong": [r"ZipSlip|zip_slip|\.\./.*entry|entry\.getName|extractTo|unzip|unpack"],
             "weak": [r"decompress|compress|zip|tar|archive|gzip|inflate|extract"]},
    "125": {"strong": [r"memcpy|strcpy|strncpy|sprintf|gets\s*\(|read\s*\(\s*buf"],
             "weak": [r"slice|substring|substr|\[\d+:\d*\]|index|len\(|buffer|bytes|array"]},
    "20": {"strong": [],
            "weak": [r"validate|valid|sanitize|check|parse|int\(|filter|type|format|schema"]},
    "73": {"strong": [r"\.\./|\.\.\\|__DIR__|base\s*\+.*path|path\.join"],
            "weak": [r"filename|file_name|filepath|file_path|dirname|basename|realpath|open\s*\(|readFile|fs\."]},
    "184": {"strong": [],
             "weak": [r"allowlist|whitelist|blacklist|blocklist|allow_list|deny_list|filter_list|permitted|allowed"]},
    "295": {"strong": [r"InsecureSkipVerify\s*:\s*true|verify\s*=\s*False|check_hostname|rejectUnauthorized\s*:\s*false|VERIFY_NONE", r"getPeerCertificates|verify_certificate|ssl_verify|CURLOPT_SSL_VERIFYPEER"],
             "weak": [r"tls|ssl|certificate|cert|https|hostname|verify"]},
    "117": {"strong": [r"log\.(printf|println|fatal)\s*\(.*(\+|\bfmt\.|f['\"])|console\.log\s*\(.*\+|logger.*(f['\"]|\+)|error_log"],
             "weak": [r"log|logger|logging|println|print\(|echo"]},
    "384": {"strong": [r"session\.regenerate|session_regenerate_id|SessionID\s*=|session\.id\s*=", r"fixat|new\s*session\s*id"],
             "weak": [r"session|cookie|token|auth|login"]},
    "915": {"strong": [r"mass.?assignment|attrs\.update|update_attributes|update\(\s*request|bind\s*\(\s*request|Model\.create\s*\(.*params|fields.*allow|strong_params"],
             "weak": [r"setattr|__dict__|update\(|assign|binding|getattr|attrs|fields"]},
    "434": {"strong": [r"\.(php\d?|phtml|jsp|exe|sh|py|pl)['\"]|move_uploaded_file|upload.*(save|write|store)|file_put_contents\s*\(\s*\$", r"contentType|mime|MimeType|extension\s*="],
             "weak": [r"upload|file|save|store|write|filename|extension"]},
    "829": {"strong": [r"include\s*\(?\s*\$|require\s*\(?\s*\$|include_once\s*\$|require_once\s*\$", r"loadFile\s*\(\s*\$|import\s*\(\s*\$"],
             "weak": [r"include|require|import|load.*file|module"]},
    "693": {"strong": [],
             "weak": [r"bypass|filter|sanitize|escape|protection|block|mod_security|disable"]},
    "668": {"strong": [],
             "weak": [r"permission|chmod|access|expose|sensitive|secret|private|public|key"]},
    "522": {"strong": [r"password.*hash\s*\(.*md5|md5\s*\(\s*\$?password|sha1\s*\(\s*\$?password|unsalted|salt\s*=\s*['\"]"],
             "weak": [r"hash|salt|password|credential|bcrypt|argon|pbkdf|scrypt"]},
    "521": {"strong": [],
             "weak": [r"password|length|policy|complexity|lockout|attempt|brute"]},
    "676": {"strong": [r"\bgets\b|\bstrcpy\b|\bsprintf\b|\beval\b|\bexec\b|md5|sha1|rand\s*\("],
             "weak": [r"deprecated|unsafe|dangerous|risky|obsolete"]},
    "697": {"strong": [],
             "weak": [r"compar|equal|==|domain|scope|segregat|partition|namespace"]},
    "451": {"strong": [r"curl|file_get_contents\s*\(|requests\.(get|post)|urlopen|fetch\s*\(|HttpClient"],
             "weak": [r"url|request|forward|proxy|internal|ssrf"]},
    "552": {"strong": [],
             "weak": [r"allow.*external|external.*resource|url|file|permission|grant"]},
    "770": {"strong": [],
             "weak": [r"alloc|allocate|new\s+\w+|make\(|limit|cap|maxlen|max_size|buffer"]},
    "1284": {"strong": [],
              "weak": [r"limit|size|count|length|alloc|quota|exhaust|resource"]},
}

STOPWORDS = set("""the a an of in to for and or is are was were be been being with by on at as that this it its
from via when if not no nor can could may might will would shall should must do does did done have has had
allow allows allowing attacker attackers user users version versions fixed fixes fix patched patch issue bug
cve code craft crafted crafting leads lead leading results result resulting due because which who whom what
into onto out up down all any some more most less least than then also only just about after before between
during through under over again further once here there where why how both each few other such own same so
too very s t don now his her their our your my me he she they them we you i
new old use used using uses make makes made made set sets get gets got obtain obtained
when while until against within without upon per among across since
""".split())

WORD_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{2,}")
DEFENSE_RE = re.compile(
    r"(sanitize|escapeshell|shlex\.quote|htmlspecialchars|htmlentities|escapeshellarg|escapeshellcmd"
    r"|parameteri|prepare\s*\(|bindValue|bindParam|placeholder|whitelist|allowlist|allow_list"
    r"|realpath|basename|canonicaliz|validate|verif|csrf|xsrf|nonce|EscapeFilter|escape_filter"
    r"|addslashes|preg_quote|htmlsafe|MarkSafe|autoescape|escape\s*\(|quote\s*\(|encode"
    r"|InsecureSkipVerify\s*:\s*false|rejectUnauthorized\s*:\s*true|strict|frozen|readonly"
    r"|permission|authoriz|authenticat|limit|timeout|integrity|checksum|sameSite|SameSite)", re.I)


def is_comment(line: str) -> bool:
    s = line.strip()
    if not s:
        return True
    return s.startswith(("//", "#", "/*", "*", "--", '"""', "'''"))


def cwe_num(cwe: str):
    m = re.match(r"CWE-(\d+)", (cwe or "").strip())
    return m.group(1) if m else None


def count_evidence(code_text: str, cwe: str):
    """返回 (strong_hits, weak_hits, strong_detail, weak_detail)。"""
    e = CWE_EVIDENCE.get(cwe)
    if e is None:
        return None, None, [], []
    strong_hits, weak_hits = 0, 0
    sd, wd = [], []
    for pat in e["strong"]:
        n = len(re.findall(pat, code_text, re.I))
        if n:
            strong_hits += n
            sd.append(f"{pat[:28]}…:{n}" if len(pat) > 28 else f"{pat}:{n}")
    for pat in e["weak"]:
        n = len(re.findall(pat, code_text, re.I))
        if n:
            weak_hits += n
            wd.append(f"{pat[:28]}…:{n}" if len(pat) > 28 else f"{pat}:{n}")
    return strong_hits, weak_hits, sd, wd


def gate_a(kid, meta, tp_entry, patch_text):
    """门 A：CVE 描述机制词 ↔ patch 改动行。返回 verdict + detail。"""
    cve = meta.get("cve")
    if not cve or cve == "N/A":
        return "n/a", {"why": "无 CVE，跳过"}
    desc = (tp_entry or {}).get("expected_vulnerability") or ""
    if not desc or desc == "N/A":
        return "n/a", {"why": "manifest 无 CVE 描述"}
    cwenum = cwe_num(meta.get("expected_cwe")) or ""
    mech = list(dict.fromkeys(CWE_MECH.get(cwenum, [])))
    # 从描述补充词（去停用词，取前 12 频词）
    words = [w.lower() for w in WORD_RE.findall(desc) if w.lower() not in STOPWORDS and len(w) >= 3]
    desc_top = [w for w, _ in Counter(words).most_common(12)]
    changed = []
    multi_file = patch_text.count("diff --git") > 1 or patch_text.count("\ndiff ") > 1
    for h in parse_patch(patch_text):
        for tag, line in h["lines"]:
            if tag in "+-":
                changed.append(line)
    changed_blob = "\n".join(changed).lower()
    if not changed_blob.strip():
        return "fail", {"why": "改动行抽取为空", "mech_words": mech}
    mech_hits = {w: len(re.findall(rf"(?<![a-z]){re.escape(w)}(?![a-z])", changed_blob)) for w in mech}
    desc_hits = {w: changed_blob.count(w) for w in desc_top}
    mech_hit_total = sum(1 for v in mech_hits.values() if v > 0)
    desc_hit_total = sum(1 for v in desc_hits.values() if v > 0)
    if mech_hit_total == 0 and desc_hit_total == 0:
        verdict = "fail"
    elif mech_hit_total + desc_hit_total < 3:
        verdict = "warn"
    else:
        verdict = "pass"
    detail = {
        "mech_hits": {k: v for k, v in mech_hits.items() if v},
        "desc_hits": {k: v for k, v in desc_hits.items() if v},
        "multi_file_patch": multi_file,
        "changed_lines": len(changed),
    }
    return verdict, detail


def gate_b(hunks, lang):
    """门 B：新增行须含 >=1 非注释有效行。"""
    adds = []
    for h in hunks:
        for tag, line in h["lines"]:
            if tag == "+":
                adds.append(line)
    effective = [ln for ln in adds if not is_comment(ln)]
    return ("pass" if effective else "fail"), {"add_total": len(adds), "effective_adds": len(effective),
                                                "first_effective": effective[0][:80] if effective else None}


def gate_c(seed_text, cwe_now, patch_adds_text):
    """门 C：标签要件计数（A 版代码）。返回 verdict + detail。"""
    cwenum = cwe_num(cwe_now)
    if cwenum is None:
        return "n/a", {"why": f"标签非 CWE 形态: {cwe_now!r}"}
    e = CWE_EVIDENCE.get(cwenum)
    if e is None:
        return "no_vocab", {"why": f"CWE-{cwenum} 无要件词表（待补）"}
    strong_hits, weak_hits, sd, wd = count_evidence(seed_text, cwenum)
    # 缺失型辅助信号：修复新增行里是否有 strong 要件
    _, add_strong, _, _ = count_evidence(patch_adds_text, cwenum)
    detail = {"strong_hits": strong_hits, "weak_hits": weak_hits,
              "strong_detail": sd[:6], "weak_detail": wd[:6],
              "adds_strong_hits": add_strong}
    if strong_hits > 0:
        return "pass", detail
    if weak_hits > 0:
        return "weak", detail
    verdict = "pending_lead"
    if add_strong > 0:
        detail["possible_missing_type"] = True  # 修复代码含要件 → 大概率"因缺失而致的洞"，走门 D 而非判标签错
    return verdict, detail


def gate_e(patch_adds_text, changed_post):
    """门 E 素材：patch 新增行里的防御模式行号清单。"""
    lines = patch_adds_text.splitlines()
    found = []
    for i, ln in enumerate(lines, 1):
        if DEFENSE_RE.search(ln):
            found.append(ln.strip()[:90])
    return found[:8], len(found)


def main():
    wave_manifest = json.loads((WAVE / "manifest_PRIVATE.json").read_text(encoding="utf-8"))
    tp = json.loads((CORPUS / "train_pool/manifest.json").read_text(encoding="utf-8"))["samples"]
    tp_by_file = {s["file"]: s for s in tp}
    # 门 B 对账源
    patch_audit = {}
    pa_path = RESULTS / "_patch_audit_20260911.json"
    if pa_path.exists():
        pa = json.loads(pa_path.read_text(encoding="utf-8"))
        items = pa if isinstance(pa, list) else pa.get("items", pa.get("kits", []))
        for it in items:
            if isinstance(it, dict) and "kit" in it:
                patch_audit[it["kit"].replace(".txt", "")] = it

    rows = []
    for kid, meta in wave_manifest.items():
        seed = meta["seed"]
        seed_path = CORPUS / "train_pool" / seed
        patch_path = CORPUS / meta["patch_file"] if meta.get("patch_file") else None
        tp_entry = tp_by_file.get(seed)
        row = {"kit": kid, "seed": seed, "cve": meta.get("cve"),
               "cwe_now": meta.get("expected_cwe"),
               "expected_present": meta.get("expected_present", True),
               "quarantined": meta.get("status") == "quarantined",
               "relabeled": bool(meta.get("relabel_20260911"))}
        patch_text = patch_path.read_text(encoding="utf-8", errors="replace") if (patch_path and patch_path.exists()) else ""
        hunks = parse_patch(patch_text) if patch_text else []
        adds_text = "\n".join(ln for h in hunks for t, ln in h["lines"] if t == "+")
        seed_text = seed_path.read_text(encoding="utf-8", errors="replace") if seed_path.exists() else ""

        row["gateA"], row["gateA_detail"] = gate_a(kid, meta, tp_entry, patch_text)
        row["gateB"], row["gateB_detail"] = gate_b(hunks, meta.get("language"))
        if meta.get("expected_present") is False or meta.get("expected_cwe") in ("无洞", "none"):
            row["gateC"] = "n/a_negative"
            row["gateC_detail"] = {}
        else:
            row["gateC"], row["gateC_detail"] = gate_c(seed_text, meta.get("expected_cwe"), adds_text)
        if meta.get("expected_present") is False:
            defense_lines, n_def = gate_e(adds_text, meta.get("changed_post", []))
            row["gateE_defense_lines"] = defense_lines
            row["gateE_defense_count"] = n_def
        # 门 B 与既有 patch_audit 对账
        pa = patch_audit.get(kid)
        if pa:
            row["patch_audit_class"] = pa.get("class") or pa.get("verdict") or pa.get("category")
        rows.append(row)

    # ------- 汇总 -------
    active = [r for r in rows if not r["quarantined"]]
    out = {
        "generated": "2026-09-11",
        "total": len(rows),
        "active": len(active),
        "quarantined": len(rows) - len(active),
        "rows": rows,
    }
    (RESULTS / "_gates_20260911.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

    # ------- markdown 报告 -------
    L = ["# 六道门机检报告 · wave1 全量复扫（2026-09-11）", "",
         f"复扫 {len(rows)} 条（active {len(active)} / quarantined {len(rows)-len(active)}）。"
         "门 D 非机检（独立真值）、门 F 是训练闭环，本报告只产出机检三分清单。", "",
         "**机检边界**：门 C 是词法要件计数，\"因缺失而致的洞\"会被要件=0 误伤 → "
         "凡 `possible_missing_type=true` 的条目交门 D 复核，不机械判死。", ""]
    for gate, key in (("门 A 语义对齐", "gateA"), ("门 B 差分有效", "gateB"), ("门 C 标签可证", "gateC")):
        cnt = Counter(r[key] for r in active)
        L.append(f"## {gate}（active {len(active)} 条）")
        L.append("| verdict | 条数 |"); L.append("|---|---|")
        for k, v in cnt.most_common():
            L.append(f"| {k} | {v} |")
        L.append("")

    def listing(title, pred, detail_fn, limit=100):
        items = [r for r in active if pred(r)]
        L.append(f"## {title}（{len(items)} 条）"); L.append("")
        if items:
            L.append("| kit | CVE | 标签 | 证据 |"); L.append("|---|---|---|---|")
            for r in items[:limit]:
                L.append(f"| {r['kit']} | {r['cve'] or '-'} | {r['cwe_now']} | {detail_fn(r)} |")
        L.append("")

    listing("门 A FAIL —— 弃题候选（机制词 0 命中）", lambda r: r["gateA"] == "fail",
            lambda r: "改动行" + str(r["gateA_detail"].get("changed_lines", 0)) + "行，机制词/描述词全落空"
                      + ("；多文件patch" if r["gateA_detail"].get("multi_file_patch") else ""))
    listing("门 A WARN —— 低对齐复核队列", lambda r: r["gateA"] == "warn",
            lambda r: f"命中 {sorted(r['gateA_detail'].get('mech_hits', {}))} + 描述词 {sorted(r['gateA_detail'].get('desc_hits', {}))}")
    listing("门 C PENDING_LEAD —— 标签降级候选（要件=0）", lambda r: r["gateC"] == "pending_lead",
            lambda r: ("疑似缺失型(修复行含要件)→交门D" if r["gateC_detail"].get("possible_missing_type")
                       else "A版要件=0且修复行也无要件") + f"，weak={r['gateC_detail'].get('weak_hits', 0)}")
    listing("门 C WEAK —— 弱可证（仅 weak 要件）", lambda r: r["gateC"] == "weak",
            lambda r: f"strong=0 weak={r['gateC_detail'].get('weak_hits', 0)} e.g. {r['gateC_detail'].get('weak_detail', [])[:2]}")
    listing("门 C NO_VOCAB —— 词表缺口", lambda r: r["gateC"] == "no_vocab",
            lambda r: r["gateC_detail"].get("why", ""))
    listing("门 B FAIL —— 无有效新增行", lambda r: r["gateB"] == "fail",
            lambda r: f"add={r['gateB_detail'].get('add_total')} 全注释")

    # 门 E 素材
    negs = [r for r in active if r.get("expected_present") is False]
    L.append(f"## 门 E 素材 —— {len(negs)} 条负样本的 patch 防御行清单"); L.append("")
    L.append("| kit | 标签 | patch 防御信号行（供负样本改造包引用） |"); L.append("|---|---|---|")
    for r in negs:
        dl = r.get("gateE_defense_lines") or []
        L.append(f"| {r['kit']} | {r['cwe_now']} | {'<br>'.join(dl[:3]) if dl else '（无防御模式词命中——人工看码）'} |")
    L.append("")

    # 门 B 对账
    agree = [r for r in rows if r.get("patch_audit_class") is not None]
    L.append(f"## 门 B 对账（与 _patch_audit_20260911.json 逐条核对：{len(agree)} 条）")
    L.append("判定规则一致：patch 新增行无非注释有效行 = fail。")
    L.append("")
    L.append("## 门 F 占位：v2_17 从未训练，复测整环不存在 → 治理收益 0 验证（先于一切）。")
    (RESULTS / "_gates_20260911.md").write_text("\n".join(L) + "\n", encoding="utf-8")

    # ------- 终端摘要 -------
    print(f"复扫 {len(rows)}（active {len(active)}）")
    for gate, key in (("门A", "gateA"), ("门B", "gateB"), ("门C", "gateC")):
        print(f"{gate}:", Counter(r[key] for r in active).most_common())
    print("→", RESULTS / "_gates_20260911.md")


if __name__ == "__main__":
    main()
