"""
正则预过滤模块 —— 在调用 LLM 之前对代码做传统规则预筛，构成"混合扫描"的第一层。

设计目标：
- 高精度规则：仅在"几乎一定是漏洞"或"几乎一定是安全"时给出初步判定，
  模糊情形一律 preliminary_verdict=None 交给 LLM 复核。
- 与 schema.py 中的 _VULN_SIGNATURE_PATTERNS / _detect_safe_pattern 思路一致，
  但定位不同：schema.py 的 apply_safe_pattern_override 是 LLM 输出"之后"的兜底后处理，
  本模块是 LLM 调用"之前"的前置预筛，可对明显样本直接短路，节省 token / 降低延迟。
- matched_rules 记录命中规则名，便于实验日志追溯与消融分析。

判定逻辑：
- 命中安全模式且未命中漏洞特征 → preliminary_verdict=False（安全）
- 命中漏洞特征且未命中安全模式 → preliminary_verdict=True（漏洞）
- 两者都命中（模糊）或都没命中 → preliminary_verdict=None（交 LLM 复核）

置信度：
- 恰好命中一类（仅漏洞或仅安全）→ high
- 漏洞与安全都命中（相互矛盾，模糊）→ medium
- 都未命中（无强烈特征，需 LLM 细判）→ low

注意：本模块为"高精度低召回"设计，宁可漏判（交给 LLM）也不可误判。
正则无法理解语义，因此所有规则均为"强烈特征"匹配；注释/字符串字面量中的
误匹配属于已知局限，由后续 LLM 层兜底纠偏。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# 预筛规则统一元数据（全项目唯一来源）
# ---------------------------------------------------------------------------
# scanner.py 的短路终判与 two_stage_scanner.py 的候选生成共用本表，
# 避免两份 rule_name → taint_type / CWE / 风险等级映射漂移。
PREFILTER_RULE_INFO: dict[str, dict[str, str]] = {
    "sqli_string_concat": {
        "taint_type": "SQL Injection",
        "cwe": "CWE-89 SQL Injection",
        "risk": "High",
        "severity": "high",
    },
    "sqli_fstring": {
        "taint_type": "SQL Injection",
        "cwe": "CWE-89 SQL Injection",
        "risk": "High",
        "severity": "high",
    },
    "sqli_percent_format": {
        "taint_type": "SQL Injection",
        "cwe": "CWE-89 SQL Injection",
        "risk": "High",
        "severity": "high",
    },
    "cmd_os_system_concat": {
        "taint_type": "Command Injection",
        "cwe": "CWE-78 Command Injection",
        "risk": "Critical",
        "severity": "critical",
    },
    "cmd_subprocess_shell_concat": {
        "taint_type": "Command Injection",
        "cwe": "CWE-78 Command Injection",
        "risk": "Critical",
        "severity": "critical",
    },
    "rce_eval_request": {
        "taint_type": "Code Injection",
        "cwe": "CWE-94 Code Injection",
        "risk": "Critical",
        "severity": "critical",
    },
    "path_traversal_open_concat": {
        "taint_type": "Path Traversal",
        "cwe": "CWE-22 Path Traversal",
        "risk": "High",
        "severity": "high",
    },
    # 2026-08-29 补：os.path.join / new File(dir,name) 等路径构造形态。
    # 必须登记，否则 two_stage_scanner 的 _PREFILTER_TYPE 查不到 → taint_type
    # 回落默认 "Detected"，裁决层拿不到类型提示（hard_crossfile_02_input 实拍）。
    "path_traversal_open_join": {
        "taint_type": "Path Traversal",
        "cwe": "CWE-22 Path Traversal",
        "risk": "High",
        "severity": "high",
    },
    "deser_pickle_loads": {
        "taint_type": "Insecure Deserialization",
        "cwe": "CWE-502 Deserialization of Untrusted Data",
        "risk": "Critical",
        "severity": "critical",
    },
    "deser_yaml_unsafe_load": {
        "taint_type": "Insecure Deserialization",
        "cwe": "CWE-502 Deserialization of Untrusted Data",
        "risk": "High",
        "severity": "high",
    },
    # --- 2026-08-29 P2 补：零召回 category 规则族（工具层优化指导 §五 P2）---
    # 每条规则的形态依据见 _build_vuln_rules 内注释；全部按"语言/框架标准写法"
    # 声明（泛化纪律三关卡），不针对具体样本。
    "open_redirect": {
        "taint_type": "Open Redirect",
        "cwe": "CWE-601 Open Redirect",
        "risk": "Medium",
        "severity": "medium",
    },
    "log_injection": {
        "taint_type": "Log Injection",
        "cwe": "CWE-117 Log Injection",
        "risk": "Medium",
        "severity": "medium",
    },
    "timing_unsafe_compare": {
        "taint_type": "Timing Attack",
        "cwe": "CWE-208 Timing Side Channel",
        "risk": "Medium",
        "severity": "medium",
    },
    "crypto_weak_hash": {
        "taint_type": "Weak Cryptography",
        "cwe": "CWE-327 Weak Cryptography",
        "risk": "High",
        "severity": "high",
    },
    "crypto_weak_cipher": {
        "taint_type": "Weak Cryptography",
        "cwe": "CWE-327 Weak Cryptography",
        "risk": "High",
        "severity": "high",
    },
    "crypto_weak_random": {
        "taint_type": "Weak Cryptography",
        "cwe": "CWE-338 Weak Random",
        "risk": "Medium",
        "severity": "medium",
    },
    "crypto_hardcoded_iv": {
        "taint_type": "Weak Cryptography",
        "cwe": "CWE-329 Hardcoded IV",
        "risk": "High",
        "severity": "high",
    },
    "proto_pollution_merge": {
        "taint_type": "Prototype Pollution",
        "cwe": "CWE-1321 Prototype Pollution",
        "risk": "High",
        "severity": "high",
    },
    "proto_pollution_direct": {
        "taint_type": "Prototype Pollution",
        "cwe": "CWE-1321 Prototype Pollution",
        "risk": "High",
        "severity": "high",
    },
    # --- 2026-08-31 补：VFlask 审计暴露的 4 条真盲区（工具层优化指导 §9.8）---
    # 全部按"框架/语言标准 API"声明（泛化纪律三关卡），不针对具体样本：
    #   jwt.decode(verify=False)  → PyJWT 标准参数
    #   return str(e)             → 异常详情返回客户端（语言无关形态）
    #   敏感字段 = 请求值 + 入库   → 字段语义词根为行业标准命名
    #   request.files + save()    → Flask/Werkzeug 标准上传 API
    "jwt_verify_disabled": {
        "taint_type": "Improper Verification of Cryptographic Signature",
        "cwe": "CWE-347 Improper Verification of Cryptographic Signature",
        "risk": "Critical",
        "severity": "critical",
    },
    "error_info_exposure": {
        "taint_type": "Information Exposure Through Error Message",
        "cwe": "CWE-209 Information Exposure Through Error Message",
        "risk": "Medium",
        "severity": "medium",
    },
    "cleartext_sensitive_storage": {
        "taint_type": "Cleartext Storage of Sensitive Information",
        "cwe": "CWE-312 Cleartext Storage of Sensitive Information",
        "risk": "High",
        "severity": "high",
    },
    "unrestricted_file_upload": {
        "taint_type": "Unrestricted File Upload",
        "cwe": "CWE-434 Unrestricted Upload of File with Dangerous Type",
        "risk": "Medium",
        "severity": "medium",
    },
    "integer_overflow_ext_arith": {
        "taint_type": "Integer Overflow",
        "cwe": "CWE-190 Integer Overflow",
        "risk": "Medium",
        "severity": "medium",
    },
}


# 需要做"配对括号内查找"的调用起点正则（各规则复用，避免重复编译）
_CALL_START_PATTERNS = {
    "open": re.compile(r"open\s*\(", re.IGNORECASE),
    "os_system": re.compile(r"os\.system\s*\(", re.IGNORECASE),
    "subprocess": re.compile(
        r"subprocess\.(?:run|Popen|call|check_output|check_call)\s*\(", re.IGNORECASE),
    # 2026-08-29 补：路径类 sink（os.path.join 结果的危险汇聚点）。
    # tar.extractall 是 CVE-2007-4559 / CVE-2025-4517 那类 tar 路径穿越的 sink；
    # send_file / shutil 是 Web 与文件操作场景的常见路径 sink。
    "extractall": re.compile(r"\.extractall\s*\(", re.IGNORECASE),
    "send_file": re.compile(r"\bsend_file\s*\(", re.IGNORECASE),
    "shutil": re.compile(
        r"shutil\.(?:copy|copy2|move|rmtree|unpack_archive)\s*\(", re.IGNORECASE),
    # Java / Node file sinks (2026-08-29): the sink table was Python-centric,
    # so non-Python code never matched even with the multi-language join table.
    "fileinput": re.compile(r"fileinput\.(?:input|FileInput)\s*\(", re.IGNORECASE),
    "fis": re.compile(r"new\s+File(?:InputStream|OutputStream|Reader|Writer)\s*\("),
    "files_nio": re.compile(
        r"Files\.(?:readAllBytes|readString|newBufferedReader|copy|move|write)\s*\("),
    "fs_node": re.compile(
        r"(?:fs|require\(.fs.\))\.(?:readFileSync|readFile|createReadStream|appendFileSync|writeFileSync)\s*\("),
    # 2026-08-29 P2 补：重定向 / 日志类 sink。
    # redirect( 尾部子串同时覆盖 Flask redirect / Django redirect / Express
    # res.redirect / Java response.sendRedirect / HttpResponseRedirect——
    # "redirect(" 是这些 API 的公共尾缀（语言级事实，非样本特判）。
    # log_call 覆盖 Python logging / logger / log 与 Java logger 的各级别方法；
    # (?<!console\.) 排除前端 console.log（浏览器端无 CWE-117 日志注入语义）。
    "redirect": re.compile(r"redirect\s*\(", re.IGNORECASE),
    "log_call": re.compile(
        r"(?<!console\.)(?:logging|logger|log)\."
        r"(?:info|debug|warning|warn|error|critical|exception|notice|log)\s*\(",
        re.IGNORECASE,
    ),
}

# 外部可控输入源标记（2026-08-29 P2 规则族共用，与 two_stage_scanner._EXT_ENTRY_RE
# 同一事实集）：request/req 对象取值、Flask/Django args/form/GET/POST、Express
# query/body/params、Spring getParameter/@RequestParam/@PathVariable、环境/argv/输入。
# 供两类消费形态使用：① sink 参数区内直接出现（_sink_arg_has_input）；
# ② 被赋值给变量后 1 跳传入（_input_var_names + _sink_arg_refs_vars）。
_INPUT_SRC_RE = re.compile(
    r"(?:request\s*\[|request\s*\.|req\s*\.|\.args\b|\.GET\b|\.POST\b|\.form\b|"
    r"\.query\b|\.params\b|\.body\b|\.cookies\b|\.headers\b|getParameter\s*\(|"
    r"@RequestParam|@PathVariable|os\.environ|os\.getenv|sys\.argv|\binput\s*\()",
    re.IGNORECASE,
)

# 时序比较敏感词（timing_unsafe_compare 用）：与"凭证/签名/校验值"语义相关的
# 标识符词根。不含 username/uid 等普通标识符——普通字段的 == 比较不构成时序
# 侧信道告警价值（避免把常见业务比较当漏洞）。
# 请求容器取值的**起始根**（2026-08-30）：用于判断比较表达式的某一侧是否"直接
# 从请求里读取"，与 _INPUT_SRC_RE（"是否含输入源"）分工——后者不限位置，前者
# 必须是表达式开头。取值器（Python 的 .get('x')）本身带括号，故不能用"含括号
# 即服务端计算值"来区分，要看最外层是不是请求容器。
_INPUT_ROOT_RE = re.compile(
    r"^(?:req\b|request\b|params\b|\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER)",
    re.IGNORECASE,
)

_SECRET_COMPARE_NAME_RE = re.compile(
    r"token|secret|signature|mac|hash|otp|password|passwd|api_?key|csrf|nonce",
    re.IGNORECASE,
)

# 定宽整数的外部来源（integer_overflow_ext_arith 用）：
# ① Spring @RequestParam/@PathVariable 标注的基本数值形参（框架级事实）；
# ② C scanf("%d", &x) 的接收变量。
_EXT_INT_SRC_RE = re.compile(
    r"@\w*(?:RequestParam|PathVariable)\b[^;\n]{0,120}?\b(?:int|long|short|double|float)\s+(\w+)"
    r"|\bscanf\s*\([^;\n]{0,80}?%d[^;\n]{0,80}?&\s*(\w+)",
    re.IGNORECASE,
)


def _line_of(code: str, pattern: "re.Pattern[str]") -> int:
    """返回 pattern 在 code 中首次命中的行号（1-based；0=未命中）。

    供多 pattern 规则的 line_func 使用（2026-08-31）：这类规则由"漏洞主体特征 +
    上下文特征"共同构成，而 _hit_line 默认取**行号最小的命中 pattern**——
    上下文特征若出现在更靠前的位置，行号就会指到无关行，审计判定（expected
    行号 ±2）随之错失。line_func 让规则显式声明"哪一条才是漏洞主体"。
    命中判定与行号定位共用同一个 pattern 对象，天然同源，不会指错。
    """
    m = pattern.search(code or "")
    if not m:
        return 0
    return code.count("\n", 0, m.start()) + 1

# 路径构造 API（2026-08-29）：各语言"父目录 + 不可信片段 → 路径"的标准写法。
# 泛化依据：语言级/标准库级事实——os.path.join 是 Python 唯一标准路径拼接 API；
# new File(dir, name) 是 Java IO 路径构造的标准构造式；path.join / Paths.get 同理。
# 不是任何测试样本的特定写法。独立集 CVE-fix 验证：Python 侧命中 cve_fix_0016
# （CWE-22 真实 CVE 修复对）；Java 侧 new File(dir, name) 由本表覆盖（此前仅 Python）。
_PATH_JOIN_PATTERNS = (
    re.compile(r"os\.path\.join\s*\("),                  # Python
    re.compile(r"path\.join\s*\("),                      # Node.js
    re.compile(r"Paths\.get\s*\("),                      # Java NIO
    re.compile(r"new\s+File\s*\(\s*\w+\s*,\s*\w+\s*\)"), # Java IO：new File(dir, name)
)

# 路径构造调用的字面量子串（供 _call_arg_contains(sub=...) 做参数区内嵌匹配）。
# 与 _PATH_JOIN_PATTERNS 一一对应，两者同增同减。
_PATH_JOIN_LITERALS = (
    "os.path.join(",
    "path.join(",
    "Paths.get(",
    "new File(",
)

# 路径类 sink 的 key 集合（_join_flows_to_sink 用）
_PATH_SINK_KEYS = ("open", "extractall", "send_file", "shutil", "fileinput",
                   "fis", "files_nio", "fs_node")


# ---------------------------------------------------------------------------
# 规则数据结构
# ---------------------------------------------------------------------------
@dataclass
class _Rule:
    """单条预筛规则。

    Args:
        name: 规则名（命中后写入 PrefilterResult.matched_rules）
        patterns: 规则依赖的正则列表
        require_all: False=任一 pattern 命中即视为规则命中（OR 语义）；
                     True=所有 pattern 都命中才视为命中（AND 语义，用于组合特征，
                     如"参数化查询 = SQL 占位符 + execute 带参数元组"）
        exclude: 任一 exclude pattern 命中则规则不命中（用于否定条件，
                 如"列表形式 subprocess 且不含 shell=True"）
        category: "vuln" 漏洞特征 / "safe" 安全特征
    """
    name: str
    patterns: list[re.Pattern]
    require_all: bool = False
    exclude: list[re.Pattern] = field(default_factory=list)
    category: str = "vuln"
    # 高置信规则：即使同时命中安全特征也直接判漏洞（如 pickle.loads / yaml.load
    # 不存在"安全用法"，安全规则命中通常是同文件其他无关代码所致）
    high_confidence: bool = False
    # 自定义匹配器（如配对括号扫描）。设置后作为 AND 条件参与判定：
    # 必须先通过 match_func，再按 patterns/require_all 逻辑判定。
    match_func: Optional[Callable[[str], bool]] = None
    # 自定义行号定位器（2026-08-30）：match_func 型规则无正则可用，_hit_line
    # 只能返回 0 → 候选无行号，裁决层须全文重新定位，审计工具也无法把它与
    # expected 行号对齐（DVNA authHandler 的 timing 命中被当成"无关噪声"实锤）。
    # 设置后优先于 patterns 定位。
    line_func: Optional[Callable[[str], int]] = None

    def match(self, code: str) -> bool:
        """判断给定代码是否命中本规则。"""
        # 否定条件：命中任一 exclude 即不命中
        for ex in self.exclude:
            if ex.search(code):
                return False
        if self.match_func is not None and not self.match_func(code):
            return False
        if not self.patterns:
            return True
        if self.require_all:
            return all(p.search(code) for p in self.patterns)
        return any(p.search(code) for p in self.patterns)


# ---------------------------------------------------------------------------
# 预筛结果
# ---------------------------------------------------------------------------
@dataclass
class PrefilterResult:
    """正则预筛结果。

    Attributes:
        has_obvious_vuln: 是否命中明显漏洞特征
        has_obvious_safe: 是否命中明显安全特征
        has_secret_marker: 是否命中"硬编码凭证痕迹"标记。标记命中不直接判漏洞
            （硬编码凭证的 CWE 归因准确率低，易误报），而是用于"抑制安全判定"
            ——有凭证痕迹时 prefilter 不判安全，强制 LLM 复核，防止含漏洞代码
            被安全规则误判为安全后短路放行。
        matched_rules: 命中的规则名列表（漏洞规则在前，安全规则在后，标记最后）
        preliminary_verdict: 初步判定。
            - has_obvious_vuln 且 not has_obvious_safe → True（漏洞）
            - has_secret_marker 为 True 时 → 不判 False（安全），回落到 None
            - has_obvious_safe 且 not has_obvious_vuln 且 not has_secret_marker → False（安全）
            - 否则 → None（交 LLM）
        confidence: 置信度 "high" / "medium" / "low"
    """
    has_obvious_vuln: bool
    has_obvious_safe: bool
    has_secret_marker: bool = False
    matched_rules: list[str] = field(default_factory=list)
    # 命中行号（2026-08-29 新增）：matched_lines[i] 对应 matched_rules[i] 的
    # 命中行（1-based，0=未能定位）。prefilter 规则此前只报"命中/未命中"无位置，
    # 裁决档候选因此全是 srcL0/sinkL0，模型须自行全文重新定位（用户实测 14 条
    # 无位置候选）。位置由规则的正则在代码中搜索得到；match_func 型规则或
    # 搜索不到时记 0（与旧行为一致，向下兼容）。
    matched_lines: list[int] = field(default_factory=list)
    preliminary_verdict: Optional[bool] = None
    confidence: str = "low"

    def __repr__(self) -> str:
        verdict_str = {True: "漏洞", False: "安全", None: "待定(交LLM)"}[self.preliminary_verdict]
        return (f"PrefilterResult(vuln={self.has_obvious_vuln}, safe={self.has_obvious_safe}, "
                f"marker={self.has_secret_marker}, verdict={verdict_str}, "
                f"confidence={self.confidence}, rules={self.matched_rules})")


# ---------------------------------------------------------------------------
# 预过滤器
# ---------------------------------------------------------------------------
class Prefilter:
    """基于正则的代码预筛器（LLM 调用前的前置规则层）。

    所有正则统一使用 re.IGNORECASE：变量名（password / Password / PASSWORD）、
    SQL 关键字（SELECT / select）大小写不一，忽略大小写可提升召回且不损精度
    （Python 模块/函数名大小写敏感，但 IGNORECASE 对 os.system 等无害）。

    规则按"高置信度强烈特征"选取，宁缺毋滥：模糊写法不纳入，留给 LLM。
    """

    def __init__(self) -> None:
        # 漏洞特征规则（命中任一即视为"明显漏洞"，除非同时命中安全模式）
        self.vuln_rules: list[_Rule] = self._build_vuln_rules()
        # 安全特征规则（命中任一即视为"明显安全"，除非同时命中漏洞特征）
        self.safe_rules: list[_Rule] = self._build_safe_rules()
        # 硬编码凭证痕迹标记（不判漏洞，仅抑制安全判定，强制 LLM 复核）
        self.secret_markers: list[_Rule] = self._build_secret_markers()
        # 长文件阈值：超过此行数的代码不判安全（避免长文件中隐藏漏洞被安全规则误判放行）
        self.longfile_threshold: int = 150

    # ------------------------------------------------------------------
    # 规则构建
    # ------------------------------------------------------------------
    def _call_arg_regions(
        self, code: str, pattern_key: str, mask_strings: bool = True,
    ):
        """yield 每个调用起点的参数区文本（配对括号扫描，支持嵌套调用）。

        Args:
            mask_strings: True 时把字符串字面量内容以空格屏蔽（默认）——
                token/sub 特征匹配（拼接号、API 名）不应被字符串内容误触发；
                False 时保留原文——输入源标记/变量名匹配（open_redirect /
                log_injection）需要看到 f"…{username}" 内插的变量名。
        """
        for m in _CALL_START_PATTERNS[pattern_key].finditer(code):
            # 正则已消费左括号，从参数区起点直接以 depth=1 扫描
            buf = None  # 惰性复制：仅在遇到字符串字面量时才屏蔽
            depth = 1
            in_str: Optional[str] = None
            escaped = False
            j = m.end()
            start = j
            while j < len(code):
                ch = code[j]
                if in_str is not None:
                    if mask_strings:
                        if buf is None:
                            buf = list(code)
                        buf[j] = " "
                    if escaped:
                        escaped = False
                    elif ch == "\\":
                        escaped = True
                    elif ch == in_str:
                        in_str = None
                    j += 1
                    continue
                if ch in ("'", '"'):
                    in_str = ch
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            end = j if j < len(code) else len(code)
            yield ("".join(buf[start:end]) if buf is not None else code[start:end])

    def _call_arg_contains(
        self, code: str, pattern_key: str, token: Optional[str] = "+",
        sub: Optional[str] = None,
    ) -> bool:
        """定位调用起点后扫描到配对右括号，判断参数区内（含嵌套）是否出现 token / sub。

        替代 `[^)]*` 正则：嵌套括号（如 open(os.path.join(d, n) + s)）不会再提前终止。
        跳过字符串字面量内容，open("a+b") 不会误命中。

        Args:
            token: 单字符特征（默认 "+"），在参数区任意位置出现即命中。
            sub:   子串特征（2026-08-29 新增，如 "os.path.join"）。指定时忽略 token，
                   在参数区做子串匹配——用于 os.path.join 这类多字符调用形态。
                   传入 sub 时 token 应设为 None（语义互斥）。
        """
        for region in self._call_arg_regions(code, pattern_key, mask_strings=True):
            if token is not None and token in region:
                return True
            if sub is not None and sub in region:
                return True
        return False

    # ------------------------------------------------------------------
    # 输入源辅助（2026-08-29 P2 规则族共用）
    # ------------------------------------------------------------------
    def _input_var_names(self, code: str) -> set[str]:
        """被赋值为外部输入表达式的变量名（1 跳，语言级标准形态）。

            target = request.args.get("url", "/")     # Flask/Django
            token = req.headers.get("X-Token")        # Express
            data = parse(request.body)                # 经函数包装
            x = request.getParameter("q")             # Java Servlet

        仅识别「= 右侧直接是 request/req 取值」的 1 跳形态；更深传递链交由
        TaintTracker/LLM 裁决层，正则层不追（保精度）。
        """
        names: set[str] = set()
        for m in re.finditer(r"(\w+)\s*=\s*(?:request|req)\s*[\.\[]", code, re.IGNORECASE):
            names.add(m.group(1))
        for m in re.finditer(
                r"(\w+)\s*=\s*[\w.]+\s*\(\s*(?:request|req)\s*[\.\[]", code, re.IGNORECASE):
            names.add(m.group(1))
        return names

    def _sink_arg_has_input(self, code: str, sink_keys) -> bool:
        """任一 sink 的参数区内直接出现外部输入源标记（保留字符串原文，见
        _call_arg_regions mask_strings=False 的说明——f-string 内插变量是
        log/redirect 场景的主流写法）。"""
        for key in sink_keys:
            if key not in _CALL_START_PATTERNS:
                continue
            for region in self._call_arg_regions(code, key, mask_strings=False):
                if _INPUT_SRC_RE.search(region):
                    return True
        return False

    def _sink_arg_refs_vars(self, code: str, sink_keys, var_names: set[str]) -> bool:
        """任一 sink 的参数区引用给定变量集合中的变量（1 跳数据流形态）。"""
        if not var_names:
            return False
        var_re = re.compile(
            r"\b(?:" + "|".join(sorted(re.escape(v) for v in var_names)) + r")\b")
        for key in sink_keys:
            if key not in _CALL_START_PATTERNS:
                continue
            for region in self._call_arg_regions(code, key, mask_strings=False):
                if var_re.search(region):
                    return True
        return False

    def _build_vuln_rules(self) -> list[_Rule]:
        """构建漏洞特征规则集。"""
        IC = re.IGNORECASE
        rules: list[_Rule] = []

        # --- SQL 注入：字符串拼接 / f-string / % 格式化进 execute ---
        rules.append(_Rule(
            name="sqli_string_concat",
            patterns=[re.compile(r"\.execute\s*\(\s*['\"][^'\"]*['\"]\s*\+", IC)],
            category="vuln",
        ))
        rules.append(_Rule(
            name="sqli_fstring",
            patterns=[re.compile(r"\.execute\s*\(\s*f['\"]", IC)],
            category="vuln",
        ))
        rules.append(_Rule(
            name="sqli_percent_format",
            patterns=[re.compile(r"\.execute\s*\(\s*['\"][^'\"]*['\"]\s*%", IC)],
            category="vuln",
        ))

        # --- 命令注入 ---
        # os.system(... + 用户输入)；配对括号扫描，支持嵌套调用
        rules.append(_Rule(
            name="cmd_os_system_concat",
            patterns=[],
            match_func=lambda code: self._call_arg_contains(code, "os_system"),
            category="vuln",
        ))
        # subprocess.*(..., shell=True) 且调用内含字符串拼接
        # 组合特征：必须同时出现 shell=True 与"subprocess 调用内含 +"，
        # 二者缺一不可（单独 shell=True 已由 schema.py 后处理层覆盖，此处要求更严）
        rules.append(_Rule(
            name="cmd_subprocess_shell_concat",
            patterns=[
                re.compile(r"shell\s*=\s*True", IC),
            ],
            require_all=True,
            match_func=lambda code: self._call_arg_contains(code, "subprocess"),
            category="vuln",
        ))
        # eval(request....) 远程代码执行
        rules.append(_Rule(
            name="rce_eval_request",
            patterns=[re.compile(r"eval\s*\(\s*request", IC)],
            category="vuln",
        ))

        # --- 路径穿越：open(... + 用户输入)；配对括号扫描，支持嵌套调用 ---
        rules.append(_Rule(
            name="path_traversal_open_concat",
            patterns=[],
            match_func=lambda code: self._call_arg_contains(code, "open"),
            category="vuln",
        ))

        # --- 路径穿越（os.path.join 形态，2026-08-29 补）---
        # 原规则只认 open(...) 参数区出现 "+" 的拼接写法，而 Python 路径拼接的
        # 主流写法是 os.path.join(base, name)（无 "+"）——实测 87 段中 4 段
        # CWE-22 样本全部使用该形态，原规则命中率 0/4。
        # 注意：join 结果常先赋给变量再传入 open（`filepath = join(...)` 然后
        # `open(filepath)`），故不能只查 open 参数区内嵌 join，须做**变量级
        # 1 跳追踪**（_join_flows_to_sink）。这是数据流的基本形态，非样本特判。
        # 安全性由现有路径类安全规则保障（abspath+startswith/basename 等
        # 命中时判安全，见 _build_safe_rules）。
        rules.append(_Rule(
            name="path_traversal_open_join",
            patterns=[],
            match_func=lambda code: self._join_flows_to_sink(code),
            category="vuln",
        ))

        # --- 硬编码敏感信息规则已移除 ---
        # 原 hardcoded_secret 漏洞规则精度过低：在合成集 8 次命中里 8 次都是把
        # Flask 的 app.secret_key（框架必需配置）误判为硬编码凭证漏洞，CWE 归因
        # 全错（命中 CWE-798，实际是 IDOR/CSRF/JWT 等主漏洞）。现降级为
        # "安全判定抑制标记"（见 _build_secret_markers）：命中时不再判漏洞，
        # 仅用于阻止 prefilter 判安全（强制 LLM 复核），避免误报 + 误放行。

        # --- 不安全反序列化 ---
        rules.append(_Rule(
            name="deser_pickle_loads",
            patterns=[re.compile(r"pickle\.loads\s*\(", IC)],
            category="vuln",
            high_confidence=True,
        ))
        # yaml.load( / yaml.load_all( —— 注意排除 yaml.safe_load(
        # 'yaml.load' 不是 'yaml.safe_load' 的子串，故该模式天然不匹配 safe_load
        rules.append(_Rule(
            name="deser_yaml_unsafe_load",
            patterns=[re.compile(r"yaml\.load(?:_all)?\s*\(", IC)],
            category="vuln",
            high_confidence=True,
        ))

        # --- 开放重定向（2026-08-29 P2，工具层优化指导 §一 缺口表）---
        # 漏洞形态（语言级事实）：redirect 类 sink 的目标来自外部输入。
        # sink 表：redirect( 尾缀覆盖 Flask/Django/Express/Java sendRedirect。
        # 两种形态：① 参数区直接出现输入源；② 输入先赋变量再传入（主流写法）。
        # 安全写法由 LLM 裁决层判断（如白名单校验后重定向为安全——但那属于
        # 语义判断，正则层只负责把"输入流入重定向"的候选送进裁决）。
        rules.append(_Rule(
            name="open_redirect",
            patterns=[],
            match_func=lambda code: (
                self._sink_arg_has_input(code, ("redirect",))
                or self._sink_arg_refs_vars(
                    code, ("redirect",), self._input_var_names(code))
            ),
            category="vuln",
        ))

        # --- 日志注入（2026-08-29 P2，CWE-117）---
        # 漏洞形态：外部输入未经净化写入日志（伪造日志条目 / 注入换行）。
        # logger.info(f"Login attempt from user: {username}") 是标准写法——
        # f-string 内插变量，故 _sink_arg_* 必须保留字符串原文（mask_strings=False）。
        rules.append(_Rule(
            name="log_injection",
            patterns=[],
            match_func=lambda code: (
                self._sink_arg_has_input(code, ("log_call",))
                or self._sink_arg_refs_vars(
                    code, ("log_call",), self._input_var_names(code))
            ),
            category="vuln",
        ))

        # --- 时序侧信道比较（2026-08-29 P2，CWE-208）---
        # 漏洞形态：外部输入派生的凭证/签名值用 ==/!= 直接比较（非常数时间）。
        # 修正写法是 hmac.compare_digest / secrets.compare_digest（语言级事实）。
        # 仅当"输入派生变量名命中凭证敏感词"且"参与 ==/!= 比较"才触发。
        rules.append(_Rule(
            name="timing_unsafe_compare",
            patterns=[],
            match_func=lambda code: self._timing_unsafe_compare(code),
            # 行号定位（2026-08-30）：命中判定与行号同源，均走 _timing_hit_line
            line_func=lambda code: self._timing_hit_line(code),
            category="vuln",
        ))

        # --- 弱加密算法族（2026-08-29 P2，CWE-327/329/338）---
        # 全部按标准库/主流库 API 名声明（语言级事实）：
        # 弱哈希：hashlib.md5/sha1、Crypto.Hash.MD5/SHA1、Java MessageDigest
        #   MD5/SHA-1、Node createHash('md5'|'sha1')。
        # 弱算法/模式：ECB 模式、DES/DESede/Blowfish/RC4。
        # 弱随机：安全语义目标（token/password/…）← random 模块可预测 API /
        #   Java new Random / Math.random / C rand / PHP mt_rand。
        #   os.urandom / random.SystemRandom / secrets 模块是 CSPRNG，不在表内。
        # 硬编码 IV：IV 后缀大写常量名（STATIC_IV 等，AES IV 的标准命名）或
        #   iv= 参数直接赋字面量。IV 模式**不用** IGNORECASE——排除 activity/
        #   derive 等含 "iv" 的普通单词。
        rules.append(_Rule(
            name="crypto_weak_hash",
            patterns=[
                re.compile(r"hashlib\.(?:md5|sha1)\s*\(", IC),
                re.compile(r"Crypto\.Hash\.(?:MD5|SHA1)\b"),
                re.compile(r"MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-?1)['\"]", IC),
                re.compile(r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]", IC),
            ],
            category="vuln",
        ))
        rules.append(_Rule(
            name="crypto_weak_cipher",
            patterns=[
                re.compile(r"\bMODE_ECB\b"),
                re.compile(r"['\"]\w+/ECB/", IC),
                re.compile(r"Cipher\.getInstance\s*\(\s*['\"](?:DES|DESede|Blowfish|RC4)[/\"']", IC),
                re.compile(r"from\s+Crypto\.Cipher\s+import\s+[\w,\s]*\b(?:DES3?|Blowfish|ARC4)\b"),
                re.compile(r"createCipheriv\s*\(\s*['\"]des", IC),
                re.compile(r"createCipheriv\s*\(\s*['\"][\w-]*ecb", IC),
            ],
            category="vuln",
        ))
        rules.append(_Rule(
            name="crypto_weak_random",
            patterns=[re.compile(
                r"\b(?:token|password|passwd|secret|nonce|salt|otp|session_?id|"
                r"csrf_?token|api_?key|verify_?code|captcha)\w*\s*=\s*[^;\n]*"
                r"\b(?:random\.(?:choices?|choice|randint|randrange|randbytes|"
                r"getrandbits|sample|uniform|random)\s*\("
                r"|Math\.random\s*\(|new\s+Random\s*\(|\bmt_rand\s*\(|\brand\s*\(\s*\))",
                IC,
            )],
            category="vuln",
        ))
        rules.append(_Rule(
            name="crypto_hardcoded_iv",
            # 大小写敏感（无 IC）：IV 后缀大写是初始化向量常量的标准命名
            patterns=[re.compile(r"\b(?:\w*IV|iv)\s*=\s*b?['\"][^'\"]{8,}['\"]")],
            category="vuln",
        ))

        # --- 原型污染（2026-08-29 P2，CWE-1321，JS）---
        # 漏洞形态（JS 事实标准）：① 递归/键遍历合并器 + 外部数据进入合并调用
        # （for-in 键遍历 + 键下标写入 + merge 族 API 收 req.body——典型三件套）；
        # ② __proto__/constructor.prototype 直接赋值。
        rules.append(_Rule(
            name="proto_pollution_merge",
            patterns=[
                re.compile(r"for\s*\(\s*(?:const|let|var)?\s*\w+\s+in\s+\w+\s*\)", IC),
                re.compile(r"\w+\[\s*\w+\s*\]\s*=\s*\w"),
                re.compile(
                    r"(?:\bmerge\b|\bextend\b|\bdefaults\b|\bdeepmerge\b|_\.merge|"
                    r"lodash\.(?:merge|set|defaultsDeep)|Object\.assign)\w*\s*\("
                    r"[^;]{0,120}?(?:req\s*\.(?:body|query|params)|"
                    r"request\s*\.(?:body|query|args|form|GET|POST))",
                    IC,
                ),
            ],
            require_all=True,
            category="vuln",
        ))
        rules.append(_Rule(
            name="proto_pollution_direct",
            patterns=[
                re.compile(r"\[\s*['\"]__proto__['\"]\s*\]\s*=", IC),
                re.compile(r"\b__proto__\s*=", IC),
                re.compile(r"\.constructor\s*\.\s*prototype\s*\[?\s*=", IC),
            ],
            category="vuln",
        ))

        # --- JWT 签名校验被关闭（2026-08-31，CWE-347）---
        # 漏洞形态（PyJWT / jsonwebtoken / jjwt 等库的标准参数名，语言级事实）：
        # 解码时显式关闭签名校验 → 攻击者可伪造任意 payload（典型可致越权）。
        # 三种标准关闭写法（均为库文档记载的 API 参数，非某仓库变量命名）：
        #   ① verify=False / verify_signature=False   （PyJWT）
        #   ② options={"verify_signature": False}     （PyJWT，字典选项形态）
        #   ③ algorithms=[] 空算法列表                （PyJWT 无算法即不校验）
        # 安全写法 `jwt.decode(token, key, algorithms=["HS256"])` 不含上述参数，
        # 天然不命中；`verify=True` 为默认值亦不命中。
        # 参数区用 `(?:[^()]|\([^()]*\))*?` 而非 `[^)]*`：后者遇到实参里的
        # **内层调用**就断了——`jwt.decode(request.args.get("t"), verify=False)`
        # 的 get(...) 自带一对括号，用 [^)] 会漏判（自检用例实锤）。前者容忍
        # 一层嵌套调用，足以覆盖"参数由函数调用/切片产生"的常见写法；
        # 同时仍以 `jwt.decode(` 为锚点，不会跨语句误配。
        rules.append(_Rule(
            name="jwt_verify_disabled",
            patterns=[
                re.compile(r"jwt\.decode\s*\((?:[^()]|\([^()]*\))*?verify\s*=\s*False", IC),
                re.compile(r"jwt\.decode\s*\((?:[^()]|\([^()]*\))*?verify_signature\s*['\"]?\s*[:=]\s*False", IC),
            ],
            category="vuln",
        ))

        # --- 异常详情返回客户端（2026-08-31，CWE-209）---
        # 漏洞形态（语言无关）：异常处理块把异常文本直接作为响应体返回。
        # 内部异常消息常含堆栈片段、SQL 片段、文件路径、配置值 → 信息泄露。
        # 只认"返回给调用方"这一动作（return/响应构造），不匹配日志/打印：
        #   logging.error(str(e)) / print(str(e)) 是正常排错行为，不算泄露。
        # 正确写法是返回通用错误文案、详情记日志。
        # 命中与行号**同源**，均走 _error_exposure_line（2026-08-31）：
        # 初版用 `str\(\w+\)` 匹配，把 `return str(result)` / `str(user_id)`
        # 这类**普通变量**也当成异常回显（87 段回归实锤：safe_16_ldap_escape、
        # hard_crossfile_03_input 两个安全样本因此误报）。必须限定为
        # `except ... as <name>` 绑定的异常变量本身，才是 CWE-209 的形态。
        rules.append(_Rule(
            name="error_info_exposure",
            patterns=[],
            match_func=lambda code: self._error_exposure_line(code) > 0,
            line_func=lambda code: self._error_exposure_line(code),
            category="vuln",
        ))

        # 敏感字段取自请求的正则单独提出：规则匹配与行号定位**必须共用同一
        # 正则**（2026-08-31 实锤）——本规则是双 pattern AND（敏感字段 + 持久化
        # 调用），而 _hit_line 取"最小行号的匹配 pattern"，VFlask app.py 的持久化
        # 调用在 L64、敏感字段在 L160，行号会落到无关的 L64，审计判定（L160±2）
        # 因此错失。漏洞主体是"敏感字段从请求进来"那一行，故显式指定 line_func。
        _sensitive_field_re = re.compile(
            r"\b(?:ccn|cc_?num|credit_?card|card_?number|card_?num|cardnum|"
            r"cvv|cvc|ssn|social_?security|iban|passport_?no)\w*\s*=\s*"
            r"(?:content|request|body|form|args|data|json|payload|"
            r"req\.body|req\.query|params)\b", IC)

        # --- 敏感字段明文入库（2026-08-31，CWE-312）---
        # 漏洞形态：支付/身份类敏感字段取自请求，随后持久化且文件内无加密痕迹。
        # 两个 AND 条件（require_all）：
        #   ① 敏感字段 = 请求值（字段语义词根 ccn/credit_card/card_number/cvv/
        #      ssn/iban 等为行业通用命名与 PCI-DSS 术语，非某仓库变量命名）；
        #   ② 文件内存在持久化调用（ORM session.add / .save() / INSERT）。
        # 是否真"明文"由裁决层判定（可能已加密），本规则只负责把这类数据流
        # 送进裁决——绝不能让支付数据静默落库而不被检视。
        #
        # **不设 exclude 排除"存在加密调用"**（2026-08-31 实锤）：exclude 是
        # **文件级**判定，只要文件任何位置出现 hashlib/encrypt 就会整体排除——
        # 而 VFlask app.py 的 L141 hashlib.md5(密码) 与 L160 的 ccn 完全无关，
        # 却把整条 312 规则排除了。"敏感字段是否被加密"是**字段级**语义，
        # 正则层判不了，交给裁决层；此处若强行排除，等于让无关的密码哈希
        # 给支付数据做了伪证。
        rules.append(_Rule(
            name="cleartext_sensitive_storage",
            patterns=[
                _sensitive_field_re,
                re.compile(
                    r"(?:session\.add\s*\(|\.save\s*\(|\.add\s*\(\s*\w+\s*\)|"
                    r"INSERT\s+INTO|\.create\s*\(|\.insert_one\s*\(|\.insert\s*\()", IC),
            ],
            require_all=True,
            # 行号指向"敏感字段从请求进来"那一行（漏洞主体），而非持久化调用行
            line_func=lambda code: _line_of(code, _sensitive_field_re),
            category="vuln",
        ))

        # --- 无限制文件上传（2026-08-31，CWE-434）---
        # 漏洞形态（Flask/Werkzeug/Express/Django 的标准上传 API，语言级事实）：
        # 取上传文件 → 落盘保存，但**未做扩展名/类型白名单校验**。
        # 两条件 AND：① 存在上传文件取值；② 存在落盘保存。
        # 排除（关键）：出现扩展名/类型校验特征时**不报**——
        #   allowed_file( / allowed_extensions / ALLOWED_EXTENSIONS /
        #   .endswith(('.png',...)) / content_type 校验 / mimetypes 校验。
        # 注意：secure_filename() **不**在此列——它只净化路径（防穿越），
        # 不限制文件类型，用它防不住上传 .php/.jsp 等危险类型（VFlask L294 实锤：
        # 该行同时有 secure_filename 与任意类型上传，正是本规则要抓的形态）。
        rules.append(_Rule(
            name="unrestricted_file_upload",
            patterns=[
                re.compile(r"request\.files\s*[\[.]|req\.files\b|request\.FILES|"
                           r"@RequestParam\s+MultipartFile|getPart\s*\(", IC),
                re.compile(r"\.\s*save\s*\(|\.write\s*\(|Files\.copy\s*\("
                           r"|move_uploaded_file\s*\(", IC),
            ],
            require_all=True,
            exclude=[
                re.compile(r"allowed_?file\b|allowed_?extensions?\b", IC),
                re.compile(r"\.endswith\s*\(\s*[\(\['\"]", IC),
                re.compile(r"splitext\s*\(|mimetypes?\.guess|content_?type\s*(?:not\s*)?in\b", IC),
                re.compile(r"ALLOWED_?(?:EXT|MIME|TYPE)", IC),
            ],
            category="vuln",
        ))

        # --- 定宽整数溢出（2026-08-29 P2，CWE-190，Java/C 族）---
        # 漏洞形态（语言级事实）：Java int/long 等定宽整数与外部输入派生操作数
        # 相乘/相加会静默回绕。只认「定宽类型声明 ← 外部来源操作数的乘法」：
        # 外部来源 = @RequestParam/@PathVariable 数值形参（Spring 标准注解）、
        # scanf %d 接收变量、Integer.parseInt(request…) 的赋值目标。
        # Python int 任意精度，不适用本规则（声明语法即语言隔离）。
        rules.append(_Rule(
            name="integer_overflow_ext_arith",
            patterns=[],
            match_func=lambda code: self._int_overflow_ext_arith(code),
            category="vuln",
        ))

        return rules

    def _timing_unsafe_compare(self, code: str) -> bool:
        """输入派生的凭证/签名变量参与 ==/!= 比较（时序侧信道候选）。

        排除：比较行含 session 取值（`token != session.get("csrf_token")` 是
        CSRF 校验的标准实现，会话内令牌比对不构成有告警价值的时序侧信道）。
        """
        return self._timing_hit_line(code) > 0

    @staticmethod
    def _both_sides_external(line: str) -> bool:
        """比较两侧**均直接取自外部输入** → 字段一致性校验，非时序侧信道。

        `req.body.password == req.body.cpassword`（注册/改密的确认密码校验）
        比较的是**用户自己提交的两个值**，攻击者两侧都能控制，响应时间的差异
        不泄露任何服务端秘密——时序侧信道成立的前提是**至少一侧为服务端持有
        的秘密**（常量、哈希结果、会话值等）。这是语言无关的安全分析事实，
        且属极常见业务写法（DVNA appHandler L152 / passport L64 实锤，两者
        均被判为无关噪声）。

        判定：比较号两侧都含输入源，且右侧未经任何函数调用加工（右侧若有调用，
        如 `req.body.token == md5(req.body.login)`，则该侧是**服务端计算值**，
        构成真实的秘密比较，必须保留）。
        """
        sides = re.split(r"==|!=", line, maxsplit=1)
        if len(sides) != 2:
            return False
        left, right = sides
        if not (_INPUT_SRC_RE.search(left) and _INPUT_SRC_RE.search(right)):
            return False
        # 右侧**起始**必须是请求容器取值（req.body.x / request.form.get('x')），
        # 才说明这一侧也是"从请求里读来的"——不能只看整行是否含 "("：同行后续
        # 语句（if (a == b) { res.send('ok'); }）里的调用会污染整行判断，且
        # Python 的 .get('x') 取值器本身带括号，按"含括号=服务端计算值"会漏判。
        right_head = right.strip().split()[0] if right.strip() else ""
        return bool(right_head) and bool(_INPUT_ROOT_RE.match(right_head))

    def _error_exposure_line(self, code: str) -> int:
        """异常详情被返回给客户端的首个行号（1-based；0=未命中）。

        CWE-209 的形态是：**异常处理块**把异常文本放进响应体。故只认
        `except ... as <name>` 绑定的那个变量被 str() 后 return——普通变量
        （`return str(result)`）与日志记录（`logging.error(str(e))`）都不算。
        另收 `traceback.format_exc()` 直接返回（同样泄露堆栈详情）。

        异常变量名由代码自己声明（`except X as e`），不做"猜名字"的特判；
        额外兜底 `e` 是因为它是 Python 社区压倒性的约定名，且部分代码用
        `except Exception:` 不绑定变量而直接引用 e（历史写法）。
        """
        names = set(re.findall(r"except\s+[\w.]+\s+as\s+(\w+)", code or ""))
        names.add("e")
        best = 0
        for name in names:
            pat = re.compile(
                r"return\s+[^\n]{0,200}?str\s*\(\s*%s\s*(?:\.\w+)*\s*\)" % re.escape(name),
                re.IGNORECASE,  # 注意：IC 是各 _build_* 方法的局部变量，此处不可用
            )
            m = pat.search(code or "")
            if m:
                ln = code.count("\n", 0, m.start()) + 1
                if best == 0 or ln < best:
                    best = ln
        m2 = re.compile(
            r"return\s+[^\n]{0,200}?(?:traceback\.format_exc|format_exception)\s*\(",
            re.IGNORECASE,
        ).search(code or "")
        if m2:
            ln = code.count("\n", 0, m2.start()) + 1
            if best == 0 or ln < best:
                best = ln
        return best

    def _timing_hit_line(self, code: str) -> int:
        """定位首次时序不安全比较所在行（1-based；0=未命中）。

        行号必须与命中判定同源（两者共用本函数），否则会出现"规则命中但行号
        为 0 / 行号指向无关行"——候选位置错配会误导裁决层定位（2026-08-30）。
        """
        best = 0
        for var in self._input_var_names(code):
            if not _SECRET_COMPARE_NAME_RE.search(var):
                continue
            esc = re.escape(var)
            for m in re.finditer(rf"\b{esc}\s*(?:==|!=)|(?:==|!=)\s*{esc}\b", code):
                line_start = code.rfind("\n", 0, m.start()) + 1
                line_end = code.find("\n", m.end())
                line = code[line_start: line_end if line_end != -1 else len(code)]
                if re.search(r"session\s*[\[.]", line, re.IGNORECASE):
                    continue
                if self._both_sides_external(line):
                    continue
                ln = code.count("\n", 0, m.start()) + 1
                if best == 0 or ln < best:
                    best = ln
        # 通道 2：内联输入源比较（2026-08-30，DVNA authHandler L49 实锤缺口）。
        #   if (req.query.token == md5(req.query.login)) { ... }
        # 凭证语义标识符直接写在比较表达式里、未经中间变量赋值——通道 1 的
        # _input_var_names 只收集**赋值目标**，这类形态此前完全漏召回。
        # 形态与通道 1 等价（都是"凭证语义值参与 ==/!= 比较"），属语言无关写法。
        # 行内必须出现输入源（_INPUT_SRC_RE），否则是比较两个常量/局部变量，
        # 与时序侧信道无关。
        for m in re.finditer(
                r"([A-Za-z_$][\w$]*)\s*(?:==|!=)|(?:==|!=)\s*([A-Za-z_$][\w$]*)", code):
            ident = m.group(1) or m.group(2) or ""
            if not ident or not _SECRET_COMPARE_NAME_RE.search(ident):
                continue
            line_start = code.rfind("\n", 0, m.start()) + 1
            line_end = code.find("\n", m.end())
            line = code[line_start: line_end if line_end != -1 else len(code)]
            if re.search(r"session\s*[\[.]", line, re.IGNORECASE):
                continue
            if self._both_sides_external(line):
                continue
            if not _INPUT_SRC_RE.search(line):
                continue
            ln = code.count("\n", 0, m.start()) + 1
            if best == 0 or ln < best:
                best = ln
        # 取**最靠前**的命中行，而非首个遍历到的变量所在行：变量集合迭代顺序
        # 与代码位置无关，直接返回首个匹配会让候选指向靠后的无关比较行
        # （DVNA authHandler 实锤：指针落到 L71 的密码一致性校验，而真正的
        #  时序敏感比较在 L49 的 token == md5(login)）。
        return best

    def _ext_int_param_names(self, code: str) -> set[str]:
        """定宽整数的外部来源变量名（@RequestParam 形参 / scanf %d / parseInt(request…)）。"""
        names: set[str] = set()
        for m in _EXT_INT_SRC_RE.finditer(code):
            for g in (m.group(1), m.group(2)):
                if g:
                    names.add(g)
        for m in re.finditer(
                r"(\w+)\s*=\s*Integer\.parseInt\s*\(\s*request", code, re.IGNORECASE):
            names.add(m.group(1))
        return names

    def _int_overflow_ext_arith(self, code: str) -> bool:
        """定宽整数声明 ← 外部来源操作数的乘法（溢出候选）。"""
        sources = self._input_var_names(code) | self._ext_int_param_names(code)
        if not sources:
            return False
        for m in re.finditer(
                r"\b(?:int|long|short|double|float|Integer|Long|Double|Float)\s+"
                r"\w+\s*=\s*(\w+)\s*\*\s*(\w+)",
                code, re.IGNORECASE):
            if m.group(1) in sources or m.group(2) in sources:
                return True
        return False

    def _join_flows_to_sink(self, code: str) -> bool:
        """路径构造 API 的结果（含经变量 1 跳传递）流入路径类 sink。

        统一形态（与语言无关）：「父目录 + 不可信片段 → 路径」→ 路径消费 sink

            filepath = os.path.join(base, name); open(filepath, "r")   # Python
            File f = new File(dir, entryName); new FileInputStream(f)  # Java IO
            const p = path.join(base, name); fs.readFileSync(p)        # Node.js

        追踪：① sink 参数区内直接出现路径构造调用 → ② 收集被赋值为路径构造
        结果的变量名，sink 实参引用该变量即命中。
        路径构造 API 由 _PATH_JOIN_PATTERNS 按语言族声明（标准库级事实），
        新增语言只需往表里加一条正则，不改逻辑。
        """
        # ① 直接内嵌形态：open(os.path.join(a, b)) / new FileInputStream(new File(d, n))
        for key in _PATH_SINK_KEYS:
            if key not in _CALL_START_PATTERNS:
                continue
            for literal in _PATH_JOIN_LITERALS:
                if self._call_arg_contains(code, key, token=None, sub=literal):
                    return True
        # ② 变量传递形态：filepath = join(...); open(filepath)
        join_vars: set[str] = set()
        for jp in _PATH_JOIN_PATTERNS:
            for m in re.finditer(r"(\w+)\s*=\s*(?:" + jp.pattern + r")", code):
                join_vars.add(m.group(1))
        if not join_vars:
            return False
        for key in _PATH_SINK_KEYS:
            if key not in _CALL_START_PATTERNS:
                continue
            for m in _CALL_START_PATTERNS[key].finditer(code):
                arg_region = code[m.end(): m.end() + 120]
                if any(re.search(rf"\b{re.escape(v)}\b", arg_region) for v in join_vars):
                    return True
        return False

    def _build_safe_rules(self) -> list[_Rule]:
        """构建安全特征规则集。"""
        IC = re.IGNORECASE
        rules: list[_Rule] = []

        # --- 参数化查询：SQL 字符串含 ?/% 占位符 + execute 带参数元组 ---
        # 组合特征（AND）：占位符特征 + execute(...) 内含逗号（第二参数即参数元组）
        # 能正确区分 "..." % uid（漏洞，% 运算符拼接）与 "...", (uid,)（安全，参数传递）
        rules.append(_Rule(
            name="parameterized_query",
            patterns=[
                re.compile(r"['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^'\"]*[?%][^'\"]*['\"]", IC),
                re.compile(r"\.execute\s*\([^)]*,", IC),
            ],
            require_all=True,
            category="safe",
        ))

        # --- 安全 subprocess：列表参数形式，且不含 shell=True ---
        rules.append(_Rule(
            name="subprocess_list_form",
            patterns=[re.compile(r"subprocess\.(?:run|Popen|call|check_output|check_call)\s*\(\s*\[", IC)],
            exclude=[re.compile(r"shell\s*=\s*True", IC)],
            category="safe",
        ))

        # --- 路径校验：os.path.abspath + .startswith 白名单 ---
        rules.append(_Rule(
            name="path_abspath_startswith",
            patterns=[
                re.compile(r"os\.path\.abspath\s*\(", IC),
                re.compile(r"\.startswith\s*\(", IC),
            ],
            require_all=True,
            category="safe",
        ))

        # --- 路径校验（Java/NIO 形态，2026-08-29 补，工具层优化指导 §五之二待办）---
        # Java 加固的标准写法：getCanonicalPath().startsWith(白名单)（解析符号链接
        # 与 ../ 归一化后再前缀校验）；NIO 等价形态是 toRealPath().startsWith。
        # 与 Python abspath+startswith 同构（结构特征，非语言特判）。
        rules.append(_Rule(
            name="path_canonical_startswith",
            patterns=[
                re.compile(r"getCanonicalPath\s*\(\s*\)\s*\.startsWith\s*\(", IC),
                re.compile(r"getCanonicalFile\s*\(\s*\)\s*\.startsWith\s*\(", IC),
                re.compile(r"toRealPath\s*\(\s*\)\s*\.startsWith\s*\(", IC),
            ],
            category="safe",
        ))

        # --- 安全反序列化：json.loads / yaml.safe_load ---
        rules.append(_Rule(
            name="safe_deserialization",
            patterns=[
                re.compile(r"json\.loads\s*\(", IC),
                re.compile(r"yaml\.safe_load\s*\(", IC),
            ],
            category="safe",
        ))

        # --- 环境变量读取规则已移除 ---
        # 原 env_var 安全规则把"代码含 os.getenv"判为安全，但 os.getenv 的存在
        # 并不证明代码无漏洞（cve_fix_0003 同时含 os.getenv 与 eval 注入，被误判
        # 安全后短路 LLM 放行漏洞）。环境变量读取不足以作为"整体安全"的强特征，
        # 移除后这类样本回落到 None 交 LLM 复核，更稳妥。

        return rules

    def _build_secret_markers(self) -> list[_Rule]:
        """构建"硬编码凭证痕迹"标记规则。

        定位与漏洞规则不同：标记命中 *不* 直接判 True（硬编码凭证的 CWE 归因
        准确率在合成集实测为 0/8，会把 Flask app.secret_key 等误报为 CWE-798），
        而是用于"抑制安全判定"——一旦发现硬编码凭证痕迹，prefilter 不再判安全，
        强制 LLM 复核，防止含漏洞代码被安全规则误判为安全后短路放行
        （如 cve_fix_0018 硬编码凭证漏洞被 parameterized_query 误判安全）。

        修复 \b 词边界 bug：原 \\b 要求关键字前是词边界（\\w 与非 \\w 交界），
        但 DB_PASSWORD、HL7_API_KEY 等下划线前缀的关键字，PASSWORD/API 前是
        下划线（属 \\w），不构成 \\b，导致 cve_fix_0018 等真实硬编码凭证漏匹配。
        改用负向后行断言 (?<![A-Za-z0-9])：仅排除"字母/数字"前缀（避免误匹配
        mypassword 这类变量名），允许下划线/点号/行首前缀正确命中。
        """
        IC = re.IGNORECASE
        return [_Rule(
            name="hardcoded_secret_marker",
            patterns=[re.compile(
                r"(?<![A-Za-z0-9])(?:password|passwd|pwd|api[_-]?key|api[_-]?secret|apikey|"
                r"secret|secret[_-]?key|client[_-]?secret|token|"
                r"access[_-]?token|auth[_-]?token)\s*=\s*['\"][^'\"]{3,}['\"]",
                IC,
            )],
            category="vuln",  # 语义上属漏洞痕迹，但 scan 内不据此判 True
        )]

    # ------------------------------------------------------------------
    # 公共 API
    # ------------------------------------------------------------------
    @staticmethod
    def _hit_line(code: str, rule: "_Rule") -> int:
        """定位规则在代码中的首次命中行号（1-based；0=未能定位）。

        两种定位通道（2026-08-30 补齐）：
          1. line_func：match_func 型规则自带的定位器（如时序比较的比较行），
             精度最高——它知道自己在哪一行命中；
          2. patterns：用每条 pattern 在原代码上 search，取最小匹配偏移换算行号。
        两者都不可用时记 0（与旧行为一致，向下兼容）。
        """
        line_func = getattr(rule, "line_func", None)
        if line_func is not None:
            try:
                ln = int(line_func(code) or 0)
            except Exception:
                ln = 0
            if ln > 0:
                return ln
        best = None
        for pat in getattr(rule, "patterns", None) or []:
            try:
                m = pat.search(code)
            except Exception:
                continue
            if m and (best is None or m.start() < best):
                best = m.start()
        if best is None:
            return 0
        return code.count("\n", 0, best) + 1

    def scan(self, code: str, language: str = "python") -> PrefilterResult:
        """对代码运行全部漏洞 / 安全规则，返回预筛结果。

        Args:
            code: 待分析源代码文本
            language: 语言标签（默认 python）。当前规则面向 Python 调优，
                     其他语言仍会运行同样规则（shell=True / eval / open 等具
                     一定跨语言普适性），属 best-effort。

        Returns:
            PrefilterResult：含初步判定与置信度。preliminary_verdict 为 None
            表示需交 LLM 复核。
        """
        if not code:
            return PrefilterResult(
                has_obvious_vuln=False,
                has_obvious_safe=False,
                has_secret_marker=False,
                matched_rules=[],
                matched_lines=[],
                preliminary_verdict=None,
                confidence="low",
            )

        matched: list[str] = []
        has_vuln = False
        has_safe = False
        has_marker = False
        has_high_conf_vuln = False

        # 长文件护栏：超过阈值行数时不跑安全规则（避免长文件中隐藏漏洞被安全
        # 规则误判放行，如 hard_longfile_01/02 前半段参数化查询掩盖末尾隐藏漏洞）
        is_long = code.count("\n") + 1 > self.longfile_threshold

        # 先跑漏洞规则，再跑安全规则（长文件跳过），最后跑凭证标记
        # （matched_rules 顺序：漏洞在前，安全在中，标记最后）
        lines: list[int] = []
        for rule in self.vuln_rules:
            if rule.match(code):
                has_vuln = True
                matched.append(rule.name)
                lines.append(self._hit_line(code, rule))
                if rule.high_confidence:
                    has_high_conf_vuln = True
        if not is_long:
            for rule in self.safe_rules:
                if rule.match(code):
                    has_safe = True
                    matched.append(rule.name)
                    lines.append(self._hit_line(code, rule))
        for rule in self.secret_markers:
            if rule.match(code):
                has_marker = True
                matched.append(rule.name)

        # 初步判定（优先级：明确漏洞 > 凭证标记抑制安全 > 明确安全 > 交 LLM）
        if has_vuln and (not has_safe or has_high_conf_vuln):
            # 命中漏洞特征且无安全特征 → 判漏洞；
            # 高置信漏洞规则（pickle/yaml 反序列化）即使与安全特征共存也直接判漏洞
            verdict: Optional[bool] = True
        elif has_marker:
            # 有硬编码凭证痕迹 → 不判安全（强制 LLM 复核），无论是否命中安全特征
            verdict = None
        elif has_safe and not has_vuln:
            # 仅命中安全特征（且无凭证痕迹）→ 判安全
            verdict = False
        else:
            # 漏洞与安全都命中（矛盾）或都没命中 → 交 LLM
            verdict = None

        # 置信度：与 verdict 对齐——明确判定为 high，弃权时按特征强度给 medium/low
        if verdict is not None:
            # 明确判定（True 漏洞 / False 安全）→ 高置信
            confidence = "high"
        elif has_vuln and has_safe:
            # 矛盾特征共存（需 LLM 裁决）→ 中置信
            confidence = "medium"
        elif has_marker:
            # 有凭证痕迹抑制了安全判定（交 LLM 复核）→ 中置信
            confidence = "medium"
        else:
            # 无任何强烈特征 → 低置信
            confidence = "low"

        return PrefilterResult(
            has_obvious_vuln=has_vuln,
            has_obvious_safe=has_safe,
            has_secret_marker=has_marker,
            matched_rules=matched,
            matched_lines=lines,
            preliminary_verdict=verdict,
            confidence=confidence,
        )


# ---------------------------------------------------------------------------
# 模块级便捷函数
# ---------------------------------------------------------------------------
_DEFAULT_PREFILTER = Prefilter()


def prefilter_code(code: str, language: str = "python") -> PrefilterResult:
    """便捷函数：用默认 Prefilter 预筛代码。

    等价于 ``Prefilter().scan(code, language)``，但复用单例避免重复构建规则。
    """
    return _DEFAULT_PREFILTER.scan(code, language=language)


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # (标签, 代码, 期望 preliminary_verdict, 期望 confidence)
    cases: list[tuple[str, str, Optional[bool], str]] = [
        # --- 漏洞特征 ---
        ("SQL字符串拼接(漏洞)",
         'cursor.execute("SELECT * FROM users WHERE id = " + uid)',
         True, "high"),
        ("SQL f-string(漏洞)",
         'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
         True, "high"),
        ("SQL %格式化(漏洞)",
         'cursor.execute("SELECT * FROM users WHERE id = %s" % uid)',
         True, "high"),
        ("os.system拼接(漏洞)",
         'os.system("ping " + host)',
         True, "high"),
        ("subprocess shell+拼接(漏洞)",
         'subprocess.run("cat " + filename, shell=True)',
         True, "high"),
        ("eval(request)(漏洞)",
         'result = eval(request.args.get("expr"))',
         True, "high"),
        ("路径拼接open(漏洞)",
         'f = open("/data/" + filename)',
         True, "high"),
        # 2026-08-29 补：os.path.join 形态（变量传递 / 直接内嵌 / 安全对照）
        ("os.path.join→open(漏洞,变量传递)",
         'filepath = os.path.join(base_dir, filename)\nf = open(filepath, "r")',
         True, "high"),
        ("os.path.join→open(漏洞,直接内嵌)",
         'f = open(os.path.join(base_dir, filename), "r")',
         True, "high"),
        # 漏洞规则与安全规则同时命中 → 按既有语义回落"待定交 LLM"
        # （与下方"模糊:参数化+硬编码"用例同款冲突处理，confidence=medium）
        ("os.path.join+前缀校验(冲突→待定,交LLM)",
         'filepath = os.path.join(base_dir, filename)\n'
         'if not os.path.abspath(filepath).startswith(os.path.abspath(base_dir) + os.sep):\n'
         '    raise ValueError\nf = open(filepath, "r")',
         None, "medium"),
        ("硬编码口令(标记→不判漏洞,交LLM)",
         'password = "admin12345"',
         None, "medium"),
        ("DB_PASSWORD下划线前缀(标记,验证词边界修复)",
         'DB_PASSWORD = "s3cr3t_pwd_2024"',
         None, "medium"),
        ("pickle反序列化(漏洞)",
         "data = pickle.loads(request.data)",
         True, "high"),
        ("yaml.load(漏洞)",
         "cfg = yaml.load(stream)",
         True, "high"),
        # --- 2026-08-29 P2 规则族用例 ---
        ("开放重定向(漏洞,变量传递)",
         'target = request.args.get("url", "/")\nreturn redirect(target)',
         True, "high"),
        ("开放重定向(安全,常量)",
         'return redirect("/")\nreturn redirect(url_for("index"))',
         None, "low"),
        ("日志注入(漏洞,f-string内插输入变量)",
         'username = request.args.get("username", "")\n'
         'logger.info(f"Login attempt from user: {username}")',
         True, "high"),
        ("日志注入(漏洞,直接内嵌输入)",
         'log.info("query from: %s", request.args.get("q"))',
         True, "high"),
        ("时序比较(漏洞,token==常量)",
         'token = request.headers.get("X-API-Token", "")\n'
         'if token == SECRET_API_TOKEN:\n    return "ok"',
         True, "high"),
        ("时序比较(不触发,普通字段比较)",
         'username = request.args.get("u")\nif username == "admin":\n    pass',
         None, "low"),
        ("时序比较(不触发,session内CSRF校验)",
         'token = request.form.get("csrf_token", "")\n'
         'if token != session.get("csrf_token"):\n    return "Invalid"',
         None, "low"),
        ("弱哈希md5(漏洞)",
         'digest = hashlib.md5(password.encode()).hexdigest()',
         True, "high"),
        ("ECB模式(漏洞)",
         'cipher = AES.new(key, AES.MODE_ECB)',
         True, "high"),
        ("弱随机(漏洞,token←random.choices)",
         'token = "".join(random.choices(string.ascii_letters + string.digits, k=16))',
         True, "high"),
        ("弱随机(不触发,os.urandom为CSPRNG)",
         'token = secrets.token_hex(32)\nsalt = os.urandom(16)',
         None, "low"),
        ("硬编码IV(漏洞,大写IV后缀常量)",
         'STATIC_IV = b"fixed_iv_value_16"  # 16 bytes for AES',
         True, "high"),
        ("原型污染(漏洞,递归merge+req.body)",
         'function merge(target, src) {\n'
         '    for (const key in src) { target[key] = src[key]; }\n'
         '}\nmerge(userConfig, req.body);',
         True, "high"),
        ("原型污染(漏洞,__proto__直接赋值)",
         'obj["__proto__"] = payload;',
         True, "high"),
        ("整数溢出(漏洞,@RequestParam相乘)",
         '@GetMapping("/calc")\n'
         'public String calc(@RequestParam(defaultValue = "0") int qty,\n'
         '                   @RequestParam(defaultValue = "100") int price) {\n'
         '    int total = price * qty;\n'
         '    return "Total: " + total;\n}',
         True, "high"),
        ("整数溢出(不触发,常量操作数)",
         'int total = PRICE_UNIT * MAX_QTY;',
         None, "low"),

        # --- 安全特征 ---
        ("参数化查询(安全)",
         'cur.execute("SELECT * FROM users WHERE id = ?", (uid,))',
         False, "high"),
        ("列表subprocess(安全)",
         'subprocess.run(["ls", "-l", target])',
         False, "high"),
        ("abspath+startswith(安全)",
         'p = os.path.abspath(user_path)\nif not p.startswith("/safe/"):\n    abort()',
         False, "high"),
        ("Java getCanonicalPath+startsWith(安全,2026-08-29补)",
         'File f = new File(baseDir, fileName);\n'
         'if (!f.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) throw;',
         False, "high"),
        ("json.loads(安全)",
         "data = json.loads(text)",
         False, "high"),
        ("yaml.safe_load(安全)",
         "cfg = yaml.safe_load(stream)",
         False, "high"),
        ("os.environ(env_var规则已移除→交LLM)",
         'api_key = os.environ["API_KEY"]',
         None, "low"),
        ("os.getenv(env_var规则已移除→交LLM)",
         'api_key = os.getenv("API_KEY", "default")',
         None, "low"),

        # --- 模糊 / 无特征 ---
        ("模糊:参数化+硬编码(待定)",
         'cur.execute("SELECT * FROM u WHERE id = ?", (uid,))\npassword = "hardcoded123"',
         None, "medium"),
        ("无害代码(待定)",
         "x = 1 + 2\nprint(x)",
         None, "low"),
    ]

    pf = Prefilter()
    all_pass = True
    for label, code, exp_verdict, exp_conf in cases:
        r = pf.scan(code)
        ok = (r.preliminary_verdict == exp_verdict and r.confidence == exp_conf)
        all_pass = all_pass and ok
        flag = "PASS" if ok else "FAIL"
        print(f"[{flag}] {label}: verdict={r.preliminary_verdict}(期望{exp_verdict}), "
              f"conf={r.confidence}(期望{exp_conf}), rules={r.matched_rules}")

    # 便捷函数一致性检查
    sample = 'cursor.execute("SELECT * FROM t WHERE id = " + uid)'
    r1 = pf.scan(sample)
    r2 = prefilter_code(sample)
    assert r1 == r2, "prefilter_code 与 Prefilter.scan 结果不一致"
    print(f"\n[{'PASS' if r1 == r2 else 'FAIL'}] 便捷函数一致性: {r2}")

    # 元信息完整性（2026-08-29）：每条漏洞规则都必须在 PREFILTER_RULE_INFO 登记，
    # 否则 two_stage_scanner 的 _PREFILTER_TYPE 回落 "Detected"——候选无类型标注、
    # 裁决层拿不到类型提示，且不报错（静默降级）。新规则遗漏登记由本用例拦截。
    missing = [r.name for r in pf.vuln_rules if r.name not in PREFILTER_RULE_INFO]
    ok_meta = not missing
    all_pass = all_pass and ok_meta
    print(f"[{'PASS' if ok_meta else 'FAIL'}] 规则元信息完整性: "
          f"缺失={missing or '无'}（未登记会导致候选类型回落 Detected）")

    # 命中行号（2026-08-30）：match_func 型规则此前只有"命中/未命中"、行号恒 0，
    # 候选无位置 → 裁决层须全文重新定位，审计工具也无法与 expected 行号对齐
    # （DVNA authHandler 的 timing 命中被误判为"无关噪声"实锤）。
    line_cases: list[tuple[str, str, str, int]] = [
        # (标签, 代码, 语言, 期望行号)
        ("时序比较·内联输入源",
         'app.get("/r", function(req, res) {\n'
         '  if (req.query.token == expected_token) { res.send("ok"); }\n'
         '});', "javascript", 2),
        # 最靠前命中：同一文件两处命中时须取行号最小者，否则候选指向靠后的
        # 无关比较（authHandler L71 密码一致性 vs L49 token 比对）
        ("时序比较·取最靠前行",
         'def f(request):\n'
         '    token = request.args.get("token")\n'
         '    b = token == SECRET\n'
         '    c = token == OTHER\n'
         '    return b, c', "python", 3),
        ("会话内令牌比对(安全)",
         'def v(request):\n'
         '    token = request.form.get("token")\n'
         '    if token != session.get("csrf_token"):\n'
         '        return "bad"', "python", 0),
        # 两侧均取自请求 = 注册/改密的确认密码校验：比较的是用户自己提交的两个
        # 值，不与服务端秘密比较，响应差异不泄露秘密（DVNA appHandler L152 /
        # passport L64 实锤——两者此前被判为无关噪声）。右侧须为请求容器取值：
        # `req.body.token == md5(req.body.login)` 的右侧是服务端计算值，须保留。
        ("两侧皆请求的字段一致性校验(安全)",
         'app.post("/r", function(req, res) {\n'
         '  if (req.body.password == req.body.cpassword) { res.send("ok"); }\n'
         '});', "javascript", 0),
        ("右侧为服务端计算值(须保留)",
         'app.post("/r", function(req, res) {\n'
         '  if (req.body.token == md5(req.body.login)) { res.send("ok"); }\n'
         '});', "javascript", 2),
    ]

    # 2026-08-31 新增 4 条规则的召回/误报用例（VFlask 审计暴露的真盲区）。
    # 每条规则都配"负样本"：证明规则抓的是漏洞形态而非"文件里恰好有这些 API"。
    _NEW_RULES_CASES: list[tuple[str, str, str, list[tuple[str, int]]]] = [
        # (标签, 代码, 语言, 期望 [(规则名, 行号)])
        ("JWT·关闭签名校验",
         'def insecure_verify():\n'
         '    token = request.headers.get("Authorization")\n'
         '    return jwt.decode(token, verify=False)\n', "python",
         [("jwt_verify_disabled", 3)]),
        ("JWT·options 字典形态关闭校验",
         'def f(request):\n'
         '    return jwt.decode(request.args.get("t"), '
         'options={"verify_signature": False})\n', "python",
         [("jwt_verify_disabled", 2)]),
        ("JWT·正常校验(安全)",
         'def f(request):\n'
         '    return jwt.decode(request.args.get("t"), KEY, algorithms=["HS256"])\n',
         "python", []),
        ("异常详情·返回客户端",
         'def f(request):\n'
         '    try:\n'
         '        db.query(request.args.get("q"))\n'
         '    except Exception as e:\n'
         '        return jsonify({"Error": str(e.message)}), 404\n', "python",
         [("error_info_exposure", 5)]),
        ("异常详情·只记日志(安全)",
         'def f(request):\n'
         '    try:\n'
         '        db.query(request.args.get("q"))\n'
         '    except Exception as e:\n'
         '        logging.error("failed: %s", str(e))\n'
         '        return jsonify({"Error": "internal"}), 500\n', "python", []),
        ("敏感字段明文入库",
         'def reg(request):\n'
         '    content = request.json\n'
         '    ccn = content["ccn"]\n'
         '    cust = Customer(ccn)\n'
         '    db.session.add(cust)\n', "python",
         [("cleartext_sensitive_storage", 3)]),
        ("普通表单入库(安全)",
         'def reg(request):\n'
         '    name = request.form.get("name")\n'
         '    u = User(name)\n'
         '    db.session.add(u)\n', "python", []),
        ("文件上传·无类型校验",
         'def up(request):\n'
         '    f = request.files["file"]\n'
         '    f.save(os.path.join(UP, secure_filename(f.filename)))\n', "python",
         [("unrestricted_file_upload", 2)]),
        ("文件上传·有白名单(安全)",
         'def up(request):\n'
         '    f = request.files["file"]\n'
         '    if not allowed_file(f.filename):\n'
         '        return "bad"\n'
         '    f.save(os.path.join(UP, f.filename))\n', "python", []),
    ]
    for label, code, lang, expect in _NEW_RULES_CASES:
        rr = pf.scan(code, lang)
        got = sorted(
            (n, ln) for n, ln in zip(rr.matched_rules, rr.matched_lines)
            if n in {"jwt_verify_disabled", "error_info_exposure",
                     "cleartext_sensitive_storage", "unrestricted_file_upload"})
        ok_case = got == sorted(expect)
        all_pass = all_pass and ok_case
        print(f"[{'PASS' if ok_case else 'FAIL'}] 新规则·{label}: {got} (期望 {sorted(expect)})")
    for label, code, lang, exp_line in line_cases:
        rr = pf.scan(code, lang)
        got = rr.matched_lines[rr.matched_rules.index("timing_unsafe_compare")] \
            if "timing_unsafe_compare" in rr.matched_rules else 0
        ok_line = got == exp_line
        all_pass = all_pass and ok_line
        print(f"[{'PASS' if ok_line else 'FAIL'}] 命中行号·{label}: 行号={got} "
              f"(期望 {exp_line})")

    print("\n=== 全部通过 ===" if all_pass and r1 == r2 else "\n=== 存在失败用例 ===")
