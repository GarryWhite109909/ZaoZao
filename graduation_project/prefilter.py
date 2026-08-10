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


# 需要做"配对括号内查找"的调用起点正则（各规则复用，避免重复编译）
_CALL_START_PATTERNS = {
    "open": re.compile(r"open\s*\(", re.IGNORECASE),
    "os_system": re.compile(r"os\.system\s*\(", re.IGNORECASE),
    "subprocess": re.compile(
        r"subprocess\.(?:run|Popen|call|check_output|check_call)\s*\(", re.IGNORECASE),
}


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
    def _call_arg_contains(self, code: str, pattern_key: str, token: str = "+") -> bool:
        """定位调用起点后扫描到配对右括号，判断参数区内（含嵌套）是否出现 token。

        替代 `[^)]*` 正则：嵌套括号（如 open(os.path.join(d, n) + s)）不会再提前终止。
        跳过字符串字面量内容，open("a+b") 不会误命中。
        """
        for m in _CALL_START_PATTERNS[pattern_key].finditer(code):
            # 正则已消费左括号，从参数区起点直接以 depth=1 扫描
            depth = 1
            in_str: Optional[str] = None
            escaped = False
            j = m.end()
            while j < len(code):
                ch = code[j]
                if in_str is not None:
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
                elif depth >= 1 and ch == token:
                    return True
                j += 1
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

        return rules

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
        for rule in self.vuln_rules:
            if rule.match(code):
                has_vuln = True
                matched.append(rule.name)
                if rule.high_confidence:
                    has_high_conf_vuln = True
        if not is_long:
            for rule in self.safe_rules:
                if rule.match(code):
                    has_safe = True
                    matched.append(rule.name)
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

    print("\n=== 全部通过 ===" if all_pass and r1 == r2 else "\n=== 存在失败用例 ===")
