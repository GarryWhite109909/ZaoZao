"""轻量级污点分析模块 —— 基于 tree-sitter 的线性 def-use 传播（单文件内过程间摘要）。

策略（v2，从"共现启发式"升级为"线性数据流"）：
- 按语句顺序扫描函数体：source 赋值给变量 v → v 入污染集；
  赋值右值含污染变量 → 左值入集（覆盖拼接 / f-string / % / format）；
  **只有 sink 调用的参数里出现污染变量（或直接出现 source 表达式）才报路径**，
  不再做 source×sink 笛卡尔积共现配对。
- 消毒识别：int()/escape()/quote() 等包裹、SQL 参数化（第二参数为元组/列表/字典
  或首参含占位符）→ 该条流标记 sanitized 且默认不输出（消除参数化查询误报）。
- 单文件过程间摘要（两遍法）：第一遍生成"参数→sink / source→return"摘要，
  第二遍在调用点拼接，覆盖 f() 传污点给 g()、sink 在 g() 内的场景。
- 路径附带传播链与行号，供 LLM 裁决层使用。

局限性（轻量静态分析，非定论）：
- 不做跨文件/路径敏感分析、不做别名分析；循环体按一次顺序处理（保守）；
- 字符串字面量内偶然匹配可能产生少量误报。

支持语言：python / javascript / js / typescript / ts / java / php。
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Optional

import tree_sitter_python as tspython
import tree_sitter_javascript as tsjs
import tree_sitter_java as tsjava
import tree_sitter_php as tsphp
import tree_sitter_typescript as tsts
from tree_sitter import Language, Node, Parser


# ---------------------------------------------------------------------------
# tree-sitter 语言对象注册表（与 code_slicer.py 保持一致，tree-sitter 0.25+ API）
# ---------------------------------------------------------------------------
_TS_LANGUAGE_OBJECTS = {
    "python": Language(tspython.language()),
    "javascript": Language(tsjs.language()),
    "java": Language(tsjava.language()),
    "php": Language(tsphp.language_php()),
    "typescript": Language(tsts.language_typescript()),
}

_LANGUAGE_MAP = {
    "python": "python", "py": "python",
    "javascript": "javascript", "js": "javascript",
    "typescript": "typescript", "ts": "typescript",
    "java": "java",
    "php": "php",
}

# 函数/方法定义节点 type（PHP 的 creation_expression 是 new 表达式，不是函数定义）
_FUNCTION_NODE_TYPES = {
    "python": {"function_definition"},
    "javascript": {"function_declaration", "method_definition", "function_expression", "arrow_function"},
    "typescript": {"function_declaration", "method_definition", "function_expression", "arrow_function"},
    "java": {"method_declaration", "constructor_declaration"},
    "php": {"function_definition", "method_declaration"},
}

_CLASS_NODE_TYPES = {"class_declaration", "class_definition"}

# 候选节点 type：调用 / 属性访问 / 下标
_CALL_NODE_TYPES = {
    "call", "call_expression", "method_invocation",
    "function_call_expression", "method_call_expression",
    "object_creation_expression",
}
_MEMBER_NODE_TYPES = {
    "attribute", "member_expression", "field_access", "member_access_expression",
}
_SUBSCRIPT_NODE_TYPES = {
    "subscript", "subscript_expression", "array_access_expression", "index_access_expression",
}

_ARGUMENT_LIST_TYPES = {"argument_list", "arguments"}

# 语句体节点（复合语句的子块）
_BODY_TYPES = {"block", "statement_block", "compound_statement", "declaration_list"}

# 单作用域最多输出路径数
_MAX_PATHS_PER_SCOPE = 50


# ---------------------------------------------------------------------------
# Source 模式（按语言）—— 用户可控输入点
# ---------------------------------------------------------------------------
_SOURCE_PATTERNS: dict[str, list[str]] = {
    "python": [
        "request.args.get(", "request.form", "request.json", "request.data",
        "request.get_data(", "request.get_json(", "request.GET", "request.POST",
        "request.headers", "request.COOKIES", "request.META", "request.files",
        "input(", "sys.argv", "os.environ", "os.getenv(", "sys.stdin",
    ],
    "javascript": [
        "req.query", "req.body", "req.params", "process.argv", "process.env",
        "location.hash", "document.URL", "document.referrer",
        "location.search", "window.name", "event.data",
    ],
    "typescript": [
        "req.query", "req.body", "req.params", "process.argv", "process.env",
        "location.hash", "document.URL", "document.referrer",
        "location.search", "window.name", "event.data",
    ],
    "java": [
        "request.getParameter", "request.getAttribute", "request.getHeader",
        "System.getenv(", "args[",
    ],
    "php": [
        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES",
    ],
}


# ---------------------------------------------------------------------------
# Sink 模式（危险函数/方法）—— (pattern, taint_type)
# ---------------------------------------------------------------------------
_SINK_DEFINITIONS: list[tuple[str, str]] = [
    # SQL 注入
    (".execute(", "SQL Injection"),
    ("executeQuery(", "SQL Injection"),
    ("executeUpdate(", "SQL Injection"),
    ("cursor.execute", "SQL Injection"),
    # 命令注入（Java 的 Runtime.exec / Node child_process.exec / Python 的 os.popen 等）
    # 2026-08-18 修正：原裸 ".exec(" 会命中 JS 的 RegExp.exec(pattern)（正则匹配不是
    # 命令执行）→ 伪命令注入路径。收紧为具体的命令执行形态。
    ("Runtime.getRuntime().exec(", "Command Injection"),
    ("child_process.exec(", "Command Injection"),
    ("os.system(", "Command Injection"),
    ("system(", "Command Injection"),
    ("os.popen(", "Command Injection"),
    ("subprocess.run(", "Command Injection"),
    ("subprocess.Popen(", "Command Injection"),
    ("ProcessBuilder", "Command Injection"),
    # 代码注入
    ("exec(", "Code Injection"),
    ("eval(", "Code Injection"),
    # 路径穿越
    ("open(", "Path Traversal"),
    # 任意文件上传 / 解压路径穿越（CWE-434 / CWE-22）：
    # - .save(  = 文件写入落盘方法（Flask FileStorage 的 file.save 等），参数含
    #   request.files 派生的污点才构成路径——靠 taint 门（污染变量必须在 sink 参数）
    #   区分真上传漏洞与 np.save/torch.save/model.save 等安全 API（2026-08-17 实证：
    #   np.save 常量参数走真实链路 0 路径）。不能用窄匹配 file.save(——会漏
    #   f.save/tgt.save 等任意变量名调用。
    # - extractall( = tarfile/zipfile 解压入口（CVE-2025-4517 类，CWE-22）
    (".save(", "Path Traversal"),
    ("extractall(", "Path Traversal"),
    # 反序列化
    ("pickle.loads(", "Insecure Deserialization"),
    ("yaml.load(", "Insecure Deserialization"),
    # XSS（2026-08-18 补：insertAdjacentHTML/outerHTML/dangerouslySetInnerHTML 为
    # 通用 JS/React HTML 注入形态；innerText/outerText 是纯文本赋值不算 sink）
    ("innerHTML", "XSS"),
    ("document.write(", "XSS"),
    ("insertAdjacentHTML", "XSS"),
    ("outerHTML", "XSS"),
    ("dangerouslySetInnerHTML", "XSS"),
    # 模板注入（2026-08-18 补：render_template_string 是 Flask/Jinja2 最直接的
    # 模板字符串渲染入口，此前漏召回）
    (".from_string(", "Server-Side Template Injection"),  # 模板来源含污点（env.from_string(用户串)）
    ("render_template_string(", "Server-Side Template Injection"),
    ("render(", "Server-Side Template Injection"),
    ("render_template(", "Server-Side Template Injection"),
]

_SINK_TAINT_TYPE: dict[str, str] = {pat: ttype for pat, ttype in _SINK_DEFINITIONS}
_SINK_PATTERNS: list[str] = [pat for pat, _ in _SINK_DEFINITIONS]

# sink 类型语言覆盖（2026-08-18）：同一调用名在不同语言生态语义不同——
# JS/TS 中裸 exec() 来自 child_process 解构导入（Node 子进程执行；浏览器无 exec
# 全局函数，RegExp.exec 是带点方法调用，裸 "exec(" 模式不会命中它）→ 命令注入；
# Python 的 exec() 是代码执行，保持 Code Injection。typical_10_cmd_js 实测归因。
_SINK_TYPE_LANG_OVERRIDE: dict[str, dict[str, str]] = {
    "javascript": {"exec(": "Command Injection"},
    "typescript": {"exec(": "Command Injection"},
}

# sink 危险度（用于截断时保留高危路径）
_SINK_RANK: dict[str, int] = {
    "Command Injection": 4,
    "Code Injection": 4,
    "Insecure Deserialization": 4,
    "SQL Injection": 3,
    "Server-Side Template Injection": 3,
    "XSS": 2,
    "Path Traversal": 2,
}

# 消毒函数（包裹污点变量后视为已消毒）。注意：
# - 参数允许一层嵌套括号（如 int(request.args.get("id"))），配合迭代剥离可处理多层
# - str 不在列表中：str() 只做字符串化，对 SQL/命令注入无消毒作用
# - 2026-08-18 修正：原全局列表含 escape/quote/html.escape/urllib.quote/re.escape 等
#   **只对特定漏洞类型有效**的消毒函数——`"SELECT ... " + html.escape(user)` 的 SQL
#   路径被误判"已消毒"丢弃（跨类型漏报）；且 `escape(` 会匹配 `unescape(`（HTML 解码
#   = 反防御）。现只保留类型无关的数值强制转换（int/float/bool 对 SQL/代码/路径的
#   数值插值有效）+ shlex.quote（命令注入专用，误用场景罕见）。HTML/URL 编码类消毒
#   交由 LLM 裁决层判断（生成为候选，不静默丢弃）。
_SANITIZER_CALL_RE = re.compile(
    r"(?:int|float|bool|shlex\.quote|intval|filter_var)"
    r"\s*\((?:[^()]|\([^()]*\))*\)",
    re.IGNORECASE,
)

# SQL 参数化占位符（? / %s / %d / :name / $1）
_PARAM_PLACEHOLDER_RE = re.compile(
    r"['\"][^'\"]*(?:\?|%[sdifr]|:\w+|\$\d+)[^'\"]*['\"]",
    re.IGNORECASE,
)


def _core(pattern: str) -> str:
    """去掉 pattern 末尾的 '(' 或 '['，得到用于匹配的核心串。"""
    p = pattern
    while p and p[-1] in "([":
        p = p[:-1]
    return p


def _compile(patterns: list[str]) -> list[tuple[str, str, "re.Pattern[str]"]]:
    """编译模式列表，返回 (原 pattern, core, regex) 三元组，按 core 长度降序。"""
    out: list[tuple[str, str, "re.Pattern[str]"]] = []
    for p in patterns:
        c = _core(p)
        if c.startswith("."):
            regex = re.compile(re.escape(c))
        else:
            regex = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(c))
        out.append((p, c, regex))
    out.sort(key=lambda x: -len(x[1]))
    return out


@dataclass
class TaintPath:
    """单条 source→sink 污点路径。"""
    source: str
    sink: str
    taint_type: str
    source_line: int  # 1-indexed
    sink_line: int    # 1-indexed
    propagation: list[str] = field(default_factory=list)  # 变量传播链（source 赋值 → ... → sink 参数）
    sanitized: bool = False  # 已消毒/参数化（默认不输出，保留字段供裁决层使用）


@dataclass
class FunctionSummary:
    """单函数摘要（两遍法第一遍产物）。"""
    name: str
    param_order: list[str] = field(default_factory=list)
    # param_name -> [(sink_label, sink_line, taint_type)]
    param_sinks: dict[str, list[tuple[str, int, str]]] = field(default_factory=dict)
    # (origin_label, origin_line) —— source 污点流入 return
    returns_taint: list[tuple[str, int]] = field(default_factory=list)


@dataclass
class _Taint:
    """单个污染变量的来源信息。"""
    origin: str
    origin_line: int
    chain: list[str]  # 传播链：source 赋值变量 → ... → 当前变量
    sanitized: bool = False


@dataclass
class _ScopeResult:
    paths: list[TaintPath] = field(default_factory=list)
    returns_taint: list[tuple[str, int]] = field(default_factory=list)


class TaintTracker:
    """轻量级污点追踪器（线性 def-use 传播 + 单文件过程间摘要）。"""

    def __init__(self) -> None:
        self._source_cache: dict[str, list[tuple[str, str, "re.Pattern[str]"]]] = {}
        self._sink_compiled: list[tuple[str, str, "re.Pattern[str]"]] = _compile(_SINK_PATTERNS)
        # Parser 按线程缓存，避免每次 trace 重建（tree-sitter Parser 非线程安全）
        self._local = threading.local()

    def _sources_for(self, ts_lang: str) -> list[tuple[str, str, "re.Pattern[str]"]]:
        if ts_lang not in self._source_cache:
            self._source_cache[ts_lang] = _compile(_SOURCE_PATTERNS.get(ts_lang, []))
        return self._source_cache[ts_lang]

    def _parser_for(self, ts_lang: str) -> Parser:
        if not hasattr(self._local, "parsers"):
            self._local.parsers = {}
        if ts_lang not in self._local.parsers:
            self._local.parsers[ts_lang] = Parser(_TS_LANGUAGE_OBJECTS[ts_lang])
        return self._local.parsers[ts_lang]

    # ------------------------------------------------------------------
    # 公共 API
    # ------------------------------------------------------------------
    def trace(self, code: str, language: str = "python", filename: str = "") -> list[TaintPath]:
        """分析代码，返回 source→sink 污点路径列表（含传播链，不含已消毒流）。

        Args:
            code: 源代码文本
            language: 项目内语言标签（python/js/ts/java/php 等）
            filename: 文件名（仅用于上下文，不参与分析）

        Returns:
            TaintPath 列表；解析失败或不支持的语言返回空列表
        """
        ts_lang = _LANGUAGE_MAP.get((language or "").lower())
        if not ts_lang or not code:
            return []

        try:
            code_bytes = code.encode("utf-8")
            tree = self._parser_for(ts_lang).parse(code_bytes)
        except Exception:
            return []

        root = tree.root_node
        scopes: list[tuple[Node, str]] = self._collect_function_scopes(root, ts_lang)
        if not scopes:
            scopes = [(root, "<module>")]

        # 第一遍：为每个函数生成摘要（参数种子 + return 污点）
        summaries: dict[str, FunctionSummary] = {}
        for func_node, qual in scopes:
            result = self._analyze_scope(
                func_node, code_bytes, ts_lang,
                seed_params=True, summaries={},
            )
            summaries[qual] = self._build_summary(qual, func_node, result)

        # 第二遍：正式分析（真实 sources + 调用点拼接摘要）
        paths: list[TaintPath] = []
        for func_node, qual in scopes:
            result = self._analyze_scope(
                func_node, code_bytes, ts_lang,
                seed_params=False, summaries=summaries,
            )
            paths.extend(result.paths)

        # 去重（同一 (source, sink, 行, 链) 只保留一条）
        seen: set[tuple] = set()
        dedup: list[TaintPath] = []
        for p in paths:
            key = (p.source, p.sink, p.source_line, p.sink_line, tuple(p.propagation))
            if key not in seen:
                seen.add(key)
                dedup.append(p)
        return dedup

    # ------------------------------------------------------------------
    # 作用域收集
    # ------------------------------------------------------------------
    def _collect_function_scopes(self, root: Node, ts_lang: str) -> list[tuple[Node, str]]:
        """递归收集顶层函数 + 类方法节点（不深入函数体内部的嵌套函数）。"""
        func_types = _FUNCTION_NODE_TYPES.get(ts_lang, set())
        class_types = _CLASS_NODE_TYPES
        result: list[tuple[Node, str]] = []

        def walk(node: Node, class_name: Optional[str] = None) -> None:
            for child in node.children:
                if child.type in class_types:
                    cls_name = self._node_name(child) or "AnonymousClass"
                    walk(child, cls_name)
                elif child.type in func_types:
                    fn_name = self._node_name(child) or "anonymous"
                    qual = f"{class_name}.{fn_name}" if class_name else fn_name
                    result.append((child, qual))
                else:
                    walk(child, class_name)

        walk(root)
        return result

    def _node_name(self, node: Node) -> Optional[str]:
        """从函数/类定义节点提取名字（第一个 identifier 子节点）。"""
        for child in node.children:
            if child.type in ("identifier", "property_identifier", "type_identifier"):
                return child.text.decode("utf-8")
            if child.type == "name":
                for cc in child.children:
                    if cc.type == "identifier":
                        return cc.text.decode("utf-8")
        return None

    # ------------------------------------------------------------------
    # 作用域分析（线性 def-use 传播）
    # ------------------------------------------------------------------
    def _analyze_scope(
        self,
        func_node: Node,
        code_bytes: bytes,
        ts_lang: str,
        seed_params: bool,
        summaries: dict[str, FunctionSummary],
    ) -> _ScopeResult:
        """分析单个作用域：按语句顺序做 def-use 传播，返回路径与 return 污点。"""
        source_compiled = self._sources_for(ts_lang)
        tainted: dict[str, _Taint] = {}
        paths: list[TaintPath] = []
        returns: list[tuple[str, int]] = []

        func_start_line = func_node.start_point[0] + 1
        if seed_params:
            for name in self._function_param_names(func_node):
                tainted[name] = _Taint(f"param:{name}", func_start_line, [name])
        else:
            # 路由/Spring 注解参数视为 source 种子
            for name, line in self._param_sources(func_node, ts_lang, code_bytes):
                tainted[name] = _Taint(f"param:{name}", line, [name])

        is_module = func_node.type not in _FUNCTION_NODE_TYPES.get(ts_lang, set())
        for stmt in self._iter_statements(func_node, ts_lang, skip_nested=is_module):
            stmt_line = stmt.start_point[0] + 1
            stmt_text = self._node_text(stmt, code_bytes)

            # 1) 赋值 def-use：source 赋值 / 污染变量传播 / 消毒识别
            for target, rhs in self._assignment_info(stmt, ts_lang, code_bytes):
                if not target:
                    continue
                rhs_clean = self._strip_string_literals(rhs)
                src = self._match(rhs_clean, source_compiled)
                if src:
                    # 消毒函数包裹的 source（如 int(request.args.get(...))）视为已消毒：
                    # 剥掉消毒调用后 source 不再裸匹配才算消毒成功
                    is_san = self._match(self._strip_sanitizer_calls(rhs_clean), source_compiled) is None
                    tainted[target] = _Taint(src, stmt_line, [target], sanitized=is_san)
                    continue
                hits = self._tainted_in_text(rhs_clean, tainted)
                if hits:
                    # 优先未消毒来源
                    best = next((h for h in hits if not h.sanitized), hits[0])
                    sanitized = best.sanitized or self._sanitizer_removes_taint(rhs_clean, [v for v in tainted])
                    tainted[target] = _Taint(
                        best.origin, best.origin_line,
                        best.chain + [target], sanitized=sanitized,
                    )

            # 2) 本语句内 sink：参数含污染变量 / 直接含 source 表达式
            sinks: list[tuple[str, list[str], str]] = []  # (label, args, arg_joined)
            for sink_node in self._sink_nodes_in(stmt, code_bytes, ts_lang):
                head = self._head_text(sink_node, code_bytes)
                label = self._match(head, self._sink_compiled)
                if not label:
                    continue
                args = self._argument_texts(sink_node, code_bytes)
                if args:
                    arg_joined = " ".join(args)
                else:
                    # 成员型 sink（如 el.innerHTML = q）：污点来自整条语句（赋值右值）
                    arg_joined = stmt_text
                sinks.append((label, args, arg_joined))
            if not sinks:
                # 文本兜底：ProcessBuilder 等非调用节点型 sink
                label = self._match(stmt_text, self._sink_compiled)
                if label:
                    sinks.append((label, [stmt_text], stmt_text))

            for label, args, arg_joined in sinks:
                ttype = (_SINK_TYPE_LANG_OVERRIDE.get(ts_lang, {}).get(label)
                         or _SINK_TAINT_TYPE.get(label, "Unknown"))
                arg_clean = self._strip_string_literals(arg_joined)

                # 直接 source 表达式出现在参数里（同语句流）；消毒包裹的不报
                direct = self._match(arg_clean, source_compiled)
                if direct:
                    if self._match(self._strip_sanitizer_calls(arg_clean), source_compiled) is not None:
                        paths.append(TaintPath(direct, label, ttype, stmt_line, stmt_line))
                    continue

                for var, t in list(tainted.items()):
                    if t.sanitized or not self._var_in_text(arg_clean, var):
                        continue
                    if self._is_parameterized_sql(label, ttype, args, var, arg_clean):
                        continue  # 参数化查询：数据在绑定参数里，不报
                    if self._context_safe_sink(label, ttype, args, var, code_bytes):
                        continue  # 语境安全：列表参数 subprocess / 模板值插值 / autoescape
                    paths.append(TaintPath(
                        t.origin, label, ttype,
                        t.origin_line, stmt_line,
                        propagation=t.chain,
                    ))

            # 3) 过程间摘要拼接（调用已知函数）
            for call_node in self._call_nodes_in(stmt, ts_lang):
                head = self._head_text(call_node, code_bytes)
                callee = self._callee_name(head)
                summary = summaries.get(callee) or summaries.get(head)
                if summary is None:
                    continue
                args = self._argument_texts(call_node, code_bytes)
                arg_joined = " ".join(args)

                # 3a) 污点参数 → 被调函数内 param → sink
                for idx, arg_text in enumerate(args):
                    if idx >= len(summary.param_order):
                        break
                    param = summary.param_order[idx]
                    sinks = summary.param_sinks.get(param)
                    if not sinks:
                        continue
                    # 该参数直接是 source 表达式
                    direct = self._match(arg_text, source_compiled)
                    if direct:
                        for (sk_label, sk_line, sk_type) in sinks:
                            paths.append(TaintPath(
                                direct, f"{callee}::{sk_label}", sk_type,
                                stmt_line, sk_line, propagation=[callee],
                            ))
                        continue
                    for var, t in list(tainted.items()):
                        if t.sanitized or not self._var_in_text(arg_text, var):
                            continue
                        for (sk_label, sk_line, sk_type) in sinks:
                            paths.append(TaintPath(
                                t.origin, f"{callee}::{sk_label}", sk_type,
                                t.origin_line, sk_line,
                                propagation=t.chain + [callee],
                            ))

                # 3b) 被调函数返回污点 → 赋值目标入污染集
                targets = self._assignment_targets(stmt, ts_lang, code_bytes) if summary.returns_taint else []
                if targets:
                    ret_origin, ret_line = summary.returns_taint[0]
                    for target in targets:
                        tainted[target] = _Taint(ret_origin, ret_line, [target])

            # 4) return 污点（供上层摘要）
            if stmt.type in ("return_statement",):
                ret_clean = self._strip_string_literals(stmt_text)
                direct_src = self._match(ret_clean, source_compiled)
                if direct_src:
                    # 直接返回 source 表达式（无中间变量）
                    returns.append((direct_src, stmt_line))
                else:
                    for var, t in tainted.items():
                        if self._var_in_text(ret_clean, var):
                            returns.append((t.origin, t.origin_line))
                            break

        # 按 sink 危险度排序后截断（保留高危路径）
        paths.sort(key=lambda p: (-_SINK_RANK.get(p.taint_type, 0), p.sink_line, p.source_line))
        paths = paths[:_MAX_PATHS_PER_SCOPE]
        return _ScopeResult(paths=paths, returns_taint=returns)

    # ------------------------------------------------------------------
    # 语句遍历 / 赋值解析
    # ------------------------------------------------------------------
    def _iter_statements(self, node: Node, ts_lang: str, skip_nested: bool):
        """按源码顺序产出语句节点；复合语句递归进入子块。"""
        func_types = _FUNCTION_NODE_TYPES.get(ts_lang, set())
        class_types = _CLASS_NODE_TYPES

        def walk(cur: Node) -> None:
            for child in cur.children:
                if skip_nested and (child.type in func_types or child.type in class_types):
                    continue
                if child.type in _BODY_TYPES:
                    yield from walk(child)
                elif self._is_stmt_node(child):
                    yield child
                    for sub in child.children:
                        if sub.type in _BODY_TYPES:
                            yield from walk(sub)

        yield from walk(node)

    def _is_stmt_node(self, node: Node) -> bool:
        t = node.type
        if t.endswith("statement"):
            return True
        return t in (
            "assignment", "augmented_assignment", "named_expression",
            "local_variable_declaration", "field_declaration",
            "variable_declaration", "lexical_declaration",
            "declaration", "return_statement", "throw_statement",
        )

    def _assignment_info(self, stmt: Node, ts_lang: str, code_bytes: bytes) -> list[tuple[str, str]]:
        """提取语句中的赋值 (目标变量, 右值文本)。支持多目标。"""
        t = stmt.type
        out: list[tuple[str, str]] = []

        # Python 的语句通常是 expression_statement 包裹 assignment
        if t == "expression_statement":
            for c in stmt.children:
                if c.type in (
                    "assignment", "augmented_assignment", "named_expression",
                    "assignment_expression", "call", "yield",
                ):
                    if c.type == "call":
                        break
                    return self._assignment_info(c, ts_lang, code_bytes)
            # 无赋值子节点：文本兜底（排除字符串字面量内的匹配与 ==/<=/>=/!=/=>）
            text = self._node_text(stmt, code_bytes)
            text_clean = self._strip_string_literals(text)
            m = re.search(r"(?<![=!<>])([A-Za-z_$][\w$]*)\s*=(?!=)", text_clean)
            if m:
                rhs = text_clean[m.end():].strip().rstrip(";")
                return [(m.group(1), rhs)]
            return []

        if t in ("assignment", "augmented_assignment"):
            children = stmt.children
            eq_idx = [i for i, c in enumerate(children) if c.type == "="]
            if not eq_idx:
                return []
            last_eq = eq_idx[-1]
            targets = [
                self._node_text(c, code_bytes)
                for c in children[:last_eq]
                if c.type in ("identifier", "attribute", "subscript", "member_expression")
            ]
            rhs = self._node_text(children[last_eq + 1], code_bytes) if last_eq + 1 < len(children) else ""
            return [(tg, rhs) for tg in targets]

        if t == "named_expression":  # Python walrus: (name := value)
            name = next((c for c in stmt.children if c.type == "identifier"), None)
            if name is not None:
                text = self._node_text(stmt, code_bytes)
                rhs = text.split(":=", 1)[1].strip() if ":=" in text else ""
                return [(name.text.decode("utf-8", errors="replace"), rhs)]
            return []

        if t in ("lexical_declaration", "variable_declaration"):
            for c in stmt.children:
                if c.type in ("variable_declarator", "variable_declaration"):
                    name = next((x for x in c.children if x.type in ("identifier", "member_expression", "property_identifier")), None)
                    eq_idx = next((i for i, x in enumerate(c.children) if x.type == "="), None)
                    if name is not None and eq_idx is not None and eq_idx + 1 < len(c.children):
                        out.append((
                            self._node_text(name, code_bytes),
                            self._node_text(c.children[eq_idx + 1], code_bytes),
                        ))
            return out

        if t == "assignment_expression":  # JS/TS/Java/PHP
            non_ops = [c for c in stmt.children if c.type not in ("=", "=>", ";")]
            if len(non_ops) >= 2:
                lhs = self._node_text(non_ops[0], code_bytes)
                rhs = self._node_text(non_ops[1], code_bytes)
                if lhs and rhs:
                    return [(lhs, rhs)]
            return []

        if t in ("local_variable_declaration", "field_declaration"):
            for c in stmt.children:
                if c.type == "variable_declarator":
                    name = next((x for x in c.children if x.type == "identifier"), None)
                    eq_idx = next((i for i, x in enumerate(c.children) if x.type == "="), None)
                    if name is not None and eq_idx is not None and eq_idx + 1 < len(c.children):
                        out.append((
                            self._node_text(name, code_bytes),
                            self._node_text(c.children[eq_idx + 1], code_bytes),
                        ))
            return out

        return out

    def _assignment_targets(self, stmt: Node, ts_lang: str, code_bytes: bytes) -> list[str]:
        return [tg for tg, _ in self._assignment_info(stmt, ts_lang, code_bytes)]

    # ------------------------------------------------------------------
    # 节点/文本工具
    # ------------------------------------------------------------------
    def _node_text(self, node: Node, code_bytes: bytes) -> str:
        try:
            return code_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _iter_descendants(self, node: Node):
        """遍历所有后代节点，跳过字符串/注释；f-string 的 interpolation 不跳过。"""
        for child in node.children:
            t = child.type
            if "comment" in t:
                continue
            if "string" in t:
                # f-string：interpolation 子节点是表达式，不能整体跳过
                for sub in child.children:
                    if sub.type == "interpolation":
                        yield sub
                        yield from self._iter_descendants(sub)
                continue
            yield child
            yield from self._iter_descendants(child)

    def _head_text(self, node: Node, code_bytes: bytes) -> str:
        """提取候选节点的"头部文本"用于模式匹配（调用节点取参数列表之前的文本）。"""
        if node.type in _CALL_NODE_TYPES:
            for c in node.children:
                if c.type in _ARGUMENT_LIST_TYPES:
                    return self._node_text(node, code_bytes)[:c.start_byte - node.start_byte].strip()
            return self._node_text(node, code_bytes).strip()

        text = self._node_text(node, code_bytes)
        if node.type in _SUBSCRIPT_NODE_TYPES:
            idx = text.find("[")
            if idx != -1:
                return text[:idx].rstrip()
        return text

    def _argument_texts(self, node: Node, code_bytes: bytes) -> list[str]:
        """提取调用节点的参数文本列表（去除逗号）。"""
        for c in node.children:
            if c.type in _ARGUMENT_LIST_TYPES:
                out: list[str] = []
                for arg in c.children:
                    if arg.type in (",", "(", ")"):
                        continue
                    text = self._node_text(arg, code_bytes).strip()
                    if text:
                        out.append(text)
                return out
        return []

    def _match(self, text: str, compiled: list[tuple[str, str, "re.Pattern[str]"]]) -> Optional[str]:
        """在 text 中查找匹配的模式，返回 core 最长的原 pattern（无匹配返回 None）。"""
        for pat, _c, regex in compiled:
            if regex.search(text):
                return pat
        return None

    def _tainted_in_text(self, text: str, tainted: dict[str, _Taint]) -> list[_Taint]:
        """返回 text 中出现的污染变量对应的 _Taint 列表。"""
        hits: list[_Taint] = []
        for var, t in tainted.items():
            if self._var_in_text(text, var):
                hits.append(t)
        return hits

    def _var_in_text(self, text: str, var: str) -> bool:
        if not var:
            return False
        if re.fullmatch(r"[A-Za-z_$][\w$]*", var):
            return re.search(r"(?<![A-Za-z0-9_$])" + re.escape(var) + r"(?![A-Za-z0-9_$])", text) is not None
        # 属性/成员路径（如 self.data、this.state.q）：直接做子串匹配。
        # 之前误用 re.escape(var)，产出带反斜杠的文本，永远匹配不到源码。
        return var in text

    def _strip_string_literals(self, text: str) -> str:
        """剥离普通字符串字面量，保留 f-string（interpolation 是表达式，需参与污点匹配）。

        逐字符扫描，正确处理转义与单/双引号混合，避免跨字符串吞掉中间代码。
        f-string 需要记住"当前在 f-string 内"，否则闭引号会被误判为新的开引号，
        把 f"{a}" + "lit" 这类拼接中间的操作符吞掉。
        """
        out: list[str] = []
        i = 0
        n = len(text)
        in_fstring = False
        fstring_quote = ""
        fstring_brace_depth = 0
        while i < n:
            ch = text[i]
            if in_fstring:
                out.append(ch)
                if ch == fstring_quote and fstring_brace_depth == 0:
                    in_fstring = False
                elif ch == "{":
                    fstring_brace_depth += 1
                elif ch == "}":
                    fstring_brace_depth = max(0, fstring_brace_depth - 1)
                i += 1
                continue
            if ch in "\"'":
                # 前面紧挨 f/F 的是 f-string：整体保留（interpolation 是表达式）
                if i > 0 and text[i - 1].lower() == "f":
                    out.append(ch)
                    in_fstring = True
                    fstring_quote = ch
                    fstring_brace_depth = 0
                    i += 1
                    continue
                quote = ch
                i += 1
                while i < n:
                    if text[i] == "\\":
                        i += 2
                        continue
                    if text[i] == quote:
                        i += 1
                        break
                    i += 1
            else:
                out.append(ch)
                i += 1
        return "".join(out)

    def _strip_sanitizer_calls(self, text: str) -> str:
        """迭代剥掉消毒函数调用（含嵌套括号情形），返回剩余文本。"""
        remaining = self._strip_string_literals(text)
        for _ in range(5):
            new = _SANITIZER_CALL_RE.sub("", remaining)
            if new == remaining:
                break
            remaining = new
        return remaining

    def _sanitizer_removes_taint(self, text: str, tainted_vars: list[str]) -> bool:
        """若 text 中污染变量的所有出现都被消毒函数包裹，返回 True。"""
        remaining = self._strip_sanitizer_calls(text)
        return not any(self._var_in_text(remaining, v) for v in tainted_vars)

    def _is_parameterized_sql(self, label: str, ttype: str, args: list[str], var: str, arg_clean: str) -> bool:
        """SQL sink 参数化查询识别：数据在绑定参数中且首参含占位符/第二参为容器。"""
        if ttype != "SQL Injection":
            return False
        if len(args) < 2:
            return False
        first = args[0]
        rest = " ".join(args[1:])
        in_first = self._var_in_text(self._strip_string_literals(first), var)
        in_rest = self._var_in_text(self._strip_string_literals(rest), var)
        if in_first:
            return False  # 模板本身被污染 → 仍报
        if not in_rest:
            return False
        second = args[1].lstrip()
        is_container = second.startswith(("(", "[", "{"))
        has_placeholder = _PARAM_PLACEHOLDER_RE.search(first) is not None
        return is_container or has_placeholder

    def _context_safe_sink(
        self, label: str, ttype: str, args: list[str], var: str, code_bytes: bytes,
    ) -> bool:
        """sink 语境安全判定（P0 修复，消灭工具规则误报）。

        子串匹配 sink 不感知参数语境，导致下列误报；这里补上语境检查：

        1. 命令注入：`subprocess.run(["ping","-c","1",host])`（列表参数）不经 shell
           解析，不构成命令注入；`subprocess.run(f"cmd {x}")` 未传 shell=True 时
           Python 同样不经过 shell。仅 **shell=True + 字符串拼接含污点** 才报。
        2. 模板注入：`env.from_string("...{{ name }}")` 是**值插值**（name 进模板
           上下文），而非把用户输入当模板体；`template.render(name=name)` /
           `render_template("x.html", name=name)` 同理为 kwargs 值插值，安全。
           模板来源（from_string/parse/render_template 位置参数）含污点才危险——
           由 `.from_string(` sink 与 render_template 位置参数检查覆盖。
        3. 值插值渲染的 autoescape 兜底：Jinja2 裸 Environment 默认 autoescape=False，
           值插值渲染到 HTML 仍有 XSS 风险；仅在函数内显式开启 autoescape
           （select_autoescape / autoescape=True）时才判定安全。

        Args:
            label: 匹配到的 sink 原 pattern（如 "subprocess.run("）
            ttype: 漏洞类型
            args: sink 调用参数文本列表（已有解析结果）
            var: 当前污染变量名
            code_bytes: 文件字节（用于检查 autoescape 语境）

        Returns:
            True = 语境安全（不应报）；False = 需进一步裁决/报告。
        """
        if ttype == "Command Injection" and label in ("subprocess.run(", "subprocess.Popen("):
            if args and args[0].lstrip().startswith("["):
                # 列表参数默认不经 shell（安全），但 argv 含 shell/解释器或
                # 执行语义参数（["sh","-c",x]、find -exec、git --upload-pack）
                # 时载荷会被解释器执行，仍需上报——2026-08-22 修正，此前一律
                # return True 吞掉此类真注入。口径与 shell_safety 唯一定义保持一致。
                from graduation_project.shell_safety import list_argv_has_exec_semantics
                if list_argv_has_exec_semantics(",".join(args)):
                    return False
                return True  # 列表参数：不经 shell，安全
            joined = " ".join(args)
            if not re.search(r"shell\s*=\s*True", joined):
                return True  # 无 shell=True：subprocess 不解析命令，安全
            return False

        if ttype == "Server-Side Template Injection":
            if label == "render_template(":
                # 位置参数 = 模板名/模板体（危险）；kwargs = 值插值（Flask 默认 autoescape）
                if not args:
                    return True  # 无参数：值插值无从谈起（模板体已由 from_string 覆盖）
                for a in args:
                    is_kwarg = "=" in a and a.split("=", 1)[0].strip().isidentifier()
                    if not is_kwarg and self._var_in_text(self._strip_string_literals(a), var):
                        return False  # 模板名被污染 → 危险
                return True
            if label == "render(":
                # 纯 kwargs（name=xxx）值插值：autoescape 开启才安全；无参数同样安全
                if not args:
                    return True
                if all("=" in a for a in args):
                    file_text = code_bytes.decode("utf-8", errors="replace")
                    if re.search(
                        r"select_autoescape|autoescape\s*=\s*(?:True|select_autoescape)",
                        file_text,
                    ):
                        return True
                    return False  # 无 autoescape 的值插值渲染 → 保守仍报
                # 位置参数（render(template_str)）→ 模板体被污染，危险
                return False

        if ttype == "Path Traversal":
            # open(污点路径) 但函数内存在完整防御链：白名单校验（filename in 集合）
            # + abspath/realpath 归一化 + startswith 前缀校验 → 判安全（safe_04 类）。
            # abspath 与 startswith 常跨行赋值（abs_target = abspath(...) 下一行
            # abs_target.startswith(...)），故按同文件共存判定而非同行。
            file_text = code_bytes.decode("utf-8", errors="replace")
            has_whitelist = re.search(
                r"(?:if|while)\s+[\w.]+\s+not\s+in\s+[\w.]+\s*:",
                file_text,
            )
            has_abspath = re.search(r"(?:abspath|realpath)\s*\(", file_text)
            has_startswith_guard = re.search(r"\.\s*startswith\s*\(", file_text)
            if has_whitelist and has_abspath and has_startswith_guard:
                return True
            return False

        return False

    # ------------------------------------------------------------------
    # 调用/摘要相关
    # ------------------------------------------------------------------
    def _sink_nodes_in(self, stmt: Node, code_bytes: bytes, ts_lang: str) -> list[Node]:
        best: dict[tuple[str, int], Node] = {}
        for desc in self._iter_descendants(stmt):
            if desc.type not in _CALL_NODE_TYPES and desc.type not in _MEMBER_NODE_TYPES \
                    and desc.type not in _SUBSCRIPT_NODE_TYPES:
                continue
            head = self._head_text(desc, code_bytes)
            if not head or not self._match(head, self._sink_compiled):
                continue
            key = (head, desc.start_point[0])
            prev = best.get(key)
            # 同一行同一头部：优先保留 call 节点（更精确），避免 attribute+call 重复
            if prev is None or (
                desc.type in _CALL_NODE_TYPES and prev.type not in _CALL_NODE_TYPES
            ):
                best[key] = desc
        return list(best.values())

    def _call_nodes_in(self, stmt: Node, ts_lang: str) -> list[Node]:
        return [n for n in self._iter_descendants(stmt) if n.type in _CALL_NODE_TYPES]

    def _callee_name(self, head: str) -> str:
        m = re.search(r"([A-Za-z_$][\w$]*)\s*$", head)
        return m.group(1) if m else ""

    def _build_summary(self, qual: str, func_node: Node, result: _ScopeResult) -> FunctionSummary:
        summary = FunctionSummary(name=qual, param_order=self._function_param_names(func_node))
        for p in result.paths:
            if p.source.startswith("param:"):
                param = p.source[len("param:"):]
                summary.param_sinks.setdefault(param, []).append((p.sink, p.sink_line, p.taint_type))
        summary.returns_taint = result.returns_taint
        return summary

    # ------------------------------------------------------------------
    # Web 上下文参数 source
    # ------------------------------------------------------------------
    def _param_sources(self, func_node: Node, ts_lang: str, code_bytes: bytes) -> list[tuple[str, int]]:
        if ts_lang == "python":
            return self._web_params(func_node)
        if ts_lang == "java":
            return self._java_web_params(func_node, code_bytes)
        return []

    def _web_params(self, func_node: Node) -> list[tuple[str, int]]:
        """Python 路由装饰器函数：参数视为 source（Flask/FastAPI 风格）。"""
        decorators = self._get_decorators(func_node)
        if not decorators:
            return []
        is_web = False
        for dec_text in decorators:
            low = dec_text.lower()
            if "route" in low:
                is_web = True
                break
            if re.search(r"@\s*[\w.]+\s*\.\s*(get|post|put|delete|patch|route)\s*\(", dec_text):
                is_web = True
                break
        if not is_web:
            return []
        params = self._function_param_names(func_node)
        if not params:
            return []
        start_line = func_node.start_point[0] + 1
        return [(name, start_line) for name in params if name not in ("self", "cls")]

    def _java_web_params(self, func_node: Node, code_bytes: bytes) -> list[tuple[str, int]]:
        """Java Spring 注解参数（@RequestParam/@PathVariable/@RequestBody 等）视为 source。"""
        params_node: Optional[Node] = None
        for c in func_node.children:
            if c.type in ("formal_parameters", "parameter_list"):
                params_node = c
                break
        if params_node is None:
            return []
        out: list[tuple[str, int]] = []
        ann_re = re.compile(r"@\s*(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|RequestPart)", re.IGNORECASE)
        for c in params_node.children:
            text = self._node_text(c, code_bytes).strip()
            if not ann_re.search(text):
                continue
            m = re.search(r"([A-Za-z_$][\w$]*)\s*$", text)
            if m:
                out.append((m.group(1), func_node.start_point[0] + 1))
        return out

    def _get_decorators(self, func_node: Node) -> list[str]:
        decs: list[Node] = [c for c in func_node.children if c.type == "decorator"]
        parent = func_node.parent
        if parent is not None and parent.type == "decorated_definition":
            for c in parent.children:
                if c.type == "decorator":
                    decs.append(c)
        out: list[str] = []
        for d in decs:
            try:
                out.append(d.text.decode("utf-8", errors="replace"))
            except Exception:
                continue
        return out

    def _function_param_names(self, func_node: Node) -> list[str]:
        """从函数定义节点提取参数名（仅形参名，不含默认值表达式中的标识符）。"""
        params_node: Optional[Node] = None
        for c in func_node.children:
            if c.type in ("parameters", "parameter_list", "formal_parameters"):
                params_node = c
                break
        if params_node is None:
            return []
        names: list[str] = []
        for c in params_node.children:
            if c.type == "identifier":
                names.append(c.text.decode("utf-8", errors="replace"))
            elif c.type in (
                "typed_parameter", "default_parameter", "typed_default_parameter",
                "list_splat_pattern", "dictionary_splat_pattern",
                "required_parameter", "rest_pattern", "formal_parameter",
                "spread_parameter", "optional_parameter", "parameter",
                "simple_parameter", "variadic_parameter", "lambda_parameter",
            ):
                for cc in c.children:
                    if cc.type == "identifier":
                        names.append(cc.text.decode("utf-8", errors="replace"))
                        break
        return names


# ---------------------------------------------------------------------------
# 模块级便捷函数
# ---------------------------------------------------------------------------
_DEFAULT_TRACKER = TaintTracker()


def trace_taint(code: str, language: str = "python", filename: str = "") -> list[TaintPath]:
    """便捷函数：用默认 TaintTracker 追踪污点路径。"""
    return _DEFAULT_TRACKER.trace(code, language=language, filename=filename)


if __name__ == "__main__":
    # 自检：含 SQL 注入、命令注入、SSTI 的 Python / JS / Java 示例
    sample_python = """\
import os
import subprocess
import pickle
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/login")
def login():
    username = request.args.get("username")
    password = request.form.get("password")
    query = "SELECT * FROM users WHERE name='" + username + "'"
    cursor.execute(query)
    os.system("echo " + username)
    return render_template("result.html", name=username)

def dangerous(data):
    obj = pickle.loads(data)
    f = open(data, "r")
    return obj

def safe_lookup(key):
    items = {"a": 1}
    return items.get(key)
"""
    sample_js = """\
app.get("/search", function(req, res) {
    var q = req.query.q;
    db.execute(q);
    document.write("<div>" + q + "</div>");
    eval(q);
});
"""
    sample_java = """\
public class Vuln {
    public void handle(HttpServletRequest request) {
        String name = request.getParameter("name");
        Statement stmt = conn.createStatement();
        stmt.execute("SELECT * FROM users WHERE name='" + name + "'");
        Runtime.getRuntime().exec("echo " + name);
    }
}
"""
    tracker = TaintTracker()

    for lang, name, src in [
        ("python", "python", sample_python),
        ("javascript", "js", sample_js),
        ("java", "java", sample_java),
    ]:
        print(f"=== {name} ===")
        for p in tracker.trace(src, language=lang, filename=f"sample.{name}"):
            chain = " → ".join(p.propagation) if p.propagation else "(直接表达式)"
            print(f"  L{p.source_line}:{p.source} -> L{p.sink_line}:{p.sink} [{p.taint_type}] 链: {chain}")
