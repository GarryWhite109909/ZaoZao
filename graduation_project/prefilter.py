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
    # 2026-09-01 补登（全规则泛化审计实锤）：secret 标记规则属**独立规则集**
    # （_build_secret_markers，第三类，既不在 vuln_rules 也不在 safe_rules），
    # 而元信息自检只覆盖 vuln_rules → 该规则在 11 个漏洞段命中却长期无 CWE
    # 登记（评测器按 §9.13.1 从本表派生映射，未登记 = 静默计成"CWE不匹配"）。
    # 自检的类别盲区已同步修复（见文件末尾元信息完整性用例）。
    "hardcoded_secret_marker": {
        "taint_type": "Hardcoded Credentials",
        "cwe": "CWE-798 Use of Hard-coded Credentials",
        "risk": "High",
        "severity": "high",
    },
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
    # --- 2026-08-31 第八波：盲区层收口（§9.20.2 清单复核 + NodeGoat 审计）---
    # 本波三条 + 312 参数形态补规则，把指导文档 §9.20.2 里"既未修也未提醒"
    # 的项里**有标准形态可写**的四类接进 finding 通道；其余（CWE-256 密码
    # 明文落库、http 明文服务、会话固定、Spring POJO 绑定）走 blind_spots
    # 提醒层（见 blind_spots.py 同日注）。
    "redos_nested_quantifier": {
        "taint_type": "ReDoS",
        "cwe": "CWE-1333 Improper Neutralization of Special Elements Used in a Regular Expression",
        "risk": "Medium",
        "severity": "medium",
    },
    "log_injection_console": {
        "taint_type": "Log Injection",
        "cwe": "CWE-117 Improper Output Neutralization for Logs",
        "risk": "Low",
        "severity": "low",
    },
    "weak_password_policy_regex": {
        "taint_type": "Weak Password Policy",
        "cwe": "CWE-521 Weak Password Requirements",
        "risk": "Medium",
        "severity": "medium",
    },
    "cleartext_sensitive_storage_field": {
        "taint_type": "Cleartext Storage of Sensitive Information",
        "cwe": "CWE-312 Cleartext Storage of Sensitive Information",
        "risk": "High",
        "severity": "high",
    },
    # --- 2026-08-31 第四波：长尾注入族（工具层优化指导 §五之五 零召回清单）---
    # 全部按"库/语言标准 API + 标准安全开关"声明（泛化纪律三关卡），不针对样本：
    #   XXE   → 解析器加固开关缺失（resolve_entities/disallow-doctype 等标准参数）
    #   LDAP  → filter 由 f-string/拼接构造（参数化传参是标准安全写法）
    #   NoSQL → 请求值进 Mongo 查询文档字面量（类型强制 str() 是标准安全写法）
    #   XPath → 表达式由 f-string/拼接构造
    #   PHP   → 松散比较 == 是 PHP 语言特性级形态（hash_equals/=== 是标准写法）
    #   915   → setattr 动态属性写入（白名单过滤是标准安全写法）
    #   fastjson / OGNL → 库专有 API 名（parseObject / Ognl.getValue）
    "xxe_unprotected_parse": {
        "taint_type": "XXE",
        "cwe": "CWE-611 Improper Restriction of XML External Entity Reference",
        "risk": "Critical",
        "severity": "critical",
    },
    "ldap_injection": {
        "taint_type": "LDAP Injection",
        "cwe": "CWE-90 Improper Neutralization of Special Elements used in an LDAP Statement",
        "risk": "High",
        "severity": "high",
    },
    # --- 2026-08-31 第五波：核心注入族（召回缺口修复）---
    # 与第四波「长尾注入族」不同，本波补的是 OWASP 主流类别的**形态缺口**：
    # 旧规则只认「输入直接出现在 sink 调用内」的内联字面量形态，而真实代码
    # 主流是「先构造变量、再把变量传入 sink」的 1 跳形态，以及 f-string /
    # 模板字符串等非拼接构造式。四类共用一套 1 跳消解与构造识别逻辑。
    "sqli_constructed_query": {
        "taint_type": "SQL Injection",
        "cwe": "CWE-89 SQL Injection",
        "risk": "Critical",
        "severity": "critical",
    },
    "cmd_injection_shell": {
        "taint_type": "Command Injection",
        "cwe": "CWE-78 Command Injection",
        "risk": "Critical",
        "severity": "critical",
    },
    "xss_unescaped_output": {
        "taint_type": "XSS",
        "cwe": "CWE-79 Cross-Site Scripting",
        "risk": "High",
        "severity": "high",
    },
    "ssrf_request_from_input": {
        "taint_type": "SSRF",
        "cwe": "CWE-918 Server-Side Request Forgery",
        "risk": "High",
        "severity": "high",
    },
    "nosql_query_injection": {
        "taint_type": "NoSQL Injection",
        "cwe": "CWE-943 Improper Neutralization of Special Elements in Data Query Logic",
        "risk": "Critical",
        "severity": "critical",
    },
    # 2026-08-31 补（NodeGoat 审计）：MongoDB $where 操作符 JS-eval 注入
    "nosql_where_injection": {
        "taint_type": "NoSQL Injection",
        "cwe": "CWE-943 Improper Neutralization of Special Elements in Data Query Logic",
        "risk": "Critical",
        "severity": "critical",
    },
    # 2026-08-31 补（NodeGoat 审计）：模板引擎 autoescape 显式关闭（XSS 系统性根因）
    "template_autoescape_disabled": {
        "taint_type": "XSS",
        "cwe": "CWE-79 Cross-Site Scripting",
        "risk": "High",
        "severity": "high",
    },
    "xpath_injection": {
        "taint_type": "XPath Injection",
        "cwe": "CWE-643 Improper Neutralization of Special Elements in XPath Expression",
        "risk": "High",
        "severity": "high",
    },
    "php_loose_compare": {
        "taint_type": "Type Juggling",
        "cwe": "CWE-843 Access of Resource Using Incompatible Type",
        "risk": "High",
        "severity": "high",
    },
    "mass_assignment_setattr": {
        "taint_type": "Mass Assignment",
        "cwe": "CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        "risk": "High",
        "severity": "high",
    },
    "deser_fastjson": {
        "taint_type": "Insecure Deserialization",
        "cwe": "CWE-502 Deserialization of Untrusted Data",
        "risk": "Critical",
        "severity": "critical",
    },
    "ognl_expression_injection": {
        "taint_type": "SpEL Injection",
        "cwe": "CWE-917 Improper Neutralization of Special Elements in Data Query Logic",
        "risk": "Critical",
        "severity": "critical",
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
    # --- 2026-08-31 第四波补：长尾注入族 sink（XXE/LDAP/NoSQL/XPath/
    # setattr/OGNL）。全部为对应库的**标准 API 名**（语言级事实）：
    # xml_parse 覆盖 lxml（etree.fromstring/parse）、minidom、通用 parseString；
    # ldap_s 覆盖 python-ldap 的 search_s 与 PHP 的 ldap_search；
    # mongo_find 覆盖 PyMongo find_one/find 与 Mongoose findOne/find——
    #   `\.find\s*\(` 的 `find` 后必须紧跟 `(`，不会误配 `.findAll(`；
    # xpath_e 是 lxml/Scrapy 的 .xpath( 评估入口；
    # setattr_call 是 Python 动态属性写入的标准 API；
    # ognl_e 是 OGNL 库的表达式求值入口。
    # 带**文件级上下文守卫**的宽 sink（.search( 之于 LDAP、mongo_find 之于
    # MongoDB）不在本表——它们由 match_func 里"上下文特征 + 宽 sink"组合判定，
    # 避免 .search( / .find( 在非对应上下文中误报。
    "xml_parse": re.compile(
        r"etree\.(?:fromstring|parse|XML)\s*\(|minidom\.parse(?:String)?\s*\("
        r"|\bparseString\s*\(", re.IGNORECASE),
    # 宽 sink（.parse(）：仅在文件含 XML 解析器上下文特征时由 match_func 启用
    #（_XML_PARSER_CTX_RE），覆盖 Java `factory.newDocumentBuilder().parse(
    # request.getInputStream())` 形态；裸 .parse( 与文件/日期解析撞词，不单独启用
    "xml_parse_w": re.compile(r"\.\s*parse\s*\(", re.IGNORECASE),
    "ldap_s": re.compile(r"\.search_s\s*\(|\bldap_search\s*\(", re.IGNORECASE),
    # 宽 sink（.search(）：仅在文件含 LDAP 上下文特征时由 match_func 启用，
    # 覆盖 node ldapjs client.search(filter) / ldap3 conn.search(...) 形态
    "ldap_search_w": re.compile(r"\.search\s*\(", re.IGNORECASE),
    "mongo_find": re.compile(r"\.(?:find_one|findOne|find)\s*\(", re.IGNORECASE),
    "xpath_e": re.compile(r"\.xpath\s*\(", re.IGNORECASE),
    "setattr_call": re.compile(r"\bsetattr\s*\(", re.IGNORECASE),
    "ognl_e": re.compile(r"\bOgnl\.(?:getValue|parseExpression)\s*\("),
    # --- 2026-08-31 第五波：核心注入族 sink 补齐（召回缺口）---
    # sql_execute：语句执行入口，各语言/db-api 的标准 API 名（语言级事实）：
    #   .execute/.executemany/.executescript → Python DB-API(PEP 249)
    #   .executeQuery/.executeUpdate         → JDBC
    #   mysqli_query                         → PHP
    # 裸 `.execute(` 与 Java 线程池 ExecutorService.execute(Runnable) 同名，
    # 故整条规则另加 SQL 上下文守卫（_SQL_CTX_RE）隔离该语义冲突。
    # 不含 Django .raw(/.extra( —— 与其他库 .raw( 撞词，暂无样本支撑，未纳入。
    "sql_execute": re.compile(
        r"\.execute(?:many|script)?\s*\(|\.executeQuery\s*\(|\.executeUpdate\s*\("
        r"|\bmysqli_query\s*\(|\.query\s*\(", re.IGNORECASE),
    # `.query(`（2026-08-31 补）：Node mysql/mysql2/pg 的标准查询 API
    #（§9.7 #1 在 taint_tracker 已论证其标准性）。词边界保证不撞
    # `req.query.id`（query 后是 `.` 非括号）与 `querySelector(`；整条规则
    # 另有 _SQL_CTX_RE 文件级守卫，无 SQL 上下文的 `.query(` 不启用。
    # http_client：SSRF 的出口——服务端主动发起外部请求的标准 API。
    # 不含裸 fetch(：浏览器端 fetch 是前端取数，无 SSRF 语义（服务端请求伪造）。
    "http_client": re.compile(
        r"\burlopen\s*\(|\burlretrieve\s*\("
        r"|requests\.(?:get|post|put|head|patch|delete|request)\s*\("
        r"|\baxios\.(?:get|post|put|head|patch|delete|request)\s*\("
        r"|\bneedle\.(?:get|post|put|head|patch|delete|request)\s*\("
        r"|https?\.request\s*\(|\bcurl_exec\s*\(",
        re.IGNORECASE),
    # cmd_exec：`exec(` 在 JS（child_process）=命令注入，在 Python =代码执行，
    # 同名不同义（语言级事实）。故该 sink 仅在文件含 child_process 引入时启用。
    "cmd_exec": re.compile(r"\bexec\s*\(", re.IGNORECASE),
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

# --- 2026-08-31 第四波：长尾注入族配套正则 ---

# LDAP 上下文特征（ldap_injection 的宽 sink `.search(` 需要：单独出现时与
# 搜索/检索语义撞词严重，仅在文件含 LDAP 库特征时才启用该 sink）。
_LDAP_CTX_RE = re.compile(
    r"\bimport\s+ldap\b|ldap\.initialize|ldap3\b|ldapjs|ldap_connect|"
    r"ldap_search|\bsearch_s\b",
    re.IGNORECASE,
)

# NoSQL 上下文特征（mongo_find 的宽 sink `.find(` 同理需要文件级守卫）。
# Sequelize `Model.findOne({where: {id: req.body.id}})` 与 Mongo findOne 同形
# （node_sequelize 负样本实锤），无守卫必误报——JS 无 mongo 字样的抽象层文件
# 因此漏报，属精度取舍（跨文件上下文是架构级局限，同 crossfile 记档）。
_NOSQL_CTX_RE = re.compile(
    r"pymongo|MongoClient|mongoose|mongodb|mongo(?:db)?\s*[\[.\"]"
    r"|require\s*\(\s*['\"](?:mongoose|mongodb|mongojs)['\"]",
    re.IGNORECASE,
)

# Java/JS XML 解析器上下文（宽 sink `.parse(` 的守卫：裸 .parse( 与
# 文件/日期/通用 parse 撞词严重，仅在文件含 XML 解析器工厂/读取器特征时启用）。
_XML_PARSER_CTX_RE = re.compile(
    r"DocumentBuilderFactory|SAXParser(?:Factory)?|XMLReader|XMLInputFactory"
    r"|libxmljs|DOMParser|etree\b|minidom|xml\.sax",
    re.IGNORECASE,
)


def _code_wo_comment_lines(code: str) -> str:
    """剥离整行注释（//、#、块注释中间行、SQL 风格 --）。

    用于"安全特征文件级判定"的净化：CVE-fix 独立集实锤——修复教学代码把
    `// Missing: factory.setFeature("...disallow-doctype-decl", true)` 写在
    注释里，_XXE_SAFE_RE 文件级搜索被注释命中 → 漏洞版被误判"已加固"。
    只剥离**整行**注释（行首即注释符），不做行内剥离（http:// 等 URL 会误伤）；
    行内注释里的守卫词仍会命中，属已知边界（教学样本为整行形态）。
    """
    return "\n".join(
        line for line in (code or "").splitlines()
        if not line.lstrip().startswith(("//", "#", "*", "/*", "--")))


def _strip_str_literals(text: str) -> str:
    """把字符串字面量替换为空白，**保留 JS 模板串的 `${}` 插值**。

    「构造式/变量引用」类判定的共享原语（第四、五波统一入口）：
    SQL/HTML 文本里的单词（FROM、WHERE、列名）是**文本**而非标识符引用，
    不剥离会被当成拼接进来的变量（noise_03 实测误报）。反引号串不能整段
    剥离——`${x}` 插值是真实的代码引用（JS 构造形态），故只保留插值段。
    """
    text = re.sub(
        r"`[^`]*`",
        lambda m: " " + " ".join(re.findall(r"\$\{[^}]*\}", m.group(0))) + " ",
        text or "", flags=re.DOTALL)
    return re.sub(r"(['\"]).*?\1", " ", text, flags=re.DOTALL)

# XXE 安全配置特征（存在任一即认为解析器已加固，xxe_unprotected_parse 不报）。
# 覆盖：lxml（resolve_entities=False / no_network / load_dtd）、Java
# （disallow-doctype-decl / FEATURE_SECURE_PROCESSING / external-*-entities /
# XMLConstants setFeature）、libxmljs（noent:false）、defusedxml 全家。
_XXE_SAFE_RE = re.compile(
    r"resolve_entities\s*=\s*False|no_network\s*=\s*True|load_dtd\s*=\s*False"
    r"|disallow-doctype-decl|FEATURE_SECURE_PROCESSING|external-[a-z-]*entit"
    r"|setFeature\s*\(\s*XMLConstants|defusedxml|defused_parse|noent\s*:\s*[Ff]alse"
    r"|(?:attribute|feature)\s*\(\s*http://xml\.org",
    re.IGNORECASE,
)

# PHP 超全局输入（php_loose_compare 用）：PHP 4.1+ 的标准输入数组，语言级事实，
# 天然语言隔离（其他语言无此形态）。既是 PHP 上下文守卫，也是输入源标记。
_PHP_SUPERGLOBAL_RE = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|SESSION)\b")

# --- 2026-08-31 第五波：配套上下文守卫 ---

# SQL 上下文特征：sql_execute 的裸 `.execute(` 与 Java 线程池
# ExecutorService.execute(Runnable) 同名，需文件级 SQL 语义隔离。
# 覆盖 SQL 关键字与主流 DB 客户端标识（均为语言/库级标准名）。
_SQL_CTX_RE = re.compile(
    r"\bselect\b|\binsert\s+into\b|\bupdate\b\s+\w|\bdelete\s+from\b"
    r"|sqlite3|mysql|postgres|psycopg|\bjdbc\b|DriverManager|createStatement"
    r"|PreparedStatement|cursor\.execute|mysqli|sqlalchemy",
    re.IGNORECASE,
)

# JS child_process 引入特征：`exec(` 在 JS 侧是命令注入（child_process.exec），
# 在 Python 侧是代码执行（内置 exec）。本守卫决定 cmd_exec sink 是否启用。
_JS_CHILDPROCESS_RE = re.compile(
    r"child_process|require\(\s*[\"']child_process[\"']", re.IGNORECASE)

# HTML 标签字面量（XSS 用）：出现在字符串字面量中说明该串是 HTML 片段，
# 而非普通文本——「HTML 片段 + 未转义输入 + 输出到响应」才是 XSS 三要素。
_HTML_TAG_RE = re.compile(
    r"<\s*(?:html|body|div|p|span|h[1-6]|a\s|table|tr|td|ul|li|script|img|"
    r"form|input|b|i|br|pre|header|footer)\b",
    re.IGNORECASE,
)

# 输出转义特征（XSS 安全写法，存在任一即不报）：把输入转义后再插入 HTML 是
# XSS 的标准修复（html.escape / markupsafe / bleach / autoescape 等）。
# 不含裸 `escape(`：`re.escape`/`shlex.escape` 语义不同（转义目标不是 HTML），
# 会误伤，故只认带命名空间或库专有的写法。
_XSS_SAFE_RE = re.compile(
    r"html\.escape|markupsafe|\bbleach\b|sanitize|escapeHtml|escape_html"
    r"|DOMPurify|autoescape|select_autoescape|xss_clean",
    re.IGNORECASE,
)

# Shell 转义特征（命令注入安全写法，存在任一即不报）：参数经 shell 引号转义后
# 再拼进命令行是命令注入的标准修复（shlex.quote / escapeshellarg 等）。
_CMD_SAFE_RE = re.compile(
    r"shlex\.quote|shlex\.join|pipes\.quote|escapeshellarg|escapeshellcmd",
    re.IGNORECASE,
)

# --- 2026-08-31 第八波：盲区层收口配套守卫 ---

# JS 服务端上下文（log_injection_console 的文件级门）：console.* 的 CWE-117
# 语义只在服务端成立（浏览器端 console 是开发工具输出，§9.20.2 "运行时双语义"）。
# 解法不是逐行判语义，而是文件级判定——两类信号（任一命中即服务端模块）：
#   ① require/启动 API：Node 服务端框架标准名，无第二语义；
#   ② Express handler 惯用法：req.session/body/query/params 与
#     res.render/send/redirect/json 只存在于服务端请求处理代码（nodegoat
#     session.js 实锤：handler 模块自身不 require express，靠惯用法判定）。
# 浏览器端文件（无以上形态）整类豁免。
_JS_SERVER_CTX_RE = re.compile(
    r"require\s*\(\s*['\"](?:express|http|https|koa|fastify|restify|@hapi/hapi|next)['\"]\s*\)"
    r"|http\.createServer\s*\(|https\.createServer\s*\("
    r"|\b(?:app|server|router)\.listen\s*\("
    r"|\breq\s*\.\s*(?:session|body|query|params|headers|cookies)\b"
    r"|\bres\s*\.\s*(?:render|send|redirect|json|status|sendFile|sendStatus)\b",
)

# 嵌套量词（ReDoS 的结构性特征）：分组内含量词、分组后紧跟量词（/([0-9]+)+/）。
# 回溯次数随输入长度指数增长——语言级事实，与具体样本拼写无关。判定时只认
# 出现在正则字面量/正则字符串**内部**的出现（裸写 (a+b)*c 是算术，不是正则）。
_REDOS_NESTED_RE = re.compile(r"\((?:[^()\n\\]|\\.)*[+*]\)\s*[+*{]")
# 动态求用（AND 条件，文件级）：只写不用的正则没有 ReDoS 攻击面。
_REDOS_DYNAMIC_USE_RE = re.compile(
    r"\.(?:test|match|exec|search)\s*\(\s*[A-Za-z_$]"
    r"|\bre\.(?:match|search|fullmatch|findall|sub)\s*\(")

# 弱口令策略（CWE-521）：pass/pwd 词根标识符赋值 ← `.{1,N}` 任意字符有界量词
# 正则。语言级事实：`.{1,N}` = 接受 1~N 个**任意字符**，无字符类/长度下限
# 要求，是最直白的弱策略声明（session.js L144 实锤：PASS_RE = /^.{1,20}$/）。
# 词根 pass/pwd 是"口令策略"的标准命名语义（与 CWE-521 的对象一致），其他
# 用途（搜索框长度限制）不用此命名形态。行级 AND：标识符正则 + 量词正则
# （量词须在 /.../ 字面量或引号字符串内部，由同一正则的跨度约束保证）。
_WEAK_PW_IDENT_RE = re.compile(r"(?:pass(?:word)?|pwd)\w*\s*=", re.IGNORECASE)
_WEAK_PW_ANY_QUANT_RE = re.compile(
    r"/[^/\n]*\\?\.\s*\{\s*1\s*,\s*\d{1,3}\s*\}[^/\n]*/"
    r"|['\"][^'\"]*\\?\.\s*\{\s*1\s*,\s*\d{1,3}\s*\}[^'\"]*['\"]")

# Mongo 持久化上下文（cleartext_sensitive_storage_field 用）：独立的守卫，
# **不复用 _NOSQL_CTX_RE**——本规则的精度主门是"敏感字段直赋 + 文档持久化
# 调用"双 AND，上下文只做第二重保险；扩 _NOSQL_CTX_RE 会连带放宽
# nosql_query_injection 的触发面（nodegoat 的 findOne({userName: x}) 会
# 新增噪声候选），违反"安全样本/噪声候选零新增"纪律。db.collection( 是
# Mongo 原生驱动的专有 API（语言级事实），与 _NOSQL_CTX_RE 的 require 形态
# 同一事实集。
_MONGO_PERSIST_CTX_RE = re.compile(
    r"db\s*\.\s*collection\s*\(|MongoClient|mongoose|\bmongo(?:db|js)\b",
    re.IGNORECASE,
)

# Mongo/文档库持久化调用（对象名排除 cipher/decipher——profile-dao 实锤：
# encrypt 工具函数里的 cipher.update( 与数据持久化无关，不能当持久化证据）。
_MONGO_PERSIST_CALL_RE = re.compile(
    r"(?:^|[^\w.])(?!(?:de)?cipher\b)[\w$]+\.(?:update(?:_one|_many)?|"
    r"replace_one|insert(?:_one|_many)?|save)\s*\(")

# 敏感字段「参数/变量直赋」形态（cleartext_sensitive_storage_field 用）：
# helper/DAO 层的敏感字段以函数形参进入（updateUser = (..., ssn, ...) →
# user.ssn = ssn;），与"请求直取"形态同构——都是敏感字段未经字段级加密
# 进入持久化。右侧仅认**裸标识符**（= 后不是函数调用）：user.ssn = encrypt(ssn)
# 的已加密写法天然豁免。password/passwd 不入本表（CWE-256 归盲区提醒层，
# 见规则注释）。
_SENSITIVE_FIELD_ASSIGN_RE = re.compile(
    r"\.\s*(?:ccn|cc_?num|credit_?card|card_?num(?:ber)?|cardnum|cvv|cvc|ssn|"
    r"social_?security|iban|passport_?no)\w*\s*=\s*[A-Za-z_$][\w$]*\s*[;,)\n]",
    re.IGNORECASE,
)

# SSRF 安全特征（URL 白名单校验，存在任一即不报）：对目标 URL 做域名/前缀
# 白名单校验是 SSRF 的标准修复写法（与路径穿越的 abspath+startswith 同构）。
_SSRF_SAFE_RE = re.compile(
    r"allow(?:ed)?_?(?:domains|hosts|urls)|whitelist|white_list"
    r"|urlparse\s*\([^)]*\)\s*\.\s*(?:netloc|hostname)"
    r"|\.startswith\s*\(\s*[\"']https?://",
    re.IGNORECASE,
)

# 响应输出 sink（XSS 用）：把内容写回 HTTP 响应的标准 API/语句。
# 仅构造不输出不构成 XSS（中间变量可能后续被转义）。
_OUTPUT_SINK_RE = re.compile(
    r"\breturn\s+|\becho\b|\bprint\s*\(|\bres\s*\.\s*(?:send|write|end|json)\s*\("
    r"|\bresponse\s*\.\s*(?:write|send)\s*\(|HttpResponse|render_template_string"
    r"|\bout\s*\.\s*print",
    re.IGNORECASE,
)

# Mass Assignment 安全特征（存在任一即不报）：请求键进入对象属性前有字段
# 白名单过滤——`if key in allowed_fields` / `fields = [...]` 白名单 /
# Django form / DRF serializer 等框架级过滤形态。
_MASS_ASSIGN_SAFE_RE = re.compile(
    r"allowed_?fields|whitelist|white_list|__fields|fillable|"
    r"\bkey\s+(?:not\s+)?in\s+\w|if\s+\w+\s+not\s+in\s+\w+\s*:|"
    r"ModelForm|serializers?\.\w+\(.*(data|instance)|filterable",
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
        # 2026-08-31 补：request/req 作为**首参**传入的函数返回值
        # （`uid = get_user_input(request, "uid")`）——跨文件/工具函数包装的
        # 主流形态，返回值必然是请求派生的（语言级事实：以 request 为输入）。
        for m in re.finditer(
                r"(\w+)\s*=\s*[\w.]+\s*\(\s*(?:request|req)\s*[,)]", code, re.IGNORECASE):
            names.add(m.group(1))
        # PHP 超全局赋值（`$name = $_GET['name']`）：PHP 的输入源标准形态，
        # 与 _PHP_SUPERGLOBAL_RE 同一事实集（PHP 4.1+ 语言特性）。
        for m in re.finditer(r"\$(\w+)\s*=\s*\$_", code):
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

        # --- XXE：未加固的 XML 解析器解析外部输入（2026-08-31 第四波，CWE-611）---
        # 漏洞形态：XML 解析 sink（lxml etree.fromstring/parse、minidom、
        # DocumentBuilderFactory 等）的参数来自外部输入，且文件内无任何解析器
        # 加固特征（_XXE_SAFE_RE：resolve_entities=False / disallow-doctype-decl /
        # defusedxml / noent:false 等标准开关）。缺失型中"有标准安全开关可查"的
        # 形态——守卫词是各库文档记载的标准 API，非样本拼写。
        # safe_14（defused 形态）由守卫词天然豁免。Java 分离形态
        #（factory.newDocumentBuilder().parse(input)）由宽 sink xml_parse_w +
        # _XML_PARSER_CTX_RE 文件级守卫承接。
        rules.append(_Rule(
            name="xxe_unprotected_parse",
            patterns=[],
            match_func=lambda code: (
                not _XXE_SAFE_RE.search(_code_wo_comment_lines(code))
                and (self._sink_hits_input_vars(code, ("xml_parse",))
                     or (bool(_XML_PARSER_CTX_RE.search(code))
                         and self._sink_hits_input_vars(code, ("xml_parse_w",))))
            ),
            line_func=lambda code: (
                self._sink_first_hit_line(code, ("xml_parse",))
                or (self._sink_first_hit_line(code, ("xml_parse_w",))
                    if _XML_PARSER_CTX_RE.search(code) else 0)
            ),
            category="vuln",
        ))

        # --- LDAP 注入（2026-08-31 第四波，CWE-90）---
        # 漏洞形态：LDAP filter 由 f-string/拼接/格式化构造后传入查询 sink。
        # sink 表：search_s（python-ldap）/ ldap_search（PHP）为专有 API；
        # 宽 sink `.search(`（node ldapjs / ldap3）仅在文件含 LDAP 上下文特征
        # 时启用（_LDAP_CTX_RE），否则与普通"搜索"语义撞词。
        # safe_16（字面量 filter + 参数化传参）因 filter 非构造式而天然豁免。
        rules.append(_Rule(
            name="ldap_injection",
            patterns=[],
            match_func=lambda code: (
                bool(_LDAP_CTX_RE.search(code))
                and (self._sink_hits_constructed(code, ("ldap_s",))
                     or self._sink_hits_constructed(code, ("ldap_search_w",)))
            ),
            line_func=lambda code: (
                self._constructed_hit_line(code, ("ldap_s",))
                or (self._constructed_hit_line(code, ("ldap_search_w",))
                    if _LDAP_CTX_RE.search(code) else 0)
            ),
            category="vuln",
        ))

        # --- NoSQL 注入（2026-08-31 第四波，CWE-943）---
        # 漏洞形态：请求值直接进入 MongoDB 查询文档（dict/object 字面量），
        # 攻击者可注入 $gt/$ne 等操作符绕过认证。触发（AND）：文件含 MongoDB
        # 上下文特征（_NOSQL_CTX_RE）+ find/find_one/findOne sink 的参数区是
        # 查询文档（含 `{`）且出现输入。DVNA 的 Sequelize（findAll/findOne ORM）
        # 无 mongo 上下文特征 → 不误报。
        rules.append(_Rule(
            name="nosql_query_injection",
            patterns=[],
            match_func=lambda code: (
                bool(_NOSQL_CTX_RE.search(code))
                and self._mongo_find_hit(code)
            ),
            line_func=lambda code: self._mongo_find_hit_line(code),
            category="vuln",
        ))

        # --- NoSQL $where JS-eval 操作符注入（2026-08-31，NodeGoat 审计）---
        # 漏洞形态：MongoDB 的 $where 接受一段 JS 字符串并在服务端 eval
        # （官方文档行为），用户输入拼接/插值进该串 → 任意 JS 执行
        # （allocations-dao L78 实锤：$where 拼接 req.query 的 threshold）。
        # 触发（AND，同行）：$where +（模板 ${} 或 与变量拼接）。$where 是
        # MongoDB 标准操作符（语言级事实），JS 模板与 Python 拼接同形态；
        # 常量 $where（无插值）不触发。
        rules.append(_Rule(
            name="nosql_where_injection",
            patterns=[],
            match_func=lambda code: self._nosql_where_hit_line(code) > 0,
            line_func=lambda code: self._nosql_where_hit_line(code),
            category="vuln",
        ))

        # --- 模板 autoescape 显式关闭（2026-08-31，NodeGoat 审计）---
        # 漏洞形态：模板引擎自动转义被显式设为 false → 全部变量输出不转义，
        # XSS 的系统性根因（server.js L137 swig.setDefaults({autoescape: false})
        # 实锤；Python 侧 jinja2 Environment(autoescape=False) 同形态）。
        # 语言级事实：autoescape 是 swig/jinja2/nunjucks 等引擎的标准选项名，
        # 显式 false/False/0 赋值即关闭；True/注释提及不触发。
        rules.append(_Rule(
            name="template_autoescape_disabled",
            patterns=[re.compile(r"\bautoescape\b\s*[:=]\s*(?:false|0)\b", IC)],
            category="vuln",
        ))

        # --- XPath 注入（2026-08-31 第四波，CWE-643）---
        # 漏洞形态：XPath 表达式由 f-string/拼接构造后传入 .xpath( 求值。
        # .xpath( 是 lxml/Scrapy 的专有评估入口（Java 走 XPathFactory，形态
        # 不同不在此覆盖）。安全写法（参数化 XPath / XPathVariableResolver）
        # 的表达式不经过 f-string 构造，天然豁免。
        rules.append(_Rule(
            name="xpath_injection",
            patterns=[],
            match_func=lambda code: self._sink_hits_constructed(code, ("xpath_e",)),
            line_func=lambda code: self._constructed_hit_line(code, ("xpath_e",)),
            category="vuln",
        ))

        # --- PHP 类型混淆（松散比较，2026-08-31 第四波，CWE-843）---
        # 详见 _php_loose_compare_line。$_ 超全局是 PHP 特有语法，天然语言隔离。
        rules.append(_Rule(
            name="php_loose_compare",
            patterns=[],
            match_func=lambda code: self._php_loose_compare_line(code) > 0,
            line_func=lambda code: self._php_loose_compare_line(code),
            category="vuln",
        ))

        # --- Mass Assignment（2026-08-31 第四波，CWE-915）---
        # 详见 _mass_assignment_hit_line。setattr() 是 Python 标准动态属性 API，
        # 业务代码正常写入用得少（ORM 字段直接赋值是主流），+ 键值遍历 + 输入
        # 关联三条件 AND 保精度；白名单过滤（allowed_fields 等）时豁免。
        rules.append(_Rule(
            name="mass_assignment_setattr",
            patterns=[],
            match_func=lambda code: self._mass_assignment_hit_line(code) > 0,
            line_func=lambda code: self._mass_assignment_hit_line(code),
            category="vuln",
        ))

        # --- Fastjson 反序列化（2026-08-31 第四波，CWE-502）---
        # 漏洞形态（框架级事实）：fastjson 的 JSON.parseObject/JSON.parse 开启
        # autoType 时可致 RCE（CVE-2017-18349 族），输入直接进 parse 即为候选。
        # JSON.parseObject( 是 fastjson 特有 API（org.json/Gson/Jackson 均不同名）
        # 可无守卫；裸 JSON.parse( 是 JS 标准 API（安全解析），必须以 fastjson
        # import 作守卫才计入。
        rules.append(_Rule(
            name="deser_fastjson",
            patterns=[],
            match_func=lambda code: (
                re.search(r"JSON\.parseObject\s*\(", code) is not None
                or (re.search(r"com\.alibaba\.fastjson", code) is not None
                    and re.search(r"JSON\.parse\s*\(", code) is not None)
            ),
            line_func=lambda code: _line_of(code, re.compile(r"JSON\.parse(?:Object)?\s*\(")),
            category="vuln",
        ))

        # --- OGNL 表达式注入（2026-08-31 第四波，CWE-917）---
        # 漏洞形态（库级事实）：Ognl.getValue/parseExpression 把字符串当表达式
        # 求值——表达式由外部输入（请求头/参数）构造即 RCE（Struts2 S2-045 族）。
        # Ognl. 前缀是库专有命名空间，无第二语义；普通代码不直接调用 OGNL。
        rules.append(_Rule(
            name="ognl_expression_injection",
            patterns=[],
            match_func=lambda code: self._sink_hits_constructed(code, ("ognl_e",)),
            line_func=lambda code: self._constructed_hit_line(code, ("ognl_e",)),
            category="vuln",
        ))

        # --- SQL 注入·构造型查询（2026-08-31 第五波，CWE-89）---
        # 详见 _sqli_hit_line。保留原 sqli_* 三条内联规则（scripts/
        # tool_smoke_test.py 依赖 sqli_string_concat 的规则名），本条作为
        # 1 跳/f-string/变量拼接形态的补充，两者 CWE 一致不会互相冲突。
        rules.append(_Rule(
            name="sqli_constructed_query",
            patterns=[],
            match_func=lambda code: self._sqli_hit_line(code) > 0,
            line_func=lambda code: self._sqli_hit_line(code),
            category="vuln",
        ))

        # --- 命令注入·f-string/模板字符串（2026-08-31 第五波，CWE-78）---
        # 详见 _cmd_hit_line。补 cmd_subprocess_shell_concat 只认 `+` 的缺口。
        rules.append(_Rule(
            name="cmd_injection_shell",
            patterns=[],
            match_func=lambda code: self._cmd_hit_line(code) > 0,
            line_func=lambda code: self._cmd_hit_line(code),
            category="vuln",
        ))

        # --- XSS·未转义输出（2026-08-31 第五波，CWE-79）---
        # 详见 _xss_hit_line。此前 prefilter 完全无 XSS 规则（87 段弃权 3 段）。
        rules.append(_Rule(
            name="xss_unescaped_output",
            patterns=[],
            match_func=lambda code: self._xss_hit_line(code) > 0,
            line_func=lambda code: self._xss_hit_line(code),
            category="vuln",
        ))

        # --- SSRF·输入决定请求目标（2026-08-31 第五波，CWE-918）---
        # 详见 _ssrf_hit_line。此前 prefilter 无 SSRF 规则（87 段弃权 2 段）。
        rules.append(_Rule(
            name="ssrf_request_from_input",
            patterns=[],
            match_func=lambda code: self._ssrf_hit_line(code) > 0,
            line_func=lambda code: self._ssrf_hit_line(code),
            category="vuln",
        ))

        # --- ReDoS·嵌套量词正则（2026-08-31 第八波，CWE-1333）---
        # 详见 _redos_hit_line。指导文档 §9.20.2 原判"需对正则字面量做正则
        # 分析（新能力域），列为未来规则机会"——本轮核实：嵌套量词是纯结构
        # 特征（分组内含量词 + 分组后紧跟量词），行级正则可判，非能力域外。
        # NodeGoat profile.js L59 实锤（/([0-9]+)+\#/，官方注释明示 ReDoS）。
        rules.append(_Rule(
            name="redos_nested_quantifier",
            patterns=[],
            match_func=lambda code: self._redos_hit_line(code) > 0,
            line_func=lambda code: self._redos_hit_line(code),
            category="vuln",
        ))

        # --- 服务端 console.* 日志注入（2026-08-31 第八波，CWE-117）---
        # 详见 _console_log_hit_line。§9.20.2 原判"运行时双语义，正则层不可
        # 判"——本轮复核：双语义可由**文件级** require/启动 API 守卫判定
        # （_JS_SERVER_CTX_RE，Node 服务端框架标准名，无第二语义），不是
        # 不可判。实测 nodegoat 全仓"console.非字面量参数"仅 1~2 行，
        # "噪声不可控"的担忧不成立（那是 res.render 泛形态的问题，不是
        # console 的问题）。浏览器端文件（无服务端上下文）整类豁免。
        rules.append(_Rule(
            name="log_injection_console",
            patterns=[],
            match_func=lambda code: (bool(_JS_SERVER_CTX_RE.search(code))
                                     and self._console_log_hit_line(code) > 0),
            line_func=lambda code: self._console_log_hit_line(code),
            category="vuln",
        ))

        # --- 弱口令策略正则（2026-08-31 第八波，CWE-521）---
        # 详见 _weak_pw_regex_line。pass/pwd 词根标识符 ← `.{1,N}` 任意字符
        # 有界量词——最直白的弱策略声明，语言级事实，无样本拼写。
        rules.append(_Rule(
            name="weak_password_policy_regex",
            patterns=[],
            match_func=lambda code: self._weak_pw_regex_line(code) > 0,
            line_func=lambda code: self._weak_pw_regex_line(code),
            category="vuln",
        ))

        # --- 敏感字段明文落库·参数直赋形态（2026-08-31 第八波，CWE-312）---
        # 详见 _cleartext_field_hit_line。与 cleartext_sensitive_storage
        # （请求直取形态）互补：DAO/helper 层的敏感字段以**函数形参**进入
        # （nodegoat profile-dao L62 实锤：updateUser = (..., ssn, ...) →
        # user.ssn = ssn; → users.update(...)）。password 不入本表——密码
        # 字段在登录流程安全样本（safe_11）同形，文件级 AND 区分不了
        # "哈希后入库"与"明文入库"，做成 finding 会误伤；CWE-256 归
        # blind_spots 提醒层。
        rules.append(_Rule(
            name="cleartext_sensitive_storage_field",
            patterns=[],
            match_func=lambda code: self._cleartext_field_hit_line(code) > 0,
            line_func=lambda code: self._cleartext_field_hit_line(code),
            category="vuln",
        ))

        return rules

    # ------------------------------------------------------------------
    # 2026-08-31 第五波：核心注入族行号定位（内联构造 + 1 跳变量传入）
    # ------------------------------------------------------------------
    def _split_first_arg(self, region: str) -> tuple[str, str]:
        """把参数区切分为「首个顶层参数」与「其余部分」。

        按第一个**顶层**逗号切分：引号内、括号内的逗号不计（如
        `execute("a,b", (x,))` 的首参是完整 SQL 字面量而非 "a）。

        顶层逗号的有无是参数化查询的结构性判据——DB-API 的安全写法正是
        把查询文本与参数**分列两个实参**（execute(sql, params)）；而注入
        形态的查询文本自身由输入构造。
        """
        depth = 0
        in_str: Optional[str] = None
        escaped = False
        for i, ch in enumerate(region):
            if in_str is not None:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == in_str:
                    in_str = None
                continue
            if ch in ("'", '"'):
                in_str = ch
            elif ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == "," and depth == 0:
                return region[:i], region[i + 1:]
        return region, ""

    def _assigned_expr(self, code: str, var: str) -> Optional[str]:
        """返回变量最后一次赋值的右侧表达式（1 跳解析，供 sink 参数消解用）。

        只取行首形态（`^\\s*var = ...`）以避开 `a == b`、字典键 `{'v': 1}`
        等伪赋值；多处赋值取最后一处（覆盖 `x = f(...)` 后又被覆盖的场景）。
        """
        expr: Optional[str] = None
        for m in re.finditer(
                rf"(?m)^[ \t]*{re.escape(var)}[ \t]*=[^=](.*)$", code):
            expr = m.group(1)
        return expr

    def _assigned_expr_line(self, code: str, var: str) -> tuple[Optional[str], int]:
        """`_assigned_expr` 的行号版：返回 (表达式, 行号)，未找到返回 (None, 0)。"""
        expr: Optional[str] = None
        line = 0
        for m in re.finditer(
                rf"(?m)^[ \t]*{re.escape(var)}[ \t]*=[^=](.*)$", code):
            expr = m.group(1)
            line = code.count("\n", 0, m.start()) + 1
        return expr, line

    def _is_constant_var(self, code: str, name: str) -> bool:
        """变量是否解析为编译期常量（拼接常量不构成注入面）。

        `name = "admin"` 这类常量拼接进 SQL/命令是硬编码而非外部输入
        （noise_03 实测：把常量当变量会误报）。未在本文件赋值（如函数形参）
        按非常量处理——保守取向，宁可保留候选交 LLM 复核。
        """
        expr = self._assigned_expr(code, name)
        if expr is None:
            return False
        return bool(re.fullmatch(
            r"(['\"]).*\1|[\d.]+|True|False|None|null", expr.strip()))

    def _expr_is_constructed(self, expr: str, var_res, code: str = "") -> bool:
        """表达式是否由「字符串构造」而来（注入候选的必要形态）。

        五种构造形态（均为主流语言的字符串构造标准写法）：
        ① f-string 前缀；② `%` 格式化；③ `.format(`；④ `+` 拼接且含变量；
        ⑤ JS 模板字符串 `` `${x}` ``（与 f-string 对等的内插构造）。
        另含「直接引用输入变量/构造变量」——整串来自外部（如 execute(user_sql)）。

        两条精度约束（均由 87 段安全对照样本实锤，非臆测）：
        · 变量引用匹配**先剥离字符串字面量**（共享原语 `_strip_str_literals`）：
          SQL 文本里的列名与输入变量同名时（safe_01 的 `WHERE username = ?` 与
          变量 username）不能算变量引用。
        · 拼接标识符须非常量：`"..." + name`（name="admin"）是硬编码拼接而非
          外部输入（noise_03）。

        参数化查询的查询文本是**含占位符的纯字面量**，五种形态全不匹配，
        天然豁免（safe_01/05/07、noise_01/02/05 实测均不误报）。
        """
        if not expr:
            return False
        if (re.search(r"\bf['\"]", expr) or re.search(r"\.format\s*\(", expr)
                or re.search(r"`[^`]*\$\{", expr)):
            return True
        if re.search(r"['\"][^'\"]*['\"]\s*%", expr):
            return True
        # 以下标识符相关判定一律在「剥离字符串字面量」后的文本上进行：
        # SQL/HTML 文本里的单词（FROM、WHERE、列名）是文本而非标识符引用，
        # 不剥离会把它们当成拼接进来的变量（noise_03 实测误报）。
        bare = _strip_str_literals(expr)
        if re.search(r"\+\s*\w|\w\s*\+", bare):
            # 拼接号作用于标识符，且该标识符不是编译期常量（noise_03 约束）
            for ident in re.findall(r"[+\s]\s*([A-Za-z_$][\w$]*)", bare):
                if not (code and self._is_constant_var(code, ident)):
                    return True
        return any(r.search(bare) for r in var_res)

    def _sqli_hit_line(self, code: str) -> int:
        """SQL 注入行号定位（1-based；0=未命中）。

        覆盖两类此前漏判的形态（87 段实测弃权 5 段全属此类）：
        ① 内联构造：`execute("..." + var)` / `execute(f"...{v}")` / 跨行拼接；
        ② 1 跳传入：`query = "..." + var` 后 `execute(query)`——即把构造后的
           变量作为查询文本传入（真实代码的主流写法，旧规则只认内联字面量）。

        排除参数化查询：查询文本未构造 + 另有参数元组 → 走参数绑定，是
        DB-API/E JDBC 的标准安全写法，不构成注入。

        行号口径：1 跳形态报**查询文本的构造行**而非 sink 行——漏洞主体是
        「把输入拼进语句」这一步，sink 只是执行点；且审计标准答案（VFlask
        manifest CWE-89@261）与真实漏洞报告均按构造行标注。内联形态构造与
        sink 同行，两种口径自然一致。
        """
        if not _SQL_CTX_RE.search(code or ""):
            return 0
        constructed = self._constructed_var_names(code)
        inputs = self._input_var_names(code)
        var_res = [re.compile(rf"\b{re.escape(v)}\b") for v in (constructed | inputs)]
        best = 0
        for start, end in self._call_arg_regions_with_pos(code, "sql_execute"):
            first, _rest = self._split_first_arg(code[start:end])
            ln = code.count("\n", 0, start) + 1
            # 首参是裸变量 → 消解其赋值表达式，判断查询文本是否经构造
            bare = re.fullmatch(r"\s*([A-Za-z_$][\w$.]*)\s*", first)
            if bare:
                expr, assign_ln = self._assigned_expr_line(code, bare.group(1))
                if expr is not None:
                    first, ln = expr, (assign_ln or ln)
            if self._expr_is_constructed(first, var_res, code):
                if best == 0 or ln < best:
                    best = ln
        return best

    def _cmd_hit_line(self, code: str) -> int:
        """命令注入行号定位（1-based；0=未命中）。

        补齐旧规则 cmd_subprocess_shell_concat 只认 `+` 拼接的形态缺口：
        ① Python f-string（`subprocess.run(f"ping {host}", shell=True)`）；
        ② JS 模板字符串（`` exec(`gzip ${file}`) ``，child_process 引入为守卫）。
        subprocess 仍要求 shell=True——列表传参形态由 subprocess_list_form
        安全规则判定，shell=True 才使字符串经 shell 解析。

        豁免：参数经 shell 引号转义（shlex.quote/escapeshellarg）后拼接是
        命令注入的标准修复（safe_08 实测），_CMD_SAFE_RE 命中即不报。
        """
        if _CMD_SAFE_RE.search(_code_wo_comment_lines(code or "")):
            return 0
        constructed = self._constructed_var_names(code)
        inputs = self._input_var_names(code)
        var_res = [re.compile(rf"\b{re.escape(v)}\b") for v in (constructed | inputs)]
        keys = ["subprocess", "os_system"]
        if _JS_CHILDPROCESS_RE.search(code or ""):
            keys.append("cmd_exec")
        best = 0
        for key in keys:
            for start, end in self._call_arg_regions_with_pos(code, key):
                region = code[start:end]
                if key == "subprocess" and not re.search(
                        r"shell\s*=\s*True", region, re.IGNORECASE):
                    continue
                hit = (
                    re.search(r"\bf['\"]", region) is not None          # Python f-string
                    or re.search(r"`[^`]*\$\{", region) is not None     # JS 模板字符串
                    or self._expr_is_constructed(region, var_res, code)
                )
                if not hit:
                    continue
                ln = code.count("\n", 0, start) + 1
                if best == 0 or ln < best:
                    best = ln
        return best

    def _xss_hit_line(self, code: str) -> int:
        """XSS 行号定位（1-based；0=未命中）。

        三要素（缺一不可，均为 XSS 的构成性事实）：
        ① 字符串字面量含 HTML 标签 → 该串是 HTML 片段而非普通文本；
        ② 片段中拼接/插值了外部输入 → 未转义注入点；
        ③ 结果被输出到响应（return / echo / res.send 等）→ 到达浏览器。
        仅构造不输出不构成 XSS（中间变量仍可能被转义），故③是必要项。

        豁免两类安全写法（87 段安全对照样本实锤）：
        · 输出前转义（html.escape / autoescape 等）：safe_06、safe_15；
        · 模板占位符 `{{ x }}` 不是字符串插值——它由模板引擎渲染，配合
          autoescape 不构成注入，不能与 f-string/`+` 拼接同等对待。
        """
        if not _HTML_TAG_RE.search(code or ""):
            return 0
        if not _OUTPUT_SINK_RE.search(code or ""):
            return 0
        if _XSS_SAFE_RE.search(_code_wo_comment_lines(code or "")):
            return 0
        constructed = self._constructed_var_names(code)
        inputs = self._input_var_names(code)
        var_res = [re.compile(rf"\b{re.escape(v)}\b") for v in (constructed | inputs)]
        best = 0
        for i, line in enumerate((code or "").splitlines()):
            if not _HTML_TAG_RE.search(line):
                continue
            # 该行需同时含「输入」与「字符串构造」：输入进入 HTML 片段
            has_input = (_INPUT_SRC_RE.search(line)
                         or any(r.search(line) for r in var_res))
            if not has_input:
                continue
            # 剥离模板占位符后再判构造：`{{ x }}` 由模板引擎渲染，不是字符串插值
            probe = re.sub(r"\{\{.*?\}\}|\{%-?.*?-?%\}", " ", line)
            if not (re.search(r"\bf['\"]", probe)
                    or re.search(r"\+\s*\w|\w\s*\+", probe)
                    or re.search(r"['\"]\s*\.\s*\$", probe)  # PHP 字符串连接符
                    or re.search(r"\$\{\s*\w+\s*\}", probe)):  # JS 模板字符串
                continue
            if best == 0:
                best = i + 1
        return best

    def _nosql_where_hit_line(self, code: str) -> int:
        """NoSQL $where 注入行号定位（1-based；0=未命中）。

        同行 AND 条件：`$where` 操作符 + 用户输入进入 JS 执行串的痕迹
        （模板 `${}` 或 引号包裹的字符串拼接）。先剥 /* */ 块注释（占位
        保行号）再逐行判——NodeGoat allocations-dao 实锤：官方注释掉的
        修复示例（L64-76 块注释内）恰好含 $where+插值形态，不剥块注释
        会命中注释行 L73 而漏真 sink L78。行内 // 与整行注释同样排除。
        """
        code = re.sub(
            r"/\*.*?\*/",
            lambda m: "\n" * m.group(0).count("\n"),
            code or "",
            flags=re.DOTALL,
        )
        for i, line in enumerate(code.splitlines(), 1):
            if "$where" not in line:
                continue
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#"):
                continue
            # 剥行内注释（// 对 JS；# 只在行首才可能是注释，已由上面排除）
            probe = line.split("//", 1)[0]
            if "$where" not in probe:
                continue
            after = probe[probe.index("$where"):]
            if "${" in after or re.search(r"['\"]\s*\+|\+\s*['\"]?\s*\w", after):
                return i
        return 0

    def _ssrf_hit_line(self, code: str) -> int:
        """SSRF 行号定位（1-based；0=未命中）。

        漏洞形态：URL 由外部输入决定并交给服务端 HTTP 客户端发起请求——
        攻击者借服务端身份访问内网/元数据服务（169.254.169.254 等）。
        安全写法是域名白名单校验，白名单形态（allowlist/startswith）
        与本规则互斥，命中即不报。
        """
        if _SSRF_SAFE_RE.search(_code_wo_comment_lines(code or "")):
            return 0
        constructed = self._constructed_var_names(code)
        inputs = self._input_var_names(code)
        var_res = [re.compile(rf"\b{re.escape(v)}\b") for v in (constructed | inputs)]
        best = 0
        for start, end in self._call_arg_regions_with_pos(code, "http_client"):
            first, _rest = self._split_first_arg(code[start:end])
            bare = re.fullmatch(r"\s*([A-Za-z_$][\w$.]*)\s*", first)
            if bare:
                first = self._assigned_expr(code, bare.group(1)) or first
            if _INPUT_SRC_RE.search(first) or any(r.search(first) for r in var_res):
                ln = code.count("\n", 0, start) + 1
                if best == 0 or ln < best:
                    best = ln
        return best

    def _timing_unsafe_compare(self, code: str) -> bool:
        """输入派生的凭证/签名变量参与 ==/!= 比较（时序侧信道候选）。

        排除：比较行含 session 取值（`token != session.get("csrf_token")` 是
        CSRF 校验的标准实现，会话内令牌比对不构成有告警价值的时序侧信道）。
        """
        return self._timing_hit_line(code) > 0

    # ------------------------------------------------------------------
    # 2026-08-31 第八波：盲区层收口（行号定位与匹配同源，命中行 = 漏洞主体行）
    # ------------------------------------------------------------------
    @staticmethod
    def _strip_block_comments_keep_lines(code: str) -> str:
        """剥 /* */ 块注释，用等量换行占位保行号（§9.20 教训②的共用实现）。

        教学仓库把"官方修复代码"整块注释在旁（NodeGoat 风格），形态与漏洞
        完全一致——不剥块注释会命中注释行。已在 nosql_where / 本波三条规则
        统一使用；新的行级规则默认先走这里再逐行判。
        """
        return re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"),
                      code or "", flags=re.DOTALL)

    def _redos_hit_line(self, code: str) -> int:
        """嵌套量词正则（ReDoS，CWE-1333）行号定位（1-based；0=未命中）。

        结构性特征：正则字面量内部出现「分组内含量词、分组后紧跟量词」
        （/([0-9]+)+/、/(a|aa)*$/ 形态的前者）——回溯次数随输入长度指数
        增长。裸算术 (a+b)*c 同形但不在正则字面量内，不触发（量词正则只在
        字面量跨度内搜索）。
        AND 条件（文件级）：存在动态求用（.test/.match/.exec/re.match…，
        实参为标识符）——只写不用的正则没有 ReDoS 攻击面。
        注释处理：剥块注释（保行号）+ 整行注释；行内注释里的正则不剥
        （已剥会在 URL // 形态误伤，属已知边界）。
        """
        if not _REDOS_DYNAMIC_USE_RE.search(_code_wo_comment_lines(code or "")):
            return 0
        code = self._strip_block_comments_keep_lines(code)
        for i, line in enumerate(code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith(("//", "#", "*", "/*", "--")):
                continue
            # 正则字面量跨度：首字符非 *（防 // 与 /*），支持 \/ 转义
            for m in re.finditer(r"/(?![/*])(?:[^/\\\n]|\\.)+/[gimsuy]*", line):
                if _REDOS_NESTED_RE.search(m.group(0)):
                    return i
        return 0

    def _console_log_hit_line(self, code: str) -> int:
        """服务端 console.* 日志注入行号定位（1-based；0=未命中）。

        调用前提（match_func 已判）：_JS_SERVER_CTX_RE 命中——console.* 的
        CWE-117 语义只在服务端成立。行级条件：console.(log|error|warn|
        info|debug) 的参数区在剥离字符串字面量后**仍含标识符**——注入面是
        变量的值（含 ${} 插值，共享原语保留），纯字面量日志无注入面。
        """
        code = self._strip_block_comments_keep_lines(code)
        for i, line in enumerate(code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith(("//", "#", "*", "/*", "--")):
                continue
            m = re.search(r"\bconsole\.(?:log|error|warn|info|debug)\s*\(", line)
            if not m:
                continue
            # 调用整体落在行内注释后半段的形态（前置位置含 //）
            probe = line[: m.start()]
            if "//" in probe:
                continue
            bare = _strip_str_literals(line[m.end():])
            if re.search(r"[A-Za-z_$][\w$]*", bare):
                return i
        return 0

    def _weak_pw_regex_line(self, code: str) -> int:
        """弱口令策略正则（CWE-521）行号定位（1-based；0=未命中）。

        行级 AND：pass/pwd 词根标识符赋值（PASS_RE = / PASSWORD_RE = …）
        + `.{1,N}` 任意字符有界量词出现在 /.../ 字面量或引号字符串内。
        `[\S]+@[\S]+` 这类邮箱正则无数值有界量词，天然不命中。
        """
        code = self._strip_block_comments_keep_lines(code)
        for i, line in enumerate(code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith(("//", "#", "*", "/*", "--")):
                continue
            if _WEAK_PW_IDENT_RE.search(line) and _WEAK_PW_ANY_QUANT_RE.search(line):
                return i
        return 0

    def _cleartext_field_hit_line(self, code: str) -> int:
        """敏感字段「参数直赋」落库行号定位（1-based；0=未命中）。

        三重 AND（精度主门是前两个，上下文是第二重保险）：
          ① Mongo 持久化上下文（_MONGO_PERSIST_CTX_RE：db.collection( 等
             专有 API）——**不复用 _NOSQL_CTX_RE**，避免连带放宽
             nosql_query_injection 触发面（见该常量处注释）；
          ② 文档持久化调用（_MONGO_PERSIST_CALL_RE：update/insert/save，
             对象名排除 cipher/decipher——profile-dao 的 cipher.update(
             是加密工具函数，不能当持久化证据）；
          ③ `obj.<敏感字段> = 裸标识符`（_SENSITIVE_FIELD_ASSIGN_RE，右侧
             非函数调用——encrypt(ssn) 的已加密写法天然豁免）。
        """
        if not (_MONGO_PERSIST_CTX_RE.search(code or "")
                and _MONGO_PERSIST_CALL_RE.search(code or "")):
            return 0
        code2 = self._strip_block_comments_keep_lines(code)
        for i, line in enumerate(code2.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith(("//", "#", "*", "/*", "--")):
                continue
            if _SENSITIVE_FIELD_ASSIGN_RE.search(line):
                return i
        return 0


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

    # ------------------------------------------------------------------
    # 长尾注入族共用辅助（2026-08-31 第四波：XXE/LDAP/NoSQL/XPath/OGNL）
    # ------------------------------------------------------------------
    def _constructed_var_names(self, code: str) -> set[str]:
        """由字符串构造表达式生成（且引用外部输入）的变量名（1 跳）。

            filter_str = f"(uid={username})"          # f-string 内插
            xpath = f"//user[username='{u}']"         # f-string
            errorMessage = "Error: " + contentType    # + 拼接

        注入类漏洞的主流写法是「查询/表达式字符串由动态构造而成」：f-string、
        JS 模板串、`+` 拼接、`%` 格式化、`.format()`。构造材料引用外部输入
        （直接或经 1 跳输入变量）→ 该变量是注入源候选。字面量常量（safe_16 的
        `filter_str = "(uid=%s)"` 配参数化传参）不收集 → 安全写法天然豁免。
        收集结果只被注入族 sink 的参数区引用检查消费，不单独构成命中。

        精度约束（与 _expr_is_constructed 同源，均实锤于安全对照样本）：
        输入引用匹配在**剥离字符串字面量后**的文本上进行（共享原语
        _strip_str_literals）——SQL 文本里的列名与输入变量同名不算引用。
        """
        names: set[str] = set()
        input_vars = self._input_var_names(code)
        var_res = [re.compile(rf"\b{re.escape(v)}\b") for v in input_vars]
        # f-string 构造（f 前缀即动态构造；是否引用输入不限定——f-string 变量
        # 传给注入 sink 本身就构成候选，输入关联由 sink 参数区判断兜底）
        for m in re.finditer(r"(\w+)\s*=\s*f['\"]", code, re.IGNORECASE):
            names.add(m.group(1))
        # JS 模板字符串构造（backtick + ${} 内插，JS 的 f-string 对等形态）
        for m in re.finditer(r"(\w+)\s*=\s*`[^`]*\$\{", code):
            names.add(m.group(1))
        # `+` 拼接 / `%` 格式化 / .format 构造，且右侧引用输入源或输入变量
        for m in re.finditer(r"(\w+)\s*=\s*([^\n=;]+)", code):
            rhs = m.group(2)
            if not re.search(r"\+|%\s*\w|\.format\s*\(", rhs):
                continue
            bare = _strip_str_literals(rhs)
            if (_INPUT_SRC_RE.search(bare)
                    or any(r.search(bare) for r in var_res)):
                names.add(m.group(1))
        return names

    def _sink_hits_input_vars(self, code: str, sink_keys) -> bool:
        """任一 sink 的参数区出现外部输入：直接出现输入源标记，或引用输入
        变量 / 构造变量（_input_var_names ∪ _constructed_var_names）。"""
        vars_ = self._input_var_names(code) | self._constructed_var_names(code)
        return (self._sink_arg_has_input(code, sink_keys)
                or self._sink_arg_refs_vars(code, sink_keys, vars_))

    def _sink_hits_constructed(self, code: str, sink_keys) -> bool:
        """任一 sink 的参数区出现「构造式」输入（命中判定，与行号同源）。"""
        return self._constructed_hit_line(code, sink_keys) > 0

    def _constructed_hit_line(self, code: str, sink_keys) -> int:
        """构造式注入的行号定位（1-based；0=未命中）。

        注入族的专用判定（比 _sink_hits_input_vars 收窄）：

        ① 参数区出现「输入参与字符串构造」形态：输入源标记与拼接号（+）共存
           （`(uid=" + request.args.get("u")` 内联拼接）；
        ② 参数区出现 f-string 前缀（`f"(uid={u})"` 内联构造）；
        ③ 参数区引用**构造式变量**（f-string/拼接/格式化的 1 跳产物）。

        不含「输入源裸出现」通道：LDAP 参数化查询把输入作为**独立参数**传入
        （`search_s(base, scope, filter_str, [username])`），若裸出现也算命中，
        参数化安全写法会被误报（safe_16 实锤）；只有 filter 字符串本身经构造
        才构成注入候选。
        """
        vars_ = self._constructed_var_names(code)
        var_res = [re.compile(rf"\b{re.escape(v)}\b") for v in vars_]
        best = 0
        for key in sink_keys:
            if key not in _CALL_START_PATTERNS:
                continue
            for region_start, region_end in self._call_arg_regions_with_pos(code, key):
                region = code[region_start:region_end]
                hit = ((re.search(r"\+", region) and _INPUT_SRC_RE.search(region))
                       or re.search(r"\bf['\"]", region) is not None
                       or re.search(r"`[^`]*\$\{", region) is not None
                       or any(r.search(region) for r in var_res))
                if hit:
                    ln = code.count("\n", 0, region_start) + 1
                    if best == 0 or ln < best:
                        best = ln
        return best

    def _sink_first_hit_line(self, code: str, sink_keys) -> int:
        """注入族规则的行号定位（1-based；0=未命中）：首个参数区含输入的 sink 调用行。

        与命中判定**同源**（遍历同一批 sink key、同一输入变量集合），避免
        "命中但行号指错"（2026-08-30 行号同源纪律）。
        """
        vars_ = self._input_var_names(code) | self._constructed_var_names(code)
        var_res = [re.compile(rf"\b{re.escape(v)}\b") for v in vars_]
        best = 0
        for key in sink_keys:
            if key not in _CALL_START_PATTERNS:
                continue
            for region_m in self._call_arg_regions_with_pos(code, key):
                start = region_m
                if (_INPUT_SRC_RE.search(code[start[0]:start[1]])
                        or any(r.search(code[start[0]:start[1]]) for r in var_res)):
                    ln = code.count("\n", 0, start[0]) + 1
                    if best == 0 or ln < best:
                        best = ln
        return best

    def _call_arg_regions_with_pos(self, code: str, pattern_key: str):
        """_call_arg_regions 的位置版：yield (start, end) 参数区绝对位置。"""
        for m in _CALL_START_PATTERNS[pattern_key].finditer(code):
            depth = 1
            in_str: Optional[str] = None
            escaped = False
            j = m.end()
            start = j
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
                j += 1
            end = j if j < len(code) else len(code)
            yield (start, end)

    def _php_loose_compare_line(self, code: str) -> int:
        """PHP 松散比较（CWE-843 类型混淆）行号定位（1-based；0=未命中）。

        漏洞形态（PHP 语言特性级事实）：`==`/`!=` 松散比较在凭证校验场景
        会被 magic-hash 绕过（"0e123" == "0e456" 均(int)0 为真）——正确写法
        是 `===`/`!==` 强比较或 hash_equals。触发条件（缺一不可）：
        ① 文件含 PHP 超全局输入（PHP 上下文 + 输入关联双保证）；
        ② 行内存在凭证语义词（_SECRET_COMPARE_NAME_RE，普通业务字段不报）；
        ③ 行内是弱比较 `==`/`!=`（`===`/`!==` 是修复写法，不命中）；
        ④ 比较至少一侧连接输入（行内超全局，或行内变量是超全局 1 跳赋值目标）；
        ⑤ 两侧均直接取自超全局 → 字段一致性校验（确认密码类），排除。
        """
        if not _PHP_SUPERGLOBAL_RE.search(code or ""):
            return 0
        php_input_vars = set(re.findall(r"\$(\w+)\s*=\s*\$_", code or ""))
        best = 0
        for i, line in enumerate((code or "").splitlines()):
            if not re.search(r"(?<![=!<>])==(?!=)|(?<![=!])!=(?!=)", line):
                continue
            if not _SECRET_COMPARE_NAME_RE.search(line):
                continue
            # 侧输入关联：行内超全局，或行内出现超全局 1 跳变量
            lhs, _, rhs = line.partition("==") if "==" in line else line.partition("!=")
            both = f"{lhs} {rhs}"
            # 两侧均直接取自超全局 → 字段一致性校验（确认密码类，攻击者两侧
            # 都能控制，不泄露服务端秘密）。注意不能复用 _both_sides_external：
            # 其 _INPUT_SRC_RE 认 `req\.`/`.POST` 前缀，PHP 的 `$_POST` 不匹配
            if (_PHP_SUPERGLOBAL_RE.search(lhs)
                    and _PHP_SUPERGLOBAL_RE.search(rhs)):
                continue
            hits_input = (_PHP_SUPERGLOBAL_RE.search(both) is not None
                          or any(re.search(rf"\$\b{re.escape(v)}\b", both)
                                 for v in php_input_vars))
            if not hits_input:
                continue
            if self._both_sides_external(line):
                continue
            if best == 0:
                best = i + 1
        return best

    def _mongo_find_hit(self, code: str) -> bool:
        """NoSQL 查询文档含输入（调用方已保证文件含 MongoDB 上下文特征）。"""
        return self._mongo_find_hit_line(code) > 0

    def _mongo_find_hit_line(self, code: str) -> int:
        """NoSQL 注入行号定位（1-based；0=未命中）。

        触发：find/find_one/findOne sink 的参数区是查询文档（含 `{` 字面量，
        Mongo 查询的标准形态）且出现输入（输入源标记直接出现，或引用输入
        变量）。Array.prototype.find 的回调形态（`arr.find(x => ...)`）参数区
        无 `{` 开头的查询文档语义且无输入 → 不命中。
        豁免：值经类型强制（`str(u)` / `int(u)`）后传入——强制类型使 `$gt`
        等操作符注入失效，是 MongoDB 官方推荐的安全写法（typical_25 的
        fix_idea 即此形态）。
        """
        vars_ = self._input_var_names(code) | self._constructed_var_names(code)
        var_res = [re.compile(rf"\b{re.escape(v)}\b") for v in vars_]
        best = 0
        for region_start, region_end in self._call_arg_regions_with_pos(
                code, "mongo_find"):
            region = code[region_start:region_end]
            if "{" not in region:
                continue
            if not (_INPUT_SRC_RE.search(region)
                    or any(r.search(region) for r in var_res)):
                continue
            # 类型强制豁免：清除所有 cast 形态（str(var)/int(var)/float(var)）
            # 后再查——仍有裸输入引用才算注入
            stripped = re.sub(
                r"\b(?:str|int|float)\s*\(\s*(?:\w+\s*(?:\+\s*\w+\s*)*)\)",
                "", region)
            if _INPUT_SRC_RE.search(stripped) or any(
                    r.search(stripped) for r in var_res):
                ln = code.count("\n", 0, region_start) + 1
                if best == 0 or ln < best:
                    best = ln
        return best

    def _mass_assignment_hit_line(self, code: str) -> int:
        """Mass Assignment（CWE-915）行号定位（1-based；0=未命中）。

        漏洞形态（Python 语言级事实）：请求体 dict 的键值对经 `setattr()`
        动态写入 ORM 对象——键由请求控制，`is_admin` 等敏感字段可被越权写入：

            data = request.get_json()
            for key, value in data.items():
                setattr(user, key, value)

        触发（AND）：① 存在 setattr 调用；② 存在 dict 键值遍历
        （`for k, v in X.items()`）且遍历对象是输入变量（1 跳）；
        ③ 文件无字段白名单安全特征（_MASS_ASSIGN_SAFE_RE）。
        Django form / DRF serializer 等框架过滤形态已在安全特征表排除。
        """
        if _MASS_ASSIGN_SAFE_RE.search(_code_wo_comment_lines(code or "")):
            return 0
        input_vars = self._input_var_names(code)
        # 收集「可迭代对象来自输入」的循环解构变量（key/value）——setattr
        # 参数区引用的是解构变量而非可迭代对象本身
        loop_vars: set[str] = set()
        for m in re.finditer(
                r"for\s+(\w+)\s*,\s*(\w+)\s+in\s+(\w+)\s*\.\s*items\s*\(\s*\)",
                code, re.IGNORECASE):
            it = m.group(3)
            if it in input_vars or _INPUT_SRC_RE.search(
                    code[max(0, m.start() - 200): m.end()]):
                loop_vars.add(m.group(1))
                loop_vars.add(m.group(2))
        if not loop_vars:
            return 0
        best = 0
        for region_start, region_end in self._call_arg_regions_with_pos(
                code, "setattr_call"):
            region = code[region_start:region_end]
            if any(re.search(rf"\b{re.escape(v)}\b", region) for v in loop_vars):
                ln = code.count("\n", 0, region_start) + 1
                if best == 0 or ln < best:
                    best = ln
        return best

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
        # --- 2026-08-31 NodeGoat 审计补用例（第七波）---
        ("NoSQL $where(漏洞,JS模板插值)",
         "allocationsCol.find({ $where: `this.userId == ${uid} && this.stocks > '${t}'` });",
         True, "high"),
        ("NoSQL $where(漏洞,Python拼接)",
         'col.find({"$where": "this.stocks > " + user_input})',
         True, "high"),
        ("NoSQL $where(安全,常量串)",
         'col.find({ $where: "this.userId == 42" });',
         None, "low"),
        ("NoSQL $where(注释示例不误触发)",
         "if (t) {\n"
         "    /*\n"
         "    // fix example: return {$where: `x > ${parsed}`};\n"
         "    */\n"
         "    return { $where: `this.x > '${t}'` };\n"
         "}",
         True, "high"),
        ("autoescape关闭(漏洞,swig配置)",
         'swig.setDefaults({\n    autoescape: false\n});',
         True, "high"),
        ("autoescape开启(安全)",
         'app.jinja_env.autoescape = True',
         None, "low"),
        ("needle SSRF(漏洞)",
         'const url = req.query.url + req.query.symbol;\nneedle.get(url, (e, r) => {});',
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

        # --- 2026-08-31 第八波：盲区层收口（正样本 = NodeGoat 审计实锤形态；
        # 负样本 = 同名 API 的常见无漏洞语义，负样本集须穷举 API 常见语义）---
        # ReDoS：嵌套量词 + 动态求用；负样本覆盖"算术括号"与"单量词分组"
        ("ReDoS嵌套量词(漏洞,JS字面量+test)",
         'const regexPattern = /([0-9]+)+#/;\n'
         'const ok = regexPattern.test(bankRouting);',
         True, "high"),
        ("ReDoS(不触发,算术括号非正则)",
         'const n = (a + b) * 2;',
         None, "low"),
        ("ReDoS(不触发,单量词分组)",
         'const re = /^([0-9]+)#/;\n'
         'ok = re.test(v);',
         None, "low"),
        # 服务端 console 日志注入：文件级服务端门 + 剥字符串后含变量
        ("console日志注入(漏洞,req.session门+变量参数)",
         'const express = require("express");\n'
         'console.log("Error: attempt to login with invalid user: ", userName);',
         True, "high"),
        ("console日志注入(漏洞,res.render惯用法门)",
         'handler = (req, res) => {\n'
         '  console.log(`user agent: ${req.headers["user-agent"]}`);\n'
         '  res.render("index");\n'
         '};',
         True, "high"),
        ("console(不触发,浏览器端无服务端门)",
         'console.log("user clicked", evt.target);',
         None, "low"),
        ("console(不触发,服务端但纯字面量参数)",
         'const express = require("express");\n'
         'console.log("server started on port 4000");',
         None, "low"),
        # 弱口令策略：pass 词根 + .{1,N} 有界任意字符量词
        ("弱口令策略(漏洞,PASS_RE={1,20})",
         'const PASS_RE = /^.{1,20}$/;',
         True, "high"),
        ("弱口令策略(不触发,邮箱正则无数值有界量词)",
         'const EMAIL_RE = /^[\\S]+@[^@]+\\.[a-z]{2,}$/;',
         None, "low"),
        ("弱口令策略(不触发,非pass词根)",
         'const LIMIT_RE = /^.{1,50}$/;',
         None, "low"),
        # 312 参数直赋落库：mongo 上下文 + 持久化调用 + 敏感字段裸标识符直赋
        ("312参数直赋(漏洞,ssn→users.update)",
         'const usersCol = db.collection("users");\n'
         'this.updateUser = (userId, ssn, callback) => {\n'
         '  user.ssn = ssn;\n'
         '  usersCol.update({userId: userId}, user);\n'
         '};',
         True, "high"),
        ("312参数直赋(不触发,cipher.update非持久化)",
         'const enc = `${cipher.update(data, "utf8", "hex")} ${cipher.final("hex")}`;',
         None, "low"),
        ("312参数直赋(不触发,已加密写法豁免)",
         'const col = db.collection("users");\n'
         'col.update({uid}, {ssn: encrypt(ssn)});\n',
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
    #
    # 2026-09-01 修复类别盲区：原实现只检查 pf.vuln_rules，而 secret 标记规则
    # 属**独立的第三类规则集**（_build_secret_markers）——hardcoded_secret_marker
    # 在 11 个漏洞段命中却长期无登记，自检却报告"缺失=无"。
    # 现按"所有会产出候选的规则集"合并检查（漏洞 + secret 标记；安全规则不产出
    # 候选、不需要 CWE 映射，故排除）。
    _audited_rules = list(getattr(pf, "vuln_rules", [])) + list(
        getattr(pf, "secret_markers", []) or [])
    missing = [r.name for r in _audited_rules if r.name not in PREFILTER_RULE_INFO]
    ok_meta = not missing
    all_pass = all_pass and ok_meta

    # 规则集重叠检测（2026-09-01，全规则泛化审计实锤的流程缺口）：
    # 第五波新增 sqli_constructed_query 时**未检查与既有规则的重叠**，导致
    # sqli_string_concat 在全部 4 种拼接形态上被完全覆盖 → 长期零命中的冗余
    # 规则（维护负担 + 未来双计风险）。新增规则必须确认不是既有规则的子集。
    # 检测方式：用一组标准形态样本，若规则 A 命中的样本集合是规则 B 的**子集**，
    # 则 A 被 B 覆盖 → 报警（不自动删，交人工判断是有意细化还是冗余）。
    _overlap_samples = [
        ("sql拼接变量", 'q = "SELECT * FROM u WHERE n=\'" + request.args.get("n") + "\'"\ncursor.execute(q)'),
        ("sql内联拼接", 'cursor.execute("SELECT * FROM u WHERE n=\'" + request.args.get("n") + "\'")'),
        ("sql f-string", 'cursor.execute(f"SELECT * FROM u WHERE n=\'{request.args.get(\'n\')}\'")'),
        ("sql 百分号", 'cursor.execute("SELECT * FROM u WHERE n=\'%s\'" % request.args.get("n"))'),
        ("sql format", 'cursor.execute("SELECT * FROM u WHERE n=\'{}\'".format(request.args.get("n")))'),
        ("cmd os.system", 'os.system("ping " + request.args.get("h"))'),
        ("cmd subprocess", 'subprocess.run("ping " + request.args.get("h"), shell=True)'),
        ("路径 open 拼接", 'open("/data/" + request.args.get("f"))'),
        ("路径 join", 'p = os.path.join("/data", request.args.get("f"))\nopen(p)'),
    ]
    _coverage: dict[str, set] = {}
    for _tag, _code in _overlap_samples:
        for _rl in set(pf.scan(_code, "python").matched_rules or []):
            _coverage.setdefault(_rl, set()).add(_tag)
    # 有意分层的白名单（家族规则 ⊇ 旧具体规则，2026-09-01 人工裁决保留）：
    # 家族规则负责类型归一与 1 跳形态，具体规则保留命中行精度并被
    # tool_smoke_test.py / 审计映射引用；候选合并按 (族, 行) 去重，无双计。
    _ACCEPTED_OVERLAPS = {
        ("sqli_fstring", "sqli_constructed_query"),
        ("sqli_percent_format", "sqli_constructed_query"),
        ("cmd_os_system_concat", "cmd_injection_shell"),
        ("cmd_subprocess_shell_concat", "cmd_injection_shell"),
    }
    _redundant = []
    for _a, _sa in _coverage.items():
        if not _sa:
            continue
        for _b, _sb in _coverage.items():
            if _a == _b or not _sb:
                continue
            if _sa < _sb and (_a, _b) not in _ACCEPTED_OVERLAPS:
                _redundant.append((_a, _b, sorted(_sa)))
    # 白名单内的重叠仅提示（防白名单失效后无人察觉），不计入失败。
    _accepted_seen = sorted(
        (_a, _b) for _a, _sa in _coverage.items() if _sa
        for _b, _sb in _coverage.items()
        if _a != _b and _sb and _sa < _sb and (_a, _b) in _ACCEPTED_OVERLAPS
    )
    ok_ovl = not _redundant
    print(f"[{'PASS' if ok_ovl else 'WARN'}] 规则集重叠检测: "
          f"{'无冗余' if ok_ovl else '被完全覆盖的规则=' + str([(a, '⊂', b) for a, b, _ in _redundant])}"
          f"（新增规则须确认不是既有规则的子集，防 sqli_string_concat 式冗余）")
    if _accepted_seen:
        print(f"[INFO] 已确认的有意分层: {[(a, '⊂', b) for a, b in _accepted_seen]}")

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
