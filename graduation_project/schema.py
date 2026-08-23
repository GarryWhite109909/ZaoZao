"""
统一输出 schema —— 全项目所有实验脚本必须使用此 schema 解析模型结论。

模型在分析代码漏洞后，必须在回答末尾输出一个 ```json``` 包裹的 JSON 对象，
字段定义见 VERDICT_SCHEMA。本模块提供：
- VERDICT_SCHEMA：字段定义字典（唯一来源）
- format_schema_for_prompt()：把 schema 渲染成 prompt 用的字段说明文本
- parse_verdict()：从模型原始输出中抽取 JSON 结论
- normalize_has_vulnerability()：把 has_vulnerability 字段归一化为 bool
- apply_safe_pattern_override()：后处理安全模式白名单兜底（仅消融对照用）
"""

import json
import re
from typing import Any, Optional


# ---------------------------------------------------------------------------
# 统一 schema 定义（全项目唯一来源）
# ---------------------------------------------------------------------------
VERDICT_SCHEMA: dict[str, str] = {
    "has_vulnerability": "bool, true 表示存在漏洞，false 表示未发现漏洞",
    "vulnerability_type": "str, 单个字符串（禁止拆成多个逗号分隔的值），格式如 'CWE-编号 漏洞名'，例如 'CWE-89 SQL Injection'、'CWE-79 Cross-site Scripting (XSS)'；无漏洞填 'none'",
    "risk_level": "str, Critical/High/Medium/Low；无漏洞填 'None'",
    "source": "str, 污染来源（用户可控输入点）。必须锚定行号，如 'line 12: request.args.get(\"id\")'；无漏洞填 'N/A'",
    "sink": "str, 危险函数或触发点。必须锚定行号，如 'line 18: cursor.execute(query)'；无漏洞填 'N/A'",
    "explanation": "str, 漏洞或安全现状说明（数据流/成因，用 -> 箭头描述）",
    "fix_suggestion": "str, 行号锚定的简短修复建议（单行、不含换行），格式如 'line 3: 应改为 ...' 或 '第 3 行：... 建议改为 ...'；指出应修改的具体行与改法即可，禁止输出完整代码/补丁/围栏代码块，行号必须是代码中真实存在的；无漏洞填 'no fix needed'",
}


def format_schema_for_prompt() -> str:
    """把 VERDICT_SCHEMA 渲染成 prompt 用的字段说明文本（多行字符串）。

    供所有 prompt 模板复用，确保 schema 说明全项目一致，避免重复维护。
    """
    lines = []
    for field, desc in VERDICT_SCHEMA.items():
        lines.append(f"   - {field}: {desc}")
    return "\n".join(lines)


def normalize_has_vulnerability(value: Any) -> Optional[bool]:
    """把 has_vulnerability 字段的各种形式归一化为 bool。

    支持 bool / "true"/"false" / "yes"/"no" / "1"/"0"；无法识别返回 None。
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "yes", "1"):
            return True
        if v in ("false", "no", "0"):
            return False
    return None


def _repair_consecutive_string_values(block: str) -> str:
    """修复模型把单个字符串字段输出成多个逗号分隔字符串的畸形 JSON。

    典型案例（DeepSeek-Coder-V2-Lite）：
        "vulnerability_type": "CWE-89", "SQL注入",
    修复为：
        "vulnerability_type": "CWE-89 SQL注入",

    仅对 VERDICT_SCHEMA 中的已知字段做修复，避免误伤合法 JSON。
    """
    known_keys = "|".join(re.escape(k) for k in VERDICT_SCHEMA.keys())
    # 匹配 "key": "val1", "val2", ... "valN",
    # 其中 key 是已知字段，val2..valN 是裸字符串（无冒号），即畸形特征
    pattern = re.compile(
        r'("(?:' + known_keys + r')"\s*:\s*)'
        r'"([^"]*)"'
        r'((?:\s*,\s*"[^"]*"\s*)+),'
    )

    def _merge(m: re.Match) -> str:
        prefix = m.group(1)
        first_val = m.group(2)
        rest_vals = re.findall(r'"([^"]*)"', m.group(3))
        all_vals = [v for v in [first_val] + rest_vals if v]
        return f'{prefix}"{" ".join(all_vals)}",'

    return pattern.sub(_merge, block)


def _try_parse_json(text: str) -> Optional[dict]:
    """尝试解析 JSON；失败时尝试修复常见畸形后重试。返回 None 表示无法解析。"""
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    # 修复 DeepSeek 风格的"连续字符串值"畸形
    repaired = _repair_consecutive_string_values(text)
    if repaired != text:
        try:
            parsed = json.loads(repaired)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    return None


def _extract_balanced_json(text: str, start: int) -> Optional[str]:
    """从 text[start] 处的 '{' 开始，提取一个花括号平衡的 JSON 片段。

    正确处理字符串内部的花括号（如 explanation 字段中含 "obj.method() {return}"）。
    返回提取的子串（含首尾花括号）；若 start 处不是 '{' 或无法平衡则返回 None。
    """
    if start >= len(text) or text[start] != '{':
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape:
            escape = False
            continue
        if ch == '\\' and in_string:
            escape = True
            continue
        if ch == '"' and not escape:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _extract_verdict_fallback(raw_output: str) -> dict:
    """字段级兜底提取：当完整 JSON 解析失败时，用正则逐字段提取。

    处理模型输出 JSON 字符串值中含未转义双引号（如 HTML 属性 class="..."）
    导致 json.loads 失败的情况。提取所有 schema 字段。
    同时处理 markdown 列表格式（如 `- **has_vulnerability**: false`）的输出。
    """
    verdict = {}

    # 提取 has_vulnerability（最关键字段）
    # 优先匹配 JSON 格式 "has_vulnerability": true/false
    m = re.search(r'"has_vulnerability"\s*:\s*(true|false|null|"[^"]*"|\d+)', raw_output, re.IGNORECASE)
    if not m:
        # 兜底匹配 markdown 格式：**has_vulnerability**: true/false
        # 形如 - **has_vulnerability**: false  或  **has_vulnerability**: false
        m = re.search(r'\*{0,2}has_vulnerability\*{0,2}\s*:\s*(true|false|null|none|"[^"]*"|\d+)',
                      raw_output, re.IGNORECASE)
    if m:
        val = m.group(1).strip().strip('"')
        if val.lower() in ("true", "1"):
            verdict["has_vulnerability"] = True
        elif val.lower() in ("false", "0"):
            verdict["has_vulnerability"] = False
        elif val.lower() in ("null", "none"):
            verdict["has_vulnerability"] = None

    # 提取 vulnerability_type（容忍未转义引号：取到下一个字段边界 " 或 }）
    m = re.search(r'"vulnerability_type"\s*:\s*"(.*?)(?=",\s*"|"\s*})', raw_output)
    if not m:
        # 兜底匹配 markdown 格式：**vulnerability_type**: none
        m = re.search(r'\*{0,2}vulnerability_type\*{0,2}\s*:\s*"?([^"\n*]+)"?(?=\s*\n|$)',
                      raw_output, re.IGNORECASE)
    if m:
        verdict["vulnerability_type"] = m.group(1).strip()

    # 提取 risk_level
    m = re.search(r'"risk_level"\s*:\s*"([^"]+)"', raw_output)
    if not m:
        # 兜底匹配 markdown 格式：**risk_level**: None
        m = re.search(r'\*{0,2}risk_level\*{0,2}\s*:\s*"?([^"\n*]+)"?(?=\s*\n|$)',
                      raw_output, re.IGNORECASE)
    if m:
        verdict["risk_level"] = m.group(1).strip()

    # 提取 source（新增：之前 fallback 缺少此字段）
    m = re.search(r'"source"\s*:\s*"(.*?)(?=",\s*"|"\s*})', raw_output)
    if not m:
        m = re.search(r'\*{0,2}source\*{0,2}\s*:\s*"?([^"\n*]+)"?(?=\s*\n|$)',
                      raw_output, re.IGNORECASE)
    if m:
        verdict["source"] = m.group(1).strip()

    # 提取 sink（新增：之前 fallback 缺少此字段）
    m = re.search(r'"sink"\s*:\s*"(.*?)(?=",\s*"|"\s*})', raw_output)
    if not m:
        m = re.search(r'\*{0,2}sink\*{0,2}\s*:\s*"?([^"\n*]+)"?(?=\s*\n|$)',
                      raw_output, re.IGNORECASE)
    if m:
        verdict["sink"] = m.group(1).strip()

    # 提取 explanation（新增：之前 fallback 缺少此字段）
    m = re.search(r'"explanation"\s*:\s*"(.*?)(?=",\s*"|"\s*})', raw_output)
    if not m:
        m = re.search(r'\*{0,2}explanation\*{0,2}\s*:\s*"?([^"\n*]+)"?(?=\s*\n|$)',
                      raw_output, re.IGNORECASE)
    if m:
        verdict["explanation"] = m.group(1).strip()

    # 提取 fix_suggestion（新增：之前 fallback 缺少此字段）
    m = re.search(r'"fix_suggestion"\s*:\s*"(.*?)(?=",\s*"|"\s*})', raw_output)
    if not m:
        m = re.search(r'\*{0,2}fix_suggestion\*{0,2}\s*:\s*"?([^"\n*]+)"?(?=\s*\n|$)',
                      raw_output, re.IGNORECASE)
    if m:
        verdict["fix_suggestion"] = m.group(1).strip()

    return verdict


def parse_verdict(raw_output: str) -> dict:
    """从模型输出中抽取最后的 JSON 结论（统一 schema）。

    解析策略（逐层降级）：
    1. 提取 ```json ... ``` 代码块内的文本，用平衡花括号提取完整 JSON
    2. 全文扫描 '{' 位置，用平衡花括号提取含 has_vulnerability 的 JSON 片段
    3. 字段级正则提取（处理 JSON 字符串值含未转义双引号的畸形）

    修复历史 bug：旧版正则 `\\{.*?\\}` 非贪婪匹配会在字符串值含 '}' 时截断，
    导致 JSON 不完整无法解析。改用平衡花括号匹配后可正确处理。

    解析失败返回空 dict。
    """
    if not raw_output:
        return {}

    # 策略 1：提取 ```json ... ``` 代码块内的文本
    # 注意：不再用 (\{.*?\}) 非贪婪匹配，改为提取围栏内全部文本再用平衡括号解析
    fence_matches = re.findall(r"```(?:json)?\s*(.*?)\s*```", raw_output, re.DOTALL)
    for fence_text in reversed(fence_matches):
        # 在围栏文本中找第一个 '{'，用平衡括号提取完整 JSON
        brace_idx = fence_text.find('{')
        if brace_idx == -1:
            continue
        balanced = _extract_balanced_json(fence_text, brace_idx)
        if balanced:
            parsed = _try_parse_json(balanced)
            if parsed and "has_vulnerability" in parsed:
                return parsed

    # 策略 2：全文扫描所有 '{' 位置，用平衡括号提取含 has_vulnerability 的 JSON
    for i, ch in enumerate(raw_output):
        if ch == '{':
            balanced = _extract_balanced_json(raw_output, i)
            if balanced and '"has_vulnerability"' in balanced:
                parsed = _try_parse_json(balanced)
                if parsed and "has_vulnerability" in parsed:
                    return parsed

    # 策略 3：字段级正则提取（处理 JSON 字符串值含未转义双引号的畸形）
    fallback = _extract_verdict_fallback(raw_output)
    if "has_vulnerability" in fallback:
        return fallback
    return {}


# ---------------------------------------------------------------------------
# 后处理白名单兜底（仅消融对照用，不作为最终论文主结论）
# ---------------------------------------------------------------------------
# 设计原则：
#   1. 仅在模型判定 has_vulnerability=True 时考虑 override；
#   2. 仅当代码命中已知安全模式（参数化查询 / 列表 subprocess + 输入校验 / abspath+startswith）时
#      且不含明显漏洞特征（shell=True、字符串拼接进 SQL/命令）时才 override；
#   3. override 时把 has_vulnerability 改为 False，并在 verdict 中加 safe_pattern_override: true 标记；
#   4. 不修改原 verdict 字段，返回新 dict。

# 明显漏洞特征：命中以下任一就不做 override
_VULN_SIGNATURE_PATTERNS = [
    re.compile(r"shell\s*=\s*True"),                      # shell=True 命令注入典型特征
    re.compile(r"execute\s*\(\s*['\"][^'\"]*['\"]\s*\+"),  # execute("..." + 用户输入 拼接 SQL
    re.compile(r"execute\s*\(\s*f['\"]"),                  # execute(f"...{user}...") f-string 拼接 SQL
    re.compile(r"os\.system\s*\(\s*[^)]*\+"),              # os.system(... + 用户输入 拼接命令
    re.compile(r"exec\s*\(\s*['\"][^'\"]*['\"]\s*\+"),     # exec("..." + 用户输入 拼接命令
    re.compile(r"eval\s*\(\s*request"),                    # eval(request....) RCE
    re.compile(r"pickle\.loads\s*\("),                     # pickle.loads 用户数据
    re.compile(r"ObjectInputStream"),                      # Java 反序列化
    re.compile(r"open\s*\(\s*[^)]*\+"),                    # open(... + 用户输入 拼接路径
    re.compile(r"innerHTML\s*=\s*[^;]*\+"),                # innerHTML 拼接用户输入
    re.compile(r"execute\s*\(\s*['\"][^'\"]*['\"]\s*%"),      # execute("..." % ...) % 格式化拼接 SQL
    re.compile(r"execute\s*\(\s*['\"][^'\"]*['\"]\s*\.format"), # execute("...".format(...)) 拼接 SQL
]

# 安全模式 1：参数化查询（占位符 + 参数元组/dict）
# 检测两个特征：(a) 代码中存在含 ? / %s 占位符的 SQL 字符串字面量；
#               (b) 存在 .execute(...) 调用，且该调用不含字符串拼接（+ / f-string）。
# 同时满足 (a)(b) 即视为参数化查询安全模式。
_SAFE_SQL_PLACEHOLDER_PATTERN = re.compile(
    r"['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^'\"]*[?%][^'\"]*['\"]",
    re.IGNORECASE,
)
_SAFE_EXECUTE_CALL_PATTERN = re.compile(r"\.execute\s*\(")

# 安全模式 2：列表参数 subprocess + 输入校验
# 匹配 subprocess.run([...], ...) / subprocess.Popen([...], ...) 不含 shell=True
_SAFE_SUBPROCESS_LIST_PATTERN = re.compile(
    r"subprocess\.(?:run|Popen|call|check_output|check_call)\s*\(\s*\[",
)
_SAFE_INPUT_VALIDATION_PATTERN = re.compile(
    r"\.isalnum\s*\(\s*\)"                         # isalnum() 输入白名单校验
)

# 安全模式 3：abspath + startswith 路径校验
_SAFE_PATH_ABSPATH_PATTERN = re.compile(
    r"os\.path\.abspath\s*\(",
)
_SAFE_PATH_STARTSWITH_PATTERN = re.compile(
    r"\.startswith\s*\(",
)


def _detect_safe_pattern(code: str) -> Optional[str]:
    """检测代码是否命中已知安全模式。返回安全模式标识字符串，未命中返回 None。

    仅当代码不含明显漏洞特征时才检测安全模式。
    """
    # 先检查明显漏洞特征：命中任一则不视为纯安全代码
    for pat in _VULN_SIGNATURE_PATTERNS:
        if pat.search(code):
            return None

    # 安全模式 1：参数化查询（含占位符的 SQL 字符串 + execute 调用）
    if (_SAFE_SQL_PLACEHOLDER_PATTERN.search(code)
            and _SAFE_EXECUTE_CALL_PATTERN.search(code)):
        return "parameterized_query"

    # 安全模式 2：列表参数 subprocess + 输入校验（argv 不含 shell/解释器/执行语义参数——
    # ["sh","-c",x]、find -exec、git --upload-pack 等列表形式仍是注入，2026-08-22 修正）
    if (_SAFE_SUBPROCESS_LIST_PATTERN.search(code)
            and _SAFE_INPUT_VALIDATION_PATTERN.search(code)):
        from graduation_project.shell_safety import list_argv_has_exec_semantics
        for m in _SAFE_SUBPROCESS_LIST_PATTERN.finditer(code):
            if list_argv_has_exec_semantics(code[m.end():m.end() + 400]):
                break
        else:
            return "subprocess_list_with_validation"

    # 安全模式 3：abspath + startswith 路径校验
    if (_SAFE_PATH_ABSPATH_PATTERN.search(code)
            and _SAFE_PATH_STARTSWITH_PATTERN.search(code)):
        return "path_abspath_startswith"

    return None


def apply_safe_pattern_override(code: str, verdict: dict) -> tuple[dict, dict]:
    """后处理白名单兜底：若代码命中已知安全模式且模型判 True，改为 False。

    仅作为消融对照与兜底，不作为最终论文主结论。

    Args:
        code: 待分析的原始代码（用于安全模式检测）
        verdict: 模型输出的判定 dict（来自 parse_verdict）

    Returns:
        (new_verdict, info)
        - new_verdict: 处理后的判定 dict（若 override 则 has_vulnerability=False 且加标记字段）
        - info: {"override_applied": bool, "reason": str, "safe_pattern": str|None}
    """
    info = {"override_applied": False, "reason": "", "safe_pattern": None}

    if not code or not verdict:
        info["reason"] = "empty input"
        return verdict, info

    has_vuln = normalize_has_vulnerability(verdict.get("has_vulnerability"))
    if has_vuln is not True:
        info["reason"] = f"model verdict is not True (={has_vuln}), no override needed"
        return verdict, info

    safe_pattern = _detect_safe_pattern(code)
    if not safe_pattern:
        info["reason"] = "no safe pattern matched or vuln signature detected"
        return verdict, info

    # 命中安全模式 + 模型判 True → override 为 False
    new_verdict = dict(verdict)
    new_verdict["has_vulnerability"] = False
    new_verdict["safe_pattern_override"] = True
    new_verdict["override_reason"] = f"matched safe pattern: {safe_pattern}"
    # 把原模型判定保留为字段，便于审计
    new_verdict["original_model_verdict"] = True

    info["override_applied"] = True
    info["reason"] = f"safe pattern matched: {safe_pattern}"
    info["safe_pattern"] = safe_pattern
    return new_verdict, info


if __name__ == "__main__":
    # 自检：schema 渲染 + 解析
    print("=== schema 字段说明 ===")
    print(format_schema_for_prompt())
    print("\n=== parse_verdict 自检 ===")

    # 用例 1：正常 JSON
    sample = '分析过程...\n```json\n{"has_vulnerability": true, "vulnerability_type": "CWE-89 SQL注入"}\n```'
    v = parse_verdict(sample)
    print("[正常]    解析结果:", v)

    # 用例 2：DeepSeek-Coder-V2 畸形 JSON（vulnerability_type 拆成两个逗号分隔字符串）
    deepseek_malformed = (
        '### JSON 结论\n```json\n'
        '{\n'
        '  "has_vulnerability": true,\n'
        '  "vulnerability_type": "CWE-89", "SQL注入",\n'
        '  "risk_level": "High",\n'
        '  "source": "username and password",\n'
        '  "sink": "sqlite3.execute",\n'
        '  "explanation": "直接拼接用户输入",\n'
        '  "fix_suggestion": "使用参数化查询"\n'
        '}\n```'
    )
    v2 = parse_verdict(deepseek_malformed)
    print("[DeepSeek] 解析结果:", v2)
    print("[DeepSeek] vulnerability_type =", v2.get("vulnerability_type"))
    print("[DeepSeek] 归一化:", normalize_has_vulnerability(v2.get("has_vulnerability")))

    # 用例 3：安全模式兜底自检
    print("\n=== apply_safe_pattern_override 自检 ===")
    safe_param_query = (
        'query = "SELECT * FROM users WHERE username = ? AND password = ?"\n'
        'cursor.execute(query, (username, password))'
    )
    safe_subprocess = (
        'host = request.args.get("host", "")\n'
        'if not host.replace(".", "").replace("-", "").isalnum():\n'
        '    return "invalid host", 400\n'
        'subprocess.run(["ping", "-c", "1", host], capture_output=True, timeout=5)'
    )
    vuln_sqli = (
        'query = "SELECT * FROM users WHERE name = \'" + username + "\'"\n'
        'cursor.execute(query)'
    )
    for label, code in [("参数化查询(安全)", safe_param_query),
                        ("列表subprocess+isalnum(安全)", safe_subprocess),
                        ("字符串拼接SQL(漏洞)", vuln_sqli)]:
        verdict_true = {"has_vulnerability": True, "vulnerability_type": "test"}
        new_v, info = apply_safe_pattern_override(code, verdict_true)
        print(f"[{label}] override={info['override_applied']}, reason={info['reason']}, "
              f"has_vuln={new_v.get('has_vulnerability')}")

    # 用例 4：JSON 字符串值中含花括号（修复后的 bug 验证）
    brace_in_string = (
        '分析过程：代码中使用了 obj.method() {return true} 的写法...\n'
        '```json\n'
        '{"has_vulnerability": false, "vulnerability_type": "none", '
        '"risk_level": "None", "source": "N/A", "sink": "N/A", '
        '"explanation": "代码中使用 obj.method() {return true} 是安全的", '
        '"fix_suggestion": "no fix needed"}\n'
        '```'
    )
    v4 = parse_verdict(brace_in_string)
    print("[花括号]  解析结果:", v4)
    print("[花括号]  has_vulnerability =", v4.get("has_vulnerability"))
    print("[花括号]  explanation =", v4.get("explanation"))

    # 用例 5：fallback 完整字段提取验证
    no_json_block = (
        '分析过程：这是一段SQL注入漏洞代码。\n'
        '- **has_vulnerability**: true\n'
        '- **vulnerability_type**: CWE-89 SQL注入\n'
        '- **risk_level**: High\n'
        '- **source**: 用户输入 username\n'
        '- **sink**: cursor.execute\n'
        '- **explanation**: 字符串拼接SQL\n'
        '- **fix_suggestion**: 使用参数化查询'
    )
    v5 = parse_verdict(no_json_block)
    print("\n[fallback] 解析结果:", v5)
    print("[fallback] 字段数:", len(v5))
