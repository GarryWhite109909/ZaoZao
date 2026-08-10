"""
统一 Prompt 模板 —— 全项目所有漏洞分析调用必须使用本模块的构建函数。

提供三种复用粒度：
- SYSTEM_PROMPT：角色 + 分析范围 + 安全模式白名单 + 硬编码凭证规则 + schema + 输出要求（system 字段用）
- build_user_prompt()：代码块 + 可选 RAG 上下文 + 收尾（user prompt）
- build_full_prompt()：SYSTEM_PROMPT + user prompt 拼接（给不用 system 字段的单 prompt 调用用）

schema 字段说明通过 graduation_project.schema.format_schema_for_prompt() 渲染，确保全项目一致。

DeepSeek 安全样本优化（2026-06-30）：
- 在 SYSTEM_PROMPT 中加入 SAFE_PATTERN_WHITELIST，显式声明常见安全写法（通用领域知识，不含测试样本代码）
- 不使用 Few-shot 示例，避免与测试样本代码重叠导致答案泄露
- 目标：把 deepseek-coder-v2:16b 在 exp_01 安全样本上的误报率从 100% 降到 ≤10%
"""

from typing import Optional

from graduation_project.schema import format_schema_for_prompt


# ---------------------------------------------------------------------------
# 分析范围（统一文本，避免各处不一致）
# ---------------------------------------------------------------------------
# 2026-07-09 改进（依据 docs/_archive/改进_历史分析_20260710.md 根因分析）：
# 旧版只列 6 类注入 + "等"，模型把"等"当成"就这些"，导致日志注入/弱密码学/
# 弱随机数 3 个 FN。现显式列出长尾 CWE，并在每类后标注 CWE 编号，迫使模型
# 在 CoT 中主动检查这些类别，而非默认跳过。
ANALYSIS_SCOPE = (
    "SQL 注入、跨站脚本（XSS）、命令注入、路径穿越、"
    "硬编码敏感信息（密钥/密码/Token）、不安全的反序列化、"
    "日志注入（CWE-117）、弱密码学（MD5/SHA1 哈希密码、CWE-327）、"
    "弱随机数（random 模块生成 token、CWE-330）、CSRF、"
    "SSTI、XXE、开放重定向、缺失认证/授权等"
)

# ---------------------------------------------------------------------------
# 安全模式白名单 —— 显式声明常见安全写法，避免模型对安全样本误报。
# 模型判定前必须自检：代码是否命中以下任一安全模式？若命中且无其他漏洞，应判 false。
# ---------------------------------------------------------------------------
SAFE_PATTERN_WHITELIST = """\
【安全模式白名单（命中以下模式且无其他漏洞时，应判 has_vulnerability=false）】
1. SQL 参数化查询：cursor.execute("... WHERE id=?", (user_id,))，占位符 + 参数元组，非字符串拼接。
2. subprocess 列表参数：subprocess.run(["cmd", arg])，shell 默认 False，列表形式不触发 shell 解释。不要捏造 shell=True。
3. 路径校验：os.path.abspath + startswith 限定目录，或白名单文件名集合。这类双重防御有效，严禁编造"可被绕过"却不给出具体 payload。
4. XSS 防护：html.escape() / 模板自动转义 / textContent。
5. 反序列化：json.loads 替代 pickle.loads，yaml.safe_load 替代 yaml.load。
6. shell 命令转义：shlex.quote() 会转义所有 shell 元字符，是 shell=True 场景下的有效防御，不能仅因 shell=True 就判漏洞。
判断要点：用户输入到达 sink 不等于漏洞，必须看 sink 前的防御是否有效。但也不要因为代码"看起来安全"就忽略实际存在的漏洞。
反偏见自检：若你倾向判"有漏洞"，必须能用一行具体攻击 payload 证明防御可被绕过；若给不出 payload，则不得判 True。严禁扭曲代码事实（如把列表参数看成字符串拼接）来配合"有漏洞"的结论。"""

# ---------------------------------------------------------------------------
# 硬编码凭证判定标准 —— 单独列出，避免与"安全模式白名单"混淆。
# ---------------------------------------------------------------------------
HARDCODED_SECRET_RULE = """\
【硬编码凭证判定标准（CWE-798）】
- 凡是源码中出现字面量形式的密码 / API Key / Secret / Token / AWS 密钥对 / 数据库连接串密码，
  无论是否被实际使用、无论是否在生产环境，都**本身就是漏洞**，应判 has_vulnerability=true。
- 不要因为"代码没有 SQL 注入、命令注入等其他风险"就把硬编码凭证降级为"敏感但非漏洞"。
- 安全的写法是：从 os.environ / 配置文件 / KMS 读取，而不是硬编码字面量。
- 检测特征：变量名含 key/secret/password/token/credential/passphrase，且赋值为字符串字面量。
- **不是凭证的常见字符串**：数据库名（如 "users.db"）、文件名、表名、URL 路径、主机名、
  端口号、SQL 语句、HTML 模板、错误消息文本。严禁把这些当成硬编码凭证强行找漏洞。
- **严禁钻空子**：当代码命中安全模式白名单（如参数化查询）时，严禁为了判 True 而强行
  在代码中挑剔其他"漏洞"（如把 "users.db" 当硬编码凭证）。若代码确实只命中安全模式而无
  真实漏洞，必须判 has_vulnerability=false。"""

# ---------------------------------------------------------------------------
# System Prompt：默认完整版
# 角色 + 分析范围 + 安全模式白名单 + 硬编码凭证规则 + schema + 输出要求。
# 注意：不使用 Few-shot 示例，避免与测试样本代码重叠导致答案泄露。
# 当前主模型 qwen2.5-coder:7b 依赖该完整 prompt 在 exp_01/exp_03 上达到 100% 准确率。
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = (
    "你是一名资深的代码安全审计专家。请对给出的代码片段进行安全分析，"
    "判断其中是否存在安全漏洞。分析范围包括但不限于："
    + ANALYSIS_SCOPE
    + "。\n\n"
    "要求：\n"
    "1. 仔细阅读代码语义，结合上下文判断用户可控输入是否被安全处理。\n"
    "2. 不要夸大风险，也不要遗漏明显的漏洞。\n"
    "3. 判定前必须自检：代码是否命中下文「安全模式白名单」中的任一安全写法？"
    "若命中且无其他漏洞，必须判 has_vulnerability=false。\n"
    "4. 严禁把已经是安全写法的代码（如参数化查询、列表参数 subprocess、abspath+startswith 路径校验）"
    "误判为漏洞；同时严禁为了让安全代码“看起来有风险”而在 fix_suggestion 中推荐与原代码等价的写法。\n"
    "5. 严禁在判定中捏造代码中不存在的 API 参数（如 shell=True、debug=True）。"
    "判定必须基于代码实际内容，不能凭空臆造。\n"
    "6. 硬编码凭证本身就是漏洞（详见下文「硬编码凭证判定标准」），"
    "不要因为代码没有其他风险就降级为“敏感但非漏洞”。\n\n"
    + SAFE_PATTERN_WHITELIST
    + "\n\n"
    + HARDCODED_SECRET_RULE
    + "\n\n在回答的最后，必须严格输出一个 JSON 对象作为最终结论，"
    "JSON 块用 ```json 包裹，字段如下（统一 schema，全项目一致）：\n"
    + format_schema_for_prompt()
    + "\n\n请先给出分析过程，然后在最后给出 JSON 结论。"
)


# ---------------------------------------------------------------------------
# System Prompt 精简版 —— exp_06 微调专用
# ---------------------------------------------------------------------------
# 设计动机：完整版 SYSTEM_PROMPT 含 1981 字符的「安全模式白名单」「硬编码凭证
# 判定标准」等具体规则条文，训练时每条样本都重复，导致梯度信号被稀释、模型
# 学成"规则背诵机"而非"判断机器"。精简版只保留角色定位 + 核心要求 + schema，
# 把具体规则交给模型从训练样本的 CoT 中学习（distill 段 400 条 GLM 教师生成的
# 多样化 CoT 已覆盖参数化查询、subprocess 列表、路径校验等安全模式）。
#
# 使用约定：
#   - exp_06 训练数据生成（combine_and_augment.py）用 SYSTEM_PROMPT_LITE
#   - exp_06 推理评估（evaluate.py）也用 SYSTEM_PROMPT_LITE（保持训练/推理一致）
#   - 其他实验（exp_01/03/04/05）继续用 SYSTEM_PROMPT，不受影响
# ---------------------------------------------------------------------------
SYSTEM_PROMPT_LITE = (
    "你是一名资深的代码安全审计专家。请对给出的代码片段进行安全分析，"
    "判断其中是否存在安全漏洞。分析范围包括但不限于："
    + ANALYSIS_SCOPE
    + "。\n\n"
    "要求：\n"
    "1. 仔细阅读代码语义，结合上下文判断用户可控输入是否被安全处理。\n"
    "2. 不要夸大风险，也不要遗漏明显的漏洞。\n"
    "3. 判定必须基于代码实际内容，不能凭空臆造 API 参数或行为。\n"
    "4. 用户输入到达 sink 不等于漏洞，必须看 sink 前的防御措施是否有效。\n"
    "5. 硬编码的字面量凭证（key/secret/password/token）本身就是漏洞，"
    "不要降级为“敏感但非漏洞”。\n"
    "6. 结论一致性校验：JSON 的 has_vulnerability 必须与上述分析过程的推理结论一致。"
    "若分析过程中识别出风险（如“弱随机”“不安全”“存在漏洞”），JSON 不得标 false；"
    "若分析过程未识别出风险，JSON 不得标 true。\n\n"
    "在回答的最后，必须严格输出一个 JSON 对象作为最终结论，"
    "JSON 块用 ```json 包裹，字段如下（统一 schema，全项目一致）：\n"
    + format_schema_for_prompt()
    + "\n\n请先给出分析过程，然后在最后给出 JSON 结论。"
)


# ---------------------------------------------------------------------------
# Base System Prompt —— exp_05 消融实验确定的最优 prompt（482 字符）
# ---------------------------------------------------------------------------
# 设计动机：exp_05_prompt_ablation 对 8+2 个变体做了严格对照实验，结论是
# 纯 base prompt（角色 + schema + 输出格式）在 strict 准确率（CWE 归因）
# 上最优（55.8%），任何额外规则维度都会干扰基座模型的原生 CWE 判断。
# loose 准确率也达 90.7%（仅次于 +consistency 的 94.3%，但后者 strict 下降）。
#
# 使用约定（全项目唯一 system prompt）：
#   - exp_06 训练数据生成（distill_v2 STUDENT_SYSTEM）用 BASE_PROMPT
#   - exp_06 推理评估（evaluate.py）也用 BASE_PROMPT（保持训练/推理一致）
#   - 已有训练数据统一改造为 BASE_PROMPT
# ---------------------------------------------------------------------------
BASE_PROMPT = (
    "你是一名安全研究员，分析给定代码的安全漏洞。\n\n"
    "在回答的最后，必须严格输出一个 JSON 对象作为最终结论，"
    "JSON 块用 ```json 包裹，字段如下（统一 schema，全项目一致）：\n"
    + format_schema_for_prompt()
    + "\n\n请先给出分析过程，然后在最后给出 JSON 结论。"
)


# ---------------------------------------------------------------------------
# v9max 专用减误报 CoT —— 供 evaluate.py --variant anti_fp_cot 使用
# ---------------------------------------------------------------------------
# 设计动机：BASE_PROMPT 只给了一句通用的"请先给出分析过程"，v9max 的减误报
# 能力完全依赖 SFT 训练。但推理时若让模型显式走"防御自检 + 具体 payload 佐证"
# 的分析步骤，可进一步压低误报。本提示词刻意保留 BASE_PROMPT 的"安全研究员"
# 框架（与 v9max 训练格式对齐，避免 format shift），只在其中追加 4 步减误报 CoT：
#   1) sink 前防御是否有效（安全模式清单）  2) 判 true 必须有具体可绕过 payload
#   3) 严禁捏造 API 参数/扭曲代码事实          4) 硬编码凭证仍判 true（防漏报）
ANTI_FP_COT = (
    "你是一名安全研究员，分析给定代码的安全漏洞。\n\n"
    "请严格按以下步骤分析后再下结论：\n"
    "1. 识别代码中的危险函数（sink）与用户可控输入（source），并确认输入是否真的到达 sink。\n"
    "2. 自检 sink 前是否有**有效**的防御措施：参数化查询/占位符、subprocess 列表参数"
    "（非字符串拼接）、shlex.quote 转义、os.path.abspath+startswith 白名单校验、"
    "html.escape/模板自动转义、json.loads 而非 pickle.loads、yaml.safe_load 等。"
    "若防御有效，代码是安全的。\n"
    "3. 反偏见自检：只有当你能用一段**具体可执行的攻击 payload** 证明防御可被绕过时，"
    "才判 has_vulnerability=true；若给不出具体 payload，必须判 false。\n"
    "4. 严禁捏造代码中不存在的 API 参数（如 shell=True、debug=True）或扭曲代码事实"
    "来支持“有漏洞”的结论；也不要把数据库名/文件名/表名等当成硬编码凭证。\n"
    "5. 硬编码的字面量凭证（key/secret/password/token 字面量）本身就是漏洞，应判 true，不要降级。\n\n"
    "在回答的最后，必须严格输出一个 JSON 对象作为最终结论，"
    "JSON 块用 ```json 包裹，字段如下（统一 schema，全项目一致）：\n"
    + format_schema_for_prompt()
    + "\n\n请先给出分析过程，然后在最后给出 JSON 结论。"
)


# ---------------------------------------------------------------------------
# 评估用 System Prompt 变体解析 —— 供 evaluate.py --variant 使用
# ---------------------------------------------------------------------------
# 用途：在微调模型（v9max）上对照不同 prompt 策略，实证确定其最优 prompt。
# 说明：exp_05 的结论（combined 最优）只在 qwen3:8b 基座 + SYSTEM_PROMPT 家族上
# 成立，未在 v9max 上验证。本函数把候选 prompt 统一暴露给 evaluate.py 做对照。
EVAL_SYSTEM_VARIANTS = ("base", "combined", "anti_fp_cot")


def get_eval_system_prompt(variant: str) -> str:
    """返回指定评估变体的 system prompt 文本。

    Args:
        variant: 取值见 EVAL_SYSTEM_VARIANTS
            - base        当前默认 BASE_PROMPT（v9max 训练对齐，基线）
            - combined    exp_05 在 qwen3:8b 上的最优变体（白名单+few-shot+CoT）
            - anti_fp_cot v9max 专用减误报 CoT

    Returns:
        system prompt 字符串。未知 variant 抛 ValueError。
    """
    if variant == "base":
        return BASE_PROMPT
    if variant == "combined":
        return build_system_prompt_variant("combined")
    if variant == "anti_fp_cot":
        return ANTI_FP_COT
    raise ValueError(f"未知评估变体: {variant}（合法值: {EVAL_SYSTEM_VARIANTS}）")


def build_user_prompt(
    code: str,
    language: str = "python",
    filename: Optional[str] = None,
    rag_context: Optional[str] = None,
) -> str:
    """构建 user prompt：代码块 + 可选 RAG 上下文 + 收尾要求。

    与 SYSTEM_PROMPT 配合使用。

    注意：filename 参数**不会**注入 prompt 文本。早期版本曾把文件名写入
    prompt 头部（"代码片段（文件名: xxx.py）"），但测试样本文件名含漏洞
    类别标签（如 sql_injection_01.py、safe_02_...py、noise_02_...py），
    导致答案泄漏——模型可从文件名直接推断 expected_present，实验指标
    失真（exp_01 100% 准确率被污染）。现已移除文件名注入，仅保留 language
    作为上下文。filename 参数仍保留以兼容调用方签名（用于结果记录、跨文件
    上下文拼接等），但不进入 prompt 文本。
    """
    parts = []
    parts.append(f"代码片段（语言: {language}）：")
    parts.append("```" + (language or "text") + "\n" + code + "\n```")

    if rag_context:
        parts.append(
            f"\n【知识库检索结果（仅供参考，可能与当前代码相关也可能无关）】\n{rag_context}\n"
            f"使用要求：\n"
            f"1. 上述知识可能命中「危险模式」或「安全模式」两类，请根据知识标题与内容自行判断。\n"
            f"2. 若知识标注 safe_pattern=true 或描述的是安全写法，应作为「避免误报」的依据，而非漏洞证据。\n"
            f"3. 若知识与当前代码漏洞类型不匹配（如代码是 SSRF 但检索到路径穿越知识），请忽略该知识，独立判断。\n"
            f"4. 严禁因为知识中提到某类漏洞就在代码中强行寻找该类漏洞；以代码实际语义为准。"
        )

    parts.append("请先给出分析过程，然后在最后给出 JSON 结论。")
    return "\n".join(parts)


def build_full_prompt(
    code: str,
    language: str = "python",
    filename: Optional[str] = None,
    rag_context: Optional[str] = None,
) -> str:
    """构建单条完整 prompt（system + user 拼接）。

    供不支持 system 字段或希望单 prompt 调用的场景使用（如 exp_01 的批量脚本
    通过 client.generate(prompt=...) 调用）。语义上等价于 system=SYSTEM_PROMPT
    + prompt=build_user_prompt(...)。
    """
    return SYSTEM_PROMPT + "\n\n" + build_user_prompt(
        code=code, language=language, filename=filename, rag_context=rag_context
    )


# ---------------------------------------------------------------------------
# Prompt 工程消融变体（exp_05_prompt_ablation 使用）
# ---------------------------------------------------------------------------
# 5 个变体用于系统对比不同 Prompt 策略对难样本召回与安全样本误报的影响：
#   1. zero_shot      当前完整版 SYSTEM_PROMPT（含白名单+硬编码规则+多条要求+schema）
#   2. whitelist_only 仅角色 + SAFE_PATTERN_WHITELIST + schema（去掉其他规则）
#                     验证白名单本身的独立价值（与 zero_shot 对比看其他规则的增量）
#   3. few_shot       在 zero_shot 基础上加 3 组示例（漏洞/安全/漏洞）
#                     示例代码刻意与 manifest 样本不同，避免答案泄露
#   4. cot            在 zero_shot 基础上显式要求按 5 步思维链分析
#   5. combined       zero_shot + few_shot + cot 三合一
# ---------------------------------------------------------------------------
PROMPT_VARIANTS = ("zero_shot", "whitelist_only", "few_shot", "cot", "combined")


# Few-shot 示例：刻意选用与 manifest 样本不同的简短代码，避免答案泄露。
# 3 组示例覆盖：SQL 注入漏洞 → 参数化查询安全 → 命令注入漏洞
FEW_SHOT_EXAMPLES = """\
【示例 1（漏洞）】
代码：
```python
def auth(user, pwd):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE name='" + user + "' AND pwd='" + pwd + "'")
    return cur.fetchone()
```
分析：用户输入 user/pwd 通过字符串拼接直接进入 SQL 语句（line 3），未使用参数化查询。
结论：
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-89 SQL注入", "risk_level": "Critical", "source": "line 1: 函数参数 user/pwd", "sink": "line 3: cur.execute 拼接 SQL", "explanation": "user/pwd -> 字符串拼接 -> query -> cur.execute", "fix_suggestion": "line 3: 改用参数化查询 cur.execute(\"SELECT * FROM users WHERE name=? AND pwd=?\", (user, pwd))"}
```

【示例 2（安全）】
代码：
```python
def auth(user, pwd):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE name=? AND pwd=?", (user, pwd))
    return cur.fetchone()
```
分析：使用 ? 占位符 + 参数元组，是参数化查询标准写法，数据库驱动会自动转义。
结论：
```json
{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "None", "source": "N/A", "sink": "N/A", "explanation": "参数化查询已正确防护", "fix_suggestion": "no fix needed"}
```

【示例 3（漏洞）】
代码：
```python
import os
def lookup(host):
    os.system("nslookup " + host)
```
分析：用户输入 host（line 2）直接拼接到 os.system 命令字符串（line 3），可注入 shell 元字符（如 `; rm -rf`）。
结论：
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-78 命令注入", "risk_level": "Critical", "source": "line 2: 函数参数 host", "sink": "line 3: os.system 拼接命令", "explanation": "host -> os.system 字符串拼接 -> 可注入 shell 元字符", "fix_suggestion": "line 3: 改用 subprocess.run(['nslookup', host], shell=False) 列表形式"}
```
"""


# 思维链（CoT）分析步骤要求
COT_STEPS = """\
【分析步骤要求（必须逐步执行）】
请严格按以下 5 步分析后再下结论：
1. 识别代码中所有用户可控输入点（source），如 request.args / 函数参数 / 文件读取等。
2. 追踪这些输入的数据流，判断是否到达危险函数（sink），如 execute / system / open / pickle.loads 等。
3. 检查 source 到 sink 之间是否存在防御措施（参数化查询、白名单校验、转义、abspath+startswith 等）。
4. 若有防御措施，评估其是否有效（如参数化查询是有效的，简单 replace/strip 过滤通常无效）。
5. 综合以上分析得出最终结论，并在 JSON 中体现 source/sink/explanation 字段。
注意：分析过程必须真实展现上述步骤，不能跳步直接给结论。"""


def _build_whitelist_only_prompt() -> str:
    """变体 2：仅角色 + 白名单 + schema（去掉其他规则）。"""
    return (
        "你是一名资深的代码安全审计专家。请对给出的代码片段进行安全分析，"
        "判断其中是否存在安全漏洞。分析范围包括但不限于："
        + ANALYSIS_SCOPE
        + "。\n\n"
        + SAFE_PATTERN_WHITELIST
        + "\n\n在回答的最后，必须严格输出一个 JSON 对象作为最终结论，"
        "JSON 块用 ```json 包裹，字段如下（统一 schema，全项目一致）：\n"
        + format_schema_for_prompt()
        + "\n\n请先给出分析过程，然后在最后给出 JSON 结论。"
    )


def _build_few_shot_prompt() -> str:
    """变体 3：在 zero_shot 基础上加入 3 组 few-shot 示例。"""
    return (
        SYSTEM_PROMPT
        + "\n\n"
        + FEW_SHOT_EXAMPLES
    )


def _apply_cot_to_system_prompt(base: str) -> str:
    """把 SYSTEM_PROMPT 末尾的"请先给出分析过程..."替换为 CoT 步骤版本。

    内部辅助函数，供 _build_cot_prompt 与 _build_combined_prompt 复用。
    """
    cot_suffix = (
        "\n\n" + COT_STEPS
        + "\n\n请按上述步骤逐步分析，然后在最后给出 JSON 结论。"
    )
    old_tail = "请先给出分析过程，然后在最后给出 JSON 结论。"
    if old_tail in base:
        # 用 rfind 定位最后一次出现（避免与 user prompt 中相同文本冲突）
        idx = base.rfind(old_tail)
        return base[:idx] + cot_suffix
    return base + cot_suffix


def _build_cot_prompt() -> str:
    """变体 4：在 zero_shot 基础上加入 CoT 思维链要求。"""
    return _apply_cot_to_system_prompt(SYSTEM_PROMPT)


def _build_combined_prompt() -> str:
    """变体 5：zero_shot + few_shot + cot 三合一。

    构造顺序：把 SYSTEM_PROMPT 的尾部替换为 CoT 版本，再追加 few-shot 示例。
    这样既保留了 CoT 步骤要求，又保留了 few-shot 示例。
    """
    cot_system = _apply_cot_to_system_prompt(SYSTEM_PROMPT)
    return cot_system + "\n\n" + FEW_SHOT_EXAMPLES


# v3 训练数据（final_train_chatml_v3.jsonl）使用的 system prompt。
# 实测 v3 的 system prompt 长度为 4448 字符，对应 combined 变体：
# SYSTEM_PROMPT + CoT 步骤 + 3 组 few-shot 示例。
# 当前所有推理入口统一对齐到训练 prompt，避免训练/推理不一致。
V3_PROMPT = _build_combined_prompt()


def build_system_prompt_variant(variant: str) -> str:
    """根据变体名返回对应的 system prompt。

    Args:
        variant: 变体名，取值见 PROMPT_VARIANTS
            - zero_shot      完整版 SYSTEM_PROMPT（基线）
            - whitelist_only 仅白名单 + schema
            - few_shot       zero_shot + 3 组示例
            - cot            zero_shot + CoT 步骤要求
            - combined       zero_shot + few_shot + cot

    Returns:
        对应的 system prompt 字符串。未知 variant 抛 ValueError。
    """
    if variant == "zero_shot":
        return SYSTEM_PROMPT
    if variant == "whitelist_only":
        return _build_whitelist_only_prompt()
    if variant == "few_shot":
        return _build_few_shot_prompt()
    if variant == "cot":
        return _build_cot_prompt()
    if variant == "combined":
        return _build_combined_prompt()
    raise ValueError(f"未知 prompt 变体: {variant}（合法值: {PROMPT_VARIANTS}）")


def build_full_prompt_variant(
    variant: str,
    code: str,
    language: str = "python",
    filename: Optional[str] = None,
    rag_context: Optional[str] = None,
) -> str:
    """构建指定变体的完整单条 prompt（system + user 拼接）。

    供 exp_05_prompt_ablation 等消融实验使用。
    """
    system = build_system_prompt_variant(variant)
    user = build_user_prompt(
        code=code, language=language, filename=filename, rag_context=rag_context
    )
    return system + "\n\n" + user


# ---------------------------------------------------------------------------
# 两阶段架构：finding 裁决 prompt（Stage 2 裁决层）
# ---------------------------------------------------------------------------
# 与主扫描不同，裁决层任务是"对具体 finding 判定真伪"（封闭判别），而非
# "在全文中发现漏洞"（开放生成）。因此 prompt 聚焦一条 source→sink 证据链，
# 并显式要求检查防御是否有效。system prompt 仍沿用 model_registry 选择的
# system_prompt（v9max→BASE_PROMPT），与训练/主扫描保持一致。
_TRIAGE_SCHEMA = """\
{"is_confirmed": true/false, "reason": "...", "fix_suggestion": "..."}
"""


def build_triage_prompt(
    finding,
    code_context: str,
    language: str = "python",
    filename: str = "",
    rag_context: Optional[str] = None,
) -> str:
    """构造 finding 裁决 prompt：封闭二分类，带证据链锚点。

    对 Stage 1 工具召回的单个候选 finding，请 LLM 判定该 source→sink 证据链
    是否为真实漏洞。判定要点：
    1. source 是否真的用户可控、sink 是否真的危险；
    2. source→sink 之间是否有**有效**防御（参数化查询/转义/白名单/列表参数）；
    3. 输出 is_confirmed=true/false 及 reason 与修复建议。

    Args:
        finding: ToolFinding（含 rule_id/source/sink/taint_type/source_line/
                 sink_line/path/severity/evidence）
        code_context: 切片后的相关代码（只含 source/sink 所在 chunk，聚焦注意力）
        language: 代码语言
        filename: 文件名（仅作展示上下文，不注入 prompt 文本，避免文件名泄漏）
        rag_context: 可选 RAG 知识（如 CWE 安全模式）

    Returns:
        完整的 user prompt 文本（配合 system prompt 使用）。
    """
    rule_id = getattr(finding, "rule_id", "unknown-rule")
    taint_type = getattr(finding, "taint_type", "Unknown")
    source = getattr(finding, "source", "")
    sink = getattr(finding, "sink", "")
    source_line = getattr(finding, "source_line", 0)
    sink_line = getattr(finding, "sink_line", 0)
    severity = getattr(finding, "severity", "medium")
    path_chain = getattr(finding, "path", None) or []
    evidence = getattr(finding, "evidence", "")

    # 传播链：source -> ... -> sink
    if path_chain:
        chain_repr = " -> ".join([f"L{source_line}:{source}"] + list(path_chain)
                                 + [f"L{sink_line}:{sink}"])
    else:
        chain_repr = f"L{source_line}:{source} -> L{sink_line}:{sink}"

    parts = []
    parts.append("【安全分析任务：裁决一个静态工具告警是否为真漏洞】")
    parts.append("")
    parts.append("静态工具报告了一个可疑代码流，请判定它是否为真实漏洞（is_confirmed）。")
    parts.append("")
    parts.append("可疑数据流：")
    parts.append(f"- 规则: {rule_id}")
    parts.append(f"- 漏洞类型: {taint_type}")
    parts.append(f"- 严重度: {severity}")
    parts.append(f"- 污染源: {source}  (line {source_line})")
    parts.append(f"- 危险点: {sink}  (line {sink_line})")
    parts.append(f"- 传播链: {chain_repr}")
    if evidence:
        parts.append(f"- 工具证据: {evidence}")
    parts.append("")
    parts.append("相关代码片段（已切片聚焦）：")
    parts.append("```" + (language or "text") + "\n" + code_context + "\n```")

    if rag_context:
        parts.append("")
        parts.append(
            f"【知识库检索结果（仅供参考，可能与当前代码相关也可能无关）】\n{rag_context}\n"
            "使用要求：若知识标注 safe_pattern=true 或描述的是安全写法，"
            "应作为「避免误报」的依据，而非漏洞证据。"
        )

    parts.append("")
    parts.append("判定要求：")
    parts.append("1. 确认 source 是否真的用户可控、sink 是否真的危险。")
    parts.append("2. 检查 source→sink 之间是否有**有效**防御（参数化查询/转义/白名单/列表参数 subprocess）。")
    parts.append("   有效防御意味着该 finding 是误报，is_confirmed=false。")
    parts.append("3. 严禁捏造代码中不存在的 API 参数或行为；判定必须基于代码实际内容。")
    parts.append("4. 若判定为真漏洞，输出 is_confirmed=true 并给出简洁 reason 与修复建议；否则 is_confirmed=false。")
    parts.append("")
    parts.append("请先给出简短分析过程，然后在回答最后输出如下 JSON：")
    parts.append("```json")
    parts.append(_TRIAGE_SCHEMA)
    parts.append("```")

    return "\n".join(parts)


if __name__ == "__main__":
    # 自检
    test_code = "cursor.execute(\"SELECT * FROM u WHERE name='\" + name + \"'\")"
    print("=== SYSTEM_PROMPT 预览（前 300 字）===")
    print(SYSTEM_PROMPT[:300] + "...")
    print(f"\n=== SYSTEM_PROMPT 总长度: {len(SYSTEM_PROMPT)} 字符 ===")
    print("\n=== build_full_prompt 预览 ===")
    print(build_full_prompt(test_code, "python", "demo.py"))

    # 自检：5 个变体
    print("\n=== 5 个 Prompt 变体长度对比 ===")
    for v in PROMPT_VARIANTS:
        sp = build_system_prompt_variant(v)
        print(f"  {v:15s}: {len(sp):5d} 字符")
