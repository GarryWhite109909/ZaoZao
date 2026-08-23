"""列表形式 subprocess 调用的安全性判定（唯一入口）。

历史实现在多处把"列表形式"无条件当安全/防御，导致
`subprocess.run(["sh", "-c", user])`、`find -exec`、`git --upload-pack`
等由解释器执行载荷的真注入在召回层（taint_tracker）、证据门/复核门
（_DEFENSE_SIGNATURES）、安全白名单（schema）被系统性拦截。
实测记录见 docs/训练优化计划.md 六.5。

规则：列表形式默认不经 shell 解释（防御），但 argv 中出现
shell/解释器或执行语义参数时，载荷会被该解释器执行，仍是命令注入。

供 counterfactual / taint_tracker / schema / prompts 各层复用，
禁止在各层自行复制"列表形式=安全"的局部判断。
"""

import re

# 列表 argv 内出现以下任一模式 → 该调用不构成防御（载荷可被执行）
# 注意：argv 元素通常带引号（"sh",），名字与逗号间须容忍闭合引号。
EXEC_SEMANTICS_PATTERNS = (
    # shell 作为 argv 元素（sh/bash/zsh/dash/ksh/ash/cmd/powershell/pwsh，
    # 覆盖 "/bin/sh"、sudo sh 等写法；无论是否带 -c，脚本路径同样可控）
    re.compile(r"\b(?:sh|bash|zsh|dash|ksh|ash|cmd|powershell|pwsh)\s*[\"']?\s*,"),
    # git 远程执行通道
    re.compile(r"--(?:upload|receive)-pack|--upload-archive"),
    # find 系执行语义参数
    re.compile(r"[-\-](?:exec|execdir|ok|okdir)\b"),
    # 解释器直接执行代码参数（python -c、perl/node/ruby/lua -e、php -r）
    re.compile(
        r"\b(?:python\d*|perl|ruby|node|php|lua|rscript)\s*[\"']?\s*,"
        r"\s*[\"']?-['\"cer]"
    ),
)


def list_argv_has_exec_semantics(argv_text: str) -> bool:
    """判断列表形式调用的 argv 文本是否含 shell/解释器或执行语义参数。

    Args:
        argv_text: 方括号内的 argv 文本（可含引号/换行；调用方应把被逗号
            分割的参数重新以逗号连接后传入，保证 "sh", 这类相邻关系可见）。
    """
    if not argv_text:
        return False
    return any(pat.search(argv_text) for pat in EXEC_SEMANTICS_PATTERNS)


# 与 _DEFENSE_SIGNATURES 配套的纯正则版本（签名表须保持 re.Pattern 接口）：
# 列表形式默认匹配（=防御），三个负向前瞻排除执行语义 argv。
LIST_FORM_DEFENSE_LOOKAHEADS = (
    r"(?![^\]]*\b(?:sh|bash|zsh|dash|ksh|ash|cmd|powershell|pwsh)\s*[\"']?\s*,)"
    r"(?![^\]]*--(?:upload|receive)-pack)"
    r"(?![^\]]*[-\-](?:exec|execdir|ok|okdir)\b)"
    r"(?![^\]]*\b(?:python\d*|perl|ruby|node|php|lua|rscript)\s*[\"']?\s*,"
    r"\s*[\"']?-['\"cer])"
)
