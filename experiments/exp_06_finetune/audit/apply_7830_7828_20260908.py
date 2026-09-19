# -*- coding: utf-8 -*-
"""FIX 队列语义类：7830（判真统一为 CWE-22）+ 7828（主洞 918→22 换位）。

7830：正文判 601 / JSON 判 safe 互相反转 → 统一判真 CWE-22
（RawPath→ReplaceAllString→未归一化转发，/v1/../admin 越前缀）；
锚 33-72→40-79, 79-137→85-158, 78→88, 89→101, 121→129, 128-131→144-147。

7828：默认空 trusted_uri 表使 isTrustedUri 恒拒绝（SSRF 前提=样本外配置假设，
与 7829 同函数定性一致化）；主洞 = _checkDir 符号链接穿越（477 行 _realpath 仅为
字符串归一化，上游修复即 7829 的 @realpath）；锚 289-305→432-443, 296→437,
88→208, 342→476；版本口径 3.1.45/4.1.1；删 R8 历史轮引用。
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path.__call__ and Path(Path(__file__).resolve().parents[1])
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"

N22 = "CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"

ROWS = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]


def R(t, x, y):
    assert t.count(x) == 1, f"替换源不唯一({t.count(x)}): {x[:60]}"
    return t.replace(x, y)


def anchor_patterns(tok_old, tok_new):
    # 旧文本中区间破折号混杂 ASCII - 与 en-dash –，统一字符类匹配
    o = re.escape(tok_old).replace(r"\-", "[-–—]")
    n = tok_new
    return [
        (rf"第\s*{o}\s*行", f"第 {n} 行"),
        (rf"第{o}行", f"第{n}行"),
        (rf"line\s*{o}(?=[::\s，,)）])", f"line {n}"),
        (rf"(?<![A-Za-z0-9])L{o}(?![0-9])", f"L{n}"),
    ]


def reline_text(text, moves):
    total = 0
    for old, new in moves:
        for pat, rep in anchor_patterns(old, new):
            text, k = re.subn(pat, rep, text)
            total += k
    return text, total


def patch_json(a, **fields):
    m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
    obj = json.loads(m.group(1))
    obj.update(fields)
    return a[: m.start()] + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```\n"


# ================= 7830 =================
i7830 = 7746 - 1
r = ROWS[i7830]
a = r["messages"][2]["content"]
moves = [("33-72", "40-79"), ("79-137", "85-158"), ("78", "88"), ("89", "101"),
         ("121", "129"), ("128-131", "144-147")]
a, n_sub = reline_text(a, moves)
print(f"7830 reline 替换 {n_sub}")

a = R(a, "但该行为与 ingress-nginx 兼容语义一致，属于配置层面的固有风险，非本代码引入的逻辑缺陷。**记为低危备注**。",
        "但转发前**未对替换结果做路径归一化**（第 144-147 行直接写入 RawPath/Path）："
        "`/v1/../admin` 这类载荷经宽松正则替换后原样到达后端，越出配置前缀的隔离边界——"
        "**这是本代码的确认漏洞（CWE-22），非单纯配置风险**。")
a = R(a, "### 四、结论\n\n唯一确认的可利用漏洞为流 C：当 `Replacement` 为含捕获组引用的绝对 URL 且 `Regex` 含捕获组时，请求路径内容可控最终 302 目标，构成开放重定向。",
        "### 四、结论\n\n唯一确认的可利用漏洞为流 A 的路径穿越（CWE-22）：替换结果未归一化即转发"
        "（第 144-147 行），`/v1/../admin` 类载荷越出配置前缀边界。流 C 的开放重定向依赖样本外"
        "运维配置（捕获组进入 authority 模板），降为配置风险备注——正文与 JSON 此前互相反转，"
        "本版统一为 CWE-22 判真。")
a = patch_json(
    a,
    has_vulnerability=True,
    vulnerability_type=N22,
    risk_level="High",
    source="line 88: currentPath := req.URL.RawPath（未解码原始路径，攻击者可控）",
    sink="line 144-147: 替换结果未做路径归一化即写入 req.URL.RawPath/Path 转发后端",
    explanation=("line 88 RawPath -> line 101 ReplaceAllString 将请求路径内容填入 replacement 的 $N 占位 -> "
                 "产出未归一化路径（如 /v1/../admin）-> line 144-147 原样写入并转发后端 -> 越出配置前缀"
                 "隔离（CWE-22）。流 C 开放重定向（601）依赖运维把捕获组放进 authority 模板的样本外配置，"
                 "降为配置风险备注；正文与 JSON 此前互相反转，本版统一为 CWE-22 判真"),
    fix_suggestion=("line 144-147: 转发前对替换结果做 path.Clean/归一化并校验结果仍在配置前缀内"
                    "（拒绝 .. 序列）；可选：对产出 URL 增加 scheme/host 白名单终检"),
)
r["messages"][2]["content"] = a
with CHANGELOG.open("a", encoding="utf-8") as f:
    f.write(json.dumps({
        "date": "2026-09-08", "step": "1.4_fix_queue_semantic", "action": "FIX",
        "fix_id": 7830, "row_line_before": i7830 + 1,
        "note": "safe/601 反转统一为 CWE-22 判真（未归一化转发越前缀）；流 C 降配置备注；锚 33-72→40-79/79-137→85-158/78→88/89→101/121→129/128-131→144-147",
        "basis": "fix_queue_20260907 spec",
    }, ensure_ascii=False) + "\n")

# ================= 7828 =================
i7828 = 7744 - 1
r = ROWS[i7828]
a = r["messages"][2]["content"]
a, n_sub = reline_text(a, [("289-305", "432-443"), ("291-293", "433-436"), ("296", "437"),
                           ("88", "208"), ("342-374", "476-478"), ("344", "477"), ("346", "482")])
print(f"7828 reline 替换 {n_sub}")

a = R(a, "1. **isTrustedUri（第 432-443 行）— 存在漏洞**",
        "1. **isTrustedUri（第 432-443 行）— 默认配置下恒拒绝，SSRF 前提为样本外配置假设**")
a = R(a, "   - 缺陷：第 437 行的匹配**未强制锚定**。若管理员配置的白名单正则形如 `#^https?://trusted.example.com#`（无 `$` 结尾锚），则攻击者可注册子域或使用 `trusted.example.com.evil.com` 这类前缀欺骗域名绕过——因为只要求“以受信主机开头”即可通过。这是真实 CVE（Smarty ≤4.0.2 的 SSRF 绕过，修复于 4.1.0，官方补丁即在文档中强制要求模式必须含 `$` 锚并收紧默认示例）。黑名单式/未锚定正则按本任务判定标准视为可绕过。",
        "   - 缺陷（条件成立）：第 437 行的匹配**未强制锚定**——但**默认 `$trusted_uri = []`（第 43 行）时 foreach 无模式可匹配、第 442 行恒抛异常，默认实现全拒绝，不构成 SSRF 面**。绕过仅在管理员配置了形如 `#^https?://trusted.example.com#`（无 `$` 锚）的白名单时成立，属样本外配置假设；姊妹样本 7829 对同一函数定性为\"配置错误非代码缺陷\"，本样本不应以该场景为主洞。对应官方 CVE-2022-29221（修复版本 3.1.45/4.1.1）。")
a = R(a, "   - sink：`{fetch}` 发起 HTTP 请求 / `{html_image}` 读取资源 → **SSRF**（CWE-918），可探测内网、读取云元数据。",
        "   - sink：`{fetch}`/`{html_image}` 发起请求 → SSRF（CWE-918）仅在上述错误配置下可达，**降级为配置风险备注**。")
a = R(a, "2. **_checkDir（第 476-478 行）— 基本有效但依赖 realpath**",
        "2. **_checkDir（第 476-478 行）— 主漏洞：符号链接穿越（CWE-22）**")
# 正文里的 _checkDir 段落（行锚已被 reline 移动至 477/482）
a = R(a, "   - 第 477 行先 `_realpath($filepath, true)` 归一化路径，第 482 行拒绝含 `../` 的残留路径，随后逐级向上冒泡比对白名单目录。防御总体成立；残余风险是符号链接指向白名单外目录（需服务器配合，非本文件可直接利用）。注意第 482 行的正则只拦 `[\\\\/][.][.][\\\\/]`，但 realpath 已消除 `..`，故不构成绕过点。",
        "   - 第 477 行 `$directory = dirname($this->smarty->_realpath($filepath, true)) . DIRECTORY_SEPARATOR;` 的 `_realpath` 只是**字符串归一化**（非文件系统 realpath），随后按字符串比对可信目录（第 482 行）——可信目录内的符号链接可指向白名单外文件，路径检查被穿越。上游修复即改用文件系统 realpath（姊妹样本 7829 第 483-484 行 `$realpath = @realpath($filepath);`，其第 479 行注释自述 '(CWE-22 path traversal)'）。")
a = R(a, "**结论**：最确凿的可利用漏洞是 **isTrustedUri 的未锚定正则匹配导致的 SSRF 白名单绕过**（对应 CVE-2022-29221）；次要风险是默认允许全部静态类访问。",
        f"**结论**：主漏洞为 **_checkDir 的符号链接穿越（{N22}）**；isTrustedUri 的未锚定正则绕过（CVE-2022-29221）依赖样本外错误配置，降为配置风险备注；次要风险是默认允许全部静态类访问。")
a = patch_json(
    a,
    has_vulnerability=True,
    vulnerability_type=N22,
    risk_level="High",
    source="line 477: _checkDir 以字符串归一化（_realpath）处理模板资源路径，可信目录内的符号链接未被解析",
    sink="line 482: 逐级目录字符串比对通过后，资源按符号链接的真实目标读取",
    explanation=("模板资源路径 -> line 477: _realpath 仅字符串归一化（非文件系统 realpath），symlink 指向"
                 "白名单外目录不被解析 -> line 482: 字符串比对通过 -> 资源按链接目标读取，越出可信目录"
                 "（CWE-22）。上游修复见姊妹样本 7829 第 483-484 行 @realpath。勘误：isTrustedUri 默认空 "
                 "trusted_uri 表恒拒绝（第 432-443 行），未锚定正则绕过（CVE-2022-29221，官方修复 "
                 "3.1.45/4.1.1）需管理员错误配置白名单才成立，降为配置风险备注；原 918 主洞判定撤销。"
                 "版本口径统一为 3.1.45/4.1.1"),
    fix_suggestion=("line 477: _checkDir 改用文件系统 realpath（@realpath($filepath)）归一化后再做可信目录"
                    "比对（与上游 7829 版本一致）"),
)
# 删 R8 历史轮引用（如有）
a = re.sub(r"[（(]R8[^）)]*[）)]", "", a)
r["messages"][2]["content"] = a
with CHANGELOG.open("a", encoding="utf-8") as f:
    f.write(json.dumps({
        "date": "2026-09-08", "step": "1.4_fix_queue_semantic", "action": "FIX",
        "fix_id": 7828, "row_line_before": i7828 + 1,
        "note": "主洞 918→22（_checkDir 符号链接穿越）；isTrustedUri 空表恒拒绝勘误（SSRF 降配置备注）；锚 289-305→432-443/296→437/88→208/342→476；版本口径 3.1.45/4.1.1",
        "basis": "fix_queue_20260907 spec + 7829 同批一致性",
    }, ensure_ascii=False) + "\n")

with DATA.open("w", encoding="utf-8", newline="\n") as f:
    for row in ROWS:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")

# 自检
for idx in (i7830, i7828):
    a2 = ROWS[idx]["messages"][2]["content"]
    m = re.search(r"\n```json\n(\{.*?\})\n```", a2, re.S)
    obj = json.loads(m.group(1))
    assert obj["has_vulnerability"] is True and "CWE-22" in obj["vulnerability_type"]
print("PASS: 7830 / 7828 已判真 CWE-22")
