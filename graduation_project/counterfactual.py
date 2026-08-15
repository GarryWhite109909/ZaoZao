"""
反事实扰动验证 —— 第 2.5 代架构 Layer 2：检验 LLM 裁决是"真理解因果"还是"模式匹配"。

背景（docs/技术研究报告.md 报告二§一）：LLM 误报的根源常是"看到危险函数名就报，
不分析输入是否可信"。反事实扰动对此的检验方式（金标准门控）：

    模型判"有漏洞" → 对代码施加最小防御性扰动（加 shlex.quote / 参数化 / 输入校验）
        ├─ 裁决翻转（漏洞→安全）→ 模型真理解防御机制 → A 级，可回填工具
        └─ 裁决不变（漏洞→漏洞）→ 模型在模式匹配 → C/D 级，禁止回填（进抑制池）

与 VulnAgent-R2 的 CER（扰动上下文证据）的区别：本模块扰动**代码本身的防御措施**，
验证的是"模型是否真正理解漏洞因果链"（反事实推理），而非"证据是否鲁棒"。

设计约束（硬性）：
  - 扰动必须**语义保持且语法正确**：只注入防御，绝不破坏代码结构。
    因此采用"**在 sink 行内对污点变量加消毒包裹**"策略（真实开发者的修复方式），
    而非改写调用结构（后者易产生语法错误——已踩坑）。
  - 先聚焦 Python（测试集主力）；其他语言降级"不可验证"（返回 None，不做翻转判定）。
  - 翻转判定用单次裁决（不 N 采样，省 5 倍推理）。
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# 防御性扰动模板：sink 行内"污点变量 → 消毒包裹"的最小替换
# ---------------------------------------------------------------------------
# 每类模板按 (正则锚点, 替换函数) 组织：锚点定位 sink 行内的危险表达式，替换为
# 包裹了消毒函数的等价形式。只动危险点，不碰其它行。
# ---------------------------------------------------------------------------
def _wrap_fstring_vars(line: str, wrapper: str) -> str:
    """把 f-string 内所有 `{expr}` 插值替换为 `{wrapper(expr)}`（语法保证正确）。"""
    def _repl(m):
        inner = m.group(1).strip()
        if not inner:
            return m.group(0)
        # 已在 wrapper 内/已是字面量则不重复包裹
        if re.match(rf"^{re.escape(wrapper)}\(", inner):
            return m.group(0)
        return "{" + f"{wrapper}({inner})" + "}"
    return re.sub(r"\{([^{}]*)\}", _repl, line)


def _wrap_concat_vars(line: str, wrapper: str) -> str:
    """把 `+ var +` 字符串拼接中的标识符替换为 `wrapper(var)`。"""
    def _repl(m):
        return f"+ {wrapper}({m.group(1)}) +"
    return re.sub(r"\+\s*([A-Za-z_$][\w$]*)\s*\+", _repl, line)


# 模板：key=taint_type → (匹配行级的锚点正则, 替换函数)
_DEFENSE_TEMPLATES: dict[str, list[tuple[re.Pattern, str]]] = {
    "Command Injection": [
        # subprocess f-string shell=True：插值变量 shlex.quote 包裹（最稳，语法恒对）
        (re.compile(r'subprocess\.(?:run|Popen)\(f["\']'),
         lambda line: _wrap_fstring_vars(line, "shlex.quote")),
        # subprocess 字符串拼接 shell=True：拼接变量 shlex.quote
        (re.compile(r"subprocess\.(?:run|Popen)\([^)]*shell\s*=\s*True"),
         lambda line: _wrap_concat_vars(line, "shlex.quote")),
    ],
    "SQL Injection": [
        # execute 内联拼接（execute("..." + x)）→ 参数化
        (re.compile(r"\.execute\(\s*['\"][^'\"]*['\"]\s*\+\s*([\w.\[\]]+)\s*\)"),
         lambda line: re.sub(
             r"\.execute\(\s*(['\"][^'\"]*['\"])\s*\+\s*([\w.\[\]]+)\s*\)",
             r".execute('SELECT 1 WHERE ?=1', (\2,))", line)),
        # 字符串拼接含单引号（"'" + x + "'"）→ 单引号转义（经典 SQL 转义修复，模型认识）
        (re.compile(r"[+=]\s*([A-Za-z_$][\w$]*)\s*\+"),
         lambda line: re.sub(r"\+(\s*[A-Za-z_$][\w$]*)\s*\+",
                             lambda m: f"+ {m.group(1)}.replace('\"', \"''\") +", line)),
    ],
    "XSS": [
        # return f-string 插值 → html.escape 包裹插值
        (re.compile(r'return\s+f["\']'),
         lambda line: _wrap_fstring_vars(line, "html.escape")),
        # return 裸变量 → html.escape 包裹
        (re.compile(r"return\s+([A-Za-z_$][\w$]*)\s*$"),
         lambda line: re.sub(r"return\s+([A-Za-z_$][\w$]*)\s*$",
                             r"return html.escape(\1)", line)),
    ],
    "Path Traversal": [
        # open(污点变量) → realpath 白名单化
        (re.compile(r"open\(\s*([\w.\[\]]+)\s*\)"),
         lambda line: re.sub(r"open\(\s*([\w.\[\]]+)\s*\)",
                             r"open(os.path.realpath(\1))", line)),
    ],
    "Server-Side Template Injection": [
        # Environment 无 autoescape → 补 autoescape=True（值插值安全）
        (re.compile(r"Environment\(\s*loader\s*=\s*\w+\(\s*\)"),
         lambda line: re.sub(r"Environment\(\s*loader\s*=\s*\w+\(\s*\)",
                             r"Environment(loader=BaseLoader(), autoescape=True)", line)),
    ],
    "Insecure Deserialization": [
        (re.compile(r"pickle\.loads\("),
         lambda line: re.sub(r"pickle\.loads\(", "json.loads(", line)),
    ],
}

# 可验证的语言（其余返回 None，不做翻转判定）
_VERIFIABLE_LANGS = {"python", "py", "javascript", "js", "typescript", "ts"}

# 防御特征 → 检测正则：用于判定"原始代码是否已含该防御"。
# 若原始已含注入的防御，说明模型之前没识别已有防御 → 该 finding 是误报（FP）；
# 若原始无防御，扰动后判安全 → 模型真理解防御 → 真阳性（TP）。
_DEFENSE_SIGNATURES: dict[str, re.Pattern] = {
    "Command Injection": re.compile(r"shlex\.quote|subprocess\.run\(\s*\[|shell\s*=\s*False"),
    "SQL Injection": re.compile(r"\?\s*,\s*\(|%(?:s|d)\s*,\s*\(|execute\(\s*['\"][^'\"]*['\"]\s*,\s*\("),
    "XSS": re.compile(r"html\.escape|markupsafe|escape\("),
    "Path Traversal": re.compile(r"abspath|realpath"),
    "Server-Side Template Injection": re.compile(r"autoescape\s*=\s*(?:True|select_autoescape)"),
    "Insecure Deserialization": re.compile(r"json\.loads|yaml\.safe_load"),
}


@dataclass
class CounterfactualResult:
    """一次反事实扰动验证的结果。"""
    applicable: bool = False          # 是否生成了可用扰动
    perturbed_code: str = ""          # 扰动后的代码
    defense_applied: str = ""         # 注入的防御描述
    flipped: Optional[bool] = None    # True=裁决翻转（模型理解防御）；False=不变（模式匹配）
    confirmed_after: Optional[bool] = None  # 扰动后裁决结果（None=不可判定）
    already_defended: bool = False    # 原始代码是否已含注入的同类防御（区分 FP/TP 关键）

    def to_dict(self) -> dict:
        return {
            "applicable": self.applicable,
            "defense_applied": self.defense_applied,
            "flipped": self.flipped,
            "confirmed_after": self.confirmed_after,
            "already_defended": self.already_defended,
        }


class DefenseInjector:
    """按 taint_type 对代码施加最小防御性扰动（sink 行内变量消毒包裹）。"""

    def inject(self, code: str, taint_type: str, sink_line: int) -> tuple[str, str]:
        """注入防御，返回 (扰动代码, 防御描述)；不适用返回 (code, "")。"""
        templates = _DEFENSE_TEMPLATES.get(taint_type)
        if not templates or sink_line <= 0:
            return code, ""
        lines = code.splitlines()
        if sink_line - 1 >= len(lines):
            return code, ""
        target = lines[sink_line - 1]
        for anchor, apply_fn in templates:
            if anchor.search(target):
                new_line = apply_fn(target)
                if new_line != target:
                    lines[sink_line - 1] = new_line
                    return "\n".join(lines), f"{taint_type}→防御注入 @L{sink_line}"
        return code, ""


class CounterfactualVerifier:
    """反事实扰动验证器：判有漏洞的 finding → 注入防御 → 重跑裁决 → 判定翻转。"""

    def __init__(self, client, system_prompt: str, num_ctx: int = 8192) -> None:
        self._client = client
        self._system_prompt = system_prompt
        self._num_ctx = num_ctx
        self._injector = DefenseInjector()

    def sync_runtime(self, client=None, system_prompt: Optional[str] = None) -> None:
        """外部同步推理运行时（switch_model 后由 TwoStageScanner.sync_runtime 调用）。

        2026-08-15 修复：此前实例在构造时捕获 client/system_prompt，后端切模型后
        只同步主扫描器，本验证器永远停留在启动时的 prompt 上（client 侥幸因原地
        mutate 是同一对象，prompt 是真 bug）。现在统一经 sync_runtime 跟随。
        """
        if client is not None:
            self._client = client
        if system_prompt is not None:
            self._system_prompt = system_prompt

    def verify(
        self,
        code: str,
        language: str,
        taint_type: str,
        sink_line: int,
        build_prompt,
        temperature: float = 0.1,
        source_line: int = 0,
    ) -> CounterfactualResult:
        """对判"有漏洞"的 finding 做反事实扰动验证。

        Args:
            code: 原始代码
            language: 语言标签
            taint_type: finding 的漏洞类型（选择防御模板）
            sink_line: sink 行号（1-indexed，扰动锚点）
            build_prompt: 构造裁决 prompt 的 callable（建议 finding 级 triage prompt，
                2026-08-15 修复：原开放扫描 prompt 问"整文件有无漏洞"——多 finding
                文件修掉一个还剩另一个 → 不翻转 → 被误判"模式匹配"；finding 级
                问句只裁决本 finding，消除该偏差）
            temperature: 翻转判定用低温（稳定，不采样）
            source_line: 污点源行号（0=未知；用于限定 already_defended 检查范围）

        Returns:
            CounterfactualResult：flipped=True（模型理解防御→A级可回填）/
            flipped=False（模式匹配→C/D级）或不可用。
        """
        if (language or "").lower() not in _VERIFIABLE_LANGS:
            return CounterfactualResult(applicable=False)

        perturbed, defense = self._injector.inject(code, taint_type, sink_line)
        if not defense:
            return CounterfactualResult(applicable=False)  # 无适用模板

        # 判定"原始代码是否已含同类防御"（区分 FP/TP：已含→模型没识别=误报；
        # 未含→模型理解防御=真阳性）。
        # 2026-08-15 修复：原实现全文搜索——文件任何位置一个 json.loads 就让全文件
        # 的 pickle finding 标记"已防御"。防御必须在污点传播路径（source→sink）上
        # 才可能拦截本 finding 的数据流；source 未知时退化为 sink 前 15 行窗口。
        already_defended = False
        sig = _DEFENSE_SIGNATURES.get(taint_type)
        if sig is not None:
            lines = code.splitlines()
            lo = source_line if source_line > 0 else max(1, sink_line - 15)
            lo = max(1, min(lo, sink_line))
            scope = "\n".join(lines[lo - 1:sink_line])
            already_defended = sig.search(scope) is not None

        # 重跑单次裁决（低温），用扰动后的代码
        try:
            prompt = build_prompt(perturbed, language)  # 纯位置传参，兼容任意参数名
            resp = self._client.generate(
                prompt=prompt,
                system_prompt=self._system_prompt,
                temperature=temperature,
                max_tokens=600,
                num_ctx=self._num_ctx,
            )
            text = resp.get("text", "") if isinstance(resp, dict) else ""
        except Exception:
            return CounterfactualResult(applicable=True, perturbed_code=perturbed,
                                        defense_applied=defense, confirmed_after=None)

        from graduation_project.schema import parse_verdict, normalize_has_vulnerability
        from graduation_project.two_stage_scanner import parse_triage_verdict, _normalize_confirmed
        # 宽松解析：兼容开放生成（has_vulnerability）与裁决式（is_confirmed）两种输出
        hv = None
        verdict = parse_verdict(text) if text else None
        if verdict:
            hv = normalize_has_vulnerability(verdict.get("has_vulnerability"))
        if hv is None:
            tv = parse_triage_verdict(text) if text else None
            confirmed = _normalize_confirmed(tv.get("is_confirmed")) if tv else None
            if confirmed is not None:
                hv = confirmed  # is_confirmed=true ↔ has_vulnerability=true

        result = CounterfactualResult(
            applicable=True,
            perturbed_code=perturbed,
            defense_applied=defense,
            confirmed_after=hv,
            already_defended=already_defended,
        )
        # 翻转判定：扰动后判安全 → 模型理解防御（A 级）；仍判漏洞 → 模式匹配（C/D 级）
        if hv is False:
            result.flipped = True
        elif hv is True:
            result.flipped = False
        else:
            result.flipped = None  # 解析失败：不作翻转判定
        return result


# ---------------------------------------------------------------------------
# 自检（离线，2026-08-15 新增：覆盖 already_defended 范围限定与 sync_runtime）
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=== 反事实验证器自检（离线） ===\n")

    from graduation_project.schema import parse_verdict  # noqa: F401

    class FakeClient:
        def __init__(self): self.calls = []
        def generate(self, **kw):
            self.calls.append(kw)
            return {"text": '```json\n{"has_vulnerability": false}\n```'}

    # 1) already_defended 只看 source→sink 区间：文件尾部无关的 json.loads
    #    不得让 line 5 的 pickle.loads finding 标记"已防御"
    code = "\n".join([
        "import pickle",
        "def load(data):",
        "    return pickle.loads(data)  # L3 sink",
        "x = 1",
        "import json",
        "cfg = json.loads(open('c.json').read())  # L6 无关防御",
    ])
    v = CounterfactualVerifier(client=FakeClient(), system_prompt="sys")
    res = v.verify(code=code, language="python", taint_type="Insecure Deserialization",
                   sink_line=3, source_line=3,
                   build_prompt=lambda c, l: f"prompt:{l}")
    ok1 = res.applicable and res.already_defended is False and res.flipped is True
    print(f"[{'PASS' if ok1 else 'FAIL'}] already_defended 范围限定: "
          f"applicable={res.applicable}, already_defended={res.already_defended}")

    # 1b) 反例：sink 邻域真有 json.loads（防御在路径上）→ already_defended=True
    code2 = "\n".join([
        "import pickle, json",
        "raw = open('f').read()",
        "safe = json.loads(raw)  # L3 防御（在 source 前仍属传播路径窗口）",
        "obj = pickle.loads(safe)  # L4 sink",
    ])
    res2 = v.verify(code=code2, language="python", taint_type="Insecure Deserialization",
                    sink_line=4, source_line=2,
                    build_prompt=lambda c, l: "p")
    ok1b = res2.already_defended is True
    print(f"[{'PASS' if ok1b else 'FAIL'}] 路径上真防御仍识别: already_defended={res2.already_defended}")

    # 2) sync_runtime：切模型后 prompt/client 跟随
    c2 = FakeClient()
    v.sync_runtime(client=c2, system_prompt="new-prompt")
    v.verify(code=code, language="python", taint_type="Insecure Deserialization",
             sink_line=3, build_prompt=lambda c, l: "p")
    ok2 = c2.calls and c2.calls[-1]["system_prompt"] == "new-prompt"
    print(f"[{'PASS' if ok2 else 'FAIL'}] sync_runtime: system_prompt 已跟随 "
          f"({c2.calls[-1]['system_prompt'] if c2.calls else '无调用'})")

    all_ok = all([ok1, ok1b, ok2])
    print(f"\n{'=== 自检通过 ===' if all_ok else '!!! 自检失败 !!!'}")
    sys.exit(0 if all_ok else 1)
