"""文件级风险打分与注意力预算调度（2026-08-31）。

背景（docs 未覆盖的架构缺口，见本文件末尾自检）：
  仓库/URL 批量扫描此前按 `os.walk` 顺序取前 `max_files`（默认 50）即 break
  （app/backend/main.py::_clone_and_collect）。这是**盲目截断**：大仓库里
  `utils/`、`models/`、`dto/` 常常排在 `auth/`、`api/` 之前，50 个名额可能
  被低危文件吃光——高危文件压根没进扫描。此时优化"每个文件复核多快"没有
  意义：复核再快，也救不了没被选中的文件。

本模块提供**纯确定性**的文件风险打分 + 预算分配：

  - 打分只用**语言习语级知识**：路径语义（auth/api/payment/crypto…）+ 公开
    漏洞形态词表（sink/外部源/入口点，与 `two_stage_scanner._PRESCREEN_*`
    同源同口径）。**不从任何测试样本挖掘**——样本挖掘属于 `SignalRegistry`
    的 learn_pool 通道（须经独立验证集审批），两者严格分离以防过拟合。
  - 分配在给定预算（文件数 / 总字符数）下按分从高到低取；未覆盖的文件
    **显式回报**（`BudgetPlan.uncovered`），绝不静默丢弃——与本项目一贯的
    "消除静默性"原则（`suppressed_by_registry` / `dropped_unowned` 留痕）
    同构：预算外文件也是"没扫到"的一种，必须可被审计。
  - 可选同构折叠：大仓库里 `model/dto/schema/entity` 常几十个近重复文件，
    按结构指纹折叠后只扫代表文件，其余记入 `duplicates_folded`。

纯确定性（同输入必同输出、无随机、无 LLM）→ 可复现、可审计、可进论文消融。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence

# ---------------------------------------------------------------------------
# 路径语义：高危 / 低危（语言习语级知识，非样本拟合）
# ---------------------------------------------------------------------------
# 高危路径词：这些目录/文件名在 Web 应用里承载认证、授权、支付、密码学、
# 外部输入入口、文件操作——是漏洞的统计学高发区（OWASP Top 10 的载体分布）。
_HIGH_PATH_RE = re.compile(
    r"(auth|login|logout|signin|signup|session|password|passwd|credential|"
    r"secret|token|jwt|oauth|saml|apikey|api_key|"
    r"admin|permission|role|acl|rbac|policy|guard|"
    r"payment|billing|invoice|order|checkout|wallet|refund|transaction|"
    r"crypto|cipher|encrypt|decrypt|hash|digest|signature|cert|ssl|tls|"
    r"upload|download|file|storage|bucket|s3|blob|"
    r"route|router|view|views|handler|controller|endpoint|middleware|webhook|"
    r"proxy|redirect|callback|oauth|fetch|client|http|request)", re.I)

# 低危路径/文件名：测试、示例、文档、迁移、生成产物、纯声明文件。
# 注意 settings/config 只是**降低**优先级（debug=True 是真实风险），
# 不排除——故权重绝对值小于高危词。
_LOW_PATH_RE = re.compile(
    r"(^|/)(tests?|testing|spec|__tests__|e2e|fixtures?|mocks?|stubs?|"
    r"examples?|samples?|demo|docs?|website|migrations?|vendor|third_party|thirdparty|"
    r"dist|build|\.next|coverage|benchmarks?|bench)/|"
    # 注意：本组**不能以 $ 结尾**。`(A|B|C)$` 的 $ 作用于整个交替组（而非仅最后
    # 一项），会让 `app/__init__.py` 在 `__init__\.` 分支匹配后仍剩 "py" 而整体
    # 失败——(^|/)(\w+/)? 前缀已锚定路径段边界，无需 $（2026-08-31 自检实锤）。
    r"(^|/)(\w+/)?(test_[\w-]*|_test\.|[\w-]+\.test\.|[\w-]+\.spec\.|conftest\.|"
    r"__init__\.|setup\.|manage\.|wsgi\.|asgi\.|celery\.|gunicorn[\w-]*\.|"
    r"constants?\.|enums?\.|enum\.|types?\.|typings?\.|"
    r"[\w-]*\.d\.ts)", re.I)

# 中等降权：配置/ORM 模型/DTO/序列化层——有风险但通常不是主攻击面
_MID_PATH_RE = re.compile(
    r"(^|/)(settings?|config|conf|configuration|env|options|defaults?|"
    r"models?|entities?|dto|schemas?|serializers?|migrations?|"
    r"forms?|validators?|utils?|helpers?|common|shared|lib)/|"
    r"(^|/)(settings?|config|models?|schema|serializers?)\.(py|js|ts|java|rb|php|go)$", re.I)

# ---------------------------------------------------------------------------
# 内容形态词表（与 two_stage_scanner._PRESCREEN_* 同源同口径，此处独立定义
# 以切断与扫描器的循环依赖；两处修改需同步）
# ---------------------------------------------------------------------------
_SINK_RE = re.compile(
    r"(\.execute\(|\.executemany\(|\.query\(|queryrow\(|"
    r"os\.system\(|subprocess\.|popen\(|runtime\.getruntime\(\)|processbuilder|"
    r"child_process|execcommand|\beval\(|new function\(|settimeout\(\s*['\"]|"
    r"unserialize\(|pickle\.loads\(|objectinputstream|readobject\(|"
    r"xmlparserfactory|documentbuilderfactory|saxparserfactory|"
    r"external-general-entities|xpath\.evaluate\(|xpathcompile\(|"
    r"sendredirect\(|redirect\(\s*[a-z_]|urlfetch|httpclient\.(get|post)|requests\.(get|post)|"
    r"\bmd5\b|\bsha1\b|\bdes\b|\becb\b|cipher\.getinstance|"
    r"open\(\s*[^)]*\+|readfile\(|file_get_contents|os\.open\(|ioutil\.readfile)", re.I)
_SOURCE_RE = re.compile(
    r"(request\.|\bparams\b|\bargs\b\[|query_params|getparameter\(|headers\[|header\(|"
    r"\bbody\b|form\[|formdata|cookies?\[|argv|stdin|environ|os\.args|r\.url|"
    r"reader\.readline|scanner\.|bufferedreader|inputstream)", re.I)
_ENTRY_RE = re.compile(
    r"(@app\.route|@router\.|@restcontroller|@requestmapping|@getmapping|@postmapping|"
    r"@api_view|@csrf_exempt|func\s+\w*handler|http\.responsewriter|app\.(get|post|use)\(|"
    r"router\.(get|post)\(|def (do_get|do_post)\(|public .*\(\s*(httpservletrequest|context))", re.I)

# 硬编码凭证提示（2026-08-31 验证轮补充，CWE-798 / OWASP A07 载体）。
# 依据（语言级事实，非样本拟合）：凭证语义的标识符**赋值为非空字符串字面量**
# 是硬编码凭证的标准形态；从环境/配置读取（os.getenv / process.env / 字面量为空）
# 是标准安全写法，天然不命中——右侧必须以引号开头，env 调用在赋值处不匹配。
# 定位是**弱风险提示**（只影响预算排序，不产生判定）：注释里的同形文本也会
# 计入，可接受——打分的唯一目的是决定"先扫谁"。
# `=` 判定用 (?<![=!<>])=(?!=)：`if password == "x"` 等比较不会误命中。
_SECRET_HINT_RE = re.compile(
    r"[\w$]*(?:secret|passw(?:or)?d|pwd|api_?key|apikey|auth_?token|"
    r"access_?token|token|private_?key|client_?secret|credential)[\w$]*"
    r"\s*(?::|(?<![=!<>])=(?!=))\s*['\"][^'\"]+['\"]", re.I)

# 单模式计次封顶，防单行刷分（与 _prescreen_chunks 同口径）
_REPEAT_CAP = 5

# 折叠的风险上限：只有风险分**低于**此值的文件才允许被同构折叠。
# 高于此分的文件（含外部源/sink/入口点，有实际攻击面）**永不折叠**——
# 折叠的收益是算力，代价是潜在漏扫；对零风险文件（DTO/常量表/复制粘贴的
# 声明层）这个交换划算，对有攻击面的文件不划算（2026-08-31：放宽数字归一化
# 后，两个"仅字段名不同"的高分文件也被折叠，据此加此闸门）。
# 由于 allocate 按分数降序遍历，同指纹组内**代表永远是最高分那个文件**。
FOLD_MAX_RISK_SCORE = 0.0

# 打分权重（确定性常量，供论文复现与消融）
W_PATH_HIGH = 3.0        # 每个高危路径词
W_PATH_HIGH_CAP = 9.0    # 路径高危分封顶
W_PATH_LOW = -6.0        # 测试/示例/文档/生成产物
W_PATH_MID = -2.0        # 配置/模型/DTO/工具层
# 内容分双通道（2026-08-31 自检修正）：
#   绝对量（absolute）：防短文件密度虚高——8 行文件含 1 sink 的"每百行密度"
#     是 500 行文件含 5 sink 的 12 倍，纯密度会让小工具脚本盖过核心业务文件。
#   密度（absolute × per100）：防大文件稀释——巨型文件靠绝对量封顶会丢信号。
# 两通道各封顶后相加，兼顾"总量"与"浓度"。
W_ABS_CAP = 15.0
W_DENSITY_CAP = 15.0
W_TINY_FILE = -12.0      # < _TINY_LINES 行：__init__.py/常量表，无漏洞载体
W_HUGE_FILE = -6.0       # > _HUGE_LINES 行：多为生成代码，且复核成本极高
W_HAS_ENTRY = 4.0        # 含 Web 入口点（路由/控制器）：直接暴露的攻击面
W_HAS_SOURCE = 3.0       # 含外部输入源
W_HAS_SINK = 3.0         # 含危险 sink
# 硬编码凭证是**直接的漏洞证据**（CWE-798 本身），与"攻击面标记"不同档：
# 无凭证词表的打分会把纯凭证文件排到队尾（验证实锤：typical_06_secret 类
# 文件在 87 段排名 86/87），预算紧张时 CWE-798 整类被饿死。
W_SECRET_HINT = 4.0      # 每处凭证字面量
W_SECRET_CAP = 2         # 计次封顶（与 _REPEAT_CAP 同思路，防单文件刷分）

_TINY_LINES = 5
_HUGE_LINES = 3000


@dataclass
class FileRisk:
    """单个文件的风险评分与可审计的分项依据。"""
    path: str
    language: str = ""
    score: float = 0.0
    lines: int = 0
    chars: int = 0
    # 分项依据（供报告/审计展示"为什么这个文件排前面"）
    signals: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "language": self.language,
            "score": round(self.score, 2),
            "lines": self.lines,
            "chars": self.chars,
            "signals": {k: (round(v, 2) if isinstance(v, float) else v)
                        for k, v in self.signals.items()},
        }


@dataclass
class BudgetPlan:
    """预算分配结果。

    selected  —— 预算内、建议扫描的文件（按风险分降序）
    uncovered —— 预算外未扫描文件（**显式回报，不静默丢弃**）
    folded    —— 被同构折叠的近重复文件（不计入 selected，但可审计）
    """
    selected: list[FileRisk] = field(default_factory=list)
    uncovered: list[FileRisk] = field(default_factory=list)
    folded: list[FileRisk] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "selected": [f.to_dict() for f in self.selected],
            "uncovered": [f.to_dict() for f in self.uncovered],
            "folded": [f.to_dict() for f in self.folded],
            "selected_count": len(self.selected),
            "uncovered_count": len(self.uncovered),
            "folded_count": len(self.folded),
        }


# ---------------------------------------------------------------------------
# 打分
# ---------------------------------------------------------------------------
def _count_capped(pattern: re.Pattern, text: str) -> int:
    return min(len(pattern.findall(text)), _REPEAT_CAP)


def score_file(path: str, language: str, code: str) -> FileRisk:
    """对单个文件做确定性风险打分（越高越应先获得扫描注意力）。

    打分的**唯一目的**是在预算不足时决定"先扫谁"，不做任何安全判定：
    分低 ≠ 安全，分高 ≠ 有漏洞。所有未覆盖文件都会显式回报给调用方。

    Args:
        path: 文件路径（相对路径即可，用于路径语义打分）
        language: 语言标识（仅记录，不参与打分——词表已是跨语言习语级）
        code: 文件内容全文

    Returns:
        FileRisk（score 可为负；signals 含分项依据）
    """
    norm_path = (path or "").replace("\\", "/")
    lines = code.count("\n") + 1 if code else 0
    fr = FileRisk(path=path, language=language, lines=lines, chars=len(code or ""))

    sig: dict = {}
    score = 0.0

    # 1) 路径语义
    is_low_path = bool(_LOW_PATH_RE.search(norm_path))
    # 测试/示例目录里的高危词是噪声（tests/test_auth.py 的 "auth" 不代表攻击面），
    # 命中 low 时不再累加 path_high——否则测试文件会凭文件名挤占预算。
    n_high = 0 if is_low_path else len(
        set(m.group(0).lower() for m in _HIGH_PATH_RE.finditer(norm_path)))
    path_high = min(n_high * W_PATH_HIGH, W_PATH_HIGH_CAP)
    sig["path_high_terms"] = n_high
    score += path_high

    if is_low_path:
        sig["path_low"] = True
        score += W_PATH_LOW

    path_mid = W_PATH_MID if _MID_PATH_RE.search(norm_path) else 0.0
    if path_mid:
        sig["path_mid"] = True
        score += path_mid

    # 2) 内容形态（绝对量 + 密度双通道）
    if code:
        n_sink = _count_capped(_SINK_RE, code)
        n_src = _count_capped(_SOURCE_RE, code)
        n_ent = _count_capped(_ENTRY_RE, code)
        absolute = n_sink * 3 + n_src * 2 + n_ent * 1
        per100 = 100.0 / max(1, lines)
        content = (min(absolute, W_ABS_CAP)
                   + min(absolute * per100, W_DENSITY_CAP))
        sig.update({"n_sink": n_sink, "n_source": n_src, "n_entry": n_ent,
                    "content_abs": round(min(absolute, W_ABS_CAP), 2),
                    "content_density": round(min(absolute * per100, W_DENSITY_CAP), 2)})
        score += content

        if n_ent:
            score += W_HAS_ENTRY
            sig["has_entry"] = True
        if n_src:
            score += W_HAS_SOURCE
            sig["has_source"] = True
        if n_sink:
            score += W_HAS_SINK
            sig["has_sink"] = True

        # 2.5) 硬编码凭证提示（CWE-798 直接证据，见 _SECRET_HINT_RE 说明）
        n_secret = 0
        for m in _SECRET_HINT_RE.finditer(code):
            # 右侧是 env/配置读取的标准安全写法时整体不匹配（引号起始要求），
            # 此处只需防"同一行多次出现"的计数膨胀
            n_secret += 1
            if n_secret >= W_SECRET_CAP:
                break
        if n_secret:
            score += n_secret * W_SECRET_HINT
            sig["n_secret"] = n_secret

    # 3) 体量修正（成本与载体能力的平衡）
    if lines < _TINY_LINES:
        score += W_TINY_FILE
        sig["tiny_file"] = True
    elif lines > _HUGE_LINES:
        score += W_HUGE_FILE
        sig["huge_file"] = True

    fr.score = round(score, 3)
    fr.signals = sig
    return fr


def score_files(files: Sequence[tuple[str, str, str]]) -> list[FileRisk]:
    """批量打分（(path, language, code) → 按分降序的 FileRisk 列表）。

    同分时按 path 升序，保证排序稳定可复现（避免 os.walk 顺序不确定性）。
    """
    scored = [score_file(p, lg, cd) for p, lg, cd in files]
    scored.sort(key=lambda f: (-f.score, f.path))
    return scored


# ---------------------------------------------------------------------------
# 同构折叠（结构指纹）
# ---------------------------------------------------------------------------
_COMMENT_PREFIXES = ("#", "//", "/*", "*", "--", ";", "<!--")


def structural_fingerprint(code: str) -> str:
    """结构指纹：剥离注释/空白/字符串字面量后的摘要。

    目的不是精确判重，而是识别"同构文件"（同一模板生成的 model/dto/entity
    系列）。它们风险形态高度雷同，扫描一个代表即可，其余折叠——这是大仓库
    最大的一块冗余算力。

    剥离字符串字面量是必要的：同构 DTO 的差异往往只在字段名字符串上。
    """
    if not code:
        return hashlib.md5(b"").hexdigest()
    stripped_lines = []
    for raw in code.split("\n"):
        line = raw.strip()
        if not line or line.startswith(_COMMENT_PREFIXES):
            continue
        # 去字符串/模板字面量内容（保留类型轮廓，抹掉具体值）
        line = re.sub(r'"[^"]*"', '""', line)
        line = re.sub(r"'[^']*'", "''", line)
        line = re.sub(r"`[^`]*`", "``", line)
        # 去数字（同构文件的序号差异）。**不能加 \b 词边界**：同模板生成的
        # Dto0/Dto19、Order1Repo/Order2Repo 里数字紧跟字母，\b 不成立会导致
        # 它们指纹不同、折叠失效——而"仅序号不同"正是同构文件的主要形态
        # （2026-08-31 仓库实测：20 个 DTO 全部未折叠，folded=0）。
        # 代价是 buf_1024/buf_4096 这类也会折叠，但其结构相同、风险形态相同，
        # 且被折叠文件在 BudgetPlan.folded 里显式回报、可审计。
        line = re.sub(r"\d+", "0", line)
        line = re.sub(r"\s+", "", line)
        if line:
            stripped_lines.append(line)
    return hashlib.md5("\n".join(stripped_lines).encode("utf-8", "replace")).hexdigest()


# ---------------------------------------------------------------------------
# 预算分配
# ---------------------------------------------------------------------------
def allocate(
    files: Sequence[tuple[str, str, str]],
    max_files: Optional[int] = None,
    max_chars: Optional[int] = None,
    fold_duplicates: bool = True,
    min_score: Optional[float] = None,
    fold_max_risk_score: float = FOLD_MAX_RISK_SCORE,
) -> BudgetPlan:
    """在预算内按风险分从高到低选取文件，未覆盖者显式回报。

    Args:
        files: (path, language, code) 序列
        max_files: 文件数预算（None = 不限文件数）
        max_chars: 总字符预算（None = 不限字符）；与 max_files 是"与"关系
        fold_duplicates: 是否折叠同构文件（仅对风险分 < fold_max_risk_score
            的文件生效；同指纹组内保留分数最高的那个作为代表）
        min_score: 分数下限（低于此值不选，但仍计入 uncovered）
        fold_max_risk_score: 折叠的风险上限（见 FOLD_MAX_RISK_SCORE 注释）

    Returns:
        BudgetPlan。selected 已按风险分降序；调用方按此顺序扫描即可。
    """
    plan = BudgetPlan()
    scored = score_files(files)

    pool: list[FileRisk] = []
    seen_fp: set[str] = set()
    by_path = {(p, lg): cd for p, lg, cd in files}
    for fr in scored:
        if fold_duplicates and fr.score < fold_max_risk_score:
            fp = structural_fingerprint(by_path.get((fr.path, fr.language), ""))
            if fp in seen_fp:
                plan.folded.append(fr)
                continue
            seen_fp.add(fp)
        pool.append(fr)

    used_chars = 0
    for fr in pool:
        if max_files is not None and len(plan.selected) >= max_files:
            plan.uncovered.append(fr)
            continue
        if max_chars is not None and used_chars + fr.chars > max_chars and plan.selected:
            # 已选到内容后再超预算即停；单个超大文件仍允许选中一次（保底不空）
            plan.uncovered.append(fr)
            continue
        if min_score is not None and fr.score < min_score:
            plan.uncovered.append(fr)
            continue
        plan.selected.append(fr)
        used_chars += fr.chars
    return plan


def plan_to_files(
    plan: BudgetPlan,
    files: Sequence[tuple[str, str, str]],
) -> list[tuple[str, str, str]]:
    """把 BudgetPlan.selected 映射回 (path, language, code) 三元组（保持风险序）。"""
    index = {}
    for p, lg, cd in files:
        index.setdefault((p, lg), cd)
    out = []
    for fr in plan.selected:
        cd = index.get((fr.path, fr.language))
        if cd is not None:
            out.append((fr.path, fr.language, cd))
    return out


# ---------------------------------------------------------------------------
# 自检（离线，与 signal_registry.py 同风格）
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    print("=== 文件风险打分 / 预算分配 自检（离线）===\n")

    VULN_PY = ("import sqlite3\nfrom flask import request, render_template_string\n"
               "@app.route('/user')\ndef user():\n"
               "    uid = request.args.get('id')\n"
               "    cur = sqlite3.connect('a.db').cursor()\n"
               "    cur.execute('SELECT * FROM u WHERE id=' + uid)\n"
               "    return render_template_string('<p>' + uid + '</p>')\n")
    MODEL_PY = ("from django.db import models\n"
                "class User(models.Model):\n"
                "    name = models.CharField(max_length=64)\n"
                "    email = models.EmailField()\n")
    TEST_PY = ("def test_login():\n    assert login('a', 'b') is True\n")
    INIT_PY = ""
    UTIL_PY = ("def fmt(x):\n    return str(x).strip()\n" * 3)

    f_vuln = score_file("app/api/auth/login.py", "python", VULN_PY)
    f_model = score_file("app/models/user.py", "python", MODEL_PY)
    f_test = score_file("tests/test_auth.py", "python", TEST_PY)
    f_init = score_file("app/__init__.py", "python", INIT_PY)
    f_util = score_file("app/utils/helpers.py", "python", UTIL_PY)

    # 只断言"高危最高、空文件最低"与"测试/示例低于业务目录"——中间层的
    # utils/models 同属低危且无内容信号，分数本就该接近（不人为制造全序）。
    ok1 = (f_vuln.score > max(f_util.score, f_model.score)
           and f_vuln.score > f_test.score
           and f_init.score == min(f_vuln.score, f_util.score, f_model.score,
                                   f_test.score, f_init.score)
           and f_test.score < f_model.score)
    print(f"[{'PASS' if ok1 else 'FAIL'}] 风险排序: "
          f"auth/login={f_vuln.score:.1f} | utils={f_util.score:.1f} "
          f"models={f_model.score:.1f} | tests={f_test.score:.1f} | "
          f"__init__={f_init.score:.1f}")

    # 1b) 测试目录里的高危词不得加分（tests/test_auth.py 的 "auth" 是噪声）
    ok1b = f_test.signals.get("path_high_terms") == 0 and f_test.signals.get("path_low")
    print(f"[{'PASS' if ok1b else 'FAIL'}] 测试目录高危词噪声抑制: "
          f"path_high_terms={f_test.signals.get('path_high_terms')}, "
          f"path_low={f_test.signals.get('path_low')}")

    # 2) 盲目截断 vs 预算调度：同一仓库，50 个 util 文件 + 1 个 auth 文件，
    #    预算 10 —— 旧行为（os.walk 顺序）漏掉 auth，预算调度必选 auth。
    #    注：区分符必须是**标识符**而非注释/数字——结构指纹会剥离注释并把
    #    数字归一化为 0，否则 50 个 util 会被误判为同构（自检自身踩过的坑）。
    many_utils = [(f"app/utils/u{i}.py", "python",
                   UTIL_PY + f"\nVAR_{chr(97 + i // 26)}{chr(97 + i % 26)} = 1\n")
                  for i in range(50)]
    auth_file = ("app/auth/session_token.py", "python", VULN_PY)
    repo_files = many_utils + [auth_file]
    # 模拟 os.walk 盲目截断（auth 排在最后）
    blind_cut = repo_files[:10]
    ok2_blind = auth_file[0] not in {p for p, _, _ in blind_cut}
    plan = allocate(repo_files, max_files=10)
    ok2 = ok2_blind and any(f.path == auth_file[0] for f in plan.selected)
    print(f"[{'PASS' if ok2 else 'FAIL'}] 预算调度保住高危文件: "
          f"盲目截断漏掉={ok2_blind}, 预算调度选中="
          f"{any(f.path == auth_file[0] for f in plan.selected)}, "
          f"uncovered={len(plan.uncovered)}")

    # 3) 未覆盖文件显式回报（不静默丢弃）：三类互斥且穷尽
    total = len(plan.selected) + len(plan.uncovered) + len(plan.folded)
    ok3 = total == len(repo_files) and len(plan.uncovered) > 0
    print(f"[{'PASS' if ok3 else 'FAIL'}] uncovered 显式回报: "
          f"selected={len(plan.selected)}, uncovered={len(plan.uncovered)}, "
          f"folded={len(plan.folded)}, 合计={total}/{len(repo_files)}")

    # 4) 同构折叠：仅折叠**结构指纹完全相同**的文件（保守策略——折叠错了就是
    #    漏扫，代价远大于省下的算力，故不折叠"仅字段名不同"的近似文件）。
    exact_dups = [(f"app/dto/Copy{i}.py", "python", MODEL_PY) for i in range(20)]
    plan_dup = allocate(exact_dups, max_files=100, fold_duplicates=True)
    ok4a = len(plan_dup.selected) == 1 and len(plan_dup.folded) == 19
    # 字段名不同的低危 DTO（数字归一化后指纹相同）→ 可折叠（同模板产物）
    varied = [(f"app/dto/Entity{i}.py", "python",
               MODEL_PY.replace("User", f"Entity{i}").replace("name", f"name{i}"))
              for i in range(20)]
    plan_var = allocate(varied, max_files=100, fold_duplicates=True)
    ok4b = len(plan_var.folded) == 19 and len(plan_var.selected) == 1
    # 保守性（关键）：**高分文件永不折叠**，哪怕内容完全相同。
    # 折叠的代价是潜在漏扫，对有攻击面的文件不划算。
    hot_dups = [(f"app/api/route{i}.py", "python", VULN_PY) for i in range(10)]
    plan_hot = allocate(hot_dups, max_files=100, fold_duplicates=True)
    ok4c = len(plan_hot.folded) == 0 and len(plan_hot.selected) == 10
    ok4 = ok4a and ok4b and ok4c
    print(f"[{'PASS' if ok4 else 'FAIL'}] 同构折叠（低危折叠/高危不折）: "
          f"相同DTO→{len(plan_dup.selected)}选/{len(plan_dup.folded)}折叠, "
          f"异名DTO→{len(plan_var.selected)}选/{len(plan_var.folded)}折叠, "
          f"高危同文→{len(plan_hot.selected)}选/{len(plan_hot.folded)}折叠(期望0)")

    # 5) 确定性（同输入两次打分必相同）+ 稳定性（同分按 path 排序）
    a = [f.score for f in score_files(repo_files)]
    b = [f.score for f in score_files(repo_files)]
    ok5 = a == b
    print(f"[{'PASS' if ok5 else 'FAIL'}] 确定性: 两次打分一致={a == b}")

    # 6) 字符预算生效
    plan3 = allocate(repo_files, max_chars=200)
    ok6 = len(plan3.selected) >= 1 and sum(f.chars for f in plan3.selected) <= max(
        200, min(f.chars for f in plan3.selected))
    print(f"[{'PASS' if ok6 else 'FAIL'}] 字符预算: selected={len(plan3.selected)}, "
          f"chars={sum(f.chars for f in plan3.selected)}")

    # 7) plan_to_files 保持风险序且能取回原文
    out_files = plan_to_files(plan, repo_files)
    ok7 = (len(out_files) == len(plan.selected)
           and any(p == auth_file[0] for p, _, _ in out_files)
           and dict(((p, lg), cd) for p, lg, cd in out_files).get(
               (auth_file[0], "python")) == VULN_PY)
    print(f"[{'PASS' if ok7 else 'FAIL'}] plan_to_files 回映射: "
          f"{len(out_files)} 个文件, 含 auth={any(p == auth_file[0] for p, _, _ in out_files)}")

    # 8) 硬编码凭证提示（2026-08-31 验证轮）：字面量凭证提权，env/比较不误提。
    #    样本须 ≥5 行：tiny-file 惩罚（-12）会把信号差淹没，测不出本用例意图。
    SECRET_PY = ("import os\nfrom flask import Flask\n"
                 "app = Flask(__name__)\n"
                 "SECRET_KEY = 'sk-live-9af1c2'\n"
                 "DB_PASSWORD = 'hunter2'\n"
                 "def health():\n    return 'ok'\n")
    SECRET_ENV_PY = ("import os\nfrom flask import Flask\n"
                     "app = Flask(__name__)\n"
                     "SECRET_KEY = os.getenv('SECRET_KEY')\n"
                     "DB_PASSWORD = ''\n"
                     "def health():\n    return 'ok'\n")
    f_secret = score_file("app/config.py", "python", SECRET_PY)
    f_secret_env = score_file("app/config.py", "python", SECRET_ENV_PY)
    f_plain = score_file("app/config.py", "python",
                         "import os\nfrom flask import Flask\n"
                         "app = Flask(__name__)\n"
                         "DEBUG_FLAG = True\n"
                         "def health():\n    return 'ok'\n")
    ok8 = (f_secret.signals.get("n_secret") == 2
           and f_secret.score > f_secret_env.score
           and f_secret_env.signals.get("n_secret") is None
           and f_secret.score > f_plain.score)
    print(f"[{'PASS' if ok8 else 'FAIL'}] 凭证提示: 字面量={f_secret.signals.get('n_secret')}处 "
          f"score={f_secret.score} > env/空值={f_secret_env.score}(n_secret={f_secret_env.signals.get('n_secret')}) "
          f"> 普通文件={f_plain.score}")
    # 比较语句（==）不计数
    f_cmp = score_file("app/x.py", "python", 'if password == "hunter2":\n    pass\n')
    ok8b = f_cmp.signals.get("n_secret") is None
    print(f"[{'PASS' if ok8b else 'FAIL'}] 凭证提示·比较不误计: "
          f"n_secret={f_cmp.signals.get('n_secret')}")

    all_ok = all([ok1, ok1b, ok2, ok3, ok4, ok5, ok6, ok7, ok8, ok8b])
    print(f"\n{'=== 自检通过 ===' if all_ok else '!!! 自检失败 !!!'}")
    sys.exit(0 if all_ok else 1)
