"""
外部扫描器模块 —— 封装传统 SAST / SCA / Secret / IaC 工具，作为 LLM 扫描的并行预筛层。

设计目标：
- 将 Bandit / Semgrep / Gitleaks / Trivy 等成熟工具的输出统一为 ExternalFinding 结构，
  与 prefilter.py（正则预筛）互补：prefilter 是"规则匹配"，本模块是"调用真实工具"。
- 所有工具可选，通过 shutil.which() 探测安装情况；未安装的工具静默跳过，不影响其他工具。
- 每个工具以子进程方式运行，输出 JSON，超时 60s；解析失败或工具异常均降级为空结果。
- scan() 聚合 SAST + Secret + SCA + IaC 四类扫描结果，供上层与 LLM 结果融合。

与 prefilter.py 的关系：
- prefilter.py 在 LLM 调用"之前"做正则快速预筛（毫秒级）；
- 本模块在 LLM 调用"之前/并行"调用传统工具（秒级），提供更高召回的候选发现；
- 二者结果均可作为 LLM 的辅助输入，构成"传统工具 + LLM"的混合扫描架构。

注意：本模块不负责修复或阻断，仅产出 ExternalFinding 列表供上层决策。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
_TOOL_TIMEOUT: int = 60  # 每个工具子进程超时（秒）

# 全部支持的工具名（与 shutil.which 检测的命令名一致）
_ALL_TOOLS: list[str] = ["bandit", "semgrep", "gitleaks", "trivy",
                         "pip-audit", "detect-secrets"]

# Semgrep 固定规则集（保证 Stage 1 工具层结果可复现）。
# 优先使用本地化的 registry 规则（models/semgrep_rules/*.yaml，离线可用，
# 见 tools/fetch_semgrep_rules.py）；本地规则缺失时回退在线 registry 包
# （需联网，且 p/owasp-top-10 实际不存在、会导致每次运行联网降级拖慢，
# 正确包名为 p/owasp-top-ten）。自写 taint 规则文件追加到 _TAINT_RULES_DIR。
def _resolve_semgrep_configs() -> list[str]:
    """解析 Semgrep 规则配置：本地 yaml 优先，缺失时回退在线 registry。"""
    from graduation_project.paths import semgrep_local_configs
    local = semgrep_local_configs()
    if local:
        return local
    # 回退：在线 registry 包（首次联网拉取；owasp-top-10 已在 semgrep.dev 404，
    # 用正确包名 owasp-top-ten）
    return ["p/security-audit", "p/owasp-top-ten"]


_SEMGREP_CONFIGS: list[str] = _resolve_semgrep_configs()

# 自研 Semgrep taint 规则目录（两阶段架构 Stage 1 召回）。
# scan_taint() 对本目录下全部 *.yaml 规则做整文件 taint 扫描。
# 目录不存在或为空时，scan_taint() 返回空列表（降级为 TaintTracker/Prefilter 召回）。
_TAINT_RULES_DIR: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "semgrep_rules")

# Gitleaks 自定义规则（2026-08-29 B2）：默认规则集之上的追加规则
# （AWS Access Key ID 前缀形态 / Python 字节串字面量凭证）。[extend]
# useDefault=true 保证默认规则不受影响。文件缺失时退回纯默认规则集（降级不报错）。
_GITLEAKS_CONFIG: str = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "gitleaks_rules.toml")

# taint 规则 id 前缀 → (taint_type, 默认严重度) 映射，用于把 semgrep finding 映射到统一结构
# severity 与 two_stage_scanner._SEVERITY_BY_TYPE 保持一致（映射表是权威来源，
# YAML 里的 severity 仅用于 semgrep 自身的展示，不参与裁决层分级）
_TAINT_TYPE_BY_RULE: dict[str, tuple[str, str]] = {
    "sqli": ("SQL Injection", "high"),
    "cmdi": ("Command Injection", "critical"),
    "codei": ("Code Injection", "critical"),  # CWE-95，勿并入 cmdi（CWE-78）
    "xss": ("XSS", "medium"),                 # CWE-79，反射型/存储型跨站脚本
}


# ---------------------------------------------------------------------------
# 发现数据结构
# ---------------------------------------------------------------------------
@dataclass
class ExternalFinding:
    """单个外部工具发现。

    Attributes:
        tool: 发现该问题的工具名（bandit / semgrep / gitleaks / trivy）
        rule_id: 工具内部的规则 / 漏洞 ID（如 B101、CVE-2021-12345、AVD-terraform-001）
        severity: 严重等级（工具原始值小写化，如 low / medium / high / critical）
        message: 问题描述文本
        filename: 受影响的文件路径（工具输出中的原始路径）
        line: 行号（1-based；工具未提供时为 0）
        category: 发现类别 —— "sast" 静态分析 / "sca" 依赖漏洞 /
                  "secret" 硬编码密钥 / "iac" 基础设施即代码配置
    """
    tool: str
    rule_id: str
    severity: str
    message: str
    filename: str
    line: int
    category: str  # "sast" / "sca" / "secret" / "iac"

    def __repr__(self) -> str:
        return (f"ExternalFinding(tool={self.tool}, category={self.category}, "
                f"severity={self.severity}, rule={self.rule_id}, "
                f"file={self.filename}:{self.line})")


def normalize_severity(value: str) -> str:
    """把各工具的 severity 归一化为 critical/high/medium/low/info。

    Bandit: LOW/MEDIUM/HIGH/UNDEFINED；Semgrep: ERROR/WARNING/INFO；
    Gitleaks: CRITICAL/HIGH/MEDIUM/LOW/INFO；Trivy: CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN。
    归一化结果为裁决层（Stage 2）提供统一输入格式。
    """
    s = (value or "").strip().lower()
    if not s or s in ("unknown", "undefined", "unassigned", "none",
                      "informational", "note", "info"):
        return "info"
    if s in ("critical", "严重", "危急"):
        return "critical"
    if s in ("high", "error", "高危"):
        return "high"
    if s in ("medium", "moderate", "warning", "warn", "中危"):
        return "medium"
    if s in ("low", "info", "低危"):
        return "low"
    # 模糊匹配（如 "CRITICAL/HIGH" 组合值）
    if "crit" in s:
        return "critical"
    if "high" in s:
        return "high"
    if "med" in s or "moderate" in s or "warn" in s:
        return "medium"
    if "low" in s or "info" in s:
        return "low"
    return "info"


def _extract_taint_endpoint(extra: dict, name: str) -> tuple[str, int]:
    """从 semgrep taint finding 提取 source/sink 的表达式与行号。

    按优先级尝试三个来源：
      1. extra.metavars["$SOURCE"/"$SINK"]（部分版本/pro 引擎注入）
      2. extra.dataflow_trace.taint_source / taint_sink（带 --dataflow-traces 时）
      3. extra.taint_source / extra.taint_sink 顶层字段（旧版本）
    注意：semgrep OSS（实测 1.172）taint 结果的 JSON 不含以上任何字段——
    finding 的 start 行即 sink 行，source 位置需由 TaintTracker 或裁决层补全。

    Returns:
        (表达式字符串, 行号)；取不到时返回 ("", 0)。
    """
    metavars = extra.get("metavars") or {}
    key = f"${name}"
    if key in metavars:
        mv = metavars[key] or {}
        content = mv.get("abstract_content") or mv.get("content") or ""
        line = int((mv.get("start") or {}).get("line", 0) or 0)
        return str(content), line

    # dataflow_trace（--dataflow-traces / pro 引擎）
    dt = extra.get("dataflow_trace") or {}
    node = dt.get("taint_source" if name == "SOURCE" else "taint_sink") or {}
    if node:
        loc = node.get("location") or {}
        content = node.get("content") or loc.get("content") or ""
        line = int((loc.get("start") or node.get("start") or {}).get("line", 0) or 0)
        if content or line:
            return str(content), line

    # 兜底：taint_source / taint_sink 字段
    field = "taint_source" if name == "SOURCE" else "taint_sink"
    ts = extra.get(field) or {}
    content = ts.get("content") or (ts.get("location") or {}).get("content") or ""
    line = int((ts.get("location") or {}).get("start", {}).get("line", 0) or 0)
    return str(content), line


def _extract_taint_path(extra: dict) -> list[str]:
    """从 semgrep taint finding 提取传播链（source→...→sink 的中间变量）。

    优先取 extra.dataflow_trace.intermediate_vars（sink 视图中逐跳传播）；
    其次取 extra.taint_trace 的 taint_source 内容。提取失败返回空列表。
    """
    trace = extra.get("dataflow_trace") or {}
    intermediates = trace.get("intermediate_vars") or []
    chain: list[str] = []
    for iv in intermediates:
        content = ((iv or {}).get("location") or {}).get("content") or ""
        if content:
            chain.append(str(content))
    if chain:
        return chain

    # 兜底：taint_source 的内容作为传播头
    ts = extra.get("taint_source") or {}
    head = ts.get("content") or (ts.get("location") or {}).get("content") or ""
    return [str(head)] if head else []


# ---------------------------------------------------------------------------
# 外部扫描器
# ---------------------------------------------------------------------------
class ExternalScanner:
    """传统安全工具聚合扫描器。

    封装 Bandit（Python SAST）、Semgrep（多语言 SAST）、Gitleaks（密钥检测）、
    Trivy（SCA 依赖漏洞 + IaC 配置扫描）四类工具，统一输出 ExternalFinding 列表。

    工具探测：
    - __init__ 时通过 shutil.which() 检测已安装工具；
    - 未安装的工具在对应 scan_* 方法中静默跳过（返回空列表），不抛异常；
    - available_tools() 返回当前已安装且被请求的工具列表。

    降级策略：
    - 工具未安装 → 跳过
    - 子进程超时（60s）→ 跳过
    - JSON 解析失败 → 跳过
    - 工具退出码非零但 stdout 有 JSON → 仍尝试解析（部分工具无发现时退出码非零）
    """

    def __init__(self, tools: list[str] | None = None) -> None:
        """初始化扫描器，探测已安装工具。

        Args:
            tools: 要启用的工具名列表（None 表示全部启用）。
                   支持的名称：bandit / semgrep / gitleaks / trivy。
                   未安装或未知的工具名会被忽略。
        """
        requested = list(tools) if tools is not None else list(_ALL_TOOLS)
        # 探测已安装工具，保存可执行文件路径。
        # 环境变量 <TOOL>_BIN（如 SEMGREP_BIN）可显式指定可执行文件路径，
        # 覆盖 PATH 探测（例如 semgrep 装在独立 venv、未加入 PATH 的场景）。
        self._installed: dict[str, str] = {}
        # P2-8（2026-08-31）：semgrep 单文件执行缓存。scan_code 对同一临时文件
        # 先 scan_taint 后 scan_sast，此前各起一次 semgrep 进程（~0.85s + ~1.2s，
        # 占单文件总耗时 ~90%）——规则加载与解析做两遍。现共享一次执行，
        # 两路解析从缓存分流（taint 规则 id 按命名约定 "-taint" 后缀识别）。
        self._semgrep_cache: dict[str, Optional[dict]] = {}
        # 执行状态留痕（2026-08-31，P2-9 消静默）：工具名 → 最近一次执行的
        # 状态（ok / empty / parse_error / timeout / not_found / os_error）。
        # 此前 20+ 处降级 return [] 全部静默——工具超时/解析失败与"无命中"
        # 在结果上无法区分（B1 的"零召回先查调用链"因此缺第一手证据）。
        # 只记录不干预：留痕是旁路，不得影响召回主流程。
        self.last_status: dict[str, str] = {}
        conda_bins = self._conda_env_bin_dirs()
        for name in requested:
            if name not in _ALL_TOOLS:
                continue  # 未知工具名，忽略
            env_bin = os.environ.get(f"{name.upper()}_BIN", "").strip()
            if env_bin and Path(env_bin).is_file():
                self._installed[name] = env_bin
                continue
            resolved = shutil.which(name)
            if not resolved:
                # PATH 找不到时去 conda env 的 bin 搜索（如 semgrep 装在独立
                # env、后端进程 PATH 未包含该 env 的场景）
                resolved = self._search_in_dirs(name, conda_bins)
            if resolved:
                self._installed[name] = resolved

    @staticmethod
    def _conda_env_bin_dirs() -> list[str]:
        """收集当前解释器所在环境的 bin 目录，用于搜索 PATH 外的工具可执行文件。

        只解析「当前环境」（sys.executable 所在 bin + CONDA_PREFIX 的 bin），
        不再扫描其他 conda env —— 安全工具由启动器在运行它的那个环境里统一安装，
        因此只需从该环境解析工具，避免"环境换来换去"导致用了别的环境的旧/损坏工具。
        """
        dirs: list[str] = []
        # 1) 当前 python 解释器所在 bin（最权威：当前环境）
        sp = Path(sys.executable).resolve()
        if sp.parent.name == "bin":
            dirs.append(str(sp.parent))
        # 2) CONDA_PREFIX 的 bin（与 sys.executable 同环境，兜底）
        prefix = os.environ.get("CONDA_PREFIX", "").strip()
        if prefix:
            bp = os.path.join(prefix, "bin")
            if bp not in dirs and os.path.isdir(bp):
                dirs.append(bp)
        return list(dict.fromkeys(dirs))

    @staticmethod
    def _search_in_dirs(name: str, dirs: list[str]) -> Optional[str]:
        """在候选目录中查找可执行文件 <name>，返回绝对路径或 None。"""
        seen: set[str] = set()
        for d in dirs:
            if not d or d in seen:
                continue
            seen.add(d)
            cand = os.path.join(d, name)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
        return None

    # ------------------------------------------------------------------
    # 公共 API
    # ------------------------------------------------------------------
    def available_tools(self) -> list[str]:
        """返回已安装且被启用的工具名列表。"""
        return list(self._installed.keys())

    def scan(self, path: str, language: str = "python") -> list[ExternalFinding]:
        """对给定文件 / 目录运行全部已启用工具，聚合发现。

        Args:
            path: 待扫描的文件或目录路径
            language: 主要语言标签（影响 SAST 工具选择，如 bandit 仅扫描 Python）

        Returns:
            所有工具发现的聚合列表（SAST + Secret + SCA + IaC）
        """
        findings: list[ExternalFinding] = []
        findings.extend(self.scan_sast(path, language))
        findings.extend(self.scan_secrets(path))
        findings.extend(self.scan_sca(path))
        findings.extend(self.scan_iac(path))
        return self._dedupe(findings)

    @staticmethod
    def _dedupe(findings: list[ExternalFinding]) -> list[ExternalFinding]:
        """按 (tool, rule_id, filename, line) 去重，保证裁决层输入稳定。"""
        seen: set[tuple] = set()
        out: list[ExternalFinding] = []
        for item in findings:
            key = (item.tool, item.rule_id, item.filename, item.line)
            if key not in seen:
                seen.add(key)
                out.append(item)
        return out

    def scan_sast(self, path: str, language: str = "python") -> list[ExternalFinding]:
        """运行 SAST 工具（Bandit + Semgrep）。

        - Bandit：仅对 Python 生效，language="python" 时启用
        - Semgrep：多语言，始终启用（若已安装）

        Args:
            path: 待扫描的文件或目录路径
            language: 语言标签

        Returns:
            SAST 发现列表（category="sast"）
        """
        findings: list[ExternalFinding] = []
        # 2026-08-16 修复：language 大小写兜底——manifest.json 用 'Python'（大写），
        # 直接 == "python" 会静默跳过 bandit（typical_18/19 只靠 bandit 召回时工具
        # 失效）。调用方应传小写，但这里内部兜底更稳。
        lang = (language or "").lower()
        if lang == "python" and "bandit" in self._installed:
            findings.extend(self._run_bandit(path))
        if "semgrep" in self._installed:
            findings.extend(self._run_semgrep(path))
        return findings

    def scan_secrets(self, path: str) -> list[ExternalFinding]:
        """运行密钥检测工具（Gitleaks）。

        Args:
            path: 待扫描的文件或目录路径（Gitleaks 在 git 仓库中效果最佳，
                  也可扫描普通文件）

        Returns:
            密钥发现列表（category="secret"）
        """
        findings: list[ExternalFinding] = []
        if "gitleaks" in self._installed:
            findings.extend(self._run_gitleaks(path))
        if "detect-secrets" in self._installed:
            findings.extend(self._run_detect_secrets(path))
        return findings

    def scan_sca(self, path: str) -> list[ExternalFinding]:
        """运行 SCA 工具（Trivy fs）扫描依赖漏洞。

        Trivy fs 会自动识别路径中的 requirements.txt / package.json /
        go.sum / Gemfile.lock 等依赖清单文件并检查已知漏洞。

        Args:
            path: 待扫描的文件或目录路径

        Returns:
            依赖漏洞发现列表（category="sca"）
        """
        findings: list[ExternalFinding] = []
        if "trivy" in self._installed:
            findings.extend(self._run_trivy_fs(path))
        if "pip-audit" in self._installed:
            findings.extend(self._run_pip_audit(path))
        return findings

    def scan_iac(self, path: str) -> list[ExternalFinding]:
        """运行 IaC 配置扫描工具（Trivy config）。

        Trivy config 会扫描 Terraform / Kubernetes / Dockerfile /
        CloudFormation 等基础设施配置文件中的安全问题。

        Args:
            path: 待扫描的文件或目录路径

        Returns:
            IaC 配置发现列表（category="iac"）
        """
        if "trivy" not in self._installed:
            return []
        return self._run_trivy_config(path)

    def scan_taint(self, path: str, language: str = "python") -> list[dict]:
        """对整文件运行 Semgrep taint 规则，返回带污点路径的候选 finding。

        两阶段架构 Stage 1 的核心召回：对原始整文件跑一次 taint 分析，
        修复长文件切片后 source/sink 跨 chunk 割裂的问题。每条结果带
        source / sink / 传播链 / 行号，供 Stage 2 LLM 裁决层判定真伪。

        Args:
            path: 待扫描的文件路径（整文件）
            language: 语言标签（当前规则面向 Python；其他语言不命中）

        Returns:
            候选 finding 的 dict 列表，每项含：
                rule_id / source / sink / taint_type / source_line /
                sink_line / path / severity / evidence / tool="semgrep"
            若 semgrep 未安装、规则目录缺失或解析失败，返回空列表（降级）。
        """
        if "semgrep" not in self._installed:
            return []
        if not os.path.isdir(_TAINT_RULES_DIR):
            return []
        return self._run_semgrep_taint(path, language)

    # ------------------------------------------------------------------
    # 子进程执行
    # ------------------------------------------------------------------
    def _run_subprocess(self, cmd: list[str], cwd: Optional[str] = None) -> Optional[str]:
        """运行子进程并返回 stdout 文本。

        Args:
            cmd: 命令行（首元素为工具名，会被替换为探测到的绝对路径）
            cwd: 工作目录。部分工具（detect-secrets 1.x）对绝对路径不做扫描，
                 必须由调用方切到目标目录并传相对文件名（见 _run_detect_secrets）。

        工具未找到 / 超时 / 其他异常均返回 None，由调用方降级处理。
        不检查退出码 —— 部分工具（如 gitleaks）在"无发现"时退出码非零，
        但 stdout 仍可能包含 JSON。
        """
        # 留痕键 = 裸工具名（替换绝对路径**之前**取；替换后是完整路径，作键无意义）
        tool = cmd[0] if cmd else "?"
        try:
            # 用 __init__ 探测到的绝对路径替换裸命令名（支持 <TOOL>_BIN 环境变量
            # 覆盖 PATH 探测，例如 semgrep 装在独立 venv 未加入 PATH 的场景）
            if cmd:
                cmd = [self._installed.get(cmd[0], cmd[0]), *cmd[1:]]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8", errors="replace",
                timeout=_TOOL_TIMEOUT,
                cwd=cwd,
            )
            # 执行层留痕：stdout 空 = 工具跑完但无输出（可能是"无命中"，也可能是
            # 工具静默失败——由调用方解析层覆盖为 parse_error 甄别）。
            self.last_status[tool] = "ok" if (proc.stdout or "").strip() else "empty"
            return proc.stdout
        except FileNotFoundError:
            self.last_status[tool] = "not_found"
            return None
        except subprocess.TimeoutExpired:
            self.last_status[tool] = "timeout"
            return None
        except OSError:
            self.last_status[tool] = "os_error"
            return None

    # ------------------------------------------------------------------
    # 各工具运行器
    # ------------------------------------------------------------------
    def _run_bandit(self, path: str) -> list[ExternalFinding]:
        """运行 Bandit（Python SAST）。

        命令：bandit -f json -q <path>
        输出 JSON 含 results 数组，每项含 test_id / issue_severity /
        issue_text / filename / line_number。
        """
        out = self._run_subprocess(["bandit", "-f", "json", "-q", path])
        if not out or not out.strip():
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            self.last_status["bandit"] = "parse_error"  # 执行层留痕（消静默）
            return []
        findings: list[ExternalFinding] = []
        for r in data.get("results", []):
            findings.append(ExternalFinding(
                tool="bandit",
                rule_id=str(r.get("test_id", "")),
                severity=normalize_severity(str(r.get("issue_severity", "UNKNOWN"))),
                message=str(r.get("issue_text", "")),
                filename=str(r.get("filename", "")),
                line=int(r.get("line_number", 0) or 0),
                category="sast",
            ))
        return findings

    def _semgrep_execute_cached(self, path: str) -> Optional[dict]:
        """同文件一次 semgrep 执行，sast/taint 两路解析共享（P2-8，2026-08-31）。

        命令：semgrep --json --quiet --config <registry 包们> --config <taint 目录> <path>
        （taint 目录缺失时自动省略该 config——与 scan_taint 的降级语义一致。）

        缓存键 = 文件绝对路径（同一 scan_code 两次调用命中同键）；上限 64 条
        超限全清——临时文件每次扫描新建，跨文件复用价值低，防内存无限增长。

        **errors 重试（2026-08-31，exp_01 审计 × LLM 跑批并发实锤）**：
        多进程并发时 semgrep-core 偶发 exit 2（"Error while matching"，疑似
        规则解析缓存/临时目录争抢），失败模式为 results=0 + errors=1（整体崩，
        什么都不出）。实测崩溃率与并发强度正相关（独跑 0%，与 LLM 跑批并发
        约 40%）。竞态是偶发的 → **对 errors 非空的执行重试 1 次**（重试成功率
        高，代价仅作用于失败场景；无 errors 的正常空结果不重试，避免双倍耗时）。

        Returns:
            解析后的 semgrep JSON dict；无输出/解析失败时返回 None
            （两路解析函数对 None 一致降级为空列表）。
        """
        key = os.path.abspath(path)
        if key in self._semgrep_cache:
            return self._semgrep_cache[key]
        cmd = ["semgrep", "--json", "--quiet"]
        cmd += [c for cfg in _SEMGREP_CONFIGS for c in ("--config", cfg)]
        if os.path.isdir(_TAINT_RULES_DIR):
            cmd += ["--config", _TAINT_RULES_DIR]
        cmd += [path]
        data: Optional[dict] = None
        for attempt in (1, 2):  # 第 2 次仅在 errors 非空时执行（见下）
            out = self._run_subprocess(cmd)
            data = None
            if not (out and out.strip()):
                break  # 空输出 = 正常"无命中"（semgrep 无发现时 stdout 可能为空），不重试
            try:
                parsed = json.loads(out)
            except json.JSONDecodeError:
                self.last_status["semgrep"] = "parse_error"  # 执行层留痕（消静默）
                break
            if not isinstance(parsed, dict):
                break
            n_err = len(parsed.get("errors") or [])
            if not n_err:
                data = parsed
                break
            # errors 非空：留痕 + 重试一次
            self.last_status["semgrep"] = f"errors_retry{attempt}:{n_err}"
            print(f"[ExternalScanner] semgrep 报错（attempt {attempt}，errors={n_err}，"
                  f"results={len(parsed.get('results') or [])}）: "
                  f"{str(parsed['errors'][0])[:160]}")
            if attempt == 1 and parsed.get("results"):
                # 有部分结果：先用部分结果兜底，再重试取更完整的一份
                data = parsed
            elif attempt == 1:
                time.sleep(0.3)  # 让并发的另一个 semgrep 进程先释放资源
                continue
        if len(self._semgrep_cache) > 64:
            self._semgrep_cache.clear()
        self._semgrep_cache[key] = data
        return data

    def _run_semgrep(self, path: str) -> list[ExternalFinding]:
        """运行 Semgrep（多语言 SAST），从共享执行缓存分流解析。

        命令见 _semgrep_execute_cached。本函数只取**非 taint 规则**的命中
        （taint 规则 id 以 "-taint" 结尾，由 _run_semgrep_taint 解析）——
        保持与合并前"sast 命令不含 taint 规则"完全一致的输出面。
        """
        data = self._semgrep_execute_cached(path)
        if data is None:
            return []
        findings: list[ExternalFinding] = []
        for r in data.get("results", []):
            rule_id = str(r.get("check_id", ""))
            if rule_id.endswith("-taint"):
                continue  # taint 规则命中归 _run_semgrep_taint（分流，不双计）
            extra = r.get("extra", {}) or {}
            start = r.get("start", {}) or {}
            findings.append(ExternalFinding(
                tool="semgrep",
                rule_id=rule_id,
                severity=normalize_severity(str(extra.get("severity", "INFO"))),
                message=str(extra.get("message", "")),
                filename=str(r.get("path", "")),
                line=int(start.get("line", 0) or 0),
                category="sast",
            ))
        return findings

    def _run_semgrep_taint(self, path: str, language: str) -> list[dict]:
        """解析自研 Semgrep taint 规则的污点路径 finding（P2-8 起从共享缓存取数）。

        命令见 _semgrep_execute_cached（sast + taint 规则合并为一次执行）。
        本函数只取 **"-taint" 结尾规则**的命中，从 extra.metavars 提取
        $SOURCE / $SINK（semgrep taint 模式自动注入的实际表达式与位置），
        传播链从 extra.dataflow_trace 或 extra.taint_source 提取。

        Returns:
            候选 finding dict 列表（见 scan_taint 文档）。失败/无结果返回 []。
        """
        data = self._semgrep_execute_cached(path)
        if data is None:
            return []

        findings: list[dict] = []
        for r in data.get("results", []):
            extra = r.get("extra", {}) or {}
            start = r.get("start", {}) or {}
            rule_id = str(r.get("check_id", ""))
            if not rule_id.endswith("-taint"):
                continue  # sast 规则命中归 _run_semgrep（分流，不双计）
            # 从规则 id 推断 taint_type 与默认严重度（sqli→SQL Injection 等）
            # 注意顺序：codei（CWE-95 代码注入）必须先于 cmdi 判断，避免子串误归
            taint_type, sev = _TAINT_TYPE_BY_RULE.get(
                "sqli" if "sqli" in rule_id else (
                    "codei" if "codei" in rule_id else (
                        "cmdi" if "cmdi" in rule_id else (
                            "xss" if "xss" in rule_id else ""))),
                ("Unknown", "medium"),
            )
            source, source_line = _extract_taint_endpoint(extra, "SOURCE")
            sink, sink_line = _extract_taint_endpoint(extra, "SINK")
            # 行号兜底：取 finding 起止行
            if not source_line:
                source_line = int(start.get("line", 0) or 0)
            if not sink_line:
                sink_line = int(start.get("line", 0) or 0)
            # 传播链：优先 dataflow_trace.intermediate_vars，其次 taint_source
            path_chain = _extract_taint_path(extra)

            findings.append({
                "rule_id": rule_id,
                "source": source,
                "sink": sink,
                "taint_type": taint_type,
                "source_line": source_line,
                "sink_line": sink_line,
                "path": path_chain,
                # 已知规则用映射表 severity（权威）；未知规则回退 YAML severity 归一化
                "severity": sev if taint_type != "Unknown"
                else normalize_severity(str(extra.get("severity", "INFO"))),
                "evidence": str(extra.get("message", "")) or rule_id,
                "tool": "semgrep",
            })
        return findings

    def _run_gitleaks(self, path: str) -> list[ExternalFinding]:
        """运行 Gitleaks（密钥检测）。

        命令：gitleaks detect --source <path> --no-git --config <自定义规则>
        --report-format json --report-path -
        输出为 JSON 数组，每项含 RuleID / Description / File / StartLine / Severity。

        2026-08-29 修复（secret 档零召回根因）：此前缺 --no-git，gitleaks 默认
        走 git 历史模式；管道用 NamedTemporaryFile（无 .git 仓库）扫描时直接零输出
        ——注释里"无 .git 时对单文件几乎不命中"的自我实现预言即来源于此（工具没坏，
        是调用方式让它必然不命中）。实测加 --no-git 后精确命中
        hard_bypass_06 的 SECRET_API_TOKEN（line 8，generic-api-key，~70ms）。

        2026-08-29 B2 补：--config 挂载自定义规则（graduation_project/
        gitleaks_rules.toml，[extend] useDefault 追加于默认规则集之上），补
        AWS Access Key ID（AKIA 前缀）与 Python 字节串字面量凭证两个语义盲区
        （typical_06 / typical_18 修复后仍 0 命中的根因）。规则文件缺失时
        退回默认规则集。
        """
        cmd = ["gitleaks", "detect"]
        if os.path.isfile(_GITLEAKS_CONFIG):
            cmd += ["--config", _GITLEAKS_CONFIG]
        cmd += [
            "--source", path,
            "--no-git",                 # 单文件/无 .git 目录必须显式指定（见 docstring）
            "--report-format", "json",
            "--report-path", "-",
        ]
        out = self._run_subprocess(cmd)
        if not out or not out.strip():
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            self.last_status["gitleaks"] = "parse_error"  # 执行层留痕（消静默）
            return []
        # gitleaks 输出为数组；个别版本可能包在 {"Results": [...]} 中
        if isinstance(data, dict):
            items = data.get("Results", data.get("findings", []))
        else:
            items = data
        findings: list[ExternalFinding] = []
        for r in items:
            raw_sev = str(r.get("Severity", "")).strip()
            severity = normalize_severity(raw_sev)
            if not raw_sev:
                severity = "high"  # 工具未给等级时密钥泄露默认高危
            # 2026-08-31：message 附命中行原文（gitleaks JSON 的 Match 字段）。
            # 此前 message 只有通用描述（不含凭证值）→ ① 凭证强度门槛
            # （_is_strong_credential 从引号提取值）取不到字面值恒判弱；
            # ② detect-secrets 弱值候选绕过门槛直出抢 top1（§9.19 实锤）。
            msg = str(r.get("Description", "") or r.get("RuleID", ""))
            match_line = str(r.get("Match", "") or "").strip()
            if match_line:
                msg += f"\n[命中行] {match_line}"
            findings.append(ExternalFinding(
                tool="gitleaks",
                rule_id=str(r.get("RuleID", "")),
                severity=severity,
                message=msg,
                filename=str(r.get("File", "")),
                line=int(r.get("StartLine", 0) or 0),
                category="secret",
            ))
        return findings

    def _run_trivy_fs(self, path: str) -> list[ExternalFinding]:
        """运行 Trivy fs（SCA 依赖漏洞扫描）。

        命令：trivy fs --skip-db-update --format json <path>
        输出 JSON 含 Results 数组，每项含 Target / Vulnerabilities 数组。
        每个 Vulnerability 含 VulnerabilityID / Severity / Title / PkgName。

        注意：必须带 --skip-db-update（离线，与 TRIVY_SKIP_DB_UPDATE 环境变量等价）——
        trivy 首次运行联网下载漏洞库（约 100MB），无代理直连不通时会卡满 _TOOL_TIMEOUT。
        漏洞库已随部署拉取到 ~/.cache/trivy/db（2026-08-13），离线扫描即可。
        """
        out = self._run_subprocess(
            ["trivy", "fs", "--skip-db-update", "--format", "json", path]
        )
        if not out or not out.strip():
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            self.last_status["trivy"] = "parse_error"  # 执行层留痕（消静默）
            return []
        findings: list[ExternalFinding] = []
        for result in data.get("Results", []):
            target = str(result.get("Target", ""))
            vulns = result.get("Vulnerabilities") or []
            for v in vulns:
                title = v.get("Title") or v.get("Description", "")
                findings.append(ExternalFinding(
                    tool="trivy",
                    rule_id=str(v.get("VulnerabilityID", "")),
                    severity=normalize_severity(str(v.get("Severity", "UNKNOWN"))),
                    message=str(title),
                    filename=target,
                    line=0,  # 依赖漏洞无行号
                    category="sca",
                ))
        return findings

    def _run_trivy_config(self, path: str) -> list[ExternalFinding]:
        """运行 Trivy config（IaC 配置扫描）。

        命令：trivy config --skip-policy-update --format json <path>
        输出 JSON 含 Results 数组，每项含 Target / Misconfigurations 数组 /
        CauseMetadata.StartLine。每个 Misconfiguration 含 ID / Severity / Message。

        注意：必须带 --skip-policy-update（离线）——trivy config 每次启动都会联网
        下载策略包（policy bundle），无代理直连不通时卡满 _TOOL_TIMEOUT（60s）。
        2026-08-14 实测：带该参数 0.4s，不带 60.1s（一个样本白等 60 秒的根因）。
        """
        out = self._run_subprocess(
            ["trivy", "config", "--skip-policy-update", "--format", "json", path]
        )
        if not out or not out.strip():
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            self.last_status["trivy"] = "parse_error"  # 执行层留痕（消静默）
            return []
        findings: list[ExternalFinding] = []
        for result in data.get("Results", []):
            target = str(result.get("Target", ""))
            cause_meta = result.get("CauseMetadata", {}) or {}
            default_line = int(cause_meta.get("StartLine", 0) or 0)
            misconfs = result.get("Misconfigurations") or []
            for m in misconfs:
                findings.append(ExternalFinding(
                    tool="trivy",
                    rule_id=str(m.get("ID", "") or m.get("AVDID", "")),
                    severity=normalize_severity(str(m.get("Severity", "UNKNOWN"))),
                    message=str(m.get("Message", "")),
                    filename=target,
                    line=default_line,
                    category="iac",
                ))
        return findings

    def _run_pip_audit(self, path: str) -> list[ExternalFinding]:
        """运行 pip-audit（Python 依赖漏洞，SCA）。

        命令：pip-audit -r <requirements.txt> -f json --progress-spinner off
        输出 JSON：{"dependencies": [{"name","version","vulns":[{"id",
        "fix_versions","description","aliases"}]}]}
        仅扫描路径顶层的 requirements*.txt（递归依赖锁文件交给 trivy fs）。
        """
        base = Path(path)
        req_files: list[Path] = []
        if base.is_file() and base.name.startswith("requirements") and base.suffix == ".txt":
            req_files = [base]
        elif base.is_dir():
            req_files = sorted(base.glob("requirements*.txt"))
        findings: list[ExternalFinding] = []
        for req in req_files:
            out = self._run_subprocess(
                ["pip-audit", "-r", str(req), "-f", "json", "--progress-spinner", "off"]
            )
            if not out or not out.strip():
                continue
            try:
                data = json.loads(out)
            except json.JSONDecodeError:
                self.last_status["pip-audit"] = "parse_error"  # 执行层留痕（消静默）
                continue
            for dep in data.get("dependencies", []):
                for v in dep.get("vulns", []):
                    aliases = v.get("aliases") or []
                    cve = next((a for a in aliases if str(a).startswith("CVE-")), "")
                    findings.append(ExternalFinding(
                        tool="pip-audit",
                        rule_id=str(v.get("id", "")),
                        severity="high",  # pip-audit 不带等级，有 CVE 的依赖漏洞默认 high
                        message=(f"{dep.get('name')}=={dep.get('version')} "
                                 f"{cve or v.get('id', '')}: "
                                 f"{str(v.get('description', ''))[:200]}"),
                        filename=str(req),
                        line=0,  # 依赖漏洞无行号
                        category="sca",
                    ))
        return findings

    def _run_detect_secrets(self, path: str) -> list[ExternalFinding]:
        """运行 detect-secrets（熵值 + 正则双引擎密钥检测，误报低于纯正则）。

        命令：detect-secrets scan --all-files <basename>（工作目录 = 文件所在目录）

        **路径形态是硬性约束（2026-08-31 实锤，与 B1 同型的接入层缺陷）**：
        detect-secrets 1.5.0 传入**绝对路径**时 `results` 恒为 `{}`（实测：同一
        文件 `--all-files /tmp/x.py` 零召回、`--all-files x.py` + cwd=/tmp 正常召回
        Secret Keyword + AWS Access Key）。此前接入层固定传绝对路径 → 该工具
        在整个项目生命周期内**从未产出过任何发现**，而冒烟脚本把"阳性零召回"
        降级为 SKIP，把这个必然失败伪装成了"插件/版本相关的环境差异"。

        修复：切到目标文件所在目录，只传文件名。results 的键随之变为文件名，
        故 filename 字段回填为调用方传入的原始 path，保持语义不变。
        """
        directory = os.path.dirname(os.path.abspath(path)) or "."
        basename = os.path.basename(path)
        out = self._run_subprocess(
            ["detect-secrets", "scan", "--all-files", basename], cwd=directory)
        if not out or not out.strip():
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            self.last_status["detect-secrets"] = "parse_error"  # 执行层留痕（消静默）
            return []
        findings: list[ExternalFinding] = []
        # 行内容缓存：detect-secrets JSON 不含命中文本（只有 type/line_number），
        # 读一次源文件按行取——凭证强度门槛需要行内的引号字面值（2026-08-31）
        src_lines: list[str] = []
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                src_lines = fh.readlines()
        except OSError:
            src_lines = []
        for _filename, items in (data.get("results") or {}).items():
            for item in items:
                line_no = int(item.get("line_number", 0) or 0)
                msg = f"检测到疑似密钥: {item.get('type', '')}"
                if 0 < line_no <= len(src_lines):
                    msg += f"\n[命中行] {src_lines[line_no - 1].strip()}"
                findings.append(ExternalFinding(
                    tool="detect-secrets",
                    rule_id=str(item.get("type", "Secret")),
                    severity="high",  # 密钥泄露默认高危（与 gitleaks 口径一致）
                    message=msg,
                    # 回填原始 path：results 的键是传给工具的 basename（见 docstring）
                    filename=str(path),
                    line=line_no,
                    category="secret",
                ))
        return findings


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import os

    print("=== 外部扫描器自检 ===\n")

    scanner = ExternalScanner()
    available = scanner.available_tools()

    print(f"支持的工具: {_ALL_TOOLS}")
    print(f"已安装的工具: {available if available else '（无，所有 scan 方法将返回空列表）'}")
    print()

    for tool in _ALL_TOOLS:
        status = "已安装" if tool in available else "未安装"
        print(f"  [{status}] {tool}")

    print()
    if available:
        # 对脚本所在目录做一次演示扫描
        demo_path = os.path.dirname(os.path.abspath(__file__))
        print(f"对目录做演示扫描: {demo_path}")
        print("（每工具超时 60s，请耐心等待）\n")
        results = scanner.scan(demo_path)
        if results:
            print(f"共发现 {len(results)} 项:")
            for f in results:
                print(f"  {f}")
        else:
            print("未发现安全问题（或工具无输出）。")

        # taint 规则演示：对 semgrep_rules 目录本身做一次（通常无命中）
        print("\n--- Semgrep taint 召回演示 ---")
        taint_findings = scanner.scan_taint(demo_path)
        if taint_findings:
            print(f"  taint 共召回 {len(taint_findings)} 条候选:")
            for t in taint_findings:
                print(f"  {t['tool']} {t['rule_id']} "
                      f"L{t['source_line']}:{t['source']} -> "
                      f"L{t['sink_line']}:{t['sink']} ({t['taint_type']})")
        else:
            print("  taint 未召回候选（semgrep 未安装或规则目录为空）。")
    else:
        print("未检测到任何外部工具，模块以降级模式运行（所有 scan 返回空列表）。")
        print("安装示例: pip install bandit semgrep  |  choco install gitleaks trivy")
