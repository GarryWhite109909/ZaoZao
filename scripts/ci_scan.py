#!/usr/bin/env python3
"""
CI 漏洞扫描脚本 —— 用于 GitHub Actions PR 审查。

复用项目核心 Scanner（LLM + RAG）对命令行传入的代码文件逐个执行漏洞检测，
并将结果以 JSON（默认）或 Markdown 评论（--format comment）输出到 stdout。

设计原则：
- 永不阻断 PR：Ollama 不可用、模型缺失或单文件扫描出错时，仅输出警告并以
  退出码 0 退出，配合工作流的 continue-on-error 确保不阻塞合并。
- 训练/推理一致：system prompt 由 model_registry 按模型自动选择
  （v9max→BASE_PROMPT，v5→SYSTEM_PROMPT_LITE），保证训练/推理一致。
- RAG 增强：默认启用知识库检索；CI 环境若无本地 embedding 模型/向量库，
  Scanner 会自动回退到纯 LLM 模式（见 Scanner.chroma 属性的容错逻辑）。

用法示例：
    # JSON 输出（默认，便于程序解析）
    python scripts/ci_scan.py path/to/file1.py path/to/file2.py

    # Markdown 评论输出（供 PR 评论使用）
    python scripts/ci_scan.py --format comment path/to/file.py

    # 指定 Ollama 地址与模型
    OLLAMA_BASE_URL=http://host:11434 VULN_SCANNER_MODEL=qwen3:8b \\
        python scripts/ci_scan.py file.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

# 项目根目录（目录名通常为 ZaoZao，历史名 Graduation-Project；以 pyproject.toml 为锚点，与目录名解耦）
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 默认模型 / 回退模型（与项目其余入口保持一致，支持环境变量覆盖）
try:
    from app.backend.services.model_registry import get_default_model as _get_default_model
    from graduation_project.transformers_client import resolve_default_backend as _resolve_default_backend
    # 与后端服务 scanner.py 同口径：transformers/vllm 用本地 LoRA 形态 α0.5，ollama 用已发布的 v9max
    DEFAULT_MODEL = os.environ.get(
        "VULN_SCANNER_MODEL", _get_default_model(_resolve_default_backend()),
    )
except Exception:
    DEFAULT_MODEL = os.environ.get(
        "VULN_SCANNER_MODEL", "garrywhite109909/graduation-vuln-scanner:v9max",
    )
FALLBACK_MODEL = os.environ.get("VULN_SCANNER_FALLBACK_MODEL", "qwen3:8b")

# 文件扩展名 → 语言映射（与 vuln_scanner_cli 保持一致）
EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".php": "php",
    ".go": "go",
}

# 风险等级 → Markdown 徽章颜色
RISK_BADGE = {
    "critical": "critical",
    "high": "high",
    "medium": "important",
    "low": "informational",
    "none": "success",
}


# ---------------------------------------------------------------------------
# 导入与初始化
# ---------------------------------------------------------------------------
def import_scanner():
    """延迟导入 Scanner，兼容两种模块路径。

    优先按 ``graduation_project.scanner`` 导入（核心包规划入口）；
    若该子模块尚不存在，回退到当前实际位置 ``app.backend.services.scanner``。
    重量级依赖（tree_sitter / chromadb 等）延迟到此才 import，
    保证 --help 在依赖缺失时也能工作。
    """
    try:
        from graduation_project.scanner import Scanner  # type: ignore[import-not-found]
        return Scanner
    except ImportError:
        from app.backend.services.scanner import Scanner
        return Scanner


def check_ollama(base_url: str) -> bool:
    """检测 Ollama 服务是否可用。"""
    try:
        import requests

        resp = requests.get(f"{base_url}/api/tags", timeout=5)
        return resp.status_code == 200
    except Exception:
        return False


def list_ollama_models(base_url: str) -> list[str]:
    """列出 Ollama 已 pull 的模型名。"""
    try:
        import requests

        resp = requests.get(f"{base_url}/api/tags", timeout=10)
        data = resp.json()
        return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


def resolve_model(base_url: str, requested: str, fallback: str) -> Optional[str]:
    """解析可用模型：优先请求模型，不可用则回退，均不可用返回 None。"""
    models = list_ollama_models(base_url)
    if requested in models:
        return requested
    if fallback in models:
        print(
            f"[CI] 模型 {requested} 不可用，回退到 {fallback}",
            file=sys.stderr,
        )
        return fallback
    return None


def detect_language(filepath: str) -> str:
    """根据扩展名推断语言。"""
    ext = Path(filepath).suffix.lower()
    return EXT_TO_LANG.get(ext, "text")


# ---------------------------------------------------------------------------
# 扫描核心
# ---------------------------------------------------------------------------
def scan_files(
    files: list[str],
    model: str,
    base_url: str,
) -> tuple[list[dict], dict]:
    """扫描文件列表。

    Returns:
        (results, summary): results 为每文件结果字典；summary 为汇总统计。
    """
    Scanner = import_scanner()
    scanner = Scanner(
        model=model,
        base_url=base_url,
        use_rag=True,
        use_prefilter=True,   # 启用传统规则预筛，明显样本跳过 LLM
        keep_alive=0,
    )

    results: list[dict] = []
    start = time.time()

    for fp in files:
        path = Path(fp)
        if not path.is_file():
            results.append(
                {
                    "filename": fp,
                    "language": detect_language(fp),
                    "has_vulnerability": None,
                    "error": "文件不存在",
                    "vulnerability_type": "none",
                    "risk_level": "None",
                }
            )
            continue

        code = path.read_text(encoding="utf-8", errors="replace")
        if not code.strip():
            results.append(
                {
                    "filename": fp,
                    "language": detect_language(fp),
                    "has_vulnerability": None,
                    "error": "文件为空",
                    "vulnerability_type": "none",
                    "risk_level": "None",
                }
            )
            continue

        language = detect_language(fp)
        try:
            r = scanner.scan_code(
                code, language=language, filename=fp, use_rag=True
            )
            results.append(r.to_dict())
        except Exception as e:  # 单文件异常不应中断整体扫描
            results.append(
                {
                    "filename": fp,
                    "language": language,
                    "has_vulnerability": None,
                    "error": f"{type(e).__name__}: {e}",
                    "vulnerability_type": "none",
                    "risk_level": "None",
                }
            )

    try:
        scanner.unload()
    except Exception:
        pass

    duration = round(time.time() - start, 2)
    summary = {
        "total_files": len(files),
        "scanned": len(results),
        "vulnerable": sum(1 for r in results if r.get("has_vulnerability") is True),
        "safe": sum(1 for r in results if r.get("has_vulnerability") is False),
        "errors": sum(1 for r in results if r.get("has_vulnerability") is None),
        "model": model,
        "rag_enabled": True,
        "duration": duration,
    }
    return results, summary


# ---------------------------------------------------------------------------
# 输出渲染
# ---------------------------------------------------------------------------
def render_json(results: list[dict], summary: dict) -> str:
    """渲染 JSON 输出。"""
    payload = {"summary": summary, "results": results}
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _risk_badge(level: str) -> str:
    """生成风险等级的 Markdown 徽章。"""
    key = (level or "none").lower()
    color = RISK_BADGE.get(key, "success")
    label = (level or "None")
    return f"![{label}](https://img.shields.io/badge/risk-{label}-{color})"


def _cell(text: str) -> str:
    """转义 Markdown 表格单元格中的管道符与换行。"""
    if text is None:
        return ""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def render_comment(results: list[dict], summary: dict) -> str:
    """渲染供 PR 评论使用的 Markdown。"""
    lines: list[str] = []
    lines.append("## 漏洞扫描报告")
    lines.append("")
    lines.append("本 PR 已由 **AI 漏洞扫描器** 自动审查。")
    lines.append("")
    lines.append(f"- 模型: `{summary.get('model', 'N/A')}`")
    lines.append(f"- RAG 知识库: {'已启用' if summary.get('rag_enabled') else '未启用'}")
    lines.append("- 扫描模式: 仅信息性，**不会阻断 PR 合并**")
    lines.append("")

    # 概要表
    lines.append("### 扫描概要")
    lines.append("")
    lines.append("| 指标 | 数量 |")
    lines.append("| --- | --- |")
    lines.append(f"| 待扫描文件 | {summary.get('total_files', 0)} |")
    lines.append(f"| 发现漏洞 | {summary.get('vulnerable', 0)} |")
    lines.append(f"| 安全 | {summary.get('safe', 0)} |")
    lines.append(f"| 错误/无法判定 | {summary.get('errors', 0)} |")
    lines.append(f"| 总耗时 | {summary.get('duration', 0)}s |")
    lines.append("")

    vuln_results = [r for r in results if r.get("has_vulnerability") is True]

    if vuln_results:
        lines.append("### 发现漏洞的文件")
        lines.append("")
        lines.append("| 文件 | 漏洞类型 | 风险等级 |")
        lines.append("| --- | --- | --- |")
        for r in vuln_results:
            lines.append(
                f"| `{_cell(r.get('filename'))}` "
                f"| {_cell(r.get('vulnerability_type', 'none'))} "
                f"| {_risk_badge(r.get('risk_level', 'None'))} |"
            )
        lines.append("")
    else:
        lines.append("### 发现漏洞的文件")
        lines.append("")
        lines.append("本次扫描未发现漏洞。")
        lines.append("")

    # 详细结果（折叠）
    lines.append("### 详细结果")
    lines.append("")
    if not results:
        lines.append("无文件被扫描。")
        lines.append("")
    for r in results:
        fname = r.get("filename", "(unknown)")
        has_vuln = r.get("has_vulnerability")
        lines.append(f"<details>")
        if has_vuln is True:
            summary_label = f"发现漏洞 — {r.get('vulnerability_type', 'unknown')} ({r.get('risk_level', 'None')})"
        elif has_vuln is False:
            summary_label = "安全"
        else:
            summary_label = f"错误/无法判定 — {r.get('error', 'unknown')}"
        lines.append(f"<summary><code>{_cell(fname)}</code> — {summary_label}</summary>")
        lines.append("")
        lines.append(f"- **语言**: {r.get('language', 'N/A')}")
        lines.append(f"- **是否存在漏洞**: {has_vuln}")
        lines.append(f"- **漏洞类型**: {r.get('vulnerability_type', 'none')}")
        lines.append(f"- **风险等级**: {r.get('risk_level', 'None')}")
        if has_vuln is True:
            lines.append(f"- **污染来源**: {r.get('source', 'N/A')}")
            lines.append(f"- **触发点**: {r.get('sink', 'N/A')}")
            explanation = r.get("explanation", "")
            if explanation:
                lines.append(f"- **说明**:")
                lines.append("")
                lines.append(f"  {explanation}")
                lines.append("")
            fix = r.get("fix_suggestion", "")
            if fix and fix != "no fix needed":
                lines.append(f"- **修复建议**:")
                lines.append("")
                lines.append(f"  {fix}")
                lines.append("")
        if r.get("error"):
            lines.append(f"- **错误**: {r.get('error')}")
        lines.append(f"- **耗时**: {r.get('duration', 0)}s")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append("---")
    lines.append(
        f"*由 凿凿（ZaoZao）漏洞扫描器自动生成 | 模型 `{summary.get('model', 'N/A')}` "
        f"| 耗时 {summary.get('duration', 0)}s | 此评论仅供参考*"
    )
    lines.append("")
    return "\n".join(lines)


def render_warning(message: str, fmt: str) -> str:
    """渲染警告信息（Ollama 不可用等场景）。"""
    if fmt == "comment":
        lines = [
            "## 漏洞扫描报告",
            "",
            "⚠️ 扫描未能执行。",
            "",
            f"**原因**: {message}",
            "",
            "本次扫描已跳过，不会阻断 PR 合并。可重新触发 CI 或检查配置后重试。",
            "",
            "---",
            "*由 凿凿（ZaoZao）漏洞扫描器自动生成 | 此评论仅供参考*",
            "",
        ]
        return "\n".join(lines)
    # JSON 警告
    payload = {
        "summary": {
            "total_files": 0,
            "scanned": 0,
            "vulnerable": 0,
            "safe": 0,
            "errors": 0,
            "skipped": True,
            "warning": message,
        },
        "results": [],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ci_scan",
        description="CI 漏洞扫描脚本 —— 基于 LLM + RAG 的 PR 代码安全审查",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "files",
        nargs="+",
        metavar="FILE",
        help="待扫描的文件路径（一个或多个）",
    )
    parser.add_argument(
        "--format",
        choices=["json", "comment"],
        default="json",
        help="输出格式：json（默认，stdout 输出 JSON）或 comment（Markdown 评论）",
    )
    parser.add_argument(
        "--ollama-url",
        default=None,
        help=f"Ollama 服务地址（默认读取 OLLAMA_BASE_URL 或 http://localhost:11434）",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=f"Ollama 模型名（默认读取 VULN_SCANNER_MODEL 或 {DEFAULT_MODEL}）",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    base_url = (
        args.ollama_url
        or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    )
    requested_model = args.model or os.environ.get(
        "VULN_SCANNER_MODEL", DEFAULT_MODEL
    )

    files = [f for f in args.files if f]
    if not files:
        print(render_warning("未提供待扫描文件", args.format))
        return 0

    # 1. 检测 Ollama 可用性 —— 不可用则输出警告并以 0 退出，不阻断 PR
    if not check_ollama(base_url):
        print(
            render_warning(
                f"Ollama 服务不可用 ({base_url})", args.format
            )
        )
        return 0

    # 2. 解析可用模型 —— 缺失则回退，仍无则警告退出
    model = resolve_model(base_url, requested_model, FALLBACK_MODEL)
    if model is None:
        print(
            render_warning(
                f"未找到可用模型（已尝试 {requested_model} 与回退 {FALLBACK_MODEL}）",
                args.format,
            )
        )
        return 0

    # 3. 执行扫描
    try:
        results, summary = scan_files(files, model, base_url)
    except Exception as e:
        # 整体异常也不阻断 PR
        print(
            render_warning(
                f"扫描过程中发生异常: {type(e).__name__}: {e}", args.format
            ),
            file=sys.stdout,
        )
        if os.environ.get("CI_SCAN_DEBUG"):
            import traceback

            traceback.print_exc(file=sys.stderr)
        return 0

    # 4. 输出结果
    if args.format == "comment":
        print(render_comment(results, summary))
    else:
        print(render_json(results, summary))

    return 0


if __name__ == "__main__":
    sys.exit(main())
