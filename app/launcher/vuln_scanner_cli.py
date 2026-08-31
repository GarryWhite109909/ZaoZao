"""
AI 漏洞扫描器 —— 命令行工具。

直接复用 app.backend.services.scanner.Scanner，无需启动 FastAPI 后端即可使用。

用法示例：
    # 健康检查（检测 Ollama 连接与模型可用性）
    python -m app.launcher.vuln_scanner_cli health

    # 扫描单个文件
    python -m app.launcher.vuln_scanner_cli scan path/to/file.py

    # 批量扫描目录下所有代码文件
    python -m app.launcher.vuln_scanner_cli batch path/to/project --output report.md

    # 扫描 URL 抓取的脚本
    python -m app.launcher.vuln_scanner_cli url https://example.com

    # 扫描 GitHub 仓库（浅克隆）
    python -m app.launcher.vuln_scanner_cli github https://github.com/user/repo

    # 启用 RAG 知识库增强
    python -m app.launcher.vuln_scanner_cli scan file.py --rag

    # 以 JSON 格式输出
    python -m app.launcher.vuln_scanner_cli scan file.py --format json

入口：
    python -m app.launcher.vuln_scanner_cli <command> [options]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

# 项目根目录（Graduation-Project/）
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 重量级项目依赖（tree_sitter / chromadb 等）延迟到命令执行时才 import，
# 保证 --help / 参数解析在依赖缺失时也能工作。
try:
    from app.backend.services.model_registry import get_default_model as _get_default_model
    DEFAULT_MODEL = os.environ.get("VULN_SCANNER_MODEL", _get_default_model())
except Exception:
    DEFAULT_MODEL = os.environ.get("VULN_SCANNER_MODEL", "garrywhite109909/graduation-vuln-scanner:v9max")
FALLBACK_MODEL = os.environ.get("VULN_SCANNER_FALLBACK_MODEL", "qwen3:8b")

# 文件扩展名 → 语言映射（与后端保持一致）
EXT_TO_LANG = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript",
    ".java": "java", ".php": "php", ".go": "go",
    ".html": "html", ".htm": "html",
    ".vue": "javascript", ".svelte": "javascript",
}

# 风险等级 → 终端配色
RISK_COLORS = {
    "critical": "\033[91m",  # 亮红
    "high": "\033[31m",      # 红
    "medium": "\033[33m",    # 黄
    "low": "\033[36m",       # 青
    "none": "\033[32m",      # 绿
}
RESET = "\033[0m"
BOLD = "\033[1m"
# 直接颜色常量（Python 3.11 f-string 表达式禁止含反斜杠字面量，须用变量引用）
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"


# ---------------------------------------------------------------------------
# 终端输出工具
# ---------------------------------------------------------------------------
def colorize(text: str, color: str) -> str:
    """终端着色（非 TTY 自动退化）。"""
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}{RESET}"


def print_header(title: str) -> None:
    width = 60
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)


def print_single_result(r, verbose: bool = False) -> None:
    """终端打印单文件扫描结果。"""
    risk_key = (r.risk_level or "none").lower()
    color = RISK_COLORS.get(risk_key, RISK_COLORS["none"])
    # 兼容 SingleResult（duration）与 TwoStageResult（total_duration）
    duration = getattr(r, "duration", None)
    if duration is None:
        duration = getattr(r, "total_duration", 0.0)

    if r.error:
        print(f"  {colorize('✗', RED)} {r.filename} — 错误: {r.error}")
        return

    if r.has_vulnerability is True:
        status = colorize("✗ 发现漏洞", color)
    elif r.has_vulnerability is False:
        status = colorize("✓ 安全", RISK_COLORS["none"])
    else:
        status = colorize("? 无法判定", "\033[33m")

    print(f"  {status}  {r.filename}  ({r.language}, {duration:.2f}s)")

    if r.has_vulnerability is True:
        print(f"     类型: {colorize(r.vulnerability_type, color)}  风险: {colorize(r.risk_level, color)}")
        if r.source and r.source != "N/A":
            print(f"     来源: {r.source}")
        if r.sink and r.sink != "N/A":
            print(f"     触发: {r.sink}")
        if verbose and r.explanation:
            print(f"     说明: {r.explanation}")
        if verbose and r.fix_suggestion and r.fix_suggestion != "no fix needed":
            print(f"     修复: {r.fix_suggestion}")
    elif verbose and r.explanation:
        print(f"     说明: {r.explanation}")

    if verbose and r.raw_output:
        print(f"     --- 模型原始输出 ---")
        print("     " + r.raw_output.replace("\n", "\n     "))


def print_batch_summary(batch) -> None:
    """终端打印批量扫描汇总。"""
    print_header("扫描汇总")
    print(f"  总文件数: {batch.total_files}")
    print(f"  已扫描:   {batch.scanned}")
    print(f"  {colorize('发现漏洞:', RED)} {batch.vulnerable}")
    print(f"  {colorize('安全:', GREEN)}     {batch.safe}")
    if batch.errors:
        print(f"  {colorize('错误:', YELLOW)}     {batch.errors}")
    print(f"  总耗时:   {batch.total_duration:.2f}s")

    if batch.vulnerable:
        print()
        print(f"  {BOLD}漏洞清单{RESET}")
        for r in batch.results:
            if r.has_vulnerability is True:
                risk_key = (r.risk_level or "none").lower()
                color = RISK_COLORS.get(risk_key, RISK_COLORS["none"])
                print(f"    {colorize('●', color)} {r.filename} — {r.vulnerability_type} ({r.risk_level})")


def save_report(report: str, output: str | None) -> None:
    """保存报告到文件（如指定）。"""
    if not output:
        return
    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    print(f"\n  报告已保存: {colorize(str(out_path), BOLD)}")


def save_json(data: dict, output: str | None) -> None:
    """保存 JSON 结果到文件（如指定）。"""
    if not output:
        return
    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n  JSON 结果已保存: {colorize(str(out_path), BOLD)}")


def build_scanner(args: argparse.Namespace):
    """根据命令行参数构建两阶段扫描器（工具召回 + LLM 裁决，与后端统一路径）。

    复用 app.backend.services.scanner.Scanner 负责 client 构建（推理后端探测/
    模型解析），实际扫描走 TwoStageScanner（同一 client，避免重复加载模型）。
    旧单遍 Scanner 仅供论文基线对照，不作为 CLI 扫描路径。
    """
    from app.backend.services.scanner import Scanner as _OldScanner
    from graduation_project.two_stage_scanner import TwoStageScanner
    from app.backend.services.model_registry import get_prompt_for_model

    model = getattr(args, "model", None) or os.environ.get("VULN_SCANNER_MODEL", DEFAULT_MODEL)
    base_url = getattr(args, "ollama_url", None) or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    use_rag = getattr(args, "rag", False)

    # 用旧 Scanner 的构建逻辑拿到推理 client（同一后端探测/回退逻辑）
    _old = _OldScanner(
        model=model,
        base_url=base_url,
        use_rag=use_rag,
        keep_alive=0,
    )
    return TwoStageScanner(
        client=_old.client,
        system_prompt=get_prompt_for_model(model),
        keep_alive=0,
        triage_aligned=True,  # 与后端一致，对齐论文 fixed5 组态
        no_candidate_mode="full_recheck",
        n_samples=3,
    )


def detect_language(filepath: str) -> str:
    """根据扩展名推断语言。"""
    ext = Path(filepath).suffix.lower()
    return EXT_TO_LANG.get(ext, "text")


def collect_files_from_dir(directory: str, recursive: bool = True) -> list[Path]:
    """收集目录下所有支持的代码文件。"""
    root = Path(directory)
    if not root.is_dir():
        raise FileNotFoundError(f"目录不存在: {directory}")

    skip_dirs = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "dist", "build"}
    files: list[Path] = []
    # --no-recursive 时只扫顶层（原先两个分支都是 rglob("*")，死分支）
    iterator = root.rglob("*") if recursive else root.glob("*")
    for p in iterator:
        if p.is_file() and p.suffix.lower() in EXT_TO_LANG:
            # 跳过依赖目录
            if any(part in skip_dirs for part in p.parts):
                continue
            files.append(p)
    return files


def result_to_json(r) -> dict:
    return r.to_dict()


# ---------------------------------------------------------------------------
# 命令实现
# ---------------------------------------------------------------------------
def cmd_health(args: argparse.Namespace) -> int:
    """健康检查（推理引擎/模型状态，与扫描管线无关）。"""
    from app.backend.services.scanner import Scanner

    model = getattr(args, "model", None) or os.environ.get("VULN_SCANNER_MODEL", DEFAULT_MODEL)
    base_url = getattr(args, "ollama_url", None) or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    scanner = Scanner(model=model, base_url=base_url, use_rag=False, keep_alive=0)
    print_header("健康检查")
    health = scanner.check_health()

    if health["ollama_connected"]:
        print(f"  Ollama 连接: {colorize('✓ 已连接', RISK_COLORS['none'])}")
    else:
        print(f"  Ollama 连接: {colorize('✗ 未连接', RED)}")
        print(f"     请确保 Ollama 服务已启动: ollama serve")
        return 1

    print(f"  当前模型:   {health['model']}")
    if health["model_available"]:
        print(f"  模型可用:   {colorize('✓ 可用', RISK_COLORS['none'])}")
    else:
        print(f"  模型可用:   {colorize('✗ 未找到', YELLOW)}")
        print(f"     可用模型: {', '.join(health['available_models']) or '(无)'}")
        print(f"     提示: ollama pull {health['model']}")

    print(f"  RAG 增强:   {'✓ 启用' if health['rag_enabled'] else '✗ 关闭'}")

    if health["available_models"]:
        print(f"  已安装模型:")
        for m in health["available_models"]:
            print(f"     - {m}")

    if args.format == "json":
        print()
        print(json.dumps(health, ensure_ascii=False, indent=2))

    return 0 if health["ollama_connected"] else 1


def cmd_scan(args: argparse.Namespace) -> int:
    """扫描单个文件。"""
    from app.backend.services.reporter import render_single_markdown

    filepath = Path(args.file)
    if not filepath.is_file():
        print(f"  {colorize('错误:', RED)} 文件不存在: {filepath}")
        return 1

    code = filepath.read_text(encoding="utf-8", errors="replace")
    if not code.strip():
        print(f"  {colorize('错误:', YELLOW)} 文件为空: {filepath}")
        return 1

    language = args.language or detect_language(str(filepath))
    scanner = build_scanner(args)

    print_header(f"扫描文件: {filepath.name}")
    print(f"  语言: {language}  RAG: {'✓' if args.rag else '✗'}  模型: {scanner.model}")
    print()

    start = time.time()
    result = scanner.scan_code(code, language=language, filename=str(filepath), use_rag=args.rag)
    elapsed = time.time() - start

    print_single_result(result, verbose=args.verbose)

    if args.format == "json":
        out = result.to_dict()
        print()
        print(json.dumps(out, ensure_ascii=False, indent=2))
        save_json(out, args.output)
    elif args.output:
        md = render_single_markdown(result)
        save_report(md, args.output)

    scanner.unload()

    if result.error:
        return 1
    return 0  # 扫描成功即返回 0


def cmd_batch(args: argparse.Namespace) -> int:
    """批量扫描目录。"""
    from app.backend.services.reporter import render_batch_markdown
    from app.backend.services.scanner import BatchResult

    files = collect_files_from_dir(args.directory, recursive=not args.no_recursive)
    if not files:
        print(f"  {colorize('提示:', YELLOW)} 目录中未找到支持的代码文件: {args.directory}")
        return 1

    # 超限时按**文件风险分**排序后取前 N（2026-08-31）。此前是 files[:limit]
    # 按遍历顺序截断——大仓库里 utils/、models/ 常排在 auth/、api/ 之前，
    # 高危文件会被"限流"掉。风险分是纯确定性的（路径语义 + 公开漏洞形态词表），
    # 不消耗 LLM，与 Web 端 /api/github-scan 的预算调度同口径。
    if args.limit and len(files) > args.limit:
        from graduation_project.risk_budget import score_file
        scored = []
        for fp in files:
            try:
                content = fp.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            rel = fp.relative_to(args.directory) if Path(args.directory) in fp.parents else fp
            scored.append((score_file(str(rel), detect_language(str(fp)), content).score,
                           str(rel), fp))
        scored.sort(key=lambda t: (-t[0], t[1]))
        files = [t[2] for t in scored[: args.limit]]
        print(f"  {colorize('提示:', YELLOW)} 文件数 {len(scored)} 超过上限 {args.limit}，"
              f"已按风险分排序，扫描风险最高的 {len(files)} 个"
              f"（最高分 {scored[0][0]:.1f} = {scored[0][1]}）")

    scanner = build_scanner(args)

    print_header(f"批量扫描: {args.directory}")
    print(f"  文件数: {len(files)}  RAG: {'✓' if args.rag else '✗'}  模型: {scanner.model}")
    print(f"  递归: {'✗' if args.no_recursive else '✓'}")
    print()
    print(f"  {BOLD}扫描进度{RESET}")

    batch = BatchResult(total_files=len(files))
    batch_start = time.time()

    for i, fp in enumerate(files, 1):
        rel = fp.relative_to(args.directory) if Path(args.directory) in fp.parents else fp
        code = fp.read_text(encoding="utf-8", errors="replace")
        language = detect_language(str(fp))

        r = scanner.scan_code(code, language=language, filename=str(rel), use_rag=args.rag)
        batch.results.append(r)
        batch.scanned += 1
        if r.has_vulnerability is True:
            batch.vulnerable += 1
        elif r.has_vulnerability is False:
            batch.safe += 1
        else:
            batch.errors += 1

        # 单行进度
        risk_key = (r.risk_level or "none").lower()
        color = RISK_COLORS.get(risk_key, RISK_COLORS["none"])
        mark = colorize("✗", color) if r.has_vulnerability else (
            colorize("✓", RISK_COLORS["none"]) if r.has_vulnerability is False else "?"
        )
        print(f"  [{i}/{len(files)}] {mark} {rel}")

    batch.total_duration = time.time() - batch_start

    print_batch_summary(batch)

    if args.format == "json":
        out = batch.to_dict()
        save_json(out, args.output)
    elif args.output:
        md = render_batch_markdown(batch)
        save_report(md, args.output)

    scanner.unload()
    return 0


def cmd_url(args: argparse.Namespace) -> int:
    """扫描 URL 抓取的脚本。"""
    from app.backend.services.fetcher import fetch_url
    from app.backend.services.reporter import render_batch_markdown
    from app.backend.services.scanner import BatchResult

    scanner = build_scanner(args)

    print_header(f"URL 扫描: {args.url}")
    print(f"  RAG: {'✓' if args.rag else '✗'}  模型: {scanner.model}")
    print()

    print("  正在抓取页面...")
    fetch_result = fetch_url(args.url)

    if fetch_result.error:
        print(f"  {colorize('抓取失败:', RED)} {fetch_result.error}")
        return 1

    print(f"  页面标题: {fetch_result.title}")
    print(f"  发现脚本: {fetch_result.total_scripts}")

    if not fetch_result.scripts:
        print(f"  {colorize('提示:', YELLOW)} 未找到可分析的脚本")
        return 0

    files = [
        (s.source if s.source != "inline" else "inline_script", s.language, s.content)
        for s in fetch_result.scripts
    ]

    print()
    print(f"  {BOLD}扫描进度{RESET}")
    batch = BatchResult(total_files=len(files))
    batch_start = time.time()

    for i, (fname, lang, code) in enumerate(files, 1):
        r = scanner.scan_code(code, language=lang, filename=fname, use_rag=args.rag)
        batch.results.append(r)
        batch.scanned += 1
        if r.has_vulnerability is True:
            batch.vulnerable += 1
        elif r.has_vulnerability is False:
            batch.safe += 1
        else:
            batch.errors += 1

        risk_key = (r.risk_level or "none").lower()
        color = RISK_COLORS.get(risk_key, RISK_COLORS["none"])
        mark = colorize("✗", color) if r.has_vulnerability else (
            colorize("✓", RISK_COLORS["none"]) if r.has_vulnerability is False else "?"
        )
        print(f"  [{i}/{len(files)}] {mark} {fname}")

    batch.total_duration = time.time() - batch_start
    print_batch_summary(batch)

    if args.format == "json":
        out = {"url": args.url, "title": fetch_result.title, "summary": batch.to_dict()}
        save_json(out, args.output)
    elif args.output:
        md = render_batch_markdown(batch, title=f"URL 扫描报告: {args.url}")
        save_report(md, args.output)

    scanner.unload()
    return 0


def cmd_github(args: argparse.Namespace) -> int:
    """扫描 GitHub 仓库（浅克隆后批量扫描）。"""
    from app.backend.services.reporter import render_batch_markdown
    from app.backend.services.scanner import BatchResult

    repo_url = args.repo_url
    if not shutil.which("git"):
        print(f"  {colorize('错误:', RED)} 系统未安装 git")
        return 1

    scanner = build_scanner(args)

    print_header(f"GitHub 仓库扫描")
    print(f"  仓库: {repo_url}")
    print(f"  RAG: {'✓' if args.rag else '✗'}  模型: {scanner.model}")
    print(f"  文件上限: {args.max_files}")
    print()

    tmp_dir = tempfile.mkdtemp(prefix="vuln_cli_")
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    clone_target = os.path.join(tmp_dir, repo_name)

    print("  正在浅克隆仓库...")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, clone_target],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            print(f"  {colorize('克隆失败:', RED)} {result.stderr[:500]}")
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return 1
    except subprocess.TimeoutExpired:
        print(f"  {colorize('错误:', RED)} git clone 超时（120s）")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return 1

    print("  克隆完成，收集代码文件...")
    code_files: list[tuple[str, str, str]] = []
    for root, _dirs, fnames in os.walk(clone_target):
        if any(skip in root for skip in [".git", "node_modules", "vendor", "__pycache__"]):
            continue
        for fname in fnames:
            ext = Path(fname).suffix.lower()
            if ext not in EXT_TO_LANG:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fp:
                    content = fp.read()
                rel_path = os.path.relpath(fpath, clone_target)
                code_files.append((rel_path, EXT_TO_LANG[ext], content))
            except Exception:
                continue
            if len(code_files) >= args.max_files:
                break
        if len(code_files) >= args.max_files:
            break

    shutil.rmtree(tmp_dir, ignore_errors=True)

    if not code_files:
        print(f"  {colorize('提示:', YELLOW)} 仓库中未找到支持的代码文件")
        return 0

    print(f"  共 {len(code_files)} 个代码文件")
    print()
    print(f"  {BOLD}扫描进度{RESET}")

    batch = BatchResult(total_files=len(code_files))
    batch_start = time.time()

    for i, (fname, lang, code) in enumerate(code_files, 1):
        r = scanner.scan_code(code, language=lang, filename=fname, use_rag=args.rag)
        batch.results.append(r)
        batch.scanned += 1
        if r.has_vulnerability is True:
            batch.vulnerable += 1
        elif r.has_vulnerability is False:
            batch.safe += 1
        else:
            batch.errors += 1

        risk_key = (r.risk_level or "none").lower()
        color = RISK_COLORS.get(risk_key, RISK_COLORS["none"])
        mark = colorize("✗", color) if r.has_vulnerability else (
            colorize("✓", RISK_COLORS["none"]) if r.has_vulnerability is False else "?"
        )
        print(f"  [{i}/{len(code_files)}] {mark} {fname}")

    batch.total_duration = time.time() - batch_start
    print_batch_summary(batch)

    if args.format == "json":
        out = {"repo": repo_url, "scanned_files": len(code_files), "summary": batch.to_dict()}
        save_json(out, args.output)
    elif args.output:
        md = render_batch_markdown(batch, title=f"GitHub 仓库扫描报告: {repo_url}")
        save_report(md, args.output)

    scanner.unload()
    return 0


# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    # 共享参数：通过 parents 机制让子命令也接受 --model / --rag / --format 等参数
    # 这样 `vuln-scanner scan file.py --rag` 和 `vuln-scanner --rag scan file.py` 都能生效
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--model", default=None, help=f"Ollama 模型名（默认 {DEFAULT_MODEL}）")
    shared.add_argument("--ollama-url", default=None, help="Ollama 服务地址（默认 http://localhost:11434）")
    shared.add_argument("--rag", action="store_true", help="启用 RAG 知识库增强（较慢但更准）")
    shared.add_argument("--format", choices=["text", "json"], default="text", help="输出格式（默认 text）")

    parser = argparse.ArgumentParser(
        prog="vuln-scanner",
        description="AI 漏洞扫描器命令行工具 —— 基于 LLM 的代码安全审计",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s health                              健康检查
  %(prog)s scan app/main.py                    扫描单个文件
  %(prog)s scan app/main.py --rag --verbose    启用 RAG 并显示详细分析
  %(prog)s batch ./src --output report.md      批量扫描目录并导出报告
  %(prog)s url https://example.com             扫描网页脚本
  %(prog)s github https://github.com/user/repo 扫描 GitHub 仓库
        """.strip(),
        parents=[shared],
    )

    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    # health
    sub.add_parser("health", help="健康检查（Ollama 连接 + 模型可用性）", parents=[shared])

    # scan
    p_scan = sub.add_parser("scan", help="扫描单个文件", parents=[shared])
    p_scan.add_argument("file", help="待扫描的文件路径")
    p_scan.add_argument("--language", default=None, help="覆盖语言检测（如 python/javascript）")
    p_scan.add_argument("--output", "-o", default=None, help="报告输出路径（.md 或 .json）")
    p_scan.add_argument("--verbose", "-v", action="store_true", help="显示详细分析说明与修复建议")

    # batch
    p_batch = sub.add_parser("batch", help="批量扫描目录下所有代码文件", parents=[shared])
    p_batch.add_argument("directory", help="待扫描的目录路径")
    p_batch.add_argument("--output", "-o", default=None, help="报告输出路径（.md 或 .json）")
    p_batch.add_argument("--no-recursive", action="store_true", help="不递归子目录")
    p_batch.add_argument("--limit", type=int, default=0, help="最多扫描文件数（0=不限）")
    p_batch.add_argument("--verbose", "-v", action="store_true", help="显示每个文件的详细分析")

    # url
    p_url = sub.add_parser("url", help="扫描 URL 抓取的脚本", parents=[shared])
    p_url.add_argument("url", help="目标 URL")
    p_url.add_argument("--output", "-o", default=None, help="报告输出路径（.md 或 .json）")

    # github
    p_github = sub.add_parser("github", help="扫描 GitHub 仓库（浅克隆）", parents=[shared])
    p_github.add_argument("repo_url", help="GitHub 仓库 URL")
    p_github.add_argument("--output", "-o", default=None, help="报告输出路径（.md 或 .json）")
    p_github.add_argument("--max-files", type=int, default=50, help="最多扫描文件数（默认 50）")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "health":
            return cmd_health(args)
        elif args.command == "scan":
            return cmd_scan(args)
        elif args.command == "batch":
            return cmd_batch(args)
        elif args.command == "url":
            return cmd_url(args)
        elif args.command == "github":
            return cmd_github(args)
        else:
            parser.print_help()
            return 1
    except KeyboardInterrupt:
        print(f"\n  {colorize('已取消', YELLOW)}")
        return 130
    except Exception as e:
        print(f"\n  {colorize('错误:', RED)} {e}")
        if os.environ.get("VULN_CLI_DEBUG"):
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
