"""
FastAPI 后端入口 —— 漏洞扫描器 API。

路由：
  GET  /api/health            健康检查（Ollama + vLLM 连接、外部工具、各层开关）
  GET  /api/stats             仪表盘统计（扫描历史汇总 + 最近动态 + 健康状态）
  POST /api/analyze           单文件分析（JSON body: code/language/filename）
  POST /api/batch             批量扫描（multipart 文件上传，NDJSON 流式进度）
  POST /api/url-scan          URL 抓取扫描
  POST /api/github-scan       GitHub 仓库扫描
  POST /api/external-scan     外部工具扫描（Bandit/Semgrep/Gitleaks/Trivy）
  POST /api/verify-fix        修复建议验证（语法校验 + 危险模式移除）
  POST /api/multi-model-scan  多模型投票扫描
  POST /api/vllm-analyze      vLLM 推理后端单文件分析
  GET  /api/report            下载最近一次批量扫描的 Markdown 报告
  POST /api/report/single     分析并下载单文件 Markdown 报告

启动：
  uvicorn app.backend.main:app --host 127.0.0.1 --port 8765 --reload
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.backend.services.fetcher import fetch_url
from app.backend.services.reporter import render_batch_markdown, render_single_markdown
from app.backend.services.scanner import DEFAULT_MODEL, BatchResult, Scanner

# 高级能力模块（外部工具扫描 / 修复验证 / 多模型投票 / vLLM 推理加速）
from graduation_project.external_scanner import ExternalScanner
from graduation_project.fix_verifier import FixVerifier
from graduation_project.multi_model_scanner import MultiModelScanner
from graduation_project.vllm_client import VLLMClient
from graduation_project.schema import parse_verdict, normalize_has_vulnerability
from graduation_project.prompts import SYSTEM_PROMPT_LITE, build_user_prompt

# ---------------------------------------------------------------------------
# 全局 Scanner 实例（单例，避免重复初始化 Chroma/OllamaClient）
# ---------------------------------------------------------------------------
scanner = Scanner(
    model=os.environ.get("VULN_SCANNER_MODEL", DEFAULT_MODEL),
    use_rag=os.environ.get("VULN_SCANNER_RAG", "0") == "1",
    use_lite_prompt=True,  # SFT v5 必须用 LITE
    use_prefilter=os.environ.get("VULN_SCANNER_PREFILTER", "1") != "0",  # 默认启用预筛
)

# ---------------------------------------------------------------------------
# 文件扩展名 → 语言映射
# ---------------------------------------------------------------------------
EXT_TO_LANG = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript",
    ".java": "java", ".php": "php", ".go": "go",
    ".html": "html", ".htm": "html",
    ".vue": "javascript", ".svelte": "javascript",
}

# ---------------------------------------------------------------------------
# Pydantic 请求模型
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    code: str
    language: str = "python"
    filename: str = "pasted_code.py"
    use_rag: Optional[bool] = None


class UrlScanRequest(BaseModel):
    url: str
    use_rag: Optional[bool] = None


class GithubScanRequest(BaseModel):
    repo_url: str
    use_rag: Optional[bool] = None
    max_files: int = 50  # 限制扫描文件数，避免大仓库超时


class ExternalScanRequest(BaseModel):
    """外部工具扫描请求（Bandit/Semgrep/Gitleaks/Trivy）。"""
    code: str
    language: str = "python"
    filename: str = "pasted_code.py"


class VerifyFixRequest(BaseModel):
    """修复建议验证请求。"""
    original_code: str
    fix_suggestion: str
    language: str = "python"


class MultiModelRequest(BaseModel):
    """多模型投票扫描请求。"""
    code: str
    language: str = "python"
    filename: str = "pasted_code.py"
    models: list[str] = []
    use_rag: Optional[bool] = None


class VllmAnalyzeRequest(BaseModel):
    """vLLM 后端单文件分析请求。"""
    code: str
    language: str = "python"
    filename: str = "pasted_code.py"
    use_rag: Optional[bool] = None


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AI 漏洞扫描器",
    description="基于 LLM 的代码安全审计系统 API",
    version="1.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["*"],
    allow_headers=["*"],
)

# 最近一次批量扫描结果（供 /api/report 下载）
_last_batch: Optional[BatchResult] = None

# 扫描历史统计（进程内，重启后清零）
_scan_stats: dict = {
    "total_scans": 0,
    "total_files": 0,
    "total_vulnerable": 0,
    "total_safe": 0,
    "total_errors": 0,
    "recent_scans": [],  # 最近 20 条扫描记录
}


# ---------------------------------------------------------------------------
# 健康检查
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def health():
    """健康检查：Ollama + vLLM 连接、模型可用性、外部工具安装情况、各层开关状态。"""
    base = scanner.check_health()

    # vLLM 推理后端探测
    try:
        vllm = VLLMClient()
        base["vllm_connected"] = vllm.check_connection()
        base["vllm_models"] = vllm.list_models() if base["vllm_connected"] else []
    except Exception as e:
        base["vllm_connected"] = False
        base["vllm_models"] = []
        base["vllm_error"] = str(e)

    # 外部安全工具探测（Bandit/Semgrep/Gitleaks/Trivy）
    try:
        ext = ExternalScanner()
        base["external_tools"] = ext.available_tools()
    except Exception as e:
        base["external_tools"] = []
        base["external_error"] = str(e)

    return base


def _record_scan(batch: BatchResult) -> None:
    """记录一次扫描到统计中（进程内，重启后清零）。"""
    _scan_stats["total_scans"] += 1
    _scan_stats["total_files"] += batch.total_files
    _scan_stats["total_vulnerable"] += batch.vulnerable
    _scan_stats["total_safe"] += batch.safe
    _scan_stats["total_errors"] += batch.errors
    # 记录最近 20 条
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total_files": batch.total_files,
        "vulnerable": batch.vulnerable,
        "safe": batch.safe,
        "errors": batch.errors,
        "duration": round(batch.total_duration, 2),
        "results": [
            {
                "filename": r.filename,
                "has_vulnerability": r.has_vulnerability,
                "vulnerability_type": r.vulnerability_type,
                "risk_level": r.risk_level,
            }
            for r in batch.results[:20]  # 最多保留 20 条文件结果
        ],
    }
    _scan_stats["recent_scans"].insert(0, entry)
    if len(_scan_stats["recent_scans"]) > 20:
        _scan_stats["recent_scans"] = _scan_stats["recent_scans"][:20]


@app.get("/api/stats")
def get_stats():
    """仪表盘统计数据：扫描历史汇总 + 最近动态 + 健康状态。

    前端 index.html 调用此端点获取真实数据，替换静态占位。
    进程重启后统计清零，前端可用 localStorage 做历史持久化。
    """
    health = scanner.check_health()
    recent = _scan_stats["recent_scans"]

    # 从最近扫描中提取漏洞列表（用于"最近动态"）
    recent_findings = []
    for scan in recent[:5]:
        for r in scan.get("results", []):
            if r.get("has_vulnerability") is True:
                recent_findings.append({
                    "filename": r["filename"],
                    "vulnerability_type": r["vulnerability_type"],
                    "risk_level": r["risk_level"],
                    "timestamp": scan["timestamp"],
                })

    return {
        "total_scans": _scan_stats["total_scans"],
        "total_files": _scan_stats["total_files"],
        "total_vulnerable": _scan_stats["total_vulnerable"],
        "total_safe": _scan_stats["total_safe"],
        "total_errors": _scan_stats["total_errors"],
        "recent_scans": recent,
        "recent_findings": recent_findings[:10],
        "health": health,
    }


# ---------------------------------------------------------------------------
# 单文件分析（代码粘贴）
# ---------------------------------------------------------------------------
@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    # 同步路由（非 async）：FastAPI 自动放线程池，避免阻塞事件循环
    result = scanner.scan_code(
        code=req.code,
        language=req.language,
        filename=req.filename,
        use_rag=req.use_rag,
    )
    return result.to_dict()


# ---------------------------------------------------------------------------
# 批量扫描（文件上传）+ SSE 进度推送
# ---------------------------------------------------------------------------
@app.post("/api/batch")
async def batch_scan(
    files: list[UploadFile] = File(...),
    use_rag: str = Form("0"),
):
    """批量扫描上传的文件。

    返回 NDJSON 流（每行一个文件的结果），前端可逐行解析显示进度。
    """
    rag = use_rag == "1"
    file_list = []
    for f in files:
        ext = Path(f.filename).suffix.lower()
        lang = EXT_TO_LANG.get(ext, "text")
        content = (await f.read()).decode("utf-8", errors="replace")
        file_list.append((f.filename, lang, content))

    def generate():
        global _last_batch
        batch = BatchResult(total_files=len(file_list))
        batch_start = time.time()

        for filename, lang, code in file_list:
            r = scanner.scan_code(code, lang, filename, use_rag=rag)
            batch.results.append(r)
            batch.scanned += 1
            if r.has_vulnerability is True:
                batch.vulnerable += 1
            elif r.has_vulnerability is False:
                batch.safe += 1
            else:
                batch.errors += 1

            # 推送单文件结果（NDJSON）
            yield json.dumps({
                "type": "progress",
                "scanned": batch.scanned,
                "total": batch.total_files,
                "result": r.to_dict(),
            }, ensure_ascii=False) + "\n"

        batch.total_duration = time.time() - batch_start
        _last_batch = batch
        _record_scan(batch)
        yield json.dumps({
            "type": "done",
            "summary": batch.to_dict(),
        }, ensure_ascii=False) + "\n"

    return StreamingResponse(generate(), media_type="application/x-ndjson")


# ---------------------------------------------------------------------------
# URL 抓取扫描
# ---------------------------------------------------------------------------
@app.post("/api/url-scan")
def url_scan(req: UrlScanRequest):
    """抓取目标 URL 的所有脚本，逐个扫描。"""
    fetch_result = fetch_url(req.url)

    if fetch_result.error:
        return JSONResponse(
            {"error": fetch_result.error, "url": req.url},
            status_code=502,
        )

    if not fetch_result.scripts:
        return {"url": req.url, "title": fetch_result.title, "results": [], "message": "未找到可分析的脚本"}

    files = [
        (s.source if s.source != "inline" else "inline_script",
         s.language, s.content)
        for s in fetch_result.scripts
    ]
    batch = scanner.scan_files(files, use_rag=req.use_rag)
    global _last_batch
    _last_batch = batch

    return {
        "url": req.url,
        "title": fetch_result.title,
        "total_scripts": fetch_result.total_scripts,
        "summary": batch.to_dict(),
    }


# ---------------------------------------------------------------------------
# GitHub 仓库扫描
# ---------------------------------------------------------------------------
@app.post("/api/github-scan")
def github_scan(req: GithubScanRequest):
    """clone GitHub 仓库 → 遍历代码文件 → 批量扫描。"""
    # 浅克隆到临时目录
    tmp_dir = tempfile.mkdtemp(prefix="vuln_scan_")
    try:
        repo_name = req.repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        clone_target = os.path.join(tmp_dir, repo_name)

        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", req.repo_url, clone_target],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0:
                return JSONResponse(
                    {"error": f"git clone 失败: {result.stderr[:500]}"},
                    status_code=502,
                )
        except subprocess.TimeoutExpired:
            return JSONResponse({"error": "git clone 超时（120s）"}, status_code=504)
        except FileNotFoundError:
            return JSONResponse({"error": "系统未安装 git"}, status_code=500)

        # 遍历代码文件
        code_files = []
        for root, _dirs, fnames in os.walk(clone_target):
            # 跳过 .git / node_modules / vendor 等
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
                if len(code_files) >= req.max_files:
                    break
            if len(code_files) >= req.max_files:
                break

        if not code_files:
            return {"repo": req.repo_url, "message": "仓库中未找到支持的代码文件"}

        batch = scanner.scan_files(code_files, use_rag=req.use_rag)
        global _last_batch
        _last_batch = batch
        _record_scan(batch)

        return {
            "repo": req.repo_url,
            "scanned_files": len(code_files),
            "summary": batch.to_dict(),
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 报告下载
# ---------------------------------------------------------------------------
@app.get("/api/report")
async def download_report():
    """下载最近一次批量扫描的 Markdown 报告。"""
    if _last_batch is None:
        return JSONResponse({"error": "暂无扫描结果，请先扫描"}, status_code=404)
    md = render_batch_markdown(_last_batch)
    return StreamingResponse(
        iter([md.encode("utf-8")]),
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=vuln_scan_report.md"},
    )


@app.post("/api/report/single")
def download_single_report(req: AnalyzeRequest):
    """分析并返回单文件 Markdown 报告。"""
    r = scanner.scan_code(
        code=req.code, language=req.language,
        filename=req.filename, use_rag=req.use_rag,
    )
    md = render_single_markdown(r)
    return StreamingResponse(
        iter([md.encode("utf-8")]),
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=single_report.md"},
    )


# ---------------------------------------------------------------------------
# 外部工具扫描（Bandit / Semgrep / Gitleaks / Trivy）
# ---------------------------------------------------------------------------
@app.post("/api/external-scan")
def external_scan(req: ExternalScanRequest):
    """调用传统安全工具对代码做 SAST/SCA/Secret/IaC 扫描。

    将粘贴代码写入临时文件后运行 ExternalScanner，未安装的工具静默跳过。
    返回 ExternalFinding 列表，供前端与 LLM 结果融合展示。
    """
    ext = ExternalScanner()
    suffix = Path(req.filename).suffix.lower() or ".py"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(req.code)
        tmp_path = tmp.name
    try:
        findings = ext.scan(tmp_path, req.language)
        return {
            "available_tools": ext.available_tools(),
            "total": len(findings),
            "findings": [
                {
                    "tool": f.tool,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "message": f.message,
                    "filename": f.filename,
                    "line": f.line,
                    "category": f.category,
                }
                for f in findings
            ],
        }
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# 修复建议验证
# ---------------------------------------------------------------------------
@app.post("/api/verify-fix")
def verify_fix(req: VerifyFixRequest):
    """对 LLM 生成的 fix_suggestion 做语法校验 + 危险模式移除检查。"""
    verifier = FixVerifier()
    result = verifier.verify_fix(
        original_code=req.original_code,
        fix_suggestion=req.fix_suggestion,
        language=req.language,
    )
    return {
        "syntax_valid": result.syntax_valid,
        "tests_passed": result.tests_passed,
        "fixed_code": result.fixed_code,
        "error_message": result.error_message,
        "duration": round(result.duration, 2),
    }


# ---------------------------------------------------------------------------
# 多模型投票扫描
# ---------------------------------------------------------------------------
@app.post("/api/multi-model-scan")
def multi_model_scan(req: MultiModelRequest):
    """多模型交叉验证扫描：顺序加载各模型 → 投票聚合 → 返回 VoteResult。

    前端需传入 ≥2 个模型名；任一时刻显存只驻留单模型（keep_alive=0）。
    """
    if len(req.models) < 2:
        return JSONResponse(
            {"error": "多模型投票至少需要 2 个模型，当前仅 " + str(len(req.models)) + " 个"},
            status_code=400,
        )
    mms = MultiModelScanner(
        models=req.models,
        use_prefilter=True,
        keep_alive=0,
    )
    result = mms.scan_code(
        code=req.code,
        language=req.language,
        filename=req.filename,
        use_rag=req.use_rag,
    )
    return result.to_dict()


# ---------------------------------------------------------------------------
# vLLM 推理后端单文件分析
# ---------------------------------------------------------------------------
@app.post("/api/vllm-analyze")
def vllm_analyze(req: VllmAnalyzeRequest):
    """使用 vLLM（OpenAI 兼容 API）后端分析单段代码。

    vLLM 通过 PagedAttention + continuous batching 提供高吞吐推理，
    适合批量评测场景；接口与 /api/analyze 对齐，便于前端无缝切换后端。
    """
    client = VLLMClient()
    if not client.check_connection():
        return JSONResponse(
            {"error": "vLLM 服务未启动（默认 http://localhost:8000）"},
            status_code=503,
        )

    # 复用统一 prompt 构建逻辑（SFT v5 用 LITE 版系统提示）
    prompt = build_user_prompt(
        code=req.code, language=req.language, filename=req.filename,
    )
    result = client.generate(prompt=prompt, system_prompt=SYSTEM_PROMPT_LITE)

    if result["error"]:
        return JSONResponse({"error": result["error"]}, status_code=502)

    verdict = parse_verdict(result["text"])
    has_vuln = normalize_has_vulnerability(verdict.get("has_vulnerability"))

    # 约束解码兜底：CoT+JSON 解析失败时用 guided_json 重试
    if has_vuln is None:
        structured = client.generate_structured(
            prompt=prompt, system_prompt=SYSTEM_PROMPT_LITE,
        )
        if not structured["error"]:
            verdict = parse_verdict(structured["text"])
            has_vuln = normalize_has_vulnerability(verdict.get("has_vulnerability"))
            if has_vuln is not None:
                result["duration"] += structured["duration"]
                result["text"] = structured["text"]

    return {
        "filename": req.filename,
        "language": req.language,
        "has_vulnerability": has_vuln,
        "vulnerability_type": verdict.get("vulnerability_type", "none"),
        "risk_level": verdict.get("risk_level", "None"),
        "source": verdict.get("source", "N/A"),
        "sink": verdict.get("sink", "N/A"),
        "explanation": verdict.get("explanation", ""),
        "fix_suggestion": verdict.get("fix_suggestion", "no fix needed"),
        "raw_output": result["text"],
        "duration": round(result["duration"], 2),
        "backend": "vllm",
    }


# ---------------------------------------------------------------------------
# 静态资源托管（Vue 构建产物，开发时不存在则跳过）
# ---------------------------------------------------------------------------
_static_dir = Path(__file__).resolve().parent / "static"
if _static_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(_static_dir), html=True), name="static")
else:
    @app.get("/", response_class=HTMLResponse)
    async def index():
        return """
        <html><body>
        <h1>AI 漏洞扫描器 API</h1>
        <p>后端已启动。前端静态资源未构建（app/backend/static/ 不存在）。</p>
        <p>API 文档：<a href="/docs">/docs</a></p>
        </body></html>
        """


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.backend.main:app",
        host="127.0.0.1",
        port=8765,
        reload=False,
    )
