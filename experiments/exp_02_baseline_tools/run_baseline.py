"""
exp_02_baseline_tools - 传统静态分析工具对比基线

复用 exp_01 的 14 段样本，分别调用 Bandit（仅 Python）和 Semgrep（多语言），
输出与 exp_01 统一格式的 JSON 结果，便于横向对比 LLM vs 传统工具。

判定口径：
- 工具输出 results 数组非空 → tool_has_vulnerability = True
- 工具输出 results 数组为空 → tool_has_vulnerability = False
- 工具不支持该语言（Bandit 跑非 Python） → tool_has_vulnerability = None（invalid）

Bandit 额外支持 severity / confidence 过滤（避免 B404 等信息级 finding 被计为漏洞）：
- --bandit-min-severity 默认 LOW
- --bandit-min-confidence 默认 MEDIUM

用法:
    python run_baseline.py                          # 跑全部工具 + 全部样本
    python run_baseline.py --tool bandit            # 只跑 Bandit
    python run_baseline.py --tool semgrep           # 只跑 Semgrep
    python run_baseline.py --limit 3                # 只跑前 3 个样本（调试）
    python run_baseline.py --semgrep-config p/default   # 指定 Semgrep 规则集
    python run_baseline.py --bandit-min-severity MEDIUM --bandit-min-confidence MEDIUM  # 严格口径
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# 把项目根加入 sys.path，保证可从任意目录运行
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# 把当前 Python 解释器所在目录加入 PATH，确保能找到同环境的 CLI 工具
# （如 bandit/semgrep 装在同一个 conda/venv 环境时，subprocess 能定位到）
_PYTHON_BIN_DIR = os.path.dirname(sys.executable)
if _PYTHON_BIN_DIR not in os.environ.get("PATH", "").split(os.pathsep):
    os.environ["PATH"] = _PYTHON_BIN_DIR + os.pathsep + os.environ.get("PATH", "")

from experiments.utils import (
    load_manifest,
    save_results_json,
    new_results_envelope,
    default_results_path,
    compute_detection_metrics,
    print_summary,
)

# ---------------------------------------------------------------------------
# 路径常量
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
# 复用 exp_01 的样本集，保证对比公平
SAMPLES_DIR = SCRIPT_DIR.parent / "exp_01_basic_scan" / "samples"
MANIFEST_PATH = SAMPLES_DIR / "manifest.json"
RESULTS_DIR = SCRIPT_DIR / "results"


# ---------------------------------------------------------------------------
# Bandit severity / confidence 过滤辅助
# ---------------------------------------------------------------------------
_SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_CONFIDENCE_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _bandit_level(level_str: str, order: dict) -> int:
    """把 Bandit 的 severity/confidence 字符串转成可比较整数。"""
    return order.get((level_str or "").upper(), 0)


def _bandit_finding_passes_filter(
    issue: dict,
    min_severity: str,
    min_confidence: str,
) -> bool:
    """判断单条 Bandit finding 是否满足 severity / confidence 阈值。"""
    sev = _bandit_level(issue.get("severity"), _SEVERITY_ORDER)
    conf = _bandit_level(issue.get("confidence"), _CONFIDENCE_ORDER)
    return (
        sev >= _bandit_level(min_severity, _SEVERITY_ORDER)
        and conf >= _bandit_level(min_confidence, _CONFIDENCE_ORDER)
    )


# ---------------------------------------------------------------------------
# 工具调用封装
# ---------------------------------------------------------------------------
def run_bandit(
    sample_path: Path,
    min_severity: str = "LOW",
    min_confidence: str = "MEDIUM",
) -> dict:
    """调用 Bandit 分析单个 Python 文件，返回统一结构。

    Args:
        min_severity: 最小 severity 阈值（LOW/MEDIUM/HIGH/CRITICAL）
        min_confidence: 最小 confidence 阈值（LOW/MEDIUM/HIGH）

    Returns:
        {
            "tool": "bandit",
            "supported": bool,          # 该语言是否被工具支持
            "findings": list[dict],     # 原始解析后的全部告警
            "filtered_findings": list[dict],  # 经 severity/confidence 过滤后的告警
            "raw_output": dict|str,     # 工具原始 JSON 输出（解析失败时为字符串）
            "error": str|None,
            "elapsed_seconds": float,
            "min_severity": str,        # 本次使用的阈值
            "min_confidence": str,
        }
    """
    result = {
        "tool": "bandit",
        "supported": True,
        "findings": [],
        "filtered_findings": [],
        "raw_output": None,
        "error": None,
        "elapsed_seconds": 0.0,
        "min_severity": min_severity,
        "min_confidence": min_confidence,
    }

    if sample_path.suffix != ".py":
        result["supported"] = False
        result["error"] = f"Bandit 仅支持 Python，跳过 {sample_path.name}"
        return result

    start = time.time()
    try:
        # -f json 输出 JSON；-q 安静模式，不打印 banner
        proc = subprocess.run(
            ["bandit", "-f", "json", "-q", str(sample_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        result["elapsed_seconds"] = round(time.time() - start, 3)

        # Bandit 即使发现漏洞也返回非 0 退出码（有告警时 exit=1），
        # 所以不能靠 returncode 判断成败，要看 stdout 是否为合法 JSON
        try:
            parsed = json.loads(proc.stdout)
            result["raw_output"] = parsed
        except json.JSONDecodeError:
            result["error"] = f"Bandit 输出不是合法 JSON。stderr={proc.stderr[:300]}"
            return result

        # Bandit exit code：0=无告警，1=有告警，2=内部错误
        # 同时检查 JSON 的 errors 字段（Bandit 出错但仍输出合法 JSON 的情况），
        # 避免把"工具出错"静默当成"无漏洞"
        if proc.returncode == 2 or parsed.get("errors"):
            err_list = parsed.get("errors", [])
            err_str = "; ".join(err_list) if isinstance(err_list, list) else str(err_list)
            result["error"] = f"Bandit 内部错误（exit={proc.returncode}）: {err_str or proc.stderr[:300]}"
            return result

        # 解析告警（保留原始全部 findings，同时生成过滤后的 filtered_findings）
        for issue in parsed.get("results", []):
            cwe_link = (issue.get("issue_cwe") or {}).get("link", "")
            cwe_match_obj = re.search(r'definitions/(\d+)\.html', cwe_link)
            finding = {
                "rule_id": issue.get("test_id"),
                "severity": issue.get("issue_severity"),
                "confidence": issue.get("issue_confidence"),
                "message": issue.get("issue_text"),
                "line": issue.get("line_number"),
                "cwe": f"CWE-{cwe_match_obj.group(1)}" if cwe_match_obj else "",
            }
            result["findings"].append(finding)
            if _bandit_finding_passes_filter(finding, min_severity, min_confidence):
                result["filtered_findings"].append(finding)
    except FileNotFoundError:
        result["error"] = "Bandit 未安装（pip install bandit）"
    except subprocess.TimeoutExpired:
        result["error"] = "Bandit 执行超时（>60s）"
    except Exception as e:
        result["error"] = f"Bandit 异常: {e}"
    return result


def run_semgrep(sample_path: Path, configs: list[str] | None = None) -> dict:
    """调用 Semgrep 分析单个文件，返回统一结构。

    Args:
        sample_path: 待测文件
        configs: Semgrep 规则集列表，默认 ["auto"]（自动从 registry 拉取）。
            多个配置各自展开为一个 --config flag（如本地 registry 快照 +
            自研 taint 规则目录，与 Stage1 external_scanner 同口径）。
    """
    configs = configs or ["auto"]
    result = {
        "tool": "semgrep",
        "supported": True,
        "findings": [],
        "raw_output": None,
        "error": None,
        "elapsed_seconds": 0.0,
    }

    start = time.time()
    try:
        # --json 输出 JSON；--config 指定规则集（可多个）；--quiet 抑制进度条
        cmd = ["semgrep", "--json", "--quiet"]
        for cfg in configs:
            cmd += ["--config", cfg]
        cmd.append(str(sample_path))
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        result["elapsed_seconds"] = round(time.time() - start, 3)

        if proc.returncode not in (0, 1):
            # returncode=1 表示有 finding，是正常情况；其他非 0 才算错误
            result["error"] = f"Semgrep 退出码 {proc.returncode}。stderr={proc.stderr[:300]}"
            return result

        try:
            parsed = json.loads(proc.stdout)
            result["raw_output"] = parsed
        except json.JSONDecodeError:
            result["error"] = f"Semgrep 输出不是合法 JSON。stdout[:200]={proc.stdout[:200]}"
            return result

        # 解析告警
        for issue in parsed.get("results", []):
            result["findings"].append({
                "rule_id": issue.get("check_id"),
                "severity": (issue.get("extra") or {}).get("severity"),
                "message": (issue.get("extra") or {}).get("message"),
                "line": issue.get("start", {}).get("line"),
                "path": issue.get("path"),
            })
    except FileNotFoundError:
        result["error"] = "Semgrep 未安装（pip install semgrep）"
    except subprocess.TimeoutExpired:
        result["error"] = "Semgrep 执行超时（>120s）"
    except Exception as e:
        result["error"] = f"Semgrep 异常: {e}"
    return result


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="传统静态分析工具对比基线")
    parser.add_argument("--tool", choices=["bandit", "semgrep", "all"], default="all",
                        help="选择工具（默认 all，两个都跑）")
    parser.add_argument("--limit", type=int, default=0,
                        help="只跑前 N 个样本，0 表示全部")
    parser.add_argument("--semgrep-config", default="auto",
                        help="Semgrep 规则集（默认 auto；逗号分隔可传多个，如 "
                             "models/semgrep_rules,graduation_project/semgrep_rules）")
    parser.add_argument("--manifest-path", type=str, default=None,
                        help="测试集 manifest 路径（默认 exp_01 14 段；"
                             "87 段合成集 / 20 段 CVE-fix 需显式指定）")
    parser.add_argument("--samples-dir", type=str, default=None,
                        help="测试集代码样本目录（默认与 manifest 同目录）")
    parser.add_argument("--bandit-min-severity", default="LOW",
                        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        help="Bandit 最小 severity 阈值（默认 LOW）")
    parser.add_argument("--bandit-min-confidence", default="MEDIUM",
                        choices=["LOW", "MEDIUM", "HIGH"],
                        help="Bandit 最小 confidence 阈值（默认 MEDIUM）")
    args = parser.parse_args()

    # 测试集可覆盖（87 段合成集 / 20 段 CVE-fix），默认 exp_01 14 段
    manifest_path = Path(args.manifest_path) if args.manifest_path else MANIFEST_PATH
    samples_dir = Path(args.samples_dir) if args.samples_dir else manifest_path.parent

    try:
        manifest, samples = load_manifest(manifest_path)
    except (FileNotFoundError, KeyError) as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 1
    if args.limit > 0:
        samples = samples[: args.limit]

    tools_to_run = ["bandit", "semgrep"] if args.tool == "all" else [args.tool]
    semgrep_configs = [c.strip() for c in args.semgrep_config.split(",") if c.strip()]

    results = new_results_envelope(
        experiment="exp_02_baseline_tools",
        tools=tools_to_run,
        semgrep_config=semgrep_configs,
        bandit_min_severity=args.bandit_min_severity,
        bandit_min_confidence=args.bandit_min_confidence,
        manifest_path=str(manifest_path),
        samples_source=str(samples_dir),
    )

    # 带时间戳的结果路径，避免每次运行覆盖 results.json；
    # tag 附带 manifest 目录名，区分 87 合成集 / CVE-fix 20 等不同测试集
    results_path = default_results_path(
        RESULTS_DIR,
        experiment="exp_02_baseline_tools",
        extra_tag=".".join(tools_to_run + [manifest_path.parent.name]),
    )

    total = len(samples)
    print(f"[信息] 共 {total} 个样本，工具: {tools_to_run}")
    print(f"[信息] 测试集 manifest: {manifest_path}")
    print(f"[信息] 样本目录: {samples_dir}")
    print(f"[信息] 结果文件: {results_path}")

    for idx, sample_meta in enumerate(samples, 1):
        filename = sample_meta["file"]
        sample_path = samples_dir / filename
        if not sample_path.exists():
            print(f"[{idx}/{total}] [跳过] 样本不存在: {sample_path}", file=sys.stderr)
            continue

        language = sample_meta.get("language", "text")
        print(f"[{idx}/{total}] {filename} ({language}, expected_present={sample_meta['expected_present']})", flush=True)

        record = {
            "file": filename,
            "language": language,
            "category": sample_meta.get("category"),
            "expected_present": sample_meta.get("expected_present"),
            "expected_vulnerability": sample_meta.get("expected_vulnerability"),
            "tools": {},
        }

        for tool in tools_to_run:
            if tool == "bandit":
                t_result = run_bandit(
                    sample_path,
                    min_severity=args.bandit_min_severity,
                    min_confidence=args.bandit_min_confidence,
                )
                # Bandit 按 severity/confidence 过滤后判定
                findings_for_verdict = t_result.get("filtered_findings", t_result["findings"])
            else:
                t_result = run_semgrep(sample_path, configs=semgrep_configs)
                findings_for_verdict = t_result["findings"]

            # 判定：有 finding → True；无 finding 且 supported → False；不支持/出错 → None
            if not t_result["supported"]:
                verdict = None
            elif t_result["error"]:
                verdict = None
            else:
                verdict = len(findings_for_verdict) > 0

            tool_record = {
                "tool_has_vulnerability": verdict,
                "findings": t_result["findings"],
                "findings_count": len(t_result["findings"]),
                "elapsed_seconds": t_result["elapsed_seconds"],
                "error": t_result["error"],
                "supported": t_result["supported"],
            }
            # Bandit 额外记录过滤后结果，便于严格/宽松口径对比
            if tool == "bandit":
                tool_record["filtered_findings"] = t_result["filtered_findings"]
                tool_record["filtered_findings_count"] = len(t_result["filtered_findings"])
                tool_record["min_severity"] = t_result["min_severity"]
                tool_record["min_confidence"] = t_result["min_confidence"]

            record["tools"][tool] = tool_record
            status = "有漏洞" if verdict else ("无漏洞" if verdict is False else "N/A")
            count_msg = f"{len(findings_for_verdict)} 条有效告警"
            if tool == "bandit" and len(t_result["findings"]) != len(findings_for_verdict):
                count_msg += f"（原始 {len(t_result['findings'])} 条）"
            print(f"        {tool}: {status}, {count_msg}, {t_result['elapsed_seconds']}s")

        results["samples"].append(record)
        # 每跑完一个样本立即落盘
        save_results_json(results_path, results)

    results["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    # 汇总指标（每个工具分别统计）
    metrics_per_tool = {}
    for tool in tools_to_run:
        # 构造与 compute_detection_metrics 兼容的记录列表
        flat_records = []
        for s in results["samples"]:
            t_data = s.get("tools", {}).get(tool, {})
            flat_records.append({
                "expected_present": s.get("expected_present"),
                "model_has_vulnerability": t_data.get("tool_has_vulnerability"),
                "elapsed_seconds": t_data.get("elapsed_seconds"),
            })
        metrics_per_tool[tool] = compute_detection_metrics(flat_records)

    results["metrics"] = metrics_per_tool
    save_results_json(results_path, results)
    print(f"\n[完成] 结果已写入 {results_path}")

    for tool, m in metrics_per_tool.items():
        print(f"\n=== {tool} 汇总 ===")
        print_summary(m)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
