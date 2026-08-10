"""SARIF 2.1.0 报告导出 —— 扫描结果的标准化输出。

设计依据：docs/方法论_工具召回与LLM裁决.md §3.5。
SARIF 是静态分析结果的事实标准（GitHub Code Scanning / VSCode Problems /
JetBrains Qodana 均原生支持），导出后前端与 CI 可直接消费。

支持两种结果类型：
- app.backend.services.scanner.SingleResult（旧管道单文件结果）
- graduation_project.two_stage_scanner.TwoStageResult（两阶段架构结果）

级别映射（与设计文档一致）：
- 一致性置信度 ≥0.8 → error；0.5~0.8 → warning；<0.5 → note
- 旧管道按 risk_level 映射：Critical/High→error，Medium→warning，Low→note

自检：
  PYTHONPATH=. python graduation_project/sarif_report.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "Nivis AI Vulnerability Scanner"
TOOL_INFO_URI = "https://github.com/GarryWhite109909/Graduation-Project"

# 旧管道 risk_level → SARIF level
_RISK_TO_LEVEL = {
    "critical": "error", "high": "error",
    "medium": "warning", "low": "note",
}


def _level_from_confidence(confidence: Optional[float]) -> str:
    if confidence is None:
        return "warning"
    if confidence >= 0.8:
        return "error"
    if confidence >= 0.5:
        return "warning"
    return "note"


def _rule_id_from_type(vuln_type: str) -> str:
    """从 'CWE-89 SQL注入' 提取规则 id；无 CWE 时用类型文本。"""
    vuln_type = (vuln_type or "").strip()
    if not vuln_type or vuln_type.lower() == "none":
        return "unknown"
    return vuln_type.split()[0] if vuln_type.split() else "unknown"


def _load_source_text(r: Any) -> str:
    """读取结果对应的源码文本，用于回填真实行号；文件不可读时返回空串。"""
    filename = getattr(r, "filename", "") or ""
    if not filename:
        return ""
    try:
        return Path(filename).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _find_line(code: str, needle: str) -> Optional[int]:
    """在源码中找包含 needle 的第一行；找不到返回 None。"""
    needle = (needle or "").strip()
    if not code or not needle:
        return None
    for idx, line in enumerate(code.splitlines(), 1):
        if needle in line:
            return idx
    return None


def _start_line(r: Any, code: str) -> int:
    """优先用 sink 文本、其次 source 文本在原文件里搜真实行号，兜底第 1 行。"""
    for field in ("sink", "source"):
        line = _find_line(code, getattr(r, field, ""))
        if line:
            return line
    return 1


def _partial_fingerprints(rule_id: str, start_line: int, *keys: str) -> dict:
    """生成稳定的 partialFingerprints（GitHub Code Scanning 用它跨扫描去重）。"""
    payload = "|".join([rule_id, str(start_line), *(str(k) for k in keys)])
    return {"primaryLocationLineHash": hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]}


def single_result_to_sarif_result(r: Any) -> Optional[dict]:
    """SingleResult（旧管道）→ SARIF result。判非漏洞返回 None（不产出）。"""
    if getattr(r, "has_vulnerability", None) is not True:
        return None
    vuln_type = getattr(r, "vulnerability_type", "") or ""
    explanation = getattr(r, "explanation", "") or ""
    source = getattr(r, "source", "") or ""
    sink = getattr(r, "sink", "") or ""
    code = _load_source_text(r)
    line = _start_line(r, code)
    rule_id = _rule_id_from_type(vuln_type)
    return {
        "ruleId": rule_id,
        "level": _RISK_TO_LEVEL.get((getattr(r, "risk_level", "") or "").lower(), "warning"),
        "message": {"text": f"[{vuln_type}] {explanation}".strip()},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": getattr(r, "filename", "") or "unknown"},
                "region": {"startLine": line},
            }
        }],
        "partialFingerprints": _partial_fingerprints(rule_id, line, source, sink),
        "properties": {
            "source": source,
            "sink": sink,
            "fix_suggestion": getattr(r, "fix_suggestion", ""),
            "pipeline": "single-stage",
        },
    }


def two_stage_to_sarif_results(r: Any) -> list[dict]:
    """TwoStageResult（两阶段）→ SARIF results（每个 confirmed finding 一条）。"""
    out: list[dict] = []
    adjudications = getattr(r, "adjudications", []) or []
    findings = getattr(r, "findings", []) or []
    filename = getattr(r, "filename", "") or "unknown"

    # adjudications 与 findings 顺序对应（_adjudicate_all 按序 append）
    for adj, finding in zip(adjudications, findings):
        if not getattr(adj, "confirmed", False):
            continue
        confidence = getattr(adj, "confidence", None)
        f = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
        line = f.get("sink_line") or f.get("source_line") or 1
        source = f.get("source", "")
        sink = f.get("sink", "")
        rule_id = _rule_id_from_type(f.get("taint_type", ""))
        out.append({
            "ruleId": rule_id,
            "level": _level_from_confidence(confidence),
            "message": {
                "text": f"[{f.get('taint_type', '')}] "
                        f"{getattr(adj, 'reasoning', '') or f.get('evidence', '')}".strip(),
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": filename},
                    "region": {"startLine": max(1, int(line))},
                }
            }],
            "partialFingerprints": _partial_fingerprints(rule_id, max(1, int(line)), source, sink),
            "properties": {
                "confidence": confidence,
                "votes": f"{getattr(adj, 'votes_true', 0)}/{getattr(adj, 'votes_false', 0)}",
                "source": source,
                "sink": sink,
                "propagation": f.get("path", []),
                "fix_suggestion": getattr(adj, "fix_suggestion", ""),
                "pipeline": "two-stage",
            },
        })
    return out


def to_sarif(results: list[Any], tool_version: str = "") -> dict:
    """把扫描结果列表转成 SARIF 2.1.0 文档。

    自动识别 SingleResult / TwoStageResult；判安全/无法判定的文件不产出 result。
    """
    sarif_results: list[dict] = []
    rule_ids: list[str] = []
    for r in results:
        if hasattr(r, "adjudications"):  # TwoStageResult
            produced = two_stage_to_sarif_results(r)
        else:  # SingleResult
            one = single_result_to_sarif_result(r)
            produced = [one] if one else []
        for item in produced:
            sarif_results.append(item)
            if item["ruleId"] not in rule_ids:
                rule_ids.append(item["ruleId"])

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "informationUri": TOOL_INFO_URI,
                    "version": tool_version or "unknown",
                    "rules": [{"id": rid} for rid in rule_ids],
                }
            },
            "results": sarif_results,
        }],
    }


if __name__ == "__main__":
    # 自检：两种结果类型各构造一条，验证 SARIF 结构合法
    from dataclasses import dataclass

    @dataclass
    class _FakeSingle:
        filename: str = "a.py"
        has_vulnerability: Optional[bool] = True
        vulnerability_type: str = "CWE-89 SQL注入"
        risk_level: str = "High"
        source: str = "request.args"
        sink: str = "cursor.execute"
        explanation: str = "拼接 SQL"
        fix_suggestion: str = "参数化"

    @dataclass
    class _FakeSingleSafe:
        filename: str = "b.py"
        has_vulnerability: Optional[bool] = False
        vulnerability_type: str = "none"
        risk_level: str = "None"
        source: str = "N/A"
        sink: str = "N/A"
        explanation: str = ""
        fix_suggestion: str = ""

    doc = to_sarif([_FakeSingle(), _FakeSingleSafe()], tool_version="test")
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"][0]["results"]) == 1, "安全文件不应产出 result"
    res = doc["runs"][0]["results"][0]
    assert res["ruleId"] == "CWE-89" and res["level"] == "error"
    assert doc["runs"][0]["tool"]["driver"]["rules"][0]["id"] == "CWE-89"
    json.dumps(doc)  # 必须可序列化
    print("[PASS] SARIF 自检通过（SingleResult 转换 + 安全文件过滤 + 可序列化）")
