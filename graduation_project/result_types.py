"""
扫描结果数据结构 —— 核心层通用结果容器。

将 SingleResult / BatchResult 从 app 层（app/backend/services/scanner.py）
下沉到核心层，使核心模块（如 graduation_project/multi_model_scanner.py）
无需反向依赖 app 层即可复用同一套结果结构。

- SingleResult：单段代码扫描结果
- BatchResult：批量扫描汇总结果

这两个数据类是纯数据容器，不依赖任何 app 层模块，可被核心层与 Web 层共同 import。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SingleResult:
    """单段代码扫描结果。"""
    filename: str
    language: str
    has_vulnerability: Optional[bool]
    vulnerability_type: str = "none"
    # 模型对漏洞类型/CWE 编号的【原始】输出（未经 CWE Normalizer 纠正）。
    # 当该值与 vulnerability_type 不一致时，说明查表工具纠正了模型标号，
    # 前端据此展示"模型原始判断 → CWE Normalizer 纠正"过程。
    raw_vulnerability_type: str = ""
    risk_level: str = "None"
    source: str = "N/A"
    sink: str = "N/A"
    explanation: str = ""
    fix_suggestion: str = "no fix needed"
    raw_output: str = ""  # 模型原始输出（含 CoT 分析过程）
    duration: float = 0.0
    error: Optional[str] = None
    sliced: bool = False
    chunk_count: int = 1
    chunk_name: str = ""  # 当前结果对应的切片名（整文件/单文件时为 ""）
    prefilter_verdict: Optional[bool] = None  # 预筛层判定（None=未预筛/交LLM）
    prefilter_rules: list[str] = field(default_factory=list)  # 预筛命中规则

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "language": self.language,
            "has_vulnerability": self.has_vulnerability,
            "vulnerability_type": self.vulnerability_type,
            "raw_vulnerability_type": self.raw_vulnerability_type,
            "risk_level": self.risk_level,
            "source": self.source,
            "sink": self.sink,
            "explanation": self.explanation,
            "fix_suggestion": self.fix_suggestion,
            "raw_output": self.raw_output,
            "duration": round(self.duration, 2),
            "error": self.error,
            "sliced": self.sliced,
            "chunk_count": self.chunk_count,
            "chunk_name": self.chunk_name,
            "prefilter_verdict": self.prefilter_verdict,
            "prefilter_rules": self.prefilter_rules,
        }


@dataclass
class BatchResult:
    """批量扫描汇总结果。"""
    total_files: int = 0
    scanned: int = 0
    vulnerable: int = 0
    safe: int = 0
    errors: int = 0
    results: list[SingleResult] = field(default_factory=list)
    total_duration: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_files": self.total_files,
            "scanned": self.scanned,
            "vulnerable": self.vulnerable,
            "safe": self.safe,
            "errors": self.errors,
            "results": [r.to_dict() for r in self.results],
            "total_duration": round(self.total_duration, 2),
        }