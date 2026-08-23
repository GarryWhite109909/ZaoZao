"""
报告生成服务 —— 把扫描结果输出为 Markdown / 纯文本。

供 Web 端下载和插件端展示用。
"""

from __future__ import annotations

from datetime import datetime

from graduation_project.result_types import BatchResult, SingleResult


def _md_cell(value) -> str:
    """表格单元格转义：裸 | 会断列，换行会断行。"""
    return str(value if value is not None else "").replace("|", "\\|").replace("\r", "").replace("\n", " ")


def _md_fence(text: str) -> str:
    """为内容选取不会被其内部 ``` 围栏截断的反引号围栏（模型输出常含代码块）。"""
    longest = run = 0
    for ch in text:
        if ch == "`":
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    return "`" * max(3, longest + 1)


def render_single_markdown(r) -> str:
    """单文件结果 → Markdown。

    兼容 SingleResult（旧单遍管线）与 TwoStageResult（两阶段管线）：
    两阶段结果无 duration 属性，用 total_duration 兜底。
    """
    duration = getattr(r, "duration", None)
    if duration is None:
        duration = getattr(r, "total_duration", 0.0)
    lines = [
        f"# 漏洞分析报告：{r.filename}",
        "",
        f"**生成时间**：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**语言**：{r.language}",
        f"**耗时**：{duration:.2f}s",
        "",
    ]

    if r.error:
        lines.append(f"❌ **错误**：{r.error}")
        return "\n".join(lines)

    if r.has_vulnerability is True:
        lines.append("## 🔴 发现漏洞")
        lines.append("")
        lines.append(f"| 字段 | 值 |")
        lines.append(f"|---|---|")
        lines.append(f"| 漏洞类型 | {_md_cell(r.vulnerability_type)} |")
        lines.append(f"| 风险等级 | {_md_cell(r.risk_level)} |")
        lines.append(f"| 污染来源 | {_md_cell(r.source)} |")
        lines.append(f"| 触发点 | {_md_cell(r.sink)} |")
        lines.append("")
        lines.append("### 说明")
        lines.append(r.explanation or "（无）")
        lines.append("")
        lines.append("### 修复建议")
        lines.append(r.fix_suggestion or "no fix needed")
    elif r.has_vulnerability is False:
        lines.append("## 🟢 未发现漏洞")
        lines.append("")
        lines.append(r.explanation or "代码经分析未发现安全风险。")
    else:
        lines.append("## ⚠️ 无法判定")
        lines.append(r.error or "模型输出无法解析。")

    if r.raw_output:
        fence = _md_fence(r.raw_output)
        lines.append("")
        lines.append("<details><summary>模型原始输出（CoT 分析过程）</summary>")
        lines.append("")
        lines.append(fence)
        lines.append(r.raw_output)
        lines.append(fence)
        lines.append("</details>")

    return "\n".join(lines)


def render_batch_markdown(batch: BatchResult, title: str = "批量扫描报告") -> str:
    """批量结果 → Markdown 汇总报告。"""
    lines = [
        f"# {title}",
        "",
        f"**生成时间**：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**总文件数**：{batch.total_files}",
        f"**发现漏洞**：{batch.vulnerable}",
        f"**安全**：{batch.safe}",
        f"**错误**：{batch.errors}",
        f"**总耗时**：{batch.total_duration:.2f}s",
        "",
        "---",
        "",
    ]

    # 漏洞汇总表
    vuln_files = [r for r in batch.results if r.has_vulnerability is True]
    if vuln_files:
        lines.append("## 漏洞清单")
        lines.append("")
        lines.append("| 文件 | 漏洞类型 | 风险等级 | 触发点 |")
        lines.append("|---|---|---|---|")
        for r in vuln_files:
            lines.append(
                f"| {_md_cell(r.filename)} | {_md_cell(r.vulnerability_type)} | "
                f"{_md_cell(r.risk_level)} | {_md_cell(r.sink)} |"
            )
        lines.append("")

    # 每个文件的详细报告
    lines.append("## 详细报告")
    lines.append("")
    for r in batch.results:
        lines.append(render_single_markdown(r))
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)
