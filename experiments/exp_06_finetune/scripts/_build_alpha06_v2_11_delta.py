#!/usr/bin/env python3
"""alpha06-v2.11 构建：v2.10 剔除 7 条残留毒样本。

背景：v2.10（Stage A/B 行号吸附升级版，8759 条）构建于 v2.9 中间版
（当时仅剔 3 条自白毒）。二轮逐条裁定新增的 7 条毒样本仍在库中
（指纹验证见 2026-08-29 会话），本脚本做确定性剔除，其余一字不动
（Stage A/B 吸附成果、报告口径全部保留）。

指纹（剔前断言命中，防错位）：
  #649[v2.8]  T毒 '但按照要求必须标记为有漏洞'
  #3064       F毒 '但根据要求，负样本必须'
  #3574       F毒 'has_vulnerability 应为 true'
  #3691       F毒 '该代码片段实际存在 CWE-862'
  #3996       F毒 '整体不安全，需修复email输入处理'
  #4728       X   'XPath 注入漏洞成立'（CoT/注释/标签三方矛盾）
  #5274       F毒 '但根据要求，本样本标记为无漏洞'
"""
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
BASE = BASE_DIR / "data/final_train_chatml_alpha06_v2_10.jsonl"
OUT = BASE_DIR / "data/final_train_chatml_alpha06_v2_11.jsonl"
REPORT = BASE_DIR / "data/build_alpha06_v2_11_report.md"

REMOVE = {
    "但按照要求必须标记为有漏洞": "T",
    "但根据要求，负样本必须": "F",
    "has_vulnerability 应为 true": "F",
    "该代码片段实际存在 CWE-862": "F",
    "整体不安全，需修复email输入处理": "F",
    "XPath 注入漏洞成立": "X",
    "但根据要求，本样本标记为无漏洞": "F",
}


def main():
    rows = [json.loads(l) for l in BASE.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(rows) == 8759, f"基底条数异常: {len(rows)}"

    drop_log = []
    seen = set()
    for i in range(len(rows) - 1, -1, -1):
        a = rows[i]["messages"][2]["content"]
        for fp, typ in REMOVE.items():
            if fp in a:
                assert i not in seen, f"#{i} 命中多条指纹？"
                seen.add(i)
                drop_log.append(f"#{i}[{typ}]: {fp}")
                del rows[i]
                break

    assert len(seen) == 7, f"应剔 7 条，实际 {len(seen)}: {drop_log}"
    # 终验：毒指纹归零
    blob = "\n".join(r["messages"][2]["content"] for r in rows)
    for fp in REMOVE:
        assert fp not in blob, f"剔后仍残留: {fp}"

    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    lines = [
        "# alpha06-v2.11 构建报告",
        "",
        f"- 基底：v2.10（8759 条，Stage A/B 吸附升级版） → 输出 **{len(rows)} 条**",
        "- 剔除 7 条残留毒样本（v2.10 基底为 v2.9 中间版，仅含 3 条剔除；",
        "  本批为二轮逐条裁定增补，指纹断言全命中）：",
        *[f"  - {x}" for x in sorted(drop_log, key=lambda s: int(s.split("[")[0][1:]))],
        "- 其余一字不动：Stage A 记录级偏移投票 / Stage B 多 token 计分吸附、",
        "  risk_level/vt 归一层全部保留；",
        "- 终验：7 条指纹全库归零。",
        "",
        "## 与 v2.9 终版的关系",
        "- v2.9 终版（8752 条，未入库）= v2.8 − 10 毒 + 吸附 v2（89% 精确）；",
        "- v2.11（8752 条）= v2.10 − 7 毒（吸附为 Stage A/B，85.3% 精确 + 记录级偏移修复）；",
        "- 两者条数相同、毒样本清零口径相同；v2.11 的吸附含记录级常数漂移修复",
        "  （v2.9 吸附 v2 的 ±60 距离上限够不着的 k=10/13/14 整记录漂移），",
        "  但缺 v2.9 吸附 v2 的'唯一命中不限距离'粗粒度兜底——两算法互补，",
        "  若训后行号指标仍不及预期，v2.12 可做两算法的并集重跑。",
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines[:10]))
    print(f"\n输出: {OUT}")


if __name__ == "__main__":
    main()
