#!/usr/bin/env python3
"""alpha06-v2.12 构建：v2.11（已清毒）+ 两波专项新数据。

背景（2026-08-28）：
- v2.11（8752 条）= v2.10 + 剔除 7 条残留毒样本，行号吸附成果完整保留。
- 新专项：
  1. crossfile_safe_pairs.jsonl（128 条，kind=variant_crossfile_safe）：
     对库中 99 个"只有漏洞侧缺安全侧"的跨文件项目，配套安全版多文件代码 +
     安全分析 + has_vulnerability=false 否定结论，补"防御有效性判断"跨文件盲区。
  2. blindspot_teaching_wave.jsonl（104 条，kind=blindspot_vuln/safe，52+52）：
     6 个盲点族的教学数据，每族完整覆盖（CWE-311/942/400/1427/200/209）。

并入原则：
- 基底用 v2.11（已清毒），逐条追加新数据。
- 新数据彼此 user 全文指纹零重复（生成时已 uid 去重）；与旧库 task_key 重叠属
  预期"同项目成败两版"对照（实例变、结构同），并非冲突，须保留。
- 不重跑行号吸附：新数据为教师直接产出，与既有吸附算法口径不适用，保持原样。
- 全量断言门：格式合法、vulnerability JSON 可解析、新 kind 计数精确、总条数=8752+232。

终验：新 kind 计数、总条数、user 全文指纹全库唯一计数。
"""
import json
import re
from collections import Counter
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SRC = BASE / "data/final_train_chatml_alpha06_v2_11.jsonl"
CROSS = BASE / "corpus/crossfile_safe_pairs.jsonl"
BLIND = BASE / "corpus/blindspot_teaching_wave.jsonl"
OUT = BASE / "data/final_train_chatml_alpha06_v2_12.jsonl"
REPORT = BASE / "data/build_alpha06_v2_12_report.md"

# 各 new-kind 期望条数
EXPECT = {"variant_crossfile_safe": 128, "blindspot_vuln": 52, "blindspot_safe": 52}


def user_content(r):
    return r["messages"][1]["content"]


def check_format(r):
    """三段消息 + 合法 kind + assistant 含可解析 json 结论。返回 err 或 None。"""
    msgs = r.get("messages")
    if not isinstance(msgs, list) or len(msgs) != 3:
        return "消息非三段"
    roles = [m.get("role") for m in msgs]
    if roles != ["system", "user", "assistant"]:
        return f"角色序列异常: {roles}"
    if not all(isinstance(m.get("content"), str) and m["content"] for m in msgs):
        return "存在空 content"
    meta = r.get("meta") or {}
    if not meta.get("kind"):
        return "meta 缺 kind"
    a = msgs[2]["content"]
    m = re.search(r"```json\s*(\{.*?\})\s*```", a, re.S)
    if not m:
        return "assistant 缺 json 结论块"
    try:
        json.loads(m.group(1))
    except json.JSONDecodeError as e:
        return f"json 解析失败: {e}"
    return None


def main():
    base_rows = [json.loads(l) for l in SRC.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(base_rows) == 8752, f"v2.11 基底条数异常: {len(base_rows)}"

    new_rows = []
    for path in (CROSS, BLIND):
        for l in path.read_text(encoding="utf-8").splitlines():
            if l.strip():
                new_rows.append(json.loads(l))
    assert len(new_rows) == 232, f"新数据待并入 {len(new_rows)} != 232"

    # 格式门
    errors = [(r.get("meta", {}).get("task_key", "?"), check_format(r))
              for r in new_rows]
    bad = [e for e in errors if e[1]]
    assert not bad, f"格式不合法 {len(bad)} 条: {bad[:3]}"

    # kind 计数门
    new_kind = Counter((r.get("meta") or {}).get("kind") for r in new_rows)
    for k, n in EXPECT.items():
        assert new_kind.get(k) == n, f"kind {k} 计数 {new_kind.get(k)} != {n}"
    assert sum(new_kind.values()) == len(new_rows)

    # 新数据内部 user 指纹唯一
    seen = {}
    for r in new_rows:
        u = user_content(r)
        if u in seen:
            raise SystemExit(f"新数据内部 user 重复: {u[:50]}")
        seen[u] = 1

    # 并入
    out_rows = base_rows + new_rows

    # 终验：总条数 + 全库 user 唯一计数
    all_user = [user_content(r) for r in out_rows]
    assert len(all_user) == 8752 + 232, f"并入后条数异常: {len(all_user)}"
    assert len(set(all_user)) == len(all_user), "并入后存在 user 全文重复"

    with open(OUT, "w", encoding="utf-8") as f:
        for r in out_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # 报告
    full_kind = Counter((r.get("meta") or {}).get("kind", "none") for r in out_rows)
    lines = [
        "# alpha06-v2.12 构建报告",
        "",
        f"- 基底：v2.11（{len(base_rows)} 条，已清毒）→ 输出 **{len(out_rows)} 条**",
        f"- 并入新数据 {len(new_rows)} 条，全部通过格式/计数/指纹断言：",
        f"  - variant_crossfile_safe（跨文件安全对照补盲）：{new_kind.get('variant_crossfile_safe')} 条",
        f"  - blindspot_vuln（盲点族漏洞侧）：{new_kind.get('blindspot_vuln')} 条",
        f"  - blindspot_safe（盲点族安全侧）：{new_kind.get('blindspot_safe')} 条",
        "- 兼容性说明：新数据与旧库 task_key 重叠 99 个属『同项目成败两版』对照，",
        "  预防防御有效性判断 FP 的训练信号，按设计保留，不做去重。",
        "- 新数据不重跑行号吸附（教师直接产出，吸附口径不适用），原样并入。",
        "",
        "## 全库 kind 分布",
        "",
        "| kind | 条数 |",
        "|------|------|",
    ]
    for k, c in sorted(full_kind.items()):
        lines.append(f"| {k} | {c} |")
    lines.append("")
    lines.append("## 断言门")
    lines.append("- [x] 新数据 232 条格式合法（三段消息 + json 结论可解析）")
    lines.append("- [x] 新 kind 计数精确（128/52/52）")
    lines.append("- [x] 新数据内部 user 全文指纹零重复")
    lines.append(f"- [x] 并入后 {len(out_rows)} 条，全库 user 全文指纹无重复")
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print(f"v2.12 构建完成：{len(out_rows)} 条 -> {OUT.name}")
    print(f"报告：{REPORT}")


if __name__ == "__main__":
    main()