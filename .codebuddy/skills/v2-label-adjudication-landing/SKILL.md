---
name: v2-label-adjudication-landing
description:
  把已裁定的标签终裁/翻案/改类/映射修复批量落入 v2_* 数据集与审计侧映射，走项目 apply_* 惯例
  （快照→内容锚断言→引文对码→替换→changelog→自检）并出闭环报告。This skill should be used
  when the user says "落库"、"一键 apply"、"执行决策卡"、"翻案落库"、"改标落库"、"映射机械修复"、
  "终裁执行"，or hands over a decision-card row list (行号 + 新旧标签) to be written into the dataset.
agent_created: true
---

# v2 数据集标签终裁落库

把"已裁定但未落库"的标签决策批量写入 `data/final_train_chatml_alpha06_v2_*.jsonl`，
并配套修复 `audit/cwe_offline/` 侧的 CVE→行映射。适用场景：决策卡/裁决卡已备齐、
用户拍板后的一键执行。

## 0. 先决条件（缺一不可）

- 用户**明确拍板**。改标是不可逆的破坏性动作；未拍板只出脚本，不写盘。
- 决策卡已列明：行号（注明版本！）、旧标签、新标签、依据。缺 CWE 选型或口径冲突要当场问清。
- 先跑 `--dry-run` 看断言是否全通，再跑正式执行。

## 1. 骨架：一个 apply 脚本 + 一个 verify 脚本

参考实现（可直接抄改）：
- `experiments/exp_06_finetune/audit/apply_final_adjudication_20260910.py`（数据集侧）
- `experiments/exp_06_finetune/audit/fix_cve_row_mapping_20260910.py`（映射侧）
- `experiments/exp_06_finetune/audit/verify_final_adjudication_20260910.py`（闭环验证）

脚本结构（`--dry-run` 用 `sys.argv` 判断，dry-run 时 `sys.exit(0)` 于写盘之前）：

```python
ROWS.append(dict(
    line=LN,                     # v2_17 行号
    old=(True, "CWE-120"),       # 旧结论断言
    anchor="copy_at_offset",     # 用户消息内容指纹（确认改的是正确行）
    quotes=[...],                # 必须逐字出现在代码块内的引文（C4 门）
    forbid=["filterEncode"],     # 互斥标记（该行绝不该出现的串）
    analysis="分析过程：...",     # 新叙事（含"非 CWE-XXX"辨析锚句）
    verdict=dict(has_vulnerability=..., vulnerability_type=..., risk_level=...,
                 source=..., sink=..., explanation=..., fix_suggestion=...),
))
```

执行链（顺序不可乱）：
1. 用户内容指纹断言（`anchor in 行 JSON`）
2. 引文对码断言（每条 `q in code_block`；`forbid` 反向断言）
3. 旧结论断言（`verdict(assistant) == spec["old"]`）
4. 生成新 assistant：`analysis + "\n\n```json\n" + json.dumps(v, ensure_ascii=False) + "\n```\n"`
5. 快照备份 → 写盘 → 追加 changelog → 重读自检（行数不变 / 新结论落位 / 7 键契约 / 含"非 CWE"）

## 2. 硬性约定（踩过的坑，逐条都是实测）

1. **叙事行号 = 代码块内 1-based**（对齐 `audit/a7_lineno.py` 的 `code_lines()`）
   —— 即 ``` 围栏内第一行算第 1 行。旧叙事普遍漂移，重写段落必须重锚，否则 a7/a8 审计报警。
2. **JSON 契约 7 键、键序固定**：`has_vulnerability, vulnerability_type, risk_level,
   source, sink, explanation, fix_suggestion`。safe 行填 `vulnerability_type="none"`、
   `risk_level="None"`、`source/sink="N/A"`、`fix_suggestion="no fix needed（可选加固：…）"`。
3. **每行分析过程必须含字面「非 CWE」**（C6 机检），形式：`非 CWE-XXX 因为…`。
4. **备份命名用 `snapshot_*`，禁用 `bak_*`**（无敏感词命名规矩）。
5. **changelog 每条含**：`date, step, action(FLIP/RECLASS/NARRATIVE), row_line,
   old_verdict, new_verdict, note, basis, label_basis(nvd|audit|teacher_retake)`。
6. **同文件多处修改必须串行**；同一脚本内一次性生成全部行，不要开两个脚本并行写同一文件。

## 3. 审计侧映射修复的专属陷阱

`audit/cwe_offline/nvd_cwe_check_full_20260908.jsonl`：

- **行号基准是 v2_16（10151 行），不是 v2_17**。决策卡里的映射行号常是 v17 口径 ——
  引用前必须先翻译，否则改错绑定。翻译表见
  `audit/cwe_offline/nvd_cve_row_map_v16_to_v17_20260910.json`（内容 sha1 唯一匹配；
  user 内容被改写或已删除的行置 null）。**彻底解法是对当前版本重跑 `nvd_check_full_20260908.py`**。
- 条目 schema：`{"cve", "samples":[{"line","kind","assistant_labels"}], "nvd_cwes", "error"}`。
- `assistant_labels` 口径 = "全文 CWE 出现集合"（会被叙事里的邻类辨析句污染）。
  解绑/改绑前用内容指纹断言；**新增改绑条目的 labels 取现行版本（v17）**，
  否则会把"已按 NVD 改判过"的行记成假冲突。
- 越界引用（行号 > 该版本行数）要一并清除（实测存在 10153/10155 两条）。
- 改绑依据优先用**样本内自带 CVE 注释**（行级自证），比外部推理可靠。

## 4. CWE 口径判据（2026-09-10 订正，务必沿用）

- CWE 的"官方"分两层：**MITRE 定义 = 语义权威**；**NVD 绑定 = 分析员判定，有噪声/弃用伞类**。
- 项目判据：**MITRE 机制类精确子类 > NVD 绑定**。L1 §A 已按此 KEEP 11 条
  （POODLE 的 NVD 310 弃用伞类、Struts2 的 NVD 74 旧映射噪声、CVE-2017-18349 绑 20 而 502 为正解）。
- 实证：CVE-2023-33201 的 NVD 记录 **CWE 字段写 CWE-295，描述原文却写 "LDAP injection"** ——
  NVD 自身不自洽。此类分歧的实质是"机制类 vs 上下文/后果类"。
- 处置模板：**取机制类为主判（top-1），在 `explanation` 里显式记录 NVD 分歧**，
  这样"与 NVD 一致率"指标仍可另算。别用"库内口径"当理由（那是从众），要用"MITRE 机制类语义"。
- 客户/用户原则若坚持 NVD 绑定即真理，先指出这与项目既有 11 条 KEEP 判例自相矛盾，再让其拍板。

## 5. 收尾

- 出执行记录 md（变更清单表 + 行号口径说明 + 自检 + 哈希链），追加到 `v2_*_known_issues_*.md`。
- 记录 **sha256 链**（发布 → 各治理波次 → 本次），行数必须恒定。
- 闭环指标：用同一判据重算审计侧"标签-NVD 无交集"冲突数（CVE 数 / 行级），给修复前后对比。
- 更新 `.workbuddy/memory/YYYY-MM-DD.md`；口径类结论同时进 `.workbuddy/memory/MEMORY.md`。
- 不要覆盖 `build_v2_*_sha256.txt`（它记录发布时状态）；新哈希写进执行记录。
