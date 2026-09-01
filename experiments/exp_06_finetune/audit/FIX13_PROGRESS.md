# 1.3 修复进度状态（供恢复上下文用，2026-08-31）

## 流水线状态
- 工作台：`agent_audit_v2_14/out/fix13_workbench.jsonl`（234 条，含 id/batch/证据/代码/教师JSON/v15_line）
- Pass1 行号重锚：`out/fix13_ops_pass1.jsonl`（86 reline + 36 manual）✅ 已抽验
- Pass2 CWE 改标：`out/fix13_ops_pass2.jsonl`（10 set_vt）✅
- Pass3 叙事重写：`out/fix13_ops_pass3_b07.json` ~ `b12.json` 已完成；**继续按 `fix13_ops_pass3_bNN.json` 编号写下去**
- 关键源数据：`data/final_train_chatml_alpha06_v2_15.jsonl`（9947 行，wave1 产物，ops 应用目标）

## op schema（应用脚本按此实现，尚未写）
- {"id", "op": "set_fields", "fields": {字段: 新值}} —— 整体替换 JSON 字段
- {"id", "op": "set_vt", "value"} —— vulnerability_type 快捷
- {"id", "op": "reline", "field", "moves": [[old,new],...]} —— 对字段文本做 "line N:"/"第N行"/"L N" 行号替换；
  **同一 op 内 moves 若有碰撞（如 [[16,21],[21,16]]）必须两阶段替换（先→占位符再回填）**
- {"id", "op": "append_field", "field", "text"} —— 字段末尾追加（中文句号衔接）
- {"id", "op": "nojson_op", "why"} / {"id", "op": "needs_human", "why"} —— 不改数据
- 应用规则：同一 (id, field) 上 evidence 类 reline **覆盖** pass1 的 identifier 类；set_fields 覆盖一切
- 应用目标：v2_15 按行定位（workbench.v15_line），解析最后 ```json 块 → 改字段 → json.dumps(ensure_ascii=False) 单行回填
- 应用后必须：字节级抽验、S3 式锚点复扫（reline 后的锚应命中）、S4 复扫（不得引入新污染）、写日志

## 裁决口径（已定，勿反复）
- 方案 §1.3 范围 = JSON 七字段；正文（analysis body）行号/叙事问题一律留 2.1/1.4，nojson_op 记录
- 反转 safe 时：has_vulnerability=false, vulnerability_type="none", risk_level="None", source/sink="N/A"
- CWE 规范名从 `out/cwe_canonical_names.json` 取；库外新标签用 MITRE 官方名（如 CWE-682 Incorrect Calculation）
- 2559 needs_human（IDOR 依赖片段外鉴权上下文）

## 关键已完成 op 批次
- b07: 270/2543/2461（含 270 两条 reline）
- b08: 3142/2559 nojson+human、1210/1011 反转改写
- b09: 1256 sink reline、7850 nojson、2382 重写
- b10: 642/2488/621（R1 向量修正 + 918→78 改标 + 重锚）
- b11: 2923/986/1732/1248/1141/1190/1153
- b12: 8182/612/9/7521/1552 reline、8243/7809/7868 nojson

## 剩余
- majors 剩 ~139（下批从 rem[24:] 开始，工作台顺序）
- minors 39 条未动
- 全部 ops 应用 + 复验 + 执行记录更新 + UNSURE 19 条人工材料
