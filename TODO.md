# 项目待优化问题清单

> 记录代码审查中发现的项目结构、代码质量、工程化问题。处理完一项勾选一项。
>
> **训练流程进度见 [规划.md](规划.md)；本文件仅保留工程化层面的当前待办。**
> 历史已处理项见 [docs/_archive/TODO_archive_202607.md](docs/_archive/TODO_archive_202607.md)。

---

## ✅ 已处理

- [x] README.md 开头优化：结果卡片、当前状态、待决策事项前置
- [x] docs/论文/大纲.md 状态表与写作进度同步
- [x] 历史 TODO 项归档至 `docs/_archive/TODO_archive_202607.md`
- [x] 为 exp_01~05 报告添加"一句话结论"卡片（含关键指标、核心发现、论文对应章节）
- [x] 创建 exp_06_finetune/exp_06_report.md 作为训练主线汇总报告
- [x] 生成 SFT v2~v6 训练趋势图并插入 README.md 与 docs/论文/第5章_训练主线.md
- [x] 统一术语与日期格式检查：修复规划.md CWE 40→42 表述，确认 HuggingFace ID 大写为合理用法
- [x] exp_01 结果文件按时间戳命名：`results.json` → `results.qwen2.5-coder-7b.20260630.json`，同步更新 exp_01_report.md 与 README.md 引用
- [x] 依赖声明补全：`requirements.txt` 与 `pyproject.toml` 补充 `pydantic` 与 `tree-sitter` 系列语言包
- [x] 一键部署脚本增强：`start_windows.bat` / `start_linux_macos.sh` 首次运行检测 Web 层 + 分析引擎层 + tree-sitter 语言包
- [x] README.md 工程化状态刷新：将 6.5/6.6 从"待启动"改为"已落地"，补充 `app/` 目录结构
- [x] 仪表盘（index.html）接入后端真实数据（`/api/stats`，2026-08-08 核实）
- [x] 扫描工作台（scan.html）报告下载入口：`/api/report` 与 `/api/report/single` 均已接入（2026-08-08 核实）
- [x] 安全态势页（posture.html）接入后端 `/api/stats`：后端优先、localStorage 回退（2026-08-08 完成）；CWE 样本库确认为静态内容，无需后端 API
- [x] 前后端路径对齐重构：`SingleResult`/`BatchResult` 下沉到核心层 `graduation_project/result_types.py`（`scanner.py` 复用同一数据源）；`multi_model_scanner.py` 迁移到业务服务层 `app/backend/services/`（消除核心层对 app 层的反向依赖）；`scan.html` 粘贴模式接入两阶段扫描入口 `/api/analyze/two-stage`

---

## 🔄 当前待办

> 训练/数据战役的待办入口已移至 `experiments/exp_06_finetune/audit/`（2026-10-09 起）：
> 执行总单见 **`WE并案工作总单_20261009.md`**，冻结蓝图见 **`α07数据配方与验收设计_20261009.md`**。
> 本文件只保留工程化/产品侧待办。

- [ ] **判定 D 落地**：fix 契约放宽（2026-10-09 拍板）——`graduation_project/prompts.py`
  ANALYSIS_FMT / build_triage_prompt 的 fix_suggestion 字段说明改为"1~2 句方向性建议"；
  `app/backend/static/scan.html` 等前端 fix 卡片渲染同步（不再假设单行/无代码）；
  rescan p1_7 口径同步放宽（保留"无洞非 no-fix"）
- [ ] **评测链脚本参数化**：`exp_07_two_stage_eval/run_alpha06_*.sh` 硬编码
  `/home/zane/文档/code/毕业设计` 与 HIP 设备变量——跨机（含 Windows/云端）跑红线
  回测前先把项目根路径与 `CUDA_VISIBLE_DEVICES/HIP_VISIBLE_DEVICES` 参数化
- [ ] **轨道二环境**：本机 Ollama 未装——安装后按 `exp_09_llm_anchor/设计文档_20261009.md`
  做 adapter 合模 + GGUF 转换（`alpha05-stage2-merged-Q4_K_M`，哈希入库）→ exp_09 冒烟
- [ ] 文档一致性：检查 `docs/方法.md`、`docs/过程.md` 中对工程化层的描述是否与当前实现
  一致（2026-08-08 已修正方法.md/规划.md/README/exp_06_report 的"SFT v5 当前最佳"漂移
  与 recall 口径，工程化层描述仍待核）；另：README/大纲仍称模型为 Nivis 系——10-09
  大纲故事线已换代为两阶段裁决架构叙事，README 的模型名段落待同步
- [ ] 簇审计门固化：`b_pack_leak_screen_20261009.py` 的三考卷集 Jaccard 筛查应作为
  每个新数据批次的常驻门（α07 配方 §4 已立项），考虑并入组装脚本而非独立手跑
