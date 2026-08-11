# 蒸馏 v2 SOP

> 落地 `docs/方法论_新蒸馏方法论.md` 的 7 类 11500 条蒸馏数据。
> 本机负责 DeepSeek 5 类 + Kimi K3 2 类 = **9700 条**；GLM 1800 条由另一台机器处理。

## 目录结构

```
scripts/distill_v2/
├── config.py              # API key / base_url / model / 并发 / 路径
├── task_specs.py          # 7 个 pack 任务规格（CWE×语言×正负×难度×数量）
├── prompts/
│   ├── deepseek.py        # DeepSeek 系统提示词 + 5 类 user 模板
│   └── kimi.py            # K3 系统提示词 + 2 类 user 模板（含压扁约束）
├── run_distill.py         # 主调度：并发调 API + 断点续传 + 重试
├── validate_sample.py     # 三段式解析 + JSON schema + CoT≤5步 + 行号锚定校验
├── merge_to_chatml.py     # 合并 7 个 pack → train_chatml_v9max.jsonl
└── README.md              # 本文件

data/distill_v2/           # 蒸馏产物（自动创建）
├── deepseek_cc_memory.jsonl     # 1000
├── deepseek_pentest.jsonl       # 1800
├── deepseek_web.jsonl           # 2500
├── deepseek_shell.jsonl         # 1200
├── deepseek_fix.jsonl           # 1200
├── kimi_cc_memory.jsonl         # 800
├── kimi_cross_file.jsonl        # 1200
├── _progress/                   # 断点续传 + 失败记录
│   └── {pack_id}_failed.jsonl
└── train_chatml_v9max.jsonl     # 最终合并产物（9700 条）
```

## 前置准备

### 1. 安装依赖

```powershell
pip install requests
```

（`requests` 是唯一外部依赖，项目已在用。）

### 2. 设置 API Key 环境变量

```powershell
# Windows PowerShell（当前会话）
$env:DEEPSEEK_API_KEY = "sk-xxx"
$env:MOONSHOT_API_KEY = "sk-yyy"

# 永久设置（推荐）
[Environment]::SetEnvironmentVariable("DEEPSEEK_API_KEY", "sk-xxx", "User")
[Environment]::SetEnvironmentVariable("MOONSHOT_API_KEY", "sk-yyy", "User")
```

```bash
# Linux/Mac
export DEEPSEEK_API_KEY=sk-xxx
export MOONSHOT_API_KEY=sk-yyy
```

API 参数详见：
- DeepSeek: [docs/prompts/deepseek_prompt.md](../../../docs/prompts/deepseek_prompt.md) 第 196-204 行
- Kimi K3: [docs/prompts/kimi_prompt.md](../../../docs/prompts/kimi_prompt.md) 第 196-206 行

## 使用流程

### Step 0. 自检任务规格

```bash
cd experiments/exp_06_finetune/scripts/distill_v2

# 列出 7 个 pack 的条数
python task_specs.py

# 或
python run_distill.py --list
```

预期输出：
```
pack_id                  model      template     vuln   safe  total
----------------------------------------------------------------------
deepseek_cc_memory       deepseek   cc_memory      250    750   1000
deepseek_pentest         deepseek   pentest        450   1350   1800
deepseek_web             deepseek   web            625   1875   2500
deepseek_shell           deepseek   shell          300    900   1200
deepseek_fix             deepseek   fix            300    900   1200
kimi_cc_memory           kimi       cc_memory      200    600    800
kimi_cross_file          kimi       cross_file     300    900   1200
----------------------------------------------------------------------
合计                                                       9700
```

### Step 1. dry-run 预览任务（不调 API）

```bash
python run_distill.py --dry-run
```

打印各 pack 前 3 条任务规格，确认 CWE/语言/难度/场景分配合理。

### Step 2. 校验提示词模板

```bash
python validate_sample.py
```

用 `kimi_prompt.md` 的压扁示例自测三段式解析 + 校验逻辑。

### Step 3. 跑蒸馏（核心步骤）

```bash
# 跑全部 7 个 pack（9700 条）
python run_distill.py

# 只跑某个 pack（推荐先小批量试跑）
python run_distill.py --pack deepseek_cc_memory

# 跑多个 pack
python run_distill.py --pack deepseek_cc_memory,kimi_cross_file

# 覆盖并发数（如 DeepSeek 限速就调小）
python run_distill.py --pack deepseek_web --workers 4
```

**特性：**
- **断点续传**：中断后重跑自动跳过已完成的 task_id，不重花 token
- **失败重试**：三段式校验失败自动重试 2 次（重新调 API），仍失败记录到 `_progress/{pack_id}_failed.jsonl`
- **追加写入**：每条成功即落盘，中途崩溃不丢数据
- **K3 思考链**：只取 `message.content`，不取 `reasoning_content`（思考链不计入训练）

### Step 4. 合并产物

```bash
# 只合并蒸馏 v2 数据（9700 条）
python merge_to_chatml.py

# 合并 v9_augmented（914 条）+ 蒸馏 v2（9700 条）= 10614 条
python merge_to_chatml.py --with-v9 --stats
```

输出：`data/distill_v2/train_chatml_v9max.jsonl`

### Step 5. 泄漏审计（训练前必做）

```bash
python experiments/exp_06_finetune/scripts/audit_leakage_precise.py \
  --train train_chatml_v9max.jsonl
```

## 关键设计

### 1. 负样本 1:3 配比

在 `task_specs.py` 的 `generate_tasks()` 层强制：每个 pack 前 `vuln_count` 条 `has_vuln=True`，后 `safe_count` 条 `has_vuln=False`。不让模型自己决定正负，保证配比。

### 2. K3 长链压扁

K3 原生推理链动辄 2900 token，8B 学不会。压扁方式：**Prompt 强约束**（[kimi_prompt.md:17-32](../../../docs/prompts/kimi_prompt.md) 第 17-32 行）：
- system prompt 明确要求"≤5 步、≤590 token、每步锚行号"
- 给出错误 vs 正确的压扁示例
- `validate_sample.py` 兜底校验 CoT 步数 ≤5

### 3. 三段式统一格式

所有样本统一为：`[代码片段] → [≤5步推理] → [JSON结论]`，JSON schema 9 字段统一（has_vulnerability / vulnerability_type / risk_level / cvss_vector / cvss_score / source / sink / explanation / fix_suggestion）。

### 4. 维度均匀覆盖

每个 pack 的 CWE/语言/难度/场景用 `itertools.cycle` 轮询，避免模型重复生成同质样本。

## 常见问题

### Q: 中断了怎么办？
A: 直接重跑 `python run_distill.py --pack {pack_id}`，自动跳过已完成的 task_id。

### Q: 失败太多怎么办？
A: 查看 `data/distill_v2/_progress/{pack_id}_failed.jsonl`，看 error 字段。常见原因：
- API 限速 → 调小 `--workers`
- K3 返回空 content → 检查 API key 和余额
- 校验失败（CoT >5 步 / JSON 缺字段）→ 模型输出不规范，重试通常能解决

### Q: 想改某个 pack 的条数或 CWE？
A: 编辑 `task_specs.py` 对应的 `PackDef`，重跑即可。已完成的样本不会重跑。

### Q: 费用估算？
A: **DeepSeek 7700 条**：V4-Flash 输出约 ¥8/M token，7700 条 × 输出 ~800 token ≈ ¥50，很便宜。

   **K3 2000 条是大头**：思考模式始终开启，`reasoning_content` 思考链也计费（训练不用但要付钱）。
   K3 输出 ¥100/M token，思考链每条 2000~8000 token（任务复杂度决定），三档估算：

   | 档位 | 思考链/条 | 2000 条合计 |
   |---|---|---|
   | 乐观 | 2000 token | ~¥570 |
   | 中位 | 4000 token | ~¥970 |
   | 保守 | 8000 token | ~¥1770 |

   **建议先充 ¥500 跑 100 条实测**，到 Moonshot 后台看真实 token 消耗，乘 20 外推 2000 条。
   若实测 >¥1500，考虑砍 K3 跨文件量（让 DeepSeek 代劳）或查 API 是否支持 `reasoning_effort: low`。
