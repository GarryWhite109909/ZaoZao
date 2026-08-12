# 方法论：工具召回 + LLM 裁决的两阶段漏洞检测架构

> 本文档描述下一阶段的核心架构升级：将现有"LLM 为主、工具为辅"的固定管道，反转为"静态工具做召回、LLM 做裁决"的两阶段架构。与 `docs/方法.md`（训练路线）互补，本文档聚焦**推理侧编排**。
>
> 版本：v1.0（2026-08-07）　状态：方案已评审，待实施

---

## 一、动机：现有管道的三个结构性问题

现有编排（Prefilter → Slicer → LLM → 约束解码兜底）是合理的工程漏斗，但在评审中暴露出三个仅靠调参无法解决的结构性问题：

### 1.1 角色错位：LLM 在干工具的活，工具在替 LLM 做决定

- **Prefilter 短路即终判**：正则命中后直接返回，不给 LLM 复核。正则无语义理解能力，对"受信任数据源上的 `pickle.loads`"这类场景必然误报，而短路机制剥夺了纠偏机会。
- **LLM 被迫"大海捞针"**：每个文件都全量过 LLM，要求模型在无任何候选线索的情况下发现漏洞。这是静态工具更擅长的任务（确定、便宜、无幻觉），却压给了最贵、最不确定的组件。

### 1.2 经济学不成立

在本地单卡（Ollama）部署约束下，每个文件都过 LLM 意味着吞吐被推理延迟钉死。而经验分布上，**80–90% 的文件没有任何可疑特征**——对它们调用 LLM 是纯浪费。

### 1.3 置信度缺失

`has_vulnerability: bool` 是裸判定，没有不确定性的表达。LLM 自报的 confidence 分数不可信（ calibration 差，论文评审必被攻击），需要统计上站得住的置信度代理。

---

## 二、核心设计：两阶段反转架构

### 2.1 架构总览

```text
                ┌─────────────────────────────┐
                │   输入：代码文件 / 项目      │
                └──────────────┬──────────────┘
                               ▼
        ┌──────────────────────────────────────────┐
        │  Stage 1：静态工具层（并行，近零成本）      │
        │  Semgrep(taint) · TaintTracker ·          │
        │  Prefilter · pip-audit(SCA)               │
        └──────────────────┬───────────────────────┘
                           ▼
                  ┌────────────────┐
                  │ 有候选 finding？ │
                  └───┬────────┬───┘
              无 ─────┘        └───── 有
             （多数文件）            （少数文件）
               ▼                      ▼
   ┌────────────────────┐   ┌──────────────────────────┐
   │ 直接判安全           │   │ Stage 2：LLM 裁决层        │
   │ + 5–10% 抽样复核     │   │ 逐 finding 判定真伪        │
   │ （防工具层漏报漂移）  │   │ 上下文：切片 + RAG + 污点   │
   └─────────┬──────────┘   │ N 次采样 → 自一致性置信度    │
             │              └─────────────┬──────────────┘
             └──────────────┬─────────────┘
                            ▼
              ┌──────────────────────────────┐
              │ 结构化报告（SARIF）             │
              │ verdict + 置信度 + 证据链 + 修复 │
              └──────────────────────────────┘
```

### 2.2 关键反转：从"工具注入 prompt"到"工具生成候选、LLM 判真伪"

| 维度 | 旧架构（工具辅助 LLM） | 新架构（工具召回 + LLM 裁决） |
| --- | --- | --- |
| LLM 的任务 | 在全文中**发现**漏洞（开放生成） | 对具体 finding 判定**真伪**（封闭判别） |
| 工具的角色 | 结果注入 prompt，LLM 可忽略 | 产出候选集合，决定 LLM 是否介入 |
| 短路逻辑 | 工具高置信 → 跳过 LLM（误报不可纠） | 工具高置信 → 仍过 LLM 裁决（可纠偏） |
| LLM 调用量 | 每文件 ≥1 次 | 仅 10–20% 有候选的文件 |
| 任务难度 | 高（漏报、幻觉双高） | 低（带证据的二分类） |

**为什么判别比生成可靠**：发现漏洞要求模型在指数级的"代码×漏洞模式"空间中搜索；裁决 finding 只需验证一条具体的 source→sink 证据链是否成立。后者的错误率在经验上低一个数量级，且每条判定都有工具证据做锚点，幻觉空间被大幅压缩。

---

## 三、各层详细设计

### 3.1 Stage 1：静态工具层

四类工具并行执行，产出统一的候选 finding 列表：

| 工具 | 职责 | 产出 | 裁决方式 |
| --- | --- | --- | --- |
| **Semgrep（taint mode）** | 单文件内跨函数 source→sink 追踪 | 带完整污点路径的 finding | 裁决档 |
| **TaintTracker（自研）** | AST 级轻量污点分析（Semgrep 的补充与交叉验证） | source→sink 路径 | 裁决档 |
| **Prefilter** | 高置信特征命中 | 粗粒度候选（不短路，只产候选） | 裁决档 |
| **Bandit / Semgrep 规则** | Python SAST / 多语言 SAST | 位置型 finding（文件+行+规则） | 裁决档（误报率高，真伪难辨） |
| **Gitleaks / detect-secrets** | 硬编码密钥检测 | 密钥 finding | 直出档 |
| **Trivy fs / pip-audit** | SCA 依赖漏洞 | 依赖漏洞 finding | 直出档 |
| **Trivy config** | IaC 配置扫描 | 配置 finding | 裁决档 |

**分档原则**：按"LLM 裁决增益"划分——密钥与依赖漏洞由确定性工具自判即可（数据库判定/高精度规则），召回即作为已确认 finding 直出，不消耗 LLM 采样；污点流、SAST、IaC 类误报率高、真伪依赖语义理解，进入 Stage 2 裁决。这一原则与全系统的哲学一致：**确定性工具能确定的，就别让 LLM 猜**。

**Semgrep taint mode 顺带修复跨 chunk 割裂**：现有缺陷是长文件切片后 chunk A 的 source 与 chunk B 的 sink 被割裂。正确解法不是缝合 chunk，而是**对原始整文件跑一次 Semgrep taint**，将找到的完整污点路径注入对应 chunk 的裁决上下文。OSS 版 Semgrep 的 taint mode 支持单文件内跨函数追踪，无需付费的 Pro interfile 分析。

示例规则：

```yaml
rules:
  - id: python-sqli-taint
    mode: taint
    pattern-sources:
      - pattern: request.GET.get(...)
      - pattern: input(...)
    pattern-sinks:
      - pattern: cursor.execute(...)
    message: "用户输入流入 SQL 执行"
    languages: [python]
```

### 3.2 Stage 2：LLM 裁决层

对每个候选 finding，构造裁决请求：

```json
{
  "task": "triage",
  "finding": {
    "rule": "python-sqli-taint",
    "source": "request.GET.get('uid')",
    "sink": "cursor.execute(query)",
    "path": ["views.py:12", "db.py:34"]
  },
  "code_context": "<切片后的相关函数 + 上下文头>",
  "rag_context": "<CWE-89 安全模式知识>"
}
```

模型输出结构化 verdict：

```json
{
  "is_true_positive": true,
  "confidence_votes": "4/5",
  "reasoning": "uid 未经参数化直接拼入 query，path 完整可达",
  "fix_suggestion": "使用参数化查询 cursor.execute(sql, (uid,))"
}
```

### 3.3 置信度：N 次采样自一致率

弃用 LLM 自报 confidence，改用**自一致率**（self-consistency）作为置信度代理：

- 对同一 finding 以 temperature > 0 采样 N=5 次；
- 置信度 = 判真票数 / N（如 4/5 = 0.8）；
- 低置信（如 2/5、3/5）的 finding 标记为"需人工复核"，不计入自动结论。

统计依据：自一致率是多数表决的软化，与 `multi_model_scanner` 已有多数表决机制同构，基础设施可直接复用——只需把"表决结果"改为"表决比例"输出。

### 3.4 无候选兜底：抽样复核 + 全量复核双模式

"无候选直接判安全"引入工具层漏报风险（工具召回是封闭集合，漏洞是开放集合——"没召回"是 absence-of-evidence，不能当作"安全"的证明）。缓解措施分两档：

- **抽样复核（默认）**：对放行文件做 **10% 随机 LLM 复核**（`VULN_SCANNER_RECHECK_RATE` 可调），持续监控工具层召回率漂移（`tool_recall_monitor` 在线估计漏报率）。复核发现的漏报案例回流为新的 Semgrep 规则/测试样本，形成闭环。
- **全量复核（full_recheck）**：URL / GitHub 等安全关键入口对每个无候选文件都跑一次全量 LLM 复核（`no_candidate_mode="full_recheck"`），彻底消除"无证据判安全"的静默放行；复核判安全才采信，复核发现漏洞则转人工复核。

### 3.5 结构化输出：SARIF

最终报告采用 SARIF 2.1.0 标准格式：

- 与 GitHub Code Scanning、VSCode Problems 面板原生互通；
- finding 携带 ruleId、level（由置信度映射：≥0.8 error，0.5–0.8 warning，<0.5 note）、evidence 链；
- 前端插件可直接消费，替换现有自定义 JSON 渲染。

---

## 四、评估方法

### 4.1 前置条件：基准修复（本次已完成）

新架构的任何指标只有在修复后的基准上才有意义。本轮已修复并**必须重跑**（详见 `experiments/REGRUN_AFTER_FIX.md`）：

- 文件名泄漏移除（exp_01/04/05/06 prompt 均变化，历史指标不可比）；
- exp_04 标注为非独立 held-out（曾被 hard sample mining 使用）；
- CVE-fix 测试集标注"全正样本"局限，仅引用 recall；
- 新增严格口径指标（parse_fail 计入漏报/错误），论文主结论优先引用。

### 4.2 公开基准补充

自制样本集之外，引入公开基准以增强外部效度：

| 基准 | 语言 | 用途 |
| --- | --- | --- |
| OWASP Benchmark | Java | 标准化 SAST 对比，含工具评分卡 |
| Juliet Test Suite | 多语言 | 系统化 CWE 覆盖 |
| PrimeVul / SVEN | C/Python | 真实漏洞，近年论文标准基准 |

### 4.3 核心对比实验设计

新架构的论文主实验：

1. **旧管道 vs 新架构**（同模型、同基准）：对比 recall / FPR / 吞吐（文件/分钟）；
2. **裁决层消融**：工具直连输出（无 LLM 裁决）vs 完整两阶段——量化 LLM 裁决的误报抑制收益；
3. **置信度校准**：自一致率与人工标注一致性的相关性分析；
4. **抽样复核有效性**：复核子集上工具层漏报率的估计。

预期假设（待验证）：工具层 recall 高但 FPR 高（如 40%），LLM 裁决将 FPR 压至 <10%，同时吞吐较全量 LLM 提升 5 倍以上。

---

## 五、实施路线

| 阶段 | 内容 | 预估 |
| --- | --- | --- |
| **P0（前置）** | 后端确定性 bug 修复 + 实验基准修复 + 重跑 | 已完成修复，重跑待 GPU 环境 |
| **P1** | Semgrep taint mode 整文件扫描接入；裁决层改造（finding→triage prompt→verdict）；自一致性采样 | 1–2 周 |
| **P2** | pip-audit/detect-secrets 集成进 ExternalScanner；SARIF 输出；抽样复核机制 | 1 周 |
| **P3（可选）** | 有界 tool-routing（固定工具集、≤2 轮、温度 0 的"LLM 选择工具"）；修复-验证闭环 demo（fix_suggestion → fix_verifier → 重扫确认） | 1 周 |

**明确不做**：

- **Joern**：与 tree-sitter + 自研 TaintTracker 能力重叠，JVM 生态接入成本高；
- **CodeQL 全语言**：仅在有富余时做 Python + 默认查询套件，findings 进裁决层；
- **DSPy**：exp_05 prompt 消融已完成，换框架等于推翻已有实验；
- **全自主 ReAct Agent**：破坏可复现性，降级为有界 tool-routing 写进展望。

---

## 六、风险与局限

1. **工具层召回是天花板**：两阶段架构的 recall 上限由 Stage 1 决定。抽样复核只能估计漏报率，不能根治。需在论文中明确讨论此局限。
2. **裁决延迟集中在少数文件**：有候选的文件需 N 次采样，单文件延迟上升；批量场景可通过 vLLM continuous batching 摊薄。
3. **Semgrep taint 规则覆盖度**：需要为各语言/ CWE 编写 taint 规则，初期覆盖可能不全——这正是抽样复核存在的意义。
4. **自一致率 ≠ 校准概率**：自一致率度量的是输出稳定性而非真实正确率，论文表述需精确（"一致性置信度"而非"正确概率"）。

---

## 七、与既有路线的关系

本文档不改变 `docs/方法.md` 的训练路线（QLoRA SFT / DPO），两者正交：

- **训练路线**提升的是单点判定能力（模型本身准不准）；
- **本架构**提升的是系统级效能（算力怎么分配、误报怎么抑制、置信度怎么表达）。

微调后的模型（v5/v9max）直接作为裁决层的判定器使用，训练与推理的系统 prompt 一致性约定（`model_registry`）继续生效。
