# 方法论：Nivis-α1 最终模型训练方案（DPO + GRPO + 数据飞轮 + CoT）

> 基座：v9max（Qwen3-8B + QLoRA SFT，格式已对齐，recall 0.95 / strict_recall 0.65）。
> 目标：在保持格式稳定的前提下，通过偏好优化与可验证奖励强化，把 strict_recall 与修复质量推上最终水平，产出论文最终模型 **Nivis-α1**。
>
> 版本：v1.0（2026-08-07）　状态：方案评审通过，待实施

---

## 一、现状基线与问题定位

| 指标 | v9max 现状 | 瓶颈归属 |
| --- | --- | --- |
| recall | 0.95 | 已接近天花板 |
| strict_recall（含 parse_fail） | 0.65 | 长/难样本推理深度不足 |
| fix_usable | 0 | **不在模型**，在 FixVerifier 判定覆盖（11 null） |
| 格式 | fix_suggestion 围栏 18/20 | 基本稳定 |

**关键判断**：strict_recall 的 35pp 缺口主要来自"被上下文迷惑"类 FN（如 0003 把 eval 合理化为安全），这类错误**靠更多 SFT 数据解决不了**——模型不是不会，是在对抗性上下文里判断漂移。这正是 DPO（偏好纠偏）与 GRPO（结果奖励）的适应症，方案方向成立。

⚠️ fix_usable=0 不要指望训练解决：瓶颈在 FixVerifier 危险模式覆盖不足，应单独立项修复（见 §七）。

---

## 二、总体路线：四件套的角色与顺序

```text
v9max (SFT 完成)
   │
   ├─(可选) CoT-SFT 增量：按《docs/方法论_新蒸馏方法论》补 1.1 万条多教师蒸馏数据
   │        仅在评估显示特定漏洞类别系统性薄弱时做
   ▼
Stage A: DPO（偏好优化，1-2 天云端）
   │   纠"判断漂移"：对错题构造 chosen/rejected 偏好对
   ▼  过评估门 G1
Stage B: GRPO（可验证奖励强化，3-5 天云端）
   │   用规则奖励直接优化 strict 指标，防 reward hacking
   ▼  过评估门 G2
Nivis-α1
   │
   ▼  数据飞轮（贯穿全程的闭环协议，见 §五）
部署 → 收集线上错题 → 教师重生成 → 回流训练 → 版本迭代（α2...）
```

**顺序不可调换**：DPO 在前是因为它能用最低成本修掉系统性误判模式，且对稳定性破坏小；GRPO 在后是因为它会放大模型的既有倾向，必须先由 DPO 把判断分布修正，否则 GRPO 会在错误的模式上加速收敛。

---

## 三、Stage A：DPO 偏好优化

### 3.1 偏好对构造（核心资产）

| 来源 | chosen | rejected | 量级目标 |
| --- | --- | --- | --- |
| 评估错题（evaluate.py 输出） | 教师修正版（正确判定 + 精炼 CoT） | 模型原始错误输出 | 800-1200 对 |
| FN 专攻（0003 类"合理化"错误） | 指出远程可控性的判定 | "视为安全"的合理化输出 | 200-300 对 |
| FP 纠偏（safe 样本误报） | 正确识别安全模式 | 过度报警输出 | 200-300 对 |
| 格式残差 | 合规围栏输出 | 偶发非合规输出 | 100 对 |

构造要点：
- **rejected 必须是模型自己的输出**（on-policy 偏好），用教师输出当 rejected 效果差；
- chosen 的 CoT 必须按《docs/方法论_新蒸馏方法论》的压缩模板（≤5 步推理），8B 学不会长推理链；
- 每对样本人工或教师双审——偏好对质量比数量重要，1500 对干净数据 > 5000 对脏数据。

### 3.2 训练配置（QLoRA-DPO，云 GPU ≥24GB）

```python
# 关键超参（基于 TRL DPOTrainer）
beta = 0.1               # KL 约束强度：判断漂移纠偏需要较小 beta，但 <0.05 会格式崩
learning_rate = 5e-6     # DPO 对 LR 极敏感，>1e-5 易出现长度坍缩
max_length = 2048        # 与 v9max 评估口径一致
max_prompt_length = 1024
lora_r = 16, lora_alpha = 32   # 与 v9max SFT 配置保持一致，便于合并
num_epochs = 1           # DPO 一过拟合就退化，1 epoch + early stop
```

### 3.3 已知风险与对策

| 风险 | 表现 | 对策 |
| --- | --- | --- |
| 长度坍缩 | 输出越来越短，CoT 消失 | beta≥0.1；监控 chosen/rejected 长度差；混入格式保持对 |
| 格式退化 | 围栏输出比例下降 | 每 50 step 在 20 条格式探针上验证，<90% 即停 |
| 保守化 | recall 掉、全判 safe | 偏好对中 FN:FP 保持 2:1，纠偏不过量 |

---

## 四、Stage B：GRPO 可验证奖励强化

漏洞检测是少数**奖励可程序化验证**的 LLM 任务（ground truth 明确），适合 GRPO。但奖励设计是全部成败所在。

### 4.1 奖励函数（规则组合，总分 1.0）

```python
def reward(output, sample):
    r = 0.0
    v = parse_verdict(output)              # 解析 JSON verdict
    # 1. 格式门（0/0.1）：不合规直接几乎零分，防格式崩
    if v is None:
        return 0.05 if has_json_block(output) else 0.0
    r += 0.1
    # 2. 判定正确性（±0.5）：核心信号，对称设计防"全判漏洞"黑客行为
    if sample.expected and v.has_vulnerability:   r += 0.5   # TP
    elif not sample.expected and not v.has_vulnerability: r += 0.5  # TN
    elif sample.expected and not v.has_vulnerability: r -= 0.3      # FN
    else: r -= 0.5                                            # FP 重罚
    # 3. CWE 匹配（0.2）：type 与 ground truth 一致
    if cwe_match(v.vulnerability_type, sample.cwe): r += 0.2
    # 4. 证据质量（0.1）：sink/source 非 N/A 且出现在代码中
    if evidence_grounded(v, sample.code): r += 0.1
    # 5. 长度约束（0.1）：CoT ≤ 300 token 奖励，防推理膨胀
    if cot_token_len(output) <= 300: r += 0.1
    return r
```

**防 reward hacking 的三道闸**（GRPO 在该任务上的文献级教训）：
1. **FP 惩罚 ≥ FN 惩罚**：否则模型学会"全判漏洞"刷 recall（CVE 测试集全正样本的教训就在这里）；
2. **格式门前置**：解析失败近零分，不给绕过解析器刷分的机会；
3. **证据接地校验**：sink/source 必须在代码文本中真实出现，防幻觉证据骗分。

### 4.2 训练配置（TRL GRPOTrainer + vLLM rollout）

```python
# 硬件门槛：云 GPU ≥40GB（A100/A800）；24GB 需 4bit + 小 batch，慢但可行
num_generations = 8        # 每 prompt 采 8 条，组内归一化
temperature = 0.9          # rollout 需要探索，但不能到 1.0+ 破坏格式
learning_rate = 1e-6
kl_coef (beta) = 0.04      # 比 DPO 小，允许更大策略移动，但必须有
rollout 引擎: vLLM colocate 模式
训练样本: 仅用训练集 + 飞轮回流样本，~2000 条 prompt 起步
每 20 step 在冻结验证集上测 strict_recall / FPR，早停
```

### 4.3 与 vLLM 推理侧的一致性

GRPO rollout 走 `vllm_client`（chat/completions），与线上推理同路径——训练/推理模板一致是 v9max 已验证的原则（format 对齐的教训），不要在 GRPO 里换模板。

---

## 五、数据飞轮协议（贯穿全程）

飞轮是 α1→α2→... 的持续机制，**协议先于自动化**：

```text
部署/评估 → 错题收集 → 教师重生成 CoT → 双审（自动校验 + 抽检）
        → 泄漏审计 → 入训练池 → 版本化重训
```

**五条铁律**：

1. **冻结集永不入轮**：CVE-fix 测试集 + 新 held-out 集物理隔离（单独目录 + manifest 锁定），飞轮样本入库前必过 `audit_leakage_precise.py`（已修复多语言覆盖）；
2. **每轮回流上限**：单次回流 ≤ 训练池 10%，防分布被自产数据淹没（model collapse 防护）；
3. **错题分级**：只有"高置信错题"（教师与模型判定一致地对立 + 证据可验证）才直接入池，模糊样本进人工队列；
4. **版本化**：每轮数据打 tag（如 `flywheel_r3`），训练命令、数据版本、评估结果三元组入库，保证论文可复现；
5. **退化检测**：每轮重训后若冻结集 strict_recall 下降 >2pp 或 FPR 上升 >3pp，回滚到上一版本并分析。

---

## 六、评估门（阶段推进的硬条件）

| 门 | 条件 | 测试集 |
| --- | --- | --- |
| G0（入口） | v9max 基线重测完成（修复后 prompt 重跑） | CVE-fix + 新 held-out |
| G1（DPO→GRPO） | strict_recall ≥ 0.70 且 FPR 不升、格式合规率 ≥95% | 同上 |
| G2（GRPO→α1 发布） | strict_recall ≥ 0.75、FPR ≤ 基线、fix_suggestion 围栏 ≥18/20 | 同上 + exp_04（注明非独立） |

所有数字以**严格口径**（`recall_with_parse_fail` 等）为准，论文引用时注明测试集局限性。

---

## 七、并行事项（不属于训练但必须做）

1. **FixVerifier 修复**（fix_usable=0 的真正瓶颈）：扩充危险模式覆盖、补 tests_passed 判定逻辑——这决定"自动修复"论文卖点能否成立；
2. **评估重跑**：按 `experiments/REGRUN_AFTER_FIX.md` 先拿到干净基线，否则 G0 不存在；
3. **工具层优化**（若走新架构）：Semgrep taint 规则 + TaintTracker P0 改造，与 α1 的"模型能力"故事互补为"系统能力"故事。

---

## 八、硬件与时间预算

| 阶段 | 硬件 | 时间 | 备注 |
| --- | --- | --- | --- |
| G0 基线重跑 | 本地 Ollama 即可 | 1 天 | prompt 修复后全量重跑 |
| DPO | 云 24GB（QLoRA） | 1-2 天 | 含数据构造 |
| GRPO | 云 40GB | 3-5 天 | rollout 是大头 |
| 飞轮首轮 | 复用上述 | 2 天 | 主要是协议落地 |

---

## 九、前置工作清单（可立即开工）

按依赖顺序：

- [ ] **G0 基线重跑**（需要 GPU/Ollama 环境，用户执行）
- [ ] DPO 偏好对构建脚本：从 evaluate.py 错题 JSON 自动生成 chosen/rejected 对（输入：评估结果 + 教师接口；输出：DPO JSONL）
- [ ] GRPO reward 函数脚本：`reward.py`（§4.1 的可执行实现 + 单元测试）
- [ ] 飞轮入库管道：`flywheel_ingest.py`（去重 → 泄漏审计 → 格式校验 → 版本 tag）
- [ ] 冻结集隔离：CVE-fix + 新 held-out 的 manifest 锁定脚本
- [ ] FixVerifier 危险模式扩充（独立任务）

---

## 十、风险清单

| 风险 | 等级 | 缓解 |
| --- | --- | --- |
| GRPO reward hacking（全判漏洞/格式取巧） | 高 | §4.1 三道闸 + 冻结集监控 |
| DPO 后格式退化 | 中 | 格式探针早停（§3.3） |
| 飞轮数据污染冻结集 | 高 | §五铁律 1，泄漏审计强制化 |
| 云 GPU 成本超预算 | 中 | DPO 先行验证收益，GRPO 可裁剪 num_generations |
| CoT 蒸馏痕迹被评审质疑 | 低 | 教师输出全部重写为统一压缩模板，方法论章节如实说明 |
