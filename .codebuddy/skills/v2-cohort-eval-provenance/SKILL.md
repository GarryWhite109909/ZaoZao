---
name: v2-cohort-eval-provenance
description:
  引用「某个族有多少条」或「某次测试的 strict/recall 读数」之前，先做两道核对：
  ① 族规模必须用**该族当前的契约字段**去数（契约改写过就得换判据）；
  ② 评测读数必须溯源到**与标签同版本**的 manifest（eval json 可能落后于后续的标签修正）。
  用于 v2_* 数据集统计、alpha0x 弱点归因、投喂/入册对账、评分口径引用。
  This skill should be used when the user asks "这个族有多少条"、"测试成绩说明什么缺陷"、
  "这个读数能不能用"、"入册率多少"、"跨版本对账"，or before quoting any cohort size / eval metric
  from this project's audits.
agent_created: true
---

# 族规模与评测口径的溯源核对

本 skill 只做一件事：**在引用任何统计数字之前，先证明这个数字的判据与版本是对的**。
项目里已经因为跳过这两步踩过坑（下面每条都附实测教训），两次都是"数字看着精确、结论方向反了"。

---

## 0. 两道必跑核对

| 核对 | 问题 | 不做的后果（实测） |
|---|---|---|
| **C1 契约判据核对** | 我数这个族用的字段，是不是它**现在**用的字段？ | T 族在 v2_13 已从 `is_confirmed` 改契约成 `has_vulnerability`；我按 `is_confirmed` 数出 **0 条**，实际 **33 条**（历史峰值 59–61）。结论从"零载体"改成"腰斩 44%"。 |
| **C2 读数版本核对** | 我引用的 eval 产物，和它依赖的 manifest，**mtime 谁新谁旧**？ | `results/mining_merged_rolling_dev_20260824.json`（08-24）用 revision 前标签算出 `strict_recall=0.0667`；`corpus/rolling_dev/manifest.json` 在 **09-02** 被官方口径修正过 6 条。正确读数是 **0.0435**。 |

---

## 1. C1：族规模核对

### 步骤

1. **不要用族名或抬头文字做判据**（抬头会被重写）。用**结论 JSON 的字段**。
2. **CWE 编号必须带词边界**——这是实测踩过的坑：

```python
# ✗ 错：'CWE-787' 含 'CWE-78'，同族计数会虚高（实测 512 → 973）
if "CWE-78" in assistant_text: ...
# ✓ 对
re.findall(r'"vulnerability_type"\s*:\s*"CWE-(\d+)(?!\d)', assistant_text)
```

   同类陷阱：`CWE-79` vs `CWE-798`、`CWE-94` vs `CWE-943`、`CWE-77` vs `CWE-776`、`CWE-89` vs `CWE-89x`。
   **凡按 CWE 编号分族，一律加 `(?!\d)`。**
3. 先扫全库，列出**存在几种结论契约**：

```python
import json, re, collections
rows = [json.loads(l) for l in open(DATASET, encoding="utf-8") if l.strip()]
def asst(r):  return " ".join(m["content"] for m in r["messages"] if m["role"] == "assistant")
def user(r):  return " ".join(m["content"] for m in r["messages"] if m["role"] == "user")
KEYS = ["has_vulnerability", "is_confirmed", "risk_level", "reason", "explanation"]
print(collections.Counter(
    tuple(k for k in KEYS if f'"{k}"' in asst(r)) for r in rows
).most_common())
```

3. **族判据用"用户侧结构 + 结论侧字段"双条件**，例如工具告警裁决族（T 族）：

```python
def is_triage(r):
    u = user(r)
    return ("- 污染源:" in u and "- 危险点:" in u and "- 传播链:" in u)   # 用户侧工具字段
    # 结论侧再按当前契约取；**不要**写成 "is_confirmed" in asst(r)
```

4. **跨版本计数**（族规模会随治理变化，必须给跨版本曲线，不能只报单版）：

```python
for v in ["alpha05", "alpha06_v2_2", "alpha06_v2_15", "alpha06_v2_17_clean",
          "alpha06_v2_23_candidate_20260914", "alpha06_v2_24_candidate_20260914"]:
    rows = load(f"data/final_train_chatml_{v}.jsonl")
    print(v, len(rows), sum(1 for r in rows if is_triage(r)))
```

### 判定口径（本项目）
- 正负构成也按**当前契约字段**数：`"vulnerability_type"` 为 `none` → 负；否则正。
- 报"某族 N 条"时必须同时报**该族的正/负拆分与规则/类型种类数**，否则数字无意义
  （实测：T 族 33 条 = 正 6 / 负 27 / 规则 21 种；补入 24 条后 = 正 21 / 负 36 / 规则 37 种）。

---

## 2. C2：评测读数核对

### 步骤

1. **查 mtime**（这一步最便宜、最有效）：

```python
import os, time
for p in [EVAL_JSON, MANIFEST_JSON]:
    print(p, time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(p))))
```

2. **逐样本对 expected 标签**（不是只看总数）：

```python
man = {s["file"]: s for s in json.load(open(MANIFEST, encoding="utf-8"))["samples"]}
for s in json.load(open(EVAL_JSON, encoding="utf-8"))["samples"]:
    a, b = norm(man.get(s["file"], {}).get("expected_cwe")), norm(s.get("expected_cwe"))
    if a != b:
        print(s["file"], "manifest=%s eval=%s" % (a, b))
```

3. **排排除整体错位**（避免把"标签修正"误判成"索引错位"）：

```python
ma = [norm(man[s["file"]]["expected_cwe"]) for s in ev]
ea = [norm(s["expected_cwe"]) for s in ev]
for sh in range(-5, 6):
    print(sh, sum(1 for i in range(len(ma)) if 0 <= i+sh < len(ea) and ma[i] == ea[i+sh]))
# 最佳对齐在 shift=0 → 是"个别标签被修正"，不是错位
```

4. **重算指标**（模型输出不变，只换真值），并**优先信 manifest**：

```python
# strict 命中 = expected_present 且 model_has_vulnerability 且 模型CWE == manifest的 expected_cwe
```

5. **若重算值与项目文档里的"重算口径"一致，但 eval json 没回写** —— 这就是结论：
   **读数要改用重算值，并在任何引用处标注版本**。

### 判定口径（本项目）
- `expected_cwe` 字段**不是真值**。要看 `_label_basis`（`nvd/ghsa-official` / `audit`）与 `_label_note`（逐条写明官方字段与修正理由）。
- `_label_basis` 为空、或 manifest 里 `expected_cwe` 无 provenance 字段（无 `_label_note`/`expected_cwe_original`）时，
  **必须回读 sink 形态独立判**，不能照抄。

---

## 3. C3（衍生）：oracle 标签的 sink 形态复核

**触发场景**：拿到一批"应该判 X 类"的样本/kit，准备投喂或入库前。

**判据**：不要信 `expected_cwe`，读 pre-fix 源码的 sink 形态。

- `CWE-77`（非 OS 命令语言）vs `CWE-78`（OS 命令）的判别轴 = **哪个解释器消费这个字符串**：
  - `sh -c` / `bash -c` / `exec.Command("sh","-c",…)` / `execSync(shell:true)` / `exec()` /
    `system()` / `Runtime.exec` / `ProcessBuilder` / `child_process.exec`（字符串） → **78**
  - `sed -e <输入>` / `awk '<输入>'` / IMAP·SMTP 命令 / SNMP OID / MVG 图形语言 /
    ffmpeg 滤镜图 / LDAP Filter / XPath / 应用配置语言（nginx·Fluentd·systemd unit） → **77**
  - 命令名固定、输入只落参数位（`tar --checkpoint-action=`、`ssh -oProxyCommand=`） → **88**
- 实测教训：`manifest_PRIVATE.json` 里 8 个 `expected_cwe=CWE-77` 的 kit，抽 5 个读码，
  **5/5 的 sink 都是 OS shell**（`sh -c` / `exec` / `execAsync` / `sshpass … ssh`），
  其中 1 个的上游补丁注释自己写着 `prevent command injection (CWE-78)`。
  ⇒ 这批 77 全是 **NVD 伞类绑定**造成的，按 MITRE 语义应判 78。

---

## 4. 输出格式（照这个写，别只报数字）

```
## 核对结果
- C1 契约判据：本族当前用 <字段>；我原用 <字段> → 修正后 N = a（原报 b）
- C2 读数版本：<eval.json> mtime <T1> < <manifest.json> mtime <T2>；不一致 n 条（列出）
              重算 strict_recall = x（原报 y）→ **采用 x**
- C3 oracle 复核：抽 n 条读 sink，应判 <类> 的 m 条（原标 <类>）
- 影响：哪些结论被推翻 / 哪些方向不变
```

---

## 5. C4（衍生）：删除/缩减类动作的纪律

**触发场景**：任何"某类太多 / 想缩减某类 / 配比不好看"的动议。

**铁律（Garry 2026-09-14）**：**配比合理性不可能是 1:1:1** —— 现实漏洞分布天然偏斜，冷门类型就是少。
**"某类占比太高"不构成删除理由。** 删除只允许命中：

`脏` / `毒` / `重复` / `懒变体` / `低价值` / `无价值` / `无营养`

**配比只能靠抬冷门侧，不能靠砍热门侧。** 可执行的配比表述是**下限约束**
（每 CWE ≥ N 条 + 口径明文类有载体），不是占比上限。

**流程**：
1. 先按五类逐条扫，产出**可删候选清单**（每条带命中类别 + 证据）。
2. 明确报出**不可删的条数**（五类全不命中的）。
3. 把"配额/冗余"视角**单独列出**，标明它是「重复啰嗦治理」而非「配比治理」，额度由人定。
4. **不要**把"每簇保留 N 条"的 N 写进目标而不说明它是配额决策。

**实测案例**：CWE-78 512 条，五类筛出可删候选仅 **64（12.5%）**，**448（87.5%）不可删**。
其中「有效行 < 8」的 62 条**不是无营养**（单条形态正确、explanation 正确），
而是同一 trick 反复出现 → 应归「重复啰嗦」，且其中 6 条落在唯一 trick 簇（不可删）。
冗余视角：512 条 → 152 簇，**76 条是唯一 trick**；"每簇保留 3 条"→ 删 228 —— 这**恰好等于**我原先凭直觉写的"512→300"，恰恰说明那个数字是配额决策而非质量决策。

---

## 6. 反面清单（这五条都真实发生过）

1. 用族名（抬头文字）判据数族 → 抬头被重写后数出 0，而实际有 33 条。
2. 用"旧契约字段"数族 → 同上，且**与自己正在引用的 memory 条目自相矛盾时没交叉核对**。
3. 直接引用 eval json 的 `expected_cwe` 与 `strict_recall`，而该 json 的标签已过期
   （manifest 在 9 天后被官方口径修正 6 条）。
4. CWE 编号不加词边界 → `CWE-787` 被算进 `CWE-78`，同族计数 512 虚高到 973。
5. 把"某类占比太高"当删除理由 → 写出"512 条砍到 300"这种配额目标；
   实测该口径下 448/512 条一条都不该删。

**共同点**：都是"精确的错数字"或"看起来很利落的配额目标"，比含糊更危险。
**先证判据与版本，再报数；先过五类，再谈删。**
