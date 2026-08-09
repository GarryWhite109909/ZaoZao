#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""分析训练数据质量的脚本"""

import json
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path

# 用真实用户主目录动态解析（不写死用户名）
DATA_FILE = Path.home() / "文档/code/毕业设计/experiments/exp_06_finetune/data/train_chatml_v9_augmented.jsonl"

# ==========================================
# 读取数据
# ==========================================
samples = []
with open(DATA_FILE, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        samples.append(json.loads(line))

total = len(samples)
print(f"{'='*70}")
print(f"  训练数据质量分析报告")
print(f"{'='*70}")
print(f"\n1. 总样本数: {total}")

# ==========================================
# 提取每条样本的各个字段
# ==========================================
def extract_json_from_assistant(assistant_content):
    """从 assistant 消息中提取 JSON 块"""
    if not assistant_content:
        return None
    # 匹配 ```json ... ``` 块
    pattern = r'```json\s*\n?(.*?)\n?```'
    matches = re.findall(pattern, assistant_content, re.DOTALL)
    if not matches:
        return None
    for m in matches:
        try:
            return json.loads(m.strip())
        except json.JSONDecodeError:
            continue
    return None

def extract_language(user_content):
    """从 user 消息中提取语言"""
    if not user_content:
        return None
    m = re.search(r'语言:\s*(\w+)', user_content)
    if m:
        return m.group(1).lower()
    return None

def extract_code(user_content):
    """从 user 消息中提取代码块内容"""
    if not user_content:
        return None
    m = re.search(r'```\w*\n(.*?)```', user_content, re.DOTALL)
    if m:
        return m.group(1).strip()
    return None

# 存储解析结果
parsed = []
issues = {
    "no_json_block": [],       # 缺少 ```json 包裹
    "json_parse_error": [],    # JSON 解析失败
    "missing_vuln_type": [],   # 缺少 vulnerability_type
    "missing_has_vuln": [],    # 缺少 has_vulnerability
    "inconsistent": [],        # has_vulnerability 与 vulnerability_type 不一致
    "empty_short": [],         # assistant 为空或过短
    "duplicate_codes": [],     # 重复的 code 内容
}

vuln_type_counter = Counter()
risk_level_counter = Counter()
language_counter = Counter()
assistant_lengths = []

has_vuln_true = 0
has_vuln_false = 0
has_vuln_missing = 0

# 用于检测重复代码
code_set = defaultdict(list)  # code -> [sample_indices]

for idx, sample in enumerate(samples):
    messages = sample.get("messages", [])
    if len(messages) < 3:
        issues["no_json_block"].append(idx)
        continue

    # 提取消息
    user_msg = None
    assistant_msg = None
    for m in messages:
        if m["role"] == "user":
            user_msg = m["content"]
        elif m["role"] == "assistant":
            assistant_msg = m["content"]

    # ---- 检查 assistant 为空或过短 ----
    if not assistant_msg or len(assistant_msg) < 50:
        issues["empty_short"].append((idx, len(assistant_msg) if assistant_msg else 0))
        # 仍然继续，因为可能还能提取到 JSON

    # ---- 统计 assistant 长度 ----
    if assistant_msg:
        assistant_lengths.append(len(assistant_msg))

    # ---- 提取 JSON ----
    json_data = extract_json_from_assistant(assistant_msg)
    if json_data is None:
        issues["no_json_block"].append(idx)
        # 继续检查其他字段
        continue

    # ---- 检查字段完整性 ----
    has_vuln = json_data.get("has_vulnerability")
    vuln_type = json_data.get("vulnerability_type")

    if has_vuln is None:
        issues["missing_has_vuln"].append(idx)
    if vuln_type is None:
        issues["missing_vuln_type"].append(idx)

    # ---- 统计 has_vulnerability ----
    if has_vuln is True:
        has_vuln_true += 1
    elif has_vuln is False:
        has_vuln_false += 1
    else:
        has_vuln_missing += 1

    # ---- 统计风险等级 ----
    risk_level = json_data.get("risk_level")
    if risk_level and risk_level != "None":
        risk_level_counter[risk_level] += 1

    # ---- 统计漏洞类型 ----
    if vuln_type and vuln_type != "none":
        vuln_type_counter[vuln_type] += 1

    # ---- 检查不一致性 ----
    if has_vuln is not None and vuln_type is not None:
        if has_vuln is True and vuln_type == "none":
            issues["inconsistent"].append((idx, "has_vulnerability=true 但 vulnerability_type='none'"))
        elif has_vuln is False and vuln_type != "none":
            issues["inconsistent"].append((idx, f"has_vulnerability=false 但 vulnerability_type='{vuln_type}'"))

    # ---- 提取语言 ----
    if user_msg:
        lang = extract_language(user_msg)
        if lang:
            language_counter[lang] += 1

    # ---- 提取代码 ----
    if user_msg:
        code = extract_code(user_msg)
        if code:
            code_set[code].append(idx)

# ==========================================
# 报告输出
# ==========================================

# 2. CWE 分布
print(f"\n{'='*70}")
print(f"2. CWE 分布表（vulnerability_type）")
print(f"{'='*70}")
if vuln_type_counter:
    print(f"   {'CWE类型':<40s} {'数量':>6s} {'占比':>8s}")
    print(f"   {'-'*56}")
    for cwe, cnt in sorted(vuln_type_counter.items(), key=lambda x: -x[1]):
        print(f"   {cwe:<40s} {cnt:>6d} {cnt/total*100:>7.2f}%")
else:
    print("   (无漏洞样本或无有效数据)")
print(f"   {'-'*56}")
print(f"   总计（含漏洞样本）: {sum(vuln_type_counter.values())}")

# 3. 漏洞/安全样本比例
print(f"\n{'='*70}")
print(f"3. 漏洞样本 vs 安全样本比例")
print(f"{'='*70}")
print(f"   has_vulnerability=true  : {has_vuln_true:>6d} ({has_vuln_true/total*100:>6.2f}%)")
print(f"   has_vulnerability=false : {has_vuln_false:>6d} ({has_vuln_false/total*100:>6.2f}%)")
if has_vuln_missing > 0:
    print(f"   缺失 has_vulnerability : {has_vuln_missing:>6d} ({has_vuln_missing/total*100:>6.2f}%)")

# 4. 风险等级分布
print(f"\n{'='*70}")
print(f"4. 漏洞样本的 risk_level 分布")
print(f"{'='*70}")
if risk_level_counter:
    total_vuln = sum(risk_level_counter.values())
    print(f"   {'风险等级':<12s} {'数量':>6s} {'占比':>8s}")
    print(f"   {'-'*28}")
    for level in ["Critical", "High", "Medium", "Low"]:
        cnt = risk_level_counter.get(level, 0)
        print(f"   {level:<12s} {cnt:>6d} {cnt/total_vuln*100:>7.2f}%")
    print(f"   {'-'*28}")
    print(f"   合计: {total_vuln}")
else:
    print("   (无数据)")

# 5. 编程语言分布
print(f"\n{'='*70}")
print(f"5. 编程语言分布")
print(f"{'='*70}")
if language_counter:
    print(f"   {'语言':<15s} {'数量':>6s} {'占比':>8s}")
    print(f"   {'-'*31}")
    for lang, cnt in sorted(language_counter.items(), key=lambda x: -x[1]):
        print(f"   {lang:<15s} {cnt:>6d} {cnt/total*100:>7.2f}%")
else:
    print("   (未提取到语言信息)")

# 6. 格式检查
print(f"\n{'='*70}")
print(f"6. JSON 格式完整性检查")
print(f"{'='*70}")
print(f"   缺少 ```json 包裹或 JSON 解析失败: {len(issues['no_json_block'])} 条")
if issues["no_json_block"]:
    print(f"     样本索引（0-based）: {issues['no_json_block'][:20]}{'...' if len(issues['no_json_block']) > 20 else ''}")
print(f"   缺少 vulnerability_type 字段: {len(issues['missing_vuln_type'])} 条")
if issues["missing_vuln_type"]:
    print(f"     样本索引: {issues['missing_vuln_type'][:20]}{'...' if len(issues['missing_vuln_type']) > 20 else ''}")
print(f"   缺少 has_vulnerability 字段: {len(issues['missing_has_vuln'])} 条")
if issues["missing_has_vuln"]:
    print(f"     样本索引: {issues['missing_has_vuln'][:20]}{'...' if len(issues['missing_has_vuln']) > 20 else ''}")

# 7. 一致性检查
print(f"\n{'='*70}")
print(f"7. has_vulnerability 与 vulnerability_type 一致性检查")
print(f"{'='*70}")
if issues["inconsistent"]:
    print(f"   发现不一致样本: {len(issues['inconsistent'])} 条")
    for idx, desc in issues["inconsistent"][:30]:
        print(f"     样本 #{idx}: {desc}")
    if len(issues["inconsistent"]) > 30:
        print(f"     ... 还有 {len(issues['inconsistent']) - 30} 条")
else:
    print(f"   全部一致，未发现问题")

# 8. 空/短响应
print(f"\n{'='*70}")
print(f"8. Assistant 响应为空或过短（< 50 字符）")
print(f"{'='*70}")
if issues["empty_short"]:
    print(f"   发现 {len(issues['empty_short'])} 条")
    for idx, length in issues["empty_short"][:20]:
        print(f"     样本 #{idx}: 长度={length}")
    if len(issues["empty_short"]) > 20:
        print(f"     ... 还有 {len(issues['empty_short']) - 20} 条")
else:
    print(f"   全部正常")

# 9. 样本长度分布
print(f"\n{'='*70}")
print(f"9. Assistant 消息字符数分布")
print(f"{'='*70}")
if assistant_lengths:
    lengths = sorted(assistant_lengths)
    n = len(lengths)
    mean_len = statistics.mean(lengths)
    median_len = statistics.median(lengths)
    min_len = min(lengths)
    max_len = max(lengths)
    print(f"   样本数: {n}")
    print(f"   最小值: {min_len}")
    print(f"   最大值: {max_len}")
    print(f"   均值  : {mean_len:.1f}")
    print(f"   中位数: {median_len}")
    # 分位数
    print(f"   P25   : {lengths[int(n*0.25)]}")
    print(f"   P75   : {lengths[int(n*0.75)]}")
    print(f"   P90   : {lengths[int(n*0.90)]}")
    print(f"   P95   : {lengths[int(n*0.95)]}")
else:
    print(f"   无数据")

# 10. 重复代码
print(f"\n{'='*70}")
print(f"10. 重复代码内容检查")
print(f"{'='*70}")
duplicates = {code: indices for code, indices in code_set.items() if len(indices) > 1}
if duplicates:
    print(f"   发现重复代码: {len(duplicates)} 组，涉及 {sum(len(v) for v in duplicates.values())} 条样本")
    for i, (code, indices) in enumerate(sorted(duplicates.items(), key=lambda x: -len(x[1])), 1):
        print(f"   重复组 #{i}: 出现 {len(indices)} 次，样本索引: {indices}")
        # 只显示前 5 组详细内容
        if i <= 5:
            print(f"     代码预览: {code[:100]}...")
else:
    print(f"   未发现重复代码")

print(f"\n{'='*70}")
print(f"  分析完成")
print(f"{'='*70}")
