#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""分析 train_chatml_v9_augmented.jsonl 中所有 CWE 命名问题"""

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

# 用真实用户主目录动态解析（不写死用户名）
JSONL_PATH = Path.home() / "文档/code/毕业设计/experiments/exp_06_finetune/data/train_chatml_v9_augmented.jsonl"

def extract_vulnerability_types():
    """从 JSONL 文件中提取所有 vulnerability_type 值"""
    raw_values = []
    parse_errors = []
    
    with open(JSONL_PATH, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                messages = data.get("messages", [])
                # assistant 消息是最后一条
                assistant_msg = None
                for msg in messages:
                    if msg.get("role") == "assistant":
                        assistant_msg = msg
                
                if not assistant_msg:
                    parse_errors.append((line_no, "no assistant message"))
                    continue
                
                content = assistant_msg.get("content", "")
                
                # 提取 ```json ... ``` 块
                json_blocks = re.findall(r'```json\s*([\s\S]*?)```', content)
                if not json_blocks:
                    parse_errors.append((line_no, "no json block found"))
                    continue
                
                # 取最后一个 json 块
                json_str = json_blocks[-1].strip()
                json_data = json.loads(json_str)
                vt = json_data.get("vulnerability_type", "")
                raw_values.append((line_no, vt))
            except Exception as e:
                parse_errors.append((line_no, str(e)))
    
    return raw_values, parse_errors


def extract_cwe_number(vt_str):
    """从 vulnerability_type 字符串中提取 CWE 编号，如 'CWE-89 SQL注入' -> 'CWE-89'"""
    if vt_str == "none":
        return "none", vt_str
    # 匹配所有 CWE-xxx 模式
    cwe_match = re.match(r'(CWE-\d+)\s*(.*)', vt_str)
    if cwe_match:
        return cwe_match.group(1), cwe_match.group(2).strip()
    # 多值情况：如 "CWE-1336; CWE-94 SSTI模板注入"
    # 这种情况需要特殊处理
    return "其他", vt_str


def extract_all_cwe_items(vt_str):
    """提取可能包含多个 CWE 编号的条目，返回 (cwe_number, chinese_name) 列表"""
    if vt_str == "none":
        return [("none", "")]
    
    items = []
    # 先用分号分割
    parts = re.split(r';\s*', vt_str)
    for part in parts:
        part = part.strip()
        if not part:
            continue
        cwe_match = re.match(r'(CWE-\d+)\s*(.*)', part)
        if cwe_match:
            cwe_num = cwe_match.group(1)
            chinese = cwe_match.group(2).strip()
            items.append((cwe_num, chinese))
        else:
            items.append(("其他", part))
    
    return items


def analyze():
    raw_values, parse_errors = extract_vulnerability_types()
    
    print(f"总行数: {len(raw_values) + len(parse_errors)}")
    print(f"成功解析: {len(raw_values)}")
    print(f"解析失败: {len(parse_errors)}")
    if parse_errors:
        print(f"\n解析失败详情（前10条）:")
        for line_no, err in parse_errors[:10]:
            print(f"  第{line_no}行: {err}")
    
    print("\n" + "=" * 80)
    print("一、所有 distinct vulnerability_type 值及出现次数")
    print("=" * 80)
    
    counter = Counter(vt for _, vt in raw_values)
    # 按出现次数降序排列
    sorted_items = sorted(counter.items(), key=lambda x: -x[1])
    for vt, count in sorted_items:
        print(f"  {count:4d} 次  |  {vt}")
    
    print(f"\n  distinct 总数: {len(sorted_items)}")
    
    # ============================================================
    # 按 CWE 编号分组，列出所有命名变体
    print("\n" + "=" * 80)
    print("二、按 CWE 编号分组，列出所有命名变体")
    print("=" * 80)
    
    # 对每个条目，提取其所有 CWE 项
    cwe_variants = defaultdict(set)  # cwe_number -> set of chinese_names
    cwe_variants_full = defaultdict(set)  # cwe_number -> set of full_vt_strings
    
    for line_no, vt in raw_values:
        items = extract_all_cwe_items(vt)
        for cwe_num, chinese in items:
            if cwe_num == "none":
                continue
            cwe_variants[cwe_num].add(chinese if chinese else "(无中文描述)")
            cwe_variants_full[cwe_num].add(vt)
    
    for cwe_num in sorted(cwe_variants.keys()):
        variants = cwe_variants[cwe_num]
        full_variants = cwe_variants_full[cwe_num]
        # 统计该 CWE 编号的总出现次数
        total_count = sum(1 for _, vt in raw_values if cwe_num in vt)
        print(f"\n  [{cwe_num}]  总出现次数: {total_count}")
        print(f"  完整 vulnerability_type 变体 ({len(full_variants)} 种):")
        for fv in sorted(full_variants):
            print(f"    - \"{fv}\"")
        print(f"  中文命名变体 ({len(variants)} 种):")
        for v in sorted(variants):
            if v:
                print(f"    - \"{v}\"")
    
    # ============================================================
    # 格式不一致问题分析
    print("\n" + "=" * 80)
    print("三、格式不一致问题分析")
    print("=" * 80)
    
    # 3.1 同一 CWE 编号有不同中文表述
    print("\n  3.1 同一 CWE 编号有不同中文表述:")
    multi_variant_found = False
    for cwe_num in sorted(cwe_variants.keys()):
        variants = cwe_variants[cwe_num]
        if len(variants) > 1:
            multi_variant_found = True
            print(f"\n    {cwe_num}:")
            for v in sorted(variants):
                items = [vt for _, vt in raw_values if cwe_num in vt]
                # 统计这个变体下具体出现了多少次
                variant_count = sum(1 for vt in items if vt.endswith(v) or 
                    f"{cwe_num} {v}" in vt or 
                    any(f"{cwe_num} {v}" == p.strip() for p in re.split(r';\s*', vt)))
                # 更精确的统计：看包含这个 cwe_num 且包含这个中文描述的
                precise_count = 0
                for _, vt in raw_values:
                    if cwe_num in vt:
                        items_list = extract_all_cwe_items(vt)
                        for c, ch in items_list:
                            if c == cwe_num and ch == v:
                                precise_count += 1
                print(f'      - "{v}" ({precise_count} 次)')
    if not multi_variant_found:
        print("    未发现多中文表述问题")
    
    # 3.2 空格不一致
    print("\n  3.2 空格不一致问题:")
    space_issues = []
    for vt, count in sorted_items:
        if vt == "none":
            continue
        # 检查是否有 CWE-xxx 后面空格不一致的问题
        # 比如 "CWE-943 NoSQL注入" vs "CWE-943  NoSQL注入"（双空格）
        cwe_match = re.match(r'(CWE-\d+)(\s+)(.*)', vt)
        if cwe_match:
            spaces = cwe_match.group(2)
            if len(spaces) != 1:
                space_issues.append((vt, count, repr(spaces)))
    if space_issues:
        for vt, count, sp in space_issues:
            print(f"    \"{vt}\"  ({count} 次)  空格: {sp}")
    else:
        print("    未发现明显的空格不一致问题（CWE 编号后均为单空格）")
    
    # 检查"注入"前是否有空格
    print("\n  3.3 中文表述内的空格不一致:")
    space_in_zh = []
    for vt, count in sorted_items:
        if vt == "none":
            continue
        # 检查中文部分是否有额外空格
        parts = re.split(r';\s*', vt)
        for part in parts:
            part = part.strip()
            cwe_match = re.match(r'(CWE-\d+)\s+(.*)', part)
            if cwe_match:
                chinese = cwe_match.group(2)
                # 检查中文内部是否有空格，如 "NoSQL注入" vs "NoSQL 注入"
                if re.search(r'[\u4e00-\u9fff]\s+[a-zA-Z]|[a-zA-Z]\s+[\u4e00-\u9fff]', chinese):
                    space_in_zh.append((vt, count, chinese))
    if space_in_zh:
        # 去重显示
        seen = set()
        for vt, count, ch in space_in_zh:
            key = (vt, ch)
            if key not in seen:
                seen.add(key)
                print(f"    \"{vt}\"  ({count} 次)  → 中文部分含空格: \"{ch}\"")
    else:
        print("    未发现中文表述内空格不一致问题")
    
    # 3.4 括号使用不一致
    print("\n  3.4 括号使用不一致:")
    bracket_issues = []
    for cwe_num in sorted(cwe_variants.keys()):
        variants = cwe_variants[cwe_num]
        # 检查是否有带括号和不带括号的变体
        real_variants = [v for v in variants if v != "(无中文描述)"]
        has_bracket = any('(' in v and ')' in v for v in real_variants)
        has_no_bracket = any('(' not in v and ')' not in v for v in real_variants)
        if has_bracket and has_no_bracket:
            bracket_issues.append(cwe_num)
            print(f"\n    {cwe_num}:")
            for v in sorted(variants):
                if v and v != "(无中文描述)":
                    # 精确统计
                    precise_count = 0
                    for _, vt in raw_values:
                        if cwe_num in vt:
                            items_list = extract_all_cwe_items(vt)
                            for c, ch in items_list:
                                if c == cwe_num and ch == v:
                                    precise_count += 1
                    print(f'      - "{v}" ({precise_count} 次)')
    if not bracket_issues:
        print("    未发现括号使用不一致问题")
    
    # 3.5 多值分号分隔格式不一致
    print("\n  3.5 多值分号分隔格式不一致:")
    multi_value_items = []
    for line_no, vt in raw_values:
        if vt != "none" and ';' in vt:
            multi_value_items.append((line_no, vt))
    
    if multi_value_items:
        # 按完整字符串去重
        unique_multi = sorted(set(vt for _, vt in multi_value_items))
        print(f"    共 {len(multi_value_items)} 条记录包含多个 CWE 值，{len(unique_multi)} 种不同格式:")
        for vt in unique_multi:
            count = sum(1 for _, v in multi_value_items if v == vt)
            # 解析每个部分
            parts = re.split(r';\s*', vt)
            print(f"    [{count} 次] \"{vt}\"")
            for p in parts:
                p = p.strip()
                cwe_match = re.match(r'(CWE-\d+)\s*(.*)', p)
                if cwe_match:
                    ch = cwe_match.group(2).strip()
                    print(f"          → {cwe_match.group(1)} / \"{ch}\"" if ch else f"          → {cwe_match.group(1)} / (无中文描述)")
                else:
                    print(f"          → {p}")
    else:
        print("    未发现多值分号分隔的记录")
    
    # ============================================================
    # 标准化建议
    print("\n" + "=" * 80)
    print("四、标准化命名建议")
    print("=" * 80)
    
    # 统计每个 CWE 编号下最常用的中文名
    cwe_chinese_counter = defaultdict(Counter)
    for line_no, vt in raw_values:
        items = extract_all_cwe_items(vt)
        for cwe_num, chinese in items:
            if cwe_num == "none":
                continue
            if chinese:
                cwe_chinese_counter[cwe_num][chinese] += 1
    
    # 给出建议
    suggestions = {
        "CWE-22": "路径穿越",
        "CWE-23": "路径穿越（限制路径名）",
        "CWE-73": "文件路径控制",
        "CWE-77": "命令注入",
        "CWE-78": "命令注入",
        "CWE-79": "XSS",
        "CWE-89": "SQL注入",
        "CWE-90": "LDAP注入",
        "CWE-91": "XPath注入",
        "CWE-94": "代码注入",
        "CWE-95": "代码注入",
        "CWE-98": "代码注入",
        "CWE-113": "HTTP响应头注入",
        "CWE-117": "日志注入",
        "CWE-200": "信息泄露",
        "CWE-201": "信息泄露",
        "CWE-209": "信息泄露",
        "CWE-250": "不安全的权限管理",
        "CWE-269": "权限管理不当",
        "CWE-276": "默认权限不正确",
        "CWE-285": "授权不当",
        "CWE-287": "认证绕过",
        "CWE-295": "证书验证不当",
        "CWE-306": "缺失认证",
        "CWE-307": "暴力破解",
        "CWE-312": "敏感信息明文存储",
        "CWE-319": "明文传输",
        "CWE-326": "弱加密",
        "CWE-327": "弱加密",
        "CWE-328": "弱哈希",
        "CWE-330": "弱随机数",
        "CWE-338": "弱随机数",
        "CWE-346": "CORS配置不当",
        "CWE-352": "CSRF",
        "CWE-362": "条件竞争",
        "CWE-377": "不安全临时文件",
        "CWE-379": "不安全临时文件",
        "CWE-400": "拒绝服务",
        "CWE-434": "文件上传",
        "CWE-444": "HTTP请求走私",
        "CWE-502": "不安全的反序列化",
        "CWE-521": "弱密码要求",
        "CWE-522": "认证凭证保护不足",
        "CWE-532": "敏感信息日志泄露",
        "CWE-601": "开放重定向",
        "CWE-611": "XXE",
        "CWE-614": "敏感Cookie设置不当",
        "CWE-640": "密码重置功能",
        "CWE-643": "XPath注入",
        "CWE-645": "LDAP注入",
        "CWE-703": "异常处理不当",
        "CWE-706": "路径解析不当",
        "CWE-732": "权限配置不当",
        "CWE-754": "异常检查不当",
        "CWE-759": "弱密码",
        "CWE-770": "资源耗尽",
        "CWE-776": "XML实体扩展",
        "CWE-798": "硬编码凭证",
        "CWE-807": "基于不可信输入的信任判断",
        "CWE-862": "缺失授权",
        "CWE-863": "授权不当",
        "CWE-915": "原型污染",
        "CWE-918": "SSRF",
        "CWE-943": "NoSQL注入",
        "CWE-1336": "SSTI模板注入",
    }
    
    for cwe_num in sorted(cwe_variants.keys()):
        variants = cwe_variants[cwe_num]
        most_common = cwe_chinese_counter[cwe_num].most_common(1)
        most_used = most_common[0][0] if most_common else "(无)"
        suggested = suggestions.get(cwe_num, "")
        
        total_count = sum(1 for _, vt in raw_values if cwe_num in vt)
        
        print(f"\n  {cwe_num}  (共 {total_count} 次)")
        print(f"    当前最常用: \"{most_used}\"")
        if suggested:
            if suggested != most_used and len(variants) > 1:
                print(f"    建议标准化: \"{suggested}\"  ← 存在 {len(variants)} 种变体，建议统一")
            elif suggested != most_used:
                print(f"    建议标准化: \"{suggested}\"")
            else:
                print(f"    建议标准化: \"{suggested}\" (✓ 已是最常用)")
        else:
            print(f"    建议: 需人工确认标准名称")
        
        if len(variants) > 1:
            all_variants_str = " / ".join(sorted(variants))
            print(f"    当前变体: {all_variants_str}")


if __name__ == "__main__":
    analyze()
