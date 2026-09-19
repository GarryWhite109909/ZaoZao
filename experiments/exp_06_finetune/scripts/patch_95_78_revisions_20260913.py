# -*- coding: utf-8 -*-
"""95/78 批预审修订补丁（20260913）：修语法错误、版本悖论、Java tokenize、find 注入位、ast.Expression fail-closed。"""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
S = Path(__file__).resolve().parents[1] / "scripts"

# ---------- 95 批 ----------
f95 = S / "build_wave2_pairs_95_20260911.py"
t = f95.read_text(encoding="utf-8")
# 1) ast.Expression 根节点 fail-closed 修复（95-01/05/06/13/15 全部 ALLOWED_NODES）
n = t.count("ast.Load,")
t = t.replace("ast.Load,", "ast.Load, ast.Expression,")
# 2) 95-09 非法语法 $$'is_admin' -> 合法动态变量形式
assert "$$'is_admin'" in t
t = t.replace("if ($$'is_admin' ?? false) {", "if (!empty(${'is_admin'})) {")
t = t.replace(
    "// 动态变量命名空间：键名成为 PHP 变量名并被赋值执行\n    $$key = $value;\n}\nif (!empty(${'is_admin'})) {",
    "// 动态变量命名空间：键名成为 PHP 变量名并被赋值执行\n    $$key = $value;\n}\nif (!empty(${'is_admin'})) {")
# 3) 95-10 版本悖论：去 PHP 7 类型声明（/e 仅 PHP<=5.6 存在）
t = t.replace("function render_bbcode(string $text): string {", "function render_bbcode($text) {")
t = t.replace("function render_bbcode(string $text): string {", "function render_bbcode($text) {")
# 95-10B safe 侧补输出转义（教师发现的反射 XSS）
t = t.replace("echo render_bbcode($_POST['body']);\n''',\n    'safe'",
              "echo htmlspecialchars(render_bbcode($_POST['body']), ENT_QUOTES, 'UTF-8');\n''',\n    'safe'") if "''',\n    'safe'" in t else t
t = t.replace("echo render_bbcode($_POST['body']);", "echo htmlspecialchars(render_bbcode($_POST['body']), ENT_QUOTES, 'UTF-8');")
f95.write_text(t, encoding="utf-8")
print(f"95 批补丁完成（ast.Expression x{n}；95-09 语法；95-10 悖论+XSS）")

# ---------- 78 批 ----------
f78 = S / "build_wave2_pairs_78s_20260911.py"
t = f78.read_text(encoding="utf-8")
# 1) 78-S-02b：Java 单串 exec 不经 shell（教师证伪）→ vuln 改数组 sh -c（真实可注入）
t = t.replace(
    '        // 单字符串 exec：按空格拆分并经默认 sh 语义\n        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);',
    '        // 数组形式 sh -c：脚本位整体可控，host 含 `; rm -rf /` 即成第二命令\n'
    '        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping -c 1 " + host});')
t = t.replace(
    '"anchor": VULN_ANCHOR + " 单串 exec 在 JVM 层按空格 tokenize，host 中的空格可注入额外 argv，"\n              "配合 shell 元字符经默认解释层扩展。",',
    '"anchor": "数组形式但 argv 含 sh -c 解释器语义参数：脚本位整体可控，归 78（镜像 S-09 同轴）；"\n              "非 22（无路径穿越）/ 非 95（无 eval 求值）/ 非 74（目标 OS 命令）。预审修订版 20260913。",')
t = t.replace(
    '''    "oracle_vuln": [
        (r'"ping -c 1 " \\+ host', "sink：拼接进单串命令"),
        (r'Runtime\\.getRuntime\\(\\)\\.exec\\("ping', "默认 shell 语义"),
    ],''',
    '''    "oracle_vuln": [
        (r'new String\\[\\]\\{"sh", "-c", "ping -c 1 " \\+ host\\}', "sink：sh -c 脚本位整体可控（数组形式仍注入）"),
        (r'host\)', "source：请求侧传入 host"),
    ],''')
# 2) 78-S-05：单串 sh -c 引号拆散不可利用（教师证伪）→ vuln 改数组形式
t = t.replace(
    '        // 单字符串命令 + shell 解释\n        Process p = Runtime.getRuntime().exec("sh -c \'unzip -o " + archive + " -d /srv/tmp\'");',
    '        // 数组形式 sh -c：脚本位整体可控，archive 含 `; rm -rf /` 即执行第二命令\n'
    '        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "unzip -o " + archive + " -d /srv/tmp"});')
t = t.replace(
    '''    "oracle_vuln": [
        (r'"sh -c \\'unzip -o " \\+ archive', "sink：经 sh -c 解释的拼接命令"),
        (r'Runtime\\.getRuntime\\(\\)\\.exec\\("sh -c', "shell 解释层"),
    ],''',
    '''    "oracle_vuln": [
        (r'new String\\[\\]\\{"sh", "-c", "unzip -o " \\+ archive', "sink：sh -c 脚本位整体可控（数组形式仍注入）"),
    ],''')
# 3) 78-S-15：vuln 注入点改到 -exec 执行体位；safe 侧封 `..`
t = t.replace(
    '	// -exec 参数位具有执行语义：name 可携带 ; 与 {} 注入执行体\n	return exec.Command("find", "/var/tmp", "-name", name, "-exec", "rm", "-rf", "{}", ";").Output()',
    '	// -exec 执行体位直接由外部传入：name 即被执行的程序\n	return exec.Command("find", "/var/tmp", "-type", "f", "-exec", name, "{}", ";").Output()')
t = t.replace(
    '''    "anchor": "argv 为列表但 `-exec` 是执行语义参数位，name 经 `-name` 通配匹配后 rm 的删除范围由用户间接控制，"
              "配合 `;` 可引入额外命令语义——列表形式不豁免，归 78。非 22/95/74 边界同主锚句。",''',
    '''    "anchor": "argv 为列表但 `-exec` 的执行体位（程序名）直接由外部 name 占据，find 将以当前进程权限执行 name 指定程序"
              "——列表形式不豁免，归 78。非 22（无路径穿越主叙事）/ 非 95（无 eval 求值）/ 非 74 抽象层同 78 主锚句。预审修订版 20260913。",''')
t = t.replace(
    '''    "oracle_vuln": [
        (r'"-exec", "rm", "-rf", "\\{\\}", ";"', "sink：-exec 执行语义参数位"),
        (r'func Purge\\(name string\\)', "source：name 外部传入"),
    ],''',
    '''    "oracle_vuln": [
        (r'"-exec", name, "\\{\\}", ";"', "sink：-exec 执行体位由外部 name 占据"),
        (r'func Purge\\(name string\\)', "source：name 外部传入"),
    ],''')
t = t.replace(
    'var nameRE = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)',
    'var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`) // 首字符限字母数字，封死 ".."')
t = t.replace(
    '''    "oracle_safe": [
        (r'nameRE\\.MatchString', "防御：文件名字符白名单"),''',
    '''    "oracle_safe": [
        (r'nameRE = regexp', "防御：文件名白名单（首字符限字母数字，封死 ..）"),
        (r'filepath\\.Join\\("/var/tmp", filepath\\.Base\\(name\\)\\)', "Join 结果被 Base 化输入约束在上跳之外"),''')
f78.write_text(t, encoding="utf-8")
print("78 批补丁完成（02b/05 数组 sh -c 重写；15 注入位迁移+safe 封 ..）")
