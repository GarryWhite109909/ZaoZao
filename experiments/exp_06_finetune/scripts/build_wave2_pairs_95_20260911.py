# -*- coding: utf-8 -*-
"""wave2 手写代码对：CWE-95 eval 注入 15 对（95-01..15，成对同码）。

口径决策（记录在案，20260911）：wave2_441_95_SPEC.md 的 95-02/95-03 形态是
"输入拼进代码文本再 eval"（eval("sorted(..." + f + ")")）——按 teacher_prompt_session.md
判别标准 B（输入直进 eval 参数位 → 95；拼进生成的代码文本再执行 → 94），该形态应属 94。
为不污染 95/94 判别边界教学，本批所有 95 对统一改为**整表达式直进求值器参数位**；
拼接形态留给后续 94 专项 wave。

形态映射：01a/01b 配置规则进 eval（Python/JS）；02a/02b 动态谓词（Python/PHP）；
03a compile+config（Python）；04a/04b 环境变量/本地存储公式（Python/JS）；
05a/05b Function 构造器/ScriptEngine（Node/Java）；06a/06b 变量变量/preg_replace /e（PHP）；
07a Groovy 引擎（Java）；08a/08b DataFrame.query/sympify（Python）；09a Ruby eval。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from wave2_pairlib import emit, write_index

P = []

# ---------------- 95-01 Python：配置文件谓词进 eval ----------------
_code = '''import json

def load_rules(path="rules.json"):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def apply_discount(order, rules):
    # rules.json 的 predicate 是完整表达式，运营后台可被租户改写
    if eval(rules["predicate"]):
        return order["amount"] * rules["rate"]
    return order["amount"]
'''
P.append({
    "pid": "95-01", "lang": "Python", "cwe": "CWE-95",
    "anchor": "非 94 因为用户数据不是被拼进以可信代码为骨架的生成文本，而是**整体**作为求值表达式直接进入 eval() "
              "参数位；非 78 因为注入目标是 Python 求值器而非 OS 命令；非 1336 因为不经过任何模板引擎。",
    "safe_anchor": "防御为何不可旁路：ast.parse(mode='eval') 后白名单节点遍历，仅放行 BoolOp/Compare/Name/"
                   "Constant/Attribute 白名单字段；Call/Import/Attribute(dunder) 一律拒绝——"
                   "任何 __import__ / __class__ 逃逸路径在节点层即被斩断。",
    "oracle_vuln": [
        (r'eval\(rules\["predicate"\]\)', "sink：整条用户规则直接进 eval 参数位"),
        (r'rules\["predicate"\]', "source：规则文本可被租户改写"),
    ],
    "oracle_safe": [
        (r'ast\.parse\(expr, mode="eval"\)', "防御：先解析为 AST，不做字符串求值"),
        (r'ALLOWED_NODES', "节点类型白名单"),
        (r'raise ValueError', "白名单外节点（Call/Import 等）直接拒绝"),
        (r'ALLOWED_ATTRS', "属性白名单，防 dunder 逃逸"),
    ],
    "vuln_code": _code,
    "safe_code": '''import ast
import json

ALLOWED_NODES = (ast.BoolOp, ast.UnaryOp, ast.Compare, ast.Name, ast.Load, ast.Expression,
                 ast.Constant, ast.Attribute, ast.And, ast.Or, ast.Not,
                 ast.Gt, ast.Lt, ast.GtE, ast.LtE, ast.Eq, ast.NotEq)
ALLOWED_ATTRS = {"amount", "quantity", "vip", "region"}

def load_rules(path="rules.json"):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def restricted_eval(expr, order):
    tree = ast.parse(expr, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_NODES):
            raise ValueError("node not allowed")
        if isinstance(node, ast.Attribute) and node.attr not in ALLOWED_ATTRS:
            raise ValueError("attr not allowed")
        if isinstance(node, ast.Name) and node.id not in ALLOWED_ATTRS:
            raise ValueError("name not allowed")
    return bool(eval(compile(tree, "<rule>", "eval"), {"__builtins__": {}}, {"order": order}))

def apply_discount(order, rules):
    if restricted_eval(rules["predicate"], order):
        return order["amount"] * rules["rate"]
    return order["amount"]
''',
})

# ---------------- 95-02 JS：配置规则进 eval ----------------
_code = '''const config = require("./rules.json");

function eligible(user) {
  // 规则表达式整体存于配置，运营端可改写
  return eval(config.eligibilityExpr)(user);
}

module.exports = { eligible };
'''
P.append({
    "pid": "95-02", "lang": "JavaScript", "cwe": "CWE-95",
    "anchor": "非 94 因为输入整体作为函数体直接进入 eval，没有可信骨架拼接结构；"
              "非 78 因为目标是 JS 求值器而非 shell；非 95 以外的 94 边界按项目判据以'直进参数位'为准。",
    "safe_anchor": "防御为何不可旁路：规则编译为 {op, left, right} 受限树，解释器只认 gte/lte/eq/in 四算子，"
                   "字段取值走静态映射，任何 JS 语法无法进入执行路径。",
    "oracle_vuln": [
        (r'eval\(config\.eligibilityExpr\)', "sink：整条表达式直接进 eval"),
        (r'config\.eligibilityExpr', "source：可被租户/运营端改写"),
    ],
    "oracle_safe": [
        (r'const OPS =', "防御：算子白名单解释器"),
        (r'gte: \(a, b\)', "仅放行受控算子"),
        (r'const FIELDS =', "字段静态映射"),
    ],
    "vuln_code": _code,
    "safe_code": '''const config = require("./rules.json");

// 规则统一编译为受限树：{op:"gte", field:"vip", value:true}
const OPS = {
  gte: (a, b) => a >= b,
  lte: (a, b) => a <= b,
  eq: (a, b) => a === b,
};
const FIELDS = { vip: u => u.vip, spend: u => u.spend };

function eligible(user) {
  const rule = config.eligibilityTree; // {op, field, value}
  const fn = OPS[rule.op];
  const field = FIELDS[rule.field];
  if (!fn || !field) return false;
  return fn(field(user), rule.value);
}

module.exports = { eligible };
''',
})

# ---------------- 95-03 Python：动态排序键 ----------------
_code = '''from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/leaderboard")
def leaderboard():
    key_expr = request.args.get("key", "row.score")
    rows = load_rows()
    # 排序键表达式整体由请求参数提供
    rows.sort(key=lambda row: eval(key_expr), reverse=True)
    return jsonify([r.name for r in rows[:10]])
'''
P.append({
    "pid": "95-03", "lang": "Python", "cwe": "CWE-95",
    "anchor": "非 94 因为 sink 是求值器（eval）而非代码生成执行（如拼代码写文件再 include/require）——"
              "按 MITRE 4.20 映射惯例按 sink 归类、更具体 Variant 优先，拼接与否不影响 95 定位；"
              "非 78 因为无 OS 命令面。",
    "safe_anchor": "防御为何不可旁路：排序键只能是 KEY_FIELDS 白名单中的属性名，经 attrgetter 取值；"
                   "表达式字符串根本不进入任何求值器。",
    "oracle_vuln": [
        (r'key_expr = request\.args\.get', "source：排序键表达式来自请求参数"),
        (r'eval\(key_expr\)', "sink：整表达式直进 eval"),
    ],
    "oracle_safe": [
        (r'KEY_FIELDS', "防御：字段白名单"),
        (r'attrgetter', "受控取值器，替代字符串求值"),
    ],
    "vuln_code": _code,
    "safe_code": '''from operator import attrgetter
from flask import Flask, request, jsonify

app = Flask(__name__)
KEY_FIELDS = {"score", "timestamp", "name"}

@app.route("/leaderboard")
def leaderboard():
    key = request.args.get("key", "score")
    if key not in KEY_FIELDS:
        return "bad key", 400
    rows = load_rows()
    rows.sort(key=attrgetter(key), reverse=True)
    return jsonify([r.name for r in rows[:10]])
''',
})

# ---------------- 95-04 PHP：请求参数整体进 eval ----------------
_code = '''<?php
// api/segment.php
$segment = $_GET['segment'] ?? 'true';
$users = load_users();
$matched = [];
foreach ($users as $u) {
    // 分母：$segment 是完整 PHP 表达式，营销后台租户可控
    if (eval("return {$segment};")) {
        $matched[] = $u['id'];
    }
}
header('Content-Type: application/json');
echo json_encode(['matched' => count($matched)]);
'''
P.append({
    "pid": "95-04", "lang": "PHP", "cwe": "CWE-95",
    "anchor": "非 94 因为 segment 整体（连同 return 前缀的模板语义）构成 eval 的完整代码文本、用户数据即代码本身，"
              "不存在'可信代码骨架+拼接'结构按项目判据归 95；非 78 因为目标是 PHP 求值器；"
              "注：return 前缀为模板固定语，若与用户数据有反转拼接关系需复核 94 边界。",
    "safe_anchor": "防御为何不可旁路：条件编译为 {field,op,value} 数组，解释器仅支持 in/gt/eq 三算子且字段走静态表；"
                   "eval 已从代码中完全移除，无求值路径可进入。",
    "oracle_vuln": [
        (r"\$_GET\['segment'\]", "source：请求参数"),
        (r'eval\("return \{\$segment\};"\)', "sink：用户表达式进 eval 求值"),
    ],
    "oracle_safe": [
        (r'function evalCondition', "防御：受限解释器"),
        (r'\$ALLOWED_OPS', "算子白名单"),
        (r'\$ALLOWED_FIELDS', "字段白名单"),
    ],
    "vuln_code": _code,
    "safe_code": '''<?php
// api/segment.php
$ALLOWED_OPS = ['in' => fn($a, $b) => in_array($a, $b),
                'gt' => fn($a, $b) => $a > $b,
                'eq' => fn($a, $b) => $a == $b];
$ALLOWED_FIELDS = ['vip', 'spend', 'age'];

function evalCondition(array $cond, array $u): bool {
    global $ALLOWED_OPS, $ALLOWED_FIELDS;
    if (!isset($ALLOWED_OPS[$cond['op']]) || !in_array($cond['field'], $ALLOWED_FIELDS, true)) {
        return false;
    }
    return ($ALLOWED_OPS[$cond['op']])($u[$cond['field']], $cond['value']);
}

$segment = $_GET['segment'] ?? [];
$cond = is_array($segment) ? $segment : [];
$users = load_users();
$matched = [];
foreach ($users as $u) {
    if (evalCondition($cond, $u)) {
        $matched[] = $u['id'];
    }
}
header('Content-Type: application/json');
echo json_encode(['matched' => count($matched)]);
''',
})

# ---------------- 95-05 Python：compile+config 完整表达式 ----------------
_code = '''import configparser

def alert_threshold_from_config():
    cp = configparser.ConfigParser()
    cp.read("alerts.ini")
    # ALERT_EXPRESSION 由配置中心下发，租户可编辑
    expr = cp.get("alert", "expression")
    code = compile(expr, "<alert>", "eval")
    return bool(eval(code, {"__builtins__": {}}, {"cpu": cpu_load(), "mem": mem_use()}))

def cpu_load():
    return read_sensor("cpu")

def mem_use():
    return read_sensor("mem")

def read_sensor(name):
    return SENSORS.get(name, 0.0)

SENSORS = {"cpu": 0.4, "mem": 0.6}
'''
P.append({
    "pid": "95-05", "lang": "Python", "cwe": "CWE-95",
    "anchor": "非 94 因为 expr 整体是 eval 的求值对象而非被拼进生成代码；compile 仅改变求值准备方式，"
              "不改变'整表达式直进参数位'的 95 定位；非 1336 因为无模板引擎。",
    "safe_anchor": "防御为何不可旁路：AST 白名单遍历 + 名字空间只含传感器值且 __builtins__ 为空，"
                   "表达式里任何名字/属性/调用白名单外即 ValueError，双重闭合。",
    "oracle_vuln": [
        (r'cp\.get\("alert", "expression"\)', "source：配置中心可下发任意表达式"),
        (r'code = compile\(expr', "中跳：编译为代码对象"),
        (r'eval\(code', "sink：代码对象被求值"),
    ],
    "oracle_safe": [
        (r'ast\.parse\(expr, mode="eval"\)', "防御：AST 解析"),
        (r'ALLOWED_NODES', "节点白名单"),
        (r'"__builtins__": \{\}', "名字空间内置项为空"),
    ],
    "vuln_code": _code,
    "safe_code": '''import ast
import configparser

ALLOWED_NODES = (ast.BoolOp, ast.UnaryOp, ast.Compare, ast.Name, ast.Load, ast.Expression,
                 ast.Constant, ast.And, ast.Or, ast.Not,
                 ast.Gt, ast.Lt, ast.GtE, ast.LtE, ast.Eq)
ALLOWED_NAMES = {"cpu", "mem"}

def alert_threshold_from_config():
    cp = configparser.ConfigParser()
    cp.read("alerts.ini")
    expr = cp.get("alert", "expression")
    tree = ast.parse(expr, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_NODES):
            raise ValueError("node not allowed")
        if isinstance(node, ast.Name) and node.id not in ALLOWED_NAMES:
            raise ValueError("name not allowed")
    return bool(eval(compile(tree, "<alert>", "eval"),
                     {"__builtins__": {}}, {"cpu": cpu_load(), "mem": mem_use()}))

def cpu_load():
    return read_sensor("cpu")

def mem_use():
    return read_sensor("mem")

def read_sensor(name):
    return SENSORS.get(name, 0.0)

SENSORS = {"cpu": 0.4, "mem": 0.6}
''',
})

# ---------------- 95-06 Python：环境变量公式 ----------------
_code = '''import os

def compute_alert_rate(events, total):
    # 运维可在部署环境注入 ALERT_FORMULA，如 "events/total*100 > 5"
    formula = os.environ.get("ALERT_FORMULA", "events / total * 100 > 5")
    return bool(eval(formula, {"__builtins__": {}}, {"events": events, "total": total}))
'''
P.append({
    "pid": "95-06", "lang": "Python", "cwe": "CWE-95",
    "anchor": "非 918/601/78/94：环境变量是非 HTTP 通道但租户/CI 注入者可控（污点源枚举不能只看 HTTP），"
              "公式整体直进 eval 参数位归 95；非 94 因为无拼接生成结构。",
    "safe_anchor": "防御为何不可旁路：公式解析为受限 AST，节点仅四则/比较/名字/常数，名字空间仅 events/total；"
                   "环境变量最多导致解析失败，不存在求值逃逸面。",
    "oracle_vuln": [
        (r'os\.environ\.get\("ALERT_FORMULA"', "source：环境变量可被注入者控制"),
        (r'eval\(formula', "sink：整公式直进 eval"),
    ],
    "oracle_safe": [
        (r'ast\.parse\(formula, mode="eval"\)', "防御：AST 解析替代 eval"),
        (r'ALLOWED_NODES', "节点白名单（四则/比较）"),
    ],
    "vuln_code": _code,
    "safe_code": '''import ast
import operator
import os

ALLOWED_NODES = (ast.BinOp, ast.UnaryOp, ast.Compare, ast.Constant, ast.Name,
                 ast.Load, ast.Expression, ast.Add, ast.Sub, ast.Mult, ast.Div,
                 ast.Gt, ast.Lt, ast.GtE, ast.LtE, ast.Eq)
OPS = {ast.Add: operator.add, ast.Sub: operator.sub,
       ast.Mult: operator.mul, ast.Div: operator.truediv}
CMP = {ast.Gt: operator.gt, ast.Lt: operator.lt,
       ast.GtE: operator.ge, ast.LtE: operator.le, ast.Eq: operator.eq}

def compute_alert_rate(events, total):
    formula = os.environ.get("ALERT_FORMULA", "events / total * 100 > 5")
    tree = ast.parse(formula, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_NODES):
            raise ValueError("node not allowed")

    def ev(n):
        if isinstance(n, ast.BinOp):
            return OPS[type(n.op)](ev(n.left), ev(n.right))
        if isinstance(n, ast.Compare):
            return CMP[type(n.ops[0])](ev(n.left), ev(n.comparators[0]))
        if isinstance(n, ast.Constant):
            return n.value
        if isinstance(n, ast.Name):
            return {"events": events, "total": total}[n.id]
        raise ValueError("bad node")

    return bool(ev(tree.body))
''',
})

# ---------------- 95-07 Node：new Function 谓词 ----------------
_code = '''const express = require("express");
const app = express();
app.use(express.json());

app.post("/filters/preview", (req, res) => {
  const { predicate } = req.body;      // 完整谓词体，如 "item.score > 10"
  const rows = req.body.rows || [];
  let fn;
  try {
    fn = new Function("item", `return (${predicate});`);
  } catch (e) {
    return res.status(400).json({ error: "bad predicate" });
  }
  const out = rows.filter(fn);
  res.json({ count: out.length });
});

app.listen(8080);
'''
P.append({
    "pid": "95-07", "lang": "JavaScript", "cwe": "CWE-95",
    "anchor": "非 94 因为 sink 是 Function 求值器，按 MITRE 4.20 映射惯例归更具体的 95 族；"
              "外层模板串仅加 return( ) 固定包装；非 78 因为无 shell。",
    "safe_anchor": "防御为何不可旁路：改为受限树解释器（op/field/value + OPS/FIELDS 白名单），"
                   "Function 构造器被完全移除，任何 JS 源码文本都无执行路径。",
    "oracle_vuln": [
        (r'const \{ predicate \} = req\.body', "source：请求体整段谓词"),
        (r'new Function\("item"', "sink：Function 构造器即 eval 语义"),
    ],
    "oracle_safe": [
        (r'const OPS =', "防御：算子白名单解释器"),
        (r'const FIELDS =', "字段白名单"),
        (r'OPS\[rule && rule\.op\]', "非白名单算子返回 undefined 即拒"),
    ],
    "vuln_code": _code,
    "safe_code": '''const express = require("express");
const app = express();
app.use(express.json());

const OPS = {
  gte: (a, b) => a >= b,
  lte: (a, b) => a <= b,
  eq: (a, b) => a === b,
};
const FIELDS = { score: i => i.score, age: i => i.age };

app.post("/filters/preview", (req, res) => {
  const { rule } = req.body;      // {op:"gte", field:"score", value:10}
  const rows = req.body.rows || [];
  const op = OPS[rule && rule.op];
  const field = FIELDS[rule && rule.field];
  if (!op || !field) return res.status(400).json({ error: "bad rule" });
  const out = rows.filter(item => op(field(item), rule.value));
  res.json({ count: out.length });
});

app.listen(8080);
''',
})

# ---------------- 95-08 Java：ScriptEngine.eval 规则 ----------------
_code = '''package rules;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

public class Eligibility {
    private final ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");

    public boolean check(String ruleExpr, int spend, boolean vip) throws Exception {
        // ruleExpr 由运营后台下发，如 "spend > 1000 && vip"
        engine.put("spend", spend);
        engine.put("vip", vip);
        Object out = engine.eval(ruleExpr);
        return Boolean.TRUE.equals(out);
    }
}
'''
P.append({
    "pid": "95-08", "lang": "Java", "cwe": "CWE-95",
    "anchor": "非 94 因为 ruleExpr 整体进 engine.eval 参数位；非 78 因为目标是脚本引擎；"
              "非 1336 因为不涉及模板渲染。",
    "safe_anchor": "防御为何不可旁路：规则编译为受限条件对象，字段/算子走静态枚举；ScriptEngine 从类路径移除，"
                   "脚本语法无从进入。",
    "oracle_vuln": [
        (r'String ruleExpr', "source：规则表达式外部下发"),
        (r'engine\.eval\(ruleExpr\)', "sink：ScriptEngine 直评"),
    ],
    "oracle_safe": [
        (r'record Condition', "防御：受限条件结构"),
        (r'enum Op \{ GT', "算子枚举"),
        (r'enum Field \{ spend', "字段枚举"),
    ],
    "vuln_code": _code,
    "safe_code": '''package rules;

public class Eligibility {

    enum Field { spend, vipScore }
    enum Op { GT, GTE, EQ }

    record Condition(Field field, Op op, int value) {}

    public boolean check(Condition c, int spend, boolean vip) {
        int actual = switch (c.field()) {
            case spend -> spend;
            case vipScore -> vip ? 1 : 0;
        };
        return switch (c.op()) {
            case GT -> actual > c.value();
            case GTE -> actual >= c.value();
            case EQ -> actual == c.value();
        };
    }
}
''',
})

# ---------------- 95-09 PHP：变量变量覆盖 ----------------
_code = '''<?php
// prefs/import.php
foreach ($_POST as $key => $value) {
    // 动态变量命名空间：键名成为 PHP 变量名并被赋值执行
    $$key = $value;
}
if (!empty(${'is_admin'})) {
    grant_admin();
}
save_prefs($_POST);
echo "imported";
'''
P.append({
    "pid": "95-09", "lang": "PHP", "cwe": "CWE-95",
    "anchor": "非 78/94 因为注入目标是 PHP 变量命名空间与脚本状态而非 OS 命令或独立求值器；"
              "按规格 95-06 归 95（动态代码/变量名构造执行语义），覆盖 $is_admin 等程序状态即完成利用。",
    "safe_anchor": "防御为何不可旁路：导入键与显式白名单比对，白名单外键被丢弃；变量变量语法被移除，"
                   "不存在动态命名空间写入路径。",
    "oracle_vuln": [
        (r'\$\$key = \$value', "sink：请求键直写变量命名空间"),
        (r'foreach \(\$_POST as \$key', "source：POST 键值对"),
    ],
    "oracle_safe": [
        (r'ALLOWED_PREFS', "防御：键白名单"),
        (r'continue;', "白名单外键丢弃"),
    ],
    "vuln_code": _code,
    "safe_code": '''<?php
// prefs/import.php
$ALLOWED_PREFS = ['theme', 'pagesize', 'lang'];

$prefs = [];
foreach ($_POST as $key => $value) {
    if (!in_array($key, $ALLOWED_PREFS, true)) {
        continue;
    }
    $prefs[$key] = $value;
}
if (($_SESSION['is_admin'] ?? false) === true) {
    grant_admin();
}
save_prefs($prefs);
echo "imported";
''',
})

# ---------------- 95-10 PHP：preg_replace /e 残留 ----------------
_code = '''<?php
// lib/bbcode.php（PHP 5.x 遗留）
function render_bbcode($text) {
    // /e 修饰符：替换串作为 PHP 代码求值，捕获组 $1 来自用户文本
    return preg_replace('/\\[b\\](.*?)\\[\\/b\\]/e', 'strtoupper("$1")', $text);
}

echo htmlspecialchars(render_bbcode($_POST['body']), ENT_QUOTES, 'UTF-8');
'''
P.append({
    "pid": "95-10", "lang": "PHP", "cwe": "CWE-95",
    "anchor": "非 94 因为被求值代码由 /e 修饰符的求值语义整体触发、用户数据经捕获组进入求值位，"
              "是 eval 族的动态求值残留（规格 95-06 归 95）；非 78 因为目标是 PHP 求值器；"
              "PHP 7 已移除 /e，此形态仅存于遗留代码面。",
    "safe_anchor": "防御为何不可旁路：preg_replace_callback 只把捕获组作为**数据**传给固定函数，"
                   "替换逻辑是编译期确定的回调，不存在字符串被求值的路径。",
    "oracle_vuln": [
        (r"/e'", "sink：/e 修饰符使替换串被 eval"),
        (r'strtoupper\("\$1"\)', "捕获组（用户数据）进入求值代码文本"),
    ],
    "oracle_safe": [
        (r'preg_replace_callback', "防御：回调替代 /e 求值"),
        (r'strtoupper\(\$m\[1\]\)', "捕获组仅作为数据传参"),
    ],
    "vuln_code": _code,
    "safe_code": '''<?php
// lib/bbcode.php
function render_bbcode($text) {
    return preg_replace_callback(
        '/\\[b\\](.*?)\\[\\/b\\]/',
        function ($m) { return strtoupper($m[1]); },
        $text
    );
}

echo htmlspecialchars(render_bbcode($_POST['body']), ENT_QUOTES, 'UTF-8');
''',
})

# ---------------- 95-11 Java：GroovyShell ----------------
_code = '''package pricing;

import groovy.lang.GroovyShell;

public class Pricing {
    public double discount(String ruleScript, double amount) {
        // ruleScript 由租户在定价控制台编辑，如 "amount > 1000 ? 0.2 : 0.05"
        GroovyShell shell = new GroovyShell();
        shell.setVariable("amount", amount);
        Object out = shell.evaluate(ruleScript);
        return ((Number) out).doubleValue();
    }
}
'''
P.append({
    "pid": "95-11", "lang": "Java", "cwe": "CWE-95",
    "anchor": "非 94 因为 ruleScript 整体进 shell.evaluate 参数位；非 78/1336 因为无 shell/模板语义；"
              "Groovy 是图灵完备脚本引擎，eval 语义完整归 95。",
    "safe_anchor": "防御为何不可旁路：SecureASTCustomizer 白名单语句/表达式/接收者类，禁用 methodCall 与 "
                   "import，编译期即拒绝任何逃逸语法；编译失败不产生可执行对象。",
    "oracle_vuln": [
        (r'String ruleScript', "source：租户可编辑脚本"),
        (r'shell\.evaluate\(ruleScript\)', "sink：Groovy 引擎整脚本求值"),
    ],
    "oracle_safe": [
        (r'SecureASTCustomizer', "防御：AST 级安全定制器"),
        (r'setDisallowedMethods', "方法调用黑名单（此处全禁）"),
        (r'setAllowedReceivers', "接收者类白名单"),
    ],
    "vuln_code": _code,
    "safe_code": '''package pricing;

import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.customizers.SecureASTCustomizer;

import java.util.List;

public class Pricing {
    public double discount(String ruleScript, double amount) {
        SecureASTCustomizer secure = new SecureASTCustomizer();
        secure.setDisallowedMethods(List.of("execute", "invokeMethod"));
        secure.setAllowedReceivers(List.of(java.lang.Math.class.getName(), java.lang.Double.class.getName()));
        secure.setIndirectImportCheckEnabled(true);
        CompilerConfiguration cfg = new CompilerConfiguration();
        cfg.addCompilationCustomizers(secure);
        GroovyShell shell = new GroovyShell(cfg);
        shell.setVariable("amount", amount);
        Object out = shell.evaluate(ruleScript);
        return ((Number) out).doubleValue();
    }
}
''',
})

# ---------------- 95-12 Python：pandas query ----------------
_code = '''import pandas as pd
from flask import Flask, request

app = Flask(__name__)

@app.route("/report")
def report():
    df = load_orders()
    expr = request.args.get("filter", "amount > 0")
    # engine="python"：表达式交给 Python 求值器（pandas 内部 eval 语义）
    out = df.query(expr, engine="python")
    return out.head(20).to_json(orient="records")
'''
P.append({
    "pid": "95-12", "lang": "Python", "cwe": "CWE-95",
    "anchor": "非 89/943 因为不是 SQL/NoSQL 查询语言注入，目标是 DataFrame 表达式求值器；"
              "非 94 因为 filter 整体作为查询表达式直进求值参数位（engine='python' 显式启用 Python 语义）归 95。",
    "safe_anchor": "防御为何不可旁路：改为列白名单 + 受限比较掩码构造（纯布尔向量运算），"
                   "query/eval 求值路径被移除，表达式字符串不再进入任何解释器。",
    "oracle_vuln": [
        (r'expr = request\.args\.get', "source：过滤表达式来自请求"),
        (r'df\.query\(expr, engine="python"\)', "sink：交给 Python 求值语义执行"),
    ],
    "oracle_safe": [
        (r'ALLOWED_COLS', "防御：列白名单"),
        (r'def build_mask', "受限掩码构造（纯布尔运算）"),
        (r'df\[mask\]', "布尔向量过滤，query/eval 路径已移除"),
    ],
    "vuln_code": _code,
    "safe_code": '''import operator
from flask import Flask, request

app = Flask(__name__)
ALLOWED_COLS = {"amount", "qty"}
CMP = {">": operator.gt, "<": operator.lt, ">=": operator.ge, "==": operator.eq}

def build_mask(df, col, op, value):
    if col not in ALLOWED_COLS or op not in CMP:
        raise ValueError("bad filter")
    return CMP[op](df[col], value)

@app.route("/report")
def report():
    df = load_orders()
    col = request.args.get("col", "amount")
    op = request.args.get("op", ">")
    value = request.args.get("value", "0")
    mask = build_mask(df, col, op, type(df[col].iloc[0])(value))
    out = df[mask]
    return out.head(20).to_json(orient="records")
''',
})

# ---------------- 95-13 Python：sympify ----------------
_code = '''import sympy
from flask import Flask, request

app = Flask(__name__)

@app.route("/integrate")
def integrate():
    expr_text = request.args.get("expr", "x**2")
    # sympy.sympify 内部经 eval 解析，可执行任意 Python 表达式
    expr = sympy.sympify(expr_text)
    x = sympy.Symbol("x")
    return str(sympy.integrate(expr, x))
'''
P.append({
    "pid": "95-13", "lang": "Python", "cwe": "CWE-95",
    "anchor": "非 94 因为 expr_text 整体作为求值输入传给 sympify 的解析求值路径（无拼接生成结构）；"
              "非 1336 因为无模板引擎；sympify 的解析语义即 eval 族，归 95。",
    "safe_anchor": "防御为何不可旁路：白名单 AST 节点（运算/名字/常数）+ 名字仅 x/常数，"
                   "在进入 sympy 前任何调用/属性/下标语法已被拒绝，sympify 只收到纯数学树。",
    "oracle_vuln": [
        (r'expr_text = request\.args\.get', "source：请求参数"),
        (r'sympy\.sympify\(expr_text\)', "sink：sympify 内部 eval 语义解析执行"),
    ],
    "oracle_safe": [
        (r'ast\.parse\(expr_text, mode="eval"\)', "防御：AST 白名单预检"),
        (r'ALLOWED_NODES', "节点白名单"),
        (r'ValueError', "越界语法拒绝"),
    ],
    "vuln_code": _code,
    "safe_code": '''import ast
import sympy
from flask import Flask, request

app = Flask(__name__)
ALLOWED_NODES = (ast.BinOp, ast.UnaryOp, ast.Constant, ast.Name, ast.Load, ast.Expression,
                 ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Pow, ast.USub, ast.UAdd)

@app.route("/integrate")
def integrate():
    expr_text = request.args.get("expr", "x**2")
    tree = ast.parse(expr_text, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_NODES):
            raise ValueError("syntax not allowed")
        if isinstance(node, ast.Name) and node.id != "x":
            raise ValueError("symbol not allowed")
    expr = sympy.sympify(expr_text)
    x = sympy.Symbol("x")
    return str(sympy.integrate(expr, x))
''',
})

# ---------------- 95-14 Ruby：eval 公式 ----------------
_code = '''require 'sinatra'

post '/reports/pivot' do
  rows = JSON.parse(request.body.read)
  formula = params['formula'] || 'x * 2'
  # formula 是完整 Ruby 表达式，报表定制功能直通 eval
  out = rows.map { |x| eval(formula) }
  { values: out }.to_json
end
'''
P.append({
    "pid": "95-14", "lang": "Ruby", "cwe": "CWE-95",
    "anchor": "非 78/94 因为注入目标是 Ruby 求值器，formula 整体直进 eval 参数位；"
              "非 1336 因为无模板渲染。",
    "safe_anchor": "防御为何不可旁路：改为公式白名单（倍率/字段枚举），eval 从路径中移除；"
                   "输入只能选择受控计算，无法携带任何 Ruby 语法。",
    "oracle_vuln": [
        (r"params\['formula'\]", "source：请求参数"),
        (r'eval\(formula\)', "sink：整表达式直进 eval"),
    ],
    "oracle_safe": [
        (r'ALLOWED_FORMULAS = \{', "防御：公式白名单"),
        (r"halt 400, 'bad formula'", "白名单外公式拒绝"),
    ],
    "vuln_code": _code,
    "safe_code": '''require 'sinatra'
require 'json'

ALLOWED_FORMULAS = { 'double' => ->(x) { x * 2 },
                     'vat'    => ->(x) { x * 1.2 },
                     'half'   => ->(x) { x / 2.0 } }.freeze

post '/reports/pivot' do
  rows = JSON.parse(request.body.read)
  formula = params['formula'] || 'double'
  fn = ALLOWED_FORMULAS[formula]
  halt 400, 'bad formula' unless fn
  out = rows.map { |x| fn.call(x.to_f) }
  { values: out }.to_json
end
''',
})

# ---------------- 95-15 Python：GraphQL 自定义标量表达式 ----------------
_code = '''from flask import Flask, request

app = Flask(__name__)

@app.route("/rule/engine", methods=["POST"])
def rule_engine():
    body = request.get_json()
    rule = body.get("rule", "amount < 100")   # 自定义标量：整段表达式
    ctx = body.get("ctx", {})
    # 规则引擎 v1：表达式直通 eval，名字空间白名单仅限业务字段
    hit = bool(eval(rule, {"__builtins__": {}}, ctx))
    return {"hit": hit}
'''
P.append({
    "pid": "95-15", "lang": "Python", "cwe": "CWE-95",
    "anchor": "非 94 因为 rule 是完整表达式直进 eval 参数位，无拼接生成结构；非 78 因为无 OS 命令面；"
              "'名字空间白名单'只是伪防御（限的是名字，限不了语法），本质仍是 95。",
    "safe_anchor": "防御为何不可旁路：AST 节点白名单 + 名字白名单 + 常数折叠校验三层；"
                   "任何 Call/Import/Attribute/下标语法在解析层即 ValueError，eval 收到的只是预校验树编译结果。",
    "oracle_vuln": [
        (r'rule = body\.get\("rule"', "source：请求体规则标量"),
        (r'bool\(eval\(rule', "sink：整表达式直进 eval（名字空间白名单是伪防御）"),
    ],
    "oracle_safe": [
        (r'ALLOWED_NODES', "防御：节点白名单"),
        (r'ALLOWED_NAMES', "名字白名单"),
        (r'ast\.parse\(rule, mode="eval"\)', "求值前强制 AST 预检"),
    ],
    "vuln_code": _code,
    "safe_code": '''import ast
from flask import Flask, request

app = Flask(__name__)
ALLOWED_NODES = (ast.BoolOp, ast.UnaryOp, ast.Compare, ast.Name, ast.Load, ast.Expression,
                 ast.Constant, ast.And, ast.Or, ast.Not,
                 ast.Gt, ast.Lt, ast.GtE, ast.LtE, ast.Eq)
ALLOWED_NAMES = {"amount", "vip", "region", "qty"}

@app.route("/rule/engine", methods=["POST"])
def rule_engine():
    body = request.get_json()
    rule = body.get("rule", "amount < 100")
    ctx = {k: v for k, v in body.get("ctx", {}).items() if k in ALLOWED_NAMES}
    tree = ast.parse(rule, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_NODES):
            raise ValueError("syntax not allowed")
        if isinstance(node, ast.Name) and node.id not in ALLOWED_NAMES:
            raise ValueError("name not allowed")
    hit = bool(eval(compile(tree, "<rule>", "eval"), {"__builtins__": {}}, ctx))
    return {"hit": hit}
''',
})

if __name__ == "__main__":
    made, failed = emit("CWE-95", P)
    print(f"95: made {len(made)} failed {len(failed)}")
    for pid, errs in failed:
        print("  FAIL", pid, errs)
    (Path(__file__).resolve().parents[1] / "corpus/diffpair_wave1/wave2_pairs" / "_index_95.md") \
        .write_text("\n".join(write_index("CWE-95", made)) + "\n", encoding="utf-8")
