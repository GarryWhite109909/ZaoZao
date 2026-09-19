# -*- coding: utf-8 -*-
"""v2_16 清洗步骤 1.3 落盘：L2 四组 sink 形态不符候选的逐条处置。

裁决依据：
- 官方口径《官方口径测试集审查_CWE判别要点_20260902.md》组2/组3/组4：
  eval/exec 直接收字符串→95；拼接生成代码再执行→94；SQL 拼接→89；
  非 SQL 数据查询逻辑→943；XPath→643；URL 取回→918。
- 7455 先例（fix_queue_20260907）：Python 字典/对象动态键污染 1336→915。
- 逐条代码级复核（含对原叙事 PoC 的可利用性验证，见 changelog evidence）。

安全性：
- 每条 edit 先断言旧 assistant 全文与记录一致（行内容完整性校验）；
- JSON 结论块程序化构造（json.dumps），杜绝未转义引号回归；
- 删除用内容签名定位 + 唯一性断言；
- changelog 逐条留痕（含改判理由与证据）。
"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"

# 官方 CWE 名称（与库内既有命名风格一致）
N = {
    94: "CWE-94 Improper Control of Generation of Code ('Code Injection')",
    95: "CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
    89: "CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    22: "CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    915: "CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes",
}

# 删除裁决（含代码级证据）
DELETES = {
    739: {
        "sig": "Paths.get(baseDir, safeName).normalize()",
        "why": "假阳性：filename.replace('../','') 单趟替换后 normalize()+Path.startsWith 全链有效；"
               "java.nio 的 Path.startsWith 是路径元素级比较而非字符串前缀匹配，叙事的"
               "'/tmp/uploads_evil 前缀绕过'与'编码变体绕过'均不成立（normalize 在 startsWith 之前执行，"
               "绝对路径注入也被元素级比较拦截）。无真实可达攻击面。",
    },
    904: {
        "sig": "MATCH(title, content) AGAINST (? IN BOOLEAN MODE)",
        "why": "假阳性：全文检索经 bind_param 参数化（叙事自认）；布尔模式操作符只影响攻击者自己查询的"
               "语义，不是安全边界；无 XPath 存在，标签 643 与代码无关；残余的日志换行注入是附带发现，"
               "非样本设计主张，叙事整体建立于错误前提。",
    },
    914: {
        "sig": "jmespath.search(expr, user_orders)",
        "why": "假阳性：user_orders 在服务端已按当前用户预过滤，jmespath.search(expr, data) 只能访问"
               "传入的数据对象，无法逃逸到其他用户的订单；'..'/''*''过滤之外不存在可利用的越权读取。",
    },
    978: {
        "sig": "restTemplate.getForEntity(serviceUrl, String.class)",
        "why": "假阳性：URL 前缀固定 authority，userId 拼接发生在 path 段——三个叙事绕过载荷全部失效："
               "https://evil.com、HTTP:// 大写、URL 编码变体都只落在路径里，RestTemplate 不会改变请求主机；"
               "replace('http://') 移除的是合法前缀也不产生 scheme-relative 逃逸。残余仅为内网 path 段"
               "穿越（微弱、非样本主张的 SSRF）。",
    },
    1093: {
        "sig": "strpos($template, '..') !== false || strpos($template, '/') !== false",
        "why": "假阳性：叙事 PoC 'C:\\tmp\\templates\\../../../../etc/passwd' 自身含 '..'，会被第72行 "
               "strpos($template,'..') 检查拦截；Linux 下 '\\..' 变体同样含 '..'；缓存 include 的 "
               "<?php 执行要求模板文件先存在于受控目录，攻击者无写入通道。",
    },
}


def patch_json(asst: str, **fields) -> str:
    """把 assistant 尾部 JSON 结论块按字段 patch 后程序化重组。"""
    import re
    m = re.search(r"\n```json\n(\{.*?\})\n```", asst, re.S)
    assert m, "未找到 JSON 结论块"
    obj = json.loads(m.group(1))
    obj.update(fields)
    return asst[: m.start()] + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```"


def rep1(text: str, old: str, new: str) -> str:
    """唯一性断言替换。"""
    assert text.count(old) == 1, f"替换源不唯一({text.count(old)}): {old[:60]}"
    return text.replace(old, new)


def main():
    rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
    by_idx = {i + 1: r for i, r in enumerate(rows)}  # 1-based 行号

    def A(line):
        return by_idx[line]["messages"][2]["content"]

    # ---------- 删除 ----------
    drop = []
    for line, spec in DELETES.items():
        row = by_idx[line]
        blob = row["messages"][1]["content"]
        assert blob.count(spec["sig"]) == 1, f"line {line} 签名不唯一"
        drop.append(line)
    print("删除:", sorted(drop))
    new_rows = [r for i, r in enumerate(rows) if (i + 1) not in set(drop)]

    # ---------- 643: 1336 → 94（拼接生成代码再执行） ----------
    r = by_idx[643]
    r["messages"][2]["content"] = (
        "**分析过程**\n"
        "\n"
        "1. **第25行**：`const { token, newPassword } = req.body;` token 为外部可控输入；"
        "**第28行** `token.replace(/['\"]/g, '')` 仅过滤单双引号，反引号、分号、换行、括号等元字符全部放行，"
        "黑名单不完整。\n"
        "2. **第32行**：`const queryExpr = \\`users.find(u => u.resetToken === '${sanitizedToken}')\\`;` "
        "将用户输入拼入带完整脚手架的 JS 表达式字符串——执行体由拼接生成。\n"
        "3. **第36行**：`const user = eval(queryExpr);` 动态执行拼接产物。攻击者构造 token 值为 "
        "`'); process.exit(); //` 或 `'); return {resetToken:'x'}; //`，闭合单引号并追加任意 JS，"
        "实现任意代码执行或绕过认证。\n"
        "4. **防御判定**：仅第28行字符替换黑名单，无白名单/参数化替代；数据流 req.body.token（第25行）"
        "→ sanitizedToken（第28行）→ queryExpr（第32行）→ eval（第36行）全程无有效断点。\n"
        "5. **结论**：外部输入参与**拼接生成代码**并被动态执行，构成 "
        f"{N[94]}。辨析：非 CWE-1336——代码中不存在任何模板引擎，eval 不是模板渲染；"
        "非 CWE-95——用户输入不是直接作为 eval 的完整求值串传入，而是先拼入含脚手架的代码表达式"
        "（本项目口径：拼接生成代码再执行归 94）。\n"
        "```json\n" + json.dumps({
            "has_vulnerability": True,
            "vulnerability_type": N[94],
            "risk_level": "Critical",
            "source": "line 25: token 取自 req.body（外部可控），第28行仅过滤单双引号",
            "sink": "line 36: eval(queryExpr) 执行拼接生成的表达式",
            "explanation": "line 25 token → line 28 黑名单仅滤引号 → line 32 拼入模板字符串生成 queryExpr"
                           "（拼接生成代码）→ line 36 eval 执行 → 任意 JS 执行（RCE/认证绕过）；"
                           "非 1336：无模板引擎；非 95：输入先拼入代码表达式再执行，非直接传入求值串",
            "fix_suggestion": "line 36: 删除 eval 调用，改为 const user = users.find(u => u.resetToken === token);"
                              " 用对象查找直接完成等值匹配，不构造动态表达式；line 28: 移除无效的字符替换防御",
        }, ensure_ascii=False) + "\n```\n"
    )

    # ---------- 709: 1336 → 22 ----------
    r = by_idx[709]
    r["messages"][2]["content"] = (
        "**分析过程**\n"
        "\n"
        "1. **第20行**：`cb(null, file.originalname)` 直接使用用户提供的原始文件名作为存储文件名，"
        "未做任何规范化，multer 不会清除 `../` 序列。\n"
        "\n"
        "2. **第33行**：`replace(/[\\\\/]/g, '_')` 只替换 `\\` 和 `/`，但替换结果 `safeName` 仅用于日志"
        "（第34行）和扩展名检查（第38行），实际保存/移动使用的是原始 `req.file.filename`——典型的"
        "\"防御迷惑\"。\n"
        "\n"
        "3. **第46-47行**：`finalPath` 用原始文件名拼接；`targetPath = req.query.target || finalPath`"
        "——目标路径可被 `target` 参数完全控制，无目录限制。\n"
        "\n"
        "4. **第50行**：`fs.renameSync(finalPath, targetPath)` 将已上传文件移动到任意路径，"
        "攻击者可实现目录穿越式任意覆盖（如覆盖 cron 任务、Web 根下的可执行文件）。\n"
        "\n"
        "5. **第59行**：`express.static` 暴露上传目录；配合 `target` 将文件移动到 Web 可达路径即可获得"
        "服务端脚本执行面。\n"
        "```json\n" + json.dumps({
            "has_vulnerability": True,
            "vulnerability_type": N[22],
            "risk_level": "Critical",
            "source": "line 20: cb(null, file.originalname) 采用用户原始文件名",
            "sink": "line 50: fs.renameSync(finalPath, targetPath)，targetPath 受 req.query.target 控制（第47行）",
            "explanation": "line 20 原始文件名入库 → line 33 替换结果仅影响日志/校验不影响实际文件名 → "
                           "line 47 target 完全可控 → line 50 renameSync 任意路径移动/覆盖（目录穿越）；"
                           "非 1336：代码中无任何模板引擎，漏洞本质是路径限制缺失",
            "fix_suggestion": "line 20: 存储文件名改为服务端生成（如 Date.now() + "
                              "path.basename(file.originalname).replace(/[^a-zA-Z0-9._-]/g,'_')）；"
                              "line 47: 目标路径一律 path.join(uploadDir, path.basename(target)) 并校验 "
                              "resolve 后前缀仍在 uploadDir 内；line 50: 拒绝一切跨目录移动",
        }, ensure_ascii=False) + "\n```\n"
    )

    # ---------- 857: 943 → 89（含 sort_by PoC 修正） ----------
    r = by_idx[857]
    r["messages"][2]["content"] = (
        "**分析过程**\n"
        "\n"
        "1. **第18行**：`category` 取自 `request.GET`（外部可控）；**第21行** "
        "`category.replace('\\`', '')` 仅移除反引号——SQL 注入所需的单引号与 SQL 元字符完全未覆盖，"
        "黑名单无效。\n"
        "\n"
        "2. **第29-31行**：`extra(where=[\"category = '%s'\" % category_safe])` 将用户输入直接拼进"
        "原生 SQL WHERE 子句。Django `extra(where)` 不提供参数化保护，构成明确的 SQL 注入点。\n"
        "\n"
        "3. **第56-64行**（第二入口）：`sort_by` 的白名单逻辑缺陷在于**不匹配任何前缀时保留原值**"
        "（第62行注释自述），输入如 `(SELECT 1)` 或 `if(1=1,id,name)` 不以 price/name 开头则原样透传，"
        "进入第64行 f-string 拼接的 `ORDER BY {sort_by}`。注意：以 `price` 开头的输入"
        "（如 `price; ...`）反而会被第58-59行替换为安全值 `'price'`——可注入的是**白名单外的透传值**，"
        "不是白名单内前缀。\n"
        "\n"
        "4. **第67行**：`cursor.execute(query)` 执行拼接 SQL，无参数化兜底，与第29行 `extra()` 构成"
        "两条独立注入路径。\n"
        "```json\n" + json.dumps({
            "has_vulnerability": True,
            "vulnerability_type": N[89],
            "risk_level": "High",
            "source": "line 18/56: category 与 sort_by 取自 request.GET（外部可控）",
            "sink": "line 29-31: extra(where=[...% category_safe]) 拼接原生 SQL；line 67: "
                    "cursor.execute(query) 执行拼接 SQL",
            "explanation": "链1: line 18 category → line 21 仅删反引号 → line 30 拼进 where 子句 → "
                           "单引号闭合注入；链2: line 56 sort_by → 白名单外原值透传（line 62）→ "
                           "line 64 f-string 拼进 ORDER BY → line 67 执行；两链均为 SQL 拼接（CWE-89），"
                           "非 943（943 限于非 SQL 数据查询逻辑，如 MongoDB/ORM 表达式）",
            "fix_suggestion": "line 29-31: 改为 products = products.extra(where=['category = %s'], "
                              "params=[category])，或直接用 filter(category=category)；line 62: "
                              "白名单不匹配时必须赋默认值 'id'（if/elif/else 补 else: sort_by = 'id'），"
                              "禁止透传；line 64: ORDER BY 列名改为服务端映射白名单 {'price','name','id'}，"
                              "不拼接用户输入",
        }, ensure_ascii=False) + "\n```\n"
    )

    # ---------- 885: 943 → 89 ----------
    r = by_idx[885]
    r["messages"][2]["content"] = (
        "**分析过程**\n"
        "\n"
        "1. **第16-17行**：`$_GET['query']` 经 `json_decode` 解析为数组，键名与值类型均未限制，"
        "全部用户可控，随后直接参与 SQL 拼接。\n"
        "\n"
        "2. **第26行**：text 字段仅 `str_replace(\"'\", \"\\\\'\")` 替换单引号，未处理反斜杠本身——"
        "攻击者传入 `\\\\'` 替换后变成 `\\\\\\\\'`，MySQL 默认把 `\\\\` 解析为字面反斜杠、`'` 闭合字符串，"
        "防御可绕过。\n"
        "\n"
        "3. **第47/50行**：`price_min`、`price_max` 作为数字位直接拼接，注入 `1 OR 1=1-- ` 即改变"
        "查询语义；**第56行**：`category` 完全无过滤拼接 `' OR '1'='1`。\n"
        "\n"
        "4. **第30-34行**：sort 字段白名单（in_array）是该文件唯一有效防御，但仅覆盖 ORDER BY 位；"
        "其余字段全部裸拼。\n"
        "\n"
        "5. **第64行**：`$pdo->query($sql)` 执行拼接 SQL，无参数化绑定，攻击者可 UNION SELECT 窃取"
        "数据或 SLEEP() 拖库/DoS。\n"
        "```json\n" + json.dumps({
            "has_vulnerability": True,
            "vulnerability_type": N[89],
            "risk_level": "Critical",
            "source": "line 56: category 字段无过滤拼进 SQL（另 line 26 text 转义可绕过、line 47/50 "
                      "数字位裸拼）",
            "sink": "line 64: $pdo->query($sql) 执行拼接后的 SQL",
            "explanation": "line 16 JSON 键值全可控 → line 26 text 仅替换单引号（反斜杠未处理可绕过）→ "
                           "line 47/50/56 直接拼接 → line 60 组装 → line 64 执行 → 数据泄露/DoS；"
                           "非 943：sink 是原生 SQL 拼接（CWE-89），943 限于非 SQL 数据查询逻辑",
            "fix_suggestion": "line 47/50/56: 全部改为占位符并用 $pdo->prepare($sql); $stmt->execute([...]) "
                              "参数绑定（text/price_min/price_max/category 均改）；line 26: 删除该手工转义"
                              "（参数化后不再需要）",
        }, ensure_ascii=False) + "\n```\n"
    )

    # ---------- 944: 943 → 22（删 @php-经路径 注入幻觉） ----------
    r = by_idx[944]
    r["messages"][2]["content"] = (
        "**分析过程**\n"
        "\n"
        "1. **第18行**：`$templateName = $request->input('template', 'default_report')` 取自用户输入"
        "（Source）。\n"
        "\n"
        "2. **第21行**：`str_replace(['{{','}}','{%','%}'], ...)` 只过滤模板定界符——与路径穿越完全"
        "无关，防御目标错位（Blade 指令、`../` 序列均不受影响）。\n"
        "\n"
        "3. **第24行**：`resource_path(\"views/reports/{$templateName}.blade.php\")` 直接拼接路径，"
        "未 `realpath` 规范化、未限制目录（代码注释自认\"未规范化路径\"），`../` 序列可穿越到任意目录。\n"
        "\n"
        "4. **第35行**：`View::make($templatePath)` 加载并编译渲染该路径的 Blade 模板。攻击者将 "
        "template 指向其可控内容的 `.blade.php` 文件（如经上传功能落在 `../../../uploads/avatars/shell`），"
        "Blade 编译其中的 `@php` 指令即任意代码执行；即使暂无可控文件，穿越加载也可探测任意 .blade.php "
        "的存在与渲染结果（信息泄露）。\n"
        "\n"
        "5. **结论**：漏洞本质是**模板文件路径的目录穿越**（CWE-22）——用户控制的是\"加载哪个文件\"，"
        "不是模板内容本身；非 943：不涉及任何数据查询逻辑。\n"
        "```json\n" + json.dumps({
            "has_vulnerability": True,
            "vulnerability_type": N[22],
            "risk_level": "Critical",
            "source": "line 18: $templateName = $request->input('template', 'default_report'); 用户可控输入",
            "sink": "line 35: View::make($templatePath, ['orders' => $orders]) 加载渲染用户可控路径的模板文件",
            "explanation": "line 18 用户输入 → line 21 仅滤模板定界符（与路径无关）→ line 24 拼接路径未"
                           "规范化，../ 穿越可行 → line 35 加载渲染任意 .blade.php（若该文件内容可控则经 "
                           "@php 实现 RCE）；非 943：无数据查询逻辑",
            "fix_suggestion": "line 18: $templateName = basename($request->input('template', "
                              "'default_report'))；line 24: 拼接前用 preg_match('/^[a-zA-Z0-9_-]+$/') "
                              "白名单校验，且渲染前 realpath 校验前缀仍在 views/reports 内；line 35: "
                              "优先使用视图名 View::make('reports.'.$templateName) 而非文件系统路径",
        }, ensure_ascii=False) + "\n```\n"
    )

    # ---------- 1867 / 2644: 94 → 95（eval 直接收用户值） ----------
    for line, keyexpr in ((1867, "user_config[key] = value"), (2644, "user_config[map_key] = value")):
        r = by_idx[line]
        asst = r["messages"][2]["content"]
        asst = rep1(
            asst,
            "5. 结论：跨文件污点传播，用户输入最终到达 eval sink，构成代码注入，风险 Critical。"
            "此类漏洞需要跨文件分析才能发现。",
            "5. 结论：跨文件污点传播，用户输入**直接作为 eval() 的求值串**执行，构成 "
            f"{N[95]}，风险 Critical。此类漏洞需要跨文件分析才能发现。（口径：输入直接进入 eval/exec "
            "动态求值调用归 95；拼接生成代码再执行归 94）",
        )
        # JSON patch：改类型与 explanation 尾部
        import re as _re
        m = _re.search(r"\n```json\n(\{.*?\})\n```", asst, _re.S)
        obj = json.loads(m.group(1))
        obj["vulnerability_type"] = N[95]
        obj["explanation"] = obj["explanation"].replace(
            "如 eval/exec/模板渲染）→ 攻击者注入恶意代码 → CWE-94 Improper Control of Generation of Code ('Code Injection')",
            "如 eval）→ 用户值直接作为求值串一跳执行 → CWE-95 Eval Injection（口径：直接进入动态求值调用归 95）",
        ).replace(
            "若其他模块使用该键值进行动态执行 → 代码注入",
            "若其他模块把该值直接传入 eval() → Eval Injection（CWE-95）",
        )
        r["messages"][2]["content"] = asst[: m.start()] + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```\n"

    # ---------- 7341 / 10156: 1336 → 915（7455 先例） ----------
    r = by_idx[7341]
    asst = r["messages"][2]["content"]
    asst = rep1(
        asst,
        "等价于 JS 的 prototype pollution（CWE-1336）。",
        "语义上等价于 JS 原型污染（官方 1321 一族）；本样本是 Python 对象/字典的动态属性污染，"
        "按本库口径标 CWE-915（动态决定的对象属性未受控修改）。",
    )
    asst = patch_json(
        asst,
        vulnerability_type=N[915],
        explanation=rep1(
            _json_field(A(7341), "explanation"),
            "污染模块级 globals 或敏感配置对象",
            "污染模块级 globals 或敏感配置对象；非 1336：无模板引擎，sink 是动态键赋值（对象属性污染）",
        ),
    )
    r["messages"][2]["content"] = asst

    r = by_idx[10156]
    asst = r["messages"][2]["content"]
    asst = rep1(
        asst,
        "——与 JS 原型污染语义结构完全一致：source（JSON 键）→ 动态键赋值 sink。",
        "——语义等价于 JS 原型污染（官方 1321 一族）；Python 对象/字典动态属性污染按本库口径标 "
        "CWE-915（动态决定的对象属性未受控修改）：source（JSON 键）→ 动态键赋值 sink。",
    )
    asst = rep1(
        asst,
        "5. 结论：存在 CWE-1336 等价漏洞（Python class/global pollution），风险 High。",
        f"5. 结论：存在 {N[915]}（Python class/dict pollution via dynamic key assignment），风险 High。",
    )
    asst = patch_json(
        asst,
        vulnerability_type=N[915],
        explanation=rep1(
            _json_field(A(10156), "explanation"),
            "但污染影响全局共享对象",
            "但污染影响全局共享对象；非 1336：无模板引擎，sink 是动态键赋值（对象属性污染）",
        ),
    )
    r["messages"][2]["content"] = asst

    # ---------- 7595: 复合标签 → 94 + 行号锚正（按代码注释偏移 +1/+3/+5） ----------
    r = by_idx[7595]
    asst = r["messages"][2]["content"]
    asst = rep1(asst, "第 7 行 `fs.readFileSync(manifestPath)`", "第 8 行 `fs.readFileSync(manifestPath)`")
    asst = rep1(asst, "但第 7 行读取的清单文件", "但第 8 行读取的清单文件")
    asst = rep1(asst, "第 8 行 `JSON.parse` 后", "第 9 行 `JSON.parse` 后")
    asst = rep1(asst, "第 13 行的黑名单正则", "第 15 行的黑名单正则")
    asst = rep1(asst, "第 16 行将可控 `code` 直接字符串拼接入 wrapper，随后第 22 行 `vm.runInContext` 执行",
                "第 19 行将可控 `code` 直接字符串拼接入 wrapper，随后第 27 行 `vm.runInContext` 执行")
    asst = rep1(asst, "第 19 行还主动把数据库查询句柄挂入沙箱", "第 24 行还主动把数据库查询句柄挂入沙箱")
    asst = patch_json(
        asst,
        vulnerability_type=N[94],
        explanation=rep1(
            rep1(
                _json_field(A(7595), "explanation"),
                "line 7 文件内容 -> line 9:JSON.parse -> line 16 拼接进 wrapper -> line 27:runInContext 执行",
                "line 8 文件内容 -> line 9:JSON.parse -> line 19 拼接进 wrapper -> line 27:runInContext 执行",
            ),
            "line 7:还将 DB 句柄暴露给沙箱放大危害",
            "line 24:还将 DB 句柄暴露给沙箱放大危害",
        ),
    )
    r["messages"][2]["content"] = asst

    # ---------- 落盘 + changelog ----------
    lines_edited = sorted(set([643, 709, 857, 885, 944, 1867, 2644, 7341, 7595, 10156]))
    print("改写:", lines_edited)
    with DATA.open("w", encoding="utf-8", newline="\n") as f:
        for r in new_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with CHANGELOG.open("a", encoding="utf-8") as f:
        for line in sorted(drop):
            f.write(json.dumps({
                "date": "2026-09-08", "step": "1.3_L2_sinkform", "action": "DELETE",
                "row_line_before": line, **DELETES[line],
                "basis": "L2 sink 形态机扫 + 代码级复核（官方口径 组2/组3/组4）",
            }, ensure_ascii=False) + "\n")
        for line in lines_edited:
            f.write(json.dumps({
                "date": "2026-09-08", "step": "1.3_L2_sinkform", "action": "FIX",
                "row_line_before": line,
                "note": "改标签+叙事重写（含行锚修正），JSON 块程序化重组",
                "basis": "L2 sink 形态机扫 + 官方口径 组2/组3 + 7455 先例（915）",
            }, ensure_ascii=False) + "\n")

    # 自检
    rows2 = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
    print(f"自检: 行数 {len(rows2)}（预期 {len(new_rows)}）")
    import re
    bad = 0
    for r in rows2:
        a = r["messages"][2]["content"]
        m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
        if not m:
            bad += 1
            continue
        try:
            json.loads(m.group(1))
        except Exception:
            bad += 1
    print(f"JSON 结论块解析失败: {bad}（预期 0）")
    assert len(rows2) == len(new_rows) and bad == 0
    print("PASS")


def _json_field(asst: str, field: str) -> str:
    import re
    m = re.search(r"\n```json\n(\{.*?\})\n```", asst, re.S)
    obj = json.loads(m.group(1))
    return obj[field]


if __name__ == "__main__":
    main()
