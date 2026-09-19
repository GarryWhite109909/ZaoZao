# -*- coding: utf-8 -*-
"""v2_21：P0-3 精读裁决落库（5 条错标翻转）。

依据（全部经实跑复现，见 audit/_flip_anchors.txt 与执行记录）：
  3100 cpp   : pixelCount 校验未扣 12 字节头部 → 越界读     → CWE-125
  3124 go    : 前缀白名单未剔除 shell 元字符 + sh -c       → CWE-78
  3146 python: content 拼进 python -c 源码 + /exports/.. 逃逸 → CWE-94（伴生 CWE-22）
  4194 python: replace('../','') 被 ....// 绕过 + startswith 只比字符串 → CWE-22
  8022 python: render_template_string 拼模板源，escape 不处理 { } → CWE-1336

用法：python apply_v2_21_flip_20260914.py --dry-run | (无参写盘)
"""
import json, os, re, sys, hashlib

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune"
SRC = os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_20_candidate_20260914.jsonl")
DST = os.path.join(ROOT, "data", "final_train_chatml_alpha06_v2_21_candidate_20260914.jsonl")
SNAP = os.path.join(ROOT, "audit", "snapshot_v2_20_rows_before_flip_20260914.jsonl")
CHG = os.path.join(ROOT, "audit", "v2_21_flip_changelog_20260914.jsonl")
DRY = "--dry-run" in sys.argv

CODE = re.compile(r"```([a-zA-Z0-9_+#\-\.]*)[ \t]*\n(.*?)```", re.S)
J = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
KEYS = ["has_vulnerability", "vulnerability_type", "risk_level", "source", "sink",
        "explanation", "fix_suggestion"]

rows = [json.loads(l) for l in open(SRC, encoding="utf-8") if l.strip()]
print("SRC rows", len(rows), "sha", hashlib.sha256(open(SRC, "rb").read()).hexdigest()[:16])
IDX = {r["src_row"]: i for i, r in enumerate(rows)}


def blk(row):
    m = list(CODE.finditer(rows[IDX[row]]["messages"][1]["content"]))
    assert len(m) == 1, f"row {row} 期望单代码块，实得 {len(m)}"
    return m[0].group(2).split("\n")


def L(row, needle, occ=1):
    lines = blk(row)
    hits = [i for i, l in enumerate(lines, 1) if needle in l]
    assert len(hits) >= occ, f"row {row} 锚点未命中: {needle!r} -> {hits}"
    return hits[occ - 1]


# ---------------------------------------------------------------- 新增叙事（行号运行时计算，块内 1-based）
N = {}
N[3100] = f"""**分析过程**

1. **第{L(3100,'uint32_t pixelCount')}行（头部解析）**：`width`/`height`/`pixelCount` 三个 32 位字段直接从 `input` 的前 12 字节读出，此前的 `inputLen < 12` 只保证头部本身可读。

2. **第{L(3100,'pixelCount > inputLen / 3')}行（像素数校验）**：`pixelCount > inputLen / 3` 的意图是把输入长度换算成像素数上界，但**没有扣除 12 字节头部**。正确的不等式应为 `12 + 3 * pixelCount <= inputLen`，等价于 `pixelCount <= (inputLen - 12) / 3`；当前写法把头部占用的 12 字节也当成了像素数据空间。

3. **第{L(3100,'pixelCount > SIZE_MAX / 4')}行与第{L(3100,'height > pixelCount / width')}行**：前者防输出侧乘法溢出，后者校验宽高一致性，二者都不约束输入侧读取下标，无法弥补第 2 点的缺口。

4. **第{L(3100,'input[12 + srcIdx]')}–{L(3100,'input[14 + srcIdx]')}行（越界读）**：循环体内 `srcIdx = i * 3`，读取下标上界为 `14 + 3 * (pixelCount - 1) = 3 * pixelCount + 11`。取 `inputLen = 12` 时，第 2 点允许 `pixelCount = 4`，循环将读取 `input[12] … input[23]`，而缓冲区只有 12 字节——**越界读 12 字节**；对任意 `inputLen`，缺口恒为 `(3 * floor(inputLen / 3) + 12) - inputLen`，即 11–12 字节。写入侧 `buf` 按 `pixelCount * 4` 分配（第{L(3100,'outSize = static_cast')}行），写不越界，因此主判是读取侧。

5. **数据流**：`input`（第{L(3100,'decodePixelStream')}行入参，来自不可信字节流）→ 第{L(3100,'input[12 + srcIdx]')}–{L(3100,'input[14 + srcIdx]')}行的三处下标读取 → sink。存在完整 source→sink 路径且校验不覆盖，非 CWE-787 因为写侧容量与循环上界一致、无越界写；非 CWE-190 因为本题的乘法已用除法规避。

**结论**：输入长度校验与读取下界之间存在 12 字节的系统性缺口，攻击者只需提交一个 12 字节的合法头部即可触发越界读（可由 ASAN/valgrind 稳定复现），构成 CWE-125 Out-of-bounds Read。
"""

N[3124] = f"""**分析过程**

1. **第{L(3124,'req.TestCmd')}行（source）**：`TestCmd` 直接取自 HTTP 请求体的 `test_cmd` 字段，完全由调用方控制。`RepoURL`（第{L(3124,'HasPrefix(req.RepoURL')}行）与 `CommitID`（第{L(3124,'len(req.CommitID) != 40')}行）的白名单/格式校验确实成立，但它们只约束另两个字段，对 `TestCmd` 没有任何约束。

2. **第{L(3124,'isAllowedTestCmd(req.TestCmd)')}行（所谓防御）**：`isAllowedTestCmd` 只用 `strings.HasPrefix` 判断前缀是否属于 `go test` / `make test` / `npm test`（第{L(3124,'HasPrefix(cmd, prefix)')}行）。**前缀校验对 shell 元字符没有任何约束**——`go test; cat /etc/passwd`、`go test && curl attacker`、`go test $(id)` 均以 `go test` 开头，全部通过校验。

3. **第{L(3124,'sh')}行与第{L(3124,'cd /tmp/build-')}行（sink）**：命令被拼成 `cd /tmp/build-<CommitID> && <TestCmd>`，并通过第{L(3124,'exec.CommandContext')}行的 `sh -c` 字符串模式执行。`;` / `&&` / `|` / `$()` 在这里都会被 shell 解释为控制符，而不是字面量参数。

4. **可达性**：`CommitID` 校验通过与否不影响本路径——注入点在 `TestCmd` 一侧，`cd` 目标是否可注入与结论无关。故 `sh -c` 下 `go test; cat /etc/passwd` 会先执行 `go test`（可失败，但 `;` 不依赖前一条命令成功），随后执行 `cat /etc/passwd`，读取结果经第{L(3124,'test failed')}行的 `fmt.Sprintf` 原样回显给调用方。

5. **排除项**：非 CWE-77 因为注入面不是命令语言语法本身而是 shell 元字符分隔；非 CWE-88 因为 `TestCmd` 落在命令拼接位而非参数位。第{L(3124,'cmdArgs = []string')}行的 `git clone` 使用列表参数（第{L(3124,'exec.CommandContext(ctx, cmdArgs[0]')}行）是有效防御，但它保护的只是 clone 这一步，不能覆盖测试命令这一步。

**结论**：前缀白名单 + `sh -c` 拼接构成典型 OS Command Injection，攻击者可执行任意命令并读取回显，构成 CWE-78。
"""

N[3146] = f"""**分析过程**

1. **第{L(3146,"request.get_json")}行（source）**：`filename` 与 `content` 均取自 POST 请求体，攻击者完全可控。

2. **第{L(3146,'filename.replace(')}行（防御 1，路径）**：`str.replace` 替换的是**全部**非重叠出现，这一点比"只替换一次"要好；但对 `....//....//etc/passwd` 而言，替换后得到 `../../etc/passwd`（残留的 `.` 与 `/` 重新构成了 `../`）。第{L(3146,'safe_filename.startswith(')}行的前缀判定只是字符串比较，`/exports/../../etc/passwd` 满足该前缀，于是第{L(3146,'as f: f.write(')}行对规范化后的 `/etc/passwd` 进行写入。

3. **第{L(3146,'content')}行（防御 3，真正的失效点）**：`content` 被 f-string 直接拼进 `python -c` 的**源码**：`f.write('{{content}}')`。`subprocess` 使用参数列表（第{L(3146,'subprocess.run')}行）确实阻断了 shell 注入，但**参数内容是 Python 源码**，等于把注入点从 shell 层移到了解释器层。

4. **复现**：取 `content = "x') or __import__('os').system('id') or f.write('"`，生成的源码为
   `with open('/exports/../../etc/passwd', 'w') as f: f.write('x') or __import__('os').system('id') or f.write('')`
   —— `compile()` 通过（实跑无 SyntaxError），`or` 链的副作用会执行 `os.system('id')`。原文"语法错误→返回非零码"的判断不成立：构造合法表达式即可绕过。

5. **排除项**：非 CWE-78 因为没有 shell 参与；非 CWE-95 因为注入的不是 `eval` 的字符串而是一段完整生成的可执行源码；主判取 CWE-94 Code Injection，路径穿越（CWE-22，写侧）作为伴生向量在第 2 点记录。

**结论**：`python -c` 的源码拼接使攻击者获得任意代码执行，构成 CWE-94。
"""

N[4194] = f"""**分析过程**

1. **第{L(4194,'template_path = request.POST.get(')}行（source）**：`template_path` 来自 POST 参数，攻击者完全可控；第{L(4194,"login_required")}行只要求登录，不构成对路径的约束。

2. **第{L(4194,'sanitized_path = template_path.replace(')}行（防御 3）**：`str.replace` 会替换全部非重叠出现，所以单写 `"../"` 会被移除；但对 `....//....//etc/passwd`，替换后残留的 `.` 与 `/` 重新拼出 `../`——实跑结果 `'....//....//etc/passwd'.replace('../','')` = `'../../etc/passwd'`。黑名单式过滤在此被经典 `....//` 形态绕过。

3. **第{L(4194,"os.path.join(base_dir")}行与第{L(4194,"startswith(base_dir)")}行（防御 4）**：`full_path = os.path.join(base_dir, '../../etc/passwd')` = `/app/templates/exports/../../etc/passwd`。第 3 行的校验是 **`startswith` 字符串前缀比较**，该字符串确实以 `base_dir` 开头，因此**校验为真并通过**（实跑 `startswith` → True）。前缀比较不做 `normpath`，无法发现 `..` 段。

4. **第{L(4194,"open(full_path")}行（sink）**：`open()` 由内核按路径语义解析 `..`，落到 `/app/etc/passwd`（实跑 `os.path.normpath` 得 `\\\\app\\\\etc\\\\passwd`，即在 base 之外）。`read()` 的内容随后写入导出结果，构成受限目录逃逸 + 任意文件读。

5. **排除项**：非 CWE-118 之类的伞类——机制明确是路径规范化缺失；未发现二次校验点（第{L(4194,"DOCTYPE")}行起是 XML 侧的独立防御，与路径无关）。

**结论**：`replace` 黑名单可被 `....//` 绕过，且 `startswith` 前缀比较不能识别 `..` 段，构成 CWE-22 Path Traversal。
"""

N[8022] = f"""**分析过程**

1. **第{L(8022,'user_svg = request.args.get(')}行（source）**：`svg` 查询参数完全由攻击者控制。

2. **第{L(8022,"SANITIZE_ENABLED")}行（防御 1）**：`SANITIZE_ENABLED = False`，`sanitize_svg` 默认原样返回；即便开启，也只是 `str.replace('<script>','')` 的字面量删除，属黑名单式弱防御，不作为结论依据。

3. **第{L(8022,"render_template_string")}行（sink，真正的失效点）**：`render_template_string` 的入参是**模板源码**，而 `escape(cleaned)` 是在拼接进源码**之前**做的。`markupsafe.escape` 只转义 `& < > ' "`，**不处理 `{{ }}` 与 `{{% %}}`**。

4. **复现**：实跑 `str(markupsafe.escape('{{{{7*7}}}}'))` = `'{{{{7*7}}}}'`（原样保留），Jinja 渲染拼接后的源码得到 `49`——即用户输入被当作模板表达式求值。可进一步读取 `config`、调用对象属性；`escape` 返回 `Markup` 后经 `str()` 转换，反而丢掉了 `Markup` 的"已安全"语义，对模板引擎毫无保护作用。

5. **排除项**：非 CWE-79 因为主机制不落在 HTML 上下文（`<script>` 已被转义），而是落在模板引擎的表达式求值；`sanitize_svg` 的绕过只是辅助条件。第{L(8022,"app.run")}行的 `debug=True` 属独立问题，不改变本判。

**结论**：修在 HTML 转义层、漏在模板引擎层，输出转义与模板源拼接的组合反而把 XSS 面升级成 SSTI，构成 CWE-1336。
"""

SPECS = {
    3100: dict(old=(False, "none"), verdict=dict(
        has_vulnerability=True,
        vulnerability_type="CWE-125 Out-of-bounds Read",
        risk_level="Medium",
        source=f"line {L(3100,'decodePixelStream')}: decodePixelStream 的 input 字节流（不可信网络数据）",
        sink=f"line {L(3100,'input[12 + srcIdx]')}-{L(3100,'input[14 + srcIdx]')}: input[12+srcIdx] / input[13+srcIdx] / input[14+srcIdx] 三处越界读取",
        explanation=(f"line {L(3100,'pixelCount > inputLen / 3')}: pixelCount 上界取 inputLen/3，未扣除 12 字节头部，"
                     f"正确不等式应为 12 + 3*pixelCount <= inputLen；循环最大读下标 3*pixelCount+11，"
                     f"inputLen=12 时允许 pixelCount=4 而实际只可读 12 字节，越界读 11-12 字节。"
                     f"line {L(3100,'outSize = static_cast')}: 写侧 buf 按 pixelCount*4 分配，不越界，故为读取侧缺陷。"),
        fix_suggestion=(f"line {L(3100,'pixelCount > inputLen / 3')}: 改为 if (inputLen < 12 || pixelCount > (inputLen - 12) / 3) return false;，"
                        f"并把循环内下标改为 size_t 以免 i*3 在 32 位下回绕"),
    )),
    3124: dict(old=(False, "none"), verdict=dict(
        has_vulnerability=True,
        vulnerability_type="CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        risk_level="High",
        source=f"line {L(3124,'TestCmd')}: BuildRequest.TestCmd（HTTP 请求体 test_cmd 字段）",
        sink=f"line {L(3124,'cd /tmp/build-')} + line {L(3124,'exec.CommandContext')}: sh -c \"cd /tmp/build-<CommitID> && <TestCmd>\"",
        explanation=(f"line {L(3124,'isAllowedTestCmd(req.TestCmd)')}: 命令前缀白名单用 strings.HasPrefix，只约束前缀不约束 shell 元字符，"
                     f"go test; cat /etc/passwd 等载荷全部通过；line {L(3124,'cd /tmp/build-')} 将 TestCmd 拼进 sh -c 字符串，"
                     f"line {L(3124,'exec.CommandContext')} 执行时 ; 与 && 被 shell 解释为控制符，命令逃逸并在 line {L(3124,'test failed')} 回显输出。"
                     f"CommitID/RepoURL 的校验覆盖不到该字段，不构成阻断。"),
        fix_suggestion=(f"line {L(3124,'cd /tmp/build-')}: 去掉 sh -c，改为 exec.CommandContext(ctx, args...) 列表参数（args 由白名单枚举映射得到，"
                        f"不接受自由文本）；若必须保留自由参数，则在 line {L(3124,'isAllowedTestCmd(req.TestCmd)')} 处额外拒绝 ; | & $ ` ( ) 换行 等元字符"),
    )),
    3146: dict(old=(False, "none"), verdict=dict(
        has_vulnerability=True,
        vulnerability_type="CWE-94 Improper Control of Generation of Code ('Code Injection')",
        risk_level="High",
        source=f"line {L(3146,'request.get_json')}: export_data 的 content 与 filename（POST body）",
        sink=f"line {L(3146,'subprocess.run')} + line {L(3146,'with open')}: python -c 的源码字符串 f.write('{{content}}')",
        explanation=(f"line {L(3146,'with open')}: content 被 f-string 拼进 python -c 的源码而非作为数据传入，"
                     f"subprocess 的列表参数只阻断 shell 层，解释器层仍可注入：content=\"x') or __import__('os').system('id') or f.write('\" "
                     f"生成合法源码并执行（实跑 compile() 通过）。伴生向量：line {L(3146,'filename.replace(')} 的 ../ 过滤可被 ....// 绕过，"
                     f"配合 line {L(3146,'safe_filename.startswith(')} 的字符串前缀比较，safe_filename 归一化后落到 /etc/passwd（CWE-22 写侧）。"),
        fix_suggestion=(f"line {L(3146,'with open')}: 不要把数据拼进代码，改为 argv 传参：[\"python\",\"-c\","
                        f"\"import sys,pathlib; pathlib.Path(sys.argv[1]).write_text(sys.argv[2])\", safe_filename, content]；"
                        f"并把 line {L(3146,'safe_filename.startswith(')} 的前缀比较换成 os.path.realpath 后再比对目录"),
    )),
    4194: dict(old=(False, "none"), verdict=dict(
        has_vulnerability=True,
        vulnerability_type="CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        risk_level="High",
        source=f"line {L(4194,'template_path = request.POST.get(')}: export_data 的 template_path（POST 参数）",
        sink=f"line {L(4194,'open(full_path')}: open(full_path).read() 读取 base_dir 之外的文件",
        explanation=(f"line {L(4194,'sanitized_path = template_path.replace(')}: 黑名单式过滤被经典 ....// 形态绕过，"
                     f"'....//....//etc/passwd'.replace('../','') 得到 '../../etc/passwd'；"
                     f"line {L(4194,'os.path.join(base_dir')} 拼接后 full_path = base_dir + '/../../etc/passwd'，"
                     f"line {L(4194,'startswith(base_dir)')} 只做字符串前缀比较、不做 normpath，该字符串确实以 base_dir 开头因而校验通过（实跑 startswith 为 True）；"
                     f"line {L(4194,'open(full_path')} 由内核按路径语义解析 .. 落到 base 之外，读取结果进入导出内容。"),
        fix_suggestion=(f"line {L(4194,'startswith(base_dir)')}: 改为对 realpath 结果做目录包含判断——"
                        f"rp = os.path.realpath(os.path.join(base_dir, template_path)); 再用 os.path.commonpath([rp, base_dir]) == base_dir 判定，"
                        f"并拒绝含 '..' 的原始输入；同时用 defusedxml 替换裸 ElementTree"),
    )),
    8022: dict(old=(False, "none"), verdict=dict(
        has_vulnerability=True,
        vulnerability_type="CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine",
        risk_level="High",
        source=f"line {L(8022,'user_svg = request.args.get(')}: render_svg 的 svg 查询参数",
        sink=f"line {L(8022,'render_template_string')}: render_template_string 的模板源码（拼接了用户输入）",
        explanation=(f"line {L(8022,'render_template_string')}: 转义发生在 HTML 层却在模板源拼接之前，"
                     f"markupsafe.escape 不处理 {{{{ }}}} / {{% %}}，实跑 escape('{{{{7*7}}}}') 原样返回且渲染结果为 49；"
                     f"line {L(8022,'SANITIZE_ENABLED')} 的净化开关默认关闭且为字面量黑名单，不构成防御；"
                     f"主机制落在模板引擎表达式求值而非 HTML 上下文。"),
        fix_suggestion=(f"line {L(8022,'render_template_string')}: 不要拼接模板源码，改为把数据作为上下文本体传入"
                        f"（render_template_string('<div id=\"viewer\">{{{{ svg }}}}</div>', svg=cleaned)），"
                        f"并保留 autoescape；按不可信内容渲染 HTML 时应改用 bleach/nh3 做白名单净化而非 escape"),
    )),
}

# ---------------------------------------------------------------- 执行
chg, meta = [], {}
new_rows = []
for i, r in enumerate(rows):
    spec = SPECS.get(r["src_row"])
    if not spec:
        new_rows.append(r)
        continue
    a = r["messages"][2]["content"]
    jm = list(J.finditer(a))
    assert jm, f"row {r['src_row']} 无 JSON"
    old_v = json.loads(jm[-1].group(1))
    ohv = str(old_v.get("has_vulnerability")).lower() == "true"
    ot = str(old_v.get("vulnerability_type", ""))
    exp_hv, exp_type = spec["old"]
    assert ohv == exp_hv, f"row {r['src_row']} 旧结论不符: {old_v}"
    assert ot.strip().lower().startswith(exp_type), f"row {r['src_row']} 旧类型不符: {ot!r}"
    body = a[:jm[-1].start()].rstrip()
    assert body, f"row {r['src_row']} 叙事为空"
    v = spec["verdict"]
    assert sorted(v.keys()) == sorted(KEYS)
    new_a = N[r["src_row"]].rstrip() + "\n\n```json\n" + json.dumps(v, ensure_ascii=False) + "\n```\n"
    new_rows.append(dict(messages=[r["messages"][0], r["messages"][1],
                                   dict(role="assistant", content=new_a)], src_row=r["src_row"]))
    meta[r["src_row"]] = dict(before=old_v, after=v)
    chg.append(dict(date="2026-09-14", step="v2_21", action="FLIP", row_line=r["src_row"],
                    old_verdict=f"{old_v.get('has_vulnerability')}/{old_v.get('vulnerability_type')}",
                    new_verdict=f"{v['has_vulnerability']}/{v['vulnerability_type']}",
                    note="P0-3 精读裁决：负样本实为可利用", basis="实测复现（compile/startswith/Jinja 渲染）",
                    label_basis="audit"))

# ---------------------------------------------------------------- 校验
bad = 0
for r in new_rows:
    jm = list(J.finditer(r["messages"][2]["content"]))
    assert jm and sorted(json.loads(jm[-1].group(1)).keys()) == sorted(KEYS), f"契约异常 {r['src_row']}"
    if r["src_row"] in SPECS and "非 CWE" not in r["messages"][2]["content"]:
        bad += 1
print("行数", len(rows), "->", len(new_rows))
print("改判行", sorted(SPECS))
print("新增叙事缺『非 CWE』的改判行:", bad)
for k, m in meta.items():
    print(f"  row {k}: {m['before'].get('vulnerability_type')} -> {m['after']['vulnerability_type']} ({m['after']['risk_level']})")

if DRY:
    print("\n[DRY-RUN] 未写盘")
else:
    with open(SNAP, "w", encoding="utf-8") as f:
        for k in SPECS:
            f.write(json.dumps(rows[IDX[k]], ensure_ascii=False) + "\n")
    with open(DST, "w", encoding="utf-8") as f:
        for r in new_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(CHG, "w", encoding="utf-8") as f:
        for c in chg:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    print(f"\n[WROTE] {DST}\n        {SNAP}\n        {CHG}")
    print("sha256", hashlib.sha256(open(DST, "rb").read()).hexdigest())
