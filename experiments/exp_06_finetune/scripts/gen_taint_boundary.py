#!/usr/bin/env python3
"""污点边界补充蒸馏：函数参数即污点源（alpha06-v2.2 修复项）。

针对弱点挖掘报告（rolling_dev 2026-08-24）最大 FN 根因：模型只认 request/input/
argv 显式 web 入口，库函数参数/文件协议内容/框架回调传入的外部数据被一律判
"无用户可控输入→安全"（25 条 FN 中 ~11 条）。行动映射承诺的"函数参数即污点边界"
跨语义结构演示 100~200 条由本脚本落地：

三形态 × 双方向：
  F1 lib_param   库/工具函数：公开参数即污点边界，全文无 web 入口标识
  F2 file_proto  文件/协议内容解析：被解析的文件内容/协议报文即不可信输入
  F3 callback    非典型回调：消息队列消费者/事件监听器/定时任务/插件钩子

方向设计（与 nosource_safe 的顶层脚本形态互补，专门对冲"库函数形态=安全"窄规则）：
  vuln：入口 → sink，无有效防御 —— 教"无显式入口 ≠ 安全"
  safe：入口 → 有效防御（参数化/白名单/转义/原生安全 API）→ sink ——
        教"参数是污点入口，但强防御覆盖完整时应判安全"

校验（在 validate 之上加三道门）：
  1) 代码禁显式入口词（request/argv/input(/environ/stdin/os.Args/gin.Context...）
  2) 分析必须点出污点边界教学点（含"污点"且含"参数/入口/边界/报文/载荷"之一）
  3) safe 侧代码或分析必须出现强防御词（参数化/白名单/转义/预编译...）

输出：corpus/taint_boundary_wave.jsonl（构建 v2_2 时并入）
用法：
  $env:OPENROUTER_KEY="sk-or-..."; python gen_taint_boundary.py --pilot
  $env:OPENROUTER_KEY="sk-or-..."; python gen_taint_boundary.py --resume --workers 4
"""
import argparse
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(Path(__file__).parent))
from graduation_project.prompts import ALPHA05_PROMPT
from distill_alpha_pairs import call_teacher, validate
from gen_alpha06_variants import (CHECKLIST_CLAUSE, SCHEMA_LOCK,
                                  largest_code_block, detect_lang,
                                  clean_analysis, normalize_verdict_json)

CORPUS = PROJECT / "experiments/exp_06_finetune/corpus"
OUT_PATH = CORPUS / "taint_boundary_wave.jsonl"
PROGRESS_PATH = CORPUS / "taint_boundary_progress.jsonl"
RAW_DIR = CORPUS / "taint_boundary_raw"

LANGS = ["python", "java", "go", "php", "javascript"]
CWES = ["CWE-89", "CWE-78", "CWE-22", "CWE-79",
        "CWE-502", "CWE-611", "CWE-918", "CWE-1336"]

FORMS = {
    "lib_param": {
        "desc": "一个库/工具模块：导出一个或多个公开函数，函数参数承载上层调用者传入的外部数据；文件内不得出现任何路由注册或 web 处理器。",
        "entry": "函数参数",
    },
    "file_proto": {
        "desc": "一个解析模块：函数接收文件路径/字节流/协议报文参数（或在函数体内读取文件/报文），把被解析的文件内容或协议报文当作不可信输入，解析结果进入危险操作；同样不得出现 web 入口。",
        "entry": "被解析的文件内容/协议报文",
    },
    "callback": {
        "desc": "一个非 web 回调处理器：消息队列消费者回调、事件监听器、定时任务入口或插件系统钩子，回调签名中的消息体/事件载荷参数承载外部数据；禁止使用 HTTP handler / 路由签名。",
        "entry": "回调参数（消息体/事件载荷）",
    },
}

SCENARIOS = [
    "报表导出工具（被上层 API 服务以用户筛选条件调用）",
    "数据导入适配器（处理外部系统传来的记录）",
    "缓存编解码模块（缓存键值承载外部数据）",
    "运维命令封装库（封装系统命令执行）",
    "文件归档/解包工具（处理外部提交的归档名）",
    "模板渲染辅助类（渲染外部提供的模板片段/变量）",
    "webhook 出站发送器（向外部提供的地址发起请求）",
    "消息消费者业务处理器（消费队列中的业务消息）",
    "插件系统的钩子实现（宿主以外部数据调用钩子）",
    "配置/清单文件解析器（解析外部提交的配置文件）",
    "静态资源定位工具（根据外部名定位服务器文件）",
    "富文本/日志格式化模块（处理外部提交的文本）",
]

# 显式 web 入口标识（requests 库等出站调用不在此列）
WEB_ENTRY = re.compile(
    r"\brequest\b|argv|\binput\s*\(|environ|stdin|os\.Args|RequestParam"
    r"|HttpContext|gin\.Context|echo\.Context|fiber\.Ctx|\.FormValue\("
    r"|http\.Request|servlet|req\.(?:Query|Param|Body|Form|Header|Value)",
    re.I)

# 强防御证据（safe 侧必须命中其一）
STRONG_DEFENSE_EV = re.compile(
    r"参数化|白名单|转义|escape|预编译|prepare|placeholder|allowlist"
    r"|whitelist|escapeshellarg|shlex|ENT_QUOTES|参数数组|execFile|参数绑定"
    r"|PathCanonicalize|filepath\.Clean|realpath|resolve\(", re.I)

# 教学点：分析必须讨论污点边界
TEACH_POINT = re.compile(r"污点")


def build_prompt(lang, form, direction, cwe, scenario):
    f = FORMS[form]
    entry = f["entry"]
    if direction == "vuln":
        req2 = (f"2. 数据从{entry}流向 {cwe} 对应的危险 sink，全程无有效防御"
                "（黑名单/正则/字符串替换这类可绕过的弱防御可以出现，"
                "且分析要指出具体绕过方式）。")
        verdict_line = ('{{"has_vulnerability": true, "vulnerability_type": "' + cwe
                        + ' ...", "risk_level": "...", "source": "line N: ...", '
                          '"sink": "line N: ...", "explanation": "... -> ...", '
                          '"fix_suggestion": "line N: ..."}}')
        tail = (f"最后输出 ```json 结论：\n{verdict_line}\n"
                f"vulnerability_type 以 {cwe} 开头。")
    else:
        req2 = ("2. 数据从" + entry + "流向危险 sink 之前存在【有效防御】——"
                "参数化查询/预编译、白名单校验、正确转义、原生安全 API"
                "（如参数数组的命令执行、框架自动转义）之一；"
                "分析必须说明该防御为何类型正确、位置正确、覆盖完整攻击面。")
        verdict_line = ('{"has_vulnerability": false, "vulnerability_type": "none", '
                        '"risk_level": "None", "source": "N/A", "sink": "N/A", '
                        '"explanation": "...", "fix_suggestion": "no fix needed"}')
        tail = f"最后输出 ```json 结论：\n{verdict_line}"

    return f"""你要为漏洞检测模型生成一条【污点边界】训练数据：一段【没有任何显式 web 入口】的代码，外部数据通过{entry}进入并流向危险操作。

【目标语言】{lang}（必须用该语言地道习语与生态常用 API）
【形态要求】{f['desc']}
【业务场景】{scenario}
【目标方向】{"存在漏洞（vuln）" if direction == "vuln" else "安全（safe，有完整防御）"}
【漏洞类型】{cwe}

【硬性要求——违反任一条即废】
1. 全文（含注释）禁止出现任何显式入口标识：request、req.、argv、input(、environ、stdin、os.Args、@RequestParam、HttpContext、gin.Context 等；外部数据进入本代码的唯一通道是{entry}。
{req2}
3. 代码 15~50 行，完整文件形态（含 import/package/use），像真实开源项目的一个模块；可用注释表明"被上层服务调用/消费队列消息"，但不得写出调用方代码。
4. {CHECKLIST_CLAUSE}

【输出格式】
LANG: <语言，小写>
```code
<完整代码>
```
然后写 4~6 步编号分析，每步锚定真实行号（"第 N 行"）：
- 第 1 步必须明确指出污点边界：本文件没有 request/input 等显式 web 入口，但{entry}承载【外部可控数据】，是等效污点源（公开接口的参数/外部提交的内容必须按不可信处理）；
- 中间步骤从{entry}追踪到 sink，逐段说明数据流与防御缺失/可绕过原因（或防御有效性与覆盖面）；
- 最后交代第二入口/替代通道检查结论。
{tail}
{SCHEMA_LOCK}
注意：JSON 字符串值内严禁出现英文双引号，需要引用代码时使用单引号或反引号。"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", action="store_true")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--per-cell", type=int, default=5, help="每 语言×形态×方向 组合的任务数")
    args = ap.parse_args()

    key = (os.environ.get("TEACHER_KEY") or os.environ.get("OPENROUTER_KEY") or "")
    if not key:
        print("错误：需要 OPENROUTER_KEY", file=sys.stderr)
        sys.exit(1)

    tasks = []
    for li, lang in enumerate(LANGS):
        for fi, form in enumerate(FORMS):
            for di, direction in enumerate(("vuln", "safe")):
                for i in range(args.per_cell):
                    cwe = CWES[(li + fi * 2 + i) % len(CWES)]
                    scen = SCENARIOS[(i * 3 + fi + li) % len(SCENARIOS)]
                    tasks.append({
                        "key": f"E:{lang}:{form}:{direction[:4]}:{i}",
                        "lang": lang, "form": form, "dir": direction,
                        "cwe": cwe, "scenario": scen,
                        "prompt": build_prompt(lang, form, direction, cwe, scen),
                    })
    if args.pilot:
        tasks = tasks[:2]

    done = set()
    if args.resume and PROGRESS_PATH.exists():
        for line in PROGRESS_PATH.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    done.add(json.loads(line)["key"])
                except Exception:
                    pass
    pending = [t for t in tasks if t["key"] not in done]
    print(f"任务总数 {len(tasks)} | 已完成 {len(done)} | 待处理 {len(pending)}", flush=True)

    RAW_DIR.mkdir(exist_ok=True)
    lock = threading.Lock()
    stats = {"ok": 0, "reject": 0, "entry_leak": 0, "no_teach": 0, "no_defense": 0}
    out_f = open(OUT_PATH, "a" if args.resume else "w", encoding="utf-8")
    prog_f = open(PROGRESS_PATH, "a" if args.resume else "w", encoding="utf-8")

    def emit(sample):
        with lock:
            out_f.write(json.dumps(sample, ensure_ascii=False) + "\n")
            out_f.flush()

    def process_output(t, text, attempt):
        """校验+入库；返回 (status, msg)，status ∈ ok/regen/fail。"""
        kind_dir = t["dir"] == "vuln"

        def regen_or_fail(msg, stat_key):
            with lock:
                stats[stat_key] += 1
            return ("regen", msg) if attempt == 0 else ("fail", msg)

        _, code = largest_code_block(text)
        if not code or len(code) < 250 or "\n" not in code:
            return regen_or_fail(f"{t['key']}: 无有效 code 块", "reject")
        if WEB_ENTRY.search(code):
            return regen_or_fail(f"{t['key']}: 代码含显式 web 入口", "entry_leak")
        lang_out = detect_lang(text, t["lang"])
        analysis = clean_analysis(text)
        rec, err = validate(normalize_verdict_json(analysis if "```json" in analysis
                                                    else text), kind_dir,
                            code.count("\n") + 1)
        if err:
            return regen_or_fail(f"{t['key']} 被拒: {err}", "reject")
        if not TEACH_POINT.search(analysis) or not re.search(
                r"参数|入口|边界|报文|载荷|消息体", analysis):
            return regen_or_fail(f"{t['key']}: 分析未点出污点边界", "no_teach")
        if not kind_dir and not STRONG_DEFENSE_EV.search(code + analysis):
            return regen_or_fail(f"{t['key']}: safe 侧无强防御证据", "no_defense")
        sample = {"messages": [
            {"role": "system", "content": ALPHA05_PROMPT},
            {"role": "user", "content":
             f"代码片段（语言: {lang_out}）：\n```{lang_out}\n{code}\n```"},
            {"role": "assistant", "content": rec["assistant"]},
        ], "meta": {"kind": f"taint_boundary_{'vuln' if kind_dir else 'safe'}",
                    "form": t["form"], "cwe": t["cwe"],
                    "task_key": t["key"], "out_lang": lang_out}}
        emit(sample)
        return ("ok", t["key"])

    def run_task(t):
        t0 = time.time()
        for attempt in range(3):
            try:
                text = call_teacher(key, t["prompt"])
            except RuntimeError as e:
                with lock:
                    stats["reject"] += 1
                return f"✗ {t['key']}: {str(e)[:60]}"
            (RAW_DIR / f"{t['key'].replace(':', '_')}.txt").write_text(
                text or "", encoding="utf-8")
            status, msg = process_output(t, text, attempt)
            if status == "ok":
                with lock:
                    prog_f.write(json.dumps({"key": t["key"]}) + "\n")
                    prog_f.flush()
                    stats["ok"] += 1
                return f"✓ {msg} ({time.time()-t0:.0f}s)" + \
                       (" [重生成]" if attempt else "")
            if status == "fail" or attempt == 2:
                return f"✗ {msg}"
        return f"✗ {t['key']}: 重生成后仍不合格"

    workers = 1 if args.pilot else args.workers
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for i, fut in enumerate(as_completed([ex.submit(run_task, t) for t in pending])):
            print(f"  [{i+1}/{len(pending)}] {fut.result()}", flush=True)

    out_f.close()
    prog_f.close()
    print(f"\n完成：{json.dumps(stats)} | 输出: {OUT_PATH}")


if __name__ == "__main__":
    main()
