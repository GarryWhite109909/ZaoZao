#!/usr/bin/env python3
"""盲区族教学蒸馏（2026-08-29，v2.9 补充审计盲区清单专项）。

背景：v2.9 审计确认 6 个漏洞族在训练集几乎为零（CWE-311/942/400/200/209/1427，
除 327×22 外 train_pool 种子全为 0）。这些族漏洞形态教科书级稳定，无需真实 CVE
种子即可合成教学数据（先例：taint_boundary 139 条、blacklist_bypass 24 对）。
评测侧考卷另走新 CVE 采集（滚动窗口制度），本脚本只做教学侧。

矩阵：6 族 × 各语言 × vuln/safe 双方向 × per-cell（默认 2）≈ 104 任务。

四道门（在 validate 之上）：
  1) vuln 侧 vulnerability_type 必须以族 CWE 开头（防塌缩回 CWE-78/89）；
  2) 分析必须点出族教学关键词（明文/CORS/资源耗尽/提示注入/信息暴露/错误泄露）；
  3) safe 侧代码或分析必须出现强防御证据（TLS/加密存储、Origin 白名单、
     输入上限/安全正则、提示隔离、脱敏、通用错误文案）；
  4) 泄漏门：对 87seg/rdev/realsafe 四评测集 J≥0.3/C≥0.5 拒收。

输出：corpus/blindspot_teaching_wave.jsonl（并入时走 v2.9 同款管道出 v2.10）
用法：
  python gen_blindspot_teaching.py --dry-run          # 离线任务矩阵验证，无需 key
  $env:TEACHER_KEY="..."; python gen_blindspot_teaching.py --pilot
  $env:TEACHER_KEY="..."; python gen_blindspot_teaching.py --resume --workers 4
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

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
OUT_PATH = CORPUS / "blindspot_teaching_wave.jsonl"
PROGRESS_PATH = CORPUS / "blindspot_teaching_progress.jsonl"
RAW_DIR = CORPUS / "blindspot_teaching_raw"

# ---------------------------------------------------------------- 族配置
FAMILIES = {
    "CWE-311": {
        "name": "CWE-311 Missing Encryption of Sensitive Data",
        "langs": ["python", "javascript", "java", "go", "php"],
        "desc": ("敏感数据（密码/令牌/密钥/PII）以明文形态跨信任边界：要么明文信道传输"
                 "（http://、ws://、ftp:// 出站调用、无 TLS 的邮件/缓存），"
                 "要么明文落盘/入库（密码明文写文件或数据库、令牌明文写日志）。"),
        "scenarios": [
            "密码重置流程（把新密码或令牌经明文信道发出）",
            "外部支付网关客户端（向 http:// 接口提交持卡人数据）",
            "用户资料导出接口（把含 PII 的数据明文写共享目录）",
            "服务间内部调用（令牌经明文消息队列/缓存传递）",
            "备份模块（把含凭证的配置明文写入备份文件）",
        ],
        "teach": re.compile(r"明文|加密|TLS|SSL|https", re.I),
        "vuln_ev": re.compile(r"http://|ws://|ftp://|telnet://|memcache|明文", re.I),
        "safe_ev": re.compile(r"https://|tls|ssl|bcrypt|argon|scrypt|encrypt|kms|vault|cipher|加密", re.I),
    },
    "CWE-942": {
        "name": "CWE-942 Permissive Cross-domain Policy",
        "langs": ["python", "javascript", "java", "go", "php"],
        "desc": ("CORS 配置过宽：Access-Control-Allow-Origin 使用通配 * 或直接反射请求 Origin，"
                 "并叠加 credentials 放行——任意源可携带凭据跨域读取响应。"
                 "框架形态：Flask-CORS/Django-CORS、Express cors 中间件、"
                 "Spring @CrossOrigin(origins=\"*\")、gin/rs CORS 中间件、PHP 手写头。"),
        "scenarios": [
            "REST API 网关（跨域配置放行全部来源并允许凭据）",
            "单页应用后端（开发图省事把 Origin 原样回显）",
            "文件上传服务（预检请求放行任意源）",
            "内部管理接口（CORS 通配叠加 Cookie 凭据）",
            "WebSocket 握手端点（Origin 校验缺失放行任意源）",
        ],
        "teach": re.compile(r"CORS|Origin|跨域|凭据", re.I),
        "vuln_ev": re.compile(r"[Oo]rigin|[Cc]rossOrigin|cors|ACAO", re.I),
        "safe_ev": re.compile(r"白名单|allowlist|whitelist|allowed_origins|Vary|explicit|精确", re.I),
    },
    "CWE-400": {
        "name": "CWE-400 Uncontrolled Resource Consumption",
        "langs": ["python", "javascript", "java", "go", "php"],
        "desc": ("不可信输入驱动无界资源消耗：灾难性回溯正则（嵌套量词如 (a+)+、(a|a)*），"
                 "或用户控制的长度/次数进入无上限的循环、分配、解压（zip 炸弹、无界 JSON 深度、"
                 "递归解析无深度限制）。"),
        "scenarios": [
            "输入校验模块（用户提交的正则被服务端执行）",
            "搜索过滤功能（对用户输入做灾难性回溯正则匹配）",
            "归档解压服务（解压用户上传的 zip 无总大小限制）",
            "配置解析器（递归下降解析无深度上限的嵌套结构）",
            "批量任务接口（用户指定条数的循环处理无上限）",
        ],
        "teach": re.compile(r"回溯|ReDoS|资源|耗尽|复杂度|上限|深度", re.I),
        "vuln_ev": re.compile(r"\(\w+[+*]\)[+*]|\(\w+\|\w+\)\*|\{[0-9]+,\}|while\s*\(|for\s*\(|extract|unzip|decompress|递归|recurse", re.I),
        "safe_ev": re.compile(r"上限|max_len|limit|长度限制|惰性|原子组|possessive|atomic|非贪婪|深度限制|max_depth|配额", re.I),
    },
    "CWE-1427": {
        "name": "CWE-1427 Improper Neutralization of Input Used in an LLM Prompt",
        "langs": ["python", "javascript"],
        "desc": ("LLM 集成中的提示注入：用户可控内容被拼接进 system prompt / 工具描述 / "
                 "RAG 检索上下文，攻击者借机改写指令、诱导工具调用或诱导数据外泄。"
                 "注意：这是提示注入（CWE-1427），不是命令注入（CWE-78）或通用代码注入（CWE-94）。"),
        "scenarios": [
            "智能客服（把用户资料拼进系统提示词做个性化）",
            "RAG 知识库问答（外部文档内容未隔离直接入上下文）",
            "AI 助手工具编排（工具描述里拼入用户可控字段）",
            "邮件自动摘要（邮件正文拼进指令模板）",
            "代码评审机器人（PR 描述拼进 system prompt）",
        ],
        "teach": re.compile(r"提示注入|prompt injection|system prompt|系统提示|工具调用|指令", re.I),
        "vuln_ev": re.compile(r"system|prompt|template|messages|llm|gpt|claude|openai|anthropic|completion", re.I),
        "safe_ev": re.compile(r"user|白名单|whitelist|allowlist|隔离|delimiter|分隔|escape|sanitize|过滤", re.I),
    },
    "CWE-200": {
        "name": "CWE-200 Exposure of Sensitive Information",
        "langs": ["python", "javascript", "java", "php"],
        "desc": ("敏感信息对不可信方暴露：API 响应直接回显敏感字段（密码哈希/内部标识/密钥），"
                 "调试模式对客户端开启，内部路径/版本/连接串写入对外可见的响应或日志。"),
        "scenarios": [
            "用户资料接口（序列化整个实体把哈希/内部字段一并返回）",
            "健康检查端点（暴露依赖版本、连接串、内部拓扑）",
            "审计日志（把明文令牌写进客户端可查询的日志视图）",
            "管理面板（调试开关未区分环境对外暴露变量）",
            "导出功能（导出字段含成本/内部定价等敏感列）",
        ],
        "teach": re.compile(r"信息暴露|敏感|泄露|脱敏|暴露", re.I),
        "vuln_ev": re.compile(r"password|token|secret|api_key|apikey|hash|debug|trace|internal", re.I),
        "safe_ev": re.compile(r"mask|脱敏|redact|\*\*\*|DTO|dto|白名单|whitelist|字段过滤|serialize", re.I),
    },
    "CWE-209": {
        "name": "CWE-209 Generation of Error Message Containing Sensitive Information",
        "langs": ["python", "javascript", "java", "go", "php"],
        "desc": ("错误信息泄露敏感内容：把异常对象/底层错误（含 SQL、堆栈、内部路径、连接细节）"
                 "原样返回给客户端——str(e)、e.getMessage()、err.Error() 直接进响应体。"),
        "scenarios": [
            "数据库查询失败（把驱动错误含 SQL 回显给前端）",
            "文件处理接口（异常堆栈直接返回）",
            "第三方调用失败（把上游 URL/密钥片段回显）",
            "反序列化失败（异常消息带内部类名与路径）",
            "支付回调（把网关原始报错透传给客户端）",
        ],
        "teach": re.compile(r"错误信息|报错|堆栈|异常|泄露|错误消息", re.I),
        "vuln_ev": re.compile(r"str\(e\)|e\.message|getMessage|err\.Error\(\)|\.Error\(\)|exception|Exception|error\.message", re.I),
        "safe_ev": re.compile(r"log|logger|logging|通用|generic|internal error|服务端|详细", re.I),
    },
}


def build_prompt(fam, cwe, name, lang, direction, scenario):
    f = FAMILIES[fam]
    if direction == "vuln":
        req2 = (f"2. 代码呈现 {name} 的典型漏洞形态：{f['desc']}；"
                "全程无有效防御。分析必须指出该形态属于本类（禁止归为命令注入/SQL 注入等其他类）。")
        verdict_line = ('{{"has_vulnerability": true, "vulnerability_type": "' + cwe
                        + ' ' + name.split(" ", 1)[1] + '", "risk_level": "High", '
                          '"source": "line N: ...", "sink": "line N: ...", '
                          '"explanation": "... -> ...", "fix_suggestion": "line N: 最小修复"}}')
        tail = (f"最后输出 ```json 结论：\n{verdict_line}\n"
                f"vulnerability_type 必须以 {cwe} 开头（不得写成 CWE-78/89/94 等其他类）。")
    else:
        req2 = ("2. 代码是【安全版】：存在与漏洞形态对应的有效防御——"
                + ("强制 TLS/加密存储（bcrypt/argon2/KMS）" if cwe == "CWE-311" else
                   "Origin 精确白名单 + Vary: Origin + 不与凭据通配组合" if cwe == "CWE-942" else
                   "输入长度上限/惰性或原子组正则/解析深度与解压总量限制" if cwe == "CWE-400" else
                   "用户数据只进 user message、模板固定、工具白名单与输出过滤" if cwe == "CWE-1427" else
                   "响应字段白名单/脱敏掩码/生产关闭调试" if cwe == "CWE-200" else
                   "客户端只返回通用错误文案、详细错误仅写服务端日志") +
                "；分析必须说明防御为何类型正确、位置正确、覆盖完整。")
        verdict_line = ('{"has_vulnerability": false, "vulnerability_type": "none", '
                        '"risk_level": "none", "source": "N/A", "sink": "N/A", '
                        '"explanation": "...", "fix_suggestion": "no fix needed"}')
        tail = f"最后输出 ```json 结论：\n{verdict_line}"

    return f"""你要为漏洞检测模型生成一条【盲区族教学】训练数据：代码涉及 {name}（{cwe}），这一类在既有训练数据中几乎为零，需要清晰、典型、无歧义的演示。

【目标语言】{lang}（必须用该语言地道习语与生态常用 API/框架）
【业务场景】{scenario}
【目标方向】{"存在漏洞（vuln）" if direction == "vuln" else "安全（safe，有完整防御）"}

【硬性要求——违反任一条即废】
1. 代码 15~50 行，完整文件形态（含 import/package/use），像真实开源项目的一个模块。
{req2}
3. {CHECKLIST_CLAUSE}

【输出格式】
LANG: <语言，小写>
```code
<完整代码>
```
然后写 4~6 步编号分析，每步锚定真实行号（"第 N 行"）：
- 第 1 步先点出本类核心特征（{f['desc'][:40]}…），明确这不是注入/越权等其他类别；
- 中间步骤从输入/敏感数据追踪到暴露点或资源消耗点，逐段说明数据流与防御缺失（或防御有效性与覆盖面）；
- 最后交代第二入口/替代通道检查结论。
{tail}
{SCHEMA_LOCK}
注意：JSON 字符串值内严禁出现英文双引号，需要引用代码时使用单引号或反引号。"""


def build_exams():
    exams = {}
    e4 = PROJECT / "experiments/exp_04_hard_samples/samples"
    if e4.exists():
        for f in e4.glob("*"):
            if f.suffix in (".py", ".java", ".js", ".php", ".go", ".ts"):
                exams[f"87seg/{f.name}"] = f.read_text(errors="replace")
    for tag, d in [("rdev", CORPUS / "rolling_dev"), ("realsafe", CORPUS / "rolling_dev_safe")]:
        if d.exists():
            for f in d.glob("corpus_*"):
                if f.is_file():
                    exams[f"{tag}/{f.name}"] = f.read_text(errors="replace")
    return exams


def norm_lines(code):
    out = set()
    for ln in code.splitlines():
        s = ln.strip()
        if not s or s.startswith(("#", "//")):
            continue
        s = re.sub(r"\s+", " ", s).lower()
        if len(s) >= 8:
            out.add(s)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="离线验证任务矩阵与 prompt，无需 key")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--per-cell", type=int, default=2, help="每 族×语言×方向 的任务数")
    args = ap.parse_args()

    tasks = []
    for fam, cfg in FAMILIES.items():
        for lang in cfg["langs"]:
            for direction in ("vuln", "safe"):
                for i in range(args.per_cell):
                    scen = cfg["scenarios"][(i + len(cfg["langs"])) % len(cfg["scenarios"])]
                    tasks.append({
                        "key": f"B:{fam}:{lang}:{direction[:4]}:{i}",
                        "fam": fam, "lang": lang, "dir": direction,
                        "scenario": scen,
                        "prompt": build_prompt(fam, fam, cfg["name"], lang, direction, scen),
                    })
    if args.pilot:
        tasks = tasks[:2]

    if args.dry_run:
        from collections import Counter
        fam_c = Counter(t["fam"] for t in tasks)
        dir_c = Counter(t["dir"] for t in tasks)
        lang_c = Counter(t["lang"] for t in tasks)
        print(f"任务总数 {len(tasks)}（不含重试）")
        print(f"按族: {dict(fam_c)}")
        print(f"按方向: {dict(dir_c)}")
        print(f"按语言: {dict(lang_c)}")
        for t in tasks[:2]:
            print(f"\n===== {t['key']} prompt 预览（前 600 字符）=====")
            print(t["prompt"][:600])
        # prompt 完整性检查：必备段落都在
        for t in tasks:
            for need in ("【硬性要求", "【输出格式】", "```json 结论"):
                assert need in t["prompt"], f"{t['key']} 缺 {need}"
        print(f"\nprompt 完整性检查: {len(tasks)}/{len(tasks)} 通过")
        return

    key = (os.environ.get("TEACHER_KEY") or os.environ.get("OPENROUTER_KEY") or "")
    if not key:
        print("错误：需要 TEACHER_KEY", file=sys.stderr)
        sys.exit(1)

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
    if not pending:
        return

    exams = build_exams()
    exam_norm = {k: norm_lines(v) for k, v in exams.items()}
    RAW_DIR.mkdir(exist_ok=True)
    lock = threading.Lock()
    stats = {"ok": 0, "reject": 0, "wrong_type": 0, "no_teach": 0, "no_defense": 0,
             "no_ev": 0, "leak": 0}
    out_f = open(OUT_PATH, "a" if args.resume else "w", encoding="utf-8")
    prog_f = open(PROGRESS_PATH, "a" if args.resume else "w", encoding="utf-8")

    def process_output(t, text, attempt):
        fam_cfg = FAMILIES[t["fam"]]
        kind_vuln = t["dir"] == "vuln"

        def regen_or_fail(msg, stat_key):
            with lock:
                stats[stat_key] += 1
            return ("regen", msg) if attempt == 0 else ("fail", msg)

        _, code = largest_code_block(text)
        if not code or len(code) < 250 or "\n" not in code:
            return regen_or_fail(f"{t['key']}: 无有效 code 块", "reject")
        lang_out = detect_lang(text, t["lang"])
        analysis = clean_analysis(text)
        rec, err = validate(normalize_verdict_json(analysis if "```json" in analysis
                                                    else text), kind_vuln,
                            code.count("\n") + 1)
        if err:
            return regen_or_fail(f"{t['key']} 被拒: {err}", "reject")
        # 门 1：族类型不塌缩
        obj = json.loads(re.search(r"```json\s*(\{.*?\})\s*```",
                                   rec["assistant"], re.S).group(1))
        if kind_vuln and not str(obj.get("vulnerability_type", "")).startswith(t["fam"]):
            return regen_or_fail(
                f"{t['key']}: 类型塌缩 {obj.get('vulnerability_type')!r} 非 {t['fam']}",
                "wrong_type")
        # 门 2：族教学关键词
        if not fam_cfg["teach"].search(analysis):
            return regen_or_fail(f"{t['key']}: 分析未点出族教学点", "no_teach")
        # 门 3：safe 侧强防御证据
        if not kind_vuln and not fam_cfg["safe_ev"].search(code + analysis):
            return regen_or_fail(f"{t['key']}: safe 侧无强防御证据", "no_defense")
        # 门 4：vuln 侧形态证据（代码含族典型形态）
        if kind_vuln and not fam_cfg["vuln_ev"].search(code):
            return regen_or_fail(f"{t['key']}: vuln 代码缺族典型形态", "no_ev")
        # 泄漏门
        un = norm_lines(code)
        for ek, ev in exam_norm.items():
            if not un or not ev:
                continue
            j = len(un & ev) / len(un | ev)
            c = len(un & ev) / min(len(un), len(ev))
            if j >= 0.3 or c >= 0.5:
                with lock:
                    stats["leak"] += 1
                return ("fail", f"{t['key']}: 泄漏 vs {ek}")
        sample = {"messages": [
            {"role": "system", "content": ALPHA05_PROMPT},
            {"role": "user", "content":
             f"代码片段（语言: {lang_out}）：\n```{lang_out}\n{code}\n```"},
            {"role": "assistant", "content": rec["assistant"]},
        ], "meta": {"kind": f"blindspot_{'vuln' if kind_vuln else 'safe'}",
                    "family": t["fam"], "scenario": t["scenario"],
                    "task_key": t["key"], "out_lang": lang_out}}
        with lock:
            out_f.write(json.dumps(sample, ensure_ascii=False) + "\n")
            out_f.flush()
            prog_f.write(json.dumps({"key": t["key"]}) + "\n")
            prog_f.flush()
            stats["ok"] += 1
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
                n = stats["ok"]
                return f"[{n}] ✓ {msg} ({time.time()-t0:.0f}s)" + \
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
