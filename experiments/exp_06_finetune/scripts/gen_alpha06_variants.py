#!/usr/bin/env python3
"""第二轮变体蒸馏：语义结构变体（框架习语 / 跨文件 / 无污点硬安全 / 信任边界对）。

铁律（用户 2026-08-23 原则）：变体必须改变【语义结构】——框架习语/语言/防御位置/
文件形态/攻击面入口——禁止只改变量名、注释、字符串等表面 token。

四类任务：
  A 框架习语改写：真实 CVE 种子 → 换框架/语言重写同型漏洞（FN 主解药）
  B 跨文件污点组：source/净化/sink 分布在多文件（单样本内以 # === file: x === 分隔）
  C 无污点硬安全：字面量脚本/常量表/配置形态，"看着危险实际安全"（FP 解药）
  D 信任边界 minimal pair：仅 header-trust 决策之差的正反成对题

输出：corpus/distill_variants_wave2.jsonl（alpha05 格式，构建时并入 alpha06-v2）
"""
import argparse
import json
import os
import random
import re
import sys
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))
from graduation_project.prompts import ALPHA05_PROMPT

sys.path.insert(0, str(Path(__file__).parent))
from distill_alpha_pairs import call_teacher, validate

CORPUS = PROJECT / "experiments/exp_06_finetune/corpus"
OUT_PATH = CORPUS / "distill_variants_wave2.jsonl"
# 2026-08-25：改写目标矩阵扩容（i%3→i%4）后任务键语义已变，启用新进度文件，
# 避免旧键错误跳过新目标的组合；输出仍追加到 wave2 文件（构建侧按 md5 去重）
PROGRESS_PATH = CORPUS / "distill_variants_progress_v2.jsonl"

# 改写目标矩阵：按种子语言指定跨框架/语言目标（确保语义结构变化）
# 2026-08-25 增补：每语言追加一个"诊断盲区栈"目标——弱点挖掘报告 第九节 FN 根因 2：
# Next.js/Nuxt middleware、FastAPI dependencies、Spring filter 型习语在训练集≈0，
# 而旧 REWRITE_TARGETS 只换到已覆盖最厚的 express/spring/flask。盲区栈占比约 1/4。
REWRITE_TARGETS = {
    "python": ["node.js express 路由处理器", "java spring @RestController 方法",
               "go net/http handler", "next.js middleware 与路由白名单鉴权链"],
    "javascript": ["python flask 路由", "php laravel 控制器方法",
                   "java spring controller", "nuxt/server middleware 鉴权中间件链"],
    "java": ["python fastapi 路由", "node.js express 中间件链",
             "go gin handler", "fastapi dependencies 鉴权依赖注入链"],
    "php": ["python django 视图", "node.js express 路由",
            "java spring controller", "spring filter/interceptor 鉴权过滤器链"],
    "go": ["python flask 路由", "node.js express 路由",
           "php 原生脚本", "gin/net-http 中间件鉴权链"],
}

# 固定分析清单（弱点挖掘报告 第十节修复项：CoT 必须演示检查清单，
# 此前 3997 条漏洞 CoT 仅 5 条执行过"第二入口"检查）
CHECKLIST_CLAUSE = ("分析必须覆盖固定清单，缺一即废：①枚举全部外部输入点并确认到 sink 的可达性；"
                    "②对每条 source→sink 数据流逐一验证防御的类型/位置/覆盖面"
                    "（黑名单/正则/字符串替换过滤视为可绕过，不算有效防御）；"
                    "③明确交代是否存在第二入口或替代通道（其他路由/参数/间接调用），"
                    "并以此支撑最终结论。")

# 精确 schema 锁（2026-08-25 试跑实测：教师会把多流写成数组并自创
# dataflow/defense_analysis/second_entry 等键——内容优质但格式不合训练 schema）
SCHEMA_LOCK = ("【结论 JSON 精确格式——违反即废】必须且只能包含以下七个键，"
               "除 has_vulnerability 外全部为单个字符串：禁止数组、禁止增删任何键。"
               "多条数据流/防御分析/第二入口结论一律以分号连接写进 explanation 一个字段。\n"
               '{"has_vulnerability": true或false, "vulnerability_type": "...", '
               '"risk_level": "Critical|High|Medium|Low", '
               '"source": "主链起点的单字符串", "sink": "主链终点的单字符串", '
               '"explanation": "所有流与成因（分号连接）", "fix_suggestion": "line N: 最小修复"}')


def build_rewrite_prompt(code, lang, cwe, desc, target):
    return f"""你要为漏洞检测模型生成一条训练数据：【把一段真实漏洞代码改写到完全不同的技术栈】，保持漏洞的语义结构不变。

【原始漏洞代码】（{lang}，标注 {cwe}）
```
{code}
```
（背景：{(desc or cwe)[:200]}）

【改写目标技术栈】{target}

【改写规则——违反任一条即废】
1. 必须使用目标技术栈的【地道习语】：真实的路由注册方式、该生态常用的数据库/命令/模板 API、该框架特有的输入获取方式。禁止用原语言语法套皮。
2. 保持相同的漏洞语义结构：等价的 source（外部输入入口）→ 等价的 sink（危险操作），防御同样缺失或同样可绕过。
3. 代码长度 15~60 行；必须是完整可读的文件形态（含 import/依赖声明）。
4. 禁止表面化改写：不允许只改变量名/函数名/注释/字符串内容而保留原语言结构。
5. {CHECKLIST_CLAUSE}

【输出格式】
LANG: <目标栈主语言，小写，如 node.js/javascript/python/java/go/php>
```code
<改写后的完整代码>
```
然后写 3~5 步编号分析（每步锚定新代码的真实行号，格式"第 N 行"，从 source 追到 sink，说明为何无有效防御），最后输出 ```json 结论：
{{"has_vulnerability": true, "vulnerability_type": "{cwe} ...", "risk_level": "...", "source": "line N: ...", "sink": "line N: ...", "explanation": "... -> ...", "fix_suggestion": "line N: ..."}}
vulnerability_type 以 {cwe} 开头（若目标栈惯用类名不同可微调名称，编号不变）。
{SCHEMA_LOCK}
注意：JSON 字符串值内严禁出现英文双引号，需要引用代码时使用单引号或反引号。"""


def build_crossfile_prompt(code, lang, cwe, desc):
    return f"""你要生成一组【跨文件污点】训练数据：把下述单文件漏洞拆分重组为 2~3 个文件，使 source 与 sink 分离在不同文件中。

【原始漏洞代码】（{lang}，{cwe}）
```
{code}
```

【要求】
1. 输出 2~3 个文件，用 `# === file: <路径> ===` 分隔；source 所在文件与 sink 所在文件必须不同；
   中间可有一个"净化看似发生实则不完整"或纯传递的文件。
2. 文件须像真实项目结构（如 routes.py / services.py / db.py），含必要 import；
   总行数 30~90 行。
3. 漏洞语义与 {cwe} 一致：调用链上无完整防御。
4. {CHECKLIST_CLAUSE}
5. 只输出一个整体分析（针对整组文件），步骤锚定"文件名+行号"；结论 JSON 的
   source/sink 写成 "L<文件序号>:line N: ..." 形式。
{SCHEMA_LOCK}
注意：JSON 字符串值内严禁出现英文双引号，需要引用代码时使用单引号或反引号。

【输出格式】
LANG: <主语言，小写>
```code
# === file: a.py ===
...
# === file: b.py ===
...
```
然后 3~5 步编号分析 + ```json 结论（七字段，has_vulnerability=true，类型以 {cwe} 开头）。"""


def build_nosource_safe_prompt(lang, shape_hint):
    return f"""你要生成一条【安全样本】训练数据：一段"看起来有危险操作、实际不可利用"的真实风格代码。

【形态要求】{shape_hint}

【要求】
1. 使用 {lang}，15~50 行，完整文件形态；危险 API（execute/system/subprocess/eval/open 等）
   必须出现，但其全部实参为字面量/常量/配置常量，不存在任何外部输入入口
   （无 request/input/argv/env/网络读取）。
2. 禁止出现 request|argv|input(|environ|stdin|socket 等任何污染源。
3. 分析需逐步说明：每个危险点的实参来源为何是常量、为何不存在可达的污点路径，
   并明确交代不存在第二入口或替代通道（函数不被外部以可控参数调用等）。

【输出格式】
```code
<代码>
```
然后 2~4 步编号分析（锚定真实行号），最后 ```json：
{{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "None", "source": "N/A", "sink": "N/A", "explanation": "各危险点实参均为常量 -> 无污点来源 -> 不可利用", "fix_suggestion": "no fix needed"}}
{SCHEMA_LOCK}
注意：JSON 字符串值内严禁出现英文双引号，需要引用代码时使用单引号或反引号。"""


def build_trust_pair_prompt(code, lang, cwe, desc):
    return f"""基于下面这段存在【信任边界缺陷】的代码（{cwe}），生成一对 minimal pair：

【原始代码】（{lang}）
```
{code}
```
（背景：{(desc or cwe)[:200]}）

【要求】
1. vuln 版：保持信任边界缺陷（如信任 XFF 头/信任自定 header/未校验跳转目标主机）。
2. safe 版：只做【一处语义修正】消除该缺陷（例如改用 socket 对端地址、增加主机白名单校验），
   其余逐 token 相同；两版都必须完整、可读。
3. 两版分析均须执行固定清单：枚举输入点与可达性、逐条验证防御有效性，
   vuln 版必须交代第二入口/替代通道检查结论，safe 版说明修正为何完整覆盖攻击面。
4. 分别给出两版的独立分析。

【输出格式】
LANG: <主语言，小写>
```code-vuln
<漏洞版>
```
```code-safe
<修复版>
```
然后分别写 3~4 步分析并各输出一个 ```json 结论（vuln 版 true 且类型以 {cwe} 开头；safe 版 false）。
{SCHEMA_LOCK}
注意：两份 JSON 的字符串值内严禁出现英文双引号，引用代码时使用单引号或反引号（两份结论均适用）。"""


SHAPE_HINTS = {
    "python": ["数据运维顶层脚本：常量表驱动批量执行固定 SQL", "部署脚本：subprocess 跑硬编码命令序列", "内部工具：open() 读固定路径配置文件"],
    "javascript": ["构建辅助脚本：child_process 执行写死的 npm 命令", "常量路由表驱动的静态校验模块"],
    "java": "工具类：PreparedStatement 执行写死的报表 SQL",
    "go": "迁移脚本：database/sql 执行内嵌 DDL",
    "php": "CLI 维护脚本：mysqli 执行硬编码查询",
}


def parse_code_block(text: str, tag: str) -> str | None:
    m = re.search(rf"```{tag}\n(.*?)\n```", text, re.S)
    return m.group(1).strip() if m else None


def code_fences(text: str) -> list:
    """按出现顺序返回全部非 json 围栏 [(tag, body)]。"""
    out = []
    for m in re.finditer(r"```([\w+#.-]*)\n(.*?)\n```", text, re.S):
        if m.group(1).lower() != "json":
            out.append((m.group(1), m.group(2).strip()))
    return out


def clean_analysis(text: str) -> str:
    """剥离 LANG 行与全部 fenced 块，只留编号分析文本。"""
    t = re.sub(r"^\s*LANG:\s*.*\n", "", text)
    t = re.sub(r"```(?!\s*json)[^\n]*\n.*?\n```", "", t, flags=re.S)  # 保留 json 结论块
    return t.strip()


def normalize_verdict_json(text: str) -> str:
    """教师结论归一为七字段字符串 schema（安全网，配合 prompt 层 SCHEMA_LOCK）。

    - 数组值 → 分号连接单字符串
    - 自创键（dataflow/defense_analysis/second_entry/reason 等）折叠进 explanation
    - 不新增事实：缺 fix_suggestion/risk_level 时保持缺失，交由 validate 拒绝重生成
    """
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.S)
    if not m:
        return text
    try:
        obj = json.loads(m.group(1))
    except json.JSONDecodeError:
        return text
    if not isinstance(obj, dict):
        return text

    def to_str(v):
        if isinstance(v, list):
            return "; ".join(str(x) for x in v)
        return v

    canon_keys = ["has_vulnerability", "vulnerability_type", "risk_level",
                  "source", "sink", "explanation", "fix_suggestion"]
    out = {k: to_str(obj[k]) for k in canon_keys if k in obj}
    if not (isinstance(out.get("explanation"), str) and len(out.get("explanation", "")) >= 4):
        folds = [str(to_str(obj[k])) for k in ("dataflow", "defense_analysis",
                                               "second_entry", "reason") if k in obj]
        if folds:
            out["explanation"] = "; ".join(folds)
    for k in obj:
        if k not in out and k not in ("dataflow", "defense_analysis",
                                      "second_entry", "reason"):
            out[k] = to_str(obj[k])
    return text[:m.start()] + "```json\n" + \
        json.dumps(out, ensure_ascii=False) + "\n```" + text[m.end():]


def parse_lang_decl(text: str) -> str | None:
    m = re.search(r"^LANG:\s*(\S+)", text, re.M)
    return m.group(1).lower() if m else None


def largest_code_block(text: str) -> tuple[str, str]:
    """取除 json 外最大的 ```fenced 块，返回 (语言标记, 内容)。"""
    best_tag, best_body = "", ""
    for m in re.finditer(r"```([\w+#.-]*)\n(.*?)\n```", text, re.S):
        tag, body = m.group(1).lower(), m.group(2)
        if tag == "json":
            continue
        if len(body) > len(best_body):
            best_tag, best_body = tag, body
    return best_tag, best_body.strip()


def detect_lang(text: str, fallback: str) -> str:
    """优先教师声明的 LANG，其次围栏语言标记，最后种子语言。"""
    decl = parse_lang_decl(text)
    if decl:
        return decl
    _, body = largest_code_block(text)
    # 围栏里常见 shebang/import 线索
    head = body[:300]
    if re.search(r"^\s*import|require\(|def |from flask", head, re.M):
        return "python"
    if re.search(r"func |package main", head):
        return "go"
    if re.search(r"public class|@RestController", head):
        return "java"
    return fallback


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", action="store_true")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--per-kind-limit", type=int, default=0)
    args = ap.parse_args()

    key = os.environ.get("OPENROUTER_KEY", "")
    if not key:
        print("错误：需要 OPENROUTER_KEY", file=sys.stderr)
        sys.exit(1)

    manifest = json.loads((CORPUS / "train_pool" / "manifest.json").read_text())["samples"]
    rng = random.Random(42)

    tasks = []
    # A 框架改写：每语言取若干种子，分配到对应目标栈
    by_lang = {}
    for s in manifest:
        by_lang.setdefault(s.get("language", "").lower(), []).append(s)
    for lang, lst in by_lang.items():
        targets = REWRITE_TARGETS.get(lang)
        if not targets:
            continue
        seeds = rng.sample(lst, min(len(lst), 18))
        for i, s in enumerate(seeds):
            t = targets[i % len(targets)]
            src = CORPUS / "train_pool" / s["file"]
            code = src.read_text(errors="replace")
            if len(code) > 8000:
                continue
            tasks.append({
                "key": f"A:{Path(s['file']).stem}:{i%len(targets)}",
                "kind": "framework_rewrite", "lang_out": lang,
                "prompt": build_rewrite_prompt(code, lang, s.get("expected_cwe", ""),
                                               s.get("expected_vulnerability", ""), t),
            })
    # B 跨文件：取注入类种子
    inj = [s for s in manifest if (s.get("expected_cwe") or "") in
           ("CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-918")][:16]
    for i, s in enumerate(inj):
        code = (CORPUS / "train_pool" / s["file"]).read_text(errors="replace")
        if len(code) > 6000:
            continue
        tasks.append({"key": f"B:{Path(s['file']).stem}", "kind": "crossfile",
                      "lang_out": s.get("language", "").lower(),
                      "prompt": build_crossfile_prompt(code, s.get("language", "").lower(),
                                                       s.get("expected_cwe"),
                                                       s.get("expected_vulnerability", ""))})
    # C 无污点硬安全
    for lang in dict.fromkeys(("python", "javascript", "go", "php")):  # 修复：原元组 python 重复导致两轮 key 冲突，--resume 跳过一半
        hints = SHAPE_HINTS[lang]
        if isinstance(hints, str):
            hints = [hints]
        for j, hint in enumerate((hints * 3)[:9]):
            tasks.append({"key": f"C:{lang}:{j}", "kind": "nosource_safe",
                          "lang_out": lang,
                          "prompt": build_nosource_safe_prompt(lang, hint)})
    # D 信任边界对：CWE-441/601/918 种子（弱点挖掘报告：CWE-441 仅 40 条且 0 覆盖工具，加量）
    trust = [s for s in manifest if (s.get("expected_cwe") or "") in ("CWE-441", "CWE-601", "CWE-918")][:12]
    for s in trust:
        code = (CORPUS / "train_pool" / s["file"]).read_text(errors="replace")
        if len(code) > 6000:
            continue
        tasks.append({"key": f"D:{Path(s['file']).stem}", "kind": "trust_pair",
                      "lang_out": s.get("language", "").lower(),
                      "prompt": build_trust_pair_prompt(code, s.get("language", "").lower(),
                                                        s.get("expected_cwe"),
                                                        s.get("expected_vulnerability", ""))})

    if args.per_kind_limit:
        seen_k, limited = {}, []
        for t in tasks:
            k = t["kind"]
            if seen_k.get(k, 0) >= args.per_kind_limit:
                continue
            seen_k[k] = seen_k.get(k, 0) + 1
            limited.append(t)
        tasks = limited
    if args.pilot:
        tasks = [t for t in tasks if t["kind"] == "framework_rewrite"][:3]

    done = set()
    if args.resume and PROGRESS_PATH.exists():
        for line in PROGRESS_PATH.read_text().splitlines():
            if line.strip():
                try:
                    done.add(json.loads(line)["key"])
                except Exception:
                    pass
    pending = [t for t in tasks if t["key"] not in done]
    print(f"任务总数 {len(tasks)} | 已完成 {len(done)} | 待处理 {len(pending)}", flush=True)

    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed
    lock = threading.Lock()
    stats = {"ok": 0, "reject": 0}
    out_f = open(OUT_PATH, "a" if args.resume else "w", encoding="utf-8")
    prog_f = open(PROGRESS_PATH, "a" if args.resume else "w", encoding="utf-8")

    RAW_DIR = CORPUS / "wave2_raw"
    RAW_DIR.mkdir(exist_ok=True)

    def emit(sample):
        with lock:
            out_f.write(json.dumps(sample, ensure_ascii=False) + "\n")
            out_f.flush()

    def dump_raw(key, text):
        try:
            (RAW_DIR / f"{key.replace(':', '_')}.txt").write_text(text or "", encoding="utf-8")
        except Exception:
            pass

    def run_task(t):
        t0 = time.time()
        for attempt in range(2):  # 校验失败自动重生成一次
            try:
                text = call_teacher(key, t["prompt"])
            except RuntimeError as e:
                with lock:
                    stats["reject"] += 1
                return f"✗ {t['key']}: {str(e)[:60]}"
            dump_raw(t["key"], text)
            outcome = process_output(t, text, attempt)
            if outcome is not None:
                return f"{outcome} ({time.time()-t0:.0f}s)" + (" [重生成]" if attempt else "")
        return f"✗ {t['key']}: 重生成后仍不合格"

    def _reject(msg):
        with lock:
            stats["reject"] += 1
        return f"✗ {msg}"

    def process_output(t, text, attempt):
        """校验+入库；返回状态字符串，返回 None 表示触发重生成。"""
        kind = t["kind"]
        if kind == "framework_rewrite":
            _, code = largest_code_block(text)
            if not code or len(code) < 300 or "\n" not in code:
                return None if attempt == 0 else _reject(f"{t['key']}: 无有效 code 块")
            lang_out = detect_lang(text, t["lang_out"])
            rec, err = validate(normalize_verdict_json(clean_analysis(text)), True, max(code.count("\n") + 1, 60))
            if err and attempt == 0:
                return None
            if err:
                return _reject(f"{t['key']} 被拒: {err}")
            sample = {"messages": [
                {"role": "system", "content": ALPHA05_PROMPT},
                {"role": "user", "content":
                 f"代码片段（语言: {lang_out}）：\n```{lang_out}\n{code}\n```"},
                {"role": "assistant", "content": rec["assistant"]},
            ], "meta": {"kind": "variant_framework", "task_key": t["key"],
                        "cwe": t.get("cwe"), "out_lang": lang_out}}
            emit(sample)
        elif kind == "crossfile":
            fences = code_fences(text)
            if len(fences) >= 2:
                ext = {"python": "py", "javascript": "js", "java": "java",
                       "go": "go", "php": "php"}.get(t["lang_out"] or "text", "txt")
                code = "\n\n".join(
                    f"# === file: gen_{i+1}.{ext} ===\n{b}" for i, (_, b) in enumerate(fences))
            else:
                _, code = largest_code_block(text)
            if not code or "# === file:" not in code:
                return None if attempt == 0 else _reject(f"{t['key']}: 缺多文件结构")
            lang_out = detect_lang(text, t["lang_out"] or "text")
            rec, err = validate(normalize_verdict_json(clean_analysis(text)), True, code.count("\n") + 100)
            if err and attempt == 0:
                return None
            if err:
                return _reject(f"{t['key']} 被拒: {err}")
            sample = {"messages": [
                {"role": "system", "content": ALPHA05_PROMPT},
                {"role": "user", "content":
                 f"代码片段（语言: {lang_out}，多文件项目）：\n```{lang_out}\n{code}\n```"},
                {"role": "assistant", "content": rec["assistant"]},
            ], "meta": {"kind": "variant_crossfile", "task_key": t["key"], "cwe": t.get("cwe")}}
            emit(sample)
        elif kind == "nosource_safe":
            _, code = largest_code_block(text)
            if not code:
                return None if attempt == 0 else _reject(f"{t['key']}: 无 code 块")
            if re.search(r"request\.|argv|input\(|environ|stdin|socket", code):
                return _reject(f"{t['key']}: 安全样本混入污染源")
            rec, err = validate(normalize_verdict_json(clean_analysis(text)), False, code.count("\n") + 1)
            if err and attempt == 0:
                return None
            if err:
                return _reject(f"{t['key']} 被拒: {err}")
            lang = detect_lang(text, t["lang_out"])
            sample = {"messages": [
                {"role": "system", "content": ALPHA05_PROMPT},
                {"role": "user", "content":
                 f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```"},
                {"role": "assistant", "content": rec["assistant"]},
            ], "meta": {"kind": "variant_nosource_safe", "task_key": t["key"]}}
            emit(sample)
        elif kind == "trust_pair":
            fences = code_fences(text)
            if len(fences) < 2:
                return None if attempt == 0 else _reject(f"{t['key']}: pair 围栏不足")
            v_code, s_code = fences[0][1], fences[-1][1]
            if not v_code or not s_code or v_code == s_code:
                return None if attempt == 0 else _reject(f"{t['key']}: pair 不完整")
            second_start = text.rfind("```", 0, text.rfind("```"))
            # 教师常产出「合并分析 + 两个结论块」：取同一份合并分析分别配对
            # 首个/末个结论，不按独立分析切段（切段会把 safe 侧切得只剩几行）。
            norm_text = normalize_verdict_json(text)
            jblocks = re.findall(r"```json\s*(\{.*?\})\s*```", norm_text, re.S)
            combined = clean_analysis(re.sub(r"```json\s*(\{.*?\})\s*```", "", norm_text, flags=re.S))
            if len(jblocks) < 2 or len(combined) < 60:
                return None if attempt == 0 else \
                    _reject(f"{t['key']}: pair 结论块不足({len(jblocks)})或分析过短")
            try:
                obj_v, obj_s = json.loads(jblocks[0]), json.loads(jblocks[-1])
            except json.JSONDecodeError as e:
                return None if attempt == 0 else _reject(f"{t['key']}: pair json 坏 {e}")
            errs = []
            for obj_, want, code_ in ((obj_v, True, v_code), (obj_s, False, s_code)):
                hv_ = obj_.get("has_vulnerability")
                if hv_ is not want:
                    errs.append(f"方向错 {hv_}")
                missing_ = [k for k in ("vulnerability_type", "risk_level",
                                        "explanation") if k not in obj_]
                if missing_:
                    errs.append(f"缺 {missing_}")
                if want and not str(obj_.get("vulnerability_type", "")).startswith("CWE"):
                    errs.append("类型非 CWE")
                n_ = max(code_.count("\n") + 1, 30)
                bad_anchor = [int(x) for x in set(re.findall(
                    r"line (\d+)", json.dumps(obj_, ensure_ascii=False)))
                    if not (1 <= int(x) <= n_)]
                if bad_anchor:
                    errs.append(f"行号越界 {bad_anchor[:3]}")
            if errs and attempt == 0:
                return None
            if errs:
                return _reject(f"{t['key']}: pair 校验失败 ({'|'.join(errs[:3])})")
            lang = detect_lang(text, t["lang_out"] or "text")
            for tag_, code_, obj_ in (("vuln", v_code, obj_v), ("safe", s_code, obj_s)):
                assistant = combined + "\n```json\n" + \
                    json.dumps(obj_, ensure_ascii=False) + "\n```"
                sample = {"messages": [
                    {"role": "system", "content": ALPHA05_PROMPT},
                    {"role": "user", "content":
                     f"代码片段（语言: {lang}）：\n```{lang}\n{code_}\n```"},
                    {"role": "assistant", "content": assistant},
                ], "meta": {"kind": f"variant_trust_{tag_}", "task_key": t["key"],
                            "pair": t["key"], "cwe": t.get("cwe")}}
                emit(sample)
        with lock:
            prog_f.write(json.dumps({"key": t["key"]}) + "\n")
            prog_f.flush()
            stats["ok"] += 1
        return f"✓ {t['key']}"

    workers = 1 if args.pilot else args.workers
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for i, fut in enumerate(as_completed([ex.submit(run_task, t) for t in pending])):
            print(f"  [{i+1}/{len(pending)}] {fut.result()}", flush=True)

    out_f.close(); prog_f.close()
    print(f"\n完成：{json.dumps(stats)} | 输出: {OUT_PATH}")


if __name__ == "__main__":
    main()
