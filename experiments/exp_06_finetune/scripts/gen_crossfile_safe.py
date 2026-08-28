#!/usr/bin/env python3
"""跨文件安全对照生成（2026-08-28，审计第一盲区专项）。

背景：v2.7/v2.8 的 crossfile 层 103 条全部是漏洞侧（166:0 的域内无 safe 对照），
翻转一致性（判对漏洞版后修复版仍报警）在这一层没有任何训练信号——FP 第一根因
（防御有效性判断）在跨文件域会原样复发。

做法：对 wave2 中每条 variant_crossfile（教师写的多文件漏洞项目），请教师产出
修复版多文件代码 + 安全分析 + 否定结论，构成最小对照对（实例变、结构同）。
产出与既有 crossfile 同格式（user=代码片段包装，assistant=编号分析+JSON），
过断言门（七字段/hv=false/行号越界）与泄漏门（J≥0.3/C≥0.5 对四个评测集）。

用法：
  TEACHER_API_URL=https://open.bigmodel.cn/api/paas/v4/chat/completions \
  TEACHER_KEY=... python gen_crossfile_safe.py --pilot     # 2 条试跑
  ... python gen_crossfile_safe.py --resume --workers 4    # 断点续跑
"""
import argparse
import json
import os
import re
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(Path(__file__).parent))
from graduation_project.prompts import ALPHA05_PROMPT
from distill_alpha_pairs import call_teacher

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
SRC = CORPUS / "distill_variants_wave2.jsonl"
OUT_PATH = CORPUS / "crossfile_safe_pairs.jsonl"
PROGRESS_PATH = CORPUS / "crossfile_safe_progress.jsonl"

PROMPT_TMPL = """你要为漏洞检测模型生成一条【安全版】训练数据：下述多文件项目当前版本存在已确认的{cwe}漏洞，请产出修复版本及其安全分析。

【当前版本代码（含漏洞）】
{code}

【输出格式——严格三段，顺序不可变】
1. 第一段：``` 包裹的修复后完整多文件代码——保持 "# === file: 路径 ===" 分段注释与原有文件划分；
   在正确的层级加入防御（参数化查询/白名单精确允许集/框架自动防护/集中式授权校验），
   禁止使用可绕过的黑名单或单点正则；除防御相关行外，其余代码逐行保留。
2. 第二段：3~5 步编号分析——逐步说明原漏洞数据流如何被新增防御阻断（每步锚定修复版真实行号），
   并检查替代通道/第二入口是否被同一防御覆盖（如另一条路由、另一函数、直接构造调用），
   确认无绕过后再下结论。
3. 第三段：```json 结论，七字段一字不差：
{{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "None", "source": "N/A", "sink": "N/A", "explanation": "<用 -> 串联的真实阻断逻辑摘要，禁止照抄本示例的占位文字>", "fix_suggestion": "no fix needed"}}

【硬性要求】
- JSON 字符串值内严禁英文双引号；
- 修复必须针对本项目的真实漏洞点，不得改写无关逻辑；
- 分析里所有 line N 必须落在修复版代码的真实行号范围内。"""


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


def parse_output(text: str):
    """返回 (fixed_code, analysis, obj) 或 (None, err)"""
    blocks = re.findall(r"```([\w+-]*)\n(.*?)```", text, re.S)
    if len(blocks) < 2:
        return None, "代码/结论块不足"
    jm = re.search(r"```json\s*(\{.*?\})\s*```", text, re.S)
    if not jm:
        return None, "无 json 块"
    try:
        obj = json.loads(jm.group(1))
    except json.JSONDecodeError as e:
        return None, f"json 解析失败: {e}"
    if obj.get("has_vulnerability") is not False:
        return None, "方向非 false"
    # 代码块：最长且含 file 分段标记的块
    code_blocks = [b for lang, b in blocks if "# === file:" in b or "# ==== file:" in b]
    if not code_blocks:
        return None, "无多文件代码块"
    fixed = max(code_blocks, key=len)
    analysis = text[: text.rfind("```json")].strip()
    # 去掉第一段代码块本身，只留分析部分
    first_end = text.find("```", text.find("```") + 3)
    analysis = text[first_end + 3: text.rfind("```json")].strip()
    if len(analysis) < 200:
        return None, "分析过短"
    return (fixed, analysis, obj), None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", action="store_true")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()

    key = os.environ.get("TEACHER_KEY") or os.environ.get("OPENROUTER_KEY") or ""
    if not key:
        print("需要 TEACHER_KEY", file=sys.stderr)
        sys.exit(1)

    recs = [json.loads(l) for l in SRC.read_text(encoding="utf-8").splitlines() if l.strip()]
    cross = [r for r in recs if (r.get("meta") or {}).get("kind") == "variant_crossfile"]
    done = set()
    if args.resume and PROGRESS_PATH.exists():
        for l in PROGRESS_PATH.read_text(encoding="utf-8").splitlines():
            if l.strip():
                try:
                    done.add(json.loads(l)["key"])
                except Exception:
                    pass
    tasks = []
    for r in cross:
        u = r["messages"][1]["content"]
        k = (r["meta"] or {}).get("task_key") or f"cf{len(tasks)}"
        if k in done:
            continue
        lang = (re.search(r"语言[:：]\s*(\w+)", u).group(1) if re.search(r"语言[:：]\s*(\w+)", u) else "text")
        cwe = (r["meta"] or {}).get("cwe") or "相应 CWE 类别"
        tasks.append({"key": k, "lang": lang, "cwe": cwe, "user": u})
    if args.pilot:
        tasks = tasks[:2]
    print(f"crossfile 源 {len(cross)} | 待处理 {len(tasks)}", flush=True)
    if not tasks:
        return

    exams = build_exams()
    exam_norm = {k: norm_lines(v) for k, v in exams.items()}
    stats = Counter()
    lock = threading.Lock()
    out_f = open(OUT_PATH, "a", encoding="utf-8")
    prog_f = open(PROGRESS_PATH, "a", encoding="utf-8")

    def run_task(t):
        try:
            text = call_teacher(key, PROMPT_TMPL.format(cwe=t["cwe"], code=t["user"]))
        except Exception as e:
            with lock:
                stats["fail"] += 1
            return f"✗ {t['key']}: {str(e)[:70]}"
        if not text or not text.strip():
            time.sleep(6)
            return f"✗ {t['key']}: 空输出"
        parsed, err = parse_output(text)
        if not parsed:
            with lock:
                stats["reject"] += 1
            return f"✗ {t['key']}: {err}"
        fixed, analysis, obj = parsed
        n_lines = fixed.count("\n") + 1
        bad = [int(n) for n in set(re.findall(r"line (\d+)", analysis))
               if not (1 <= int(n) <= n_lines)]
        if bad:
            with lock:
                stats["reject"] += 1
            return f"✗ {t['key']}: 行号越界 {bad[:3]}"
        user = f"代码片段（语言: {t['lang']}，多文件项目）：\n```\n{fixed}\n```"
        un = norm_lines(user)
        for ek, ev in exam_norm.items():
            if not un or not ev:
                continue
            j = len(un & ev) / len(un | ev)
            c = len(un & ev) / min(len(un), len(ev))
            if j >= 0.3 or c >= 0.5:
                with lock:
                    stats["leak"] += 1
                return f"✗ {t['key']}: 泄漏 vs {ek}"
        rec = {"messages": [
            {"role": "system", "content": ALPHA05_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": analysis + "\n\n```json\n" +
                json.dumps(obj, ensure_ascii=False) + "\n```"},
        ], "meta": {"kind": "variant_crossfile_safe", "task_key": t["key"],
                    "cwe": t["cwe"], "lang": t["lang"]}}
        with lock:
            out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            out_f.flush()
            prog_f.write(json.dumps({"key": t["key"]}) + "\n")
            prog_f.flush()
            stats["ok"] += 1
            n = stats["ok"]
        return f"[{n}] ✓ {t['key']}"

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(run_task, t) for t in tasks]
        for fu in as_completed(futs):
            print(fu.result(), flush=True)
    print(f"完成: {dict(stats)} | 输出 {OUT_PATH}", flush=True)


if __name__ == "__main__":
    main()
