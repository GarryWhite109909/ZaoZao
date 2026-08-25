#!/usr/bin/env python3
"""长文件梯度补充蒸馏（alpha06-v2.3 修复项，P1）。

背景：v2.2 中 >4k token 样本仅 2.6%（224/8635），而 rolling_dev 实测长文件
出现 OOM/静默截断/unknown 等 5 种坏结局；训练分布与部署分布的长度错配是
已被证实的失败模式，12288 长度守门留出的 4k~12k 空间基本空置
（数据分布审计 2026-08-25 P1 项）。

做法：train_pool 长文件（>=MIN_LINES 行）× 双方向：
  vuln 侧 = 教师分析 train_pool 原文件（CVE 漏洞文件）；
  safe 侧 = 教师分析 train_pool_fixed 官方修复版（_fixed 文件已由既有管道产出）。
天然 minimal pair + 真实 CVE 形态，直接补"真实代码数据流复杂度"。

种子规模：train_pool >=120 行约 232 个文件 → 464 条；--min-lines 80 可扩到
约 600 条。目标并入后 >4k token 占比 8~10%。

泄漏纪律：种子只用 train_pool / train_pool_fixed（训练侧资产），
禁用 rolling_dev / rolling_dev_safe（一次性测量集）。

校验门（在 validate 之上）：
  1) verdict 方向与种子一致（vuln 文件→true；fixed 文件→false）；
  2) 行号锚定真实文件（validate 内建）；
  3) 产出总 token（用 chars/3 粗估）落在 [3500, 12000]，低于下限说明
     教师没认真分析长文件（只看了前半），高于上限会在训练时被截断。

输出：corpus/long_file_wave.jsonl（构建 v2.3+ 时并入）
用法：
  $env:OPENROUTER_KEY="sk-or-..."; python gen_long_file_wave.py --pilot
  $env:OPENROUTER_KEY="sk-or-..."; python gen_long_file_wave.py --resume --workers 4 --min-lines 80
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
from gen_alpha06_variants import clean_analysis, normalize_verdict_json

CORPUS = PROJECT / "experiments/exp_06_finetune/corpus"
VULN_DIR = CORPUS / "train_pool"
FIXED_DIR = CORPUS / "train_pool_fixed"
OUT_PATH = CORPUS / "long_file_wave.jsonl"
PROGRESS_PATH = CORPUS / "long_file_progress.jsonl"
RAW_DIR = CORPUS / "long_file_raw"

MIN_TOKEN, MAX_TOKEN = 3500, 12000  # chars/3 粗估口径
LANG_BY_EXT = {".py": "python", ".js": "javascript", ".java": "java",
               ".php": "php", ".go": "go", ".ts": "typescript"}

# 教师专注分析的指令（不给生成自由度，防止改写代码）
PROMPT_TMPL = """分析下面这段完整的 {lang} 真实代码（来自开源项目），判断是否存在安全漏洞。

【分析要求】
1. 这是长文件：必须通读全文，逐一枚举所有入口点（路由/参数/文件/环境/回调），不得只看前半；
2. 对每条 source→sink 数据流验证防御有效性；黑名单/正则过滤视为可绕过，不算有效防御；
3. 检查第二入口与替代通道；
4. 结论必须基于全文证据，不得猜测。

【代码】
```{lang}
{code}
```

先写编号分析（每步锚定真实行号"第 N 行"，覆盖全文主要函数），最后输出 ```json 结论：
{verdict_line}
注意：JSON 字符串值内严禁出现英文双引号，需要引用代码时使用单引号或反引号。"""

VULN_VERDICT = ('{"has_vulnerability": true, "vulnerability_type": "CWE-... ", '
                '"risk_level": "...", "source": "line N: ...", "sink": "line N: ...", '
                '"explanation": "... -> ...", "fix_suggestion": "line N: ..."}')
SAFE_VERDICT = ('{"has_vulnerability": false, "vulnerability_type": "none", '
                '"risk_level": "none", "source": "N/A", "sink": "N/A", '
                '"explanation": "...", "fix_suggestion": "no fix needed"}')


def detect_lang_of(path: Path, code: str) -> str:
    lang = LANG_BY_EXT.get(path.suffix.lower())
    if lang:
        return lang
    if "def " in code or "import " in code[:2000]:
        return "python"
    return "java"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", action="store_true")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--workers", type=int, default=2,
                    help="长文件分析耗 token，建议 2~3 防限流")
    ap.add_argument("--min-lines", type=int, default=120,
                    help="种子文件最小行数（80 可扩量至 ~600 条）")
    ap.add_argument("--only-vuln", action="store_true",
                    help="只跑 vuln 侧（safe 侧延后）")
    args = ap.parse_args()

    key = os.environ.get("OPENROUTER_KEY", "")
    if not key:
        print("错误：需要 OPENROUTER_KEY", file=sys.stderr)
        sys.exit(1)

    tasks = []
    for f in sorted(VULN_DIR.glob("corpus_*")):
        if f.suffix.lower() not in LANG_BY_EXT:
            continue
        code = f.read_text(errors="replace")
        if code.count("\n") + 1 < args.min_lines:
            continue
        lang = detect_lang_of(f, code)
        tasks.append({"key": f"L:vuln:{f.stem}", "lang": lang, "code": code,
                      "expect_vuln": True,
                      "prompt": PROMPT_TMPL.format(
                          lang=lang, code=code, verdict_line=VULN_VERDICT)})
        if args.only_vuln:
            continue
        ff = FIXED_DIR / (f.stem + "_fixed" + f.suffix)
        if ff.exists():
            fcode = ff.read_text(errors="replace")
            tasks.append({"key": f"L:safe:{f.stem}", "lang": lang, "code": fcode,
                          "expect_vuln": False,
                          "prompt": PROMPT_TMPL.format(
                              lang=lang, code=fcode, verdict_line=SAFE_VERDICT)})
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
    stats = {"ok": 0, "reject": 0, "too_short": 0, "too_long": 0}
    out_f = open(OUT_PATH, "a" if args.resume else "w", encoding="utf-8")
    prog_f = open(PROGRESS_PATH, "a" if args.resume else "w", encoding="utf-8")

    def emit(sample):
        with lock:
            out_f.write(json.dumps(sample, ensure_ascii=False) + "\n")
            out_f.flush()

    def process_output(t, text, attempt):
        def regen_or_fail(msg, stat_key):
            with lock:
                stats[stat_key] += 1
            return ("regen", msg) if attempt == 0 else ("fail", msg)

        analysis = clean_analysis(text)
        rec, err = validate(normalize_verdict_json(analysis if "```json" in analysis
                                                   else text), t["expect_vuln"],
                            t["code"].count("\n") + 1)
        if err:
            return regen_or_fail(f"{t['key']} 被拒: {err}", "reject")
        total_chars = len(ALPHA05_PROMPT) + len(t["code"]) + len(rec["assistant"])
        est_tok = total_chars // 3
        if est_tok < MIN_TOKEN:
            return regen_or_fail(
                f"{t['key']}: 产出过短 est~{est_tok} tok（教师可能没通读全文）",
                "too_short")
        if est_tok > MAX_TOKEN:
            return regen_or_fail(f"{t['key']}: 超 12288 守门 est~{est_tok} tok",
                                 "too_long")
        sample = {"messages": [
            {"role": "system", "content": ALPHA05_PROMPT},
            {"role": "user", "content":
             f"代码片段（语言: {t['lang']}）：\n```{t['lang']}\n{t['code']}\n```"},
            {"role": "assistant", "content": rec["assistant"]},
        ], "meta": {"kind": f"long_file_{'vuln' if t['expect_vuln'] else 'safe'}",
                    "seed_file": t["key"].split(":")[-1] + (
                        "" if t["expect_vuln"] else "_fixed"),
                    "out_lang": t["lang"],
                    "est_tokens": est_tok}}
        emit(sample)
        return ("ok", t["key"])

    def run_task(t):
        t0 = time.time()
        # 长文件：max_tokens 提到 10000（分析篇幅 + 推理模型思考预算）
        for attempt in range(3):
            try:
                text = call_teacher(key, t["prompt"], max_tokens=10000)
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
