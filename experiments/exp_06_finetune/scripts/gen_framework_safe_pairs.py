#!/usr/bin/env python3
"""framework 变体 safe 配对生成（alpha06-v2.3 修复项，P1）。

背景：v2.2 中 variant_framework 115 条全部 vuln 方向、零 safe 对照
（数据分布审计 2026-08-25 P1 项），存在"见框架习语→报漏洞"的形态触发
偏置风险（FP 第一根因"猜测式报警"的数据侧镜像）。

做法：以 wave2 的 framework vuln 样本代码为种子，教师生成同框架习语 +
有效防御的 safe 版本（minimal pair：代码形态保持、仅防御语义反转）。

校验门（在 validate 之上）：
  1) verdict 必须 has_vulnerability=false；
  2) 代码或分析必须出现强防御证据（参数化/白名单/转义/预编译...）；
  3) 与原 vuln 代码 shingle Jaccard >= 0.35（保持框架习语形态，
     防止教师重写成完全无关代码）；上不封顶（防御插入自然降相似度）。

输出：corpus/framework_safe_pairs.jsonl（构建 v2.3+ 时并入）
用法：
  $env:OPENROUTER_KEY="sk-or-..."; python gen_framework_safe_pairs.py --pilot
  $env:OPENROUTER_KEY="sk-or-..."; python gen_framework_safe_pairs.py --resume --workers 4
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
from gen_alpha06_variants import (SCHEMA_LOCK, largest_code_block,
                                   detect_lang, clean_analysis,
                                   normalize_verdict_json)

CORPUS = PROJECT / "experiments/exp_06_finetune/corpus"
SEED = CORPUS / "distill_variants_wave2.jsonl"
OUT_PATH = CORPUS / "framework_safe_pairs.jsonl"
PROGRESS_PATH = CORPUS / "framework_safe_progress.jsonl"
RAW_DIR = CORPUS / "framework_safe_raw"

STRONG_DEFENSE_EV = re.compile(
    r"参数化|白名单|转义|escape|预编译|prepare|placeholder|allowlist"
    r"|whitelist|escapeshellarg|shlex|ENT_QUOTES|参数数组|execFile|参数绑定"
    r"|realpath|resolve\(|参数化查询|PreparedStatement"
    # 密码学类 CWE-327/798 的强防御形态（2026-08-26 补：原词表缺位导致
    # 弱哈希样本的 safe 侧无论怎么修都过不了证据门）
    r"|hmac|sha-?256|bcrypt|argon2|password_hash|scrypt|随机盐"
    r"|compare_digest|getenv|os\.environ\b", re.I)


def shingle(code: str, n=8):
    words = re.sub(r"\s+", " ", code.lower()).split()
    return {" ".join(words[j:j + n]) for j in range(max(0, len(words) - n + 1))}


def build_prompt(lang, vuln_code, cwe_hint):
    return f"""你要为漏洞检测模型生成一条【框架习语安全样本】训练数据：把下面这段存在漏洞的 {lang} 框架代码改写成【安全版本】，作为它的 minimal pair 对照。

【原漏洞代码（{lang}，漏洞类型 {cwe_hint}）】
```{lang}
{vuln_code}
```

【硬性要求——违反任一条即废】
1. 保持原代码的框架习语与整体结构：同框架（路由注册/中间件/依赖注入/ORM 用法不变）、同业务场景、同数据流走向；不得换框架、换业务、换漏洞类型场景。
2. 【最小 diff 纪律】函数名、路由路径、类名、变量名与整体控制流必须与原代码保持一致（防御必需的新增辅助函数/参数除外），只允许插入或替换防御相关语句；整段重写、更换标识符都会导致样本直接废弃。
3. 修复必须是【有效防御】：参数化查询/预编译、白名单精确允许集、正确转义、框架原生安全 API 之一；黑名单、正则过滤、str_replace 不算有效防御，禁止作为修复手段。
4. 若原代码有多个数据流，只要求修复目标漏洞所在数据流，其余保持原样（保持 minimal pair 的局部对照性）。
5. {SCHEMA_LOCK}

【输出格式】
LANG: <语言，小写>
```code
<修复后的完整代码>
```
然后写 4~6 步编号分析，每步锚定真实行号（"第 N 行"）：
- 第 1 步枚举用户可控输入点（框架参数绑定/请求对象字段）；
- 中间步骤追踪到 sink，逐段论证防御的类型正确性、位置正确性、攻击面覆盖完整性；
- 最后交代第二入口/替代通道检查结论。

最后输出 ```json 结论：
{{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "none", "source": "N/A", "sink": "N/A", "explanation": "...", "fix_suggestion": "no fix needed"}}
注意：JSON 字符串值内严禁出现英文双引号，需要引用代码时使用单引号或反引号。"""


def load_seeds():
    seeds = []
    seen = set()  # wave2 meta 的 task_key 有重复（2026-08-26 实测 97 条仅 79 唯一），
                  # 不去重会同一种子并发蒸馏多次、输出重复样本
    for line in SEED.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        d = json.loads(line)
        m = d.get("meta") or {}
        if m.get("kind") != "variant_framework":
            continue
        user = next(x["content"] for x in d["messages"] if x["role"] == "user")
        cm = re.search(r"```[\w+-]*\n(.*?)\n```", user, re.S)
        if not cm:
            continue
        obj = json.loads(re.findall(r"```json\s*(\{.*?\})\s*```",
                                    next(x["content"] for x in d["messages"]
                                         if x["role"] == "assistant"), re.S)[-1])
        key = "F:" + (m.get("task_key") or str(len(seeds)))
        if key in seen:
            continue
        seen.add(key)
        seeds.append({
            "key": key,
            "lang": m.get("out_lang") or detect_lang(user, "python"),
            "code": cm.group(1),
            "cwe": obj.get("vulnerability_type", "CWE-78"),
        })
    return seeds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", action="store_true")
    ap.add_argument("--resume", action="store_true",
                    help="兼容旧用法：断点续跑已是默认行为")
    ap.add_argument("--fresh", action="store_true",
                    help="清空输出/进度文件从头重跑（默认总是追加，防止误截断已完成样本）")
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()

    key = os.environ.get("OPENROUTER_KEY", "")
    if not key:
        print("错误：需要 OPENROUTER_KEY", file=sys.stderr)
        sys.exit(1)

    seeds = load_seeds()
    print(f"framework vuln 种子: {len(seeds)} 条", flush=True)
    tasks = [{"key": s["key"], "lang": s["lang"], "code": s["code"],
              "cwe": s["cwe"],
              "sig": shingle(s["code"]),
              "prompt": build_prompt(s["lang"], s["code"], s["cwe"])}
             for s in seeds]
    if args.pilot:
        tasks = tasks[:2]

    done = set()
    if not args.fresh and PROGRESS_PATH.exists():
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
    stats = {"ok": 0, "reject": 0, "no_defense": 0, "drift": 0}
    mode = "w" if args.fresh else "a"
    out_f = open(OUT_PATH, mode, encoding="utf-8")
    prog_f = open(PROGRESS_PATH, mode, encoding="utf-8")

    def emit(sample):
        with lock:
            out_f.write(json.dumps(sample, ensure_ascii=False) + "\n")
            out_f.flush()

    def process_output(t, text, attempt):
        def regen_or_fail(msg, stat_key):
            with lock:
                stats[stat_key] += 1
            return ("regen", msg) if attempt < 2 else ("fail", msg)

        _, code = largest_code_block(text)
        if not code or len(code) < 200 or "\n" not in code:
            return regen_or_fail(f"{t['key']}: 无有效 code 块", "reject")
        lang_out = detect_lang(text, t["lang"])
        analysis = clean_analysis(text)
        rec, err = validate(normalize_verdict_json(analysis if "```json" in analysis
                                                   else text), False,
                            code.count("\n") + 1)
        if err:
            return regen_or_fail(f"{t['key']} 被拒: {err}", "reject")
        if not STRONG_DEFENSE_EV.search(code + analysis):
            return regen_or_fail(f"{t['key']}: safe 侧无强防御证据", "no_defense")
        j = len(shingle(code) & t["sig"]) / max(1, len(shingle(code) | t["sig"]))
        if j < 0.35:
            return regen_or_fail(f"{t['key']}: 与原 vuln 形态漂移 J={j:.2f}", "drift")
        sample = {"messages": [
            {"role": "system", "content": ALPHA05_PROMPT},
            {"role": "user", "content":
             f"代码片段（语言: {lang_out}）：\n```{lang_out}\n{code}\n```"},
            {"role": "assistant", "content": rec["assistant"]},
        ], "meta": {"kind": "framework_safe_pair", "cwe": t["cwe"],
                    "task_key": t["key"], "out_lang": lang_out,
                    "pair_of": "variant_framework"}}
        emit(sample)
        return ("ok", t["key"])

    def run_task(t):
        t0 = time.time()
        prompt = t["prompt"]
        for attempt in range(3):
            try:
                text = call_teacher(key, prompt)
            except RuntimeError as e:
                with lock:
                    stats["reject"] += 1
                return f"✗ {t['key']}: {str(e)[:60]}"
            suffix = "" if attempt == 0 else f"_r{attempt}"
            (RAW_DIR / f"{t['key'].replace(':', '_')}{suffix}.txt").write_text(
                text or "", encoding="utf-8")
            status, msg = process_output(t, text, attempt)
            if status == "regen":
                # 把拒绝原因回灌给教师，避免同 prompt 盲抽（2026-08-25 实测
                # 同 prompt 重试 12/12 仍漂移）；按失败类型给针对性指令
                reason = msg.split(': ', 1)[-1]
                extra = ("重新生成时必须保留原代码的函数名、路由路径、变量名与控制流，"
                         "只做防御相关的最小修改；与原代码形态差异过大将被直接废弃。")
                if "无强防御证据" in reason:
                    extra = ("修复必须采用强防御机制，并在代码与分析中明确写出机制名称"
                             "（参数化查询/预编译、白名单精确允许集、输出转义、"
                             "框架原生安全 API）；黑名单或正则过滤不算有效防御。")
                prompt = t["prompt"] + \
                    f"\n\n【重生成要求——上一次输出因「{reason}」被拒】{extra}"
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
