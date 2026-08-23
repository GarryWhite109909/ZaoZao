#!/usr/bin/env python3
"""OpenRouter 教师蒸馏：语料样本 → alpha05 格式训练数据（漏洞侧 + minimal pair 安全侧）。

设计要点：
  - 训练样本的 system/user 与 final_train_chatml_alpha05.jsonl 完全同构
    （system=ALPHA05_PROMPT 原文，user="代码片段（语言: x）"+code fence），
    assistant 为编号步骤 CoT + ```json 七字段结论；
  - 漏洞侧：把 GHSA/NVD 标签与修复 diff 作为【事实校准】喂给教师——标签不靠教师定，
    教师只负责写出锚定真实行号的自然分析；这从根上避免教师误标；
  - 安全侧（minimal pair）：同一文件的修复后版本，模型要指出哪个防御中和了哪条数据流
    ——"形似实安全"的黄金负样本，直接针对 FP 弱点；
  - 校验：JSON 可解析、七字段齐全、判定方向符合预期、行号锚点在文件范围内。

用法：
  OPENROUTER_KEY=sk-or-... python3 distill_alpha_pairs.py --pilot        # 4 条试跑
  OPENROUTER_KEY=sk-or-... python3 distill_alpha_pairs.py --resume       # 全量断点续跑
"""
import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))
from graduation_project.prompts import ALPHA05_PROMPT

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
OUT_PATH = CORPUS / "distill_alpha_pairs.jsonl"
PROGRESS_PATH = CORPUS / "distill_progress.jsonl"

API_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = os.environ.get("TEACHER_MODEL", "stealth/ox-alpha")

SCHEMA_VULN = ('{"has_vulnerability": true, "vulnerability_type": "CWE-编号 漏洞名", '
               '"risk_level": "Critical/High/Medium/Low", "source": "line N: ...", '
               '"sink": "line N: ...", "explanation": "... -> ...", '
               '"fix_suggestion": "line N: ..."}')
SCHEMA_SAFE = ('{"has_vulnerability": false, "vulnerability_type": "none", '
               '"risk_level": "None", "source": "N/A", "sink": "N/A", '
               '"explanation": "...", "fix_suggestion": "no fix needed"}')


def call_teacher(key: str, user_prompt: str, max_tokens: int = 6000,
                 temperature: float = 0.4, retries: int = 5) -> str:
    import requests
    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": user_prompt}],
        "max_tokens": max_tokens,
        "temperature": temperature,
        # 教师是推理模型：不限思考长度会把 token 预算全部耗在 reasoning 上
        # 导致正文为空（实测 2026-08-22）。medium 平衡分析质量与产出稳定性。
        "reasoning": {"effort": os.environ.get("TEACHER_EFFORT", "medium")},
    }
    for attempt in range(retries):
        try:
            resp = requests.post(
                API_URL, timeout=240,
                headers={"Authorization": f"Bearer {key}",
                         "Content-Type": "application/json"},
                json=payload)
            if resp.status_code == 429:
                wait = int(resp.headers.get("X-RateLimit-Reset", "60") or 60)
                print(f"    [429] 等待 {min(wait, 180)}s", flush=True)
                time.sleep(min(wait, 180))
                continue
            resp.raise_for_status()
            try:
                data = resp.json()
            except ValueError:
                # 大响应偶发截断/非 JSON（2026-08-23 实测）：带诊断重试
                raise ValueError(f"non-json body: {resp.text[:120]!r}")
            msg = data["choices"][0]["message"]
            content = msg.get("content")
            if not content and msg.get("reasoning"):
                # 推理模型偶发只回 reasoning：重试
                raise ValueError("empty content (reasoning only)")
            return content or ""
        except Exception as e:
            wait = 20 * (attempt + 1)
            print(f"    [重试 {attempt+1}/{retries}] {type(e).__name__}: {str(e)[:80]}", flush=True)
            time.sleep(wait)
    raise RuntimeError("teacher 调用失败（重试耗尽）")


def build_vuln_prompt(code: str, lang: str, cwe: str, desc: str, patch: str) -> str:
    return f"""你要为一段【确认存在漏洞】的真实项目代码撰写安全分析，用于训练数据。你的结论必须与给定事实一致，但分析过程要像独立审查一样自然。

【代码】（语言: {lang}）
```
{code}
```

【事实校准】（内部参考，分析中不得提及本节或 diff）
- 该文件来自真实项目某安全修复 commit 的父版本，被标注为 {cwe}
- 漏洞描述：{(desc or cwe)[:300]}
- 官方修复 diff（摘要）：
{(patch or '(无 diff)')[:1500]}

【输出要求】
0. 直接以"1."编号步骤开始，不要使用 markdown 标题、加粗或分节符。
1. 先写 3~6 步编号分析。每步必须锚定【真实存在】的行号（格式如"第 12 行"），引用代码里真实的函数名/变量名；从入口(source)追踪到危险操作(sink)，说明为何防御缺失或无效。
2. 分析结束后，另起一行输出 ```json 包裹的结论，字段严格如下（一字不差）：
{SCHEMA_VULN}
3. source/sink 写成 "line N: 真实代码片段"；fix_suggestion 单行、行号必须真实存在；explanation 用 "->" 描述数据流。
4. vulnerability_type 必须以 "{cwe}" 开头。"""


def build_safe_prompt(code: str, lang: str, cve_hint: str) -> str:
    return f"""你要为一段【已确认安全】的真实项目代码撰写安全审查分析，用于训练"形似实安全"样本。这段代码常被误判为有漏洞，你的任务是解释为什么它是安全的。

【代码】（语言: {lang}）
```
{code}
```
（背景参考：该文件所在模块曾有姊妹漏洞 {cve_hint}，但当前版本已包含正确防护。）

【输出要求】
0. 直接以"1."编号步骤开始，不要使用 markdown 标题、加粗或分节符。
1. 先写 3~5 步编号分析。每步锚定【真实存在】的行号（格式如"第 8 行"），指出关键防御机制（参数化/白名单/转义/框架自动防护等）位于哪里、覆盖了哪条攻击面；如有看起来危险但实际不可达的 sink，要明确说明为何不可达（无外部输入/字面量/框架保证）。
2. 分析结束后，另起一行输出 ```json 包裹的结论，字段严格如下：
{SCHEMA_SAFE}
3. explanation 说明防御如何完整覆盖攻击面（用 "->" 描述）。"""


def validate(text: str, expect_vuln: bool, n_lines: int):
    """返回 (record_dict, err)。err=None 表示通过。"""
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.S)
    if not m:
        return None, "无 json 块"
    raw = m.group(1)
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        # 教师写正则时常漏双反斜杠（如 "\d+"）：把非法转义修成合法后重试
        fixed = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', raw)
        try:
            obj = json.loads(fixed)
        except json.JSONDecodeError as e:
            return None, f"json 解析失败: {e}"
    required = ["has_vulnerability", "vulnerability_type", "risk_level",
                "source", "sink", "explanation", "fix_suggestion"]
    missing = [k for k in required if k not in obj]
    if missing:
        return None, f"缺字段: {missing}"
    hv = obj.get("has_vulnerability")
    if expect_vuln and hv is not True:
        return None, f"判定方向错误: has_vulnerability={hv}"
    if not expect_vuln and hv is not False:
        return None, f"判定方向错误: has_vulnerability={hv}"
    # 行号范围检查
    body = json.dumps(obj, ensure_ascii=False)
    for ln in {int(n) for n in re.findall(r"line (\d+)", body)}:
        if not (1 <= ln <= max(n_lines, 1)):
            return None, f"行号越界: line {ln} > {n_lines}"
    cot = text[:m.start()].strip()
    if len(cot) < 80:
        return None, "分析过短"
    assistant = cot + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```"
    return {"verdict": obj, "assistant": assistant}, None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pilot", action="store_true", help="只跑 4 条验证质量")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--max-samples", type=int, default=0)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()

    key = os.environ.get("OPENROUTER_KEY", "")
    if not key:
        print("错误：需要 OPENROUTER_KEY 环境变量", file=sys.stderr)
        sys.exit(1)

    manifest = json.loads((CORPUS / "train_pool" / "manifest.json").read_text())
    fixed_map_path = CORPUS / "train_pool_fixed" / "fixed_map.json"
    fixed_map = json.loads(fixed_map_path.read_text()) if fixed_map_path.exists() else {}

    done_keys = set()
    if args.resume and PROGRESS_PATH.exists():
        for line in PROGRESS_PATH.read_text().splitlines():
            if not line.strip():
                continue
            try:
                done_keys.add(json.loads(line).get("key"))
            except json.JSONDecodeError:
                continue  # 停电等造成的撕裂行：跳过（该任务会被重做）

    # ---- 组装任务列表（漏洞侧 + 有修复版时的安全侧）----
    tasks = []
    for s in manifest["samples"]:
        stem = Path(s["file"]).stem
        lang = (s.get("language") or "text").lower()
        src = CORPUS / "train_pool" / s["file"]
        code = src.read_text(errors="replace")
        n_lines = code.count("\n") + 1
        patch = ""
        pf = s.get("patch_file")
        if pf and (CORPUS / pf).exists():
            patch = (CORPUS / pf).read_text(errors="replace")
        tasks.append({
            "key": f"{stem}:vuln", "expect_vuln": True, "code": code,
            "n_lines": n_lines, "lang": lang, "seed": s["file"],
            "cve_id": s.get("cve_id"), "cwe": s.get("expected_cwe"),
            "prompt": build_vuln_prompt(code, lang, s.get("expected_cwe", ""),
                                        s.get("expected_vulnerability", ""), patch),
            "src_file": src.name,
        })
        info = fixed_map.get(stem) or {}
        if info.get("status") == "ok":
            fixed_code = (CORPUS / "train_pool_fixed" / info["fixed_file"]).read_text(errors="replace")
            tasks.append({
                "key": f"{stem}:safe", "expect_vuln": False, "code": fixed_code,
                "n_lines": fixed_code.count("\n") + 1, "lang": lang, "seed": s["file"],
                "cve_id": s.get("cve_id"), "cwe": s.get("expected_cwe"),
                "prompt": build_safe_prompt(fixed_code, lang, s.get("cve_id", "")),
                "src_file": info["fixed_file"],
            })

    if args.pilot:
        tasks = tasks[:8]
    if args.max_samples:
        tasks = tasks[:args.max_samples]
    pending = [t for t in tasks if t["key"] not in done_keys]
    print(f"任务总数 {len(tasks)} | 已完成 {len(done_keys)} | 待处理 {len(pending)}", flush=True)

    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed
    lock = threading.Lock()
    stats = {"ok": 0, "reject": 0}
    out_f = open(OUT_PATH, "a", encoding="utf-8") if args.resume else open(OUT_PATH, "w", encoding="utf-8")
    prog_f = open(PROGRESS_PATH, "a", encoding="utf-8") if args.resume else open(PROGRESS_PATH, "w", encoding="utf-8")

    def run_task(t):
        t0 = time.time()
        try:
            text = call_teacher(key, t["prompt"])
        except RuntimeError as e:
            with lock:
                stats["reject"] += 1
            return f"✗ {t['key']}: {str(e)[:60]}"
        rec, err = validate(text, t["expect_vuln"], t["n_lines"])
        if err:
            with lock:
                stats["reject"] += 1
            return f"✗ {t['key']} 被拒: {err}"
        kind = "vuln" if t["expect_vuln"] else "safe_pair"
        sample = {"messages": [
            {"role": "system", "content": ALPHA05_PROMPT},
            {"role": "user", "content":
             f"代码片段（语言: {t['lang']}）：\n```{t['lang']}\n{t['code']}\n```"},
            {"role": "assistant", "content": rec["assistant"]},
        ], "meta": {"cve_id": t["cve_id"], "kind": kind,
                    "seed_file": t["seed"], "cwe": t["cwe"]}}
        with lock:
            out_f.write(json.dumps(sample, ensure_ascii=False) + "\n")
            prog_f.write(json.dumps({"key": t["key"]}) + "\n")
            out_f.flush(); prog_f.flush()
            stats["ok"] += 1
        return f"✓ {t['key']} ({time.time()-t0:.0f}s)"

    workers = 1 if args.pilot else args.workers
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for i, fut in enumerate(as_completed([ex.submit(run_task, t) for t in pending])):
            print(f"  [{i+1}/{len(pending)}] {fut.result()}", flush=True)

    out_f.close(); prog_f.close()
    print(f"\n完成：{json.dumps(stats)} | 输出: {OUT_PATH}")


if __name__ == "__main__":
    main()
