#!/usr/bin/env python3
"""检查清单 CoT 重蒸馏（alpha06-v2 修复项：弱点挖掘报告 第十节 ②）。

背景：alpha06 训练集 3997 条漏洞 CoT 仅 5 条执行过"第二入口"检查——system 里
声明了固定清单但 assistant 演示率≈0。本脚本从 train_pool 按 CWE×语言 分层抽样
（默认 ~300 条），请教师按【强制清单】重写分析：枚举输入点→可达性→防御逐一
验证→第二入口/替代通道→结论。CVE 标签与修复 diff 作为事实校准喂给教师
（标签不靠教师定，同 distill_alpha_pairs 方法论），产出 alpha05 格式样本。

输出：corpus/checklist_cot_wave.jsonl（构建 v2 时并入）
用法：
  OPENROUTER_KEY=sk-... python3 gen_checklist_cot.py --pilot      # 2 条试跑
  OPENROUTER_KEY=sk-... python3 gen_checklist_cot.py              # 全量断点续跑
"""
import argparse
import collections
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

CORPUS = PROJECT / "experiments/exp_06_finetune/corpus"
OUT_PATH = CORPUS / "checklist_cot_wave.jsonl"
PROGRESS_PATH = CORPUS / "checklist_cot_progress.jsonl"

CHECKLIST = ("【分析步骤——必须逐条执行，缺一即废】\n"
             "1. 枚举全部用户可控输入点，逐一追踪是否到达危险 sink；\n"
             "2. 对每条 source→sink 数据流验证防御有效性：确认防御类型、位置、"
             "能否完整覆盖该条流；黑名单/正则/字符串替换过滤视为可绕过，不算有效防御；\n"
             "3. 检查是否存在第二入口或替代通道（其他路由/参数/间接调用/备用通道）；\n"
             "4. 结论。")


def build_prompt(code: str, lang: str, cwe: str, vuln_desc: str) -> str:
    return f"""你要为漏洞检测模型生成一条训练数据：对下述代码写出符合固定清单的漏洞分析。

【代码】（{lang}，标注 {cwe}）
```
{code}
```
（背景：{(vuln_desc or cwe)[:200]}）

{CHECKLIST}

【要求】
1. 分析 3~6 步编号格式，每步锚定真实行号（格式"第 N 行"或"line N"，行号必须在文件范围内）；
2. 步骤 1~4 的清单项都要有对应内容；无漏洞时同样执行清单（说明为何每条流被防御覆盖、
   为何不存在第二入口）；
3. 最后输出 ```json 结论（七字段按序：has_vulnerability/vulnerability_type/risk_level/
   source/sink/explanation/fix_suggestion），vulnerability_type 以 {cwe} 开头；
4. JSON 字符串值内严禁英文双引号，引用代码用单引号或反引号。"""


def stratified_sample(manifest, n_total: int):
    """CWE×语言 分层抽样（2026-08-27 扩量版）：
    - 文件字符上限 9000→12000、单族封顶 12→24；
    - CWE-798/CWE-190 长尾强制全收（v2.x 审查发现清单源这两族为 0）；
    - 主循环不满时回填剩余样本——分层只影响顺序，不影响可达总量。
    """
    eligible = []
    for s in manifest:
        code_p = CORPUS / "train_pool" / s["file"]
        if not code_p.exists() or len(code_p.read_text(errors="replace")) > 12000:
            continue
        eligible.append(s)
    FORCED = {"CWE-798", "CWE-190"}
    picked, taken = [], set()
    for s in eligible:
        if s.get("expected_cwe") in FORCED and s["file"] not in taken:
            picked.append(s); taken.add(s["file"])
    rest = [s for s in eligible if s["file"] not in taken]
    by_cwe = collections.defaultdict(list)
    for s in rest:
        by_cwe[s.get("expected_cwe", "?")].append(s)
    per_cap = max(6, min(24, (n_total // max(len(by_cwe), 1)) + 4))
    for cwe in sorted(by_cwe, key=lambda c: len(by_cwe[c])):  # 长尾先挑
        pool = [x for x in by_cwe[cwe] if x["file"] not in taken]
        by_lang = collections.defaultdict(list)
        for x in pool:
            by_lang[(x.get("language") or "?")].append(x)
        i = 0
        while len([p for p in picked if p.get("expected_cwe") == cwe]) < per_cap and any(by_lang.values()):
            langs = sorted(by_lang)
            lang = langs[i % len(langs)]
            if by_lang[lang]:
                nxt = by_lang[lang].pop(0)
                if nxt["file"] not in taken:
                    picked.append(nxt); taken.add(nxt["file"])
            else:
                by_lang.pop(lang); continue
            i += 1
            if len(picked) >= n_total:
                return picked
    for s in rest:  # 回填：长尾已尽、封顶未满时不再丢样本
        if len(picked) >= n_total:
            break
        if s["file"] not in taken:
            picked.append(s); taken.add(s["file"])
    return picked[:n_total]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-total", type=int, default=300)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--pilot", action="store_true")
    args = ap.parse_args()

    key = (os.environ.get("TEACHER_KEY") or os.environ.get("OPENROUTER_KEY") or "")
    if not key:
        print("需要 OPENROUTER_KEY", file=sys.stderr)
        sys.exit(1)

    manifest = json.loads((CORPUS / "train_pool" / "manifest.json").read_text())["samples"]
    # 考卷簇种子过滤（P2，2026-08-27）：dedupe_real_corpus.py 审计出的
    # 隔离淘汰种子（与 rolling_dev/rolling_dev_safe 同簇）不再送教师——
    # 省无谓 API 开销，泄漏拦截前移到种子层
    _bl = CORPUS.parent / "results/corpus_cluster_blocklist.json"
    if _bl.exists():
        _banned = set(json.loads(_bl.read_text(encoding="utf-8"))["filenames"])
        _n = len(manifest)
        manifest = [s for s in manifest if Path(s["file"]).name not in _banned]
        if _n != len(manifest):
            print(f"[blocklist] 滤除考卷簇种子 {_n - len(manifest)} 个", flush=True)
    seeds = stratified_sample(manifest, args.n_total)
    done = set()
    if PROGRESS_PATH.exists():
        for line in PROGRESS_PATH.read_text().splitlines():
            if line.strip():
                try:
                    done.add(json.loads(line)["key"])
                except Exception:
                    pass
    tasks = []
    for s in seeds:
        k = f"COT:{s['file']}"
        if k in done:
            continue
        code = (CORPUS / "train_pool" / s["file"]).read_text(errors="replace")
        expect_true = bool(s.get("expected_present", True))
        tasks.append({"key": k, "seed": s, "code": code, "expect": expect_true,
                      "prompt": build_prompt(code, (s.get("language") or "").lower(),
                                             s.get("expected_cwe", ""),
                                             s.get("expected_vulnerability", ""))})
    if args.pilot:
        tasks = tasks[:2]
    print(f"分层种子 {len(seeds)} | 待处理 {len(tasks)} | "
          f"CWE 族 {len(set(t['seed'].get('expected_cwe') for t in tasks))}", flush=True)

    lock = threading.Lock()
    stats = {"ok": 0, "reject": 0}
    out_f = open(OUT_PATH, "a", encoding="utf-8")
    prog_f = open(PROGRESS_PATH, "a", encoding="utf-8")

    def run_task(t):
        s = t["seed"]
        raw_dir = CORPUS / "checklist_raw"
        raw_dir.mkdir(exist_ok=True)
        for attempt in range(2):
            try:
                # call_teacher 无 system 参数：schema 上下文与任务指令合并为单条 user
                text = call_teacher(key, ALPHA05_PROMPT + "\n\n---\n\n" + t["prompt"])
            except Exception as e:
                with lock:
                    stats["reject"] += 1
                return f"✗ {t['key']}: {str(e)[:60]}"
            (raw_dir / f"{t['key'].replace(':', '_')}.txt").write_text(text or "", encoding="utf-8")
            if not text or not text.strip():
                time.sleep(8)
                continue
            n_lines = max(t["code"].count("\n") + 1, 30)
            rec, err = validate(text, t["expect"], n_lines)
            # 清单演示校验：分析部分必须出现防御验证与第二入口字样
            analysis = re.sub(r"```json.*?```", "", text, flags=re.S) if text else ""
            checklist_ok = ("防御" in analysis or "参数化" in analysis) and \
                           ("第二入口" in analysis or "替代通道" in analysis or "其他路由" in analysis)
            if err is None and checklist_ok:
                lang_out = (s.get("language") or "text").lower()
                sample = {"messages": [
                    {"role": "system", "content": ALPHA05_PROMPT},
                    {"role": "user", "content":
                     f"代码片段（语言: {lang_out}）：\n```{lang_out}\n{t['code']}\n```"},
                    {"role": "assistant", "content": rec["assistant"]},
                ], "meta": {"kind": "checklist_cot", "seed_file": s["file"],
                            "cve": s.get("cve_id"), "cwe": s.get("expected_cwe")}}
                with lock:
                    out_f.write(json.dumps(sample, ensure_ascii=False) + "\n")
                    out_f.flush()
                    prog_f.write(json.dumps({"key": t["key"]}) + "\n")  # 只记成功
                    prog_f.flush()
                    stats["ok"] += 1
                return f"✓ {t['key']}"
            if attempt == 0:
                time.sleep(8)
        with lock:
            stats["reject"] += 1
        return f"✗ {t['key']} 不合格"

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for i, fut in enumerate(as_completed([ex.submit(run_task, t) for t in tasks])):
            print(f"[{i+1}/{len(tasks)}] {fut.result()}", flush=True)
    out_f.close(); prog_f.close()
    print(f"完成: {json.dumps(stats)} | 输出 {OUT_PATH}")


if __name__ == "__main__":
    main()
