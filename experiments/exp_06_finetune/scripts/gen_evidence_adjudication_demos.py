#!/usr/bin/env python3
"""证据消费裁决 SFT 演示生成器（弱点挖掘报告 第十节 修复项 ②b）。

背景：rolling_dev 实测切片裁决 4/5 推翻工具污点链——模型不会"消费证据"。
本脚本从 train_pool（训练侧资产）挖真实种子，请教师写出"逐段核验污点链"的
裁决演示，正面示范与反面示范成对补：

  正例种子：stage1 带传播链命中真实 CVE 漏洞文件   → GT=true，教"确认每跳成立"
  反例种子：同文件的官方修复版上工具仍开火（工具误报）→ GT=false，教"指认断点行"

产出与生产裁决完全同构的训练样本（system=ALPHA05_PROMPT、user=build_triage_prompt），
追加写入 corpus/evidence_adjudication_demos.jsonl。

用法：
  python3 gen_evidence_adjudication_demos.py --dry-run          # 只统计种子
  OPENROUTER_KEY=sk-... python3 gen_evidence_adjudication_demos.py [--limit N]
"""
import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import ALPHA05_PROMPT, build_triage_prompt
from graduation_project.two_stage_scanner import TwoStageScanner

CORPUS = PROJECT_ROOT / "experiments/exp_06_finetune/corpus"
OUT_PATH = CORPUS / "evidence_adjudication_demos.jsonl"
API_URL = "https://openrouter.ai/api/v1/chat/completions"


def apply_patch_to(vuln_code: str, src_path: str, patch_text: str) -> str | None:
    """复用 build_rolling_dev_safe 的离线补丁逻辑（重建文件头+末行换行）。"""
    if not patch_text.endswith("\n"):
        patch_text += "\n"
    full_patch = f"--- a/{src_path}\n+++ b/{src_path}\n" + patch_text
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / src_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(vuln_code)
        r = subprocess.run(["git", "apply", "--whitespace=nowarn", "-"],
                           cwd=td, input=full_patch, capture_output=True, text=True)
        if r.returncode != 0:
            return None
        return target.read_text(errors="replace")


def collect_seeds(limit: int = 0):
    """扫 train_pool 漏洞版+修复版，返回 (正例种子, 反例种子)。"""
    from graduation_project.two_stage_scanner import ToolFinding  # noqa: F401 类型引用
    scanner = TwoStageScanner(client=None, system_prompt="", num_ctx=8192,
                              use_conformal=False, use_signal_feedback=False)
    manifest = json.loads((CORPUS / "train_pool" / "manifest.json").read_text())
    pos, neg = [], []
    for s in manifest["samples"]:
        p = CORPUS / (s.get("patch_file") or "")
        if not p.exists():
            continue
        vuln_code = (CORPUS / "train_pool" / s["file"]).read_text(errors="replace")
        lang = (s.get("language") or "text").lower()
        # 漏洞版：带传播链的 finding 才是"证据消费"正例素材
        try:
            findings = scanner._stage1_recall(vuln_code, lang, s["file"])
        except Exception:
            continue
        chained = [f for f in findings if getattr(f, "path", None)]
        if chained:
            pos.append({"sample": s, "code": vuln_code, "findings": chained})
        # 修复版：工具仍开火 = 工具误报现场 → 反例素材
        fixed = apply_patch_to(vuln_code, s.get("source_path") or "",
                               p.read_text(errors="replace"))
        if fixed:
            try:
                f_findings = scanner._stage1_recall(fixed, lang, s["file"])
            except Exception:
                f_findings = []
            if f_findings:
                neg.append({"sample": s, "code": fixed,
                            "findings": f_findings[:2], "vuln_code": vuln_code})
        if limit and len(pos) >= limit and len(neg) >= limit:
            break
    return pos, neg


def build_demo_prompt(seed: dict, expected_true: bool) -> tuple[str, str]:
    """组装教师 prompt：与生产裁决同构的 user 内容 + 方向约束。"""
    s = seed["sample"]
    finding = seed["findings"][0]
    scanner = TwoStageScanner.__new__(TwoStageScanner)  # 仅复用 _slice_context
    scanner._slicer = TwoStageScanner(client=None, system_prompt="", num_ctx=8192,
                                      use_conformal=False)._slicer
    context = scanner._slice_context(seed["code"], (s.get("language") or "").lower(), finding)
    user_content = build_triage_prompt(finding, context,
                                       (s.get("language") or "").lower(),
                                       aligned=True)
    direction = "真实存在（GT=true，该文件因该 CVE 被收录并已由官方修复）" if expected_true \
        else "不成立（GT=false，这是官方修复后的版本，防御已生效或告警位置本就无害）"
    teacher_instr = f"""
你要为漏洞检测模型生成一条【裁决演示】训练数据。下面是一道真实的裁决题及标准答案方向。

【标准答案】该告警对应漏洞{direction}
{"你必须给出 has_vulnerability=true。" if expected_true else "你必须给出 has_vulnerability=false。"}

【写作要求——违反即废】
1. 分析必须执行「证据链逐段核验」：对提示中给出的传播链逐跳回应；"""
    if expected_true:
        teacher_instr += ("确认每跳可达，说明链上为何无有效防御"
                          "（若存在过滤代码，解释它为何可被绕过）；")
    else:
        teacher_instr += ("明确指出链断在哪一行、断因是什么"
                          "（变量被改写为常量/参数化绑定/autoescape 等有效防御覆盖了该流），"
                          "不得笼统说\"代码有过滤\"；")
    teacher_instr += """
2. 结论 JSON 用 ```json 包裹，七字段按序（has_vulnerability/vulnerability_type/
   risk_level/source/sink/explanation/fix_suggestion），字符串值内禁英文双引号；
3. 分析 3~5 步、每步锚定真实行号；总长 ≤600 字。"""
    return user_content, teacher_instr


def call_teacher(key: str, system: str, user: str) -> str:
    import requests
    last_err = None
    for wait in (0, 20, 45, 90):  # 429 限流指数退避（免费档常见）
        if wait:
            time.sleep(wait)
        try:
            r = requests.post(API_URL,
                              headers={"Authorization": f"Bearer {key}"},
                              json={"model": __import__("os").environ.get(
                                  "TEACHER_MODEL", "stealth/ox-alpha"),
                                  "messages": [{"role": "system", "content": system},
                                               {"role": "user", "content": user}],
                                  "temperature": 0.4, "max_tokens": 8000},
                              timeout=300)
            if r.status_code == 429:
                last_err = RuntimeError("429 Too Many Requests")
                continue
            r.raise_for_status()
            msg = r.json()["choices"][0]["message"]
            content = msg.get("content") or ""
            if not content.strip():
                # 思考型模型可能把预算耗在思维链上：content 空时从 reasoning 兜底提取
                content = msg.get("reasoning_content") or msg.get("reasoning") or ""
            return content
        except Exception as e:
            last_err = e
    raise last_err if last_err else RuntimeError("teacher 调用失败")


def validate(text: str, expect_true: bool) -> str | None:
    if not text:
        return "空响应"
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.S)
    if not m:
        # 兜底：思考型输出可能没围栏，抓最后一个含 has_vulnerability 的 JSON 对象
        cand = re.findall(r"\{[^{}]*\"has_vulnerability\"[^{}]*\}", text)
        if not cand:
            return "无 json 块"
        try:
            obj = json.loads(cand[-1])
        except json.JSONDecodeError as e:
            return f"json 解析失败 {e}"
    else:
        try:
            obj = json.loads(m.group(1))
        except json.JSONDecodeError as e:
            return f"json 解析失败 {e}"
    hv = obj.get("has_vulnerability")
    if hv is not expect_true:
        return f"方向错: {hv}"
    if expect_true and not str(obj.get("vulnerability_type", "")).startswith("CWE"):
        return "类型非 CWE"
    if not expect_true and obj.get("vulnerability_type") != "none":
        return "safe 但类型非 none"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    print("扫描种子（train_pool 漏洞版+修复版双 pass）...", flush=True)
    pos, neg = collect_seeds(args.limit)
    print(f"正例种子（链+真漏洞）: {len(pos)} | 反例种子（修复版仍开火）: {len(neg)}")
    if args.dry_run:
        for tag, lst in (("POS", pos), ("NEG", neg)):
            for x in lst[:8]:
                print(f"  [{tag}] {x['sample']['file']} {x['sample'].get('expected_cwe')} "
                      f"rules={[getattr(f,'rule_id','?') for f in x['findings']][:2]}")
        return

    key = __import__("os").environ.get("OPENROUTER_KEY", "")
    if not key:
        print("需要 OPENROUTER_KEY", file=sys.stderr)
        sys.exit(1)

    out_f = OUT_PATH.open("a", encoding="utf-8")
    stats = {"ok": 0, "reject": 0}
    jobs = ([(x, True) for x in pos] + [(x, False) for x in neg])
    # 断点续跑：跳过已入库的 seed（append 模式防重复）
    done = set()
    if OUT_PATH.exists():
        for line in OUT_PATH.read_text().splitlines():
            if line.strip():
                try:
                    meta = json.loads(line)["meta"]
                    done.add((meta.get("seed_file"), meta.get("kind")))
                except Exception:
                    pass
    if done:
        print(f"断点续跑：跳过已完成 {len(done)} 条")
    stats = {"ok": 0, "reject": 0}
    out_f = OUT_PATH.open("a", encoding="utf-8")
    for i, (seed, expect_true) in enumerate(jobs):
        kind = "evidence_adjudication_" + ("pos" if expect_true else "neg")
        if (seed["sample"]["file"], kind) in done:
            continue
        user_content, teacher_instr = build_demo_prompt(seed, expect_true)
        text = None
        for attempt in range(2):
            try:
                text = call_teacher(key, ALPHA05_PROMPT,
                                    user_content + "\n\n" + teacher_instr)
            except Exception as e:
                print(f"[{i+1}/{len(jobs)}] 调用失败: {str(e)[:60]}", flush=True)
                text = None
                break  # 限流/网络已由 call_teacher 内部退避，外层不再重复打
            err = validate(text, expect_true)
            if err is None:
                break
            print(f"[{i+1}/{len(jobs)}] 重生成（{err}）", flush=True)
            time.sleep(8)
        if text is None or validate(text, expect_true) is not None:
            stats["reject"] += 1
            continue
        rec = {"messages": [
            {"role": "system", "content": ALPHA05_PROMPT},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": text},
        ], "meta": {"kind": kind,
                    "seed_file": seed["sample"]["file"],
                    "cve": seed["sample"].get("cve_id"),
                    "cwe": seed["sample"].get("expected_cwe")}}
        out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        out_f.flush()
        stats["ok"] += 1
        print(f"[{i+1}/{len(jobs)}] ✓ {seed['sample']['file']}", flush=True)
    out_f.close()
    print(f"完成: {json.dumps(stats)} | 输出 {OUT_PATH}")


if __name__ == "__main__":
    main()
