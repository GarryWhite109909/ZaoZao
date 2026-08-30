"""前端卡片模拟核对脚本——对重点样本产出"前端实拍级"逐字段核对。

背景：eval JSON 与前端卡片同源（同一 scan_code()）但不同层——后端组装层
（source/sink 锚、vulnerability_types、行号纠正后全文）此前未落盘，渲染层
（徽章语义、CWE 纠正条）只在浏览器。本脚本对重点样本跑真实
TwoStageScanner.scan_code() → to_dict()，并按 app/backend/static/scan.html
的渲染逻辑逐字段核对，输出 Markdown 卡片核对报告。

按 scan.html 实现核对的渲染规则（2026-08-30 版）：
  R1 判定徽章：has_vulnerability true→漏洞卡 / false→安全卡 / null→
     两阶段结果必须显示"需人工复核"卡（warning 色系），仅当 _kind==='error'
     且非两阶段才允许失败卡（L877-883, L1991, L2007）
  R2 CWE 纠正条：rawType 存在 && != 'none' && vulnType 匹配 /CWE-?\d+/ &&
     rawType != vulnType 才显示"模型输出 → 纠正后"（L2056）；且映射必须有
     因果关系（模型原文与最终类型同源——hard_bypass_06 实锤的反例）
  R3 风险徽章：risk_level 首字母大写；缺省时从裁决最高严重度推导（L1471-1473）
  R4 证据链：source/sink/explanation/fix 全文行号锚 vs 源码真实行
  R5 多漏洞：vulnerability_types 与"全部确认漏洞"区一致，top1=vulnerability_type
  R6 复核区：reviewer_findings 展示待复核候选（含 rule_id/置信度）
  R7 伴生凭证标注（2026-08-30 §8.5 过渡方案）：唯一 confirmed 候选属 secret 族
     → 类型行显示「伴生凭证发现」徽标（与 scan.html 同步实现）

用法（GPU 空闲时）：
  # 自动挑选重点样本（type_miss/FP/真漏洞复核/多漏洞共现）
  python mock_frontend_card.py --auto \
      --result results/exp_07_full87.nivis-alpha0.combined_nosource.20260830.json
  # 指定样本
  python mock_frontend_card.py --files typical_08_eval.py hard_cve_03_tarfile_2025_4517.py
"""
import argparse
import json
import re
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parents[1]
SAMPLES_DIR = HERE.parent / "exp_04_hard_samples" / "samples"
MANIFEST = SAMPLES_DIR / "manifest.json"
DEFAULT_RESULT = HERE / "results" / "exp_07_full87.nivis-alpha0.combined_nosource.20260830.json"

_CWE_RE = re.compile(r"CWE-(\d+)")
_LINE_RE = re.compile(r"line\s*(\d+)\s*[:：]?\s*(.*)", re.IGNORECASE)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip()).lower()


def load_manifest() -> dict[str, dict]:
    d = json.loads(MANIFEST.read_text(encoding="utf-8"))
    items = d if isinstance(d, list) else d.get("samples", d)
    if isinstance(items, dict):
        items = list(items.values())
    return {r["file"]: r for r in items if isinstance(r, dict) and r.get("file")}


def pick_auto(eval_json: dict) -> list[str]:
    """自动挑重点样本：类型错 / FP / 真漏洞复核 / 多漏洞共现 / 可疑修复。"""
    picks: list[str] = []
    for s in eval_json.get("samples", []):
        exp = bool(s.get("expected_present"))
        pred = s.get("predicted")
        got = set(_CWE_RE.findall(s.get("vulnerability_type") or ""))
        want = set(_CWE_RE.findall(s.get("expected_cwe") or ""))
        fams = set()
        for a in s.get("adjudications") or []:
            if a.get("confirmed"):
                fams.update(_CWE_RE.findall(a.get("vulnerability_type") or ""))
        if pred is False and exp:
            picks.append(s["file"])
        elif pred is True and not exp:
            picks.append(s["file"])
        elif pred is None and exp:
            picks.append(s["file"])
        elif exp and got and not (got & want):
            picks.append(s["file"])
        elif len(fams) >= 2:
            picks.append(s["file"])
    return sorted(set(picks))


def anchor_issues(text: str, code: str, is_fix: bool = False) -> list[str]:
    """行号锚核对（与 triage_report 同口径：多锚截断 + 修复目标态豁免）。"""
    issues = []
    lines = code.splitlines()
    matches = list(_LINE_RE.finditer(text or ""))
    for i, m in enumerate(matches):
        n = int(m.group(1))
        seg_end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        content = _norm(text[m.end():seg_end].lstrip(":： "))
        if n < 1 or n > len(lines):
            issues.append(f"锚越界 L{n}（源码 {len(lines)} 行）")
            continue
        actual = _norm(lines[n - 1])
        if not content or len(content) < 6:
            continue
        if is_fix and re.search(r"(应改为|改为|修改为|应使用|替换为|replace)", content):
            tokens = [w for w in re.split(r"[^\w.]+", content) if len(w) >= 4]
            if tokens and any(t in actual for t in tokens):
                continue
        probe = content[:12].strip(":： ")
        if probe and probe not in actual and actual[:12] not in content:
            issues.append(f"锚内容不符 L{n}: 卡「{content[:36]}」≠ 源码「{actual[:36]}」")
    return issues


def check_card(r: dict, code: str, rec: dict) -> dict:
    """对单张卡片逐字段核对，返回 {字段: [问题]}。"""
    issues: dict[str, list[str]] = {}
    hv = r.get("has_vulnerability")

    # R1 判定徽章
    if hv is None:
        kind = r.get("_kind", "two-stage")
        if kind == "error":
            issues.setdefault("判定徽章", []).append(
                "两阶段 null 但 _kind=error → 会渲染成失败卡（应为需复核卡）")
    # R2 CWE 纠正条
    vt = r.get("vulnerability_type") or ""
    raw = r.get("raw_vulnerability_type") or ""
    show = bool(raw and raw.lower() != "none"
                and re.search(r"CWE-?\d+", vt, re.IGNORECASE) and raw != vt)
    if show:
        got_cwes = set(_CWE_RE.findall(vt))
        raw_cwes = set(_CWE_RE.findall(raw))
        if raw_cwes and got_cwes and not (raw_cwes & got_cwes):
            issues.setdefault("CWE纠正条", []).append(
                f"映射无因果关系：「{raw} → {vt}」两者 CWE 无交集（同源性破坏）")
    # R3 风险徽章
    rl = (r.get("risk_level") or "").strip()
    if hv is True and not rl:
        issues.setdefault("风险徽章", []).append("判真但 risk_level 为空（前端将退回推导，仍算字段缺失）")
    # R3b 风险等级 vs 标注（2026-08-30 用户要求判对样本也要查）：仅记 notes 待综合考量
    exp_risk = _norm(rec.get("expected_risk_level") or "")
    if hv is True and rl and exp_risk and exp_risk != "none":
        if exp_risk not in _norm(rl):
            issues.setdefault("_notes", []).append(
                f"风险等级 vs 标注不一致：卡 {rl!r} / 标注 {rec.get('expected_risk_level')!r}"
                f"——需综合考量（标注可能不细）")
    # R4 证据链行号锚
    for field in ("source", "sink", "explanation", "fix_suggestion"):
        is_fix = field == "fix_suggestion"
        for iss in anchor_issues(r.get(field) or "", code, is_fix=is_fix):
            issues.setdefault(f"证据链.{field}", []).append(iss)
    # R5 多漏洞列表
    vts = r.get("vulnerability_types") or []
    if hv is True and vt and vts and vt not in vts:
        issues.setdefault("多漏洞列表", []).append(
            f"top1 类型 {vt!r} 不在 vulnerability_types {vts}（不一致）")
    # 与 manifest 比对（判定方向 + 类型 strict hit；标注可能不全对 → 仅记录不判错）
    rec_exp = rec.get("expected_present")
    notes = []
    if rec_exp is not None and hv is not None and bool(rec_exp) != hv:
        notes.append(f"判定 vs 标注不一致（标注 {'真' if rec_exp else '安'} / 卡片 "
                     f"{'真' if hv else '安'}）——需综合考量标注是否漏标/误标")
    exp_cwes = set(_CWE_RE.findall(rec.get("expected_cwe") or ""))
    got_cwes = set(_CWE_RE.findall(vt))
    if hv is True and got_cwes and exp_cwes and not (got_cwes & exp_cwes):
        notes.append(f"类型 vs 标注不一致：卡 {sorted(got_cwes)} vs 标注 {sorted(exp_cwes)}"
                     f"——需综合考量（标注单标/近邻概念/主次排序）")
    issues["_notes"] = notes
    # R7 伴生凭证标注（2026-08-30，工具层优化指导 §8.5 过渡方案，与 scan.html
    # 同步）：唯一 confirmed 候选属 secret 族（B105 族/hardcoded-*/Hardcoded
    # Credentials/gitleaks 规则名）→ 前端类型行显示「伴生凭证发现」徽标（纯展示，
    # 不改判定）。核对报告记录哪些卡会出现该标注，防两份渲染实现漂移。
    # 注意：必须在 issues["_notes"] = notes 赋值之后追加（该赋值是整体覆写）。
    if hv is True and (r.get("_kind") or "two-stage") == "two-stage":
        sec = re.compile(
            r"B10[567]|hardcoded[-_.]?(?:token|secret|password|credential|api[_-]?key)"
            r"|Hardcoded Credentials|generic-api-key|aws-access-key-id|python-bytes-literal-secret",
            re.IGNORECASE)
        conf = [a for a in r.get("adjudications") or [] if a.get("confirmed")]
        only_secret = bool(conf) and all(
            ((a.get("category")
              or (a.get("finding") or {}).get("category") or "") == "secret")
            or sec.search(a.get("rule_id")
                          or (a.get("finding") or {}).get("rule_id") or "")
            or sec.search(a.get("taint_type")
                          or (a.get("finding") or {}).get("taint_type") or "")
            for a in conf)
        if only_secret:
            issues["_notes"].append(
                "唯一 confirmed 候选为 secret 族 → 前端显示「伴生凭证发现」标注"
                "（§8.5 过渡方案：文件级类型可能只是伴生发现）")
    return issues


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--result", type=str, default=str(DEFAULT_RESULT))
    ap.add_argument("--files", nargs="*", default=None)
    ap.add_argument("--auto", action="store_true")
    ap.add_argument("--all", action="store_true",
                    help="全量 87 段都过卡片核对（2026-08-30 用户要求：判对的卡也要查行号/修复/风险等字段）")
    ap.add_argument("--resume", action="store_true",
                    help="跳过已有卡实拍 JSON 中的样本（配合 --all 补跑）")
    ap.add_argument("--out", type=str, default=None)
    args = ap.parse_args()

    manifest = load_manifest()
    if args.files:
        files = args.files
    elif args.all:
        files = sorted(manifest.keys())
    elif args.auto:
        eval_json = json.loads(Path(args.result).read_text(encoding="utf-8"))
        files = pick_auto(eval_json)
    else:
        files = []
    # 断点续跑：--resume 时并入已有结果，跳过已完成样本
    prev_cards: list[dict] = []
    out = Path(args.out) if args.out else None
    if args.resume:
        import glob
        cands = sorted(glob.glob(str(HERE / "results" / "frontend_card_check_*.json")))
        if cands:
            latest = Path(cands[-1])
            prev = json.loads(latest.read_text(encoding="utf-8"))
            done = {c["file"] for c in prev.get("cards", [])}
            files = [f for f in files if f not in done]
            prev_cards = prev.get("cards", [])
            out = out or latest      # 续写同一文件
            print(f"[resume] 已有 {len(done)} 段卡实拍，本次补跑 {len(files)} 段")
    if not out:
        ts = time.strftime("%Y%m%d_%H%M%S")
        out = HERE / "results" / f"frontend_card_check_{ts}.json"
    print(f"卡实拍 {len(files)} 段：{files}")

    # 惰性加载真实管线。2026-08-30 二次对齐（逐项比对 app/backend 生产链路）：
    #   system_prompt = ALPHA05_PROMPT（生产 get_prompt_for_model(alpha05) 的返回，
    #     model_registry.py:150-152；此前误用 V3_PROMPT，与生产差 2400 字）
    #   num_ctx = 16384（生产 16GB ROCm 档，bootstrap.recommend_config vram>=15872 →
    #     16384 → VULN_SCANNER_NUM_CTX → scanner._num_ctx；此前误用 8192）
    #   adapter/base = resolve_adapter_path()/resolve_base_model_path() 无参调用
    #     （与 scanner.py:44-46 生产同款探测；实测均解析到 adapter_alpha05_stage2）
    #   triage_aligned=True + full_recheck + n=3（main.py:108-116 全局 two_stage 组态）
    #   use_rag=None（main.py:126 analyze 端点默认，scan_code 同默认）
    from graduation_project.two_stage_scanner import TwoStageScanner
    from graduation_project.transformers_client import create_llm_client
    from graduation_project.paths import resolve_base_model_path, resolve_adapter_path
    from graduation_project.prompts import ALPHA05_PROMPT

    base_model = resolve_base_model_path()
    adapter = resolve_adapter_path()
    num_ctx = 16384        # 生产 16GB ROCm 档（bootstrap.recommend_config）
    system_prompt = ALPHA05_PROMPT
    # 对齐检查表：启动时打印，供人工核对（来源已注明）
    print("=== 生产组态对齐检查表 ===")
    print(f"  system_prompt : ALPHA05_PROMPT len={len(system_prompt)}"
          f"（生产=model_registry._get_prompt('alpha05')）")
    print(f"  num_ctx       : {num_ctx}（生产=bootstrap 16GB ROCm 档 16384）")
    print(f"  base_model    : {base_model}（生产=scanner.py:44 同款探测）")
    print(f"  adapter       : {adapter}（生产=scanner.py:46 同款探测）")
    print(f"  裁决组态       : triage_aligned=True, full_recheck, n_samples=3"
          f"（生产=main.py:108-116）")
    print(f"  注册表/共形    : 生产 registry.json + conformal_calibration.json（默认加载）")
    client = create_llm_client(
        "transformers",
        model_id=base_model,
        adapter=adapter,
        num_ctx=num_ctx,
    )
    ts = TwoStageScanner(
        client=client, system_prompt=system_prompt, n_samples=3,
        triage_aligned=True, no_candidate_mode="full_recheck",
    )

    ts_run = time.strftime("%Y%m%d_%H%M%S")
    rows = []
    for fn in files:
        code_path = SAMPLES_DIR / fn
        if not code_path.exists():
            print(f"[skip] {fn} 不在样本目录")
            continue
        code = code_path.read_text(encoding="utf-8")
        t0 = time.time()
        r = ts.scan_code(code, "python", fn)
        card = r.to_dict()
        card["_kind"] = "two-stage"        # 前端 singleAnalyze 注入
        rec = manifest.get(fn, {})
        issues = check_card(card, code, rec)
        dur = round(time.time() - t0, 1)
        n_bad = sum(len(v) for k, v in issues.items() if not k.startswith("_"))
        print(f"[{fn}] {dur}s 判定={card.get('has_vulnerability')} "
              f"类型={card.get('vulnerability_type')!r} 问题字段数={n_bad}")
        rows.append({"file": fn, "duration": dur, "card": card,
                     "issues": {k: v for k, v in issues.items()}, "manifest": rec})
        # 边跑边落盘（2026-08-30）：长跑中断不丢已完成样本，配合 --resume 续跑
        all_cards = prev_cards + rows
        out.write_text(json.dumps(
            {"meta": {"generated": ts_run, "files": [c["file"] for c in all_cards]},
             "cards": all_cards}, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"卡片核对数据已写入: {out}")


if __name__ == "__main__":
    main()
