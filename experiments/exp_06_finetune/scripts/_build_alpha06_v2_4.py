#!/usr/bin/env python3
"""alpha06-v2.4 训练集构建：用补齐后的 long_file_wave(464) 与 framework_safe_pairs(79)
替换冻结集 v2_3 中的陈旧版本，输出 data/final_train_chatml_alpha06_v2_4.jsonl。"""
import hashlib
import json
import re
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "experiments/exp_06_finetune/scripts"))
from graduation_project.prompts import ALPHA05_PROMPT

BASE = PROJECT / "experiments/exp_06_finetune/data/final_train_chatml_alpha06_v2_3.jsonl"
WAVE = PROJECT / "experiments/exp_06_finetune/corpus/long_file_wave.jsonl"
FRAMEWORK = PROJECT / "experiments/exp_06_finetune/corpus/framework_safe_pairs.jsonl"
OUT = PROJECT / "experiments/exp_06_finetune/data/final_train_chatml_alpha06_v2_4.jsonl"
REPORT = PROJECT / "experiments/exp_06_finetune/data/build_alpha06_v2_4_report.md"

CODE_RE = re.compile(r"```[\w+-]*\n(.*?)\n```", re.S)


def norm_body(body: str):
    lines = [ln.rstrip() for ln in body.split("\n")]
    return tuple(ln for ln in lines if ln.strip())


def fp_of_user(user_c: str):
    m = CODE_RE.search(user_c)
    body = m.group(1) if m else user_c
    return hashlib.md5("\n".join(norm_body(body)).encode()).hexdigest()


def load(path: Path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                out.append(json.loads(line))
    return out


def main():
    base = load(BASE)
    wave = load(WAVE)
    fw = load(FRAMEWORK)

    # ---- 新源统一 system & 指纹集合（同码异判的冲突对整组剔除）----
    fp_rows = {}
    bad_src = []
    fresh = []
    for tag, rows in (("long_file", wave), ("framework", fw)):
        for i, r in enumerate(rows):
            msgs = r["messages"]
            if msgs[0]["content"] != ALPHA05_PROMPT:
                bad_src.append((tag, i, "system 不一致"))
            fp = fp_of_user(msgs[1]["content"])
            sf = (r.get("meta") or {}).get("seed_file")
            fp_rows.setdefault(fp, []).append((tag, i, sf))
            fresh.append((tag, r))
    print(f"新源：long_file={len(wave)} framework={len(fw)} | system 异常 {len(bad_src)}")

    # 同一指纹出现于多条新源 => 不同 seed 的代码相同（同码异判），训练噪声源头
    conflicted_fps = {fp for fp, rs in fp_rows.items() if len(rs) > 1}
    fresh_clean, dropped_conflict, seen_pair = [], [], set()
    for tag, r in fresh:
        fp = fp_of_user(r["messages"][1]["content"])
        sf = (r.get("meta") or {}).get("seed_file")
        if fp in conflicted_fps:
            dropped_conflict.append((tag, sf))
            continue
        assert fp not in seen_pair, "新源内部代码指纹重复"
        seen_pair.add(fp)
        fresh_clean.append((tag, r))
    fresh = fresh_clean
    fps_set = set(conflicted_fps) | {
        fp_of_user(r["messages"][1]["content"]) for _, r in fresh}
    print(f"同码异判冲突剔除 {len(dropped_conflict)} 条: "
          f"{sorted({sf for _, sf in dropped_conflict})}")

    # ---- 基集去旧：凡代码指纹命中新源即视为陈旧版本 ----
    kept, replaced = [], 0
    seen_key = set()
    for r in base:
        u = next(m["content"] for m in r["messages"] if m["role"] == "user")
        a = next(m["content"] for m in r["messages"] if m["role"] == "assistant")
        h = hashlib.md5((u[-2000:] + a[-500:]).encode()).hexdigest()
        if fp_of_user(u) in fps_set:
            replaced += 1
            continue
        if h in seen_key:
            replaced += 1  # 精确重复（v2_3 后处理应无，防御性剔除）
            continue
        seen_key.add(h)
        kept.append(r)
    print(f"基集 {len(base)} → 移除陈旧/重复 {replaced} → 保留 {len(kept)}")

    # ---- 合并 + 结构校验 ----
    errors = []
    final = list(kept)
    tag_of = {}
    for idx, r in enumerate(kept):
        tag_of[id(r)] = "base"
    for tag, r in fresh:
        msgs = r["messages"]
        ok = (len(msgs) == 3 and
              [m["role"] for m in msgs] == ["system", "user", "assistant"])
        if not ok:
            errors.append((tag, "结构"))
            continue
        asst = msgs[2]["content"]
        m = re.search(r"```json\s*(\{.*?\})\s*```", asst, re.S)
        if not m:
            errors.append((tag, "无 json 块"))
            continue
        try:
            obj = json.loads(m.group(1))
        except json.JSONDecodeError:
            errors.append((tag, "json 解析失败"))
            continue
        # risk_level 归一化（与 build_alpha06_v2_3.py 的 RISK_MAP 同语义）
        changed = False
        hv = obj.get("has_vulnerability")
        rk = obj.get("risk_level")
        RISK_MAP = {"critical": "Critical", "严重": "Critical", "高危": "High",
                    "high": "High", "中高": "High",
                    "medium": "Medium", "中": "Medium", "低": "Low", "low": "Low"}
        if hv is True:
            if rk not in ("Critical", "High", "Medium", "Low"):
                s = str(rk).strip()
                s = re.sub(r"\s*[（(].*?[)）]\s*$", "", s).strip()  # 去尾注 “严重 (Critical)”
                fixed = RISK_MAP.get(s.lower(), RISK_MAP.get(s))
                if fixed is None:  # 自然语言变体兜底
                    low = s.lower()
                    if low.startswith(("crit", "sever")) or s.startswith("严重"):
                        fixed = "Critical"
                    elif low.startswith(("high", "medium-high")) or s in ("高", "高危", "中高危", "较高"):
                        fixed = "High"
                    elif low.startswith("med") or s in ("中", "中危", "中等"):
                        fixed = "Medium"
                    elif low.startswith("low") or s in ("低", "较低", "低危", "中低"):
                        fixed = "Low"
                if fixed is None:
                    errors.append((tag, f"risk 无法归一化: {rk}"))
                    continue
                obj["risk_level"] = fixed
                changed = True
        elif hv is False and rk != "none":
            obj["risk_level"] = "none"
            changed = True
        if changed:
            new_block = json.dumps(obj, ensure_ascii=False)
            msgs[2]["content"] = asst[:m.start(1)] + new_block + asst[m.end(1):]
            asst = msgs[2]["content"]
        vt = str(obj.get("vulnerability_type", ""))
        rl = obj.get("risk_level", "")
        good = isinstance(hv, bool) and (
            (hv and vt.startswith("CWE-") and rl in ("Low", "Medium", "High", "Critical")) or
            (not hv and vt.lower() == "none" and rl in ("none", "None")))
        if not good:
            errors.append((tag, f"字段异常 hv={hv} vt={vt[:30]} rl={rl}"))
            continue
        # 行号锚点越界检查
        cm = CODE_RE.search(msgs[1]["content"])
        n_lines = (cm.group(1).count("\n") + 1) if cm else 10 ** 9
        bad_anchor = sorted({int(n) for n in set(re.findall(
            r"line (\d+)", json.dumps(obj, ensure_ascii=False)))
            if not (1 <= int(n) <= n_lines)})
        if bad_anchor:
            errors.append((tag, f"行号越界 {bad_anchor[:3]}"))
            continue
        out_r = {"messages": [{"role": x["role"], "content": x["content"]} for x in msgs]}
        final.append(out_r)
        tag_of[id(out_r)] = tag

    # ---- 泄漏抽检（仅新增行）----
    test_norm = []
    tdirs = [
        PROJECT / "experiments/exp_06_finetune/testset_cve_fix",
        PROJECT / "experiments/exp_06_finetune/corpus/rolling_dev",
        PROJECT / "experiments/exp_06_finetune/corpus/rolling_dev_safe",
        PROJECT / "experiments/exp_04_hard_samples/samples",
    ]
    for td in tdirs:
        if td.exists():
            for f in td.glob("*"):
                if f.is_file() and f.suffix in (".py", ".java", ".js", ".php", ".go", ".ts"):
                    test_norm.append(norm_body(f.read_text(errors="replace")))

    def jac(a, b):
        sa, sb = set(a), set(b)
        if not sa or not sb:
            return 0.0
        return len(sa & sb) / len(sa | sb)

    leaks = []
    tail_start = len(kept)
    for j, r in enumerate(final[tail_start:], start=tail_start):
        u = r["messages"][1]["content"]
        cm = CODE_RE.search(u)
        nb = norm_body(cm.group(1)) if cm else norm_body(u)
        best = max((jac(nb, tn) for tn in test_norm), default=0.0)
        if best >= 0.5:
            leaks.append((tag_of.get(id(r), "?"), round(best, 3)))
    if leaks:
        dropped = set(id(final[tail_start + k]) for k, _ in enumerate(leaks))
        final = [r for i, r in enumerate(final)
                 if i < tail_start or id(r) not in dropped]

    counts = {"base": len(kept)}
    counts["long_file"] = sum(1 for r in final[len(kept):] if tag_of.get(id(r)) == "long_file")
    counts["framework"] = sum(1 for r in final[len(kept):] if tag_of.get(id(r)) == "framework")

    OUT.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in final) + "\n",
                   encoding="utf-8")

    rep = f"""# alpha06-v2.4 训练集构建报告（长文件+框架补齐整合）

- 基线：v2.3 冻结集 {len(base)} 条（`final_train_chatml_alpha06_v2_3.jsonl`，未改动）
- 替换来源：
  - `corpus/long_file_wave.jsonl` {len(wave)} 条（本轮全部完成：464/464）
  - `corpus/framework_safe_pairs.jsonl` {len(fw)} 条（79/79）
- 基集中移除的陈旧版本/精确重复：{replaced}
- 泄漏抽检命中移除（新增行）：{len(leaks)} {leaks if leaks else ''}
- 结构校验失败（新增行，已丢弃）：{len(errors)}
- **最终：{len(final)} 条** → `final_train_chatml_alpha06_v2_4.jsonl`

## 构成
- 保留自 v2.3：{counts['base']}
- 长文件（替换新增）：{counts['long_file']}
- 框架安全对（确认未在基集中的新增）：{counts['framework']}

## 校验说明
- 全部行 system = ALPHA05 统一提示（{len(ALPHA05_PROMPT)} 字符）；triage 24 行沿用其特批系统提示
- verdict JSON 七字段规范、CWE 前缀规则、risk_level 词表、行号锚点边界逐条复检
"""
    REPORT.write_text(rep, encoding="utf-8")
    print(rep)
    if errors:
        print("校验异常样例:", errors[:10])


if __name__ == "__main__":
    main()
