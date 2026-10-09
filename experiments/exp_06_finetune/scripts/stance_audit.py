# -*- coding: utf-8 -*-
"""封闭式安全论证率审计器（2026-10-09，α07 配方③的落地件）。

背景：α06 归因（台账 α06 条目 + prompts.py _build_knowledge_supplement docstring）
发现 v2_26 训据安全侧大量用"入口封闭/不可达"式论证替代数据流论证——模型学会把
"入口不可见"当"不可达"，无候选复核判真 14→7 腰斩。历史统计：α05 安全侧 ≈4.5%~5%，
v2_26 安全侧 ≈19.1%~22%（口径详见 audit/alpha06_vs_alpha05_同prompt对照_20260922.md）。

操作性定义（本文件的规范口径，蒸馏门禁与训前基线共用同一 matcher）：
  对 has_vulnerability=false 的行，取 ```json 前的叙事正文：
    命中 = 正文存在「入口系词（入口/调用方/调用者/调用点/路由/暴露）与封闭成分
           （不可见/封闭/不可达/无法/未/无/不对外/不可触/不暴露）」在 25 字窗内
           共现（双向匹配），即安全结论由"入口不可见 → 不可达"承担。
  不设"无行号锚"前置条件（校准表明历史口径不要求；行号锚与封闭论证可共存）。

校准记录（2026-10-09 实测，见 git 历史各变体对比）：
  a05=4.6%（历史 4.5%）/ v2_26=17.4%（历史 19.1%）——两独立时代 ±2pp 复现。
  被否决的变体：无锚点前置版（0.5%/0.4%）、裸入口系词版（17.5%/38.9%）、
  近距封闭∧无行号版（0.7%/2.2%）——均出带。

用途：
  1. 批次门禁：repair_wave_common.batch_closed_rate() —— 蒸馏批次封闭式论证率
     >8% 拒收（α07 配方③）；
  2. 训前基线：本脚本直接跑，输出各数据集封闭式论证率，同时是论文
     "4.5% → 17.4% → ≤8%"三点折线图的数据源。
"""
import json, re, sys

CLOSED_SIDE = "不可见|封闭|不可达|无法|未|无|不对外|不可触|不暴露"
ENTRY_SIDE = "入口|调用方|调用者|调用点|路由|暴露"
CLOSED_RE = re.compile(
    rf"(?:{ENTRY_SIDE})[^。！？\n]{{0,25}}(?:{CLOSED_SIDE})|"
    rf"(?:{CLOSED_SIDE})[^。！？\n]{{0,25}}(?:{ENTRY_SIDE})")
LINE_REF_RE = re.compile(r"(?:line\s*\d+|第\s*\d+\s*行|(?<![A-Za-z0-9_])L\d{1,4})", re.I)
FLOW_RE = re.compile(r"污点|传播链|数据流|流向|source|sink|污染源|危险点|taint", re.I)


def split_body(assistant: str):
    """返回 (```json 前正文, verdict_obj 或 None)。与 repair_wave_common.split_analysis_json 同语义。"""
    m = re.search(r"```json\s*(\{.*?\})\s*```", assistant, re.S)
    if not m:
        return assistant, None
    try:
        obj = json.loads(m.group(1))
    except Exception:
        return assistant[:m.start()], None
    return assistant[:m.start()], obj


def closed_argument_hit(assistant: str):
    """返回命中详情 dict 或 None。仅对安全结论行有意义。"""
    body, obj = split_body(assistant)
    if obj is None or str(obj.get("has_vulnerability")).lower() != "false":
        return None
    m = CLOSED_RE.search(body)
    if not m:
        return None
    return dict(evidence=m.group(0), n_line_refs=len(LINE_REF_RE.findall(body)),
                has_flow=bool(FLOW_RE.search(body)), body_len=len(body))


def rate(records):
    """records: iterable of assistant strings → (rate, n_safe, n_hit)。"""
    n_safe = n_hit = 0
    for a in records:
        body, obj = split_body(a)
        if obj is None or str(obj.get("has_vulnerability")).lower() != "false":
            continue
        n_safe += 1
        if closed_argument_hit(a):
            n_hit += 1
    return (n_hit / n_safe if n_safe else 0.0), n_safe, n_hit


def batch_closed_rate(records, threshold=0.08):
    """蒸馏批次门禁（α07 配方③）：封闭式论证率超阈值 → 拒收整批并附逐行清单。"""
    r, n_safe, n_hit = rate(records)
    bad = [closed_argument_hit(a) for a in records]
    bad = [b for b in bad if b]
    return dict(rate=round(r, 4), n_safe=n_safe, n_hit=n_hit,
                threshold=threshold, passed=r <= threshold, hits=bad[:50])


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    import os
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA = os.path.join(ROOT, "data")
    SETS = [
        ("alpha05", "final_train_chatml_alpha05.jsonl"),
        ("v2_26", "final_train_chatml_alpha06_v2_26_candidate_20260914.jsonl"),
        ("v2_27_w3", "final_train_chatml_alpha06_v2_27_w3reanchor_20261009.jsonl"),
    ]
    print(f"{'数据集':<12} {'安全侧行数':>8} {'命中':>6} {'封闭式论证率':>10}")
    for name, f in SETS:
        p = os.path.join(DATA, f)
        if not os.path.exists(p):
            print(f"{name:<12} (缺文件，跳过)")
            continue
        assistants = [json.loads(l)["messages"][2]["content"]
                      for l in open(p, encoding="utf-8") if l.strip()]
        r, ns, nh = rate(assistants)
        print(f"{name:<12} {ns:>8} {nh:>6} {r:>10.1%}")
