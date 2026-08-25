#!/usr/bin/env python3
"""构建 alpha06-v2.3 训练集（final_train_chatml_alpha06_v2_3.jsonl）。

基于 v2.2（冻结不动）的确定性质量修复，不引入新数据源（新数据源仍走
build_alpha06_final_v2_2.py 同款管道并入后再过本脚本）。

修复项（源自 2026-08-25 全量分布审计 + 补充质量审计）：
  1. risk_level 词表统一：high/High/严重/高危/中/中高 → 规范枚举
     {Critical, High, Medium, Low}（v2.2 中混有 7 种写法 ~85 条）；
  2. 剔除 CoT 终判与 JSON 结论确定性矛盾的样本（#246：终判句明确
     "原始代码无漏洞"但 verdict 报 vuln）；
  3. 同方向近重复去重：代码 shingle Jaccard>=0.95 且 vuln 方向一致的
     跨源重复对（wave1 与 checklist 同种子同代码、仅 CoT 不同；v2.2 的
     md5 去重哈希含 assistant 尾部故漏检），保留教学价值更高的一条：
     checklist/taint/blacklist > wave1，同优先级保留 CoT 更长者；
     反方向对（vuln/safe minimal pair，306 对）为设计使然，全部保留；
  4. 16 条疑似 CoT-结论矛盾（启发式误报率约 2/3，抽检证实多为防御
     论证文本触发）不做自动处置，输出人工复核清单。

管道与 v2.2 一致的部分：七字段契约、类型白名单、断言门（重跑校验）。

用法：
  python build_alpha06_v2_3.py            # 正式产出
  python build_alpha06_v2_3.py --dry-run  # 只出报告不改盘
"""
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROJECT = Path(__file__).resolve().parents[3]
SRC = PROJECT / "experiments/exp_06_finetune/data/final_train_chatml_alpha06_v2_2.jsonl"
OUT = PROJECT / "experiments/exp_06_finetune/data/final_train_chatml_alpha06_v2_3.jsonl"
REPORT = PROJECT / "experiments/exp_06_finetune/data/build_alpha06_v2_3_report.md"

CANONICAL = ["has_vulnerability", "vulnerability_type", "risk_level",
             "source", "sink", "explanation", "fix_suggestion"]

RISK_MAP = {
    "critical": "Critical", "严重": "Critical", "高危": "High",
    "high": "High", "中高": "High",
    "medium": "Medium", "中": "Medium", "低": "Low", "low": "Low",
}

# CoT 终判句与 JSON 结论确定性矛盾（人工确认后写死；终判句明确无歧义）
HARD_CONTRA_ROWS = [246]

SEGS = [
    ("old", 0, 7599), ("wave1", 7599, 8173), ("wave2+checklist", 8173, 8472),
    ("taint", 8472, 8611), ("blacklist", 8611, 8635), ("evidence", 8635, 8672),
    ("triage", 8672, 8696),
]


def seg_of(i):
    for name, lo, hi in SEGS:
        if lo <= i < hi:
            return name
    return "?"


SEG_PRIORITY = {"checklist": 0, "taint": 1, "blacklist": 2, "wave2": 3,
                "wave1": 4, "old": 5, "evidence": 6, "triage": 7}


def seg_prio(seg):
    for k, v in SEG_PRIORITY.items():
        if k in seg:
            return v
    return 9


def shingle(code: str, n=8):
    words = re.sub(r"\s+", " ", code.lower()).split()
    return {" ".join(words[j:j + n]) for j in range(max(0, len(words) - n + 1))}


def parse_row(i, line):
    d = json.loads(line)
    msgs = d["messages"]
    user = next(m["content"] for m in msgs if m["role"] == "user")
    asst = next(m["content"] for m in msgs if m["role"] == "assistant")
    blocks = re.findall(r"```json\s*(\{.*?\})\s*```", asst, re.S)
    obj = json.loads(blocks[-1]) if blocks else None
    return {"i": i, "d": d, "user": user, "asst": asst, "obj": obj,
            "seg": seg_of(i)}


def reorder_json(text: str, obj: dict) -> str:
    """按 CANONICAL 顺序重排并回写 risk_level。"""
    blocks = re.findall(r"```json\s*(\{.*?\})\s*```", text, re.S)
    if not blocks:
        return text
    raw = blocks[-1]
    ordered = {k: obj[k] for k in CANONICAL if k in obj}
    for k, v in obj.items():
        if k not in ordered:
            ordered[k] = v
    new_block = "```json\n" + json.dumps(ordered, ensure_ascii=False) + "\n```"
    idx = text.rfind("```json")
    return text[:idx] + new_block


def main():
    dry = "--dry-run" in sys.argv
    rows = []
    with open(SRC, encoding="utf-8") as f:
        for i, line in enumerate(f):
            rows.append(parse_row(i, line))
    assert len(rows) == 8696, f"行数异常 {len(rows)}"

    stats = Counter()
    risk_fixes = []
    # ---------- 1) risk_level 归一化 ----------
    # vuln 侧：{Critical, High, Medium, Low}；safe 侧：统一小写 "none"
    # （v2.2 中 safe 侧混有字符串 "None" 4431 条 + "Low" 3 条）
    for r in rows:
        if r["obj"] is None:
            continue
        hv = r["obj"].get("has_vulnerability")
        rk = r["obj"].get("risk_level")
        if hv is True and isinstance(rk, str) and \
                rk not in ("Critical", "High", "Medium", "Low"):
            fixed = RISK_MAP.get(rk.strip().lower(), RISK_MAP.get(rk.strip()))
            if fixed is None:
                stats["risk_unknown"] += 1
                continue
            r["obj"]["risk_level"] = fixed
            r["asst"] = reorder_json(r["asst"], r["obj"])
            r["d"]["messages"][2]["content"] = r["asst"]
            stats["risk_fixed"] += 1
            risk_fixes.append((r["i"], rk, fixed))
        elif hv is False and rk != "none":
            r["obj"]["risk_level"] = "none"
            r["asst"] = reorder_json(r["asst"], r["obj"])
            r["d"]["messages"][2]["content"] = r["asst"]
            stats["risk_safe_fixed"] += 1

    # ---------- 2) CoT 终判矛盾剔除 ----------
    drop_contra = [r for r in rows if r["i"] in HARD_CONTRA_ROWS]
    stats["drop_contra"] = len(drop_contra)
    drop_idx = {r["i"] for r in drop_contra}

    # ---------- 3) 同方向近重复去重 ----------
    codes = {}
    for r in rows:
        cm = re.search(r"```[\w+-]*\n(.*?)\n```", r["user"], re.S)
        codes[r["i"]] = shingle(cm.group(1) if cm else r["user"])
    inv = defaultdict(list)
    for r in rows:
        if r["i"] in drop_idx:
            continue
        for s in codes[r["i"]]:
            inv[s].append(r["i"])
    pair_count = Counter()
    for s, lst in inv.items():
        if 1 < len(lst) <= 5:
            for a in range(len(lst)):
                for b in range(a + 1, len(lst)):
                    pair_count[(lst[a], lst[b])] += 1
    hv_map = {r["i"]: (r["obj"].get("has_vulnerability") if r["obj"] else None)
              for r in rows}
    dup_groups = defaultdict(set)  # i -> 邻接
    for (a, b), c in pair_count.items():
        if c < 60:
            continue
        ja, jb = codes[a], codes[b]
        j = len(ja & jb) / len(ja | jb) if ja | jb else 0
        if j >= 0.95 and hv_map[a] == hv_map[b]:
            dup_groups[a].add(b)
            dup_groups[b].add(a)
    # 贪心：按 seg 优先级 + CoT 长度决定保留者，从组里逐个剔除
    drop_dup = set()
    adj = {k: set(v) for k, v in dup_groups.items()}
    while adj:
        # 选当前组中度最大的节点开始
        start = max(adj, key=lambda k: len(adj[k]))
        group = set([start])
        stack = [start]
        while stack:
            cur = stack.pop()
            for nb in adj.get(cur, ()):
                if nb not in group:
                    group.add(nb)
                    stack.append(nb)
        seg_of_row = {r["i"]: r["seg"] for r in rows}
        cot_len = {r["i"]: len(r["asst"]) for r in rows}
        keep = sorted(group, key=lambda i: (seg_prio(seg_of_row[i]), -cot_len[i]))[0]
        for i in group:
            if i != keep:
                drop_dup.add(i)
            adj.pop(i, None)
        for i in group:
            for nb in adj:
                adj[nb].discard(i)
    stats["drop_dup"] = len(drop_dup)
    drop_idx |= drop_dup

    final = [r for r in rows if r["i"] not in drop_idx]
    stats["final"] = len(final)

    # ---------- 4) 断言门复跑 ----------
    for r in final:
        assert r["obj"] is not None, f"#{r['i']} obj 缺失"
        if r["seg"] in ("evidence", "triage"):
            continue
        obj = r["obj"]
        assert obj.get("has_vulnerability") in (True, False), f"#{r['i']} hv"
        assert all(k in obj for k in CANONICAL), f"#{r['i']} 字段"
        if obj["has_vulnerability"]:
            assert str(obj["vulnerability_type"]).startswith("CWE-"), f"#{r['i']} vt"
            assert obj["risk_level"] in ("Critical", "High", "Medium", "Low"), \
                f"#{r['i']} risk={obj['risk_level']}"
        else:
            assert str(obj["vulnerability_type"]).lower() == "none", f"#{r['i']} none"
            assert obj["risk_level"] == "none", f"#{r['i']} safe risk={obj['risk_level']}"

    # ---------- 5) 人工复核清单（CoT 疑似矛盾，不剔除）----------
    SAFE_FINAL = re.compile(r"(代码(是安全|无|不存在|没有)(的)?漏洞|不构成漏洞|判定(代码)?(为|是)安全|代码安全|无安全(风险|问题)|不存在可利用)")
    VULN_FINAL = re.compile(r"(存在(安全)?漏洞|构成(安全)?漏洞|代码(是)?(一个)?漏洞|确认漏洞|漏洞确实存在)")
    review = []
    for r in rows:
        if r["obj"] is None or r["seg"] in ("evidence", "triage"):
            continue
        hv = r["obj"].get("has_vulnerability")
        cot = r["asst"].split("```json")[0][-300:]
        s, v = SAFE_FINAL.search(cot), VULN_FINAL.search(cot)
        if hv is True and s and not v:
            review.append((r["i"], "CoT终判安全/JSON报vuln"))
        elif hv is False and v and not s:
            review.append((r["i"], "CoT终判漏洞/JSON报safe"))
    review = [(i, t) for i, t in review if i not in drop_idx]

    # ---------- 输出 ----------
    if not dry:
        with open(OUT, "w", encoding="utf-8") as f:
            for r in final:
                f.write(json.dumps(r["d"], ensure_ascii=False) + "\n")

    seg_before = Counter(r["seg"] for r in rows)
    seg_after = Counter(r["seg"] for r in final)
    lines = [
        "# alpha06-v2.3 训练集构建报告（确定性质量修复版）",
        "",
        f"- 输入：v2.2 冻结集 8696 条（`{SRC.name}`，不动）",
        f"- risk_level 归一化：vuln 侧 {stats['risk_fixed']} 条（未知写法 {stats['risk_unknown']}）；"
        f"safe 侧统一 \"none\" {stats['risk_safe_fixed']} 条",
        f"- CoT 终判确定性矛盾剔除：{stats['drop_contra']} 条（行号 {sorted(HARD_CONTRA_ROWS)}）",
        f"- 同方向近重复去重（代码 shingle J>=0.95）：{stats['drop_dup']} 条",
        f"- **最终：{stats['final']} 条** → `{OUT.name}`",
        "",
        "## 来源构成（前 → 后）",
        *[f"- {k}: {seg_before[k]} → {seg_after[k]}" for k in
          ["old", "wave1", "wave2+checklist", "taint", "blacklist", "evidence", "triage"]],
        "",
        "## risk_level 修复明细",
        *[f"- #{i}: {a} → {b}" for i, a, b in risk_fixes],
        "",
        "## 近重复剔除明细（保留者见组内首行）",
        *[f"- 剔除 #{i}（seg={seg_of(i)}，与保留样本代码 J>=0.95 同方向）"
          for i in sorted(drop_dup)],
        "",
        f"## 人工复核清单：CoT 疑似与结论矛盾 {len(review)} 条（未剔除，抽检误报率约 2/3）",
        *[f"- #{i}[{seg_of(i)}] {t}" for i, t in review],
        "",
        "## 校验",
        "- 断言门全量复跑通过（七字段 / hv 布尔 / CWE 前缀 / none 小写 / risk 枚举）",
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines[:14]))
    print(f"报告: {REPORT}")
    if dry:
        print("[dry-run] 未写出数据文件")


if __name__ == "__main__":
    main()
