# -*- coding: utf-8 -*-
"""wave B:联立(矛盾对/近重复簇)配对审查包生成器。

审查单位 = 簇(对/三元/四元):并排呈现全部成员的编号代码与教师结论,
附 unified diff 高亮差异行,要求对级 verdict。
排除:已裁决 10 组(重审价值低,单独存档)、与 wave A 重叠的簇。
"""
import difflib
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
AUD = Path(__file__).resolve().parent
S7 = AUD / "agent_audit_v2_14/out/s7_conflict_clusters.jsonl"
JB = re.compile(r"```json\s*(.*?)```", re.S)
FENCE = re.compile(r"```[\w+#.\-/]*[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)

HEADER = """你是独立安全审查员,审查"矛盾对/近重复簇":同一(或近同)代码被标注了不同结论的多个样本。你的任务是判断【哪一侧的标注正确】——这类样本的价值恰在于标签关系,请务必做逐行对比后再下结论。

【方法】
1. 并排读两侧代码,找出全部差异行(diff 已给出);
2. 判断差异是否足以支撑两侧不同的标签(如:加一行 uint64 转换消除了溢出 → 有洞/安全分化成立;仅删了无效防御 → "安全侧"存疑);
3. 对每侧独立核对 CWE/风险级;
4. 常见陷阱:两侧都错(同码同错)、差异行不是决定性行、上游库行为误断。

【输出格式】每簇输出一行 JSON(不要代码块):
{"ids": [idA, idB], "label_correct": "A|B|both|neither|partial", "decisive_diff": "决定性差异的一句话", "issues": ["每侧的问题,如 A:CWE 应为 xxx"], "note": "一句话理由"}
label_correct: A=仅 A 侧标注正确;B=仅 B 侧;both=两侧标注各对其样本成立(如漏洞版/修复版);neither=两侧都错;partial=一侧对另一侧部分对。
每簇之后不需要汇总;所有簇输出完即结束。

【簇】
"""

def token_est(s):
    cjk = sum(1 for ch in s if "\u4e00" <= ch <= "\u9fff")
    return int(1.616 * cjk + 0.24 * (len(s) - cjk))

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=20000)
    ap.add_argument("--per-packet", type=int, default=3, help="单包簇数上限")
    ap.add_argument("--out", default=str(AUD / "web_review"))
    ap.add_argument("--limit-packs", type=int, default=0, help="只生成前 N 包(0=全部)")
    args = ap.parse_args()

    waveA_ids = set()
    wf = AUD / "waveA_ids.json"
    if wf.exists():
        for x in json.load(open(wf, encoding="utf-8")):
            waveA_ids.add(x["id"] if isinstance(x, dict) else x)

    # 行号映射(基底 + 尾部 fix_distill.orig)
    del_ids = {json.loads(l)["id"] for l in
               (AUD / "agent_audit_v2_14/out/manifest_DELETE.jsonl").open(encoding="utf-8") if l.strip()} | {8288, 8968}
    id2line = {}
    n = 0
    for i in range(1, 10022):
        if i in del_ids:
            continue
        n += 1
        id2line[i] = n
    lines = DATA.read_text(encoding="utf-8").split("\n")
    n_base = len(id2line)
    for l in lines[n_base:]:
        if not l.strip():
            continue
        n_base += 1
        rec = json.loads(l)
        orig = (rec.get("fix_distill") or {}).get("orig")
        if orig:
            id2line[orig] = n_base

    # 读取样本(id → 代码行列表/教师 JSON)
    cache = {}
    def sample(wid):
        if wid in cache:
            return cache[wid]
        ln = id2line.get(wid)
        if ln is None or ln - 1 >= len(lines):
            cache[wid] = None
            return None
        rec = json.loads(lines[ln - 1])
        code = FENCE.findall(rec["messages"][1]["content"])
        code = code[0] if code else ""
        o = {}
        ms = JB.findall(rec["messages"][2]["content"])
        if ms:
            try:
                o = json.loads(ms[-1])
            except Exception:
                pass
        numbered = "\n".join(f"{i+1:4d}| {l}" for i, l in enumerate(code.split("\n")))
        s = {"code": code, "numbered": numbered, "n": len(code.split("\n")), "json": o}
        cache[wid] = s
        return s

    # 载入簇,排除已裁决与 wave A 重叠
    ADJUDICATED = [{"8195", "8290"}, {"8029", "8030"}, {"8187", "8288"}, {"8966", "8968"},
                   {"8078", "8079"}, {"8140", "8141"}, {"7992", "7993"}, {"7816", "7817"},
                   {"6926", "6927"}, {"7806", "7807"}]
    clusters = [json.loads(l) for l in S7.open(encoding="utf-8") if l.strip()]
    pending = []
    skipped = 0
    for r in clusters:
        members = [m["id"] if isinstance(m, dict) else int(m) for m in (r.get("members") or [])]
        if {int(m) for m in members} in [{int(x) for x in a} for a in ADJUDICATED]:
            skipped += 1
            continue
        if waveA_ids & {int(m) for m in members}:
            skipped += 1
            continue
        pending.append(members)
    print(f"簇 {len(clusters)} | 已裁决排除 {skipped} | waveA 重叠排除计入 skipped | 待审簇 {len(pending)}"
          f"(对 {sum(1 for p in pending if len(p)==2)} / 三元 {sum(1 for p in pending if len(p)==3)} / 四元 {sum(1 for p in pending if len(p)==4)})")

    def member_block(wid, side, meta=None):
        s = sample(int(wid))
        if s is None:
            return f"── 样本 {wid}(id 无映射)──\n<缺失>", 0, None
        o = s["json"]
        head = (f"── {side} 侧样本 id={wid} ──\n"
                f"【教师标注】has_vulnerability={o.get('has_vulnerability')}, "
                f"{o.get('vulnerability_type')}, risk={o.get('risk_level')}\n"
                f"【explanation】{str(o.get('explanation'))[:300]}\n"
                f"【代码({s['n']} 行)】\n{s['numbered']}\n")
        return head, token_est(head), o

    packets = []
    cur, cur_tok, cur_groups = [], 0, []
    for members in pending:
        group_text_parts = []
        group_ids = []
        gtok = token_est("diff占位") + 200
        ok = True
        codes = []
        for k, m in enumerate(members):
            wid = m["id"] if isinstance(m, dict) else int(m)
            meta = m if isinstance(m, dict) else {}
            head, tk, o = member_block(wid, "AB"[k] if len(members) == 2 else f"S{k+1}", meta)
            if tk == 0:
                ok = False
                break
            group_text_parts.append(head)
            gtok += tk
            s = sample(int(wid))
            codes.append(s["code"])
            group_ids.append(wid)
        if not ok or len(codes) < 2:
            continue
        # unified diff(首两侧行数平衡处理:直接 diff 全文)
        diff = "\n".join(difflib.unified_diff(codes[0].split("\n"), codes[1].split("\n"),
                                              f"id{group_ids[0]}", f"id{group_ids[1]}", lineterm="", n=1))
        diff_text = "【两侧代码 diff(前 60 行)】\n" + "\n".join(diff.split("\n")[:60]) if diff else ""
        gtok += token_est(diff_text)
        if cur and (cur_tok + gtok > args.budget or len(cur_groups) >= args.per_packet):
            packets.append((cur, cur_tok, cur_groups))
            cur, cur_tok, cur_groups = [], 0, []
        cur.append("\n\n════ 簇 ids={ids} ════\n\n".format(ids=",".join(str(x) for x in group_ids)) + "\n".join(group_text_parts) + ("\n" + diff_text if diff_text else ""))
        cur_tok += gtok
        cur_groups.append(group_ids)
    if cur:
        packets.append((cur, cur_tok, cur_groups))

    outdir = Path(args.out)
    outdir.mkdir(exist_ok=True)
    start = 1
    if (outdir / "web_review_manifest.json").exists():
        old = json.load(open(outdir / "web_review_manifest.json", encoding="utf-8"))
        existing = [m["packet"] for m in old]
        start = max([int(re.search(r"(\d+)", p).group(1)) for p in existing if re.search(r"(\d+)", p)] or [0]) + 1
    manifest = json.load(open(outdir / "web_review_manifest.json", encoding="utf-8")) if (outdir / "web_review_manifest.json").exists() else []
    n = 0
    for pi, (parts, tok, ids) in enumerate(packets):
        if args.limit_packs and n >= args.limit_packs:
            break
        pnum = start + n
        p = outdir / f"pack_{pnum:02d}.txt"
        p.write_text(HEADER + "\n".join(parts), encoding="utf-8")
        manifest.append({"packet": p.name, "groups": ids, "est_tokens": tok + token_est(HEADER)})
        print(f"  {p.name}: {len(ids)} 簇 ids={ids} ~{tok + token_est(HEADER)} tok")
        n += 1
    (outdir / "web_review_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"生成 {n} 包(剩余 {len(packets) - n} 包未生成,重跑本脚本继续) -> {outdir}")

if __name__ == "__main__":
    main()
