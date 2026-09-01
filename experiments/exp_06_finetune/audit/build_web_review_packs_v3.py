# -*- coding: utf-8 -*-
"""网页 AI 审查包生成器 v3(用户自有协议版,无 prompt、两段式防偷看)。

任务清单 JSON(jobs):
  [{"name": "waveA", "ids": [35 个 id], "per_packet": 5},
   {"name": "waveB_pairs", "pair_mode": true, "exclude_ids": [23 条裁决+waveA 已含的 id]}]
pair_mode 任务自动读取 s7_conflict_clusters.jsonl 的簇表,一簇一批;
簇内成员展开为单条样本(flags 带 pair_with=对端 id),仍走用户逐条协议。

包结构:
  batch=NN 样本数=K
  ████ 第 0 步区:全部 [CODE](独立重解,勿看后文)███
  ████ 第 1-5 步区:[ANALYSIS]/[JSON](核对用)███
"""
import argparse
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

def token_est(s):
    cjk = sum(1 for ch in s if "\u4e00" <= ch <= "\u9fff")
    return int(1.616 * cjk + 0.24 * (len(s) - cjk))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", required=True)
    ap.add_argument("--out", default=str(AUD / "web_review"))
    ap.add_argument("--budget", type=int, default=20000)
    ap.add_argument("--limit-packs", type=int, default=0)
    args = ap.parse_args()
    jobs = json.load(open(args.jobs, encoding="utf-8"))

    # ---- id -> 行号 + 样本缓存 ----
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
        orig = (json.loads(l).get("fix_distill") or {}).get("orig")
        if orig:
            id2line[orig] = n_base

    cache = {}
    def render(wid):
        if wid in cache:
            return cache[wid]
        ln = id2line.get(wid)
        if ln is None or ln - 1 >= len(lines):
            cache[wid] = None
            return None
        rec = json.loads(lines[ln - 1])
        u, a = rec["messages"][1]["content"], rec["messages"][2]["content"]
        lang_m = re.search(r"```([\w+#.\-/]*)", u)
        code_m = FENCE.search(u)
        lang = lang_m.group(1) if lang_m else "text"
        code = code_m.group(1) if code_m else ""
        numbered = "\n".join(f"{i+1:4d}| {l}" for i, l in enumerate(code.split("\n")))
        ms = JB.findall(a)
        try:
            o = json.loads(ms[-1])
        except Exception:
            cache[wid] = None
            return None
        body = a.split("```json")[0].strip() if "```json" in a else a.strip()
        fd = rec.get("fix_distill") or {}
        teacher = str(fd.get("teacher", "unknown"))
        flags = []
        if "wave1" in teacher:
            flags.append("redistilled")
        if o.get("has_vulnerability") is False and re.search(r"CWE-\d+", str(o.get("explanation", ""))):
            flags.append("safe_but_cwe_in_expl")
        if not a.rstrip().endswith("```"):
            flags.append("maybe_truncated")
        s = {
            "code_part": f"### id={wid} lang={lang}\n[CODE]\n{numbered}\n",
            "ans_part": (f"### id={wid} teacher={teacher} flags=[{','.join(flags)}]\n"
                         f"[ANALYSIS]\n{body}\n[JSON]\n{json.dumps(o, ensure_ascii=False)}\n"),
            "tokens": token_est(numbered) + token_est(body) + token_est(json.dumps(o, ensure_ascii=False)),
            "teacher": teacher,
        }
        cache[wid] = s
        return s

    # ---- 构造批 ----
    outdir = Path(args.out)
    outdir.mkdir(exist_ok=True)
    mpath = outdir / "web_review_manifest.json"
    manifest = json.load(open(mpath, encoding="utf-8")) if mpath.exists() else []
    used = {m["packet"] for m in manifest}
    next_num = 1
    for m in manifest:
        mm = re.search(r"(\d+)", m["packet"])
        if mm:
            next_num = max(next_num, int(mm.group(1)) + 1)

    all_batches = []   # (job_name, [ids])
    emitted = set()
    for m in manifest:
        emitted |= set(m.get("ids", []))
    for job in jobs:
        name = job["name"]
        budget = job.get("budget", args.budget)
        per = job.get("per_packet", 6)
        if job.get("pair_mode"):
            exclude = set(job.get("exclude_ids", []))
            clusters = [json.loads(l) for l in S7.open(encoding="utf-8") if l.strip()]
            wave_a = set()
            for m in manifest:
                wave_a |= set(m.get("ids", []))
            groups = []
            for r in clusters:
                mem = [m2["id"] if isinstance(m2, dict) else int(m2) for m2 in r["members"]]
                mem = [x for x in mem if x not in emitted]
                if len(mem) < 2:
                    continue
                if set(mem) & exclude or set(mem) & wave_a:
                    continue
                if all(id2line.get(x) for x in mem):
                    groups.append(mem)
            for g in groups:
                all_batches.append((name, g))
        else:
            ids = [x for x in job["ids"] if x not in emitted]
            for k in range(0, len(ids), per):
                all_batches.append((name, ids[k:k + per]))

    # ---- 产出(预算内装箱;一簇/一批不拆) ----
    n_out = 0
    for name, grp in all_batches:
        if args.limit_packs and n_out >= args.limit_packs:
            print(f"已到 --limit-packs {args.limit_packs},剩余 {len(all_batches) - n_out} 批未生成")
            break
        grp = [x for x in grp if x not in emitted]
        if not grp:
            continue
        rendered, tok, ids_ok = [], 0, []
        for wid in grp:
            if wid in emitted:
                continue
            s = render(wid)
            if s is None or wid in emitted:
                continue
            rendered.append(s)
            tok += s["tokens"]
            ids_ok.append(wid)
            emitted.add(wid)
        if not rendered:
            continue
        while True:
            p = outdir / f"pack_{next_num:02d}.txt"
            if not p.exists():
                break
            next_num += 1
        text = (f"batch={next_num} 样本数={len(ids_ok)}\n\n"
                f"████ 第 0 步区:以下为本批全部 [CODE](先独立重解,勿看后文)████\n\n"
                + "\n".join(s["code_part"] for s in rendered)
                + "\n\n████ 第 1-5 步区:核对用 [ANALYSIS]/[JSON](读完上区再来看这里)████\n\n"
                + "\n".join(s["ans_part"] for s in rendered))
        p.write_text(text, encoding="utf-8")
        manifest.append({"packet": p.name, "batch": next_num, "ids": ids_ok, "job": name,
                         "est_tokens": tok})
        emitted |= set(ids_ok)
        n_out += 1
        print(f"  {p.name}: {len(ids_ok)} 样本 ids={ids_ok} ~{tok} tok(不含协议头)", flush=True)
    mpath.write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"本轮生成 {n_out} 包;manifest 共 {len(manifest)} 包 -> {mpath}")

if __name__ == "__main__":
    main()
