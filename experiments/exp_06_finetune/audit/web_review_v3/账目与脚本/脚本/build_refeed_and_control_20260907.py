# -*- coding: utf-8 -*-
"""重投喂 pack(8025/8141/8176) + 7862 再蒸馏队列 + 对照批 pack(12%)。"""
import json, re, sys, random, hashlib
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[4]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
V3 = BASE / "audit/web_review_v3"
lines = DATA.read_text(encoding="utf-8").split("\n")
n_rec = sum(1 for l in lines if l.strip())
JB = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)
FENCE = re.compile(r"```[\w+#.\-/]*[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)

def token_est(s):
    cjk = sum(1 for ch in s if "\u4e00" <= ch <= "\u9fff")
    return int(1.616 * cjk + 0.24 * (len(s) - cjk))

def locate(wid):
    """map 行号(删除前编号) -> 当前行号, 内容 token 双验证"""
    mp = json.loads((BASE / "audit/result_id_map.json").read_text(encoding="utf-8"))
    e = mp.get(str(wid))
    if not e or not e.get("v15_line"):
        return None
    orig = e["v15_line"]
    deleted = [6206, 7260, 7267, 7272, 7483, 7727, 7803, 8121, 8123, 8129,
               1676, 2512, 7201, 7204, 7217, 7224, 7231, 7247, 7400, 7758]
    cur = orig - sum(1 for d in deleted if d < orig)
    if orig > 7202:  # 7261 删除于(删前编号)7202
        cur -= 1
    return cur

def render(wid, ln):
    rec = json.loads(lines[ln - 1])
    u, a = rec["messages"][1]["content"], rec["messages"][2]["content"]
    lang_m = re.search(r"```([\w+#.\-/]*)", u)
    code_m = FENCE.search(u)
    lang = lang_m.group(1) if lang_m else "text"
    code = code_m.group(1) if code_m else ""
    numbered = "\n".join(f"{i+1:4d}| {l}" for i, l in enumerate(code.split("\n")))
    ms = JB.findall(a)
    ok = True
    try:
        o = json.loads(ms[-1])
    except Exception:
        ok = False
        o = {}
    body = a.split("```json")[0].strip() if "```json" in a else a.strip()
    flags = []
    if not ok:
        flags.append("broken_json_redistill")
    s = {"code_part": f"### id={wid} lang={lang}\n[CODE]\n{numbered}\n",
         "ans_part": (f"### id={wid} teacher=record flags=[{','.join(flags)}]\n"
                      f"[ANALYSIS]\n{body}\n[JSON]\n{json.dumps(o, ensure_ascii=False)}\n"),
         "tokens": token_est(numbered) + token_est(body), "ok": ok}
    return s

# ---- 1) 重投喂 pack ----
toks = {8025: ["_nb_redirects", "safe_target"], 8141: ["detectXss", "sanitizeSVG"], 8176: ["seededRand", "SanitizeResponseData"]}
refeed = []
for wid, tt in toks.items():
    ln = locate(wid)
    ok_tokens = ln and all(t.lower() in lines[ln - 1].lower() for t in tt)
    if not ok_tokens:
        cand = [i for i, l in enumerate(lines, 1) if all(t.lower() in l.lower() for t in tt)]
        print(f"  警告: id={wid} map定位(行{ln})token不符, 内容搜索候选={cand}")
        ln = cand[0] if cand else None
    s = render(wid, ln)
    s["line"] = ln
    refeed.append(s)
    print(f"  id={wid} 行{ln} json完整={s['ok']} ~{s['tokens']}tok")
text = (f"batch=R1 样本数=3\n\n"
        f"████ 第 0 步区:以下为本批全部 [CODE](先独立重解,勿看后文)████\n\n"
        + "\n".join(s["code_part"] for s in refeed)
        + "\n\n████ 第 1-5 步区:核对用 [ANALYSIS]/[JSON](读完上区再来看这里)████\n\n"
        + "\n".join(s["ans_part"] for s in refeed))
(V3 / "refeed_pack_R1_8025_8141_8176.txt").write_text(text, encoding="utf-8")
print("重投喂包: refeed_pack_R1_8025_8141_8176.txt,",
      f"json异常={[s['line'] for s in refeed if not s['ok']]}")

# ---- 2) 7862 再蒸馏队列 ----
src = None
for cand in ["corpus/checklist_raw/COT_corpus_00074.go.txt", "corpus/long_file_raw/L_vuln_corpus_00074.txt"]:
    p = BASE / "corpus" / Path(cand).name if False else BASE / cand
    if p.exists() and "VersionTLS10" in p.read_text(encoding="utf-8", errors="replace"):
        src = p
        break
if src is None:
    hits = [p for p in (BASE / "corpus").rglob("*.txt") if "VersionTLS10" in p.read_text(encoding="utf-8", errors="replace")]
    src = hits[0] if hits else None
q = {"id": 7862, "status": "redistill_queue",
     "reason": "教师输出截断无JSON(wave1按旧政策删除); batch_20_30语境下弱TLS=CWE-327(Medium档, R6无污点流配置类)",
     "code_source": str(src.relative_to(BASE)) if src else None,
     "action": "以corpus源码重新蒸馏教师输出 -> 重审计 -> 按新verdict政策处置"}
(V3 / "refeed_redistill_queue_20260907.json").write_text(
    json.dumps([q], ensure_ascii=False, indent=1), encoding="utf-8")
print("7862 源码:", q["code_source"])

# ---- 3) 对照批(12%, 未标记池) ----
mf = json.load(open(V3 / "web_review_manifest.json", encoding="utf-8"))
packed = {i for m in mf for i in m.get("ids", [])}
tol = json.loads((BASE / "audit/web_review/_result_tolparse_20260902.json").read_text(encoding="utf-8"))
reviewed = set(tol.keys()) | packed
sf = json.load(open(BASE / "audit/scan_v2_15_flags.json", encoding="utf-8"))
flag_lines = set()
for cat, items in sf.items():
    for it in items:
        if isinstance(it, dict) and it.get("line"):
            flag_lines.add(int(it["line"]))
pool = [i for i in range(1, 10022) if i not in reviewed and i not in flag_lines and lines[i - 1].strip()]
rng = random.Random(20260907)
n_reviewed = len(reviewed)
n_ctrl = max(10, -(-n_reviewed * 12 // 100))
ctrl_ids = sorted(rng.sample(pool, min(n_ctrl, len(pool))))
ctrl = []
for wid in ctrl_ids:
    s = render(wid, wid)  # 基础id == 当前会漂移, 用内容重定位
    ctrl.append((wid, s))
# 行号漂移修正: 按删除偏移
deleted_sorted = sorted([6206, 7260, 7267, 7272, 7483, 7727, 7803, 8121, 8123, 8129,
                         1676, 2512, 7201, 7204, 7217, 7224, 7231, 7247, 7400, 7758, 7202])
ctrl_ok = []
for wid, s in ctrl:
    cur = wid - sum(1 for d in deleted_sorted if d < wid)
    try:
        rec = json.loads(lines[cur - 1])
        u = rec["messages"][1]["content"]
        cm = FENCE.search(u)
        if not cm:
            continue
        code = cm.group(1)
        numbered = "\n".join(f"{i+1:4d}| {l}" for i, l in enumerate(code.split("\n")))
        a = rec["messages"][2]["content"]
        ms = JB.findall(a)
        try:
            o = json.loads(ms[-1]); ok = True
        except Exception:
            o = {}; ok = False
        body = a.split("```json")[0].strip() if "```json" in a else a.strip()
        lang_m = re.search(r"```([\w+#.\-/]*)", u)
        ctrl_ok.append({"wid": wid, "line": cur,
                        "code_part": f"### id={wid} lang={(lang_m.group(1) if lang_m else 'text')}\n[CODE]\n{numbered}\n",
                        "ans_part": (f"### id={wid} teacher=record flags=[{'' if ok else 'broken_json_redistill'}]\n"
                                     f"[ANALYSIS]\n{body}\n[JSON]\n{json.dumps(o, ensure_ascii=False)}\n"),
                        "tokens": token_est(numbered) + token_est(body), "ok": ok})
    except Exception as ex:
        print(f"  对照 id={wid} 跳过: {ex}")
# 装箱(每包~5条, 预算20000)
packs, cur_pack, tok = [], [], 0
for s in ctrl_ok:
    if cur_pack and (tok + s["tokens"] > 20000 or len(cur_pack) >= 5):
        packs.append(cur_pack); cur_pack, tok = [], 0
    cur_pack.append(s); tok += s["tokens"]
if cur_pack:
    packs.append(cur_pack)
manifest_pub = json.loads((V3 / "web_review_manifest.json").read_text(encoding="utf-8"))
next_num = 1 + max(int(re.search(r"(\d+)", m["packet"]).group(1)) for m in manifest_pub)
ctrl_manifest = []
for k, grp in enumerate(packs, 1):
    pname = f"pack_{next_num + k - 1:03d}.txt"
    text = (f"batch={next_num + k - 1} 样本数={len(grp)}\n\n"
            f"████ 第 0 步区:以下为本批全部 [CODE](先独立重解,勿看后文)████\n\n"
            + "\n".join(s["code_part"] for s in grp)
            + "\n\n████ 第 1-5 步区:核对用 [ANALYSIS]/[JSON](读完上区再来看这里)████\n\n"
            + "\n".join(s["ans_part"] for s in grp))
    (V3 / pname).write_text(text, encoding="utf-8")
    ctrl_manifest.append({"packet": pname, "ids": [s["wid"] for s in grp],
                          "est_tokens": sum(s["tokens"] for s in grp)})
priv = {"purpose": "未标记对照批(10-15%配额): 审计端不可区分; 用于量化未审计池基底错误率 vs 被标记批",
        "seed": 20260907, "ratio": 0.12, "reviewed_count_basis": n_reviewed,
        "pool_size": len(pool), "generated": "2026-09-07",
        "packs": ctrl_manifest,
        "note": "对照组裁决结果按 packet 分桶统计 false_positive/fix 率, 与被标记批对比"}
(V3 / "control_manifest_PRIVATE.json").write_text(json.dumps(priv, ensure_ascii=False, indent=1), encoding="utf-8")
print(f"对照批: {len(packs)} 包 / {len(ctrl_ok)} 样本 (池 {len(pool)}, 基准 {n_reviewed} 已审, 12%)")
print("  私有映射: control_manifest_PRIVATE.json;", ", ".join(m["packet"] + ':' + str(len(m['ids'])) for m in ctrl_manifest))
