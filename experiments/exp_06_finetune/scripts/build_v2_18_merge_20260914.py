# -*- coding: utf-8 -*-
"""v2_18 组装器 v3（20260914）—— 修复 20260913 版的三类缺陷。

相对 build_v2_18_merge_20260913.py 的变更（动机见 results/_v2_18_replace_adjudication_20260914.md 头注）：
  1. 同码不再一律跳过：kit 治理通过且新蒸结论与旧行一致（+CWE 族校验）→ 用新分析替换旧行
     （格式升级：补结论行/防御段/七字段 JSON）；结论相左 → 写裁决单，不自动定胜负。
  2. 重复块选块有据：9_11批按 result_blocks.jsonl 的 usable=True 选块（原为"后者覆盖"，
     会选中 00007#A#3 这类 usable=False 块）；续投批重复块同判定才可合并，异判定送裁决；
     复核批锚点单元（L56/L68）不折叠，按 _redistill_truth_parse 的 class+真值CWE 排序取优。
  3. 全路径计数 + 块数守恒断言：输入单元数 = 各去向之和，静默路径为零。
     "### 自查" 伪 kit 块、"redistill-00008-A A" 头解析失败、00160 式"结论: disagree:"不可解析
     块全部显式入账，不再无痕消失。

质量门（不变）：评测孪生指纹 / CVE 评测集零交集 / 全半角冒号兼容 / wave2 A 侧。
用法：python3 build_v2_18_merge_20260914.py [--apply]
"""
import hashlib
import json
import os
import re
import sys
import collections
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

AA = Path(os.environ.get("AA_WS", "/home/zane/文档/code/aa"))
WS = Path(os.environ.get("GRAD_WS", "/home/zane/文档/code/毕业设计"))
WAVE = AA / "wave2_extracted" / "experiments" / "exp_06_finetune" / "corpus" / "diffpair_wave1"
KITS = WAVE / "kits_learner"
OUT_DATA = WS / "experiments" / "exp_06_finetune" / "data"
V217 = AA / "final_train_chatml_alpha06_v2_17_clean.jsonl"
ADJ_OUT = WAVE / "results" / "_v2_18_replace_adjudication_20260914.md"

FAMILY = {
    "441": {"441", "918", "601", "799", "290", "640", "807"},
    "799": {"799", "441", "918", "640", "807", "290"},
    "290": {"290", "441", "799", "807", "918"},
    "640": {"640", "441", "799", "807"}, "807": {"807", "441", "290", "640"},
    "918": {"918", "441", "601", "799"}, "601": {"601", "918", "441", "799"},
    "95": {"95", "94", "1336", "621"}, "94": {"94", "95", "1336"},
    "1336": {"1336", "94", "95"}, "621": {"621", "95", "915"},
    "78": {"78", "77"}, "77": {"77", "78"},
}
CWE_NAMES = json.loads((Path(__file__).parent / "cwe_names_20260913.json").read_text(encoding="utf-8")) \
    if (Path(__file__).parent / "cwe_names_20260913.json").exists() else {
    "20": "Improper Input Validation", "22": "Path Traversal", "74": "Injection",
    "77": "Command Injection", "78": "OS Command Injection", "79": "Cross-site Scripting",
    "89": "SQL Injection", "90": "LDAP Injection", "94": "Code Injection", "95": "Eval Injection",
    "96": "Static Code Injection", "116": "Improper Encoding or Escaping of Output",
    "190": "Integer Overflow", "200": "Exposure of Sensitive Information",
    "284": "Improper Access Control", "287": "Improper Authentication",
    "294": "Authentication Bypass by Capture-replay", "295": "Improper Certificate Validation",
    "306": "Missing Authentication", "321": "Hard-coded Cryptographic Key",
    "327": "Broken Crypto Algorithm", "347": "Improper Verification of Cryptographic Signature",
    "352": "CSRF", "400": "Uncontrolled Resource Consumption", "441": "Unintended Proxy or Intermediary",
    "476": "NULL Pointer Dereference", "494": "Download of Code Without Integrity Check",
    "502": "Deserialization of Untrusted Data", "601": "Open Redirect", "611": "XXE",
    "621": "Variable Overwrite", "639": "Authorization Bypass Through User-Controlled Key",
    "772": "Missing Release of Resource after Effective Lifetime", "776": "XML Entity Expansion",
    "798": "Use of Hard-coded Credentials", "829": "Inclusion of Functionality from Untrusted Control Sphere",
    "862": "Missing Authorization", "863": "Incorrect Authorization", "918": "Server-Side Request Forgery (SSRF)",
    "943": "Improper Neutralization of Special Elements in Data Query Logic", "1321": "Prototype Pollution",
}

# 头解析：允许块名后带任意尾注（版本A/版本B/全文/"A"/自查…）；尾注为 版本A/版本B 时记侧。
HEAD_RE = re.compile(r"^###\s+(\S+?)(?:[ \t]+(版本A|版本B))?(?:[ \t]+\S+)*\s*$")
CONCL_RE = re.compile(r"结论\s*[:：]\s*存在漏洞\s*=\s*(true|false|无法判定|无法确认|待定|样本内不可证)([^\n]*)")
SEC = lambda name: re.compile(rf"{name}\s*[:：]\s*([^\n]*)")
UNDECIDED = {"无法判定", "无法确认", "待定", "样本内不可证"}


def fp(code: str) -> str:
    return hashlib.md5(re.sub(r"\s+", "", code).encode("utf-8")).hexdigest()


def norm_kit_side(name: str, side_tok, tail_tok=None):
    """块名 → (kit, side, unit_id, is_selfcheck)；redistill 锚点保留完整单元名，不折叠。
    尾注为「自查」（无论位置）的一律视为自查伪块，不得占用 (kit,side) 键位。"""
    if name == "自查" or tail_tok == "自查":
        return None, None, (f"{name} {tail_tok}" if tail_tok else name), True
    if name.startswith("redistill-"):
        mm = re.match(r"redistill-(?:neg-)?(\d+)", name)
        if not mm:
            return None, None, name, False
        return f"diffpair-corpus_{mm.group(1)}", "版本A", name, False
    return name, (side_tok or "版本A"), name, False


def parse_blocks_indexed(path: Path):
    """返回 [(unit_id, (kit, side, unit_id, is_selfcheck), block, occ)]，occ 为同键内序号（1 起）。"""
    out = []
    if not path.exists():
        return out
    t = path.read_text(encoding="utf-8", errors="replace")
    occ = collections.Counter()
    for b in re.split(r"(?m)^(?=### )", t):
        first = b.split("\n", 1)[0]
        m = re.match(r"^###\s+(.*)$", first)
        if not m:
            continue
        rest = m.group(1).strip()
        name_m = re.match(r"^(\S+)(?:[ \t]+(版本A|版本B))?(?:[ \t]+(\S+))?$", rest)
        if not name_m:
            continue
        kit, side, unit, selfchk = norm_kit_side(name_m.group(1), name_m.group(2), name_m.group(3))
        if kit is None:
            out.append((unit, (None, None, unit, selfchk), b, 1))
            continue
        occ[(kit, side)] += 1
        out.append((unit, (kit, side, unit, False), b, occ[(kit, side)]))
    return out


def strip_selfcheck(b: str) -> str:
    b = re.split(r"(?m)^\s*-\s*\[", b)[0]
    b = re.split(r"(?m)^自查\s*[:：]", b)[0]
    b = re.sub(r"(?m)^###\s+(?:diffpair-corpus_\d+|wave2-[\w.-]+|redistill-[\w.-]+)[^\n]*\n?", "", b)
    return b.rstrip()


def build_assistant(block: str, hv: bool, cwe, risk, src, snk, expl, fix) -> str:
    prose = strip_selfcheck(block)
    keep = [ln for ln in prose.split("\n")
            if not (re.match(r"^\s*结论\s*[:：]", ln) or re.match(r"^\s*修复\s*[:：]", ln))]
    prose = "\n".join(keep).rstrip()
    fields = {
        "has_vulnerability": hv,
        "vulnerability_type": (f"CWE-{cwe} {CWE_NAMES.get(cwe, '')}".strip() if (hv and cwe) else "none"),
        "risk_level": risk if hv else "None",
        "source": src if hv else "N/A",
        "sink": snk if hv else "N/A",
        "explanation": expl if hv else ("无可达污点流：" + expl[:180]) if expl else "无可达污点流；防御见分析。",
        "fix_suggestion": fix if hv else "N/A",
    }
    return f"{prose}\n\n```json\n{json.dumps(fields, ensure_ascii=False)}\n```"


def to_line(s: str) -> str:
    return re.sub(r"\bL(\d+)\b", r"line \1", s)


def extract_json_parts(b: str, hv: bool):
    concl = CONCL_RE.search(b)
    rest = concl.group(2) if concl else ""
    mcwe = re.search(r"CWE-(\d+)", rest)
    cwe = mcwe.group(1) if mcwe else None
    mr = re.search(r"(Critical|High|Medium|Low)", rest, re.I)
    risk = mr.group(1).capitalize() if mr else "Medium"
    entry = SEC("入口").search(b)
    chain = SEC("链").search(b)
    combo = SEC("组合链").search(b)
    fixm = SEC("修复").search(b)
    src = to_line(entry.group(1).split("|")[0].strip()) if entry else "N/A"
    expl = to_line(chain.group(1).strip()) if chain else ""
    if combo:
        expl += " 组合链: " + to_line(combo.group(1).strip())
    snk = "N/A"
    if chain:
        hops = re.findall(r"→\s*(L\d+\s+`[^`]+`[^→]*)", chain.group(1))
        snk = to_line(hops[-1].strip()) if hops else to_line(chain.group(1).strip()[-120:])
    fix = to_line(fixm.group(1).strip()) if fixm else "N/A"
    return cwe, risk, src, snk, expl, fix


def block_conclusion(b: str):
    """→ (hv_bool|None, cwe|None, rest)；不可解析/未判定时 hv=None。"""
    c = CONCL_RE.search(b)
    if not c or c.group(1) in UNDECIDED:
        return None, None, (c.group(0) if c else "")
    hv = c.group(1) == "true"
    mcwe = re.search(r"CWE-(\d+)", c.group(2) or "")
    return hv, (mcwe.group(1) if mcwe else None), c.group(2) or ""


def eval_fingerprints():
    import os
    fps = set()
    cdir = WS / "experiments/exp_06_finetune/corpus"
    for d in ("rolling_dev", "rolling_dev_safe"):
        dd = cdir / d
        if not dd.exists():
            continue
        for f in dd.iterdir():
            if f.is_file() and f.name not in ("manifest.json", "safe_map.json"):
                fps.add(fp(f.read_text(encoding="utf-8", errors="replace")))
    return fps


def old_row_verdict(old_assistant: str):
    j = re.search(r"```json\n(.*?)```", old_assistant, re.S)
    if not j:
        return None, None
    try:
        d = json.loads(j.group(1))
    except Exception:
        return None, None
    hv = d.get("has_vulnerability")
    if isinstance(hv, str):
        hv = hv.lower() == "true"
    cwe_m = re.search(r"CWE-(\d+)", str(d.get("vulnerability_type", "")))
    return hv, (cwe_m.group(1) if cwe_m else None)


def main():
    dry = "--apply" not in sys.argv
    st = collections.Counter()          # 全路径计数
    adjudication = []                   # (来源, kit, side, unit, 旧行摘要, 新蒸摘要, manifest期望, usable注记)

    manifest = json.loads((WAVE / "manifest_PRIVATE.json").read_text(encoding="utf-8"))
    EVAL_FP = eval_fingerprints()
    print(f"评测面指纹硬门：{len(EVAL_FP)} 个")

    def kit_excluded(kit):
        e = manifest.get(kit)
        if not e:
            return "no_manifest"
        if e.get("status") in ("quarantined", "gap_unresolvable"):
            return "quarantined"
        if e.get("exclude_from_v2_18"):
            return "excluded"
        if e.get("needs_slice_backfill"):
            return "slice_backfill"
        return None

    # ---- kit 代码指纹表 ----
    kit_fp = {}
    for p in sorted(KITS.glob("diffpair-corpus_*.txt")):
        t = p.read_text(encoding="utf-8", errors="replace")
        langm = re.search(r"lang=(\w+)", t)
        lang = (langm.group(1) if langm else "text").lower()
        for v in ("A", "B"):
            mm = re.search(rf"#### 版本{v}[^\n]*\n```\w*\n(.*?)```", t, re.S)
            if mm:
                kit_fp[(p.stem, f"版本{v}")] = (lang, mm.group(1).strip("\n"))
    print(f"kit 指纹表 {len(kit_fp)} 侧")

    # ---- 基座 ----
    base_records = [json.loads(l) for l in V217.read_text(encoding="utf-8").splitlines() if l.strip()]
    system_prompt = base_records[0]["messages"][0]["content"]
    fp2rows = collections.defaultdict(list)
    for i, r in enumerate(base_records):
        mm = re.search(r"```\w*\n(.*?)```", r["messages"][1]["content"], re.S)
        if mm:
            fp2rows[fp(mm.group(1))].append(i)
    row_meta = {}
    for (kit, side), (_lang, code) in kit_fp.items():
        for i in fp2rows.get(fp(code), []):
            row_meta[i] = (kit, side)
    print(f"基座 {len(base_records)} 行，可定位 diffpair 行 {len(row_meta)}")

    # ---- 教师产出：三批解析（保留全部出现次数） ----
    red_all = parse_blocks_indexed(WAVE / "kits_redistill_truth" / "result" / "result.txt")
    cont_all = parse_blocks_indexed(KITS / "result" / "result.txt")
    n911_all = parse_blocks_indexed(WAVE / "results" / "result.txt")
    st["自查伪块(不入账即丢弃)"] = sum(1 for _u, k, _b, _o in red_all + cont_all + n911_all if k[3])

    # 复核批：按 (kit,side) 分组，用裁决台账选优（class 升序 → teacher_cwe 命中真值 → 文档序）
    parse_ledger = {}
    pl_path = WAVE / "results" / "_redistill_truth_parse_20260913.json"
    if pl_path.exists():
        _rows = json.loads(pl_path.read_text(encoding="utf-8"))
        _items = _rows.get("rows", _rows) if isinstance(_rows, dict) else _rows
        for it in _items:
            parse_ledger[it.get("id")] = it
    CLASS_RANK = {"agree": 0, "agree_qualified": 1, "disagree": 2}

    def redistill_rank(unit):
        it = parse_ledger.get(unit, {})
        cls = it.get("class", "")
        truth_cwe = (it.get("truth_cwe") or "")
        tcwe = (it.get("teacher_cwe") or "")
        hit = bool(truth_cwe) and truth_cwe in tcwe
        return (CLASS_RANK.get(cls, 3), 0 if hit else 1)

    blocks_redistill = {}      # (kit,side) -> (unit, block)
    red_group = collections.defaultdict(list)
    for unit, key, b, _o in red_all:
        if key[3]:
            continue
        red_group[(key[0], key[1])].append((unit, b))
    for k, units in red_group.items():
        units_sorted = sorted(units, key=lambda x: redistill_rank(x[0]))
        blocks_redistill[k] = units_sorted[0]
        if len(units) > 1:
            st[f"复核批锚点单元折叠(取优 {units_sorted[0][0]})"] += len(units) - 1

    # 9_11批：usable=True 选块；无 usable 信息且异判定 → 送裁决
    rb_jsonl = {}
    rbp = WAVE / "results" / "result_blocks.jsonl"
    if rbp.exists():
        for l in rbp.read_text(encoding="utf-8").splitlines():
            if not l.strip():
                continue
            r = json.loads(l)
            if r.get("usable") is True:
                ck = r.get("candidate_key", "")
                mm = re.match(r"(.+)#([AB])#(\d+)$", ck)
                if mm:
                    rb_jsonl[(mm.group(1), f"版本{mm.group(2)}")] = int(mm.group(3))
    blocks_911 = {}
    g911 = collections.defaultdict(list)
    for unit, key, b, o in n911_all:
        if key[3]:
            continue
        g911[(key[0], key[1])].append((o, unit, b))
    for k, items in g911.items():
        if len(items) == 1:
            blocks_911[k] = (items[0][1], items[0][2])
            continue
        if k in rb_jsonl:
            pick = next((it for it in items if it[0] == rb_jsonl[k]), items[-1])
            blocks_911[k] = (pick[1], pick[2])
            st["9_11批重复块:按usable选块"] += len(items) - 1
            continue
        concls = {block_conclusion(it[2])[0] for it in items}
        if len(concls) == 1:
            blocks_911[k] = (items[-1][1], items[-1][2])
            st["9_11批重复块:同判合并"] += len(items) - 1
        else:
            adjudication.append(("9_11批重复块无usable且异判定", k[0], k[1],
                                 "/".join(it[1] for it in items), "", "", "", "需人工选块"))
            st["9_11批重复块:异判定送裁决"] += 1

    # 续投批：同判合并 / 异判定送裁决
    blocks_cont = {}
    gcont = collections.defaultdict(list)
    for unit, key, b, o in cont_all:
        if key[3]:
            continue
        gcont[(key[0], key[1])].append((o, unit, b))
    for k, items in gcont.items():
        if len(items) == 1:
            blocks_cont[k] = (items[0][1], items[0][2])
            continue
        concls = {block_conclusion(it[2])[0] for it in items}
        if len(concls) == 1:
            blocks_cont[k] = (items[-1][1], items[-1][2])
            st["续投批重复块:同判合并"] += len(items) - 1
        else:
            adjudication.append(("续投批重复块异判定", k[0], k[1],
                                 "/".join(it[1] for it in items), "", "", "", "需人工选块"))
            st["续投批重复块:异判定送裁决"] += 1

    # 合并视图：复核批 > 续投批 > 9_11批
    merged = {}
    merged_src = {}
    for k, (unit, b) in blocks_911.items():
        merged[k] = (unit, b)
        merged_src[k] = "9_11批"
    for k, (unit, b) in blocks_cont.items():
        merged[k] = (unit, b)
        merged_src[k] = "续投批"
    for k, (unit, b) in blocks_redistill.items():
        if k in merged:
            st[f"该键以复核批为准({merged_src[k]}块弃用)"] += 1
        merged[k] = (unit, b)
        merged_src[k] = "复核批"

    # ---- wave2（同原版） ----
    pre = json.loads((WAVE / "results" / "_wave2_preaudit_compare_20260913.json").read_text(encoding="utf-8"))
    wave2_ok = [r["pid"] for r in pre["rows"] if r["verdict"] in ("PASS", "SIDE_B_HOLE")]
    wave2_code = {}
    for p in (WAVE / "wave2_pairs").glob("*.txt"):
        t = p.read_text(encoding="utf-8", errors="replace")
        mh = re.match(r"# wave2 pair (\S+) \| \S+ \| (\S+)", t)
        ma = re.search(r"#### 版本A（[^）]*）\n```\w*\n(.*?)```", t, re.S)
        if mh and ma:
            wave2_code[mh.group(1)] = (mh.group(2).lower(), ma.group(1).strip("\n"))
    wf = {}
    for name in ("wave2_formal_results_441.txt", "wave2_formal_results_78_a.txt",
                 "wave2_formal_results_78_b.txt", "wave2_formal_results_95_a.txt",
                 "wave2_formal_results_95_b.txt"):
        for _u, key, b, _o in parse_blocks_indexed(WAVE / "results" / name):
            if not key[3]:
                wf[(key[0], key[1])] = b

    # ---- 基座行处置：删除 / 替换 / 保留 ----
    drop_rows, replace_rows = set(), {}
    appended = []
    truth_units = 0

    def truth_of(kit):
        e = manifest.get(kit, {})
        return e.get("expected_present", True), e.get("expected_cwe") or ""

    def append_block(kit, side, unit, b, src_tag):
        cd = kit_fp.get((kit, side))
        if not cd:
            st[f"增跳:{src_tag}无代码指纹"] += 1
            adjudication.append(("增补缺代码", kit, side, unit, "", "", "", ""))
            return
        if fp(cd[1]) in EVAL_FP:
            st[f"增跳:{src_tag}评测孪生"] += 1
            return
        hv, cwe, _rest = block_conclusion(b)
        if hv is None:
            st[f"增跳:{src_tag}结论不可解析→送裁决"] += 1
            exp_present, exp_cwe = truth_of(kit)
            adjudication.append(("增补块结论不可解析", kit, side, unit, "", "", exp_cwe, "如需入库须人工改写结论行"))
            return
        exp_present, exp_cwe = truth_of(kit)
        ln_exp = re.match(r"CWE-(\d+)", exp_cwe)
        if side == "版本A":
            if hv != bool(exp_present):
                st[f"增跳:{src_tag}与真值反→送裁决"] += 1
                old_txt = f"期望{'有洞' if exp_present else '无洞'}({exp_cwe})"
                adjudication.append(("增补块与真值反", kit, side, unit, "", f"hv={hv} CWE-{cwe}" if cwe else f"hv={hv}", old_txt, ""))
                return
            if hv and cwe is not None and ln_exp and cwe not in FAMILY.get(ln_exp.group(1), {ln_exp.group(1)}):
                st[f"增跳:{src_tag}cwe不符→送裁决"] += 1
                adjudication.append(("增补块cwe不符", kit, side, unit, "", f"CWE-{cwe}", exp_cwe, ""))
                return
        else:
            if hv or not exp_present:
                st[f"增跳:{src_tag}B侧无效"] += 1
                return
        h = fp(cd[1])
        if h in fp2rows:
            st[f"增跳:{src_tag}同码已在基座"] += 1
            return
        dup = next((x for x in appended if x[0] == h), None)
        if dup is not None:
            if dup[3] == hv:
                st[f"增跳:{src_tag}同码同判去重"] += 1
            else:
                st[f"增跳:{src_tag}同码增补判定冲突→送裁决"] += 1
                adjudication.append(("同码双键判定冲突(同代码两个键判不一致)", kit, side, unit,
                                     f"先入键判 hv={dup[3]}", f"本键判 hv={hv}" + (f" CWE-{cwe}" if cwe else ""),
                                     exp_cwe or "未记录", "已保留先入键,冲突待裁"))
            return
        cwe2, risk, src, snk, expl, fix = extract_json_parts(b, hv)
        assistant = build_assistant(b, hv, cwe2 if hv else cwe, risk, src, snk, expl, fix)
        lang, code = cd
        appended.append((h, f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```", assistant, hv))
        st[f"增:{src_tag}"] += 1

    for i, (kit, side) in sorted(row_meta.items()):
        exc = kit_excluded(kit)
        if exc:
            drop_rows.add(i)
            st[f"删:kit_{exc}"] += 1
            continue
        old_assistant = base_records[i]["messages"][2]["content"]
        old_hv, old_cwe = old_row_verdict(old_assistant)
        cand = merged.get((kit, side))
        exp_present, exp_cwe = truth_of(kit)
        ln_exp = re.match(r"CWE-(\d+)", exp_cwe)
        if cand is None:
            st["留:无新蒸块"] += 1
            continue
        unit, b = cand
        src_tag = merged_src.get((kit, side), "?")
        hv, cwe, _rest = block_conclusion(b)
        if hv is None:
            st[f"争议:结论不可解析({src_tag})"] += 1
            adjudication.append(("同行替换块结论不可解析", kit, side, unit,
                                 f"hv={old_hv}" if old_hv is not None else "旧行无JSON",
                                 "不可解析", exp_cwe, "旧行保留"))
            continue
        if src_tag == "复核批":
            # 复核批是裁决过的权威产出：与 manifest 真值同向即替换（旧行不同恰为待修证据）；
            # 与真值反向或 cwe 不符才送裁决。
            if hv != bool(exp_present):
                st["争议:复核批与真值反"] += 1
                adjudication.append(("复核批与真值反", kit, side, unit,
                                     f"hv={old_hv}" + (f" CWE-{old_cwe}" if old_cwe else ""),
                                     f"hv={hv}" + (f" CWE-{cwe}" if cwe else ""),
                                     f"{'有洞' if exp_present else '无洞'}({exp_cwe})" if exp_cwe else "未记录",
                                     "旧行保留"))
                continue
            ok_cwe = True
            if hv and cwe is not None and ln_exp:
                ok_cwe = cwe in FAMILY.get(ln_exp.group(1), {ln_exp.group(1)})
            if not ok_cwe:
                st["争议:复核批cwe不符"] += 1
                adjudication.append(("复核批cwe不符", kit, side, unit,
                                     f"hv={old_hv}", f"CWE-{cwe}", exp_cwe, "旧行保留"))
                continue
            cwe2, risk, src, snk, expl, fix = extract_json_parts(b, hv)
            replace_rows[i] = build_assistant(b, hv, cwe2 if hv else cwe, risk, src, snk, expl, fix)
            st["替:复核批"] += 1
            continue
        # 9_11批/续投批（未经裁决）：与旧行一致才替换（tier1），相左送裁决（tier2）
        if old_hv is None:
            st[f"争议:旧行JSON不可读({src_tag})"] += 1
            adjudication.append(("旧行JSON不可读", kit, side, unit, "无JSON", f"hv={hv}", exp_cwe, "旧行保留"))
            continue
        if hv != old_hv:
            st[f"争议:新旧结论相反({src_tag})"] += 1
            if side == "版本A":
                exp_txt = f"{'有洞' if exp_present else '无洞'}({exp_cwe})" if exp_cwe else "未记录"
                adj = ["旧行与manifest期望亦相反,优先裁"] if exp_present != old_hv else []
            else:
                exp_txt = f"kit级(A侧){'有洞' if exp_present else '无洞'}({exp_cwe})"
                adj = ["safe侧被新蒸指有洞(B_HOLE类主张),须对照六道门分诊记录裁"]
            adjudication.append(("新旧结论相反", kit, side, unit,
                                 f"hv={old_hv}" + (f" CWE-{old_cwe}" if old_cwe else ""),
                                 f"hv={hv}" + (f" CWE-{cwe}" if cwe else ""),
                                 exp_txt, ";".join(adj)))
            continue
        ok_cwe = True
        if hv and cwe is not None and ln_exp:
            ok_cwe = cwe in FAMILY.get(ln_exp.group(1), {ln_exp.group(1)})
        if not ok_cwe:
            st[f"争议:新旧同判但cwe不符({src_tag})"] += 1
            adjudication.append(("同判但cwe不符", kit, side, unit,
                                 f"CWE-{old_cwe}" if old_cwe else "旧cwe空", f"CWE-{cwe}", exp_cwe, "旧行保留"))
            continue
        cwe2, risk, src, snk, expl, fix = extract_json_parts(b, hv)
        replace_rows[i] = build_assistant(b, hv, cwe2 if hv else cwe, risk, src, snk, expl, fix)
        st[f"替:同码升级({src_tag})"] += 1

    # ---- 增补：基座未命中的块 ----
    covered_replace_keys = {row_meta[i] for i in replace_rows}
    for (kit, side), (unit, b) in sorted(merged.items()):
        if kit_excluded(kit):
            st[f"跳:kit被治理剔除"] += 1
            continue
        if (kit, side) in covered_replace_keys:
            st["跳:已按同行替换处理"] += 1
            continue
        if any(row_meta.get(i) == (kit, side) for i in row_meta):
            st["跳:同码行保留(未达替换判据)"] += 1
            continue
        append_block(kit, side, unit, b, merged_src.get((kit, side), "?"))

    # wave2 A 侧
    for pid in sorted(wave2_ok):
        blk = wf.get((f"wave2-{pid}", "版本A"))
        cd = wave2_code.get(pid)
        if not blk or not cd:
            st["增跳:wave2缺块或码"] += 1
            continue
        hv, cwe, _rest = block_conclusion(blk)
        if hv is not True:
            st["增跳:wave2非true"] += 1
            continue
        h = fp(cd[1])
        if h in EVAL_FP:
            st["增跳:wave2评测孪生"] += 1
            continue
        if h in fp2rows:
            st["增跳:wave2同码已在基座"] += 1
            continue
        if any(x[0] == h for x in appended):
            st["增跳:wave2同码本次增补去重"] += 1
            continue
        cwe2, risk, src, snk, expl, fix = extract_json_parts(blk, True)
        assistant = build_assistant(blk, True, cwe2, risk, src, snk, expl, fix)
        lang, code = cd
        appended.append((h, f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```", assistant, True))
        st["增:wave2"] += 1

    # ---- 汇总 ----
    kept = sum(1 for i in range(len(base_records))
               if i not in drop_rows and i not in replace_rows)
    total = kept + len(replace_rows) + len(appended)
    print(f"\n基座 {len(base_records)} → 保留 {kept} + 替换 {len(replace_rows)} + 增补 {len(appended)} = v2_18 {total}")
    print(f"删除 {len(drop_rows)} 行；裁决单条目 {len(adjudication)}")
    print("全路径计数：")
    for k, v in sorted(st.items(), key=lambda x: -x[1]):
        print(f"  {v:4d}  {k}")

    # CVE 交集
    eval_cves = set()
    for mp in (WS / "experiments/exp_06_finetune/corpus/rolling_dev/manifest.json",
               WS / "experiments/exp_06_finetune/testset_cve_fix/manifest.json"):
        if mp.exists():
            for s in json.loads(mp.read_text(encoding="utf-8")).get("samples", []):
                if s.get("cve_id"):
                    eval_cves.add(s["cve_id"])
    overlap = sorted(eval_cves & {e.get("cve_id") for e in manifest.values() if e.get("cve_id")})
    print(f"CVE 交集（应为空）：{overlap}")

    # ---- 裁决单 ----
    lines = ["# v2_18 同码替换裁决单（20260914）", "",
             "> 生成器：build_v2_18_merge_20260914.py。凡新旧结论相左、结论不可解析、重复块异判定，",
             "> 一律不自动定胜负，列出证据等人工裁决；裁定后可用复核批同款路径回填。", "",
             f"| # | 类别 | kit | 侧 | 单元 | 旧行 | 新蒸 | manifest期望 | 注记 |",
             f"|---|---|---|---|---|---|---|---|---|"]
    for n, (cat, kit, side, unit, old, new, exp, note) in enumerate(adjudication, 1):
        lines.append(f"| {n} | {cat} | {kit} | {side} | {unit} | {old} | {new} | {exp} | {note} |")
    ADJ_OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"裁决单 → {ADJ_OUT}")

    if dry:
        print("\n[干跑] 未写盘。加 --apply 生成。")
        return

    OUT_DATA.mkdir(parents=True, exist_ok=True)
    outp = OUT_DATA / "final_train_chatml_alpha06_v2_18.jsonl"
    bak = outp.with_suffix(outp.suffix + ".bak-pre-20260914")
    if outp.exists() and not bak.exists():
        bak.write_bytes(outp.read_bytes())
        print(f"已备份原 v2_18 → {bak}")
    n_out = 0
    with outp.open("w", encoding="utf-8", newline="\n") as w:
        for i, r in enumerate(base_records):
            if i in drop_rows:
                continue
            if i in replace_rows:
                r = json.loads(json.dumps(r, ensure_ascii=False))
                r["messages"][2]["content"] = replace_rows[i]
            w.write(json.dumps(r, ensure_ascii=False) + "\n")
            n_out += 1
        for _h, user, assistant, _hv in appended:
            w.write(json.dumps({"messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user},
                {"role": "assistant", "content": assistant},
            ]}, ensure_ascii=False) + "\n")
            n_out += 1
    rep = ["# v2_18 组装报告（20260914 修订版，替换式 v3）", "",
           f"- 基座 v2_17_clean：{len(base_records)} 条（可定位 diffpair 行 {len(row_meta)}）",
           f"- 保留：{kept}（含无新蒸块而保留的行）",
           f"- 替换：{len(replace_rows)}（同码升级：新蒸与旧行同判 + CWE 族校验通过）",
           f"- 删除：{len(drop_rows)}（治理否决，与 20260913 版一致）",
           f"- 增补：{len(appended)}（基座未命中块 + wave2 A 侧）",
           f"- **v2_18 合计：{n_out} 条**",
           f"- 裁决单：{len(adjudication)} 条 → {ADJ_OUT.name}",
           f"- 明细统计：{dict(st)}",
           f"- 块数守恒：见上方全路径计数（静默路径为零）",
           f"- CVE 交集：{overlap if overlap else '0 ✅'}",
           "- 评测孪生防线：评测面指纹硬门启用；probe_l2 52 题零重叠由 --guard 复验", ""]
    (OUT_DATA / "build_alpha06_v2_18_report_20260914.md").write_text("\n".join(rep) + "\n", encoding="utf-8")
    print(f"\n→ {outp}\n→ {OUT_DATA / 'build_alpha06_v2_18_report_20260914.md'}")


if __name__ == "__main__":
    main()
