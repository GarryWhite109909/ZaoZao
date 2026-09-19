# -*- coding: utf-8 -*-
"""
配置族全量审计（2026-09-10）
v2_17 全库 bash/dockerfile/yaml 三族 → shellcheck / hadolint / checkov(k8s+compose) 全量。
oracle 定位：
  shellcheck : D:/tools/bin/shellcheck.exe -f json
  hadolint   : D:/tools/bin/hadolint.exe -f json（只吃 Windows 路径）
  checkov    : D:/miniconda/python.exe run_checkov.py（批量目录模式，临时目录必须在 D: 盘，
               否则 os.path.relpath 跨盘符 ValueError；-f 单文件模式无效，文件名需 Dockerfile*）
产出：
  audit/实测门_配置族全量_20260910.jsonl   每行一条
  audit/实测门_配置族全量_20260910_汇总.md
只读数据集，不改任何样本。
"""
import json, re, sys, os, shutil, subprocess, collections
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[1]
V17 = BASE / "data/final_train_chatml_alpha06_v2_17.jsonl"
OUTJ = BASE / "audit/实测门_配置族全量_20260910.jsonl"
OUTM = BASE / "audit/实测门_配置族全量_20260910_汇总.md"
SHELLCHECK = r"D:/tools/bin/shellcheck.exe"
HADOLINT = r"D:/tools/bin/hadolint.exe"
CHECKOV = [r"D:/miniconda/python.exe", str(BASE / "audit/实测门_配置族/run_checkov.py")]
TMPROOT = Path(os.path.abspath(str(BASE / "audit/实测门_配置族/_tmp_full_20260910")))

ga = lambda r: [m["content"] for m in r["messages"] if m["role"] == "assistant"][-1]
gu = lambda r: [m["content"] for m in r["messages"] if m["role"] == "user"][0]


def code_of(u):
    fs = re.findall(r"```[A-Za-z0-9_+\-]*\n(.*?)```", u, re.S)
    return max(fs, key=len) if fs else ""


def verd(a):
    m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
    if not m:
        return None
    v = json.loads(m.group(1))
    hv = v.get("has_vulnerability")
    if isinstance(hv, str):
        hv = hv.strip().lower() == "true"
    c = re.search(r"CWE-(\d+)", str(v.get("vulnerability_type") or ""))
    return (hv, "CWE-" + c.group(1) if c else "")


def lang_of(u):
    m = re.search(r"语言[:：]\s*([^\s）)，,]+)", u)
    l = (m.group(1) if m else "?").lower()
    first = re.split(r"[，,、/（(]", l)[0].strip()
    return {"sh": "bash", "shell": "bash", "zsh": "bash"}.get(first, first)


rows = [json.loads(l) for l in V17.open(encoding="utf-8") if l.strip()]
print(f"v2_17 共 {len(rows)} 行")

fam = collections.defaultdict(list)  # fam -> [(idx1based, code)]
for i, r in enumerate(rows, 1):
    lang = lang_of(gu(r))
    code = code_of(gu(r))
    if not code.strip():
        continue
    if lang == "bash":
        fam["bash"].append((i, code))
    elif lang == "dockerfile":
        fam["dockerfile"].append((i, code))
    elif lang == "yaml":
        fam["yaml"].append((i, code))
for k, v in fam.items():
    print(f"  {k}: {len(v)}")

results = {}  # idx -> {"bash":[...], "dockerfile_hadolint":..., "dockerfile_checkov":[...], "yaml_checkov":[...]}


def run(cmd, timeout=120):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT", "", ""
    except Exception as e:
        return "ERR", "", str(e)[:150]


# ---------- shellcheck（bash，逐文件，快） ----------
if fam.get("bash"):
    td = TMPROOT / "bash"
    td.mkdir(parents=True, exist_ok=True)
    for n, (idx, code) in enumerate(fam["bash"]):
        f = td / f"s{idx}.sh"
        f.write_text(code, encoding="utf-8", errors="replace")
        rc, out, err = run([SHELLCHECK, "-f", "json", str(f)])
        items = []
        if out.strip():
            try:
                j = json.loads(out)
                items = [{"line": x.get("line"), "level": x.get("level"),
                          "code": f"SC{x.get('code')}", "msg": (x.get("message") or "")[:160]} for x in j]
            except Exception:
                items = [{"parse_error": True}]
        elif rc == "TIMEOUT" or rc == "ERR":
            items = [{"error": str(rc)}]
        results.setdefault(idx, {})["shellcheck"] = items
        # 不逐文件删除：安全钩子会拦截批量 unlink；临时文件累积，结束后统一人工清理
        if (n + 1) % 100 == 0:
            print(f"  shellcheck {n+1}/{len(fam['bash'])}")
    print(f"shellcheck 完成 {len(fam['bash'])}")

# ---------- hadolint（dockerfile，逐文件，快） ----------
if fam.get("dockerfile"):
    td = TMPROOT / "df"
    td.mkdir(parents=True, exist_ok=True)
    for n, (idx, code) in enumerate(fam["dockerfile"]):
        f = td / f"Dockerfile.s{idx}"
        f.write_text(code, encoding="utf-8", errors="replace")
        rc, out, err = run([HADOLINT, "-f", "json", str(f)])
        items = []
        if out.strip():
            try:
                j = json.loads(out)
                items = [{"line": x.get("line"), "level": x.get("level"),
                          "code": x.get("code"), "msg": (x.get("message") or "")[:160]} for x in j]
            except Exception:
                items = [{"parse_error": True}]
        elif rc == "TIMEOUT" or rc == "ERR":
            items = [{"error": str(rc)}]
        results.setdefault(idx, {})["hadolint"] = items
        # 不逐文件删除（安全钩子会拦截批量 unlink）；临时文件累积，结束后统一人工清理
        if (n + 1) % 100 == 0:
            print(f"  hadolint {n+1}/{len(fam['dockerfile'])}")
    print(f"hadolint 完成 {len(fam['dockerfile'])}")


# ---------- checkov（批量目录模式） ----------
def parse_checkov(out):
    dec = json.JSONDecoder()
    pos, failed, passed, perr = 0, {}, {}, []
    while pos < len(out):
        while pos < len(out) and out[pos] not in "[{":
            pos += 1
        if pos >= len(out):
            break
        try:
            obj, end = dec.raw_decode(out, pos)
            pos = end
            if isinstance(obj, dict) and "results" in obj:
                for e in obj["results"].get("failed_checks") or []:
                    fp = e.get("file_path") or e.get("repo_file_path") or e.get("file") or "?"
                    failed.setdefault(fp, []).append(
                        {"check": e.get("check_id"), "name": (e.get("check_name") or "")[:80],
                         "line": e.get("file_line_range") or e.get("resource")})
                for e in obj["results"].get("passed_checks") or []:
                    fp = e.get("file_path") or e.get("repo_file_path") or e.get("file") or "?"
                    passed.setdefault(fp, []).append(e.get("check_id"))
                perr += obj["results"].get("parsing_errors") or []
        except Exception:
            pos += 1
    return failed, passed, perr


def batch_checkov(samples, framework, tag, batch=120):
    """samples: [(idx, code)]；文件命名按 framework 要求。返回 idx->failed 列表。"""
    res = {}
    td = TMPROOT / f"ck_{tag}"
    td.mkdir(parents=True, exist_ok=True)
    for start in range(0, len(samples), batch):
        chunk = samples[start:start + batch]
        for idx, code in chunk:
            nm = f"Dockerfile.s{idx}" if framework == "dockerfile" else f"s{idx}.yaml"
            (td / nm).write_text(code, encoding="utf-8", errors="replace")
        rc, out, err = run(CHECKOV + ["--framework", framework, "-d", str(td), "--output", "json"], 900)
        failed, passed, perr = parse_checkov(out)
        for idx, code in chunk:
            nm = f"Dockerfile.s{idx}" if framework == "dockerfile" else f"s{idx}.yaml"
            # checkov file_path 形如 /Dockerfile.s123（相对扫描目录）；多形态候选逐一匹配
            key = None
            for cand in (nm, "/" + nm, str(td / nm), f".\\{nm}", f"./{nm}"):
                if cand in failed or cand in passed:
                    key = cand
                    break
            if key is None:
                # 兜底：按文件名尾部匹配
                for k in list(failed) + list(passed):
                    if k.replace("\\", "/").endswith(nm):
                        key = k
                        break
            res[idx] = {
                "failed": failed.get(key, []) if key else [],
                "passed_n": len(passed.get(key, [])) if key else 0,
                "scanned": key is not None,
                "parsing_error": key is None,
            }
        # 不清理批次文件：同目录累积即可（不触发删除钩子）
        print(f"  checkov[{framework}] 批次 {start//batch+1}/{(len(samples)+batch-1)//batch} 完成")
    return res


if fam.get("dockerfile"):
    print("checkov dockerfile 批量扫描…")
    res = batch_checkov(fam["dockerfile"], "dockerfile", "df")
    for idx, v in res.items():
        results.setdefault(idx, {})["checkov_dockerfile"] = v
if fam.get("yaml"):
    print("checkov kubernetes 批量扫描…")
    res = batch_checkov(fam["yaml"], "kubernetes", "k8s")
    for idx, v in res.items():
        results.setdefault(idx, {})["checkov_k8s"] = v
    print("checkov docker_compose 批量扫描…")
    res = batch_checkov(fam["yaml"], "docker_compose", "comp")
    for idx, v in res.items():
        results.setdefault(idx, {})["checkov_compose"] = v

# ---------- 落盘 + 汇总 ----------
with OUTJ.open("w", encoding="utf-8") as f:
    for idx in sorted(results):
        v17v = verd(ga(rows[idx - 1]))
        rec = {"line_v17": idx, "label": list(v17v) if v17v else None, "tools": results[idx]}
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

def cnt(items):
    """信号级发现数：shellcheck/hadolint 只算 error/warning，style/info 是噪声。"""
    if not isinstance(items, list):
        return 0
    n = 0
    for x in items:
        if not isinstance(x, dict):
            continue
        lv = x.get("level")
        if lv in ("error", "warning") or lv is None:
            n += 1
    return n

stat = collections.defaultdict(lambda: collections.Counter())
for idx, tools in results.items():
    lab = verd(ga(rows[idx - 1]))
    hv = bool(lab and lab[0])
    for t, v in tools.items():
        if isinstance(v, dict):
            stat[t]["scan" if v.get("scanned") else "unscanned"] += 1
            stat[t][f"{'vuln' if hv else 'safe'}_有发现" if v["failed"] else f"{'vuln' if hv else 'safe'}_零发现"] += 1
        else:
            stat[t][f"{'vuln' if hv else 'safe'}_有发现" if cnt(v) else f"{'vuln' if hv else 'safe'}_零发现"] += 1

lines = ["# 配置族全量审计汇总（2026-09-10）\n",
         f"数据源：v2_17（{len(rows)} 行）。bash→shellcheck；dockerfile→hadolint+checkov；yaml→checkov(k8s+compose)。\n",
         "\n## 标签 × 工具交叉\n",
         "| 工具 | vuln行有发现 | vuln行零发现 | safe行有发现 | safe行零发现 | 扫描失败 |",
         "|---|---|---|---|---|---|"]
for t in ("shellcheck", "hadolint", "checkov_dockerfile", "checkov_k8s", "checkov_compose"):
    c = stat.get(t)
    if not c:
        continue
    lines.append(f"| {t} | {c['vuln_有发现']} | {c['vuln_零发现']} | {c['safe_有发现']} | {c['safe_零发现']} | {c['unscanned']} |")
lines.append("\n> 判读纪律：静态工具召回低是已知属性（RealVuln 2026：Semgrep F3=17.7），"
             "vuln 行零发现≠错标；**safe 行有发现才是错标信号**，需逐条 L1 复核，不得机改。\n")
OUTM.write_text("\n".join(lines), encoding="utf-8")
print(f"\n落盘: {OUTJ}\n落盘: {OUTM}")
print("汇总表:")
print("\n".join(lines[5:]))
