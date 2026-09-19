# -*- coding: utf-8 -*-
"""
实测门扩展 L0 普测（2026-09-10）：v2_17 全库 python / go / javascript 三语言。
oracle 沿用 实测门_优先队列_L0_20260909.py 口径：
  python  : py_compile + 隔离运行(python -I, 10s, stdin=DEVNULL)
  go      : go build（未用 import 自动剥离重试一次；GOPROXY=off 防联网）
  js      : node --check（仅语法层）
安全护栏（本次新增）：
  python 运行前过"危险载荷防护"正则（绝对路径删除/系统命令破坏类）→ 跳过运行只做编译，
  记 SKIPPED_危险载荷防护。护栏只用于执行安全，不影响标签判读。
产出：audit/实测门_扩展L0_py_go_js_20260910.jsonl + 汇总交叉表。
只读数据集，不改任何样本。
"""
import json, re, sys, os, subprocess, tempfile, collections
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[1]
V17 = BASE / "data/final_train_chatml_alpha06_v2_17.jsonl"
OUT = BASE / "audit/实测门_扩展L0_py_go_js_20260910.jsonl"
PYEXE = sys.executable
NODE = r"C:/Users/zane/.workbuddy/binaries/node/versions/22.22.2-2/node.exe"
GO = r"D:/tools/go/bin/go.exe"
RUN_TIMEOUT = 10

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
    return {"py": "python", "node": "javascript", "ts": "javascript", "typescript": "javascript",
            "golang": "go", "node.js": "javascript"}.get(first, first)


DANGER = [
    r"(shutil\.rmtree|os\.remove|os\.unlink|os\.rmdir)\s*\(\s*['\"]\s*(?:[A-Za-z]:[\\/]|/(?:etc|usr|var|bin|sbin|lib|home|root)|~)",
    r"(rm\s+-rf\s+(?:/|[A-Za-z]:[\\/]|~|/etc|/usr|/var))",
    r"(del\s+/[sfq]\s+(?:/q\s+)?[\"']?[A-Za-z]:[\\/])",
    r"(format\s+[A-Za-z]:|mkfs(\.\w+)?\s|shutdown\s+[-rs]|dd\s+if=.*of=/dev/[sh]d)",
    r"(Remove-Item\s+.*-Recurse\s+.*[A-Za-z]:\\)",
    r"(os\.system|subprocess\.\w+)\s*\(\s*['\"][^'\"]*(rm\s+-rf\s+/|del\s+/[sf]|format\s+[A-Za-z]:|shutdown|mkfs)",
]


def danger_hit(code):
    for pat in DANGER:
        if re.search(pat, code, re.I):
            return pat
    return None


def run(cmd, cwd, timeout=RUN_TIMEOUT):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, errors="replace",
                           timeout=timeout, stdin=subprocess.DEVNULL)
        return p.returncode, (p.stderr or "")
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""
    except Exception as e:
        return "ERR", str(e)[:120]


def l0(lang, code, td):
    if lang == "python":
        guard = danger_hit(code)
        f = td / "s.py"
        f.write_text(code, encoding="utf-8", errors="replace")
        rc, err = run([PYEXE, "-m", "py_compile", f.name], td, 30)
        if rc != 0:
            return "COMPILE_FAIL", err.splitlines()[:2]
        if guard:
            return "SKIPPED_危险载荷防护", guard
        rc2, err2 = run([PYEXE, "-I", f.name], td)
        if rc2 == "TIMEOUT":
            return "运行超时(常驻)", ""
        if rc2 == 3221225477:
            return "硬崩溃_访问违例", ""
        if rc2 == 3221226356:
            return "硬崩溃_栈溢出", ""
        return f"RC={rc2}", err2.splitlines()[:2]
    if lang == "go":
        env = dict(os.environ, GOPROXY="off")
        code2 = code
        f = td / "main.go"
        f.write_text(code2, encoding="utf-8", errors="replace")
        try:
            p = subprocess.run([GO, "build", "-o", "a.exe", "main.go"], cwd=td, capture_output=True,
                               text=True, errors="replace", timeout=60, env=env,
                               stdin=subprocess.DEVNULL)
            rc, err = p.returncode, p.stderr or ""
        except subprocess.TimeoutExpired:
            return "BUILD_TIMEOUT", ""
        if rc != 0 and "imported and not used" in err:
            code2 = re.sub(r'^\t*"[^"]+"\n', "", code, flags=re.M)
            f.write_text(code2, encoding="utf-8", errors="replace")
            try:
                p = subprocess.run([GO, "build", "-o", "a.exe", "main.go"], cwd=td, capture_output=True,
                                   text=True, errors="replace", timeout=60, env=env,
                                   stdin=subprocess.DEVNULL)
                rc, err = p.returncode, p.stderr or ""
            except subprocess.TimeoutExpired:
                return "BUILD_TIMEOUT", ""
        if rc != 0:
            return "COMPILE_FAIL", [x for x in err.splitlines() if "error" in x.lower()][:2] or err.splitlines()[:2]
        return "COMPILE_OK", ""
    if lang == "javascript":
        f = td / "s.js"
        f.write_text(code, encoding="utf-8", errors="replace")
        rc, err = run([NODE, "--check", f.name], td, 20)
        return ("SYNTAX_OK", "") if rc == 0 else ("SYNTAX_FAIL", err.splitlines()[:2])
    return "SKIP_无oracle", ""


rows = [json.loads(l) for l in V17.open(encoding="utf-8") if l.strip()]
queue = []
for i, r in enumerate(rows, 1):
    lang = lang_of(gu(r))
    if lang in ("python", "go", "javascript"):
        queue.append((i, lang))
print(f"v2_17 共 {len(rows)} 行；本次 L0 队列 = {len(queue)} "
      f"({dict(collections.Counter(l for _, l in queue))})")

out = []
RUNDIR = BASE / "audit" / "_l0_tmp_20260910"
RUNDIR.mkdir(exist_ok=True)  # 单目录复用+覆盖写，全程零删除（安全钩子会拦批量 unlink）
for n, (idx, lang) in enumerate(queue, 1):
    r = rows[idx - 1]
    u = gu(r)
    code = code_of(u)
    v = verd(ga(r))
    o = {"line_v17": idx, "lang": lang, "label": list(v) if v else None}
    if not code.strip():
        o["l0"] = "SKIP_无代码"
    else:
        o["l0"], o["detail"] = l0(lang, code, RUNDIR)
    out.append(o)
    if n % 50 == 0 or n == len(queue):
        cc = collections.Counter(x["l0"].split("_")[0] for x in out)
        print(f"  进度 {n}/{len(queue)} | {dict(cc)}", flush=True)
        with OUT.open("w", encoding="utf-8") as f:
            for x in out:
                f.write(json.dumps(x, ensure_ascii=False) + "\n")

with OUT.open("w", encoding="utf-8") as f:
    for x in out:
        f.write(json.dumps(x, ensure_ascii=False) + "\n")

# 汇总：标签 × 结果
cross = collections.defaultdict(collections.Counter)
for x in out:
    lab = x["label"]
    hv = bool(lab and lab[0])
    cross[("vuln" if hv else "safe")][x["l0"]] += 1
print("\n=== 汇总：标签 × L0 结果 ===")
for lab, c in sorted(cross.items()):
    print(lab, dict(c.most_common(12)))
print(f"\n落盘: {OUT}")
