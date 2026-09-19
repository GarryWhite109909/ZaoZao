# -*- coding: utf-8 -*-
"""
实测门优先队列 L0（2026-09-09 晚）

队列 = 37 条 FLIP（重投要翻转 has_vuln，扣下未落）∪ 15 条双模型判定冲突行，去重。
L0 oracle 按语言：
  c/cpp   : gcc 编译 + 运行(10s) → 记录硬崩溃(0xC0000005/0xC00000FD)
  python  : py_compile + 隔离运行(10s)
  go      : go build（未用 import 自动剥离重试一次）
  javascript: node --check（仅语法层；服务型行为留给 L1）
  php     : php -l
  其他    : 跳过（无本地 oracle）
输出：实测门_优先队列_L0_20260909.jsonl + 控制台交叉表（FLIP 方向 × L0 结果）
"""
import json, re, sys, os, subprocess, tempfile, collections
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_16.jsonl"
WAVE = BASE / "corpus/redistill_wave"
OUT = BASE / "audit/实测门_优先队列_L0_20260909.jsonl"
GCC = "gcc"
NODE = "node"
GO = r"D:/tools/go/bin/go.exe"
PHP = r"D:/tools/php/php.exe"

rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
ga = lambda r: [m["content"] for m in r["messages"] if m["role"] == "assistant"][-1]


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


FLAGS = {}
for l in (WAVE / "verify_report.jsonl").open(encoding="utf-8"):
    r = json.loads(l)
    if r.get("line"):
        FLAGS[r["line"]] = r.get("flags", [])
id2line = {}
for l in (WAVE / "verify_report.jsonl").open(encoding="utf-8"):
    r = json.loads(l)
    if r.get("id") and r.get("line"):
        id2line[r["id"]] = r["line"]
src = {}
for fn in ("glm5.3.jsonl", "qwen_flip.jsonl", "retake.jsonl"):
    for l in (WAVE / "parsed" / fn).open(encoding="utf-8"):
        o = json.loads(l)
        ln = o["id"].split("-")[-1]
        src.setdefault(int(ln), {})[fn.replace(".jsonl", "")] = o["fields"].get("has_vulnerability")

queue = set()
for ln, fl in FLAGS.items():
    if any(f.startswith("FLIP") for f in fl):
        queue.add(ln)
queue |= {ln for ln, v in src.items() if len(v) > 1 and len(set(v.values())) > 1}
queue = sorted(queue)


def lang_of(u):
    m = re.search(r"语言[:：]\s*([^\s）)，,]+)", u)
    l = (m.group(1) if m else "?").lower()
    return {"c++": "cpp", "c#": "csharp", "py": "python", "js": "javascript", "node": "javascript",
            "ts": "javascript", "typescript": "javascript", "golang": "go", "sh": "bash",
            "shell": "bash", "node.js": "javascript"}.get(re.split(r"[，,、/（(]", l)[0].strip(), l)


def run(cmd, cwd, timeout=10):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, errors="replace", timeout=timeout)
        return p.returncode, (p.stderr or "")[-400:]
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""
    except Exception as e:
        return "ERR", str(e)[:120]


def l0(lang, code, td):
    if lang in ("c", "cpp"):
        ext = ".cpp" if lang == "cpp" else ".c"
        f = td / f"s{ext}"
        f.write_text(code, encoding="utf-8", errors="replace")
        rc, err = run([GCC, "-fno-strict-overflow", "-O0", "-o", str(td / "a.exe"), f.name], td, 30)
        if rc != 0:
            return "COMPILE_FAIL", err.splitlines()[:2]
        if lang == "cpp" and rc != 0:
            pass
        rc2, _ = run([str(td / "a.exe")], td, 10)
        if rc2 in (3221225477,):
            return "硬崩溃_访问违例", ""
        if rc2 == 3221226356:
            return "硬崩溃_栈溢出", ""
        if rc2 == "TIMEOUT":
            return "运行超时(常驻)", ""
        return f"RC={rc2}", ""
    if lang == "python":
        f = td / "s.py"
        f.write_text(code, encoding="utf-8", errors="replace")
        rc, err = run([sys.executable, "-m", "py_compile", f.name], td, 20)
        if rc != 0:
            return "COMPILE_FAIL", err.splitlines()[:2]
        rc2, err2 = run([sys.executable, "-I", f.name], td, 10)
        if rc2 == "TIMEOUT":
            return "运行超时(常驻)", ""
        return f"RC={rc2}", err2.splitlines()[:2]
    if lang == "go":
        d = td / "go"
        d.mkdir(exist_ok=True)
        code2 = code
        f = d / "main.go"
        f.write_text(code2, encoding="utf-8", errors="replace")
        rc, err = run([GO, "build", "-o", "a.exe", "main.go"], d, 60)
        if rc != 0 and "imported and not used" in err:
            code2 = re.sub(r'^\t*"[^"]+"\n', "", code, flags=re.M)
            f.write_text(code2, encoding="utf-8", errors="replace")
            rc, err = run([GO, "build", "-o", "a.exe", "main.go"], d, 60)
        if rc != 0:
            return "COMPILE_FAIL", [x for x in err.splitlines() if "error" in x.lower()][:2] or err.splitlines()[:2]
        return "COMPILE_OK", ""
    if lang == "javascript":
        f = td / "s.js"
        f.write_text(code, encoding="utf-8", errors="replace")
        rc, err = run([NODE, "--check", f.name], td, 20)
        return ("SYNTAX_OK", "") if rc == 0 else ("SYNTAX_FAIL", err.splitlines()[:2])
    if lang == "php":
        f = td / "s.php"
        f.write_text("<?php\n" + code if "<?php" not in code else code, encoding="utf-8", errors="replace")
        rc, err = run([PHP, "-l", f.name], td, 20)
        return ("LINT_OK", "") if rc == 0 else ("LINT_FAIL", err.splitlines()[:2])
    return "SKIP_无oracle", ""


out = []
for ln in queue:
    r = rows[ln - 1]
    u = [m["content"] for m in r["messages"] if m["role"] == "user"][0]
    lang = lang_of(u)
    fs = re.findall(r"```[A-Za-z0-9_+\-]*\n(.*?)```", u, re.S)
    code = max(fs, key=len) if fs else ""
    glm = (src.get(ln) or {}).get("glm5.3")
    qwen = (src.get(ln) or {}).get("qwen_flip")
    v16 = verd(ga(r))
    o = {"line": ln, "lang": lang, "v2_16_now": list(v16) if v16 else None,
         "glm": glm, "qwen": qwen,
         "flip_flag": next((f for f in FLAGS.get(ln, []) if f.startswith("FLIP")), "")}
    if not code:
        o["l0"] = "SKIP_无代码"
    else:
        with tempfile.TemporaryDirectory() as t:
            o["l0"], o["l0_detail"] = l0(lang, code, Path(t))
    out.append(o)
    print(f"  行{ln:>5} {lang:<10} 现={str(o['v2_16_now'][0]) if o['v2_16_now'] else '?':<5} "
          f"glm={str(glm):<5} qwen={str(qwen):<5} L0={o['l0']}")

with OUT.open("w", encoding="utf-8") as f:
    for o in out:
        f.write(json.dumps(o, ensure_ascii=False) + "\n")
print()
print("队列:", len(out), "| 语言:", dict(collections.Counter(o["lang"] for o in out)))
print("L0 结果:", dict(collections.Counter(o["l0"].split("_")[0] for o in out)))
