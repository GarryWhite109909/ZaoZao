# -*- coding: utf-8 -*-
"""web_review FIX 应用工具。

子命令:
  show <id> [--code]      打印样本当前行号/语言/assistant 分析(--code 连 user 代码)
  patch <id> <spec.json>  按 spec 应用补丁: {"subs": [[old,new],...], "verify_code": [[行号,片段],...]}
                          - subs 在 assistant content 上做精确替换, 每个 old 必须恰好出现 1 次
                          - verify_code: 校验 user 代码块第 N 行包含片段(锚点核验, 可选)
  done <id>               在 changelog 标记完成

行号定位: result_id_map.json 的 v15_line, 经 wave1/wave2 两批删除偏移校正到当前文件。
所有写回均校验整行 JSON 可解析; changelog 落 audit/web_review/fix_changelog_20260902.jsonl。
"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
MAP = BASE / "audit/result_id_map.json"
CHANGELOG = BASE / "audit/web_review/fix_changelog_20260902.jsonl"
TOL = BASE / "audit/web_review/_result_tolparse_20260902.json"

# wave1: audit 空间删除行; wave2: post-wave1 空间删除行(apply 脚本"现第X条")
W1 = [6206, 7260, 7267, 7272, 7483, 7727, 7803, 8121, 8123, 8129]
W2 = [1676, 2512, 7200, 7203, 7216, 7223, 7230, 7246, 7396, 7752]

def audit_to_current(audit_line):
    """map 的 audit 空间 1-based 行号 -> 当前文件 1-based 行号。"""
    p1 = audit_line - sum(1 for d in W1 if d < audit_line)
    p2 = p1 - sum(1 for d in W2 if d < p1)
    return p2

_lines = None
def load_lines():
    global _lines
    if _lines is None:
        _lines = [l for l in DATA.read_text(encoding="utf-8").split("\n") if l.strip()]
    return _lines

def locate(wid):
    """返回 (当前 1-based 行号, rec)。"""
    ent = json.loads(MAP.read_text(encoding="utf-8"))[str(wid)]
    old_line = ent["v15_line"]
    if not old_line:
        raise SystemExit(f"id={wid} no_match in map")
    idx = audit_to_current(old_line) - 1
    lines = load_lines()
    if not (0 <= idx < len(lines)):
        raise SystemExit(f"id={wid} idx 越界: audit {old_line} -> idx {idx}")
    return idx + 1, json.loads(lines[idx])

def code_of(rec):
    return rec["messages"][1]["content"]

def asst_of(rec):
    return rec["messages"][2]["content"]

def main():
    cmd = sys.argv[1]
    wid = sys.argv[2]
    cur, rec = locate(wid)
    if cmd == "show":
        fd = rec.get("fix_distill") or {}
        print(f"id={wid} 当前行={cur}/{len(load_lines())} teacher={fd.get('teacher')}")
        if "--code" in sys.argv:
            print("=" * 30, "USER [CODE]", "=" * 30)
            print(code_of(rec))
        print("=" * 30, "ASSISTANT", "=" * 30)
        print(asst_of(rec))
    elif cmd == "grep":
        import re
        pat = re.compile(sys.argv[3])
        a = asst_of(rec)
        for i, ln in enumerate(a.split("\n"), 1):
            if pat.search(ln):
                print(f"[{i}] {ln}")
    elif cmd == "codegrep":
        import re
        pat = re.compile(sys.argv[3])
        for i, ln in enumerate(code_of(rec).split("\n"), 1):
            if pat.search(ln):
                print(f"[{i}] {ln}")
    elif cmd == "codelines":
        s, e = int(sys.argv[3]), int(sys.argv[4])
        for i, ln in enumerate(code_of(rec).split("\n"), 1):
            if s <= i <= e:
                print(f"{i}| {ln}")
    elif cmd == "patch":
        spec = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
        a = asst_of(rec)
        subs = spec.get("subs", [])
        for old, new in subs:
            n = a.count(old)
            if n != 1:
                raise SystemExit(f"id={wid} 替换源出现 {n} 次(须为1): {old[:80]!r}")
        for old, new in subs:
            a = a.replace(old, new)
        # 可选: 代码行锚点核验(按 [CODE] 围栏内行号, 与审计编号一致)
        if spec.get("verify_code"):
            codelines = code_of(rec).split("\n")
            for i, ln in enumerate(codelines):
                if ln.startswith("```"):
                    codelines = codelines[i + 1:]
                    break
            for lineno, frag in spec.get("verify_code", []):
                if not (0 < lineno <= len(codelines)) or frag not in codelines[lineno - 1]:
                    actual = codelines[lineno - 1] if 0 < lineno <= len(codelines) else "OOB"
                    raise SystemExit(f"id={wid} 代码锚点核验失败: 第{lineno}行应含 {frag!r}, 实为 {actual!r}")
        rec["messages"][2]["content"] = a
        load_lines()[cur - 1] = json.dumps(rec, ensure_ascii=False)
        DATA.write_text("\n".join(load_lines()), encoding="utf-8")
        with CHANGELOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"id": int(wid), "action": "FIX", "n_subs": len(subs),
                                "subs": subs}, ensure_ascii=False) + "\n")
        print(f"id={wid} 已应用 {len(subs)} 处替换 (行{cur})")
    else:
        raise SystemExit("未知子命令")

if __name__ == "__main__":
    main()
