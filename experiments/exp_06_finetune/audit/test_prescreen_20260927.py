# -*- coding: utf-8 -*-
"""§1.1 预筛修复的针对性验证（2026-09-27，离线无 LLM）。

覆盖四点：① 正分块不足 k 时零分块均匀回填；② 全零分等距全文件覆盖（首尾必含、
槽位 3k、预算兜底）；③ 词表补盲（Java 反射/Go NewRequest/exec.Command/__reduce__）；
④ recheck_prescreen_zero_cov 监控打点。
"""
import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from graduation_project.two_stage_scanner import TwoStageScanner, _MONITOR
from graduation_project.code_slicer import CodeSlicer

ts = TwoStageScanner.__new__(TwoStageScanner)
ts._slicer = CodeSlicer(min_lines=150)
ts.num_ctx = 16384  # wave8 生产组态


def make_file(n_funcs, lines_per, sink_at=None):
    parts = []
    for i in range(n_funcs):
        ls = [f"def func_{i}(payload, cfg):"]
        for j in range(lines_per - 3):
            ls.append(f"    v{i}_{j} = payload + cfg * {j}")
        if i == sink_at:
            ls.append("    cursor.execute('SELECT * FROM t WHERE id=' + payload)")
        ls.append(f"    return v{i}_0")
        parts.append("\n".join(ls))
    return "\n\n".join(parts)


# ---- Case 1：单正分块 + 其余零分 → 回填到 k=3（旧实现只送 1 块，corpus_00066 形态）
code1 = make_file(24, 40, sink_at=20)
picked, info = ts._prescreen_chunks(code1, "python")
print(f"case1 coverage={info.get('coverage')} picked={len(info.get('picked', []))} "
      f"scores={info.get('picked_scores')} zero_ratio={info.get('zero_ratio')}")
assert len(info["picked"]) == 3, info["picked"]
assert info["picked_scores"][0] > 0 and info["picked_scores"].count(0) == 2
assert info["coverage"] == "positive_plus_backfill"

# ---- Case 2：全零分 → 等距覆盖（首尾必含 + 槽位 3k + 预算兜底）
code2 = make_file(24, 40)
picked, info = ts._prescreen_chunks(code2, "python")
spans = [(p["start"], p["end"]) for p in info["picked"]]
n_lines = len(code2.split("\n"))
print(f"case2 coverage={info.get('coverage')} zero_ratio={info.get('zero_ratio')} "
      f"picked={len(spans)} spans={spans} (总行 {n_lines})")
assert info["coverage"] == "full"
assert len(spans) >= 3
assert spans[0][0] <= 200, f"首块未覆盖文件头部：{spans}"
assert spans[-1][1] >= n_lines - 150, f"末块未覆盖文件尾部：{spans}"
assert info["zero_ratio"] == 1.0

# ---- Case 3：真实 A′ 样本（rolling_dev 确定性漏报三例）覆盖回归
base = r"experiments/exp_06_finetune/corpus/rolling_dev"
for name, lang, cwe, flag in [
    ("corpus_00005.java", "java", "CWE-862", {(100, 104), (120, 139), (155, 160)}),
    ("corpus_00066.go", "go", "CWE-77", None),
    ("corpus_00080.py", "python", "CWE-94", None),
]:
    code = open(f"{base}/{name}", encoding="utf-8", errors="replace").read()
    picked, info = ts._prescreen_chunks(code, lang)
    spans = [(p["start"], p["end"]) for p in info["picked"]]
    cov = sum(e - s + 1 for s, e in spans)
    n = len(code.split("\n"))
    line = f"case3 {name} [{cwe}] coverage={info['coverage']} picked={len(spans)} 覆盖率 {100*cov/n:.0f}%"
    if flag:
        hit = sum(1 for fs, fe in flag if any(s <= fe and e >= fs for s, e in spans))
        assert hit == len(flag), f"{name} 调研标记区命中 {hit}/{len(flag)}"
        line += f" 标记区命中 {hit}/{len(flag)}"
    print(line)
    assert info["coverage"] in ("full", "positive_plus_backfill")

# ---- Case 4：词表补盲
for snippet, tag in [
    ("MethodHandles.lookup().findStatic(cls, \"run\", mt).invoke(p);", "java反射"),
    ("req, err := http.NewRequestWithContext(ctx, \"GET\", userURL, nil)", "go新请求"),
    ("cls.__reduce__ = lambda self: (os.system, (cmd,))", "py pickle链"),
    ("exec.Command(\"git\", \"clone\", repo)", "go命令执行"),
]:
    assert TwoStageScanner._PRESCREEN_SINK_RE.search(snippet), tag
print("case4 词表补盲 4/4 命中")

# ---- Case 5：监控打点
before = _MONITOR["recheck_prescreen_zero_cov"]
ts._prescreen_chunks(code2, "python")
assert _MONITOR["recheck_prescreen_zero_cov"] == before + 1, "监控计数未生效"
print("case5 recheck_prescreen_zero_cov 打点生效")

print("\n== §1.1 预筛修复验证：全部通过 ==")
