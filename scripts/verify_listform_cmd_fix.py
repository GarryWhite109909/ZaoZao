#!/usr/bin/env python3
"""列表形式命令注入修复的回归验证（无模型，纯工具层/规则层）。

背景：2026-08-22 实测发现"列表形式 subprocess = 安全"的假设在四层生效，
导致 ["sh","-c",user] / find -exec / git --upload-pack 真注入被系统性拦截。
本次修复涉及 counterfactual（签名表）/ taint_tracker（召回）/ schema（安全白名单）
/ prompts（裁决提示词）。本脚本固化修复后的预期行为，防回归。

运行：PYTHONPATH=. python3 scripts/verify_listform_cmd_fix.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graduation_project.counterfactual import _DEFENSE_SIGNATURES
from graduation_project.schema import _detect_safe_pattern
from graduation_project.prompts import build_triage_prompt
from graduation_project.two_stage_scanner import (
    TwoStageScanner, ToolFinding, AdjudicationVerdict,
)

SIG = _DEFENSE_SIGNATURES["Command Injection"]

SH_C = ('import subprocess\n'
        'def deploy(cmd_from_request):\n'
        '    return subprocess.run(["sh", "-c", cmd_from_request], capture_output=True)\n')
SH_C_REQ = ('import subprocess\n'
            'from flask import request\n'
            'def deploy():\n'
            '    cmd = request.args.get("cmd")\n'
            '    return subprocess.run(["sh", "-c", cmd], capture_output=True)\n')
FIND_EXEC = ('import subprocess\n'
             'def clean(user_pat):\n'
             '    return subprocess.run(["find", "/data", "-name", user_pat,'
             ' "-exec", "rm", "{}", ";"])\n')
GIT_UPLOAD = ('import subprocess\n'
              'def fetch(tool, repo):\n'
              '    return subprocess.Popen(["git", "ls-remote", "--upload-pack", tool, repo])\n')
PY_C = ('import subprocess\n'
        'def run_code(code_str):\n'
        '    return subprocess.check_output(["python3", "-c", code_str])\n')
PING_SAFE = ('import subprocess\n'
             'from flask import request\n'
             'def ping():\n'
             '    host = request.args.get("host", "")\n'
             '    return subprocess.run(["ping", "-c", "1", host], capture_output=True)\n')
OS_SYSTEM_RAW = ('import os\n'
                 'def run(cmd_from_request):\n'
                 '    return os.system("ping -c 1 " + cmd_from_request)\n')
MULTILINE_LIST = ('import subprocess\n'
                  'def p(host):\n'
                  '    return subprocess.run([\n'
                  '        "ping", "-c", "1", host,\n'
                  '    ])\n')

passed, failed = 0, 0


def check(name, cond):
    global passed, failed
    status = "PASS" if cond else "FAIL"
    if cond:
        passed += 1
    else:
        failed += 1
    print(f"  [{status}] {name}")


print("=" * 72)
print("A) 防御签名表（_DEFENSE_SIGNATURES['Command Injection']）")
print("=" * 72)
check("安全 ping 列表形式仍是防御（匹配）", bool(SIG.search(PING_SAFE)))
check("多行安全列表形式仍是防御（匹配）", bool(SIG.search(MULTILINE_LIST)))
check("sh -c 列表注入不再视为防御（不匹配）", not SIG.search(SH_C))
check("find -exec 列表注入不再视为防御（不匹配）", not SIG.search(FIND_EXEC))
check("git --upload-pack 不再视为防御（不匹配）", not SIG.search(GIT_UPLOAD))
check("python -c 执行代码参数不再视为防御（不匹配）", not SIG.search(PY_C))
check("shlex.quote 防御仍匹配", bool(SIG.search("subprocess.run(shlex.quote(x), shell=True)"[:0] + 'x = shlex.quote(arg)')))
check("shell=False 仍匹配", bool(SIG.search("subprocess.run(cmd, shell=False)")))

print()
print("=" * 72)
print("B) 复核采信门（_recheck_type_plausible @ CWE-78）")
print("=" * 72)
ts = TwoStageScanner.__new__(TwoStageScanner)
check("sh -c 真注入可被采信（plausible=True）",
      TwoStageScanner._recheck_type_plausible(ts, SH_C, "python", "CWE-78 Command Injection")[0])
check("find -exec 真注入可被采信（plausible=True）",
      TwoStageScanner._recheck_type_plausible(ts, FIND_EXEC, "python", "CWE-78 Command Injection")[0])
ok_git, why_git = TwoStageScanner._recheck_type_plausible(
    ts, GIT_UPLOAD, "python", "CWE-78 Command Injection")
check("git --upload-pack 可被采信（plausible=True）", ok_git)
ok_ping, why_ping = TwoStageScanner._recheck_type_plausible(
    ts, PING_SAFE, "python", "CWE-78 Command Injection")
check(f"安全 ping 仍被拦截（plausible=False，理由含'已防御'）",
      (not ok_ping) and "已防御" in (why_ping or ""))
check("os.system 无防御拼接可被采信（plausible=True）",
      TwoStageScanner._recheck_type_plausible(ts, OS_SYSTEM_RAW, "python", "CWE-78 Command Injection")[0])

print()
print("=" * 72)
print("C) 召回层（_stage1_recall，生产配置全开）")
print("=" * 72)
from graduation_project.prompts import ALPHA05_PROMPT


def recall(code):
    scanner = TwoStageScanner(client=None, system_prompt=ALPHA05_PROMPT, n_samples=3)
    try:
        return TwoStageScanner._stage1_recall(scanner, code=code, language="python", filename="t.py")
    finally:
        scanner.unload()


sh_findings = recall(SH_C_REQ)
cats = sorted({f.category for f in sh_findings})
rules = [f.rule_id for f in sh_findings]
check(f"sh -c 注入获得候选（{rules}）", len(sh_findings) > 0)
check(f"sh -c 候选中包含高信任 taint 类告警（修复前被吞；实际类别: {','.join(cats)}）",
      "taint" in cats)
ping_findings = recall(PING_SAFE)
# 安全 ping：semgrep 泛规则可能命中（历史行为），但 taint_tracker 自身不应新增
check("安全 ping 不产生 taint_tracker 类别的新增告警",
      all(f.tool != "taint_tracker" for f in ping_findings))

print()
print("=" * 72)
print("D) 证据门（_evidence_gate_pass）")
print("=" * 72)


def gated_verdict(code, sink_line):
    v = AdjudicationVerdict(
        confirmed=True, confidence=0.9, votes_true=3, votes_false=0,
        votes_invalid=0, reasoning="test", fix_suggestion="",
        finding={"rule_id": "B603", "taint_type": "B603", "source": "req arg",
                 "sink": "subprocess.run", "source_line": sink_line,
                 "sink_line": sink_line, "severity": "high"},
    )
    v.evidence_gate = None
    ts_full = TwoStageScanner.__new__(TwoStageScanner)
    lines = code.splitlines()
    # 直接调用内部逻辑：手工复刻 gate 对单条 verdict 的处理
    from graduation_project.counterfactual import _DEFENSE_SIGNATURES as DS
    sig = DS.get(TwoStageScanner._infer_taint_type(v.finding))
    lo = max(0, sink_line - 1 - 4)
    hi = min(len(lines), sink_line - 1 + 4)
    return bool(sig and sig.search("\n".join(lines[lo:hi])))


check("sh -c 注入的判中不被'已防御'降权", not gated_verdict(SH_C, 3))
check("安全 ping 的判中会被'已防御'降权（FP 防线保留）", gated_verdict(PING_SAFE, 5))

print()
print("=" * 72)
print("E) schema 安全模式白名单")
print("=" * 72)
check("安全 ping + isalnum 校验仍识别为安全模式",
      _detect_safe_pattern(PING_SAFE.replace('request.args.get("host", "")',
                                             'request.args.get("host", "")\n    assert host.isalnum()'))
      == "subprocess_list_with_validation")
SH_C_ALNUM = SH_C.replace("cmd_from_request):", "cmd_from_request):\n    assert cmd_from_request.isalnum()")
check("sh -c 注入即使带 isalnum 校验也不得判为安全模式", _detect_safe_pattern(SH_C_ALNUM) is None)

print()
print("=" * 72)
print("F) 裁决提示词文本")
print("=" * 72)


class _F:
    rule_id = "B602"
    taint_type = "Command Injection"
    source = "request arg"
    sink = "subprocess.run"
    source_line = 3
    sink_line = 3
    severity = "high"
    category = "sast"
    path = []
    evidence = ""


tp = build_triage_prompt(_F(), PING_SAFE, "python", aligned=True)
check("提示词不再含'必为误报'绝对化表述", "必为误报" not in tp)
check("提示词包含'列表形式不等于安全'修正表述", "列表形式不等于安全" in tp)
check("提示词保留黑名单/正则非有效防御的否定面", "不是有效防御" in tp)

print()
print("=" * 72)
print(f"结果: {passed} 通过 / {failed} 失败")
print("=" * 72)
sys.exit(1 if failed else 0)
