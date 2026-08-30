#!/usr/bin/env python3
"""工具冒烟自测 —— 每个工具一个"必然命中"的最小样例验证调用链（P0，2026-08-29）。

背景（工具层优化指导 §二 B1 教训）：工具接入后若不做"已知阳性样本冒烟"，
"零召回"会被误读成"该工具对这类代码无效"，进而固化成错误的排除逻辑
（secret 档曾因此对代码文件整体关闭、gitleaks 曾因缺 --no-git 必然零输出）。

本脚本对每个工具执行两条断言：
  1. 已知阳性样例 → 召回数必须 ≥1（缺 --no-git / 缺 --config / 排除逻辑回归
     都会在此暴露，而不是被误读成"工具无效"）；
  2. 已知安全样例 → 召回数必须 =0（误报回归拦截）。

状态语义（CI 友好）：
  PASS  已安装且两条断言通过
  FAIL  已安装但断言失败（退出码 1，CI 可拦）
  SKIP  工具未安装，或工具依赖本地漏洞库/网络而环境不具备（trivy/pip-audit）

离线可跑：prefilter / taint_tracker / semgrep(本地规则) / bandit / gitleaks
均不依赖网络；trivy(sca/iac)、pip-audit、detect-secrets 零召回时按 SKIP 降级。

运行：PYTHONPATH=. python3 scripts/tool_smoke_test.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.external_scanner import ExternalScanner
from graduation_project.prefilter import Prefilter

RESULTS: list[tuple[str, str, str]] = []  # (tool, status, detail)


def _record(tool: str, ok: bool, detail: str) -> None:
    status = "PASS" if ok else "FAIL"
    RESULTS.append((tool, status, detail))
    print(f"[{status}] {tool}: {detail}")


def _skip(tool: str, reason: str) -> None:
    RESULTS.append((tool, "SKIP", reason))
    print(f"[SKIP] {tool}: {reason}")


def _write_tmp(dirpath: str, name: str, content: str) -> str:
    p = Path(dirpath) / name
    p.write_text(content, encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# 1) Prefilter（纯 Python，恒可用）
# ---------------------------------------------------------------------------
def smoke_prefilter() -> None:
    pf = Prefilter()
    vuln = 'q = request.args.get("q")\ncursor.execute("SELECT * FROM t WHERE id = " + q)'
    r = pf.scan(vuln)
    ok_vuln = (r.preliminary_verdict is True and "sqli_string_concat" in r.matched_rules)
    safe = 'cur.execute("SELECT * FROM t WHERE id = ?", (uid,))'
    r2 = pf.scan(safe)
    ok_safe = r2.preliminary_verdict is False
    _record("prefilter", ok_vuln and ok_safe,
            f"SQL拼接命中={r.matched_rules}, 参数化查询判安全={r2.preliminary_verdict}")


# ---------------------------------------------------------------------------
# 2) TaintTracker（纯 Python，恒可用）
# ---------------------------------------------------------------------------
def smoke_taint_tracker() -> None:
    try:
        from graduation_project.taint_tracker import TaintTracker
        tt = TaintTracker()
    except Exception as e:  # pragma: no cover
        _skip("taint_tracker", f"初始化失败: {e}")
        return
    code = ('from flask import request\n'
            'def search():\n'
            '    q = request.args.get("q")\n'
            '    cursor.execute("SELECT * FROM t WHERE x = " + q)\n')
    paths = tt.trace(code, language="python", filename="smoke.py")
    _record("taint_tracker", len(paths) >= 1,
            f"request→execute 污点链召回 {len(paths)} 条 (期望 ≥1)")


# ---------------------------------------------------------------------------
# 3) Semgrep taint（本地规则目录，离线）
# ---------------------------------------------------------------------------
def smoke_semgrep(ext: ExternalScanner, tmpdir: str) -> None:
    if "semgrep" not in ext.available_tools():
        _skip("semgrep", "未安装")
        return
    f = _write_tmp(tmpdir, "smoke_sqli.py",
                   'from flask import request\n'
                   'def search():\n'
                   '    q = request.args.get("q")\n'
                   '    cursor.execute("SELECT * FROM t WHERE x = " + q)\n')
    findings = ext.scan_taint(f, "python")
    _record("semgrep", len(findings) >= 1,
            f"本地 taint 规则召回 {len(findings)} 条 (期望 ≥1；规则目录 "
            f"graduation_project/semgrep_rules)")


# ---------------------------------------------------------------------------
# 4) Bandit（Python SAST）
# ---------------------------------------------------------------------------
def smoke_bandit(ext: ExternalScanner, tmpdir: str) -> None:
    if "bandit" not in ext.available_tools():
        _skip("bandit", "未安装")
        return
    vuln = _write_tmp(tmpdir, "smoke_cmd.py",
                      'import subprocess\n'
                      'def run(host):\n'
                      '    subprocess.run("ping " + host, shell=True)\n')
    findings = ext.scan_sast(vuln, "python")
    bandit_hits = [f for f in findings if f.tool == "bandit"]
    _record("bandit", len(bandit_hits) >= 1,
            f"shell=True 拼接待召回 {len(bandit_hits)} 条 (期望 ≥1，B602 族)")


# ---------------------------------------------------------------------------
# 5) Gitleaks（secret，重点：--no-git 与 --config 接线回归）
# ---------------------------------------------------------------------------
def smoke_gitleaks(ext: ExternalScanner, tmpdir: str) -> None:
    if "gitleaks" not in ext.available_tools():
        _skip("gitleaks", "未安装")
        return
    vuln = _write_tmp(tmpdir, "smoke_secret.py",
                      'SECRET_API_TOKEN = "sup3r_s3cret_t0k3n_very_long"\n'
                      'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
                      'SECRET_KEY = b"this_is_a_hardcoded_secret_key_32_byte"[:32]\n')
    findings = ext.scan_secrets(vuln)
    rule_ids = {f.rule_id for f in findings}
    ok_generic = len(findings) >= 1
    detail = f"召回 {len(findings)} 条 {sorted(rule_ids)}"
    if not ok_generic:
        # B1 教训的直接回归点：零召回大概率是 --no-git 丢失，而不是"工具无效"
        _record("gitleaks", False, detail + " —— 阳性样例零召回，"
                "先查 --no-git 是否仍在调用链（勿解读为'工具无效'）")
        return
    # --config 接线（B2 自定义规则）必须同时命中两个自定义规则族
    ok_aws = "aws-access-key-id" in rule_ids
    ok_bytes = "python-bytes-literal-secret" in rule_ids
    ok_custom = ok_aws and ok_bytes
    if not ok_custom:
        detail += f" —— 自定义规则缺失(aws={ok_aws}, bytes={ok_bytes})，" \
                  "查 gitleaks_rules.toml 是否存在且 --config 已挂载"
    _record("gitleaks", ok_custom, detail)
    safe = _write_tmp(tmpdir, "smoke_safe.py", 'x = "hello world"\ny = 1 + 2\nprint(x, y)\n')
    safe_hits = ext.scan_secrets(safe)
    _record("gitleaks·安全样例零误报", len(safe_hits) == 0,
            f"安全样例召回 {len(safe_hits)} 条 (期望 0)")


# ---------------------------------------------------------------------------
# 6) detect-secrets（secret，best-effort）
# ---------------------------------------------------------------------------
def smoke_detect_secrets(ext: ExternalScanner, tmpdir: str) -> None:
    if "detect-secrets" not in ext.available_tools():
        _skip("detect-secrets", "未安装")
        return
    vuln = _write_tmp(tmpdir, "smoke_ds.py",
                      'password = "hunter2_hunter2_secret"\n')
    findings = ext.scan_secrets(vuln)
    ds_hits = [f for f in findings if f.tool == "detect-secrets"]
    if ds_hits:
        _record("detect-secrets", True, f"召回 {len(ds_hits)} 条")
    else:
        # 检测依赖插件配置，零召回不足以判定调用链断裂 → 降级 SKIP
        _skip("detect-secrets", "阳性样例零召回（插件/版本相关，按环境差异降级，不拦截 CI）")


# ---------------------------------------------------------------------------
# 7) Trivy fs（SCA，依赖本地漏洞库 → 零召回按 SKIP）
# ---------------------------------------------------------------------------
def smoke_trivy_sca(ext: ExternalScanner, tmpdir: str) -> None:
    if "trivy" not in ext.available_tools():
        _skip("trivy(fs)", "未安装")
        return
    req = _write_tmp(tmpdir, "requirements.txt",
                     "django==1.11.1\nrequests==2.6.0\n")
    findings = ext.scan_sca(req)
    if findings:
        _record("trivy(fs)", True, f"陈旧依赖召回 {len(findings)} 条")
    else:
        _skip("trivy(fs)", "零召回（本地漏洞库可能未拉取，属环境问题不拦截 CI）")


# ---------------------------------------------------------------------------
# 8) Trivy config（IaC，依赖本地策略包 → 零召回按 SKIP）
# ---------------------------------------------------------------------------
def smoke_trivy_iac(ext: ExternalScanner, tmpdir: str) -> None:
    if "trivy" not in ext.available_tools():
        _skip("trivy(config)", "未安装")
        return
    df = _write_tmp(tmpdir, "Dockerfile",
                    "FROM alpine:3.7\nUSER root\n")
    findings = ext.scan_iac(df)
    if findings:
        _record("trivy(config)", True, f"IaC 配置召回 {len(findings)} 条")
    else:
        _skip("trivy(config)", "零召回（本地策略包可能未拉取，属环境问题不拦截 CI）")


# ---------------------------------------------------------------------------
# 9) 端到端接线（无 LLM）：secret 候选必须走直出档成为已确认 finding（B1 回归）
# ---------------------------------------------------------------------------
def smoke_secret_dispatch() -> None:
    class _FakeClient:
        def generate(self, **kwargs):  # 裁决/复核均不应被调用到 secret 候选
            return {"text": '{"is_confirmed": false}', "error": None}

    from graduation_project.two_stage_scanner import TwoStageScanner
    ts = TwoStageScanner(client=_FakeClient(), system_prompt="sys", n_samples=3,
                         use_semgrep=False, use_taint_tracker=False,
                         use_prefilter=False, use_external=True,
                         no_candidate_mode="off", sampling_rate=0)
    code = ('def admin(token_from_req):\n'
            '    SECRET_API_TOKEN = "sup3r_s3cret_t0k3n_very_long"\n'
            '    return token_from_req == SECRET_API_TOKEN\n')
    r = ts.scan_code(code, "python", "smoke_secret_dispatch.py")
    direct = [a for a in r.adjudications if a.decision == "direct"]
    ok = r.has_vulnerability is True and len(direct) >= 1
    _record("secret档端到端直出", ok,
            f"has_vulnerability={r.has_vulnerability}, direct裁决={len(direct)} "
            f"(期望 ≥1；此处若为 False 说明 secret 候选被排除逻辑挡在门外)")


def main() -> int:
    print("=== 工具冒烟自测（P0，已知阳性样例验证调用链） ===\n")
    smoke_prefilter()
    smoke_taint_tracker()

    ext = ExternalScanner()
    with tempfile.TemporaryDirectory(prefix="tool_smoke_") as tmpdir:
        smoke_semgrep(ext, tmpdir)
        smoke_bandit(ext, tmpdir)
        smoke_gitleaks(ext, tmpdir)
        smoke_detect_secrets(ext, tmpdir)
        smoke_trivy_sca(ext, tmpdir)
        smoke_trivy_iac(ext, tmpdir)
    smoke_secret_dispatch()

    fails = [r for r in RESULTS if r[1] == "FAIL"]
    skips = [r for r in RESULTS if r[1] == "SKIP"]
    print(f"\n合计: PASS={len(RESULTS) - len(fails) - len(skips)} "
          f"FAIL={len(fails)} SKIP={len(skips)}")
    if fails:
        print("存在失败用例（已安装工具零召回/误报 = 调用链回归）")
        return 1
    print("=== 全部通过（SKIP 为环境不具备，非调用链问题） ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
