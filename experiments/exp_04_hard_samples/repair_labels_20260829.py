#!/usr/bin/env python3
"""测试集 manifest 标签治理 2026-08-29：A 级实锤漏标 2 条 + B 级灰色口径 3 条。

来源：2026-08-29 测试集标签审计（87 段逐样本比对代码与标注，A/B/C 分级）。
  A 级（实锤漏标，影响 strict 评估公正性）：
    - hard_longfile_03：漏 CWE-79（Environment() 默认 autoescape=False，greeting
      未转义进 <h1>，XSS 真实成立）+ 漏 CWE-798（line 12 硬编码 Flask session
      密钥，与 typical_06/hard_bypass_06 口径一致）
    - typical_18：漏 CWE-798（line 7 硬编码 AES 密钥；描述自己写着"硬编码密钥"，
      同"硬编码凭证+另一主漏洞"型 hard_bypass_06 已双标，口径拉齐）
  B 级（灰色口径，低危伴生，建议补）：
    - hard_cve_03：补 CWE-377（tmp = "/tmp/upload.tar" 可预测共享路径，bandit
      B108 同报）
    - hard_longfile_01：补 CWE-760（SALT 静态盐削弱 PBKDF2）+ CWE-208（verify_password
      用 == 非常数时间比较，与 hard_bypass_06 同型口径拉齐，利用难度远高于 bypass_06）
    - hard_longfile_02：补 CWE-377（EXPORT_DIR = "/tmp/exports"，B108 同报）

惯例沿用 2026-08-18 治理（commit b6fc7d6）：
  - expected_cwe 追加 "； " 分隔的双标/多标（"; " 分隔符）
  - expected_vulnerability 追加 "（测试集治理 2026-08-29 补标注：<证据>）"
  - 改前备份 manifest.json.bak_20260829
  - 脚本幂等：已应用则跳过，重复运行无副作用

C 级核查通过的样本本脚本一律不触碰。
"""
from __future__ import annotations

import copy
import json
import re
import shutil
from pathlib import Path

MANIFEST = Path(__file__).resolve().parent / "samples" / "manifest.json"
BACKUP = MANIFEST.parent / "manifest.json.bak_20260829"

GOV_DATE = "2026-08-29"
NOTE_MARK = f"测试集治理 {GOV_DATE} 补标注"

# file -> (旧 expected_cwe, 新 expected_cwe, 追加到 expected_vulnerability 的证据注释)
FIXES: dict[str, tuple[str, str, str]] = {
    "hard_longfile_03_hidden_ssti.py": (
        "CWE-1336; CWE-94",
        "CWE-1336; CWE-94; CWE-79; CWE-798",
        'Environment(loader=BaseLoader()) 默认 autoescape=False，custom_greeting '
        '未转义渲染进 <h1> → 伴生 XSS；app.secret_key = '
        '"very_long_dev_secret_key_for_testing_only"（line 12）硬编码 Flask 会话密钥 '
        '→ CWE-798，与 typical_06/hard_bypass_06 口径一致',
    ),
    "typical_18_hardcoded_iv.py": (
        "CWE-329",
        "CWE-329; CWE-798",
        'line 7 SECRET_KEY = b"this_is_a_hardcoded_secret_key_32_byte" 硬编码 AES '
        '密钥 → CWE-798，与 typical_06/hard_bypass_06 硬编码凭证口径一致',
    ),
    "hard_cve_03_tarfile_2025_4517.py": (
        "CWE-22",
        "CWE-22; CWE-377",
        'line 10 tmp = "/tmp/upload.tar" 可预测共享临时路径 → CWE-377，bandit B108 '
        '同报，与 hard_longfile_02 口径一致',
    ),
    "hard_longfile_01_hidden_sql.py": (
        "CWE-89",
        "CWE-89; CWE-760; CWE-208",
        'line 27 SALT = b"static-salt-do-not-change" 静态盐削弱 PBKDF2 → CWE-760；'
        'line 59 verify_password 用 == 比较摘要非常数时间 → CWE-208，与 '
        'hard_bypass_06 同型口径拉齐（利用难度远高于 bypass_06）',
    ),
    "hard_longfile_02_hidden_cmd.py": (
        "CWE-78",
        "CWE-78; CWE-377",
        'line 21 EXPORT_DIR = "/tmp/exports" 可预测共享目录 → CWE-377，bandit B108 '
        '同报，与 hard_cve_03 口径一致',
    ),
}

CWE_FIELD_RE = re.compile(r"^(CWE-\d+)(; CWE-\d+)*$")


def cwe_types(manifest: dict) -> set[str]:
    types: set[str] = set()
    for s in manifest["samples"]:
        for c in s["expected_cwe"].replace("N/A", "").split(";"):
            if c.strip():
                types.add(c.strip())
    return types


def main() -> None:
    raw = MANIFEST.read_text(encoding="utf-8")
    manifest = json.loads(raw)
    before = copy.deepcopy(manifest)

    applied: list[tuple[str, str, str]] = []
    for fname, (old_cwe, new_cwe, evidence) in FIXES.items():
        sample = next((s for s in manifest["samples"] if s["file"] == fname), None)
        assert sample is not None, f"样本不存在: {fname}"
        if sample["expected_cwe"] == new_cwe and NOTE_MARK in sample["expected_vulnerability"]:
            print(f"[skip] {fname} 已应用过本次治理")
            continue
        assert sample["expected_cwe"] == old_cwe, (
            f"{fname} 当前 expected_cwe={sample['expected_cwe']!r} 与预期旧值 {old_cwe!r} 不符，拒绝盲改"
        )
        assert NOTE_MARK not in sample["expected_vulnerability"], f"{fname} 已有本次治理注释"
        note = f"（{NOTE_MARK}：{evidence}）"
        sample["expected_vulnerability"] = sample["expected_vulnerability"] + note
        sample["expected_cwe"] = new_cwe
        applied.append((fname, old_cwe, new_cwe))
        print(f"[fix ] {fname}: {old_cwe} -> {new_cwe}")

    if not applied:
        print("无事可做（全部已应用），不写回文件")
        return

    # 全字段校验：expected_cwe 格式合法（safe/noise 样本为 N/A）
    for s in manifest["samples"]:
        assert s["expected_cwe"] == "N/A" or CWE_FIELD_RE.match(s["expected_cwe"]), (
            f"{s['file']} expected_cwe 格式异常: {s['expected_cwe']!r}"
        )
        assert s["expected_vulnerability"].strip(), f"{s['file']} 描述为空"

    # 样本数与未涉样本不可变性
    assert len(manifest["samples"]) == len(before["samples"]) == 87
    touched = set(FIXES)
    for s_new, s_old in zip(manifest["samples"], before["samples"]):
        assert s_new["file"] == s_old["file"]
        if s_new["file"] not in touched:
            assert s_new == s_old, f"C 级/未涉样本被意外改动: {s_new['file']}"
        else:
            allowed = {"expected_cwe", "expected_vulnerability"}
            assert all(
                s_new[k] == s_old[k] for k in s_new if k not in allowed
            ), f"{s_new['file']} 不得改动 expected_cwe/expected_vulnerability 之外的字段"

    # CWE 类型计数同步进描述（补标前实际 37 类，描述滞留 34；补标后 39）
    n_types = len(cwe_types(manifest))
    desc = manifest["description"]
    m = re.search(r"（(\d+) CWE）", desc)
    if m and int(m.group(1)) != n_types:
        manifest["description"] = desc.replace(m.group(0), f"（{n_types} CWE）")
        print(f"[fix ] description CWE 类型计数: {m.group(1)} -> {n_types}")

    # 备份（存在则不覆盖，保留首次快照）
    if not BACKUP.exists():
        shutil.copy2(MANIFEST, BACKUP)
        print(f"[bak ] {BACKUP.name}")

    out = json.dumps(manifest, ensure_ascii=False, indent=2)
    assert not raw.endswith("\n"), "原文件无尾换行的假设被破坏，请人工确认写回格式"
    MANIFEST.write_text(out, encoding="utf-8")
    print(f"[done] {MANIFEST} 已写回（{len(applied)} 条修复）")


if __name__ == "__main__":
    main()
