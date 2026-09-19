# -*- coding: utf-8 -*-
"""FIX 队列：1289（1188→798+250，删虚构 deploy.sh 引用）+ 7829（删可证伪断言）。"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(Path(__file__).resolve().parents[1])
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"

N798 = "CWE-798 Use of Hard-coded Credentials"

ROWS = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]


def R(t, x, y):
    assert t.count(x) == 1, f"替换源不唯一({t.count(x)}): {x[:60]}"
    return t.replace(x, y)


# ================= 1289 =================
r = ROWS[1249 - 1]
assert "datasync" in r["messages"][1]["content"]
new_text = (
    "**分析过程**\n\n"
    "1. **第 15-16 行（[Service] 段）**：`Environment=DB_PASSWORD=admin123` 与 "
    "`Environment=API_TOKEN=sk_live_9f8e7d6c5b4a` 将明文凭据硬编码进 systemd unit——官方字面"
    "（配置文件 contains 硬编码密码/密钥字面量）即成立，构成 CWE-798 Use of Hard-coded "
    "Credentials；任何本地用户可经 `systemctl show datasync` 或直接读取 unit 文件获取敏感信息。\n"
    "2. **第 7 行 `User=root`（辅）**：服务以最高权限运行，违反最小权限原则（CWE-250），"
    "与硬编码凭据叠加放大失陷面。\n"
    "3. **第 9 行 `EnvironmentFile=/etc/datasync/env.conf`** 本可用于外部注入凭据，但第 15-16 行的 "
    "`Environment=` 与之并存——实际生效值取决于 systemd 解析顺序，破坏\"凭据不入 unit 文件\"的"
    "安全设计。\n"
    "4. **第 10 行 `ExecStartPre`** 调用的 preflight.sh 由 root 执行且无完整性保障；若目录权限未"
    "收紧，攻击者可替换该脚本实现 root 任意命令执行（纵深备注）。\n"
    "5. **结论**：主洞 CWE-798（硬编码凭据），辅 CWE-250（root 运行），风险 High。\n"
    "```json\n" + json.dumps({
        "has_vulnerability": True,
        "vulnerability_type": N798,
        "risk_level": "High",
        "source": "line 15-16: Environment=DB_PASSWORD=admin123 / Environment=API_TOKEN=sk_live_9f8e7d6c5b4a 明文硬编码凭据",
        "sink": "line 15-16: 凭据写入 unit 文件，任何本地用户可经 systemctl show 或读取文件获取（辅：line 7 User=root 放大后果）",
        "explanation": "line 15-16 明文硬编码 DB_PASSWORD/API_TOKEN（官方字面 contains 即成立，CWE-798）-> "
                       "unit 文件本地可读/systemctl show 可见 -> 凭据泄露；辅 line 7 User=root（CWE-250）"
                       "使服务漏洞可直达 root；line 9 EnvironmentFile 与 line 15-16 并存造成解析顺序混乱；"
                       "勘误：原判 CWE-1188 不成立（无默认权限语义），deploy.sh 内嵌 unit 的 35/37/41 行"
                       "引用为虚构产物已删（unit 本体以 ini 为准）",
        "fix_suggestion": "line 15-16: 删除两行 Environment=，凭据移入 line 9 的 EnvironmentFile"
                          "（权限 600 的独立 env 文件）；line 7: 改为专用低权限用户（User=datasync）",
    }, ensure_ascii=False) + "\n```\n"
)
r["messages"][2]["content"] = new_text
with CHANGELOG.open("a", encoding="utf-8") as f:
    f.write(json.dumps({
        "date": "2026-09-08", "step": "1.4_fix_queue_semantic", "action": "FIX",
        "fix_id": 1289, "row_line_before": 1249,
        "note": "1188→798（官方字面 contains 即成立）辅 250；删虚构 deploy.sh 产物引用；锚 20→7/22→15/26→9/30→10；JSON sink 补 line 16；fix 去重",
        "label_basis": "audit",
    }, ensure_ascii=False) + "\n")

# ================= 7829 =================
r = ROWS[7745 - 1]
a = r["messages"][2]["content"]
assert "Smarty" in a
a = R(a, "缓存属性 `_resource_dir/_template_dir/_config_dir` 的失效逻辑（`_updateResourceDir`）在目录变更时正确清理旧前缀。",
        "缓存属性失效逻辑（`_updateResourceDir`）的\"正确清理旧前缀\"断言已删除——第 455-457 行的值迭代"
        "恒为 no-op，可证伪（原教师断言不可靠）。")
a = R(a, "6. **isTrustedUri（约 505–525 行）**", "6. **isTrustedUri（约 432-443 行）**")
r["messages"][2]["content"] = a
with CHANGELOG.open("a", encoding="utf-8") as f:
    f.write(json.dumps({
        "date": "2026-09-08", "step": "1.4_fix_queue_semantic", "action": "FIX",
        "fix_id": 7829, "row_line_before": 7745,
        "note": "教师=none 判定维持（_checkDir @realpath 修复有效）；删 _updateResourceDir 可证伪断言；锚 505-525→432-443",
        "basis": "fix_queue_20260907 spec",
    }, ensure_ascii=False) + "\n")

with DATA.open("w", encoding="utf-8", newline="\n") as f:
    for row in ROWS:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")

for idx, key in ((1249 - 1, "CWE-798"), (7745 - 1, "_updateResourceDir")):
    a2 = ROWS[idx]["messages"][2]["content"]
    m = re.search(r"\n```json\n(\{.*?\})\n```", a2, re.S)
    json.loads(m.group(1))
print("PASS: 1289 → 798+250；7829 断言清理完成")
