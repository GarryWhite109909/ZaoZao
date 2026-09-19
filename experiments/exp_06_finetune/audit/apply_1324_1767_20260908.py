# -*- coding: utf-8 -*-
"""FIX 队列收官：1324（锚+5 错位、删 R8/R1 悬空引用、High→Critical）+ 1767（锚全修+穿越算术+转义清理）。"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(Path(__file__).resolve().parents[1])
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_16_20260908.jsonl"

ROWS = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]


def R(t, x, y):
    assert t.count(x) == 1, f"不唯一({t.count(x)}): {x[:60]}"
    return t.replace(x, y)


def patch(a, **fields):
    m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
    obj = json.loads(m.group(1))
    obj.update(fields)
    return a[: m.start()] + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```\n"


# ================= 1324 =================
r = ROWS[1284 - 1]
a = r["messages"][2]["content"]
# 正文锚（码验证：L13 source / L19-23 docker build / L26 mysql / L29-35 service create）
a = R(a, "1. **第18行**：`source \"$CONFIG_FILE\"` 直接执行外部配置文件。", "1. **第13行**：`source \"$CONFIG_FILE\"` 直接执行外部配置文件。")
a = R(a, "2. **第24-26行**：`docker build` 的", "2. **第19-23行**：`docker build` 的")
a = R(a, "3. **第31行**：`mysql -p\"${DB_PASS}\"`", "3. **第26行**：`mysql -p\"${DB_PASS}\"`")
a = R(a, "4. **第36-40行**：`docker service create`", "4. **第29-35行**：`docker service create`")
a = R(a, "但核心漏洞是第18行的 `source` 命令执行了不可信内容。", "但核心漏洞是第13行的 `source` 命令执行了不可信内容。")
a = R(a, "但漏洞链起点仍是第18行的命令注入。", "但漏洞链起点仍是第13行的命令注入。")
# 未闭合括号修复
a = R(a, "导致任意命令注入（CWE-78 OS Command Injection\n", "导致任意命令注入（CWE-78 OS Command Injection）。\n")
a = R(a, "2. **第19-23行**：`docker build` 的 `--build-arg` 值来自被 source 的文件。若 `BASE_IMAGE` 被注入 `--network=host` 或恶意 Dockerfile 参数，可影响构建环境。",
        "2. **第19-23行**：`docker build` 的 `--build-arg` 值来自被 source 的文件。若 `BASE_IMAGE` 被注入 `--network=host` 或恶意 Dockerfile 参数，可影响构建环境（次要面，变量双引号包裹不构成命令注入）。")
a = R(a, "5. 该脚本缺少对 `PROJECT_NAME` 的校验（如白名单正则），也未使用 `set -u` 防止未定义变量，导致攻击面扩大。",
        "5. 该脚本缺少对 `PROJECT_NAME` 的校验（如白名单正则），也未使用 `set -u` 防止未定义变量，导致攻击面扩大。主漏洞（第 8→13 行）为 source 执行攻击者可控路径的配置内容，可达 RCE，定级 Critical。")
# JSON：删"原 JSON"R8 悬空引用 + 删（R1）+ source 行 9→8 + High→Critical
m = re.search(r"\n```json\n(\{.*?\})\n```", a, re.S)
obj = json.loads(m.group(1))
obj["risk_level"] = "Critical"
obj["source"] = "line 8: CONFIG_FILE=\"/etc/deploy/projects/${PROJECT_NAME}.conf\"——PROJECT_NAME 未校验即拼入路径（可 ../ 穿越至攻击者可控位置）"
obj["explanation"] = ("line 19/26/29-35 所有变量均双引号包裹（--build-arg BASE_IMAGE=\"${BASE_IMAGE}\"、"
                      "mysql -h \"${DB_HOST}\" 等），双引号内分号/管道由数据携带不作命令分隔；"
                      "--build-arg 的值也不会被 docker 重新解析为命令行选项——docker/mysql 链不成立。"
                      "真实漏洞链：PROJECT_NAME（line 8）未校验 → 参与构造 CONFIG_FILE 路径（line 8）"
                      "可 ../ 穿越出配置目录 → line 13 source \"$CONFIG_FILE\" 执行攻击者可控文件内容"
                      "（任意命令执行/RCE，CWE-78；主 CWE 78 经码核验成立，非 22/73）")
obj["fix_suggestion"] = ("line 8 前: 对 PROJECT_NAME 做白名单校验 "
                         "if [[ ! \"$PROJECT_NAME\" =~ ^[A-Za-z0-9_-]+$ ]]; then echo \"Invalid PROJECT_NAME\"; exit 1; fi"
                         "（不含 ./ 即封死穿越）；line 13: source 前对解析路径做 realpath 前缀校验，"
                         "仅允许 /etc/deploy/projects/ 内文件")
a = a[: m.start()] + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```\n"
r["messages"][2]["content"] = a
with CHANGELOG.open("a", encoding="utf-8") as f:
    f.write(json.dumps({
        "date": "2026-09-08", "step": "1.4_fix_queue_semantic", "action": "FIX",
        "fix_id": 1324, "row_line_before": 1284,
        "note": "锚 18→13/24-26→19-23/31→26/36-40→29-35/source 9→8；删'原 JSON'R8 悬空引用与（R1）；High→Critical（可达 RCE）；主 CWE 78 经码核验维持",
        "basis": "fix_queue_20260907 spec + R2 relabelled 账目",
    }, ensure_ascii=False) + "\n")

# ================= 1767 =================
r = ROWS[1717 - 1]
a = r["messages"][2]["content"]
a = R(a, "1. 第23行：`snprintf` 将用户可控的 `filename` 直接拼接到固定路径前缀 `/var/lib/app/data/` 后，未检查是否包含 `../` 或绝对路径。",
        "1. 第14行：`snprintf` 将用户可控的 `filename` 直接拼接到固定路径前缀 `/var/lib/app/data/` 后，未检查是否包含 `../` 或绝对路径。")
a = R(a, "2. 第36行：`fopen(filepath, \"w\")` 使用构造后的路径打开文件，若 `filename` 为 `../../etc/passwd`，则实际写入路径逃逸到 `/var/lib/app/data/../../etc/passwd`，即 `/etc/passwd`。",
        "2. 第24行：`fopen(filepath, \"w\")` 使用构造后的路径打开文件，若 `filename` 为 "
        "`../../../../etc/passwd`，则实际写入路径逃逸到 `/var/lib/app/data/../../../../etc/passwd`，"
        "即 `/etc/passwd`（/var/lib/app/data 至根需 4 级穿越，原PoC 的 2 级只到 /var/lib/etc，"
        "算术已修正）。")
a = R(a, "3. 第40行：`fputs(data_buffer, fp)`", "3. 第30行：`fputs(data_buffer, fp)`")
a = patch(a,
          explanation="用户输入 filename 含 ../ → line 14 拼接出 /var/lib/app/data/../../../../etc/passwd（4 级穿越至根）→ line 24 fopen 打开任意文件 → line 30 fputs 写入用户数据 → 任意文件写入",
          fix_suggestion="line 14: 建议改为 if (strstr(filename, \"..\") != NULL || strchr(filename, '/') != NULL) return -1; snprintf(filepath, sizeof(filepath), \"/var/lib/app/data/%s\", filename);（拒绝绝对路径、.. 与路径分隔符；原双重转义已清理）")
r["messages"][2]["content"] = a
with CHANGELOG.open("a", encoding="utf-8") as f:
    f.write(json.dumps({
        "date": "2026-09-08", "step": "1.4_fix_queue_semantic", "action": "FIX",
        "fix_id": 1767, "row_line_before": 1717,
        "note": "锚 23→14/36→24/40→30；explanation 13→14/31→30；fix 13→14；穿越深度算术修正（至 /etc 需 4 级）；fix 双重转义清理",
        "basis": "fix_queue_20260907 spec",
    }, ensure_ascii=False) + "\n")

with DATA.open("w", encoding="utf-8", newline="\n") as f:
    for row in ROWS:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")

for idx in (1284 - 1, 1717 - 1):
    a2 = ROWS[idx]["messages"][2]["content"]
    m2 = re.search(r"\n```json\n(\{.*?\})\n```", a2, re.S)
    json.loads(m2.group(1))
print("PASS: 1324 / 1767 已落盘 — FIX 队列 27/27 全部处理完毕")
