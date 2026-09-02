# -*- coding: utf-8 -*-
"""补删上一批漏掉的 DELETE verdict 样本。

背景: 上一批 apply_web_review_delete.py 用严格 json.loads 解析 result.txt,
68 行因 evidence 内含未转义引号解析失败被静默跳过, 其中含 11 个 DELETE。
本次容错重析后补删在库的 10 个 (7807/7808 本就 no_match 跳过)。

- 定位: audit/result_id_map.json 的 v15_line, 按 20260902 第一批已删 10 行做偏移校正
- 核验: 每行须含审计特征词之一, 否则中止该 id 并报错
- 安全: 备份先行; manifest 逐条留痕; 删除后自检
"""
import json
import shutil
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
MAP = BASE / "audit/result_id_map.json"
BAK = DATA.with_suffix(DATA.suffix + ".bak_wr_delete2_20260902")
OUT = BASE / "audit/web_review"

# 第一批已删的 1-based 行号 (来自 web_review_DELETE_manifest_20260902.json)
WAVE1_DELETED = [6206, 7260, 7267, 7272, 7483, 7727, 7803, 8121, 8123, 8129]

# 补删清单: id -> (审计特征词, 简要理由)
TARGETS = {
    1717: (["Runtime.getRuntime().exec", "grep"], "PoC 建立在 exec 无 shell 语义上全部失效; JSON 修复反向引入 bash -c 拼接注入"),
    2559: (["System.getProperty", "app.config.path"], "假阳性: 系统属性为启动期操作员控制, 无远程污点流; 教师沿注释自标注复制结论"),
    7255: (["tensorflow", "ArrayOpTest", "upper_bound"], "假阳性: 纯 TF 单元测试无外部输入, 对样本外库代码虚构漏洞叙事, fix 为无操作"),
    7258: (["aquasecurity", "trivy", "plugin"], "假阳性: URL 常量当外部 source, 以样本外不可见代码立论; 与 7257 同码互斥判定"),
    7271: (["is_safe_url", "requests.get"], "假阴性: 默认跟随重定向绕过 SSRF 黑名单, 却教学生『防护完整』"),
    7278: (["graphql-ws", "toMap", "getVariables"], "假阳性: 纯接口声明无 sink, CWE-502/RCE 全链路虚构; 与 7279 同文件相反判定"),
    7285: (["IsSameSite"], "假阳性: 纯单元测试不含被测实现, source/sink 依赖样本外虚构请求流"),
    7301: (["StringPiece", "fromJSON", "normalizeNewlines"], "假阳性: 数据模型类无渲染 sink, 以样本外 Trix 渲染层假设立论"),
    7455: (["TRANSLATIONS", "deep_assign"], "假阳性: 普通 dict 键写入被虚构为 Python 类污染, PoC 无效"),
    7817: (["adb", "Popen", "screenshot"], "假阴性: 无校验 cmd.split 直达 Popen, 与 7816 同码互斥判 safe"),
}

mp = json.loads(MAP.read_text(encoding="utf-8"))
lines = [l for l in DATA.read_text(encoding="utf-8").split("\n") if l.strip()]
n_before = len(lines)
print(f"当前 v2_15: {n_before} 条")
if not BAK.exists():
    shutil.copy(DATA, BAK)
    print(f"已备份 -> {BAK.name}")

remove_idx, log, problems = set(), [], []
for wid, (tokens, why) in sorted(TARGETS.items()):
    ent = mp.get(str(wid))
    if not ent or not ent.get("v15_line"):
        problems.append(f"id={wid} map 无 v15_line: {ent}")
        continue
    old_line = ent["v15_line"]
    idx = old_line - 1 - sum(1 for d in WAVE1_DELETED if d < old_line)
    if not (0 <= idx < len(lines)) or idx in remove_idx:
        problems.append(f"id={wid} 偏移后行号越界/重复: 原{old_line} -> 现idx {idx}")
        continue
    rec = json.loads(lines[idx])
    content = "\n".join(m.get("content", "") for m in rec.get("messages", []))
    hit = [t for t in tokens if t and t in content]
    if tokens and not hit:
        problems.append(
            f"id={wid} 行{old_line}->idx{idx} 特征词全未命中 {tokens}, "
            f"开头: {content[:100]!r}")
        continue
    remove_idx.add(idx)
    fd = rec.get("fix_distill") or {}
    log.append({"id": wid, "v15_line_orig": old_line, "idx_now": idx,
                "hit_tokens": hit, "reason": why,
                "teacher": fd.get("teacher", "")})
    print(f"  定位 id={wid}: 原{old_line} -> 现第{idx + 1}条, 命中{hit}")

if problems:
    print("\n!! 存在定位问题, 不执行删除:")
    for p in problems:
        print("  ", p)
    sys.exit(1)

new_lines = [l for i, l in enumerate(lines) if i not in remove_idx]
DATA.write_text("\n".join(new_lines), encoding="utf-8")
n_after = sum(1 for l in new_lines if l.strip())
print(f"删除后 v2_15: {n_after} 条 (删 {n_before - n_after})")

manifest = {
    "date": "2026-09-02",
    "action": "补删第一批漏掉的 web_review DELETE verdict: 上一批脚本严格 json.loads 解析 result.txt 失败 68 行(未转义引号), 其中 11 个 DELETE 未应用; 本批补删在库 10 个(7807 no_match 跳过)",
    "source": "audit/web_review/result.txt (容错解析 _result_tolparse_20260902.json) + audit/result_id_map.json",
    "wave1_deleted_lines": WAVE1_DELETED,
    "n_deleted": n_before - n_after,
    "deleted": log,
}
mpath = OUT / "web_review_DELETE_manifest_20260902_missed10.json"
mpath.write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
print("manifest 写入:", mpath.name)

# 自检: 全文件 JSON 可解析
bad = 0
for i, l in enumerate(new_lines):
    try:
        json.loads(l)
    except Exception:
        bad += 1
        print("  !! 第", i + 1, "行 JSON 解析失败")
print("自检: JSON 失败", bad)
