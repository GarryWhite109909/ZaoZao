# -*- coding: utf-8 -*-
"""alpha06_v2.12 数据集全量体检报告修复脚本 —— 产出 v2.13。

依据 audit/审计报告_alpha06_v2.12_数据集全量体检.md 第 9 节修复清单，
可确定性执行的修复项全部在本脚本内完成，需教师重跑的项写入重蒸馏清单。

修复项对应关系（报告编号 -> 本脚本步骤）：
  P0-1  risk_level 小写 none -> None 归一化            [步骤 4]
  P0-2  剔除教师独白样本（13+5=18 条，含 2 条 JSON 失效）[步骤 9]
  P0-3  24 条异种契约转写为主契约                      [步骤 1]
  P0-4  6 条矛盾标签剔除（探查确认正文与 user 代码错位，
        机械翻转会残留错误，取报告备选方案"直接剔除"）  [步骤 3]
  P0-5  290 条空壳分析剔除 + 重复 assistant 组清理      [步骤 9]
  P0-6  explanation=N/A 从分析正文结论提取补齐，
        提取不到的进重蒸馏清单                          [步骤 6]
  P1-7  删除 cvss_vector/cvss_score(661) 与 fix_code(70) [步骤 5]
  P1-8  source/sink 行号校验 + 保守自动修正             [步骤 7]
  P1-9  18 条 vulnerability_type 格式归一               [步骤 2]
  P2-15 1-shot CWE 剔除（归一后计数==1）                [步骤 9]
  P2-18 安全样本 source/sink/fix 规范放宽（system prompt 同步更新）[步骤 8]
  P2-20 训练脚本硬断言另行修改 train_qlora.py

输出：
  data/final_train_chatml_alpha06_v2_13.jsonl   修复后数据集
  audit/repair_v2_13_out.txt                    执行日志（全量审计数字）
  audit/redistill_manifest_v2_13.jsonl          重蒸馏清单（含 user 全文）
  audit/lineno_review_v2_13.jsonl               行号待人工复核清单
"""
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path("/home/zane/文档/code/毕业设计/experiments/exp_06_finetune")
SRC = BASE / "data/final_train_chatml_alpha06_v2_12.jsonl"
OUT_DATA = BASE / "data/final_train_chatml_alpha06_v2_13.jsonl"
OUT_LOG = BASE / "audit/repair_v2_13_out.txt"
OUT_MANIFEST = BASE / "audit/redistill_manifest_v2_13.jsonl"
OUT_LINENO = BASE / "audit/lineno_review_v2_13.jsonl"

JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)
LINE_ANCHOR = re.compile(r"line\s*(\d+)")

# ---------------------------------------------------------------- 工具函数
def get(msgs, role):
    for m in msgs:
        if m.get("role") == role:
            return m.get("content", "")
    return ""

def last_json_object(assistant: str):
    """返回 (json块完整文本, 解析后对象)；失败返回 (None, None)。"""
    blocks = JSON_BLOCK.findall(assistant)
    if not blocks:
        return None, None
    try:
        return blocks[-1], json.loads(blocks[-1])
    except Exception:
        return blocks[-1], None

def replace_last_json(assistant: str, new_text: str) -> str:
    """将 assistant 中最后一个 ```json 块整体替换。"""
    matches = list(JSON_BLOCK.finditer(assistant))
    m = matches[-1]
    return assistant[: m.start()] + "```json\n" + new_text + "\n```" + assistant[m.end():]

VALID_RISK = {"Critical", "High", "Medium", "Low", "None"}
CONTRACT_FIELDS = ["has_vulnerability", "vulnerability_type", "risk_level",
                   "source", "sink", "explanation", "fix_suggestion"]

# ---------------------------------------------------------------- 读入
rows = []  # (orig_line, record)
with SRC.open(encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if line:
            rows.append((i, json.loads(line)))
R = dict(rows)
LOG = []
MANIFEST = []
LINENO_REVIEW = []

def P(*a):
    LOG.append(" ".join(str(x) for x in a))

P(f"读入 {len(rows)} 条（v2_12）")
n_total = len(rows)

# 主 system prompt（取自行 1，a1 审计 hash b91ad125a9，len=1982）
MAIN_SYSTEM = get(R[1]["messages"], "system")
assert len(MAIN_SYSTEM) == 1982, f"主 system 长度异常: {len(MAIN_SYSTEM)}"

# =================================================================
# 步骤 1 [P0-3] 转写 24 条异种契约（行 8069-8092）
# =================================================================
P("=" * 78)
P("[步骤1] P0-3 异种契约转写（is_confirmed -> has_vulnerability 等 7 字段）")
P("=" * 78)
SEV_MAP = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
transcribed = []
for i in range(8069, 8093):
    rec = R[i]
    msgs = rec["messages"]
    u = get(msgs, "user")
    a = get(msgs, "assistant")
    _, o = last_json_object(a)
    if o is None or "is_confirmed" not in o:
        P(f"  !! line {i}: 无 is_confirmed JSON，跳过（人工处理）")
        continue
    confirmed = bool(o["is_confirmed"])
    # 1a. system 换成主契约 prompt
    msgs[0]["content"] = MAIN_SYSTEM
    m_sev = re.search(r"严重度:\s*(\S+)", u)
    risk = SEV_MAP.get(m_sev.group(1).lower(), "Medium") if (confirmed and m_sev) else ("None" if not confirmed else "Medium")

    def anchor(kind_label):
        """从 user 提取 '- 污染源: xxx  (line 9)' / '- 危险点: yyy  (line 13)'。"""
        m = re.search(rf"-\s*{kind_label}:\s*(.+?)\s*\(([^)]*line[^)]*)\)", u)
        if not m:
            return None
        loc = m.group(2).strip()
        m_ln = re.search(r"line\s*(\d+)", loc)
        if not m_ln:
            return None
        return f"line {m_ln.group(1)}: {m.group(1).strip()}"

    if confirmed:
        src = anchor("污染源") or "N/A"
        snk = anchor("危险点") or "N/A"
    else:
        src = snk = "N/A"
    new_o = {
        "has_vulnerability": confirmed,
        "vulnerability_type": o.get("vulnerability_type") if confirmed else "none",
        "risk_level": risk,
        "source": src,
        "sink": snk,
        "explanation": o.get("reason", ""),
        "fix_suggestion": o.get("fix_suggestion", "no fix needed"),
    }
    msgs[2]["content"] = replace_last_json(a, json.dumps(new_o, ensure_ascii=False))
    if not confirmed and new_o["vulnerability_type"] != "none":
        P(f"  !! line {i}: false 但 vt={new_o['vulnerability_type']}（人工复核）")
    transcribed.append(i)
P(f"  已转写 {len(transcribed)} 条: {transcribed}")
for i in transcribed[:2] + transcribed[-1:]:
    o = last_json_object(get(R[i]["messages"], "assistant"))[1]
    P(f"  样例 line {i}: {json.dumps(o, ensure_ascii=False)[:220]}")

# =================================================================
# 步骤 2 [P1-9] vulnerability_type 归一（18 条）
# =================================================================
P("\n" + "=" * 78)
P("[步骤2] P1-9 vulnerability_type 格式归一")
P("=" * 78)
VT_MAP = {
    "CWE-184": "CWE-184 Input Validation",
    "CWE-95": "CWE-95 Eval Injection",
    "CWE-200": "CWE-200 Exposure of Sensitive Information",
    "CWE-770": "CWE-770 Allocation of Resources Without Limits",
    "CWE-532": "CWE-532 Insertion of Sensitive Information into Log File",
    "CWE-295": "CWE-295 Improper Certificate Validation",
    "CWE-209": "CWE-209 Sensitive Information in Error Messages",
    "CWE-204": "CWE-204 Observable Response Discrepancy",
    "CWE-88": "CWE-88 Argument Injection",
    "CWE-347": "CWE-347 Improper Verification of Cryptographic Signature",
    "CWE-170/CWE-22 路径前缀校验不严格": "CWE-22 Path Traversal",
    "CWE-282/862 授权默认放行叠加上下文状态直写": "CWE-862 Missing Authorization",
    "CWE-15: 外部可控的系统配置（用户注解覆盖安全敏感 webhook 配置）":
        "CWE-15 External Control of System or Configuration Setting",
    "CWE-93: Improper Neutralization of CRLF Sequences in HTTP Headers (Email Header Injection)":
        "CWE-93 CRLF Injection",
    "CWE-918": "CWE-918 Server-Side Request Forgery (SSRF)",
    "CWE-20 输入未正确验证（Improper Input Validation），导致 CWE-400/CWE-789 拒绝服务":
        "CWE-20 Improper Input Validation",
    "CWE-770 / CWE-400 资源分配缺乏限制（输入长度校验不一致）":
        "CWE-770 Allocation of Resources Without Limits",
}
# 违规形态（对齐 a1 审计的 18 条）：纯编号无漏洞名 / 编号后冒号分隔 / 编号后直接"/编号"合并。
# 注意：官方英文名内的斜杠（如 Include/Require）与"/ 补充说明"不算违规。
def vt_bad_form(vt: str) -> bool:
    return (re.fullmatch(r"CWE-\d+", vt) is not None
            or re.match(r"CWE-\d+\s*[:：]", vt) is not None
            or re.search(r"CWE-\d+\s*/\s*(?:CWE-)?\d+", vt) is not None)
vt_fixed = []
vt_unmapped = []
for i, rec in rows:
    a = get(rec["messages"], "assistant")
    _, o = last_json_object(a)
    if not isinstance(o, dict):
        continue
    vt = o.get("vulnerability_type")
    if not isinstance(vt, str) or vt in ("none", ""):
        continue
    if not vt_bad_form(vt):
        continue
    new_vt = VT_MAP.get(vt)
    if new_vt is None:
        # 冒号形态兜底：取首个 CWE 编号 + 官方名查表
        m = re.match(r"^CWE-(\d+)", vt)
        if m:
            fallback = f"CWE-{m.group(1)}"
            if fallback in VT_MAP and not re.search(r"CWE-\d+\s*/\s*(?:CWE-)?\d+", vt):
                new_vt = VT_MAP[fallback]
    if new_vt is None:
        vt_unmapped.append((i, vt))
        continue
    _, o2 = last_json_object(get(rec["messages"], "assistant"))
    o2["vulnerability_type"] = new_vt
    rec["messages"][2]["content"] = replace_last_json(
        get(rec["messages"], "assistant"), json.dumps(o2, ensure_ascii=False))
    vt_fixed.append((i, vt, new_vt))
P(f"  已归一 {len(vt_fixed)} 条:")
for i, old, new in vt_fixed:
    P(f"    line {i}: {old!r} -> {new!r}")
if vt_unmapped:
    P(f"  !! 未映射 {len(vt_unmapped)} 条（人工处理）:")
    for i, vt in vt_unmapped:
        P(f"    line {i}: {vt!r}")

# =================================================================
# 步骤 3 [P0-4] 6 条矛盾标签剔除
# =================================================================
P("\n" + "=" * 78)
P("[步骤3] P0-4 矛盾标签样本剔除（has_vulnerability=true 但 source/sink/explanation 自述无漏洞；")
P("        探查确认正文行号与 user 代码错位，翻转/重建均会残留错误，取报告备选方案'直接剔除'）")
P("=" * 78)
CONTRA_LINES = [608, 1309, 1323, 1358, 1430, 1432]
drop_contra = set()
for i in CONTRA_LINES:
    rec = R[i]
    u = get(rec["messages"], "user")
    _, o = last_json_object(get(rec["messages"], "assistant"))
    MANIFEST.append({
        "orig_line": i, "reason": "contradictory_label",
        "kind": (rec.get("meta") or {}).get("kind", "fix_distill"),
        "has_vulnerability": o.get("has_vulnerability") if isinstance(o, dict) else None,
        "vulnerability_type": o.get("vulnerability_type") if isinstance(o, dict) else None,
        "note": "JSON true 但 source/sink/explanation 自述无漏洞；正文引用行号与 user 代码错位（蒸馏上下文丢失）。"
                "重蒸馏时应重跑全文分析。",
        "user": u,
    })
    drop_contra.add(i)
P(f"  已标记剔除 {len(drop_contra)} 条: {sorted(drop_contra)}")

# =================================================================
# 步骤 4 [P0-1] risk_level 归一化（none -> None）
# =================================================================
P("\n" + "=" * 78)
P("[步骤4] P0-1 risk_level 归一化")
P("=" * 78)
risk_fixed = 0
risk_bad = []
for i, rec in rows:
    a = get(rec["messages"], "assistant")
    _, o = last_json_object(a)
    if not isinstance(o, dict):
        continue
    rl = o.get("risk_level")
    if rl == "none":
        o["risk_level"] = "None"
        rec["messages"][2]["content"] = replace_last_json(a, json.dumps(o, ensure_ascii=False))
        risk_fixed += 1
    elif rl is None or rl == "":
        if i not in transcribed:  # 转写过的已修复
            risk_bad.append(i)
    elif rl not in VALID_RISK:
        risk_bad.append((i, rl))
P(f"  小写 none -> None: {risk_fixed} 条")
P(f"  仍异常的 risk_level: {risk_bad if risk_bad else '无'}")

# =================================================================
# 步骤 5 [P1-7] 删除契约外字段 cvss_vector / cvss_score / fix_code
# =================================================================
P("\n" + "=" * 78)
P("[步骤5] P1-7 删除多余字段")
P("=" * 78)
extra_removed = Counter()
for i, rec in rows:
    a = get(rec["messages"], "assistant")
    _, o = last_json_object(a)
    if not isinstance(o, dict):
        continue
    ex = [k for k in o if k not in CONTRACT_FIELDS]
    if not ex:
        continue
    for k in ex:
        del o[k]
    rec["messages"][2]["content"] = replace_last_json(a, json.dumps(o, ensure_ascii=False))
    extra_removed[tuple(sorted(ex))] += 1
for k, v in extra_removed.most_common():
    P(f"  删除字段 {k}: {v} 条")
P(f"  合计清理 {sum(extra_removed.values())} 条")

# =================================================================
# 步骤 6 [P0-6] explanation=N/A 从分析正文结论提取
# =================================================================
P("\n" + "=" * 78)
P("[步骤6] P0-6 explanation=N/A 提取修复（空壳样本稍后整体剔除，此处跳过）")
P("=" * 78)
SHELL_VAGUE = [
    r"^检查用户可控输入点", r"^追踪输入到 sink 的路径", r"^N/A[，,]?\s*需判断",
    r"^识别代码中的用户输入点与处理逻辑", r"^N/A$", r"^未发现漏洞",
    r"^代码是安全的", r"^无$",
]

def shell_steps(body: str):
    lines = [l for l in body.split("\n") if re.match(r"^\s*\d+\.\s*", l)]
    if not lines:
        return 0, 0
    sh = 0
    for l in lines:
        m = re.match(r"^\s*\d+\.\s*([^：:]{2,20})[：:]\s*(.*)$", l)
        if not m:
            continue
        tail = m.group(2).strip()
        if any(re.search(p, tail) for p in SHELL_VAGUE):
            sh += 1
    return len(lines), sh

expl_fixed, expl_failed, shell_lines = [], [], []
for i, rec in rows:
    a = get(rec["messages"], "assistant")
    body = a.split("```json")[0] if "```json" in a else a
    tot, sh = shell_steps(body)
    is_shell = tot > 0 and sh >= 2
    if is_shell:
        shell_lines.append(i)
    _, o = last_json_object(a)
    if not isinstance(o, dict):
        continue
    if str(o.get("explanation", "")).strip() not in ("N/A", "n/a", ""):
        continue
    if is_shell:
        continue  # 空壳将被剔除，不处理
    m = list(re.finditer(r"结论[：:]\s*(\S.*)", body))
    if not m:
        expl_failed.append((i, "无结论步骤"))
        continue
    text = m[-1].group(1).strip().rstrip("。")
    if len(text) < 6:
        expl_failed.append((i, f"结论过短: {text!r}"))
        continue
    if len(text) > 400:
        expl_failed.append((i, f"结论过长({len(text)}字)"))
        continue
    o["explanation"] = text + "。"
    rec["messages"][2]["content"] = replace_last_json(a, json.dumps(o, ensure_ascii=False))
    expl_fixed.append(i)
P(f"  空壳分析样本（>=2 条空壳步骤）: {len(shell_lines)} 条（步骤9剔除）")
P(f"  explanation 提取修复: {len(expl_fixed)} 条")
if expl_fixed:
    P(f"    行号样例: {expl_fixed[:10]} ... {expl_fixed[-5:]}")
    i0 = expl_fixed[0]
    P(f"    样例 line {i0}: {last_json_object(get(R[i0]['messages'], 'assistant'))[1].get('explanation')!r}")
P(f"  提取失败（进重蒸馏清单）: {len(expl_failed)} 条")
for i, why in expl_failed[:10]:
    P(f"    line {i}: {why}")
for i, why in expl_failed:
    rec = R[i]
    MANIFEST.append({
        "orig_line": i, "reason": "explanation_na",
        "kind": (rec.get("meta") or {}).get("kind", "base"),
        "note": f"explanation=N/A 且分析正文无法提取结论（{why}），需教师补写结论摘要。",
        "user": get(rec["messages"], "user"),
    })

# =================================================================
# 步骤 7 [P1-8] source/sink 行号校验 + 保守自动修正
# =================================================================
P("\n" + "=" * 78)
P("[步骤7] P1-8 行号-内容校验与保守修正（仅唯一候选时修；多候选/无候选进复核清单）")
P("=" * 78)
STOP_TOKENS = {"line", "none", "http", "https", "null", "true", "false"}

def code_lines(user: str):
    d = {}
    for m in re.finditer(r"^\s*(\d+)\|(.*)$", user, re.M):
        d[int(m.group(1))] = m.group(2)
    return d

def desc_hit(code: str, tokens):
    return any(t in code or t.split(".")[-1] in code for t in tokens)

lineno_fixed, lineno_multi, lineno_nocand = [], [], []
for i, rec in rows:
    a = get(rec["messages"], "assistant")
    _, o = last_json_object(a)
    if not isinstance(o, dict) or o.get("has_vulnerability") is not True:
        continue
    u = get(rec["messages"], "user")
    lines = code_lines(u)
    if not lines:
        continue
    for fld in ("source", "sink"):
        v = str(o.get(fld, ""))
        m = re.search(r"line\s*(\d+)", v)
        if not m:
            continue
        if re.match(r"line\s*\d+\s*[-–~]", v[m.start():]):
            continue  # "line 419-421" 等范围锚点不自动修
        ln = int(m.group(1))
        if ln not in lines:
            continue
        desc = v[m.end():].lstrip(" :：")
        # 多锚点时截到下一个锚点
        m2 = re.search(r"[；;。]|\bline\s+\d+", desc)
        if m2:
            desc = desc[: m2.start()]
        tokens = [t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_.\-]{3,}", desc)
                  if t.lower().rstrip(".-") not in STOP_TOKENS and len(t) >= 4]
        tokens.sort(key=len, reverse=True)
        if not tokens:
            continue
        if desc_hit(lines[ln], tokens):
            continue  # 原锚点命中（宽松判定），不动
        fixed = False
        for t in tokens[:3]:
            t_main = t.rstrip(".")
            cand = [n for n, c in lines.items()
                    if t_main in c or t_main.split(".")[-1] in c]
            if len(cand) == 1 and cand[0] != ln:
                new_v = v.replace(f"line {ln}:", f"line {cand[0]}:", 1)
                o[fld] = new_v
                rec["messages"][2]["content"] = replace_last_json(
                    get(rec["messages"], "assistant"), json.dumps(o, ensure_ascii=False))
                lineno_fixed.append((i, fld, ln, cand[0], t, desc[:60]))
                a = get(rec["messages"], "assistant")
                _, o = last_json_object(a)
                fixed = True
                break
            if len(cand) >= 2:
                lineno_multi.append((i, fld, ln, t, cand[:6]))
                fixed = True  # 已归档，不再尝试更短 token
                break
        if not fixed:
            lineno_nocand.append((i, fld, ln, tokens[0] if tokens else "", desc[:60]))
for i, fld, ln, new_ln, tok, desc in lineno_fixed:
    P(f"  修正 line {i} {fld}: line {ln} -> line {new_ln}（依据 {tok!r}; {desc!r}）")
P(f"  合计自动修正: {len(lineno_fixed)} 处；多候选待人工: {len(lineno_multi)}；无候选待人工: {len(lineno_nocand)}")
for rec_list, note in ((lineno_multi, "多候选"), (lineno_nocand, "无候选")):
    for item in rec_list:
        i, fld, ln = item[0], item[1], item[2]
        LINENO_REVIEW.append({
            "orig_line": i, "field": fld, "annotated_line": ln,
            "issue": note, "detail": json.dumps(item[3:], ensure_ascii=False),
            "user": get(R[i]["messages"], "user"),
        })

# =================================================================
# 步骤 8 [P2-18] system prompt 规范放宽（source/sink/fix 允许锚定说明）
# =================================================================
P("\n" + "=" * 78)
P("[步骤8] P2-18 安全样本 source/sink/fix 规范放宽（全库 system 同步更新）")
P("=" * 78)
OLD_SRC = "   - source: str, 行号锚定的污染来源（如 'line 3: request.args.get(\"id\")'）；无漏洞填 'N/A'\n"
NEW_SRC = ("   - source: str, 行号锚定的污染来源（如 'line 3: request.args.get(\"id\")'）；无漏洞填 'N/A'，"
           "若存在看似危险但输入不可控的入口，可改为锚定说明（如 'line 7: subprocess.run()（但输入为常量，不可控）'）\n")
OLD_SNK = "   - sink: str, 行号锚定的危险点（如 'line 5: cursor.execute'）；无漏洞填 'N/A'\n"
NEW_SNK = ("   - sink: str, 行号锚定的危险点（如 'line 5: cursor.execute'）；无漏洞填 'N/A'，"
           "若存在看似危险但输入不可控的 sink，可改为锚定说明（如 'line 7: os.system()（但输入为常量，不可控）'）\n")
OLD_FIX = "   - fix_suggestion: str, 最小局部改正：只给应修改的具体行+改法即可（单行、行号须真实存在、禁止输出完整代码/补丁/代码块）；无漏洞填 'no fix needed'\n"
NEW_FIX = ("   - fix_suggestion: str, 最小局部改正：只给应修改的具体行+改法即可（单行、行号须真实存在、禁止输出完整代码/补丁/代码块）；"
           "无漏洞填 'no fix needed'，可选追加一句简短加固建议（不含代码块）\n")

sys_updated = 0
sys_mismatch = []
for i, rec in rows:
    s = get(rec["messages"], "system")
    if MAIN_SYSTEM not in s and OLD_SRC not in s:
        sys_mismatch.append(i)
        continue
    s2 = s.replace(OLD_SRC, NEW_SRC).replace(OLD_SNK, NEW_SNK).replace(OLD_FIX, NEW_FIX)
    if s2 != s:
        rec["messages"][0]["content"] = s2
        sys_updated += 1
P(f"  system 规范更新: {sys_updated} 条")
P(f"  未匹配主 system 的记录: {sys_mismatch if sys_mismatch else '无'}")

# =================================================================
# 步骤 9 剔除集合：独白 / 空壳 / 重复组 / 1-shot CWE / 矛盾
# =================================================================
P("\n" + "=" * 78)
P("[步骤9] 剔除集合计算（教师独白 / 空壳 / 重复 assistant 组 / 1-shot CWE / 矛盾标签）")
P("=" * 78)
# 9a 教师独白：报告 13 条 + a2[D]/a3[1] 同病灶超长英文独白 5 条
MONO = [8760, 8764, 8766, 8779, 8780, 8781, 8797, 8800, 8806, 8809, 8826, 8863, 8868,
        8774, 8776, 8810, 8813, 8843]
drop_mono = set(MONO)
for i in sorted(drop_mono):
    rec = R[i]
    kind = (rec.get("meta") or {}).get("kind", "base")
    MANIFEST.append({
        "orig_line": i, "reason": "teacher_monologue",
        "kind": kind,
        "note": "assistant 为英文教师独白（Actually/Hmm/Let me... + 元话语泄漏），超长且 2 条 JSON 失效。"
                "重蒸馏后补回该 task_key 的跨文件安全对照。",
        "user": get(rec["messages"], "user"),
    })
P(f"  9a 教师独白: {len(drop_mono)} 条（含 JSON 解析失败的 8797/8826）")

# 9b 空壳分析
drop_shell = set(shell_lines)
P(f"  9b 空壳分析: {len(drop_shell)} 条")
for i in sorted(drop_shell):
    rec = R[i]
    MANIFEST.append({
        "orig_line": i, "reason": "shell_analysis",
        "kind": (rec.get("meta") or {}).get("kind", "base"),
        "note": "分析步骤只复述步骤名（伪推理 + '代码命中安全模式白名单'元信息泄漏），需教师重蒸馏。",
        "user": get(rec["messages"], "user"),
    })

# 9c assistant 全文重复组（去空白 md5；空壳已含 x72/x52，此处兜底清 x3/x2 组）
dup = defaultdict(list)
for i, rec in rows:
    a = get(rec["messages"], "assistant")
    dup[hashlib.md5(re.sub(r"\s+", "", a).encode()).hexdigest()].append(i)
dup_groups = [g for g in dup.values() if len(g) > 1]
drop_dup = set()
for g in dup_groups:
    drop_dup.update(g)
resid = sorted(drop_dup - drop_shell - drop_mono - drop_contra)
P(f"  9c assistant 全文重复组: {len(dup_groups)} 组 {len(drop_dup)} 条；其中空壳/独白外残余 {len(resid)} 条")
if resid:
    P(f"     残余行号: {resid}")
for i in sorted(drop_dup - drop_shell - drop_mono - drop_contra):
    rec = R[i]
    MANIFEST.append({
        "orig_line": i, "reason": "duplicate_assistant",
        "kind": (rec.get("meta") or {}).get("kind", "base"),
        "note": "与其它样本 assistant 全文相同（模板坍塌残余组），需教师重蒸馏。",
        "user": get(rec["messages"], "user"),
    })

# 9d 1-shot CWE（报告口径：vulnerability_type 中 findall 全计数==1）
cwe_all = Counter()
cwe_lines = defaultdict(list)
for i, rec in rows:
    _, o = last_json_object(get(rec["messages"], "assistant"))
    if not isinstance(o, dict):
        continue
    vt = str(o.get("vulnerability_type", ""))
    for c in set(re.findall(r"CWE-(\d+)", vt)):
        cwe_all[c] += 1
        cwe_lines[c].append(i)
oneshot = {c for c, n in cwe_all.items() if n == 1}
drop_oneshot = {i for c in oneshot for i in cwe_lines[c]}
P(f"  9d 1-shot CWE: {len(oneshot)} 种 {sorted('CWE-' + c for c in oneshot)}")
P(f"     -> 剔除 {len(drop_oneshot)} 条: {sorted(drop_oneshot)}")
for i in sorted(drop_oneshot):
    rec = R[i]
    hit = [c for c in oneshot if i in cwe_lines[c]]
    MANIFEST.append({
        "orig_line": i, "reason": "oneshot_cwe",
        "kind": (rec.get("meta") or {}).get("kind", "base"),
        "note": f"{'/'.join(sorted('CWE-' + c for c in hit))} 全库仅 1 条，学不会只会乱猜；从训练集剔除，评测时作未知类。",
        "user": get(rec["messages"], "user"),
    })

drop_all = drop_mono | drop_shell | drop_dup | drop_oneshot | drop_contra
hv_drop = Counter()
for i in drop_all:
    _, o = last_json_object(get(R[i]["messages"], "assistant"))
    hv = o.get("has_vulnerability") if isinstance(o, dict) else None
    hv_drop[str(hv)] += 1
P(f"  剔除合计: {len(drop_all)} 条（去重后），正负构成: {dict(hv_drop)}")

# =================================================================
# 写出
# =================================================================
kept = [(i, rec) for i, rec in rows if i not in drop_all]
with OUT_DATA.open("w", encoding="utf-8") as f:
    for i, rec in kept:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
seen_ml = set()
MANIFEST_DEDUP = []
for m in MANIFEST:
    if m["orig_line"] in seen_ml:
        continue
    seen_ml.add(m["orig_line"])
    MANIFEST_DEDUP.append(m)
MANIFEST = MANIFEST_DEDUP
with OUT_MANIFEST.open("w", encoding="utf-8") as f:
    for m in MANIFEST:
        f.write(json.dumps(m, ensure_ascii=False) + "\n")
with OUT_LINENO.open("w", encoding="utf-8") as f:
    for m in LINENO_REVIEW:
        f.write(json.dumps(m, ensure_ascii=False) + "\n")

P("\n" + "=" * 78)
P("[输出]")
P("=" * 78)
P(f"  v2_13: {OUT_DATA}  {len(kept)} 条（v2_12 {n_total} - 剔除 {len(drop_all)}）")
P(f"  重蒸馏清单: {OUT_MANIFEST}  {len(MANIFEST)} 条")
P(f"  行号复核清单: {OUT_LINENO}  {len(LINENO_REVIEW)} 条")

# =================================================================
# 自检
# =================================================================
P("\n" + "=" * 78)
P("[自检] 对 v2_13 复跑关键审计")
P("=" * 78)
risk_cnt = Counter()
extra_cnt = Counter()
vt_bad = []
parse_fail = []
sys_kinds = Counter()
hv_cnt = Counter()
dup2 = defaultdict(int)
no_anchor = 0
vuln_n = 0
for i, rec in kept:
    msgs = rec["messages"]
    s = get(msgs, "system")
    sys_kinds[hashlib.md5(s.encode()).hexdigest()[:10]] += 1
    a = get(msgs, "assistant")
    dup2[hashlib.md5(re.sub(r"\s+", "", a).encode()).hexdigest()] += 1
    blk, o = last_json_object(a)
    if not isinstance(o, dict):
        parse_fail.append(i)
        continue
    hv_cnt[str(o.get("has_vulnerability"))] += 1
    risk_cnt[str(o.get("risk_level"))] += 1
    for k in o:
        if k not in CONTRACT_FIELDS:
            extra_cnt[k] += 1
    vt = str(o.get("vulnerability_type", ""))
    if vt != "none" and vt_bad_form(vt):
        vt_bad.append((i, vt))
    if o.get("has_vulnerability") is True:
        vuln_n += 1
        for fld in ("source", "sink"):
            if not re.search(r"line\s*\d+", str(o.get(fld, ""))):
                no_anchor += 1
dup_groups2 = sum(1 for v in dup2.values() if v > 1)
P(f"  条数: {len(kept)}")
P(f"  risk_level 分布: {dict(risk_cnt)}")
P(f"  多余字段: {dict(extra_cnt) if extra_cnt else '无'}")
P(f"  vt 非规范: {len(vt_bad)} {vt_bad[:5]}")
P(f"  JSON 解析失败: {len(parse_fail)}")
P(f"  system 种类: {dict(sys_kinds)}")
P(f"  assistant 重复组: {dup_groups2}")
P(f"  正负: {dict(hv_cnt)}  漏洞样本 {vuln_n}")
P(f"  漏洞样本 source/sink 无 line 锚点: {no_anchor}")

OUT_LOG.write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("repair done ->", OUT_DATA.name)
