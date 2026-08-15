# -*- coding: utf-8 -*-
"""α0.5 训练数据修正脚本。

输入：
  - 老部分 final_train_chatml_quality_final_fix.jsonl (7692)
  - 新增 supplement_*.jsonl (924, 6 文件)
输出：
  - data/final_train_chatml_alpha05_raw.jsonl  （修正但未去重/未骨架裁剪）

修正项（每一项都有独立开关与统计）：
  1. 删除测试集泄露样本（Jaccard >= 0.50 的 12 条，含 ssti_auth:32）
  2. 修正归因错误（JWT 无过期 287→613；MD5 287→327；eval/exec 917→94/95；open+exec 610→98）
  3. safe 硬矛盾改标签（has_vulnerability False→True，并补 verdict 字段）
  4. 清理 CoT 中的"题目要求/本题要求"类元注释
  5. 同码完全重复去重（归一化后）
说明：
  - 7 组"同码标签冲突"经人工裁决为"漏洞版 vs 修复版"正反样本对，非标签错误，保留。
  - supplement_samples 的骨架模板化在本脚本仅统计，实际按骨架去重放 alpha05 最终化阶段。
"""
import json, re, sys
from collections import defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(r"D:\code\毕业设计\Graduation-Project")
DATA = ROOT / "experiments" / "exp_06_finetune" / "data"
TESTSET = ROOT / "experiments" / "exp_04_hard_samples" / "samples"

OLD_FILE = "final_train_chatml_quality_final_fix.jsonl"
SUPP_FILES = [
    "supplement_samples.jsonl", "supplement_ssti_auth.jsonl",
    "supplement_mode_a.jsonl", "supplement_mode_b.jsonl",
    "supplement_mode_d.jsonl", "supplement_low_cwe.jsonl",
]
OUT = DATA / "final_train_chatml_alpha05_raw.jsonl"

CODE_RE = re.compile(r"```(?:\w+)?\n(.*?)```", re.S)
JSON_RE = re.compile(r"```json\s*(.*?)```", re.S)
CWE_RE = re.compile(r"CWE-(\d+)")

# ---------------- 归一化（与 GLM audit_train_full 一致） ----------------
COMMENT_RE = re.compile(r"(#[^\n]*|//[^\n]*|/\*.*?\*/)", re.S)
STR_RE = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`")
NUM_RE = re.compile(r"\b\d+\b")

def norm_lines(code):
    code = COMMENT_RE.sub(" ", code)
    code = STR_RE.sub("S", code)
    code = NUM_RE.sub("N", code)
    return [t for ln in code.splitlines() if (t := ln.strip()) and len(t) >= 4]

# ---------------- 骨架归一化（与 GLM audit_train_full 一致） ----------------
_KEEP = set("""if elif else for while def return class import from as try except finally with
lambda pass break continue raise yield async await const let var function new this self
none true false null nil undefined and or not in is
eval exec compile pickle marshal yaml json load loads dumps parse open read write send
request response args form cookies query body get post route render template
os sys subprocess popen system shell curl socket recv connect bind
flask django fastapi express app cursor execute query sql select insert update delete where
document window innerhtml html dom cookie localstorage fetch ajax axios
jwt token md5 sha1 sha256 hmac base64 secret key password user admin
hashlib crypto random uuid venv strip replace format join encode decode headers
int str list dict set tuple len range print
map filter reduce sort foreach instanceof typeof delete void enum struct public private static void
string integer boolean double float char
caasaa""".split())
ID_RE = re.compile(r"\b[A-Za-z_]\w*\b")

def skeleton(code):
    """骨架归一化：非保留标识符 → ID（用于模板去重）。"""
    code = COMMENT_RE.sub(" ", code)
    code = STR_RE.sub("S", code)
    code = NUM_RE.sub("N", code)
    return "\n".join(
        ID_RE.sub(lambda m: m.group(0) if m.group(0).lower() in _KEEP else "ID", ln.strip())
        for ln in code.splitlines() if ln.strip()
    )

# ---------------- 泄露清单（Jaccard>=0.50，来自 GLM 审计） ----------------
LEAKS = {
    ("ssti_auth", 32), ("old", 3391), ("old", 2337), ("old", 1934),
    ("old", 2329), ("old", 2328), ("old", 3394), ("old", 3412),
    ("old", 3415), ("old", 6541), ("old", 6562), ("mode_b", 36),
}

# ---------------- 归因错误修正（rule -> 应改 CWE 号） ----------------
# 模式判定与 GLM G 检测一致；CWE 号映射：
#   JWT 无过期 287 -> 613；MD5 287 -> 327；eval/exec 917 -> 94；open+exec 610 -> 98
def fix_misattr(verdict, code_l, cot_l, cot):
    """返回 (修正后 verdict, 是否修改, 说明)。按 G 规则逐条修。"""
    m = CWE_RE.search(verdict.get("vulnerability_type", "") or "")
    cwe = int(m.group(1)) if m else 0
    if cwe == 287 and ("jwt" in code_l or "jwt" in cot_l) and re.search(r"过期|expire|exp\b", cot_l):
        return _set_cwe(verdict, 613, "JWT 无过期 287→613"), True, "JWT 无过期 287→613"
    if cwe == 287 and ("md5" in code_l or "md5" in cot_l):
        return _set_cwe(verdict, 327, "MD5 弱哈希 287→327"), True, "MD5 弱哈希 287→327"
    if cwe == 917 and re.search(r"\beval\s*\(|\bexec\s*\(", code_l):
        return _set_cwe(verdict, 94, "eval/exec 917→94"), True, "eval/exec 917→94"
    if cwe == 610 and re.search(r"\bopen\s*\(", code_l) and re.search(r"\bexec\s*\(", code_l):
        return _set_cwe(verdict, 98, "open+exec 610→98"), True, "open+exec 610→98"
    return verdict, False, ""

def _set_cwe(verdict, new_cwe, new_name):
    vt = verdict.get("vulnerability_type", "") or ""
    new_vt = re.sub(r"CWE-\d+\s*", f"CWE-{new_cwe} ", vt, count=1).strip()
    verdict = dict(verdict)
    verdict["vulnerability_type"] = new_vt
    return verdict

# ---------------- safe 硬矛盾（CoT 明确写"CWE-x"却标 safe） ----------------
# 来自 GLM I_safe_hard：old 3642/3915/3949/6071
SAFE_HARD = {3642, 3915, 3949, 6071}

# ---------------- 元注释清理 ----------------
META_RE = re.compile(r"[。；\n]?\s*[（(]?(?:题目要求|本题要求|根据题目|按题目|题目设定|题目中)[^。\n]{0,40}[。；\n]?")
META_SIMPLE = re.compile(r"题目要求|本题要求|根据题目|按题目|题目设定|题目中")

# ---------------- 加载 ----------------
print("加载数据...")
all_samples = []  # (source, line, record, code, verdict, cot)
src_line = defaultdict(int)
for src, fname in [("old", OLD_FILE)] + [("samples", "supplement_samples.jsonl"),
                                          ("ssti_auth", "supplement_ssti_auth.jsonl"),
                                          ("mode_a", "supplement_mode_a.jsonl"),
                                          ("mode_b", "supplement_mode_b.jsonl"),
                                          ("mode_d", "supplement_mode_d.jsonl"),
                                          ("low_cwe", "supplement_low_cwe.jsonl")]:
    path = DATA / fname
    with path.open(encoding="utf-8") as fh:
        for i, ln in enumerate(fh):
            ln = ln.strip()
            if not ln:
                continue
            rec = json.loads(ln)
            msgs = rec["messages"]
            user, asst = msgs[1]["content"], msgs[2]["content"]
            cm = CODE_RE.search(user)
            jm = JSON_RE.search(asst)
            code = cm.group(1) if cm else ""
            verdict = None
            if jm:
                try:
                    verdict = json.loads(jm.group(1))
                except Exception:
                    verdict = None
            cot = asst[: jm.start()] if jm else asst
            src_line[src] += 1
            all_samples.append({"src": src, "line": src_line[src], "rec": rec,
                                "code": code, "verdict": verdict, "cot": cot, "asst": asst})
print(f"加载 {len(all_samples)} 条")

# ---------------- 逐项统计 ----------------
stats = {"leak": 0, "misattr": 0, "safe_hard": 0, "meta": 0, "dup": 0, "skel": 0}
kept = []
seen_norm = set()
seen_skel = set()

for s in all_samples:
    key = (s["src"], s["line"])
    # 1. 泄露删除
    if key in LEAKS:
        stats["leak"] += 1
        continue
    # 5. 同码完全重复去重（归一化后，同 label 保留首条）
    norm_key = "\n".join(norm_lines(s["code"]))
    label = (s["verdict"] or {}).get("has_vulnerability")
    if norm_key and (norm_key, label) in seen_norm:
        stats["dup"] += 1
        continue
    if norm_key:
        seen_norm.add((norm_key, label))

    # 5b. 骨架级去重（仅 supplement_samples：同骨架+同标签+同CWE 保留首条，消除模板过度复用）
    if s["src"] == "samples":
        sk = skeleton(s["code"])
        vm = CWE_RE.search((s["verdict"] or {}).get("vulnerability_type", "") or "")
        sk_cwe = vm.group(1) if vm else 0
        sk_key = (sk, label, sk_cwe)
        if sk_key in seen_skel:
            stats["skel"] += 1
            continue
        seen_skel.add(sk_key)

    rec = s["rec"]
    msgs = rec["messages"]
    verdict = s["verdict"]

    # 2. 归因错误修正
    if verdict:
        nv, changed, why = fix_misattr(verdict, s["code"].lower(), s["cot"].lower(), s["cot"])
        if changed:
            stats["misattr"] += 1
            verdict = nv
            # 重写 assistant 的 json block
            jm = JSON_RE.search(s["asst"])
            new_json = json.dumps(verdict, ensure_ascii=False)
            msgs[2]["content"] = s["asst"][: jm.start()] + "```json\n" + new_json + "\n```" + s["asst"][jm.end():]

    # 3. safe 硬矛盾改标签
    if s["src"] == "old" and s["line"] in SAFE_HARD and verdict:
        if verdict.get("has_vulnerability") is False:
            verdict = dict(verdict)
            verdict["has_vulnerability"] = True
            # 从 CoT 提取 CWE 作为 vulnerability_type
            cm2 = CWE_RE.search(s["cot"])
            verdict["vulnerability_type"] = f"CWE-{cm2.group(1)}" if cm2 else "CWE-79"
            verdict["risk_level"] = "High"
            jm = JSON_RE.search(s["asst"])
            new_json = json.dumps(verdict, ensure_ascii=False)
            msgs[2]["content"] = s["asst"][: jm.start()] + "```json\n" + new_json + "\n```" + s["asst"][jm.end():]
            stats["safe_hard"] += 1

    # 4. 元注释清理（仅删句子，不改 verdict）
    if META_SIMPLE.search(s["cot"]):
        new_asst = s["asst"]
        # 只清理 json block 之前的 CoT 文本
        jm = JSON_RE.search(new_asst)
        head = new_asst[: jm.start()] if jm else new_asst
        head_new = META_RE.sub("", head)
        head_new = re.sub(r"\n{3,}", "\n\n", head_new).strip()
        if head_new != head.strip():
            stats["meta"] += 1
            msgs[2]["content"] = head_new + ("\n\n" + new_asst[jm.start():] if jm else "")

    kept.append(rec)

print(f"修正统计: {stats}")
print(f"保留: {len(kept)} 条")

with OUT.open("w", encoding="utf-8") as fh:
    for rec in kept:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"写出 -> {OUT}")

# 修正后标签分布
from collections import Counter
lab = Counter()
for rec in kept:
    a = rec["messages"][2]["content"]
    jm = JSON_RE.search(a)
    if jm:
        try:
            lab[json.loads(jm.group(1)).get("has_vulnerability")] += 1
        except Exception:
            lab["parse"] += 1
print("修正后标签分布:", dict(lab))
