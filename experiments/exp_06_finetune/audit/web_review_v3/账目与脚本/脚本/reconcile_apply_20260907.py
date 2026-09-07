# -*- coding: utf-8 -*-
"""2026-09-07 对账执行: 删 7261 + 重建 7271/7455 + changelog。前置: snapshot_v2_15_pre_reconcile_20260907.jsonl"""
import json, re, sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parents[4]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
lines = DATA.read_text(encoding="utf-8").split("\n")
n_before = sum(1 for l in lines if l.strip())
log = []

# ---- 1) 删除 7261 (L7202, pack_21 代码全等) ----
pack21 = (BASE / "audit/web_review_v3/pack_21.txt").read_text(encoding="utf-8")
b21 = next(x for x in re.split(r"(?=### id=\d+)", pack21) if x.startswith("### id=7261"))
c21 = "\n".join(re.sub(r"^\s*\d+\| ?", "", l) for l in re.search(r"\[CODE\]\n(.*?)(?=\n\n|\Z)", b21, re.S).group(1).split("\n")).strip()
rec = json.loads(lines[7202 - 1])
fu = re.search(r"```[\w]*\n(.*?)```", rec["messages"][1]["content"], re.S)
assert fu and fu.group(1).strip() == c21, "7261 验证失败，中止"
del lines[7202 - 1]
log.append({
    "action": "DELETE", "id": 7261, "line_before_delete": 7202,
    "policy": "batch_20_30 DELETE(假阳性major: rclone本地后端按设计接受用户路径,无跨信任边界输入面;正文行号系统性偏移) 取代 v1 KEEP",
    "verified": "pack_21 code exact-match",
})

# ---- 2) 重建 7271 / 7455 并追加 ----
SYS = json.loads(lines[0])["messages"][0]["content"]

def rebuild(packfile, wid):
    pack = (BASE / "audit/web_review_v3" / packfile).read_text(encoding="utf-8")
    blocks = re.split(r"(?=### id=\d+)", pack)
    b_code = next(x for x in blocks if x.startswith(f"### id={wid} lang="))
    b_ans = next(x for x in blocks if x.startswith(f"### id={wid} teacher=") and "[ANALYSIS]" in x)
    lang = re.search(r"### id=\d+ lang=([\w+#.\-/]+)", b_code).group(1)
    numbered = re.search(r"\[CODE\]\n(.*?)(?=\n\n████|\n\n###|\Z)", b_code, re.S).group(1)
    code = "\n".join(re.sub(r"^\s*\d+\| ?", "", l) for l in numbered.split("\n")).strip()
    ans = re.search(r"\[ANALYSIS\]\n(.*?)\n\[JSON\]\n(\{.*\})", b_ans, re.S)
    body, jtxt = ans.group(1).strip(), ans.group(2).strip()
    o = json.loads(jtxt)
    assistant = body + "\n\n```json\n" + json.dumps(o, ensure_ascii=False) + "\n```"
    user = f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```"
    return {"messages": [{"role": "system", "content": SYS},
                          {"role": "user", "content": user},
                          {"role": "assistant", "content": assistant}]}

for packfile, wid, reason, pol in [
    ("pack_24.txt", 7271,
     "batch_20_30: 教师判safe实为SSRF(默认跟随重定向/::ffff:127.0.0.1/0.0.0.0三重绕过黑名单), critical假阴性",
     "新政策:假阴性倾向FIX(补发现即可改好); wave2按旧政策DELETE, 本批从pack_24完整重建入待修"),
    ("pack_27.txt", 7455,
     "batch_20_30: 漏洞真实(动态键写入全局TRANSLATIONS), 应CWE-915, 教师'类污染链'影响叙事虚构需改写",
     "新政策: batch_20_30 FIX 取代 wave2 旧DELETE('类污染虚构'说); 本批从pack_27完整重建入待修"),
]:
    rec2 = rebuild(packfile, wid)
    json.dumps(rec2, ensure_ascii=False)
    lines.append(json.dumps(rec2, ensure_ascii=False))
    log.append({
        "action": "RESTORE", "id": wid, "append_at_record": n_before + sum(1 for x in log if x["action"] == "RESTORE") + 1,
        "policy": pol, "reason": reason, "verified": "pack代码完整重建, 记录json可解析",
    })

n_after = sum(1 for l in lines if l.strip())
DATA.write_text("\n".join(lines), encoding="utf-8")
(BASE / "audit/web_review_v3/reconcile_changelog_20260907.jsonl").write_text(
    "\n".join(json.dumps(x, ensure_ascii=False) for x in log), encoding="utf-8")
print(f"完成: {n_before} -> {n_after} 条 (期望 10162: -1删 +2恢复)")
for x in log:
    print(" ", x["action"], x["id"], "OK")
