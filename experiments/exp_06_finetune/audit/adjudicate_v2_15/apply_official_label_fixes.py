# -*- coding: utf-8 -*-
"""P0 按官方口径修正测试集错标(9 处),来源: audit/官方口径测试集审查_CWE判别要点_20260902.md

rolling_dev 6 处(全部有 NVD API / GHSA advisory 官方字段背书):
  corpus_00001.js 89   -> 94   (JSONata 表达式执行任意代码,NVD 官方)
  corpus_00002.py 89   -> 95   (Xinference eval(model_output),NVD 官方)
  corpus_00003.go 1336 -> 150  (终端 ANSI/OSC 转义序列注入,GHSA-x3g7-qrwc-f6c5)
  corpus_00004.php 1336-> 639  (绕过文件名随机化下载他人文件=IDOR,NVD 官方)
  corpus_00005.java 1336->862  (edit 权限->script 提权=缺失授权,GHSA-45ph-gxxr-gwgw)
  corpus_00053.php 352 -> 502  (主洞 unserialize 对象注入,GHSA-9369-69wj-7m2f)
exp04 复合标签修剪 3 处(删标签,非改标签):
  hard_bypass_07_ssti_attr_chain.py 删 91(无 XML/XPath)
  typical_23_ssti.py                删 915(无动态属性赋值)
  typical_24_ldap_injection.py      删 797(无绝对位置过滤)
幂等:已改过则跳过。备份先行,并写 _changelog。
"""
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

E6 = Path(__file__).resolve().parents[2]          # exp_06_finetune/
EXP = Path(__file__).resolve().parents[3]         # experiments/
RD = E6 / "corpus/rolling_dev/manifest.json"
E4 = EXP / "exp_04_hard_samples/samples/manifest.json"
DATE = "2026-09-02"

RD_FIX = {
    "corpus_00001.js":  ("CWE-94",  "NVD API 官方标签;JSONata 表达式执行任意代码,与 SQL 无关"),
    "corpus_00002.py":  ("CWE-95",  "NVD API 官方标签;Xinference eval(model_output)=eval 注入"),
    "corpus_00003.go":  ("CWE-150", "GHSA-x3g7-qrwc-f6c5 官方字段=150;终端转义序列注入非模板引擎"),
    "corpus_00004.php": ("CWE-639", "NVD API 官方标签;用户可控 key 越权下载=IDOR"),
    "corpus_00005.java": ("CWE-862", "GHSA-45ph-gxxr-gwgw 官方字段=862;edit->script 提权=缺失授权"),
    "corpus_00053.php": ("CWE-502", "GHSA-9369-69wj-7m2f 官方字段=502;主洞 unserialize 对象注入,CSRF 仅投递链"),
}

# exp04: (目标文件名片段, 需删除的标签, 理由)
E4_FIX = [
    ("hard_bypass_07_ssti_attr_chain.py", "CWE-91",  "CWE-91=XML/Blind XPath 注入,样本无 XML"),
    ("typical_23_ssti.py",                "CWE-915", "CWE-915=mass assignment,样本无动态属性赋值"),
    ("typical_24_ldap_injection.py",      "CWE-797", "CWE-797 要求仅在绝对位置过滤,样本无过滤"),
]

def backup(p):
    b = p.with_suffix(p.suffix + f".bak_{DATE}_officialfix")
    if not b.exists():
        shutil.copy(p, b)
        print(f"  备份 -> {b.name}")

def norm_tags(v):
    return [t.strip() for t in str(v).split(";") if t.strip()]

def main():
    changed_rd, changed_e4 = [], []

    # ---- rolling_dev ----
    d = json.loads(RD.read_text(encoding="utf-8"))
    for s in d["samples"]:
        f = s["file"]
        if f in RD_FIX:
            new, why = RD_FIX[f]
            old = s.get("expected_cwe")
            if str(old) == new:
                print(f"  {f}: 已是 {new},跳过")
                continue
            backup(RD)
            s["expected_cwe"] = new
            s.setdefault("_label_basis", "nvd/ghsa-official")
            s.setdefault("_label_note", why)
            changed_rd.append((f, old, new))
    if changed_rd:
        d.setdefault("_changelog", []).append({
            "date": DATE,
            "action": "按 MITRE v4.20 官方定义 + NVD API/GHSA advisory 官方字段修正 6 处错标",
            "source": "audit/官方口径测试集审查_CWE判别要点_20260902.md §二",
            "changes": [{"file": f, "from": str(o), "to": n} for f, o, n in changed_rd],
        })
        RD.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
        for f, o, n in changed_rd:
            print(f"  rolling_dev {f}: {o} -> {n}")

    # ---- exp04 复合标签修剪 ----
    e = json.loads(E4.read_text(encoding="utf-8"))
    items = e.get("samples", [])
    for frag, drop, why in E4_FIX:
        for s in items:
            fn = s.get("file") or s.get("name") or ""
            if frag not in fn:
                continue
            old = str(s.get("expected_cwe", ""))
            tags = norm_tags(old)
            if drop not in tags:
                print(f"  {fn}: 无 {drop},跳过")
                continue
            backup(E4)
            tags = [t for t in tags if t != drop]
            s["expected_cwe"] = "; ".join(tags)
            s.setdefault("_label_note", why)
            changed_e4.append((fn, old, s["expected_cwe"]))
            print(f"  exp04 {fn}: {old} -> {s['expected_cwe']}  (删 {drop})")
    if changed_e4:
        e.setdefault("_changelog", []).append({
            "date": DATE,
            "action": "按官方语义修剪 3 处复合标签中的不成立标签(仅删不改)",
            "source": "audit/官方口径测试集审查_CWE判别要点_20260902.md §二",
            "changes": [{"file": f, "from": o, "to": n} for f, o, n in changed_e4],
        })
        E4.write_text(json.dumps(e, ensure_ascii=False, indent=2), encoding="utf-8")

    print()
    print(f"完成: rolling_dev {len(changed_rd)} 处 / exp04 {len(changed_e4)} 处")

if __name__ == "__main__":
    main()
