# -*- coding: utf-8 -*-
"""g25 safe 侧防御演示机检(入库前)。

期望:全部 has_vulnerability=False(safe);explanation 引用文件内具体防御代码
(配置/开关 = "安全配置项被显式设置→攻击面关闭";realpath = 归一+前缀校验),
不得把有效防御当漏洞。safe 样本若判 vuln → 标注需人工复核(样本本身经独立审查
确认无洞,若教师判 vuln 说明仍不识别该防御,是教学要修正的行为)。

输出: audit/adjudicate_v2_15/verify_g25_out.txt
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]  # exp_06_finetune/
OUT_DIR = BASE / "corpus/repair_wave/_wave1_out_g25"
OUT_LOG = BASE / "audit/adjudicate_v2_15/verify_g25_out.txt"
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)

# 防御锚句(explanation 应体现;匹配其一即认为引用了防御,宽松判定)
CFG_ANCHOR = ["安全配置", "配置", "显式", "verify", "白名单", "allowlist", "校验",
              "校验证书", "SafeLoader", "shell=False", "ObjectInputFilter", "严格校验",
              "默认校验", "攻击面关闭", "内部", "可信"]
RP_ANCHOR = ["realpath", "real path", "归一", "前缀", "EvalSymlinks", "toRealPath",
             "getCanonicalPath", "canonical", "符号链接", "symlink", "startswith",
             "startsWith", "HasPrefix", "攻击面关闭", "校验"]

LOG = []
def P(*a):
    s = " ".join(str(x) for x in a)
    LOG.append(s)
    print(s, flush=True)

def main():
    sp = OUT_DIR / "success.jsonl"
    rp = OUT_DIR / "rejects.jsonl"
    if not sp.exists():
        P("!! success.jsonl 不存在")
        return
    recs = [json.loads(l) for l in sp.open(encoding="utf-8") if l.strip()]
    P(f"g25 产出 {len(recs)} 条")
    if rp.exists():
        rej = [json.loads(l) for l in rp.open(encoding="utf-8") if l.strip()]
        P(f"拒收 {len(rej)} 条:")
        for j in rej:
            P(f"  {j.get('orig')}: {str(j.get('reject'))[:90]}")

    verdict = Counter()
    problems = []
    for r in recs:
        o = r.get("fix_distill", {}).get("orig", "")
        # 判断是 cfg 还是 rp(默认按锚句集合)
        is_rp = str(o).startswith("g25-rp")
        anchors = RP_ANCHOR if is_rp else CFG_ANCHOR
        blk = JSON_BLOCK.findall(r["messages"][2]["content"])
        if not blk:
            problems.append(f"{o}: 无 JSON 块")
            verdict["FAIL"] += 1
            continue
        try:
            j = json.loads(blk[-1])
        except Exception as e:
            problems.append(f"{o}: JSON 解析失败 {e}")
            verdict["FAIL"] += 1
            continue
        hv = str(j.get("has_vulnerability"))
        expl = str(j.get("explanation", ""))
        issues = []
        if hv != "False":
            issues.append(f"hv={hv}(期望 safe/False)")
        hit = any(a.lower() in expl.lower() for a in anchors)
        if not hit:
            issues.append("explanation 未引用防御锚句")
        # safe 侧不应给高危 vuln 类型
        vt = str(j.get("vulnerability_type", ""))
        m = re.search(r"CWE[-_]?(\d+)", vt)
        if hv == "False" and m and m.group(1) != "none":
            issues.append(f"safe 却标了类型 {vt[:30]}")
        if issues:
            verdict["FAIL"] += 1
            problems.append(f"{o} [{is_rp and 'rp' or 'cfg'}]: " + "; ".join(issues))
        else:
            verdict["PASS"] += 1

    P("")
    P(f"== g25 机检汇总: PASS {verdict['PASS']} / FAIL {verdict['FAIL']} ==")
    for p in problems:
        P("  " + p)
    OUT_LOG.write_text("\n".join(LOG) + "\n", encoding="utf-8")

if __name__ == "__main__":
    main()
