# -*- coding: utf-8 -*-
"""v2_16 清洗步骤 1.2：L1 官方标签机检全库化（方法论 §1.1 L1）。

数据集全部 CVE 绑定行提取唯一 CVE → 增量查 NVD 2.0 API（无 key 限速 6.5s/req）→
输出冲突清单（dataset cwe ∩ nvd cwes == ∅）。

与既有 nvd_check.py 的差异：
- 输入从 157 条抽查 dump 换成数据集全库（唯一 CVE 提取）；
- 结果续写到 nvd_cwe_check_full_20260908.jsonl（不动历史抽查文件）；
- 冲突判定同时输出每条数据集行的定位信息（行号 + meta.kind + assistant 当前标签），
  供逐条裁决（改标 + label_basis / 降级 / 待人工）。

裁决纪律：冲突 ≠ 自动改标。逐条核代码形态后处置；本脚本只提名。
"""
import json
import re
import sys
import time
import urllib.request
from collections import defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]          # exp_06_finetune/
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
OUT = BASE / "audit/cwe_offline/nvd_cwe_check_full_20260908.jsonl"
HIST = BASE / "audit/cwe_offline/nvd_cwe_check.jsonl"

CVE_RE = re.compile(r"CVE-\d{4}-\d+")


def load_dataset_cves():
    """返回 {cve: [(row_index_1based, kind, assistant_labels...), ...]}。"""
    per = defaultdict(list)
    with DATA.open(encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            if "CVE-" not in line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            cves = set(CVE_RE.findall(line))
            meta = row.get("meta") or {}
            kind = meta.get("kind", "") if isinstance(meta, dict) else ""
            asst = row["messages"][2]["content"]
            labels = sorted(set(re.findall(r"CWE-\d{1,4}", asst)))
            for c in cves:
                per[c].append({"line": i, "kind": kind, "assistant_labels": labels})
    return per


def main(apply=False):
    per = load_dataset_cves()
    print(f"数据集唯一 CVE: {len(per)}")

    done = {}
    for p in (HIST, OUT):
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                try:
                    o = json.loads(line)
                    if o.get("error") is None and o.get("nvd_cwes"):
                        done[o["cve"]] = o["nvd_cwes"]
                except Exception:
                    pass
    print(f"已有结果（抽查+本轮）: {len(done)}")

    todo = [c for c in sorted(per) if c not in done]
    print(f"待查: {len(todo)}")

    if apply:
        mode = "a" if OUT.exists() else "w"
        with OUT.open(mode, encoding="utf-8") as f:
            for n, cve in enumerate(todo, 1):
                rec = {"cve": cve, "samples": per[cve], "nvd_cwes": None, "error": None}
                try:
                    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
                    req = urllib.request.Request(url, headers={"User-Agent": "cwe-audit/1.0"})
                    j = json.loads(urllib.request.urlopen(req, timeout=30).read().decode("utf-8"))
                    cwes = set()
                    for v in j.get("vulnerabilities", []):
                        for w in v["cve"].get("weaknesses", []):
                            for dv in w["description"]:
                                cwes.add(dv["value"])
                    rec["nvd_cwes"] = sorted(cwes)
                except Exception as e:
                    rec["error"] = str(e)[:200]
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                f.flush()
                print(f"[{n}/{len(todo)}] {cve} nvd={rec['nvd_cwes']} {rec['error'] or ''}")
                time.sleep(6.5)
        print("DONE")
    else:
        for c in todo:
            print(c, per[c][:2])


if __name__ == "__main__":
    main(apply="--apply" in sys.argv)
