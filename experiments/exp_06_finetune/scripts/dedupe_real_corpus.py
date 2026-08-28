#!/usr/bin/env python3
"""全库真实语料近重复聚类审计（P1，2026-08-27）。

动机：alpha06-v2.6 增量构建中泄漏门拦下 97 条增量（checklist 种子与
rolling_dev 重合至 J=0.837、crossfile 合成代码贴近 87seg）——说明"同一份
真实代码的多个化身"散布在训练种子池与评测集两侧，行级线性拦截只能事后撞见。

本脚本做的事：
1. 收集全部真实代码文件：train_pool（训练种子）、rolling_dev(+safe)、
   cve20、87seg hard samples（全部评测侧），按规范化非注释行集合计算
   两两 Jaccard 与双向 containment；
2. 并查集聚类：Jaccard>=J_T 或 containment>=C_T 视为同簇；
3. 簇级角色分配：簇内任一成员属于评测集 ⇒ 整簇标记为 EXAM_SIDE
   （其 train_pool 成员即"隔离淘汰"，禁止再作蒸馏种子）；纯训练成员为 TRAIN；
4. 产出：
   - results/corpus_cluster_manifest.json —— 每文件的角色与匹配明细，
     供生成器前置过滤与构建管线组级校验消费；
   - results/corpus_cluster_audit_20260827.md —— 人读报告。
纪律对应：弱点挖掘报告 第九节 防作弊第1~4条；L2/L3 考卷纯净性前提。
"""
import itertools
import json
import re
from collections import defaultdict
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]          # .../exp_06_finetune
RES = BASE / "results"
EXP_ROOT = BASE.parent                              # .../experiments

J_T, C_T = 0.30, 0.45

SOURCES = {
    # tag -> (目录, 文件 glob 模式列表, 角色)
    "train_pool": (BASE / "corpus/train_pool", ["*"], "TRAIN"),
    "rolling_dev": (BASE / "corpus/rolling_dev", ["corpus_*"], "EXAM"),
    "rolling_dev_safe": (BASE / "corpus/rolling_dev_safe", ["corpus_*"], "EXAM"),
    "cve20": (BASE / "testset_cve_fix", ["cve_fix_*"], "EXAM"),
    "seg87": (EXP_ROOT / "exp_04_hard_samples/samples",
              ["*.py", "*.java", "*.js", "*.php", "*.go", "*.ts"], "EXAM"),
}

CODE_EXT = {".py", ".java", ".js", ".php", ".go", ".ts", ".rb", ".rs", ".c",
            ".cpp", ".h", ".hpp", ".sh", ".yaml", ".yml", ".ini", ".conf"}
IMG_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico"}


def norm_lines(code: str):
    out = set()
    for ln in code.splitlines():
        s = ln.strip()
        if not s or s.startswith(("#", "//")):
            continue
        s = re.sub(r"\s+", " ", s).lower()
        if len(s) >= 8:
            out.add(s)
    return out


def main():
    files = {}
    for tag, (d, pats, role) in SOURCES.items():
        if not d.exists():
            print(f"[warn] 缺目录 {d}")
            continue
        for pat in pats:
            for f in d.glob(pat):
                if f.is_file() and f.suffix.lower() in CODE_EXT:
                    rel = f"{tag}/{f.name}"
                    files[rel] = {
                        "path": f, "source": tag, "role": role,
                        "lines": norm_lines(f.read_text(errors="replace")),
                    }
    keys = sorted(files)
    n = len(keys)
    print(f"参与聚类的真实文件数: {n}")

    # 倒排索引粗筛 + 精算 J/C
    inv = defaultdict(list)
    for k in keys:
        for ln in files[k]["lines"]:
            inv[ln].append(k)

    parent = list(range(n))
    idx = {k: i for i, k in enumerate(keys)}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    matches = defaultdict(dict)
    for i, ka in enumerate(keys):
        la = files[ka]["lines"]
        if not la:
            continue
        cand = defaultdict(int)
        for ln in la:
            for kb in inv[ln]:
                if kb != ka:
                    cand[kb] += 1
        for kb, inter in cand.items():
            lb = files[kb]["lines"]
            uni = len(la | lb)
            j = inter / uni if uni else 0.0
            c_ab = inter / len(la) if la else 0.0
            c_ba = inter / len(lb) if lb else 0.0
            if j >= J_T or max(c_ab, c_ba) >= C_T:
                ia, ib = idx[ka], idx[kb]
                union(ia, ib)
                matches[ka][kb] = round(min(1.0, max(j, c_ab, c_ba)), 3)

    clusters = defaultdict(list)
    for k in keys:
        clusters[find(idx[k])].append(k)

    # 角色分配
    manifest = {}
    roles = {}
    conflict = []           # (train_pool文件, 匹配到的评测文件, 相似度)
    for cid, (root, members) in enumerate(sorted(clusters.items(), key=lambda kv: kv[0])):
        src_roles = {files[m]["role"] for m in members}
        has_exam = "EXAM" in src_roles
        for m in members:
            role = ("QUARANTINE_TRAIN" if (has_exam and files[m]["role"] == "TRAIN")
                    else ("EXAM" if files[m]["role"] == "EXAM" else "TRAIN"))
            roles[m] = role
            manifest[m] = {
                "cluster": cid,
                "role": role,
                "similar_to": sorted(matches[m].items(), key=lambda kv: -kv[1]),
            }
            if role == "QUARANTINE_TRAIN":
                for peer, sim in sorted(matches[m].items(), key=lambda kv: -kv[1]):
                    if files[peer]["role"] == "EXAM":
                        conflict.append((m, peer, sim))
                        break

    quarantined = [m for m, r in roles.items() if r == "QUARANTINE_TRAIN"]
    n_multi = sum(1 for ms in clusters.values() if len(ms) > 1)

    out_manifest = RES / "corpus_cluster_manifest.json"
    out_manifest.write_text(json.dumps(
        {"generated": "2026-08-27", "thresholds": {"jaccard": J_T, "containment": C_T},
         "roles": manifest}, ensure_ascii=False, indent=1), encoding="utf-8")

    report = [
        "# 真实语料近重复聚类审计（2026-08-27）\n",
        f"- 参与文件 {n} | 近重复簇 **{n_multi}** 个（阈值 J>={J_T} 或 C>={C_T}）",
        f"- 隔离淘汰的训练种子（训练候选与评测同簇）：**{len(quarantined)}** 个\n",
        "## 隔离淘汰明细（这些 train_pool 文件今后不得作为蒸馏种子）\n",
    ]
    for m, peer, sim in sorted(conflict, key=lambda x: -x[2]):
        report.append(f"- `{m}` ↔ `{peer}`（相似度 {sim:.3f}）")

    banned_lines = ", ".join(json.dumps(m.split("/")[-1])
                             for m in sorted(quarantined))
    bl = RES / "corpus_cluster_blocklist.json"
    bl.write_text(json.dumps({
        "_comment": "gen_checklist_cot / gen_alpha06_variants 候选过滤：命中者跳过",
        "filenames": sorted(m.split("/")[-1] for m in quarantined),
    }, ensure_ascii=False, indent=1), encoding="utf-8")

    report += ["", "## 使用方式",
               "- `corpus_cluster_manifest.json`：构建管线组级校验（P2）数据源",
               "- `corpus_cluster_blocklist.json`：生成器 seed 过滤（已接入两脚本）"]
    (RES / "corpus_cluster_audit_20260827.md").write_text("\n".join(report), encoding="utf-8")
    print("\n".join(report[:12]))
    print(f"manifest: {out_manifest}")
    print(f"blocklist: {bl}")


if __name__ == "__main__":
    main()
