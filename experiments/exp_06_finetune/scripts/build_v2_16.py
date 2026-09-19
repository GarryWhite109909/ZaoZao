# -*- coding: utf-8 -*-
"""v2_16 构建（方法论 §1.3 第 3 项 + §2.3 管道硬门）。

输入：data/final_train_chatml_alpha06_v2_15.jsonl（清洗后活文件，10151 行）。
输出：data/final_train_chatml_alpha06_v2_16.jsonl + audit/build_v2_16_report.md。

步骤：
  G6a --purge-quarantined-seeds：隔离种子衍生反查（幂等，簇表 meta 指纹，预期 0）；
  G6b 78 头部封顶 502→300：按代码指纹簇（对称 Jaccard≥0.5）做轮转取样——
      每簇先各取 1 条、再各取第 2 条……直到 300，保留形态多样性（非随机砍）；
  落盘 v2_16 + 构建报告（前后分布、被裁清单、sha256）。

纪律：v2_15 本体不动（封顶在 build 层执行，不在数据层删——方法论 §2.3）。
"""
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(Path(__file__).resolve().parents[1])
SRC = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
DST = BASE / "data/final_train_chatml_alpha06_v2_16.jsonl"
MANIFEST = BASE / "results/corpus_cluster_manifest.json"
REPORT = BASE / "audit/build_v2_16_report.md"

CAP_TARGET = 78       # CWE 编号
CAP_KEEP = 300        # 封顶数量
J_T = 0.50
FENCE = re.compile(r"```[a-zA-Z0-9+#]*\n(.*?)```", re.S)

# ---------- 训练价值评分（20260908 增补：封顶从"形态多样性"升级为"价值+多样性"） ----------
SINK_CLASSES = [
    ("py_sys", ["os.system", "subprocess", "os.popen", "commands.get"]),
    ("php_sys", ["shell_exec", "passthru", "proc_open", "popen", "exec("]),
    ("go_exec", ["exec.Command", "syscall.ForkExec", "exec.CommandContext"]),
    ("js_childproc", ["child_process", "execSync", ".spawn(", ".exec("]),
    ("java_proc", ["Runtime.getRuntime", "ProcessBuilder"]),
    ("cs_proc", ["Process.Start", "System.Diagnostics"]),
    ("rb_sys", ["IO.popen", "Open3"]),
    ("eval_like", ["eval(", "evalu("]),
]
FRAMEWORKS = ["express", "flask", "django", "fastapi", "spring", "laravel", "symfony",
              "gin-gonic", "tornado", "celery", "jenkins", "ansible", "wordpress",
              "drupal", "grav", "smarty", "twig", "nuclio", "fastify", "koa", "rails"]
BYPASS_MARKS = ["二次编码", "双重编码", "编码绕过", "绕过", "变体", "TOCTOU", "竞态",
                "原型", "混淆", "归一", "反斜杠", "注入链", "嵌套", "白名单", "黑名单",
                "引号闭合", "转义", "%2f", "%25", "大小写"]


def lang_of(user: str):
    m = re.search(r"代码片段（语言[:：]\s*(\w+)）", user)
    if m:
        return {"javascript": "js", "typescript": "ts"}.get(m.group(1).lower(), m.group(1).lower())
    return "?"


def sink_class(code: str):
    low = code.lower()
    for name, toks in SINK_CLASSES:
        if any(t.lower() in low for t in toks):
            return name
    return "other"


def value_score(idx, row, cluster_size, combo_freq):
    """训练价值（可解释信号；分数只用于排序）。

    S1 形态稀缺度（lang×sink 组合池内频率的反比）——基座"想不到"的形态信息量大；
    S2 推理深度（叙事行引用数 + 绕过链标记）——多跳证据链基座难自学；
    S3 新颖性代理（2026 CVE / 罕见框架 / 簇单例）；
    S5 平凡惩罚（短叙事 + ≤2 行引用 + 无绕过标记 = 基座零样本可会）。
    """
    code = "\n".join(FENCE.findall(row["messages"][1]["content"]))
    ana = row["messages"][2]["content"].split("```json")[0]
    meta = row.get("meta") or {}
    lang = lang_of(row["messages"][1]["content"])
    sc = sink_class(code)

    s1 = 2.0 / (1 + combo_freq.get((lang, sc), 1) - 1)
    refs = len(set(re.findall(r"第\s*\d+|line\s*\d+", ana)))
    marks = sum(1 for mk in BYPASS_MARKS if mk.lower() in ana.lower())
    s2 = min(refs, 12) * 0.25 + marks * 0.5
    s3 = 0.0
    if re.search(r"CVE-202[5-6]", json.dumps(meta, ensure_ascii=False)):
        s3 += 1.0
    if any(f in code.lower() for f in FRAMEWORKS):
        s3 += 0.5
    if cluster_size == 1:
        s3 += 0.5
    # S5（平凡惩罚）已撤销（2026-09-08 用户质询后承认）：
    #   基线实测 recall 0.351 / deepseek FPR 0.444 证明基座在"平凡形态"上也常错；
    #   典型样本还承担输出契约稳定 + 判真基率校准（SFT recall +24pt 的主要来源）。
    #   "基座已会"必须靠零样本实测（base-model probe）判定，不能凭叙事长短推断。
    #   probe 上线前，S5 恒为 0——宁可少裁也不误裁基本功。
    s5 = 0.0
    return round(s1 + s2 + s3 + s5, 3), {"lang": lang, "sink": sc, "refs": refs, "marks": marks}


def select_by_value(cap_idx, rows, clusters):
    """价值加权选择：簇按最优成员价值排序 → 逐簇取 1 → (lang,sink) 覆盖率保护。"""
    combo_freq = defaultdict(int)
    tags = {}
    for i in cap_idx:
        _, tag = value_score(i, rows[i], 1, {})
        tags[i] = tag
        combo_freq[(tag["lang"], tag["sink"])] += 1
    info = {i: value_score(i, rows[i], len(clusters[find(i)]), combo_freq) for i in cap_idx}
    cl_val = []
    for root, members in clusters.items():
        best = max(members, key=lambda i: info[i][0])
        cl_val.append((info[best][0], root, best))
    cl_val.sort(key=lambda t: -t[0])
    keep = []
    for _, _, best in cl_val:
        if len(keep) >= CAP_KEEP:
            break
        keep.append(best)
    # 覆盖率保护：池内出现过的 (lang,sink) 组合必须至少留 1 条
    have = {info[i][1] for i in keep}
    for i in cap_idx:
        tag = info[i][1]
        if tag not in have:
            worst = min(keep, key=lambda j: info[j][0])
            if info[worst][0] < info[i][0]:
                keep.remove(worst)
                keep.append(i)
                have.add(tag)
    return set(keep), info


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
    rows = [json.loads(l) for l in SRC.open(encoding="utf-8") if l.strip()]
    n_src = len(rows)
    print(f"源 {SRC.name}: {n_src} 行")

    # ---- G6a: 隔离种子反查（幂等） ----
    m = json.loads(MANIFEST.read_text(encoding="utf-8"))
    seeds = {rel.split("/", 1)[1] for rel, info in m["roles"].items()
             if info.get("role") == "QUARANTINE_TRAIN"}
    leak = [i for i, r in enumerate(rows)
            if isinstance(r.get("meta"), dict)
            and (r["meta"].get("seed_file") in seeds)]
    print(f"G6a 隔离种子衍生: {len(leak)}（预期 0）")
    assert not leak, "发现隔离种子衍生样本——先回清洗通道处置再构建"
    kept = list(rows)

    # ---- G6b: 78 封顶（簇内多样性轮转 + 辨析锚豁免） ----
    # 豁免名单：g 系列辨析锚（信任边界孪生/77↔78 边界/命令语言）——高投资教学样本,
    # 独簇或小簇,轮转取样会整簇裁掉(2026-09-08 实测 10 条全灭),必须强制保留。
    ANCHOR_PREFIXES = ("g20-", "g24-", "g26-")
    def is_anchor(row):
        o = str((row.get("fix_distill") or {}).get("orig", ""))
        return o.startswith(ANCHOR_PREFIXES)
    def top_cwe(row):
        mm = re.search(r'"vulnerability_type": "CWE-(\d+)', row["messages"][2]["content"])
        return mm.group(1) if mm else None

    cap_idx = [i for i, r in enumerate(kept)
               if re.search(r'"has_vulnerability": true', r["messages"][2]["content"])
               and top_cwe(r) == str(CAP_TARGET)]
    cap_on = "--cap" in sys.argv
    print(f"G6b CWE-{CAP_TARGET} top-1 样本: {len(cap_idx)}"
          + (f" → 封顶 {CAP_KEEP}" if cap_on else
             " → 配额封顶已关闭（20260908 用户指令：只删脏/毒，基本功全保留；敷衍样本走修复队列）"))
    anchor_idx = [i for i in cap_idx if is_anchor(kept[i])]
    rot_idx = [i for i in cap_idx if i not in set(anchor_idx)]
    quota = max(CAP_KEEP - len(anchor_idx), 0) if cap_on else len(rot_idx)
    print(f"  辨析锚豁免 {len(anchor_idx)} 条: "
          f"{[str((kept[i]['fix_distill'] or {}).get('orig','')) for i in sorted(anchor_idx)]}")
    print(f"  轮转配额 {quota}（{len(rot_idx)} 条参与）")

    docs = {i: norm_lines("\n".join(FENCE.findall(kept[i]["messages"][1]["content"])))
            for i in rot_idx}
    inv = defaultdict(set)
    for i, nl in docs.items():
        for s in nl:
            inv[s].add(i)
    parent = {i: i for i in rot_idx}
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    pairs = set()
    for i, nl in docs.items():
        cand = defaultdict(int)
        for s in nl:
            for j in inv[s]:
                if j != i:
                    cand[j] += 1
        for j, c in cand.items():
            if j > i:
                continue
            jac = c / (len(docs[i]) + len(docs[j]) - c)
            if jac >= J_T:
                pairs.add((j, i))
    for a_, b_ in pairs:
        ra, rb = find(a_), find(b_)
        if ra != rb:
            parent[ra] = rb
    clusters = defaultdict(list)
    for i in rot_idx:
        clusters[find(i)].append(i)
    order = sorted(clusters.values(), key=lambda ms: (-len(ms), ms[0]))
    keep_set, picked = set(anchor_idx), 0   # 配额已扣除锚数，picked 从 0 起算（原差一错误）
    rnd = 0
    while picked < quota:
        progressed = False
        for ms in order:
            if rnd < len(ms) and picked < quota:
                keep_set.add(ms[rnd])
                picked += 1
                progressed = True
        if not progressed:
            break
        rnd += 1
    dropped = sorted(set(cap_idx) - keep_set)
    print(f"簇数 {len(clusters)}（最大 {len(order[0]) if order else 0}），裁掉 {len(dropped)}，"
          f"保留 {picked}（含锚 {len(anchor_idx)}）")

    out_rows = [r for i, r in enumerate(kept) if i not in set(dropped)]
    with DST.open("w", encoding="utf-8", newline="\n") as f:
        for r in out_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    h = hashlib.sha256(DST.read_bytes()).hexdigest()
    print(f"输出 {DST.name}: {len(out_rows)} 行 sha256 {h[:16]}")

    # ---- 构建报告 ----
    def dist(rs):
        c = defaultdict(int)
        vul = 0
        for r in rs:
            mm = re.search(r'"has_vulnerability": true', r["messages"][2]["content"])
            if mm:
                vul += 1
                cw = top_cwe(r)
                if cw:
                    c[cw] += 1
        return vul, c

    vul_b, dist_b = dist(rows)
    vul_a, dist_a = dist(out_rows)
    lines = [
        "# build_v2_16 构建报告（2026-09-08）", "",
        f"- 源：`{SRC.name}`（{n_src} 行，sha256 前 16 位见台账）",
        f"- 输出：`{DST.name}`（{len(out_rows)} 行，sha256 `{h[:16]}…`）",
        f"- G6a 隔离种子衍生：{len(leak)}（幂等门通过）",
        f"- G6b CWE-{CAP_TARGET}：{'封顶 ' + str(CAP_KEEP) if cap_on else '配额关闭（用户指令 20260908）'}，"
        f"{len(cap_idx)} → {picked}（裁 {len(dropped)}；簇 {len(clusters)} 个，J≥{J_T}）",
        f"- 漏洞样本 {vul_b} → {vul_a}；安全样本 {n_src - vul_b} → {len(out_rows) - vul_a}",
        "", "## CWE top-12（封顶前 → 后）", "",
        "| CWE | 前 | 后 |", "|---|---|---|",
    ]
    for cw, _ in sorted(dist_b.items(), key=lambda kv: -kv[1])[:12]:
        lines.append(f"| {cw} | {dist_b[cw]} | {dist_a.get(cw, 0)} |")
    lines += ["", "## 被裁样本（G6b）", ""]
    for i in dropped:
        meta = kept[i].get("meta") or {}
        lines.append(f"- 行 {i+1} kind={meta.get('kind')} cve={meta.get('cve')}")
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"报告 → {REPORT.name}")


if __name__ == "__main__":
    main()
