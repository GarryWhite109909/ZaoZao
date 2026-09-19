# -*- coding: utf-8 -*-
"""
簇内 has_vuln 冲突的**分诊**（2026-09-09）

背景：初算得到 573 组 / 1439 行"簇内 has_vuln 冲突"，数字过大，必含大量假信号。
      抽查证实：绝大多数是**刻意设计的差分对**（同一骨架，vuln 侧带危险 sink、
      safe 侧带防御，代码骨架高度重合 → Jaccard 0.5 被聚成同簇）。
      差分对是方法论 §2.1 的主力数据源（~60%），不是脏数据。

本脚本目的：把 573 组切成三档，只把"无法用差分对解释"的交给人工。
  档 A 刻意差分对 —— vuln 侧含危险 token 而 safe 侧不含，或 safe 侧含防御 token 而 vuln 侧不含
  档 B 可解释但需备案 —— 差异落在非安全相关行（注释/变量名/框架版本）
  档 C 无法解释（真嫌疑） —— 两侧安全相关 token 无差异，或差异方向与标签相反

产出：实测门_簇冲突分诊_20260909.jsonl + 控制台摘要
"""
import json, re, sys, os, collections

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.normpath(os.path.join(ROOT, "..", "data", "final_train_chatml_alpha06_v2_16.jsonl"))
CONFLICT = os.path.join(ROOT, "实测门_簇内标签冲突_20260909.jsonl")
OUT = os.path.join(ROOT, "实测门_簇冲突分诊_20260909.jsonl")

DANGER = re.compile(
    r"eval\s*\(|exec\s*\(|os\.system|subprocess|shell\s*=\s*True|Runtime\.getRuntime|ProcessBuilder|"
    r"innerHTML|dangerouslySetInnerHTML|document\.write|"
    r"execute\s*\(\s*[\"'`][^\"'`]*[\"'`]\s*%|cursor\.execute\s*\([^,)]*%|\+\s*keyword|\+\s*user|\+\s*name|"
    r"strcpy|strcat|sprintf|gets\s*\(|memcpy|"
    r"md5|sha1|DES|RC4|ECB|TLSv1(?:\.[01])?|SSLv3|InsecureSkipVerify|verify\s*=\s*False|CERT_NONE|"
    r"random\.random|math\.rand|Math\.random|rand\s*\(|srand\s*\(|time\(NULL\)|"
    r"csrf\s*\(\s*\)\s*\.disable|csrf\(\)\.disable|\.disable\(\)|"
    r"pickle\.loads|yaml\.load\s*\((?!.*Safe)|unserialize|"
    r"root|chmod\s+777|--privileged|allowPrivilegeEscalation|hostNetwork|"
    r"password\s*=\s*[\"']|secret\s*=\s*[\"']|api_?key\s*=\s*[\"']|token\s*=\s*[\"']", re.I)

DEFENSE = re.compile(
    r"parameterized|prepared|placeholder|\?\s*,\s*\(|%s\s*,\s*\("  # 参数化查询
    r"|escape|sanitiz|bleach|html\.escape|quote|urlencode|"
    r"whitelist|allowlist|allowed_|re\.match\s*\(.*\$$|"
    r"secrets\.|os\.urandom|SystemRandom|random\.SystemRandom|bcrypt|argon2|scrypt|"
    r"csrf_token|csrfToken|csrf\(|CsrfFilter|\.csrf|"
    r"verify\s*=\s*True|InsecureSkipVerify\s*:\s*false|CERT_REQUIRED|TLSv1_[23]|"
    r"snprintf|strncpy|strnlen|fgets|memcpy_s|strcpy_s|"
    r"USER\s+(?!root)|useradd|adduser|runAsNonRoot|readOnlyRootFilesystem|drop\s+\[|"
    r"seccomp|AppArmor|no-new-privileges", re.I)


def code_of(user_text):
    fences = re.findall(r"```[A-Za-z0-9_+\-]*\n(.*?)```", user_text, re.S)
    if fences:
        return max(fences, key=len)
    return user_text


def lines_with(code, rx):
    return [l.strip() for l in code.split("\n") if rx.search(l)]


def main():
    want = set()
    conflicts = []
    with open(CONFLICT, encoding="utf-8") as f:
        for l in f:
            o = json.loads(l)
            if o.get("conflict") != "has_vuln":
                continue
            conflicts.append(o)
            want.update(int(x) for x in o["cluster_rows"])

    rows = {}
    with open(DATA, encoding="utf-8") as f:
        for i, l in enumerate(f):
            ln = i + 1
            if ln not in want:
                continue
            try:
                r = json.loads(l)
            except Exception:
                continue
            u = ""
            for m in r.get("messages", []):
                if m.get("role") == "user":
                    u = m.get("content", "")
            rows[ln] = code_of(u)

    tiers = collections.Counter()
    out = []
    for c in conflicts:
        T = [d["line"] for d in c["detail"] if d["has_vuln"] is True]
        F = [d["line"] for d in c["detail"] if d["has_vuln"] is False]
        tcode = "\n".join(rows.get(x, "") for x in T)
        fcode = "\n".join(rows.get(x, "") for x in F)
        t_dang = set(lines_with(tcode, DANGER))
        f_dang = set(lines_with(fcode, DANGER))
        t_def = set(lines_with(tcode, DEFENSE))
        f_def = set(lines_with(fcode, DEFENSE))
        only_t_dang = list(t_dang - f_dang)[:3]
        only_f_def = list(f_def - t_def)[:3]
        only_t_def = list(t_def - f_def)[:3]   # 反常：vuln 侧反而有防御
        only_f_dang = list(f_dang - t_dang)[:3]  # 反常：safe 侧反而有危险

        if (only_t_dang or only_f_def) and not (only_t_def or only_f_dang):
            tier = "A_刻意差分对"
        elif only_t_def or only_f_dang:
            tier = "C_嫌疑_防御与标签反向"
        else:
            tier = "C_嫌疑_无安全差异"
        tiers[tier] += 1
        out.append({
            "cluster_rows": c["cluster_rows"], "size": c["size"], "lang": c.get("lang", ""),
            "n_true": len(T), "n_false": len(F), "tier": tier,
            "only_vuln_side_danger": only_t_dang, "only_safe_side_defense": only_f_def,
            "only_vuln_side_defense": only_t_def, "only_safe_side_danger": only_f_dang,
        })

    with open(OUT, "w", encoding="utf-8") as f:
        for o in out:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")

    print("=== 簇内 has_vuln 冲突分诊 ===")
    print(f"总冲突簇 {len(out)} 组")
    for k, v in tiers.most_common():
        print(f"  {k:<24} {v:>4} 组")
    print()
    for tier in ("C_嫌疑_无安全差异", "C_嫌疑_防御与标签反向"):
        sub = [o for o in out if o["tier"] == tier]
        sub.sort(key=lambda x: -x["size"])
        print(f"--- {tier}（前 10，按簇规模）---")
        for o in sub[:10]:
            print(f"  簇{o['size']:>2} {o['lang']:>10} T={o['n_true']} F={o['n_false']} rows={o['cluster_rows'][:8]}")
            if o["only_safe_side_danger"]:
                print(f"      safe侧独有危险行: {o['only_safe_side_danger']}")
            if o["only_vuln_side_defense"]:
                print(f"      vuln侧独有防御行: {o['only_vuln_side_defense']}")
        print()
    print(f"明细: {os.path.basename(OUT)}")


if __name__ == "__main__":
    main()
