# -*- coding: utf-8 -*-
"""把 g21-g24 辨析组蒸馏产出合并进 v2_15。

1. 从两个批次输出目录读 success.jsonl(_wave1_out_g21_22 / _wave1_out_g23_24)
2. 按 orig 前缀路由写四个溯源包:
     g21-* -> g21_crypto_boundary.jsonl      (F12 密码学互斥)
     g22-* -> g22_evidence_confidence.jsonl  (F11 E3/E2 高置信)
     g23-* -> g23_primary_vs_secret.jsonl    (F10 伴生凭证 vs 主洞)
     g24-* -> g24_case_anchors.jsonl         (案例 D 族边界)
3. 查重(归一 md5) + 契约校验后追加进 v2_15,source_pack 按组分列
4. 自检并写 audit/adjudicate_v2_15/merge_g2124_out.txt

幂等:两批可分批落库,重复执行时已入库样本被查重拦截,溯源包按当前 success 重写。
"""
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]  # exp_06_finetune/
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
OUT_DIRS = [BASE / "corpus/repair_wave/_wave1_out_g21_22",
            BASE / "corpus/repair_wave/_wave1_out_g23_24",
            BASE / "corpus/repair_wave/_wave1_out_g23b",
            BASE / "corpus/repair_wave/_wave1_out_g24_tail",  # g24 后半并行批(与 g23_24 有重叠,按 orig 去重)
            BASE / "corpus/repair_wave/_wave1_out_g2122_retry",  # G4 拒收重试批
            BASE / "corpus/repair_wave/_wave1_out_g22b",  # g22b 危害具体化 + 拒收重试
            BASE / "corpus/repair_wave/_wave1_out_g24_final",  # g24 收尾重试批(batchC)
            BASE / "corpus/repair_wave/_wave1_out_g24_c2",  # g24-csrf-04 精简hint重试(batchC2)
            BASE / "corpus/repair_wave/_wave1_out_g25",  # g25 safe 侧防御演示(batchC 续,D9 尾项第6项)
            BASE / "corpus/repair_wave/_wave1_out_g26",  # g26 命令语言注入(真77)+338/329 补样
            BASE / "corpus/repair_wave/_wave1_out_g26_retry"]  # g26 G4 拒收重试批
GROUPS = [
    ("g21-", "g21_crypto_boundary.jsonl", "g21/crypto_boundary"),
    ("g22-", "g22_evidence_confidence.jsonl", "g22/evidence_confidence"),
    ("g22b-", "g22_evidence_confidence.jsonl", "g22/evidence_confidence"),  # g22b 补做包回同一溯源包
    ("g23-", "g23_primary_vs_secret.jsonl", "g23/primary_vs_secret"),
    ("g23b-", "g23_primary_vs_secret.jsonl", "g23/primary_vs_secret"),  # 补做包并回同一溯源包
    ("g24-", "g24_case_anchors.jsonl", "g24/case_anchors"),
    ("g25-", "g25_safe_defense.jsonl", "g25/safe_defense"),  # safe 侧配置/开关 + realpath 归一防御演示
    ("g26-cmdlang-", "g26_command_language.jsonl", "g26/command_language"),  # 真 CWE-77:非 OS 命令语言注入
    ("g26-c338-", "g26_crypto_weak_prng.jsonl", "g26/crypto_weak_prng"),  # 338 弱 PRNG 补样
    ("g26-c329-", "g26_crypto_nonce.jsonl", "g26/crypto_nonce"),  # 329 固定 IV/nonce 补样
]
OUT_LOG = BASE / "audit/adjudicate_v2_15/merge_g2124_out.txt"

CONTRACT = ["has_vulnerability", "vulnerability_type", "risk_level",
            "source", "sink", "explanation", "fix_suggestion"]
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)

# 机检未通过、禁止入库的条目(见 verify_g2124_out.txt)。
# 2026-09-01: g23 首轮 4 条被 CWE-798 抢占 top1(F10 黑洞在蒸馏教师身上复现),
# 入库会反向教模型"看到硬编码凭证 + 越权 -> 判 798",与 D9 ③ 目标相反,故剔除;
# 其辨析目标由 g23b 强化版 4 条承担(主洞危害升级 + 凭证退到角落)。
DROP = {
    "g23-idor-01",  # 实判 798,期望 639
    "g23-idor-02",  # 实判 798,期望 639
    "g23-authz-02",  # 实判 798,期望 862
    "g23-up-01",  # 实判 798,期望 434
    "g23-idor-03",  # 实判 862,期望 639(近邻混淆,见 verify_g2124_out.txt;639 目标由 g23b-del/transfer 承担)
    "g24-php-04",  # 实判 862,期望 843(in_array 松散比较近邻混淆;843 目标由 php-01/02/03 承担)
}

LOG = []


def P(*a):
    LINE = " ".join(str(x) for x in a)
    LOG.append(LINE)
    print(LINE, flush=True)


def norm_md5(s):
    return hashlib.md5(re.sub(r"\s+", "", s).encode()).hexdigest()


# ---------- 1. 收集产出 ----------
recs = []          # (pack_file, source_pack, rec)
origs = Counter()
for d in OUT_DIRS:
    sp = d / "success.jsonl"
    if not sp.exists():
        P(f".. 跳过(不存在): {d}")
        continue
    n_dir = 0
    for l in sp.open(encoding="utf-8"):
        if not l.strip():
            continue
        rec = json.loads(l)
        o = str(rec.get("fix_distill", {}).get("orig", ""))
        if o in DROP:
            P(f"  xx {o}: 在 DROP 名单(机检未过)，跳过")
            continue
        for pref, pack_name, source_pack in GROUPS:
            if o.startswith(pref):
                recs.append((pack_name, source_pack, rec))
                origs[o] += 1
                n_dir += 1
                break
    P(f"批次 {d.name}: 命中 {n_dir} 条")

P(f"g21-g24 蒸馏产出合计: {len(recs)} 条(去重前)")
if not recs:
    P("!! 无产出，退出")
    OUT_LOG.write_text("\n".join(LOG) + "\n", encoding="utf-8")
    sys.exit(1)

# 同 orig 多次记录(重跑导致)只取最后一条
by_orig = {}
for pack_name, source_pack, rec in recs:
    by_orig[rec["fix_distill"]["orig"]] = (pack_name, source_pack, rec)
P(f"按 orig 去重后: {len(by_orig)} 条")
per_group = Counter(p for _, p, _ in by_orig.values())
P(f"分组计数: {dict(per_group)}")

# ---------- 2. 写溯源包 ----------
# 按 pack_name 去重后再写(g23- 与 g23b- 共用同一溯源包,否则后者会覆盖前者)
seen_pack, pack_list = set(), []
for _, pack_name, source_pack in GROUPS:
    if pack_name not in seen_pack:
        seen_pack.add(pack_name)
        pack_list.append((pack_name, source_pack))
for pack_name, source_pack in pack_list:
    subset = [(p, sp, r) for p, sp, r in by_orig.values() if p == pack_name]
    if not subset:
        continue
    with (BASE / "corpus/repair_wave" / pack_name).open("w", encoding="utf-8") as f:
        for _, _, r in subset:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    P(f"溯源包 {pack_name}: {len(subset)} 条")

# ---------- 3. 查重与合并 ----------
lines = DATA.read_text(encoding="utf-8").split("\n")
user_md5, assist_md5 = set(), set()
for l in lines:
    if not l.strip():
        continue
    rec = json.loads(l)
    user_md5.add(norm_md5(rec["messages"][1]["content"]))
    assist_md5.add(norm_md5(rec["messages"][2]["content"]))

appended, dupe, bad_contract = 0, 0, 0
appended_by_group = Counter()
for o, (pack_name, source_pack, rec) in sorted(by_orig.items()):
    msgs = rec["messages"]
    if len(msgs) != 3:
        bad_contract += 1
        P(f"  !! {o}: messages 非三段，跳过")
        continue
    blk = JSON_BLOCK.findall(msgs[2]["content"])
    ok = False
    if blk:
        try:
            ok = list(json.loads(blk[-1]).keys()) == CONTRACT
        except Exception:
            ok = False
    if not ok:
        bad_contract += 1
        P(f"  !! {o}: 契约不符，跳过")
        continue
    um, am = norm_md5(msgs[1]["content"]), norm_md5(msgs[2]["content"])
    if um in user_md5 or am in assist_md5:
        dupe += 1
        P(f"  -- {o}: 重复，跳过")
        continue
    rec.setdefault("fix_distill", {})["source_pack"] = source_pack
    lines.append(json.dumps(rec, ensure_ascii=False))
    user_md5.add(um)
    assist_md5.add(am)
    appended += 1
    appended_by_group[source_pack] += 1

P(f"追加 {appended} / 查重拦截 {dupe} / 契约拒 {bad_contract}")
P(f"分组追加: {dict(appended_by_group)}")

if appended:
    DATA.write_text("\n".join(lines), encoding="utf-8")
    P("v2_15 已写回")
else:
    P("无新增，v2_15 未改动")

# ---------- 4. 自检 ----------
n = 0
hv = Counter()
bad_json = 0
packs = Counter()
for l in lines:
    if not l.strip():
        continue
    n += 1
    rec = json.loads(l)
    packs[rec.get("fix_distill", {}).get("source_pack", "-")] += 1
    try:
        o = json.loads(JSON_BLOCK.findall(rec["messages"][2]["content"])[-1])
        hv[str(o.get("has_vulnerability"))] += 1
    except Exception:
        bad_json += 1
P(f"自检: v2_15 总条数 {n} | JSON 失败 {bad_json} | 正负 {dict(hv)}")
P(f"g2x 溯源标记计数: { {k: v for k, v in packs.items() if k.startswith('g2')} }")
OUT_LOG.write_text("\n".join(LOG) + "\n", encoding="utf-8")
