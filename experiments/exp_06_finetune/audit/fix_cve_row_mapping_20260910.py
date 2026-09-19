# -*- coding: utf-8 -*-
"""
CVE→行 映射机械修复（2026-09-10）

对象：audit/cwe_offline/nvd_cwe_check_full_20260908.jsonl（145 条唯一 CVE 的 NVD 全量查证）
依据：《L1待人工_12项_裁决卡_20260910.md》动作汇总 1；用户 2026-09-10 拍板"全量执行"。

⚠️ 关键口径（本轮核验发现，务必知悉）：
    该文件内的行号基准是 **v2_16**（文件共 10151 行），而决策卡 / L1 裁决卡列的
    映射行号是 **v17** 口径。因此本脚本一律以文件自身行号为准，且每条解绑/改绑
    都先用 v2_16 样本内容做指纹断言，防止改错绑定。
    v16 ↔ v17 内容对照（已逐条核验）：6645↔/、7152↔7090、7153↔7091、7159↔7097、
    7160↔7098、7161↔7099、7816↔7721、2094↔2067、7191↔7129、8056↔7959、
    7444↔7378、7646↔7573。

动作：
  A 解绑（8 组，机械）：7308 / 7494 / 2019-10909 / 22555 / 23337 / 22195+34064 /
                        44364 / 47117 对无关行的绑定全部移除。
  B 越界引用清除：CVE-2022-1509→10153、CVE-2026-44364→10155 均 > v2_16 行数 10151。
  C 改绑（3 组，样本自带 CVE 注释作证）：7152→CVE-2022-22965、7153→CVE-2017-18349、
                        7160→CVE-2007-4559，归位到各自真实 CVE 条目下。

只动 cwe_offline 侧 JSON，不碰数据集本体。
惯例：快照备份 → 内容指纹断言 → 改写 → 动作日志 → 自检（无越界引用、无残留错绑）。
"""
import json
import re
import sys
import hashlib
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]          # experiments/exp_06_finetune
MAP = BASE / "audit/cwe_offline/nvd_cwe_check_full_20260908.jsonl"
SNAP = BASE / "audit/cwe_offline/nvd_cwe_check_full_20260908.snapshot_pre_rebind_20260910.jsonl"
LOG = BASE / "audit/cwe_offline/nvd_cwe_remap_log_20260910.jsonl"
V16 = BASE / "data/final_train_chatml_alpha06_v2_16.jsonl"

DRY = "--dry-run" in sys.argv
CODE_BLOCK = re.compile(r"```[a-zA-Z0-9_+#\-\.]*[ \t]*\r?\n(.*?)```", re.S)

# line -> (指纹子串, 处置说明)
UNBIND = {
    "CVE-2017-7308":  [(6645, "api_client.py", "Python flask api_client 教学样本（top-1 CWE-113 CRLF），与 ebpf 整数截断→OOB 写无关")],
    "CVE-2017-7494":  [(7152, "CVE-2022-22965", "Spring4Shell 形态样本，非 SambaCry 代码"),
                       (7153, "fastjson", "fastjson 反序列化样本，非 SambaCry 代码"),
                       (7159, "CVE-2021-44228", "Node 日志注入样本，非 SambaCry 代码"),
                       (7160, "zipfile.extractall", "zip-slip 样本，非 SambaCry 代码"),
                       (7161, "requests.get", "SSRF 样本，非 SambaCry 代码")],
    "CVE-2019-10909": [(7816, "Grav\\Common\\GPM", "Grav CMS GPM Installer zip-slip（top-1 CWE-22 自洽）；NVD 对 2019-10909 绑 79 与代码机制不符")],
    "CVE-2021-22555": [(2094, "AWS_ACCESS_KEY_ID", "boto3 硬编码凭证样本（top-1 CWE-798 自洽）；NVD 对 22555 绑 787（netfilter）与本代码无关")],
    "CVE-2021-23337": [(7191, "The TensorFlow Authors", "TensorFlow 数组算子单元测试（无注入面、判 safe）；NVD 对 23337 绑 94（lodash）无关")],
    "CVE-2024-22195": [(8056, "from itertools import tee", "spaCy BuiltinTask + jinja2 模板样本（top-1 CWE-1336）；NVD 对 22195 绑 79（Jinja2 xmlattr）时本文件无 xmlattr")],
    "CVE-2024-34064": [(8056, "from itertools import tee", "同上，一行双 CVE 同解绑")],
    "CVE-2026-44364": [(7444, "Licensed to the Apache Software Foundation", "Airflow DAG source 端点样本（top-1 CWE-200 自洽）；NVD 对 44364 绑 352（CSRF）与代码机制不符"),
                       (10155, None, "越界引用：10155 > v2_16 行数 10151，直接清除")],
    "CVE-2026-47117": [(7646, "models.semg", "证据裁决 pos 行；族内 pos/neg 标签不一致系映射错绑所致，解绑后自消解"),
                       (7673, "taint_track", "证据裁决 neg 行；同上")],
    "CVE-2022-1509":  [(10153, None, "越界引用：10153 > v2_16 行数 10151，直接清除")],
}

# 改绑：把行归位到样本自带 CVE 注释所指的真实 CVE 条目下
REBIND = {
    "CVE-2022-22965": [(7152, "CVE-2022-22965", "行内注释自述 CVE-2022-22965：Spring MVC @ModelAttribute 数据绑定 → RCE")],
    "CVE-2017-18349": [(7153, "fastjson", "行内注释自述 fastjson 反序列化：用户输入 JSON.parseObject")],
    "CVE-2007-4559":  [(7160, "zipfile.extractall", "行内注释自述 CVE-2007-4559 类：zipfile.extractall 未校验成员路径")],
}

# ---------------------------------------------------------------- 载入

v16 = [json.loads(l) for l in V16.open(encoding="utf-8") if l.strip()]
N16 = len(v16)
V17 = BASE / "data/final_train_chatml_alpha06_v2_17.jsonl"
v17 = [json.loads(l) for l in V17.open(encoding="utf-8") if l.strip()]


def user_of(ln):
    return [m["content"] for m in v16[ln - 1]["messages"] if m["role"] == "user"][0]


def labels_of(ln):
    """按文件既有口径重算 assistant_labels = '全文 CWE 出现集合'。

    基准说明：旧有绑定沿用 v2_16 基准（与文件同期）；**本次新增的改绑条目取 v2_17
    （现行数据集）**，否则会把 7090 这类"已按 NVD 改判过"的行记成假冲突
    （例：7152 在 v2_16 是 CWE-915，在 v2_17 已改判 CWE-94 = NVD 口径，不应再报冲突）。
    """
    src = v17 if ln in V17_BASED else v16
    a = [m["content"] for m in src[ln - 1]["messages"] if m["role"] == "assistant"][-1]
    return sorted({"CWE-" + c for c in re.findall(r"CWE-(\d+)", a)},
                  key=lambda s: int(s.split("-")[1]))


V17_BASED = {ln for items in REBIND.values() for ln, _, _ in items}


def _sha(text):
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


# v2_17 user 内容哈希桶（只接受唯一命中），用于 v16 → v17 行号翻译
_bucket = {}
for _i, _r in enumerate(v17, 1):
    _k = _sha([m["content"] for m in _r["messages"] if m["role"] == "user"][0])
    _bucket.setdefault(_k, []).append(_i)
_UNIQ = {k: v[0] for k, v in _bucket.items() if len(v) == 1}
_DUP = {k: v for k, v in _bucket.items() if len(v) > 1}


def v17_of(ln):
    """v2_16 行号 → v2_17 行号（内容 sha1 唯一匹配；删除/改写过的行返回 None）。"""
    if ln < 1 or ln > N16:
        return None
    return _UNIQ.get(_sha(user_of(ln)))


def labels_of(ln):
    """按文件既有口径重算 assistant_labels = '全文 CWE 出现集合'。

    基准说明：旧有绑定沿用 v2_16 基准（与文件同期）；**本次新增的改绑条目取 v2_17
    （现行数据集，经 v17_of 翻译行号）**，否则会把 7090 这类"已按 NVD 改判过"的行
    记成假冲突（例：7152 在 v2_16 是 CWE-915，在 v2_17 已改判 CWE-94 = NVD 口径，
    不应再报冲突）。翻译不到时回退 v2_16 基准。
    """
    if ln in V17_BASED:
        t = v17_of(ln)
        if t:
            a = [m["content"] for m in v17[t - 1]["messages"] if m["role"] == "assistant"][-1]
            return sorted({"CWE-" + c for c in re.findall(r"CWE-(\d+)", a)},
                          key=lambda s: int(s.split("-")[1]))
    a = [m["content"] for m in v16[ln - 1]["messages"] if m["role"] == "assistant"][-1]
    return sorted({"CWE-" + c for c in re.findall(r"CWE-(\d+)", a)},
                  key=lambda s: int(s.split("-")[1]))


def code_of(ln):
    """内容指纹域：整条 user 消息（含代码块外的裁决元信息，为代码块的超集）。"""
    return user_of(ln)


objs = [json.loads(l) for l in MAP.open(encoding="utf-8") if l.strip()]
by_cve = {o["cve"]: o for o in objs}
N_BIND_BEFORE = sum(len(o["samples"]) for o in objs)
# 原始 line -> assistant_labels 快照（供改绑沿用，避免解绑后才取值取到空）
LINE_LABELS = {}
for _o in objs:
    for _s in _o["samples"]:
        LINE_LABELS.setdefault(_s["line"], _s.get("assistant_labels") or [])
print(f"载入映射 {MAP.name}：{len(objs)} 条 CVE / {N_BIND_BEFORE} 条绑定；v2_16 参照 {N16} 行")

actions = []

# ---------------------------------------------------------------- A/B 解绑

print("\n[A/B] 解绑 + 越界引用清除")
for cve, items in UNBIND.items():
    o = by_cve.get(cve)
    assert o is not None, f"映射中不存在 {cve}"
    for ln, fp, why in items:
        hit = [s for s in o["samples"] if s["line"] == ln]
        assert hit, f"{cve} 未绑定行 {ln}（已变更？）"
        if fp is not None:
            assert ln <= N16, f"{cve} 行 {ln} 越界，不应有指纹"
            assert fp in code_of(ln), f"{cve} 行 {ln} 内容指纹不符（期望 {fp!r}）"
        else:
            assert ln > N16, f"{cve} 行 {ln} 未越界，却按越界处理"
        o["samples"] = [s for s in o["samples"] if s["line"] != ln]
        actions.append({"op": "UNBIND", "cve": cve, "line": ln,
                        "fingerprint": fp, "reason": why,
                        "basis": "L1待人工_12项_裁决卡_20260910 动作汇总 1"})
        print(f"  - {cve:17s} 解绑 {ln:5d}  {'[越界清除]' if fp is None else ''}")

# ---------------------------------------------------------------- C 改绑

print("\n[C] 改绑（样本自带 CVE 注释作证）")
for cve, items in REBIND.items():
    o = by_cve.get(cve)
    assert o is not None, f"映射中不存在 {cve}"
    for ln, fp, why in items:
        assert fp in code_of(ln), f"{cve} 行 {ln} 内容指纹不符（期望 {fp!r}）"
        if any(s["line"] == ln for s in o["samples"]):
            print(f"  = {cve:17s} 已含 {ln:5d}，跳过")
            continue
        label = labels_of(ln)
        o["samples"].append({"line": ln, "kind": "", "assistant_labels": label or []})
        o["samples"].sort(key=lambda s: s["line"])
        actions.append({"op": "REBIND", "cve": cve, "line": ln, "fingerprint": fp,
                        "reason": why, "assistant_labels": label,
                        "basis": "样本内 CVE 注释（行级自证）"})
        print(f"  + {cve:17s} 改绑 {ln:5d}  labels={label}")

# ---------------------------------------------------------------- D 行号基准翻译表

print("\n[D] 生成 v2_16 → v2_17 行号翻译表（sidecar，不改映射文件 schema）")
TRANS = BASE / "audit/cwe_offline/nvd_cve_row_map_v16_to_v17_20260910.json"


def h(text):
    return _sha(text)


ref_lines = sorted({s["line"] for o in objs for s in o["samples"]})
table, miss = {}, []
for ln in ref_lines:
    if ln > N16:
        table[str(ln)] = {"v17_line": None, "fingerprint": None, "note": "v2_16 越界引用"}
        continue
    fp = _sha(user_of(ln))
    if fp in _UNIQ:
        table[str(ln)] = {"v17_line": _UNIQ[fp], "fingerprint": fp}
    elif fp in _DUP:
        table[str(ln)] = {"v17_line": None, "fingerprint": fp,
                          "note": f"内容重复，候选行 {_DUP[fp]}"}
        miss.append(ln)
    else:
        table[str(ln)] = {"v17_line": None, "fingerprint": fp,
                          "note": "v2_17 中无同内容行（该行已被治理删除，或其 user 内容被改写）"}
        miss.append(ln)
resolved = sum(1 for v in table.values() if v.get("v17_line"))
print(f"  引用行 {len(ref_lines)} 个：可解析 {resolved} / 不可解析 {len(ref_lines) - resolved}"
      f"（重复内容 {len(_DUP)} 组）")
if miss:
    print(f"  未解析行（前 20）：{miss[:20]}")

# ---------------------------------------------------------------- 写盘 + 自检

if DRY:
    print("\nDRY-RUN 结束：断言全部通过，拟动作 %d 条；未写盘。" % len(actions))
    sys.exit(0)

SNAP.write_bytes(MAP.read_bytes())
with MAP.open("w", encoding="utf-8", newline="\n") as f:
    for o in objs:
        f.write(json.dumps(o, ensure_ascii=False) + "\n")
with LOG.open("a", encoding="utf-8") as f:
    for a in actions:
        a["date"] = "2026-09-10"
        f.write(json.dumps(a, ensure_ascii=False) + "\n")
TRANS.write_text(json.dumps({
    "generated": "2026-09-10",
    "base": "nvd_cwe_check_full_20260908.jsonl 的行号基准为 v2_16（10151 行）；本表给出对应 v2_17 行号",
    "method": "user 消息内容 sha1 前 16 位唯一匹配（重复内容与已删除行置 null）",
    "map": table,
}, ensure_ascii=False, indent=1), encoding="utf-8")

# 自检
objs2 = [json.loads(l) for l in MAP.open(encoding="utf-8") if l.strip()]
assert len(objs2) == len(objs), "条目数变化"
oor = [(o["cve"], s["line"]) for o in objs2 for s in o["samples"] if s["line"] > N16 or s["line"] < 1]
assert not oor, f"仍存在越界引用：{oor}"
for cve, items in UNBIND.items():
    for ln, _, _ in items:
        o = next(x for x in objs2 if x["cve"] == cve)
        assert all(s["line"] != ln for s in o["samples"]), f"{cve} 行 {ln} 未被解绑"
for cve, items in REBIND.items():
    o = next(x for x in objs2 if x["cve"] == cve)
    for ln, _, _ in items:
        assert any(s["line"] == ln for s in o["samples"]), f"{cve} 行 {ln} 未被改绑"

print("\n" + "-" * 60)
print(f"快照 → {SNAP.name}")
print(f"动作日志 → {LOG.name}（+{len(actions)} 条）")
print(f"行号翻译表 → {TRANS.name}（{resolved}/{len(ref_lines)} 可解析）")
print(f"自检：{len(objs2)} 条 CVE / 越界引用 0 条 / 8 组解绑落位 / 3 组改绑落位")
print(f"      绑定行总数 {sum(len(o['samples']) for o in objs2)}（修复前 {N_BIND_BEFORE}）")
