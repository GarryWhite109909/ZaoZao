#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""仿真模拟密钥生成器 + 训练集密钥迁移工具。

背景（2026-09-07 密钥普查）：v2_15 中 38 个不同 sk_live_ 串约 87% 不仿真——
2/3 是纯十六进制体（真实 Stripe 键为 base62 随机），其余多为顺序行走
（9f8e7d…）或占位词（123456/abc123）。教师样本从此类假形态学到的
"硬编码密钥长什么样"会欠拟合真实世界的 base62 高熵键。

政策（2026-09-07）：
- 训练数据一律不入仓库（训练语料渲染包 pack_* 已 gitignore）；
- 模拟密钥必须真实一点：base62 密码学随机、熵 ≥4.2、禁 hex 体与顺序序列；
- 高熵 sk_live_ 组合只允许存在于本地数据，永不写入任何会公开的文件
  （公开面用官方文档示例键或 sk_test_ 前缀）。

用法：
  # 生成（供蒸馏管线/造数脚本 import 或 CLI 调用）
  python scripts/simulated_credentials.py gen --provider stripe --mode test --count 5
  python scripts/simulated_credentials.py gen --provider github --mode live

  # 迁移既有数据集（同串全局一致替换；保持前缀与长度；引文自动同步）
  python scripts/simulated_credentials.py migrate --data data/final_train_chatml_alpha06_v2_15.jsonl --dry-run
  python scripts/simulated_credentials.py migrate --data data/final_train_chatml_alpha06_v2_15.jsonl --apply

迁移只替换"不仿真"的密钥（hex 体/顺序行走/占位词/低多样性）；
已是 base62 高熵的串保持不动。--apply 前自动落快照，变更写对账 changelog。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import secrets
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
ENTROPY_FLOOR = 4.2

# 顺序行走片段（hex/字母表升 or 降），命中即重造
_SEQ = re.compile(
    r"(?:0123|1234|2345|3456|4567|5678|6789|789a|89ab|9abc|abcd|bcde|cdef"
    r"|fedc|edcb|dcba|cba9|ba98|a987|9876|8765|7654|6543|5432|4321|3210"
    r"|9f8e|8e7d|7d6c|6c5b|5b4a|efgh|ghij|hijk|ijkl|jklm|klmn|lmno|mnop"
    r"|ponm|onml|nmlk|mlkj|lkji|kjih|jihg|ihgf|hgfe|gfed|fedc)", re.IGNORECASE)

PROVIDERS = {
    # name: (前缀模板, body 长度区间, 字符集, 熵下限)
    # 熵下限按 字符集大小×长度 校准：短 body 的理论样本熵上限低（AWS 16 位@36 字符集 ≈3.7）
    "stripe": ("sk_{mode}_", (24, 60), BASE62, 4.2),
    "stripe_pk": ("pk_{mode}_", (24, 34), BASE62, 4.0),
    "aws_access_key": ("AKIA", (16, 16), "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 3.3),
    "github": ("ghp_", (36, 36), BASE62, 4.2),
    "slack": ("xoxb-", (30, 40), BASE62 + "-", 4.2),
}


def shannon(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def _ok(body: str, charset: str, floor: float) -> bool:
    if any(ch not in charset for ch in body):
        return False
    if _SEQ.search(body):
        return False
    if shannon(body) < floor:
        return False
    # 单字符重复率过高也重造（如同一字符占 1/4 以上）
    if Counter(body).most_common(1)[0][1] > max(4, len(body) // 4):
        return False
    return True


def gen_body(n: int) -> str:
    """生成 n 位 base62 高熵体（Stripe 全系密钥共用；过短时由调用方抬高 n）。"""
    charset, floor = PROVIDERS["stripe"][2], PROVIDERS["stripe"][3]
    for _ in range(200):
        body = "".join(secrets.choice(charset) for _ in range(n))
        if _ok(body, charset, floor):
            return body
    raise RuntimeError("200 次采样未通过校验")


def gen_key(provider: str = "stripe", mode: str = "test", length: int | None = None) -> str:
    """生成一个格式/熵均逼近真实形态的模拟密钥。"""
    if provider not in PROVIDERS:
        raise ValueError(f"未知 provider: {provider}（可选 {sorted(PROVIDERS)}）")
    template, (lo, hi), charset, floor = PROVIDERS[provider]
    n = length if length is not None else secrets.choice(range(lo, hi + 1))
    if provider == "stripe":
        return template.format(mode=mode) + gen_body(n)
    for _ in range(200):
        body = "".join(secrets.choice(charset) for _ in range(n))
        if _ok(body, charset, floor):
            return template.format(mode=mode) + body
    raise RuntimeError("200 次采样未通过校验，请检查 charset/长度配置")


# ---- 迁移：识别"不仿真"的既有密钥 ----

KEY_TOKEN = re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,120}\b")


def is_unrealistic(key: str) -> str | None:
    """返回不仿真的原因；仿真达标返回 None（保持不动）。"""
    body = key.split("_", 2)[2]
    if re.search(r"123456|abc123|xxxx|placeholder|example", key, re.I):
        return "占位词"
    if _SEQ.search(body):
        return "顺序行走"
    if re.fullmatch(r"[0-9a-fA-F]+", body):
        return "纯十六进制体"
    if len(set(body)) <= 6:
        return "字符多样性低"
    if shannon(body) < ENTROPY_FLOOR:
        return f"熵低({shannon(body):.2f})"
    return None


def build_plan(raw: str) -> dict:
    """扫描整份数据集原文，产出 old→new 一致替换计划（同旧串全局映射到同一新串）。"""
    legacy = sorted({m.group(0) for m in KEY_TOKEN.finditer(raw) if is_unrealistic(m.group(0))})
    mapping = {}
    for old in legacy:
        prefix, body = old.rsplit("_", 1)[0] + "_", old.split("_", 2)[2]
        mapping[old] = {"new": None, "reason": is_unrealistic(old), "len": len(body)}
    # 逐个生成替换串：保留原前缀（pk_/sk_/rk_ 语义不同，不得漂移），只换 body。
    # 长度：保持原长；但 base62@4.2 熵需要 ≥22 位才可达，过短的旧键升到 24 位
    #（真实 Stripe 键普遍更长，升长反而更仿真）
    kept = {m.group(0) for m in KEY_TOKEN.finditer(raw)} - set(legacy)
    for old, meta in mapping.items():
        head = old[: old.rfind("_") + 1]
        n = max(meta["len"], 24)
        for _ in range(500):
            cand = head + gen_body(n)
            if cand not in kept and cand not in mapping.values():
                meta["new"] = cand
                break
        if meta["new"] is None:
            raise RuntimeError(f"无法为 {old} 生成不冲突的替换串")
    return {"mapping": mapping}


def migrate(data_path: Path, apply_changes: bool) -> int:
    raw = data_path.read_text(encoding="utf-8")
    plan = build_plan(raw)
    mapping = {k: v["new"] for k, v in plan["mapping"].items()}
    n_lines_changed = sum(1 for line in raw.splitlines() if line and any(k in line for k in mapping))
    print(f"发现不仿真密钥 {len(mapping)} 个（涉及 {n_lines_changed} 行）；替换示意（前 5）：")
    for old in list(mapping)[:5]:
        print(f"  {old[:14]}… → {mapping[old][:14]}…  ({plan['mapping'][old]['reason']})")
    if not apply_changes:
        plan_path = data_path.with_suffix(".keyplan.json")
        plan_path.write_text(json.dumps(plan, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"[dry-run] 计划已写 {plan_path.name}；确认后加 --apply 执行")
        return 0

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    snap = data_path.with_name(data_path.stem + f".pre_keyfix_{stamp}{data_path.suffix}")
    snap.write_text(raw, encoding="utf-8")

    def swap(line: str) -> str:
        # 单遍正则回调：KEY_TOKEN 贪婪匹配天然取最长 token，避免前缀嵌套的
        # 旧键（如 28 位是 40 位的前缀）被短键替换毁掉长键
        return KEY_TOKEN.sub(lambda m: mapping.get(m.group(0), m.group(0)), line)

    out_lines, touched = [], 0
    for line in raw.splitlines():
        if not line.strip():
            continue
        new_line = swap(line)
        json.loads(new_line)  # 替换后必须仍可解析
        if new_line != line:
            touched += 1
        out_lines.append(new_line)
    data_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")

    log = {
        "action": "simulated_key_migration",
        "data_file": data_path.name,
        "snapshot": snap.name,
        "snapshot_sha256": hashlib.sha256(raw.encode()).hexdigest()[:16],
        "mapping": plan["mapping"],
        "lines_touched": touched,
        "applied_at": stamp,
    }
    log_path = data_path.parent / f"keyfix_changelog_{stamp}.json"
    log_path.write_text(json.dumps(log, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[apply] 已替换 {len(mapping)} 个密钥、触及 {touched} 行；"
          f"快照 {snap.name}，对账 {log_path.name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen", help="生成模拟密钥")
    g.add_argument("--provider", default="stripe", choices=sorted(PROVIDERS))
    g.add_argument("--mode", default="test", choices=["test", "live"], help="stripe 专用")
    g.add_argument("--count", type=int, default=1)
    g.add_argument("--length", type=int, default=None)
    m = sub.add_parser("migrate", help="数据集内不仿真密钥迁移")
    m.add_argument("--data", required=True, type=Path)
    m.add_argument("--dry-run", action="store_true")
    m.add_argument("--apply", action="store_true")
    args = ap.parse_args(argv)

    if args.cmd == "gen":
        for _ in range(args.count):
            print(gen_key(args.provider, args.mode, args.length))
        return 0
    if args.cmd == "migrate":
        return migrate(args.data, apply_changes=args.apply and not args.dry_run)
    return 1


if __name__ == "__main__":
    sys.exit(main())
