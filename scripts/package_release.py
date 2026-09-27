#!/usr/bin/env python3
"""HNCPC 参赛包（可安装软件）打包脚本 —— 覆盖式 v2（2026-09-22 重写）。

== 为什么重写 ==
v1 以「v2 包的 211 文件清单」为**固定基线**（`/tmp/old_zip_manifest.txt`），只额外
`EXTRA` 少数文件。后果：**基线之后新增的文件永远不会进包**，而包内文档的链接会
引用它们 → 断链（实测：README/用户手册 引用的 `docs/项目历程.md`、`docs/实验路线图.md`
仓库里有、包里没有）。且该基线文件一旦丢失，脚本直接跑不起来。

v2 改为**覆盖式**：枚举仓库工作区 → 按排除清单筛 → 打包。
**"仓库 = 打包唯一事实来源"由此从口号变为结构保证**（读的就是当前工作区，
不存在"包落后仓库"这种状态）。

== 用法 ==
    python scripts/package_release.py --dry-run          # 只出清单，不写 ZIP（建议先跑）
    python scripts/package_release.py                    # 产出 ZIP
    python scripts/package_release.py <输出路径>

== 可切换开关（对应 2026-09-22 审查里的待定项，默认=现状）==
    --with-eval-kit        带上评估复现物（scripts/score_batch.py 等 + experiments/scoring_config/）
                           ※ 说明书 §3.6.0 与附录 D 承诺「随附评估脚本一键复现」；不开则承诺落空
    --without-distill-protocol
                           不带 docs/prompts/*_prompt.md 与 docs/方法论_新蒸馏方法论.md
    --without-learned-registry
                           出厂清空 models/signal_registry.json（改成空结构）→ 评委首跑=空池起步

== 硬性排除（不可关闭）==
    __pycache__/.git/node_modules/dist/outputs/... 等构建垃圾
    experiments/            实验产物（体积大、含内部分数与语料）※--with-eval-kit 只放行 scoring_config
    data/                   运行期数据（向量库），由首启构建
    models/conformal_calibration*.json
                            共形校准件——in-sample 拟合、覆盖率保证不成立（说明书 §4.3.2/§5.2.3
                           声明"生产未校准"）。**若进包，解压运行即自动加载并打印
                           `[TwoStageScanner] 共形校准已加载`，当场推翻说明书声明。**
    docs/ 内部审计与过程件（清单见 INTERNAL_DOCS）
"""
from __future__ import annotations

import argparse
import re
import stat
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO.parent / "衡阳师范学院1号作品+信息安全类+可安装软件_v5.ZIP"
ARC_PREFIX = "ZaoZao/"          # 包内根目录名（评委解压后看到的结构）
# 基线为 v2 包的 211 文件，保持稳定（参赛包结构评委已见过）
LEGACY_FILE_COUNT_HINT = 211

# ---------------------------------------------------------------- 排除清单
# 两套匹配，缺一不可（2026-09-22 实测教训）：
#   · EXCLUDE_SEGMENTS —— 路径**任一层级**出现该目录名即排除。`.gradle`/`.idea` 这类
#     既可能出现在仓库根、也可能出现在 `app/intellij-extension/` 下。
#   · EXCLUDE_PREFIXES —— 多段前缀（`docs/论文/` 这类）。
# 只用前缀匹配会把 `app/intellij-extension/.gradle/`（24 个构建缓存）、`.idea/`（6）、
# `bin/*.class`（5）整批漏进交付包；只用单段集合又会把 `docs/论文/`、`.preview/`
# 整批放进来（清单会从 ~200 膨胀到 844 文件 / 27.4 GB）。两次都真实发生过。

# 目录名（任一层级命中即整棵排除）
EXCLUDE_SEGMENTS = {
    "__pycache__", ".gradle", ".idea", ".vscode", ".cache", ".venv",
    "node_modules", "dist", "outputs", ".git", ".zcode", ".preview",
    ".workbuddy", ".codebuddy",
}

# 多段前缀（命中即整棵排除）
EXCLUDE_PREFIXES = (
    "app/intellij-extension/bin/",         # IDE 编译中间产物（正式插件包在 releases/）
    "docs/_archive/", "docs/论文/", "docs/省赛报名/",   # 内部资料（含实名/内部分数）
    "experiments/",                        # 实验产物（仅放行 scoring_config/）
    "data/",                               # 运行期数据（向量库由首启构建）
    "models/ollama/", "models/transformers/", "models/llamacpp/",
    "models/alpha06log/",
    "models/adapter_alpha06_stage1/", "models/adapter_alpha06_stage2/",  # 未接入产品的训练产物
    "models/adapter_alpha05_stage1/",      # stage1 仅兜底；--with-stage1-adapter 可放行
    "docs/logo/",                          # 与 app/backend/static/logo/ 互为副本（前端用后者）
    "scripts/ppt_slim/", "tools/_archive/",
    "tools/release_model.sh",              # 模型发布工具链（内部）
    "tools/merge_lora.py",
    "tools/Modelfile",
    "scripts/recall_audit.py",             # 内部评测脚本（与"软件运行"无关）
    "scripts/rescore_offline.py",
)

# 单文件排除（仓库相对路径）
EXCLUDE_FILES = {
    "规划.md", "TODO.md",                 # 内部规划/待办，且引用了 experiments/ 路径
    "scripts/package_release.py",         # 自身：注释里写死学校名（无用且有风险）
    "scripts/rebalance_rolling_dev.py",   # 内部实验脚本，含 /home/<user> 路径
    "scripts/check_terminology.py",
    "scripts/verify_listform_cmd_fix.py",
    "tools/install_rocm_7.2.4.sh",        # 开发机专用 ROCm 版本脚本
    "tools/revert_rocm_to_ubuntu.sh",
    "wave2_宿舍工作包_20260913.zip",        # 内部协作工作包（26 MB ×2）
    "wave2_宿舍工作包_20260913_v2.zip",
    ".gitignore", ".gitattributes",        # 仓库配置文件，交付无意义
}

EXCLUDE_SUFFIX = (".pyc", ".pyo")
EXCLUDE_NAME = {"graduation_project.egg-info", "zaozao.egg-info"}

# docs/ 只留用户向文档（Garry 2026-09-22：包内只放"核心运行代码 + 产物"）
DOCS_ALLOW = {
    "docs/用户手册.md",
    "docs/项目历程.md",
}

# docs/ 白名单之外的 docs 文件一律不随包（见 DOCS_ALLOW）——含研究过程文档
# （方法论_*/方法.md/管线分层与依据.md/实验路线图.md/蒸馏出题协议等）。

# 评估复现物（说明书 §3.6.0 与附录 D 明文承诺"随附评估脚本一键复现"）。
# 默认随包 = 让交付物自洽；若改为不随包，必须同步改说明书的措辞。
EVAL_KIT = {
    "scripts/score_batch.py",
    "scripts/weighted_score.py",
    "experiments/scoring_config/weights_20260903.json",
}

# 不可入包（安全/口径）：无论开关如何都排除
FORBIDDEN_PATTERNS = (
    re.compile(r"^models/conformal_calibration.*\.json$"),
)

# ---------------------------------------------------------------- 检查用的关键词

IDENTITY_KEYWORDS = [
    "衡阳师范", "陈纪友", "白明耀", "易卓玥", "谭依晴", "晏碧涛",
    "87531880", "/home/zane", "C:/Users/zane", "C:\\Users\\zane",
]
# 说明书承诺必须随包的物证
REQUIRED_IN_PACKAGE = [
    "app/launcher/start_windows.bat",
    "app/launcher/start_linux_macos.sh",
    "app/launcher/vuln_scanner_cli.py",
    "app/backend/main.py",
    "graduation_project/two_stage_scanner.py",
    "releases/vuln-scanner-1.3.0.vsix",
    "releases/vuln-scanner-0.1.0.zip",
    "requirements.txt",
    "uninstall.py", "uninstall.sh", "uninstall_windows.bat",
    "README.md", "快速上手.md",
    "models/semgrep_rules/security-audit.yaml",
    "graduation_project/semgrep_rules/sqli_taint.yaml",
]
TEXT_SUFFIXES = (".md", ".py", ".js", ".json", ".yaml", ".yml", ".toml",
                 ".bat", ".sh", ".html", ".css", ".java", ".xml", ".txt")


# ---------------------------------------------------------------- 清单构建

def build_manifest(args) -> list[str]:
    """枚举仓库 → 按段/前缀/单文件排除 → 返回仓库相对路径（正斜杠）列表。"""
    rels: list[str] = []
    for p in sorted(REPO.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(REPO).as_posix()
        # 目录名（任一层级）
        if set(rel.split("/")) & EXCLUDE_SEGMENTS:
            continue
        # 多段前缀（含两个可放行的例外）
        if any(rel.startswith(pref) for pref in EXCLUDE_PREFIXES):
            if rel in EVAL_KIT and args.with_eval_kit:
                pass
            elif rel.startswith("models/adapter_alpha05_stage1/") and args.with_stage1_adapter:
                pass
            else:
                continue
        if rel in EXCLUDE_FILES:
            continue
        if any(rx.match(rel) for rx in FORBIDDEN_PATTERNS):
            continue
        if p.suffix in EXCLUDE_SUFFIX:
            continue
        if p.name in EXCLUDE_NAME:
            continue
        # docs/ 走白名单：只留用户向文档
        if rel.startswith("docs/") and rel not in DOCS_ALLOW:
            continue
        if rel in EVAL_KIT and not args.with_eval_kit:
            continue
        if rel.startswith("experiments/") and rel not in EVAL_KIT:
            continue
        rels.append(rel)
    return rels


def build_zip(rels: list[str], out: Path, args) -> tuple[int, int]:
    total = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for rel in rels:
            src = REPO / rel
            data = src.read_bytes()
            if (not args.with_learned_registry) and rel == "models/signal_registry.json":
                data = b'{\n  "signals": {},\n  "learn_pool": {}\n}\n'
            if src.suffix == ".bat" and b"\r\n" not in data[:4096]:
                data = data.replace(b"\n", b"\r\n")        # cmd.exe 兼容
            elif src.suffix == ".sh":
                data = data.replace(b"\r\n", b"\n")        # Linux bad interpreter 规避
            zi = zipfile.ZipInfo(ARC_PREFIX + rel)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = (stat.S_IFREG | (0o755 if src.suffix in (".sh", ".py") else 0o644)) << 16
            zi.create_system = 3
            z.writestr(zi, data)
            total += len(data)
    return len(rels), total


# ---------------------------------------------------------------- 干跑检查

def scan_links(rels: set[str]) -> list[str]:
    """包内 md 的内链是否都落在包里。"""
    bad = []
    for rel in sorted(rels):
        if not rel.endswith(".md"):
            continue
        try:
            s = (REPO / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        base = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
        for m in re.finditer(r"\]\(([^)#\s]+\.(?:md|png|jpg|json|yaml))\)", s):
            tgt = m.group(1)
            if tgt.startswith(("http://", "https://", "mailto:")):
                continue
            norm = str(Path(base + tgt).as_posix())
            # 归一化 ../ 
            while "/../" in norm:
                norm = re.sub(r"[^/]+/\.\./", "", norm, count=1)
            if norm not in rels:
                bad.append(f"{rel} -> {tgt}")
    return bad


def scan_identity(rels: list[str]) -> list[str]:
    hits = []
    for rel in sorted(rels):
        if not rel.lower().endswith(TEXT_SUFFIXES):
            continue
        try:
            s = (REPO / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for k in IDENTITY_KEYWORDS:
            if k in s:
                hits.append(f"{rel}  ← {k}")
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description="HNCPC 参赛包（覆盖式打包）")
    ap.add_argument("out", nargs="?", default=None, help="输出 ZIP 路径")
    ap.add_argument("--dry-run", action="store_true", help="只出清单，不写文件")
    # 默认随包 = 让交付物与说明书自洽（说明书明文承诺"随附评估脚本一键复现"）
    ap.add_argument("--with-eval-kit", dest="with_eval_kit", action="store_true", default=True)
    ap.add_argument("--without-eval-kit", dest="with_eval_kit", action="store_false",
                    help="不随包；若选这个，必须同步改说明书 §3.6.0/附录 D 的措辞")
    ap.add_argument("--with-stage1-adapter", action="store_true",
                    help="连 stage1 适配器一起发（+87 MB；stage1 仅作兜底，出货默认不含）")
    ap.add_argument("--with-learned-registry", action="store_true",
                    help="保留 signal_registry.json 的已学习态（默认出厂清空=全新安装语义）")
    args = ap.parse_args()
    out = Path(args.out) if args.out else DEFAULT_OUT

    rels = build_manifest(args)
    relset = set(rels)
    total = sum((REPO / r).stat().st_size for r in rels)

    print(f"清单：{len(rels)} 个文件 / {total / 1e6:.1f} MB（未压缩）")
    print(f"  （v2 基线为 {LEGACY_FILE_COUNT_HINT} 个；覆盖式下新增文件会自动纳入）")

    # 顶层分布
    tops: dict[str, int] = {}
    for r in rels:
        k = "/".join(r.split("/")[:2]) if "/" in r else r
        tops[k] = tops.get(k, 0) + 1
    print("\n顶层分布：")
    for k, v in sorted(tops.items()):
        print(f"  {v:5d}  {k}")

    # 硬性排除的确认
    forbidden = sorted(r for r in relset if any(rx.match(r) for rx in FORBIDDEN_PATTERNS))
    print(f"\n[不可入包项] 命中 {len(forbidden)} 个（应为 0）：{forbidden}")

    # 说明书承诺物
    missing = [r for r in REQUIRED_IN_PACKAGE if r not in relset]
    print(f"\n[承诺物核对] 缺 {len(missing)} 项：{missing if missing else '无'}")

    # 断链
    bad = scan_links(relset)
    print(f"\n[包内内链] 断链 {len(bad)} 处：")
    for b in bad[:15]:
        print(f"    {b}")
    if len(bad) > 15:
        print(f"    …另有 {len(bad) - 15} 处")

    # 身份信息
    idh = scan_identity(rels)
    print(f"\n[身份信息] 命中 {len(idh)} 处（应为 0）：")
    for h in idh[:20]:
        print(f"    {h}")
    if len(idh) > 20:
        print(f"    …另有 {len(idh) - 20} 处")

    # 待定项
    print("\n[出厂默认策略]")
    print(f"    评估复现物（说明书 §3.6.0/附录 D 承诺）："
          f"{'已随包（承诺自洽）' if args.with_eval_kit else '未随包 ← 承诺落空，须改说明书措辞'}")
    print(f"    docs/ 随包：{sorted(r for r in relset if r.startswith('docs/'))}")
    print(f"    models/signal_registry.json："
          f"{'已学习态（--with-learned-registry）' if args.with_learned_registry else '出厂清空（全新安装语义）'}")
    print(f"    models/adapter_alpha05_stage1/："
          f"{'随包（--with-stage1-adapter）' if 'models/adapter_alpha05_stage1/adapter_model.safetensors' in relset else '不随包（仅 stage2）'}")
    print(f"    .github/workflows/pr-review.yml（说明书 §3.2.5 引用）："
          f"{'随包' if '.github/workflows/pr-review.yml' in relset else '未随包'}")

    if args.dry_run:
        print("\n[dry-run] 未写出任何文件。")
        return 0

    n, tot = build_zip(rels, out, args)
    print(f"\n打包 {n} 个文件 → {out}（{out.stat().st_size / 1e6:.1f} MB）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
