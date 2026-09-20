#!/usr/bin/env python3
"""HNCPC 参赛包（可安装软件）打包脚本。

2026-09-20 引入：v2 包是在打包机上手工挑文件打的，与仓库脱节——发出去的
ZIP 落后工作区 753 行未提交改动、prompts.py 停留在 9 天前、缺 URL 扫描演示
靶页与新写的 c_cmdi 规则。本脚本让"仓库 = 打包唯一事实来源"：

- 清单：以 v2 包的 211 个文件为基线（参赛包结构评委已见过，保持稳定），
  全部内容取自当前仓库工作区；并显式追加基线里没有的新文件（见 EXTRA）。
- 行尾：.bat 统一 CRLF（老 cmd 的兼容最保险），.sh 统一 LF，其余保持仓库
  原样（Linux 评委机器上 CRLF 的 .sh 会直接报 `bad interpreter`，绝不放开）。
- 排除：__pycache__/构建产物/锁文件等开发垃圾；5 GB 的 Ollama 模型与实验
  adapter 仍不随包分发（与 v2 口径一致，由首启引导拉取）。

用法：python3 scripts/package_release.py [输出路径]
默认输出到仓库同级目录：衡阳师范学院1号作品+信息安全类+可安装软件_v3.ZIP
"""
import stat
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO.parent / "衡阳师范学院1号作品+信息安全类+可安装软件_v3.ZIP"
OLD_MANIFEST = Path("/tmp/old_zip_manifest.txt")  # 由 v2 包生成的基线清单

# v2 基线之外的追加项（仓库相对路径 → 包内 ZaoZao/ 前缀路径）
EXTRA = [
    "demo-site/index.html",                              # URL 扫描演示靶页（0bc123a）
    "graduation_project/semgrep_rules/c_cmdi_system.yaml",
    "models/signal_registry.json",                       # 信号注册表学习池，缺了从空池起步
    "快速上手.md",                                        # v2 包里是打包现场手写的，仓库此前没有
]
# 基线中允许缺席的文件（仓库已删除/移走的，缺了不报错）
OPTIONAL_BASELINE = {
    # 本地工作区已无此文件（chroma 运行时自动重建向量库），按仓库现状打包
    "data/chroma_db/chroma.sqlite3",
}

EXCLUDE_PARTS = {
    "__pycache__", ".gradle", "build", "node_modules", ".git",
    ".idea", ".vscode", ".cache", "dist", "outputs",
}
EXCLUDE_SUFFIX = (".pyc", ".pyo", ".lock#", "#")
EXCLUDE_NAME = {"graduation_project.egg-info", "zaozao.egg-info"}


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    base = sorted(OLD_MANIFEST.read_text().splitlines()) if OLD_MANIFEST.exists() else []
    if not base:
        print("错误：找不到 v2 基线清单 /tmp/old_zip_manifest.txt", file=sys.stderr)
        return 1

    rels = [n[len("ZaoZao/"):] for n in base if n.startswith("ZaoZao/")]
    rels += [r for r in EXTRA if r not in rels]

    missing, packed = [], []
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for rel in rels:
            src = REPO / rel
            if not src.is_file():
                if rel not in OPTIONAL_BASELINE:
                    missing.append(rel)
                continue
            if any(p in EXCLUDE_PARTS for p in src.parts):
                continue
            if src.suffix in EXCLUDE_SUFFIX or src.name in EXCLUDE_NAME:
                continue
            data = src.read_bytes()
            if src.suffix == ".bat" and b"\r\n" not in data[:4096]:
                data = data.replace(b"\n", b"\r\n")   # cmd.exe 兼容
            elif src.suffix == ".sh":
                data = data.replace(b"\r\n", b"\n")   # Linux 上 CRLF 会 bad interpreter
            zi = zipfile.ZipInfo("ZaoZao/" + rel)
            zi.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if src.suffix in (".sh", ".py") else 0o644
            zi.external_attr = (stat.S_IFREG | mode) << 16
            zi.create_system = 3  # unix
            z.writestr(zi, data)
            packed.append(rel)

    print(f"打包 {len(packed)} 个文件 → {out}（{out.stat().st_size / 1e6:.1f} MB）")
    if missing:
        print("基线中存在但仓库缺失（未打包）：")
        for m in missing:
            print("  -", m)
        return 2
    print("基线全覆盖，无缺失。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
