#!/usr/bin/env bash
# 凿凿 AI 漏洞扫描器 —— 一键卸载（Linux / macOS）
# 用法:
#   bash uninstall.sh              # 交互确认模式
#   bash uninstall.sh --yes        # 全自动
#   bash uninstall.sh --dry-run    # 模拟，只查看不删除
# 注意:
#   - 请在与安装依赖时相同的 Python 环境（conda/venv/系统 Python）中运行，
#     卸载脚本只清理“运行它的那个环境”。
#   - 实验/训练环境（如 graproj、AI）不要执行卸载。
set -euo pipefail
cd "$(dirname "$0")"

echo "============================================================"
echo "  凿凿 AI 漏洞扫描器 —— 一键卸载"
echo "  将清理：后端进程、Python 依赖、Ollama 及模型、"
echo "          NVIDIA/ROCm/Apple 加速栈、本地数据、"
echo "          编辑器插件、项目文件夹"
echo "============================================================"
echo "  提示：如果在 conda/venv 环境里安装过依赖，"
echo "        请先激活同一个环境再运行本脚本。"
echo "  参数：--yes 全自动 / --dry-run 模拟 / --keep-* 保留部分内容"
echo "============================================================"

if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    echo "错误：未找到 python3 / python，请先安装 Python 3.10+。" >&2
    exit 1
fi

exec "$PY" uninstall.py "$@"
