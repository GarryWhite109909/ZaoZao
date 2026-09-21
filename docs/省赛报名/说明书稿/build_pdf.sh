#!/usr/bin/env bash
# 系统设计说明书 PDF 构建脚本
# 用法：bash build_pdf.sh
# 依赖：pandoc、xelatex(texlive-xetex)、fonts-noto-cjk
#
# 目录自适应：脚本自动探测"仓库布局"或"素材包布局"两种取图位置。
#   - 仓库布局：docs/省赛报名/说明书稿/  → 图在 docs/论文/figures/ 等
#   - 素材包布局：系统设计说明书_素材包/01_说明书稿/ → 图在 ../04_图片资产/
set -euo pipefail

# ---------- 路径探测 ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSETS_DIR="${SCRIPT_DIR}/assets"
BUILD_DIR="${SCRIPT_DIR}/build"
MERGED_MD="${BUILD_DIR}/说明书合并.md"
OUTPUT_PDF="${BUILD_DIR}/说明书正文.pdf"

FIG_SRC=""      # 架构与数据图目录
SHOT_SRC=""     # 界面截图目录
SNAP_SRC=""     # 待补插件截图目录

if [[ -d "${SCRIPT_DIR}/../04_图片资产/架构与数据图" ]]; then
  # 素材包布局
  LAYOUT="素材包"
  FIG_SRC="${SCRIPT_DIR}/../04_图片资产/架构与数据图"
  SHOT_SRC="${SCRIPT_DIR}/../04_图片资产/界面截图"
  SNAP_SRC="${SCRIPT_DIR}/../04_图片资产/待补截图清单"
elif [[ -d "${SCRIPT_DIR}/../../../docs/论文/figures" ]]; then
  # 仓库布局
  LAYOUT="仓库"
  PROJ_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
  FIG_SRC="${PROJ_ROOT}/docs/论文/figures"
  SHOT_SRC="${PROJ_ROOT}/docs/论文/ppt图片提取_20260903"
  SNAP_SRC="${PROJ_ROOT}/docs/论文/screenshots"
else
  echo "[error] 无法定位图片资产目录（既非素材包布局也非仓库布局）"
  echo "        期望其一：${SCRIPT_DIR}/../04_图片资产/架构与数据图"
  echo "                  ${SCRIPT_DIR}/../../../docs/论文/figures"
  exit 1
fi

echo "构建布局：${LAYOUT}"
mkdir -p "${ASSETS_DIR}" "${BUILD_DIR}"

# ---------- 1. 收集图片资产 ----------
echo "[1/4] 收集图片资产 -> assets/"
# ---------- 架构与数据图 ----------
# 命名策略：正文引用稳定名；源文件可能是 _v2 版本（wave8 口径），
# 这里显式做「源名 -> 正文名」映射，避免正文跟着源文件改名。
copy_fig() {
  local dst="$1"; shift
  local f
  for f in "$@"; do
    if [[ -f "${FIG_SRC}/${f}" ]]; then
      cp -f "${FIG_SRC}/${f}" "${ASSETS_DIR}/${dst}"
      return 0
    fi
  done
  echo "  [warn] 缺失图：${dst}（候选：$*）"
  return 1
}

# 图 3-1 两阶段架构：优先 wave8（v2，含完整信任层与复核分支），回退 fixed5 版
copy_fig "two_stage_architecture.png" "two_stage_architecture_v2.png" "two_stage_architecture.png"
# 图 3-2 平台矩阵
copy_fig "backend_platform_matrix.png" "backend_platform_matrix.png"
# 图 3-4 ~ 3-8 效果指标（第三篇 §3.6）
copy_fig "sft_strict_recall_evolution.png" "sft_strict_recall_evolution.png"
copy_fig "quantization_gap.png"            "quantization_gap.png"
copy_fig "fixed_convergence.png"           "fixed_convergence.png"
copy_fig "data_lineage.png"                "data_lineage.png"
copy_fig "cost_breakdown.png"              "cost_breakdown.png"
copy_fig "alpha05_stage1_train_curve.png"  "alpha05_stage1_train_curve.png"
# 图 4-1 自研工具链 / 图 4-2 信任层 / 图 4-3 信任分级回填（优先 v2 全流程版）
copy_fig "self_developed_tools.png"   "self_developed_tools.png"
copy_fig "trust_layer_25.png"          "trust_layer_25.png"
copy_fig "trust_graded_feedback.png"   "trust_layer_25_v2.png" "trust_graded_feedback.png"
# 备份/可选（正文未引用，供队友取用）
copy_fig "two_stage_architecture_fixed5.png" "two_stage_architecture.png" 2>/dev/null || true
copy_fig "methodology_awareness_loop.png" "methodology_awareness_loop.png"
copy_fig "data_credibility_system.png"    "data_credibility_system.png"
copy_fig "data_governance_path.png"       "data_governance_path.png"
copy_fig "alpha0_train_curve.png"         "alpha0_train_curve.png"
copy_fig "architecture_three_layer.svg"   "architecture_three_layer.svg"

# 界面截图：统一重命名为正文引用的稳定名（避免正文引用含 P20 等 PPT 页码）
# 映射：正文名 <- 源文件名
copy_shot() {
  local dst="$1"; shift
  local f
  for f in "$@"; do
    if [[ -f "${SHOT_SRC}/${f}" ]]; then
      cp -f "${SHOT_SRC}/${f}" "${ASSETS_DIR}/${dst}"
      return 0
    fi
  done
  echo "  [warn] 缺失截图：${dst}（候选：$*）"
  return 1
}
copy_shot "ui_dashboard.png"      "P20_原图_仪表盘截图主.png"
copy_shot "ui_scan_workbench.png" "P21_原图_扫描工作台截图.png"
copy_shot "ui_scan_result.png"    "P21_原图_CWE详情放大卡片.png"
copy_shot "ui_cwe_library.png"    "P23_原图_CWE样本库截图.png"
copy_shot "ui_cwe_detail.png"     "P23_原图_CWE79详情弹窗.png"
copy_shot "ui_report_history.png" "P22_原图_报告历史截图.png"
# 安全态势拆两半（2026-09-19 自 PPT 新提取，比原拼图更清晰）
copy_shot "ui_posture_top.png"    "P24_原图_安全态势上半.png" "P24-25_原图_安全态势截图.png"
copy_shot "ui_posture_bottom.png" "P25_原图_安全态势下半.png"

# 待补素材（正文引用；缺失不阻断构建，但成稿前须补齐）
# 待补素材：缺失不阻断构建——生成浅灰占位图，让 pandoc 正常出稿，
# 并保留 [gap] 提示（成稿前必须替换为实机截图）。
# 占位图为 800x450 浅灰底 + 对角线（纯像素，无文字），一次性内联 base64，无外部依赖。
PLACEHOLDER_B64="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"
# 2026-09-21：编辑器插件与设置/主题截图已就位；IntelliJ 未实机安装，正文改文字说明，
# 故只保留以下三张（缺失时仍生成占位，见下）。
for pair in "vscode_plugin.png" "model_drawer.png" "theme_compare.png"; do
  if [[ -f "${SNAP_SRC}/${pair}" ]]; then
    cp -f "${SNAP_SRC}/${pair}" "${ASSETS_DIR}/"
    echo "  [ok]   待补素材已就位：${pair}"
  else
    echo "  [gap]  待补素材缺失：${pair}（已写入占位图，见 04_图片资产/待补截图清单/README.md）"
    printf '%s' "${PLACEHOLDER_B64}" | base64 -d > "${ASSETS_DIR}/${pair}" 2>/dev/null \
      || printf '%s' "${PLACEHOLDER_B64}" | base64 -D > "${ASSETS_DIR}/${pair}" 2>/dev/null \
      || echo "         [warn] 占位图生成失败（base64 不可用），请手动放置同名图片"
  fi
done

# ---------- 2. 合并篇文件 ----------
echo "[2/4] 合并篇文件 -> ${MERGED_MD}"
: > "${MERGED_MD}"
shopt -s nullglob
# 正文篇 = 02_* ~ 11_*（前置页 + 八篇 + 附录）；00_/01_ 为制作说明，不进 PDF 正文
for f in "${SCRIPT_DIR}"/0[2-9]_*.md "${SCRIPT_DIR}"/1[01]_*.md; do
  echo "  追加 $(basename "$f")"
  {
    cat "$f"
    printf '\n\n\\newpage\n\n'
  } >> "${MERGED_MD}"
done
shopt -u nullglob

if [[ ! -s "${MERGED_MD}" ]]; then
  echo "  [error] 未找到任何正文文件，请先创建 02_*.md ~ 11_*.md"; exit 1
fi

# ---------- 3. 生成 PDF ----------
if ! command -v pandoc >/dev/null 2>&1; then
  echo "[3/4] [error] 未找到 pandoc，无法生成 PDF。"
  echo "        已生成合并稿：${MERGED_MD}（可直接用 Typora / VS Code 预览）"
  echo "        安装工具链：sudo apt install pandoc texlive-xetex texlive-lang-chinese \\"
  echo "                                  fonts-noto-cjk poppler-utils qpdf"
  exit 1
fi
if ! command -v xelatex >/dev/null 2>&1; then
  echo "[3/4] [error] 未找到 xelatex（中文 PDF 引擎）。安装：sudo apt install texlive-xetex texlive-lang-chinese"
  exit 1
fi

echo "[3/4] pandoc -> ${OUTPUT_PDF}"
# 编号策略（互斥二选一，当前采用【方案 A】）：
#   方案 A（当前）：正文标题已手写「第X篇 / X.Y」编号 → 关闭 --number-sections，
#                   并改用 article 类（避免 report 类把 H1 渲染成英文 "Chapter N"）。
#   方案 B（备选）：去掉正文中手写的编号 + 启用 --number-sections + documentclass=report。
# 采用 A 的理由：篇名「第X篇」需保留中文序数词，自动编号无法生成。
pandoc "${MERGED_MD}" \
  -o "${OUTPUT_PDF}" \
  --pdf-engine=xelatex \
  --toc --toc-depth=3 \
  --listings \
  --highlight-style=tango \
  -V documentclass=article \
  -V geometry:a4paper,margin=2.5cm \
  -V linestretch=1.3 \
  -V CJKmainfont="Noto Serif CJK SC" \
  -V mainfont="Noto Serif" \
  -V monofont="Noto Sans Mono" \
  -V fontsize=11pt \
  -V linkcolor=black \
  -V urlcolor=blue \
  --resource-path="${ASSETS_DIR}:${SCRIPT_DIR}"

# ---------- 4. 提示后续步骤 ----------
echo "[4/4] 完成：${OUTPUT_PDF}"
cat <<'EOF'

下一步：
  1) 用 LibreOffice 打开官方封面 docx 填字段 -> 另存 PDF（先删除模板页脚提示行）
  2) 合并封面与正文：qpdf --empty --pages 封面.pdf 说明书正文.pdf -- 最终.pdf
  3) 匿名终检（只检正文 PDF，封面按官方模板填写不含在检查范围）：
       bash check_anonymity.sh 说明书正文.pdf
  4) 终检：目录页码 / 图片清晰度 / 无死链
  5) 命名：衡阳师范学院N号作品+信息安全类+系统设计说明书.pdf
EOF
