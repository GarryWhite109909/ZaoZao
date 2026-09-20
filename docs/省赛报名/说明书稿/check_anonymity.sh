#!/usr/bin/env bash
# 系统设计说明书 · 匿名与合规终检
#
# 用法：bash check_anonymity.sh [PDF路径]
#   不带参数：检查说明书稿/ 下的正文篇（02_* ~ 11_*）
#   带 PDF 路径：检查该 PDF 的文本层
#
# ⚠️ 检查范围说明（重要）：
#   最终交付 PDF = 官方封面 + 正文。官方封面模板本身含「作者 / 指导老师 / 单位」
#   字段，按模板填写必然出现身份信息 —— 这是官方模板要求，与匿名条款的冲突
#   需向组委会确认，不属本脚本可裁决范围。
#   因此本脚本只对【正文 PDF】要求零命中：
#       bash check_anonymity.sh build/说明书正文.pdf        ← 推荐
#   若对整个最终 PDF 运行，封面命中属预期，请人工确认后忽略。
#   可用 --allow-cover 显式声明"接受封面命中"。
#
# 依赖：pdftotext（poppler-utils）
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET=""
ALLOW_COVER=0

for arg in "$@"; do
  case "$arg" in
    --allow-cover) ALLOW_COVER=1 ;;
    *) TARGET="$arg" ;;
  esac
done

# ---------- 红线词表 ----------
# 身份信息：学校 / 姓名 / 真实用户名 / 模型全名 / 联系方式
# 队员名单（2026-09-20 更新，新增谭依晴）；新增队员时必须同步追加到本词表
TEAM_MEMBERS='白明耀|易卓玥|谭依晴'
IDENTITY_PATTERN="衡阳|师范|陈纪友|${TEAM_MEMBERS}|GarryWhite|garrywhite|graduation-vuln-scanner|@qq\.com|3284263390"
# 真实 GitHub 仓库地址（排除通用占位 user/repo）
REPO_PATTERN='github\.com/(?!user/)[A-Za-z0-9._-]+/[A-Za-z0-9._-]+'
# 口径红线：不得出现的模型版本（未接入产品）
FORBIDDEN_MODEL_PATTERN='α0\.6|α06|alpha0[._]6|alpha06'
# 未实测估计值（素材库明令禁止）
ESTIMATE_PATTERN='10-20% ?有候选|80% ?(的)?文件不(调|进)|大约 ?[0-9]+% ?的?文件'

fail=0

check_text() {
  local label="$1" body="$2"
  local h1 h2 h3 h4

  h1="$(printf '%s' "$body" | grep -nE "$IDENTITY_PATTERN" || true)"
  h2="$(printf '%s' "$body" | grep -nP "$REPO_PATTERN" 2>/dev/null | grep -v 'github\.com/user/' || true)"
  h3="$(printf '%s' "$body" | grep -nE "$FORBIDDEN_MODEL_PATTERN" || true)"
  h4="$(printf '%s' "$body" | grep -nE "$ESTIMATE_PATTERN" || true)"

  if [[ -n "$h1$h2$h3$h4" ]]; then
    echo "  [FAIL] ${label}"
    [[ -n "$h1" ]] && printf '%s\n' "$h1" | sed 's/^/        身份词:   /'
    [[ -n "$h2" ]] && printf '%s\n' "$h2" | sed 's/^/        仓库地址: /'
    [[ -n "$h3" ]] && printf '%s\n' "$h3" | sed 's/^/        禁用版本: /'
    [[ -n "$h4" ]] && printf '%s\n' "$h4" | sed 's/^/        未实测估计: /'
    fail=1
  else
    echo "  [ok]   ${label}"
  fi
}

echo "== 匿名与口径终检 =="
echo "身份词：${IDENTITY_PATTERN}"
echo "禁用版本：${FORBIDDEN_MODEL_PATTERN}"
echo

if [[ -n "${TARGET}" && -f "${TARGET}" ]]; then
  command -v pdftotext >/dev/null 2>&1 || { echo "  [error] 未安装 pdftotext（apt install poppler-utils）"; exit 2; }
  echo "检查 PDF：${TARGET}"
  if [[ ${ALLOW_COVER} -eq 1 ]]; then
    echo "  [info] 已声明 --allow-cover：封面页的身份信息命中将被忽略，请人工确认"
  fi
  check_text "PDF 文本层" "$(pdftotext -layout "${TARGET}" - 2>/dev/null)"
else
  echo "检查 Markdown 正文篇（02_*.md ~ 11_*.md；00_/01_/素材索引 为制作说明，跳过）"
  shopt -s nullglob
  files=("${SCRIPT_DIR}"/0[2-9]_*.md "${SCRIPT_DIR}"/1[01]_*.md)
  shopt -u nullglob
  [[ ${#files[@]} -eq 0 ]] && echo "  [warn] 暂未发现正文篇文件（02_*.md ~ 11_*.md）"
  for f in "${files[@]}"; do
    check_text "$(basename "$f")" "$(cat "$f")"
  done
fi

echo
echo "== 死链与图片嵌入检查 =="
shopt -s nullglob
md_files=("${SCRIPT_DIR}"/0[2-9]_*.md "${SCRIPT_DIR}"/1[01]_*.md)
shopt -u nullglob

# md 相对内链（转 PDF 后必为死链）
link_found=0
for f in "${md_files[@]}"; do
  hits="$(grep -nE '\]\([^)]*\.md([)#?][^)]*)?\)' "$f" || true)"
  if [[ -n "$hits" ]]; then
    echo "  [FAIL] $(basename "$f") 含 md 内链（转 PDF 后死链）："
    printf '%s\n' "$hits" | sed 's/^/        /'
    link_found=1; fail=1
  fi
done
[[ ${link_found} -eq 0 ]] && echo "  [ok]   未发现 md 内链"

# 图片嵌入检查
# 说明：正文统一引用 assets/<稳定名>，该目录由 build_pdf.sh 生成；
#       因此这里只做"语法正确性 + 由构建脚本保证可解析"的校验：
#       1) 引用必须走 assets/ 前缀（不得直引仓库路径，保证打包后可构建）；
#       2) 若 assets/ 已生成，则逐个核对文件确实存在；
#       3) 未生成时仅提示（构建脚本负责从素材包/仓库布局拷贝）。
img_bad_syntax=0
for f in "${md_files[@]}"; do
  hits="$(grep -nE '!\[[^]]*\]\((?!assets/)[^)]+\)' "$f" 2>/dev/null \
          | grep -vE '!\[[^]]*\]\(assets/' || true)"
  if [[ -n "$hits" ]]; then
    echo "  [FAIL] $(basename "$f") 图片未走 assets/ 前缀（打包后可能失效）："
    printf '%s\n' "$hits" | sed 's/^/        /'
    img_bad_syntax=1; fail=1
  fi
done
[[ ${img_bad_syntax} -eq 0 ]] && echo "  [ok]   图片引用均走 assets/ 前缀"

if [[ -d "${SCRIPT_DIR}/assets" ]]; then
  img_missing=0; img_declared=0
  # 已声明的缺口（README §三 缺口清单）：需实机截取，缺失不阻断构建
  DECLARED_GAPS="vscode_diagnostic.png intellij_balloon.png model_drawer.png theme_transition.gif batch_progress.png"
  for f in "${md_files[@]}"; do
    while IFS= read -r img; do
      [[ -z "$img" ]] && continue
      base="${img##*/}"
      if [[ ! -f "${SCRIPT_DIR}/${img}" ]]; then
        if [[ " ${DECLARED_GAPS} " == *" ${base} "* ]]; then
          echo "  [gap]  已声明缺口：${base}（需实机截取，见 README 缺口清单）"
          img_declared=1
        else
          echo "  [FAIL] $(basename "$f") 引用的图片不存在：${img}"
          img_missing=1; fail=1
        fi
      fi
    done < <(grep -oE '!\[[^]]*\]\(assets/[^)]+\)' "$f" | sed 's/.*(\(assets\/[^)]*\)).*/\1/' | sort -u)
  done
  [[ ${img_missing} -eq 0 ]] && echo "  [ok]   assets/ 中除已声明缺口外，正文引用的图片全部存在"
  [[ ${img_declared} -eq 1 ]] && echo "  [warn] 存在已声明缺口，成稿前须补齐"
else
  echo "  [info] assets/ 尚未生成，跳过存在性核对（先跑 bash build_pdf.sh）"
fi

echo
if [[ ${fail} -eq 0 ]]; then
  echo "== 通过 =="; exit 0
else
  echo "== 未通过：请按上文逐条修正后重跑 =="; exit 1
fi
