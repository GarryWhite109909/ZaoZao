# -*- coding: utf-8 -*-
"""git 历史瘦身驱动（2026-09-27）：从全部历史中剔除已归档的比赛材料与二进制。

剔除范围（对历史中每个 blob 的路径判定）：
  1. docs/省赛报名/                       比赛材料（已归档 _archive_20260927）
  2. docs/论文/*.pptx                     全部历史版本的答辩 PPT
  3. docs/论文/ppt-rework-20260903/       旧 PPT 工作目录
  4. docs/论文/ppt图片提取*               PPT 图片提取
  5. docs/论文/screenshots/               PPT 截图（已归档）
  6. *.exe                                实测门/仲裁僵局等 307 个测试编译产物
  7. models/adapter/                      旧路径 adapter 副本（safetensors×2 + gguf，
                                          现 adapter 在 models/adapter_alpha0x_stagey/，保留）
运行前提：工作区干净；--force 允许在非 fresh clone 上执行。
"""
import git_filter_repo as fr


def filename_callback(filename_bytes):
    p = filename_bytes.decode("utf-8", errors="replace")
    if p.startswith("docs/省赛报名"):
        return b""
    if p.startswith("docs/论文/") and p.endswith(".pptx"):
        return b""
    if p.startswith("docs/论文/ppt-rework-20260903"):
        return b""
    if p.startswith("docs/论文/ppt图片提取"):
        return b""
    if p.startswith("docs/论文/screenshots"):
        return b""
    if p.endswith(".exe"):
        return b""
    if p.startswith("models/adapter/"):
        return b""
    return filename_bytes


args = fr.FilteringOptions.parse_args(["--force"])
fr.RepoFilter(args, filename_callback=filename_callback).run()
