# -*- coding: utf-8 -*-
"""git 历史瘦身第二轮驱动（2026-10-09）：剔除第一轮漏网的比赛材料。

背景：2026-09-27 第一轮 filter-repo（tools/filter_repo_driver_20260927.py）清了
docs/论文/*.pptx、省赛报名、exe、models/adapter/，但遗漏了：
  1. 根目录的 Nivis：基于分层裁决式AI的漏洞分析系统.pptx（7.3MB 答辩PPT，
     3ea6273 加入、2f1b1c9 删除——模式只匹配 docs/论文/ 前缀，没覆盖根目录）
  2. docs/论文/ 下 PPT/答辩 类文本（口播稿、话语库、审查报告、参赛校对稿），
     HEAD 已删但历史仍可达

本轮全部目标都不在 HEAD 工作树中（运行前已核验），HEAD 树哈希应保持不变：
  3204f8c22a730233f25a6024881decc9de10efd1
运行前提：工作区干净；--force 允许在非 fresh clone 上执行。
运行后 origin 远端会被 filter-repo 移除，需重新 git remote add origin。
"""
import git_filter_repo as fr


def filename_callback(filename_bytes):
    p = filename_bytes.decode("utf-8", errors="replace")
    # 1. 根目录答辩 PPT（旧文件名带全角冒号，endswith 匹配任何目录层级的同名文件）
    if p.endswith("Nivis：基于分层裁决式AI的漏洞分析系统.pptx"):
        return b""
    # 2. docs/论文/ 下 PPT / 答辩 / 参赛 类文本（均为 HEAD 已删的历史遗留；
    #    HEAD 论文目录文件名均不含这些词，运行前已核验零交集）
    if p.startswith("docs/论文/") and any(
        k in p.rsplit("/", 1)[-1] for k in ("PPT", "答辩", "HNCPC")
    ):
        return b""
    return filename_bytes


# --partial：本仓库已跑过 09-27 第一轮（.git/filter-repo/already_ran 存在），
# 非交互环境下需显式声明这是新一轮继续过滤，否则会卡在 Y/N 询问
args = fr.FilteringOptions.parse_args(["--force", "--partial"])
fr.RepoFilter(args, filename_callback=filename_callback).run()
