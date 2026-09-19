# -*- coding: utf-8 -*-
"""
checkov 启动器（2026-09-09 修复）

背景：PATH 上的 python 是隔离环境（workbuddy 3.13.12），**没有安装 checkov**；
      checkov 实际装在 D:\\miniconda。原 checkov.cmd 因此坠入 ".py 关联缺失" 分支。
      旧版还写成 `from checkov.main import checkov` —— 模块里并没有这个名字，
      正确的是 `Checkov` 类。

用法（必须用 miniconda 解释器，不要用 PATH 上的 python）：
    D:\\miniconda\\python.exe run_checkov.py --framework dockerfile --compact -d <目录>

已验证的坑：
  1. `-f 单文件` 模式无效 —— checkov 只扫目录里命名为 Dockerfile* 的文件。
     单样本要先落到临时目录并改名为 Dockerfile 再扫。
  2. 不要加 --quiet，它会把 FAILED/PASSED 判定一起吞掉。
  3. 传 argv 时不要带程序名（Checkov 直接把列表喂给 parse_args）。
"""
import sys

from checkov.main import Checkov

if __name__ == "__main__":
    sys.argv = ["checkov"] + sys.argv[1:]
    sys.exit(Checkov().run())
