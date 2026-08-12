"""
Semgrep registry 规则本地化工具 —— 把 `p/xxx` 在线规则包拉到项目目录。

背景：semgrep 的 `p/security-audit` / `p/owasp-top-ten` 等 registry 规则包
每次运行都从 semgrep.dev 重新下载到临时文件，无持久缓存、离线不可用，且
规则包名不存在（如 p/owasp-top-10，已 404）会导致每次运行联网降级拖慢。
本工具把规则主动拉取到 `models/semgrep_rules/`（与 models/transformers、
models/ollama 同一"模型/资产放项目目录"分类模式），扫描时
external_scanner 用 `--config <本地 yaml>` 完全离线运行。

用法：
    python tools/fetch_semgrep_rules.py            # 拉取全部默认规则包（幂等）
    python tools/fetch_semgrep_rules.py --check    # 只检查是否已本地化

代理：尊重 HTTPS_PROXY / HTTP_PROXY 环境变量（requests 自动读取）；
     也可 --proxy http://127.0.0.1:7897 显式指定。
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# 默认规则包：registry 包名 → 本地文件名（下载内容即 rules.yaml 文本）
DEFAULT_PACKAGES = {
    "p/security-audit": "security-audit.yaml",
    "p/owasp-top-ten": "owasp-top-ten.yaml",
}
_REGISTRY_URL = "https://semgrep.dev/c/{pkg}"


def _rules_dir() -> Path:
    from graduation_project.paths import semgrep_rules_dir
    return semgrep_rules_dir()


def _http_get(url: str, proxies: dict | None) -> bytes:
    import requests
    resp = requests.get(url, timeout=60, proxies=proxies)
    resp.raise_for_status()
    return resp.content


def fetch_package(pkg: str, target: Path, proxies: dict | None) -> bool:
    """拉取单个 registry 包到 target；已存在且非空则跳过（幂等）。"""
    if target.is_file() and target.stat().st_size > 0:
        return True  # 已本地化，跳过
    url = _REGISTRY_URL.format(pkg=pkg)
    print(f"  [fetch] {pkg} → {target.name}（{url}）...")
    try:
        content = _http_get(url, proxies)
    except Exception as e:
        print(f"  [FAIL] {pkg} 拉取失败: {e}（联网或代理配置是否正确？）")
        return False
    if not content.strip():
        print(f"  [FAIL] {pkg} 返回空内容")
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    # 校验：本地 yaml 文件跑 semgrep 时 rules 数应与在线一致
    print(f"  [OK]   {pkg} → {target.name}（{len(content)} bytes）")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--proxy", default="", help="HTTP 代理地址，如 http://127.0.0.1:7897（默认读环境变量）")
    ap.add_argument("--check", action="store_true", help="只检查是否已全部本地化，不拉取")
    args = ap.parse_args()

    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}
    else:
        env_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        if env_proxy:
            proxies = {"http": env_proxy, "https": env_proxy}

    rules_dir = _rules_dir()
    missing = [pkg for pkg, fname in DEFAULT_PACKAGES.items()
               if not (rules_dir / fname).is_file()]
    if not missing:
        print(f"全部规则已本地化（{rules_dir}），无需拉取。")
        return 0
    if args.check:
        print(f"缺失规则包: {missing}（运行 tools/fetch_semgrep_rules.py 拉取）")
        return 1

    print(f"拉取 Semgrep registry 规则到项目目录: {rules_dir}")
    ok = all(fetch_package(pkg, rules_dir / fname, proxies)
             for pkg, fname in DEFAULT_PACKAGES.items())
    if ok:
        print(f"\n完成：{len(DEFAULT_PACKAGES)} 个规则包已本地化，"
              f"external_scanner 将离线使用（--config <本地 yaml>）。")
        return 0
    print("\n部分规则包拉取失败（可稍后重试；缺失时 external_scanner 自动降级）。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
