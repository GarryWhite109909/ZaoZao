"""
网页抓取服务 —— 抓取目标 URL 的所有 <script> 标签内容（内联 + 外链），
用于 URL 扫描入口。

安全策略（2026-08 加固）：
- 仅允许 http/https，并拦截内网/回环/链路本地/保留地址（防 SSRF）
- 手动跟随重定向（最多 5 跳），每一跳都重新校验目标地址
- 响应体大小上限（HTML 与脚本均 2MB），防止内存被打满
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests

# 单个响应体最大字节数
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
# 最大重定向跳数
MAX_REDIRECTS = 5
# 允许的 URL scheme
ALLOWED_SCHEMES = ("http", "https")


@dataclass
class FetchedScript:
    """抓取到的单个脚本片段。"""
    source: str  # "inline" | 外链 URL
    language: str  # "javascript" | "html"
    content: str
    char_count: int = 0

    def __post_init__(self):
        self.char_count = len(self.content)


@dataclass
class FetchResult:
    """URL 抓取结果。"""
    url: str
    title: str = ""
    scripts: list[FetchedScript] = field(default_factory=list)
    inline_html: str = ""  # 含事件处理器的 HTML 片段
    error: str | None = None

    @property
    def total_scripts(self) -> int:
        return len(self.scripts)


def _resolve_ips(host: str, port: int) -> set:
    """解析主机名的全部 IP（解析失败返回空集）。"""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        return set()
    return {info[4][0] for info in infos}


def validate_target_url(url: str) -> str | None:
    """校验目标 URL 是否允许抓取；返回 None=允许，否则返回错误信息。

    含 DNS rebinding 缓解：requests 无法把"校验时的解析结果"钉到连接上
    （TOCTOU 窗口客观存在，HTTPS 下改写 Host 又会破坏 SNI/TLS），此处采用
    双重解析一致性校验收窄窗口——两次解析 IP 集合不一致（rebinding 特征）
    则直接拒绝。
    """
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return "URL 格式无效"
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return f"仅支持 {'/'.join(ALLOWED_SCHEMES)} 协议"
    hostname = parsed.hostname
    if not hostname:
        return "URL 缺少主机名"
    if port is not None and not (1 <= port <= 65535):
        return "端口号无效"
    host = hostname.rstrip(".").lower()
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    ips_first = _resolve_ips(host, port or default_port)
    if not ips_first:
        return f"无法解析主机名: {host}"
    for ip_str in ips_first:
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified
        ):
            return f"禁止访问内网/保留地址: {ip_str}"
    # 二次解析一致性校验（DNS rebinding 缓解）
    if _resolve_ips(host, port or default_port) != ips_first:
        return f"DNS 解析结果不一致（疑似 DNS rebinding）: {host}"
    return None


def _read_limited(resp: requests.Response, limit: int = MAX_RESPONSE_BYTES) -> str:
    """流式读取响应体，超过 limit 立即截断。"""
    chunks = []
    total = 0
    for chunk in resp.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        total += len(chunk)
        if total > limit:
            chunks.append(chunk[: limit - (total - len(chunk))])
            break
        chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _safe_get(session: requests.Session, url: str, timeout: int, redirects_left: int = MAX_REDIRECTS):
    """带 SSRF 校验与重定向控制的 GET 请求。

    Returns:
        (requests.Response | None, str | None)：成功返回响应与 None，失败返回 (None, 错误信息)。
    """
    err = validate_target_url(url)
    if err:
        return None, err
    try:
        resp = session.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0)"},
            allow_redirects=False,
            stream=True,
        )
    except requests.RequestException as e:
        return None, f"{type(e).__name__}: {e}"

    if resp.is_redirect:
        location = resp.headers.get("location")
        resp.close()
        if not location:
            return None, "重定向缺少 Location 头"
        if redirects_left <= 0:
            return None, "重定向次数过多"
        return _safe_get(session, urljoin(url, location), timeout, redirects_left - 1)
    return resp, None


def fetch_url(url: str, timeout: int = 15) -> FetchResult:
    """抓取目标 URL，提取所有 JS 脚本和可疑 HTML 片段。

    Args:
        url: 目标网页 URL
        timeout: 请求超时秒数

    Returns:
        FetchResult，scripts 至少包含 0 个元素。
    """
    result = FetchResult(url=url)
    session = requests.Session()

    resp, err = _safe_get(session, url, timeout)
    if err:
        result.error = err
        return result
    try:
        resp.raise_for_status()
        html = _read_limited(resp)
    except requests.HTTPError as e:
        status = e.response.status_code if e.response is not None else "?"
        result.error = f"HTTP {status}"
        return result
    except requests.RequestException as e:
        # 正文流式读取阶段的中断（ChunkedEncodingError / ConnectionError 等）
        # 原先只捕 HTTPError，这类异常会穿透成 url-scan 500
        result.error = f"读取中断 ({type(e).__name__})"
        return result
    finally:
        resp.close()

    # 提取 title
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        result.title = m.group(1).strip()

    # 提取内联 <script>...</script>
    inline_pattern = re.compile(
        r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>",
        re.IGNORECASE | re.DOTALL,
    )
    for m in inline_pattern.finditer(html):
        content = m.group(1).strip()
        if content:
            result.scripts.append(FetchedScript(
                source="inline",
                language="javascript",
                content=content,
            ))

    # 提取外链 <script src="...">
    src_pattern = re.compile(
        r'<script[^>]*\bsrc=["\']([^"\']+)["\'][^>]*>',
        re.IGNORECASE,
    )
    for m in src_pattern.finditer(html):
        src_url = m.group(1)
        full_url = urljoin(url, src_url)
        js_resp, js_err = _safe_get(session, full_url, timeout)
        if js_err:
            continue  # 外链失败不阻断，跳过
        try:
            js_resp.raise_for_status()
            result.scripts.append(FetchedScript(
                source=full_url,
                language="javascript",
                content=_read_limited(js_resp),
            ))
        except requests.RequestException:
            # HTTPError / ChunkedEncodingError / ConnectionError 统统跳过该外链
            continue
        finally:
            js_resp.close()

    # 提取含事件处理器的 HTML 片段（onclick=, onload= 等）
    event_pattern = re.compile(
        r"<[^>]+\bon\w+\s*=\s*[\"'][^\"']+[\"'][^>]*>",
        re.IGNORECASE,
    )
    event_matches = event_pattern.findall(html)
    if event_matches:
        result.inline_html = "\n".join(event_matches[:20])  # 限制数量
        result.scripts.append(FetchedScript(
            source="inline-html-events",
            language="html",
            content=result.inline_html,
        ))

    return result


if __name__ == "__main__":
    # 自检
    import sys
    if len(sys.argv) < 2:
        print("用法: python fetcher.py <url>")
        sys.exit(1)
    r = fetch_url(sys.argv[1])
    print(f"URL: {r.url}")
    print(f"Title: {r.title}")
    print(f"脚本数: {r.total_scripts}")
    for i, s in enumerate(r.scripts, 1):
        print(f"  [{i}] {s.source[:60]} ({s.language}, {s.char_count} 字符)")
    if r.error:
        print(f"错误: {r.error}")