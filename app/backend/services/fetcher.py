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
import os
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

# ---------------------------------------------------------------------------
# 公共库过滤（2026-08-30，URL 扫描提速）：抓取的每个脚本都要过两阶段扫描
# （3 次 LLM 采样，实测 ~70s/个），第三方公共库（jQuery/GA/bundle 等）不是
# 站点自有攻击面，全量扫直接把整页扫描拖到数十分钟。按"公共 CDN 域名 +
# 库名路径关键词"两级模式过滤，只匹配 URL 形态、不猜内容——站点自有代码
# （/static/app.js 等）不受影响；同名自托管库被过滤也安全（库本身非攻击面）。
# ---------------------------------------------------------------------------
# 公共 CDN / 分析统计服务的域名（子域匹配）
_LIB_HOST_RE = re.compile(
    r"(?:^|\.)(?:"
    r"jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com|bootcdn\.net|"
    r"staticfile\.org|jquery\.com|code\.jquery\.com|jqueryui\.com|"
    r"ajax\.googleapis\.com|fonts\.googleapis\.com|gstatic\.com|"
    r"googletagmanager\.com|google-analytics\.com|googlesyndication\.com|"
    r"doubleclick\.net|cloudflareinsights\.com|bootstrapcdn\.com|"
    r"connect\.facebook\.net|analytics\.tiktok\.com|snap\.licdn\.com|"
    r"hm\.baidu\.com|cdn\.cnzz\.com|s\.cnzz\.com|pos\.baidu\.com|"
    r"matomo\.cloud|piwik\.pro|clarity\.ms|mc\.yandex\.ru|"
    r"hotjar\.com|fullstory\.com|mouseflow\.com|smartlook\.com|"
    r"mixpanel\.com|segment\.(?:io|com)|amplitude\.com|heapanalytics\.com|"
    r"sentry\.io|browser\.sentry-cdn\.com|newrelic\.com|nr-data\.net|"
    r"bugsnag\.com|rollbar\.com|trackjs\.com|datadoghq\.com|"
    r"intercom\.(?:io|cdn)|widget\.intercom\.io|static\.zdassets\.com|"
    r"tawk\.to|disqus\.com|addthis\.com|sharethis\.com|addtoany\.com|"
    r"recaptcha\.net|hcaptcha\.com|turnstile\.cloudflare\.com|"
    r"js\.stripe\.com|paypal(?:objects)?\.com|checkout\.razorpay\.com|"
    r"criteo\.com|taboola\.com|outbrain\.com|amazon-adsystem\.com|"
    r"adsbygoogle\.com|at\.alicdn\.com"
    r")$",
    re.IGNORECASE,
)
# 注意：本正则只对 hostname 匹配（is_common_library_url 传入 parsed.hostname），
# hostname 永不含 "/"——带路径的模式（如 google.com/recaptcha、gitee.com/libs、
# taobao.com/a.js）必须写进下方 _LIB_NAME_RE（对 URL path 匹配），写在这里永不命中。
# 路径/文件名中的库名关键词（词边界防误杀：/myapp/reactive-api.js 不含 react 库形态）
# 尾部允许一个"扩展名尾巴"（.min.js / .js / .bundle.js 等）：只有 jquery 显式写了
# \.min\.js，其余库名会漏掉 /resources/js/bootstrap.min.js 这类自托管副本（站点把
# CDN 库下载到自己服务器，形态与站点自有代码相同）——按"库本身非攻击面"原则同样过滤
_LIB_NAME_RE = re.compile(
    r"(?:^|[/_.-])(?:"
    r"jquery[\w.-]{0,10}\.min\.js|jquery(?:[-.]ui|-mobile|\.[0-9])?|zepto(?:\.min)?|"
    r"prototype(?:\.min)?|mootools|backbone(?:\.min)?|underscore(?:\.min)?|"
    r"lodash(?:\.min)?|moment(?:\.min)?(?:-with-locales)?|dayjs(?:\.min)?|"
    r"angular(?:\.min)?(?:-animate|-route|-aria)?|react(?:\.production|-dom|\.min)?(?:-dom\.production)?|"
    r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?|bootstrap(?:\.bundle|\.min)?|"
    r"popper(?:\.min)?|chart(?:\.umd|\.min)?|echarts(?:\.min)?|d3(?:\.v[0-9]+)?(?:\.min)?|"
    r"three(?:\.module)?(?:\.min)?|swiper(?:\.bundle)?(?:\.min)?|gsap(?:\.min)?|"
    r"gtag(?:/js|\.)|gtm\.js|googletagmanager\.js|fbevents\.js|pixel(?:\.min)?\.js|"
    r"analytics(?:\.min)?\.js|hm\.js|web-sdk|js-sdk|td\.js|ga\.js|"
    # 带域名才有意义的库（自 _LIB_HOST_RE 迁入的路径形态）：reCAPTCHA /
    # Yandex Metrika。
    # 2026-09-20 收窄（宁可少拦、不可误杀站点自有脚本）：libs 改为要求路径段
    # 形式 libs(?=/)（即 /libs/…，裸 libs 连 /mysite/libs.py 都会误杀）；删除裸
    # a\.js（任何叫 a.js 的站点自有脚本都会被误杀）；pixel/analytics 收窄为
    # 要求 .js 文件名形态（裸 analytics 连 /api/analytics 路径都会误杀）
    r"recaptcha|metrika|libs(?=/)"
    r")(?:\.[\w.]*)?(?:$|[/?#])",
    re.IGNORECASE,
)


def is_common_library_url(url: str) -> bool:
    """判断脚本 URL 是否为公共 CDN 库 / 统计分析脚本。

    仅按 URL 形态（域名 + 路径关键词）判断，不下载内容。
    纯函数，供 fetcher 过滤与单测复用。
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").rstrip(".").lower()
        path = parsed.path or ""
    except ValueError:
        return False
    if _LIB_HOST_RE.search(host):
        return True
    # 路径关键词：/js/jquery-3.6.0.min.js、/gtag/js?id= 等
    probe = f"{path.lower()}"
    if _LIB_NAME_RE.search(probe):
        return True
    return False


def is_minified_bundle(content: str) -> bool:
    """判断脚本是否为打包/压缩后的构建产物（纯文本启发式，无网络请求）。

    命中条件（内容 ≥ 4KB 时任一满足）：
      - 带 sourceMappingURL 注释（打包器产出标志）；
      - 平均行长 > 250 字符（正常源码平均约 30-40）；
      - 或超过一半的行单行 > 2000 字符。

    压缩产物标识符被破坏、变量名全毁，LLM 语义裁决价值极低且召回多为
    打包器形态的假阳性（gitee 实测 53/57 个 webpack chunk 全部进裁决、
    逐条被驳回，预算几乎白烧）。URL 扫描入口据此默认跳过并显式回报
    （VULN_SCANNER_SCAN_MINIFIED=1 恢复全量扫描）。
    """
    if not content or len(content) < 4096:
        return False
    if "sourceMappingURL=" in content[-4000:]:
        return True
    lines = content.split("\n")
    if not lines:
        return False
    if len(content) / len(lines) > 250:
        return True
    long_lines = sum(1 for ln in lines if len(ln) > 2000)
    return long_lines >= max(1, len(lines) // 2)


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
    skipped_libs: list[str] = field(default_factory=list)  # 被公共库过滤跳过的外链
    # 2026-09-20 新增：因 max_scripts 预算在下载前被截断的外链（供前端提示，
    # 与"公共库"区分——这些不是库，只是预算外）
    skipped_budget: list[str] = field(default_factory=list)
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


def _proxy_configured_for(scheme: str, host: str) -> bool:
    """判断该请求是否将经 HTTP 代理发出（requests 遵循环境变量代理）。

    代理模式下 requests 把主机名原样交给代理、由代理解析并建连——本机
    getaddrinfo 的结果与实际连接目标无关，IP 级 SSRF 校验（内网地址/rebinding
    复检）只在直连时有意义。大陆网络下 jsdelivr/github.io 等域名本机 DNS
    被污染（解析为空），但经代理完全可达（实测 HTTP 200）。
    """
    if scheme not in ("http", "https"):
        return False
    no_proxy = {
        h.strip().lower().lstrip(".")
        for h in (os.environ.get("NO_PROXY", "") + "," + os.environ.get("no_proxy", "")).split(",")
        if h.strip()
    }
    if "*" in no_proxy:
        return False
    for pat in no_proxy:
        if host == pat or host.endswith("." + pat):
            return False
    env = os.environ
    if scheme == "https":
        proxy = (env.get("HTTPS_PROXY") or env.get("https_proxy")
                 or env.get("ALL_PROXY") or env.get("all_proxy"))
    else:
        proxy = (env.get("HTTP_PROXY") or env.get("http_proxy")
                 or env.get("ALL_PROXY") or env.get("all_proxy"))
    return bool(proxy and proxy.strip())


def validate_target_url(url: str) -> str | None:
    """校验目标 URL 是否允许抓取；返回 None=允许，否则返回错误信息。

    含 DNS rebinding 缓解：requests 无法把"校验时的解析结果"钉到连接上
    （TOCTOU 窗口客观存在，HTTPS 下改写 Host 又会破坏 SNI/TLS），此处采用
    双重解析校验收窄窗口——复检出现内网地址（rebinding 特征）则直接拒绝。

    代理模式例外（2026-09-20）：请求将经 HTTP 代理发出时（环境变量配置，
    且主机不在 NO_PROXY），本机解析失败不再一票拒绝——连接目标是代理，
    由代理解析并建连，本机 DNS（可能被污染为空）与实际连接无关。IP 级
    校验在能解析时照常执行。
    """
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return "URL 格式无效"
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return f"仅支持 {'/'.join(ALLOWED_SCHEMES)} 协议"
    hostname = parsed.hostname
    if not hostname:
        return "URL 缺少主机名"
    if port is not None and not (1 <= port <= 65535):
        return "端口号无效"
    host = hostname.rstrip(".").lower()
    default_port = 443 if scheme == "https" else 80
    proxied = _proxy_configured_for(scheme, host)
    ips_first = _resolve_ips(host, port or default_port)
    if not ips_first:
        if proxied:
            return None  # 代理模式：由代理解析，本机 DNS 污染不阻断（见 docstring）
        return f"无法解析主机名: {host}"
    for ip_str in ips_first:
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified
        ):
            return f"禁止访问内网/保留地址: {ip_str}"
    # 二次解析复检（DNS rebinding 缓解）：第二次解析只要求"仍可解析且全部为
    # 公网地址"，不再要求与第一次完全一致——严格相等会把 Azure Front Door /
    # Cloudflare 等解析结果轮换的 CDN 站点误判成 rebinding（实测 demo.owasp-
    # juice.shop 被误拦）。rebinding 攻击的特征是"后续解析返回内网 IP"，
    # 复检内网地址即可守住该防线（剩余 TOCTOU 窗口与严格相等时相同）。
    ips_second = _resolve_ips(host, port or default_port)
    if not ips_second:
        if not proxied:
            return f"DNS 二次解析失败（疑似 DNS rebinding）: {host}"
        # 代理模式：本机二次解析失败（污染/抖动）不阻断，由代理解析
        return None
    for ip_str in ips_second:
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified
        ):
            return f"二次解析出现内网/保留地址（疑似 DNS rebinding）: {ip_str}"
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


def fetch_url(
    url: str,
    timeout: int = 15,
    skip_common_libs: bool = True,
    max_scripts: int | None = None,
) -> FetchResult:
    """抓取目标 URL，提取所有 JS 脚本和可疑 HTML 片段。

    Args:
        url: 目标网页 URL
        timeout: 请求超时秒数
        skip_common_libs: 是否跳过公共 CDN/统计分析库（这些脚本不是站点
            自有攻击面，却各消耗 3 次 LLM 采样，是 URL 扫描慢的主因）。
            被跳过的外链记入 result.skipped_libs 供前端提示。
        max_scripts: 脚本总数预算（None 不设限）。2026-09-20 修复（审计）：
            预算检查前移到外链**下载之前**——原先所有外链全量下载完，才由
            上层扫描预算截断，预算外脚本的流量（各至多 2MB）白白消耗。
            达到预算后未下载的外链记入 result.skipped_budget 供前端提示。

    Returns:
        FetchResult，scripts 至少包含 0 个元素。
    """
    result = FetchResult(url=url)
    session = requests.Session()
    # 2026-09-20 修复（审计）：Session 显式关闭——原先依赖 GC 回收底层连接池，
    # 长驻后端进程反复抓取会泄漏 socket/fd
    try:
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
        # src= 前用 (?<![\w-]) 而非 \b：\b 会被 data-src= / lazy-src= 里的 "-" 边界
        # 误判为外链，导致真实内联逻辑被漏扫
        inline_pattern = re.compile(
            r"<script(?![^>]*(?<![\w-])src=)[^>]*>(.*?)</script>",
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
            if skip_common_libs and is_common_library_url(full_url):
                result.skipped_libs.append(full_url)
                continue  # 公共库不下载、不进扫描
            # 预算检查必须在下载之前（2026-09-20 前移，见 docstring）
            if max_scripts is not None and len(result.scripts) >= max_scripts:
                result.skipped_budget.append(full_url)
                continue
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
    finally:
        session.close()


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