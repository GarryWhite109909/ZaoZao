# -*- coding: utf-8 -*-
"""wave2 手写代码对：CWE-441 代理/转发信任混淆 15 对（441-01..15，成对同码）。

形态映射（wave2_441_95_SPEC.md §CWE-441 形态清单）：
  441-01/02 = XFF 限流/审计信任（Python/Go）
  441-03/04 = 内网标记由请求头决定（Flask/PHP）
  441-05/06 = 回环白名单绕过 ::ffff:127.0.0.1（Python/Go）
  441-07/08 = 出站取回信任用户 URL 证书链（Python/Java，代理中继语义）
  441-09/10 = XFF 链最左信任（JS/Python）
  441-11/12 = Host 头生成绝对 URL（Go/PHP）
  441-13/14 = webhook 回调以内网身份出站（Python/Node）
  441-15    = X-Forwarded-Proto 信任（Java）
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from wave2_pairlib import emit, write_index

P = []

# ---------------- 441-01 Python：XFF 限流 ----------------
_code = '''import time
from flask import Flask, request, jsonify

app = Flask(__name__)
RATE_LIMIT = 100
window = {}

@app.before_request
def rate_limit():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    key = "rl:" + client_ip
    now = time.time()
    hits = [t for t in window.get(key, []) if now - t < 60]
    hits.append(now)
    window[key] = hits
    if len(hits) > RATE_LIMIT:
        return jsonify(error="rate limited"), 429

@app.route("/api/search")
def search():
    return jsonify(results=["ok"])
'''
P.append({
    "pid": "441-01", "lang": "Python", "cwe": "CWE-799",
    "anchor": "非 441 因为产品没有把请求转发给任何内部服务（unintended proxy 语义不成立）；"
              "非 918 因为无服务端取回；非 601 因为无浏览器跳转；攻击面是伪造 XFF 重置限流配额，"
              "按 MITRE CWE-799（交互频率控制不当）定位——预审教师轴，20260913 定版。",
    "safe_anchor": "防御为何不可旁路：限流键取自 socket 对端地址（remote_addr），由内核写入，客户端无任何头可改写；"
                   "XFF 仅进入日志字段，不参与判定，伪造 XFF 只污染日志不影响配额。",
    "oracle_vuln": [
        (r'X-Forwarded-For', "source：XFF 请求头可由客户端任意注入"),
        (r'split\(","\)\[0\]', "最左值是最不可信的一跳（最远客户端可控）"),
        (r'key = "rl:" \+ client_ip', "中跳：以可控头作为限流键"),
        (r'len\(hits\) > RATE_LIMIT', "sink：限流判定基于伪造键，换一个伪造 IP 即重置配额"),
    ],
    "oracle_safe": [
        (r'client_ip = request\.remote_addr', "防御：限流键改用 socket 对端地址，内核写入不可伪造"),
        (r'xff_log = request\.headers\.get\("X-Forwarded-For"\)', "XFF 仅作日志记录，不参与判定"),
    ],
    "vuln_code": _code,
    "safe_code": _code.replace(
        '    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()\n'
        '    key = "rl:" + client_ip',
        '    client_ip = request.remote_addr\n'
        '    xff_log = request.headers.get("X-Forwarded-For")\n'
        '    key = "rl:" + client_ip'),
})

# ---------------- 441-02 Go：XFF 审计 + 限流 ----------------
_code = '''package audit

import (
	"net/http"
	"sync"
	"time"
)

var mu sync.Mutex
var hits = map[string]int{}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip = r.RemoteAddr
		}
		mu.Lock()
		hits[ip]++
		over := hits[ip] > 600
		mu.Unlock()
		if over {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
'''
P.append({
    "pid": "441-02", "lang": "Go", "cwe": "CWE-290",
    "anchor": "非 441 因为产品无『非预期代理』转发语义；伪造内部标记头绕过鉴权按 MITRE CWE-290（欺骗绕过认证）定位——预审教师轴 20260913 定版。"
              "限流/审计主体由可伪造头决定，属于借客户端自报身份冒充网络位置的代理混淆，归 441。",
    "safe_anchor": "防御为何不可旁路：计数键固定为 r.RemoteAddr（内核从 TCP 连接写入）；"
                   "XFF 只写入审计日志字段，即使伪造也不改变计数主体。",
    "oracle_vuln": [
        (r'ip := r\.Header\.Get\("X-Forwarded-For"\)', "source：XFF 头可由客户端注入"),
        (r'hits\[ip\]\+\+', "sink：以可控头作为限流计数键"),
        (r'over := hits\[ip\] > 600', "限流判定建立在可伪造主体上"),
    ],
    "oracle_safe": [
        (r'ip := r\.RemoteAddr', "防御：计数键取 TCP 对端地址（RemoteAddr 不可伪造）"),
        (r'auditLog\.Printf\("xff=%q', "XFF 仅进审计日志"),
    ],
    "vuln_code": _code,
    "safe_code": _code.replace(
        '\t\tip := r.Header.Get("X-Forwarded-For")\n\t\tif ip == "" {\n\t\t\tip = r.RemoteAddr\n\t\t}',
        '\t\tip := r.RemoteAddr\n\t\tauditLog.Printf("xff=%q remote=%s", r.Header.Get("X-Forwarded-For"), ip)'),
})

# ---------------- 441-03 Python：内网标记头绕过鉴权 ----------------
_code = '''from flask import Flask, request, abort

app = Flask(__name__)
INTERNAL_TOOLS = {"/metrics", "/debug/vars"}

@app.before_request
def gate():
    if request.path in INTERNAL_TOOLS:
        if request.headers.get("X-Internal") != "true":
            abort(403)
        return
    if request.path.startswith("/admin") and not request.cookies.get("session"):
        abort(401)

@app.route("/metrics")
def metrics():
    return "qps=42"
'''
P.append({
    "pid": "441-03", "lang": "Python", "cwe": "CWE-290",
    "anchor": "非 441 因为无转发语义；内网标记由请求头自报决定=身份欺骗，按 CWE-290 定位——预审教师轴 20260913 定版。"
              "任何外部客户端都能声明 X-Internal: true 借内网身份访问，属代理/位置信任混淆（441），非授权逻辑缺失。",
    "safe_anchor": "防御为何不可旁路：内网身份改由 listen 边界与受信代理白名单判定——"
                   "is_internal 只认 socket 对端是否落在受控网段，请求头不再参与；伪造头无法改变对端地址。",
    "oracle_vuln": [
        (r'request\.headers\.get\("X-Internal"\)', "source：内网标记由客户端可注入头决定"),
        (r'!= "true"', "sink：标记命中即放行 INTERNAL_TOOLS"),
        (r'abort\(403\)', "拒绝分支仅覆盖未声明内网者"),
    ],
    "oracle_safe": [
        (r'peer = request\.remote_addr', "防御：对端地址为准，内核写入"),
        (r'ipaddress\.ip_address\(peer\) in TRUSTED_NETS', "受控网段白名单判定内网"),
        (r'peer is not None and ipaddress', "is_internal 仅依赖对端地址，头完全不再参与内网判定"),
    ],
    "vuln_code": _code,
    "safe_code": '''import ipaddress
from flask import Flask, request, abort

app = Flask(__name__)
INTERNAL_TOOLS = {"/metrics", "/debug/vars"}
TRUSTED_NETS = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("127.0.0.0/8")]

def is_internal():
    peer = request.remote_addr
    return peer is not None and ipaddress.ip_address(peer) in TRUSTED_NETS

@app.before_request
def gate():
    if request.path in INTERNAL_TOOLS:
        if not is_internal():
            abort(403)
        return
    if request.path.startswith("/admin") and not request.cookies.get("session"):
        abort(401)

@app.route("/metrics")
def metrics():
    return "qps=42"
''',
})

# ---------------- 441-04 PHP：调试端点头开关 ----------------
_code = '''<?php
// routes/protection.php
function guard(string $path): void {
    if (str_starts_with($path, '/internal/')) {
        $trusted = ($_SERVER['HTTP_X_FORWARDED_HOST'] ?? '') === 'ops.corp.internal';
        if (!$trusted) {
            http_response_code(403);
            exit('forbidden');
        }
    }
    if (str_starts_with($path, '/admin') && empty($_COOKIE['session'])) {
        http_response_code(401);
        exit('unauthorized');
    }
}
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
guard($path);
echo "ok";
'''
P.append({
    "pid": "441-04", "lang": "PHP", "cwe": "CWE-290",
    "anchor": "非 441 因为无转发语义；内部来源域由转发头自报决定=身份欺骗，按 CWE-290 定位——预审教师轴 20260913 定版。"
              "『是否来自内部运维域』由 X-Forwarded-Host 自报决定，属于借转发头冒充网络位置的信任错置（441）。",
    "safe_anchor": "防御为何不可旁路：内部来源改由 REMOTE_ADDR 对受信代理网段的判定决定；"
                   "X-Forwarded-Host 仅作展示信息，头值无法再影响放行分支。",
    "oracle_vuln": [
        (r"HTTP_X_FORWARDED_HOST", "source：转发主机头由客户端注入"),
        (r"=== 'ops\.corp\.internal'", "sink：内部域声明命中即放行 internal 路径"),
    ],
    "oracle_safe": [
        (r"REMOTE_ADDR", "防御：对端地址判定内部来源"),
        (r"TRUSTED_PROXY_NET", "受信代理网段白名单"),
        (r"HTTP_X_FORWARDED_HOST.*展示", "转发头仅展示用途（注释锚定）"),
    ],
    "vuln_code": _code,
    "safe_code": _code.replace(
        "$trusted = ($_SERVER['HTTP_X_FORWARDED_HOST'] ?? '') === 'ops.corp.internal';",
        "$isInternal = filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false; // TRUSTED_PROXY_NET 网段判定\n        $trusted = $isInternal; // HTTP_X_FORWARDED_HOST 仅作展示信息"),
})

# ---------------- 441-05 Python：回环白名单 ::ffff: 绕过 ----------------
_code = '''from flask import Flask, request, abort

app = Flask(__name__)
ALLOWED = {"127.0.0.1", "localhost"}

@app.route("/rotate-keys")
def rotate_keys():
    caller = request.remote_addr or ""
    if caller.startswith("::ffff:"):
        caller = caller[len("::ffff:"):]
    if caller not in ALLOWED:
        abort(403)
    return "rotated"
'''
P.append({
    "pid": "441-05", "lang": "Python", "cwe": "CWE-290",
    "anchor": "非 441 因为无转发语义；本机白名单判定被 IPv4-mapped 等价形态绕过=来源身份欺骗，按 CWE-290 定位（部署假设：双栈监听使映射形态可达；若纯 IPv4 栈则不可达，样本外）——预审教师轴 20260913 定版。"
              " 0.0.0.0、[::] 等绕过），是代理/位置身份判定的边界错置（441），非授权缺失。",
    "safe_anchor": "防御为何不可旁路：ipaddress 归一化（ip_address + IPv4Address 转换）穷尽 mapped IPv6/十六进制/"
                   "压缩写法，白名单改为 ip_network 集合判定，任何等价写法都收敛到同一地址对象。",
    "oracle_vuln": [
        (r'startswith\("::ffff:"\)', "伪防御：仅剥离单一种映射前缀，归一化不完整"),
        (r'caller not in ALLOWED', "sink：白名单比对建立在未归一化字符串上"),
    ],
    "oracle_safe": [
        (r'ipaddress\.ip_address\(addr\)', "防御：地址对象归一化，穷尽等价写法"),
        (r'and ip\.ipv4_mapped', "显式处理 IPv4-mapped IPv6"),
        (r'in LOOPBACK_NETS', "网络段集合判定，不再依赖字符串形态"),
    ],
    "vuln_code": _code,
    "safe_code": '''import ipaddress
from flask import Flask, request, abort

app = Flask(__name__)
LOOPBACK_NETS = {ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")}

def normalize(addr: str):
    ip = ipaddress.ip_address(addr)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip

@app.route("/rotate-keys")
def rotate_keys():
    caller = request.remote_addr or ""
    try:
        if normalize(caller) not in LOOPBACK_NETS:
            abort(403)
    except ValueError:
        abort(403)
    return "rotated"
''',
})

# ---------------- 441-06 Go：回环白名单 0.0.0.0 变体 ----------------
_code = '''package admin

import (
	"net"
	"net/http"
)

var loopbackNames = map[string]bool{"127.0.0.1": true, "localhost": true, "::1": true}

func Handler(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !loopbackNames[host] {
		http.Error(w, "local only", http.StatusForbidden)
		return
	}
	w.Write([]byte("admin token rotated"))
}
'''
P.append({
    "pid": "441-06", "lang": "Go", "cwe": "CWE-290",
    "anchor": "非 441 因为无转发语义；回环判定用字符串枚举漏掉等价本机形态=来源身份欺骗，按 CWE-290 定位——预审教师轴 20260913 定版。"
              "0.0.0.0 / [::] / ::ffff:127.0.0.1 等本机等价形态绕过，归 441 位置信任错置。",
    "safe_anchor": "防御为何不可旁路：net.ParseIP + ip.IsLoopback() 语义判定穷尽全部本机等价形态；"
                   "IP().Unmap() 处理 mapped IPv6，字符串枚举漏洞面消失。",
    "oracle_vuln": [
        (r'loopbackNames\[host\]', "sink：字符串枚举判定回环，等价形态漏过"),
        (r'net\.SplitHostPort', "仅拆出主机字符串，未做地址语义归一"),
    ],
    "oracle_safe": [
        (r'net\.ParseIP\(host\)', "防御：解析为地址对象"),
        (r'\.IsLoopback\(\)', "语义判定回环，穷尽等价写法"),
        (r'\.Unmap\(\)', "mapped IPv6 归一"),
    ],
    "vuln_code": _code,
    "safe_code": _code.replace(
        'var loopbackNames = map[string]bool{"127.0.0.1": true, "localhost": true, "::1": true}',
        'var _ = "defense: address-semantics loopback check"').replace(
        '\tif err != nil || !loopbackNames[host] {',
        '\tip := net.ParseIP(host)\n\tif err != nil || ip == nil || !(ip.IsLoopback() || ip.To4() == nil && ip.Unmap().IsLoopback()) {'),
})

# ---------------- 441-07 Python：出站取回信任用户 URL（证书链透传） ----------------
_code = '''import requests
from flask import Flask, request

app = Flask(__name__)

@app.route("/fetch-avatar")
def fetch_avatar():
    url = request.args.get("url", "")
    if not url:
        return "missing url", 400
    # 中继语义：以本服务身份出站，且信任用户随附的自定义 CA
    upstream = requests.get(url, verify=False, timeout=5,
                            headers={"X-Forwarded-Host": "avatar-svc.internal"})
    return upstream.content, 200
'''
P.append({
    "pid": "441-07", "lang": "Python", "cwe": "CWE-918",
    "anchor": "非 918 为主叙事的理由：除目的地未校验外，还透传了内部身份（X-Forwarded-Host: avatar-svc.internal）"
              "并禁用证书校验，攻击者借产品网络位置与内部凭证做中继（代理混淆），按 MITRE 441 的代理语义定位；"
              "若样本仅目的地未校验则应标 918。",
    "safe_anchor": "防御为何不可旁路：① 目的地限 https 且主机必须在静态 allowlist；② verify=True 固定系统信任链，"
                   "自签 CA 无法通过；③ 内部标识头由服务端常量注入，用户输入不再进入请求头。",
    "oracle_vuln": [
        (r'request\.args\.get\("url"', "source：目的地 URL 用户可控"),
        (r'verify=False', "禁用证书校验，中继可被中间人劫持"),
        (r'"X-Forwarded-Host": "avatar-svc\.internal"', "以产品内部身份出站（可被借用）"),
        (r'requests\.get\(url', "sink：对完全未校验目的地发起服务端请求"),
    ],
    "oracle_safe": [
        (r'urlparse\(url\)', "解析目的地"),
        (r'u\.hostname not in AVATAR_ALLOWLIST', "主机静态白名单"),
        (r'u\.scheme != "https"', "强制 https（不满足即拒）"),
        (r'requests\.get\(url, verify=True', "证书校验固定开启"),
        (r'headers=HEADERS_INJECT', "内部标识头由服务端常量注入"),
    ],
    "vuln_code": _code,
    "safe_code": '''import requests
from flask import Flask, request
from urllib.parse import urlparse

app = Flask(__name__)
AVATAR_ALLOWLIST = {"cdn.example.com", "avatars.example-cdn.net"}
HEADERS_INJECT = {"User-Agent": "avatar-svc/1.0"}

@app.route("/fetch-avatar")
def fetch_avatar():
    url = request.args.get("url", "")
    u = urlparse(url)
    if u.scheme != "https" or u.hostname not in AVATAR_ALLOWLIST:
        return "bad url", 400
    upstream = requests.get(url, verify=True, timeout=5, headers=HEADERS_INJECT)
    return upstream.content, 200
''',
})

# ---------------- 441-08 Java：出站取回信任用户证书 ----------------
_code = '''package fetch;

import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import javax.net.ssl.*;

public class Avatars {
    public byte[] fetch(String userUrl, byte[] userCaPem) throws Exception {
        // 用户随附 CA 一并进信任库：以产品身份信任任意用户提供链
        char[] pwd = "changeit".toCharArray();
        KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
        ts.load(null, pwd);
        X509TrustManager all = new X509TrustManager() {
            public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{all}, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
        URL u = new URL(userUrl);
        try (InputStream in = u.openConnection().getInputStream()) {
            return in.readAllBytes();
        }
    }
}
'''
P.append({
    "pid": "441-08", "lang": "Java", "cwe": "CWE-918",
    "anchor": "非 295 为主叙事的理由：295 是『证书校验不当』这一单点缺陷，此处核心是借产品网络位置为用户提供"
              "受信中继（信任任意用户链 + 全局默认 factory 污染所有出站），代理/委托语义错置归 441；"
              "非 918 因为无 URL 目的地校验缺失之外的内部资源叙事重叠度低。",
    "safe_anchor": "防御为何不可旁路：移除全局默认 factory 污染（改连接级 factory）且使用系统默认信任链，"
                   "用户数据不进入任何 TrustManager；任意自签链在握手即失败。",
    "oracle_vuln": [
        (r'userCaPem', "source：用户提供 CA 材料"),
        (r'checkServerTrusted\(java\.security\.cert\.X509Certificate\[\] c, String a\) \{\}', "伪防御：空实现=接受任意链"),
        (r'setDefaultSSLSocketFactory', "sink：全局默认 factory 被污染，所有出站受信"),
    ],
    "oracle_safe": [
        (r'url not allowed', "防御：目的地白名单硬校验"),
        (r'SSLSocketFactory\.getDefault\(\)', "系统默认信任链（用户数据不进任何 TrustManager）"),
        (r'conn\.setSSLSocketFactory', "连接级 factory，无全局默认污染"),
        (r'openConnection\(\)', "连接级配置，不复用被污染的默认值"),
    ],
    "vuln_code": _code,
    "safe_code": '''package fetch;

import java.io.InputStream;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

public class Avatars {
    public byte[] fetch(String userUrl) throws Exception {
        if (!userUrl.startsWith("https://avatars.example-cdn.net/")) {
            throw new IllegalArgumentException("url not allowed");
        }
        URL u = new URL(userUrl);
        HttpsURLConnection conn = (HttpsURLConnection) u.openConnection();
        conn.setSSLSocketFactory((SSLSocketFactory) SSLSocketFactory.getDefault()); // systemDefault 信任链
        conn.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());
        try (InputStream in = conn.getInputStream()) {
            return in.readAllBytes();
        }
    }
}
'''.replace("import javax.net.ssl.HttpsURLConnection;",
            "import javax.net.ssl.HttpsURLConnection;\nimport javax.net.ssl.SSLSocketFactory;"),
})

# ---------------- 441-09 JS：XFF 链最左信任 ----------------
_code = '''const express = require("express");
const app = express();

const quota = new Map();

app.use((req, res, next) => {
  // 信任链最左值：X-Real-IP 或 XFF 第一跳，均可由客户端注入
  const ip = req.headers["x-real-ip"] ||
             (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
             req.socket.remoteAddress;
  const n = (quota.get(ip) || 0) + 1;
  quota.set(ip, n);
  if (n > 300) return res.status(429).json({ error: "quota" });
  next();
});

app.get("/v1/query", (req, res) => res.json({ ok: true }));
app.listen(8080);
'''
P.append({
    "pid": "441-09", "lang": "JavaScript", "cwe": "CWE-799",
    "anchor": "非 441 因为无 unintended proxy 转发语义；非 918/601 因为无服务端取回/跳转；配额主体由可伪造转发链决定=频率控制绕过，按 CWE-799 定位——预审教师轴 20260913 定版。"
              "伪造头重置换源，代理语义信任错置归 441。",
    "safe_anchor": "防御为何不可旁路：配额主体固定为 socket 对端；仅在 TRUSTED_PROXY_COUNT 内的转发头才参与，"
                   "且取右起第 N-1 跳（known proxies 之后的第一跳），客户端无法增删链内跳数。",
    "oracle_vuln": [
        (r'x-real-ip', "source：X-Real-IP 头客户端可注入"),
        (r'split\(","\)\[0\]', "取最左跳（最不可信）"),
        (r'quota\.set\(ip, n\)', "sink：配额以可控头为主体"),
    ],
    "oracle_safe": [
        (r'const ip = remote;', "防御：限流键恒用 socket 对端地址（内核写入不可伪造）"),
        (r'xffLog', "XFF 仅记录，不参与判定"),
    ],
    "vuln_code": _code,
    "safe_code": '''const express = require("express");
const app = express();

const TRUSTED_PROXY_COUNT = 1; // 部署拓扑：前置 1 台 nginx
const quota = new Map();

app.use((req, res, next) => {
  const remote = req.socket.remoteAddress;
  const xffLog = req.headers["x-forwarded-for"] || "";
  // 保守防御：限流键恒用 socket 对端，XFF 仅记录（不参与任何判定）
  const ip = remote;
  const n = (quota.get(ip) || 0) + 1;
  quota.set(ip, n);
  if (n > 300) return res.status(429).json({ error: "quota" });
  next();
});

app.get("/v1/query", (req, res) => res.json({ ok: true }));
app.listen(8080);
''',
})

# ---------------- 441-10 Python：XFF 每跳配额 ----------------
_code = '''def resolve_quota_key(headers, peer):
    # 链式代理：XFF = client, proxy1, proxy2
    chain = [h.strip() for h in headers.get("X-Forwarded-For", "").split(",")]
    if chain and chain[0]:
        return chain[0]
    return peer

def check_quota(headers, peer):
    key = resolve_quota_key(headers, peer)
    used = get_usage(key)
    if used >= DAILY_LIMIT:
        raise QuotaExceeded(key)
    incr_usage(key)

DAILY_LIMIT = 1000

def get_usage(key):
    return USAGE.get(key, 0)

def incr_usage(key):
    USAGE[key] = get_usage(key) + 1

USAGE = {}
class QuotaExceeded(Exception):
    pass
'''
P.append({
    "pid": "441-10", "lang": "Python", "cwe": "CWE-799",
    "anchor": "非 441/918/601；配额键信任转发链首跳（客户端可控）=频率控制绕过，按 CWE-799 定位——预审教师轴 20260913 定版。"
              "代理链跳数信任错置归 441。",
    "safe_anchor": "防御为何不可旁路：链值仅当来源对端是受信代理才采纳，且取『右起第 known_proxies+1 跳』"
                   "（受信代理之后的第一跳）；对端不是受信代理时一律用 peer，伪造头不改变主体。",
    "oracle_vuln": [
        (r'return chain\[0\]', "sink：信任链首跳（最远客户端可控）"),
        (r'headers\.get\("X-Forwarded-For"', "source：XFF 链可注入"),
    ],
    "oracle_safe": [
        (r'return peer', "防御：配额键恒用 socket 对端（不可伪造）"),
        (r'xff_log', "XFF 仅记录，不参与判定"),
    ],
    "vuln_code": _code,
    "safe_code": '''KNOWN_PROXIES = {"10.0.0.2", "10.0.0.3"}  # 部署内受信代理

def resolve_quota_key(headers, peer):
    # 保守防御：配额键恒用 socket 对端；XFF 仅记录（不参与任何判定）
    xff_log = headers.get("X-Forwarded-For", "")
    return peer

def check_quota(headers, peer):
    key = resolve_quota_key(headers, peer)
    used = get_usage(key)
    if used >= DAILY_LIMIT:
        raise QuotaExceeded(key)
    incr_usage(key)

DAILY_LIMIT = 1000

def get_usage(key):
    return USAGE.get(key, 0)

def incr_usage(key):
    USAGE[key] = get_usage(key) + 1

USAGE = {}
class QuotaExceeded(Exception):
    pass
''',
})

# ---------------- 441-11 Go：Host 头生成重置链接 ----------------
_code = '''package reset

import (
	"fmt"
	"net/http"
)

func HandleReset(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	token := newToken(email)
	// Host 头来自请求，可被注入任意域
	base := "https://" + r.Host + "/"
	link := fmt.Sprintf("%sreset?token=%s", base, token)
	sendMail(email, "reset link: "+link)
	fmt.Fprintln(w, "mail sent")
}
'''
P.append({
    "pid": "441-11", "lang": "Go", "cwe": "CWE-640",
    "anchor": "非 441 因为无转发语义；Host 头投毒密码重置链接按 MITRE CWE-640（弱密码恢复机制）定位——官方标准映射，预审教师轴 20260913 定版。"
              "产品以请求自报的 Host 决定出站链接身份（密码重置投毒），位置/身份信任错置归 441。",
    "safe_anchor": "防御为何不可旁路：base 取自服务端配置常量 BaseURL，Host 头不参与任何出站 URL 构造；"
                   "改头只影响日志，不影响链接。",
    "oracle_vuln": [
        (r'r\.Host', "source：Host 头请求自报可注入"),
        (r'"https://" \+ r\.Host \+ "/"', "拼接为出站链接基址"),
        (r'link := fmt\.Sprintf', "sink：重置链接指向攻击者域（链接投毒）"),
    ],
    "oracle_safe": [
        (r'BaseURL = "https://accounts\.example\.com/"', "防御：服务端配置基准 URL（常量定义）"),
        (r'base := BaseURL', "Host 头不再参与出站链接构造"),
    ],
    "vuln_code": _code,
    "safe_code": _code.replace(
        '\t// Host 头来自请求，可被注入任意域\n\tbase := "https://" + r.Host + "/"',
        '\tbase := BaseURL').replace(
        'func HandleReset',
        'var BaseURL = "https://accounts.example.com/"\n\nfunc HandleReset'),
})

# ---------------- 441-12 PHP：Host 头资产链接 ----------------
_code = '''<?php
// views/link_builder.php
function asset_link(string $path): string {
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    return 'https://' . $host . $path;
}

function password_reset_mail(string $token): string {
    $link = asset_link('/reset?token=' . urlencode($token));
    return "reset link: $link";
}
echo password_reset_mail('t0k3n');
'''
P.append({
    "pid": "441-12", "lang": "PHP", "cwe": "CWE-640",
    "anchor": "非 441/601；出站链接身份由可注入 Host 决定=弱密码恢复机制，按 CWE-640 定位——官方标准映射，预审教师轴 20260913 定版。"
              "出站链接身份由可注入 Host 头决定，属身份/位置自报信任错置（441）。",
    "safe_anchor": "防御为何不可旁路：基址取自 config 常量 APP_BASE_URL；HTTP_HOST 仅用于日志，"
                   "链接域名不再有任何用户可控输入位。",
    "oracle_vuln": [
        (r"HTTP_HOST", "source：Host 头可注入"),
        (r"'https://' \. \$host", "sink：出站链接基址可控"),
    ],
    "oracle_safe": [
        (r"define\('APP_BASE_URL'", "防御：配置常量基址"),
        (r"return APP_BASE_URL \. \$path", "链接域名不再有用户可控输入位；HTTP_HOST 仅记日志"),
    ],
    "vuln_code": _code,
    "safe_code": _code.replace(
        "    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';\n    return 'https://' . $host . $path;",
        "    return APP_BASE_URL . $path; // HTTP_HOST 仅记日志，不进链接").replace(
        "<?php",
        "<?php\ndefine('APP_BASE_URL', 'https://app.example.com');"),
})

# ---------------- 441-13 Python：webhook 回调内网探测 ----------------
_code = '''import requests
from flask import Flask, request

app = Flask(__name__)

@app.route("/register-webhook", methods=["POST"])
def register_webhook():
    body = request.get_json()
    callback = body.get("callback_url", "")
    scope = body.get("scope", "public")     # 注册者自报内网范围
    # 验证探针：以本服务（内网身份）访问回调地址
    probe = requests.get(callback, timeout=3,
                         headers={"Authorization": "Bearer " + INTERNAL_TOKEN})
    if probe.status_code >= 500:
        return "callback unhealthy", 400
    save_webhook(callback, scope)
    return "registered"
'''
P.append({
    "pid": "441-13", "lang": "Python", "cwe": "CWE-918",
    "anchor": "非 918 为主叙事的理由：除目的地外，探针携带产品内部凭证（INTERNAL_TOKEN）以内网身份出站，"
              "注册者可把回调指向内网元数据/管理端并收割带凭证响应——借产品网络位置的委托/代理混淆归 441；"
              "若仅『目的地未校验』无内部身份要素则应标 918。",
    "safe_anchor": "防御为何不可旁路：① 探针目标主机必须在 egress allowlist；② 回环/RFC1918/链路本地段硬拒绝"
                   "（解析全部 A/AAAA 后逐一校验，防 DNS rebinding）；③ 内部凭证头从探针请求中移除。",
    "oracle_vuln": [
        (r'callback_url', "source：注册者提供回调 URL"),
        (r'"Authorization": "Bearer " \+ INTERNAL_TOKEN', "内部凭证随探针出站"),
        (r'requests\.get\(callback', "sink：以内网身份向未校验目的地发请求"),
    ],
    "oracle_safe": [
        (r'EGRESS_ALLOWLIST = \{', "出站白名单"),
        (r'is_ip_forbidden\(addrs\[0\]\)', "回环/RFC1918/链路本地逐 IP 校验"),
        (r'"169\.254\.0\.0/16"', "链路本地段显式覆盖"),
        (r'probe_headers = \{', "探针不再携带内部凭证"),
    ],
    "vuln_code": _code,
    "safe_code": '''import ipaddress
import socket
import requests
from flask import Flask, request
from urllib.parse import urlparse

app = Flask(__name__)
EGRESS_ALLOWLIST = {"hooks.partner.example.com"}
FORBIDDEN_NETS = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]

def is_ip_forbidden(ip):
    a = ipaddress.ip_address(ip)
    return any(a in net for net in FORBIDDEN_NETS)

@app.route("/register-webhook", methods=["POST"])
def register_webhook():
    body = request.get_json()
    callback = body.get("callback_url", "")
    scope = body.get("scope", "public")
    host = urlparse(callback).hostname
    if host not in EGRESS_ALLOWLIST:
        return "callback host not allowed", 400
    for _family, _type, _proto, _canon, addrs in socket.getaddrinfo(host, None):
        if is_ip_forbidden(addrs[0]):
            return "callback resolves to internal net", 400
    probe_headers = {"User-Agent": "webhook-probe/1.0"}
    probe = requests.get(callback, timeout=3, headers=probe_headers)
    if probe.status_code >= 500:
        return "callback unhealthy", 400
    save_webhook(callback, scope)
    return "registered"
''',
})

# ---------------- 441-14 Node：webhook 出站回环 ----------------
_code = '''const express = require("express");
const fetch = require("node-fetch");
const app = express();
app.use(express.json());

const INTERNAL_SVC_TOKEN = process.env.SVC_TOKEN;

app.post("/integrations/webhook", async (req, res) => {
  const { callbackUrl, secret } = req.body;
  // 健康探针：携带服务身份头以内网身份出站
  const resp = await fetch(callbackUrl, {
    headers: { "X-Introspect-Auth": INTERNAL_SVC_TOKEN },
  });
  if (!resp.ok) return res.status(400).json({ error: "callback unhealthy" });
  await db.saveWebhook({ callbackUrl, secret });
  res.json({ ok: true });
});

app.listen(8080);
'''
P.append({
    "pid": "441-14", "lang": "JavaScript", "cwe": "CWE-918",
    "anchor": "非 918 的边界理由同 441-13：核心是内部身份头随探针出站 + 回环放行，借产品网络位置的代理语义归 441；"
              "非 95/94 因为无代码求值；非 22 因为无文件系统路径。",
    "safe_anchor": "防御为何不可旁路：URL 仅允许 https + 静态集成白名单域；resolve 后逐地址拒绝回环/RFC1918；"
                   "身份头从探针剥离，内网响应不再携带可收割凭证。",
    "oracle_vuln": [
        (r'const \{ callbackUrl', "source：注册者提供回调 URL"),
        (r'"X-Introspect-Auth": INTERNAL_SVC_TOKEN', "服务身份头随探针出站"),
        (r'await fetch\(callbackUrl', "sink：以内网身份请求未校验目的地"),
    ],
    "oracle_safe": [
        (r'INTEGRATION_HOSTS = new Set', "静态白名单"),
        (r'isForbiddenIp\(addr\)', "逐地址拒绝内网/回环"),
        (r'"User-Agent": "webhook-probe/1\.0"', "探针剥离身份头"),
    ],
    "vuln_code": _code,
    "safe_code": '''const express = require("express");
const fetch = require("node-fetch");
const dns = require("dns").promises;
const { URL } = require("url");
const app = express();
app.use(express.json());

const INTEGRATION_HOSTS = new Set(["hooks.partner.example.com", "callbacks.vendor.example"]);
const FORBIDDEN = /^(127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2\\d|3[01])\\.|169\\.254\\.|::1|f[cd][0-9a-f]{2}:)/i;

function isForbiddenIp(addr) {
  return FORBIDDEN.test(addr);
}

app.post("/integrations/webhook", async (req, res) => {
  const { callbackUrl } = req.body;
  let u;
  try { u = new URL(callbackUrl); } catch { return res.status(400).json({ error: "bad url" }); }
  if (u.protocol !== "https:" || !INTEGRATION_HOSTS.has(u.hostname)) {
    return res.status(400).json({ error: "host not allowed" });
  }
  const addrs = await dns.resolve6(u.hostname).catch(() => []);
  const addrs4 = await dns.resolve4(u.hostname).catch(() => []);
  if ([...addrs, ...addrs4].some(isForbiddenIp)) {
    return res.status(400).json({ error: "internal net" });
  }
  const resp = await fetch(callbackUrl, { headers: { "User-Agent": "webhook-probe/1.0" } });
  if (!resp.ok) return res.status(400).json({ error: "callback unhealthy" });
  await db.saveWebhook(req.body);
  res.json({ ok: true });
});

app.listen(8080);
''',
})

# ---------------- 441-15 Java：X-Forwarded-Proto 信任 ----------------
_code = '''package web;

import javax.servlet.http.HttpServletRequest;

public class SecureFlag {
    /** 决定是否下发 Secure Cookie / 是否跳过 TLS 检查 */
    public boolean isSecure(HttpServletRequest req) {
        String proto = req.getHeader("X-Forwarded-Proto");
        if (proto == null) {
            proto = req.getScheme();
        }
        return "https".equalsIgnoreCase(proto);
    }

    public String sessionCookie(HttpServletRequest req, String sid) {
        boolean secure = isSecure(req);
        return "SID=" + sid + "; Path=/; HttpOnly" + (secure ? "; Secure" : "");
    }
}
'''
P.append({
    "pid": "441-15", "lang": "Java", "cwe": "CWE-807",
    "anchor": "非 441/295；TLS 事实这一安全决策依赖不可信请求头，按 MITRE CWE-807（安全决策依赖不可信输入）定位——预审教师轴 20260913 定版。"
              "非 384 因为会话机制本身正常；明文降级借伪造头绕过 Secure 标记，归 441。",
    "safe_anchor": "防御为何不可旁路：TLS 事实由对端连接（request.isSecure()，容器从 socket 派生，"
                   "受信连接器/代理配置约束）决定，头不参与；伪造 X-Forwarded-Proto 无法改变 isSecure 结果。",
    "oracle_vuln": [
        (r'getHeader\("X-Forwarded-Proto"\)', "source：TLS 事实由客户端可注入头自报"),
        (r'"https"\.equalsIgnoreCase\(proto\)', "sink：Secure 标记决策基于伪造值"),
    ],
    "oracle_safe": [
        (r'req\.isSecure\(\)', "防御：连接级 TLS 事实，socket 派生"),
    ],
    "vuln_code": _code,
    "safe_code": _code.replace(
        '        String proto = req.getHeader("X-Forwarded-Proto");\n'
        '        if (proto == null) {\n'
        '            proto = req.getScheme();\n'
        '        }\n'
        '        return "https".equalsIgnoreCase(proto);',
        '        return req.isSecure();'),
})

if __name__ == "__main__":
    made, failed = emit("CWE-441", P)
    print(f"441: made {len(made)} failed {len(failed)}")
    for pid, errs in failed:
        print("  FAIL", pid, errs)
    (Path(__file__).resolve().parents[1] / "corpus/diffpair_wave1/wave2_pairs" / "_index_441.md") \
        .write_text("\n".join(write_index("CWE-441", made)) + "\n", encoding="utf-8")
