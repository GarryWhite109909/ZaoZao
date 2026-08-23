"""
从 GitHub 搜索 CVE 修复 commit，提取漏洞版本代码作为独立测试集（held-out）。

v2 改进（2026-07-22）：
  - 增加 NVD API 查询获取真实 CWE 编号和漏洞描述
  - 增加文件级漏洞模式筛选（危险 API 正则），只保留含漏洞模式的文件
  - 排除 vendor/依赖更新类 commit（bump/update dep/go mod 等）
  - 每个 CVE 最多取 2 个文件，避免单一 CVE 占满测试集
  - 排除测试/配置文件（test/spec/.json/.yaml 等）
  - 文件大小限制 500-15000 字节
  - 支持代理（NVD API 可能需要）

背景：
  v1 版本（2026-07-07）把每个 CVE 修复 commit 的所有修改文件都标 expected_present=True，
  导致 30 个样本全是同一个依赖更新 commit 的无关文件（golang.org/x/sys syscall 封装），
  与真实漏洞（golang.org/x/net/html CWE-1333）完全无关。Qwen3-8B 判 false 是正确的，
  但被标为 FN。v2 修复此问题。

数据源：
  1. NVD API: 按 CWE 搜索 CVE，从 references 中提取 GitHub 修复 commit URL
  2. GitHub Commits API: 获取 commit detail（files 列表 + parent sha）
  3. GitHub Contents API: 获取修复前（parent sha）的目标文件代码

输出：
  experiments/exp_06_finetune/testset_cve_fix/
    ├── manifest.json
    └── cve_fix_0001.py 等

用法：
  export GITHUB_TOKEN=ghp_xxx  # 可选，未认证 60 req/h，认证 5000 req/h
  python prepare_cve_fix_testset.py --max-samples 20 --resume

依赖：仅 Python 标准库（urllib/json/base64/pathlib/argparse）
"""

import argparse
import base64
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

GITHUB_API = "https://api.github.com"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXP06_DIR = Path(__file__).resolve().parents[1]
OUTPUT_DIR = EXP06_DIR / "testset_cve_fix"

# 支持的语言扩展名 -> manifest 中的 language 字段
LANG_EXT_MAP = {
    ".py": "Python",
    ".java": "Java",
    ".js": "JavaScript",
    ".php": "PHP",
    ".go": "Go",
}
LANG_FILTER = {
    "python": {".py"},
    "java": {".java"},
    "javascript": {".js"},
    "php": {".php"},
    "go": {".go"},
}

# ---------------------------------------------------------------------------
# 质量筛选：排除非漏洞修复的 commit
# ---------------------------------------------------------------------------
# v1 的根本错误：把"修复 commit 涉及的所有文件"等同于"含漏洞的文件"。
# 实际上一个 CVE 修复 commit 可能涉及：依赖更新（vendor/go.mod/package.json）、
# 文档、测试、构建配置等无关文件。必须排除。
VENDOR_COMMIT_PATTERNS = re.compile(
    r"\b(bump|update\s+dep|upgrade\s+dep|go\s+mod|vendor|"
    r"update\s+dependenc|upgrade\s+dependenc|"
    r"update\s+requirements|update\s+package\.json|"
    r"chore|ci\s*:|docs\s*:)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# 质量筛选：CWE 白名单（硬性过滤，与 SYSTEM_PROMPT ANALYSIS_SCOPE 对齐）
# ---------------------------------------------------------------------------
# 只保留代码级漏洞的 CWE（能用危险 API 正则检测的），排除逻辑缺陷类
# （CWE-400 资源耗尽 / CWE-863 授权缺陷 / CWE-121 栈溢出 等无法用正则检测的）。
# 这样能聚焦模型"识别代码中危险 API"的能力评估。
CWE_WHITELIST = {
    "CWE-89": "SQL注入",
    "CWE-78": "命令注入",
    "CWE-94": "代码注入",
    "CWE-502": "不安全反序列化",
    "CWE-22": "路径穿越",
    "CWE-79": "XSS",
    "CWE-918": "SSRF",
    "CWE-1336": "SSTI",
    "CWE-798": "硬编码凭证",
    "CWE-327": "弱密码学",
    "CWE-611": "XXE",
    "CWE-601": "开放重定向",
    "CWE-90": "LDAP注入",
    "CWE-917": "表达式注入（OGNL/SpEL）",
    "CWE-330": "弱随机数",
    "CWE-74": "注入（通用）",
    "CWE-77": "命令注入（通用）",
    "CWE-95": "代码注入（eval）",
    "CWE-98": "PHP 文件包含",
    "CWE-441": "未受信任的反序列化",
    "CWE-123": "缓冲区溢出（写越界）",
    "CWE-125": "缓冲区越界读",
    "CWE-190": "整数溢出",
    "CWE-476": "空指针解引用",
    "CWE-548": "信息泄露（目录遍历）",
}


# ---------------------------------------------------------------------------
# 质量筛选：文件级漏洞模式检测（辅助标注，非硬性过滤）
# ---------------------------------------------------------------------------
# 检测代码中是否含已知危险 API。匹配到的样本标注 vuln_patterns，
# 未匹配到的样本仍保留（只要 CWE 在白名单内），但标注 pattern_not_matched。
VULN_PATTERNS = [
    # SQL 注入（字符串拼接 / f-string / % 格式化 / .format 进入 execute）
    (re.compile(r"\.execute\s*\(\s*[^)]*[\+%]"), "SQLi"),
    (re.compile(r"\.execute\s*\(\s*f['\"]"), "SQLi"),
    (re.compile(r"\.execute\s*\(\s*['\"][^'\"]*['\"]\s*\.format"), "SQLi"),
    # 命令注入
    (re.compile(r"shell\s*=\s*True"), "CMDi"),
    (re.compile(r"os\.system\s*\("), "CMDi"),
    (re.compile(r"subprocess\.(?:run|Popen|call)\s*\([^)]*shell\s*=\s*True"), "CMDi"),
    # 代码注入
    (re.compile(r"\beval\s*\(\s*[^)]*request"), "CodeInject"),
    (re.compile(r"\bexec\s*\(\s*[^)]*request"), "CodeInject"),
    # 不安全反序列化
    (re.compile(r"pickle\.loads?\s*\("), "Deser"),
    (re.compile(r"yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.Loader"), "Deser"),
    (re.compile(r"ObjectInputStream"), "Deser"),
    (re.compile(r"readObject\s*\("), "Deser"),
    (re.compile(r"fastjson.*JSON\.parse"), "Deser"),
    # 路径穿越（用户输入拼接到路径）
    (re.compile(r"open\s*\(\s*[^)]*\+\s*[^)]*request"), "PathTraversal"),
    (re.compile(r"os\.path\.join\s*\([^)]*request"), "PathTraversal"),
    # XSS（未转义输出）
    (re.compile(r"innerHTML\s*=\s*[^;]*\+"), "XSS"),
    (re.compile(r"document\.write\s*\([^)]*request"), "XSS"),
    (re.compile(r"echo\s*\$"), "XSS"),  # PHP 直接 echo 变量
    # SSRF
    (re.compile(r"urllib\.request\.urlopen\s*\([^)]*request"), "SSRF"),
    (re.compile(r"requests\.get\s*\(\s*[^)]*request"), "SSRF"),
    # SSTI
    (re.compile(r"render_template_string\s*\("), "SSTI"),
    (re.compile(r"Template\s*\(\s*[^)]*request"), "SSTI"),
    (re.compile(r"\$\{.*\}.*request\.getParameter"), "SSTI"),  # Java EL
    # 硬编码凭证
    (re.compile(r"(?:password|passwd|pwd|api_key|apikey|secret|token|access_key)\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE), "HardcodedSecret"),
    # 弱密码学
    (re.compile(r"hashlib\.md5\s*\("), "WeakCrypto"),
    (re.compile(r"hashlib\.sha1\s*\("), "WeakCrypto"),
    (re.compile(r"MD5\.encrypt|SHA1\.encrypt"), "WeakCrypto"),
    # XXE
    (re.compile(r"etree\.parse\s*\([^)]*(?:resolve_entities|no_network)"), "XXE"),
    (re.compile(r"XMLReader.*setFeature.*false"), "XXE"),
    # 开放重定向
    (re.compile(r"redirect\s*\(\s*request\."), "OpenRedirect"),
    (re.compile(r"Response\.sendRedirect\s*\(\s*request\."), "OpenRedirect"),
    # LDAP 注入
    (re.compile(r"search\s*\(\s*['\"][^'\"]*['\"]\s*\+\s*[^)]*request"), "LDAPi"),
    # OGNL / SpEL 注入（Java）
    (re.compile(r"OgnlUtil\.getValue|Ognl\.getValue"), "OGNLi"),
    (re.compile(r"SpelExpressionParser.*parseExpression"), "SpELi"),
    # JNDI 注入（Log4Shell 类）
    (re.compile(r"\$\{jndi:ldap:|\$\{jndi:rmi:"), "JNDIi"),
    # 不安全随机数
    (re.compile(r"random\.(?:choice|randint|random)\s*\(\s*\)\s*\)|random\.choices?\("), "WeakRandom"),
]

# 排除的文件名模式（测试/配置/文档）
EXCLUDE_FILE_PATTERNS = re.compile(
    r"(?:^|/)(?:test_|_test|spec_|_spec|__test__|tests?/|__tests__/|"
    r"\.min\.|vendor/|node_modules/|third_party/|"
    r"conftest|setup\.py|__init__\.py|package\.json|package-lock\.json|"
    r"go\.mod|go\.sum|requirements.*\.txt|pom\.xml|build\.gradle|"
    r"Makefile|Dockerfile|\.md$|\.rst$|\.txt$|\.json$|\.yaml$|\.yml$|\.toml$|\.xml$)",
    re.IGNORECASE,
)


def check_token() -> str:
    """检查 GITHUB_TOKEN 环境变量。未设置返回空字符串（未认证模式，60 req/h）。"""
    raw = os.environ.get("GITHUB_TOKEN", "")
    token = raw.strip()
    if not token:
        print("[警告] GITHUB_TOKEN 未设置，使用未认证模式（60 req/h）", file=sys.stderr)
        return ""
    try:
        token.encode("ascii")
    except UnicodeEncodeError as e:
        print(f"错误：GITHUB_TOKEN 包含非 ASCII 字符: {e}", file=sys.stderr)
        sys.exit(1)
    return token


def github_request(url: str, token: str, accept: str = "application/vnd.github+json"):
    """发起 GitHub API 请求，处理 rate limit 与重试。"""
    headers = {"Accept": accept, "User-Agent": "graduation-project-cve-fix-fetcher"}
    if token:
        headers["Authorization"] = f"token {token}"
    for attempt in range(2):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                try:
                    parsed = json.loads(body)
                except json.JSONDecodeError:
                    parsed = None
                return resp.status, dict(resp.headers), parsed
        except urllib.error.HTTPError as e:
            if e.code == 403:
                reset = e.headers.get("X-RateLimit-Reset") if e.headers else None
                if attempt == 0 and reset:
                    try:
                        wait = int(reset) - int(time.time()) + 5
                    except ValueError:
                        wait = 0
                    if 0 < wait < 3600:
                        print(f"  [rate limit] 等待 {wait}s 至 reset...", file=sys.stderr)
                        time.sleep(wait)
                        continue
                print(f"  [403] 访问被拒: {url}", file=sys.stderr)
                return 403, dict(e.headers or {}), None
            print(f"  [HTTP {e.code}] {url}: {e.reason}", file=sys.stderr)
            return e.code, dict(e.headers or {}), None
        except urllib.error.URLError as e:
            print(f"  [网络错误] {url}: {e.reason}", file=sys.stderr)
            if attempt == 0:
                time.sleep(3)
                continue
            return 0, {}, None
    return 0, {}, None


def search_nvd_by_cwe(cwe_id, proxy=None, max_results=20,
                      pub_start=None, pub_end=None, api_key=None):
    """用 NVD API 按 CWE 搜索 CVE。

    URL: https://services.nvd.nist.gov/rest/json/cves/2.0?cweId={cwe_id}&resultsPerPage={max_results}
    支持代理（urllib.request.ProxyHandler）。
    NVD 无 API key 时限速 5 req/30s，调用方应自行 sleep（保守 7s）。
    pub_start/pub_end（ISO8601，如 "2023-06-01T00:00:00.000"）限定发布窗口：
      不带日期时 NVD 按发布时间升序返回，会拿到前 GitHub 时代（<2012 年）的
      老 CVE——它们没有 commit 链接；无 key 时单窗口跨度上限 120 天。
    api_key：NVD_API_KEY 时走 50 req/30s 限额。

    返回 list of dict:
      [{"cve_id": "CVE-XXXX-XXXX", "cwe_id": "CWE-89",
        "description": "...", "references": [...]}]
    从 vulnerabilities[].cve 中提取 cve_id、weaknesses（取第一个 CWE-xxx）、
    descriptions（取英文）、references。
    """
    url = f"{NVD_API}?cweId={cwe_id}&resultsPerPage={max_results}"
    if pub_start and pub_end:
        url += f"&pubStartDate={pub_start}&pubEndDate={pub_end}"
    proxy_handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy}) if proxy else None
    opener = urllib.request.build_opener(proxy_handler) if proxy else urllib.request.build_opener()
    headers = {"User-Agent": "graduation-project-cve-fix-fetcher"}
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:
        print(f"  [NVD 查询失败] {cwe_id}: {e}", file=sys.stderr)
        return []

    results = []
    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "")

        # 取第一个 CWE-xxx
        first_cwe = None
        for weak in cve_data.get("weaknesses", []):
            for desc in weak.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    first_cwe = val
                    break
            if first_cwe:
                break

        # 取英文描述
        description = None
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        references = cve_data.get("references", [])

        results.append({
            "cve_id": cve_id,
            "cwe_id": first_cwe,
            "description": description,
            "references": references,
        })

    return results


def extract_github_commit_url(references):
    """从 NVD references 列表中提取 GitHub commit URL。

    匹配 pattern: https://github.com/{owner}/{repo}/commit/{sha}
    排除 /security/advisories/、/pull/、/issues/ 等非 commit URL。

    返回 (owner, repo, sha) 或 None。
    """
    pattern = re.compile(
        r"https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})"
    )
    for ref in references or []:
        if not isinstance(ref, dict):
            continue
        url = ref.get("url", "")
        if not url:
            continue
        # 排除非 commit URL（双重保险，pattern 已限定 /commit/ 路径）
        if "/security/advisories/" in url or "/pull/" in url or "/issues/" in url:
            continue
        m = pattern.search(url)
        if m:
            return m.group(1), m.group(2), m.group(3)
    return None


def get_repo_stars(token: str, owner: str, repo: str) -> int:
    """查询仓库 star 数（用于过滤低质量学生作业仓库）。

    返回 star 数；查询失败返回 -1（不过滤）。
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}"
    status, _headers, data = github_request(url, token)
    if status != 200 or not data:
        return -1
    return data.get("stargazers_count", -1)


def get_commit_detail(token: str, owner: str, repo: str, sha: str):
    """获取单个 commit 的 files 列表与 parents。"""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/commits/{sha}"
    status, _headers, data = github_request(url, token)
    if status != 200 or not data:
        return None
    return data


def get_file_content(token: str, owner: str, repo: str, path: str, ref: str):
    """获取指定 ref 的文件内容（base64 解码为文本）。"""
    encoded_path = urllib.parse.quote(path, safe="/")
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{encoded_path}?ref={ref}"
    status, _headers, data = github_request(url, token)
    if status != 200 or not data:
        return None
    if data.get("encoding") != "base64":
        return None
    content_b64 = data.get("content", "")
    try:
        raw = base64.b64decode(content_b64)
        return raw.decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  [解码失败] {path}: {e}", file=sys.stderr)
        return None


def lang_of_file(filename: str):
    """根据扩展名返回 manifest 中的 language 名。"""
    ext = Path(filename).suffix.lower()
    return LANG_EXT_MAP.get(ext)


def is_vendor_commit(message: str) -> bool:
    """判断 commit 是否为依赖更新/vendor 提交（应排除）。"""
    return bool(VENDOR_COMMIT_PATTERNS.search(message or ""))


def detect_vuln_patterns(code: str) -> list:
    """检测代码中是否含已知漏洞模式。返回匹配的漏洞类型列表（如 ['SQLi', 'CMDi']）。"""
    matched = []
    for pattern, vtype in VULN_PATTERNS:
        if pattern.search(code):
            if vtype not in matched:
                matched.append(vtype)
    return matched


def is_excluded_file(filename: str) -> bool:
    """判断文件是否应排除（测试/配置/文档/vendor 等）。"""
    return bool(EXCLUDE_FILE_PATTERNS.search(filename))


def load_existing_manifest(manifest_path: Path) -> dict:
    """读取已有 manifest（用于 --resume）。"""
    if not manifest_path.exists():
        return {"experiment": "exp_06_cve_fix_testset", "samples": []}
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"experiment": "exp_06_cve_fix_testset", "samples": []}


def save_manifest(manifest_path: Path, manifest: dict) -> None:
    """保存 manifest（UTF-8，缩进 2）。"""
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def main():
    parser = argparse.ArgumentParser(
        description="用 NVD API 按 CWE 搜索 CVE 修复 commit，提取漏洞版本代码作为独立测试集（v3 NVD 驱动）"
    )
    parser.add_argument("--max-samples", type=int, default=20,
                        help="最多抓取的样本数（默认 20）")
    parser.add_argument("--language", choices=list(LANG_FILTER.keys()), default=None,
                        help="只抓取指定语言的文件（默认全部）")
    parser.add_argument("--resume", action="store_true",
                        help="从上次中断处继续（跳过已下载的样本）")
    parser.add_argument("--since-years", type=int, default=2,
                        help="（已弃用，NVD 搜索不按时间过滤）保留以兼容旧调用")
    parser.add_argument("--max-per-cve", type=int, default=2,
                        help="每个 CVE 最多取 N 个文件（默认 2，避免单一 CVE 占满）")
    parser.add_argument("--max-file-size", type=int, default=15000,
                        help="文件最大字节数（默认 15000，过大模型处理不了）")
    parser.add_argument("--min-file-size", type=int, default=500,
                        help="文件最小字节数（默认 500，过小无意义）")
    parser.add_argument("--nvd-proxy", type=str, default="http://127.0.0.1:7897",
                        help="NVD API 代理地址（默认 http://127.0.0.1:7897）")
    parser.add_argument("--output-dir", type=str, default=str(OUTPUT_DIR),
                        help="输出目录")
    parser.add_argument("--max-pages", type=int, default=5,
                        help="（已弃用，NVD 搜索不用分页）保留以兼容旧调用")
    parser.add_argument("--min-stars", type=int, default=3,
                        help="仓库最低 star 数（默认 3，NVD 收录的 CVE 仓库质量已较高）")
    args = parser.parse_args()

    token = check_token()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "manifest.json"

    if args.resume:
        manifest = load_existing_manifest(manifest_path)
        existing_shas = {s.get("source_sha") for s in manifest.get("samples", [])}
        existing_files = {s.get("file") for s in manifest.get("samples", [])}
        existing_cves = {}
        for s in manifest.get("samples", []):
            cve = s.get("cve_id", "")
            existing_cves[cve] = existing_cves.get(cve, 0) + 1
        print(f"[resume] 已有 {len(manifest.get('samples', []))} 个样本，将跳过")
    else:
        manifest = {
            "experiment": "exp_06_cve_fix_testset",
            "description": (
                "CVE-fix 独立测试集 v3：用 NVD API 按 CWE 搜索 CVE，"
                "从 NVD references 中提取 GitHub 修复 commit URL，"
                "获取修复前（parent sha）的目标文件代码。"
                "expected_cwe 为 NVD 返回的真实 CWE 编号（如 CWE-89）。"
            ),
            "schema_version": "8col_v1",
            "source": "nvd_cwe_search + github_commit_detail + vuln_pattern_annotate",
            "ground_truth_columns": [
                "file", "language", "category", "difficulty",
                "expected_present", "expected_vulnerability",
                "expected_cwe", "expected_risk_level",
                "source", "sink", "taint_path", "fix_idea",
                "cve_id", "vuln_patterns",
            ],
            "samples": [],
        }
        existing_shas = set()
        existing_files = set()
        existing_cves = {}

    allowed_exts = LANG_FILTER.get(args.language) if args.language else set(LANG_EXT_MAP.keys())

    print(f"用 NVD API 按 CWE 搜索 CVE，目标 {args.max_samples} 个样本...")

    collected = len(manifest.get("samples", []))
    target = args.max_samples
    stats = {
        "commits_seen": 0,
        "commits_vendor_skipped": 0,
        "commits_no_cve_skipped": 0,
        "commits_low_stars_skipped": 0,
        "no_github_commit": 0,
        "files_seen": 0,
        "files_excluded": 0,
        "files_no_pattern": 0,
        "files_too_large": 0,
        "files_too_small": 0,
        "cve_capped": 0,
        "nvd_failed": 0,
        "cwe_not_in_whitelist": 0,
    }
    repo_star_cache = {}  # owner/repo -> star 数，避免重复查询

    # 按 CWE 编号升序遍历，保证每次运行顺序一致（CWE-22, CWE-74, CWE-77, CWE-78, ...）
    for cwe_id, cwe_name in sorted(CWE_WHITELIST.items(),
                                   key=lambda x: int(x[0].split("-")[1])):
        if collected >= target:
            break

        print(f"\n{'='*40}")
        print(f"按 {cwe_id} ({cwe_name}) 搜索 NVD...")

        # NVD API 按 CWE 搜索（限速 5 req/30s，保守 sleep 7s）
        time.sleep(7)
        cves = search_nvd_by_cwe(cwe_id, proxy=args.nvd_proxy, max_results=20)
        print(f"  NVD 返回 {len(cves)} 个 CVE")

        for cve_data in cves:
            if collected >= target:
                break

            cve_id = cve_data["cve_id"]
            nvd_desc = cve_data["description"]

            # 每 CVE 最多 max_per_cve 个文件
            if existing_cves.get(cve_id, 0) >= args.max_per_cve:
                stats["cve_capped"] += 1
                continue

            # 从 references 中提取 GitHub commit URL
            commit_info = extract_github_commit_url(cve_data["references"])
            if not commit_info:
                stats["no_github_commit"] += 1
                continue

            owner, repo, sha = commit_info
            if sha in existing_shas:
                continue

            print(f"  [{cve_id}] {owner}/{repo}@{sha[:8]} ({cwe_id})")

            # 仓库 star 数过滤（过滤学生作业/练习项目）
            repo_key = f"{owner}/{repo}"
            if repo_key in repo_star_cache:
                stars = repo_star_cache[repo_key]
            else:
                time.sleep(random.uniform(0.5, 1.0))
                stars = get_repo_stars(token, owner, repo)
                repo_star_cache[repo_key] = stars

            if stars >= 0 and stars < args.min_stars:
                stats["commits_low_stars_skipped"] += 1
                print(f"    跳过低 star 仓库: {owner}/{repo} (★{stars} < {args.min_stars})")
                continue

            print(f"    ★{stars}，获取 commit detail...")

            # 获取 commit detail
            time.sleep(random.uniform(1.0, 2.0))
            detail = get_commit_detail(token, owner, repo, sha)
            if not detail:
                continue
            parents = detail.get("parents", [])
            if not parents:
                continue
            parent_sha = parents[0].get("sha")
            if not parent_sha:
                continue

            # 过滤目标语言文件
            target_files = []
            for f in detail.get("files", []):
                fname = f.get("filename", "")
                stats["files_seen"] += 1
                if not lang_of_file(fname):
                    continue
                if Path(fname).suffix.lower() not in allowed_exts:
                    continue
                if is_excluded_file(fname):
                    stats["files_excluded"] += 1
                    continue
                status = f.get("status", "")
                if status == "removed":
                    continue
                target_files.append(f)

            if not target_files:
                continue

            # 获取文件内容 + 保存
            for f in target_files:
                if collected >= target:
                    break
                if existing_cves.get(cve_id, 0) >= args.max_per_cve:
                    stats["cve_capped"] += 1
                    break

                fname = f.get("filename", "")
                lang = lang_of_file(fname)
                ext = Path(fname).suffix.lower()

                time.sleep(random.uniform(1.0, 2.0))
                code = get_file_content(token, owner, repo, fname, parent_sha)
                if code is None:
                    continue

                # 文件大小筛选
                if len(code) < args.min_file_size:
                    stats["files_too_small"] += 1
                    continue
                if len(code) > args.max_file_size:
                    stats["files_too_large"] += 1
                    continue

                # 漏洞模式检测（辅助标注，非硬性过滤）
                # CWE 已在白名单内，即使正则没匹配到也保留样本
                matched_patterns = detect_vuln_patterns(code)
                if not matched_patterns:
                    stats["files_no_pattern"] += 1

                # 通过所有筛选，保存样本
                idx = collected + 1
                base_name = f"cve_fix_{idx:04d}{ext}"
                while base_name in existing_files:
                    idx += 1
                    base_name = f"cve_fix_{idx:04d}{ext}"
                file_path = output_dir / base_name
                file_path.write_text(code, encoding="utf-8")
                existing_files.add(base_name)

                # 用 NVD 描述作为 expected_vulnerability，CWE 作为 expected_cwe
                description_short = (nvd_desc or f"{cve_id} vulnerability")[:200]
                sample = {
                    "file": base_name,
                    "language": lang,
                    "category": "cve_fix",
                    "difficulty": "real",
                    "expected_present": True,
                    "expected_vulnerability": description_short,
                    "expected_cwe": cwe_id,  # 真实 CWE 编号（如 CWE-89）
                    "expected_risk_level": "High",
                    "source": "N/A",
                    "sink": "N/A",
                    "taint_path": "N/A",
                    "fix_idea": f"参考修复 commit {owner}/{repo}@{sha[:8]}",
                    "source_sha": sha,
                    "source_repo": f"{owner}/{repo}",
                    "source_path": fname,
                    "cve_id": cve_id,
                    "vuln_patterns": matched_patterns,  # 检测到的漏洞模式（用于审计）
                    "pattern_not_matched": len(matched_patterns) == 0,
                }
                manifest.setdefault("samples", []).append(sample)
                existing_shas.add(sha)
                existing_cves[cve_id] = existing_cves.get(cve_id, 0) + 1
                collected += 1
                print(f"    ✓ 保存 {base_name} ({lang}, {len(code)} chars, patterns={matched_patterns})")

                # 增量保存 manifest
                save_manifest(manifest_path, manifest)

    save_manifest(manifest_path, manifest)

    # 打印统计
    print(f"\n{'='*60}")
    print(f"完成：共 {collected} 个样本，输出到 {output_dir}")
    print(f"{'='*60}")
    print(f"统计：")
    print(f"  commits 看过: {stats['commits_seen']}")
    print(f"  commits vendor 跳过: {stats['commits_vendor_skipped']}")
    print(f"  commits 低 star 跳过: {stats['commits_low_stars_skipped']}")
    print(f"  commits 无 CVE 跳过: {stats['commits_no_cve_skipped']}")
    print(f"  CVE 无 GitHub commit 跳过: {stats['no_github_commit']}")
    print(f"  CVE 达上限跳过: {stats['cve_capped']}")
    print(f"  NVD 查询失败: {stats['nvd_failed']}")
    print(f"  CWE 不在白名单: {stats['cwe_not_in_whitelist']}")
    print(f"  files 看过: {stats['files_seen']}")
    print(f"  files 排除(测试/配置): {stats['files_excluded']}")
    print(f"  files 无漏洞模式: {stats['files_no_pattern']}")
    print(f"  files 过大: {stats['files_too_large']}")
    print(f"  files 过小: {stats['files_too_small']}")
    print(f"  最终保留: {collected}")


if __name__ == "__main__":
    main()
