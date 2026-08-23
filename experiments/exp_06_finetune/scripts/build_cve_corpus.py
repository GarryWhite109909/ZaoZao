#!/usr/bin/env python3
"""CVE 真实语料管道（训练种子 + 滚动 dev 集 + 工具层挖掘原料）。

发现源（按序）：
  1. GHSA（GitHub Advisory Database，/advisories?cwe_id=...）——主源：
     references 中 commit 链接密度高（实测每条 1-5 个），分页即可遍历全量历史，
     直接复用 GITHUB_TOKEN 限额（5000 req/h）。
  2. NVD（按 115 天发布窗口迭代）——后备源：references 中 commit 链接密度
     仅 ~10%，且无 key 限速 5 req/30s。

与 expand_cve_fix_testset.py（20 段测试集）的区别：
  1. 规模化：目标数百条，分 train_pool / rolling_dev 两池；
  2. 分池纪律：rolling_dev 由 cve_id 哈希确定性分配，达到上限后冻结——
     只在发布前测一次，不参与训练与选型（防 test set reuse）；
  3. 去重：跨 testset_cve_fix（20 段）+ 两池 manifest 按 CVE ID/commit SHA 去重；
  4. 保存修复 patch：教师蒸馏时可用 ground-truth 修复语义生成变体；
  5. 框架标记：检测 next/react/express/spring 等，供工具层按框架挖 sink/defense 词表；
  6. 漏洞模式正则只记录不强制：来源（CVE + 修复 commit 的 parent 版本）本身就是
     漏洞存在的证据，标签噪声由教师蒸馏环节二次校验。

用法：
  export GITHUB_TOKEN=ghp_xxx            # 必需（GHSA 与 GitHub API 共用）
  python build_cve_corpus.py --target-train 300 --dev-cap 50 --resume
"""

import argparse
import hashlib
import json
import os
import random
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from prepare_cve_fix_testset import (
    check_token,
    github_request,
    search_nvd_by_cwe,
    extract_github_commit_url,
    get_repo_stars,
    get_commit_detail,
    get_file_content,
    lang_of_file,
    detect_vuln_patterns,
    is_excluded_file,
    save_manifest,
    load_existing_manifest,
    CWE_WHITELIST,
)

GITHUB_API = "https://api.github.com"
CORPUS_DIR = Path(__file__).resolve().parents[1] / "corpus"
TESTSET_MANIFEST = Path(__file__).resolve().parents[1] / "testset_cve_fix" / "manifest.json"

_COMMIT_URL_RE = re.compile(
    r"https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})")

# 默认目标 CWE（训练头部 + 真实集失败类 + 框架语义类），值 = train_pool 内上限
DEFAULT_CWE_CAPS = {
    "CWE-89": 40, "CWE-78": 40, "CWE-79": 30, "CWE-22": 30, "CWE-798": 20,
    "CWE-1336": 20, "CWE-918": 20, "CWE-611": 20, "CWE-90": 20, "CWE-95": 20,
    "CWE-502": 20, "CWE-94": 15, "CWE-601": 15, "CWE-441": 20, "CWE-862": 15,
    "CWE-639": 15, "CWE-327": 15, "CWE-352": 10, "CWE-190": 10, "CWE-77": 15,
}

# 框架标记（供工具层按框架挖 sink/defense 词表；也用于训练变体的框架分布统计）
FRAMEWORK_PATTERNS = [
    ("nextjs", re.compile(r"next/server|next\.config|getServerSideProps|NextResponse|createServer", re.I)),
    ("react", re.compile(r"from ['\"]react['\"]|ReactDOM", re.I)),
    ("vue", re.compile(r"from ['\"]vue['\"]|createApp\(", re.I)),
    ("nuxt", re.compile(r"from ['\"]nuxt|defineEventHandler|useFetch", re.I)),
    ("express", re.compile(r"require\(['\"]express['\"]\)|from ['\"]express['\"]", re.I)),
    ("fastify", re.compile(r"require\(['\"]fastify['\"]\)", re.I)),
    ("django", re.compile(r"django\.|from django", re.I)),
    ("flask", re.compile(r"from flask|Flask\(", re.I)),
    ("fastapi", re.compile(r"from fastapi|APIRouter\(", re.I)),
    ("spring", re.compile(r"springframework|@RestController|@RequestMapping", re.I)),
    ("laravel", re.compile(r"Illuminate\\\\|laravel", re.I)),
    ("symfony", re.compile(r"Symfony\\\\", re.I)),
    ("rails", re.compile(r"ActionController|ActiveRecord", re.I)),
    ("gin", re.compile(r"github\.com/gin-gonic/gin", re.I)),
    ("echov4", re.compile(r"github\.com/labstack/echo", re.I)),
    ("beego", re.compile(r"github\.com/astaxie/beego|github\.com/beego/beego", re.I)),
    ("actix", re.compile(r"actix_web", re.I)),
    ("aspnet", re.compile(r"Microsoft\.AspNetCore|System\.Web", re.I)),
    ("struts", re.compile(r"org\.apache\.struts", re.I)),
]


def detect_frameworks(code: str) -> list:
    return [name for name, pat in FRAMEWORK_PATTERNS if pat.search(code)]


def iter_pub_windows(since_year: int, days_per_window: int = 115):
    """生成 (pub_start, pub_end) ISO 窗口序列，从 since-01-01 到今天。"""
    end = time.time()
    cur = time.mktime(time.strptime(f"{since_year}-01-01", "%Y-%m-%d"))
    step = days_per_window * 86400
    while cur < end:
        win_end = min(cur + step, end)
        yield (time.strftime("%Y-%m-%dT00:00:00.000", time.gmtime(cur)),
               time.strftime("%Y-%m-%dT00:00:00.000", time.gmtime(win_end)))
        cur = win_end


def iter_ghsa_advisories(cwe_id: str, token: str, max_pages: int = 20):
    """遍历 GHSA advisory（按 CWE 过滤，每页 100 条，最多 max_pages 页）。

    返回 list of dict: {"cve_id", "description", "references"(list[str])}
    """
    out = []
    # 实测（2026-08-22）：cwes 参数只接受纯数字（"89"），带 "CWE-" 前缀返回空；
    # "cwe_id" 参数会被静默忽略（返回未过滤的全局列表）。GitHub 文档未说明。
    cwe_num = cwe_id.split("-", 1)[-1]
    for page in range(1, max_pages + 1):
        url = (f"{GITHUB_API}/advisories?type=reviewed&cwes={cwe_num}"
               f"&per_page=100&page={page}")
        status, _h, data = github_request(url, token)
        if status != 200 or not data:
            break
        for adv in data:
            cve_id = adv.get("cve_id") or ""
            if not cve_id:
                continue
            # 服务端过滤失效的哨兵：advisory 自带 cwes 数组，不匹配则计数
            adv_cwes = {c.get("cwe_id", "").upper() for c in adv.get("cwes", [])}
            if adv_cwes and cwe_id.upper() not in adv_cwes:
                out.append({"cve_id": cve_id, "description": "", "references": [],
                            "_cwe_mismatch": True})
                continue
            out.append({
                "cve_id": cve_id,
                "description": adv.get("description") or adv.get("summary") or "",
                "references": adv.get("references") or [],
            })
        if len(data) < 100:
            break
        time.sleep(0.5)
    return out


def extract_commit_from_str_refs(refs: list):
    """GHSA references 是纯字符串列表；提取第一个 GitHub commit URL。"""
    for url in refs or []:
        if not isinstance(url, str):
            continue
        m = _COMMIT_URL_RE.search(url)
        if m:
            return m.group(1), m.group(2), m.group(3)
    return None


def load_seen_cves_and_shas():
    """跨 testset + 两池的去重集合。"""
    seen_cves, seen_shas = set(), set()
    sources = [TESTSET_MANIFEST,
               CORPUS_DIR / "train_pool" / "manifest.json",
               CORPUS_DIR / "rolling_dev" / "manifest.json"]
    for mpath in sources:
        if not mpath.exists():
            continue
        try:
            m = json.loads(mpath.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[警告] 无法解析 {mpath}: {e}", file=sys.stderr)
            continue
        for s in m.get("samples", []):
            if s.get("cve_id"):
                seen_cves.add(s["cve_id"])
            if s.get("source_sha"):
                seen_shas.add(s["source_sha"])
    return seen_cves, seen_shas


def assign_pool(cve_id: str, dev_cap: int, dev_cur: int, dev_pct: int) -> str:
    """确定性分池：dev 未满时按 cve_id 哈希百分比进入 rolling_dev。"""
    if dev_cur >= dev_cap:
        return "train_pool"
    h = int(hashlib.md5(cve_id.encode()).hexdigest(), 16) % 100
    return "rolling_dev" if h < dev_pct else "train_pool"


def main():
    parser = argparse.ArgumentParser(description="CVE 真实语料管道（train_pool + rolling_dev）")
    parser.add_argument("--target-train", type=int, default=300)
    parser.add_argument("--dev-cap", type=int, default=50)
    parser.add_argument("--dev-pct", type=int, default=20)
    parser.add_argument("--per-cwe-cap", type=int, default=0)
    parser.add_argument("--cwes", type=str, default="")
    parser.add_argument("--source", choices=["ghsa", "nvd", "both"], default="ghsa",
                        help="发现源：ghsa（默认，commit 密度高）/ nvd / both")
    parser.add_argument("--ghsa-max-pages", type=int, default=20,
                        help="每个 CWE 最多遍历多少页 GHSA（每页 100 条）")
    parser.add_argument("--max-files-per-cve", type=int, default=1)
    parser.add_argument("--max-files-scan", type=int, default=10)
    parser.add_argument("--min-stars", type=int, default=3)
    parser.add_argument("--min-file-size", type=int, default=400)
    parser.add_argument("--max-file-size", type=int, default=20000)
    parser.add_argument("--nvd-proxy", type=str, default="http://127.0.0.1:7897")
    parser.add_argument("--nvd-results", type=int, default=50)
    parser.add_argument("--since-year", type=int, default=2019)
    parser.add_argument("--max-windows-per-cwe", type=int, default=0)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    token = check_token()

    cwe_caps = dict(DEFAULT_CWE_CAPS)
    if args.per_cwe_cap > 0:
        cwe_caps = {k: args.per_cwe_cap for k in DEFAULT_CWE_CAPS}
    if args.cwes:
        wanted = {c.strip().upper() for c in args.cwes.split(",") if c.strip()}
        cwe_caps = {k: v for k, v in cwe_caps.items() if k in wanted}

    train_dir = CORPUS_DIR / "train_pool"
    dev_dir = CORPUS_DIR / "rolling_dev"
    patch_dir = CORPUS_DIR / "patches"
    for d in (train_dir, dev_dir, patch_dir):
        d.mkdir(parents=True, exist_ok=True)

    train_manifest_path = train_dir / "manifest.json"
    dev_manifest_path = dev_dir / "manifest.json"
    if args.resume:
        train_m = load_existing_manifest(train_manifest_path)
        dev_m = load_existing_manifest(dev_manifest_path)
    else:
        if train_manifest_path.exists() or dev_manifest_path.exists():
            print("错误：已存在 manifest，增量抓取请加 --resume（防误覆盖）", file=sys.stderr)
            sys.exit(1)
        train_m = {"experiment": "cve_corpus_train_pool",
                   "discipline": "训练种子池；与 rolling_dev/testset 按 CVE ID 去重",
                   "samples": []}
        dev_m = {"experiment": "cve_corpus_rolling_dev",
                 "discipline": "滚动 dev 集：达到上限后冻结，不参与训练/选型，仅发布前测量",
                 "samples": []}

    seen_cves, seen_shas = load_seen_cves_and_shas()
    n_train = len(train_m["samples"])
    n_dev = len(dev_m["samples"])
    print(f"去重基线：已知 {len(seen_cves)} 个 CVE / {len(seen_shas)} 个 commit")
    print(f"池状态：train {n_train}/{args.target_train} | dev {n_dev}/{args.dev_cap}")
    print(f"发现源：{args.source} | CWE 目标：{len(cwe_caps)} 类\n")

    pool_manifests = {"train_pool": train_m, "rolling_dev": dev_m}
    pool_dirs = {"train_pool": train_dir, "rolling_dev": dev_dir}
    pool_paths = {"train_pool": train_manifest_path, "rolling_dev": dev_manifest_path}
    pool_next_idx = {}
    for pool, m in pool_manifests.items():
        idxs = [int(re.match(r"corpus_(\d+)", s["file"]).group(1))
                for s in m["samples"] if re.match(r"corpus_(\d+)", s.get("file", ""))]
        pool_next_idx[pool] = (max(idxs) + 1) if idxs else 1

    cwe_done = {}
    for s in train_m["samples"]:
        cwe_done[s.get("expected_cwe")] = cwe_done.get(s.get("expected_cwe"), 0) + 1

    stats = {"seen": 0, "skipped_known": 0, "no_commit": 0, "low_stars": 0,
             "detail_fail": 0, "no_file": 0, "oversize_commit": 0,
             "saved": 0, "pool_train": 0, "pool_dev": 0, "nvd_queries": 0}
    repo_star_cache = {}

    def save_all():
        save_manifest(train_manifest_path, train_m)
        save_manifest(dev_manifest_path, dev_m)

    def full():
        return n_train >= args.target_train and n_dev >= args.dev_cap

    def process_candidate(cve_id, desc, owner, repo, sha, query_cwe):
        """单个 CVE 候选的完整处理链。返回 True 表示已入库。"""
        nonlocal n_train, n_dev
        pool = assign_pool(cve_id, args.dev_cap, n_dev, args.dev_pct)
        if pool == "train_pool" and cwe_done.get(query_cwe, 0) >= (cwe_caps.get(query_cwe, 0)):
            if n_dev >= args.dev_cap:
                return False
            pool = "rolling_dev"

        repo_key = f"{owner}/{repo}"
        if repo_key in repo_star_cache:
            stars = repo_star_cache[repo_key]
        else:
            time.sleep(random.uniform(0.4, 0.8))
            stars = get_repo_stars(token, owner, repo)
            repo_star_cache[repo_key] = stars
        if 0 <= stars < args.min_stars:
            stats["low_stars"] += 1
            return False

        time.sleep(random.uniform(0.8, 1.6))
        detail = get_commit_detail(token, owner, repo, sha)
        if not detail or not detail.get("parents"):
            stats["detail_fail"] += 1
            return False
        parent_sha = detail["parents"][0]["sha"]
        if len(detail.get("files", [])) > 50:
            stats["oversize_commit"] += 1
            return False

        taken = 0
        scanned = 0
        for f in detail.get("files", []):
            if taken >= args.max_files_per_cve or scanned >= args.max_files_scan:
                break
            fname = f.get("filename", "")
            if not lang_of_file(fname) or is_excluded_file(fname):
                continue
            if f.get("status") == "removed":
                continue
            scanned += 1

            time.sleep(random.uniform(0.4, 0.8))
            code = get_file_content(token, owner, repo, fname, parent_sha)
            if code is None:
                continue
            if not (args.min_file_size <= len(code) <= args.max_file_size):
                continue

            idx = pool_next_idx[pool]
            ext = Path(fname).suffix.lower()
            base_name = f"corpus_{idx:05d}{ext}"
            (pool_dirs[pool] / base_name).write_text(code, encoding="utf-8")

            patch = f.get("patch") or ""
            patch_file = ""
            if patch:
                # 用 CVE ID 命名（全局唯一）——此前按 corpus_NNNNN 命名，
                # 两池同号互相覆盖（2026-08-22 事故：350 应存实存 265）
                patch_file = f"patches/{cve_id.replace('/', '_')}.patch"
                (CORPUS_DIR / patch_file).write_text(patch, encoding="utf-8")

            matched = detect_vuln_patterns(code)
            sample = {
                "file": base_name,
                "pool": pool,
                "language": lang_of_file(fname),
                "category": "cve_corpus",
                "difficulty": "real",
                "expected_present": True,
                "expected_vulnerability": (desc or cve_id)[:200],
                "expected_cwe": query_cwe,
                "expected_risk_level": "High",
                "source": "N/A", "sink": "N/A", "taint_path": "N/A",
                "fix_idea": f"参考修复 commit {owner}/{repo}@{sha[:8]}",
                "source_sha": sha,
                "source_repo": repo_key,
                "source_path": fname,
                "source_parent_sha": parent_sha,
                "cve_id": cve_id,
                "vuln_patterns": matched,
                "pattern_not_matched": len(matched) == 0,
                "frameworks": detect_frameworks(code),
                "patch_file": patch_file,
                "_built": time.strftime("%Y-%m-%d"),
            }
            pool_manifests[pool]["samples"].append(sample)
            pool_next_idx[pool] += 1
            seen_cves.add(cve_id)
            seen_shas.add(sha)
            taken += 1
            stats["saved"] += 1
            if pool == "train_pool":
                n_train += 1
                cwe_done[query_cwe] = cwe_done.get(query_cwe, 0) + 1
                stats["pool_train"] += 1
            else:
                n_dev += 1
                stats["pool_dev"] += 1
            print(f"    ✓ [{pool}] {base_name} {fname} "
                  f"({sample['language']}, {len(code)}B, pat={len(matched)})")
            save_all()
        if taken == 0:
            stats["no_file"] += 1
        return taken > 0

    def run_batch(candidates, query_cwe, batch_label):
        """处理一批候选（dict: cve_id/description/references），打印批次增量统计。"""
        before = {k: stats[k] for k in ("seen", "skipped_known", "no_commit",
                                        "low_stars", "detail_fail", "no_file",
                                        "oversize_commit", "saved",
                                        "cwe_mismatch") if k in stats}
        for cve in candidates:
            if full():
                return
            cve_id = cve["cve_id"]
            if cve.get("_cwe_mismatch"):
                stats["cwe_mismatch"] = stats.get("cwe_mismatch", 0) + 1
                continue
            stats["seen"] += 1
            if cve_id in seen_cves:
                stats["skipped_known"] += 1
                continue
            commit_info = extract_commit_from_str_refs(cve["references"])
            if not commit_info:
                stats["no_commit"] += 1
                continue
            owner, repo, sha = commit_info
            if sha in seen_shas:
                stats["no_commit"] += 1
                continue
            process_candidate(cve_id, cve.get("description", ""), owner, repo,
                              sha, query_cwe)
        d = {k: stats[k] - before[k] for k in before}
        print(f"    [批次统计 {batch_label}] 看+{d['seen']} 已知+{d['skipped_known']} "
              f"无commit+{d['no_commit']} 低star+{d['low_stars']} "
              f"detail败+{d['detail_fail']} 无文件+{d['no_file']} "
              f"超大commit+{d['oversize_commit']} 入库+{d['saved']}")

    done = False
    nvd_key = os.environ.get("NVD_API_KEY", "").strip()
    for cwe_id, cap in sorted(cwe_caps.items()):
        if done or full():
            done = True
            break
        have = cwe_done.get(cwe_id, 0)
        if have >= cap:
            continue
        print(f"\n{'=' * 56}\n[{cwe_id} {CWE_WHITELIST.get(cwe_id, '')}] "
              f"train 已有 {have}/{cap}")

        # ---- 主源：GHSA ----
        if args.source in ("ghsa", "both"):
            advisories = iter_ghsa_advisories(cwe_id, token,
                                              max_pages=args.ghsa_max_pages)
            print(f"  GHSA 返回 {len(advisories)} 条")
            run_batch(advisories, cwe_id, f"GHSA {cwe_id}")
            save_all()

        # ---- 后备源：NVD 窗口 ----
        if args.source in ("nvd", "both") and not full() \
                and cwe_done.get(cwe_id, 0) < cap:
            windows = list(iter_pub_windows(args.since_year))
            if args.max_windows_per_cwe > 0:
                windows = windows[-args.max_windows_per_cwe:]
            else:
                windows = windows[::-1]
            for w_start, w_end in windows:
                if full() or cwe_done.get(cwe_id, 0) >= cap:
                    break
                time.sleep(7)
                cves = search_nvd_by_cwe(cwe_id, proxy=args.nvd_proxy,
                                         max_results=args.nvd_results,
                                         pub_start=w_start, pub_end=w_end,
                                         api_key=nvd_key or None)
                stats["nvd_queries"] += 1
                print(f"  NVD 窗口 {w_start[:10]}~{w_end[:10]}: {len(cves)} 条")
                run_batch(cves, cwe_id, f"NVD {cwe_id}")
                save_all()

    save_all()

    print(f"\n{'=' * 60}")
    print(f"完成：train {n_train}（+{stats['pool_train']}） | dev {n_dev}（+{stats['pool_dev']}）")
    print(f"总统计：{json.dumps(stats, ensure_ascii=False)}")
    dist = {}
    for s in train_m["samples"]:
        dist[s.get("expected_cwe", "?")] = dist.get(s.get("expected_cwe", "?"), 0) + 1
    print("train_pool CWE 分布：")
    for c, n in sorted(dist.items(), key=lambda x: -x[1]):
        print(f"  {c}: {n}")
    fw_dist = {}
    for s in train_m["samples"]:
        for f in s.get("frameworks", []):
            fw_dist[f] = fw_dist.get(f, 0) + 1
    if fw_dist:
        print("框架分布：", dict(sorted(fw_dist.items(), key=lambda x: -x[1])))


if __name__ == "__main__":
    main()
