"""修复性质分类：判断每个 CVE 的修复属于哪类改动，反推规则可学性。

三类：
  A 加转义/校验/门控函数（+ 行引入新安全 API）      → 形态可学（规则可写）
  B 换 API（+ 行与 - 行同功能不同 API）            → 可学但需 API 对知识
  C 重构逻辑/结构改动/删代码（无新安全 API 引入）    → 形态不可学
"""
import json, os, re, glob, collections

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = os.path.join(_ROOT, 'experiments/exp_06_finetune/corpus')
PATCH = os.path.join(BASE, 'patches')

# 安全 API 词典（修复常引入的）
SECURE_API = [
    'escape', 'sanitiz', 'quote', 'shlex', 'basename', 'normpath', 'realpath',
    'filepath.Join', 'filepath.Clean', 'secure_filename', 'htmlspecialchars',
    'htmlentities', 'setFeature', 'setObjectInputFilter', 'validate', 'check',
    'allowlist', 'whitelist', 'denylist', 'blacklist', 'BLOCKED', 'sandbox',
    'Sandboxed', 'verify', 'authoriz', 'permission', 'hasLength', 'equalsIgnoreCase',
    'isExactMatch', 'parseUri', 'SecurityError', 'ValueError', 'throw new',
    'ip_network', 'normalize', 'setDefault', 'withNoLock', 'scoped',
]
# 危险 API 词典（漏洞侧常在）
DANGER_API = [
    'exec', 'eval', 'system', 'popen', 'Runtime', 'ProcessBuilder',
    'unserialize', 'readObject', 'ObjectInputStream', 'fromXML', 'loadXML',
    'md5', 'sha1', 'innerHTML', 'document.write', 'renderString', 'Environment',
    'Template', 'query', 'execute', 'open', 'fopen', 'requests.get', 'axios',
]

meta = {}
for pool in ['rolling_dev', 'train_pool']:
    p = os.path.join(BASE, pool, 'manifest.json')
    if not os.path.exists(p):
        continue
    for s in json.load(open(p))['samples']:
        meta[re.sub(r'\.\w+$', '', s['file'])] = (s.get('language'), s.get('expected_cwe'))

stat = collections.defaultdict(lambda: collections.Counter())
lang_stat = collections.defaultdict(lambda: collections.Counter())
for f in sorted(glob.glob(os.path.join(PATCH, '*.patch'))):
    k = os.path.basename(f).replace('.patch', '')
    if k not in meta:
        continue
    lang, cwe = meta[k]
    if not cwe:
        continue
    minus, plus = [], []
    for ln in open(f, encoding='utf-8', errors='ignore'):
        ln = ln.rstrip()
        if ln.startswith('-') and not ln.startswith('---'):
            minus.append(ln[1:])
        elif ln.startswith('+') and not ln.startswith('+++'):
            plus.append(ln[1:])
    mbody, pbody = '\n'.join(minus), '\n'.join(plus)
    has_new_sec = any(a.lower() in pbody.lower() for a in SECURE_API)
    has_danger = any(a.lower() in mbody.lower() for a in DANGER_API)
    # 换 API：漏洞侧与修复侧都调用了某个同名/近名 API，但修复侧出现新标识
    if has_danger and has_new_sec:
        cls = 'A 加校验/门控'
    elif has_danger and not has_new_sec:
        cls = 'B 仅删改危险调用'
    elif has_new_sec and not has_danger:
        cls = 'C 仅加校验(洞不在词面)'
    else:
        cls = 'D 纯结构/逻辑重构'
    stat[cwe][cls] += 1
    lang_stat[lang][cls] += 1

print(f'{"CWE":<10} {"n":>3}  A加校验  B删危险  C仅校验  D纯重构')
print('-' * 56)
tot = collections.Counter()
for cwe, c in sorted(stat.items(), key=lambda kv: -sum(kv[1].values())):
    n = sum(c.values())
    if n < 3:
        continue
    tot.update(c)
    print(f'{cwe:<10} {n:>3}  {c["A 加校验/门控"]:>6}  {c["B 仅删改危险调用"]:>6}  {c["C 仅加校验(洞不在词面)"]:>6}  {c["D 纯结构/逻辑重构"]:>6}')
n = sum(tot.values())
print('-' * 56)
print(f'{"合计":<10} {n:>3}  {tot["A 加校验/门控"]:>6}  {tot["B 仅删改危险调用"]:>6}  {tot["C 仅加校验(洞不在词面)"]:>6}  {tot["D 纯结构/逻辑重构"]:>6}')
print(f'\n形态可学(A+B): {(tot["A 加校验/门控"]+tot["B 仅删改危险调用"])*100//max(n,1)}%   形态不可学(C+D): {(tot["C 仅加校验(洞不在词面)"]+tot["D 纯结构/逻辑重构"])*100//max(n,1)}%')
print('\n按语言:')
for lang, c in sorted(lang_stat.items(), key=lambda kv: -sum(kv[1].values())):
    nn = sum(c.values())
    learn = c["A 加校验/门控"] + c["B 仅删改危险调用"]
    print(f'  {lang:<12} n={nn:>3}  可学 {learn:>3} ({learn*100//max(nn,1)}%)')
