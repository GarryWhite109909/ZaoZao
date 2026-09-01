"""形态 mining：从 CVE patch 的 -/+ 行提取漏洞形态与安全对照形态。

- 行 = 官方确认的漏洞位置（要召回）
+ 行 = 官方修复形态（要不误报）
pair 两者即可得出"该 CWE 在该语言下的 sink 形态 + 安全对照形态"。
"""
import json, os, re, glob, collections, sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = os.path.join(_ROOT, 'experiments/exp_06_finetune/corpus')
PATCH = os.path.join(BASE, 'patches')

# 1. 映射 corpus_NNNNN -> (lang, cwe, file)
meta = {}
for pool in ['rolling_dev', 'train_pool']:
    p = os.path.join(BASE, pool, 'manifest.json')
    if not os.path.exists(p):
        continue
    for s in json.load(open(p))['samples']:
        stem = re.sub(r'\.\w+$', '', s['file'])
        meta[stem] = (s.get('language'), s.get('expected_cwe'), pool)

# 2. 抽取 -/+ 行（跳过 @@ / --- / +++ 头）
def split_patch(path):
    minus, plus = [], []
    for ln in open(path, encoding='utf-8', errors='ignore'):
        ln = ln.rstrip('\n')
        if ln.startswith('@@') or ln.startswith('+++') or ln.startswith('---'):
            continue
        if ln.startswith('-'):
            minus.append(ln[1:])
        elif ln.startswith('+'):
            plus.append(ln[1:])
    return minus, plus

# 3. 调用/API 抽取：ident( 或 .ident( 或 语言特有构造
CALL = re.compile(r'([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(')
def calls(lines):
    c = collections.Counter()
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith('//') or s.startswith('#') or s.startswith('*'):
            continue
        for m in CALL.finditer(s):
            name = m.group(1)
            # 记录末段（方法名）与全限定名
            c[name] += 1
    return c

# 4. 按 (lang, cwe) 聚合
agg = collections.defaultdict(lambda: {'m': collections.Counter(), 'p': collections.Counter(), 'n': 0})
for f in sorted(glob.glob(os.path.join(PATCH, '*.patch'))):
    k = os.path.basename(f).replace('.patch', '')
    if k not in meta:
        continue
    lang, cwe, pool = meta[k]
    minus, plus = split_patch(f)
    key = (lang, cwe)
    agg[key]['m'].update(calls(minus))
    agg[key]['p'].update(calls(plus))
    agg[key]['n'] += 1

# 5. 输出：修复侧新增的函数（安全对照形态）优先——这是写规则的关键负样本信息
def report(min_n=3, topn=14):
    rows = sorted(agg.items(), key=lambda kv: -kv[1]['n'])
    print(f'{"语言":<10} {"CWE":<10} {"样本":>4}  漏洞侧(-行)高频调用 | 修复侧(+行)新增调用')
    print('-' * 130)
    for (lang, cwe), d in rows:
        if d['n'] < min_n:
            continue
        # 修复侧"新增"= 在 + 行出现且 - 行频次的 2 倍以上（即修复引入的新调用）
        only_plus = [(c, n) for c, n in d['p'].most_common(60)
                     if n >= 3 and d['m'].get(c, 0) * 2 < n]
        mtop = [f'{c}' for c, n in d['m'].most_common(topn) if n >= 2]
        ptop = [f'{c}' for c, n in only_plus[:topn]]
        print(f'{lang:<10} {cwe:<10} {d["n"]:>4}  -: {", ".join(mtop[:9])}')
        if ptop:
            print(f'{"":26}+: {", ".join(ptop[:9])}')

if __name__ == '__main__':
    min_n = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    report(min_n)
