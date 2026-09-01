"""形态可检测性评估：用现有工具 sink 词典客观判定每个 CWE 的漏洞侧是否可静态检测。

判定：patch 的漏洞侧(-)行中若出现任一已知 sink 形态 → "可检测"；
否则为"无静态形态"（验证/配置/数据流型，规则写不出）。
输出按 CWE 聚合的可检测率，用于指导规则投入优先级。
"""
import json, os, re, glob, collections, sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _ROOT)

BASE = os.path.join(_ROOT, 'experiments/exp_06_finetune/corpus')
PATCH = os.path.join(BASE, 'patches')

# 从现有工具层抽取 sink 词典（客观基准，非主观判断）
import graduation_project.prefilter as PF
import graduation_project.taint_tracker as TT

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sink_terms = set()
# taint sink 定义
for k in getattr(TT, '_SINK_DEFINITIONS', {}):
    if isinstance(k, tuple):
        sink_terms.update(x for x in k if isinstance(x, str))
    elif isinstance(k, str):
        sink_terms.add(k)
# prefilter 的 vuln 类规则 pattern 源串（粗取，够用作词典）
src = open(PF.__file__, encoding='utf-8').read()
for m in re.finditer(r'"([a-z_]*(?:exec|eval|query|render|read|write|open|request|url|deserial|unserial|template|file|cmd|shell|system|inject)[a-z_]*)"', src, re.I):
    sink_terms.add(m.group(1))

# 补充通用危险 API 词典（跨语言公认 sink）
sink_terms |= {
    'exec', 'eval', 'system', 'popen', 'subprocess', 'os.system', 'Runtime.exec',
    'ProcessBuilder', 'exec.Command', 'execAsync', 'execFile', 'shell_exec',
    'passthru', 'proc_open', 'assert', 'pickle.loads', 'yaml.load', 'unserialize',
    'ObjectInputStream', 'readObject', 'deserialize', 'fromXML', 'loadXML',
    'innerHTML', 'document.write', 'echo', 'print', 'res.send', 'res.write',
    'renderString', 'render', 'Environment', 'Template', 'md5', 'sha1',
    'cursor.execute', 'mysqli_query', 'query', 'createQuery', 'find',
    'urllib', 'requests.get', 'axios.get', 'needle.get', 'http.get',
    'open', 'fopen', 'file_get_contents', 'readFile', 'FileInputStream',
}

meta = {}
for pool in ['rolling_dev', 'train_pool']:
    p = os.path.join(BASE, pool, 'manifest.json')
    if not os.path.exists(p):
        continue
    for s in json.load(open(p))['samples']:
        meta[re.sub(r'\.\w+$', '', s['file'])] = (s.get('language'), s.get('expected_cwe'))

# 逐 patch 判定
stat = collections.defaultdict(lambda: {'n': 0, 'det': 0})
lang_stat = collections.defaultdict(lambda: {'n': 0, 'det': 0})
for f in sorted(glob.glob(os.path.join(PATCH, '*.patch'))):
    k = os.path.basename(f).replace('.patch', '')
    if k not in meta:
        continue
    lang, cwe = meta[k]
    if not cwe:
        continue
    vuln = []
    for ln in open(f, encoding='utf-8', errors='ignore'):
        ln = ln.rstrip()
        if ln.startswith('-') and not ln.startswith('---'):
            vuln.append(ln[1:])
    body = '\n'.join(vuln)
    det = any(t in body for t in sink_terms)
    stat[cwe]['n'] += 1
    stat[cwe]['det'] += 1 if det else 0
    lang_stat[lang]['n'] += 1
    lang_stat[lang]['det'] += 1 if det else 0

print(f'{"CWE":<10} {"样本":>4} {"可检测":>6} {"率":>6}')
print('-' * 34)
rows = sorted(stat.items(), key=lambda kv: -kv[1]['n'])
tot_n = tot_d = 0
for cwe, d in rows:
    if d['n'] < 3:
        continue
    tot_n += d['n']; tot_d += d['det']
    print(f'{cwe:<10} {d["n"]:>4} {d["det"]:>6} {d["det"]*100//d["n"]:>5}%')
print('-' * 34)
print(f'{"合计(n>=3)":<10} {tot_n:>4} {tot_d:>6} {tot_d*100//max(tot_n,1):>5}%')
print()
print('按语言:')
for lang, d in sorted(lang_stat.items(), key=lambda kv: -kv[1]['n']):
    print(f'  {lang:<12} {d["n"]:>4} 样本  可检测 {d["det"]:>3} ({d["det"]*100//max(d["n"],1)}%)')
