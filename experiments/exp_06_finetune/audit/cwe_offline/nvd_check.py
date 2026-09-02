import json, time, urllib.request, sys
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
data = json.loads(Path('all_samples_for_review.json').read_text(encoding='utf-8'))
cves = {}
for d in data:
    c = d.get('cve')
    if c and c != 'N/A':
        cves.setdefault(c, []).append((d['set'], d['id'], d['cwe']))
print('unique CVEs to query:', len(cves))
out_path = Path('nvd_cwe_check.jsonl')
done = set()
if out_path.exists():
    for line in out_path.read_text(encoding='utf-8').splitlines():
        try: done.add(json.loads(line)['cve'])
        except Exception: pass
print('already done:', len(done))
for cve, samples in cves.items():
    if cve in done: continue
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}'
    rec = {'cve': cve, 'samples': samples, 'nvd_cwes': None, 'error': None}
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'cwe-audit/1.0'})
        resp = urllib.request.urlopen(req, timeout=30)
        j = json.loads(resp.read().decode('utf-8'))
        cwes = set()
        for v in j.get('vulnerabilities', []):
            descs = v['cve']['metrics'].keys()
            for cm in v['cve']['metrics'].get('cvssMetricV31', []) + v['cve']['metrics'].get('cvssMetricV30', []) + v['cve']['metrics'].get('cvssMetricV2', []):
                pass
            for dd in v['cve']['descriptions']:
                pass
            weaknesses = v['cve'].get('weaknesses', [])
            for w in weaknesses:
                for dv in w['description']:
                    cwes.add(dv['value'])
        rec['nvd_cwes'] = sorted(cwes)
    except Exception as e:
        rec['error'] = str(e)[:200]
    with out_path.open('a', encoding='utf-8') as f:
        f.write(json.dumps(rec, ensure_ascii=False) + '\n')
    print(cve, rec['nvd_cwes'], rec['error'] or '')
    time.sleep(6.5)  # NVD без key: 5 req/30s -> безопасный темп
print('DONE')
