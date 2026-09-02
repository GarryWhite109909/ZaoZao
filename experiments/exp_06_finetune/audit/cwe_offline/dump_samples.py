import json, sys
from pathlib import Path
data = json.loads(Path('all_samples_for_review.json').read_text(encoding='utf-8'))
which = sys.argv[1]; start = int(sys.argv[2]); count = int(sys.argv[3])
sel = [d for d in data if d['set'] == which]
for d in sel[start:start+count]:
    code = d['code']
    lines = [l for l in code.split('\n')]
    # trim leading/trailing blanks
    while lines and not lines[0].strip(): lines.pop(0)
    while lines and not lines[-1].strip(): lines.pop()
    if len(lines) > 55: lines = lines[:55] + ['...<truncated %d lines>' % (code.count(chr(10))-55)]
    print('='*80)
    print(f"[{d['set']}] {d['id']} | cwe={d['cwe']} | present={d['present']} | {d.get('cve','')}")
    print(f"desc: {d['desc']}")
    print('-'*40)
    print('\n'.join(lines))
