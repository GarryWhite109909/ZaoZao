# 诊断配方（可复制执行的离线复现模板）

所有脚本在仓库根目录执行，使用带依赖的解释器（如 `~/miniconda3/bin/python3`）。

## 1. 最小 mock client 复现（最常用）

用假模型输出驱动整条管道，隔离"工具层是否正确"与"模型判得对不对"：

```python
import sys, json; sys.path.insert(0, '.')
from graduation_project.two_stage_scanner import TwoStageScanner

MODEL_OUT = '{"has_vulnerability": true, "vulnerability_type": "CWE-22 Path Traversal",' \
            '"risk_level": "High", "source": "line 9: request.args.get(...)",' \
            '"sink": "line 14: tar.extractall(...)", "explanation": "e", "fix_suggestion": "f"}'
it = iter([MODEL_OUT] * 12)   # 多备几个，避免 StopIteration

ts = TwoStageScanner(
    client=type("M", (), {"model": "m", "generate": staticmethod(
        lambda **kw: {"text": next(it), "error": None, "duration": 0.1})})(),
    system_prompt="x", triage_aligned=True, no_candidate_mode="full_recheck",
    n_samples=3, trust_llm_recheck=True,
    use_conformal=False, use_signal_feedback=False, use_counterfactual=False, num_ctx=8192)

code = open('experiments/exp_04_hard_samples/samples/<FILE>', encoding='utf-8').read()
d = ts.scan_code(code=code, language="python", filename="<FILE>").to_dict()

print('decision :', d.get('stage1', {}).get('decision'))
print('by_tool  :', {k: v for k, v in d.get('stage1', {}).get('by_tool', {}).items() if v})
print('type     :', d.get('vulnerability_type'), '| raw:', d.get('raw_vulnerability_type'))
for a in d.get('adjudications', []):
    f = a.get('finding') or {}
    print(f"  votes={a.get('votes_true')}/{a.get('votes_false')}/{a.get('votes_invalid')}",
          f"srcL={f.get('source_line')} sinkL={f.get('sink_line')} rule={str(f.get('rule_id'))[:40]}")
```

## 2. 零召回：区分「没命中」还是「命中后被丢弃」

```python
from graduation_project.external_scanner import ExternalScanner
from graduation_project.prefilter import Prefilter
import tempfile, os

with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as t:
    t.write(code); p = t.name
raw = ExternalScanner().scan_sast(p, 'python'); os.unlink(p)
print('工具原始告警:', [(getattr(r, 'rule_id', '?'), getattr(r, 'line', '?')) for r in raw])
print('prefilter    :', Prefilter().scan(code, 'python'))

fs = ts._stage1_recall(code, 'python', filename)
print('最终候选:', len(fs))
# 原始有输出但最终 0 → 命中后被丢弃（剔除规则误杀），查 _infer_taint_type 与白名单
```

## 3. 类型归因链路核查

```python
from graduation_project.two_stage_scanner import TwoStageScanner, _STANDARD_TAINT_TYPES
for f in fs:
    claimed = TwoStageScanner._infer_taint_type(f.to_dict())
    print(f"{str(f.rule_id)[:44]:46s} taint={str(f.taint_type)[:22]:24s} "
          f"claimed={claimed[:22]} 白名单内={claimed in _STANDARD_TAINT_TYPES}")
    # claimed 不在白名单 → sast/iac 候选会被 _drop_irrelevant_positional 剔除
```

## 4. 行号正确性验证（对所有锚点）

```python
from graduation_project.line_normalizer import normalize_line_numbers
for anchor in ['line 7: xxx', 'line 8-10: yyy', '第 9 行: zzz']:
    print(normalize_line_numbers(anchor, code))
```

纠不动的典型原因（均为已修盲区，遇到新形态照此排查）：
纯中文叙述无代码锚 / 区间锚 / f-string 前缀一字差 / 修复建议长新代码挤占片段 / import 行抢占定位。

## 5. 修复后：全量 87 段回归

```python
import json
from pathlib import Path
S = Path('experiments/exp_04_hard_samples/samples')
meta = {s['file']: s for s in json.load(open(S / 'manifest.json', encoding='utf-8'))['samples']}

vuln_cand = safe_cand = 0; vuln_zero = []
for f, m in sorted(meta.items()):
    fp = S / f
    if not fp.exists(): continue
    c = fp.read_text(encoding='utf-8')
    lang = 'java' if f.endswith('.java') else ('javascript' if f.endswith('.js') else 'python')
    n = len(mk()._stage1_recall(c, lang, f))          # mk() = 配方 1 的构造器
    if m.get('expected_present'):
        vuln_cand += n
        if n == 0: vuln_zero.append(f)
    else:
        safe_cand += n
print(f'真漏洞候选 {vuln_cand}｜安全样本候选 {safe_cand}（应基本持平）｜真漏洞 0 候选 {len(vuln_zero)} 段')
```

## 6. 模拟前端分析（检查展示字段完整性）

```python
for k in ['has_vulnerability', 'vulnerability_type', 'raw_vulnerability_type', 'risk_level',
          'source', 'sink', 'explanation', 'fix_suggestion']:
    v = str(d.get(k))
    print(('OK ' if v and v != 'None' else '空 '), k, '=', v[:60])
print('stage1.decision =', d.get('stage1', {}).get('decision'))
```

前端依赖的候选字段：`rule_id` / `category` / `tool`（工具来源徽章）、
`source_line` / `sink_line`（行号徽章）、`votes_true/false/invalid` + `confidence`（裁决卡）。

## 7. 前端逻辑的 node 实测（不改后端也能验证）

提取 `scan.html` 里的纯函数用 node 跑，避免"改了前端但无法离线验证"：

```python
import io, subprocess, re
html = io.open('app/backend/static/scan.html', encoding='utf-8').read()
i = html.index('function <FN>'); j = html.index('function <NEXT_FN>')
js = "var TOOL_LABELS={}; function escapeHtml(s){return String(s);}" + html[i:j] + "<测试代码>"
subprocess.run(['node', '/tmp/t.js'], ...)   # 见 /tmp 临时文件写法
```

## 8. 重启判断

```bash
ps -eo pid,lstart,cmd | grep bootstrap            # 进程启动时间
stat -c '%y' graduation_project/two_stage_scanner.py graduation_project/prefilter.py ...
```
代码修改时间晚于进程启动 → 需重启；否则无需。
