#!/usr/bin/env python3
"""Generic long_file manual data filler. Usage: _manual_longfile_runner.py <data.json> [--commit]"""
import sys, os, json
from pathlib import Path
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(HERE))
os.environ.setdefault("OPENROUTER_KEY", "dummy")
from graduation_project.prompts import ALPHA05_PROMPT
from gen_alpha06_variants import clean_analysis, normalize_verdict_json
from distill_alpha_pairs import validate

CORPUS = ROOT / "experiments" / "exp_06_finetune" / "corpus"
MIN_TOKEN, MAX_TOKEN = 3500, 12000

def main():
    data_path = Path(sys.argv[1])
    commit = "--commit" in sys.argv
    data = json.loads(data_path.read_text(encoding="utf-8"))
    kind_default = data.get("kind", "vuln")
    report, passed = [], []
    for item in data["entries"]:
        key = item["key"]
        kind = kind_default
        tag, kk, stem_full = key.split(":", 2)
        is_safe = stem_full.endswith("_fixed")
        stem = stem_full[:-6] if is_safe else stem_full
        ext = item.get("ext") or {"go": ".go", "php": ".php", "py": ".py", "js": ".js", "java": ".java"}[item["lang"]]
        rel = (f"train_pool/{stem}{ext}" if not is_safe else f"train_pool_fixed/{stem}_fixed{ext}")
        code = (CORPUS / rel).read_text(errors="replace")
        n_lines = code.count("\n") + 1
        lang = item["lang"]
        errs = []
        analysis = clean_analysis("\n".join(item["text"])).strip()
        jblock = json.dumps(item["json"], ensure_ascii=False)
        combined = analysis + "\n```json\n" + jblock + "\n```"
        rec, err = validate(normalize_verdict_json(combined), expect_vuln=(kind == "vuln"), n_lines=n_lines)
        if err:
            errs.append("validate: %s" % err)
        est_gen = 0
        if rec:
            A = len(rec["assistant"]); C = len(code)
            est_gen = (len(ALPHA05_PROMPT) + C + A) // 3
            print("  %s: A=%d C=%d est=%d" % (key, A, C, est_gen))
            if est_gen < MIN_TOKEN: errs.append("est~%d too short" % est_gen)
            elif est_gen > MAX_TOKEN: errs.append("too long")
        lines = code.splitlines()
        for ln, sub in item.get("anchors", []):
            if ln < 1 or ln > len(lines) or sub not in lines[ln - 1]:
                errs.append("anchor fail L%d want %r got %r" % (ln, sub, lines[ln-1][:48]))
        report.append((key, "PASS" if not errs else "FAIL", errs))
        if not errs and commit:
            passed.append((key, lang, rec, code, is_safe, ext))
    print_result(report, len(passed), len(data["entries"]))
    if commit and passed:
        write_out(passed, kind_default)

def print_result(report, npass, total):
    print("PASS %d/%d" % (npass, total))
    for k, st, e in report:
        print("[%s] %s %s" % (st, k, "; ".join(e)))

def write_out(passed, kind):
    with open(CORPUS / "long_file_wave.jsonl", "a", encoding="utf-8") as f, \
         open(CORPUS / "long_file_progress.jsonl", "a", encoding="utf-8") as pf:
        for key, lang, rec, code, is_safe, ext in passed:
            _, _, stem_full = key.split(":", 2)
            stem = stem_full[:-6] if is_safe else stem_full
            sample = {
                "messages": [
                    {"role": "system", "content": ALPHA05_PROMPT},
                    {"role": "user",
                     "content": f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```"},
                    {"role": "assistant", "content": rec["assistant"]},
                ],
                "meta": {"kind": f"long_file_{kind}", "seed_file": stem,
                         "out_lang": lang,
                         "est_tokens": (len(ALPHA05_PROMPT) + len(code) + len(rec["assistant"])) // 3},
            }
            f.write(json.dumps(sample, ensure_ascii=False) + "\n")
            pf.write(json.dumps({"key": key}) + "\n")

if __name__ == "__main__":
    main()
