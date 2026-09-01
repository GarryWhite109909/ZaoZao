# -*- coding: utf-8 -*-
"""v2_15 wave1 重蒸馏 runner(GLM-5.3-flash + 锚表增强 prompt)。

用法:
  export ZHIPU_API_KEY=...        # 不落盘、不入 git
  python distill_repair_wave_v15.py --mode redistill \\    # 14 条重蒸馏
      [--limit N] [--model glm-5.3-flash]
  python distill_repair_wave_v15.py --mode groups --kits corpus/repair_wave/wave2  # 辨析组任务包

管线门(任一不过即拒,写入 rejects):
  G1 dual 一致性:temp0.7 采样两次,has_vulnerability 与 CWE 编号必须一致;
     不一致时 temp0.3 第三次仲裁,仍分裂则拒(转人工)
  G2 F8 sink 特征:vulnerability_type 声称的 sink 特征必须出现在单文件代码中
  G3 锚点范围:source/sink 的 line N 不得越界
  G4 契约:单行 JSON、七字段按序、无契约外字段、除 json 块外无代码块
成功样本写入 _wave1_out/success.jsonl(messages 三元组 + teacher 元数据),
格式与 corpus/repair_wave/*.jsonl 一致,可直接进 merge。
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
CORPUS = BASE / "corpus/repair_wave"
OUT_DIR = CORPUS / "_wave1_out"
# 默认走 coding plan 端点(套餐额度只在此通道有效);普通 API 端点按余额计费
API_URL = os.environ.get("ZHIPU_API_URL",
                         "https://open.bigmodel.cn/api/coding/paas/v4/chat/completions")

JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)
CODE_FENCE = re.compile(r"```[\w+#.\-/]*[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)
CONTRACT = ["has_vulnerability", "vulnerability_type", "risk_level",
            "source", "sink", "explanation", "fix_suggestion"]

# G2: CWE -> sink 特征(命中任一即可;未列出的 CWE 跳过 G2)
SINK_SIG = {
    "78": ["system", "exec", "popen", "subprocess", "eval", "os.popen", "sh"],
    "89": ["execute", "query", "SELECT", "INSERT", "UPDATE", "rawQuery"],
    "22": ["open", "readFile", "file_get_contents", "send_file", "FileResponse", "fopen",
           "tar", "archive", "path.combine", "file.exists", "extractto"],
    "79": ["send", "echo", "render", "write", "innerHTML", "print"],
    "502": ["loads", "unserialize", "unmarshal", "yaml.load", "pickle"],
    "94": ["eval", "exec"],
    "1336": ["render_template_string", "Template", "render", "eval"],
    "611": ["parse", "XML", "DocumentBuilder", "ET.fromstring"],
    "918": ["requests.get", "http.Get", "http.Post", "urlopen", "curl", "client.Get", "PostAsync"],
}

def call_teacher(key, model, system, user, temperature, thinking="disabled"):
    global CALL_N, TOK_IN, TOK_OUT
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "temperature": temperature,
        "max_tokens": 16384,   # 放宽:长分析+长输出防截断(JSON 截断会被 G4 拒)
    }
    # glm-5.3-flash 是强制思考模型:thinking disabled 会被 400 拒绝,
    # 因此 disabled 时不发送该字段(默认思考,content 输出仍干净);enabled 照发。
    if thinking != "disabled":
        payload["thinking"] = {"type": thinking}
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(API_URL, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
    })
    last_err = None
    for attempt in range(5):
        if CALL_N >= MAX_CALLS:
            raise RuntimeError(f"预算用尽({MAX_CALLS} 次调用)")
        try:
            t0 = time.time()
            # 1800s:智谱算力紧张时排队+思考模型长生成可能远超 15 分钟(用户要求放宽防误判)
            with urllib.request.urlopen(req, timeout=1800) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            CALL_N += 1
            u = data.get("usage", {})
            TOK_IN += u.get("prompt_tokens", 0)
            TOK_OUT += u.get("completion_tokens", 0)
            return data["choices"][0]["message"]["content"], u
        except urllib.error.HTTPError as e:
            last_err = e
            wait = 30 * (attempt + 1)   # 429/限流感知退避
            print(f"    ! HTTP {e.code},退避 {wait}s", flush=True)
            time.sleep(wait)
        except Exception as e:
            last_err = e
            time.sleep(5 * (attempt + 1))
    raise RuntimeError(f"重试 5 次仍失败: {last_err}")

def gates(assistant, code):
    """返回 (ok, reason)。G2/G3/G4。"""
    ms = list(re.finditer(r"```json\s*(.*?)```", assistant, re.S))
    if not ms:
        return False, "G4: 无 json 块"
    try:
        o = json.loads(ms[-1].group(1))
    except Exception as e:
        return False, f"G4: JSON 解析失败 {e}"
    if list(o.keys()) != CONTRACT:
        return False, f"G4: 字段序/集不符 {list(o.keys())}"
    if re.search(r"```", assistant[: ms[-1].start()]):
        return False, "G4: json 块之外存在代码块"
    code_lines = code.split("\n") if code else []
    cwe_num = None
    m = re.search(r"CWE-(\d+)", str(o.get("vulnerability_type", "")))
    if m:
        cwe_num = m.group(1)
    if str(o.get("has_vulnerability")) == "True" and cwe_num:
        sigs = SINK_SIG.get(cwe_num)
        if sigs and code:
            nc = code.lower()
            if not any(s.lower() in nc for s in sigs):
                return False, f"G2: CWE-{cwe_num} sink 特征不在代码中"
    for fld in ("source", "sink"):
        for am in re.finditer(r"line\s*(\d+)", str(o.get(fld, "") or "")):
            if code_lines and int(am.group(1)) > len(code_lines):
                return False, f"G3: {fld} 锚点 {am.group(1)} 越界(共 {len(code_lines)} 行)"
    return True, "ok"

CALL_N = TOK_IN = TOK_OUT = 0
MAX_CALLS = 10 ** 9

def consensus(key, model, system, user, code, thinking="disabled"):
    """G1 dual 双采样 + 三次仲裁。返回 (assistant, note, usage合计) 或 (None, reject_reason, usage)。"""
    outs, usages = [], []
    for k in range(2):
        t, u = call_teacher(key, model, system, user, temperature=0.7, thinking=thinking)
        outs.append(t); usages.append(u)
    def concl(t):
        ms = re.findall(r"```json\s*(.*?)```", t, re.S)
        if not ms:
            return None
        try:
            o = json.loads(ms[-1])
        except Exception:
            return None
        m = re.search(r"CWE-(\d+)", str(o.get("vulnerability_type", "")))
        return (o.get("has_vulnerability"), m.group(1) if m else None)
    c1, c2 = concl(outs[0]), concl(outs[1])
    if c1 is not None and c1 == c2:
        return outs[0], "dual 一致", usages
    arb, u = call_teacher(key, model, system, user, temperature=0.3, thinking=thinking)
    usages.append(u)
    c3 = concl(arb)
    if c3 is not None and (c3 == c1 or c3 == c2):
        return arb, "2v1 仲裁", usages
    return None, f"G1: dual 分裂 {c1} vs {c2} vs {c3}", usages

def compose_system():
    base = json.loads((CORPUS / "g9_1321.jsonl").open(encoding="utf-8").readline())
    base_sys = base["messages"][0]["content"]
    anchors = (CORPUS / "teacher_prompt_v15_wave1.md").read_text(encoding="utf-8")
    # 取追加层部分(截至 runner 说明之前)
    anchors = anchors.split("## 追加层一")[1]
    anchors = "## 追加层一" + anchors.split(" runner 侧管线门")[0]
    return base_sys + "\n\n" + anchors.strip() + "\n"

def main():
    global MAX_CALLS
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["redistill", "groups"], required=True)
    ap.add_argument("--kits", default=str(CORPUS / "wave2"))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--model", default="glm-5.3-flash")
    ap.add_argument("--thinking", choices=["disabled", "enabled"], default="disabled")
    ap.add_argument("--max-calls", type=int, default=400)
    ap.add_argument("--manifest",
                    default=str(BASE / "audit/redistill_manifest_v2_15_wave1.jsonl"))
    args = ap.parse_args()
    key = os.environ.get("ZHIPU_API_KEY")
    if not key:
        print("缺少 ZHIPU_API_KEY 环境变量"); sys.exit(1)
    MAX_CALLS = args.max_calls

    system = compose_system()
    OUT_DIR.mkdir(exist_ok=True)
    tasks = []
    if args.mode == "redistill":
        manifest = [json.loads(l) for l in
                    Path(args.manifest).open(encoding="utf-8")
                    if l.strip()]
        for mrec in manifest:
            user = mrec["user"]
            if mrec.get("hint"):
                user += ("\n\n【前期审计已实测的事实(供参考;仍需你在分析中独立核对代码)】\n"
                         + mrec["hint"])
            tasks.append({"orig": mrec["orig_line"], "user": user})
    else:
        for kf in sorted(Path(args.kits).glob("*.jsonl")):
            for l in kf.open(encoding="utf-8"):
                if l.strip():
                    tasks.append(json.loads(l))
    if args.limit:
        tasks = tasks[: args.limit]
    print(f"任务 {len(tasks)} 条 | model={args.model} | thinking={args.thinking} | 预算 {args.max_calls} 次调用",
          flush=True)

    ok_f = (OUT_DIR / "success.jsonl").open("a", encoding="utf-8")
    rj_f = (OUT_DIR / "rejects.jsonl").open("a", encoding="utf-8")
    done_origs = set()
    sp = OUT_DIR / "success.jsonl"
    if sp.exists():
        for l in sp.open(encoding="utf-8"):
            if l.strip():
                try:
                    done_origs.add(json.loads(l)["fix_distill"]["orig"])
                except Exception:
                    pass
    n_ok = n_rj = n_skip = 0
    for i, t in enumerate(tasks, 1):
        if t.get("orig") in done_origs:
            n_skip += 1
            continue
        user = t["user"]
        if t.get("hint"):   # groups 模式与 redistill 模式统一支持 hint 注入
            user += ("\n\n【前期审计已实测的事实(供参考;仍需你在分析中独立核对代码)】\n"
                     + t["hint"])
        code_m = CODE_FENCE.search(user)
        code = code_m.group(1) if code_m else ""
        t0 = time.time()
        try:
            assistant, note, usages = consensus(key, args.model, system, user, code,
                                                thinking=args.thinking)
        except Exception as e:
            rj_f.write(json.dumps({"orig": t.get("orig"), "reject": f"API 失败: {e}"},
                                  ensure_ascii=False) + "\n")
            rj_f.flush()
            n_rj += 1
            print(f"  [{i}/{len(tasks)}] orig={t.get('orig')} !! {str(e)[:60]} "
                  f"(calls={CALL_N} tok={TOK_IN}/{TOK_OUT})", flush=True)
            continue
        if assistant is None:
            rj_f.write(json.dumps({"orig": t.get("orig"), "reject": note},
                                  ensure_ascii=False) + "\n")
            rj_f.flush()
            n_rj += 1
            print(f"  [{i}/{len(tasks)}] orig={t.get('orig')} 拒: {note} "
                  f"(calls={CALL_N} tok={TOK_IN}/{TOK_OUT})", flush=True)
            continue
        ok, reason = gates(assistant, code)
        if not ok:
            rj_f.write(json.dumps({"orig": t.get("orig"), "reject": reason,
                                   "assistant": assistant[:800]},
                                  ensure_ascii=False) + "\n")
            rj_f.flush()
            n_rj += 1
            print(f"  [{i}/{len(tasks)}] orig={t.get('orig')} 闸拒: {reason} "
                  f"(calls={CALL_N} tok={TOK_IN}/{TOK_OUT})", flush=True)
            continue
        # 抽取结论摘要供实时质检
        try:
            o = json.loads(re.findall(r"```json\s*(.*?)```", assistant, re.S)[-1])
            brief = f"hv={o.get('has_vulnerability')} {str(o.get('vulnerability_type'))[:38]} {o.get('risk_level')}"
        except Exception:
            brief = "?"
        ok_f.write(json.dumps({
            "messages": [
                {"role": "system", "content": json.loads(
                    (CORPUS / "g9_1321.jsonl").open(encoding="utf-8").readline())["messages"][0]["content"]},
                {"role": "user", "content": user},
                {"role": "assistant", "content": assistant},
            ],
            "fix_distill": {"teacher": f"{args.model}-wave1(t={args.thinking[0]})",
                            "generated_at": "2026-08-31",
                            "gate_note": note, "orig": t.get("orig")},
        }, ensure_ascii=False) + "\n")
        ok_f.flush()
        n_ok += 1
        print(f"  [{i}/{len(tasks)}] orig={t.get('orig')} OK {brief} | {note} "
              f"| {time.time()-t0:.0f}s calls={CALL_N} tok={TOK_IN}/{TOK_OUT}", flush=True)
    ok_f.close(); rj_f.close()
    print(f"完成: 成功 {n_ok} / 拒 {n_rj} / 跳过 {n_skip} | 总调用 {CALL_N} "
          f"tokens {TOK_IN}/{TOK_OUT} -> {OUT_DIR}", flush=True)

if __name__ == "__main__":
    main()
