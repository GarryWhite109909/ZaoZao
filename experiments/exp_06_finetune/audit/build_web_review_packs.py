# -*- coding: utf-8 -*-
"""网页 AI 审查包生成器 v2:把指定样本拆成 ≤20K token 的审查包。

id 语义 = v2_14 行号(与审计/manifest 对账一致):
  - 未被删除的样本 → v2_15 中原位(行号 = id - 前方删除数)
  - 重蒸馏追加的 11 条(4378/6345/8965/4771/7456/7877/8210/9067/9170/9750/8081)
    → v2_15 文件尾部追加区,按 success.jsonl 顺序定位
用法:
  python build_web_review_packs.py --ids-file waveA_ids.json
  waveA_ids.json: [{"id": 4378, "tag": "重蒸馏回归"}, ...]
输出: audit/web_review/pack_NN.txt + web_review_manifest.json(回收聚合用)
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
SUCC = BASE / "corpus/repair_wave/_wave1_out/success.jsonl"
AUD = Path(__file__).resolve().parent
JB = re.compile(r"```json\s*(.*?)```", re.S)
FENCE = re.compile(r"```[\w+#.\-/]*[ \t]*\r?\n(.*?)(?:```|\Z)", re.S)

HEADER = """你是独立安全审查员,对一份漏洞分析数据集的样本做质检。对每个样本:忽略给出的教师结论,自己读代码独立判断,再对比教师结论找差异。

【常见教师错误方向(逐条对照)】
1. bash/eval 引号语义:双引号内 ; | \\ 不作分隔;但 $( ) 反引号会展开;eval 场景二次解析可逃逸;shlex.quote 后不可注入
2. 诱饵注释不可信:代码注释自称"漏洞点/真正漏洞"不是依据,必须找到对应数据流
3. SSTI 先分位:常量模板+输入走形参=数据位(非 SSTI);输入拼进模板源码=模板位(成立);escape 不处理花括号
4. Path.Combine/os.path.join 的 rooted-path 与 .. 逃逸;node 列表参数中 argv[0] 可控仍是注入
5. 硬编码密钥/OTP 常量本身即漏洞,恒时比较救不了
6. 行号必须与编号代码核对(行内自标注释的行号不可信)
7. CWE 归类:shell 元字符=78 非 88/95;硬编码加密密钥=321;HQL=943;mass assignment=915;堆溢出=122;双free=415/UAF=416;信息泄露=200;缓存投毒XSS=79
8. 风险校准:未认证 RCE/接管=Critical;反射 XSS/DoS=Medium;需部署假设的降级并声明

【输出格式】每个样本输出一行 JSON(不要代码块):
{"id": <样本id>, "verdict": "AGREE|DISAGREE|UNSURE", "teacher_hv_correct": true/false, "cwe_should": "CWE-xxx 或 none", "issues": ["发现的问题,每条一句"], "note": "一句话理由"}
最后一个样本之后,单独输出一行汇总:{"packet_done": true, "agree": n, "disagree": n, "unsure": n}

【样本】
"""

def token_est(s):
    cjk = sum(1 for ch in s if "\u4e00" <= ch <= "\u9fff")
    return int(1.616 * cjk + 0.24 * (len(s) - cjk))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids-file", required=True)
    ap.add_argument("--out", default=str(AUD / "web_review"))
    ap.add_argument("--budget", type=int, default=20000)
    ap.add_argument("--per-packet", type=int, default=10)
    args = ap.parse_args()

    raw = json.load(open(args.ids_file, encoding="utf-8"))
    wanted = [(x["id"], x.get("tag", "")) if isinstance(x, dict) else (x, "") for x in raw]

    # id -> v2_15 行号
    del_ids = {json.loads(l)["id"] for l in
               (AUD / "agent_audit_v2_14/out/manifest_DELETE.jsonl").open(encoding="utf-8") if l.strip()} | {8288, 8968}
    id2line = {}
    n = 0
    for i in range(1, 10022):
        if i in del_ids:
            continue
        n += 1
        id2line[i] = n
    # 重蒸馏追加区:v2_15 第 9948 行起为追加样本,记录自带 fix_distill.orig
    lines = DATA.read_text(encoding="utf-8").split("\n")
    n_base = len(id2line)   # 基底条数(未删样本按序占 1..n_base 行)
    tail = {}
    tline = n_base
    for l in lines[n_base:]:
        if not l.strip():
            continue
        tline += 1
        rec = json.loads(l)
        orig = (rec.get("fix_distill") or {}).get("orig")
        if orig:
            id2line[orig] = tline
            tail[orig] = tline
    n_total = tline

    # 抽取样本块
    blocks = []
    for wid, tag in wanted:
        ln = id2line.get(wid)
        if ln is None or ln - 1 >= len(lines):
            print(f"  !! id={wid} 无行映射,跳过")
            continue
        rec = json.loads(lines[ln - 1])
        code = FENCE.findall(rec["messages"][1]["content"])
        code = code[0] if code else ""
        cl = code.split("\n")
        numbered = "\n".join(f"{i+1:4d}| {l}" for i, l in enumerate(cl))
        ms = JB.findall(rec["messages"][2]["content"])
        try:
            o = json.loads(ms[-1])
        except Exception:
            continue
        compact = {k: o.get(k) for k in ("has_vulnerability", "vulnerability_type",
                                         "risk_level", "source", "sink",
                                         "explanation", "fix_suggestion")}
        block = (f"── 样本 id={wid}" + (f"({tag})" if tag else "") + f" | 代码共 {len(cl)} 行 ──\n"
                 f"【教师结论】has_vulnerability={o.get('has_vulnerability')}, "
                 f"{o.get('vulnerability_type')}, risk={o.get('risk_level')}\n"
                 f"【source】{o.get('source')}\n【sink】{o.get('sink')}\n"
                 f"【explanation】{o.get('explanation')}\n【fix_suggestion】{o.get('fix_suggestion')}\n"
                 f"【代码】\n{numbered}\n")
        blocks.append({"id": wid, "tag": tag, "text": block, "tokens": token_est(block)})

    # 打包
    outdir = Path(args.out)
    outdir.mkdir(exist_ok=True)
    packets = []
    cur, cur_tok, cur_ids = [], 0, []
    for b in blocks:
        if cur and (cur_tok + b["tokens"] > args.budget or len(cur) >= args.per_packet):
            packets.append((cur, cur_tok, cur_ids))
            cur, cur_tok, cur_ids = [], 0, []
        cur.append(b); cur_tok += b["tokens"]; cur_ids.append(b["id"])
    if cur:
        packets.append((cur, cur_tok, cur_ids))

    manifest = []
    for pi, (bs, tok, ids) in enumerate(packets, 1):
        p = outdir / f"pack_{pi:02d}.txt"
        p.write_text(HEADER + "\n".join(b["text"] for b in bs), encoding="utf-8")
        manifest.append({"packet": p.name, "ids": ids, "est_tokens": tok + token_est(HEADER)})
        print(f"  {p.name}: {len(bs)} 样本 ids={ids} ~{tok + token_est(HEADER)} tok")
    (outdir / "web_review_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"共 {len(blocks)} 样本 -> {len(packets)} 包 -> {outdir}")

if __name__ == "__main__":
    main()
