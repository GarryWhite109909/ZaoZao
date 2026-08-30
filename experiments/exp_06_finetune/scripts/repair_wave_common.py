#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""修复蒸馏波共享工具：上下文加载 / 校验器 / prompt 构造。"""
import hashlib
import json
import re
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(Path(__file__).parent))
from distill_alpha_pairs import call_teacher  # noqa: F401  BigModel GLM 流式+重试
from gen_alpha06_variants import SCHEMA_LOCK, normalize_verdict_json  # noqa: F401

BASE = PROJECT / "experiments/exp_06_finetune"
CORPUS = BASE / "corpus/repair_wave"
PROGRESS = CORPUS / "_progress"
FAILED = CORPUS / "_failed"
V2_13 = BASE / "data/final_train_chatml_alpha06_v2_13.jsonl"
V2_12 = BASE / "data/final_train_chatml_alpha06_v2_12.jsonl"
MANIFEST = BASE / "audit/redistill_manifest_v2_13.jsonl"

CONTRACT = ["has_vulnerability", "vulnerability_type", "risk_level",
            "source", "sink", "explanation", "fix_suggestion"]
MONO_MARK = re.compile(r"\b(Actually|Hmm+|Let me|Wait,|sorry|I'll|I've|Okay,|Ah,)\b")
SHELL_VAGUE = [
    r"^检查用户可控输入点", r"^追踪输入到 sink 的路径", r"^N/A[，,]?\s*需判断",
    r"^识别代码中的用户输入点与处理逻辑", r"^N/A$", r"^未发现漏洞",
    r"^代码是安全的", r"^无$",
]
CHECKLIST = ("②对每条数据流逐一验证防御的类型/位置/覆盖面（黑名单/正则/字符串替换视为可绕过）；"
             "③明确交代第二入口或替代通道检查结论")


def load_context():
    ctx = {"rows12": {}, "rows13": {}, "assist_md5": set(), "user_md5": set(),
           "main_system": None, "manifest": [], "readj_user": None,
           "readj_system": None, "adjud_tail": None}
    for i, l in enumerate(open(V2_13, encoding="utf-8"), 1):
        if not l.strip():
            continue
        r = json.loads(l)
        msgs = r["messages"]
        ctx["assist_md5"].add(hashlib.md5(re.sub(r"\s+", "", msgs[2]["content"]).encode()).hexdigest())
        ctx["user_md5"].add(hashlib.md5(re.sub(r"\s+", "", msgs[1]["content"]).encode()).hexdigest())
        if ctx["main_system"] is None and len(msgs[0]["content"]) > 1900:
            ctx["main_system"] = msgs[0]["content"]
        if i == 1:
            ctx["main_system"] = msgs[0]["content"]
        if i == 7725:
            ctx["readj_user"], ctx["readj_system"] = msgs[1]["content"], msgs[0]["content"]
        if ctx["adjud_tail"] is None and (r.get("meta") or {}).get("kind") == "evidence_adjudication_pos":
            p = msgs[1]["content"].find("判定要求：")
            if p > 0:
                ctx["adjud_tail"] = msgs[1]["content"][p:]
    for i, l in enumerate(open(V2_12, encoding="utf-8"), 1):
        if l.strip():
            ctx["rows12"][i] = json.loads(l)
    for i, l in enumerate(open(V2_13, encoding="utf-8"), 1):
        if l.strip():
            ctx["rows13"][i] = json.loads(l)
    ctx["manifest"] = [json.loads(l) for l in MANIFEST.open(encoding="utf-8") if l.strip()]
    return ctx


def normalize_schema(obj):
    """教师结论 JSON → 主契约七字段（label/is_confirmed/reason/severity 等别名归一）。"""
    if not isinstance(obj, dict):
        return obj
    o = dict(obj)
    hv = o.get("has_vulnerability")
    if hv is None:
        for k in ("label", "is_confirmed", "verdict", "vulnerable", "is_vulnerable"):
            if k in o:
                v = o[k]
                hv = v if isinstance(v, bool) else str(v).strip().lower() in (
                    "true", "1", "yes", "存在漏洞", "真")
                break
    if hv is not None:
        o["has_vulnerability"] = bool(hv)
    vt = o.get("vulnerability_type")
    cid = o.pop("cwe_id", None)
    if vt is None or str(vt).strip() in ("无", "none", "None", ""):
        o["vulnerability_type"] = "none" if not cid or str(cid).strip() in ("无", "none", "") \
            else str(cid).strip()
    elif cid and str(cid).strip() not in ("无", "none", "") and str(cid).strip() not in str(vt):
        o["vulnerability_type"] = f"{vt}"
    if o.get("risk_level") is None:
        sev = o.pop("severity", None)
        if sev is not None:
            m = {"critical": "Critical", "high": "High", "medium": "Medium",
                 "moderate": "Medium", "low": "Low", "info": "Low",
                 "无": "None", "none": "None"}
            o["risk_level"] = m.get(str(sev).strip().lower(),
                                    m.get(str(sev).strip(), str(sev)))
    if not o.get("explanation") and "reason" in o:
        o["explanation"] = o["reason"]
    if o.get("has_vulnerability") is False:
        o["source"] = "N/A"
        o["sink"] = "N/A"
        if not o.get("fix_suggestion"):
            o["fix_suggestion"] = "no fix needed"
        if "external_inputs" in o and "external_inputs" not in str(o.get("explanation", "")):
            o["explanation"] = str(o.get("explanation", "")) + " 外部输入核查：" + str(o["external_inputs"])
    return {k: o[k] for k in CONTRACT if k in o}


def parse_json_block(text: str):
    """从教师输出提取最后一个 JSON 对象（括号配对扫描，字符串感知）+ schema 归一。"""
    idx = text.rfind("```json")
    if idx >= 0:
        s = text.find("{", idx)
    else:
        s = text.rfind("{")
    if s < 0:
        return None, "无 json 块"
    depth = 0
    in_str = False
    esc = False
    for i in range(s, len(text)):
        c = text[i]
        if esc:
            esc = False
            continue
        if c == "\\":
            esc = True
            continue
        if c == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                frag = text[s:i + 1]
                for cand in (frag, re.sub(r"\\(?!['\"\\/bfnrtu])", r"\\\\", frag)):
                    try:
                        obj = normalize_schema(json.loads(cand))
                        if isinstance(obj, dict) and obj.get("risk_level") is not None:
                            # 教师可能输出小写 none/high 等；统一为首字母大写规范值
                            obj["risk_level"] = str(obj["risk_level"]).strip().capitalize()
                        return obj, ""
                    except json.JSONDecodeError:
                        continue
                return None, "json 解析失败"
    return None, "JSON 未闭合（输出截断）"


def code_max_line(code: str) -> int:
    nums = [int(m.group(1)) for m in re.finditer(r"^\s*(\d+)\|", code, re.M)]
    return max(nums) if nums else 0


def check_contract(obj, expect_vuln, code_text):
    """七字段完整性 + 方向 + 枚举 + 行号范围。返回 err 或 None。"""
    missing = [k for k in CONTRACT if k not in obj]
    if missing:
        return f"缺字段 {missing}"
    hv = obj.get("has_vulnerability")
    if not isinstance(hv, bool):
        return "has_vulnerability 非布尔"
    if hv != expect_vuln:
        return f"方向错误: 期望 {expect_vuln}"
    if str(obj.get("risk_level", "")).capitalize() not in ("Critical", "High", "Medium", "Low", "None"):
        rl_raw = str(obj.get("risk_level", "")).strip().lower()
        # GLM 对安全样本写 risk_level="N/A"（语义合理，契约值应为 None），
        # hv=false 时归一（2026-08-29：47 条该型拒绝，最大浪费源）；漏洞样本
        # 的 N/A 无风险等级语义，保持拒绝
        if rl_raw in ("n/a", "na", "无", "不适用") and hv is False:
            obj["risk_level"] = "None"
        else:
            return f"risk_level 非法 {obj.get('risk_level')}"
    if not expect_vuln:
        vt_raw = str(obj.get("vulnerability_type", "")).strip()
        if vt_raw.lower() in ("none", ""):
            return None
        # GLM 习惯在安全样本的 vt 写"无漏洞（…已被…防御）"类防御说明而非逐字
        # none（2026-08-29 活体探测：r2 被拒 268 条方向门全过、分析全在论证安全）。
        # 无 CWE 编号的描述性 vt 归一为 none——方向判定已由教师确认，归一无信息损失；
        # 含 CWE 编号视为教师指认具体漏洞类型，保持拒绝走重试。
        if re.search(r"CWE-\d+", vt_raw, re.I):
            return "安全样本 vt 应为 none"
        obj["vulnerability_type"] = "none"
        return None
    vt = str(obj.get("vulnerability_type", ""))
    if not re.match(r"^CWE-\d+", vt):
        m = re.search(r"CWE-\d+", vt)
        if not m:
            return f"vt 非规范: {vt[:40]}"
        # GLM 混合形态（"容器以root特权运行（CWE-250）"）归一：提取首个
        # CWE 编号作规范 vt，教师已指认类型，完整描述保留在分析文本中
        obj["vulnerability_type"] = m.group(0)
        vt = m.group(0)
    if re.search(r"CWE-\d+\s*/\s*(?:CWE-)?\d+", vt) or re.match(r"CWE-\d+\s*[:：]", vt):
        # 合并/冒号形态同理归一到首个编号
        m = re.search(r"CWE-\d+", vt)
        obj["vulnerability_type"] = m.group(0)
        vt = m.group(0)
    mx = code_max_line(code_text)
    if mx > 0:
        for m in re.finditer(r"line\s*(\d+)", json.dumps(obj, ensure_ascii=False), re.I):
            if not (1 <= int(m.group(1)) <= mx + 2):
                return f"行号越界 line {m.group(1)} > {mx}"
    return None


def check_style(assistant: str):
    """独白/空壳/超长/泄漏/无步骤门。返回 err 或 None。"""
    if len(assistant) > 6000:
        return f"assistant 过长 {len(assistant)}"
    aw = re.findall(r"[A-Za-z]{2,}", assistant)
    cjk = len(re.findall(r"[\u4e00-\u9fff]", assistant))
    if len(aw) > 60 and len(aw) > 3 * max(cjk, 1):
        return "英文独白嫌疑"
    if MONO_MARK.search(assistant):
        return "独白标记命中"
    if "安全模式白名单" in assistant or "命中安全模式" in assistant:
        return "元信息泄漏"
    steps = [l for l in assistant.split("```json")[0].split("\n")
             if re.match(r"^\s*\d+\.\s*", l)]
    if not steps:
        return "无编号步骤"
    sh = sum(1 for l in steps
             if (m := re.match(r"^\s*\d+\.\s*([^：:]{2,20})[：:]\s*(.*)$", l))
             and any(re.search(p, m.group(2).strip()) for p in SHELL_VAGUE))
    if sh >= 2:
        return "空壳步骤"
    return None


def clean_analysis_text(body: str) -> str:
    """正文清洗：去 markdown 标题/粗体（保持与库内正文风格一致）。"""
    body = re.sub(r"^#{1,6}\s*[^\n]*$", "", body, flags=re.M)
    body = re.sub(r"\*\*([^*\n]{1,60})\*\*", r"\1", body)
    return re.sub(r"\n{3,}", "\n\n", body).strip()


def norm_md5(s: str) -> str:
    return hashlib.md5(re.sub(r"\s+", "", s).encode()).hexdigest()


def split_analysis_json(text: str):
    """teacher 输出 → (分析正文, verdict_obj, err)。"""
    text = normalize_verdict_json(text)
    obj, err = parse_json_block(text)
    if obj is None:
        return None, None, err
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.S)
    body = re.sub(r"^LANG:\s*\S+\s*$", "", text[:m.start()], flags=re.M).strip()
    return body, obj, ""


def make_analysis_validator(kind, user_content, system, expect_vuln, task_key,
                            ctx, style_check=True, dup_check=True):
    """构造分析重跑类任务的 validator（正文+JSON → 训练记录）。"""
    def _val(text):
        body, obj, err = split_analysis_json(text)
        if obj is None:
            return None, err
        body = clean_analysis_text(body)
        e = check_contract(obj, expect_vuln if expect_vuln is not None else bool(obj.get("has_vulnerability")),
                           user_content)
        if e:
            return None, e
        assistant = body + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```"
        if style_check:
            e = check_style(assistant)
            if e:
                return None, e
        if dup_check and norm_md5(assistant) in ctx["assist_md5"]:
            return None, "与现有库重复"
        return ({"messages": [{"role": "system", "content": system},
                              {"role": "user", "content": user_content},
                              {"role": "assistant", "content": assistant}],
                 "meta": {"kind": kind, "task_key": task_key}}, None)
    return _val


def gen_user(lang: str, code: str) -> str:
    return f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```"


ANALYSIS_FMT = ("【输出格式】\n"
                "1. 直接以\"1.\"编号步骤开始，3~6 步，每步锚定真实行号（写\"第 N 行\"），"
                "引用代码里真实的函数名/变量名；禁止英文独白、禁止元话语（Actually/Hmm/Let me）、"
                "禁止 markdown 标题、禁止输出代码。\n"
                "2. " + CHECKLIST + "。\n"
                "3. 分析结束后另起一行输出 ```json 七字段结论（字段顺序：has_vulnerability, "
                "vulnerability_type, risk_level, source, sink, explanation, fix_suggestion）。"
                "JSON 字符串值内严禁英文双引号；source/sink 格式 'line N: 代码标识'；"
                "无漏洞时 vulnerability_type='none'、risk_level='None'、source/sink='N/A'、"
                "fix_suggestion='no fix needed'。")
