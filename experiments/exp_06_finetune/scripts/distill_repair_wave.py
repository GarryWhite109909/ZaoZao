#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""审计修复蒸馏波主脚本：r 包（重蒸馏）+ g 包（新数据生成）。

用法：
  set -a; source scripts/.env; set +a
  python3 scripts/distill_repair_wave.py --pilot
  python3 scripts/distill_repair_wave.py --packs r1_expl --workers 6
断点续传：corpus/repair_wave/_progress/{pack}.jsonl
"""
import argparse
import json
import os
import re
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from repair_wave_common import (
    CORPUS, PROGRESS, FAILED, call_teacher, load_context, parse_json_block,
    check_contract, check_style, norm_md5, gen_user, clean_analysis_text,
    CONTRACT,
)
from gen_alpha06_variants import SCHEMA_LOCK

random = __import__("random")
random.seed(42)

LANGS_MAIN = ["python", "java", "go", "php", "javascript"]
LANGS_NEW = ["typescript", "csharp", "kotlin"]
CWES = {
    "python": ["CWE-89", "CWE-78", "CWE-22", "CWE-79", "CWE-502", "CWE-611", "CWE-918", "CWE-1336"],
    "java": ["CWE-89", "CWE-78", "CWE-22", "CWE-611", "CWE-502", "CWE-918", "CWE-1336", "CWE-327"],
    "go": ["CWE-89", "CWE-78", "CWE-22", "CWE-79", "CWE-502", "CWE-918", "CWE-1333", "CWE-117"],
    "php": ["CWE-89", "CWE-78", "CWE-22", "CWE-79", "CWE-502", "CWE-611", "CWE-918", "CWE-98"],
    "javascript": ["CWE-79", "CWE-22", "CWE-78", "CWE-1336", "CWE-918", "CWE-1333", "CWE-502", "CWE-611"],
    "typescript": ["CWE-79", "CWE-22", "CWE-78", "CWE-1336", "CWE-918", "CWE-1333", "CWE-502", "CWE-89"],
    "csharp": ["CWE-89", "CWE-78", "CWE-22", "CWE-79", "CWE-502", "CWE-611", "CWE-918", "CWE-327"],
    "kotlin": ["CWE-89", "CWE-78", "CWE-22", "CWE-79", "CWE-502", "CWE-611", "CWE-918", "CWE-330"],
}
DEFENSES = ["参数化查询/预编译语句", "白名单精确允许集（枚举后映射）", "输出处上下文转义/编码",
            "语言原生安全 API（参数化/沙箱/安全解析）", "框架自动防护确认启用且未被关闭",
            "强类型转换后使用（int() 强转使注入失效）", "路径规范化后前缀校验（canonical path 双重校验）",
            "最小权限上下文隔离（只读连接/受限角色）"]
SCENARIOS = ["报表导出服务", "文件上传管理器", "用户资料查询接口", "订单处理后台任务",
             "日志归档工具", "配置中心客户端", "消息队列消费者", "定时对账任务",
             "静态资源服务", "模板渲染辅助", "webhook 出站发送器", "缓存编解码模块",
             "数据导入适配器", "运维命令封装库", "富文本处理模块", "会话管理组件",
             "权限校验中间件", "图片处理流水线", "邮件模板服务", "审计日志查询",
             "搜索索引构建器", "支付回调处理器", "API 网关转发器", "数据同步工作线程"]
TRUST_FLAW_TEXT = {
    "CWE-441": "对外部请求指定的目标主机/URL 或 Host 头完全信任，未加白名单即转发或回调（混淆代理人）",
    "CWE-862": "敏感操作只依赖调用方自觉传入的标志位/角色参数，服务端没有集中鉴权强制点",
    "CWE-863": "有鉴权但把'内部服务/本地调用'默认视为已授权，未校验来源身份",
    "CWE-346": "以来源 IP/内网网段/自定义请求头判断可信身份，这些凭据可被伪造",
}
SPECIAL = {
    "request_smuggling": ("CWE-444", "HTTP 请求走私",
                          "前端代理与后端对 Content-Length / Transfer-Encoding 解析优先级不一致，"
                          "或对 CL+TE 并存/混淆大小写/重复头处理分歧，可走私第二个请求绕过前端控制"),
    "cache_poisoning": ("CWE-525", "Web 缓存投毒",
                        "缓存键遗漏影响响应内容的头（X-Forwarded-Host/Accept-Language 等）或路径规范化差异，"
                        "攻击者可注入缓存供其他用户命中"),
    "dependency_confusion": ("CWE-1357", "依赖混淆",
                             "安装脚本对内部私有包名未限定私有源，或版本解析优先公共仓库，"
                             "攻击者注册同名公共包即可在构建/运行环境执行代码"),
}

FMT_HEAD = ("【输出格式】只输出以下部分，不要多余说明：\n"
            "LANG: {lang}\n"
            "```{lang}\n<完整代码>\n```\n"
            "1. <编号步骤分析，3~5 步，引用真实行号（第 N 行）与真实标识符，"
            "禁止英文独白/元话语/markdown 标题/输出代码>\n")
FMT_JSON_TRUE = ("```json\n<七字段 JSON，has_vulnerability=true，"
                 "vulnerability_type='{cwe} '+官方英文名，risk_level 按 CVSS 直觉给，"
                 "source/sink 格式 'line N: 标识'，explanation 用 -> 串联数据流，"
                 "fix_suggestion 给最小修复行+改法>\n```\n"
                 "JSON 字符串值内严禁英文双引号。\n" + SCHEMA_LOCK)
FMT_JSON_FALSE = ("```json\n<七字段 JSON，has_vulnerability=false，vulnerability_type='none'，"
                  "risk_level='None'，source='N/A'，sink='N/A'，explanation 说明防御为何有效，"
                  "fix_suggestion='no fix needed'>\n```\n"
                  "JSON 字符串值内严禁英文双引号。\n" + SCHEMA_LOCK)


def fmt_head(lang):
    return FMT_HEAD.replace("{lang}", lang)


def gen_prompt_vuln(lang, cwe, scenario, extra=""):
    ex = f"   5. 额外要求：{extra}。\n" if extra else ""
    return (f"生成一条【真实存在漏洞】的漏洞检测训练样本。\n\n"
            f"【要求】\n"
            f"1. 语言 {lang}，漏洞类型 {cwe}，功能场景：{scenario}。\n"
            f"2. 代码 15~45 行，自包含可读（含少量合理注释），外部输入入口清晰，"
            f"从入口到 sink 的数据流真实可达，无有效防御（不得用参数化/白名单等把漏洞堵上）。\n"
            f"3. 分析须覆盖：入口枚举、到 sink 的数据流、防御缺失/可绕过原因、替代通道检查结论。\n"
            f"4. 严禁出现真实凭据/密钥/密码明文。\n{ex}\n"
            + fmt_head(lang) + FMT_JSON_TRUE.replace("{cwe}", cwe))


def gen_prompt_safe(lang, cwe, scenario, defense):
    return (f"生成一条【看似危险实安全】的漏洞检测训练样本。\n\n"
            f"【要求】\n"
            f"1. 语言 {lang}，表面涉及 {cwe} 相关的危险 API/模式，功能场景：{scenario}。\n"
            f"2. 代码 15~45 行，自包含可读。代码表面包含危险调用，但存在真实有效的防御使其安全："
            f"{defense}。防御必须真实生效（不是黑名单、不是可绕过正则、不是字符串替换），"
            f"且在代码中清晰可见。\n"
            f"3. 分析须说明为什么这条数据流是安全的（防御类型/位置/覆盖面），"
            f"并交代替代通道检查结论。\n"
            f"4. 严禁出现真实凭据/密钥/密码明文。\n\n"
            + fmt_head(lang) + FMT_JSON_FALSE)


def make_gen_validator(kind, expect_vuln, task_key, ctx, min_lines=15, max_lines=45,
                       multi_file=False):
    """生成型任务 validator：解析 LANG/代码块/正文/JSON，装配训练记录。"""
    def _val(text):
        text = text.strip()
        m_lang = re.match(r"LANG:\s*(\S+)", text)
        if not m_lang:
            return None, "缺 LANG 行"
        lang = m_lang.group(1).strip()
        obj, err = parse_json_block(text)
        if obj is None:
            return None, err
        jm = text.rfind("```json")
        pre = text[:jm]
        blocks = list(re.finditer(r"```[\w+#]*\n(.*?)```", pre, re.S))
        if not blocks:
            return None, "无代码块"
        body = pre[blocks[-1].end():].strip()
        if multi_file:
            parts = re.findall(r"###\s*文件:\s*(\S+)\s*\n```[\w+#]*\n(.*?)```", pre, re.S)
            if len(parts) < 2:
                return None, f"多文件样本需 ≥2 个文件块，实得 {len(parts)}"
            user = ("【多文件项目片段】\n\n" + "\n\n".join(
                f"### 文件: {p}\n```{lang}\n{c.rstrip()}\n```" for p, c in parts))
            code_text = "\n".join(c for _, c in parts)
            n_lines = max(c.count("\n") + 1 for _, c in parts)
            if not (min_lines <= n_lines <= max_lines):
                return None, f"最大文件 {n_lines} 行不在 [{min_lines},{max_lines}]"
        else:
            code = blocks[0].group(1).rstrip()
            n_lines = code.count("\n") + 1
            if not (min_lines <= n_lines <= max_lines):
                return None, f"代码 {n_lines} 行不在 [{min_lines},{max_lines}]"
            user = gen_user(lang, code)
            code_text = code
        e = check_contract(obj, expect_vuln, code_text)
        if e:
            return None, e
        mx = max((int(m.group(1)) for m in re.finditer(r"第\s*(\d+)\s*行", body)), default=0)
        if mx > n_lines + 2:
            return None, f"正文引用第 {mx} 行 > 代码 {n_lines} 行"
        body = clean_analysis_text(body)
        assistant = body + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```"
        e = check_style(assistant)
        if e:
            return None, e
        if norm_md5(assistant) in ctx["assist_md5"] or norm_md5(user) in ctx["user_md5"]:
            return None, "与现有库重复"
        return ({"messages": [{"role": "system", "content": ctx["main_system"]},
                              {"role": "user", "content": user},
                              {"role": "assistant", "content": assistant}],
                 "meta": {"kind": kind, "task_key": task_key, "gen": True}}, None)
    return _val


def load_pairs(pack):
    f = CORPUS / f"{pack}.jsonl"
    out = []
    if f.exists():
        for l in f.open(encoding="utf-8"):
            if l.strip():
                out.append(json.loads(l))
    return out


def lang_code_of(rec):
    u = rec["messages"][1]["content"]
    m = re.match(r"代码片段（语言:\s*(\w+)）：\s*\n```[\w+#]*\n(.*?)```", u, re.S)
    return (m.group(1), m.group(2).rstrip()) if m else ("python", "")


def build_tasks(ctx, packs, pilot):
    T = []
    def add(pack, key, prompt, validator, **kw):
        T.append({"pack": pack, "key": key, "prompt": prompt,
                  "validator": validator, **kw})
    man = ctx["manifest"]
    by_reason = {}
    for m in man:
        by_reason.setdefault(m["reason"], []).append(m)

    # ---------- r1_expl ----------
    if "r1_expl" in packs:
        for m in by_reason.get("explanation_na", []):
            ol = m["orig_line"]
            r12 = ctx["rows12"].get(ol)
            if not r12:
                continue
            a = r12["messages"][2]["content"]
            jm = re.findall(r"```json\s*(.*?)```", a, re.S)
            if not jm:
                continue
            try:
                o = json.loads(jm[-1])
            except Exception:
                continue
            body = a.split("```json")[0].strip()
            user = (f"【代码】\n{r12['messages'][1]['content']}\n\n"
                    f"【已有分析步骤】\n{body[:3500]}\n\n"
                    f"【任务】已有分析结论 has_vulnerability={o.get('has_vulnerability')}，"
                    f"但结论 JSON 的 explanation 字段是 N/A。请只重写 explanation 字段："
                    f"1~3 句中文，用 -> 串联关键数据流或防御逻辑，与分析步骤一致；"
                    f"不要输出 JSON、代码块或任何多余内容，只输出 explanation 的文本。")
            def val_r1(text, o=o, body=body, r12=r12, ol=ol):
                t = text.strip().strip('"').strip()
                if not (15 <= len(t) <= 320):
                    return None, f"长度 {len(t)} 不合"
                if t.upper().startswith("N/A"):
                    return None, "仍是 N/A"
                # v2_12 原行可能带旧 system / 小写 risk_level / cvss_* 残留字段，
                # 合并回 v2_13 前必须全部归一，否则破坏 P0-1/P1-7/P2-18 三项审计
                o7 = {k: o[k] for k in CONTRACT if k in o}
                o7["explanation"] = t
                o7["risk_level"] = str(o7.get("risk_level", "None")).strip().capitalize()
                assistant = body + "\n```json\n" + json.dumps(o7, ensure_ascii=False) + "\n```"
                return ({"messages": [{"role": "system", "content": ctx["main_system"]},
                                      dict(r12["messages"][1]),
                                      {"role": "assistant", "content": assistant}],
                         "meta": {"kind": (r12.get("meta") or {}).get("kind", "base"),
                                  "task_key": f"rd_expl:{ol}"}}, None)
            add("r1_expl", f"r1:{ol}", user, val_r1)

    # ---------- r2_regen ----------
    REGEN = {"teacher_monologue", "shell_analysis", "duplicate_assistant",
             "contradictory_label"}
    seen = set()
    for m in man:
        ol = m["orig_line"]
        if ol in seen or m["reason"] not in REGEN:
            continue
        seen.add(ol)
        r12 = ctx["rows12"].get(ol)
        if not r12:
            continue
        user12 = r12["messages"][1]["content"]
        ev = None
        if m["reason"] != "contradictory_label":
            try:
                o12 = json.loads(re.findall(r"```json\s*(.*?)```",
                                            r12["messages"][2]["content"], re.S)[-1])
                ev = bool(o12.get("has_vulnerability"))
            except Exception:
                pass
        if ev is None:
            direction = "请基于代码本身自由判定（true 或 false 均可，必须与代码事实一致）"
            schema_line = "true/false 按你的独立判定"
        else:
            direction = ("这段代码最终判定为【存在漏洞 has_vulnerability=true】——请写出从入口到 sink "
                         "的完整数据流与防御缺失/可绕过分析" if ev else
                         "这段代码最终判定为【安全 has_vulnerability=false】——"
                         "你必须找出使其安全的有效防御并说明其类型/位置/覆盖面")
            schema_line = (f"has_vulnerability 必须为 {ev}"
                           if ev else
                           f"has_vulnerability 必须为 false，vulnerability_type 必须逐字写 none（禁止填防御说明文字）")
        prompt = (f"你要为漏洞检测模型重新生成一条训练数据的【分析部分】。原始任务如下：\n\n"
                  f"{user12}\n\n【要求】\n"
                  f"1. {direction}。\n"
                  f"2. 直接以\"1.\"编号步骤开始，3~6 步，每步锚定真实行号（第 N 行），"
                  f"引用代码里真实的函数名/变量名；禁止英文独白、禁止元话语（Actually/Hmm/Let me）、"
                  f"禁止 markdown 标题、禁止输出代码。\n"
                  f"3. 分析必须覆盖：①枚举全部外部输入点并确认到 sink 的可达性；"
                  f"②对每条数据流逐一验证防御的类型/位置/覆盖面（黑名单/正则/字符串替换视为可绕过）；"
                  f"③明确交代第二入口或替代通道检查结论。\n"
                  f"4. 分析结束后另起一行输出 ```json 七字段结论（{schema_line}）。"
                  f"JSON 字符串值内严禁英文双引号。\n{SCHEMA_LOCK}")

        def make_val_r2(ev=ev, user12=user12, ol=ol, reason=m["reason"]):
            def _val(text):
                text = text.strip()
                obj, err = parse_json_block(text)
                if obj is None:
                    return None, err
                exp = ev if ev is not None else bool(obj.get("has_vulnerability"))
                e = check_contract(obj, exp, user12)
                if e:
                    return None, e
                jm = text.rfind("```json")
                body = clean_analysis_text(text[:jm].strip())
                assistant = body + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```"
                e = check_style(assistant)
                if e:
                    return None, e
                if norm_md5(assistant) in ctx["assist_md5"]:
                    return None, "与现有库重复"
                return ({"messages": [{"role": "system", "content": ctx["main_system"]},
                                      {"role": "user", "content": user12},
                                      {"role": "assistant", "content": assistant}],
                         "meta": {"kind": f"rd_{reason}", "task_key": f"rd_regen:{ol}"}}, None)
            return _val
        add("r2_regen", f"r2:{ol}", prompt, make_val_r2())

    # ---------- r3_readj ----------
    if "r3_readj" in packs and ctx["readj_user"]:
        prompt = (f"{ctx['readj_user']}\n\n"
                  f"（复核提示：告警所称 sink 与传播链的每一跳都必须逐一在代码中核验；"
                  f"链断、sink 不存在或输入不可达时判 false。输出主契约七字段 JSON。）\n{SCHEMA_LOCK}")

        def val_r3(text):
            text = text.strip()
            obj, err = parse_json_block(text)
            if obj is None:
                return None, err
            exp = bool(obj.get("has_vulnerability"))
            e = check_contract(obj, exp, ctx["readj_user"])
            if e:
                return None, e
            jm = text.rfind("```json")
            body = clean_analysis_text(text[:jm].strip())
            assistant = body + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```"
            e = check_style(assistant)
            if e:
                return None, e
            return ({"messages": [{"role": "system", "content": ctx["readj_system"]},
                                  {"role": "user", "content": ctx["readj_user"]},
                                  {"role": "assistant", "content": assistant}],
                     "meta": {"kind": "evidence_adjudication_recheck",
                              "task_key": "rd_readj:7725"}}, None)
        add("r3_readj", "r3:7725", prompt, val_r3)

    # ---------- g1_looks_safe（200）----------
    if "g1_looks_safe" in packs:
        grid = []
        for li, lang in enumerate(LANGS_MAIN):
            for ci, cwe in enumerate(CWES[lang]):
                for di, dfn in enumerate(DEFENSES[:5]):
                    grid.append((lang, cwe, dfn,
                                 SCENARIOS[(li * 8 + ci * 5 + di) % len(SCENARIOS)]))
        random.shuffle(grid)
        for idx, (lang, cwe, dfn, scen) in enumerate(grid[:200]):
            add("g1_looks_safe", f"g1:{idx}",
                gen_prompt_safe(lang, cwe, scen, dfn),
                make_gen_validator("looks_like_vuln_safe", False,
                                   f"gen_looks_safe:{idx}", ctx))

    # ---------- g2_evidence（23）----------
    if "g2_evidence" in packs:
        for idx in range(23):
            lang = LANGS_MAIN[idx % 5]
            cwe = CWES[lang][(idx // 5) % 8]
            scen = SCENARIOS[(idx * 3) % len(SCENARIOS)]
            prompt = (f"分三步生成一条【裁决类正例】训练素材：\n\n"
                      f"【第一步】写一段真实存在 {cwe} 漏洞的 {lang} 代码（15~40 行，场景：{scen}，"
                      f"入口到 sink 可达、无有效防御）。\n"
                      f"【第二步】以静态分析工具口吻写一条告警（4~8 行：规则名含 {cwe}、污染源入口、"
                      f"2~3 跳传播、sink 行号必须与代码真实行号一致）。\n"
                      f"【第三步】对该告警做裁决（结果应为 true，须验证告警传播链每一跳真实存在）。\n\n"
                      f"【输出格式】\nLANG: {lang}\n```{lang}\n<代码>\n```\n"
                      f"【模拟工具告警】\n<告警文本，sink 行号必须真实>\n"
                      f"1. <裁决分析 3~5 步，引用真实行号与标识符>\n" + FMT_JSON_TRUE.replace("{cwe}", cwe)
                      + "\n严禁使用 label/cwe_id/severity/reason 等旧键名。")
            def val_g2(text, idx=idx, lang=lang):
                text = text.strip()
                if not re.match(r"LANG:\s*(\S+)", text):
                    return None, "缺 LANG"
                obj, err = parse_json_block(text)
                if obj is None:
                    return None, err
                if "【模拟工具告警】" not in text:
                    return None, "缺告警段"
                pre_alert = text.split("【模拟工具告警】")[0]
                blocks = list(re.finditer(r"```[\w+#]*\n(.*?)```", pre_alert, re.S))
                if not blocks:
                    return None, "无代码块"
                code = blocks[0].group(1).rstrip()
                n = code.count("\n") + 1
                if not (15 <= n <= 40):
                    return None, f"代码 {n} 行不合"
                alert = text.split("【模拟工具告警】")[1].split("```json")[0].strip()
                bad = [int(x) for x in re.findall(r"line\s*(\d+)", alert, re.I) if int(x) > n]
                if bad:
                    return None, f"告警行号越界 {bad[:3]} > {n}"
                e = check_contract(obj, True, code)
                if e:
                    return None, e
                after_code = text.split("```", 2)[2].split("```json")[0]
                segs = after_code.split("1. ", 1)
                body = ("1. " + segs[1]) if len(segs) > 1 else after_code.strip()
                body = clean_analysis_text(body)
                user = (gen_user(lang, code) + f"\n\n【静态工具告警】\n{alert}\n\n"
                        + (ctx["adjud_tail"] or "判定要求：核实告警传播链每一跳后给出七字段结论。"))
                assistant = body + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```"
                e = check_style(assistant)
                if e:
                    return None, e
                if norm_md5(assistant) in ctx["assist_md5"]:
                    return None, "重复"
                return ({"messages": [{"role": "system", "content": ctx["main_system"]},
                                      {"role": "user", "content": user},
                                      {"role": "assistant", "content": assistant}],
                         "meta": {"kind": "evidence_adjudication_pos",
                                  "task_key": f"gen_evidence_pos:{idx}", "gen": True}}, None)
            add("g2_evidence", f"g2:{idx}", prompt, val_g2)

    # ---------- g3a/g3b trust（28 对）----------
    if "g3a_trust" in packs:
        items = list(TRUST_FLAW_TEXT.items())
        for idx in range(28):
            cwe, flaw = items[idx % len(items)]
            lang = LANGS_MAIN[idx % 5]
            scen = SCENARIOS[(idx * 5) % len(SCENARIOS)]
            add("g3a_trust", f"g3a:{idx}",
                gen_prompt_vuln(lang, cwe, scen,
                                extra=f"核心缺陷：{flaw}。不得用其他 CWE 的高频套路（如 SQL 注入）替代"),
                make_gen_validator("variant_trust_vuln", True,
                                   f"gen_trust_vuln:{idx}", ctx))
    if "g3b_trust" in packs:
        for idx, rec in enumerate(load_pairs("g3a_trust")):
            lang, code = lang_code_of(rec)
            tk = str((rec.get("meta") or {}).get("task_key", idx))
            prompt = (f"下面代码存在信任边界类漏洞（{tk}）。\n\n"
                      f"```{lang}\n{code}\n```\n\n"
                      f"【任务】给出最小修复：只改必要行（加集中鉴权/白名单/来源校验等），"
                      f"保持功能不变。输出修复后完整代码 + 安全分析（说明修复点如何封住原漏洞，"
                      f"并交代替代通道检查）+ 七字段结论。\n\n"
                      + fmt_head(lang) + FMT_JSON_FALSE)
            add("g3b_trust", f"g3b:{idx}", prompt,
                make_gen_validator("variant_trust_safe", False,
                                   f"gen_trust_safe:{idx}", ctx))

    # ---------- g4a/g4b blacklist（28 对）----------
    WEAK = ["黑名单关键字过滤（可大小写/编码/注释绕过）", "不完整正则（可嵌套/换行/同义函数绕过）",
            "字符串替换清洗（可重组绕过）", "仅过滤部分危险函数（存在同义 sink）",
            "前置 if 判断特定模式（逻辑可跳过）", "基于长度/格式的浅校验（语义层不可控）",
            "过滤特定字符（双写/URL 编码可绕过）"]
    if "g4a_blacklist" in packs:
        for idx in range(28):
            lang = LANGS_MAIN[idx % 5]
            cwe = CWES[lang][(idx // 5) % 8]
            scen = SCENARIOS[(idx * 7) % len(SCENARIOS)]
            add("g4a_blacklist", f"g4a:{idx}",
                gen_prompt_vuln(lang, cwe, scen,
                                extra=f"代码里必须存在一段【弱防御】：{WEAK[idx % len(WEAK)]}；"
                                      f"分析必须说明它如何被绕过"),
                make_gen_validator("blacklist_bypass_vuln", True,
                                   f"gen_blacklist_vuln:{idx}", ctx))
    if "g4b_blacklist" in packs:
        for idx, rec in enumerate(load_pairs("g4a_blacklist")):
            lang, code = lang_code_of(rec)
            prompt = (f"下面代码的防御是弱防御（黑名单/可绕过正则/字符串替换），存在绕过。\n\n"
                      f"```{lang}\n{code}\n```\n\n"
                      f"【任务】把弱防御替换为真实有效的强防御（参数化/白名单/原生安全 API/"
                      f"框架防护），功能不变。输出修复后代码 + 安全分析 + 七字段结论。\n\n"
                      + fmt_head(lang) + FMT_JSON_FALSE)
            add("g4b_blacklist", f"g4b:{idx}", prompt,
                make_gen_validator("blacklist_bypass_safe", False,
                                   f"gen_blacklist_safe:{idx}", ctx))

    # ---------- g5_extreme（200）----------
    if "g5_extreme" in packs:
        TRICKS = ["含伪装防御（黑名单/不完整正则，看似安全实可绕过→判 true）",
                  "主数据流安全但存在第二入口可达同一 sink（→判 true）",
                  "多数据流中仅一条可达 sink，其余有真防御（→判 true）",
                  "所有数据流都有真实有效防御，表面危险实安全（→判 false）"]
        for idx in range(200):
            lang = LANGS_MAIN[idx % 5]
            cwe = CWES[lang][(idx // 5) % 8]
            scen = SCENARIOS[(idx * 11) % len(SCENARIOS)]
            trick = idx % 4
            expect = trick != 3
            ext = "py" if lang == "python" else ("ts" if lang in ("javascript", "typescript")
                                                 else "java" if lang == "java" else
                                                 "go" if lang == "go" else "php")
            prompt = (f"生成一条【极难】漏洞检测训练样本（多文件 + 陷阱）。\n\n"
                      f"【要求】\n"
                      f"1. 语言 {lang}；文件 1 为主文件 main.{ext}，文件 2 为辅助模块 helper.{ext}；"
                      f"单文件 20~45 行。\n"
                      f"2. 场景：{scen}；涉及 {cwe} 相关模式；至少 3 条候选数据流（多入口）。\n"
                      f"3. 陷阱：{TRICKS[trick]}。\n"
                      f"4. 严禁真实凭据明文。\n\n"
                      f"【输出格式】\nLANG: {lang}\n"
                      f"### 文件: main.{ext}\n```{lang}\n<代码1>\n```\n"
                      f"### 文件: helper.{ext}\n```{lang}\n<代码2>\n```\n"
                      f"1. <编号步骤 3~6 步，跨文件数据流须写明文件名与行号，"
                      f"覆盖全部入口与每条流的防御判定>\n"
                      f"```json\n<主契约七字段，has_vulnerability={expect}，"
                      f"{'vulnerability_type=' + chr(39) + cwe + ' ' + '官方名' + chr(39) if expect else '安全侧全 N/A'}>\n```\n"
                      f"JSON 字符串值内严禁英文双引号。\n{SCHEMA_LOCK}")
            add("g5_extreme", f"g5:{idx}", prompt,
                make_gen_validator("extreme_multifile", expect,
                                   f"gen_extreme:{idx}", ctx, multi_file=True,
                                   min_lines=18, max_lines=50))

    # ---------- g6a/g6b lang（3×(75+75)）----------
    if "g6a_lang" in packs:
        for li, lang in enumerate(LANGS_NEW):
            for k in range(75):
                idx = li * 75 + k
                add("g6a_lang", f"g6a:{idx}",
                    gen_prompt_vuln(lang, CWES[lang][k % 8],
                                    SCENARIOS[(k * 3 + li) % len(SCENARIOS)]),
                    make_gen_validator(f"lang_{lang}_vuln", True,
                                       f"gen_{lang}_vuln:{idx}", ctx))
    if "g6b_lang" in packs:
        for li, lang in enumerate(LANGS_NEW):
            for k in range(75):
                idx = li * 75 + k
                add("g6b_lang", f"g6b:{idx}",
                    gen_prompt_safe(lang, CWES[lang][k % 8],
                                    SCENARIOS[(k * 3 + li) % len(SCENARIOS)],
                                    DEFENSES[(k + li * 2) % len(DEFENSES)]),
                    make_gen_validator(f"lang_{lang}_safe", False,
                                       f"gen_{lang}_safe:{idx}", ctx))

    # ---------- g7_special（90）----------
    if "g7_special" in packs:
        for tidx, (tkey, (cwe, name, desc)) in enumerate(SPECIAL.items()):
            for k in range(30):
                i2 = tidx * 30 + k
                lang = LANGS_MAIN[i2 % 5]
                expect = k % 2 == 0
                if expect:
                    prompt = gen_prompt_vuln(lang, cwe, f"{name}场景-{k}",
                                             extra=f"核心缺陷：{desc}。"
                                                   f"代码要体现该主题的解析/键/源差异细节")
                else:
                    prompt = gen_prompt_safe(
                        lang, cwe, f"{name}场景-{k}",
                        f"正确对齐了主题相关的安全配置（{name} 的标准防护："
                        f"显式固定解析顺序/缓存键包含全部影响头/私有源锁定+哈希校验）")
                add("g7_special", f"g7:{i2}", prompt,
                    make_gen_validator(f"special_{tkey}", expect,
                                       f"gen_{tkey}:{i2}", ctx))

    # ---------- r4_fixes：审计队列定点重蒸馏（vt 改标/捏造 API 重写） ----------
    if "r4_fixes" in packs:
        R4 = [(1883, "CWE-117", "explanation 必须含「注入换行/控制符伪造日志条目」锚句，"
                           "不得使用「敏感信息泄露」叙事（用户名是任意可控内容而非敏感字面值）"),
              (1008, None, "fix_suggestion 严禁捏造 API：只允许代码中已 import/定义或语言标准库"
                           "真实存在的函数；若推荐第三方库必须写明其来源（如 DOMPurify）"),
              (2038, None, "fix_suggestion 中引用的 sanitizer 必须先在构造函数注入 "
                           "（private sanitizer: DomSanitizer），或改用 textContent 等无注入面的写法"),
              (2848, None, "fix_suggestion 中引用的 sanitizer 必须先在构造函数注入，或改用 textContent"),
              (2849, None, "fix_suggestion 中引用的 sanitizer 必须先在构造函数注入，或改用 textContent")]
        for ol, cwe_hint, extra in R4:
            r13 = ctx["rows13"].get(ol)
            if not r13:
                continue
            user13 = r13["messages"][1]["content"]
            o13 = json.loads(re.findall(r"```json\s*(.*?)```",
                                        r13["messages"][2]["content"], re.S)[-1])
            exp_vt = cwe_hint or (re.match(r"CWE-\d+", str(o13.get("vulnerability_type", ""))) or re.match(r".*", "")).group(0)
            prompt = (f"你要为漏洞检测模型重新生成一条训练数据的【分析部分】。原始任务如下：\n\n"
                      f"{user13}\n\n【要求】\n"
                      f"1. 这段代码最终判定为【存在漏洞 has_vulnerability=true】，"
                      f"vulnerability_type 必须以 {exp_vt} 开头。\n"
                      f"2. 直接以\"1.\"编号步骤开始，3~6 步，每步锚定真实行号（第 N 行），"
                      f"引用代码里真实的函数名/变量名；禁止英文独白、禁止 markdown 标题、禁止输出代码。\n"
                      f"3. {extra}。\n"
                      f"4. 分析结束后另起一行输出 ```json 七字段结论。"
                      f"JSON 字符串值内严禁英文双引号。\n{SCHEMA_LOCK}")

            def make_val_r4(user13=user13, exp_vt=exp_vt, ol=ol):
                def _val(text):
                    text = text.strip()
                    obj, err = parse_json_block(text)
                    if obj is None:
                        return None, err
                    e = check_contract(obj, True, user13)
                    if e:
                        return None, e
                    if not str(obj.get("vulnerability_type", "")).startswith(exp_vt):
                        return None, f"vt 应为 {exp_vt}"
                    jm = text.rfind("```json")
                    body = clean_analysis_text(text[:jm].strip())
                    assistant = body + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```"
                    e = check_style(assistant)
                    if e:
                        return None, e
                    if norm_md5(assistant) in ctx["assist_md5"]:
                        return None, "与现有库重复"
                    return ({"messages": [{"role": "system", "content": ctx["main_system"]},
                                          {"role": "user", "content": user13},
                                          {"role": "assistant", "content": assistant}],
                             "meta": {"kind": "rd_audit_fix", "task_key": f"r4:{ol}"}}, None)
                return _val
            add("r4_fixes", f"r4:{ol}", prompt, make_val_r4())

    # ---------- g8_logfam：P0-2 日志类五兄弟辨析组（双采样一致性门） ----------
    if "g8_logfam" in packs:
        JUDGE_TABLE = (
            "【日志类 CWE 判定表——逐级排除，判定与辨析都必须遵循】\n"
            "用户输入到达日志写入点（logger/log/logging/print/写日志文件）：\n"
            "1. 输入出现在【格式串参数位】吗？logger.info(user_input) 输入即格式串 → CWE-134；"
            "logger.info(f\"...{x}\") 输入是数据位 → 不是 134\n"
            "2. 输入【内容本身】是敏感字面值（密码/token/密钥/卡号）吗？是 → 落日志文件=CWE-532；"
            "落非日志存储（文件/DB/缓存明文）=CWE-312\n"
            "3. 输入是【任意可控内容】（可含换行/控制符/伪造条目结构）→ CWE-117（日志注入/伪造），"
            "explanation 必须写「可注入换行伪造日志条目」，不得写成「读取敏感信息」\n"
            "近邻辨析：数据位(117) vs 格式串位(134)；伪造条目(117) vs 敏感字面值落日志(532)；"
            "日志(117) vs 非日志存储明文(312)")
        G8_LANGS = ["python", "javascript", "java", "go", "php"]
        G8_SCEN = ["登录审计日志", "支付回调日志", "请求追踪日志", "运维部署日志",
                   "安全告警日志", "用户操作日志"]
        g8_n = 0
        def _g8_add(expect_cwe, anchor_req, shape_desc, n, key_tag):
            nonlocal g8_n
            for k in range(n):
                lang = G8_LANGS[g8_n % 5]
                scen = G8_SCEN[g8_n % 6]
                g8_n += 1
                prompt = (f"生成一条【真实存在漏洞】的漏洞检测训练样本。\n\n"
                          f"【要求】\n"
                          f"1. 语言 {lang}，功能场景：{scen} 变体{k+1}。{shape_desc}\n"
                          f"2. 代码 15~40 行，自包含可读，外部输入入口清晰，数据流真实可达，无有效防御。\n"
                          f"3. analysis 里必须包含以下锚句：{anchor_req}\n"
                          f"4. 严禁真实凭据明文。\n{JUDGE_TABLE}\n"
                          f"5. 分析 3~6 步编号，锚定真实行号，最后 ```json 七字段结论，"
                          f"vulnerability_type 必须以 {expect_cwe} 开头。"
                          f"JSON 字符串值内严禁英文双引号。\n"
                          f"【输出格式】第一行必须是 LANG: {lang}，随后是 ```{lang} 代码块、"
                          f"编号分析、```json 结论。\n{SCHEMA_LOCK}")
                def make_val_g8(expect_cwe=expect_cwe, anchor_req=anchor_req, tk=f"g8:{key_tag}{k}"):
                    base_v = make_gen_validator(f"logfam_{expect_cwe}", True, tk, ctx,
                                                min_lines=15, max_lines=40)
                    def _val(text):
                        rec, err = base_v(text)
                        if rec is None:
                            return rec, err
                        asst = rec["messages"][2]["content"]
                        vt = re.search(r'"vulnerability_type":\s*"([^"]*)"', asst)
                        if not vt or not vt.group(1).startswith(expect_cwe):
                            return None, f"vt 应为 {expect_cwe}，实得 {vt.group(1)[:40] if vt else '?'}"
                        body = asst.split("```json")[0]
                        for phrase in anchor_req.split("|"):
                            if phrase.strip() and phrase.strip() not in body:
                                return None, f"缺锚句「{phrase.strip()}」"
                        return rec, None
                    return _val
                add("g8_logfam", f"g8:{key_tag}{k}", prompt,
                    make_val_g8(), dual=True)
        # A: 117 正例 ×12（f-string 数据位）
        _g8_add("CWE-117", "注入换行 | 伪造日志条目",
                "漏洞：logger/log 写日志时用 f-string/模板拼接【任意可控内容】（用户名/搜索词/UA 等非敏感字段），"
                "攻击者可注入换行与控制符伪造日志条目（这是 117：任意内容输出中和缺失）", 12, "a")
        # B: 117 反例辨析 ×6（数据位形态，显式排除 134）
        _g8_add("CWE-117", "不是 134：输入在数据位而非格式串位 | 伪造",
                "漏洞：logger.info(f\"...{user_input}\") 这类【数据位】形态标 117，"
                "analysis 必须显式写一句「不是 134：输入在数据位而非格式串位」的排除论证", 6, "b")
        # C: 532/312 反例辨析 ×8
        _g8_add("CWE-532", "敏感字面值落日志 | 不是 117：值本身是敏感字面值而非任意可控内容",
                "漏洞：把【密码/token/密钥/卡号】等敏感字面值写入日志（logger 记录凭据/卡号），"
                "analysis 必须显式辨析「不是 117：值本身是敏感字面值而非任意可控内容，属 532」", 4, "c1")
        _g8_add("CWE-312", "明文落非日志存储 | 不是 532：存储介质不是日志文件",
                "漏洞：敏感字面值（密码/token）明文写入【非日志存储】（配置文件/数据库/缓存），"
                "analysis 必须显式辨析「不是 532：存储介质不是日志文件，属 312」", 4, "c2")
        # D: 134 正例 ×6（格式串位真 134）
        _g8_add("CWE-134", "格式串位 | 不是 117：输入是格式模板而非数据",
                "漏洞：用户输入被直接用作【格式串/日志模板】（logger.info(user_input)、"
                "log.write(user_format)、syslog(pf, ...)），analysis 必须显式辨析"
                "「不是 117：输入占据格式串参数位而非数据位，属 134」", 6, "d")

    if pilot:
        cnt, kept = {}, []
        for t in T:
            c = cnt.get(t["pack"], 0)
            if c < 2:
                kept.append(t)
                cnt[t["pack"]] = c + 1
        T = kept
    return T


def main():
    ALL_PACKS = ["r1_expl", "r2_regen", "r3_readj", "r4_fixes",
                 "g1_looks_safe", "g2_evidence", "g3a_trust", "g3b_trust",
                 "g4a_blacklist", "g4b_blacklist", "g5_extreme", "g6a_lang",
                 "g6b_lang", "g7_special", "g8_logfam"]
    ap = argparse.ArgumentParser()
    ap.add_argument("--packs", default=",".join(ALL_PACKS))
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--pilot", action="store_true")
    args = ap.parse_args()
    packs = [p.strip() for p in args.packs.split(",") if p.strip()]

    CORPUS.mkdir(parents=True, exist_ok=True)
    PROGRESS.mkdir(parents=True, exist_ok=True)
    FAILED.mkdir(parents=True, exist_ok=True)

    print("加载上下文 ...", flush=True)
    ctx = load_context()
    tasks = build_tasks(ctx, set(packs), args.pilot)
    print(f"任务 {len(tasks)} 条 | packs={packs} | workers={args.workers}", flush=True)

    todo = []
    for t in tasks:
        pf = PROGRESS / f"{t['pack']}.jsonl"
        done = set()
        if pf.exists():
            done = {json.loads(l)["key"] for l in pf.open(encoding="utf-8") if l.strip()}
        if t["key"] not in done:
            todo.append(t)
    print(f"断点过滤后待跑 {len(todo)} 条", flush=True)

    lock = threading.Lock()
    stats = Counter()
    out_fs = {}

    def run_task(t):
        t0 = time.time()
        try:
            text = call_teacher(os.environ["TEACHER_KEY"], t["prompt"])
            if t.get("dual"):
                # P0-2 双采样一致性门：同一 prompt 让教师答两次，两次标签
                # （方向+vt 编号）不一致 → 教师自漂移，不入库、进人工辨析
                text2 = call_teacher(os.environ["TEACHER_KEY"], t["prompt"])
                def _lab(x):
                    hv = re.findall(r'"has_vulnerability":\s*(\w+)', x)
                    vt = re.findall(r'"vulnerability_type":\s*"([^"]*)"', x)
                    c = re.match(r"CWE-(\d+)", vt[-1]) if vt else None
                    return (hv[-1].lower() if hv else None, c.group(1) if c else None)
                if _lab(text) != _lab(text2):
                    with lock:
                        stats["reject"] += 1
                    with open(FAILED / f"{t['pack']}.jsonl", "a", encoding="utf-8") as f:
                        f.write(json.dumps({"key": t["key"], "err": "双采样标签不一致（教师自漂移）→ 人工辨析",
                                            "raw_head": text[:600], "raw2_head": text2[:600]},
                                           ensure_ascii=False) + "\n")
                    return f"✗ {t['key']} 双采样不一致"
        except Exception as e:
            with lock:
                stats["api_fail"] += 1
            return f"✗ {t['key']} API: {str(e)[:60]}"
        try:
            rec, err = t["validator"](text)
        except Exception as e:
            rec, err = None, f"validator 异常 {type(e).__name__}: {e}"
        with lock:
            if rec is None:
                stats["reject"] += 1
                with open(FAILED / f"{t['pack']}.jsonl", "a", encoding="utf-8") as f:
                    f.write(json.dumps({"key": t["key"], "err": str(err)[:200],
                                        "raw_head": text[:2000]}, ensure_ascii=False) + "\n")
            else:
                f = out_fs.setdefault(t["pack"], open(CORPUS / f"{t['pack']}.jsonl",
                                                      "a", encoding="utf-8"))
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                f.flush()
                with open(PROGRESS / f"{t['pack']}.jsonl", "a", encoding="utf-8") as pf:
                    pf.write(json.dumps({"key": t["key"]}) + "\n")
                stats["ok"] += 1
        return (f"✓ {t['key']} ({time.time()-t0:.0f}s)" if rec is not None
                else f"✗ {t['key']} 拒: {str(err)[:80]}")

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(run_task, t) for t in todo]
        for i, fut in enumerate(as_completed(futs)):
            print(f"  [{i+1}/{len(todo)}] {fut.result()}", flush=True)

    for f in out_fs.values():
        f.close()
    print(f"\n完成 {json.dumps(stats, ensure_ascii=False)} | 输出 {CORPUS}", flush=True)


if __name__ == "__main__":
    main()
