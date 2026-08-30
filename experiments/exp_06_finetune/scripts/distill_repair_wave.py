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
    if "r2_regen" in packs:
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

    # ================================================================
    # v2_15a P0-B 余量辨析组（2026-08-30）：原型污染族 / 模板族 / 主次关系 /
    #   from_string 语义修正。依据 audit/优化建议_alpha06_日志类CWE归因辨析_v2_15.md
    #   P0-B 规格表 + §四判定锚表（P1-D.1 原文嵌入）。教师：GLM-5.3-flash 代班
    #   （DeepSeek 涨价，用户 2026-08-30 指定）。
    #   质量门：dual 双采样一致性门 + F8 入库门禁（sink 特征必须在代码中）+ 锚句必含。
    # ================================================================
    if packs & {"g9_1321", "g10_915", "g11_1336", "g12_1336_79", "g13_1336_134",
                "g14_priority", "g15_fromstring", "g17_priority_authz",
                "g18_authz_family", "g19_134_boundary"}:
        # ---- F8 数据侧入库门禁：vulnerability_type 主类型的 sink 特征必须出现在代码中
        SINK_GATE = {
            "1321": re.compile(r"__proto__|constructor|prototype"),
            "915": re.compile(r"Object\.assign|\.\.\.\s*\w|defineProperty"),
            "1336": re.compile(r"from_string\(|Template\(|render_template_string|ejs\.render|ejs\.compile|_\.template|nunjucks\.renderString|Handlebars\.compile|createTemplate|new Template\(|VelocityEngine|\.evaluate\(|text/template|html/template|\.compile\("),
            "208": re.compile(r"==|!=|\.equals\("),
            "209": re.compile(r"str\(e|printStackTrace|getMessage\(|\.message|traceback|Exception|\.Error\(\)|String\(e|\$\{e\}|http\.Error"),
            "79": re.compile(r"\|safe|Markup\(|mark_safe|<%-|innerHTML|render_template|document\.write"),
            "89": re.compile(r"execute\(|\.query\(|raw\(|raw_query"),
            "798": re.compile(r"(?i)((password|secret|token|api_?key|access_?key)\s*=\s*['\"][^'\"]{6,}['\"]|://[^'\"@\s]+:[^'\"@\s]{4,}@)"),
            "78": re.compile(r"subprocess|os\.system|shell=True|exec\(|child_process|system\("),
            "94": re.compile(r"eval\(|exec\(|Function\("),
            "22": re.compile(r"open\(|extractall\(|\.extract\(|os\.path\.join|readFile|createReadStream|Files\.|send_file|shutil"),
        }
        # ---- 教师判定锚表（v2_15 文档 §四，P1-D.1：原文嵌入教师 prompt）
        TABLE_PROTO = (
            "【原型污染族判定表——判定与辨析都必须遵循】\n"
            "JS 递归合并/深赋值（for-in 键遍历递归赋值、merge 族 API 收外部对象）+ 攻击者控制键名"
            "（__proto__/constructor/prototype）→ CWE-1321：explanation 必须写「攻击者控制键名污染原型链」，"
            "并显式写「不是 912」（912 是隐藏功能语义，与原型污染无关）\n"
            "JS 对象【自身属性】动态修改（mass assignment/配置覆盖；写入走 Object.assign/展开等 "
            "define 自有属性语义，或键名不含原型键）→ CWE-915：explanation 必须写「对象属性修改而非原型键注入」，"
            "显式写「不是 1321」\n"
            "修复白名单（fix_suggestion 只允许）：①键名过滤 if (key === '__proto__' || "
            "key === 'constructor' || key === 'prototype') continue；②null-prototype 目标 "
            "Object.create(null)；禁止值比较（!== Object.prototype / instanceof）——值比较挡不住键名注入")
        TABLE_TPL = (
            "【模板族判定表——判定与辨析都必须遵循】\n"
            "1. 用户输入拼入模板【源码】（env.from_string(f\"...{u}\") / Template(u_str) / "
            "render_template_string(u) / ejs.render(u_str) / _.template(u) / nunjucks.renderString(u) / "
            "Twig createTemplate(u) / FreeMarker new Template(new StringReader(u)) / go text/template "
            "Parse(u)）→ CWE-1336：from_string 等编译入口将字符串编译为模板并渲染，"
            "{{}}/{%%} 模板语法会被执行——「按字面量执行」是错误认知；explanation 必须写"
            "「输入被当作模板语法执行」\n"
            "2. 用户输入仅作模板【变量值】（render(name=u)/render_template(\"t.html\", name=u)）→ "
            "变量值不进入模板源码，模板语法不执行：autoescape 开启且输出已转义 → 安全；"
            "输出未转义（|safe/mark_safe/<%-/Markup）→ CWE-79，explanation 必须写"
            "「不是 1336：变量值不进入模板源码，模板语法不执行」\n"
            "3. 1336 vs 134：模板串的执行语义由模板引擎定义（{{}} 语法）→ 1336；printf 格式串的 "
            "%n/%s 由 C 库解析 → 134。仅表层形似，不是同族\n"
            "4. autoescape 只影响变量值输出的转义，不影响模板语法是否被执行")
        TABLE_PRIORITY = (
            "【多漏洞共现主次规则——判定必须遵循】\n"
            "多漏洞同时成立时按【危害可达性】取主类型：可 RCE/可绕过认证 > 可读取任意数据 > "
            "信息泄露 > 输出未转义。主类型写在 vulnerability_type 开头，伴生漏洞必须以"
            "「; CWE-编号 官方名」并列写入同一 vulnerability_type 字段，不得省略\n"
            "模板注入+XSS：存在模板源码注入时主类型 CWE-1336（模板语法执行可 RCE），"
            "XSS（输出未转义）为伴生漏洞同时成立；autoescape 只影响变量值输出的转义，"
            "不影响模板语法是否被执行\n"
            "时序+硬编码：== 对字符串是非常数时间比较（逐字节比较，可测量爆破）→ 主类型 CWE-208；"
            "同段代码里的硬编码凭证 CWE-798 同时成立但不遮挡主类型\n"
            "异常回显+SQLi：str(e) 直接返回客户端泄露 SQL/路径/库版本 → 主类型 CWE-209；"
            "同函数里的拼接查询 CWE-89 同时成立\n"
            "授权缺失+硬编码凭证：鉴权/授权缺失（可绕过认证直达敏感操作）为主类型"
            "（862/639/384/352/347），测试用硬编码字面值凭证 CWE-798 为伴生发现，不遮挡主类型")

        def _gate_val(base_v, expect_cwe, anchor_req, gate_key, also_cwe=None):
            def _val(text):
                rec, err = base_v(text)
                if rec is None:
                    return rec, err
                user = rec["messages"][1]["content"]
                code = "\n".join(re.findall(r"```[\w+#-]*\n(.*?)```", user, re.S))
                if gate_key and not SINK_GATE[gate_key].search(code):
                    return None, f"F8 门禁：代码缺少 CWE-{gate_key} 的 sink 特征"
                asst = rec["messages"][2]["content"]
                vt = re.search(r'"vulnerability_type":\s*"([^"]*)"', asst)
                if expect_cwe and (not vt or not vt.group(1).startswith(expect_cwe)):
                    return None, f"vt 应为 {expect_cwe}，实得 {vt.group(1)[:40] if vt else '?'}"
                if (expect_cwe and vt and vt.group(1).strip() == expect_cwe):
                    return None, "vt 只写裸编号，编号后须跟空格与漏洞名"
                if also_cwe and vt and also_cwe not in vt.group(1):
                    return None, f"vulnerability_type 缺伴生 {also_cwe}（主次规则要求并列写入）"
                body = asst.split("```json")[0]
                for phrase in anchor_req.split("|"):
                    phrase = phrase.strip()
                    if phrase and phrase not in body:
                        return None, f"缺锚句「{phrase}」"
                return rec, None
            return _val

        def _add_gen(pack, tag, lang, scen, shape, expect_cwe, anchor_req, gate_key,
                     n, expect_vuln=True, also_cwe=None, table=""):
            for k in range(n):
                verdict = (f"vulnerability_type 必须以 {expect_cwe} 开头（编号后必须跟空格与漏洞名，"
                           f"禁止只写裸编号）"
                           + (f"，并以「; {also_cwe} 官方名」并列伴生类型" if also_cwe else "")
                           + "。" if expect_vuln else
                           "has_vulnerability=false，vulnerability_type='none'，risk_level='None'，"
                           "source/sink='N/A'，fix_suggestion='no fix needed'。")
                prompt = (f"生成一条【{'真实存在漏洞' if expect_vuln else '看似危险实安全'}】的"
                          f"漏洞检测训练样本。\n\n【要求】\n"
                          f"1. 语言 {lang}，功能场景：{scen} 变体{k+1}。{shape}\n"
                          f"2. 代码 15~40 行，自包含可读（含少量注释），外部输入入口清晰，"
                          f"{'数据流真实可达，无有效防御' if expect_vuln else '防御真实生效且在代码中可见'}。\n"
                          f"3. analysis 必须逐字包含以下锚句（以 | 分隔的每句都要出现）：{anchor_req}\n"
                          f"4. 严禁真实凭据明文、严禁捏造不存在的标准库 API。\n{table}\n"
                          f"5. 分析 3~6 步编号，锚定真实行号与真实标识符，最后 ```json 七字段结论。{verdict}"
                          f"JSON 字符串值内严禁英文双引号。\n"
                          f"【输出格式】第一行必须是 LANG: {lang}，随后是 ```{lang} 代码块、"
                          f"编号分析、```json 结论。\n{SCHEMA_LOCK}")

                def make_v(expect_cwe=expect_cwe, anchor_req=anchor_req, gate_key=gate_key,
                           also_cwe=also_cwe, expect_vuln=expect_vuln,
                           tk=(f"{pack}:{tag}" if n == 1 else f"{pack}:{tag}{k}")):
                    kind = {"g9_1321": "proto_1321", "g10_915": "proto_915",
                            "g11_1336": "tpl_1336", "g12_1336_79": "tpl_1336_79",
                            "g13_1336_134": "tpl_1336_134", "g14_priority": "priority_multi",
                            "g15_fromstring": "tpl_fromstring",
                            "g17_priority_authz": "priority_multi",
                            "g18_authz_family": "authz_family",
                            "g19_134_boundary": "tpl_134_boundary"}.get(pack, "v2_15a_gen")
                    if not expect_vuln:
                        kind += "_safe"
                    base_v = make_gen_validator(kind, expect_vuln, tk, ctx,
                                                min_lines=15, max_lines=40)
                    return _gate_val(base_v, expect_cwe, anchor_req, gate_key, also_cwe)
                key = f"{pack}:{tag}" if n == 1 else f"{pack}:{tag}{k}"
                add(pack, key, prompt, make_v(), dual=True)

        # ---- g9_1321：原型污染正例 ×15（JS 必须含 __proto__/constructor/prototype 键）
        if "g9_1321" in packs:
            G9_SCEN = ["配置合并服务", "用户偏好设置", "功能开关管理", "购物车更新", "权限矩阵合并",
                       "i18n 文案合并", "webhook 配置合并", "缓存选项合并", "模板数据装配",
                       "插件选项注册", "默认值深合并工具", "表单字段合并", "环境配置覆盖",
                       "请求体转对象存储", "租户配置叠加"]
            for k in range(15):
                scen = G9_SCEN[k]
                shape = ("JS（Node/express/koa 皆可）：外部对象（req.body/JSON.parse 载荷）进入递归 merge/"
                         "深赋值（for-in 键遍历递归 target[key] = source[key]），代码或注释中必须出现 "
                         "__proto__（或 constructor.prototype）键的攻击载荷示例（如 // 载荷：{\"__proto__\": "
                         "{\"isAdmin\": true}}），analysis 按载荷演示污染链到 isAdmin/权限标志。"
                         "analysis 必须显式写「不是 912：912 是隐藏功能语义，与原型污染无关」")
                _add_gen("g9_1321", f"a{k}", "javascript", scen, shape, "CWE-1321",
                         "攻击者控制键名污染原型链|不是 912", "1321", 1, table=TABLE_PROTO)

        # ---- g10_915：JS 对象自身属性动态修改 ×4（非原型键）
        if "g10_915" in packs:
            G10_SCEN = ["个人资料批量更新", "订单收货信息更新", "商品库存字段覆盖", "报表列配置保存"]
            for k in range(4):
                shape = ("JS：外部字段对象经 Object.assign(record, req.body) 或展开 {...record, ...req.body} "
                         "覆盖数据对象的【自身属性】（攻击者覆盖 plan/price/note 等业务字段，实现越权改值或"
                         "计费字段篡改）；写入语义为 define 自有属性、键名不含原型键。analysis 必须显式写"
                         "「不是 1321：Object.assign/展开采用定义自有属性语义，__proto__ 键只会成为自身属性，"
                         "不会污染原型链，此处危害是对象属性修改而非原型键注入」")
                _add_gen("g10_915", f"a{k}", "javascript", G10_SCEN[k], shape, "CWE-915",
                         "对象属性修改而非原型键注入|不是 1321", "915", 1, table=TABLE_PROTO)

        # ---- g11_1336：模板源码注入正例 ×10
        if "g11_1336" in packs:
            G11 = [("python", "报表导出服务",
                    "Flask/Jinja2：env.from_string(f\"...{用户输入}...\")，用户输入直接拼入模板源码",
                    "输入被当作模板语法执行|{{7*7}}|from_string"),
                   ("python", "邮件模板服务",
                    "string.Template(user_str) 或 jinja2 render_template_string(用户输入)，模板文本本身来自用户",
                    "输入被当作模板语法执行|${|from_string"),
                   ("javascript", "页面渲染服务",
                    "ejs.render(userStr) 或 _.template(userStr)，模板字符串本身来自用户输入",
                    "输入被当作模板语法执行|<%"),
                   ("javascript", "营销落地页生成器",
                    "nunjucks.renderString(userStr) 或 Handlebars.compile(userStr)（js:{{7*7}} 可换为引擎语法演示）",
                    "输入被当作模板语法执行|renderString"),
                   ("java", "通知中心",
                    "FreeMarker：new Template(\"t\", new StringReader(userTpl), cfg) 后 process 输出，模板源码来自用户",
                    "输入被当作模板语法执行|FreeMarker"),
                   ("php", "文档渲染服务",
                    "Twig：$env->createTemplate($userTpl)->render([])，模板源码来自用户",
                    "输入被当作模板语法执行|createTemplate"),
                   ("go", "报表生成器",
                    "text/template：template.New(\"t\").Parse(userTpl) 后 Execute，模板源码来自用户",
                    "输入被当作模板语法执行|Parse")]
            for k in range(10):
                lang, scen, shape, anchor = G11[k % len(G11)]
                shape_k = shape + ("；analysis 的演示载荷必须展示该引擎语法被执行（如 {{7*7}}=49 / "
                                   "<%= 7*7 %>=49 / ${7*7}=49 等）" if k < 4 else
                                   "；analysis 说明该引擎把字符串当模板编译执行（RCE 链到 __class__.__globals__ 或等价沙箱逃逸路径）")
                _add_gen("g11_1336", f"a{k}", lang, scen, shape_k,
                         "CWE-1336", anchor, "1336", 1, table=TABLE_TPL)

        # ---- g12_1336_79：辨析对 ×6（3×79 值位未转义 + 3×1336 源码位显式排除 79）
        if "g12_1336_79" in packs:
            G12_79 = [("python", "站内信渲染", "Flask/Jinja2：render_template(\"msg.html\", body=user) 且模板里 body 经 |safe 过滤（或 Markup(user)），用户输入仅是变量值且输出未转义 → 79"),
                      ("javascript", "评论渲染", "ejs：res.render 内 <%- userComment %>（非 <%%=），用户输入仅是变量值、输出未转义 → 79"),
                      ("python", "个人主页", "Django：mark_safe(user_bio) 渲染，用户输入仅是变量值、转义被关闭 → 79")]
            for k in range(3):
                lang, scen, shape = G12_79[k]
                _add_gen("g12_1336_79", f"n79-{k}", lang, scen, shape + "；analysis 必须显式写"
                         "「不是 1336：变量值不进入模板源码，模板语法不执行」",
                         "CWE-79", "不是 1336：变量值不进入模板源码，模板语法不执行", "79", 1,
                         table=TABLE_TPL)
            G12_1336 = [("python", "动态问卷渲染", "env.from_string(f\"<p>{question}</p>\") 且 question 来自用户 → 源码位注入"),
                        ("python", "自定义仪表盘", "env.from_string(\"标题：\" + user_title) 字符串拼接进模板源码 → 1336"),
                        ("javascript", "告警模板编辑器", "ejs.render(userTemplate) 用户编辑的模板字符串整体被编译执行 → 1336")]
            for k in range(3):
                lang, scen, shape = G12_1336[k]
                _add_gen("g12_1336_79", f"n1336-{k}", lang, scen, shape + "；analysis 必须显式写"
                         "「不是 79：输入进入模板源码而非仅输出未转义」（输入在模板编译入口，{{}} 语法会被执行）",
                         "CWE-1336", "不是 79：输入进入模板源码而非仅输出未转义", "1336", 1,
                         table=TABLE_TPL)

        # ---- g13_1336_134：1336↔134 辨析对 ×4（属性名位拼接，hard_bypass_07 形态）
        if "g13_1336_134" in packs:
            G13 = [("python", "对象属性查询接口", "env.from_string(\"{{ obj.\" + user_field + \" }}\" 属性名位拼接进模板源码，可注入完整表达式链 __class__.__init__.__globals__"),
                   ("python", "动态字段导出", "env.from_string(f\"{{{{ record.{user_field} }}}}\") 拼接字段名进模板源码"),
                   ("javascript", "动态表格渲染", "ejs 模板源码 \"<%= obj.\" + userField + \" %>\" 拼接后整体编译执行"),
                   ("java", "动态报表列", "FreeMarker 模板源码 \"${obj.\" + userField + \"}\" 拼接后编译")]
            for k in range(4):
                lang, scen, shape = G13[k]
                _add_gen("g13_1336_134", f"a{k}", lang, scen, shape + "；analysis 必须显式写"
                         "「不是 134：134 是 printf 格式串语义（%n/%s 由 C 库解析），"
                         "模板串的执行语义由模板引擎定义；两者仅表层形似，不是同族」",
                         "CWE-1336", "不是 134|printf 格式串语义|模板引擎定义", "1336", 1,
                         table=TABLE_TPL)

        # ---- g14_priority：主次关系样本 ×12（F7，三形态各 4）
        if "g14_priority" in packs:
            P14_LANGS = ["python", "javascript", "java", "go"]
            # 14a SSTI(主 1336)+XSS(伴生 79)
            for k in range(4):
                lang = P14_LANGS[k]
                shape = {"python": "Flask/Jinja2：env = Environment(autoescape=False)；env.from_string(f\"<div>{user_bio}</div>\").render()",
                         "javascript": "express + ejs：app.render 用户模板场景下用 <%- %> 渲染用户可控模板串（模板串经 compile 执行且输出未转义）",
                         "java": "FreeMarker cfg 默认配置 + new Template(new StringReader(f\"<div>\" + user + \"</div>\"))，输出未转义",
                         "go": "text/template：tplSrc 为用户可控模板源码，template.New(\"t\").Parse(tplSrc) 后 Execute——用户控制模板源码本身，{{}} 语法被执行"}[lang]
                _add_gen("g14_priority", f"ssti_xss-{k}", lang, "用户生成内容页", shape +
                         "；判定主 1336 伴生 79（两个漏洞同时成立，vulnerability_type 并列写入）",
                         "CWE-1336", "主类型 1336|XSS（输出未转义）为伴生漏洞同时成立|autoescape 只影响变量值输出的转义",
                         "1336", 1, also_cwe="CWE-79", table=TABLE_PRIORITY)
            # 14b 时序攻击(主 208)+硬编码凭证(伴生 798)
            for k in range(4):
                lang = P14_LANGS[k]
                shape = {"python": "SECRET_API_TOKEN = \"长随机串\"（常量硬编码）；if request.headers.get('X-API-Token') == SECRET_API_TOKEN: 放行",
                         "javascript": "const SECRET_API_TOKEN = \"长随机串\"（常量硬编码）；if (req.headers['x-api-token'] === SECRET_API_TOKEN) 放行",
                         "java": "private static final String SECRET_API_TOKEN = \"长随机串\"（常量硬编码）；token.equals(SECRET_API_TOKEN) 放行",
                         "go": "const SECRET_API_TOKEN = \"长随机串\"（常量硬编码）；if r.Header.Get(\"X-API-Token\") == SECRET_API_TOKEN 放行"}[lang]
                _add_gen("g14_priority", f"timing_hc-{k}", lang, "API 鉴权中间件", shape +
                         "；判定主 208 伴生 798（== 非常数时间可测量爆破为主类型；硬编码凭证同时成立，"
                         "vulnerability_type 并列写入）",
                         "CWE-208", "非常数时间|主类型 208|798 同时成立", "208", 1,
                         also_cwe="CWE-798", table=TABLE_PRIORITY)
            # 14c 异常回显(主 209)+SQLi(伴生 89)
            for k in range(4):
                lang = P14_LANGS[k]
                shape = {"python": "cursor.execute(f\"SELECT * FROM orders WHERE id = '{oid}'\") 异常时 except Exception as e: return str(e) 直接返回响应",
                         "javascript": "db.query(`SELECT * FROM orders WHERE id = '${oid}'`) catch (e) { res.send(String(e)) }",
                         "java": "stmt.execute(\"SELECT * FROM orders WHERE id='\" + oid + \"'\") catch (Exception e) { response.getWriter().println(e.getMessage()) }",
                         "go": "db.Query(\"SELECT * FROM orders WHERE id='\" + oid + \"'\") 出错时 http.Error(w, err.Error(), 500)"}[lang]
                _add_gen("g14_priority", f"disc_sqli-{k}", lang, "订单查询接口", shape +
                         "；判定主 209 伴生 89（异常回显泄露 SQL/路径/库版本为主；拼接查询同时成立，"
                         "vulnerability_type 并列写入）",
                         "CWE-209", "主类型 209|89 同时成立", "209", 1,
                         also_cwe="CWE-89", table=TABLE_PRIORITY)

        # ---- g15_fromstring：from_string 语义修正对照 ×6（专杀 F3「按字面量执行」）
        if "g15_fromstring" in packs:
            for k in range(3):
                scen = ["告警规则渲染", "审批流文案渲染", "动态标签渲染"][k]
                shape = ("Flask/Jinja2：env.from_string(用户提交的模板串) —— from_string 将字符串编译为模板并渲染，"
                         "analysis 必须逐字写「from_string 将字符串编译为模板并渲染，模板语法（{{}}/{%%}）会被执行」，"
                         "并用 {{7*7}} 载荷演示执行结果 49")
                _add_gen("g15_fromstring", f"exec-{k}", "python", scen, shape, "CWE-1336",
                         "from_string 将字符串编译为模板并渲染，模板语法（{{}}/{%%}）会被执行|{{7*7}}",
                         "1336", 1, table=TABLE_TPL)
            for k in range(3):
                scen = ["告警订阅页", "用户昵称展示", "公告详情页"][k]
                shape = ("Flask/Jinja2：return render_template(\"page.html\", name=用户输入) —— 用户输入仅作为"
                         "变量值传入渲染上下文，autoescape 默认开启且输出已转义，无模板注入无 XSS。"
                         "analysis 必须逐字写「name 仅作为变量值传入，不进入模板源码，模板语法不执行」，"
                         "并说明 autoescape 开启时变量值输出的转义已生效")
                _add_gen("g15_fromstring", f"safe-{k}", "python", scen, shape, None,
                         "name 仅作为变量值传入，不进入模板源码，模板语法不执行", None, 1,
                         expect_vuln=False, table=TABLE_TPL)

        # ---- g17_priority_authz：授权主类型 + 硬编码凭证伴生 ×4（§8.5 六连实锤）
        if packs & {"g17_priority_authz", "g18_authz_family", "g19_134_boundary"}:
            TABLE_AUTHZ = (
                "【授权族判定表——判定与辨析都必须遵循】\n"
                "前置问题：代码里有没有访问控制机制（session 校验/current_user/权限装饰器/token 验证）？\n"
                "1. 完全没有任何检查 + 敏感操作（改密/删数据/列全表）→ 862 Missing Authorization\n"
                "2. 有检查，但「访问谁的资源」由用户可控参数决定（url uid/account 直接查库）→ 639"
                "（IDOR：检查了「登录没有」，没检查「这资源是不是你的」）\n"
                "3. 会话生命周期：登录成功后不 regenerate session id → 384\n"
                "4. 跨站伪造：state-changing 操作只靠「请求来自同源」假设，无 per-request token → 352\n"
                "5. JWT：alg=none 接受 / 签名不校验 → 347（签名验证缺陷，不是凭证问题）\n"
                "6. 798 边界：password=\"admin123\" 字面值 ≠ 授权缺陷。798 只在「硬编码凭证本身构成"
                "攻击路径」（生产密钥写死、后门账号）时才是主类型；判文件主类型看【用户可控数据流到达的"
                "危险 sink】，字面值凭证是伴生发现\n"
                "7. 862 vs 639 vs 306：先问「有没有检查」（无→862/306），再问「检查了拦没拦住越权」"
                "（对象可控→639）。306 用于 API 级别缺失授权的表述，862 更通用，两者同现时以 639>862>306 为主次")
            if "g17_priority_authz" in packs:
                G17 = [
                    ("python", "用户管理后台", "删除用户接口无任何权限校验（无 session/current_user/装饰器检查），"
                     "且模块级 ADMIN_PASSWORD = \"admin123\" 硬编码字面值", "CWE-862"),
                    ("python", "订单导出服务", "导出全部订单的 handler 无任何权限校验，且 DATABASE_URL 含硬编码口令字面值", "CWE-862"),
                    ("javascript", "登录后跳转", "登录成功处理直接沿用请求携带的旧 session id（未 regenerate），"
                     "且代码内硬编码测试口令字面值", "CWE-384"),
                    ("javascript", "资料修改接口", "state-changing POST 仅假设「请求来自同源」，无 per-request token/CSRF 校验，"
                     "且硬编码 API 口令字面值", "CWE-352"),
                ]
                for k, (lang, scen, shape, main_cwe) in enumerate(G17):
                    _add_gen("g17_priority_authz", f"a{k}", lang, scen, shape +
                             "；判定主类型为授权/会话缺陷，硬编码字面值凭证为伴生发现（798 同时成立但不遮挡主类型，"
                             "vulnerability_type 并列写入）；analysis 必须显式写「字面值凭证是伴生发现」",
                             main_cwe, f"主类型 {main_cwe[4:]}|798 同时成立|字面值凭证是伴生发现",
                             "798", 1, also_cwe="CWE-798", table=TABLE_PRIORITY + "\n\n" + TABLE_AUTHZ)
            # ---- g18_authz_family：授权族纯源码归因 ×6（无工具锚点形态，§3.1 306/639 实锤）
            if "g18_authz_family" in packs:
                G18 = [
                    ("639a", "python", "订单详情接口", "已登录用户通过 /orders/<id> 直接按 url 参数查任意订单，"
                     "有 session 登录校验、无资源归属校验 → 639；analysis 必须显式写"
                     "「不是 862：存在认证检查，缺的是资源归属校验」", "CWE-639",
                     "不是 862：存在认证检查，缺的是资源归属校验"),
                    ("639b", "javascript", "发票下载接口", "req.user 已认证后用 req.params.invoiceId 直接查库返回，"
                     "无 owner 字段比对 → 639；analysis 必须显式写「检查了登录没有，没检查这资源是不是你的」",
                     "CWE-639", "检查了登录没有，没检查这资源是不是你的"),
                    ("862", "python", "评论删除接口", "DELETE /comment/<id> 无任何登录/权限检查即可删除任意评论 → 862；"
                     "analysis 必须显式写「不是 639：连认证都没有，谈不上对象级授权」", "CWE-862",
                     "不是 639：连认证都没有，谈不上对象级授权"),
                    ("306", "python", "内部 REST API", "内部管理 API 无任何 API key/session/token 校验即返回全表数据"
                     "（API 级别缺失认证）→ 306；analysis 必须显式写「不是 862：该接口属 API 级别缺失认证的表述，"
                     "两者同现时以 639>862>306 为主次」", "CWE-306",
                     "API 级别缺失认证"),
                    ("384", "python", "登录会话管理", "校验密码成功后直接向 session 写 user_id，"
                     "未调用 session.clear()/regenerate → 会话固定 384", "CWE-384",
                     "登录成功后未重新生成会话标识"),
                    ("352", "javascript", "转账操作", "POST /transfer 仅依赖 SameSite/同源假设执行转账，"
                     "无 CSRF token 与二次确认 → 352", "CWE-352",
                     "无 per-request token"),
                ]
                for k, (tag, lang, scen, shape, main_cwe, anchor) in enumerate(G18):
                    _add_gen("g18_authz_family", tag, lang, scen, shape,
                             main_cwe, anchor, None, 1, table=TABLE_AUTHZ)
            # ---- g19_134_boundary：134 误报抑制 ×2（hard_cve_03 实锤"离谱错"）
            if "g19_134_boundary" in packs:
                G19 = [
                    ("python", "归档解压服务", "tarfile.extractall 成员名含 % 字样（用户上传归档内路径如 "
                     "re%port.pdf）→ 路径穿越 22；analysis 必须显式写「不是 134：非 printf 族函数出现 % 字样"
                     "不构成 134，% 在这里是普通路径字符」", "CWE-22", "不是 134|路径"),
                    ("python", "商品搜索接口", "cursor.execute(f\"SELECT * FROM products WHERE name LIKE "
                     "'%{q}% '\")——% 是 LIKE 通配符且用户输入进值位 → 89；analysis 必须显式写"
                     "「不是 134：% 在 SQL LIKE 中是通配符语义，输入未占据 printf 格式串参数位」",
                     "CWE-89", "不是 134|通配符"),
                ]
                for k, (lang, scen, shape, main_cwe, anchor) in enumerate(G19):
                    _add_gen("g19_134_boundary", f"a{k}", lang, scen, shape, main_cwe,
                             anchor, main_cwe[4:], 1, table=TABLE_TPL)

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
