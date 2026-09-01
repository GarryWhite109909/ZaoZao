# -*- coding: utf-8 -*-
"""为 23 条样本生成可读审察稿：编号代码 + 教师分析 + JSON 结论。"""
import json
import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "samples")
OUT = os.path.join(HERE, "review")
os.makedirs(OUT, exist_ok=True)

NOTES = {
    524: "无请求级污点流，config/R6 族设计功能，教师过度判 Backdoor；信任边界需确认部署模型",
    1108: "签名缺失字段是真实设计缺陷但无法独立构造有效绕过，可用性依赖环境密钥",
    8199: "凭据字面量确在 L15-32 事实正确，但 R6 无污点流；行号漂移+冗长",
    1667: "CWE-798 凭据确在 L31，R6 无污点流；行号锚定混乱+遗漏空参数越界读",
    8196: "pendingAuth 表无容量上限属真实加固缺失，但可达端点/取值不在文件内，无污点",
    2833: "jsonify 不转义 <script> 已由 M3 实测确认；跨浏览器 MIME 嗅探行为不可从代码判定",
    7899: "newYaml() 非 SafeConstructor 方向与独立判断一致，可利用性依赖 snakeyaml 版本；行号大面积漂移",
    7218: "绑定形态确为 CVE-2022-22965 暴露模式，但补丁后 Spring 是标准写法，版本不可判定",
    8037: "InsecureSkipVerify opt-in + 条件性白名单是否计 295 属框架裁决；无攻击者可控数据流",
    7862: "上游 beego 库代码无文件内污点流，0777 真实但 R6 交人工；近重复矛盾对伴侣样本；行号全错",
    8025: "L198 $_REQUEST 回退确为真实污点源且作者自认 TODO，可利用性取决于样本外 twig autoescape；教师 true vs 独立复核 false",
    8176: ".prompty 信任边界不可判定；机制断言全部实测为真（绝对路径弃基路径/..逃逸/resolve 无约束）",
    8141: "sendRequest(L431) 向管理员配置 webhook URL 发请求，本片段为官方 SSRF 加固前版本（上游 diff 实证）；教师设计权衡论亦合理",
    1289: "root/权限类无污点配置缺陷 R6；教师全部行号脱靶且修复含功能性回归",
    1724: "updateEmail equals 校验正确；transfer CSRF 缺失独立分析亦 uncertain——文件内无 CSRF 启用证据",
    1449: "无攻击者输入可达 eval/wget（config 受信）；教师 fix 的 tr 过滤方向错误、bash -c 无效",
    7980: "是否越权取决于 flag_value 来源，文件内无调用方，威胁模型依赖；与 524 同类；行号系统性偏移",
    7531: "机制描述准确、fix 有效纵深防御；卡点=unserialize 数据来源",
    1717: "CSRF 技术上可辩护但超污点流框架；正文含参数化日志错误断言与系统性行号漂移",
    2559: "JSON 的 915 数据流断言被证伪（line 39 仅显式复制 email，admin/role 取自会话）；候选 IDOR 依赖片段外鉴权上下文",
    7301: "CWE-78 链依赖虚构 install.js 行为；真实关切是 prev[p]='*' 通配版本+postinstall 供应链（CWE-1357/494）但无污点流；邻近重复样本结论相反",
    8184: "SanitizePath 仅 Clean+Abs 无 base 约束属库层纵深缺口（R6），文件内无可达污点流且 sink 数据流虚构；docstring 过度承诺属实",
    6347: "app.secret_key='super_secret_key' 硬编码（798/321）未被教师分析且无污点流——可伪造会话架空 CSRF 防护",
}

for fn in sorted(os.listdir(SAMPLES)):
    if not fn.endswith(".json"):
        continue
    rid = int(fn[2:-5])
    rec = json.load(open(os.path.join(SAMPLES, fn), encoding="utf-8"))
    msgs = rec.get("messages", [])
    user = next((m["content"] for m in msgs if m.get("role") == "user"), "")
    asst = next((m["content"] for m in msgs if m.get("role") == "assistant"), "")
    ml = re.search(r"```(\w+)\n(.*?)```", user, re.S)
    lang = ml.group(1) if ml else "?"
    code = ml.group(2) if ml else user
    nlines = code.count("\n") + 1
    numbered = "\n".join(f"{i+1:4d}| {l}" for i, l in enumerate(code.split("\n")))
    try:
        jm = re.search(r"```json\s*(\{.*?\})\s*```", asst, re.S)
        j = json.loads(jm.group(1)) if jm else {}
        jf = json.dumps(j, ensure_ascii=False, indent=2)
    except Exception as e:
        jf = f"(JSON 解析失败: {e})\n{asst[-800:]}"
    analysis = asst.split("```json")[0]
    out = f"""# id={rid} 审察稿（{lang}，{nlines} 行）

> 审计疑点：{NOTES.get(rid, '')}

## 教师分析

{analysis.strip()}

## JSON 结论

```json
{jf}
```

## 代码（带行号）

```{lang}
{numbered}
```
"""
    with open(os.path.join(OUT, f"id{rid}.md"), "w", encoding="utf-8") as f:
        f.write(out)
    print(f"id={rid} -> review/id{rid}.md ({nlines} 行代码)")
