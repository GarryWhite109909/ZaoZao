# -*- coding: utf-8 -*-
"""v2_16 清洗步骤 1.3：L2 sink 形态机扫（方法论 §1.1 L2，四组全库派生）。

原理：标签声称的 CWE 与代码 sink 形态不符 → 候选。机扫只提名，逐条裁决人工/agent 复核。

四组（方法论 §1.3：1336 组 18 / 943 组 11 / 94 组 18 / 643 组 5 的重新派生）：
- CWE-1336 模板引擎：代码须出现模板引擎形态（jinja/mustache/twig/freemarker/...）
- CWE-943  数据查询逻辑：须出现 HQL/JPQL/Criteria/NoSQL 查询构造（SQL 不算 → 那是 89）
- CWE-94   代码生成：须出现动态代码执行（eval/exec/compile/Function 构造器/脚本引擎）
          或模板求值形态（94 常为 SSTI→RCE 链的伴生标签）
- CWE-643  XPath：须出现 XPath 构造

输出：audit/scan_v2_16_l2_sinkform_flags.jsonl（每行一条候选 + 证据）。
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
OUT = BASE / "audit/scan_v2_16_l2_sinkform_flags.jsonl"

FENCE = re.compile(r"```[a-zA-Z0-9+#]*\n(.*?)```", re.S)
JSON_BLK = re.compile(r"\{[^{}]*has_vulnerability[^{}]*\}", re.S)

MARKS = {
    "1336": ["jinja", "template", "mustache", "chevron", "twig", "freemarker",
             "smarty", "velocity", "handlebars", "hbs", "ejs", "pug", "nunjucks",
             "dot.template", "_.template", "pebble", "thymeleaf", "mako", "genshi",
             "liquid", "stringtemplate", "viewengine", "razor", "blade", "latte",
             "twing", "environment("],
    "943": ["hql", "jpql", "createquery", "createnativequery", "createnamedquery",
            "criteria", "entitymanager", "persistence", "hibernate",
            "querydsl", "jooq", "$where", "$ne", "$gt", "$lt", "$regex", "$nin",
            "$elemmatch", "mongoclient", "getcollection", "bson", "mongoose",
            "nosql", "cassandra", "cql", "lucene", "elasticsearch", "querystring",
            "query_builder", "querybuilder", "expressionbuilder", "odata", "graphql",
            "sequelize"],
    "94": ["eval(", "exec(", "compile(", "new function", "function(", "vm.",
           "runincontext", "runinnewcontext", "scriptengine", "groovy", "jshell",
           "nashorn", "ast.literal_eval", "roslyn", "csharpcodeprovider",
           "compilesource", "generatedcode", "createprocess", "invokescript",
           "engines.eval", "pythoninterpreter"],
    "643": ["xpath", "selectnodes", "xpathexpression", "xpathfactory", "lxml",
            "etree", "documentbuilderfactory", "xmlpath", "evaluate("],
}


def top_label(assistant: str):
    """取 assistant [JSON] 块的 vulnerability_type 与 has_vulnerability。"""
    m = JSON_BLK.search(assistant)
    if not m:
        return None, None
    try:
        o = json.loads(m.group(0))
        return o.get("has_vulnerability"), (o.get("vulnerability_type") or "")
    except Exception:
        return "unparseable", (m.group(0)[:80])


def main():
    flags = []
    n_vuln = 0
    lab_count = {}
    with DATA.open(encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            try:
                row = json.loads(line)
            except Exception:
                continue
            asst = row["messages"][2]["content"]
            has_v, vt = top_label(asst)
            if has_v is not True:
                continue
            n_vuln += 1
            m = re.match(r"CWE-(\d{1,4})", vt.strip())
            if not m:
                continue
            cwe = m.group(1)
            lab_count[cwe] = lab_count.get(cwe, 0) + 1
            if cwe not in MARKS:
                continue
            user = row["messages"][1]["content"]
            code = "\n".join(FENCE.findall(user)).lower()
            if not code.strip():
                # 无围栏块：退化为整个 user（排除任务指令文字的干扰风险由裁决兜底）
                code = user.lower()
            hits = [mk for mk in MARKS[cwe] if mk.lower() in code]
            if hits:
                continue
            flags.append({
                "line": i,
                "label": vt,
                "kind": (row.get("meta") or {}).get("kind") if isinstance(row.get("meta"), dict) else None,
                "missing": MARKS[cwe][:0],
                "code_head": code[:240],
                "assistant_head": asst[:240],
            })
    with OUT.open("w", encoding="utf-8") as f:
        for fl in flags:
            f.write(json.dumps(fl, ensure_ascii=False) + "\n")
    print(f"漏洞样本 {n_vuln}，L2 形态不符候选 {len(flags)} → {OUT.name}")
    from collections import Counter
    print(Counter(re.match(r"CWE-(\d+)", f["label"]).group(1) for f in flags).most_common())


if __name__ == "__main__":
    main()
