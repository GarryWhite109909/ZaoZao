# -*- coding: utf-8 -*-
"""g21-g24 辨析组入库前机检:类型命中 / 锚句命中 / 叙事互斥。

断言来源(全部取自优化建议文档,非测试集):
  F12 密码学互斥:329 组禁"弱算法"叙事;330/338 组禁 md5/sha1/破解作论证;
                327 组禁把随机源写成主因(P0-B 表 + §四速查表)
  F11 定论纪律:E3/E2 高置信样本禁"需运行时验证/证据不足/无法确认"等保守表述
  F10 伴生凭证:主类型不得为 798,explanation 必须承认伴生凭证存在
  CSRF/PHP:352 修复禁转义类叙事;843 须落在比较语义上
输出 audit/adjudicate_v2_15/verify_g2124_out.txt
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]  # exp_06_finetune/
OUT_DIRS = [BASE / "corpus/repair_wave/_wave1_out_g21_22",
            BASE / "corpus/repair_wave/_wave1_out_g23_24",
            BASE / "corpus/repair_wave/_wave1_out_g23b",
            BASE / "corpus/repair_wave/_wave1_out_g24_tail",  # g24 后半并行批
            BASE / "corpus/repair_wave/_wave1_out_g2122_retry",  # G4 拒收重试批
            BASE / "corpus/repair_wave/_wave1_out_g22b"]  # g22b 危害具体化 + 拒收重试
OUT_LOG = BASE / "audit/adjudicate_v2_15/verify_g2124_out.txt"
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)

# orig -> (期望 CWE 集合, 必含锚句(任一), 禁用词(任一命中即 WARN), 附注)
EXPECT = {
    # ---- g21 F12 密码学互斥 ----
    "g21-iv01": ({"329"}, ["IV", "初始向量"], ["弱算法", "算法强度", "md5", "sha1", "DES", "RC4"], "329 禁弱算法叙事"),
    "g21-iv02": ({"329"}, ["IV", "初始向量"], ["弱算法", "算法强度", "md5", "sha1", "DES", "RC4"], "329 禁弱算法叙事"),
    "g21-iv03": ({"329"}, ["IV", "初始向量"], ["弱算法", "算法强度", "md5", "sha1", "DES", "RC4"], "329 禁弱算法叙事"),
    "g21-alg01": ({"327"}, ["算法"], ["随机源", "随机数不可预测", "IV"], "327 算法强度,禁随机/IV 主因"),
    "g21-alg02": ({"327"}, ["算法"], ["随机源", "随机数不可预测", "IV"], "327 DES-ECB"),
    "g21-alg03": ({"327"}, ["算法"], ["随机源", "随机数不可预测", "IV"], "327 SHA-1 口令摘要"),
    "g21-rnd01": ({"330", "338"}, ["随机"], ["md5", "sha1", "破解", "哈希", "摘要"], "330 禁哈希论证"),
    "g21-rnd02": ({"330", "338"}, ["随机"], ["md5", "sha1", "破解", "哈希", "摘要"], "330 禁哈希论证"),
    "g21-rnd03": ({"330", "338"}, ["随机"], ["md5", "sha1", "破解", "哈希", "摘要"], "330 禁哈希论证"),
    "g21-dig01": ({"327"}, ["算法"], ["随机源", "随机数不可预测"], "327 md5 口令哈希"),
    "g21-dig02": ({"327"}, ["算法"], ["随机源", "随机数不可预测"], "327 md5 口令哈希"),
    "g21-dig03": ({"327"}, ["算法"], ["随机源", "随机数不可预测"], "327 md5 认证哈希"),
    # ---- g22 F11 E3/E2 ----
    "g22-trav-e3a": ({"22"}, ["污点链", "完整链", "可直接确认"], [], "E3 路径穿越"),
    "g22-trav-e3b": ({"22"}, ["污点链", "完整链", "可直接确认"], [], "E3 路径穿越"),
    "g22-trav-e2a": ({"22"}, [], [], "E2 位置告警+上下文自证"),
    "g22-trav-e2b": ({"22"}, [], [], "E2 位置告警+上下文自证"),
    "g22-log-e3a": ({"117"}, ["污点链", "完整链", "可直接确认"], ["敏感信息泄露"], "E3 日志注入,禁 532 叙事"),
    "g22-log-e3b": ({"117"}, ["污点链", "完整链", "可直接确认"], ["敏感信息泄露"], "E3 日志注入,禁 532 叙事"),
    "g22-log-e2a": ({"117"}, [], ["敏感信息泄露"], "E2 日志注入"),
    "g22-log-e2b": ({"117"}, [], ["敏感信息泄露"], "E2 日志写入"),
    "g22-race-e3a": ({"362"}, ["污点链", "完整链", "可直接确认", "竞态", "并发"], [], "E3 竞态"),
    "g22-race-e3b": ({"362"}, ["污点链", "完整链", "可直接确认", "竞态", "并发"], [], "E3 TOCTOU"),
    "g22-race-e2a": ({"362"}, ["竞态", "并发"], [], "E2 无锁读改写"),
    "g22-race-e2b": ({"362"}, ["竞态", "并发"], [], "E2 非原子 get/set"),
    # ---- g22b 危害具体化补做(原样本危害不显著导致退守 safe)----
    "g22b-race-01": ({"362", "367"}, ["竞态", "并发", "锁", "事务"], [], "提现限额 TOCTOU,可超额取款"),
    "g22b-race-02": ({"362", "367"}, ["竞态", "并发", "锁", "约束"], [], "并发注册 TOCTOU,可覆盖他人账号"),
    "g22b-log-01": ({"117"}, ["污点链", "完整链", "可直接确认"], [], "E3 UA 头注入审计日志"),
    # ---- g23 F10 伴生凭证 ----
    "g23-csrf-01": ({"352"}, ["798", "硬编码", "凭证", "密钥"], [], "主 352,伴生 798"),
    "g23-csrf-02": ({"352"}, ["798", "硬编码", "凭证", "密钥"], [], "主 352,伴生 798"),
    "g23-csrf-03": ({"352"}, ["798", "硬编码", "凭证", "密钥"], [], "主 352,伴生 798"),
    "g23-fix-01": ({"384"}, ["798", "硬编码", "凭证", "密钥"], [], "主 384 会话固定"),
    "g23-fix-02": ({"384"}, ["798", "硬编码", "凭证", "密钥"], [], "主 384 未轮换"),
    "g23-idor-01": ({"639"}, ["798", "硬编码", "凭证", "密钥"], [], "主 639"),
    "g23-idor-02": ({"639"}, ["798", "硬编码", "凭证", "密钥"], [], "主 639"),
    "g23-idor-03": ({"639"}, ["798", "硬编码", "凭证", "密钥"], [], "主 639"),
    "g23-authz-01": ({"862"}, ["798", "硬编码", "凭证", "密钥"], [], "主 862"),
    "g23-authz-02": ({"862"}, ["798", "硬编码", "凭证", "密钥"], [], "主 862"),
    "g23-up-01": ({"434"}, ["798", "硬编码", "凭证", "密钥"], [], "主 434"),
    "g23-up-02": ({"434"}, ["798", "硬编码", "凭证", "密钥"], [], "主 434"),
    # ---- g23b F10 强化版(主洞危害升级 + 凭证退到角落)----
    "g23b-del-01": ({"639", "862"}, ["798", "硬编码", "凭证", "密钥"], [], "主 639/862 越权删除退款"),
    "g23b-transfer-01": ({"639", "862"}, ["798", "硬编码", "凭证", "密钥"], [], "主 639/862 越权转账"),
    "g23b-grant-01": ({"862"}, ["798", "硬编码", "凭证", "密钥"], [], "主 862 越权提权"),
    "g23b-up-03": ({"434"}, ["798", "硬编码", "凭证", "密钥"], [], "主 434 配置热加载"),
    # ---- g24 案例 D ----
    "g24-csrf-01": ({"352"}, [], [], "352 纯(修复须 token 校验)"),
    "g24-csrf-02": ({"352"}, [], [], "352 + autoescape 在场"),
    "g24-csrf-03": ({"352"}, ["79"], [], "352 主 79 伴生"),
    "g24-csrf-04": ({"79"}, ["校验"], [], "79 主,csrf 防御有效不得倒贴 352"),
    "g24-php-01": ({"843"}, ["比较", "类型"], [], "0e 弱比较"),
    "g24-php-02": ({"843"}, ["比较", "类型"], [], "strcmp 数组返回 NULL"),
    "g24-php-03": ({"843"}, ["比较", "类型"], [], "数字字符串弱比较"),
    "g24-php-04": ({"843"}, ["比较", "类型"], [], "in_array 松散模式"),
    "g24-cmd-01": ({"78"}, [], [], "shell 解释层在场"),
    "g24-cmd-02": ({"78"}, [], [], "execSync shell 元字符"),
    "g24-cmd-03": ({"78"}, [], [], "bash -c 解释层"),
    "g24-cmd-04": ({"77"}, [], [], "无 shell 层,命令整体可控"),
    "g24-cmd-05": ({"77"}, [], [], "spawn 命令名可控"),
    "g24-cmd-06": ({"77"}, [], [], "exec.Command 工具名可控"),
    "g24-code-01": ({"95"}, [], [], "eval 直接求值"),
    "g24-code-02": ({"95"}, [], [], "eval 直接求值"),
    "g24-code-03": ({"94"}, [], [], "输入拼进生成的代码文本"),
    "g24-code-04": ({"94"}, [], [], "SpEL 表达式注入"),
}

# F11 反模式:高置信样本禁止的保守表述
F11_BAN = ["需运行时验证", "证据不足", "无法确认", "不能确认", "需更多上下文",
           "需要人工复核", "需人工复核", "无法判断", "信息有限"]
# g22 适用 F11 断言;其余组不做(样本形态不同)
F11_GROUPS = ("g22-",)
# 352 组修复禁转义类叙事(语义错位)
NO_ESCAPE_FIX = ("g24-csrf-01", "g24-csrf-02", "g24-csrf-03")
# 判 safe 且经人工复核认可的样本:原 kit 主洞危害不显著(无实际安全影响),
# 教师退守 safe 站得住,不按期望类型判 FAIL;样本本身留作安全侧候选,不入库。
SAFE_OK = {
    "g22-log-e2b",  # 函数形参写日志,片段内无可见 source,注入不可证
    "g22-race-e3b",  # TOCTOU 但并发双写同一 placeholder,无后果
    "g22-race-e2a",  # 计数器 +=1 非原子,只影响指标精度
}

LOG = []
def P(*a):
    LINE = " ".join(str(x) for x in a)
    LOG.append(LINE)
    print(LINE, flush=True)


def cwe_of(s):
    m = re.search(r"CWE-(\d+)", str(s))
    return m.group(1) if m else None


def main():
    recs = {}
    for d in OUT_DIRS:
        sp = d / "success.jsonl"
        if not sp.exists():
            continue
        for l in sp.open(encoding="utf-8"):
            if not l.strip():
                continue
            r = json.loads(l)
            o = str(r.get("fix_distill", {}).get("orig", ""))
            recs[o] = r

    P(f"产出 {len(recs)} 条 | 期望表 {len(EXPECT)} 条")
    missing = [o for o in EXPECT if o not in recs]
    if missing:
        P(f"!! 尚未产出(可能仍在蒸馏或已拒收): {missing}")
    rejects = []
    for d in OUT_DIRS:
        rp = d / "rejects.jsonl"
        if rp.exists():
            for l in rp.open(encoding="utf-8"):
                if l.strip():
                    j = json.loads(l)
                    rejects.append((d.name, j.get("orig"), str(j.get("reject"))[:90]))
    if rejects:
        P(f"拒收 {len(rejects)} 条:")
        for d, o, why in rejects:
            P(f"  [{d}] {o}: {why}")

    verdict = Counter()
    problems = []
    safe_notes = []
    for o, (exp_cwes, anchors, bans, note) in sorted(EXPECT.items()):
        r = recs.get(o)
        if r is None:
            continue
        a = r["messages"][2]["content"]
        blk = JSON_BLOCK.findall(a)
        if not blk:
            problems.append(f"{o}: 无 JSON 块")
            verdict["FAIL"] += 1
            continue
        j = json.loads(blk[-1])
        hv = str(j.get("has_vulnerability"))
        cwe = cwe_of(j.get("vulnerability_type", ""))
        expl = str(j.get("explanation", ""))
        fix = str(j.get("fix_suggestion", ""))

        issues = []
        # 判 safe 且人工复核认可:不按期望类型判 FAIL,改计 SAFE
        if o in SAFE_OK and hv == "False":
            verdict["SAFE(人工认可)"] += 1
            safe_notes.append(f"{o} [{note}]: 判 safe,人工复核认可(原 kit 危害不显著)")
            for b in F11_BAN:
                if b in expl:
                    problems.append(f"{o}: safe 侧出现 F11 反模式表述:{b}")
            continue
        if hv != "True":
            issues.append(f"hv={hv}")
        if cwe not in exp_cwes:
            issues.append(f"类型 {cwe} != 期望 {'/'.join(sorted(exp_cwes))}")
        for anc in anchors:
            if anc.lower() not in expl.lower():
                issues.append(f"缺锚句/关键词:{anc}")
        for b in bans:
            if b.lower() in expl.lower():
                issues.append(f"叙事互斥违规:{b}")
        if o.startswith(F11_GROUPS):
            for b in F11_BAN:
                if b in expl:
                    issues.append(f"F11 反模式表述:{b}")
        if o in NO_ESCAPE_FIX and re.search(r"转义|escape", fix, re.I):
            issues.append("352 修复出现转义类叙事(语义错位)")

        if issues:
            verdict["FAIL"] += 1
            problems.append(f"{o} [{note}]: " + "; ".join(issues))
        else:
            verdict["PASS"] += 1

    P("")
    P(f"== 机检汇总: PASS {verdict['PASS']} / FAIL {verdict['FAIL']} ==")
    for p in problems:
        P("  " + p)

    # 类型分布
    dist = Counter()
    for o, r in recs.items():
        blk = JSON_BLOCK.findall(r["messages"][2]["content"])
        if blk:
            try:
                j = json.loads(blk[-1])
                dist[cwe_of(j.get("vulnerability_type", ""))] += 1
            except Exception:
                dist["?"] += 1
    P("")
    P(f"CWE 分布: {dict(sorted(dist.items(), key=lambda x: (x[0] is None, str(x[0])), reverse=False))}")
    OUT_LOG.write_text("\n".join(LOG) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
