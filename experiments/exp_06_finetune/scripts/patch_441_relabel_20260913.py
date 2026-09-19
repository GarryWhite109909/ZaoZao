# -*- coding: utf-8 -*-
"""441 批改标补丁（20260913，专家裁决定版）：接受预审教师轴，10 对改标+锚句重写+safe 保守化。"""
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
F = Path(__file__).resolve().parents[1] / "scripts" / "build_wave2_pairs_441_20260911.py"
t = F.read_text(encoding="utf-8")

PAIRS = [
    ("441-02", "CWE-290",
     "非 441 因为产品无『非预期代理』转发语义；伪造内部标记头绕过鉴权按 MITRE CWE-290（欺骗绕过认证）定位——预审教师轴 20260913 定版。"),
    ("441-03", "CWE-290",
     "非 441 因为无转发语义；内网标记由请求头自报决定=身份欺骗，按 CWE-290 定位——预审教师轴 20260913 定版。"),
    ("441-04", "CWE-290",
     "非 441 因为无转发语义；内部来源域由转发头自报决定=身份欺骗，按 CWE-290 定位——预审教师轴 20260913 定版。"),
    ("441-05", "CWE-290",
     "非 441 因为无转发语义；本机白名单判定被 IPv4-mapped 等价形态绕过=来源身份欺骗，按 CWE-290 定位"
     "（部署假设：双栈监听使映射形态可达；若纯 IPv4 栈则不可达，样本外）——预审教师轴 20260913 定版。"),
    ("441-06", "CWE-290",
     "非 441 因为无转发语义；回环判定用字符串枚举漏掉等价本机形态=来源身份欺骗，按 CWE-290 定位——预审教师轴 20260913 定版。"),
    ("441-09", "CWE-799",
     "非 441 因为无 unintended proxy 转发语义；非 918/601 因为无服务端取回/跳转；"
     "配额主体由可伪造转发链决定=频率控制绕过，按 CWE-799 定位——预审教师轴 20260913 定版。"),
    ("441-10", "CWE-799",
     "非 441/918/601；配额键信任转发链首跳（客户端可控）=频率控制绕过，按 CWE-799 定位——预审教师轴 20260913 定版。"),
    ("441-11", "CWE-640",
     "非 441 因为无转发语义；Host 头投毒密码重置链接按 MITRE CWE-640（弱密码恢复机制）定位——官方标准映射，预审教师轴 20260913 定版。"),
    ("441-12", "CWE-640",
     "非 441/601；出站链接身份由可注入 Host 决定=弱密码恢复机制，按 CWE-640 定位——官方标准映射，预审教师轴 20260913 定版。"),
    ("441-15", "CWE-807",
     "非 441/295；TLS 事实这一安全决策依赖不可信请求头，按 MITRE CWE-807（安全决策依赖不可信输入）定位——预审教师轴 20260913 定版。"),
]

# 锚句替换：按 pid 定位到 "pid": "<pid>" 后的第一个 "anchor": "..." 整段
for pid, new_cwe, new_anchor in PAIRS:
    m = re.search(rf'("pid": "{pid}".*?"anchor": ")([^"]+)(")', t, re.S)
    assert m, f"{pid} anchor 未找到"
    t = t[:m.start(2)] + new_anchor + t[m.end(2):]
    m2 = re.search(rf'("pid": "{pid}".*?"cwe": ")(CWE-\d+)(")', t, re.S)
    assert m2, f"{pid} cwe 未找到"
    t = t[:m2.start(2)] + new_cwe + t[m2.end(2):]

# 441-09 safe：恒用对端地址做限流键（保守方案，消除取位争议）
old_09 = '''app.use((req, res, next) => {
  const remote = req.socket.remoteAddress;
  const xff = (req.headers["x-forwarded-for"] || "").split(",").map(s => s.trim());
  const ip = xff.length > TRUSTED_PROXY_COUNT
    ? xff.slice(-TRUSTED_PROXY_COUNT - 1)[0]
    : remote;'''
new_09 = '''app.use((req, res, next) => {
  const remote = req.socket.remoteAddress;
  const xffLog = req.headers["x-forwarded-for"] || "";
  // 保守防御：限流键恒用 socket 对端，XFF 仅记录（不参与任何判定）
  const ip = remote;'''
assert old_09 in t, "441-09 safe 源码未找到"
t = t.replace(old_09, new_09)
t = t.replace(
    '''    "oracle_safe": [
        (r'TRUSTED_PROXY_COUNT = 1', "已知代理数固定"),
        (r'remoteAddress', "socket 对端为兜底主体"),
        (r'xff\\.slice\\(-TRUSTED_PROXY_COUNT - 1', "取右起受信边界值"),
    ],''',
    '''    "oracle_safe": [
        (r'const ip = remote;', "防御：限流键恒用 socket 对端地址（内核写入不可伪造）"),
        (r'xffLog', "XFF 仅记录，不参与判定"),
    ],''')

# 441-10 safe：恒用 peer 为键（消除越界/取位争议）
old_10 = '''def resolve_quota_key(headers, peer):
    chain = [h.strip() for h in headers.get("X-Forwarded-For", "").split(",")]
    if peer in KNOWN_PROXIES and len(chain) > len(KNOWN_PROXIES):
        return chain[-len(KNOWN_PROXIES) - 1]
    return peer'''
new_10 = '''def resolve_quota_key(headers, peer):
    # 保守防御：配额键恒用 socket 对端；XFF 仅记录（不参与任何判定）
    xff_log = headers.get("X-Forwarded-For", "")
    return peer'''
assert old_10 in t, "441-10 safe 源码未找到"
t = t.replace(old_10, new_10)
t = t.replace(
    '''    "oracle_safe": [
        (r'KNOWN_PROXIES = \\{', "受信代理集合"),
        (r'peer in KNOWN_PROXIES', "仅对端是受信代理时才采纳链值"),
        (r'chain\\[-len\\(KNOWN_PROXIES\\) - 1\\]', "取右起受信边界后的第一跳"),
    ],''',
    '''    "oracle_safe": [
        (r'return peer', "防御：配额键恒用 socket 对端（不可伪造）"),
        (r'xff_log', "XFF 仅记录，不参与判定"),
    ],''')

F.write_text(t, encoding="utf-8")
print("441 批补丁完成：10 对改标 + 锚句重写 + 09/10 safe 保守化")
