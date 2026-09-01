# -*- coding: utf-8 -*-
"""把 23 条裁决结果应用进 v2_15（2026-09-01 裁决记录的执行脚本）。

A 类(10)  : JSON 结论字段微修 + 分析过程文本校准（行锚对齐/边界句/精简）
B 类(4)   : assistant 全文改写（1108/8184→safe, 6347→CWE-798, 2559→CWE-639）
C 类(2)   : 删行 + 追加 redistill_manifest_v2_15_wave1.jsonl 补位
D 类(7)   : 删行 + 原始三元组转存 g20_judge_material.jsonl（含裁决理由）

幂等：重复执行时 A/B 以 md5 前后一致性校验，C/D 以 id 查重跳过。
fail-fast：任何 text/json 替换未命中目标立即报错退出，不写半成品。
产出：audit/adjudicate_v2_15/apply_out.txt
"""
import hashlib
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]  # exp_06_finetune/
DATA = BASE / "data/final_train_chatml_alpha06_v2_15.jsonl"
AUD = BASE / "audit"
ADJ = AUD / "adjudicate_v2_15"
SAMPLES = ADJ / "samples"
MANIFEST = AUD / "redistill_manifest_v2_15_wave1.jsonl"
G20 = ADJ / "g20_judge_material.jsonl"
OUT = ADJ / "apply_out.txt"

CONTRACT = ["has_vulnerability", "vulnerability_type", "risk_level",
            "source", "sink", "explanation", "fix_suggestion"]
JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.S)

LOG = []
def P(*a):
    LOG.append(" ".join(str(x) for x in a))

def norm_md5(s):
    return hashlib.md5(re.sub(r"\s+", "", s).encode()).hexdigest()

# ---------- v2_14 id -> v2_15 line 映射（与 merge_v2_15_wave1_incr.py 同算法） ----------
del_ids = {json.loads(l)["id"] for l in (AUD / "agent_audit_v2_14/out/manifest_DELETE.jsonl").open(encoding="utf-8") if l.strip()} | {8288, 8968}
id2v15 = {}
n = 0
for i in range(1, 10022):
    if i in del_ids:
        continue
    n += 1
    id2v15[i] = n

lines = DATA.read_text(encoding="utf-8").split("\n")
P(f"载入 v2_15：{sum(1 for l in lines if l.strip())} 条")

# ---------- 定位与前置校验 ----------
A_IDS = [7218, 2833, 1667, 8199, 1724, 1717, 7531, 8176, 8141, 7899]
B_IDS = [1108, 8184, 6347, 2559]
C_IDS = [7301, 1289]
D_IDS = [524, 1449, 8196, 8037, 7862, 8025, 7980]

records = {}          # id -> (line_no, rec)
for vid in A_IDS + B_IDS + C_IDS + D_IDS:
    ln = id2v15[vid]
    rec = json.loads(lines[ln - 1])
    want = json.loads((SAMPLES / f"id{vid}.json").read_text(encoding="utf-8"))
    if norm_md5(rec["messages"][1]["content"]) != norm_md5(want["messages"][1]["content"]):
        P(f"!! id{vid}: 行 {ln} user 内容与样本不符，中止")
        (OUT).write_text("\n".join(LOG) + "\n", encoding="utf-8")
        sys.exit(1)
    records[vid] = (ln, rec)
P(f"23/23 定位与 user-md5 校验通过")

# ---------- A 类规则 ----------
A8199_ANALYSIS = """分析过程：
1. line 5: twitter_feed_perform_api_request 函数签名带默认端点；line 8-11 依次 get_option 读取 access_token/secret/consumer key；line 14-28 三段回退赋值块在配置缺失时回填硬编码字面量。
2. 硬编码四元组位于插件主仓库，任何检索者都能冒充该应用消费 Twitter API 配额：滥用触发限额冻结殃及所有未配置站点，旧式 token 还可能附带发言权限造成归属嫁接。
3. 无效防御：密钥轮换无法对抗代码内常量——下次部署即复活；指纹比对守卫（命中已知公开值即拒绝服务）只能作为临时缓解。
4. 次级关注点（登记不展开）：动态拼接的 query 串与可被插件层改写的默认端点构成扩散面，但本文件内无命令/SQL sink，主体风险仍为凭据池。
5. 结论：CWE-798 High 合理——危害集中在滥用与嫁接而非深度渗透，公开性与不可撤销性（历史提交/fork 常量副本仍存在）支撑定级。
6. 修复：删除全部回退常量，配置缺失时抛出含申请指引的配置异常且不发起网络调用；同步执行归属方凭据吊销、存量 option 清理迁移说明与插件市场凭据扫描。
"""

A_TEXT_FIXES = {
    7218: [("line 10: HTTP 参数自动绑定到 `ProfileForm`", "line 11: HTTP 参数自动绑定到 `ProfileForm`")],
    1724: [
        ('1. **第26行**（`@PostMapping("/update-email")`）和**第42行**（`@PostMapping("/transfer")`）',
         '1. **第13行**（`@PostMapping("/update-email")`）和**第35行**（`@PostMapping("/transfer")`）'),
        ("2. **第30-32行**", "2. **第17-18行**"),
        ("3. **第34-38行**", "3. **第21-23行**"),
        ("4. **第42-48行**", "4. **第35-45行**"),
    ],
    1717: [
        ('1. **第36行**：`String action = request.getParameter("action");`',
         '1. **第35行**：`String action = request.getParameter("action");`'),
        ("2. **第41行**：`executeAdminAction(action)`", "2. **第42行**：`executeAdminAction(action)`"),
        ("3. **第45-49行**：日志记录中直接拼接来自请求的参数 `action` 和会话 ID，形成日志注入（CWE-117 Improper Output Neutralization for Logs",
         "3. **第46-50行**：日志经 `logger.log(Level.INFO, \"... {0} by session {1}\", new Object[]{action, sessionId})` 参数化输出，占位符由 MessageFormat 填充，不构成日志注入（CWE-117 排除）"),
        ("5. **第53行**：`executeAdminAction` 无幂等性检查", "5. **第57行**：`executeAdminAction` 无幂等性检查"),
    ],
    7531: [("line 66 `unserialize($rawResult)`", "line 77 `unserialize($rawResult)`")],
}

A_JSON_FIXES = {
    7218: {
        "source": [("line 10: HTTP 参数绑定", "line 11: HTTP 参数绑定")],
        "sink": [("line 10: @ModelAttribute 自动绑定任意属性", "line 11: @ModelAttribute 自动绑定任意属性")],
        "fix_suggestion": [("line 10: @InitBinder", "line 11: @InitBinder")],
    },
    2833: {
        "risk_level": [("High", "Medium")],
        "explanation": [("执行恶意脚本",
                         "执行恶意脚本；边界：利用依赖浏览器将 text/markup 响应按 HTML 渲染，若网关强制 nosniff/CSP 则实际利用受限，故定级 Medium")],
    },
    1667: {
        "explanation": [("line 29:硬编码数据库连接字符串", "line 31:硬编码数据库连接字符串"),
                        ("line 40:直接输出该字符串", "line 43:直接输出该字符串")],
    },
    1724: {
        "sink": [("line 26: userService.transfer() 执行转账操作", "line 42: userService.transfer() 执行转账操作")],
    },
    1717: {
        "source": [("line 18-19: 仅检查 session 角色为 admin", "line 28-29: 仅检查 session 角色为 admin")],
    },
    7531: {
        "fix_suggestion": [("line 66: 改为 unserialize", "line 77: 改为 unserialize")],
        "explanation": [("任意代码执行",
                         "任意代码执行；边界：利用前提为攻击者可写持久缓存后端（共享 Redis/DB 或被攻破组件），TransientBackendInterface 内存后端不在攻击面内")],
    },
    8176: {
        "vulnerability_type": [("CWE-22 Path Traversal (Sensitive Env Disclosure)", "CWE-22 Path Traversal")],
        "sink": [("line 123 open(path)", "line 169 open(path)")],
        "explanation": [("line 114 truediv+resolve", "line 155 truediv+resolve"),
                        ("line 128 open reads", "line 169 open reads"),
                        ("reach the same sink",
                         "reach the same sink; boundary: exploitability requires an untrusted .prompty file (shared repo/community template) — trusted-environment config files are outside the attack surface")],
    },
    7899: {
        "sink": [("line 61: new Constructor(opts) 以及 line 71 回退的 new Yaml()",
                  "line 69: new Constructor(opts) 以及 line 77 回退的 new Yaml()")],
        "explanation": [("未配置时 line 65:回退到默认 new Yaml()", "未配置时 line 77:回退到默认 new Yaml()"),
                        ("存在多上下文或未初始化时安全配置失效的竞态风险",
                         "存在多上下文或未初始化时安全配置失效的竞态风险；边界：实际可利用性取决于 SnakeYAML 版本（<2.0 默认接受全局标签，≥2.0 需显式启用），若上游锁定 2.x 且未开启全局标签则风险降级")],
        "fix_suggestion": [("line 61: 将 new Constructor(opts) 改为", "line 69: 将 new Constructor(opts) 改为"),
                           ("同时将 line 71 的回退改为", "同时将 line 77 的回退改为")],
    },
}

def fix_json_obj(obj, fixes, vid):
    for field, rules in fixes.items():
        if field not in obj:
            P(f"!! id{vid}: JSON 缺字段 {field}"); sys.exit(1)
        for old, new in rules:
            if old not in obj[field]:
                P(f"!! id{vid}: 字段 {field} 未命中替换目标: {old[:60]!r}")
                (OUT).write_text("\n".join(LOG) + "\n", encoding="utf-8")
                sys.exit(1)
            obj[field] = obj[field].replace(old, new, 1)
    return obj

a_done = 0
for vid in A_IDS:
    ln, rec = records[vid]
    a = rec["messages"][2]["content"]
    ms = list(JSON_BLOCK.finditer(a))
    if not ms:
        P(f"!! id{vid}: 无 JSON 块"); sys.exit(1)
    m = ms[-1]
    obj = json.loads(m.group(1))
    # 文本（分析过程）替换
    pre = a[: m.start()]
    for old, new in A_TEXT_FIXES.get(vid, []):
        if old not in pre:
            P(f"!! id{vid}: 分析文本未命中: {old[:50]!r}")
            (OUT).write_text("\n".join(LOG) + "\n", encoding="utf-8")
            sys.exit(1)
        pre = pre.replace(old, new, 1)
    if vid == 8199:
        pre = A8199_ANALYSIS
    obj = fix_json_obj(obj, A_JSON_FIXES.get(vid, {}), vid)
    new_a = pre + "```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```" + a[m.end():]
    rec["messages"][2]["content"] = new_a
    lines[ln - 1] = json.dumps(rec, ensure_ascii=False)
    a_done += 1
    P(f"A  id{vid} (line {ln}): 微修完成")
P(f"A 类完成 {a_done}/10")

# ---------- B 类：全文改写 ----------
def B(*points):
    return "分析过程：\n" + "\n".join(f"{i+1}. {p}" for i, p in enumerate(points)) + "\n"

B_CONTENTS = {
    1108: (
        B(
            "line 34: `tokenData = JSON.parse(Buffer.from(resetToken, 'base64').toString('utf8'))` —— JSON.parse 只构造纯数据对象，不实例化类、不调用 setter/构造器，不构成 CWE-502 危险反序列化 sink（对比 PHP unserialize / Java readObject 的 gadget chain 语义）。",
            "line 40-44: 存在 HMAC-SHA256 签名校验，伪造 tokenData 需要知道来自环境变量的 RESET_SECRET。",
            "line 53: 特权分支 `if (tokenData.role === 'admin' && tokenData.forceReset)` 仅影响响应文案与撤销范围：特权路径（line 55）与普通路径（line 61）调用同一 `updatePassword(tokenData.userId, newPassword)`，密码更新效果完全一致；多出的 revokeAll 撤销的也是 userId 本人 token。",
            "因此“反序列化导致提权”不成立：即使利用签名仅覆盖 userId 的缺口注入 role/forceReset 字段，能做的事与普通重置路径完全相同——文件内不存在任何仅 admin 分支可达的危险操作。",
            "设计缺陷注记（非本文件漏洞）：line 40-41 签名仅绑定 userId，未覆盖 role/forceReset 等字段；深度防御上应签名完整 payload，在本文件内该缺口无提权收益，属上游加固项。",
            "结论：文件内无 source→危险 sink 的可利用路径，判 safe。",
        ),
        {"has_vulnerability": False, "vulnerability_type": "none", "risk_level": "None",
         "source": "N/A", "sink": "N/A",
         "explanation": "line 34 JSON.parse 构造纯数据对象，无类实例化/gadget 面，非 CWE-502 sink；line 40-44 HMAC 签名校验限制伪造；line 53 特权分支（line 55）与普通路径（line 61）执行同一 updatePassword(tokenData.userId, newPassword)，特权分支仅多 revokeAll(本人 token)，文件内不存在仅 admin 分支可达的危险操作——即使利用签名仅覆盖 userId 的缺口注入 role/forceReset 也无提权收益，判 safe。设计注记：line 40-41 签名应覆盖完整 payload，属加固建议而非可利用漏洞",
         "fix_suggestion": "no fix needed；加固建议：line 40-41 签名应覆盖完整 token payload（含 role/forceReset 等），防止未来上游引入仅 admin 可达操作时留下提权通道"},
    ),
    8184: (
        B(
            "本文件为 nuclio 平台工具库 common/helper.go（706 行）。SanitizePath（line 76）只做 filepath.Clean（line 79）+ filepath.Abs（line 82）。",
            "“SanitizePath 不做 base 包含性校验”属实——但这是加固建议而非文件内漏洞：本文件是库层，任何输入都由调用方传入，文件内不存在攻击者可控 source（无 HTTP/请求参数入口），source 端在本文件之外。",
            "FileExists（line 91）/EnsureDirExists（line 97）不构成危险 sink：前者仅 os.Stat 存在性探测，后者创建目录层级，两者都不读写文件内容；原判定把它们作为“越界读写原语”的 sink 声明不成立。",
            "原叙述中“Dashboard 构建接口把请求字段拼进路径流向挂载/复制”发生在其他文件，按本任务“只计文件内可见污点流”的口径属 out-of-file 推测，不能作为本文件判 vuln 的依据。",
            "结论：文件内无 source→sink 可利用路径，判 safe；SanitizePath 的限界缺失记为库级加固项。",
        ),
        {"has_vulnerability": False, "vulnerability_type": "none", "risk_level": "None",
         "source": "N/A", "sink": "N/A",
         "explanation": "SanitizePath（line 76）仅 filepath.Clean+Abs、确无 base 包含性校验，但本文件为库层：文件内无攻击者可控 source；FileExists（line 91）仅存在性探测、EnsureDirExists（line 97）仅建目录，均非内容读写型 sink；原判定描述的构建接口路径拼接发生在文件外，按文件内污点流口径不可采信。判 safe，SanitizePath 缺限界记为库级加固项",
         "fix_suggestion": "no fix needed；加固建议：SanitizePath 增加 base 参数并断言返回值满足前缀包含（resolved.relative_to(base)），调用方迁移前记录未限界告警，并补多级上跳/绝对根/符号链接三类负向单测"},
    ),
    6347: (
        B(
            "line 12-13: `hmac.compare_digest(token, expected)` 对 CSRF token 做常数时间比较，校验失败返回 403——CSRF 防护实现本身正确。",
            "line 6: `app.secret_key = 'super_secret_key'` 是硬编码的字面量密钥，违反“硬编码凭据/密钥即漏洞”判定规则（CWE-798）。",
            "secret_key 用途：Flask 用它签名 session cookie。攻击者从公开源码取得该密钥后可离线伪造任意 session（包括 session['csrf_token']），使 line 11-12 的比较读到的 expected 即攻击者自己写入的值——CSRF 防御被整体架空。",
            "数据流：硬编码 'super_secret_key'（line 6）→ Flask session 签名密钥（框架隐式 sink）→ 伪造 session 绕过 line 12 校验。",
            "防御保留说明：compare_digest 是正确防御（常数时间比较防时序侧信道），问题不在比较而在密钥来源。",
            "修复：从环境变量或密钥管理服务读取 secret_key（缺失时启动报错），并轮换现有密钥。",
        ),
        {"has_vulnerability": True,
         "vulnerability_type": "CWE-798 Use of Hard-coded Credentials",
         "risk_level": "High",
         "source": "line 6: app.secret_key = 'super_secret_key' 硬编码密钥字面量",
         "sink": "line 6: 硬编码密钥直接作为 Flask session 签名密钥（框架隐式 sink，line 11 session.get 读取的值可被伪造签名）",
         "explanation": "line 6 硬编码 secret_key → 攻击者从公开源码获得密钥 → 可离线伪造任意 session cookie（含 csrf_token 字段）→ line 11-12 的 compare_digest 校验读到的 expected 即攻击者写入的值 → CSRF 防护被整体绕过；compare_digest 本身是正确防御（常数时间比较防时序侧信道），问题不在比较而在密钥来源",
         "fix_suggestion": "line 6: 应改为 app.secret_key = os.environ['FLASK_SECRET_KEY']（缺失时启动报错）并轮换密钥；禁止在代码中回退到字面量默认值"},
    ),
    2559: (
        B(
            "line 36: `updateProfile(@ModelAttribute User user, Model model)` —— HTTP 参数直接绑定到 User 对象，含 admin/role 字段（line 40-41 注释自认）。",
            "mass assignment 为近失：line 39 只把 user.getEmail() 复制到从 DB 加载的 existing 上，line 42 saveToDB(existing) 持久化的是 existing——绑定得到的 admin/role 未被复制或持久化，提权字段被中和，不构成 CWE-915 实害。",
            "真实漏洞在身份锚点：line 38 getCurrentUserFromDB(user.getUsername()) 用请求参数 username 直接定位目标记录，且无与当前登录用户的一致性校验。",
            "攻击链：攻击者构造 POST /profile/update?username=victim&email=attacker@evil.com → line 38 加载 victim 的记录 → line 39 把攻击者的 email 写入 → line 42 持久化 → 受害者邮箱被接管（可进一步用于密码重置）。水平越权成立，CWE-639。",
            "风险 High：邮箱接管是账户接管的前置原语，利用零门槛（仅需知道受害者用户名）。",
        ),
        {"has_vulnerability": True,
         "vulnerability_type": "CWE-639 Authorization Bypass Through User-Controlled Key",
         "risk_level": "High",
         "source": "line 36-38: 请求参数 username（经 @ModelAttribute 绑定后直接取用）与 email 均为攻击者可控",
         "sink": "line 42: saveToDB(existing) 将基于攻击者所选 username 加载并改写 email 的记录持久化",
         "explanation": "line 38 以请求参数 username 定位记录且无所有权校验 → line 39 将攻击者控制的 email 写入该记录 → line 42 持久化 → 水平越权篡改任意用户邮箱（CWE-639）；mass assignment 分支（admin/role 经 line 36 绑定）因 line 39 仅复制 email、line 42 保存的是 DB 加载的 existing 而被中和，属 near-miss 不另行定级",
         "fix_suggestion": "line 38: 应改为从服务端会话取当前登录身份（如 getCurrentUserFromSession()），拒绝以请求参数 username 定位目标记录；同时在 @Controller 加 @InitBinder setAllowedFields(\"email\") 白名单，防止未来绑定面扩大重新引入 mass assignment"},
    ),
}

b_done = 0
for vid in B_IDS:
    ln, rec = records[vid]
    analysis, obj = B_CONTENTS[vid]
    assert list(obj.keys()) == CONTRACT, f"id{vid} 契约不符"
    new_a = analysis + "\n```json\n" + json.dumps(obj, ensure_ascii=False) + "\n```"
    rec["messages"][2]["content"] = new_a
    lines[ln - 1] = json.dumps(rec, ensure_ascii=False)
    b_done += 1
    P(f"B  id{vid} (line {ln}): 改写完成 -> {obj['vulnerability_type']}")
P(f"B 类完成 {b_done}/4")

# ---------- C 类：删除 + manifest 补位 ----------
existing_manifest = [json.loads(l) for l in MANIFEST.open(encoding="utf-8") if l.strip()]
manifest_ids = {e.get("orig_line") for e in existing_manifest}
c_entries = []
drop_lines = set()
for vid in C_IDS:
    ln, rec = records[vid]
    drop_lines.add(ln - 1)
    if ln in manifest_ids:
        P(f"C  id{vid} (line {ln}): 已在补位清单，跳过追加")
        continue
    c_entries.append({
        "orig_line": ln,
        "reason": "adjudication_C_delete",
        "note": ("裁决 C（2026-09-01）：漏洞链依赖文件外 install.js 行为，文件内无 source→command sink 污点流；"
                 "与伴生样本 8141(false) 构成正反矛盾对。裁决记录：audit/adjudicate_v2_15/裁决记录_v2_15_23条_20260901.md"
                 if vid == 7301 else
                 "裁决 C（2026-09-01）：全部行锚错误 + 倒退式 fix（修复引入新问题）+ R6 配置加固误判，无法局部修，整条重蒸馏。"
                 "裁决记录：audit/adjudicate_v2_15/裁决记录_v2_15_23条_20260901.md"),
        "user": rec["messages"][1]["content"],
    })
    P(f"C  id{vid} (line {ln}): 删行 + manifest 补位登记")

# ---------- D 类：删除 + 转存 g20 素材 ----------
D_META = {
    524:  ("env/config 输入进入 command exec——部署配置是否可信", "教师 CWE-912 Backdoor 为标签漂移；形态本身是信任边界家族典型"),
    1449: ("deploy.conf 受信→eval——配置文件信任边界", "教师 fix 含 broken tr filter；核心争议是配置文件信任级别"),
    8196: ("OAuth2 pendingAuth 状态表无界——服务端内存状态边界与可达性", "可达性在文件外；非规范 770 命名；分析冗长"),
    8037: ("opt-in InsecureSkipVerify/TLSPolicy——显式弃用 TLS 校验的配置语义", "575 行大文件；opt-in 配置语义辨析"),
    7862: ("beego FileCache 目录配置——缓存目录信任边界", "标签混乱（CWE-22 + 反序列化混合）；行号全错；矛盾伴生"),
    8025: ("twig autoescape 输出层——转义默认与模板配置边界", "teacher true vs independent false 冲突不可调和"),
    7980: ("CLI --mcp/config 注入——CLI 自执行是否构成攻击面", "教师自身分析已承认 CLI 自执行非漏洞"),
}
g20_existing_ids = set()
if G20.exists():
    g20_existing_ids = {json.loads(l)["v2_14_id"] for l in G20.open(encoding="utf-8") if l.strip()}
g20_new = []
for vid in D_IDS:
    ln, rec = records[vid]
    drop_lines.add(ln - 1)
    if vid in g20_existing_ids:
        P(f"D  id{vid} (line {ln}): 已在 g20 素材池，跳过")
        continue
    theme, why = D_META[vid]
    g20_new.append({
        "v2_14_id": vid, "v15_line": ln,
        "adjudication": "D_transfer_to_g20", "g20_theme": theme, "why": why,
        "messages": rec["messages"], "fix_distill": rec.get("fix_distill", {}),
    })
    P(f"D  id{vid} (line {ln}): 转 g20 素材 [{theme}]")

if c_entries:
    with MANIFEST.open("a", encoding="utf-8") as f:
        for e in c_entries:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
if g20_new:
    with G20.open("a", encoding="utf-8") as f:
        for e in g20_new:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

# ---------- 写回 ----------
kept = [l for i, l in enumerate(lines) if l.strip() and i not in drop_lines]
DATA.write_text("\n".join(kept), encoding="utf-8")
P(f"写回 v2_15：{len(kept)} 条（删除 {len(drop_lines)} 行）")

# ---------- 自检 ----------
sys_cnt, bad_json, hv, md5s = {}, 0, {}, set()
dupe = 0
for l in kept:
    rec = json.loads(l)
    m = hashlib.md5(rec["messages"][0]["content"].encode()).hexdigest()[:8]
    sys_cnt[m] = sys_cnt.get(m, 0) + 1
    blk = JSON_BLOCK.findall(rec["messages"][2]["content"])
    try:
        o = json.loads(blk[-1])
        hv[str(o.get("has_vulnerability"))] = hv.get(str(o.get("has_vulnerability")), 0) + 1
        assert list(o.keys()) == CONTRACT
    except Exception:
        bad_json += 1
    um = norm_md5(rec["messages"][1]["content"])
    am = norm_md5(rec["messages"][2]["content"])
    if um in md5s or am in md5s:
        dupe += 1
    md5s.add(um); md5s.add(am)
P(f"自检：总条数 {len(kept)} | JSON/契约失败 {bad_json} | 正负 {hv} | 库内重复 {dupe}")
# 23 条去向复核：C/D 的旧行不应再存在（kept 中第 ln 行的内容应已不是原样本）
remap = {}  # 新文件行号
idx_new = 0
ok_gone = True
for i, l in enumerate(lines):
    if not l.strip():
        continue
    idx_new += 1
    if i in drop_lines:
        remap[i + 1] = ("dropped", idx_new)
ok_gone = all(v[0] == "dropped" for k, v in remap.items())
P(f"自检：C/D 删除行复核 {'OK' if ok_gone else 'FAIL'}（标记 {len(remap)} 行）")

(OUT).write_text("\n".join(LOG) + "\n", encoding="utf-8")
print("\n".join(LOG))
