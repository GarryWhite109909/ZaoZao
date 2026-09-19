# -*- coding: utf-8 -*-
"""
口径终裁 + 补投回收 + safe-硬崩翻案 + L1 标签动作 —— v2_17 一键落库（2026-09-10）

用户 2026-09-10 拍板："全量执行"。范围 = 《口径终裁_决策卡_20260910.md》执行清单 11 行
+ 《L1待人工_12项_裁决卡_20260910.md》标签动作 2 行，共 13 行在册：
  7872 确认为无操作；3854 仅叙事升级（标签不动）；其余 11 行实际改标。

分组：
  A 口径终裁（翻 safe）：113 / 153 / 218 / 1644
  B 确认无操作：7872（True/CWE-639 维持）
  C 补投回收：3446 → True/CWE-90；3854 叙事升级；7900 → safe；
              7901 → True/CWE-90（连带新发现）
  D safe-硬崩翻案：3531 → True/CWE-787；3762 → True/CWE-415
  L1：7090 → CWE-915 改判 CWE-94；7573 → safe

7901 口径留痕：NVD 对 CVE-2023-33201 的 CWE 字段绑定 CWE-295
（source=nvd@nist.gov, Primary），但 NVD 同一记录的描述原文写 "LDAP injection"，
即 NVD 自身描述与 CWE 字段不自洽。本行取 MITRE 机制类 CWE-90
（"Improper Neutralization of Special Elements used in an LDAP Query"，
与本代码机制字面命中，且与库内 3446 等 LDAP 判例同源、在 22 类目标清单内），
并在 explanation 中显式记录 CWE-295 分歧，供 NVD 一致率指标另算。

行号口径：全部按"代码块内 1-based"，与 audit/a7_lineno.py 的 code_lines() 同口径。

安全惯例：备份(snapshot_*) → 旧结论断言 + 用户内容指纹断言 + 引文对码断言
          → 替换 → changelog → 自检。
"""
import json
import re
import sys
import hashlib
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[1]          # experiments/exp_06_finetune
DATA = BASE / "data/final_train_chatml_alpha06_v2_17.jsonl"
BACKUP = BASE / "data/snapshot_v2_17_pre_final_adjudication_20260910.jsonl"
CHANGELOG = BASE / "audit/清洗changelog_v2_17_20260910.jsonl"

CODE_BLOCK = re.compile(r"```[a-zA-Z0-9_+#\-\.]*[ \t]*\r?\n(.*?)```", re.S)

# ---------------------------------------------------------------- 工具

def ga(row):
    return [m["content"] for m in row["messages"] if m["role"] == "assistant"][-1]


def sa(row, text):
    for m in row["messages"]:
        if m["role"] == "assistant":
            m["content"] = text
            return


def code_of(row):
    u = [m["content"] for m in row["messages"] if m["role"] == "user"][0]
    cbs = CODE_BLOCK.findall(u)
    if not cbs:
        return ""
    cb = max(cbs, key=len)
    return cb[:-1] if cb.endswith("\n") else cb


def verdict(text):
    m = re.search(r"```json\s*(.*?)```", text, re.S)
    if not m:
        return None
    v = json.loads(m.group(1))
    hv = v.get("has_vulnerability")
    if isinstance(hv, str):
        hv = hv.strip().lower() == "true"
    c = re.search(r"CWE-(\d+)", str(v.get("vulnerability_type") or ""))
    return (hv, "CWE-" + c.group(1) if c else "CWE-none")


KEYS = ["has_vulnerability", "vulnerability_type", "risk_level",
        "source", "sink", "explanation", "fix_suggestion"]


def mk_verdict(**kw):
    d = {k: kw.get(k, "") for k in KEYS}
    if not d["vulnerability_type"]:
        d["vulnerability_type"] = "none"
    if not d["risk_level"]:
        d["risk_level"] = "None"
    if not d["source"]:
        d["source"] = "N/A"
    if not d["sink"]:
        d["sink"] = "N/A"
    return d


# ---------------------------------------------------------------- 各行内容

ROWS = []

# ============ A1. 113 → safe（口径终裁，样本内可达性纪律） ============
ROWS.append(dict(
    line=113,
    old=(True, "CWE-120"),
    anchor="copy_at_offset",
    quotes=["memcpy(dst->data + offset, src, src_len);",
            "if (offset < 0 || offset > dst->len)",
            "if (total > MAX_BUF)",
            "out.data = (char *)malloc(MAX_BUF);",
            "out.len = MAX_BUF;",
            "copy_at_offset(dst, tmp, 0, total);"],
    forbid=[],
    analysis="""分析过程：
1. 缺陷事实（成立）：line 18 `memcpy(dst->data + offset, src, src_len);` 所在函数 copy_at_offset（line 13）的入口守卫只有 line 14 `if (offset < 0 || offset > dst->len)` —— 只校验 offset 本身，缺 `offset + src_len <= dst->len` 的剩余空间校验。这是真实的 API 契约缺陷。
2. 样本内调用链（唯一路径）：唯一调用点是 line 40 `copy_at_offset(dst, tmp, 0, total);`，其 dst 来自 line 57 `merge_buffers(&out, &a, &b);` 中的 out；out.data 由 line 54 `out.data = (char *)malloc(MAX_BUF);` 分配、out.len 在 line 55 显式设为 MAX_BUF（=128，line 5）。
3. 入参上界被调用方封死：total 在 line 27 `int total = src1->len + src2->len;` 计算后，立即被 line 28 `if (total > MAX_BUF) { return -1; }` 拦截；main 中 src1/src2 的 len 来自 line 51-52 的 strlen("hello")/strlen(" world!")，分别为 5 与 7。
4. 写入区间核算：offset=0、src_len=total（≤128）、dst->len=128 → 写入区间 [0, total] ⊆ [0, 128]，line 18 在样本内全路径不越界；读侧 src 指向 malloc(total) 且已被 line 36-37 写满 total 字节，同样在界内。
5. 可达性纪律：line 14 的守卫不足只有在"调用方传入的 len 与分配容量不一致"时才被激活，需要样本外的敌意调用方。实测留痕：按敌意调用重放（外部 harness 传 1MB src_len 与 dst->len=128）可复现崩溃，证明缺陷真实，但触发条件在样本之外。
6. 处置：按样本内可达性纪律（与 1665 同口径）判 safe。非 CWE-120 因为样本内不存在可达的缓冲区复制越界（复制长度恒受 total ≤ MAX_BUF 与 dst->len = MAX_BUF 双重约束）；非 CWE-787 因为无任何越界写实际发生；非 CWE-125 因为读取侧 src 与写入侧同受该 total 上界约束。
7. 教学价值保留：line 17 的自述注释与缺陷本体原样保留，作为"API 契约设计缺陷 vs 样本内可达漏洞"的辨析教材；跨函数信任边界的加固建议写进 fix_suggestion 作防御纵深。""",
    verdict=dict(
        has_vulnerability=False,
        vulnerability_type="none",
        risk_level="None",
        source="N/A",
        sink="N/A",
        explanation="样本内全路径不可达越界：copy_at_offset（line 13）的守卫仅覆盖 offset（line 14），确缺 offset+src_len<=dst->len 校验，但唯一调用点 line 40 的目标缓冲由 line 54-55 按 MAX_BUF 分配并把 len 设为 128，且 total 已在 line 28 被 MAX_BUF 上界拦截 → 写入区间恒落在容量内。缺陷真实存在（敌意调用方可触发，实测已复现崩溃），但触发需要样本外敌意调用方，按样本内可达性纪律判 safe；非 CWE-120 因为不存在样本内可达的缓冲区复制越界；非 CWE-787 因为无越界写实际发生；非 CWE-125 因为读取侧同样受该上界约束。",
        fix_suggestion="no fix needed（防御纵深建议：line 14 守卫改为 if (offset < 0 || src_len < 0 || offset + src_len > dst->len) { return -1; }，使契约自洽、不依赖调用方配合）",
    ),
))

# ============ A2. 153 → safe（口径终裁，唯一调用点在检查之后） ============
ROWS.append(dict(
    line=153,
    old=(True, "CWE-121"),
    anchor="DRV_IOCTL_READ_REG",
    quotes=["for (i = 0; i < rio->buf_len; i++)",
            "dst[i] = (char)(rio->buf[i] ^ 0xA5);",
            "if (rio.buf_len > MAX_REG_BUF)",
            "drv_prepare_data(&rio, stack_buf);",
            "char stack_buf[MAX_REG_BUF];",
            "copy_to_user((void __user *)rio.buf, stack_buf, rio.buf_len)"],
    forbid=[],
    analysis="""分析过程：
1. 叙事主张的缺陷形态：drv_prepare_data（line 20）内 line 24 `for (i = 0; i < rio->buf_len; i++)` 以 rio->buf_len 为循环上界，line 25 `dst[i] = (char)(rio->buf[i] ^ 0xA5);` 同时写 dst（调用方传入的 128 字节栈数组 stack_buf，line 32）与读 rio->buf（struct reg_io 内 char[128]，line 15）—— 若 buf_len > 128 则读写双向越界。
2. 调用点核验（关键）：drv_prepare_data 在全样本内只有一个调用点 —— line 50，且它位于 `case DRV_IOCTL_READ_REG:`（line 44）分支内、严格排在 line 45 `if (rio.buf_len > MAX_REG_BUF) { ret = -EINVAL; goto unlock; }` 之后。
3. 边界封死：line 38 `copy_from_user(&rio, (void __user *)arg, sizeof(rio))` 拷入的 rio.buf_len 一旦 > MAX_REG_BUF（=128，line 10）即在 line 45-48 被拒并跳转 unlock，控制流根本到不了 line 50；line 51 的 `copy_to_user((void __user *)rio.buf, stack_buf, rio.buf_len)` 也同受该上界约束。
4. "仅调用方检查不算漏洞"的适用性：drv_ioctl（line 29）是该 ioctl 的解统一入口，不存在绕过 line 45 的第二条调用路径；被信任的是同一函数前几行刚校验过的同一变量，中间无任何可被外部改写的重赋值。因此原叙事"跨函数后信任了外部输入"的推论不成立。
5. 原叙事自相矛盾：其称"攻击者传入 buf_len = 256 越界 128 字节"，但 buf_len = 256 在 line 45 即被拒 —— 叙事假设与代码控制流直接冲突。
6. 处置：判 safe。非 CWE-121 因为样本内不存在可达的栈缓冲区溢出（写入长度上界 128 = stack_buf 容量）；非 CWE-787 因为无越界写发生；非 CWE-125 因为 rio.buf 的读取也同受该上界约束。跨函数防御纵深（drv_prepare_data 内部复校 buf_len）保留为加固建议，不计为样本内漏洞。""",
    verdict=dict(
        has_vulnerability=False,
        vulnerability_type="none",
        risk_level="None",
        source="N/A",
        sink="N/A",
        explanation="唯一调用点受上界保护：drv_prepare_data 的写入长度上界 rio->buf_len 在 line 45 已被 MAX_REG_BUF 拦截，且 line 50 是该函数在样本内的唯一调用点、位于拦截之后，故 dst（stack_buf，128 字节）与 rio.buf 的写入恒 ≤ 128。原文所称 buf_len=256 触发的情形在 line 45 即返回 -EINVAL，叙事与代码控制流冲突。按样本内可达性纪律判 safe；非 CWE-121 因为不存在可达的栈溢出；非 CWE-787 因为无越界写发生。",
        fix_suggestion="no fix needed（防御纵深建议：line 24 改为 for (i = 0; i < rio->buf_len && i < MAX_REG_BUF; i++)，使被调函数不依赖调用方的前置校验）",
    ),
))

# ============ A3. 218 → safe（口径终裁，全程持锁） ============
ROWS.append(dict(
    line=218,
    old=(True, "CWE-476"),
    anchor="SharedBuffer",
    quotes=["std::lock_guard<std::mutex> lock(mtx_);",
            "delete[] data_;",
            "data_ = new int[new_size];",
            "if (index >= size_) return -1;",
            "return data_[index];",
            "std::mutex mtx_;"],
    forbid=[],
    analysis="""分析过程：
1. 原叙事核心主张：resize 中 `delete[] data_;`（line 28）与 `data_ = new int[new_size];`（line 30）之间的窗口会被另一线程的 read 撞上（line 35-37），从而解引用悬垂指针 → 主张 CWE-476/416。
2. 锁域核验：SharedBuffer 的全部公开访问器持同一把 mtx_ —— allocate 在 line 16、resize 在 line 25、read 在 line 35、write 在 line 41，析构在 line 11，全部为 `std::lock_guard<std::mutex> lock(mtx_);` 并在整个临界区持有。
3. 并发可见性结论：read/write 必须在同一 mtx_ 上排队，只能观察到 resize 临界区结束后的完整状态（data_ 已重指向新块 line 30、size_ 已同步 line 31），不存在"已完成 delete 但尚未完成 new"的对外可见中间态 —— 原叙事的竞态窗口对持锁的 read/write 不可达。
4. 主流程核验：main（line 70）line 72 先 allocate(50)，再启动 t1=writer_thread（line 52，循环 line 54 `buf.resize(100);` + line 55 write）与 t2=reader_thread（line 60，line 62 `int val = buf.read(i);`），两线程仅在锁上互斥推进。
5. 越界与双重释放另核：line 36 `if (index >= size_) return -1;` 已在 line 37 解引用前做上界检查；data_ 仅在分配路径（line 18/28）与析构（line 12）各释放一次，无双重释放。
6. 残留瑕疵与语义不符：line 30 若 `new int[new_size]` 抛 bad_alloc，则 data_ 悬垂 —— 属异常安全缺陷（CWE-754 邻域），但该路径需宿主内存耗尽、样本内不可控不可达，且与 CWE-476 的定义（对 NULL 指针解引用）不符：代码从未把 data_ 置为 NULL 后解引用。
7. 处置：判 safe。非 CWE-476 因为不存在 NULL 解引用路径（data_ 初值 nullptr 在 line 8 构造，解引用前均有 line 36 上界与对象已构造保证）；非 CWE-416 因为无释放后解引用（无对外可见的悬垂窗口）；非 CWE-362 因为读写全程持同一把锁、不存在竞态窗口。"释放后置 nullptr + new 的异常安全"保留为防御纵深建议。""",
    verdict=dict(
        has_vulnerability=False,
        vulnerability_type="none",
        risk_level="None",
        source="N/A",
        sink="N/A",
        explanation="全程持同一把 mtx_：allocate/resize/read/write/析构分别在 line 16/25/35/41/11 持锁，resize 的 delete（line 28）与 new（line 30）之间不存在对其它线程可见的中间态，故原叙事主张的竞态窗口不可达。另核 line 36 已在 line 37 解引用前做上界检查，data_ 无双重释放，代码从未在置 NULL 后解引用 → 判 safe；非 CWE-476 因为无 NULL 解引用路径；非 CWE-416 因为无释放后解引用；非 CWE-362 因为不存在竞态窗口。",
        fix_suggestion="no fix needed（防御纵深建议：line 30 改用 data_ = new (std::nothrow) int[new_size]; 并判空，或先 new 成功再 delete 旧块，消除异常路径下的悬垂）",
    ),
))

# ============ A4. 1644 → safe（口径终裁，Python 无 UAF） ============
ROWS.append(dict(
    line=1644,
    old=(True, "CWE-416"),
    anchor="ConfigManager",
    quotes=["cls._instances[path] = loader",
            "del self._cache[filepath]",
            "self._loaded_files.append(filepath)",
            "return cls._instances.get(path)",
            "cached_loader._cache.get(path)"],
    forbid=[],
    analysis="""分析过程：
1. 语义前提核验：CWE-416（Use After Free）属内存安全类，成立前提是"内存被释放后仍可被解引用/重新分配给攻击者"。Python 为托管运行时，对象存活由引用计数 + 循环 GC 决定，不存在"提前释放但引用仍可解引用"的语义 —— 该类别对 GC 语言结构性不适用。
2. 引用生命周期核验：line 37 `cls._instances[path] = loader` 使 ConfigManager._instances（line 32）持有 loader 的强引用；line 23 `del self._cache[filepath]` 只删除 _cache 字典中的一个键，既不销毁 loader 对象，也不使任何 Python 引用悬垂；line 25 `self._loaded_files.append(filepath)` 仅追加路径字符串。
3. 危害路径核验：unload 之后 main 在 line 52 `cached_loader = ConfigManager.get_loader(path)` 经 line 40-41 `return self._instances.get(path)` 取回的是同一个存活对象；line 55 `data = cached_loader._cache.get(path)` 使用 dict.get()，键已被删时返回 None —— 既不抛 AttributeError，也不访问任何已释放内存；line 56 print(None) 无副作用。
4. 另核：_cache 属性本身从未被删除（line 23 只删键），故原叙事设想的"访问已被删除的 _cache 属性 → AttributeError"路径同样不成立。
5. 注释红鲱鱼：line 54 注释自述"（UAF场景）"、line 55 注释标"漏洞行：28"，是教学性的误导标注 —— 与样本内实际控制流不符。
6. 定性：唯一可议之处是"卸载后全局管理器仍保留对象引用"属引用生命周期与业务生命周期不同步的设计瑕疵，但无任何可达的危害路径，且不落入内存安全类。
7. 处置：判 safe。非 CWE-416 因为 GC 语言不存在释放后解引用语义，本样本亦无悬垂引用；非 CWE-476 因为无空指针解引用（line 53 `if cached_loader:` 已做真值检查，line 55 用 .get() 不出错）；非 CWE-672 因为对象未被销毁、引用仍有效。"卸载时同步注销全局引用"保留为代码整洁建议。""",
    verdict=dict(
        has_vulnerability=False,
        vulnerability_type="none",
        risk_level="None",
        source="N/A",
        sink="N/A",
        explanation="Python 托管运行时无 UAF 语义：line 37 的 _instances[path] = loader 持有强引用，对象在 unload（line 23 仅删 _cache 键）后仍存活；line 55 用 dict.get() 取已删键返回 None，无 AttributeError、无已释放内存访问；line 53 已做真值检查。源代码注释自述的 UAF/漏洞行标注与样本内控制流不符，属教学红鲱鱼。判 safe；非 CWE-416 因为 GC 语言不存在释放后解引用；非 CWE-476 因为无空指针解引用。",
        fix_suggestion="no fix needed（代码整洁建议：line 23 删除缓存后补 ConfigManager.unregister(filepath)，使全局引用生命周期与卸载语义同步）",
    ),
))

# ============ C1. 3446 → True/CWE-90（补投回收，教师裁决已落） ============
ROWS.append(dict(
    line=3446,
    old=(False, "CWE-none"),
    anchor="authenticateSafe",
    quotes=['String filter = "(uid=" + username + ")";',
            "return ldapTemplate.authenticate(searchBase, filter, password);",
            "LdapEncoder.filterEncode(username)",
            "public boolean authenticate(String username, String password)",
            'String userDn = "uid=" + username + ",ou=users,dc=example,dc=com";'],
    forbid=[],
    analysis="""分析过程：
1. 入口枚举（Java/Spring LDAP 认证服务，两个 public 方法均为可调用入口）：①line 24 `public boolean authenticate(String username, String password)` —— 其 javadoc（line 20）自述 username "未经任何转义"；②line 46 `public boolean authenticateSafe(String username, String password)`。
2. 污点链逐跳（vuln 路径 = authenticate）：
   跳1 line 24 方法签名 —— 调用方传入登录表单类外部输入；
   跳2 line 26 `String userDn = "uid=" + username + ",ou=users,dc=example,dc=com";` —— 用户输入拼入 DN（该变量在本方法内未被使用，但已显示拼接习惯）；
   跳3 line 30 `String filter = "(uid=" + username + ")";` —— 未中立化的用户输入直接进入 LDAP 查询表达式，`*` / `(` / `)` / `\\` / NUL 等元字符可改变查询结构（如 `*)(uid=admin))(|(uid=`）；
   跳4（sink）line 35 `return ldapTemplate.authenticate(searchBase, filter, password);` —— Spring LDAP 以该 filter 搜索目录并绑定认证，注入可改变匹配目标条目（认证逻辑操纵 / 目录结构枚举）。
3. 防御逐段核验：
   (a) authenticateSafe（line 46-64）确实示范了正确写法 —— line 48 `String safeUsername = LdapEncoder.filterEncode(username);` 后于 line 52 拼入 filter —— 但这只是同类中的另一个安全方法，**不构成对 authenticate 主路径的防御**：两方法各自独立可达，存在安全旁路方法不消除漏洞入口；
   (b) authenticateSafe line 49 的 userDn 拼接同样未做 DN 编码（LdapEncoder.filterEncode 只适用于 filter 语境，DN 分量应使用 nameEncode），且该变量为死代码 —— 不影响判定，仅作叙事注脚；
   (c) catch 块 line 36-40 仅吞异常返回 false，与注入无关。
4. 利用可行性：username 取 `*)(uid=*))(|(uid=*` 类载荷可改变 filter 结构 → authenticate 对非预期条目执行绑定流程；所需条件仅为应用把登录输入传入本方法（javadoc 自述使用场景），现实常见形态。
5. 原 False 判定的依据（"Spring LDAP 框架内部会强制转义 filter 参数 / 存在 authenticateSafe 示范"）不成立：框架的 authenticate(searchBase, filter, password) 不会再转义调用方传入的 filter 字符串；安全方法与漏洞方法是并列独立入口。
6. 处置：翻 True/CWE-90。非 CWE-862 因为目录访问存在认证流程，缺陷特定于查询表达式元字符未被中立化，而非缺失授权检查；非 CWE-639 因为不涉及对象键与属主的绑定；非 CWE-78/74 因为无命令执行或通用注入语义，注入目标是 LDAP 查询解释器；非 CWE-89 因为 sink 是 LDAP 而非 SQL 解释器。""",
    verdict=dict(
        has_vulnerability=True,
        vulnerability_type="CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
        risk_level="High",
        source="line 24: public boolean authenticate(String username, String password) — 调用方登录输入，javadoc（line 20）自述\"未经任何转义\"",
        sink="line 35: return ldapTemplate.authenticate(searchBase, filter, password); — 携带 line 30 `String filter = \"(uid=\" + username + \")\"` 的未中立化表达式",
        explanation="authenticate 主路径把用户输入直接拼入 LDAP 过滤器（line 30）后交 ldapTemplate.authenticate 执行（line 35），查询结构可被 `*` `(` `)` `\\` NUL 等元字符操纵（如 `*)(uid=admin))(|(uid=`）→ LDAP 注入，可导致认证逻辑操纵与目录枚举。原 False 依据不成立：authenticateSafe（line 46-64）的 LdapEncoder.filterEncode 转义只覆盖另一条并列入口，安全方法的存在不消除漏洞入口，两方法各自独立可达。非 CWE-862 因为存在认证流程、缺陷在于查询元字符未中立化而非缺授权检查；非 CWE-639 因为不涉及对象键属主绑定；非 CWE-78/74 因为注入目标是 LDAP 查询解释器而非命令/通用注入位；非 CWE-89 因为 sink 非 SQL。",
        fix_suggestion="line 30: 改为 String filter = \"(uid=\" + LdapEncoder.filterEncode(username) + \")\";（与 line 48 的 authenticateSafe 写法对齐）；若 DN（line 26）后续参与查询，DN 分量改用 LdapNameBuilder/nameEncode 构造；长期方案是 authenticate 内部直接复用 authenticateSafe，或删除未转义入口。",
    ),
))

# ============ C2. 3854 维持 safe + 叙事升级（标签不变） ============
ROWS.append(dict(
    line=3854,
    old=(False, "CWE-none"),
    anchor="safe_csv_field",
    quotes=["action_filter = request.GET.get('action', 'all')",
            "action_filter.replace(';', '').replace('--', '')",
            "logs = ActivityLog.objects.filter(user=user)",
            "log.action.startswith(action_filter)",
            "if value.startswith(('=', '+', '-', '@')):",
            "response['Content-Disposition'] = 'attachment; filename=\"activity_logs.csv\"'"],
    forbid=[],
    analysis="""分析过程：
1. 入口枚举（Django CSV 导出视图，装饰器 @login_required（line 9）+ @require_GET（line 10））：①line 18 `action_filter = request.GET.get('action', 'all')` —— 唯一外部输入；②line 16 `user = request.user` —— 认证上下文。
2. 污点链逐跳：
   跳1 line 18：用户可控字符串进入 action_filter；
   跳2 line 22 `action_filter = action_filter.replace(';', '').replace('--', '')` —— 无实际安全语义的清洗（对 Python 侧过滤既不必要也无害，是样本预设的"防御迷惑点"）；
   跳3 line 34 `logs = [log for log in logs if log.action.startswith(action_filter)]` —— action_filter 仅作为 **Python 字符串前缀匹配参数**，不进入任何解释器（无 SQL / 命令 / 路径 / 模板语义）；
   跳4 line 27 `logs = ActivityLog.objects.filter(user=user)` —— ORM 参数化查询，user 为认证上下文而非外部自由文本，无注入位；
   跳5（写出侧）line 52-56 `writer.writerow([safe_csv_field(log.timestamp), safe_csv_field(log.action), safe_csv_field(log.details)])` —— 导出内容逐字段经 safe_csv_field 处理。
3. 防御逐段核验：
   (a) line 43-49 safe_csv_field：对以 `=`、`+`、`-`、`@` 开头的值加单引号前缀（line 47-48 `if value.startswith(('=', '+', '-', '@')): return "'" + value`）—— CSV 公式注入的标准缓解，timestamp/action/details 三个写出字段全覆盖；
   (b) line 59-60：`response = HttpResponse(output.getvalue(), content_type='text/csv')` 与 `response['Content-Disposition'] = 'attachment; filename="activity_logs.csv"'` —— Content-Type 固定、文件名静态，无响应头注入；
   (c) 全文件无 eval/exec/os.system/subprocess/路径拼接。
4. 利用可行性：不存在可达污点链 —— action_filter 止于 Python 内存比较，log 字段写出前已被公式注入防御覆盖。
5. 注释红鲱鱼：line 20-24 注释自述"看似用 replace 清理，实际未阻断注入""CWE-943 关注数据导出逻辑的注入，比如 CSV 公式注入"—— 该叙述为教学性误导：注释自称的"未做严格校验"只影响过滤结果集大小，不构成注入；且 CWE-943 的对象是数据查询逻辑（ORM/HQL/NoSQL），本样本已参数化。
6. 处置：维持 safe，按教师裁决升级叙事（本次仅叙事升级，has_vulnerability 与 vulnerability_type 均不变）。非 CWE-943 因为 ORM filter 已参数化、跨层查询注入位不存在；非 CWE-1236 因为 CSV 导出字段已做公式注入前缀转义；非 CWE-79 因为响应为纯附件下载、无 HTML 反射上下文。""",
    verdict=dict(
        has_vulnerability=False,
        vulnerability_type="none",
        risk_level="None",
        source="line 18: action_filter = request.GET.get('action', 'all') — 唯一外部输入，止于 Python 前缀比较",
        sink="line 52-56: writer.writerow([...]) — 导出字段已经 safe_csv_field（line 43-49）前缀转义，无解释器注入位",
        explanation="全文件无可达污点链：外部输入（line 18）经 line 22 的无害 replace 后仅用于 Python 字符串前缀匹配（line 34），不进入 SQL/命令/路径/模板解释器；line 27 的 ORM 查询已参数化；CSV 公式注入被 line 47-48 的 `=`,`+`,`-`,`@` 前缀单引号防御覆盖；line 59-60 的 Content-Type 与文件名均静态。源代码注释自称的 CWE-943/CSV 公式注入属教学红鲱鱼 → 判 safe；非 CWE-943 因为查询逻辑已参数化；非 CWE-1236 因为导出字段已公式注入转义；非 CWE-79 因为无 HTML 反射上下文。",
        fix_suggestion="no fix needed（可选加固：line 30 的 action_filter 改为枚举白名单校验，属代码整洁而非漏洞修复）",
    ),
))

# ============ C3. 7900 → safe（NVD 锚定铁证：修复后语义被标成漏洞侧） ============
ROWS.append(dict(
    line=7900,
    old=(True, "CWE-90"),
    anchor="X509LDAPCertStoreSpi",
    quotes=["return filterEncode(temp);",
            "private String filterEncode(String value)",
            "private String parseDN(String subject, String subjectAttributeName)",
            "String attrValue = parseDN(subject, subjectAttributeName);"],
    forbid=[],
    analysis="""分析过程：
1. 文件定性（对照 CVE-2023-33201 / GHSL-2023-045）：本文件是 BouncyCastle X509LDAPCertStoreSpi，含 RFC2254 转义表与 filterEncode —— line 68-72 `FILTER_ESCAPE_TABLE['*'] = "\\\\2a";` / `'(' = "\\\\28"` / `')' = "\\\\29"` / `'\\\\' = "\\\\5c"` / `[0] = "\\\\00"`（覆盖 `* ( ) \\ NUL` 全部危险元字符），line 427 `private String filterEncode(String value)` 实现转义，line 129 `private String parseDN(String subject, String subjectAttributeName)` 的出口在 line 162 为 `return filterEncode(temp);`。
2. 攻击者影响面与污点链：影响面 = 证书验证场景下攻击者自签证书的 Subject/Issuer DN。污点链逐跳：
   跳1 line 266 `.getSubjectX500Principal().getName("RFC1779")` —— 攻击者可控 DN 字符串；
   跳2 line 282 `String attrValue = parseDN(subject, subjectAttributeName);` —— 进入 DN 解析；
   跳3 line 162 `return filterEncode(temp);` —— parseDN 出口对值做 RFC2254 转义；
   跳4 line 283 `set.addAll(search(attrName, "*" + attrValue + "*", attrs));` —— 已转义值作为子串匹配进 filter（外层 `*` 为字面量通配，属预期语义）；
   跳5（最终查询）line 466 `private Set search(String attributeName, String attributeValue, ...)` 内以 `attributeName + "=" + attributeValue` 组装后交 ctx.search。
3. 防御逐段核验（对照 CVE 漏洞形态"certificate's Subject Name inserted into LDAP filter without any escaping"，PoC `CN=Subject*)(objectclass=`）：
   (a) 证书侧路径（line 282-283）与 CRL 侧路径（line 379、385、388）的攻击者值**全部**先经 parseDN → filterEncode 才进 search —— CVE 所述的未转义路径在本文件不存在；
   (b) serial 路径（line 289 附近）的 attrValue 来自序列号数字串，无元字符；
   (c) 其余插值来自 params（开发者配置的 X509LDAPCertStoreParameters），非攻击者面；
   (d) 对照上游修复 commit e8c409a8（新增 FILTER_ESCAPE_TABLE + filterEncode 并包装 search 入参）：本文件已含转义表与 filterEncode 方法、parseDN 出口已包装；残留差异仅是 search() 内未对 attributeValue 二次包装 filterEncode（上游的防御纵深行），但所有调用点传入值均已转义，不构成可达注入。
4. 利用可行性：按 CVE 攻击路径重放（自签证书 Subject = `CN=Subject*)(objectclass=`）：parseDN 提取后经 filterEncode 输出 `Subject\\2a\\29\\28objectclass\\3d`，查询结构不可被改变 → 不可利用。
5. 处置：翻 safe。原标签 True/CWE-90 是把**修复后语义**标成了漏洞侧，与行 7901（同一类的未修复修订，却被标 safe）恰好构成"标签互为颠倒"的差分对。非 CWE-90 因为查询元字符已被中立化、过滤结构不可被攻击者改变；非 CWE-295 因为证书验证流程本身无缺陷（NVD 对 CVE-2023-33201 绑 295 针对的是 pre-1.74 未转义版本，本文件非该形态）；非 CWE-94 因为不存在动态代码执行。""",
    verdict=dict(
        has_vulnerability=False,
        vulnerability_type="none",
        risk_level="None",
        source="N/A",
        sink="N/A",
        explanation="本文件为 CVE-2023-33201 修复后语义的库代码：Subject/Issuer 经 parseDN（line 129/282）→ filterEncode（line 162/427，RFC2254 表 line 68-72 覆盖 * ( ) \\ NUL）后才进 line 283/388 的 search，serial 为数字串，其余插值来自开发者配置 → 判 safe。按 CVE-2023-33201 攻击路径重放（自签证书 Subject=`CN=Subject*)(objectclass=`）时 filterEncode 输出转义序列，查询结构不可改变。原标签 True/CWE-90 系把修复后代码标成漏洞侧，与行 7901（未修复修订却标 safe）互为颠倒；非 CWE-90 因为元字符已中立化；非 CWE-295 因为本文件非 pre-1.74 未转义形态。",
        fix_suggestion="no fix needed（若作为差分对教材：本行为 safe 侧，可补一句防御纵深建议 —— search() 内对 attributeValue 二次 filterEncode，与上游修复 commit e8c409a8 的包装做法对齐）",
    ),
))

# ============ C4. 7901 → True/CWE-90（连带新发现，NVD 锚定 pre-fix 形态） ============
ROWS.append(dict(
    line=7901,
    old=(False, "CWE-none"),
    anchor="X509LDAPCertStoreSpi",
    quotes=["String attrValue = LDAPUtils.parseDN(subject, subjectAttributeName);",
            'set.addAll(search(attrName, "*" + attrValue + "*", attrs));',
            "private Set search(String attributeName, String attributeValue,",
            'String filter = attributeName + "=" + attributeValue;'],
    forbid=["filterEncode", "FILTER_ESCAPE_TABLE"],
    analysis="""分析过程：
1. 文件定性：本文件与行 7900 同属 BouncyCastle X509LDAPCertStoreSpi，但为**更老的修订版** —— 全文件无 FILTER_ESCAPE_TABLE、无 filterEncode（字符串级检索均为 0 处），DN 解析依赖外部工具类 `LDAPUtils.parseDN`。这正是 CVE-2023-33201 / GHSL-2023-045 所述的 pre-1.74 形态（"certificate's Subject Name inserted into an LDAP search filter without any escaping"）。
2. 攻击者影响面：证书验证场景下攻击者自签证书的 Subject / Issuer DN（经 X509CertSelector / X509CRLSelector 进入 engineGetCertificates / engineGetCRLs）。
3. 污点链逐跳：
   跳1 line 209 `.getSubjectX500Principal().getName("RFC1779")` —— 攻击者可控 DN 字符串；
   跳2 line 225 `String attrValue = LDAPUtils.parseDN(subject, subjectAttributeName);` —— 解析后的值**不做任何转义**（对比 7900 的 line 162 `return filterEncode(temp);`，本文件对应出口无包装）；
   跳3（sink 入口）line 226 `set.addAll(search(attrName, "*" + attrValue + "*", attrs));` —— 未转义值直接以字符串拼接进入 LDAP 过滤器；CRL 侧同型路径见 line 322 / 328 / 331；
   跳4（最终查询）line 373 `private Set search(String attributeName, String attributeValue, ...)` 内 line 377 `String filter = attributeName + "=" + attributeValue;` → line 398 `String filter2 = "(&(" + filter + ")(" + temp[0] + "=*))";` → line 403-404 `ctx.search(params.getBaseDN(), filter2, constraints)` —— filter 结构完全由拼接结果决定。
4. 利用可行性：攻击者证书 Subject 取 `CN=Subject*)(objectclass=`（CVE 官方 PoC 形态）时，`*` `(` `)` `=` 元字符直接改变 filter 结构，可扩大匹配集、枚举目录条目或操纵证书检索结果 —— 与 CVE-2023-33201 描述的可注入形态一致，真实可利用。
5. 防御核验：无过滤函数、无转义表、search() 内无白名单/参数化；唯一的"缓解"是其调用方（证书选择器）本应由宿主应用约束，但证书 Subject 本身即由被验证方提供，属典型不可信输入。
6. 处置：翻 True/CWE-90。CWE 口径留痕 —— NVD 对 CVE-2023-33201 的 CWE 字段绑定 CWE-295（source=nvd@nist.gov, type=Primary），但 NVD 同一记录的描述原文为 "leads to an LDAP injection vulnerability"，即 NVD 描述与 CWE 字段不自洽；CWE-295（Improper Certificate Validation）描述的是"为什么该洞要紧"（发生在证书校验路径），CWE-90（Improper Neutralization of Special Elements used in an LDAP Query）描述的才是缺陷本身。本行取 MITRE 机制类 CWE-90：与本代码机制字面命中，与库内 3446 等 LDAP 判例同源，且在 22 类训练目标清单内；CWE-295 分歧在此显式记录备查。
7. 差分对价值：本行（pre-fix，判 vuln）与行 7900（post-fix，判 safe）构成同库两修订版的标签对齐对，是"NVD 官方 advisory + 代码修订对照"锚定的翻案，非模型循环裁决。非 CWE-295 的取舍理由见上（记录分歧、不否认其存在）；非 CWE-89 因为 sink 是 LDAP 而非 SQL 解释器；非 CWE-94 因为无动态代码执行。""",
    verdict=dict(
        has_vulnerability=True,
        vulnerability_type="CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
        risk_level="High",
        source="line 209: .getSubjectX500Principal().getName(\"RFC1779\") — 被验证方提供的证书 Subject DN，攻击者可控",
        sink="line 226: set.addAll(search(attrName, \"*\" + attrValue + \"*\", attrs)); — 携带 line 225 经 LDAPUtils.parseDN 未转义的 attrValue；最终落在 line 377/398/403 的 ctx.search",
        explanation="pre-1.74 未转义形态（CVE-2023-33201 / GHSL-2023-045）：全文件无 FILTER_ESCAPE_TABLE、无 filterEncode，证书 Subject 经 line 225 LDAPUtils.parseDN 解析后原样拼入 line 226 的 filter，`*` `(` `)` `=` 元字符可改变查询结构（PoC `CN=Subject*)(objectclass=`）→ 真实可利用。与行 7900（同类的 post-fix 修订，已含 RFC2254 转义表与 filterEncode）构成标签对齐的差分对。CWE 口径留痕：NVD 对 CVE-2023-33201 的 CWE 字段绑定 CWE-295，但其描述原文自述 \"LDAP injection\"，二者不自洽；本行按 MITRE 机制类定义取 CWE-90（与库内 3446 判例同源、在 22 类目标清单内），CWE-295 分歧记录备查。非 CWE-89 因为 sink 非 SQL 解释器；非 CWE-94 因为无动态代码执行。",
        fix_suggestion="line 225 后对 attrValue 施加 RFC2254 转义（对齐上游修复 commit e8c409a8 的 FILTER_ESCAPE_TABLE + filterEncode 做法，`*`→`\\\\2a`、`(`→`\\\\28`、`)`→`\\\\29`、`\\\\`→`\\\\5c`、NUL→`\\\\00`）；line 331 的 CRL 侧同型路径一并处理；根本方案是升级到含 filterEncode 的修订版（即本库 7900 行的形态）。",
    ),
))

# ============ D1. 3531 → True/CWE-787（safe-硬崩翻案） ============
ROWS.append(dict(
    line=3531,
    old=(False, "CWE-none"),
    anchor="payload_len",
    quotes=["char header[MAX_HEADER_LEN];",
            "char payload[MAX_PKT_LEN];",
            "size_t payload_len;",
            "buf = (char *)malloc(MAX_HEADER_LEN + MAX_PKT_LEN);",
            "pkt = (packet_t *)buf;",
            "pkt->payload_len = input_len - MAX_HEADER_LEN;",
            "process_packet(test_data, sizeof(test_data));"],
    forbid=[],
    analysis="""分析过程：
1. 结构体容量核算：packet_t（line 8-12）为 `char header[MAX_HEADER_LEN]`（line 9，MAX_HEADER_LEN=8，line 6）+ `char payload[MAX_PKT_LEN]`（line 10，MAX_PKT_LEN=128，line 5）+ `size_t payload_len`（line 11）。成员偏移为 header@0、payload@8、payload_len@136（136 满足 8 字节对齐），对象完整尺寸 = 136 + sizeof(size_t) = 144 字节。
2. 分配容量核算：line 46 `buf = (char *)malloc(MAX_HEADER_LEN + MAX_PKT_LEN);` 只申请 8 + 128 = 136 字节 —— 恰好等于 payload_len 字段的起始偏移，**缺了该字段自身的 8 字节**。
3. 越界写入定位（sink）：line 59 `pkt = (packet_t *)buf;` 把 136 字节块当成 packet_t 解释，line 60 `pkt->payload_len = input_len - MAX_HEADER_LEN;` 以 size_t 宽度写在偏移 [136, 144) —— 完全落在 136 字节分配之外，属堆上越界写 8 字节。
4. 触发条件（直线可达，无需敌意调用方）：main（line 70）line 74 `process_packet(test_data, sizeof(test_data));` 即以合法入参调用：input_len=128 ≥ MAX_HEADER_LEN（line 41 的拒绝条件不命中），parse_packet（line 15）的 line 19 `raw_len > MAX_PKT_LEN`（128 > 128 为假）与 line 24 `out_cap < MAX_HEADER_LEN + MAX_PKT_LEN`（136 < 136 为假）两项检查均通过 → 控制流直线抵达 line 60。
5. 前置检查为何失效：line 23-26 的 out_cap 检查只保证"写 header + payload 够用"（要求 ≥ 136），而其阈值与 line 46 的 malloc 实参同源（都写 MAX_HEADER_LEN + MAX_PKT_LEN），二者自洽地漏掉了尾部 payload_len 字段 —— 这是"分配尺寸与结构体尺寸不一致"的典型根因，静态/运行都表现为"看似处处有边界检查"。
6. 危害：越界写的 8 字节位于紧随 malloc 块之后的堆块头/邻接数据，可破坏堆元数据；line 64 `free(buf);` 时的堆链表操作可被利用（unlink 类攻击原语）。
7. 定性：现标签 False（safe）系漏报。实测与读码双证一致（同一函数在同等入参下崩溃）。按本行终裁口径取 CWE-787（Out-of-bounds Write，通用父类）；本判定同时与 CWE-122（Heap-based Buffer Overflow）同族 —— 若按库内 CVE-2023-38545 判例（堆型取更具体子类 122）亦可归 122，本行保留 787 为 top-1 并在本处记录 122 语义。非 CWE-120 因为缺陷不在 memcpy 的复制长度（line 29/31 的复制长度受 out_cap 约束），而在结构体字段写入超出分配；非 CWE-125 因为缺陷在写入侧。""",
    verdict=dict(
        has_vulnerability=True,
        vulnerability_type="CWE-787 Out-of-bounds Write",
        risk_level="High",
        source="line 46: buf = (char *)malloc(MAX_HEADER_LEN + MAX_PKT_LEN); — 只分配 136 字节，而 packet_t 需 144 字节",
        sink="line 60: pkt->payload_len = input_len - MAX_HEADER_LEN; — size_t 宽度写在偏移 [136,144)，超出 136 字节分配",
        explanation="分配尺寸与结构体尺寸不一致导致堆越界写 8 字节：packet_t 为 header[8] + payload[128] + size_t payload_len，payload_len 位于偏移 136、对象尺寸 144（line 8-12），而 line 46 只 malloc(8+128)=136；line 59 把该块当作 packet_t 后，line 60 对 pkt->payload_len 的写入完全落在分配之外。触发为直线路径：line 74 的合法调用即可抵达，line 19/24 的前置检查阈值与 line 46 的 malloc 同源、自洽地漏掉尾部字段 → 前置检查全部通过。越界字节覆盖堆块元数据，line 64 free 时可被利用。判定与 CWE-122（Heap-based Buffer Overflow）同族，本行按终裁口径取通用父类 CWE-787，122 语义记录于此；非 CWE-120 因为复制长度受 out_cap 约束而非复制越界；非 CWE-125 因为缺陷在写入侧。",
        fix_suggestion="line 46: 改为 buf = (char *)malloc(sizeof(packet_t));（或 MAX_HEADER_LEN + MAX_PKT_LEN + sizeof(size_t)）；line 24: out_cap 阈值同步改为 sizeof(packet_t)（或显式校验 out_cap < sizeof(packet_t)），使分配、解释与校验三者尺寸一致。",
    ),
))

# ============ D2. 3762 → True/CWE-415（safe-硬崩翻案） ============
ROWS.append(dict(
    line=3762,
    old=(False, "CWE-none"),
    anchor="safe_free_buffer",
    quotes=["buf->data = NULL;",
            "free(buf);",
            "if (!buf || !buf->data) {",
            "safe_free_buffer(my_buf);",
            "process_buffer(my_buf);",
            "free(my_buf);"],
    forbid=[],
    analysis="""分析过程：
1. 释放次数清点：safe_free_buffer（line 23）在 line 25 `free(buf->data);` 释放 data 块、line 26 置 NULL、line 27 `free(buf);` **释放结构体本身** —— 即调用一次会释放两个对象，且 line 28 注释自述"buf本身未被置NULL，但调用方负责"，调用方持有的 my_buf 指针因此悬垂。
2. 双重释放定位（sink）：main（line 43）line 44 `Buffer *my_buf = create_buffer(100);` 建对象；line 51 `safe_free_buffer(my_buf);` 内已 free(my_buf)；line 57 `free(my_buf);` 对同一地址再次 free —— 这是直线代码：line 57 之后仅剩 line 59 `return 0;`，中间无任何分支可跳过，故 line 57 必然执行 → 双重释放（CWE-415）。line 56 的注释自称"这里不会执行，因为逻辑上不会走到"，与代码实际完全不符。
3. 悬垂解引用定位（同源伴生）：line 54 `process_buffer(my_buf);  // line 45: 再次使用 - 安全` 的"安全"标注不成立 —— line 51 已 free(my_buf)，line 54 传入的是悬垂指针；process_buffer 的 line 33 `if (!buf || !buf->data) {` 必须先解引用 buf 才能读 buf->data，读取已释放内存即 UAF（CWE-416）。
4. 原 False 判定的错误来源（逐条）：
   (a) 其称"line 26 置 NULL + line 33 空指针检查完全阻断了 UAF 路径"—— 该组合只保护 data 成员，无法保护结构体本身；line 51 释放的是 buf 结构体，line 54 读取的也是 buf 结构体，置 NULL 的却是 buf->data，保护对象错位；
   (b) 其称"main 在第 46 行 return（实际执行路径不会到达 free(my_buf)）"—— 与代码顺序（line 44 建对象 → line 49/51/54 → line 57 free → line 59 return）不符，line 57 并无前置分支。
5. 触发条件：直线可达，line 51 + line 57 两次 free 同一地址，无需任何敌意输入 —— 属必然发生的缺陷而非条件漏洞。
6. 危害：同一堆块被两次交还分配器，破坏堆管理结构；在升序 free 与后续分配场景下可导致同地址被重复分配（对象重叠）进而被利用为任意写。
7. 主判 CWE-415（双重释放，直线必执行、后果最确定）；line 54 对已释放结构体的读取按 CWE-416 记为同源伴生缺陷。非 CWE-476 因为 line 33 的空检查无 NULL 路径（指针非空、只是已释放）；非 CWE-120 因为无缓冲区复制越界。""",
    verdict=dict(
        has_vulnerability=True,
        vulnerability_type="CWE-415 Double Free",
        risk_level="High",
        source="line 51: safe_free_buffer(my_buf); — line 27 内 free(buf) 已释放 my_buf 结构体，且未将调用方指针置空（line 28 注释自述）",
        sink="line 57: free(my_buf); — 对 line 51 已释放的同一地址再次 free；line 57 后仅剩 line 59 return 0，无分支可跳过，必然执行",
        explanation="双重释放直线可达：safe_free_buffer（line 23）在 line 27 free(buf) 把结构体交还分配器，调用方 my_buf 因此悬垂；main 的 line 57 free(my_buf) 对同一地址二次释放，且其后不存在任何可跳过该行的分支，故必然执行。原 False 判定的两条依据均不成立：line 26 的 buf->data = NULL 与 line 33 的空指针检查只保护 data 成员，保护对象与释放对象（结构体）错位；其'执行路径不会到达 free(my_buf)'的断言与代码顺序冲突。同源伴生缺陷：line 54 process_buffer(my_buf) 在 line 51 之后解引用已释放结构体（line 33 需先读 buf->data），构成 UAF（CWE-416）。非 CWE-476 因为无 NULL 路径（指针非空、仅已释放）；非 CWE-120 因为无复制越界。",
        fix_suggestion="line 57: 删除该行（line 51 已释放 my_buf）；或改为 safe_free_buffer 内 line 27 之后由调用方把指针置空，并将释放接口统一为 'Buffer **p' 形态（释放后 *p = NULL），从根本上消除调用方持有悬垂指针的可能；line 54 的再度使用应删除或改为重新创建对象。",
    ),
))

# ============ L1-1. 7090 → CWE-915 改判 CWE-94（NVD 官方绑定 + 清单内） ============
ROWS.append(dict(
    line=7090,
    old=(True, "CWE-915"),
    anchor="ProfileForm",
    quotes=['@PostMapping("/profile/update")',
            "public String update(ProfileForm form)",
            "class ProfileForm",
            "form.getDisplayName()"],
    forbid=[],
    analysis="""分析过程：
1. 代码事实：ProfileController（line 7）在 line 9 `@PostMapping("/profile/update")` + line 11 `public String update(ProfileForm form)` 上以复合对象形参接收请求参数（Spring MVC 对非简单类型形参默认按 @ModelAttribute 处理），line 12 `return "ok " + form.getDisplayName();` 回显绑定结果。
2. 绑定机制核验：形参类型 ProfileForm（line 16-20）是含 setter 的 POJO，Spring 默认 WebDataBinder 会按请求参数名**递归写入嵌套属性路径**（`a.b.c` 形式）—— 这正是 CVE-2022-22965（Spring4Shell）的入口形态：攻击者构造属性链（`class.module.classLoader...`）把外部输入写到框架内部对象，终点是落在可代码执行的配置位（Tomcat AccessLogValve 的 pattern / fileDateFormat → 写入 web 根目录的 JSP → 请求即执行）。
3. 判定依据：NVD 对 CVE-2022-22965 官方绑定 CWE-94（Improper Control of Generation of Code）；CWE-94 亦在本项目 22 类训练目标清单内。
4. 邻类辨析：CWE-915（Improperly Controlled Modification of Dynamically-Determined Object Attributes）描述的是"受外部影响的属性被写入"这一**前置机制**，其本身不是本样本的终局危害 —— 危害终点是攻击者输入经属性链抵达可生成并执行代码的配置位（RCE），因此以 CWE-94 为主判，CWE-915 语义作为前置机制记录。
5. 处置：has_vulnerability 维持 True，vulnerability_type 由 CWE-915 改判 CWE-94。非 CWE-915 作为 top-1 因为其语义停在"属性被写"，未覆盖代码生成与执行这一终局危害；非 CWE-89/78 因为注入目标不是 SQL/命令解释器；非 CWE-1336 因为 sink 非模板引擎渲染位（本样本是框架绑定→配置写入链）。""",
    verdict=dict(
        has_vulnerability=True,
        vulnerability_type="CWE-94 Improper Control of Generation of Code ('Code Injection')",
        risk_level="Critical",
        source="line 11: public String update(ProfileForm form) — HTTP 请求参数经 WebDataBinder 按参数名递归绑定进复合对象，外部可控",
        sink="line 11/12: @ModelAttribute 自动绑定（对象图属性链写入终点；CVE-2022-22965 形态为 class.module.classLoader.resources.context.parent.pipeline.first.* → 写入 JSP），line 12 form.getDisplayName() 展示绑定结果",
        explanation="Spring MVC 对复合形参的默认 @ModelAttribute 绑定允许攻击者按参数名递归写入嵌套属性路径（line 11 的 ProfileForm 形参），构成 CVE-2022-22965 的入口形态：属性链可达框架内部对象并最终落到可代码执行的配置位（AccessLogValve pattern → 写 JSP → RCE），故判 CWE-94（NVD 对 CVE-2022-22965 的官方绑定，且在 22 类目标清单内）。CWE-915（动态属性修改）作为前置机制保留注记，但不作 top-1，因为其语义停在'属性被写入'、未覆盖代码生成与执行。非 CWE-89/78 因为注入目标非 SQL/命令解释器；非 CWE-1336 因为 sink 非模板渲染位。",
        fix_suggestion="line 11: 对绑定对象使用 @InitBinder 的 setAllowedFields / setDisallowedFields 白名单，或改用显式 @RequestParam 逐字段接收；升级 Spring Framework 至修复版（≥5.3.18 / 5.2.20）并同步 Tomcat 修复；对 form 对象禁用 class / classLoader 相关属性路径。",
    ),
))

# ============ L1-2. 7573 → safe（sink 不在切片内，对码不过） ============
ROWS.append(dict(
    line=7573,
    old=(True, "CWE-22"),
    anchor="resolve_privacy_filter_model",
    quotes=["def resolve_privacy_filter_model(",
            "return model_name",
            "actual_model = resolve_privacy_filter_model(model_name, backend)"],
    forbid=["open("],
    analysis="""分析过程：
1. 切片范围核验：本样本是 OpenMed 推理后端文件的切片组合 —— ①函数 resolve_privacy_filter_model（切片内以原始行号 `216|` 起的段，函数体至 `243| return model_name`）；②文件级上下文（imports / 全局常量 / 类骨架）；③函数 create_privacy_filter_pipeline 的切片（末尾 `246| def create_privacy_filter_pipeline(...)` 段）。
2. 原叙事的关键引文不存在（对码失败）：其主张 sink 为某行 `open(` —— 把 model_name 当作本地路径打开。全样本检索：`open(` 出现 **0 处**；resolve_privacy_filter_model 的返回路径只有 `243| return model_name`（模型名原样透传）与 MLX 分支的同类 return，全函数无任何文件系统调用，也无路径拼接（无 os.path.join / pathlib.Path / open）。
3. 唯一外部输入的去向：model_name 仅参与 `230| if "mlx" in (model_name or "").lower():` 的字符串包含判断、`231| target = _torch_fallback_for(model_name)` 的查表替换（常量表 _TORCH_FALLBACK_BY_FAMILY 为框架内定义的模型名清单）、以及 `241| _warned_substitutions.add(model_name)` 的集合记录 —— 全部是内存侧字符串操作，不产生解释器污染。
4. 调用点核验：切片末尾 `254| actual_model = resolve_privacy_filter_model(model_name, backend);` 仅把返回值转交后续 pipeline 构造（create_mlx_pipeline / PrivacyFilterTorchPipeline），切片内无文件打开、无目录遍历语义。
5. 结论：按"teacher 引文必须对码"政策（20260909 成文），原叙事的关键引文（`open(`）在本样本中不存在，分析-代码错配，**在证性不成立**；即使补全文件，"模型名 → 本地打开"也更接近任意文件读或正常 API 形态，而 CWE-22 所要求的"逃逸受限目录"语义在切片内完全无从证实。
6. 处置：翻 safe（原标签 True/CWE-22 属未对码的过度归因）。非 CWE-22 因为切片内不存在路径构造与目录逃逸点（无 open/Path/join）；非 CWE-918 因为不存在服务端以外部 URL 取回内容；非 CWE-73 同理因为无外部控制的路径名。""",
    verdict=dict(
        has_vulnerability=False,
        vulnerability_type="none",
        risk_level="None",
        source="N/A",
        sink="N/A",
        explanation="切片内无 CWE-22 所需的任何要素：resolve_privacy_filter_model 对 model_name 只做字符串包含判断（`230| if \"mlx\" in (model_name or \"\").lower():`）、常量表查表（`231|`）与集合记录（`241|`），返回路径为 `243| return model_name` 原样透传；全样本 `open(` 出现 0 处，无路径拼接、无目录逃逸点。原叙事所引 sink（`open(`）在样本中不存在，按'teacher 引文必须对码'政策在证性不成立 → 判 safe。非 CWE-22 因为无路径构造与逃逸点；非 CWE-918 因为无服务端外部取回；非 CWE-73 因为无外部控制的路径名。",
        fix_suggestion="no fix needed（如后续补全整文件仍要主张路径语义，需先给出样本内可对码的 sink 行；建议在数据侧校验该类切片的 sink 行必须落在切片范围内）",
    ),
))

# ---------------------------------------------------------------- 主流程

DRY = "--dry-run" in sys.argv

rows = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
N0 = len(rows)
print(f"载入 {DATA.name}：{N0} 行{'（DRY-RUN，不写盘）' if DRY else ''}")

# 2) 逐行断言 + 替换
changelog = []
stat = {"翻案": 0, "改类": 0, "叙事升级": 0}

for spec in ROWS:
    ln = spec["line"]
    row = rows[ln - 1]

    # 2.1 用户内容指纹断言（确认改的是正确行）
    assert spec["anchor"] in json.dumps(row, ensure_ascii=False), \
        f"行 {ln} 用户内容指纹缺失：{spec['anchor']}"
    code = code_of(row)
    for q in spec["quotes"]:
        assert q in code, f"行 {ln} 引文对码失败（用户代码块中找不到）：{q!r}"
    for f in spec["forbid"]:
        assert f not in code, f"行 {ln} 互斥标记本应缺席却出现：{f!r}"

    # 2.2 旧结论断言
    old_now = verdict(ga(row))
    assert old_now == spec["old"], \
        f"行 {ln} 旧结论与预期不符：实际 {old_now}，预期 {spec['old']}（文件可能已变更）"

    # 2.3 生成新 assistant 内容
    v = mk_verdict(**spec["verdict"])
    if not v["has_vulnerability"]:
        v["vulnerability_type"] = v["vulnerability_type"] or "none"
    new_a = spec["analysis"].rstrip() + "\n\n```json\n" + json.dumps(v, ensure_ascii=False) + "\n```\n"
    new_v = verdict(new_a)
    assert new_v[0] is not None, f"行 {ln} 新内容 JSON 解析失败"

    sa(row, new_a)

    # 2.4 归类统计
    if old_now[0] != new_v[0]:
        kind = "FLIP"
        stat["翻案"] += 1
    elif old_now[1] != new_v[1]:
        kind = "RECLASS"
        stat["改类"] += 1
    else:
        kind = "NARRATIVE"
        stat["叙事升级"] += 1

    changelog.append({
        "date": "2026-09-10",
        "step": "3.1_final_adjudication_v2_17",
        "action": kind,
        "row_line": ln,
        "old_verdict": [old_now[0], old_now[1]],
        "new_verdict": [new_v[0], new_v[1]],
        "note": spec.get("note", f"{kind}：{old_now[1]} → {new_v[1]}"),
        "basis": "口径终裁_决策卡_20260910 / L1待人工_12项_裁决卡_20260910 / retake2 教师裁决 / NVD 官方 advisory",
        "label_basis": "nvd" if ln in (7900, 7901, 7090) else "audit",
    })
    print(f"  行 {ln:5d}  {kind:9s} {old_now[1]:>10s} → {new_v[1]:>10s}")

# 3) 写盘
if DRY:
    print("-" * 60)
    print(f"DRY-RUN 结束：断言全部通过，拟改动 {len(changelog)} 行 → {stat}；未写盘、未备份。")
    sys.exit(0)

# 3.1 备份
BACKUP.write_bytes(DATA.read_bytes())
print(f"备份 → {BACKUP.name}（{BACKUP.stat().st_size} B, sha256={hashlib.sha256(BACKUP.read_bytes()).hexdigest()[:16]}…）")

with DATA.open("w", encoding="utf-8", newline="\n") as f:
    for row in rows:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
with CHANGELOG.open("a", encoding="utf-8") as f:
    for c in changelog:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")

# 4) 自检
rows2 = [json.loads(l) for l in DATA.open(encoding="utf-8") if l.strip()]
assert len(rows2) == N0, f"行数变化：{N0} → {len(rows2)}"
bad = []
for spec in ROWS:
    got = verdict(ga(rows2[spec["line"] - 1]))
    want = verdict(spec["analysis"] + "\n```json\n" + json.dumps(mk_verdict(**spec["verdict"]), ensure_ascii=False) + "\n```\n")
    if got != want:
        bad.append((spec["line"], got, want))
assert not bad, f"自检失败：{bad}"
# JSON 契约完整性
for spec in ROWS:
    txt = ga(rows2[spec["line"] - 1])
    o = json.loads(re.search(r"```json\s*(.*?)```", txt, re.S).group(1))
    assert list(o.keys()) == KEYS, f"行 {spec['line']} JSON 键序异常：{list(o.keys())}"
    assert "非 CWE" in txt, f"行 {spec['line']} 缺'非 CWE'辨析锚句"

print("-" * 60)
print(f"结论：行数 {len(rows2)}（不变）；改动 {len(changelog)} 行 → {stat}")
print(f"changelog 追加 → {CHANGELOG.name}（+{len(changelog)} 条）")
print(f"自检：13 行新结论全部落位 / JSON 契约完整 / 引文对码通过 / '非 CWE' 锚句齐全")
