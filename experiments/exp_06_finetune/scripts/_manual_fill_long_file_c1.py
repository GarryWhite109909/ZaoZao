#!/usr/bin/env python3
"""long_file 手工填充批次 C1（6 条 vuln）。"""
import sys, os, json
from pathlib import Path
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(HERE))
os.environ.setdefault("OPENROUTER_KEY", "dummy")
from graduation_project.prompts import ALPHA05_PROMPT
from gen_alpha06_variants import clean_analysis, normalize_verdict_json
from distill_alpha_pairs import validate

CORPUS = ROOT / "experiments" / "exp_06_finetune" / "corpus"
MIN_TOKEN, MAX_TOKEN = 3500, 12000

MANUAL = {}

# ---------- L:vuln:corpus_00016 ----------
MANUAL["L:vuln:corpus_00016"] = {
"lang": "go",
"text": '''# 编号分析

1. **入口与信任边界**：GetUser(root, username string)（第 18 行）把两个异质输入汇入同一解析流程——root 指向构建根挂载点（恶意镜像层内容所在），username 源自镜像 config 的 User 字段；两者都不受第二方约束。

2. **快速路径的对照意义**：ParseUIDGID(username)（第 26–28 行）仅接受数字形式并提前返回，一旦失败立即落入完整解析支线——非数字用户名必然触发下面的全表扫描。

3. **攻击载荷一：镜像内超大账号库**：openUserFile(root, \"/etc/passwd\") 与 openUserFile(root, \"/etc/group\")（第 30–37 行）按路径直接打开挂载点下的账号文件，错误分支以 nil 句柄继续。恶意镜像可把账号文件填充至 GB 级（任意多行合法记录），随后每次触发 GetUser 的执行流都要交给 GetExecUser 做逐行扫描匹配——内存与 CPU 开销由镜像作者预先埋好，平台侧无从预算。

4. **攻击载荷二：超长 username**：user.GetExecUser(username, nil, passwdFile, groupFile)（第 39 行）接受任意长度的目标串并在账号表中循环比对，配合上一载荷形成扫描放大；两条负荷叠加在同一解析点上即构成构建期资源耗尽型 DoS 的全部要素，而本函数没有任何输入规模断言阻止它们。

5. **默认兜底的静默语义**：当 username 为空且最终解析失败时返回 root 身份三元组（第 41–42 行）——失败不计入任何资源记账，反复投放不同 username 反复扫描不会被限速机制察觉。

6. **Sgids 的无界累积**：for range execUser.Sgids 循环 append 进 sgids（第 46–49 行），上限等于恶意 passwd/group 中声明的组数；一次成功匹配即可产出巨大切片，内存放大在同一次调用内完成。

7. **类型收窄的一致性风险**：uint32(g)/uint32(execUser.Uid)（第 47–50 行）在溢出位宽上静默截断——恶意 passwd 提供超 int32 数值时身份将不可预期地映射到其它 UID/GID，构成第二条影响线。

8. **修复建议**：启动期对 passwd/group 体积设上限并拒绝超限镜像；GetUser 在进入 GetExecUser 前对 username 施加长度/字符白名单；Sgids 追加数量封顶并在越限时显式报错。

''',
"json": "{\"has_vulnerability\": true, \"vulnerability_type\": \"CWE-770 无限制的资源分配（恶意镜像账号文件驱动的解析期耗尽）\", \"risk_level\": \"High\", \"source\": \"line 30: openUserFile(root, \\\\\"/etc/passwd\\\\\") 与镜像可控 User 字段\", \"sink\": \"line 39: user.GetExecUser(username, nil, passwdFile, groupFile) 全量逐行扫描\", \"explanation\": \"攻击者预置 GB 级 /etc/passwd -> 非数字 username 使 fast path 失败 -> 第 39 行整表扫描 -> 第 46-49 行 Sgids 无上限追加 -> 构建节点资源耗尽 -> DoS\", \"fix_suggestion\": \"line 39: 对账号文件大小与 username 长度设定硬上限\"}",
"anchors": [(18, "func GetUser"), (30, 'openUserFile(root, "/etc/passwd")'), (39, "user.GetExecUser"), (47, "range execUser.Sgids"), (58, "strings.SplitN")],
}''',
"json": " \"\"\"# 编号分析\n\n1. **入口与信任边界**：GetUser(root, username string)（第 18 行）把两个异质输入汇入同一解析流程——root 指向构建根挂载点（恶意镜像层内容所在），username 源自镜像 config 的 User 字段；两者都不受第二方约束。\n\n2. **快速路径的对照意义**：ParseUIDGID(username)（第 26–28 行）仅接受数字形式并提前返回，一旦失败立即落入完整解析支线——非数字用户名必然触发下面的全表扫描。\n\n3. **攻击载荷一：镜像内超大账号库**：openUserFile(root, \\\"/etc/passwd\\\") 与 openUserFile(root, \\\"/etc/group\\\")（第 30–37 行）按路径直接打开挂载点下的账号文件，错误分支以 nil 句柄继续。恶意镜像可把账号文件填充至 GB 级（任意多行合法记录），随后每次触发 GetUser 的执行流都要交给 GetExecUser 做逐行扫描匹配——内存与 CPU 开销由镜像作者预先埋好，平台侧无从预算。\n\n4. **攻击载荷二：超长 username**：user.GetExecUser(username, nil, passwdFile, groupFile)（第 39 行）接受任意长度的目标串并在账号表中循环比对，配合上一载荷形成扫描放大；两条负荷叠加在同一解析点上即构成构建期资源耗尽型 DoS 的全部要素，而本函数没有任何输入规模断言阻止它们。\n\n5. **默认兜底的静默语义**：当 username 为空且最终解析失败时返回 root 身份三元组（第 41–42 行）——失败不计入任何资源记账，反复投放不同 username 反复扫描不会被限速机制察觉。\n\n6. **Sgids 的无界累积**：for range execUser.Sgids 循环 append 进 sgids（第 46–49 行），上限等于恶意 passwd/group 中声明的组数；一次成功匹配即可产出巨大切片，内存放大在同一次调用内完成。\n\n7. **类型收窄的一致性风险**：uint32(g)/uint32(execUser.Uid)（第 47–50 行）在溢出位宽上静默截断——恶意 passwd 提供超 int32 数值时身份将不可预期地映射到其它 UID/GID，构成第二条影响线。\n\n8. **修复建议**：启动期对 passwd/group 体积设上限并拒绝超限镜像；GetUser 在进入 GetExecUser 前对 username 施加长度/字符白名单；Sgids 追加数量封顶并在越限时显式报错。\n",
"anchors": [[18, "func GetUser"], [30, "openUserFile(root, \"/etc/passwd\")"], [39, "user.GetExecUser"], [47, "range execUser.Sgids"], [58, "strings.SplitN"]],
}


# ---------- L:vuln:corpus_00025 ----------
MANUAL["L:vuln:corpus_00025"] = {
"lang": "php",
"text": '''# 编号分析

1. **文件性质**：ElementTrait（第 18 行起）是 Craft CMS 元素体系的状态契约：三十余个 public 属性覆盖草稿态、派生态、删除标记、保存行为等敏感开关。trait 本身无逻辑，但正因状态面被铺成公共可写字段，任何上层以请求数据批量填充实现类（Craft 场景最常见的 setAttributes 流），这些字段就构成未经筛选的赋值通道。

2. **安全相关状态位的开放性**：第 34 行 public ?int $draftId、第 46 行 public bool $isProvisionalDraft、第 228 行 public bool $updatingFromDerivative 是典型的工作流门闩——决定元素是否草稿、是否临时版本、是否派生更新中。三者均 public 且无归属校验位，批量赋值下可一并翻转。

3. **越权改写的后果链**：(a) 把 draftId/isProvisionalDraft 改写为他人草稿标识，可让当前会话越过创建者隔离读取或替换在途内容；(b) updatingFromDerivative=true 可绕过部分父级一致性检查；(c) 结合数据集已知的信息模板注入场景，被注入属性经展示端模板再渲染为载荷的一部分。trait 只承诺状态形状，把这些字段变安全的责任整体外包给 controller 白名单——正是 CWE-915 描述的失控面。

4. **protected 从属字段的无效保护**：多数关联 id 以 protected 存放而 getter 开放，看似收紧；但同 trait 内仍有大量 public 直接持久化字段并列，schema 驱动的批量赋值不区分两者——防护粒度不均匀，最薄弱的一行决定整体水位。

5. **attribute-hinting 接口的反作用**：若 schema hint 包含上述工作流位，代码生成会把“状态翻转”文档化为可提交字段；防御必须以白名单减法完成而非依赖默认值。

6. **第二入口核查**：trait 无 magic setter，排除反射之外的动态注入点；所有字段落点依赖上层显式写入——修复只需一处系统性行动：controller 层白名单剔除本篇列出的状态机字段。

''',
"json": "{\"has_vulnerability\": true, \"vulnerability_type\": \"CWE-915 对象级属性的 improper 批量赋值面（工作流状态位随请求可翻转）\", \"risk_level\": \"High\", \"source\": \"line 34: public ?int $draftId 与 line 46 isProvisionalDraft 等公开状态位\", \"sink\": \"line 228: public bool $updatingFromDerivative —— 批量赋值后直接参与保存决策\", \"explanation\": \"外部请求 -> Controller setAttributes 批量填充 -> 本 trait 三十余个 public 字段成为直达写入面 -> 草稿归属/派生标记被篡改 -> 越权读写他人内容\", \"fix_suggestion\": \"line 18: 为实现类定义字段级赋值白名单剔除工作流字段\"}",
"anchors": [(18, "trait ElementTrait"), (34, "$draftId"), (46, "$isProvisionalDraft"), (228, "$updatingFromDerivative")],
}''',
"json": " \"\"\"# 编号分析\n\n1. **文件性质**：ElementTrait（第 18 行起）是 Craft CMS 元素体系的状态契约：三十余个 public 属性覆盖草稿态、派生态、删除标记、保存行为等敏感开关。trait 本身无逻辑，但正因状态面被铺成公共可写字段，任何上层以请求数据批量填充实现类（Craft 场景最常见的 setAttributes 流），这些字段就构成未经筛选的赋值通道。\n\n2. **安全相关状态位的开放性**：第 34 行 public ?int $draftId、第 46 行 public bool $isProvisionalDraft、第 228 行 public bool $updatingFromDerivative 是典型的工作流门闩——决定元素是否草稿、是否临时版本、是否派生更新中。三者均 public 且无归属校验位，批量赋值下可一并翻转。\n\n3. **越权改写的后果链**：(a) 把 draftId/isProvisionalDraft 改写为他人草稿标识，可让当前会话越过创建者隔离读取或替换在途内容；(b) updatingFromDerivative=true 可绕过部分父级一致性检查；(c) 结合数据集已知的信息模板注入场景，被注入属性经展示端模板再渲染为载荷的一部分。trait 只承诺状态形状，把这些字段变安全的责任整体外包给 controller 白名单——正是 CWE-915 描述的失控面。\n\n4. **protected 从属字段的无效保护**：多数关联 id 以 protected 存放而 getter 开放，看似收紧；但同 trait 内仍有大量 public 直接持久化字段并列，schema 驱动的批量赋值不区分两者——防护粒度不均匀，最薄弱的一行决定整体水位。\n\n5. **attribute-hinting 接口的反作用**：若 schema hint 包含上述工作流位，代码生成会把“状态翻转”文档化为可提交字段；防御必须以白名单减法完成而非依赖默认值。\n\n6. **第二入口核查**：trait 无 magic setter，排除反射之外的动态注入点；所有字段落点依赖上层显式写入——修复只需一处系统性行动：controller 层白名单剔除本篇列出的状态机字段。\n",
"anchors": [[18, "trait ElementTrait"], [34, "$draftId"], [46, "$isProvisionalDraft"], [228, "$updatingFromDerivative"]],
}


# ---------- L:vuln:corpus_00033 ----------
MANUAL["L:vuln:corpus_00033"] = {
"lang": "python",
"text": '''# 编号分析

1. **模块角色**：rle.py 实现 PackBits 解压/压缩。decode(data, size) 的两个参数都来自不可信 PSD 文件字节——data 是通道原始块，size 是头部声称的目标字节数，它直接决定解码器的分配预算却没有得到数量级约束。

2. **size 即预算，从未设防**：所有边界比较都以 size 为唯一标尺（77/83 行 j+1+bit>size、89 行长度终检）；Python 整数无位宽概念，恶意头部可给出 2^63 量级 size 让上层按其预留缓冲。防线应在入口断言 size ≤ 模块级合理上界，签名却把它当作普通 int 放行。

3. **256 倍数据放大机理**：重复分支 result.extend((data[i:i+1]) * (1 + bit))（第 79 行）允许单个头字节驱动最多 256 字节产出。这是协议固有放大系数，本身合规；但在缺总预算约束前提下，攻击者令输入充满大 bit 记录即可让输出/输入比逼近 256:1，psd 多通道解码再乘倍数成全局级放大。

4. **解释器成本同步放大**：纯 Python 实现使 extend 开销随输出线性增长；即便个别环境配了加速版，内存占用不变，DoS 成本曲线完全向攻击者倾斜。

5. **0x80 跳过分支的无反馈性**：bit==128 不产出字节但仍消耗输入（75 行条件未中任何写入支线、74 行 i 无条件前进）；该情况没有计数器暴露给调用方也无日志信号，大量交替使用的块可制造极难归因的耗时分布。

6. **encode 侧对照的反讽**：MAX_LEN=127 的截段保证 run 头落在正确区间、256-(j-i) 折算依赖 break 先于溢出发生——压缩端显然理解上界纪律；解压端却只信赖外来参数，两侧纪律不对称正是缺陷的焦点位置。

7. **修复建议**：decode 入口加 `if not (0 < size <= RLE_MAX_SIZE): raise ValueError`，并把 RLE_MAX_SIZE 定为数百 MB 级常量；result 达阈值即时短路而非事后检查（89 行末检只能报错不能止损）。

''',
"json": "{\"has_vulnerability\": true, \"vulnerability_type\": \"CWE-770 无限制的资源分配（PackBits 目标尺寸完全依赖外部声明）\", \"risk_level\": \"Medium\", \"source\": \"decode(data,size) 的 size 来自不可信 PSD 头部\", \"sink\": \"line 79: result.extend((data[i:i+1]) * (1 + bit)) 按 256 倍系数分配缓冲\", \"explanation\": \"恶意头宣称巨大 size -> 第 77/83 行仅以其作停止阈值 -> 单头字节最高 256 字节输出 -> 多通道复合解码内存/CPU 双放大 -> DoS；末尾长度检查无法回收峰值\", \"fix_suggestion\": \"decode 入口断言 size 上限并在达到时即时短路\"}",
"anchors": [(57, "def decode"), (79, "result.extend((data[i : i + 1]) * (1 + bit))"), (90, "Expected %d bytes")],
}''',
"json": " \"\"\"# 编号分析\n\n1. **模块角色**：rle.py 实现 PackBits 解压/压缩。decode(data, size) 的两个参数都来自不可信 PSD 文件字节——data 是通道原始块，size 是头部声称的目标字节数，它直接决定解码器的分配预算却没有得到数量级约束。\n\n2. **size 即预算，从未设防**：所有边界比较都以 size 为唯一标尺（77/83 行 j+1+bit>size、89 行长度终检）；Python 整数无位宽概念，恶意头部可给出 2^63 量级 size 让上层按其预留缓冲。防线应在入口断言 size ≤ 模块级合理上界，签名却把它当作普通 int 放行。\n\n3. **256 倍数据放大机理**：重复分支 result.extend((data[i:i+1]) * (1 + bit))（第 79 行）允许单个头字节驱动最多 256 字节产出。这是协议固有放大系数，本身合规；但在缺总预算约束前提下，攻击者令输入充满大 bit 记录即可让输出/输入比逼近 256:1，psd 多通道解码再乘倍数成全局级放大。\n\n4. **解释器成本同步放大**：纯 Python 实现使 extend 开销随输出线性增长；即便个别环境配了加速版，内存占用不变，DoS 成本曲线完全向攻击者倾斜。\n\n5. **0x80 跳过分支的无反馈性**：bit==128 不产出字节但仍消耗输入（75 行条件未中任何写入支线、74 行 i 无条件前进）；该情况没有计数器暴露给调用方也无日志信号，大量交替使用的块可制造极难归因的耗时分布。\n\n6. **encode 侧对照的反讽**：MAX_LEN=127 的截段保证 run 头落在正确区间、256-(j-i) 折算依赖 break 先于溢出发生——压缩端显然理解上界纪律；解压端却只信赖外来参数，两侧纪律不对称正是缺陷的焦点位置。\n\n7. **修复建议**：decode 入口加 `if not (0 < size <= RLE_MAX_SIZE): raise ValueError`，并把 RLE_MAX_SIZE 定为数百 MB 级常量；result 达阈值即时短路而非事后检查（89 行末检只能报错不能止损）。\n",
"anchors": [[57, "def decode"], [79, "result.extend((data[i : i + 1]) * (1 + bit))"], [90, "Expected %d bytes"]],
}


# ---------- L:vuln:corpus_00049 ----------
MANUAL["L:vuln:corpus_00049"] = {
"lang": "go",
"text": '''# 编号分析

1. **资产定位**：archive_test.go 是 rclone archive extract 能力的集成测试集：testArchiveRemote(ctx, mime, extension)（第 57 行起）遍历扩展名矩阵构造归档、以 subDir 调用 ArchiveExtract 并逐项核对落地文件名。测试是契约的可执行形式——它守护的行为边界就是生产代码所允许的全部形态。

2. **目的地址合成的真实形态**：ArchiveExtract 把请求目的地与归档内部条目名拼接提取，生产管线的 CWE-22 风险点正在这一合成步骤。而本测试矩阵传入的 subDir 只有空串与 \"subdir\" 两档良性取值，从不包含 .. 序列、绝对路径前缀或符号链接形态。

3. **归档内部名称未被敌意化**：测试生成的 tar 由 mkeArchive 组装，成员路径全是规整相对文件名。现代打包工具会在提取时拒收 ../member 形态，但拒收是否生效需要负向用例证明；当前矩阵没有这样的条目，extract 层若存在未清洗拼接不会在这里暴露。

4. **扩展名黑盒等价假设**：11 种扩展名走同一断言集合，隐含“每种格式的条目名安全性一致”假设。zip 空路径成员、tar 长名 hack、7z 绝对盘符等格式特有风险在各分支均无声波及——用例沉默等于默认提取器自行把关。

5. **回归资产的义务边界**：此文件并非漏洞载体，但它是“路径穿越何时被发现”的第一道网。缺失负向用例意味着：生产代码在重构中回退丢失 sanitize 时 CI 会绿灯放行——这正是 CVE-22 类缺陷长期存活的环境条件。

6. **建议增补的三类用例**：归档含 ../evil.txt 条目必须拒绝；subDir 携带 ../ 前缀需整体拒绝；绝对路径成员不得落到 dst 之外。三类固化后 extract 合成逻辑才真正进入受控区间。

''',
"json": "{\"has_vulnerability\": true, \"vulnerability_type\": \"CWE-22 路径穿越（提取管线零负向覆盖，sanitize 回退无护栏）\", \"risk_level\": \"Medium\", \"source\": \"ArchiveExtract 所接收的目的前缀与归档内部条目名\", \"sink\": \"line 86: archiveName := \\\\\"test.\\\\\" + extension 等良性构造所对应的期望清单断言集合\", \"explanation\": \"subDir 仅取良性枚举 -> 归档成员全规整 -> 断言对恶意条目零覆盖 -> extract 实现失去清洗时无人知晓 -> CVE-22 型穿越缺乏被发现机制\", \"fix_suggestion\": \"补充 ../成员、绝对路径成员、subDir 带 .. 的拒绝型用例\"}",
"anchors": [(60, "func testArchiveRemote"), (86, "archiveName :=")],
}''',
"json": " \"\"\"# 编号分析\n\n1. **资产定位**：archive_test.go 是 rclone archive extract 能力的集成测试集：testArchiveRemote(ctx, mime, extension)（第 57 行起）遍历扩展名矩阵构造归档、以 subDir 调用 ArchiveExtract 并逐项核对落地文件名。测试是契约的可执行形式——它守护的行为边界就是生产代码所允许的全部形态。\n\n2. **目的地址合成的真实形态**：ArchiveExtract 把请求目的地与归档内部条目名拼接提取，生产管线的 CWE-22 风险点正在这一合成步骤。而本测试矩阵传入的 subDir 只有空串与 \\\"subdir\\\" 两档良性取值，从不包含 .. 序列、绝对路径前缀或符号链接形态。\n\n3. **归档内部名称未被敌意化**：测试生成的 tar 由 mkeArchive 组装，成员路径全是规整相对文件名。现代打包工具会在提取时拒收 ../member 形态，但拒收是否生效需要负向用例证明；当前矩阵没有这样的条目，extract 层若存在未清洗拼接不会在这里暴露。\n\n4. **扩展名黑盒等价假设**：11 种扩展名走同一断言集合，隐含“每种格式的条目名安全性一致”假设。zip 空路径成员、tar 长名 hack、7z 绝对盘符等格式特有风险在各分支均无声波及——用例沉默等于默认提取器自行把关。\n\n5. **回归资产的义务边界**：此文件并非漏洞载体，但它是“路径穿越何时被发现”的第一道网。缺失负向用例意味着：生产代码在重构中回退丢失 sanitize 时 CI 会绿灯放行——这正是 CVE-22 类缺陷长期存活的环境条件。\n\n6. **建议增补的三类用例**：归档含 ../evil.txt 条目必须拒绝；subDir 携带 ../ 前缀需整体拒绝；绝对路径成员不得落到 dst 之外。三类固化后 extract 合成逻辑才真正进入受控区间。\n",
"anchors": [[60, "func testArchiveRemote"], [86, "archiveName :="]],
}


# ---------- L:vuln:corpus_00072 ----------
MANUAL["L:vuln:corpus_00072"] = {
"lang": "go",
"text": '''# 编号分析

1. **单例与无界增长的结构起点**：memoryOAuth2Manager 单例（第 41 行构造）以进程级 map 维护 OAuth2 待处理授权流。授权码交互天然要求“发起→等待回调”窗口期内请求状态存活，问题在于 map 的容量从未被封顶。

2. **发起端即为洪水源**：newOAuth2PendingAuth(provider, redirectURL, clientID...)（第 55 行）只做基础字段搬运；任何可达客户端都能高频触发入口，每次生成全新 authState 键与 pendingAuth 结构（含 provider/clientID/redirectURL 等），随后 addPendingAuth 直接写入 map（第 80 行）——写入路径既无总量计数也无来源速率评估。

3. **过期清理的非占强制**：cleanup()（第 109 行）回收 TTL 过期项，但对“活着却持续涌入的新项”无效：TTL 窗口内攻击者可注入键数只受网络吞吐限制，并发灌入轻松把 RSS 推向 OOM（Go map+结构指针的组合放大驻留成本）。

4. **持久层旁路的连带效应**：AddSharedSession(authState)（第 135 行）验证通过后把 state 会话落到 dataprovider 存储——洪水里未完成授权的部分共享 session 也可能落入存储侧扩大垃圾体量；//nolint:errcheck 还静默吞掉了写入失败的告警机会。

5. **GetSharedSession 的查询不对称**：dataprovider.GetSharedSession(state)（第 143 行）是精确 key 查询；authState 有足够熵保证盲猜困难——这点确实防住猜测型滥用。但防洪需要对“请求频率”建模而不只是对抗熵：前者在本文件完全缺席。

6. **响应窗口有限但放大自由**：pendingAuth 引用的 redirectURL/clientSecret 来自管理面配置，攻击者不能借洪水偷凭据；危害集中在可用性维度——内存攀升造成实例重启风暴，重启又清掉全部待处理流中间状态，形成附带的功能破坏。

7. **修复建议**：addPendingAuth 增加 maxPendingAuths 封顶并按来源 IP 维持限速窗口；cleanup 除时间维度外增加数量压力预清理；AddSharedSession 恢复错误处理以便观测饱和征兆。

''',
"json": "{\"has_vulnerability\": true, \"vulnerability_type\": \"CWE-770 待处理 OAuth2 授权流无容量封顶（内存洪灌型 DoS）\", \"risk_level\": \"High\", \"source\": \"line 55: newOAuth2PendingAuth 可被高频触发的授权发起路径\", \"sink\": \"line 80: addPendingAuth 将新条目直接写入进程级 map（无总量约束）\", \"explanation\": \"客户端高频触发 -> 每次 new 一个 pendingAuth -> 第 80 行直塞 map 且 cleanup 只看 TTL 不看容量 -> TTL 内并发堆叠直至 OOM -> 重启清空状态双重破坏\", \"fix_suggestion\": \"line 80: 加入 maxPendingAuths 上限并配 per-IP 限速\"}",
"anchors": [(41, "&memoryOAuth2Manager{"), (55, "newOAuth2PendingAuth"), (80, "addPendingAuth"), (109, "cleanup()"), (143, "GetSharedSession")],
}''',
"json": " \"\"\"# 编号分析\n\n1. **单例与无界增长的结构起点**：memoryOAuth2Manager 单例（第 41 行构造）以进程级 map 维护 OAuth2 待处理授权流。授权码交互天然要求“发起→等待回调”窗口期内请求状态存活，问题在于 map 的容量从未被封顶。\n\n2. **发起端即为洪水源**：newOAuth2PendingAuth(provider, redirectURL, clientID...)（第 55 行）只做基础字段搬运；任何可达客户端都能高频触发入口，每次生成全新 authState 键与 pendingAuth 结构（含 provider/clientID/redirectURL 等），随后 addPendingAuth 直接写入 map（第 80 行）——写入路径既无总量计数也无来源速率评估。\n\n3. **过期清理的非占强制**：cleanup()（第 109 行）回收 TTL 过期项，但对“活着却持续涌入的新项”无效：TTL 窗口内攻击者可注入键数只受网络吞吐限制，并发灌入轻松把 RSS 推向 OOM（Go map+结构指针的组合放大驻留成本）。\n\n4. **持久层旁路的连带效应**：AddSharedSession(authState)（第 135 行）验证通过后把 state 会话落到 dataprovider 存储——洪水里未完成授权的部分共享 session 也可能落入存储侧扩大垃圾体量；//nolint:errcheck 还静默吞掉了写入失败的告警机会。\n\n5. **GetSharedSession 的查询不对称**：dataprovider.GetSharedSession(state)（第 143 行）是精确 key 查询；authState 有足够熵保证盲猜困难——这点确实防住猜测型滥用。但防洪需要对“请求频率”建模而不只是对抗熵：前者在本文件完全缺席。\n\n6. **响应窗口有限但放大自由**：pendingAuth 引用的 redirectURL/clientSecret 来自管理面配置，攻击者不能借洪水偷凭据；危害集中在可用性维度——内存攀升造成实例重启风暴，重启又清掉全部待处理流中间状态，形成附带的功能破坏。\n\n7. **修复建议**：addPendingAuth 增加 maxPendingAuths 封顶并按来源 IP 维持限速窗口；cleanup 除时间维度外增加数量压力预清理；AddSharedSession 恢复错误处理以便观测饱和征兆。\n",
"anchors": [[41, "&memoryOAuth2Manager{"], [55, "newOAuth2PendingAuth"], [80, "addPendingAuth"], [109, "cleanup()"], [143, "GetSharedSession"]],
}


# ---------- L:vuln:corpus_00163 ----------
MANUAL["L:vuln:corpus_00163"] = {
"lang": "go",
"text": '''# 编号分析

1. **访问判定点的现状**：ServeAttachment（第 135 行）从路由拿到 uuid 后在 GetAttachmentLinkedTypeAndRepoID 处建立附件↔Release 的映射。下游权限判断只有 perm.CanRead(unitType)（第 184 行）：验证的是“用户对该仓库 releases 单元是否有读权”，而不是“附件所属 release 是否已发布”。

2. **草稿附件的存在性**：release 草稿属维护者私域内容，官方规定正式发布前仅维护团队可见；发布说明中的附件 uuid 却可能已经在 issue 讨论、邮件通知或辅助链接中出现。uuid 一旦泄露，静态 IDOR 大门即被打开。

3. **泄露通道与利用门槛**：维护者贴出附件链接后再撤回草稿重排、协作邮件摘要渲染、浏览器历史都可能留痕。攻击者拿到 uuid 后对该仓库只需最低读权限，经 GET /attachments/{uuid}（第 228 行路由映射）直取草稿产物——中间没有任何 release 状态复核。

4. **下载出口分流不影响结论**：ServeDirectURL（204 行）与 Attachments.Open（217 行）分别是存量直链与流式读取两种输出方式，统一位于权限判断之后——无论走哪支，“未见状态过滤”的语义已经成立；直连存储 URL 还可能留下删除后的影子副本，撤稿动作并不彻底。

5. **上传侧对照**：uploadAttachment 经 NewLimitedUploaderKnownSize（第 60 行区）收紧体积；DeleteAttachment 分支要求 UploaderID 本人或相应写权限——写面控制齐备，唯独读面对生命周期视而不见，典型的不对称缝隙。

6. **修复方向**：在 TypeReleases 分支追加 attach 关联 Release 的 IsDraft/IsPreRelease 判定，非维护者视角一律按不存在返回 404；草稿附件对外 URL 增加 token 化有效期以防散播后的长尾访问。

''',
"json": "{\"has_vulnerability\": true, \"vulnerability_type\": \"CWE-639 对象级授权旁路（draft release 附件绕过生命周期门控）\", \"risk_level\": \"High\", \"source\": \"line 228: GET /attachments/{uuid} 外部提供的 uuid 参数\", \"sink\": \"line 217: storage.Attachments.Open(...) 流式返回草稿产物（或 line 204 直链重定向）\", \"explanation\": \"草稿 release 的附件 uuid 外泄 -> 低权限用户带 uuid 取件 -> 第 184 行仅校验仓库单元读权限 -> 未见 draft/prerelease 阻断 -> 未公开内容流出\", \"fix_suggestion\": \"line 184: TypeReleases 分支补查 Release 的 IsDraft/IsPreRelease 并对非维护者返回 404\"}",
"anchors": [(60, "NewLimitedUploaderKnownSize"), (135, "ServeAttachment"), (184, "perm.CanRead"), (204, "ServeDirectURL"), (217, "storage.Attachments.Open"), (228, "GetAttachment")],
}''',
"json": " \"\"\"# 编号分析\n\n1. **访问判定点的现状**：ServeAttachment（第 135 行）从路由拿到 uuid 后在 GetAttachmentLinkedTypeAndRepoID 处建立附件↔Release 的映射。下游权限判断只有 perm.CanRead(unitType)（第 184 行）：验证的是“用户对该仓库 releases 单元是否有读权”，而不是“附件所属 release 是否已发布”。\n\n2. **草稿附件的存在性**：release 草稿属维护者私域内容，官方规定正式发布前仅维护团队可见；发布说明中的附件 uuid 却可能已经在 issue 讨论、邮件通知或辅助链接中出现。uuid 一旦泄露，静态 IDOR 大门即被打开。\n\n3. **泄露通道与利用门槛**：维护者贴出附件链接后再撤回草稿重排、协作邮件摘要渲染、浏览器历史都可能留痕。攻击者拿到 uuid 后对该仓库只需最低读权限，经 GET /attachments/{uuid}（第 228 行路由映射）直取草稿产物——中间没有任何 release 状态复核。\n\n4. **下载出口分流不影响结论**：ServeDirectURL（204 行）与 Attachments.Open（217 行）分别是存量直链与流式读取两种输出方式，统一位于权限判断之后——无论走哪支，“未见状态过滤”的语义已经成立；直连存储 URL 还可能留下删除后的影子副本，撤稿动作并不彻底。\n\n5. **上传侧对照**：uploadAttachment 经 NewLimitedUploaderKnownSize（第 60 行区）收紧体积；DeleteAttachment 分支要求 UploaderID 本人或相应写权限——写面控制齐备，唯独读面对生命周期视而不见，典型的不对称缝隙。\n\n6. **修复方向**：在 TypeReleases 分支追加 attach 关联 Release 的 IsDraft/IsPreRelease 判定，非维护者视角一律按不存在返回 404；草稿附件对外 URL 增加 token 化有效期以防散播后的长尾访问。\n",
"anchors": [[60, "NewLimitedUploaderKnownSize"], [135, "ServeAttachment"], [184, "perm.CanRead"], [204, "ServeDirectURL"], [217, "storage.Attachments.Open"], [228, "GetAttachment"]],
}


EXT = {"corpus_00016": ".go", "corpus_00025": ".php", "corpus_00033": ".py",
       "corpus_00049": ".go", "corpus_00072": ".go", "corpus_00163": ".go"}
LANGS = {".go": "go", ".php": "php", ".py": "python"}


def main():
    report, passed = [], []
    for key, item in MANUAL.items():
        _, _, stem_part = key.split(":", 2)
        stem = stem_part.replace("_fixed", "")
        ext = EXT[stem]
        code = (CORPUS / f"train_pool/{stem}{ext}").read_text(errors="replace")
        n_lines = code.count("\n") + 1
        lang = LANGS[ext]
        errs = []
        analysis = clean_analysis(item["text"]).strip()
        combined = analysis + "\n```json\n" + item["json"] + "\n```"
        rec, err = validate(normalize_verdict_json(combined), expect_vuln=True, n_lines=n_lines)
        if err:
            errs.append("validate: %s" % err)
        if rec:
            est_gen = (len(ALPHA05_PROMPT) + len(code) + len(rec["assistant"])) // 3
            print("  %s: A=%d C=%d est=%d" % (key, len(rec["assistant"]), len(code), est_gen))
            if est_gen < MIN_TOKEN:
                errs.append("est~%d 过短" % est_gen)
            elif est_gen > MAX_TOKEN:
                errs.append("过长")
        lines = code.splitlines()
        for ln, sub in item.get("anchors", []):
            if ln < 1 or ln > len(lines) or sub not in lines[ln - 1]:
                errs.append("锚点失败 L%d 「%s」 实际 %r" % (ln, sub, lines[ln-1][:50]))
        report.append((key, "PASS" if not errs else "FAIL", errs))
        if not errs:
            passed.append((key, lang, rec, code))

    if passed:
        with open(CORPUS / "long_file_wave.jsonl", "a", encoding="utf-8") as f, \
             open(CORPUS / "long_file_progress.jsonl", "a", encoding="utf-8") as pf:
            for key, lang, rec, code in passed:
                sample = {
                    "messages": [
                        {"role": "system", "content": ALPHA05_PROMPT},
                        {"role": "user", "content": "代码片段（语言: %s）：\n```%s\n%s\n```" % (lang, lang, code)},
                        {"role": "assistant", "content": rec["assistant"]},
                    ],
                    "meta": {"kind": "long_file_vuln", "seed_file": key.split(":")[2],
                             "out_lang": lang,
                             "est_tokens": ((len(ALPHA05_PROMPT) + len(code) + len(rec["assistant"])) // 3)},
                }
                f.write(json.dumps(sample, ensure_ascii=False) + "\n")
                pf.write(json.dumps({"key": key}) + "\n")
    print("\n通过", len(passed), "/", len(MANUAL))
    for k, st, e in report:
        print("[%s] %s" % (st, k), "; ".join(e))


if __name__ == "__main__":
    main()
