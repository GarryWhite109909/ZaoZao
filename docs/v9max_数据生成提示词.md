# v9max 数据生成提示词（三模型蒸馏）

> **用途**：本地 QLoRA 训练 v9max（11500 条三模型蒸馏数据）的生成提示词
> **适用**：DeepSeek V4-Flash / Kimi K3 / GLM-5.2 API 调用
> **配套**：《docs/方法论_新蒸馏方法论.md》调整后分配表
> **编写人**：GLM-5.2（兼实验一把手）

---

## 一、总体说明

### 1.1 三模型分工

| 模型 | 数据类别 | 数量 | 发挥优势 | 反偏置重点 |
|---|---|---|---|---|
| DeepSeek V4-Flash | C/C++ 内存 / 渗透命令注入 / Web 漏洞 / Shell 配置 / 漏洞修复 | 7700 | Agent 推理、命令注入、运维链路 | 内存类"近半误报"→ 强制锚定行号 |
| Kimi K3 | C/C++ 内存重构 / 跨文件分块审计 | 2000 | 长上下文、跨 .so 调用链 | 原生长链（数万 token）→ 压成 ≤5 步 |
| GLM-5.2 | CWE+CVSS 严格格式 / 负样本 | 1500+ | 指令遵循、JSON 合法性 100% | 格式反射强化 |
| **合计** | | **11200+** | | |

> 负样本按 1:3 配比分散到各类，由 GLM 主导生成（最稳）。

### 1.2 三条铁律（所有模型必须遵守）

1. **CoT ≤5 步、≤590 token**：DeepSeek-R1 蒸馏到 8B 的官方经验，长链直接照搬会导致小模型"边想边说还反复修改"，准确率不升反降
2. **三段式统一输出**：`[代码片段] → [≤5步推理] → [JSON结论]`，以 GLM schema 为锚
3. **负样本 1:3 配比**：每生成 1 条漏洞样本，必须生成 3 条同类无漏洞样本，标注"已检查 X/Y/Z 点，未发现可利用路径"

---

## 二、统一输出格式

所有模型生成的每条样本必须严格遵循以下 ChatML 格式：

```json
{
  "messages": [
    {"role": "system", "content": "<系统提示词>"},
    {"role": "user", "content": "<代码片段>"},
    {"role": "assistant", "content": "<分析过程 + JSON 结论>"}
  ],
  "metadata": {
    "generator": "deepseek-v4-flash | kimi-k3 | glm-5.2",
    "category": "c-memory | penetration | web-vuln | shell-config | fix-example | cwe-cvss | crossfile-audit | negative",
    "language": "c | cpp | python | java | javascript | shell | php | go | ruby",
    "cwe": "CWE-XXX",
    "has_vulnerability": true
  }
}
```

### assistant 内容模板

```
分析过程：
1. {步骤1：定位污染源，锚定行号}
2. {步骤2：追踪数据流，锚定行号}
3. {步骤3：评估防御措施，锚定行号}
4. {步骤4：判断可利用性}
5. {步骤5：综合结论}

```json
{
  "has_vulnerability": true,
  "vulnerability_type": "CWE-89 SQL注入",
  "risk_level": "Critical",
  "source": "request.args.get('id')",
  "sink": "cursor.execute(query)",
  "explanation": "request.args.get('id') → uid → str.format 拼接 → query → cursor.execute",
  "fix_suggestion": "使用参数化查询：cursor.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))"
}
```
```

### 负样本（无漏洞）模板

```
分析过程：
输入点 `{source}` 来自 {来源描述}。数据流经 {中间函数}，最终传递给 {sink}。防御措施 {防御描述}，有效阻断 {威胁}。已检查 {X/Y/Z 点}，未发现可利用路径，无漏洞。

```json
{
  "has_vulnerability": false,
  "vulnerability_type": "none",
  "risk_level": "None",
  "source": "N/A",
  "sink": "N/A",
  "explanation": "N/A",
  "fix_suggestion": "no fix needed"
}
```
```

---

## 三、DeepSeek V4-Flash 提示词

### 3.1 系统提示词（所有类别共用）

```
你是一名资深安全研究员，专精渗透测试、命令注入、运维链路安全与 Web 漏洞审计。你正在为代码漏洞检测模型生成高质量训练样本。

【核心原则】
1. 基于证据：每个漏洞必须锚定到具体行号，禁止凭空臆造 API 参数或行为
2. 克制报告：只在确有漏洞时报告。你在内存类漏洞上有"量高但近半误报"的已知问题，本次必须克制——宁可漏报也不要误报
3. 推理简洁：CoT 最多 5 步，每步一句话锚定行号。禁止"边想边说还反复修改"
4. 防御识别：必须显式评估 sink 前的防御措施是否有效，不能只看到 source→sink 就报漏洞
5. 负样本配比：每生成 1 条漏洞样本，必须生成 3 条同类无漏洞样本

【CWE 归因规则】
- 注入类按 sink 区分：SQL execute → CWE-89；shell/os.system → CWE-78；eval/exec → CWE-95/94；LDAP search → CWE-90；template render → CWE-1336/CWE-94；HTTP header → CWE-113
- 访问控制类按缺陷本质区分：IDOR → CWE-639；缺失授权 → CWE-862；缺失认证 → CWE-306；信任源误判 → CWE-441
- 密码学类：硬编码 IV → CWE-329；JWT 签名不严 → CWE-347；弱算法 → CWE-327；硬编码凭证 → CWE-798；弱随机数 → CWE-330
- 并发与逻辑类：Race Condition → CWE-362；Mass Assignment → CWE-915；原型链污染 → CWE-1321
- 其他：反序列化 → CWE-502；XXE → CWE-611；SSRF → CWE-918；信息泄露 → CWE-200；开放重定向 → CWE-601；路径穿越 → CWE-22；XSS → CWE-79；CSRF → CWE-352；日志注入 → CWE-117

【输出格式】
严格三段式，见下方模板。JSON 必须用 ```json 包裹。
```

### 3.2 C/C++ 内存类漏洞（1000 条）

```
【数据类别】C/C++ 内存类漏洞
【数量】1000 条（漏洞 250 + 安全 750，1:3 配比）
【CWE 覆盖】CWE-416 UAF / CWE-415 Double Free / CWE-120 Buffer Overflow / CWE-122 Heap Overflow / CWE-121 Stack Overflow / CWE-476 Null Deref / CWE-367 TOCTOU / CWE-190 Integer Overflow / CWE-787 Out-of-bounds Write / CWE-125 Out-of-bounds Read

【生成要求】
1. 代码必须是真实可编译的 C/C++ 片段（20-80 行），模拟真实项目结构（含 struct/函数调用/指针运算）
2. 漏洞样本必须能被静态分析识别，但不能太明显（避免 int* p = NULL; *p = 1; 这种教科书式）
3. 安全样本必须包含有效的防御措施（如 free 后置 NULL、RAII、边界检查、智能指针）
4. 每个漏洞必须锚定到具体行号：如"第 42 行 free(ptr) 后未置 NULL，第 45 行 return path 解引用 ptr"

【用户提示词模板】
请生成 1 条 {CWE-XXX 漏洞类型} 的训练样本：
- 语言：{C 或 C++}
- 难度：{简单/中等/困难}（困难 = 涉及跨函数调用或宏定义）
- 是否有漏洞：{是/否}
- 代码场景：{如：网络协议解析 / 文件系统操作 / 内存管理 / 多线程}

输出严格三段式格式。
```

### 3.3 渗透/命令注入/运维安全（1800 条）

```
【数据类别】渗透/命令注入/运维安全
【数量】1800 条（漏洞 450 + 安全 1350，1:3 配比）
【CWE 覆盖】CWE-78 OS Command Injection / CWE-77 Command Injection / CWE-88 Argument Injection / CWE-134 Format String / CWE-918 SSRF / CWE-912 Hidden Functionality / CWE-749 Exposed Dangerous Method

【生成要求】
1. 这是 DeepSeek 的强项（Agent 后训练偏向），充分发挥运维链路推理能力
2. 场景真实：CI/CD 脚本、运维自动化、容器配置、API 网关、日志处理
3. 命令注入样本必须包含 shell=True + 用户输入拼接、os.system + 字符串拼接等真实模式
4. 安全样本必须包含有效防御：subprocess 列表参数 + shell=False、shlex.quote、白名单校验
5. 必须区分"shell=True + shlex.quote 是有效防御"vs"shell=True + 字符串拼接是漏洞"

【用户提示词模板】
请生成 1 条 {CWE-XXX 漏洞类型} 的训练样本：
- 语言：{Python/Shell/Go/JavaScript}
- 场景：{如：运维脚本 / API 服务 / 定时任务 / 容器入口}
- 是否有漏洞：{是/否}
- 关键点：{如：用户输入到 os.system 的数据流 / subprocess 列表参数的有效防御}

输出严格三段式格式。
```

### 3.4 Java/Python Web 漏洞（2500 条，DeepSeek 主力）

```
【数据类别】Java/Python Web 漏洞
【数量】2500 条（漏洞 625 + 安全 1875，1:3 配比）
【CWE 覆盖】CWE-89 SQLi / CWE-79 XSS / CWE-22 Path Traversal / CWE-502 反序列化 / CWE-611 XXE / CWE-352 CSRF / CWE-79 XSS / CWE-1336 SSTI / CWE-643 XPath / CWE-943 NoSQL / CWE-90 LDAP / CWE-441 信任边界 / CWE-639 IDOR / CWE-862 缺失授权 / CWE-306 缺失认证 / CWE-601 开放重定向 / CWE-117 日志注入 / CWE-798 硬编码凭证

【生成要求】
1. 模拟真实 Web 框架代码：Spring/Django/Flask/Express/FastAPI
2. 漏洞样本必须包含真实业务逻辑（用户登录、订单查询、文件上传、API 调用），不要教科书式 demo
3. 防御迷惑样本：包含部分防御但不充分的代码（如 replace("'", "") 转义、startswith 未规范化、部分 LDAP 编码）
4. 注意力分散样本：包含无关安全措施（如 bcrypt + LDAP 注入、CSRF token + SQLi），教模型不被分散
5. 框架代码样本：JSON-RPC eval、动态模板、插件动态导入——真实漏洞不要误判为演示代码

【用户提示词模板】
请生成 1 条 {CWE-XXX 漏洞类型} 的训练样本：
- 语言：{Java/Python/JavaScript/PHP}
- 框架：{Spring/Flask/Django/Express/原生}
- 场景：{如：用户认证 / 订单查询 / 文件上传 / 模板渲染}
- 是否有漏洞：{是/否}
- 难度：{典型/防御迷惑/注意力分散/框架代码}

输出严格三段式格式。
```

### 3.5 Shell/配置文件安全（1200 条）

```
【数据类别】Shell/配置文件安全
【数量】1200 条（漏洞 300 + 安全 900，1:3 配比）
【CWE 覆盖】CWE-78 命令注入 / CWE-798 硬编码凭证 / CWE-276 不安全文件权限 / CWE-326 弱加密 / CWE-1188 不安全默认初始化 / CWE-732 不安全资源权限

【生成要求】
1. 真实 Shell 脚本（bash/sh）、Dockerfile、docker-compose.yml、nginx.conf、systemd unit、CI/CD yaml
2. 漏洞模式：eval 用户输入、硬编码密码、chmod 777、弱 TLS 配置、容器以 root 运行
3. 安全样本：使用环境变量引用凭证、最小权限、TLS 1.2+、容器非 root 用户
4. 配置文件要真实可解析，不要伪配置

【用户提示词模板】
请生成 1 条 {CWE-XXX} 的训练样本：
- 类型：{Shell 脚本 / Dockerfile / nginx 配置 / systemd unit / CI/CD yaml}
- 场景：{如：部署脚本 / 反向代理 / 容器构建 / 定时任务}
- 是否有漏洞：{是/否}

输出严格三段式格式。
```

### 3.6 漏洞修复样例（1200 条）

> **2026-08-08 修订**：`fix_suggestion` 字段已从"完整修复代码"改为"行号锚定的
> 简短修复建议"（单行，如 `line 3: 应改为 ...` / `第 3 行：... 建议改为 ...`）。
> 原因：客户端 6K~8K 上下文下完整代码会被截断，且 FixVerifier 已证伪（瓶颈在
> 模型未输出 fix_suggestion，而非验证器）。后续蒸馏 fix pack 时按新格式生成。

```
【数据类别】漏洞修复样例
【数量】1200 条
【格式特殊】每条含 2 个版本：漏洞版本 + 修复版本

【生成要求】
1. 从 3.2-3.5 的漏洞样本中选取，生成对应的修复版本
2. 修复必须真正消除漏洞，不能引入新问题
3. 教模型"不仅报漏洞，还要给可用补丁"
4. 输出格式特殊：在 fix_suggestion 字段给出完整修复代码，而非简单建议

【用户提示词模板】
请针对以下漏洞代码生成修复样例：
```{语言}
{漏洞代码}
```
漏洞类型：{CWE-XXX}
要求：
1. 给出修复后的完整代码
2. 说明修复原理（1-2 句话）
3. 确认修复不引入新漏洞

输出三段式，fix_suggestion 字段给出完整修复代码块。
```

---

## 四、Kimi K3 提示词

### 4.1 系统提示词

```
你是一名资深安全研究员，专精内存安全与长代码库审计。你正在为代码漏洞检测模型生成高质量训练样本。

【你的核心优势】
- 长上下文（1M）+ Delta Attention，能跨 .so 追踪调用链
- 在 Redis 双重释放（CVE-2026-25589）上 27 分钟自主挖出 0day
- 看雪实测三模型中误报最少、精度最高

【关键约束——必须遵守】
1. 输出必须极度简洁：你的原生长链推理（动辄数万 token 的调用链追踪）8B 模型学不会。本次输出必须压成 ≤5 步、≤590 token
2. 每步锚定行号：不要展开调用链细节，只保留"第 X 行 free(ptr) → 第 Y 行 return *ptr"这种关键锚点
3. 三段式格式：[代码片段] → [≤5步推理] → [JSON结论]
4. 负样本 1:3 配比

【输出压扁示例】
错误（你的原生风格，8B 学不会）：
"从 main() 进入 process_request()，在第 42 行调用 parse_header()，该函数在第 87 行 malloc 了 64 字节给 header_buf，然后在第 92 行通过 strncpy 拷贝数据，接着在第 105 行 free(header_buf)，但第 108 行的 error_handler 路径仍引用 header_buf..."

正确（压扁后，8B 可学）：
"1. 第 105 行 free(header_buf) 释放内存
2. 第 108 行 error_handler 路径仍解引用 header_buf
3. free 后未置 NULL
4. 错误路径触发 UAF
5. CWE-416 UAF，Critical"

【CWE 归因规则】
（同 DeepSeek 系统提示词的 CWE 归因部分）
```

### 4.2 C/C++ 内存漏洞重构（800 条）

```
【数据类别】C/C++ 内存漏洞重构
【数量】800 条（漏洞 200 + 安全 600，1:3 配比）
【K3 优势】跨 .so 调用链追踪、Redis 式 0day 挖掘

【生成要求】
1. 代码场景真实：网络协议解析、文件系统驱动、内存池、对象生命周期管理
2. 漏洞必须涉及跨函数或跨文件的调用链，但输出必须压扁为 ≤5 步
3. 重点覆盖：UAF / Double Free / Heap Overflow / TOCTOU / Integer Overflow 导致的缓冲区溢出
4. 安全样本：使用 RAII、智能指针、free 后置 NULL、边界检查、原子操作
5. 每个漏洞的 CoT 必须压成以下格式：
   [漏洞类型] {CWE-XXX}
   [位置] file.c:{行号}
   [关键证据] {1 句话核心}
   [3-5 步推理] 1) ... 2) ... 3) ...
   [修复] {1 句话}

【用户提示词模板】
请生成 1 条 {CWE-XXX 内存漏洞} 的训练样本：
- 语言：{C/C++}
- 场景：{如：协议解析 / 内存池 / 对象生命周期 / 多线程同步}
- 难度：{中等/困难}（必须跨函数或跨文件）
- 是否有漏洞：{是/否}

【关键】输出必须压成 ≤5 步，不要展开调用链细节。8B 模型学不会数万 token 的追踪。
```

### 4.3 跨文件分块审计（1200 条）

```
【数据类别】跨文件分块审计
【数量】1200 条（漏洞 300 + 安全 900，1:3 配比）
【K3 优势】长上下文 + 跨文件业务漏洞（越权、N+1、循环引用）

【这是新增类别——模拟文件切割工具的产出】
8B 模型上下文有限，无法处理长文件。本类样本教模型：
1. 在单个文件块（≤4K token）内识别漏洞
2. 结合"上游调用方摘要"判断跨文件风险
3. 标注"需结合上游 X 函数验证"的待确认项

【输入格式特殊】
每条样本的 user 消息包含两部分：
1. 【当前文件块】{≤4K token 的代码片段}
2. 【上游调用方摘要】{200 token 内的调用方信息，如"server.js 第 45 行调用此模块的 handleRequest(req)，req 来自 HTTP 请求，未做认证"}

【输出格式特殊】
分析过程必须包含：
1. 本块内的数据流分析（≤3 步）
2. 跨文件风险标注："需结合上游 {X 函数} 验证 {Y 条件}"
3. 待确认项（如有）："本块内未见 {Z}，但需确认上游调用方是否 {条件}"

【生成要求】
1. 场景：微服务架构、模块化项目、前后端分离
2. 漏洞类型：信任边界绕过（CWE-441）、IDOR（CWE-639）、缺失授权（CWE-862）、SSRF（CWE-918）、跨文件 SQL 注入
3. 安全样本：上游调用方已做认证/授权，本块内无需重复
4. 代码必须分块：模拟 tree-sitter 按函数边界切割的产出

【用户提示词模板】
请生成 1 条跨文件分块审计样本：
- 漏洞类型：{CWE-XXX 或 无漏洞}
- 场景：{如：微服务 API / 模块化后端 / 前后端分离}
- 文件角色：{入口文件 / 中间处理 / 数据访问层}
- 上游调用方：{简述调用方是否做了认证/授权}

输出格式：
- user 消息含【当前文件块】+【上游调用方摘要】
- assistant 含本块分析 + 跨文件风险标注 + 待确认项
- CoT ≤5 步
```

---

## 五、GLM-5.2 提示词

### 5.1 系统提示词

```
你是一名资深安全研究员，专精 CWE 标准化与 CVSS 评分。你正在为代码漏洞检测模型生成严格格式的训练样本。

【你的核心优势】
- 指令遵循稳定，JSON 合法性 100%
- 结构化输出强，适合标准化流水线
- SWE-bench Pro 62.1

【你的任务】
1. 生成 CWE+CVSS 严格格式样本（1500 条）：补 8B 模型的格式短板
2. 生成负样本（无漏洞代码）：配合 1:3 配比
3. 作为格式锚：DeepSeek/K3 的输出最终改写填充为 GLM schema

【严格格式要求】
1. 每条样本的 JSON 必须包含完整字段，缺一不可
2. CVSS 3.1 向量必须符合 FIRST.org 标准
3. CWE 编号必须在 MITRE 官方列表内
4. vulnerability_type 必须以 CWE-XXX 开头
5. CoT ≤5 步，每步锚定行号

【CVSS 3.1 向量格式】
格式：CVSS:3.1/AV:{N|A|L|P}/AC:{L|H}/PR:{N|L|H}/UI:{N|R}/S:{U|C}/C:{H|L|N}/I:{H|L|N}/A:{H|L|N}
示例：CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N（SQL 注入，9.1 Critical）
示例：CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N（反射型 XSS，5.4 Medium）

【CWE 归因规则】
（同 DeepSeek 系统提示词的 CWE 归因部分）
```

### 5.2 CWE+CVSS 严格格式（1500 条）

```
【数据类别】CWE+CVSS 严格格式
【数量】1500 条（漏洞 1050 + 安全 450，此处负样本比例不同，因为其他类别已有大量负样本）
【目的】补 8B 模型格式短板，让模型稳定输出结构化字段

【生成要求】
1. 覆盖 6 类漏洞类型，每类约 175 条漏洞 + 75 条安全：
   - 注入类（CWE-89/78/95/90/643/943/917）
   - 访问控制类（CWE-639/862/306/441/384）
   - 密码学类（CWE-327/329/347/330/798）
   - 并发与逻辑类（CWE-362/915/1321/843/208）
   - 资源管理与内存类（CWE-416/415/502/611/190）
   - 信息泄露与配置类（CWE-200/601/117/22/79/352）
2. 每条漏洞样本必须含 CVSS 3.1 向量 + 分数 + 严重等级
3. JSON 字段比其他类别多 cvss_vector / cvss_score 两个字段
4. 格式严格到字符级：字段顺序固定、无多余空格、无注释

【输出格式（GLM 严格版）】
```json
{
  "has_vulnerability": true,
  "vulnerability_type": "CWE-89 SQL注入",
  "risk_level": "Critical",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "cvss_score": 9.1,
  "source": "request.args.get('id')",
  "sink": "cursor.execute(query)",
  "explanation": "request.args.get('id') → uid → str.format 拼接 → query → cursor.execute",
  "fix_suggestion": "使用参数化查询：cursor.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))"
}
```

【用户提示词模板】
请生成 1 条 CWE+CVSS 严格格式样本：
- CWE：{CWE-XXX}
- 语言：{Python/Java/JavaScript/C/PHP}
- 是否有漏洞：{是/否}
- 难度：{典型/中等}

输出必须含 cvss_vector 和 cvss_score 字段。
```

### 5.3 负样本生成（配合 1:3 配比）

```
【数据类别】负样本（无漏洞代码）
【数量】配合其他类别 1:3 配比，由 GLM 主导生成
【目的】避免模型"见代码就报漏洞"的偏置（DeepSeek 的已知毛病）

【生成要求】
1. 负样本必须包含真实有效的防御措施，不是"没有漏洞因为代码简单"
2. CoT 必须显式列出已检查的点："已检查 {X/Y/Z 点}，未发现可利用路径"
3. 防御措施必须多样化：参数化查询、shlex.quote、PreparedStatement、白名单、RAII、Lock、bcrypt、CSRF token、secrets.token_urlsafe、defusedxml、yaml.safe_load
4. 包含"防御有效但模式脆弱"的边界样本：如 shell=True + shlex.quote（有效但脆弱）、startswith 校验（有效但未规范化）
5. 负样本的 has_vulnerability 必须为 false，vulnerability_type 必须为 "none"

【负样本 CoT 模板】
分析过程：
输入点 {source} 来自 {来源}。数据流经 {中间处理}，最终传递给 {sink}。防御措施 {防御描述}，有效阻断 {威胁}。已检查：1) {检查点1} 2) {检查点2} 3) {检查点3}，未发现可利用路径，无漏洞。

【用户提示词模板】
请生成 1 条无漏洞训练样本：
- 语言：{Python/Java/JavaScript/Shell}
- 场景：{如：用户查询 / 文件操作 / 命令执行 / 密码存储}
- 防御措施：{如：参数化查询 / shlex.quote / PreparedStatement / 白名单}

输出严格三段式，has_vulnerability=false。
```

---

## 六、质量要求与反偏置

### 6.1 各模型反偏置重点

| 模型 | 已知弱点 | 反偏置措施 |
|---|---|---|
| DeepSeek | 内存类"近半误报" | 强制锚定行号 + "宁可漏报不要误报" + 负样本 1:3 |
| Kimi K3 | 原生长链数万 token | 硬约束 ≤5 步 + 压扁示例 + "8B 学不会调用链" |
| GLM-5.2 | 推理速度慢、指令漂移 | 格式严格 + 固定字段顺序 + CVSS 标准化 |

### 6.2 质量门禁（生成后由审查脚本检查）

每条样本必须通过以下检查（详见审查脚本框架）：
1. JSON schema 完整且可解析
2. CWE 编号在 MITRE 官方列表内
3. 行号标注在代码行数范围内
4. CoT 步数 ≤5
5. CoT token ≤590
6. has_vulnerability 与 vulnerability_type 一致
7. 负样本 has_vulnerability=false 且 vulnerability_type="none"
8. 无训练-测试泄漏（Jaccard ≥0.5）

### 6.3 分层审查（详见审查脚本框架）

- L1 规则校验（全量，免费）
- L2 三模型交叉投票（全量，API 成本）
- L3 闭源模型仲裁（分歧 + 抽样，Claude Opus 4.1 主审）
- L4 金标准集校准（一次性，评估生成模型本身）

---

## 七、API 调用示例

### 7.1 DeepSeek V4-Flash

```python
import openai

client = openai.OpenAI(
    api_key="your-deepseek-api-key",
    base_url="https://api.deepseek.com/v1"
)

response = client.chat.completions.create(
    model="deepseek-chat",
    messages=[
        {"role": "system", "content": DEEPSEEK_SYSTEM_PROMPT},
        {"role": "user", "content": "请生成 1 条 CWE-78 命令注入的训练样本，语言 Python，场景运维脚本，有漏洞，难度中等。输出严格三段式格式。"}
    ],
    temperature=0.7,  # 多样性
    max_tokens=1024,  # 限制输出长度，强制简洁
    response_format={"type": "json_object"}  # 可选，部分 API 支持
)
```

### 7.2 Kimi K3

```python
import openai

client = openai.OpenAI(
    api_key="your-kimi-api-key",
    base_url="https://api.moonshot.cn/v1"
)

response = client.chat.completions.create(
    model="kimi-k3",
    messages=[
        {"role": "system", "content": KIMI_SYSTEM_PROMPT},
        {"role": "user", "content": "请生成 1 条 CWE-416 UAF 的训练样本，语言 C，场景协议解析，有漏洞，难度困难（跨函数）。输出必须压成 ≤5 步，不要展开调用链细节。"}
    ],
    temperature=0.5,  # K3 已经保守，温度可以低一点
    max_tokens=1024   # 硬限制，防止长链
)
```

### 7.3 GLM-5.2

```python
import zhipuai

client = zhipuai.ZhipuAI(api_key="your-glm-api-key")

response = client.chat.completions.create(
    model="glm-5.2",
    messages=[
        {"role": "system", "content": GLM_SYSTEM_PROMPT},
        {"role": "user", "content": "请生成 1 条 CWE+CVSS 严格格式样本，CWE-89 SQL注入，语言 Python，有漏洞，难度典型。输出必须含 cvss_vector 和 cvss_score 字段。"}
    ],
    temperature=0.3,  # GLM 格式稳定，温度低保证一致性
    max_tokens=1024
)
```

### 7.4 批量生成建议

```python
# 每类数据分批生成，每批 50-100 条
# 每批后立即跑 L1 规则校验，过滤格式错误
# 累积 500 条后跑 L2 交叉投票
# 分歧样本送 L3 闭源仲裁

BATCH_SIZE = 50
CATEGORIES = {
    "c-memory": {"model": "deepseek", "count": 1000, "vuln_ratio": 0.25},
    "penetration": {"model": "deepseek", "count": 1800, "vuln_ratio": 0.25},
    "web-vuln": {"model": "deepseek", "count": 2500, "vuln_ratio": 0.25},
    "shell-config": {"model": "deepseek", "count": 1200, "vuln_ratio": 0.25},
    "fix-example": {"model": "deepseek", "count": 1200, "vuln_ratio": 1.0},  # 全漏洞
    "c-memory-k3": {"model": "kimi", "count": 800, "vuln_ratio": 0.25},
    "crossfile-audit": {"model": "kimi", "count": 1200, "vuln_ratio": 0.25},
    "cwe-cvss": {"model": "glm", "count": 1500, "vuln_ratio": 0.7},
}
```

---

## 八、生成顺序建议

1. **GLM-5.2 先行**：生成 1500 条 CWE+CVSS 严格格式样本，作为格式锚
2. **DeepSeek 主力**：按 3.2→3.3→3.4→3.5→3.6 顺序生成 7700 条
3. **Kimi K3 补位**：生成 2000 条 C/C++ 内存重构 + 跨文件分块审计
4. **每批 L1 校验**：格式错误的立即重新生成
5. **累积 500 条后 L2 投票**：标记分歧
6. **分歧样本 L3 仲裁**：Claude Opus 4.1
7. **合并去重 + 泄漏审计**：Jaccard ≥0.5
8. **输出 train_chatml_v9max.jsonl**
