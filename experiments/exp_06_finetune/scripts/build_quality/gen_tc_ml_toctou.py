#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成 CWE-843/401/367/123/362 训练样本（ChatML JSONL 格式）。

覆盖类别：
  - CWE-843 Access of Resource Using Incompatible Type (Type Confusion): 5 条
  - CWE-401 Missing Release of Memory after Effective Lifetime (Memory Leak): 5 条
  - CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition: 5 条
  - CWE-123 Write-what-where Condition: 3 条
  - CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization: 2 条

配比：14 漏洞正样本 + 6 安全负样本（hard negative）。

用法：
  cd ~/文档/code/毕业设计/experiments/exp_06_finetune
  python3 scripts/build_quality/gen_tc_ml_toctou.py
"""
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(PROJECT_ROOT))
from graduation_project.prompts import BASE_PROMPT as SYSTEM_PROMPT
from graduation_project.schema import parse_verdict

# 脚本位于 experiments/exp_06_finetune/scripts/build_quality/，
# parents[2] = exp_06_finetune，数据目录为 exp_06_finetune/data
DATA_DIR = Path(__file__).resolve().parents[2] / "data"
OUTPUT_FILE = DATA_DIR / "quality" / "hard_samples_tc_ml_toctou.jsonl"

# 标准英文 CWE 名称（任务要求）
CWE_843 = "CWE-843 Access of Resource Using Incompatible Type"
CWE_401 = "CWE-401 Missing Release of Memory after Effective Lifetime"
CWE_367 = "CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition"
CWE_123 = "CWE-123 Write-what-where Condition"
CWE_362 = "CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization"


# ---------------------------------------------------------------------------
# 样本定义（20 条）
# ---------------------------------------------------------------------------
SAMPLES = [
    # =====================================================================
    # CWE-843 Type Confusion（5 条：3 漏洞 + 2 安全）
    # =====================================================================

    # ----- 1. 漏洞：C++ RPC union 类型混淆 -----
    {
        "code": """// RPC 服务端：根据 type_id 从 union 读取，未校验客户端写入类型
#include <cstdint>
#include <cstring>

union Payload {
    int64_t as_int;
    double  as_double;
    char    as_str[16];
};

struct RpcMsg {
    uint32_t type_id;          // 1=int 2=double 3=string (客户端可控)
    Payload  payload;
};

int64_t handle(const RpcMsg& msg) {
    // 漏洞：仅按客户端给的 type_id 选择 union 成员访问
    if (msg.type_id == 1) return msg.payload.as_int;        // line 18
    if (msg.type_id == 2) return (int64_t)msg.payload.as_double;  // line 19
    if (msg.type_id == 3) {
        // 客户端声称 string，但 payload 内存仍按 int 读取 -> 类型混淆
        return msg.payload.as_int;                            // line 22
    }
    return 0;
}

extern "C" int64_t dispatch(const RpcMsg* m) { return handle(*m); }""",
        "language": "cpp",
        "filename": "vuln_cwe843_union_type_confusion.cpp",
        "is_vuln": True,
        "vulnerability_type": CWE_843,
        "risk_level": "High",
        "source": "line 13: msg.type_id (网络可控的 RpcMsg::type_id 字段)",
        "sink": "line 18-22: msg.payload.as_int / as_double 访问 union 成员",
        "explanation": "RpcMsg::type_id (line 13) 来自网络输入 -> handle() 按 type_id 选择 union 成员 (line 18-22) -> 客户端可声称 type_id=3 但实际写入 int，或反之 -> union 成员按非实际写入类型读取，导致内存被以不兼容类型解释 (CWE-843)",
        "fix_suggestion": "line 18-22: 不要依赖客户端 type_id 选择 union 成员；改用 std::variant<int64_t, double, std::string> 在协议层包装，并用 std::visit 类型安全分发，类型由服务端解析时确定而非客户端声称",
        "fix_code": """// RPC 服务端：用 std::variant + std::visit 实现类型安全访问
#include <cstdint>
#include <variant>
#include <string>
#include <stdexcept>

using Payload = std::variant<int64_t, double, std::string>;

struct RpcMsg {
    uint32_t type_id;
    Payload  payload;   // 解析层已用 variant 包装，类型与实际存储一致
};

struct Visitor {
    int64_t operator()(int64_t v) const { return v; }
    int64_t operator()(double v) const { return static_cast<int64_t>(v); }
    int64_t operator()(const std::string& v) const {
        throw std::runtime_error("type mismatch: string payload cannot be read as int");
    }
};

int64_t handle(const RpcMsg& msg) {
    // 安全：std::visit 按 variant 实际存储类型分发，与客户端 type_id 无关
    return std::visit(Visitor{}, msg.payload);
}

extern "C" int64_t dispatch(const RpcMsg* m) { return handle(*m); }""",
        "cot": """分析过程：
1. line 7-11 定义 union Payload，三种成员共享同一块内存。
2. line 13 RpcMsg::type_id 是 uint32_t，注释标注"客户端可控"——这是污染源，攻击者可任意设置。
3. line 16 handle() 函数完全依赖 msg.type_id 决定访问 union 的哪个成员（line 18/19/22）。
4. 关键漏洞：union 成员的"活跃类型"由最后一次写入决定，但服务端从未校验客户端是否真的按 type_id 写入了对应类型。攻击者发送 type_id=3 但 payload 实际是 int64 字节，line 22 按 int 读取 string 内存；或发送 type_id=1 但实际只写了 4 字节，line 18 读取 8 字节 union 越界。
5. 这是典型 CWE-843：内存被以与实际存储不兼容的类型访问。

结论：存在类型混淆漏洞 (CWE-843)，客户端通过 type_id 字段控制 union 成员的解释方式。""",
    },

    # ----- 2. 漏洞：JavaScript 对象形状混淆 -----
    {
        "code": """// Node.js RPC：根据 msg.kind 决定访问哪个 payload 字段
const express = require('express');
const app = express();
app.use(express.json());

function applyUpdate(msg) {
    // msg.kind 来自客户端，未在协议层校验 payload 形状
    if (msg.kind === 'increment') {
        return msg.payload.amount + 1;              // line 9
    }
    if (msg.kind === 'rename') {
        // 漏洞：若客户端发 {kind:'rename', payload:{amount: 42}}
        // msg.payload.name 是 undefined，调用 .toUpperCase() 抛 TypeError
        return msg.payload.name.toUpperCase();       // line 14
    }
    if (msg.kind === 'flag') {
        // payload 期望 {value: boolean}，但若为 {amount:1} 则 value 为 undefined
        return msg.payload.value ? 'on' : 'off';    // line 18
    }
    return null;
}

app.post('/rpc', (req, res) => {
    res.json({result: applyUpdate(req.body)});       // line 23
});
app.listen(3000);""",
        "language": "javascript",
        "filename": "vuln_cwe843_js_shape_confusion.js",
        "is_vuln": True,
        "vulnerability_type": CWE_843,
        "risk_level": "High",
        "source": "line 23: req.body (HTTP POST JSON body，msg.kind 与 msg.payload 形状均由客户端控制)",
        "sink": "line 14: msg.payload.name.toUpperCase() (以 string 方法访问非 string 类型)",
        "explanation": "req.body (line 23) -> applyUpdate(msg) -> 按 msg.kind (line 9/14/18) 选择 payload 字段访问 -> 客户端可发送 kind 与 payload 形状不匹配的请求 -> line 14 对 undefined 调用 .toUpperCase() 触发 TypeError，或 line 18 把 undefined 当 boolean 解释 (CWE-843)",
        "fix_suggestion": "line 9/14/18: 每个分支前用 typeof 严格校验 payload 字段类型；或在协议层用 JSON Schema 验证 req.body 形状后再进入 applyUpdate。见 fix_code 完整补丁。",
        "fix_code": """// Node.js RPC：每个分支显式校验 payload 形状再访问
const express = require('express');
const app = express();
app.use(express.json());

function applyUpdate(msg) {
    if (msg.kind === 'increment') {
        if (typeof msg.payload?.amount !== 'number' || !Number.isFinite(msg.payload.amount)) {
            throw new Error('invalid amount');
        }
        return msg.payload.amount + 1;
    }
    if (msg.kind === 'rename') {
        if (typeof msg.payload?.name !== 'string' || msg.payload.name.length === 0) {
            throw new Error('invalid name');
        }
        return msg.payload.name.toUpperCase();
    }
    if (msg.kind === 'flag') {
        if (typeof msg.payload?.value !== 'boolean') {
            throw new Error('invalid flag value');
        }
        return msg.payload.value ? 'on' : 'off';
    }
    throw new Error('unknown kind');
}

app.post('/rpc', (req, res) => {
    try {
        res.json({result: applyUpdate(req.body)});
    } catch (e) {
        res.status(400).json({error: e.message});
    }
});
app.listen(3000);""",
        "cot": """分析过程：
1. line 7 applyUpdate(msg) 接收 req.body 直接传入（line 23），msg.kind 与 msg.payload 完全由客户端 JSON 控制。
2. line 9 msg.payload.amount + 1 假设 amount 是 number；若客户端发 {kind:'increment', payload:{amount:'abc'}} 则变成字符串拼接。
3. line 14 msg.payload.name.toUpperCase() 假设 name 是 string；若 payload 是 {amount:42} 则 name 为 undefined，调用 .toUpperCase() 抛 TypeError；但更危险的是若 name 是 number 类型（如 {name:42}），JS 不会抛异常而是把 number 当对象访问 .toUpperCase，得到 undefined——这是 JS 的隐式类型混淆。
4. line 18 msg.payload.value ? 'on' : 'off' 假设 value 是 boolean；若客户端发 {value: 0}（falsy 但非 boolean）会被当作 off，{value: 1} 当作 on，类型语义被混淆。
5. 根因：服务端信任 msg.kind 决定 payload 形状，但未做运行时形状校验。这是 CWE-843（Access of Resource Using Incompatible Type）。

结论：存在类型混淆漏洞 (CWE-843)，客户端可通过 kind 与 payload 形状不匹配触发不兼容类型访问。""",
    },

    # ----- 3. 漏洞：PHP strcmp 类型混淆绕过 -----
    {
        "code": """<?php
// 登录验证：strcmp 比较密码，传入数组导致类型混淆
session_start();

function verifyPassword($input, $storedHash) {
    // 漏洞：未检查 $input 是否为字符串
    // strcmp 收到数组参数时返回 NULL（PHP < 8.0），NULL == 0 为 true
    if (strcmp($input, $storedHash) == 0) {   // line 8
        return true;
    }
    return false;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['user'] ?? '';             // line 14
    $pass = $_POST['pass'] ?? '';             // line 15
    // 攻击：发送 pass[]=anything（数组），strcmp 返回 NULL == 0 -> true
    $expected = '$2y$10$abcdef...';          // 从 DB 取出的哈希
    if (verifyPassword($pass, $expected)) {   // line 18
        $_SESSION['user'] = $user;
        echo "Welcome, $user";
    } else {
        http_response_code(401);
        echo "Invalid";
    }
}
?>""",
        "language": "php",
        "filename": "vuln_cwe843_php_strcmp_array.php",
        "is_vuln": True,
        "vulnerability_type": CWE_843,
        "risk_level": "Critical",
        "source": "line 15: $_POST['pass'] (客户端可发送数组形式 pass[]=...)",
        "sink": "line 8: strcmp($input, $storedHash) == 0 (strcmp 对数组返回 NULL，== 0 为 true)",
        "explanation": "$_POST['pass'] (line 15) -> $pass -> verifyPassword($pass) (line 18) -> strcmp($input, $storedHash) (line 8) -> 若 $pass 是数组，strcmp 返回 NULL -> NULL == 0 在 PHP 松散比较下为 true -> 绕过密码校验 (CWE-843 类型混淆)",
        "fix_suggestion": "line 8: 改用 === 严格比较 strcmp 返回值，并在 strcmp 前用 is_string 校验 $input；或直接用 hash_equals 比较哈希避免 strcmp。见 fix_code。",
        "fix_code": """<?php
// 登录验证：用 hash_equals 严格比较，避免 strcmp 类型混淆
session_start();

function verifyPassword(string $input, string $storedHash): bool {
    // 类型提示强制 string；非 string 传入会抛 TypeError
    // hash_equals 返回 bool，避免 strcmp 的 NULL 问题
    return hash_equals($storedHash, $input);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['user'] ?? '';
    // 强制转换为 string，数组会被转为 'Array' 字符串
    $pass = is_string($_POST['pass'] ?? null) ? $_POST['pass'] : '';
    $expected = '$2y$10$abcdef...';
    if (verifyPassword($pass, $expected)) {
        $_SESSION['user'] = $user;
        echo "Welcome, " . htmlspecialchars($user, ENT_QUOTES, 'UTF-8');
    } else {
        http_response_code(401);
        echo "Invalid";
    }
}
?>""",
        "cot": """分析过程：
1. line 15 $pass = $_POST['pass'] ?? '' 获取用户输入。PHP 中若客户端发送 pass[]=x（数组形式），$pass 会变成 array 而非 string。
2. line 18 verifyPassword($pass, $expected) 将可能为数组的 $pass 传入函数。
3. line 8 strcmp($input, $storedHash) == 0 是漏洞核心：strcmp 在收到数组参数时返回 NULL（PHP < 8.0）而非整数比较结果。
4. NULL == 0 在 PHP 松散比较（==）下为 true，因此 strcmp 返回 NULL 时整个条件为 true，函数返回 true，密码校验被绕过。
5. 这是 CWE-843（类型混淆）：strcmp 期望 string 参数，但收到 array 时返回值类型从 int 变为 NULL，与 == 0 比较时发生隐式类型转换导致逻辑错误。
6. 攻击 payload：POST user=admin&pass[]=anything 即可绕过密码校验登录任意用户。

结论：存在类型混淆漏洞 (CWE-843)，攻击者通过数组参数绕过 strcmp 密码校验。""",
    },

    # ----- 4. 安全：C++ std::variant 类型安全访问 -----
    {
        "code": """// C++ RPC：使用 std::variant + std::visit 实现类型安全访问
#include <cstdint>
#include <variant>
#include <string>
#include <stdexcept>

using Payload = std::variant<int64_t, double, std::string>;

struct RpcMsg {
    uint32_t type_id;
    Payload  payload;   // 解析层已用 variant 包装，类型与实际存储一致
};

struct Visitor {
    int64_t operator()(int64_t v) const { return v; }
    int64_t operator()(double v) const { return static_cast<int64_t>(v); }
    int64_t operator()(const std::string& v) const {
        // string 分支不允许转 int，抛异常而非 reinterpret_cast
        throw std::runtime_error("type mismatch: string payload");
    }
};

int64_t handle(const RpcMsg& msg) {
    // 安全：std::visit 根据 variant 实际存储的类型分发
    // 客户端的 type_id 不再控制内存解释方式
    return std::visit(Visitor{}, msg.payload);   // line 26
}

extern "C" int64_t dispatch(const RpcMsg* m) { return handle(*m); }""",
        "language": "cpp",
        "filename": "safe_cwe843_cpp_variant.cpp",
        "is_vuln": False,
        "vulnerability_type": "none",
        "risk_level": "None",
        "source": "N/A",
        "sink": "N/A",
        "explanation": "Payload 用 std::variant 包装 (line 7)，类型由解析层写入时确定且不可变 -> handle() 用 std::visit (line 26) 按 variant 实际存储类型分发，客户端 type_id 不参与内存解释 -> 类型安全，无类型混淆路径",
        "fix_suggestion": "no fix needed",
        "fix_code": "N/A",
        "cot": """分析过程：
1. line 7 using Payload = std::variant<int64_t, double, std::string> 用类型安全的 variant 替代 union，variant 内部记录当前活跃类型。
2. line 13 RpcMsg::payload 类型为 Payload（variant），解析层在写入时已确定类型，客户端无法事后修改解释方式。
3. line 16-24 Visitor 结构体为每种类型提供重载，string 分支抛异常而非 reinterpret_cast，避免不兼容类型访问。
4. line 26 std::visit(Visitor{}, msg.payload) 是类型安全的分发：编译器保证调用与 variant 当前活跃类型匹配的重载，无法误访问。
5. 与漏洞版对比：原版依赖客户端 type_id 选择 union 成员，而 variant 的类型由 C++ 运行时记录，客户端无法绕过。
6. 即使客户端伪造 type_id=1 但 payload 实际是 string，std::visit 仍会调用 string 分支抛异常，而非按 int 读取内存。

结论：防御有效，无类型混淆漏洞。""",
    },

    # ----- 5. 安全：JavaScript 严格类型校验 -----
    {
        "code": """// Node.js RPC：每个分支显式校验 payload 字段类型再访问
const express = require('express');
const app = express();
app.use(express.json());

function applyUpdate(msg) {
    if (msg.kind === 'increment') {
        // 严格校验：payload.amount 必须是有限 number
        if (typeof msg.payload?.amount !== 'number' ||
            !Number.isFinite(msg.payload.amount)) {   // line 10
            throw new Error('invalid amount');
        }
        return msg.payload.amount + 1;
    }
    if (msg.kind === 'rename') {
        // 严格校验：payload.name 必须是非空 string
        if (typeof msg.payload?.name !== 'string' ||
            msg.payload.name.length === 0) {          // line 17
            throw new Error('invalid name');
        }
        return msg.payload.name.toUpperCase();
    }
    if (msg.kind === 'flag') {
        if (typeof msg.payload?.value !== 'boolean') {  // line 22
            throw new Error('invalid flag value');
        }
        return msg.payload.value ? 'on' : 'off';
    }
    throw new Error('unknown kind');
}

app.post('/rpc', (req, res) => {
    try {
        res.json({result: applyUpdate(req.body)});
    } catch (e) {
        res.status(400).json({error: e.message});
    }
});
app.listen(3000);""",
        "language": "javascript",
        "filename": "safe_cwe843_js_strict_typeof.js",
        "is_vuln": False,
        "vulnerability_type": "none",
        "risk_level": "None",
        "source": "N/A",
        "sink": "N/A",
        "explanation": "req.body 进入 applyUpdate -> 每个分支用 typeof 严格校验 payload 字段类型 (line 10/17/22) -> 不匹配抛异常而非继续访问 -> 类型混淆路径被阻断",
        "fix_suggestion": "no fix needed",
        "fix_code": "N/A",
        "cot": """分析过程：
1. line 9-11 increment 分支：用 typeof msg.payload?.amount !== 'number' && !Number.isFinite 校验，确保 amount 是有限数字后才做 +1 运算。
2. line 16-18 rename 分支：用 typeof msg.payload?.name !== 'string' && length === 0 校验，确保 name 是非空字符串后才调用 .toUpperCase()。
3. line 21-23 flag 分支：用 typeof msg.payload?.value !== 'boolean' 严格校验，避免 truthy/falsy 隐式转换导致语义混淆。
4. line 28-31 app.post 用 try/catch 捕获异常返回 400，避免服务崩溃。
5. 与漏洞版对比：原版直接按 msg.kind 访问 payload 字段无校验；本版在每个分支入口用 typeof 校验类型，类型不匹配立即抛异常，阻断了不兼容类型访问路径。
6. 防御有效：typeof 是 JS 运行时类型检查，无法被构造的 payload 绕过。

结论：防御有效，无类型混淆漏洞。""",
    },

    # =====================================================================
    # CWE-401 Memory Leak（5 条：3 漏洞 + 2 安全）
    # =====================================================================

    # ----- 6. 漏洞：C malloc 后错误路径未 free -----
    {
        "code": """/* C Web 服务：解析配置文件，错误路径未 free 堆内存 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* load_config(const char* path) {
    FILE* f = fopen(path, "r");            // line 7
    if (!f) return NULL;
    char* buf = malloc(8192);              // line 9
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, 8191, f);     // line 11
    if (n == 0) {
        /* 漏洞：fread 失败时直接返回，未 free(buf) */
        fclose(f);
        return NULL;                       // line 15 -> buf 泄漏
    }
    buf[n] = '\\0';
    fclose(f);
    return buf;                            // line 19 -> 调用方需 free
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        char* cfg = load_config(argv[i]);   // line 23
        if (cfg) printf("%s\\n", cfg);
        /* 漏洞：cfg 使用后未 free，每轮循环泄漏 8KB */
    }
    return 0;
}""",
        "language": "c",
        "filename": "vuln_cwe401_c_malloc_leak.c",
        "is_vuln": True,
        "vulnerability_type": CWE_401,
        "risk_level": "Medium",
        "source": "line 9: malloc(8192) 分配堆内存（fread 失败或调用方未 free 时泄漏）",
        "sink": "line 15: return NULL 未 free(buf); line 23-24: 调用方未 free(cfg)",
        "explanation": "malloc(8192) (line 9) -> fread 失败时 line 15 return NULL 未 free(buf) -> 8KB 泄漏; 调用方 line 23-24 收到 cfg 后使用完未 free -> 每次循环泄漏 8KB -> 长期运行服务内存持续增长 (CWE-401)",
        "fix_suggestion": "line 14-16: fread 失败分支加 free(buf) 再 return; line 23-25: 调用方使用完 cfg 后 free(cfg)。见 fix_code 完整补丁。",
        "fix_code": """/* C Web 服务：goto cleanup 模式确保所有路径释放资源 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* load_config(const char* path) {
    char* buf = NULL;
    FILE* f = fopen(path, "r");
    if (!f) return NULL;
    buf = malloc(8192);
    if (!buf) goto cleanup_f;
    size_t n = fread(buf, 1, 8191, f);
    if (n == 0) goto cleanup_buf;   /* 失败也走 cleanup，统一释放 */
    buf[n] = '\\0';
    fclose(f);
    return buf;                     /* 成功：所有权转移给调用方 */
cleanup_buf:
    free(buf);
cleanup_f:
    fclose(f);
    return NULL;
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        char* cfg = load_config(argv[i]);
        if (cfg) {
            printf("%s\\n", cfg);
            free(cfg);              /* 使用完立即释放 */
        }
    }
    return 0;
}""",
        "cot": """分析过程：
1. line 9 char* buf = malloc(8192) 分配 8KB 堆内存。
2. line 11 size_t n = fread(buf, 1, 8191, f) 读取文件。若文件为空或读取出错，n == 0。
3. line 14-16 漏洞1：n==0 时 fclose(f) 后 return NULL，但 buf 未 free，8KB 内存泄漏。每次读到空文件泄漏一次。
4. line 19 漏洞2：成功路径返回 buf 的所有权给调用方，但调用方需负责 free。
5. line 23-25 漏洞3：main 循环中 cfg = load_config()，使用 printf 后未 free(cfg)，每轮循环泄漏 8KB。
6. 对于长期运行的 Web 服务，每次请求泄漏 8KB 会导致内存持续增长，最终 OOM。这是 CWE-401（内存释放后有效生命周期结束前未释放）。

结论：存在内存泄漏漏洞 (CWE-401)，错误路径和调用方均未释放堆内存。""",
    },

    # ----- 7. 漏洞：C++ new 后异常/提前 return 未释放 -----
    {
        "code": """// C++ 服务：HTTP 处理器分配后异常路径泄漏
#include <vector>
#include <stdexcept>

class HttpRequest { public: const char* path() { return "/"; } };
class Filter {
public:
    virtual void process(HttpRequest&) = 0;
    virtual ~Filter() = default;
};
class AuthFilter : public Filter {
public:
    void process(HttpRequest&) override {}
};
class LogFilter : public Filter {
public:
    void process(HttpRequest&) override {}
};

void handle_request(HttpRequest& req) {
    Filter* authFilter = new AuthFilter();      // line 21
    Filter* logFilter  = new LogFilter();       // line 22
    // 漏洞1：若 LogFilter 构造抛异常，authFilter 不会释放
    if (strcmp(req.path(), "/health") == 0) {
        // 漏洞2：提前 return，两个 Filter 都未 delete
        return;                                  // line 26
    }
    authFilter->process(req);
    logFilter->process(req);
    // 漏洞3：函数正常结束也未 delete authFilter / logFilter
}                                                // line 31""",
        "language": "cpp",
        "filename": "vuln_cwe401_cpp_new_leak.cpp",
        "is_vuln": True,
        "vulnerability_type": CWE_401,
        "risk_level": "High",
        "source": "line 21-22: new AuthFilter() / new LogFilter() 分配堆对象",
        "sink": "line 26: return 未 delete; line 31: 函数结束未 delete",
        "explanation": "new AuthFilter (line 21) + new LogFilter (line 22) -> 提前 return (line 26) 或正常结束 (line 31) 均未 delete -> 每次请求泄漏两个 Filter 对象; 若 LogFilter 构造抛异常，authFilter 也泄漏 (CWE-401)",
        "fix_suggestion": "line 21-22: 改用 std::unique_ptr 持有 Filter，异常或正常 return 都会自动 delete。见 fix_code。",
        "fix_code": """// C++ 服务：用 std::unique_ptr 自动管理 Filter 生命周期
#include <memory>
#include <vector>
#include <stdexcept>

class HttpRequest { public: const char* path() { return "/"; } };
class Filter {
public:
    virtual void process(HttpRequest&) = 0;
    virtual ~Filter() = default;
};
class AuthFilter : public Filter {
public:
    void process(HttpRequest&) override {}
};
class LogFilter : public Filter {
public:
    void process(HttpRequest&) override {}
};

void handle_request(HttpRequest& req) {
    // unique_ptr 在出作用域（含异常、提前 return）时自动 delete
    auto authFilter = std::make_unique<AuthFilter>();
    auto logFilter  = std::make_unique<LogFilter>();
    if (strcmp(req.path(), "/health") == 0) {
        return;   // unique_ptr 析构自动释放
    }
    authFilter->process(req);
    logFilter->process(req);
    // 无需手动 delete，unique_ptr 自动释放
}""",
        "cot": """分析过程：
1. line 21 Filter* authFilter = new AuthFilter() 在堆上分配 AuthFilter 对象。
2. line 22 Filter* logFilter = new LogFilter() 在堆上分配 LogFilter 对象。
3. 漏洞1（异常路径）：若 line 22 new LogFilter() 抛 bad_alloc 异常，line 21 已分配的 authFilter 不会被释放（C++ 异常展开时不会调用 delete）。
4. line 25-27 漏洞2（提前 return）：若 req.path() == "/health"，函数直接 return，两个 Filter 指针都未 delete。
5. line 30-31 漏洞3（正常路径）：函数正常结束也未有 delete authFilter / logFilter 语句。
6. 这是一个高频调用的 HTTP 处理器，每次请求都泄漏两个对象，长期运行会导致内存持续增长。
7. 根因：裸指针 new/delete 模式在多出口函数中极易遗漏 delete，异常安全也无法保证。这是 CWE-401。

结论：存在内存泄漏漏洞 (CWE-401)，多个执行路径均未释放堆对象。""",
    },

    # ----- 8. 漏洞：Python 全局缓存无清理 -----
    {
        "code": """# Python 服务：用户会话缓存无清理，持续累积内存泄漏
import threading

class UserSession:
    def __init__(self, uid):
        self.uid = uid
        self.history = []   # 持续追加不清理

    def add_event(self, event):
        # 漏洞：history 列表永不清理，单会话内存持续增长
        self.history.append(event)         # line 11

# 全局缓存：会话对象从未清理
_sessions = {}                              # line 14

def get_session(uid):
    # 漏洞：每个新 uid 都创建并加入 _sessions，但永不删除
    if uid not in _sessions:
        _sessions[uid] = UserSession(uid)  # line 19
    return _sessions[uid]

def handle_request(uid, event):
    sess = get_session(uid)                # line 23
    sess.add_event(event)
    return sess.history[-1]

# 长时间运行的服务：_sessions 字典无限增长，
# 每个 session.history 也无限增长 -> 内存泄漏
def worker():
    import random, string
    while True:
        uid = ''.join(random.choices(string.ascii_lowercase, k=8))
        handle_request(uid, 'event')       # line 32

for _ in range(10):
    threading.Thread(target=worker, daemon=True).start()""",
        "language": "python",
        "filename": "vuln_cwe401_py_session_leak.py",
        "is_vuln": True,
        "vulnerability_type": CWE_401,
        "risk_level": "High",
        "source": "line 19: _sessions[uid] = UserSession(uid) 累积不清理; line 11: history.append(event) 单会话累积",
        "sink": "line 14: _sessions 全局字典无淘汰; line 11: self.history 无上限",
        "explanation": "get_session (line 19) 把新 UserSession 加入 _sessions 永不删除 -> _sessions 无限增长; UserSession.add_event (line 11) 持续 append history 永不清理 -> 单会话内存无限增长 -> 长期运行服务 OOM (CWE-401)",
        "fix_suggestion": "line 14: _sessions 改用带 TTL 的缓存（如 functools.lru_cache 或 cachetools.TTLCache）; line 11: history 限制最大长度（如 collections.deque(maxlen=1000)）。见 fix_code。",
        "fix_code": """# Python 服务：用 TTLCache + deque 限制会话与历史大小
import threading
import time
from collections import deque
from cachetools import TTLCache

class UserSession:
    def __init__(self, uid):
        self.uid = uid
        # 限制 history 最大长度，超过自动淘汰旧条目
        self.history = deque(maxlen=1000)

    def add_event(self, event):
        self.history.append(event)

# 全局缓存：TTL=3600s，maxsize=10000，自动淘汰过期会话
_sessions = TTLCache(maxsize=10000, ttl=3600)
_lock = threading.Lock()

def get_session(uid):
    with _lock:
        if uid not in _sessions:
            _sessions[uid] = UserSession(uid)
        return _sessions[uid]

def handle_request(uid, event):
    sess = get_session(uid)
    sess.add_event(event)
    return sess.history[-1]

def worker():
    import random, string
    while True:
        uid = ''.join(random.choices(string.ascii_lowercase, k=8))
        handle_request(uid, 'event')

for _ in range(10):
    threading.Thread(target=worker, daemon=True).start()""",
        "cot": """分析过程：
1. line 11 self.history.append(event) 持续向列表追加事件，从未清理或限制大小。单个会话长期运行会无限增长。
2. line 14 _sessions = {} 全局字典缓存所有会话，从未调用 del 或 _sessions.pop()。
3. line 19 _sessions[uid] = UserSession(uid) 每个新 uid 都创建并加入缓存，永不淘汰。
4. line 32 worker 模拟高并发请求，每轮用随机 uid 调用 handle_request。10 个线程持续运行。
5. 内存累积路径：worker -> handle_request -> get_session -> _sessions 增长 + UserSession.history 增长。
6. 对于 Web 服务，攻击者只需持续发请求（用不同 uid）即可让 _sessions 字典无限增长，最终 OOM。这是 CWE-401（有效生命周期结束后未释放内存）。
7. 注意：Python 的 GC 会回收无引用对象，但 _sessions 持有所有会话的强引用，GC 无法回收。

结论：存在内存泄漏漏洞 (CWE-401)，全局缓存与会话历史均无上限清理。""",
    },

    # ----- 9. 安全：C++ unique_ptr RAII -----
    {
        "code": """// C++ 服务：用 std::unique_ptr 自动管理堆内存，异常安全
#include <memory>
#include <vector>
#include <fstream>
#include <stdexcept>
#include <sstream>

std::string load_config(const std::string& path) {
    // 安全：unique_ptr 在出作用域（含异常）时自动释放
    auto buf = std::make_unique<char[]>(8192);   // line 10
    std::ifstream f(path);
    if (!f) throw std::runtime_error("open failed");
    f.read(buf.get(), 8191);                      // line 13
    // 即使 read 失败抛异常，buf 和 f 都会被自动析构释放
    buf[f.gcount()] = '\\0';
    return std::string(buf.get());
}

class Filter {
public:
    virtual void process() = 0;
    virtual ~Filter() = default;
};
class AuthFilter : public Filter {
public:
    void process() override {}
};
class LogFilter : public Filter {
public:
    void process() override {}
};

void handle_request() {
    // 安全：unique_ptr 持有 filter，异常或正常 return 都会自动删除
    auto auth = std::make_unique<AuthFilter>();  // line 32
    auto log  = std::make_unique<LogFilter>();   // line 33
    auth->process();
    log->process();
    // 无需手动 delete，unique_ptr 自动释放
}""",
        "language": "cpp",
        "filename": "safe_cwe401_cpp_unique_ptr.cpp",
        "is_vuln": False,
        "vulnerability_type": "none",
        "risk_level": "None",
        "source": "N/A",
        "sink": "N/A",
        "explanation": "make_unique<char[]> (line 10) 持有堆内存 -> unique_ptr 出作用域自动 delete[] -> ifstream 析构自动关闭 -> make_unique<Filter> (line 32-33) 异常安全 -> 无内存泄漏路径",
        "fix_suggestion": "no fix needed",
        "fix_code": "N/A",
        "cot": """分析过程：
1. line 10 auto buf = std::make_unique<char[]>(8192) 用 unique_ptr 持有 8KB 堆内存。
2. line 12-14 std::ifstream f 自动管理文件句柄；f.read 即使抛异常，f 和 buf 都会通过 RAII 析构释放。
3. line 15 buf[f.gcount()] = '\\0' 后返回 std::string(buf.get())，string 拷贝构造后 buf 出作用域自动 delete[]。
4. line 32-33 auto auth/log = std::make_unique<...Filter>() 用 unique_ptr 持有 Filter 对象。
5. line 34-35 auth->process() / log->process()，即使抛异常，unique_ptr 析构也会 delete。
6. 与漏洞版对比：原版用裸 new/delete，异常或多出口函数会遗漏 delete；本版用 unique_ptr 把释放责任交给 RAII，编译器保证所有路径释放。
7. 防御有效：unique_ptr 的析构函数在异常展开、提前 return、正常结束三种路径都会调用 delete，无内存泄漏路径。

结论：防御有效，无内存泄漏漏洞。""",
    },

    # ----- 10. 安全：C goto cleanup 模式 -----
    {
        "code": """/* C 服务：goto cleanup 模式确保所有路径释放资源 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* load_config(const char* path) {
    char* buf = NULL;
    FILE* f = fopen(path, "r");          // line 7
    if (!f) return NULL;
    buf = malloc(8192);                  // line 10
    if (!buf) goto cleanup_f;
    size_t n = fread(buf, 1, 8191, f);   // line 12
    if (n == 0) goto cleanup_buf;       /* 失败也走 cleanup，统一释放 */
    buf[n] = '\\0';
    fclose(f);
    return buf;                          /* 成功：所有权转移给调用方 */
cleanup_buf:
    free(buf);                           /* line 18: 失败路径释放 buf */
cleanup_f:
    fclose(f);                           /* line 20: 失败路径关闭 f */
    return NULL;
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        char* cfg = load_config(argv[i]);  /* line 25 */
        if (cfg) {
            printf("%s\\n", cfg);
            free(cfg);                    /* line 28: 使用完立即释放 */
        }
    }
    return 0;
}""",
        "language": "c",
        "filename": "safe_cwe401_c_goto_cleanup.c",
        "is_vuln": False,
        "vulnerability_type": "none",
        "risk_level": "None",
        "source": "N/A",
        "sink": "N/A",
        "explanation": "malloc (line 10) -> 失败路径 goto cleanup_buf -> free(buf) (line 18) + fclose(f) (line 20) 统一释放 -> 调用方 line 28 free(cfg) 使用完即释放 -> 无泄漏路径",
        "fix_suggestion": "no fix needed",
        "fix_code": "N/A",
        "cot": """分析过程：
1. line 7 FILE* f = fopen(path, "r") 打开文件，若失败直接 return NULL（此时 buf 尚未分配，无泄漏）。
2. line 10 buf = malloc(8192) 分配堆内存，若失败 goto cleanup_f 跳到 line 20 fclose(f) 后 return NULL（buf 为 NULL，free(NULL) 安全但此处未执行 free）。
3. line 12 fread 读取文件，若 n==0 表示读到空文件或出错，goto cleanup_buf 跳到 line 18 free(buf) 释放堆内存，再 fall through 到 line 20 fclose(f)。
4. line 15-16 成功路径：fclose(f) + return buf，所有权转移给调用方（buf 仍存活，调用方需负责 free）。
5. line 25-28 调用方：cfg = load_config()，使用 printf 后立即 free(cfg)，无累积泄漏。
6. 关键设计：所有失败路径都通过 goto 跳到 cleanup 标签统一释放资源，避免遗漏 free。这是 C 语言中处理多资源释放的标准模式（Linux 内核也大量使用）。
7. 与漏洞版对比：原版 fread 失败直接 return NULL 未 free(buf)；本版用 goto cleanup 确保失败路径也释放。

结论：防御有效，无内存泄漏漏洞。""",
    },

    # =====================================================================
    # CWE-367 TOCTOU Race Condition（5 条：4 漏洞 + 1 安全）
    # =====================================================================

    # ----- 11. 漏洞：C access() + open() TOCTOU -----
    {
        "code": """/* C 服务：先 access 检查权限再 open，存在 TOCTOU 竞争 */
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

int read_secret(const char* path) {
    /* 漏洞：access 和 open 之间存在时间窗口 */
    if (access(path, R_OK) != 0) {        // line 7: 检查点
        return -1;
    }
    /* 攻击者在此窗口内把 path 替换为 /etc/shadow 的符号链接 */
    int fd = open(path, O_RDONLY);        // line 11: 使用点
    if (fd < 0) return -1;
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n > 0) write(STDOUT_FILENO, buf, n);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    return read_secret(argv[1]);          // line 22: 用户可控 path
}""",
        "language": "c",
        "filename": "vuln_cwe367_c_access_open.c",
        "is_vuln": True,
        "vulnerability_type": CWE_367,
        "risk_level": "High",
        "source": "line 22: argv[1] (用户可控的文件路径)",
        "sink": "line 11: open(path, O_RDONLY) (access 检查后打开，可被符号链接替换)",
        "explanation": "argv[1] (line 22) -> access(path, R_OK) (line 7) 检查通过 -> 攻击者在 access 与 open 之间替换 path 为指向 /etc/shadow 的符号链接 -> open(path) (line 11) 打开被替换的文件 -> 读取敏感内容 (CWE-367 TOCTOU)",
        "fix_suggestion": "line 7-11: 移除 access 检查，直接 open 后用 fstat 校验文件描述符（而非路径）；并加 O_NOFOLLOW 防止符号链接。见 fix_code。",
        "fix_code": """/* C 服务：直接 open 后用 fstat 校验，避免 TOCTOU */
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>

int read_secret(const char* path) {
    /* 安全：直接 open，不在 open 前做 access 检查；O_NOFOLLOW 拒绝符号链接 */
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
    /* 安全：用 fstat 检查已打开的文件描述符，而非路径 */
    if (!S_ISREG(st.st_mode)) { close(fd); return -1; }
    if (st.st_uid != getuid()) { close(fd); return -1; }
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n > 0) write(STDOUT_FILENO, buf, n);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    return read_secret(argv[1]);
}""",
        "cot": """分析过程：
1. line 22 read_secret(argv[1])，argv[1] 是用户可控的文件路径。
2. line 7 access(path, R_OK) 检查调用进程是否有读权限。这是"检查点"（Time-of-check）。
3. line 11 open(path, O_RDONLY) 打开文件。这是"使用点"（Time-of-use）。
4. 关键漏洞：access 与 open 之间存在时间窗口。攻击者可在 access 通过后、open 执行前，把 path 指向的文件替换为符号链接指向 /etc/shadow。
5. access 检查的是"当前进程对 path 的权限"（基于进程 uid），但 open 打开的是"open 时刻 path 指向的实际文件"。两者操作的文件可能不同。
6. 经典攻击：攻击者先放一个自己有读权限的文件让 access 通过，然后在窗口内替换为指向 /etc/shadow 的符号链接。open 会以进程权限打开 /etc/shadow（若进程是 root 则可读）。
7. 这是 CWE-367（TOCTOU）：检查与使用之间资源状态可被改变。

结论：存在 TOCTOU 竞争漏洞 (CWE-367)，access 与 open 之间可被符号链接替换攻击。""",
    },

    # ----- 12. 漏洞：Python os.path.exists + open TOCTOU -----
    {
        "code": """# Python 服务：先检查文件存在再打开，TOCTOU
import os

def read_token(path):
    # 漏洞：exists 和 open 之间存在时间窗口
    if not os.path.exists(path):           # line 5: 检查点
        return None
    # 攻击者在此窗口把 path 替换为符号链接指向 /etc/shadow
    with open(path, 'r') as f:             # line 8: 使用点
        return f.read()

def handle_request(user_path):
    # user_path 来自用户输入
    token = read_token(user_path)          # line 13
    if token:
        return f"Token loaded: {token[:8]}..."
    return "Token not found"

if __name__ == '__main__':
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/token'
    print(handle_request(path))            # line 19: 用户可控 path
""",
        "language": "python",
        "filename": "vuln_cwe367_py_exists_open.py",
        "is_vuln": True,
        "vulnerability_type": CWE_367,
        "risk_level": "Medium",
        "source": "line 19: sys.argv[1] / user_path (用户可控的文件路径)",
        "sink": "line 8: open(path, 'r') (exists 检查后打开，可被替换)",
        "explanation": "user_path (line 13) -> os.path.exists(path) (line 5) 检查通过 -> 攻击者替换 path 为符号链接 -> open(path) (line 8) 打开被替换的文件 -> 读取敏感内容 (CWE-367)",
        "fix_suggestion": "line 5-8: 移除 exists 检查，直接用 open + try/except 处理 FileNotFoundError；若需校验文件属性，open 后用 os.fstat 检查文件描述符。见 fix_code。",
        "fix_code": """# Python 服务：直接 open 用异常处理，避免 TOCTOU
import os

def read_token(path):
    # 安全：直接 open，用异常处理文件不存在；不依赖 exists 检查
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)   # 拒绝符号链接
    except (FileNotFoundError, OSError):
        return None
    try:
        st = os.fstat(fd)        # 检查已打开的 fd，而非路径
        if not os.path.isfile(st.st_mode) if hasattr(os.path, 'isfile') else not stat.S_ISREG(st.st_mode):
            return None
        with os.fdopen(fd, 'r') as f:
            return f.read()
    except OSError:
        os.close(fd)
        return None

def handle_request(user_path):
    token = read_token(user_path)
    if token:
        return f"Token loaded: {token[:8]}..."
    return "Token not found"

if __name__ == '__main__':
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/token'
    print(handle_request(path))""",
        "cot": """分析过程：
1. line 19 path = sys.argv[1]，用户可控的文件路径。
2. line 13 handle_request(user_path) 把用户路径传入 read_token。
3. line 5 os.path.exists(path) 检查文件是否存在。这是检查点。
4. line 8 open(path, 'r') 打开文件。这是使用点。
5. 关键漏洞：exists 与 open 之间存在时间窗口。攻击者可在 exists 通过后、open 执行前，把 path 替换为指向 /etc/shadow 的符号链接。
6. 攻击场景：服务以 root 运行，攻击者提供一个 /tmp/token 路径，先放一个真实文件让 exists 通过，然后在窗口内替换为指向 /etc/shadow 的符号链接。open 以 root 权限打开 /etc/shadow，read 返回敏感内容。
7. 这是 CWE-367（TOCTOU）：Python 的 os.path.exists 与 open 之间非原子操作。
8. 防御缺失：未用 O_NOFOLLOW 拒绝符号链接，未用 fstat 校验已打开的文件描述符。

结论：存在 TOCTOU 竞争漏洞 (CWE-367)，exists 与 open 之间可被符号链接替换。""",
    },

    # ----- 13. 漏洞：Java File.exists + FileInputStream TOCTOU -----
    {
        "code": """// Java 服务：先检查文件存在再打开，TOCTOU
import java.io.*;
import java.nio.file.*;

public class TokenLoader {
    public String readToken(String path) throws IOException {
        // 漏洞：exists 和 new FileInputStream 之间存在窗口
        File f = new File(path);               // line 6
        if (!f.exists()) {                    // line 7: 检查点
            return null;
        }
        // 攻击者在此窗口内替换 path 为符号链接
        try (FileInputStream fis = new FileInputStream(f)) {  // line 11: 使用点
            byte[] buf = new byte[256];
            int n = fis.read(buf);
            return new String(buf, 0, n);
        }
    }

    public String handle(String userPath) {
        try {
            String token = readToken(userPath);   // line 19: 用户可控
            return token != null ? "Token: " + token.substring(0, 8) : "missing";
        } catch (IOException e) {
            return "error";
        }
    }
}""",
        "language": "java",
        "filename": "vuln_cwe367_java_exists_fis.java",
        "is_vuln": True,
        "vulnerability_type": CWE_367,
        "risk_level": "Medium",
        "source": "line 19: userPath (用户可控的文件路径)",
        "sink": "line 11: new FileInputStream(f) (exists 检查后打开，可被替换)",
        "explanation": "userPath (line 19) -> new File(path) (line 6) -> f.exists() (line 7) 检查通过 -> 攻击者替换 path 为符号链接 -> new FileInputStream(f) (line 11) 打开被替换文件 -> 读取敏感内容 (CWE-367)",
        "fix_suggestion": "line 7-11: 移除 exists 检查，直接用 try-with-resources 打开 FileInputStream 并捕获 FileNotFoundException；或用 java.nio.file.Files.newInputStream + LinkOption.NOFOLLOW_LINKS 拒绝符号链接。见 fix_code。",
        "fix_code": """// Java 服务：直接打开 + 拒绝符号链接，避免 TOCTOU
import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.*;

public class TokenLoader {
    public String readToken(String path) throws IOException {
        Path p = Paths.get(path);
        // 安全：直接打开，用 NOFOLLOW_LINKS 拒绝符号链接
        try (InputStream is = Files.newInputStream(p, LinkOption.NOFOLLOW_LINKS)) {
            byte[] buf = new byte[256];
            int n = is.read(buf);
            if (n <= 0) return null;
            // 安全：用 Files.readAttributes 检查已打开路径属性（仍可能有小窗口，
            // 但 NOFOLLOW_LINKS + 直接 open 已大幅缩小攻击面）
            BasicFileAttributes attrs = Files.readAttributes(p, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (!attrs.isRegularFile()) return null;
            return new String(buf, 0, n);
        } catch (NoSuchFileException e) {
            return null;
        }
    }

    public String handle(String userPath) {
        try {
            String token = readToken(userPath);
            return token != null ? "Token: " + token.substring(0, 8) : "missing";
        } catch (IOException e) {
            return "error";
        }
    }
}""",
        "cot": """分析过程：
1. line 19 handle(userPath) 接收用户可控路径。
2. line 6 File f = new File(path) 构造 File 对象（仅构造，不打开）。
3. line 7 f.exists() 检查文件是否存在。这是检查点。
4. line 11 new FileInputStream(f) 打开文件。这是使用点。
5. 关键漏洞：exists 与 FileInputStream 构造之间存在时间窗口。攻击者可在 exists 通过后、FileInputStream 打开前，把 path 替换为指向 /etc/shadow 的符号链接。
6. File.exists() 检查的是路径指向的当前文件，FileInputStream 打开的是"打开时刻路径指向的文件"。两者可能不同。
7. 攻击场景：服务以高权限运行，攻击者提供一个路径，先放真实文件让 exists 通过，窗口内替换为符号链接，FileInputStream 打开敏感文件。
8. 这是 CWE-367（TOCTOU）：Java 标准库的 File.exists 与 FileInputStream 之间非原子操作。

结论：存在 TOCTOU 竞争漏洞 (CWE-367)，exists 与 FileInputStream 之间可被符号链接替换。""",
    },

    # ----- 14. 漏洞：C /tmp 临时文件符号链接竞争 -----
    {
        "code": """/* C 服务：在 /tmp 创建日志文件，存在符号链接竞争 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void write_log(const char* msg) {
    char path[64];
    snprintf(path, sizeof(path), "/tmp/log_%d.txt", getpid());  // line 8
    /* 漏洞：先 unlink，再 fopen，攻击者可在中间插入符号链接 */
    unlink(path);                                   // line 11: 检查点
    FILE* f = fopen(path, "w");                     // line 12: 使用点
    if (!f) return;
    fprintf(f, "%s\\n", msg);
    fclose(f);
}

int main() {
    write_log("service started");                   // line 19
    return 0;
}""",
        "language": "c",
        "filename": "vuln_cwe367_c_tmp_symlink.c",
        "is_vuln": True,
        "vulnerability_type": CWE_367,
        "risk_level": "High",
        "source": "line 8: snprintf 生成 /tmp/log_<pid>.txt 路径（可预测）",
        "sink": "line 12: fopen(path, \"w\") (unlink 后创建，可被符号链接替换)",
        "explanation": "snprintf 生成可预测路径 (line 8) -> unlink(path) (line 11) 删除旧文件 -> 攻击者插入符号链接 path -> /etc/passwd -> fopen(path, 'w') (line 12) 覆盖符号链接指向的文件 -> 破坏 /etc/passwd (CWE-367)",
        "fix_suggestion": "line 11-12: 用 open(path, O_WRONLY|O_CREAT|O_EXCL, 0600) 原子创建，O_EXCL 失败则拒绝；或用 mkstemp 生成不可预测路径。见 fix_code。",
        "fix_code": """/* C 服务：用 O_EXCL 原子创建 + 不可预测路径，避免 TOCTOU */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

void write_log(const char* msg) {
    /* 安全：mkstemp 生成不可预测路径并原子创建文件 */
    char tmpl[] = "/tmp/log_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return;
    /* mkstemp 已用 O_EXCL 原子创建，无竞争窗口 */
    FILE* f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(tmpl); return; }
    fprintf(f, "%s\\n", msg);
    fclose(f);   /* 同时关闭 fd */
}

int main() {
    write_log("service started");
    return 0;
}""",
        "cot": """分析过程：
1. line 8 snprintf(path, ..., "/tmp/log_%d.txt", getpid()) 生成可预测路径（攻击者知道 pid 即可推断路径）。
2. line 11 unlink(path) 删除旧文件。这是检查点（清理）。
3. line 12 fopen(path, "w") 创建并打开新文件。这是使用点。
4. 关键漏洞：unlink 与 fopen 之间存在时间窗口。攻击者可在 unlink 后、fopen 前，创建指向 /etc/passwd 的符号链接 path。
5. fopen(path, "w") 会以写模式打开符号链接指向的 /etc/passwd（若进程有权限），fprintf 写入会覆盖 /etc/passwd 内容，破坏系统。
6. 路径可预测：getpid() 可通过 /proc/[pid]/status 或暴力枚举获取，攻击者能预先生成符号链接。
7. 这是 CWE-367（TOCTOU）：unlink 与 fopen 之间非原子，且路径可预测便于攻击者布线。
8. 防御缺失：未用 O_EXCL 原子创建，未用 mkstemp 生成不可预测路径。

结论：存在 TOCTOU 竞争漏洞 (CWE-367)，可预测路径 + unlink/fopen 竞争窗口导致符号链接攻击。""",
    },

    # ----- 15. 安全：C open + fstat 原子检查 -----
    {
        "code": """/* C 服务：直接 open 后用 fstat 校验，避免 TOCTOU */
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>

int read_secret(const char* path) {
    /* 安全：直接 open，不在 open 前做 access 检查 */
    int fd = open(path, O_RDONLY | O_NOFOLLOW);   /* line 7: 拒绝符号链接 */
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
    /* 安全：用 fstat 检查已打开的文件描述符，而非路径 */
    if (!S_ISREG(st.st_mode)) { close(fd); return -1; }   /* line 12 */
    if (st.st_uid != getuid()) { close(fd); return -1; } /* line 13 */
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n > 0) write(STDOUT_FILENO, buf, n);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    return read_secret(argv[1]);
}""",
        "language": "c",
        "filename": "safe_cwe367_c_open_fstat.c",
        "is_vuln": False,
        "vulnerability_type": "none",
        "risk_level": "None",
        "source": "N/A",
        "sink": "N/A",
        "explanation": "open(path, O_NOFOLLOW) (line 7) 原子打开并拒绝符号链接 -> fstat(fd) (line 10) 检查已打开的 fd 而非路径 -> S_ISREG + uid 校验 (line 12-13) 基于 fd 不可被替换 -> 无 TOCTOU 窗口",
        "fix_suggestion": "no fix needed",
        "fix_code": "N/A",
        "cot": """分析过程：
1. line 7 open(path, O_RDONLY | O_NOFOLLOW) 直接打开文件。O_NOFOLLOW 标志使 open 对符号链接返回 ELOOP，拒绝跟随符号链接。
2. 关键设计：不在 open 前做 access/exists 检查，避免"检查-使用"窗口。open 本身是原子操作（要么打开成功要么失败，无中间状态可被攻击）。
3. line 10 fstat(fd, &st) 获取已打开文件描述符的属性。fstat 操作的是 fd（内核中已固定的文件引用），而非路径，因此即使路径在 open 后被替换，fstat 检查的仍是 open 时刻打开的文件。
4. line 12 !S_ISREG(st.st_mode) 拒绝非普通文件（如设备文件、目录）。
5. line 13 st.st_uid != getuid() 拒绝非当前用户拥有的文件，防止打开其他用户的文件。
6. 与漏洞版对比：原版 access + open 之间有窗口可被符号链接替换；本版 open 后用 fstat 检查 fd，攻击者无法在 open 后替换已打开的文件描述符。
7. 防御有效：open + fstat 是处理 TOCTOU 的标准模式（CVE-2017-... 等多个真实漏洞的修复方式）。

结论：防御有效，无 TOCTOU 漏洞。""",
    },

    # =====================================================================
    # CWE-123 Write-what-where Condition（3 条：3 漏洞）
    # =====================================================================

    # ----- 16. 漏洞：C 设备驱动 ioctl 用户控制偏移 -----
    {
        "code": """/* C 设备驱动：ioctl 接收用户提供的偏移和值，写入任意位置 */
#include <stdint.h>
#include <string.h>

#define BUFSIZE 256
static char buffer[BUFSIZE];

/* 用户态：ioctl(fd, WRITE_CMD, struct { int offset; int value; }) */
struct write_req {
    int32_t  offset;    /* 客户端可控 */
    int64_t  value;      /* 客户端可控 */
};

int handle_write(struct write_req* req) {
    /* 漏洞：offset 未做边界检查，可正可负 */
    /* 写入 buffer[offset] = req->value，可写到 buffer 之外 */
    *(int64_t*)(buffer + req->offset) = req->value;   /* line 18 */
    return 0;
}

int dispatch(int cmd, void* arg) {
    if (cmd == 0x1001) return handle_write((struct write_req*)arg);
    return -1;
}""",
        "language": "c",
        "filename": "vuln_cwe123_c_ioctl_offset.c",
        "is_vuln": True,
        "vulnerability_type": CWE_123,
        "risk_level": "Critical",
        "source": "line 8: req->offset (用户可控的写入偏移); line 9: req->value (用户可控的写入值)",
        "sink": "line 18: *(int64_t*)(buffer + req->offset) = req->value (用户控制 where 和 what)",
        "explanation": "req->offset (line 8) + req->value (line 9) 来自 ioctl 参数 -> handle_write (line 17) -> *(buffer + req->offset) = req->value (line 18) 未校验 offset 范围 -> 攻击者设 offset 为负或超大值，写入 buffer 之外的任意内存地址 -> 可覆盖函数指针/GOT 表实现任意代码执行 (CWE-123)",
        "fix_suggestion": "line 18: 写入前校验 req->offset >= 0 且 req->offset + sizeof(int64_t) <= BUFSIZE；拒绝越界写入。见 fix_code。",
        "fix_code": """/* C 设备驱动：校验 offset 范围后再写入，避免 write-what-where */
#include <stdint.h>
#include <string.h>

#define BUFSIZE 256
static char buffer[BUFSIZE];

struct write_req {
    int32_t  offset;
    int64_t  value;
};

int handle_write(struct write_req* req) {
    /* 安全：校验 offset 范围，防止越界写入 */
    if (req->offset < 0 ||
        (size_t)req->offset + sizeof(int64_t) > BUFSIZE) {
        return -1;   /* 拒绝越界写入 */
    }
    /* 安全：offset 已校验，写入范围在 buffer 内 */
    memcpy(buffer + req->offset, &req->value, sizeof(int64_t));
    return 0;
}

int dispatch(int cmd, void* arg) {
    if (cmd == 0x1001) return handle_write((struct write_req*)arg);
    return -1;
}""",
        "cot": """分析过程：
1. line 8-9 struct write_req 含 offset 和 value 字段，均由客户端通过 ioctl 提供（注释标注"客户端可控"）。
2. line 17 handle_write(req) 接收用户提供的 write_req 结构体指针。
3. line 18 *(int64_t*)(buffer + req->offset) = req->value 是漏洞核心：
   - req->offset 控制写入位置（where）：可为负数（写到 buffer 之前的内存）或超大正数（写到 buffer 之后的内存）。
   - req->value 控制写入内容（what）：8 字节任意值。
4. 攻击场景：buffer 是全局静态数组（.bss 段），攻击者设 offset 为负值，可写到 buffer 之前的相邻全局变量（如函数指针表、函数指针 GOT 表），覆盖为 shellcode 地址或 system 函数地址，实现任意代码执行。
5. 这是 CWE-123（Write-what-where）：攻击者完全控制写入的目标地址（where）和写入的值（what）。
6. 防御完全缺失：无任何边界检查，直接信任用户提供的 offset。
7. 真实 CVE 案例：CVE-2017-7308（Linux packet socket）、CVE-2016-0728（Linux keyring）都是类似模式。

结论：存在 write-what-where 漏洞 (CWE-123)，用户可通过 offset 字段越界写入任意内存。""",
    },

    # ----- 17. 漏洞：C++ 共享内存用户控制偏移 -----
    {
        "code": """// C++ 服务：共享内存按用户提供的偏移写入
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

class ShmWriter {
    uint8_t* base_;
    size_t   size_;
public:
    ShmWriter(uint8_t* base, size_t sz) : base_(base), size_(sz) {}

    // 漏洞：offset 来自网络协议字段，未做边界检查
    void write_at(int64_t offset, int64_t value) {   // line 14
        // 漏洞：负 offset 或超大 offset 都会越界写入
        int64_t* p = reinterpret_cast<int64_t*>(base_ + offset);   // line 16
        *p = value;   // write-what-where：用户控制 where（offset）和 what（value）
    }
};

extern "C" void handle_packet(uint8_t* buf, size_t len) {
    // 模拟：buf 是 mmap 的共享内存，size=4096
    ShmWriter w(buf, 4096);
    // 从网络包解析 offset 和 value（用户可控）
    int64_t offset = *(int64_t*)(buf + 8);    // line 25: 用户可控
    int64_t value  = *(int64_t*)(buf + 16);   // line 26: 用户可控
    w.write_at(offset, value);                // line 27
}""",
        "language": "cpp",
        "filename": "vuln_cwe123_cpp_shm_offset.cpp",
        "is_vuln": True,
        "vulnerability_type": CWE_123,
        "risk_level": "Critical",
        "source": "line 25: *(int64_t*)(buf + 8) (网络包中的 offset 字段); line 26: *(int64_t*)(buf + 16) (网络包中的 value 字段)",
        "sink": "line 17: *p = value (reinterpret_cast 后写入用户控制的位置)",
        "explanation": "网络包 offset (line 25) + value (line 26) -> write_at(offset, value) (line 27) -> reinterpret_cast<int64_t*>(base_ + offset) (line 16) -> *p = value (line 17) 未校验 offset 范围 -> 攻击者写任意值到任意地址 (CWE-123)",
        "fix_suggestion": "line 14-17: write_at 内校验 offset >= 0 且 offset + sizeof(int64_t) <= size_，拒绝越界写入。见 fix_code。",
        "fix_code": """// C++ 服务：校验 offset 范围后再写入共享内存
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <sys/mman.h>
#include <unistd.h>

class ShmWriter {
    uint8_t* base_;
    size_t   size_;
public:
    ShmWriter(uint8_t* base, size_t sz) : base_(base), size_(sz) {}

    // 安全：校验 offset 范围，防止越界写入
    void write_at(int64_t offset, int64_t value) {
        if (offset < 0 ||
            (size_t)offset + sizeof(int64_t) > size_) {
            throw std::out_of_range("offset out of bounds");
        }
        // 安全：offset 已校验，写入范围在 base_[0, size_) 内
        std::memcpy(base_ + offset, &value, sizeof(int64_t));
    }
};

extern "C" void handle_packet(uint8_t* buf, size_t len) {
    ShmWriter w(buf, 4096);
    if (len < 24) return;
    int64_t offset = *(int64_t*)(buf + 8);
    int64_t value  = *(int64_t*)(buf + 16);
    try {
        w.write_at(offset, value);
    } catch (const std::out_of_range&) {
        /* 拒绝越界写入 */
    }
}""",
        "cot": """分析过程：
1. line 14 write_at(int64_t offset, int64_t value) 接收两个用户可控参数：offset（写入位置）和 value（写入值）。
2. line 16 int64_t* p = reinterpret_cast<int64_t*>(base_ + offset) 把 base_ 指针加上用户提供的 offset，得到目标地址。offset 是有符号 int64，可为负数。
3. line 17 *p = value 写入用户提供的 8 字节值到目标地址。
4. 攻击路径：line 25-26 从网络包 buf 解析 offset 和 value（用户完全控制）。line 27 调用 write_at(offset, value)。
5. 由于 base_ 是 mmap 的共享内存（典型大小 4096 字节），攻击者设 offset = -4096 可写到 base_ 之前 4096 字节的内存，设 offset = 0xFFFFFFFF 可写到 base_ 之后任意位置。
6. 这是 CWE-123（Write-what-where）：攻击者通过 offset 控制 where（写入地址），通过 value 控制 what（写入值）。
7. 危害：可覆盖相邻内存中的函数指针、vtable 指针、控制结构体，实现任意代码执行或权限提升。
8. 防御缺失：write_at 内未做任何边界检查，完全信任用户提供的 offset。

结论：存在 write-what-where 漏洞 (CWE-123)，用户可通过 offset 字段越界写入任意内存。""",
    },

    # ----- 18. 漏洞：C 数组索引越界写入 -----
    {
        "code": """/* C 服务：处理数组更新请求，索引来自网络未校验 */
#include <stdint.h>
#include <string.h>

#define MAX_ENTRIES 1024
static int64_t entries[MAX_ENTRIES];

struct update_req {
    int32_t  index;     /* 客户端可控 */
    int64_t  value;     /* 客户端可控 */
};

int update_entry(struct update_req* req) {
    /* 漏洞：req->index 可为负数或 >= MAX_ENTRIES */
    /* 写入 entries[index] = value，越界写入相邻内存 */
    entries[req->index] = req->value;   /* line 16 */
    return 0;
}

int process_packet(const uint8_t* data, size_t len) {
    if (len < sizeof(struct update_req)) return -1;
    return update_entry((struct update_req*)data);   /* line 22 */
}""",
        "language": "c",
        "filename": "vuln_cwe123_c_array_index.c",
        "is_vuln": True,
        "vulnerability_type": CWE_123,
        "risk_level": "Critical",
        "source": "line 8: req->index (网络包中的 index 字段); line 9: req->value (网络包中的 value 字段)",
        "sink": "line 16: entries[req->index] = req->value (用户控制索引和值，越界写入)",
        "explanation": "网络包 data (line 22) -> update_req{index, value} (line 8-9) -> entries[req->index] = req->value (line 16) 未校验 index 范围 -> 攻击者设 index 为负或 >= 1024 -> 越界写入相邻全局内存 -> 可覆盖其他全局变量/函数指针 (CWE-123)",
        "fix_suggestion": "line 16: 写入前校验 req->index >= 0 且 req->index < MAX_ENTRIES，拒绝越界索引。见 fix_code。",
        "fix_code": """/* C 服务：校验 index 范围后再写入，避免越界写入 */
#include <stdint.h>
#include <string.h>

#define MAX_ENTRIES 1024
static int64_t entries[MAX_ENTRIES];

struct update_req {
    int32_t  index;
    int64_t  value;
};

int update_entry(struct update_req* req) {
    /* 安全：校验 index 范围，防止越界写入 */
    if (req->index < 0 || req->index >= MAX_ENTRIES) {
        return -1;   /* 拒绝越界索引 */
    }
    /* 安全：index 已校验，写入范围在 entries[0, MAX_ENTRIES) 内 */
    entries[req->index] = req->value;
    return 0;
}

int process_packet(const uint8_t* data, size_t len) {
    if (len < sizeof(struct update_req)) return -1;
    return update_entry((struct update_req*)data);
}""",
        "cot": """分析过程：
1. line 7 static int64_t entries[MAX_ENTRIES] 是全局静态数组（1024 个 int64，共 8KB）。
2. line 8-9 struct update_req 含 index 和 value 字段，均由网络包直接 cast 而来（line 22）。
3. line 16 entries[req->index] = req->value 是漏洞核心：
   - req->index 控制 where：C 语言数组访问 entries[i] 等价于 *(entries + i)，i 为负或 >= 1024 时会访问数组之外的内存。
   - req->value 控制 what：8 字节任意值写入。
4. 攻击场景：entries 是 .bss 段全局数组，其前后是其他全局变量。攻击者设 index = -1 写到 entries 之前 8 字节，设 index = 1024 写到 entries 之后 8 字节。若相邻内存有函数指针或权限标志，可被覆盖。
5. int32_t index 是有符号整数，负值合法；MAX_ENTRIES=1024 但未校验 index < 1024。
6. 这是 CWE-123（Write-what-where）：用户通过 index 控制写入位置，通过 value 控制写入内容。
7. 与缓冲区溢出（CWE-787）区别：CWE-123 强调用户直接控制写入地址和值，而非顺序溢出。本例中 index 是任意整数，非顺序写入。

结论：存在 write-what-where 漏洞 (CWE-123)，用户可通过 index 字段越界写入任意位置。""",
    },

    # =====================================================================
    # CWE-362 并发执行共享资源未同步（2 条：1 漏洞 + 1 安全）
    # =====================================================================

    # ----- 19. 漏洞：Python 多线程共享字典无锁 -----
    {
        "code": """# Python 服务：多线程处理请求，共享订单字典无锁
import threading
import uuid

orders = {}   # 全局共享，无锁                 # line 5
_lock = threading.Lock()   # 已定义但未使用     # line 6

def create_order(user, amount):
    # 漏洞：读写 orders 字典未加锁
    order_id = str(uuid.uuid4())                # line 10
    orders[order_id] = {'user': user, 'amount': amount}  # line 11
    # 漏洞：检查与更新之间存在竞态
    if orders[order_id]['amount'] > 1000:       # line 13
        orders[order_id]['status'] = 'pending_approval'
    else:
        orders[order_id]['status'] = 'confirmed'
    return order_id

def update_amount(order_id, new_amount):
    # 漏洞：读改写非原子
    if order_id in orders:                      # line 19
        old = orders[order_id]['amount']        # line 20
        orders[order_id]['amount'] = old + new_amount  # line 21
    return orders.get(order_id)

def worker(user, amount):
    for _ in range(100):
        create_order(user, amount)             # line 26

# 多线程并发：orders 字典竞态
threads = [threading.Thread(target=worker, args=('alice', 100))
           for _ in range(10)]                 # line 30
for t in threads: t.start()
for t in threads: t.join()""",
        "language": "python",
        "filename": "vuln_cwe362_py_shared_dict.py",
        "is_vuln": True,
        "vulnerability_type": CWE_362,
        "risk_level": "High",
        "source": "line 5: orders = {} (全局共享字典，多线程读写无锁)",
        "sink": "line 11/13/21: orders[order_id] = ... / orders[order_id]['amount'] = ... (读改写非原子)",
        "explanation": "orders (line 5) 全局共享 -> create_order 写 orders (line 11) + 读改 status (line 13) 无锁 -> update_amount 读改写 amount (line 19-21) 非原子 -> 多线程并发 (line 30) 导致字典竞态 -> 数据丢失/状态不一致 (CWE-362)",
        "fix_suggestion": "line 11-14/19-21: 用 with _lock 包裹读写 orders 的临界区，确保原子性；或改用 threading.Lock 保护所有访问。见 fix_code。",
        "fix_code": """# Python 服务：用 threading.Lock 保护共享字典访问
import threading
import uuid

orders = {}
_lock = threading.Lock()

def create_order(user, amount):
    order_id = str(uuid.uuid4())
    # 安全：用锁保护整个读改写临界区
    with _lock:
        orders[order_id] = {'user': user, 'amount': amount}
        if orders[order_id]['amount'] > 1000:
            orders[order_id]['status'] = 'pending_approval'
        else:
            orders[order_id]['status'] = 'confirmed'
    return order_id

def update_amount(order_id, new_amount):
    # 安全：用锁保护读改写，避免竞态
    with _lock:
        if order_id in orders:
            old = orders[order_id]['amount']
            orders[order_id]['amount'] = old + new_amount
        return orders.get(order_id)

def worker(user, amount):
    for _ in range(100):
        create_order(user, amount)

threads = [threading.Thread(target=worker, args=('alice', 100))
           for _ in range(10)]
for t in threads: t.start()
for t in threads: t.join()""",
        "cot": """分析过程：
1. line 5 orders = {} 是全局共享字典，10 个线程并发读写。
2. line 6 _lock = threading.Lock() 虽然定义了锁但整个代码中从未使用（dead code，迷惑性）。
3. line 10-11 create_order 中 order_id 生成后写入 orders，无锁保护。多线程同时写可能导致 CPython 字典内部状态不一致（虽然 CPython GIL 保护单条字节码，但多步操作不原子）。
4. line 13 orders[order_id]['amount'] > 1000 读 amount 后设置 status，这是"检查-使用"模式，但中间无锁。若另一线程在 line 11 写入后、line 13 读取前修改了 amount，会读到不一致状态。
5. line 19-21 update_amount 是典型"读改写"竞态：line 19 检查存在性，line 20 读 amount，line 21 写新值。两线程同时执行可能都读到旧值，最终只加了一次 new_amount（丢失更新）。
6. line 30 启动 10 个线程并发调用 worker，每个 worker 调用 100 次 create_order，竞态窗口大。
7. CPython 的 GIL 仅保证单条字节码原子，多步操作（读-判断-写）仍可被打断。这是 CWE-362（共享资源并发执行未同步）。
8. 危害：订单丢失、金额错误、状态不一致。

结论：存在并发执行未同步漏洞 (CWE-362)，共享字典读写无锁导致竞态。""",
    },

    # ----- 20. 安全：Java ConcurrentHashMap + synchronized -----
    {
        "code": """// Java 服务：用 ConcurrentHashMap + 同步块保护共享状态
import java.util.concurrent.*;
import java.util.*;

public class OrderService {
    // 安全：使用并发安全的 ConcurrentHashMap
    private final ConcurrentHashMap<String, Order> orders = new ConcurrentHashMap<>();  // line 6
    private final Object approvalLock = new Object();   // line 7

    public String createOrder(String user, int amount) {
        String orderId = UUID.randomUUID().toString();
        Order o = new Order(user, amount);
        // 安全：put 是原子的
        orders.put(orderId, o);                          // line 13
        // 安全：审批状态用同步块保护读改写
        synchronized (approvalLock) {                    // line 15
            if (amount > 1000) {
                o.status = "pending_approval";
            } else {
                o.status = "confirmed";
            }
        }
        return orderId;
    }

    public void updateAmount(String orderId, int delta) {
        // 安全：compute 是原子的，避免读改写竞态
        orders.computeIfPresent(orderId, (k, v) -> {      // line 24
            v.amount += delta;
            return v;
        });
    }

    static class Order {
        String user; int amount; String status;
        Order(String u, int a) { user = u; amount = a; }
    }
}""",
        "language": "java",
        "filename": "safe_cwe362_java_concurrent_hashmap.java",
        "is_vuln": False,
        "vulnerability_type": "none",
        "risk_level": "None",
        "source": "N/A",
        "sink": "N/A",
        "explanation": "orders 用 ConcurrentHashMap (line 6) -> put (line 13) 原子操作 -> 审批状态用 synchronized 块 (line 15) 保护读改写 -> updateAmount 用 computeIfPresent (line 24) 原子读改写 -> 无竞态路径",
        "fix_suggestion": "no fix needed",
        "fix_code": "N/A",
        "cot": """分析过程：
1. line 6 orders = new ConcurrentHashMap<>() 使用并发安全的 Map 实现。ConcurrentHashMap 的 put/get 是线程安全的原子操作。
2. line 13 orders.put(orderId, o) 写入订单，ConcurrentHashMap 保证此操作原子性，无需外部锁。
3. line 15-20 synchronized (approvalLock) 用同步块保护"判断金额 + 设置 status"的读改写临界区。approvalLock 是专用锁对象（line 7），避免与 ConcurrentHashMap 内部锁冲突。
4. line 24 orders.computeIfPresent(orderId, (k, v) -> {...}) 是 ConcurrentHashMap 提供的原子读改写方法：在 ConcurrentHashMap 内部对 key 对应的 bucket 加锁，执行 lambda，保证"读取-修改-写回"原子性。
5. 与漏洞版对比：原版用普通 dict + 无锁读改写，导致丢失更新；本版用 ConcurrentHashMap 的原子方法 + synchronized 块保护复合操作。
6. 关键设计：单一操作（put/get）用 ConcurrentHashMap 自带的原子性；复合操作（判断+修改）用 synchronized 块或 computeIfPresent。这是处理并发共享资源的标准模式。
7. 防御有效：ConcurrentHashMap + synchronized 阻断了所有竞态路径。

结论：防御有效，无并发执行未同步漏洞。""",
    },
]


# ---------------------------------------------------------------------------
# ChatML 构建
# ---------------------------------------------------------------------------
def build_sample(sample: dict) -> dict:
    """构建训练样本的 ChatML 格式（system=BASE_PROMPT, user=代码, assistant=CoT+JSON）。"""
    code = sample["code"]
    language = sample["language"]
    filename = sample["filename"]

    user_prompt = (
        f"代码片段（文件名: {filename}，语言: {language}）：\n"
        f"```{language}\n{code}\n```\n\n"
        f"请先给出分析过程，然后在最后给出 JSON 结论。"
    )

    if sample["is_vuln"]:
        json_block = {
            "has_vulnerability": True,
            "vulnerability_type": sample["vulnerability_type"],
            "risk_level": sample["risk_level"],
            "source": sample["source"],
            "sink": sample["sink"],
            "explanation": sample["explanation"],
            "fix_suggestion": sample["fix_suggestion"],
            "fix_code": sample["fix_code"],
        }
    else:
        json_block = {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": sample["explanation"],
            "fix_suggestion": "no fix needed",
            "fix_code": "N/A",
        }

    assistant_content = (
        sample["cot"]
        + "\n\n```json\n"
        + json.dumps(json_block, ensure_ascii=False, indent=2)
        + "\n```"
    )

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": assistant_content},
        ]
    }


# ---------------------------------------------------------------------------
# 验证
# ---------------------------------------------------------------------------
def verify(recs):
    """验证 parse_verdict 全部通过 + source/sink 含行号 + 字段完整。"""
    import re as _re
    from collections import Counter

    total = len(recs)
    pos = 0
    neg = 0
    parse_ok = 0
    src_line = 0
    sink_line = 0
    fix_code_present = 0
    cwes = Counter()
    langs = Counter()

    for i, r in enumerate(recs, 1):
        assistant = r["messages"][2]["content"]
        v = parse_verdict(assistant)
        if not v:
            print(f"  [FAIL] sample {i}: parse_verdict 返回空")
            continue
        has_vuln = v.get("has_vulnerability")
        if has_vuln is True:
            pos += 1
        elif has_vuln is False:
            neg += 1
        else:
            print(f"  [FAIL] sample {i}: has_vulnerability 非 bool: {has_vuln}")
            continue

        parse_ok += 1

        # 检查 source/sink 含行号
        if _re.search(r"line\s*\d+", str(v.get("source", "")), _re.I):
            src_line += 1
        if _re.search(r"line\s*\d+", str(v.get("sink", "")), _re.I):
            sink_line += 1
        # 检查 fix_code 非空（正样本）
        if has_vuln is True and v.get("fix_code") and v.get("fix_code") != "N/A":
            fix_code_present += 1
        # CWE 与语言统计
        cwes[str(v.get("vulnerability_type", "?"))[:40]] += 1
        m = _re.search(r"```(\w+)", r["messages"][1]["content"])
        langs[m.group(1) if m else "?"] += 1

    print(f"\n===== 验证结果 ({total} 条) =====")
    print(f"  正样本(漏洞) : {pos}")
    print(f"  负样本(安全) : {neg}")
    print(f"  parse_verdict 成功: {parse_ok}/{total}")
    print(f"  source 含行号: {src_line}/{pos} ({src_line/max(pos,1)*100:.1f}% 正样本)")
    print(f"  sink   含行号: {sink_line}/{pos} ({sink_line/max(pos,1)*100:.1f}% 正样本)")
    print(f"  fix_code 非空: {fix_code_present}/{pos} ({fix_code_present/max(pos,1)*100:.1f}% 正样本)")
    print(f"  语言分布: {dict(langs.most_common())}")
    print(f"  CWE 分布:")
    for cwe, n in cwes.most_common():
        print(f"    {n}x  {cwe}")

    all_ok = (parse_ok == total and pos == 14 and neg == 6
              and src_line == pos and sink_line == pos
              and fix_code_present == pos)
    if all_ok:
        print("\n[OK] 所有验证通过：14 漏洞 + 6 安全，parse_verdict 全部成功，"
              "source/sink 均含行号，fix_code 均完整。")
    else:
        print("\n[FAIL] 验证未通过，请检查上述输出。")
    return all_ok


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    # 确保输出目录存在
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    print(f"生成 {len(SAMPLES)} 条 CWE-843/401/367/123/362 样本")
    print(f"  漏洞样本: {sum(1 for s in SAMPLES if s['is_vuln'])}")
    print(f"  安全样本: {sum(1 for s in SAMPLES if not s['is_vuln'])}")
    print(f"输出文件: {OUTPUT_FILE}")

    # 构建并写入
    recs = []
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for sample in SAMPLES:
            obj = build_sample(sample)
            recs.append(obj)
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    print(f"\n[OK] 写入 {len(recs)} 条到 {OUTPUT_FILE}")

    # 验证
    all_ok = verify(recs)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
