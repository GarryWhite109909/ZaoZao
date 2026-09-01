# -*- coding: utf-8 -*-
"""生成 g20 信任边界辨析组任务包(13 个蒸馏任务)。

组成:
  seeds.jsonl   7 条 D 类原样本(524/1449/8196/8037/7862/8025/7980)
                user=原样本,尾部附 g20 辨析框架(无答案倾向)
  twins.jsonl   4 个孪生代码(524/1449/7980/8037 的"边界内可控输入"版本)
                攻击链在文件内闭合,教师独立分析应得出 vuln
  refills.jsonl C 类补位 2 条(7301/1289),user 取自 redistill manifest,hint 给审计实测事实

orig 命名: "g20-seed-<id>" / "g20-twin-<id>" / "g20-refill-<id>"
蒸馏后按 orig 前缀从 _wave1_out/success.jsonl 过滤合并。
"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]  # exp_06_finetune/
ADJ = BASE / "audit/adjudicate_v2_15"
G20MAT = ADJ / "g20_judge_material.jsonl"
MANIFEST = BASE / "audit/redistill_manifest_v2_15_wave1.jsonl"
OUT = BASE / "corpus/repair_wave/wave2_g20"
OUT.mkdir(exist_ok=True)

SEED_HINT = (
    "【g20 信任边界辨析要求】\n"
    "本样本属于信任边界辨析组。请先明确判定污染输入的信任层级(HTTP 请求输入 / CLI 参数 / 环境变量 / "
    "配置文件 / 管理员后台配置 / 服务端内部状态),再论证该层级在本文件的调用语境下是否可被攻击者触达。"
    "判 vuln 的必要条件:文件内存在攻击者可控 source 行到危险 sink 行的完整链路;"
    "若污染源仅由部署者/管理员/开发者设定、或攻击链需要引用文件外行为才能闭合,则判 safe,"
    "并在 explanation 中记录配置加固建议与隔离边界注记。分析必须逐一核对你引用的行号与代码实际内容。"
)

TWIN_TAIL = "\n请先给出分析过程，然后在最后给出 JSON 结论。"

TWIN_524 = """// 容器编排服务 admin_api.js —— 运维平台提供的容器初始化命令配置接口
const express = require('express');
const { execSync } = require('child_process');
const fs = require('fs');
const app = express();
app.use(express.json());

const configPath = '/etc/container-config.json';

// 读取容器配置
function loadConfig() {
  return JSON.parse(fs.readFileSync(configPath, 'utf8'));
}

// 执行初始化命令
function runUserCommands(commands) {
  for (const cmd of commands) {
    const result = execSync(cmd, { shell: true, encoding: 'utf8' });
    console.log(`[init] ${result.trim()}`);
  }
}

// GET /api/container/init-status
app.get('/api/container/init-status', (req, res) => {
  res.json({ config: loadConfig() });
});

// POST /api/container/init-commands —— 前端"自定义初始化"表单提交的命令
app.post('/api/container/init-commands', (req, res) => {
  const commands = req.body.commands;
  fs.writeFileSync(configPath, JSON.stringify({ userInitCommands: commands }));
  runUserCommands(commands);
  res.json({ ok: true });
});

app.listen(8080);
"""

TWIN_1449 = """#!/bin/bash
# web_deploy.cgi —— 运维平台网页触发部署入口(CGI)
set -e

DEPLOY_DIR="/opt/myapp"
BACKUP_DIR="/var/backups/myapp"

# 从 CGI 查询串解析参数
POST_DEPLOY_SCRIPT=$(echo "$QUERY_STRING" | sed -n 's/.*post_script=\\([^&]*\\).*/\\1/p' | sed 's/%20/ /g')
APP_VERSION=$(echo "$QUERY_STRING" | sed -n 's/.*version=\\([^&]*\\).*/\\1/p')

# 备份当前版本
tar czf "$BACKUP_DIR/backup_$(date +%Y%m%d_%H%M%S).tar.gz" "$DEPLOY_DIR" 2>/dev/null || true

# 下载新版本
echo "Downloading version $APP_VERSION..."
wget -q "http://downloads.internal.example.com/app-$APP_VERSION.tar.gz" -O /tmp/app.tar.gz
tar xzf /tmp/app.tar.gz -C "$DEPLOY_DIR"

# 执行调用方指定的部署后脚本
if [ -n "$POST_DEPLOY_SCRIPT" ]; then
    echo "Running post-deploy script..."
    eval "$POST_DEPLOY_SCRIPT"
fi

rm -f /tmp/app.tar.gz
echo "Deployment complete"
"""

TWIN_7980 = '''"""
MCP HTTP Bridge.

Exposes MCP server registration over the web API so that tenant
dashboards can attach MCP tools to their agents.

Usage (web): POST /api/agents/{id}/mcp {"command": "npx -y @modelcontextprotocol/server-filesystem ."}
"""

import json
import shlex
import subprocess
from typing import Any, Dict, Tuple, List


class MCPHttpBridge:
    """Bridges MCP server commands coming from HTTP payloads."""

    def parse_mcp_command(self, command: str, env_vars: str = None) -> Tuple[str, List[str], Dict[str, str]]:
        """Parse MCP command string into command, args, and environment."""
        parts = shlex.split(command)
        cmd, args = parts[0], parts[1:]
        env: Dict[str, str] = {}
        if env_vars:
            for kv in env_vars.split(","):
                k, _, v = kv.partition("=")
                env[k] = v
        return cmd, args, env

    def register_from_request(self, payload: dict) -> Dict[str, Any]:
        """Register an MCP server from the tenant dashboard form.

        payload: {"command": "...", "env": "KEY=value,KEY2=value2"}
        The dashboard posts whatever the tenant typed into the form.
        """
        command = payload["command"]
        env_vars = payload.get("env")
        cmd, args, env = self.parse_mcp_command(command, env_vars)
        # 启动租户注册的 MCP server 子进程
        proc = subprocess.Popen([cmd] + args, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return {"pid": proc.pid, "cmd": cmd}
'''

TWIN_8037 = """package config

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"time"
)

// UserStorageRequest 是用户在控制台"自定义对象存储"表单提交的参数。
type UserStorageRequest struct {
	Endpoint  string `json:"endpoint"`
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
	Bucket    string `json:"bucket"`
}

// NewUserStorageClient 根据控制台表单提交的参数构造对象存储客户端。
// 兼容用户自建 MinIO 的自签证书，默认放宽 TLS 校验。
func NewUserStorageClient(req *http.Request) (*http.Client, *UserStorageRequest, error) {
	var form UserStorageRequest
	if err := json.NewDecoder(req.Body).Decode(&form); err != nil {
		return nil, nil, err
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, &form, nil
}

// PushSnapshot 把节点快照上传到用户指定的对象存储端点。
func PushSnapshot(req *http.Request, data []byte) error {
	client, form, err := NewUserStorageClient(req)
	if err != nil {
		return err
	}
	resp, err := client.Post("https://"+form.Endpoint+"/upload", "application/octet-stream", bytes.NewReader(data))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
"""

TWINS = [
    ("g20-twin-524", "javascript", TWIN_524),
    ("g20-twin-1449", "bash", TWIN_1449),
    ("g20-twin-7980", "python", TWIN_7980),
    ("g20-twin-8037", "go", TWIN_8037),
]

REFILL_HINT = {
    7301: ("教师此前声称的漏洞链依赖 install.js(本文件之外)的行为;请核对本文件内是否存在 exec/system/"
           "child_process 等命令执行 sink,以及每个 sink 的输入源是否在本文件内可见且攻击者可控。"
           "引用文件外行为作为论证依据无效。"),
    1289: ("此前教师的行号锚多处与代码实际内容不符,请逐行核对引用行号;"
           "另注意把部署配置的加固建议(hardening)与漏洞判定区分开。"),
}

def lang_of(user):
    import re
    m = re.search(r"语言: (\w+)", user)
    return m.group(1) if m else "text"

def main():
    # seeds
    mat = [json.loads(l) for l in G20MAT.open(encoding="utf-8") if l.strip()]
    seeds = []
    for r in mat:
        vid = r["v2_14_id"]
        user = r["messages"][1]["content"] + "\n\n" + SEED_HINT
        seeds.append({"orig": f"g20-seed-{vid}", "user": user})
    with (OUT / "seeds.jsonl").open("w", encoding="utf-8") as f:
        for t in seeds:
            f.write(json.dumps(t, ensure_ascii=False) + "\n")
    print(f"seeds: {len(seeds)}")

    # twins
    twins = []
    for orig, lang, code in TWINS:
        user = f"代码片段（语言: {lang}）：\n```{lang}\n{code}```{TWIN_TAIL}"
        twins.append({"orig": orig, "user": user})
    with (OUT / "twins.jsonl").open("w", encoding="utf-8") as f:
        for t in twins:
            f.write(json.dumps(t, ensure_ascii=False) + "\n")
    print(f"twins: {len(twins)}")

    # refills: 取本次裁决追加的 manifest 条目
    man = [json.loads(l) for l in MANIFEST.open(encoding="utf-8") if l.strip()]
    refills = []
    for e in man:
        if e.get("reason") != "adjudication_C_delete":
            continue
        ln = e["orig_line"]
        vid = None
        # 行号反查 v2_14 id
        for v, l in _id2v15().items():
            if l == ln and v in REFILL_HINT:
                vid = v
                break
        if vid is None:
            continue
        refills.append({"orig": f"g20-refill-{vid}", "user": e["user"],
                        "hint": REFILL_HINT[vid]})
    with (OUT / "refills.jsonl").open("w", encoding="utf-8") as f:
        for t in refills:
            f.write(json.dumps(t, ensure_ascii=False) + "\n")
    print(f"refills: {len(refills)}")

    # 行数与可过门自检:孪生代码行数(供 G3 参考)与 G2 特征粗检
    import re
    for orig, lang, code in TWINS:
        n = len(code.rstrip("\n").split("\n"))
        low = code.lower()
        print(f"  {orig}: {n} 行代码, exec={'exec' in low} subprocess={'subprocess' in low} eval={'eval' in low}")

def _id2v15():
    AUD = BASE / "audit"
    del_ids = {json.loads(l)["id"] for l in (AUD / "agent_audit_v2_14/out/manifest_DELETE.jsonl").open(encoding="utf-8") if l.strip()} | {8288, 8968}
    id2v15 = {}
    n = 0
    for i in range(1, 10022):
        if i in del_ids:
            continue
        n += 1
        id2v15[i] = n
    return id2v15

if __name__ == "__main__":
    main()
