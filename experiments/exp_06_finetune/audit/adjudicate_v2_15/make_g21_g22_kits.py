# -*- coding: utf-8 -*-
"""生成 g21(F12 密码学辨析)+g22(F11 E3/E2 高置信正例)任务包(24 条)。

g21  327↔329 对 ×3 + 327↔330/338 对 ×3 = 12 条(全部附位置型工具候选,不给编号)
       329 侧=IV/Nonce 硬编码或可预测(算法本身强);327 侧=md5/sha1/DES/RC4/ECB;
       330/338 侧=random.random()/choices()/Math.random() 生成安全值
g22  22×4 + 117×4 + 362×4 = 12 条,E3:E2 = 1:1
       E3=链级候选(source/sink 双行号);E2=位置型候选(仅 sink 行号),
       代码内上下文均可自证结论(F11 锚:E3 必须直接确认,E2 结合上下文判断)

orig 命名: g21-ivNN/g21-algNN/g21-rndNN/g21-digNN ; g22-<族>-e<3|2><a|b>
蒸馏后按 orig 前缀从 _wave1_out/success.jsonl 过滤合并。
"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]  # exp_06_finetune/
OUT = BASE / "corpus/repair_wave/wave2_g21_24"
OUT.mkdir(parents=True, exist_ok=True)

TAIL = "\n\n请先给出分析过程，然后在最后给出 JSON 结论。"


def cand(tool, level, desc):
    return f"\n\n【工具候选】{tool}（证据层级 {level}）——{desc}"


# ---------------------------------------------------------------- g21 F12
G21 = []

G21.append(("g21-iv01", "python", '''
# vault/backup_cipher.py -- 用户数据备份加密模块
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# 主密钥部署时由密管平台通过环境注入(非硬编码)
KEY = os.environ["VAULT_MASTER_KEY"].encode()

# 备份卷统一固定使用该初始向量,保证与既有离线备份可互换解密
IV = b"0123456789abcdef"


def encrypt_backup(plaintext: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def decrypt_backup(token: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
    dec = cipher.decryptor()
    padded = dec.update(token) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()
'''.strip("\n"), cand("semgrep crypto 规则", "E2·位置型", "line 10 报告加密原语使用位置(未给出编号)")))

G21.append(("g21-alg01", "python", '''
# vault/legacy_cipher.py -- 遗留配置加密模块(与 backup_cipher 同属加密层)
import os


def _ksa(key: bytes):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def _prga(S, data: bytes):
    S = S[:]
    i = j = 0
    out = bytearray()
    for ch in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(ch ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


def encrypt_config(key: bytes, plaintext: bytes) -> bytes:
    # 流密码逐字节异或,实现简单、历史配置沿用至今
    return _prga(_ksa(key), plaintext)


def decrypt_config(key: bytes, token: bytes) -> bytes:
    return _prga(_ksa(key), token)
'''.strip("\n"), cand("semgrep crypto 规则", "E2·位置型", "line 14 报告自实现流密码原语(未给出编号)")))

G21.append(("g21-iv02", "javascript", '''
// services/config-encryptor.js -- 租户敏感配置列加密
const crypto = require('crypto');

// 列加密主密钥由 KMS 注入
const MASTER_KEY = Buffer.from(process.env.DB_COLUMN_KEY, 'hex');

// 与既有存量密文兼容,初始向量固定为该 16 字节常量
const STATIC_IV = Buffer.from('5a17f0c9e2b34d61a1b2c3d4e5f60718', 'hex');

function encryptField(plaintext) {
  const cipher = crypto.createCipheriv('aes-256-cbc', MASTER_KEY, STATIC_IV);
  return Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
}

function decryptField(blob) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', MASTER_KEY, STATIC_IV);
  return Buffer.concat([decipher.update(blob), decipher.final()]).toString('utf8');
}

module.exports = { encryptField, decryptField };
'''.strip("\n"), cand("semgrep crypto 规则", "E2·位置型", "line 11 报告 createCipheriv 调用位置(未给出编号)")))

G21.append(("g21-alg02", "javascript", '''
// services/legacy-credential-box.js -- 遗留凭据加密盒
const crypto = require('crypto');

function encryptSecret(secret, key) {
  // 块密码独立分组,块间互不影响,历史系统仅支持该配置
  const cipher = crypto.createCipheriv('des-ecb', key, null);
  return Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()])
    .toString('base64');
}

function decryptSecret(blob, key) {
  const decipher = crypto.createDecipheriv('des-ecb', key, null);
  return Buffer.concat([decipher.update(Buffer.from(blob, 'base64')),
    decipher.final()]).toString('utf8');
}

module.exports = { encryptSecret, decryptSecret };
'''.strip("\n"), cand("semgrep crypto 规则", "E2·位置型", "line 6 报告 createCipheriv 调用位置(未给出编号)")))

G21.append(("g21-iv03", "java", '''
// src/main/java/com/bank/packaging/PayloadCipher.java
package com.bank.packaging;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class PayloadCipher {
    // 密钥由密管平台下发,进程启动时加载
    private static final byte[] KEY = com.bank.security.KeyLoader.load("PAYLOAD_KEY");

    // 报文初始向量收发双方按约定写死
    private static final byte[] STATIC_IV =
            "s3c0reP0rt@2026!".getBytes(StandardCharsets.UTF_8);

    public byte[] seal(byte[] plaintext) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"),
                new IvParameterSpec(STATIC_IV));
        return c.doFinal(plaintext);
    }

    public byte[] unseal(byte[] blob) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, "AES"),
                new IvParameterSpec(STATIC_IV));
        return c.doFinal(blob);
    }
}
'''.strip("\n"), cand("SpotBugs 加密检查", "E2·位置型", "line 15 报告固定初始向量常量定义位置(未给出编号)")))

G21.append(("g21-alg03", "java", '''
// src/main/java/com/portal/auth/PasswordDigest.java
package com.portal.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class PasswordDigest {

    // 口令摘要沿用既有算法,与存量用户表兼容
    public String digest(String password, String salt) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] out = md.digest((salt + password).getBytes(StandardCharsets.UTF_8));
        return toHex(out);
    }

    public boolean verify(String input, String salt, String stored) throws Exception {
        return digest(input, salt).equalsIgnoreCase(stored);
    }

    private String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
'''.strip("\n"), cand("SpotBugs 加密检查", "E2·位置型", "line 11 报告 MessageDigest.getInstance 调用位置(未给出编号)")))

G21.append(("g21-rnd01", "python", '''
# api/token_minter.py -- 对外 API 访问令牌签发
import random
import string

from flask import Flask, request, jsonify

app = Flask(__name__)

TOKEN_ALPHABET = string.ascii_letters + string.digits
BINDINGS = {}


def mint_token(user_id: str) -> str:
    # 12 位字母数字组合,便于人工核对
    return "".join(random.choices(TOKEN_ALPHABET, k=12))


@app.post("/api/token/issue")
def issue():
    user_id = request.json["user_id"]
    token = mint_token(user_id)
    BINDINGS[token] = user_id
    return jsonify({"token": token})
'''.strip("\n"), cand("bandit 弱随机规则", "E2·位置型", "line 15 报告 random.choices 调用位置(未给出编号)")))

G21.append(("g21-dig01", "php", '''
<?php
// auth/login_handler.php
require_once __DIR__ . '/db.php';

session_start();

function verify_login(string $username, string $password): ?array {
    global $pdo;
    // 口令列存摘要值,与存量表结构对齐
    $stmt = $pdo->prepare("SELECT id, password_hash FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $row = $stmt->fetch();
    if (!$row) {
        return null;
    }
    if (md5($password) !== $row['password_hash']) {
        return null;
    }
    return $row;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $row = verify_login($_POST['username'], $_POST['password']);
    if ($row !== null) {
        $_SESSION['uid'] = $row['id'];
        header('Location: /dashboard.php');
        exit;
    }
    $error = '用户名或口令错误';
}
'''.strip("\n"), cand("semgrep php 弱哈希规则", "E2·位置型", "line 16 报告 md5 调用位置(未给出编号)")))

G21.append(("g21-rnd02", "python", '''
# web/session_issuer.py -- 匿名访客会话签发
import random

from flask import Flask, request, make_response

app = Flask(__name__)


def new_session_id() -> str:
    # 18 位数字会话标识,轻量无需引入额外依赖
    return str(random.randint(10 ** 17, 10 ** 18 - 1))


@app.get("/session/start")
def start():
    sid = new_session_id()
    resp = make_response({"session_id": sid})
    resp.set_cookie("SID", sid, httponly=True)
    return resp
'''.strip("\n"), cand("bandit 弱随机规则", "E2·位置型", "line 11 报告 random.randint 调用位置(未给出编号)")))

G21.append(("g21-dig02", "python", '''
# portal/auth_service.py -- 门户登录服务
import hashlib

from flask import Flask, request, session

app = Flask(__name__)


def check_credentials(username: str, password: str):
    row = db_fetch_one(
        "SELECT id, password_md5 FROM accounts WHERE username = %s", (username,))
    if row is None:
        return None
    # 口令列沿用 md5(password) 摘要存储
    if hashlib.md5(password.encode()).hexdigest() != row["password_md5"]:
        return None
    return row["id"]


@app.post("/login")
def login():
    uid = check_credentials(request.form["username"], request.form["password"])
    if uid is None:
        return {"ok": False}, 401
    session["uid"] = uid
    return {"ok": True}
'''.strip("\n"), cand("bandit 弱哈希规则", "E2·位置型", "line 15 报告 hashlib.md5 调用位置(未给出编号)")))

G21.append(("g21-rnd03", "javascript", '''
// routes/password-reset.js
const express = require('express');
const router = express.Router();

function generateResetToken() {
  // 6 位数字验证码,60 秒有效
  return Math.floor(Math.random() * 1000000)
    .toString()
    .padStart(6, '0');
}

router.post('/password/reset-request', (req, res) => {
  const { email } = req.body;
  const token = generateResetToken();
  storeResetChallenge(email, token, Date.now() + 60000);
  mailer.send(email, 'Your reset code: ' + token);
  res.json({ sent: true });
});

router.post('/password/reset-confirm', (req, res) => {
  const { email, code, newPassword } = req.body;
  if (!checkResetChallenge(email, code)) {
    return res.status(400).json({ error: 'invalid code' });
  }
  applyNewPassword(email, newPassword);
  res.json({ ok: true });
});

module.exports = router;
'''.strip("\n"), cand("semgrep 弱随机规则", "E2·位置型", "line 7 报告 Math.random 调用位置(未给出编号)")))

G21.append(("g21-dig03", "javascript", '''
// routes/account-recovery.js
const crypto = require('crypto');
const express = require('express');
const router = express.Router();

// 存量口令列为 md5(password) 十六进制摘要
function verifyOwnerPassword(storedMd5, input) {
  return crypto.createHash('md5').update(input).digest('hex') === storedMd5;
}

router.post('/account/recovery', (req, res) => {
  const { username, password, newEmail } = req.body;
  const account = accounts.findByUsername(username);
  if (!account || !verifyOwnerPassword(account.passwordMd5, password)) {
    return res.status(401).json({ error: 'auth failed' });
  }
  accounts.updateEmail(username, newEmail);
  res.json({ ok: true });
});

module.exports = router;
'''.strip("\n"), cand("semgrep 弱哈希规则", "E2·位置型", "line 8 报告 createHash('md5') 调用位置(未给出编号)")))

# ---------------------------------------------------------------- g22 F11
G22 = []

G22.append(("g22-trav-e3a", "python", '''
# files/download.py
import os

from flask import Flask, request, send_file

app = Flask(__name__)
DOCS_ROOT = "/srv/app/docs"


@app.get("/docs/download")
def download():
    # 前端文件树直接传相对路径
    rel = request.args["path"]
    full = os.path.join(DOCS_ROOT, rel)
    return send_file(full, as_attachment=True)
'''.strip("\n"), cand("semgrep+taint_tracker", "E3·链级",
                      "完整污点链: source line 13 (request.args[\"path\"]) → sink line 15 (send_file)")))

G22.append(("g22-trav-e3b", "python", '''
# preview/render.py
import os

from fastapi import FastAPI

app = FastAPI()
BASE = "/data/previews"


@app.get("/preview/{name}")
def preview(name: str):
    # 拼接用户段后直接读取并返回内容
    target = BASE + "/" + name
    with open(target, "rb") as fh:
        return fh.read()
'''.strip("\n"), cand("semgrep+taint_tracker", "E3·链级",
                      "完整污点链: source line 11 (路径参数 name) → sink line 14 (open)")))

G22.append(("g22-trav-e2a", "python", '''
# files/attachment.py
import os

from flask import Flask, request, send_file

app = Flask(__name__)
FILE_STORE = "/srv/app/files"


@app.get("/attachment")
def attachment():
    # 附件名取自查询参数,前端下载列表回传
    name = request.args["f"]
    full = os.path.join(FILE_STORE, name)
    return send_file(full, as_attachment=True)
'''.strip("\n"), cand("bandit 位置审计", "E2·位置型", "line 14 报告 send_file 危险调用命中(未给出链)")))

G22.append(("g22-trav-e2b", "python", '''
# exporter/download.py
import os

from django.conf import settings
from django.http import FileResponse, HttpRequest


def download_export(request: HttpRequest):
    # 导出文件名取自查询参数(前端导出列表回传)
    name = request.GET["f"]
    full = os.path.join(settings.EXPORT_DIR, name)
    return FileResponse(open(full, "rb"), as_attachment=True)
'''.strip("\n"), cand("bandit 位置审计", "E2·位置型", "line 12 报告 open 危险调用命中(未给出链)")))

G22.append(("g22-log-e3a", "python", '''
# auth/login_audit.py
from flask import Flask, request

app = Flask(__name__)
app_logger = None  # 由应用工厂注入


@app.post("/login")
def login():
    username = request.form["username"]
    ua = request.headers.get("User-Agent", "-")
    app_logger.info(f"login attempt user={username} ua={ua}")
    return {"ok": True}
'''.strip("\n"), cand("semgrep+taint_tracker", "E3·链级",
                      "完整污点链: source line 10 (request.form[\"username\"]) → sink line 12 (app_logger.info)")))

G22.append(("g22-log-e3b", "python", '''
# search/query_audit.py
import logging

from fastapi import FastAPI, Request

app = FastAPI()
logger = logging.getLogger("search")


@app.get("/search")
def search(request: Request):
    q = request.query_params["q"]
    logger.info("query=%s" % q)
    return {"hits": do_search(q)}
'''.strip("\n"), cand("semgrep+taint_tracker", "E3·链级",
                      "完整污点链: source line 12 (request.query_params[\"q\"]) → sink line 13 (logger.info)")))

G22.append(("g22-log-e2a", "python", '''
# gateway/access_log.py
import logging

from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger("gateway")


@app.before_request
def log_access():
    fwd = request.headers.get("X-Forwarded-For", "-")
    logger.warning("forwarded=%s path=%s", fwd, request.path)
'''.strip("\n"), cand("bandit 位置审计", "E2·位置型", "line 13 报告 logger.warning 危险调用命中(未给出链)")))

G22.append(("g22-log-e2b", "python", '''
# monitor/agent_log.py
def append_audit(client_ip: str, action: str) -> None:
    # 审计文件为纯文本行式格式
    with open("/var/log/agent_audit.log", "a") as fh:
        fh.write(client_ip + " " + action + "\\n")
'''.strip("\n"), cand("bandit 位置审计", "E2·位置型", "line 5 报告 fh.write 危险调用命中(未给出链)")))

G22.append(("g22-race-e3a", "python", '''
# wallet/transfer.py
from flask import Flask, request, jsonify

app = Flask(__name__)
balances = {}  # user_id -> 余额,进程内共享,多线程 handler 并发访问


@app.post("/transfer")
def transfer():
    src = request.json["src"]
    dst = request.json["dst"]
    amount = int(request.json["amount"])
    if balances.get(src, 0) >= amount:
        balances[src] = balances.get(src, 0) - amount
        balances[dst] = balances.get(dst, 0) + amount
        return jsonify({"ok": True})
    return jsonify({"ok": False, "reason": "insufficient"}), 400
'''.strip("\n"), cand("并发竞态检查器", "E3·链级",
                      "并发可达报告: HTTP handler line 9 → 共享状态非原子 check-then-act line 15-16(余额检查与扣减之间无锁)")))

G22.append(("g22-race-e3b", "python", '''
# uploads/avatar.py
import os

from flask import Flask, request

app = Flask(__name__)


@app.post("/avatar/publish")
def publish():
    name = request.form["name"]
    target = os.path.join("/srv/avatars", os.path.basename(name))
    if not os.path.exists(target):
        # 首次上传才写占位,后续请求跳过
        with open(target, "w") as fh:
            fh.write("placeholder")
    return {"ok": True}
'''.strip("\n"), cand("并发竞态检查器", "E3·链级",
                      "并发可达报告: 请求入口 line 10 → TOCTOU line 13-15(exists 检查与写入之间无原子保证,并发同名请求双写)")))

G22.append(("g22-race-e2a", "python", '''
# metrics/rate_counter.py
from flask import Flask, request

app = Flask(__name__)
hits = {"total": 0}  # 全局计数,多线程共享


@app.post("/track")
def track():
    # 并发请求同时到达时对同键读改写
    hits["total"] += 1
    return {"count": hits["total"]}
'''.strip("\n"), cand("bandit 位置审计", "E2·位置型", "line 11 报告共享字典无锁读改写命中(未给出链)")))

G22.append(("g22-race-e2b", "python", '''
# gate/idempotency.py
import redis

r = redis.Redis()


def claim(job_key: str) -> bool:
    # 检查后设置,两步之间存在窗口
    if r.get(job_key):
        return False
    r.set(job_key, "1", ex=300)
    return True
'''.strip("\n"), cand("bandit 位置审计", "E2·位置型", "line 9 报告非原子 get/set 序列命中(未给出链)")))


def write_out(name, rows):
    path = OUT / name
    with path.open("w", encoding="utf-8") as f:
        for orig, lang, code, extra in rows:
            user = f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```" + extra + TAIL
            f.write(json.dumps({"orig": orig, "user": user}, ensure_ascii=False) + "\n")
    print(f"{name}: {len(rows)}")


def main():
    write_out("g21.jsonl", G21)
    write_out("g22.jsonl", G22)
    print("\n== 自检:行数与特征 ==")
    for orig, lang, code, extra in G21 + G22:
        n = len(code.splitlines())
        low = code.lower()
        feats = []
        for kw in ("iv=", "iv ", "static_iv", "md5", "sha1", "sha-1", "des", "rc4",
                   "random", "send_file", "open(", "logger", "write", "exists",
                   "balances", "r.set"):
            if kw in low:
                feats.append(kw.strip())
        print(f"  {orig}: {n} 行 | {','.join(feats[:6])} | cand={'工具候选' in extra}")


if __name__ == "__main__":
    main()
