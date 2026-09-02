# -*- coding: utf-8 -*-
"""生成 g26 命令语言注入辨析组(真 CWE-77,按 MITRE 官方适用域)+ 338/329 密码学补样。

CWE-77 官方适用域 = 非 OS shell 的命令语言注入。样本全部取自 MITRE Observed
Examples 的真实 CVE 形态:sed 脚本注入(CVE-2022-1509 族)、SNMP 命令注入
(CVE-2020-11698)、MVG 图形语言(CVE-2019-12921)、IMAP/SMTP 命令(CAPEC-183)。
另有 338(随机子类独立场景)与 329(硬编码 IV)密码学补样。

orig: g26-cmdlang-* / g26-c338-* / g26-c329-*
产物: corpus/repair_wave/wave2_g26/
"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]
OUT = BASE / "corpus/repair_wave/wave2_g26"
OUT.mkdir(exist_ok=True)

TAIL = "\n请先给出分析过程，然后在最后给出 JSON 结论。"

HINT_77 = (
    "【命令语言辨析要求】本样本含将外部输入送入某种命令语言解释器执行的形态。"
    "请先识别注入目标的命令语言类型:若是 OS shell(system/sh -c/execSync 等 shell 元字符)则判 "
    "CWE-78;若是 sed 脚本、SNMP 命令、图形语言(MVG)、IMAP/SMTP 命令、正则等非 OS 的"
    "自定义命令语言,则判 CWE-77(命令注入泛化,官方适用域)。给出污点链与该命令语言"
    "的具体注入向量。"
)
HINT_338 = (
    "【随机数辨析要求】请按密码学族互斥判据判断:缺陷在'用了哪个算法'(327)、'IV/Nonce "
    "怎么来的'(329)、还是'随机值怎么生成的'(330/338)?若缺陷在使用了不可预测性不足的"
    "随机源生成安全敏感值(令牌/会话/密钥),判 CWE-330 或其子类 CWE-338(二者语义同粒度"
    "不同,标注任一均可,优先 338 以标明'密码学不足用途')。禁止以 md5/sha1/破解作论证。"
)
HINT_329 = (
    "【密码学 IV 辨析要求】请判断缺陷是否在'IV/Nonce 的生成方式':硬编码/固定/可预测的 "
    "IV 或 nonce(即使算法本身是 AES-256)判 CWE-329,锚句'IV 不可重用';禁止以'算法强度"
    "不足'叙事(那是 327)。"
)

ITEMS = [
    # ============ A. 真 CWE-77:非 OS 命令语言注入(官方 Observed Examples 形态) ============
    {
        "orig": "g26-cmdlang-01", "lang": "bash", "hint": HINT_77,
        "why": "sed 脚本注入(CVE-2022-1509 族):用户输入拼进 sed 表达式,可注入 & 分隔命令/w 命令写文件",
        "code": '''#!/bin/bash
# 日志清洗服务:按用户提供的模式过滤日志行
LOGFILE="/var/log/app/events.log"

echo "Enter filter pattern:"
read -r PATTERN

# 用 sed 过滤包含该模式的行
sed -n "/$PATTERN/p" "$LOGFILE" > /tmp/filtered.out
wc -l /tmp/filtered.out''',
    },
    {
        "orig": "g26-cmdlang-02", "lang": "python", "hint": HINT_77,
        "why": "sed -e 表达式注入:search 模式拼进 sed -e 参数,可注入 ; 分隔多条 sed 命令含 w 写文件",
        "code": '''import subprocess

def highlight_matches(log_path: str, user_query: str) -> str:
    """把用户搜索词高亮后输出匹配行。"""
    # 用 sed 的 s 命令给匹配词加 [HIGHLIGHT] 标记
    expr = f"s/{user_query}/[HIGHLIGHT]&[\\/HIGHLIGHT]/g"
    out = subprocess.run(
        ["sed", "-e", expr, log_path],
        capture_output=True, text=True, timeout=10
    )
    return out.stdout''',
    },
    {
        "orig": "g26-cmdlang-03", "lang": "python", "hint": HINT_77,
        "why": "SNMP 命令注入(CVE-2020-11698):OID 值拼进 snmpwalk 的协议命令参数(无 shell)",
        "code": '''import subprocess

def query_device(host: str, community: str, oid: str) -> str:
    """网管面板:对指定设备做 SNMP 查询。host/community/oid 来自请求表单。"""
    # snmpwalk 命令语言:OID 参数位置可注入附加参数与协议命令
    # (无 shell;snmpwalk 自身的参数/命令解析是注入面)
    out = subprocess.run(
        ["snmpwalk", "-v", "2c", "-c", community, host, oid],
        capture_output=True, text=True, timeout=15
    )
    return out.stdout''',
    },
    {
        "orig": "g26-cmdlang-04", "lang": "java", "hint": HINT_77,
        "why": "IMAP 命令注入(CAPEC-183):用户输入的邮箱名拼进 IMAP SEARCH 命令串",
        "code": '''import javax.mail.*;
import javax.mail.internet.*;
import javax.mail.search.*;

public class MailSearch {
    private Store store;
    private Folder inbox;

    public String searchBySender(String senderEmail) throws Exception {
        // senderEmail 来自 Web 表单,拼进 IMAP SEARCH 命令
        inbox = store.getFolder("INBOX");
        inbox.open(Folder.READ_ONLY);
        // IMAP SEARCH HEADER 命令注入:换行/CRLF 可追加任意 IMAP 命令
        String imapCommand = "SEARCH HEADER FROM \\"" + senderEmail + "\\"";
        // 直接执行拼接的 IMAP 协议命令
        IMAPFolder ifolder = (IMAPFolder) inbox;
        return String.valueOf(ifolder.doCommand(p -> {
            p.simpleCommand(imapCommand, null);
            return null;
        }));
    }
}''',
    },
    {
        "orig": "g26-cmdlang-05", "lang": "python", "hint": HINT_77,
        "why": "ImageMagick MVG 图形语言注入(CVE-2019-12921):用户文本拼进 draw 语句",
        "code": '''import subprocess

def render_user_label(caption: str) -> bytes:
    """把用户提供的标签文字渲染到图片上。caption 来自请求。"""
    # MVG (Magick Vector Graphics) 图形命令语言:push graphic-context 等
    # 用户文本拼入 draw 表达式,可注入 ';' 分隔新的 MVG 命令
    mvg = f"push graphic-context\\nviewbox 0 0 200 60\\n"
    mvg += f"fill '#333'\\nfont 18\\n"
    mvg += f"text 10,40 '{caption}'\\n"
    mvg += "pop graphic-context\\n"
    proc = subprocess.run(
        ["magick", "mvg:-", "png:-"],
        input=mvg.encode(), capture_output=True, timeout=15
    )
    return proc.stdout''',
    },
    {
        "orig": "g26-cmdlang-06", "lang": "javascript", "hint": HINT_77,
        "why": "sed 分隔符注入 JS 形态:JSON API 的替换词拼进 sed s 命令",
        "code": '''const { execFile } = require('child_process');

// 配置热更新:用 sed 把 nginx.conf 里的端口占位替换成运维面板提交的值
function updatePort(newPort) {
  // newPort 来自运维面板表单(多人共用的内网工具)
  const expr = `s/PORT_PLACEHOLDER/${newPort}/`;
  execFile('sed', ['-i', expr, '/etc/nginx/nginx.conf'], (err) => {
    if (err) console.error('update failed');
  });
}

module.exports = { updatePort };''',
    },
    {
        "orig": "g26-cmdlang-07", "lang": "go", "hint": HINT_77,
        "why": "ffmpeg 滤镜语言注入:用户样式参数拼进 -vf 滤镜图表达式",
        "code": '''package media

import (
	"os/exec"
	"strings"
)

// 生成缩略图:用户可选的缩放样式直接拼进 ffmpeg 滤镜表达式
func MakeThumb(src, style string) ([]byte, error) {
	// style 来自 API 请求(如 "640:-1"),拼入 -vf 滤镜图
	// ffmpeg 滤镜图是一门命令语言:',' 分隔滤镜,';' 分隔滤镜链,
	// 可注入 scale 之外的任意滤镜(如 subtitle 读任意文件)
	vf := "scale=" + style
	cmd := exec.Command("ffmpeg", "-i", src, "-vf", vf,
		"-frames:v", "1", "f:image2pipe", "-")
	return cmd.Output()
}

var _ = strings.TrimSpace''',
    },
    {
        "orig": "g26-cmdlang-08", "lang": "python", "hint": HINT_77,
        "why": "git 命令语言参数注入(degit CVE 形态,同库 7906 的变体):--upload-pack 走 git 协议命令",
        "code": '''import subprocess

def clone_template(template_spec: str, dest: str) -> None:
    """脚手架服务:按用户给的模板标识克隆仓库。template_spec 来自请求。"""
    # git 的远程标识语法支持 ext::sh -c <cmd> 与 --upload-pack <cmd>
    # 无 shell 拼接,但 git 协议自身的命令语言可被注入
    subprocess.run(
        ["git", "clone", template_spec, dest],
        capture_output=True, timeout=60
    )''',
    },
    # ============ B. CWE-338 补样(330 子类,独立场景) ============
    {
        "orig": "g26-c338-01", "lang": "python", "hint": HINT_338,
        "why": "random.random() 生成密码重置令牌(非 secrets)",
        "code": '''import random
import time

def gen_reset_token(user_id: int) -> str:
    """生成密码重置令牌(24小时有效)。"""
    # 令牌基于可预测种子与弱随机源
    random.seed(user_id ^ int(time.time()))
    return format(random.getrandbits(64), "016x")''',
    },
    {
        "orig": "g26-c338-02", "lang": "javascript", "hint": HINT_338,
        "why": "Math.random() 生成会话 ID",
        "code": '''// 会话管理:用 Math.random 生成 session token
function createSession(userId) {
  const token = Math.random().toString(36).substring(2) +
                Math.random().toString(36).substring(2);
  sessions.set(token, { userId, created: Date.now() });
  return token;
}

const sessions = new Map();
module.exports = { createSession };''',
    },
    {
        "orig": "g26-c338-03", "lang": "java", "hint": HINT_338,
        "why": "java.util.Random 生成 API key(非 SecureRandom)",
        "code": '''import java.util.Random;

public class ApiKeyService {
    private static final Random RNG = new Random(42L);

    public static String generateApiKey(long accountId) {
        // API key 用固定种子+弱随机生成
        Random r = new Random(accountId);
        long hi = RNG.nextLong(), lo = r.nextLong();
        return String.format("%016x%016x", hi, lo);
    }
}''',
    },
    {
        "orig": "g26-c338-04", "lang": "go", "hint": HINT_338,
        "why": "rand.Intn 非密码学源生成验证码",
        "code": '''package otp

import (
	"fmt"
	"math/rand"
)

// 生成 6 位短信验证码
func GenOtpCode(phone string) string {
	seed := 0
	for _, c := range phone {
		seed += int(c)
	}
	r := rand.New(rand.NewSource(int64(seed)))
	return fmt.Sprintf("%06d", r.Intn(1000000))
}''',
    },
    # ============ C. CWE-329 补样(硬编码 IV/Nonce) ============
    {
        "orig": "g26-c329-01", "lang": "python", "hint": HINT_329,
        "why": "AES-GCM 用模块级固定 nonce(每次加密同一 12 字节)",
        "code": '''import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 全局密钥与固定 nonce
KEY = os.environ.get("DATA_KEY", "").encode() or b"0123456789abcdef0123456789abcdef"
FIXED_NONCE = b"0123456789ab"  # 12 字节,所有加密共用

def encrypt_field(plaintext: bytes) -> bytes:
    aes = AESGCM(KEY)
    # AES-256-GCM,但 nonce 每次相同 → 密文可被 nonce 重用攻击
    return aes.encrypt(FIXED_NONCE, plaintext, None)

def decrypt_field(ciphertext: bytes) -> bytes:
    aes = AESGCM(KEY)
    return aes.decrypt(FIXED_NONCE, ciphertext, None)''',
    },
    {
        "orig": "g26-c329-02", "lang": "java", "hint": HINT_329,
        "why": "AES-CBC 用硬编码 IV 字节数组(即使算法 AES-256)",
        "code": '''import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class TokenCodec {
    // 硬编码 IV:所有 Token 共用
    private static final byte[] IV = {(byte)0x01,(byte)0x02,(byte)0x03,(byte)0x04,
                                      (byte)0x05,(byte)0x06,(byte)0x07,(byte)0x08,
                                      (byte)0x09,(byte)0x0a,(byte)0x0b,(byte)0x0c,
                                      (byte)0x0d,(byte)0x0e,(byte)0x0f,(byte)0x10};
    private static SecretKeySpec key(String k) {
        return new SecretKeySpec(k.getBytes(), "AES");
    }

    public static String encode(String secret, String data) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key(secret), new IvParameterSpec(IV));
        return Base64.getEncoder().encodeToString(c.doFinal(data.getBytes()));
    }
}''',
    },
    {
        "orig": "g26-c329-03", "lang": "go", "hint": HINT_329,
        "why": "计数器模式固定 nonce 前缀+自增计数(跨进程重启重置)",
        "code": '''package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// 固定 nonce 前缀;计数器从 1 起且进程重启后重置
var noncePrefix = []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}

var counter uint32 = 1

func Seal(master []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	copy(nonce, noncePrefix)
	binary.BigEndian.PutUint32(nonce[8:], counter)
	counter++
	gcm, _ := cipher.NewGCMWithNonceSize(block, 12)
	return gcm.Seal(nil, nonce, plaintext, nil)
}''',
    },
    {
        "orig": "g26-c329-04", "lang": "javascript", "hint": HINT_329,
        "why": "createCipheriv 用常量 IV(每次初始化同一个)",
        "code": '''const crypto = require('crypto');

// 会话 cookie 加密:IV 是写死的常量
const SECRET = process.env.COOKIE_KEY || 'k'.repeat(32);
const STATIC_IV = Buffer.from('1234567890abcdef1234567890abcdef', 'hex').slice(0, 16);

function encryptCookie(payload) {
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(SECRET), STATIC_IV);
  let enc = cipher.update(payload, 'utf8', 'base64');
  enc += cipher.final('base64');
  return enc;
}

module.exports = { encryptCookie };''',
    },
]


def main():
    with (OUT / "g26_kits.jsonl").open("w", encoding="utf-8") as f:
        for it in ITEMS:
            user = f"代码片段（语言: {it['lang']}）：\n```{it['lang']}\n{it['code']}```{TAIL}"
            f.write(json.dumps({"orig": it["orig"], "user": user, "hint": it["hint"]},
                               ensure_ascii=False) + "\n")
    print(f"g26 任务包: {len(ITEMS)} 条 -> {OUT.name}/")
    print(f"  命令语言注入(真77): {sum(1 for i in ITEMS if i['orig'].startswith('g26-cmdlang'))}")
    print(f"  CWE-338 补样: {sum(1 for i in ITEMS if i['orig'].startswith('g26-c338'))}")
    print(f"  CWE-329 补样: {sum(1 for i in ITEMS if i['orig'].startswith('g26-c329'))}")
    for it in ITEMS:
        n = len(it["code"].rstrip("\n").split("\n"))
        print(f"  {it['orig']} [{it['lang']}]: {n}行")


if __name__ == "__main__":
    main()
