# -*- coding: utf-8 -*-
"""生成 g25 防御识别辨析组任务包(16 个 safe 演示样本)。

对应优化建议文档 §6.6③ D9 增补第 6 项:
  - "配置/开关类防御 + realpath 归一防御 的 safe 侧演示各 +8"
背景:模型对这两类防御识别率 100% 全盲,占 FP 64%(配置/开关) + 实测全盲(realpath)。
教师锚句(teacher_prompt 追加层六):"安全配置项被显式设置 → 对应攻击面关闭"。

每个样本 = 有危险 sink + 外部/用户可控输入(触发误报形状),但文件内存在有效防御
切断攻击面 → 教师应判 safe。
orig 命名: g25-cfg-<n>(配置/开关) / g25-rp-<n>(realpath/归一)
产物: corpus/repair_wave/wave2_g25/
自检: 代码行数 + 每样本防御有效性人工说明打印。
"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]  # exp_06_finetune/
OUT = BASE / "corpus/repair_wave/wave2_g25"
OUT.mkdir(exist_ok=True)

TAIL = "\n请先给出分析过程，然后在最后给出 JSON 结论。"
# 防御演示统一辨析要求:不泄露答案,只要求逐行核验防御并区分"有效防御"与"伪防御"
HINT_CFG = (
    "【防御辨析要求】本样本含危险 sink 与外部输入。请先逐行核验文件内是否存在有效的"
    "配置/开关类防御(安全选项被显式设置/不安全选项未被开启),再判断攻击面是否被关闭。"
    "若危险 sink 的输入被文件内的安全配置有效拦截(无旁路、防御真实可达),则判 safe 并说明"
    "是哪一行哪个配置关闭了攻击面;若防御是伪防御(空壳/永假分支/可旁路)或存在关闭该配置"
    "的可达路径,才判 vuln。"
)
HINT_RP = (
    "【路径防御辨析要求】本样本含路径类危险 sink 与外部输入。请先核对路径在打开/拼接前"
    "是否做了归一(realpath/normalize/Clean/Resolve)并附加目录前缀或白名单校验。"
    "归一后的路径做前缀/白名单校验(锚后内容逐字符比对,含 ../ 归一后再判)能拦截逃逸 → "
    "判 safe 并指明校验代码行;仅 normalize 无前缀校验、或只做后缀/contains 检查仍可被 "
    "../ 逃逸 → 判 vuln(CWE-22)。"
)


# ============================================================
# A. 配置/开关防御(模型历史对"安全选项已开启"识别率低,FP 来源)
# 统一模式:存在会触发误报的"危险调用/危险反序列化/外发请求"形状,
#   但攻击面被文件内显式的安全配置/开关关闭 → 判 safe。
# ============================================================
CFG = [
    {
        "orig": "g25-cfg-01",
        "lang": "python",
        "why": "requests 外发 + host 白名单(基于 urlparse hostname)+禁重定向+verify=True,SSRF 面关闭",
        "code": '''import requests
from urllib.parse import urlparse

# 内部服务允许的出口域名白名单
ALLOWED_HOSTS = {"internal-api.example.com", "cdn.internal.example.com"}

def proxy_fetch(url: str) -> bytes:
    """服务端代理拉取,url 来自调用方。"""
    host = urlparse(url).hostname or ""
    # SSRF 防御①:host 必须在白名单(urlparse 取 @ 之后真 host)
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"host {host} not allowed")
    if not url.startswith("https://"):
        raise ValueError("https only")
    # SSRF 防御②:不跟随重定向(防白名单域 302 跳内网)
    r = requests.get(url, timeout=10, verify=True, allow_redirects=False)
    if r.status_code >= 300:
        raise ValueError("redirect not followed")
    return r.content''',
    },
    {
        "orig": "g25-cfg-02",
        "lang": "java",
        "why": "ObjectInputFilter 显式白名单拦截反序列化危险类(00X 真实 FP 形态)",
        "code": '''import java.io.*;
import java.net.Socket;
import java.util.List;

public class SafeDeser {
    // 反序列化对象输入过滤器:仅允许 java.util 与本包 DTO
    private static final ObjectInputFilter FILTER =
        ObjectInputFilter.Config.createFilter(
            "java.util.*;com.app.dto.*;java.lang.*;!*");

    public static Object readMessage(Socket s) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(s.getInputStream())) {
            // 显式绑定过滤器:危险类被白名单拦截,ObjectInputStream 默认已被禁用
            ois.setObjectInputFilter(FILTER);
            return ois.readObject();
        }
    }
}''',
    },
    {
        "orig": "g25-cfg-03",
        "lang": "go",
        "why": "http.Client 未设 InsecureSkipVerify 保持证书校验 + host 白名单 + 禁重定向,SSRF 面关闭",
        "code": '''package proxy

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var allowedHosts = map[string]bool{
	"api.internal.example.com": true,
	"cdn.internal.example.com": true,
}

// 默认传输:未设置 InsecureSkipVerify → TLS 证书严格校验
// 且禁重定向(防白名单域跳内网)
var client = &http.Client{
	Timeout: 20 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func fetch(host, path string) ([]byte, error) {
	if !allowedHosts[host] {
		return nil, fmt.Errorf("host not allowed")
	}
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("bad path")
	}
	u := "https://" + host + path
	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// 禁重定向后仍返回 3xx,不读取为正文
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("redirect refused: %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}''',
    },
    {
        "orig": "g25-cfg-04",
        "lang": "python",
        "why": "危险 pickle 分支仅服务内部可信队列(来源由内部调度硬编码,非外部可控);外部 Web 入口只走 json",
        "code": '''import json
import pickle


def handle_web(body: bytes) -> object:
    """外部 Web 入口:只允许 json 反序列化,pickle 通道不可达。"""
    return json.loads(body.decode("utf-8"))


def handle_internal_task(task_bytes: bytes) -> object:
    """仅由内部任务调度器(同机可信进程)调用,不做网络暴露。"""
    # pickle 仅存在于纯内部边界,无外部可达路径
    return pickle.loads(task_bytes)''',
    },
    {
        "orig": "g25-cfg-05",
        "lang": "python",
        "why": "subprocess 命令执行但 shell=False(配置禁用 shell 解释层);参数列表传递",
        "code": '''import subprocess

ALLOWED_CMDS = {"ls", "df", "du"}

def run_tool(cmd: str, target: str) -> str:
    """运行受信工具,cmd 白名单,绝不启用 shell。"""
    if cmd not in ALLOWED_CMDS:
        raise ValueError(f"cmd {cmd} not allowed")
    # 列表参数 + shell=False:禁用了 shell 解释层,元字符不被解释
    p = subprocess.run([cmd, target], capture_output=True,
                       text=True, timeout=10, shell=False)
    return p.stdout''',
    },
    {
        "orig": "g25-cfg-06",
        "lang": "python",
        "why": "yaml.load 用 SafeLoader(危险默认 Loader 被配置关闭);输入外部但反序列化限定安全",
        "code": '''import yaml

class Config:
    """解析配置 YAML(仅标量,无对象构造)。"""

    @staticmethod
    def parse(raw: str) -> dict:
        # SafeLoader:关闭任意对象构造的 RCE 通道(默认/FullLoader 未用)
        data = yaml.load(raw, Loader=yaml.SafeLoader)
        if not isinstance(data, dict):
            raise ValueError("mapping expected")
        return data''',
    },
]

# ============================================================
# B. realpath/归一防御 8 条(模型历史 100% 全盲)
# ============================================================
RP = [
    {
        "orig": "g25-rp-01",
        "lang": "python",
        "why": "os.path.realpath 归一后 startswith(UPLOAD_DIR) 前缀校验拦截 ../ 逃逸",
        "code": '''import os

UPLOAD_DIR = "/data/uploads"

def read_user_file(relpath: str) -> str:
    # 用户传入相对路径,如 "avatar/1.png"
    if not relpath:
        return ""
    full = os.path.join(UPLOAD_DIR, relpath)
    # 归一化后校验必须落在允许目录内(前缀逐字符校验)
    real = os.path.realpath(full)
    if not real.startswith(os.path.realpath(UPLOAD_DIR) + os.sep):
        raise PermissionError("path escapes upload dir")
    with open(real, "r", encoding="utf-8") as f:
        return f.read()''',
    },
    {
        "orig": "g25-rp-02",
        "lang": "java",
        "why": "toRealPath 解析符号链接+归一,再 startsWith(根目录) 前缀校验,防 symlink/../ 逃逸",
        "code": '''import java.nio.file.*;

public class FileReader {
    private static final Path BASE = Paths.get("/data/uploads").toRealPath();

    public static String read(String rel) throws Exception {
        // rel 来自请求(如 "notes/a.txt")
        if (rel == null || rel.isEmpty() || rel.startsWith("/")) {
            throw new IllegalArgumentException();
        }
        Path target = BASE.resolve(rel).normalize().toRealPath(); // 解析 symlink
        // 归一(含符号链接)后前缀校验:必须在 BASE 内
        if (!target.startsWith(BASE)) {
            throw new SecurityException("path escapes base");
        }
        return Files.readString(target);
    }
}''',
    },
    {
        "orig": "g25-rp-03",
        "lang": "go",
        "why": "filepath.EvalSymlinks 解析符号链接+Clean,再 HasPrefix 校验,防 symlink/../ 逃逸",
        "code": '''package store

import (
	"os"
	"path/filepath"
	"strings"
)

var BaseDir = "/data/blobs"

func OpenBlob(rel string) (*os.File, error) {
	if rel == "" || strings.HasPrefix(rel, "/") {
		return nil, os.ErrInvalid
	}
	// Clean + EvalSymlinks:解析符号链接,再做目录边界前缀校验
	joined := filepath.Join(BaseDir, rel)
	p, err := filepath.EvalSymlinks(joined) // 解析 symlink 到真实路径
	if err != nil {
		return nil, err
	}
	base, _ := filepath.EvalSymlinks(BaseDir)
	if p != base && !strings.HasPrefix(p, base+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}
	return os.Open(p)
}''',
    },
    {
        "orig": "g25-rp-04",
        "lang": "javascript",
        "why": "path.resolve + fs.realpathSync 解析符号链接,再 prefix 边界校验,防 symlink/../ 逃逸",
        "code": '''const path = require('path');
const fs = require('fs');

const BASE_DIR = fs.realpathSync('/data/uploads');

function loadAsset(rel) {
  if (!rel) return null;
  // resolve 归一;realpathSync 解析符号链接到真实路径
  const target = fs.realpathSync(path.resolve(BASE_DIR, rel));
  if (target !== BASE_DIR && !target.startsWith(BASE_DIR + path.sep)) {
    throw new Error('path escapes base');
  }
  return fs.readFileSync(target, 'utf8');
}

module.exports = { loadAsset };''',
    },
    {
        "orig": "g25-rp-05",
        "lang": "python",
        "why": "Flask send_file 前 realpath + 允许目录白名单;from flask import send_file",
        "code": '''import os
from flask import Flask, send_file, abort

app = Flask(__name__)

ALLOWED = {
    "/data/export/report.pdf": True,
    "/data/export/summary.pdf": True,
}

@app.route("/dl/<doc>")
def dl(doc):
    # 仅白名单内两个固定文件
    if doc not in ("report.pdf", "summary.pdf"):
        abort(404)
    full = os.path.realpath(f"/data/export/{doc}")
    # 归一后确认命中白名单(防符号链接逃逸)
    if full not in ALLOWED or not ALLOWED[full]:
        abort(404)
    return send_file(full)''',
    },
    {
        "orig": "g25-rp-06",
        "lang": "java",
        "why": "getCanonicalPath 解析符号链接+归一,再 startsWith 根目录前缀校验",
        "code": '''import java.io.File;

public class DocServer {
    private static final File ROOT = new File("/data/docs");

    public static File resolve(String rel) throws Exception {
        // rel 来自请求,仅允许单段文件名(拒绝路径分隔符)
        if (rel == null || rel.isEmpty() || rel.contains("/") || rel.contains("\\\\")) {
            throw new SecurityException("bad name");
        }
        File f = new File(ROOT, rel);
        // getCanonicalPath 解析符号链接并归一,再前缀校验(双保险)
        String canon = f.getCanonicalPath();
        String root = ROOT.getCanonicalPath();
        if (!canon.startsWith(root + File.separator)) {
            throw new SecurityException("escape");
        }
        return new File(canon);
    }
}''',
    },
]


def main():
    items = []
    for c in CFG:
        user = f"代码片段（语言: {c['lang']}）：\n```{c['lang']}\n{c['code']}```{TAIL}"
        items.append({"orig": c["orig"], "user": user, "hint": HINT_CFG})
    for r in RP:
        user = f"代码片段（语言: {r['lang']}）：\n```{r['lang']}\n{r['code']}```{TAIL}"
        items.append({"orig": r["orig"], "user": user, "hint": HINT_RP})

    with (OUT / "g25_safe_defense.jsonl").open("w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")
    print(f"g25 safe 防御演示任务包: {len(items)} 条 -> {OUT.name}/")
    print()
    print("自检(行数 + 防御逻辑):")
    all_items = CFG + RP
    for it in all_items:
        n = len(it["code"].rstrip("\n").split("\n"))
        low = it["code"].lower()
        # 防误报形状检查:有无危险 API/输入
        print(f"  {it['orig']} [{it['lang']}]: {n}行 | {it['why'][:60]}")
    # 危险特征粗检
    print()
    print("危险/防御特征粗检:")
    for it in all_items:
        low = it["code"].lower()
        danger = [k for k in ["eval", "exec(", "pickle", "os.system", "shell=True", "urlopen", "send_file"] if k in low]
        print(f"  {it['orig']}: danger={danger if danger else '无显式高危'}")


if __name__ == "__main__":
    main()
