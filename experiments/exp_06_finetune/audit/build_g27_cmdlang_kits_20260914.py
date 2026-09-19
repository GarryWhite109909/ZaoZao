# -*- coding: utf-8 -*-
"""g27_cmdlang 出题包生成器 —— 真 CWE-77（非 OS 命令语言注入）首批 16 条 / 8 形态（2026-09-14）

设计口径（必须逐条满足，否则教师会改判 78，样本作废）
-----------------------------------------------------
1. **oracle = CWE-77**：注入目标是 **非 OS 命令语言**——awk 程序、SMTP 命令、TeX 宏、
   groff 宏、CUPS 选项语言、ExifTool 标签表达式、iptables/nftables 规则语言、应用配置语言。
2. **不经 shell**：全程 argv list form（`subprocess.run([...])` / `exec.Command(a,b,...)` /
   `execFile(...)`），或直接交给解释器/协议端的 API。**代码里不得出现** `sh -c` / `bash -c` /
   `shell=True` / `shell:true` / `system()` / `execSync` / `Runtime.exec` / `ProcessBuilder`。
3. **source 真实可控**：HTTP 表单/JSON 之外，至少一半用非 HTTP 通道
   （CRD 字段、配置文件、DB 回读、CLI 参数、stdin、消息队列、运维面板提交值）。
4. **代码注释守 v2_22/v2_23 口径**：不写 CWE 编号、不写"漏洞点/这里有洞/看似安全"、
   不写防御迷惑。注释只描述业务行为。
5. **形态各异**：同形态 2 条用不同语言 + 不同业务上下文，避免又变成"同 trick 冗余"。
6. 每条给 hint（与 g26 同款口径：先判注入目标是不是 OS shell）。

输出：corpus/repair_wave/wave2_g27/g27_kits.jsonl（schema 同 g26：{orig, user, hint}）
"""
import sys, os, json
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "corpus/repair_wave/wave2_g27"

HINT = ("【命令语言辨析要求】本样本含将外部输入送入某种命令语言解释器执行的形态。"
        "请先识别注入目标的命令语言类型：若是 OS shell（system/sh -c/execSync/ProcessBuilder 等"
        "经 shell 元字符解析）则判 CWE-78；若是 sed/awk 程序、SMTP·IMAP 协议命令、TeX/groff 宏、"
        "CUPS 选项、ExifTool 标签表达式、iptables/nftables 规则、应用配置语言等"
        "**非 OS 的自定义命令语言**，则判 CWE-77（命令注入泛化，官方适用域）。"
        "给出污点链与该命令语言的具体注入向量。")

SAMPLES = []


def add(orig, lang, code, note=""):
    SAMPLES.append({
        "orig": orig,
        "user": f"代码片段（语言: {lang}）：\n```{lang}\n{code.strip()}\n```\n请先给出分析过程，然后在最后给出 JSON 结论。",
        "hint": HINT + (f"\n（形态备注：{note}）" if note else ""),
    })


# ============================================================ 形态 1：awk 程序语言
add("g27-cmdlang-01", "python", r'''
import subprocess

FIELD_SEP = "\t"

def build_report(log_path, out_path):
    """运营报表：按租户上传的报表模板做聚合。

    模板文件由租户经控制台上传（content-type 校验后落盘），字段表达式
    直接取自上传 JSON 的 "field_expr" 键。
    """
    with open(UPLOADED_TEMPLATE, "r", encoding="utf-8") as fh:
        spec = json.load(fh)
    field_expr = spec["field_expr"]
    program = f'BEGIN{{FS="{FIELD_SEP}"}} {{sum[{field_expr}]++; total++}} END{{for (k in sum) print k, sum[k]}}'
    with open(out_path, "wb") as fh:
        proc = subprocess.run(
            ["awk", program, log_path],
            stdout=fh, stderr=subprocess.PIPE, timeout=60,
        )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace")[:500])
    return out_path
''', "awk 程序语言：field_expr 拼进 awk 程序体，可改变程序结构（新增语句/嵌套块）")

add("g27-cmdlang-02", "bash", r'''
#!/bin/bash
# 字段聚合工具:按运维给出的字段引用表达式做求和
# 用法: ./aggregate.sh <logfile> <field_ref> [label]

LOG="$1"
TEMPLATE="$2"          # 租户经控制台上传的报表模板（含 field_expr 键）
LABEL="${3:-total}"

if [ -z "$LOG" ] || [ -z "$TEMPLATE" ]; then
  echo "usage: $0 <logfile> <uploaded_template.json> [label]" >&2
  exit 2
fi

FIELD_REF=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['field_expr'])" "$TEMPLATE")

# 字段引用直接拼进 awk 程序体的取值表达式位置
awk -v label="$LABEL" "
  { running += $FIELD_REF }
  END { printf \"%s=%.4f\\n\", label, running+0 }
" "$LOG"
''', "awk 程序语言：FIELD_REF 进入 awk 程序体的表达式位置，可改程序结构（含 awk 自身的 getline 取文件）")

# ============================================================ 形态 2：SMTP 协议命令语言
add("g27-cmdlang-03", "python", r'''
import socket

class SmtpRelay:
    """轻量 SMTP 投递器：直连上游 MTA 逐条发送协议命令。"""

    def __init__(self, host, port=25, helo="relay.internal"):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.helo = helo

    def _cmd(self, line):
        self.sock.sendall((line + "\r\n").encode("ascii", "replace"))
        return self.sock.recv(1024)

    def deliver(self, sender, recipients, body):
        # sender/recipients 来自入站投递请求（MTA 转发的信封字段），未做 CRLF 归一
        self._cmd(f"EHLO {self.helo}")
        self._cmd(f"MAIL FROM:<{sender}>")
        for rcpt in recipients:
            self._cmd(f"RCPT TO:<{rcpt}>")
        self._cmd("DATA")
        self.sock.sendall(body + b"\r\n.\r\n")
        return self._cmd("QUIT")
''', "SMTP 命令语言：sender/rcpt 未做 CRLF 校验，可注入额外 SMTP 动词")

add("g27-cmdlang-04", "java", r'''
import java.io.*;
import java.net.Socket;

public class MailboxVerifier {
    private final Socket socket;
    private final BufferedReader in;
    private final Writer out;

    public MailboxVerifier(String host, int port) throws IOException {
        this.socket = new Socket(host, port);
        this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.out = new OutputStreamWriter(socket.getOutputStream());
    }

    private String command(String verb, String argument) throws IOException {
        out.write(verb + " " + argument + "\r\n");
        out.flush();
        return in.readLine();
    }

    /** 批量核验收件地址是否存在；address 来自入站验证请求的信封字段 */
    public boolean verify(String address) throws IOException {
        command("HELO", "mailcheck.internal");
        command("MAIL", "FROM:<>");
        String reply = command("RCPT", "TO:<" + address + ">");
        return reply != null && reply.startsWith("250");
    }
}
''', "SMTP 命令语言：address 拼入 RCPT 动词参数")

# ============================================================ 形态 3：TeX 宏语言
add("g27-cmdlang-05", "python", r'''
import subprocess

PREAMBLE = r"""
\documentclass[11pt]{article}
\usepackage[utf8]{inputenc}
\begin{document}
"""

def render_invoice(template_dir, out_pdf):
    """开票服务：把订单字段填进 LaTeX 源后编译成 PDF。

    订单字段来自下单 API 的请求体（未做 LaTeX 特殊字符转义）。
    """
    invoice = json.loads(requests.post(ORDER_API, timeout=10).text)
    fields = {
        "title": invoice["title"],
        "customer": invoice["customer_name"],
        "address": invoice["billing_address"],
        "total": f"{invoice['total_cents'] / 100:.2f}",
    }
    source = PREAMBLE
    source += "\\section*{" + fields["title"] + "}\n"
    source += "\\textbf{Bill to:} " + fields["customer"] + "\\\\\n"
    source += fields["address"] + "\\\\\n"
    source += "\\textbf{Amount:} " + fields["total"] + "\n"
    source += "\\end{document}\n"

    tex_file = template_dir / f"invoice_{invoice['id']}.tex"
    tex_file.write_text(source, encoding="utf-8")

    proc = subprocess.run(
        ["pdflatex", "-interaction=nonstopmode", "-halt-on-error",
         "-output-directory", str(template_dir), str(tex_file)],
        capture_output=True, timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stdout.decode("utf-8", "replace")[-800:])
    return out_pdf
''', "TeX 宏语言：订单字段未转义直接进入 .tex 源，可引入 \\input 等宏读任意文件、或构造无法收敛的排版指令（未见 -shell-escape，故影响为文件读/DoS，不含外部命令执行）")

add("g27-cmdlang-06", "go", r'''
package render

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// makeCertificate 生成培训证书 PDF。
// 学员姓名与课程名取自报名系统回传的 JSON（含用户自填字段，未转义）。
func makeCertificate(workdir string) (string, error) {
	payload, err := os.ReadFile(filepath.Join(workdir, "enrollment.json"))
	if err != nil {
		return "", err
	}
	var meta struct{ Name, Course, IssuedAt string }
	if err := json.Unmarshal(payload, &meta); err != nil {
		return "", err
	}
	name, course, issuedAt := meta.Name, meta.Course, meta.IssuedAt
	tex := fmt.Sprintf(`\documentclass{article}
\usepackage{geometry}
\begin{document}
\begin{center}
{\Huge %s}\\[1cm]
{\large %s}\\[0.5cm]
Issued: %s
\end{center}
\end{document}`, name, course, issuedAt)

	src := filepath.Join(workdir, "cert.tex")
	if err := os.WriteFile(src, []byte(tex), 0o600); err != nil {
		return "", err
	}

	cmd := exec.Command("pdflatex", "-interaction=batchmode", "-output-directory", workdir, src)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("pdflatex: %v: %s", err, stderr.String())
	}
	return filepath.Join(workdir, "cert.pdf"), nil
}
''', "TeX 宏语言：name/course 进入 .tex 源；未见 -shell-escape，影响为宏语言层面的文件读/DoS")

# ============================================================ 形态 4：groff 宏语言
add("g27-cmdlang-07", "python", r'''
import subprocess

def build_manpage(section_dir):
    """文档流水线：把内部 API 元数据渲染成 man page。

    元数据来自文档总线的消息体（各仓库维护者自助提交，未做 roff 转义）。
    """
    page = json.loads(MESSAGE_BODY)
    parts = ['.TH "%s" "%s"' % (page["name"].upper(), page["section"])]
    parts.append('.SH NAME')
    parts.append('%s \\- %s' % (page["name"], page["summary"]))
    parts.append('.SH SYNOPSIS')
    parts.append('.B %s' % page["usage"])
    parts.append('.SH DESCRIPTION')
    parts.append(page["description"])
    parts.append('.SH AUTHOR')
    parts.append(page["maintainer"])

    src = section_dir / (page["name"] + ".1")
    src.write_text("\n".join(parts) + "\n", encoding="utf-8")

    out = section_dir / (page["name"] + ".1.gz")
    proc = subprocess.run(
        ["groff", "-man", "-Tutf8", str(src)],
        capture_output=True, timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace")[:400])
    return out
''', "groff 宏语言：元数据字段成为宏参数/新行，可引入 .so/.sy 等请求")

add("g27-cmdlang-08", "bash", r'''
#!/bin/bash
# 变更通告生成:把工单字段排版成 roff 文本后转 PostScript
# 用法: ./notice.sh <ticket_id> <subject> <body>

TICKET_JSON="$1"     # 工单系统导出的 JSON（工单人自助填写，未转义）
OUTDIR="/srv/notices"

read -r SUBJECT BODY < <(python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print(d['subject'],d['body'])" "$TICKET_JSON")
TICKET=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['id'])" "$TICKET_JSON")

{
  printf '.TL\n%s\n' "$SUBJECT"
  printf '.AU\n%s\n' "change-window"
  printf '.AI\n'
  printf '.SH DETAILS\n.PP\n%s\n' "$BODY"
  printf '.SH TICKET\n%s\n' "$TICKET"
} > "$OUTDIR/$TICKET.roff"

groff -ms -Tps "$OUTDIR/$TICKET.roff" > "$OUTDIR/$TICKET.ps"
echo "$OUTDIR/$TICKET.ps"
''', "groff 宏语言：工单字段未转义，可注入以点开头的请求行")

# ============================================================ 形态 5：CUPS 选项语言
add("g27-cmdlang-09", "python", r'''
import subprocess

ALLOWED_PRINTERS = {"floor-1", "floor-2", "reception"}

def submit_print_job(pdf_path):
    """打印服务：把文档按用户选择的参数投递到指定打印机。

    打印参数来自打印接口的 JSON 请求体（print_options 字段），
    形如 "media=A4 sides=two-sided-long-edge"。
    """
    body = json.loads(requests.get(JOB_API, timeout=10).text)
    printer = body["printer"]
    options = body["print_options"]
    if printer not in ALLOWED_PRINTERS:
        raise ValueError("unknown printer")

    argv = ["lp", "-d", printer]
    for token in options.split():
        argv += ["-o", token]
    argv.append(pdf_path)

    proc = subprocess.run(argv, capture_output=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace")[:400])
    return proc.stdout.decode("utf-8", "replace").strip()
''', "CUPS 选项语言：token 逐个成为 -o 选项，可写入作业属性/横幅/输出顺序等选项语言字段（弱形态：影响面为作业属性，非任意命令执行）")

add("g27-cmdlang-10", "javascript", r'''
const { execFile } = require('node:child_process');
const path = require('node:path');

const PRINTERS = new Set(['lab-a', 'lab-b']);

// 实验室自助打印：按提交的作业属性投递
function printDocument(fileKey, done) {
  // printer / jobOptions 来自打印请求体（POST /print）
  const { printer, jobOptions } = readPrintRequest(fileKey);
  if (!PRINTERS.has(printer)) {
    return done(new Error('invalid printer'));
  }

  const file = path.join('/var/spool/upload', path.basename(fileKey));
  const args = ['-d', printer];
  for (const opt of jobOptions.split(',')) {
    args.push('-o', opt.trim());
  }
  args.push(file);

  execFile('lp', args, { timeout: 60000 }, (err, stdout, stderr) => {
    if (err) return done(new Error(stderr || err.message));
    done(null, stdout.trim());
  });
}

module.exports = { printDocument };
''', "CUPS 选项语言：jobOptions 逐项进入 -o（弱形态：影响面为作业属性/输出顺序，非任意命令执行）")

# ============================================================ 形态 6：ExifTool 标签表达式
add("g27-cmdlang-11", "python", r'''
import subprocess

def dump_metadata(images):
    """素材清点：按运营上传的输出模板导出元数据清单。

    模板文件由运营上传（形如 "${FileName}\t${FileSize}"），
    内容直接交给 ExifTool 的打印格式字符串求值。
    """
    template = open(UPLOADED_REPORT_TEMPLATE, "r", encoding="utf-8").read()
    argv = ["exiftool", "-q", "-q", "-p", template]
    argv.extend(images)

    proc = subprocess.run(argv, capture_output=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace")[:400])
    return proc.stdout.decode("utf-8", "replace")
''', "ExifTool 打印格式表达式（-p）：template 进入 Perl 格式串求值位，与 12 的 -if 条件表达式是两个不同入口")

add("g27-cmdlang-12", "javascript", r'''
const { execFile } = require('node:child_process');

// 图库批处理：按条件筛选并回写说明字段
// condition / caption 来自批处理接口的查询参数（未转义）
function annotate(images, condition, caption) {
  const args = ['-r', '-overwrite_original'];
  if (condition) {
    args.push('-if', condition);
  }
  args.push('-ImageDescription=' + caption);
  args.push(...images);

  return new Promise((resolve, reject) => {
    execFile('exiftool', args, { timeout: 120000 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr || err.message));
      resolve(stdout.trim().split('\n').length);
    });
  });
}

module.exports = { annotate };
''', "ExifTool 表达式语言：condition 直接进入 -if 布尔表达式位")

# ============================================================ 形态 7：iptables / nftables 规则语言
add("g27-cmdlang-13", "python", r'''
import subprocess

CHAINS = {"input": "INPUT", "forward": "FORWARD", "output": "OUTPUT"}

def apply_policy(chain):
    """边界防护：把租户在控制台提交的网段策略下发到防火墙。

    策略行由租户经 /policies API 写入 DB，此处回读后拼成规则文本
    整体交给 iptables-restore 解析（避免逐条 fork 的开销）。
    """
    cidr, action = fetch_policy(chain)   # SELECT ... FROM tenant_policies
    target = CHAINS.get(chain)
    if target is None:
        raise ValueError("unknown chain")

    rules = "*filter\n"
    rules += f"-A {target} -s {cidr} -j {action}\n"
    rules += "COMMIT\n"

    proc = subprocess.run(
        ["iptables-restore", "--noflush"],
        input=rules.encode("utf-8"),
        capture_output=True, timeout=15,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace")[:300])
    return True

def list_rules(chain):
    target = CHAINS.get(chain)
    proc = subprocess.run(["iptables", "-S", target], capture_output=True, timeout=15)
    return proc.stdout.decode("utf-8", "replace")
''', "iptables 规则语言（-restore 解析）：cidr/action 拼进规则文本的可注入位置，可引入新规则行/COMMIT/新表（与 14 的 nft 单串表达式、16 的 nginx 配置分属不同规则语言）")

add("g27-cmdlang-14", "go", r'''
package firewall

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

var allowedFamilies = map[string]string{
	"v4": "ip",
	"v6": "ip6",
}

// Upsert 下发一条入站策略规则。
// 参数来自租户经策略 API 写入的记录（回读后拼装，未做规则语法转义）。
func Upsert(family string) error {
	p, err := loadPolicy(family) // SELECT family,cidr,ports,action FROM tenant_policies
	if err != nil {
		return err
	}
	cidr, ports, action := p.CIDR, p.Ports, p.Action
	fam, ok := allowedFamilies[family]
	if !ok {
		return fmt.Errorf("unsupported family %q", family)
	}

	expr := fmt.Sprintf("%s saddr %s ", fam, cidr)
	for _, p := range strings.Split(ports, ",") {
		expr += fmt.Sprintf("%s dport %s ", fam, strings.TrimSpace(p))
	}
	expr += action

	cmd := exec.Command("nft", "add", "rule", "inet", "filter", "input", expr)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, stderr.String())
	}
	return nil
}
''', "nftables 规则语言：cidr/ports/action 拼成规则表达式，可改变规则结构")

# ============================================================ 形态 8：应用配置语言
add("g27-cmdlang-15", "go", r'''
package render

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Flow 是日志采集平台的采集流定义，字段由租户经平台 API 提交
// （低权限角色即可创建，平台不校验配置语法）。
type Flow struct {
	Name       string
	MatchTags  string
	BufferPath string
	OutputTag  string
	Extra      map[string]string
}

// RenderFluentConf 把采集流渲染成 Fluentd 配置片段。
func RenderFluentConf(f Flow) string {
	var b strings.Builder
	b.WriteString("<match " + f.MatchTags + ">\n")
	b.WriteString("  @type forward\n")
	b.WriteString("  buffer_path " + f.BufferPath + "\n")
	b.WriteString("  tag " + f.OutputTag + "\n")
	for k, v := range f.Extra {
		b.WriteString(fmt.Sprintf("  %s %s\n", k, v))
	}
	b.WriteString("</match>\n")
	return b.String()
}

// InstallFlow 落盘采集流配置并让采集进程重新加载。
func InstallFlow(f Flow, confDir string) (string, error) {
	fragment := RenderFluentConf(f)
	safe := filepath.Base(f.Name) + ".conf"
	path := filepath.Join(confDir, safe)

	if err := os.WriteFile(path, []byte(fragment), 0o644); err != nil {
		return "", err
	}
	if err := exec.Command("fluentd", "--dry-run", "-c", path).Run(); err != nil {
		return "", fmt.Errorf("config rejected: %w", err)
	}
	if err := exec.Command("systemctl", "reload", "fluentd").Run(); err != nil {
		return "", fmt.Errorf("reload failed: %w", err)
	}
	return path, nil
}
''', "应用配置语言（Fluentd）：CRD 字段未做配置语法转义，落盘后由 fluentd 加载生效，可注入新指令/闭合指令块（对应 rolling_dev 唯一真 77 样本 corpus_00065.go 的同族形态）")

add("g27-cmdlang-16", "bash", r'''
#!/bin/bash
# 站点发布:按发布服务收到的请求体写入 upstream 配置片段
# 用法: ./publish.sh <request_body.json>

REQ="$1"
CONF_DIR="/etc/nginx/conf.d"

read -r SITE UPSTREAM_HOST UPSTREAM_PORT HEALTH_PATH < <(
  python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print(d['site'],d['upstream_host'],d['upstream_port'],d.get('health_path','/health'))" "$REQ"
)

# 站点名只用于文件名,限定字母数字与连字符
if ! [[ "$SITE" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
  echo "invalid site name" >&2
  exit 3
fi

printf 'upstream %s_backend {\n    server %s:%s;\n}\n\nserver {\n    listen 80;\n    server_name %s.internal;\n\n    location %s {\n        proxy_pass http://%s_backend;\n    }\n}\n' \
  "$SITE" "$UPSTREAM_HOST" "$UPSTREAM_PORT" "$SITE" "${HEALTH_PATH:-/health}" "$SITE" \
  > "$CONF_DIR/${SITE}.conf"

nginx -t && nginx -s reload
''', "应用配置语言（nginx）：面板字段经 printf %s 直接进入 server/location 块，可注入新指令（无 shell 命令替换、无 sed 二次注入面）")

# ============================================================ 输出
OUT_DIR.mkdir(parents=True, exist_ok=True)
out = OUT_DIR / "g27_kits.jsonl"
with out.open("w", encoding="utf-8", newline="\n") as f:
    for s in SAMPLES:
        f.write(json.dumps(s, ensure_ascii=False) + "\n")

print(f"写入 {out}  {len(SAMPLES)} 条")

# ---- 自检门（oracle 先行）
BANNED = [r"\bsh\s+-c", r"\bbash\s+-c", r"shell\s*=\s*True", r"shell:\s*true", r"shell:true",
          r"\bsystem\s*\(", r"execSync", r"Runtime\.getRuntime", r"ProcessBuilder",
          r"os\.system", r"\bpopen\b", r"std::system"]
# 次级风险：计划外的 shell 展开 / 第二注入面（只对 bash/sh 逐字检查；Go 的反引号是 raw string 语法）
SECONDARY = [r"<<(?!\s*')\s*[A-Za-z_]+", r"\$\([^)]*\)", r"`[^`]+`", r"sed\s+-i", r"\$\(\("]
import re
print("\n自检 1：OS-shell 指纹扫描（必须 0 命中）")
bad = 0
for s in SAMPLES:
    code = re.search(r"```[a-zA-Z0-9_+-]*\n(.*?)```", s["user"], re.S).group(1)
    hits = [p for p in BANNED if re.search(p, code)]
    if hits:
        print(f"  !! {s['orig']}: {hits}")
        bad += 1
print(f"  命中 {bad} 条" + ("  ✅ 全部为非 OS 命令语言" if bad == 0 else "  ❌ 需修"))

print("\n自检 2：计划外 shell 展开 / 第二注入面（只查 bash；Go/JS 的反引号、模板串是语言语法）")
bad2 = 0
for s in SAMPLES:
    lang = re.search(r"语言[:：]\s*([a-zA-Z+#]+)", s["user"]).group(1)
    if lang.lower() not in ("bash", "sh"):
        continue
    code = re.search(r"```[a-zA-Z0-9_+-]*\n(.*?)```", s["user"], re.S).group(1)
    hits = [p for p in SECONDARY if re.search(p, code)]
    if hits:
        print(f"  ?  {s['orig']}: {hits}")
        bad2 += 1
print(f"  命中 {bad2} 条" + ("  ✅ 无" if bad2 == 0 else "  ← 逐条人工确认"))

print("\n自检 3：sink 存在性（必须出现消费端：进程执行 / 文件落盘+加载 / 协议写入）")
SINK_HINT = [r"subprocess\.run", r"exec\.Command", r"execFile", r"socket", r"WriteFile",
             r"out\.write", r"sendall", r"\.Run\(\)", r"\bawk\b", r"\bgroff\b", r"\bnft\b",
             r"iptables-restore", r"\bnginx\b", r"\blp\b", r"\bpdflatex\b", r"\bfluentd\b",
             r">\s*\"", r"\"\s*>\s*", r"\bcurl\b", r"\bsendmail\b"]
bad3 = 0
for s in SAMPLES:
    code = re.search(r"```[a-zA-Z0-9_+-]*\n(.*?)```", s["user"], re.S).group(1)
    if not any(re.search(p, code) for p in SINK_HINT):
        print(f"  !! {s['orig']}: 未见消费端")
        bad3 += 1
print(f"  缺失 {bad3} 条" + ("  ✅ 每条都有消费端" if bad3 == 0 else "  ❌ 需补 sink"))

print("\n形态覆盖:")
for s in SAMPLES:
    code = re.search(r"```[a-zA-Z0-9_+-]*\n(.*?)```", s["user"], re.S).group(1)
    n = len([l for l in code.splitlines() if l.strip()])
    print(f"  {s['orig']:<20} 码 {n:>3} 行")
