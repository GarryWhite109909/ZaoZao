# P0-3 B 桶人工复核包（承认攻击成立 + 样本外洗白）

共 69 条。每条：行号 / 语言 / JSON 结论 / 代码块 / 命中句。


---

## row 112  ·  c  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 样本内全路径不可达越界：copy_at_offset（line 13）的守卫仅覆盖 offset（line 14），确缺 offset+src_len<=dst->len 校验，但唯一调用点 line 40 的目标缓冲由 line 54-55 按 MAX_BUF 分配并把 len 设为 128，且 total 已在 line 28 被 MAX_BUF 上界拦截 → 写入区间恒落在容量内。缺陷真实存在（敌意调用方可触发，实测已复现崩溃），但触发需要样本外敌意调用方，按样本内可达性纪律判 safe；非 CWE-120 因为不存在样本内可达的缓冲区复制越界；非 CWE-787 因为无越界写实际发生；非 CWE-125 因为读取侧同样受该上界约束。

**命中句**
> 5. 可达性纪律：line 14 的守卫不足只有在"调用方传入的 len 与分配容量不一致"时才被激活，需要样本外的敌意调用方
>

**代码块**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 128

typedef struct {
    char *data;
    int len;
} Buffer;

/* 内部辅助函数：按指定偏移拷贝，返回是否成功 */
static int copy_at_offset(Buffer *dst, const char *src, int offset, int src_len) {
    if (offset < 0 || offset > dst->len) {
        return -1;
    }
    /* 缺少剩余空间检查：offset+src_len可能超过dst->len */
    memcpy(dst->data + offset, src, src_len);
    return 0;
}

/* 外部接口：合并两个缓冲区 */
int merge_buffers(Buffer *dst, const Buffer *src1, const Buffer *src2) {
    if (!dst || !src1 || !src2) {
        return -1;
    }
    int total = src1->len + src2->len;
    if (total > MAX_BUF) {
        return -1;
    }

    char *tmp = (char *)malloc(total);
    if (!tmp) {
        return -1;
    }
    memcpy(tmp, src1->data, src1->len);
    memcpy(tmp + src1->len, src2->data, src2->len);

    /* 先拷贝到临时缓冲区，安全 */
    copy_at_offset(dst, tmp, 0, total);

    free(tmp);
    return 0;
}

int main() {
    Buffer a = {NULL, 0}, b = {NULL, 0}, out = {NULL, 0};
    char buf1[64] = "hello";
    char buf2[64] = " world!";

    a.data = buf1; a.len = strlen(buf1);
    b.data = buf2; b.len = strlen(buf2);

    out.data = (char *)malloc(MAX_BUF);
    out.len = MAX_BUF;

    if (merge_buffers(&out, &a, &b) == 0) {
        printf("merged: %s\n", out.data);
    }

    free(out.data);
    return 0;
}
```

---

## row 1067  ·  javascript  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: line 34 JSON.parse 构造纯数据对象，无类实例化/gadget 面，非 CWE-502 sink；line 40-44 HMAC 签名校验限制伪造；line 53 特权分支（line 55）与普通路径（line 61）执行同一 updatePassword(tokenData.userId, newPassword)，特权分支仅多 revokeAll(本人 token)，文件内不存在仅 admin 分支可达的危险操作——即使利用签名仅覆盖 userId 的缺口注入 role/forceReset 也无提权收益，判 safe。设计注记：line 40-41 签名应覆盖完整 payload，属加固建议而非可利用漏洞

**命中句**
> 深度防御上应签名完整 payload，在本文件内该缺口无提权收益，属上游加固项
>

**代码块**
```javascript
// PasswordResetController.js - Spring Boot password reset endpoint
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const db = require('./db');
const { sendEmail } = require('./mailer');
const { verifyToken } = require('./tokenUtils');

// Simulate Spring-style dependency injection (simplified)
class PasswordResetService {
  constructor(userRepo, tokenStore) {
    this.userRepo = userRepo;
    this.tokenStore = tokenStore;
  }

  // Endpoint: POST /api/password-reset/confirm
  async confirmReset(req, res) {
    const { resetToken, newPassword, confirmPassword } = req.body;

    // Basic validation - not the focus
    if (!resetToken || !newPassword || newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'Invalid request' });
    }

    // Security check: prevent prototype pollution via token (defensive)
    if (resetToken.includes('__proto__') || resetToken.includes('constructor')) {
      return res.status(400).json({ error: 'Invalid token format' });
    }

    
    let tokenData;
    try {

      tokenData = JSON.parse(Buffer.from(resetToken, 'base64').toString('utf8'));
    } catch (e) {
      return res.status(400).json({ error: 'Malformed token' });
    }

    // Verify token signature (defensive layer - but bypassable)
    const expectedSig = crypto.createHmac('sha256', process.env.RESET_SECRET)
                              .update(tokenData.userId || '').digest('hex');
    if (tokenData.sig !== expectedSig) {
      return res.status(401).json({ error: 'Invalid signature' });
    }


    const user = await this.userRepo.findById(tokenData.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update password - tokenData could contain malicious properties
    if (tokenData.role === 'admin' && tokenData.forceReset) {
      // Privilege escalation path via deserialized object
      await this.userRepo.updatePassword(tokenData.userId, newPassword);
      await this.tokenStore.revokeAll(user.id);
      return res.json({ message: 'Password reset with elevated privileges' });
    }

    // Normal path
    await this.userRepo.updatePassword(tokenData.userId, newPassword);
    await this.tokenStore.revoke(tokenData.jti || '');
    res.json({ message: 'Password reset successful' });
  }
}

// Route registration
router.post('/confirm', (req, res) => {
  const service = new PasswordResetService(db.users, db.tokens);
  service.confirmReset(req, res);
});

module.exports = router;
```

---

## row 3081  ·  yaml  ·  JSON=False none  ·  risk=None

- 承认词: ['可注入']
- 洗白词: ['容器内']
- 强防御证据: []
- JSON.explanation: 否定推理：假设攻击者尝试通过恶意请求或环境注入破坏代理——(1) 容器以非root用户运行且capabilities全部删除，阻断提权；(2) 根文件系统只读，配置不可篡改；(3) TLS 1.2+强制，阻断协议降级；(4) 证书路径通过环境变量注入且只读挂载，无硬编码密钥；(5) proxy_pass目标固定，无动态参数拼接，所有数据流路径均被有效防御阻断。

**命中句**
> `before_script` 中的证书生成使用 `openssl`，密钥文件输出到 `/certs/client/key.pem`，该目录由 Docker Daemon 管理，且容器内以 `:ro` 只读挂载，阻断恶意写入路径
>
> 3. **第20-22行（Dockerfile权限）**：`nginx.conf` 由 `proxy` 用户所有（`chown`），权限为 `644`（仅 owner 可写），且容器内用户无密码、无 shell（`adduser -S -D`），阻断提权路径
>

**代码块**
```yaml
# .gitlab-ci.yml
stages:
  - deploy

deploy_reverse_proxy:
  stage: deploy
  image: docker:24.0
  services:
    - docker:24.0-dind
  variables:
    DOCKER_TLS_CERTDIR: "/certs"
  before_script:
    - apk add --no-cache openssl
  script:
    # 生成自签名证书（仅用于内部测试环境）
    - mkdir -p ${DOCKER_TLS_CERTDIR}/client
    - openssl req -x509 -newkey rsa:2048 -nodes -keyout ${DOCKER_TLS_CERTDIR}/client/key.pem -out ${DOCKER_TLS_CERTDIR}/client/cert.pem -days 365 -subj "/CN=internal-proxy"
    # 构建并运行反向代理容器，非root用户，最小权限
    - docker build -t internal/proxy:latest .
    - docker run -d --name proxy \
        --read-only \
        --cap-drop ALL \
        --cap-add NET_BIND_SERVICE \
        --user 10001:10001 \
        -p 8443:8443 \
        -v ${DOCKER_TLS_CERTDIR}/client:/certs:ro \
        internal/proxy:latest
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
```

---

## row 3100  ·  cpp  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: 否定推理：假设恶意输入构造超大 pixelCount 或宽高值。路径1：pixelCount 与 inputLen/3 比较，除法先于乘法，阻断像素数超限；路径2：pixelCount 与 SIZE_MAX/4 比较，阻断 outSize 乘法溢出；路径3：宽高一致性检查作为第二道防线。所有数据流路径均被阻断，无整数溢出可达内存分配或循环边界。

**命中句**
> 第28-31行循环中，`srcIdx` 和 `dstIdx` 均由 `i` 推导，因 `pixelCount` 已被验证，`i*3` 和 `i*4` 均在安全范围内，无整数溢出（`i` 最大为 `pixelCount-1`，乘积已在上游验证）
>

**代码块**
```cpp
#include <cstdint>
#include <cstring>
#include <vector>
#include <stdexcept>

// RAII wrapper for raw buffer to prevent leaks and double-free
class BufferGuard {
    uint8_t* ptr;
public:
    explicit BufferGuard(size_t size) : ptr(new uint8_t[size]) {}
    ~BufferGuard() { delete[] ptr; }
    BufferGuard(const BufferGuard&) = delete;
    BufferGuard& operator=(const BufferGuard&) = delete;
    uint8_t* get() { return ptr; }
};

// Decodes a 24-bit RGB pixel stream into a 32-bit ARGB buffer
// Returns false on any input validation failure
bool decodePixelStream(const uint8_t* input, size_t inputLen,
                       uint8_t*& output, size_t& outputLen) {
    output = nullptr;
    outputLen = 0;

    // Header: 4 bytes width, 4 bytes height, 4 bytes pixel count
    if (inputLen < 12) return false;

    uint32_t width = (input[0] << 24) | (input[1] << 16) | (input[2] << 8) | input[3];
    uint32_t height = (input[4] << 24) | (input[5] << 16) | (input[6] << 8) | input[7];
    uint32_t pixelCount = (input[8] << 24) | (input[9] << 16) | (input[10] << 8) | input[11];

    // Guard against integer overflow: each pixel is 3 bytes input, 4 bytes output
    // Use division instead of multiplication to avoid overflow in the check itself
    if (pixelCount > inputLen / 3) return false;
    if (pixelCount > SIZE_MAX / 4) return false;

    // Validate dimensions are consistent with pixel count
    if (width > 0 && height > pixelCount / width) return false;
    if (width == 0 || height == 0) return false;

    size_t outSize = static_cast<size_t>(pixelCount) * 4;
    BufferGuard buf(outSize);  // RAII: freed automatically on any return path

    // Convert RGB (24-bit) to ARGB (32-bit) with alpha=0xFF
    for (uint32_t i = 0; i < pixelCount; ++i) {
        uint32_t srcIdx = i * 3;
        uint32_t dstIdx = i * 4;
        buf.get()[dstIdx] = input[12 + srcIdx];       // R
        buf.get()[dstIdx + 1] = input[13 + srcIdx];   // G
        buf.get()[dstIdx + 2] = input[14 + srcIdx];   // B
        buf.get()[dstIdx + 3] = 0xFF;                 // A
    }

    // Transfer ownership to caller
    output = buf.get();
    outputLen = outSize;
    return true;
}
```

---

## row 3124  ·  go  ·  JSON=False none  ·  risk=None

- 承认词: ['可注入']
- 洗白词: ['容器内', '宿主机', '沙箱']
- 强防御证据: ['白名单校验。`isAllowedTestCmd` 仅允许 `go test`、`make test`、`npm test` 三种前缀，这些前缀本身是合法命令，不包含可注入的 shell 元字符。即使攻击者传入 `go test; rm -rf /`，由于白名单只校验前缀，后接的 `; rm -rf /` 会被 sh 解释执行——但这里的关键在于：**整个命令是 `cd /tmp/build-<commitID> && <TestCmd>`，而 commitID 已被第 48-57 行严格限定']
- JSON.explanation: 否定推理：攻击者试图通过 TestCmd 注入 shell 命令，但 (1) RepoURL 被限制为 github/gitlab 的 HTTPS 域名，(2) CommitID 被限制为 40 位十六进制字符，排除了所有 shell 元字符，(3) TestCmd 必须匹配白名单前缀（go test/make test/npm test），且这些前缀本身不含可注入字符。即使攻击者追加 '; cat /etc/passwd'，由于 commitID 无法注入且 cd 路径固定，命令只能在沙箱构建环境中执行，且这是构建服务的预期功能。三重防御（域名白名单 + 严格格式校验 + 命令前缀白名单）共同阻断了所有命令注入路径，因此代码安全。

**命中句**
> 第 48-57 行），`cd /tmp/build-<hex>` 是安全的固定路径，而 `go test` 本身是白名单允许的合法命令，攻击者通过 `;` 追加的 `cat /etc/passwd` 虽然会执行，但**该行为发生在构建容器的沙箱环境中**（API 网关的构建服务通常运行在隔离容器内），且攻击者原本就有权在构建环境中执行任意测试命令（这是构建服务的正常功能）
>
> 真正的漏洞场景是攻击者能逃逸出构建环境或访问宿主机资源，而本代码通过 commitID 校验、仓库域名白名单、命令前缀白名单三重防线，已确保攻击者无法篡改命令执行路径或注入系统级命令
>

**代码块**
```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

type BuildRequest struct {
	RepoURL  string `json:"repo_url"`
	CommitID string `json:"commit_id"`
	TestCmd  string `json:"test_cmd"`
}

type BuildResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// 白名单：允许的测试命令前缀
var allowedTestPrefixes = []string{
	"go test",
	"make test",
	"npm test",
}

func isAllowedTestCmd(cmd string) bool {
	for _, prefix := range allowedTestPrefixes {
		if strings.HasPrefix(cmd, prefix) {
			return true
		}
	}
	return false
}

func handleBuild(w http.ResponseWriter, r *http.Request) {
	var req BuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// 输入校验：repo URL 必须为 HTTPS 且来自白名单域名
	if !strings.HasPrefix(req.RepoURL, "https://github.com/") &&
		!strings.HasPrefix(req.RepoURL, "https://gitlab.com/") {
		http.Error(w, "repo URL not allowed", http.StatusBadRequest)
		return
	}

	// Commit ID 校验：仅允许 40 位十六进制字符（SHA-1）
	if len(req.CommitID) != 40 {
		http.Error(w, "invalid commit ID", http.StatusBadRequest)
		return
	}
	for _, c := range req.CommitID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			http.Error(w, "invalid commit ID format", http.StatusBadRequest)
			return
		}
	}

	// 测试命令白名单校验
	if !isAllowedTestCmd(req.TestCmd) {
		http.Error(w, "test command not allowed", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// 安全执行：使用列表参数 + shell=False（默认）
	cmdArgs := []string{
		"git",
		"clone",
		"--depth",
		"1",
		req.RepoURL,
		"/tmp/build-" + req.CommitID,
	}

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("clone failed: %s", string(output)), http.StatusInternalServerError)
		return
	}
…（截断）
```

---

## row 3171  ·  c  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: 否定推理：假设恶意输入（超长payload_len或非法pkt->len），从handle_packet入口追踪数据流——line 37拦截len>256，line 39拦截len<4，因此payload_len恒在[0,252]；process_payload内部line 13再次校验payload_len≤252，阻断malloc/memcpy越界；line 31的buffer=NULL消除悬垂指针风险；line 44的data+HEADER_SIZE偏移访问始终在data[256]边界内。所有数据流路径均被防御阻断，无CWE-121漏洞。

**命中句**
> 2. **line 37 - line 44（调用链上游校验）**：`handle_packet` 首先验证 `pkt->len <= MAX_PKT_SIZE`（line 37），再验证 `pkt->len >= HEADER_SIZE`（line 39），因此 `payload_len = pkt->len - HEADER_SIZE` 的取值范围是 `[0, 252]
>

**代码块**
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_PKT_SIZE 256
#define HEADER_SIZE 4

typedef struct {
    uint8_t data[MAX_PKT_SIZE];
    uint16_t len;
} packet_t;

static int process_payload(const uint8_t *payload, uint16_t payload_len) {
    // but double-check for defense-in-depth
    if (payload_len > MAX_PKT_SIZE - HEADER_SIZE) {
        return -1;
    }
    
    uint8_t *buffer = (uint8_t *)malloc(payload_len);
    if (!buffer) {
        return -2;
    }
    
    memcpy(buffer, payload, payload_len);
    
    // Simulate processing
    uint32_t checksum = 0;
    for (uint16_t i = 0; i < payload_len; i++) {
        checksum += buffer[i];
    }
    
    free(buffer);
    buffer = NULL;  // prevent dangling pointer
    
    return (int)(checksum % 100);
}

int handle_packet(packet_t *pkt) {
    if (!pkt || pkt->len > MAX_PKT_SIZE) {
        return -3;
    }
    
    // validate header length before parsing
    if (pkt->len < HEADER_SIZE) {
        return -4;
    }
    
    uint16_t payload_len = pkt->len - HEADER_SIZE;
    
    
    return process_payload(pkt->data + HEADER_SIZE, payload_len);
}

int main(void) {
    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    
    // Simulate receiving a packet
    pkt.len = 10;  // header(4) + payload(6)
    memcpy(pkt.data, "\x01\x02\x03\x04", HEADER_SIZE);
    memcpy(pkt.data + HEADER_SIZE, "abcdef", 6);
    
    int result = handle_packet(&pkt);
    printf("Result: %d\n", result);
    return 0;
}
```

---

## row 3195  ·  dockerfile  ·  JSON=False none  ·  risk=None

- 承认词: ['可被利用']
- 洗白词: ['宿主机']
- 强防御证据: []
- JSON.explanation: 否定推理：环境变量引用替代硬编码凭据；非root用户+只读文件系统+no-new-privileges阻断提权路径；cap_drop ALL+最小cap_add限制内核能力；TLSv1.2+和强密码套件禁用弱加密；HTTP强制跳转HTTPS覆盖明文传输。所有潜在利用路径均被多层防御阻断。

**命中句**
> 1. 第1-4行（docker-compose environment）：`DB_PASSWORD=${DB_PASSWORD}` 和 `API_TOKEN=${API_TOKEN}` 从宿主机环境变量注入
>
> 假设攻击者注入恶意值，该值仅作为环境变量传入容器，但应用层需自行验证格式——Dockerfile层面不存在硬编码或可被利用的静态凭据，攻击面转移到应用代码而非配置层
>

**代码块**
```dockerfile
# docker-compose.yml
version: '3.8'

services:
  api:
    build: .
    image: myapp-api:latest
    environment:
      - DB_PASSWORD=${DB_PASSWORD}   # 引用外部环境变量，不硬编码
      - API_TOKEN=${API_TOKEN}
    ports:
      - "8080:8080"
    user: "10001:10001"              # 非root运行
    read_only: true                  # 只读文件系统
    security_opt:
      - no-new-privileges:true       # 禁止提权
    cap_drop:
      - ALL                          # 移除所有capabilities
    cap_add:
      - NET_BIND_SERVICE             # 仅保留绑定端口所需
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 5s
      retries: 3
    networks:
      - internal

  nginx:
    image: nginx:1.25-alpine
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - api
    networks:
      - internal
    ports:
      - "443:443"

networks:
  internal:
    driver: bridge
```

---

## row 3416  ·  bash  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: ['shell=False']
- JSON.explanation: 否定推理：假设恶意 branch 输入，首先被第7-17行白名单验证阻断（仅允许 staging/qa/release）；即使绕过白名单，第25行以列表参数方式直接执行脚本路径，双引号包裹 branch 作为单个 argv 元素传递，无 shell -c 字符串解析，命令注入路径被彻底切断；第21行 printf '%s' 将 branch 作为纯数据输出，不解析任何 shell 元字符。三层防御各自独立阻断，无任何数据流可达命令执行点。

**命中句**
> 即使第25行部署脚本异常退出，也不会继续执行后续命令，但更重要的是，白名单验证（步骤1）已在上游杜绝了所有注入可能，此处的严格模式仅为防御纵深
>

**代码块**
```bash
#!/usr/bin/env bash
# deploy_trigger.sh - CI/CD pipeline hook for staging deployment
# Usage: ./deploy_trigger.sh <branch_name>

set -euo pipefail

DEPLOY_BRANCHES=("staging" "qa" "release")

validate_branch() {
    local branch="$1"
    local valid=false
    for allowed in "${DEPLOY_BRANCHES[@]}"; do
        if [[ "$branch" == "$allowed" ]]; then
            valid=true
            break
        fi
    done
    if [[ "$valid" == "false" ]]; then
        echo "ERROR: Branch '$branch' not in allowlist: ${DEPLOY_BRANCHES[*]}" >&2
        exit 1
    fi
}

deploy() {
    local branch="$1"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Log deployment attempt with branch metadata (no shell interpolation of user input)
    echo "[$timestamp] INFO: Deployment requested for branch: $(printf '%s' "$branch")"
    
    # Execute deployment script with branch as argument - no shell concatenation
    /usr/local/bin/run_deploy.sh "$branch"
}

main() {
    if [[ $# -ne 1 ]]; then
        echo "Usage: $0 <branch_name>" >&2
        exit 1
    fi
    
    local branch="$1"
    validate_branch "$branch"
    deploy "$branch"
}

main "$@"
```

---

## row 3561  ·  yaml  ·  JSON=False none  ·  risk=None

- 承认词: ['可导致']
- 洗白词: ['容器内', '宿主机']
- 强防御证据: []
- JSON.explanation: 否定推理：假设恶意日志文件名或环境变量注入，但容器以非root运行（user 10001）、read_only文件系统、cap_drop ALL、no-new-privileges，且find命令参数不经过shell解析，set -eu保证失败即退出。所有攻击路径均被权限隔离和命令参数安全处理阻断，无CWE-276 Incorrect Default Permissions

**命中句**
> 日志目录挂载为只读卷（第19-21行 `volumes` 定义），容器内无法修改挂载点权限，从权限提升路径被阻断
>
> 中的变量引用**：`LOG_DIR`、`ROTATE_INTERVAL` 等来自宿主环境变量，但第24行 `command` 中所有变量均用双引号包裹（`"$LOG_DIR"`），且 `sh -c` 使用单引号包裹整个脚本，变量展开发生在容器内部，不存在宿主环境变量注入容器 shell 的路径
>
> _INTERVAL` 在第29行被 `date -d "next $ROTATE_INTERVAL"` 解析，若攻击者控制该变量可导致 `date` 报错，但 `set -eu` 使容器退出，不会执行后续命令，且容器非 root 无权限影响宿主机
>
> 4. **第32-34行 `cap_drop: ALL` 与 `security_opt: no-new-privileges`**：即使容器内进程被利用，也无法提升权限或获取新能力
>
> 第33行 `read_only: true` 确保文件系统只读，日志目录通过 volume 挂载（第19-21行）但容器内无写权限（`user` 非 root 且 volume 权限由宿主机控制），所有防御层叠加，无单点绕过路径
>

**代码块**
```yaml
version: '3.8'

services:
  log-rotator:
    image: alpine:3.19
    container_name: log-rotator
    restart: unless-stopped
    user: "10001:10001"
    read_only: true
    tmpfs:
      - /tmp
    environment:
      - LOG_DIR=${LOG_DIR:-/var/log/app}
      - ROTATE_INTERVAL=${ROTATE_INTERVAL:-daily}
      - MAX_LOG_SIZE=${MAX_LOG_SIZE:-100M}
      - KEEP_DAYS=${KEEP_DAYS:-30}
    volumes:
      - type: volume
        source: app-logs
        target: /var/log/app
        volume:
          nocopy: true
    command: >
      sh -c '
      set -eu;
      while true; do
        if [ -d "$LOG_DIR" ]; then
          find "$LOG_DIR" -type f -name "*.log" -size +"$MAX_LOG_SIZE" -mtime +"$KEEP_DAYS" -delete 2>/dev/null || true;
          find "$LOG_DIR" -type f -name "*.log" -mtime +"$KEEP_DAYS" -exec gzip {} \; 2>/dev/null || true;
        fi;
        sleep $(( $(date -d "next $ROTATE_INTERVAL" +%s) - $(date +%s) ));
      done
      '
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  app-logs:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: ${HOST_LOG_PATH:-/var/log/secure-app}
```

---

## row 3571  ·  dockerfile  ·  JSON=False none  ·  risk=None

- 承认词: ['可被利用']
- 洗白词: ['容器内']
- 强防御证据: []
- JSON.explanation: 否定推理：假设恶意输入尝试通过容器逃逸或权限提升——但非root用户(USER appuser + user:1000)阻断提权路径，read_only+privileged:false阻断文件写入和内核模块加载，no-new-privileges阻断setuid提权，数组CMD阻断shell注入，环境变量引用避免凭据硬编码。所有攻击面均被有效防御阻断，故无CWE-276漏洞。

**命中句**
> `security_opt: no-new- privileges:true` 防止进程提升权限，即使容器内被攻破也无法获得宿主root权限
>
> 所有数据流（环境变量→应用→数据库）均通过非root用户权限和只读文件系统，无写权限可被利用
>

**代码块**
```dockerfile
# Dockerfile
FROM ubuntu:22.04

# 创建非root用户，最小权限原则
RUN groupadd -r appgroup && useradd -r -g appgroup -m -s /usr/sbin/nologin appuser

# 安装依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# 复制应用并设置正确所有权
WORKDIR /app
COPY --chown=appuser:appgroup . .

# 切换至非root用户运行
USER appuser

# 暴露端口
EXPOSE 8080

# 使用数组形式执行命令，避免shell注入
CMD ["python3", "/app/app.py"]
```

---

## row 3577  ·  yaml  ·  JSON=False none  ·  risk=None

- 承认词: ['可注入']
- 洗白词: ['容器内', '宿主机']
- 强防御证据: []
- JSON.explanation: 否定推理：假设恶意日志文件名或环境变量注入，首先容器以非root用户运行且根文件系统只读，无法提权或篡改系统文件；其次日志目录只读挂载，轮转命令mv因权限不足失败，无法删除或移动日志；find的-name '*.log'白名单限制文件名模式，-exec直接传递参数不经shell解释，无法注入额外命令；环境变量通过$$转义并使用set -eu，恶意值导致find参数错误使容器立即退出，无后续执行路径。所有数据流路径均被权限限制、白名单过滤、参数化执行三层防御阻断，无漏洞。

**命中句**
> 1. **第14-16行（user与read_only）**：`user: "10001:10001"` 指定非 root 用户运行容器，`read_only: true` 使根文件系统只读，两者结合阻断容器内任意文件写入路径——即使 `entrypoint` 中的 shell 命令被恶意构造，也无法修改系统二进制或配置文件
>
> 攻击者若想提权，必须突破非 root 用户限制，但容器内无 SUID 文件（只读根文件系统），此路径被阻断
>
> 2. **第24-29行（volume 挂载与权限）**：`LOG_DIR` 目录以 `read_only: true` 绑定挂载，容器内对该目录只有读权限
>
> 这反而成为安全特性：日志文件无法被容器内进程修改或删除，只能被外部 cron 以宿主机权限处理
>
> 恶意输入（如日志内容含 `; rm -rf`）无法在容器内执行，因为 `find -exec` 的参数是固定命令 `mv` 和 `gzip`，且文件名通过 `-name "*.log"` 白名单过滤，无法注入额外参数
>
> 3. **第30-35行（归档处理与清理）**：`find /archive -name "*.gz" -mtime "+30" -delete` 删除过期归档，`-delete` 操作受限于 `/archive` 卷（容器内可写），但归档文件名由 `gzip` 自动生成（`.gz` 后缀），攻击者无法通过日志内容控制文件名（`mv` 的目标路径是固定 `/archive/` 加原文件名，而原文件名来自 `find` 的结果，`-name "*.log"` 限制只能匹配 `.log` 结尾，无路径分隔符可注入）
>
> 4. **第11-13行（环境变量引用）**：`LOG_DIR` 和 `RETENTION_DAYS` 通过 `${VAR:-default}` 语法注入，容器内 `$$LOG_DIR` 转义为 shell 变量
>

**代码块**
```yaml
version: "3.8"

services:
  log-rotator:
    image: alpine:3.18
    container_name: log-rotator
    # 非 root 运行，最小权限
    user: "10001:10001"
    read_only: true
    tmpfs:
      - /tmp
    environment:
      # 日志目录通过环境变量注入，避免硬编码路径
      LOG_DIR: ${LOG_DIR:-/var/log/myapp}
      # 保留天数，默认 7 天
      RETENTION_DAYS: ${RETENTION_DAYS:-7}
    volumes:
      # 只读挂载日志目录，轮转由外部 cron 触发
      - type: bind
        source: ${HOST_LOG_DIR:-/srv/logs}
        target: /var/log/myapp
        read_only: true
      # 轮转后的归档目录，单独可写卷
      - type: volume
        source: archive
        target: /archive
    entrypoint: ["/bin/sh", "-c"]
    command:
      - |
        set -eu
        # 使用 find 的 -mtime 参数实现按天轮转，避免 shell 通配符注入
        # 只处理 .log 文件，白名单模式
        find "$$LOG_DIR" -maxdepth 1 -type f -name "*.log" -mtime "+$$RETENTION_DAYS" -exec mv {} /archive/ \;
        # 归档文件压缩，同样只针对 .log 文件
        find /archive -maxdepth 1 -type f -name "*.log" -exec gzip {} \;
        # 清理过期归档（超过 30 天）
        find /archive -maxdepth 1 -type f -name "*.gz" -mtime "+30" -delete
        echo "Log rotation completed at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

volumes:
  archive:
    driver: local
```

---

## row 3960  ·  yaml  ·  JSON=False none  ·  risk=None

- 承认词: ['可注入']
- 洗白词: ['容器内', '宿主机']
- 强防御证据: []
- JSON.explanation: 否定推理：假设恶意输入尝试通过环境变量注入或文件写入攻击——${APP_DOMAIN}仅用于Nginx配置且默认localhost，无shell拼接；所有挂载为只读+read_only根文件系统阻断持久化写入；user:101+no-new-privileges阻断提权；internal网络阻断外连；certbot容器root权限被固定命令和容器边界限制，无用户可控输入。每条路径均被防御阻断，故安全。

**命中句**
> 1. **第 9-11 行（端口与挂载）**：仅暴露 443 端口，且所有挂载均使用 `:ro` 只读模式，阻断通过容器内写入篡改宿主机 `/html`、`/certs` 或 `nginx.conf` 的路径
>
> 2. **第 14 行（环境变量）**：`APP_DOMAIN` 通过 `${APP_DOMAIN:-localhost}` 从宿主机环境安全注入，默认值限定为 `localhost`，不存在硬编码凭据或可注入的敏感值
>
> 4. **第 24-31 行（certbot 容器）**：`user: "0:0"` 看似违反最小权限，但该容器仅执行 `certbot renew` 且挂载 `./certs` 为 `rw`，root 权限被限制在容器内，且命令为固定参数（无用户输入），`trap exit TERM` 确保优雅退出
>

**代码块**
```yaml
version: '3.8'

services:
  app:
    image: nginx:1.25-alpine
    container_name: web-app
    restart: unless-stopped
    ports:
      - "443:443"
    volumes:
      - ./html:/usr/share/nginx/html:ro
      - ./certs:/etc/nginx/certs:ro
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    environment:
      - NGINX_HOST=${APP_DOMAIN:-localhost}
      - NGINX_PORT=443
    networks:
      - internal
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /var/cache/nginx
      - /var/run
    user: "101:101"
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

  certbot:
    image: certbot/certbot:latest
    container_name: cert-renewer
    restart: unless-stopped
    volumes:
      - ./certs:/etc/letsencrypt:rw
      - ./html:/var/www/html:rw
    entrypoint: ["/bin/sh", "-c"]
    command:
      - |
        trap exit TERM
        while :; do
          certbot renew --webroot -w /var/www/html --quiet
          sleep 12h & wait $${!}
        done
    networks:
      - internal
    user: "0:0"

networks:
  internal:
    driver: bridge
    internal: true
```

---

## row 3990  ·  go  ·  JSON=False 无（未发现漏洞）  ·  risk=Low

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 用户输入仅作为 line 33 白名单精确匹配的分支选择键，line 42/44/46 的 exec.Command 命令名与参数均为字面量且 line 54 无 shell 层，注入不可达；非 CWE-78/77/88 因为输入从未进入 OS 程序执行面（78）、不存在命令语言注入点（77）、亦未落在参数位（88）——仅作枚举键使用。

**命中句**
> 该风险是否成立取决于网关是否前置认证（样本外部署假设，不作为本记录结论依据）
>

**代码块**
```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
)

// CommandRequest represents a validated command execution request
type CommandRequest struct {
	Action string `json:"action"` // must be one of: "status", "restart", "reload"
}

// allowedActions is a strict whitelist of permitted operations
var allowedActions = map[string]bool{
	"status":  true,
	"restart": true,
	"reload":  true,
}

// handleCommand processes API gateway commands with strict input validation
func handleCommand(w http.ResponseWriter, r *http.Request) {
	var req CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Whitelist validation reject any action not explicitly allowed
	if !allowedActions[req.Action] {
		http.Error(w, "action not permitted", http.StatusForbidden)
		return
	}

	// Map whitelisted action to fixed command no user input reaches exec
	var cmd *exec.Cmd
	switch req.Action {
	case "status":
		cmd = exec.Command("systemctl", "status", "nginx") // fixed args
	case "restart":
		cmd = exec.Command("systemctl", "restart", "nginx")
	case "reload":
		cmd = exec.Command("systemctl", "reload", "nginx")
	default:
		// unreachable due to whitelist, but defensive
		http.Error(w, "invalid action", http.StatusBadRequest)
		return
	}

	// Execute with no shell args are passed directly to execve
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("command failed: %v", err)
		http.Error(w, "command execution failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"output": strings.TrimSpace(string(output)),
	})
}

func main() {
	http.HandleFunc("/api/command", handleCommand)
	fmt.Println("API gateway listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

---

## row 4131  ·  c  ·  JSON=False none  ·  risk=None

- 承认词: ['可导致']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: 否定推理：假设攻击者通过 sysfs 写入超长字符串，line 46 的 count 检查拒绝 count>=256；即使绕过该检查，line 18:的 len 检查在 process_data 入口再次拒绝 len>255；最后 line 31:的 kmalloc(copy_len+1) 确保目标缓冲区大小精确匹配拷贝长度，memcpy 不可能越界。所有写入和释放操作均在 mutex 保护下，line 36:的 NULL 赋值防止 UAF。不存在任何可导致 CWE-121 Stack-based Buffer Overflow

**命中句**
> 由于 `copy_len` 已在上游被限制为 ≤255，分配大小 ≥ 拷贝大小，栈/堆缓冲区溢出路径被彻底阻断
>

**代码块**
```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/device.h>

#define MAX_BUF_SIZE 256
#define DRV_NAME "safe_drv"

struct drv_data {
    char *buffer;
    size_t size;
    struct mutex lock;
};

static struct drv_data *drv;

static int process_data(struct drv_data *d, const char *input, size_t len)
{
    char *temp;
    size_t copy_len;

    /* Validate input length against buffer capacity */
    if (len == 0 || len > MAX_BUF_SIZE - 1) {
        return -EINVAL;
    }

    copy_len = len;

    /* Allocate temporary buffer with exact size */
    temp = kmalloc(copy_len + 1, GFP_KERNEL);
    if (!temp) {
        return -ENOMEM;
    }

    /* Bounded copy */
    memcpy(temp, input, copy_len);
    temp[copy_len] = '\0';

    /* Swap buffer under lock */
    mutex_lock(&d->lock);
    kfree(d->buffer);
    d->buffer = temp;
    d->size = copy_len;
    mutex_unlock(&d->lock);

    return 0;
}

static ssize_t drv_write(struct device *dev, struct device_attribute *attr,
                         const char *buf, size_t count)
{
    /* Kernel's sysfs layer already bounds count to PAGE_SIZE */
    if (count >= MAX_BUF_SIZE) {
        return -EINVAL;
    }

    /* Pass through with explicit size no strlen reliance */
    return process_data(drv, buf, count);
}

static DEVICE_ATTR_WO(drv_write);

static int __init drv_init(void)
{
    drv = kzalloc(sizeof(*drv), GFP_KERNEL);
    if (!drv) {
        return -ENOMEM;
    }

    /* Initialize buffer to safe empty state */
    drv->buffer = kzalloc(1, GFP_KERNEL);
    if (!drv->buffer) {
        kfree(drv);
        return -ENOMEM;
    }
    drv->size = 0;
    mutex_init(&drv->lock);

    return 0;
}

static void __exit drv_exit(void)
{
    mutex_lock(&drv->lock);
    kfree(drv->buffer);
    drv->buffer = NULL;  /* NULL after free */
    mutex_unlock(&drv->lock);
    kfree(drv);
}
…（截断）
```

---

## row 4495  ·  go  ·  JSON=False none  ·  risk=None

- 承认词: ['可被利用']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: 否定推理：虽然使用 shell=True 和命令拼接，但 cfg.Database 经白名单校验（仅允许三个固定值），cfg.TargetDir 经 shlexQuote 安全引用（特殊字符被单引号包裹）。恶意输入在两条数据流路径上均被阻断：白名单拒绝非预期数据库名，引用机制防止路径参数被解释为 shell 命令。因此不存在命令注入漏洞。

**命中句**
> 4. **第33-36行**：`exec.CommandContext` 使用 `sh -c` 执行拼接命令，但因为没有其他未过滤的输入变量，且所有动态值已在上游安全化处理，所以整体命令字符串是固定的安全模板加白名单值加引用后的路径
>
> 不存在可被利用的注入点
>

**代码块**
```go
package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// BackupConfig 定义备份任务配置
type BackupConfig struct {
	Database string
	TargetDir string
}

// runBackup 执行数据库备份任务（定时任务入口）
func runBackup(ctx context.Context, cfg BackupConfig) error {
	// 白名单：仅允许备份指定的数据库
	allowedDBs := map[string]bool{
		"orders":   true,
		"customers": true,
		"inventory": true,
	}

	// 校验数据库名是否在白名单中
	if !allowedDBs[cfg.Database] {
		return fmt.Errorf("database %q not allowed for backup", cfg.Database)
	}

	// 使用 shlex.Quote 对目标目录进行安全引用
	quotedTarget := shlexQuote(cfg.TargetDir)

	// 使用 shell=True + 命令拼接
	cmdStr := fmt.Sprintf("mysqldump -u backup_user %s | gzip > %s/backup.gz", cfg.Database, quotedTarget)

	// 在实际安全实现中，应使用参数列表形式 + shell=False
	// 直接执行拼接命令
	cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("backup failed for %s: %v, output: %s", cfg.Database, err, string(output))
		return err
	}

	log.Printf("backup completed for %s, output: %s", cfg.Database, string(output))
	return nil
}

// shlexQuote 模拟 shlex.quote 的行为（安全引用 shell 参数）
func shlexQuote(s string) string {
	if s == "" {
		return "''"
	}
	// 简单实现：如果包含特殊字符则用单引号包裹
	safe := true
	for _, c := range s {
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '/' && c != '.' && c != '-' && c != '_' {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 定时任务配置
	cfg := BackupConfig{
		Database:  "orders",
		TargetDir: "/backups/daily",
	}

	// 模拟定时器触发
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("backup scheduler stopped")
			return
		case <-ticker.C:
			if err := runBackup(ctx, cfg); err != nil {
…（截断）
```

---

## row 4504  ·  yaml  ·  JSON=False none  ·  risk=None

- 承认词: ['能够读取']
- 洗白词: ['容器内', '宿主机']
- 强防御证据: []
- JSON.explanation: 否定推理：假设攻击者获得应用容器的代码执行权限——(1) 非 root 用户 + 全部 capabilities 被丢弃，无法提权；(2) 根文件系统只读且 tmpfs 不持久化，无法写入持久化恶意文件；(3) 环境变量引用外部注入的敏感值，无硬编码凭据；(4) 内部网络隔离，无端口暴露，无法横向移动或外联；(5) no-new-privileges 阻止 setuid 提权。所有攻击路径均被阻断，配置符合最小权限原则。

**命中句**
> 攻击者即使通过应用漏洞获得代码执行权限，也无法获得 root 权限或提升权限，因为容器内没有 setuid 二进制且 capabilities 被最小化
>
> 攻击者无法在容器内写入持久化文件（如 cron 脚本、SSH 密钥），也无法修改应用配置
>
> 4. **第 25-30 行（网络隔离）**：`networks: internal: internal: true` 将服务置于内部网络，不暴露任何端口到宿主机
>
> 即使攻击者控制应用容器，也无法直接访问外部网络或宿主机服务，横向移动被阻断
>

**代码块**
```yaml
version: '3.8'

services:
  app:
    image: myapp:latest
    container_name: myapp
    restart: unless-stopped
    user: "10001:10001"
    environment:
      - DB_HOST=${DB_HOST}
      - DB_PORT=${DB_PORT}
      - DB_USER=${DB_USER}
      - DB_PASSWORD=${DB_PASSWORD}
      - APP_SECRET=${APP_SECRET}
    volumes:
      - app-data:/var/lib/myapp
    networks:
      - internal
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'

  redis:
    image: redis:7-alpine
    container_name: myapp-redis
    user: "999:999"
    command: ["redis-server", "--appendonly", "yes", "--requirepass", "${REDIS_PASSWORD}"]
    volumes:
      - redis-data:/data
    networks:
      - internal
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - SETGID
      - SETUID
      - CHOWN
    deploy:
      resources:
        limits:
          memory: 128M
          cpus: '0.25'

volumes:
  app-data:
  redis-data:

networks:
  internal:
    internal: true
```

---

## row 4598  ·  dockerfile  ·  JSON=False none  ·  risk=None

- 承认词: ['可被利用']
- 洗白词: ['宿主机']
- 强防御证据: []
- JSON.explanation: 否定推理：假设攻击者尝试通过容器逃逸或权限提升，但容器以非root用户(user: 101/70)运行，根文件系统只读(read_only: true)，所有Linux capabilities被丢弃(cap_drop: ALL)仅保留NET_BIND_SERVICE，且no-new-privileges禁止提权。数据库密码通过环境变量${DB_PASSWORD}注入而非硬编码，且数据库端口仅内部暴露(expose)。所有权限最小化措施形成完整防御链，攻击者无法获得持久化写入能力、无法提权、无法获取敏感凭据，因此不存在CWE-276权限过大漏洞。

**命中句**
> 即使攻击者写入恶意文件，也无法持久化到宿主机，且无法修改系统配置
>
> 所有权限最小化设计相互配合，无任何可被利用的权限提升链
>

**代码块**
```dockerfile
# docker-compose.yml
version: '3.8'

services:
  app:
    image: nginx:1.25-alpine
    container_name: webapp
    # 非root用户运行，避免容器内提权
    user: "101:101"
    ports:
      - "8443:443"
    volumes:
      - ./certs:/etc/nginx/certs:ro
      - ./html:/usr/share/nginx/html:ro
    environment:
      - NGINX_ENTRYPOINT_QUIET_LOGS=1
    # 只读根文件系统，限制容器内写操作
    read_only: true
    tmpfs:
      - /var/cache/nginx
      - /var/run
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
    restart: unless-stopped

  db:
    image: postgres:15-alpine
    container_name: database
    # 数据库专用非root用户
    user: "70:70"
    volumes:
      - pgdata:/var/lib/postgresql/data
    environment:
      # 通过环境变量注入，避免硬编码密码
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_DB=${DB_NAME}
    # 数据库不需要对外暴露端口，仅内部网络访问
    expose:
      - "5432"
    networks:
      - internal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER}"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  internal:
    driver: bridge

volumes:
  pgdata:
    driver: local
```

---

## row 4921  ·  yaml  ·  JSON=False none  ·  risk=None

- 承认词: ['可被利用']
- 洗白词: ['容器内']
- 强防御证据: []
- JSON.explanation: 否定推理：假设恶意CI变量注入，但目录权限被chmod 750和stat验证双重限制，用户创建使用无密码系统账号，无硬编码凭据，且操作仅限CI容器内非root环境，所有数据流路径均被阻断，无CWE-732风险。

**命中句**
> 整个 init job 无密码、token 或私钥操作，数据流中不存在可被利用的硬编码凭据
>
> **否定推理**：假设攻击者尝试通过 CI 变量注入恶意 `$DEPLOY_DIR`（如 `../../etc`），但第22-24行 `mkdir -p` 和 `chown` 限定在 CI 容器内，且第26-31行验证权限为 `750` 而非 `777`，无法提权
>
> 假设攻击者利用 `$RUN_AS_USER` 注入特殊字符（如 `root`），`id -u` 检查会因 root 已存在而跳过创建，但后续 `chown root:root` 仍有效——不过 CI 容器内无敏感文件且非特权，风险被隔离
>

**代码块**
```yaml
# .gitlab-ci.yml
stages:
  - init
  - build
  - test

variables:
  DEPLOY_DIR: "/opt/app"
  RUN_AS_USER: "appuser"

init-job:
  stage: init
  image: alpine:3.18
  before_script:
    - apk add --no-cache shadow  # 提供 usermod/groupmod
  script:
    # 创建非root用户，最小权限
    - |
      if ! id -u "$RUN_AS_USER" >/dev/null 2>&1; then
        addgroup -S "$RUN_AS_USER" && adduser -S -G "$RUN_AS_USER" "$RUN_AS_USER"
      fi
    # 设置目录权限：owner=appuser，group=appuser，权限750（rwxr-x---）
    - mkdir -p "$DEPLOY_DIR"
    - chown "$RUN_AS_USER":"$RUN_AS_USER" "$DEPLOY_DIR"
    - chmod 750 "$DEPLOY_DIR"
    # 验证权限（防误配）
    - |
      perms=$(stat -c "%a" "$DEPLOY_DIR")
      if [ "$perms" != "750" ]; then
        echo "ERROR: unexpected permissions $perms" >&2
        exit 1
      fi
    # 使用环境变量引用，避免硬编码密码（此job无密码操作）
    - echo "Init done for user $RUN_AS_USER"
  after_script:
    - echo "Job finished"

build-job:
  stage: build
  image: docker:24.0
  services:
    - docker:24.0-dind
  script:
    - docker build --no-cache -t myapp:latest .
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'

test-job:
  stage: test
  image: alpine:3.18
  script:
    - echo "Run tests (placeholder)"
  dependencies:
    - build-job
```

---

## row 5055  ·  dockerfile  ·  JSON=False none  ·  risk=None

- 承认词: ['可被利用']
- 洗白词: ['宿主机']
- 强防御证据: []
- JSON.explanation: 否定推理：端口仅绑定127.0.0.1阻断外部访问；密码通过环境变量注入无硬编码；非root用户+read_only+cap_drop ALL+no-new-privileges 多层防御阻断提权与文件写入；数据库同样以非root运行且凭证来自环境变量。所有攻击路径均被有效阻断，无CWE-276风险。

**命中句**
> 攻击者无法从宿主机外部触达该服务，阻断外部数据流入口
>
> 即使容器被攻破，攻击者无法从镜像或配置文件中提取明文密码，因为变量值仅在运行时由宿主机注入
>
> 未映射数据卷到宿主机（仅使用命名卷 `db_data`），避免直接暴露宿主机目录
>
> **否定推理**：假设恶意输入尝试通过容器逃逸或提权——由于 root 被禁用、所有能力被丢弃、文件系统只读，且敏感信息来自运行时环境变量，不存在可被利用的写路径或凭证泄露路径
>

**代码块**
```dockerfile
# docker-compose.yml
version: '3.8'

services:
  app:
    image: myapp:latest
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      - DB_PASSWORD=${DB_PASSWORD}
      - API_KEY=${API_KEY}
    user: "1000:1000"
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    restart: unless-stopped
    networks:
      - internal

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - db_data:/var/lib/postgresql/data
    user: "999:999"
    networks:
      - internal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  db_data:

networks:
  internal:
    driver: bridge
```

---

## row 5277  ·  bash  ·  JSON=False none  ·  risk=None

- 承认词: ['可被利用']
- 洗白词: ['容器内']
- 强防御证据: []
- JSON.explanation: 否定推理：假设恶意输入注入 IMAGE_NAME/TAG/DOCKER_PASSWORD，路径1：validate_name 白名单正则拒绝非法字符并 exit 1；路径2：密码通过 stdin 管道传递，不进入命令行 shell 解析；路径3：环境变量强制要求（:?）阻断缺失凭据的默认值回退。所有数据流路径均被阻断，无 shell 命令拼接点，故安全。

**命中句**
> 4. **第29-31行**：`docker build` 使用 `--build-arg` 传递非 root 用户 ID（`id -u`/`id -g`），容器内进程以非特权用户运行
>
> 结合第5-8行的强制环境变量注入，整条数据流从 source（环境变量）到 sink（docker 命令）均有白名单校验和参数化传递双重防护，无 shell 解释路径可被利用
>

**代码块**
```bash
#!/bin/bash
# 容器构建脚本
# 场景：在 CI 流水线中构建并推送 Docker 镜像

set -euo pipefail

# 安全配置：使用环境变量而非硬编码凭据
REGISTRY="${REGISTRY:-registry.example.com}"
IMAGE_NAME="${IMAGE_NAME:-myapp}"
TAG="${TAG:-latest}"
# 从 CI secret 注入，不在代码中明文存储
DOCKER_USERNAME="${DOCKER_USERNAME:?必须设置 DOCKER_USERNAME}"
DOCKER_PASSWORD="${DOCKER_PASSWORD:?必须设置 DOCKER_PASSWORD}"

# 输入校验：仅允许字母数字、连字符、点、下划线（白名单模式）
validate_name() {
    local input="$1"
    if [[ ! "$input" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        echo "错误：非法字符，仅允许字母数字、连字符、点、下划线" >&2
        exit 1
    fi
}

validate_name "$IMAGE_NAME"
validate_name "$TAG"

# 使用参数化方式传递凭据，避免在命令行中暴露
echo "$DOCKER_PASSWORD" | docker login "$REGISTRY" -u "$DOCKER_USERNAME" --password-stdin

# 构建镜像（非 root 用户运行，使用最小权限）
docker build \
    --build-arg BUILD_UID="$(id -u)" \
    --build-arg BUILD_GID="$(id -g)" \
    -t "${REGISTRY}/${IMAGE_NAME}:${TAG}" \
    .

# 推送镜像
docker push "${REGISTRY}/${IMAGE_NAME}:${TAG}"

# 清理：登出并删除本地凭据
docker logout "$REGISTRY"
```

---

## row 5291  ·  yaml  ·  JSON=False none  ·  risk=None

- 承认词: ['可导致']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: 否定推理：假设攻击者能控制 pipeline 变量或修改配置——但变量受保护且仅 main 分支可用；证书挂载为只读且 nginx 以非 root 运行；TLS 1.3 白名单阻断降级攻击；nginx -t 在 reload 前校验配置，恶意修改无法生效。所有数据流路径均被防御阻断。

**命中句**
> 4. **第33行**：`proxy_hide_header X-Powered-By` 移除上游应用版本信息，减少攻击面
>

**代码块**
```yaml
# .gitlab-ci.yml
stages:
  - deploy

variables:
  NGINX_CONF_PATH: "/etc/nginx/conf.d/reverse-proxy.conf"
  # 敏感信息通过 CI/CD 变量注入，不硬编码在仓库中
  UPSTREAM_HOST: "internal-backend:8080"
  TLS_CERT_PATH: "/etc/nginx/certs/server.crt"
  TLS_KEY_PATH: "/etc/nginx/certs/server.key"

deploy_reverse_proxy:
  stage: deploy
  image: nginx:1.25-alpine
  before_script:
    - apk add --no-cache openssl
  script:
    # 使用受保护变量（在 GitLab 中标记为 protected），仅对受保护分支可用
    - echo "Deploying reverse proxy with TLS 1.3 only"
    # 生成临时自签名证书用于演示（生产环境应用用受管 CA 证书）
    - openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /tmp/server.key -out /tmp/server.crt \
        -subj "/CN=api.example.com"
    # 将证书复制到 nginx 容器挂载目录（由运维在 runner 上以最小权限挂载）
    - cp /tmp/server.crt /tmp/server.key ${TLS_CERT_PATH} ${TLS_KEY_PATH}
    # 使用环境变量动态生成 nginx 配置，避免硬编码内部 IP
    - cat > ${NGINX_CONF_PATH} <<EOF
      server {
          listen 443 ssl;
          # 仅启用 TLS 1.3，禁用旧协议
          ssl_protocols TLSv1.3;
          ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384';
          ssl_certificate ${TLS_CERT_PATH};
          ssl_certificate_key ${TLS_KEY_PATH};

          location / {
              proxy_pass http://${UPSTREAM_HOST};
              # 限制上游响应头，防止信息泄露
              proxy_hide_header X-Powered-By;
          }
      }
      EOF
    # 以非 root 用户运行 nginx（nginx 官方镜像默认用户为 nginx）
    - nginx -t -c ${NGINX_CONF_PATH}
    - nginx -s reload
  only:
    - main
  environment:
    name: production
```

---

## row 5631  ·  go  ·  JSON=False 无  ·  risk=Low

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 用户 Name 只作 map 精确查找键，未命中即拒绝，命令与参数全部来自固定常量且不经 shell——OS 命令注入路径被闭合；非 CWE-78/CWE-88 因为用户输入从未到达命令名或任何参数位，亦不存在 shell 元字符解释层。

**命中句**
> 残余观察（均非样本内可利用链）：line 36/58-59 错误信息把脚本 CombinedOutput 回显给客户端（信息暴露倾向，需脚本输出敏感内容才成立——样本外）
>
> 端点无认证层（部署/架构事项——样本外假设）
>

**代码块**
```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

type TaskRequest struct {
	Name string `json:"name"`
}

var allowedTasks = map[string]string{
	"backup":  "/usr/local/bin/backup.sh",
	"cleanup": "/usr/local/bin/cleanup.sh",
	"report":  "/usr/local/bin/generate_report.sh",
}

func runScheduledTask(ctx context.Context, taskName string) error {
	// 白名单校验——只允许预定义的任务名
	scriptPath, ok := allowedTasks[taskName]
	if !ok {
		return fmt.Errorf("task %q is not in the allowed list", taskName)
	}

	// 使用 exec.CommandContext 而非 exec.Command
	// 参数以列表形式传递 不使用 shell 解释
	cmd := exec.CommandContext(ctx, scriptPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("task execution failed: %v, output: %s", err, string(output))
	}
	log.Printf("task %s completed successfully", taskName)
	return nil
}

func taskHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// 直接调用 runScheduledTask 不经过 shell
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if err := runScheduledTask(ctx, req.Name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("task executed"))
}

func main() {
	http.HandleFunc("/api/task", taskHandler)
	log.Println("scheduler service listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

---

## row 7131  ·  php  ·  JSON=False none  ·  risk=None

- 承认词: ['可构造']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：line 49/line 52 赋值 `$filepath` → line 62 `$smarty = $source->getSmarty()` → line 63 `is_object($smarty->security_policy) && strpos($filepath, '://')` → line 64 `isTrustedStream(str

**命中句**
> 入口: L49 `$source->getResourceName()` / L52 `$source->getFullResourceName()` Smarty 资源名（样本外可控） | 次要: L62 `$source->getSmarty()` 取配置对象
>
> L63-L65 `isTrustedStream` 显式校验 scheme → 有效（样本外假设：`isTrustedStream` 在不受信时抛异常/终止）
>
> 此点依赖样本外 `Smarty\Security::isTrustedStream` 行为
>
> 样本外假设 StreamPlugin 资源名通常经 L52 生成含 `://`，否则存在 CWE-22 残留
>
> 若样本外方法只返回 `false`，则同载荷可触发
>
> me 且 `Security::$streams` 允许 `php`，可构造 `stream:php://filter/resource=phar://attacker/evil.phar` 使内部 `phar://` 不被检查（依赖配置，样本外）
>

**代码块**
```php
<?php
/**
 * Smarty Internal Plugin Resource Stream
 * Implements the streams as resource for Smarty template
 *


 * @author     Uwe Tews
 * @author     Rodney Rehm
 */

namespace Smarty\Resource;

use Smarty\Smarty;
use Smarty\Template;
use Smarty\Template\Source;

/**
 * Smarty Internal Plugin Resource Stream
 * Implements the streams as resource for Smarty template
 *
 * @link       https://php.net/streams


 */
class StreamPlugin extends RecompiledPlugin {

	/**
	 * populate Source Object with meta data from Resource
	 *
	 * @param Source $source source object
	 * @param Template $_template template object
	 *
	 * @return void
	 */
	public function populate(Source $source, ?Template $_template = null) {
		$source->uid = false;
		$source->content = $this->getContent($source);
		$source->timestamp = $source->exists = !!$source->content;
	}

	/**
	 * Load template's source from stream into current template object
	 *
	 * @param Source $source source object
	 *
	 * @return string template source
	 */
	public function getContent(Source $source) {

		if (strpos($source->getResourceName(), '://') !== false) {
			$filepath = $source->getResourceName();
		} else {
			$filepath = str_replace(':', '://', $source->getFullResourceName());
		}

		// Validate the underlying stream wrapper against the security policy.
		// When the built-in "stream" resource type is used (e.g.
		// stream:php://filter/...), BasePlugin::load() matches the "stream"
		// sysplugin before the stream_get_wrappers()/isTrustedStream() check,
		// so the nested wrapper ("php" here) is never validated. Parse the
		// wrapper scheme from the resolved path and check it explicitly so that
		// e.g. Security $streams = null blocks it before fopen() .
		$smarty = $source->getSmarty();
		if (is_object($smarty->security_policy) && ($_pos = strpos($filepath, '://')) !== false) {
			$smarty->security_policy->isTrustedStream(strtolower(substr($filepath, 0, $_pos)));
		}

		$t = '';
		$fp = fopen($filepath, 'r+');
		if ($fp) {
			while (!feof($fp) && ($current_line = fgets($fp)) !== false) {
				$t .= $current_line;
			}
			fclose($fp);
			return $t;
		} else {
			return false;
		}
	}

}
```

---

## row 7134  ·  python  ·  JSON=False none  ·  risk=None

- 承认词: ['可注入']
- 洗白词: ['沙箱']
- 强防御证据: []
- JSON.explanation: 所有文件路径均来自 get_temp_dir() 沙箱字面量拼接，无外部输入 -> KerasFileEditor 对 HDF5 中 ExternalLink 与 SoftLink 均采取 fail-closed 拒绝策略（第 118-137 行测试显式验证 CVE-2026-9335 同类攻击面已被封堵）-> 权重保存/加载受 Keras 框架 schema 与 shape 校验约束（错误形状在第 88-90 行被判定为 error）-> 全部 I/O sink 不可达外部控制，攻击面完整覆盖

**命中句**
> 本文件中所有文件路径（第 27、28 行，第 100–104 行，第 110–113 行）均来自 `self.get_temp_dir()` 测试沙箱目录拼接的字符串字面量，不存在任何外部用户输入作为路径来源，因此路径遍历/任意文件读写的攻击面在源头即不可达
>
> 5. 综合来看：所有 I/O 均限定于测试沙箱临时目录 -> 无外部输入进入路径或文件内容 -> KerasFileEditor 对 ExternalLink/SoftLink 双向 fail-closed 校验（第 118–137 行测试证明防护生效）-> 权重加载受框架 schema 校验约束 -> 攻击面完整覆盖，无可达漏洞 sink
>

**代码块**
```python
import os

import h5py
import numpy as np
import pytest

import keras
from keras.src import testing
from keras.src.saving.file_editor import KerasFileEditor


def get_source_model():
    inputs = keras.Input((2,))
    x = keras.layers.Dense(3, name="mydense")(inputs)
    outputs = keras.layers.Dense(3, name="output_layer")(x)
    model = keras.Model(inputs, outputs)
    return model


def get_target_model():
    inputs = keras.Input((2,))
    x = keras.layers.Dense(3, name="mydense")(inputs)
    x = keras.layers.Dense(3, name="myotherdense")(x)
    outputs = keras.layers.Dense(3, name="output_layer")(x)
    model = keras.Model(inputs, outputs)
    return model


class SavingTest(testing.TestCase):
    def test_basics(self):
        temp_filepath = os.path.join(self.get_temp_dir(), "my_model.keras")

        model = get_source_model()
        model.save(temp_filepath)

        editor = KerasFileEditor(temp_filepath)
        editor.summary()

        target_model = get_target_model()

        out = editor.compare(model)  # Succeeds
        self.assertEqual(out["status"], "success")
        out = editor.compare(target_model)  # Fails

        editor.add_object(
            "layers/dense_3", weights={"0": np.random.random((3, 3))}
        )
        out = editor.compare(target_model)  # Fails
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["error_count"], 2)

        editor.rename_object("dense_3", "dense_4")
        editor.rename_object("layers/dense_4", "dense_2")
        editor.add_weights("dense_2", weights={"1": np.random.random((3,))})
        out = editor.compare(target_model)  # Succeeds
        self.assertEqual(out["status"], "success")

        editor.add_object(
            "layers/dense_3", weights={"0": np.random.random((3, 3))}
        )
        out = editor.compare(target_model)  # Fails
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["error_count"], 1)

        editor.delete_object("layers/dense_3")
        out = editor.compare(target_model)  # Succeeds
        self.assertEqual(out["status"], "success")
        editor.summary()

        temp_filepath = os.path.join(self.get_temp_dir(), "resaved.weights.h5")
        editor.save(temp_filepath)
        target_model.load_weights(temp_filepath)

        editor = KerasFileEditor(temp_filepath)
        editor.summary()
        out = editor.compare(target_model)  # Succeeds
        self.assertEqual(out["status"], "success")

        editor.delete_weight("dense_2", "1")
        out = editor.compare(target_model)  # Fails
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["error_count"], 1)

        editor.add_weights("dense_2", {"1": np.zeros((7,))})
        out = editor.compare(target_model)  # Fails
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["error_count"], 1)

        editor.delete_weight("dense_2", "1")
        editor.add_weights("dense_2", {"1": np.zeros((3,))})
…（截断）
```

---

## row 7147  ·  php  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现“存储字节直达危险 sink”的污点流，原因： sink 前防御封死——唯一反序列化点 line 89 `$deserializer->deserialize($rawResult, VariableFrontend::class)` 之外，写入侧 line 63 `$deserializer->serialize($data, VariableFro

**命中句**
> 入口： L79 存储通道（文件流/DB 回读/Redis/Memcached，后端实现样本外） `$rawResult` | 次要： L38 内部 API 传参 `$entryIdentifier`/`$data`/`$tags`
>
> ($rawResult, VariableFrontend::class)` 之外，写入侧 L63 `$deserializer->serialize($data, VariableFrontend::class)` 已附消息级 HMAC（样本外假设①：`AuthenticatedMessageDeserializer`/`HashService` 实现正确）
>
> 1. 原生反序列化 sink 扫描：`unserialize`/`serialize` 均不出现，L63/L89 是自定义类方法——其内部安全性无法在样本内证明，只能列为样本外假设而非结论
>
> 排除：Transient 后端为进程内存储（样本外），字节来源仍是本进程 set() 原值（L60 条件下不编码），无外部污染入口
>
> 3. set 侧注入：L63 第二实参 `VariableFrontend::class` 是编译期类名常量（语义为 HMAC 上下文或类白名单域，样本外），非攻击者可控
>
> 5. 密钥链路两个样本外核验点：`new HashService()`（L62/L88 无参构造）——样本外：TYPO3 的 HashService 以 `$GLOBALS['TYPO3_CONF_VARS']['SYS']['encryptionKey']` 为 HMAC 密钥
>
> 7. 调用方缓存对象图的回读实例化：经 L63 合法管道写入的对象在 L89 仍会被重新实例化——上限取决于 `DeserializationService` 的类限制（样本外）
>
> 8. L42/L75 异常消息回显 `$entryIdentifier`：父类白名单（样本外）限制字符集，无标签能力
>
> L40/L73 `isValidEntryIdentifier($entryIdentifier)` → 有效（样本外假设：父类白名单不含路径分隔符）：键名无 `../` 能力
>
> L63 `AuthenticatedMessageDeserializer::serialize` 附签 → 有效（样本外假设①+密钥保密）：无密钥者无法构造通过 L89 验签的消息，篡改必然落入 L90
>
> 前提是验签失败确以 `DeserializerException`/其子类抛出——若抛其他类型将逃逸 catch（样本外核验点③）
>
> 伪造前提 = 获取 SYS/encryptionKey（样本外组合链），单靠样本内代码不可达
>
> 组合链： 密钥泄露/空钥（样本外）→ 按 L63 消息格式伪造带签 payload 写入后端存储 → L89 验签通过 → 终点取决于 DeserializationService 类白名单（样本外）→ 可能回到对象注入，样本内无任何一环可证
>
> 锚句： 非 CWE-502 因 反序列化点（L89）前有消息级验签且篡改路径收敛为 false（L89→L90→L91，实现正确性为样本外假设①）
>
> 非 CWE-347 因 验签未被禁用、走 HMAC 体系（样本外②）
>
> 非 CWE-22 因 L40/L73 标识符白名单（父类，样本外）无路径分隔符
>
> （判定由三项样本外假设支撑：① AuthenticatedMessageDeserializer/DeserializationService 实现正确（验签+类限制）
>

**代码块**
```php
<?php

declare(strict_types=1);

/*
 * This file is part of the TYPO3 CMS project.
 *
 * It is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, either version 2
 * of the License, or any later version.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with this source code.
 *
 * The TYPO3 project - inspiring people to share!
 */

namespace TYPO3\CMS\Core\Cache\Frontend;

use TYPO3\CMS\Core\Cache\Backend\TransientBackendInterface;
use TYPO3\CMS\Core\Crypto\HashService;
use TYPO3\CMS\Core\Serializer\AuthenticatedMessageDeserializer;
use TYPO3\CMS\Core\Serializer\DeserializationService;
use TYPO3\CMS\Core\Serializer\Exception\DeserializerException;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * A cache frontend for any kinds of PHP variables
 */
class VariableFrontend extends AbstractFrontend
{
    /**
     * Saves the value of a PHP variable in the cache. Note that the variable
     * will be serialized if necessary.
     *
     * @param int|null $lifetime Lifetime of this cache entry in seconds. If NULL is specified, the default lifetime is used. "0" means unlimited lifetime.
     */
    public function set(string $entryIdentifier, mixed $data, array $tags = [], ?int $lifetime = null): void
    {
        if (!$this->isValidEntryIdentifier($entryIdentifier)) {
            throw new \InvalidArgumentException(
                '"' . $entryIdentifier . '" is not a valid cache entry identifier.',
                1233058264
            );
        }
        foreach ($tags as $tag) {
            if (!$this->isValidTag($tag)) {
                throw new \InvalidArgumentException('"' . $tag . '" is not a valid tag for a cache entry.', 1233058269);
            }
        }
        foreach ($GLOBALS['TYPO3_CONF_VARS']['SC_OPTIONS']['t3lib/cache/frontend/class.t3lib_cache_frontend_variablefrontend.php']['set'] ?? [] as $_funcRef) {
            $params = [
                'entryIdentifier' => &$entryIdentifier,
                'variable' => &$data,
                'tags' => &$tags,
                'lifetime' => &$lifetime,
            ];
            GeneralUtility::callUserFunction($_funcRef, $params, $this);
        }
        if (!$this->backend instanceof TransientBackendInterface) {
            // No DI/GeneralUtility::makeInstance usage, since caching needs to operate prior to DI container setup.
            $deserializer = new AuthenticatedMessageDeserializer(new HashService(), new DeserializationService());
            $data = $deserializer->serialize($data, VariableFrontend::class);
        }
        $this->backend->set($entryIdentifier, $data, $tags, $lifetime);
    }

    /**
     * Finds and returns a variable value from the cache.
     */
    public function get(string $entryIdentifier): mixed
    {
        if (!$this->isValidEntryIdentifier($entryIdentifier)) {
            throw new \InvalidArgumentException(
                '"' . $entryIdentifier . '" is not a valid cache entry identifier.',
                1233058294
            );
        }
        $rawResult = $this->backend->get($entryIdentifier);
        if ($rawResult === false) {
            return false;
        }
        if ($this->backend instanceof TransientBackendInterface) {
            return $rawResult;
        }
        try {
            // No DI/GeneralUtility::makeInstance usage, since caching needs to operate prior to DI container setup.
            $deserializer = new AuthenticatedMessageDeserializer(new HashService(), new DeserializationService());
            return $deserializer->deserialize($rawResult, VariableFrontend::class);
        } catch (DeserializerException) {
…（截断）
```

---

## row 7148  ·  java  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现可达污点流，原因： line 42/line 48/line 53/line 58/line 71 均为无方法体的抽象声明；line 21 `import org.jspecify.annotations.Nullable;` 与其在 line 48/line 53 的两处使用只引入注解、不引入可执行路径；文件内不存在任何 sink。 组合链: 无。

**命中句**
> （通道同样来自 Javadoc 契约，JSON 绑定实现不在样本内——**样本外假设**
>
> 此外不能因“值可为 null”套 CWE-20：本接口不承担校验职责（L25 Javadoc 自述仅为传给 GraphQL service 的输入载体——**样本外假设**：引擎侧校验不在本文件）
>
> 非 CWE-20 因 本文件是数据契约接口，校验按分层设计位于引擎/transport 层（样本外），非本层缺陷
>

**代码块**
```java
/*
 * Copyright 2002-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.graphql;

import java.util.Map;

import org.jspecify.annotations.Nullable;


/**
 * Represents a GraphQL request with the inputs to pass to a GraphQL service
 * including a {@link #getDocument() document}, {@link #getOperationName()
 * operationName}, and {@link #getVariables() variables}.
 *
 * <p>The request can be turned to a Map via {@link #toMap()} and to be
 * submitted as JSON over HTTP or WebSocket.
 *
 * @author Rossen Stoyanchev
 * @since 1.0.0
 */
public interface GraphQlRequest {

	/**
	 * Return the GraphQL document which is the textual representation of an
	 * operation (or operations) to perform, including any selection sets and
	 * fragments.
	 */
	String getDocument();

	/**
	 * Return the name of the operation in the {@link #getDocument() document}
	 * to execute, if the document contains multiple operations.
	 */
	@Nullable String getOperationName();

	/**
	 * Return values for variables defined by the operation.
	 */
	Map<String, @Nullable Object> getVariables();

	/**
	 * Return implementor specific, protocol extensions, if any.
	 */
	Map<String, Object> getExtensions();

	/**
	 * Convert the request to a {@link Map} as defined in
	 * <a href="https://github.com/graphql/graphql-over-http/blob/main/spec/GraphQLOverHTTP.md">GraphQL over HTTP</a> and
	 * <a href="https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md">GraphQL over WebSocket</a>.
	 * <table>
	 * <tr><th>Key</th><th>Value</th></tr>
	 * <tr><td>query</td><td>{@link #getDocument() document}</td></tr>
	 * <tr><td>operationName</td><td>{@link #getOperationName() operationName}</td></tr>
	 * <tr><td>variables</td><td>{@link #getVariables() variables}</td></tr>
	 * </table>
	 */
	Map<String, Object> toMap();

}
```

---

## row 7162  ·  php  ·  JSON=False none  ·  risk=None

- 承认词: ['可被绕过']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现可达污点流，原因: line 45-line 50 在 line 61 `loadXML` 前用 `Assert::notRegex($xml, '/<(\s*)!(\s*)DOCTYPE/', ...)` 拒绝 DOCTYPE；line 30 `DEFAULT_OPTIONS` 不含 `LIBXML_DTDLOAD`、`LIBXML_DTDATTR`

**命中句**
> 样本外假设: 若传入 UTF-16 等非 ASCII 兼容编码，字节级正则可被绕过
>

**代码块**
```php
<?php

declare(strict_types=1);

namespace SimpleSAML\XML;

use DOMDocument;
use SimpleSAML\Assert\Assert;
use SimpleSAML\XML\Exception\IOException;
use SimpleSAML\XML\Exception\RuntimeException;
use SimpleSAML\XML\Exception\UnparseableXMLException;

use function file_get_contents;
use function func_num_args;
use function libxml_clear_errors;
use function libxml_get_last_error;
use function libxml_set_external_entity_loader;
use function libxml_use_internal_errors;
use function sprintf;

/**
 * @package simplesamlphp/xml-common
 */
final class DOMDocumentFactory
{
    /**
     * @var non-negative-int
     * TODO: Add LIBXML_NO_XXE to the defaults when PHP 8.4.0 + libxml 2.13.0 become generally available
     */
    public const DEFAULT_OPTIONS = LIBXML_COMPACT | LIBXML_NONET | LIBXML_NSCLEAN;


    /**
     * @param string $xml
     * @param non-negative-int $options
     *
     * @return \DOMDocument
     */
    public static function fromString(
        string $xml,
        int $options = self::DEFAULT_OPTIONS,
    ): DOMDocument {
        libxml_set_external_entity_loader(null);
        Assert::notWhitespaceOnly($xml);
        Assert::notRegex(
            $xml,
            '/<(\s*)!(\s*)DOCTYPE/',
            'Dangerous XML detected, DOCTYPE nodes are not allowed in the XML body',
            RuntimeException::class,
        );

        $internalErrors = libxml_use_internal_errors(true);
        libxml_clear_errors();

        // If LIBXML_NO_XXE is available and option not set
        if (func_num_args() === 1 && defined('LIBXML_NO_XXE')) {
            $options != LIBXML_NO_XXE;
        }

        $domDocument = self::create();
        $loaded = $domDocument->loadXML($xml, $options);

        libxml_use_internal_errors($internalErrors);

        if (!$loaded) {
            $error = libxml_get_last_error();
            libxml_clear_errors();

            throw new UnparseableXMLException($error);
        }

        libxml_clear_errors();

        foreach ($domDocument->childNodes as $child) {
            Assert::false(
                $child->nodeType === XML_DOCUMENT_TYPE_NODE,
                'Dangerous XML detected, DOCTYPE nodes are not allowed in the XML body',
                RuntimeException::class,
            );
        }

        return $domDocument;
    }


    /**
     * @param string $file
     * @param non-negative-int $options
     *
     * @return \DOMDocument
…（截断）
```

---

## row 7163  ·  python  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现可达污点流，原因: line 55 对 `dag_id` 做 CODE 授权；line 84 取源码后，line 86-line 98 在同文件范围内做文件级授权覆盖，line 97 `file_dag_ids.issubset(readable_dag_ids)` 不成立时 line 98 将 `content` 替换为常量 `REDACTED_SO

**命中句**
> L86 `if dag_model is not None and dag_model.relative_fileloc:` → 样本外注意: 若 `relative_fileloc` 为空则跳过 L87-L98
>

**代码块**
```python
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from __future__ import annotations

from fastapi import Depends, HTTPException, Response, status
from sqlalchemy import select

from airflow.api_fastapi.app import get_auth_manager
from airflow.api_fastapi.auth.managers.models.resource_details import DagAccessEntity
from airflow.api_fastapi.common.db.common import SessionDep
from airflow.api_fastapi.common.headers import HeaderAcceptJsonOrText
from airflow.api_fastapi.common.router import AirflowRouter
from airflow.api_fastapi.common.types import Mimetype
from airflow.api_fastapi.core_api.datamodels.dag_sources import DAGSourceResponse
from airflow.api_fastapi.core_api.openapi.exceptions import create_openapi_http_exception_doc
from airflow.api_fastapi.core_api.security import GetUserDep, requires_access_dag
from airflow.models import DagModel
from airflow.models.dag_version import DagVersion

REDACTED_SOURCE = "REDACTED - you do not have read permission on all Dags in the file"
dag_sources_router = AirflowRouter(tags=["DagSource"], prefix="/dagSources")


@dag_sources_router.get(
    "/{dag_id}",
    responses={
        **create_openapi_http_exception_doc(
            [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_404_NOT_FOUND,
                status.HTTP_406_NOT_ACCEPTABLE,
            ]
        ),
        "200": {
            "description": "Successful Response",
            "content": {
                Mimetype.TEXT: {"schema": {"type": "string", "example": "dag code"}},
            },
        },
    },
    response_model=DAGSourceResponse,
    dependencies=[Depends(requires_access_dag(method="GET", access_entity=DagAccessEntity.CODE))],
)
def get_dag_source(
    accept: HeaderAcceptJsonOrText,
    dag_id: str,
    session: SessionDep,
    user: GetUserDep,
    version_number: int | None = None,
):
    """Get source code using file token."""
    dag_version = DagVersion.get_version(dag_id, version_number, session=session)
    if not dag_version:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"The source code of the Dag {dag_id}, version_number {version_number} was not found",
        )
    if not dag_version.dag_code:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail=f"Code not found. dag_id='{dag_id}' version_number='{version_number}'",
        )

    # Per-file authorization overlay on top of the ``DagAccessEntity.CODE``
    # check above: a single source file may define multiple Dags, and the
    # caller having CODE access to ``dag_id`` does not imply they may read
    # every other Dag co-located in the file. Match the file by
    # ``(relative_fileloc, bundle_name)`` -- the same keying
    # ``import_error.py`` uses for its equivalent check -- and redact the
    # response when any co-located Dag is not in the caller's readable set.
    content = dag_version.dag_code.source_code
    dag_model = dag_version.dag_model
    if dag_model is not None and dag_model.relative_fileloc:
        file_dag_ids = set(
            session.scalars(
                select(DagModel.dag_id).where(
…（截断）
```

---

## row 7164  ·  go  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: ['filepath.Clean']
- JSON.explanation: 外部输入 filename 先经第 18 行正则白名单清洗（去除路径分隔符等非白名单字符；点号在白名单内，【..】 不会被删除）(Safe 白名单 -> 截断)，再进入 Unique 的 Stat 探测；路径拼接场景由 SafeJoin 覆盖：filepath.Join 规范化 -> HasPrefix 精确前缀校验（附加分隔符防 /a 匹配 /aa）-> 失败返回 ErrEscapesBase，路径穿越攻击面被完整阻断；os.Stat 仅只读探测，无写入/执行 sink，递归后缀为内部字面量格式化，不可控。

**命中句**
> 综上，所有潜在 sink（Join 结果的使用、Stat 调用）均被上游白名单清洗与规范化+前缀双重校验覆盖，攻击面不可达
>

**代码块**
```go
// TODO: this package shouldn't really exist. we can usually just attempt our normal filesystem operations
// and handle errors atomically. eg.
// - Safe could instead be try create file, handle error
// - Unique could be try create file, on err create file (1), etc
package fileutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var ErrEscapesBase = errors.New("path escapes base")

var nonAlphaNumExpr = regexp.MustCompile("[^a-zA-Z0-9_.]+")

const maxFilenameLength = 200

func Safe(filename string) string {
	filename = nonAlphaNumExpr.ReplaceAllString(filename, "")
	ext := filepath.Ext(filename)
	filename = filename[:min(maxFilenameLength, len(filename))-len(ext)]
	return filename + ext
}

// try to find a unqiue file (or dir) name. incrementing like "example (1)"
func Unique(base, filename string) (string, error) {
	return unique(base, filename, 0)
}

func unique(base, filename string, count uint) (string, error) {
	var suffix string
	if count > 0 {
		suffix = fmt.Sprintf(" (%d)", count)
	}
	path := base + suffix
	if filename != "" {
		noExt := strings.TrimSuffix(filename, filepath.Ext(filename))
		path = filepath.Join(base, noExt+suffix+filepath.Ext(filename))
	}
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return path, nil
	}
	if err != nil {
		return "", err
	}
	return unique(base, filename, count+1)
}

func First(path ...string) (string, error) {
	var err error
	for _, p := range path {
		_, err = os.Stat(p)
		if err == nil {
			return p, nil
		}
	}
	return "", err
}

// HasPrefix checks a path has a prefix, making sure to respect path boundaries. So that /aa & /a does not match, but /a/a & /a does.
func HasPrefix(p, prefix string) bool {
	return p == prefix || strings.HasPrefix(p, filepath.Clean(prefix)+string(filepath.Separator))
}

func SafeJoin(base, rel string) (string, error) {
	abs := filepath.Join(base, rel)
	if !HasPrefix(abs, base) {
		return "", fmt.Errorf("%w: %q", ErrEscapesBase, rel)
	}
	return abs, nil
}
```

---

## row 7173  ·  python  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现样本内可证可达污点流，原因: class 链 line 28 → line 30 → line 50 → line 66 → line 68 在 line 68 `escape_text(_cls)` 处被转义，无法闭合 line 65 的 `class="admonition ` 属性；title 链需补样本外代码确认。 组合链: class 链被 

**命中句**
> title 链需补样本外代码确认
>
> L65 `name` 直接拼接 → 样本外假设: `name` 来自 L26 `parse_type(m)`，但 `__call__` 仅注册 `SUPPORTED_NAMES`
>
> L72 `render_admonition_title` 直接拼接 `text` → 样本外假设: 若 L32 `parse_title(m)` 返回原始用户标题且 renderer 未自动转义，则 title 路径仍可 XSS
>
> title 路径若样本外成立，可试 `~~~{note} <img src=x onerror=alert(1)>`，但当前样本内不能证
>
> 若 title 样本外假设成立，则 directive 标题 → L32 `parse_title` → L40 `text` → L72 拼接，与版本A同类
>

**代码块**
```python
from typing import TYPE_CHECKING, Any, Dict, Match
from ..util import escape as escape_text

from ._base import BaseDirective, DirectivePlugin

if TYPE_CHECKING:
    from ..block_parser import BlockParser
    from ..core import BlockState
    from ..markdown import Markdown


class Admonition(DirectivePlugin):
    SUPPORTED_NAMES = {
        "attention",
        "caution",
        "danger",
        "error",
        "hint",
        "important",
        "note",
        "tip",
        "warning",
    }

    def parse(self, block: "BlockParser", m: Match[str], state: "BlockState") -> Dict[str, Any]:
        name = self.parse_type(m)
        attrs = {"name": name}
        options = dict(self.parse_options(m))
        if "class" in options:
            attrs["class"] = options["class"]

        title = self.parse_title(m)
        if not title:
            title = name.capitalize()

        content = self.parse_content(m)
        children = [
            {
                "type": "admonition_title",
                "text": title,
            },
            {
                "type": "admonition_content",
                "children": self.parse_tokens(block, content, state),
            },
        ]
        return {
            "type": "admonition",
            "children": children,
            "attrs": attrs,
        }

    def __call__(self, directive: "BaseDirective", md: "Markdown") -> None:
        for name in self.SUPPORTED_NAMES:
            directive.register(name, self.parse)

        assert md.renderer is not None
        if md.renderer.NAME == "html":
            md.renderer.register("admonition", render_admonition)
            md.renderer.register("admonition_title", render_admonition_title)
            md.renderer.register("admonition_content", render_admonition_content)


def render_admonition(self: Any, text: str, name: str, **attrs: Any) -> str:
    html = '<section class="admonition ' + name
    _cls = attrs.get("class")
    if _cls:
        html += " " + escape_text(_cls)
    return html + '">\n' + text + "</section>\n"


def render_admonition_title(self: Any, text: str) -> str:
    return '<p class="admonition-title">' + text + "</p>\n"


def render_admonition_content(self: Any, text: str) -> str:
    return text
```

---

## row 7194  ·  go  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现可达污点流，原因: sink 前防御封死——line 77 `p := arg["path"].(string)` → line 83 `if !util.IsAbsPathInWorkspace(p) { ret.Code = -1; ret.Msg = "Path [" + p + "] is not in workspace"; return }

**命中句**
> 但函数体在样本外（`util` 包未贴出）：若实现为 `strings.HasPrefix(clean, workspaceDir)` 而**不带分隔符**，同级前缀（workspace=`/data/siyuan` 时 `/data/siyuan-evil/x`）可绕过
>
> 若 workspace 内存在指向外部的 symlink，或 Windows 盘符大小写差异，亦可逃逸——标"样本外假设"，需补 `util.IsAbsPathInWorkspace`
>
> 残余面载荷（悬在样本外）：`{"path":"<workspace>/conf/conf.json","id":"20210808180117-czj9bvb"}`——能否成立取决于 `model.RenderTemplate` 是否做敏感路径排除
>
> 非 CWE-668 因 该缺陷完全悬在样本外 `model.RenderTemplate` 上，按"样本外假设不得单独支撑 true"不计入本结论
>

**代码块**
```go
// SiYuan - Refactor your thinking
// Copyright (c) 2020-present, b3log.org
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package api

import (
	"net/http"

	"github.com/88250/gulu"
	"github.com/gin-gonic/gin"
	"github.com/siyuan-note/siyuan/kernel/model"
	"github.com/siyuan-note/siyuan/kernel/util"
)

func renderSprig(c *gin.Context) {
	ret := gulu.Ret.NewResult()
	defer c.JSON(http.StatusOK, ret)

	arg, ok := util.JsonArg(c, ret)
	if !ok {
		return
	}

	template := arg["template"].(string)
	content, err := model.RenderGoTemplate(template)
	if err != nil {
		ret.Code = -1
		ret.Msg = util.EscapeHTML(err.Error())
		return
	}
	ret.Data = content
}

func docSaveAsTemplate(c *gin.Context) {
	ret := gulu.Ret.NewResult()
	defer c.JSON(http.StatusOK, ret)

	arg, ok := util.JsonArg(c, ret)
	if !ok {
		return
	}

	id := arg["id"].(string)
	name := arg["name"].(string)
	overwrite := arg["overwrite"].(bool)
	code, err := model.DocSaveAsTemplate(id, name, overwrite)
	if err != nil {
		ret.Code = -1
		ret.Msg = util.EscapeHTML(err.Error())
		return
	}
	ret.Code = code
}

func renderTemplate(c *gin.Context) {
	ret := gulu.Ret.NewResult()
	defer c.JSON(http.StatusOK, ret)

	arg, ok := util.JsonArg(c, ret)
	if !ok {
		return
	}

	p := arg["path"].(string)
	id := arg["id"].(string)
	if util.InvalidIDPattern(id, ret) {
		return
	}

	if !util.IsAbsPathInWorkspace(p) {
		ret.Code = -1
		ret.Msg = "Path [" + p + "] is not in workspace"
		return
	}

	preview := false
	if previewArg := arg["preview"]; nil != previewArg {
…（截断）
```

---

## row 7200  ·  python  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游', '样本外']
- 强防御证据: ['os.path.realpath']
- JSON.explanation: 无可达污点流：未发现可达污点流，原因: sink 前防御封死 —— line 33 `realpath` 归一后由 line 35 `os.path.isabs(relpath) or os.path.commonpath([source_dir, dest]) != source_dir` 把 `dest` 强制收敛在 `source_dir` 内，且判断先于 line

**命中句**
> L17 `state.env["__file__"]`（决定 L32 基准目录，由渲染方或外层 include 设置，样本外）
>
> L87-88 的 `block_html` 通道内容取自源目录内被 include 的 `.html` 文件（谁能写该目录属样本外）
>
> **样本外**）: 该防线依赖 L75 `state.child_state(content)` 生成的子状态能否看到父状态写入的 `__include_stack__`
>
> `_escape` 的赋值时机与 `escape=False` 语义属样本外（未提供 `BaseRenderer` 定义），若该实例就是按关闭转义构造的，本行等价于不存在，此时源目录内存在攻击者可控内容的文件即退化为 XSS
>
> 要利用需攻击者能在 `source_dir` 内落地 `.html` 文件（上传目录/共享目录），属样本外部署事实
>
> 若上游主题/模板另读 `attrs.filepath` 输出，则构成绝对路径信息泄露（样本外）
>
> 非 CWE-674 因 L47-58 的循环栈在 `child_state` 共享 env 的前提下拦住互 include（该前提见上，样本外）
>

**代码块**
```python
import os
from typing import TYPE_CHECKING, Any, Dict, List, Match, Union

from ..util import escape as escape_text
from ._base import BaseDirective, DirectivePlugin

if TYPE_CHECKING:
    from ..block_parser import BlockParser
    from ..core import BaseRenderer, BlockState
    from ..markdown import Markdown


class Include(DirectivePlugin):
    def parse(
        self, block: "BlockParser", m: Match[str], state: "BlockState"
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        source_file = state.env.get("__file__")
        if not source_file:
            return {"type": "block_error", "raw": "Missing source file"}

        encoding = "utf-8"
        options = self.parse_options(m)
        if options:
            attrs = dict(options)
            if "encoding" in attrs:
                encoding = attrs["encoding"]
        else:
            attrs = {}

        relpath = self.parse_title(m)
        source_file = os.path.realpath(source_file)
        source_dir = os.path.dirname(source_file)
        dest = os.path.realpath(os.path.join(source_dir, relpath))

        if os.path.isabs(relpath) or os.path.commonpath([source_dir, dest]) != source_dir:
            return {
                "type": "block_error",
                "raw": "Could not include outside source dir: " + relpath,
            }

        if dest == source_file:
            return {
                "type": "block_error",
                "raw": "Could not include self: " + relpath,
            }

        include_stack = state.env.setdefault("__include_stack__", [])
        source_added = False
        if source_file not in include_stack:
            include_stack.append(source_file)
            source_added = True
        if dest in include_stack:
            if source_added:
                include_stack.pop()
            return {
                "type": "block_error",
                "raw": "Could not include circular reference: " + relpath,
            }

        if not os.path.isfile(dest):
            if source_added:
                include_stack.pop()
            return {
                "type": "block_error",
                "raw": "Could not find file: " + relpath,
            }

        include_stack.append(dest)
        try:
            with open(dest, "rb") as f:
                content = f.read().decode(encoding)

            ext = os.path.splitext(dest)[1]
            if ext in {".md", ".markdown", ".mkd"}:
                new_state = state.child_state(content)
                previous_file = new_state.env.get("__file__")
                new_state.env["__file__"] = dest
                try:
                    block.parse(new_state)
                finally:
                    if previous_file is None:
                        new_state.env.pop("__file__", None)
                    else:
                        new_state.env["__file__"] = previous_file
                return new_state.tokens

            elif ext in {".html", ".xhtml", ".htm"}:
                return {"type": "block_html", "raw": content}

            attrs["filepath"] = dest
…（截断）
```

---

## row 7204  ·  go  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游', '样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现可达污点流，原因: line 80 `b, rest := clearsign.Decode(data)` 解出的签名包流仍是攻击者可控输入（hash 算法字节可任选），但 line 86-line 92 `openpgp.CheckDetachedSignatureAndHash(kr, bytes.NewReader(b.Bytes), b.Arm

**命中句**
> 入口: L78 `data []byte`（同A，来源样本外）| 次要: L62 `verifyAndDecodeJSON(data, v, kr)`、L98 `isLegacySignature(data)`
>
> L44 `config.Hash()` 在 config 为 nil 时安全并落在默认 SHA256（样本外：go-crypto `Config.Hash()` 对 nil 接收者返回默认值），与 L41-L42 注释声称一致
>
> 该函数文档承诺 "checks that the expected hash functions were used"，实现为对 `expectedHashes` 遍历精确比对、不匹配即 `UnsupportedError`（样本外：库源码
>
> L100 `clearsign.Decode` + L107 前缀判定仍是"未验签明文选路"（与 L70/L77 同一写法，此处是独立判断），是否构成组合缺陷取决于调用方（样本外），本文件内不可证
>
> 5. 调用 `verifyAndDecodeJSON` 的上游（确认 `data` 确实取自不可信镜像文件）
>

**代码块**
```go
// Copyright (c) 2020-2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

var errClearsignedMsgNotFound = errors.New("clearsigned message not found")

// Hash functions specified for OpenPGP in RFC4880, excluding those that are not currently
// recommended by NIST.
var supportedPGPAlgorithms = []crypto.Hash{
	crypto.SHA224,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
}

// hashAlgorithmSupported returns whether h is a supported PGP hash function.
func hashAlgorithmSupported(h crypto.Hash) bool {
	for _, alg := range supportedPGPAlgorithms {
		if alg == h {
			return true
		}
	}
	return false
}

// signAndEncodeJSON encodes v, clear-signs it with privateKey, and writes it to w. If config is
// nil, sensible defaults are used.
func signAndEncodeJSON(w io.Writer, v interface{}, privateKey *packet.PrivateKey, config *packet.Config) error {
	if !hashAlgorithmSupported(config.Hash()) {
		return errHashUnsupported
	}

	// Get clearsign encoder.
	plaintext, err := clearsign.Encode(w, privateKey, config)
	if err != nil {
		return err
	}
	defer plaintext.Close()

	// Wrap clearsign encoder with JSON encoder.
	return json.NewEncoder(plaintext).Encode(v)
}

// verifyAndDecodeJSON reads the first clearsigned message in data, verifies its signature, and
// returns the signing entity any suffix of data which follows the message. The plaintext is
// unmarshalled to v (if not nil).
func verifyAndDecodeJSON(data []byte, v interface{}, kr openpgp.KeyRing) (*openpgp.Entity, []byte, error) {
	// Decode clearsign block and check signature.
	e, plaintext, rest, err := verifyAndDecode(data, kr)
	if err != nil {
		return e, rest, err
	}

	// Unmarshal plaintext, if requested.
	if v != nil {
		err = json.Unmarshal(plaintext, v)
	}
	return e, rest, err
}

// verifyAndDecode reads the first clearsigned message in data, verifies its signature, and returns
// the signing entity, plaintext and suffix of data which follows the message.
func verifyAndDecode(data []byte, kr openpgp.KeyRing) (*openpgp.Entity, []byte, []byte, error) {
	// Decode clearsign block.
	b, rest := clearsign.Decode(data)
	if b == nil {
		return nil, nil, rest, errClearsignedMsgNotFound
	}

	// Check signature.
	e, err := openpgp.CheckDetachedSignatureAndHash(
		kr,
		bytes.NewReader(b.Bytes),
		b.ArmoredSignature.Body,
		supportedPGPAlgorithms,
…（截断）
```

---

## row 7631  ·  php  ·  JSON=False 无  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['样本外', '通常由']
- 强防御证据: []
- JSON.explanation: handle/type 自 fields 表（line 362-365）经 heredoc 插值（line 283-298）与 str_replace（line 307-318）拼入生成代码后由 eval（line 345）执行，但样本内无任何攻击者可控数据写入该链，链条不可达；非 CWE-94 因为拼入代码文本的成分均来自框架自身 DB 状态与固定路径模板而非外部可控输入，非 CWE-95 因为输入并非直接作为 eval 参数求值，非 CWE-1336 因为“模板”是 PHP 源码文本的占位替换、无模板引擎表达式求值语义。

**命中句**
> 故抵达 eval/include 的全部变量成分＝固定模板＋框架自身维护的 DB 状态，样本内不存在攻击者可控输入（标注样本外假设：fields 表通常由 Craft 控制面板侧维护——该假设不作为结论依据）
>
> ass, FieldInterface::class)`——有效：DB 的 type 列不能驱动任意类静态调用，line 244 仅限实现 FieldInterface 的已安装类，valueType() 输出来自受信插件代码（其内部实现在样本外）
>
> 样本内不存在任一前置写入入口，攻击者须已持有管理员/DB/文件系统权限（样本外场景），届时已具备等价执行能力，本链不提供新增攻击面
>

**代码块**
```php
<?php
/**
 * @link https://craftcms.com/
 * @copyright Copyright (c) Pixel & Tonic, Inc.
 * @license https://craftcms.github.io/license/
 */

use craft\base\FieldInterface;
use craft\behaviors\CustomFieldBehavior;
use craft\db\Query;
use craft\db\Table;
use craft\helpers\App;
use craft\helpers\ArrayHelper;
use craft\helpers\Component;
use craft\helpers\DateTimeHelper;
use craft\helpers\FileHelper;
use craft\helpers\StringHelper;
use GuzzleHttp\Client;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use yii\base\ExitException;
use yii\base\InvalidConfigException;
use yii\db\Expression;
use yii\helpers\VarDumper;
use yii\web\Request;
use function GuzzleHttp\default_user_agent;

/**
 * Craft is helper class serving common Craft and Yii framework functionality.
 * It encapsulates [[Yii]] and ultimately [[yii\BaseYii]], which provides the actual implementation.
 *
 * @mixin CraftTrait
 * @author Pixel & Tonic, Inc. <support@pixelandtonic.com>
 * @since 3.0.0
 */
class Craft extends Yii
{
    // Edition constants
    public const Solo = 0;
    public const Pro = 1;

    /**
     * @var array The default cookie configuration.
     */
    private static array $_baseCookieConfig;

    /**
     * @inheritdoc
     * @template T
     * @param class-string<T>|array{class:class-string<T>}|array{__class:class-string<T>}|callable():T $type
     * @param array $params
     * @return T
     */
    public static function createObject($type, array $params = [])
    {
        if (is_array($type) && isset($type['__class']) && isset($type['class'])) {
            throw new InvalidConfigException('`__class` and `class` cannot both be specified.');
        }

        return parent::createObject($type, $params);
    }

    /**
     * Checks if a string references an environment variable (`$VARIABLE_NAME`)
     * and/or an alias (`@aliasName`), and returns the referenced value.
     *
     * If the string references an environment variable with a value of `true`
     * or `false`, a boolean value will be returned.
     *
     * ---
     *
     * 
```
```
     *
     * @param string|null $str
     * @return string|null|false The parsed value, or the original value if it didn’t
     * reference an environment variable or alias.
     * @since 3.1.0
     * @deprecated in 3.7.29. [[App::parseEnv()]] should be used instead.
     */
    public static function parseEnv(?string $str = null): string|null|false
    {
        return App::parseEnv($str);
    }

    /**
     * Checks if a string references an environment variable (`$VARIABLE_NAME`) and returns the referenced
     * boolean value, or `null` if a boolean value can’t be determined.
     *
     * ---
     *
     * 
```
```
     *
     * @param mixed $value
     * @return bool|null
     * @since 3.7.22
     * @deprecated in 3.7.29. [[App::parseBooleanEnv()]] should be used instead.
     */
    public static function parseBooleanEnv(mixed $value): ?bool
    {
        return App::parseBooleanEnv($value);
    }

    /**
     * Displays a variable.
     *
     * @param mixed $var The variable to be dumped.
     * @param int $depth The maximum depth that the dumper should go into the variable.
     * @param bool $highlight Whether the result should be syntax-highlighted.
     * @param bool $return Whether the dump result should be returned instead of output.
     * @return string|null The output, if `$return` is true
     */
    public static function dump(mixed $var, int $depth = 20, bool $highlight = true, bool $return = false): ?string
    {
        if (!$highlight) {
            if ($return) {
                ob_start();
            }
            VarDumper::dump($var, $depth);
            echo "\n";
            return $return ? ob_get_clean() : null;
        }

        $data = (new VarCloner())->cloneVar($var)->withMaxDepth($depth);
        return Craft::$app->getDumper()->dump($data, $return ? true : null);
    }

    /**
     * Displays a variable and ends the request. (“Dump and die”)
     *
     * @param mixed $var The variable to be dumped.
     * @param int $depth The maximum depth that the dumper should go into the variable.
     * @param bool $highlight Whether the result should be syntax-highlighted.
     * @throws ExitException if the application is in testing mode
     */
    public static function dd(mixed $var, int $depth = 20, bool $highlight = true): void
    {
        // Turn off output buffering and discard OB contents
        while (ob_get_length() !== false) {
            // If ob_start() didn't have the PHP_OUTPUT_HANDLER_CLEANABLE flag, ob_get_clean() will cause a PHP notice
            // and return false.
            if (@ob_get_clean() === false) {
                break;
            }
        }

        static::dump($var, $depth, $highlight);
        exit();
    }

    /**
     * Generates and returns a cookie config.
     *
     * @param array $config Any config options that should be included in the config.
     * @param Request|null $request The request object
     * @return array The cookie config array.
     */
    public static function cookieConfig(array $config = [], ?Request $request = null): array
    {
        if (!isset(self::$_baseCookieConfig)) {
            $generalConfig = static::$app->getConfig()->getGeneral();

            if ($generalConfig->useSecureCookies === 'auto') {
                $request = $request ?? static::$app->getRequest();

                if (!$request->getIsConsoleRequest()) {
                    $generalConfig->useSecureCookies = $request->getIsSecureConnection();
                }
            }

            self::$_baseCookieConfig = [
                'domain' => $generalConfig->defaultCookieDomain,
                'secure' => $generalConfig->useSecureCookies,
                'httpOnly' => true,
                'sameSite' => $generalConfig->sameSiteCookieValue,
            ];
        }

        return array_merge(self::$_baseCookieConfig, $config);
    }

    /**
…（截断）
```

---

## row 7638  ·  python  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: ['shlex.quote']
- JSON.explanation: 无可达污点流：未发现可达污点流，原因: 所有视图先经 line 63-line 65、line 99-line 101、line 129-line 131、line 151-line 153、line 175-line 177、line 206-line 208、line 227-line 229、line 285-line 287、line 310-line 312 的

**命中句**
> L81/L136/L158/L183/L215/L237/L292/L317 将输入交给 `Environment` 样本外方法
>
> L107-L109 `get_adb()`/`get_device()` 样本外
>
> 可控输入在进入样本外 `Environment` 前分别被 L73 `cmd_injection_check`、L139 `is_attack_pattern`+`is_md5`、L160/L185 `is_md5`、L247-L250 `is_number`、L294/L297/L320/L323 白名单处理
>
> 样本内可支持“未发现代码内可证漏洞”，但 `cmd_injection_check`、`is_attack_pattern`、`Environment.*`、`get_adb`、`get_device` 均为样本外，所以“安全语义在样本外不可证”成立
>
> L73 `cmd_injection_check(identifier)` → 样本外，无法在样本内判有效或伪防御
>
> L80 `docker_translate_localhost(identifier)` → 样本外，无法证明是否引入或消除污点
>
> `is_attack_pattern(comp)` 样本外，不能证明其覆盖全部危险模式
>
> L245 `shlex.quote(x)` → 依赖样本外 `env.adb_command` 的消费方式
>
> L247-L250 `is_number(x/y/max_x/max_y)` + L253-L254 `int(float(...))` → 样本外假设 `is_number` 严格
>

**代码块**
```python
# -*- coding: utf_8 -*-
"""Dynamic Analyzer Operations."""
import json
import logging
import os
import random
import shlex
import subprocess
import threading
from pathlib import Path

from django.conf import settings
from django.views.decorators.http import require_http_methods

from mobsf.DynamicAnalyzer.views.common.shared import (
    invalid_params,
    is_attack_pattern,
    send_response,
)
from mobsf.DynamicAnalyzer.views.android.environment import (
    Environment,
)
from mobsf.MobSF.utils import (
    cmd_injection_check,
    docker_translate_localhost,
    get_adb,
    get_device,
    is_md5,
    is_number,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    permission_required,
)

logger = logging.getLogger(__name__)


# Helpers

def get_package_name(checksum):
    """Get Package Name from DB or Device."""
    try:
        static_android_db = StaticAnalyzerAndroid.objects.get(
            MD5=checksum)
        return static_android_db.PACKAGE_NAME
    except Exception:
        pkg_file = Path(settings.DWD_DIR) / 'packages.json'
        if not pkg_file.exists():
            return None
        with pkg_file.open(encoding='utf-8') as src:
            packages = json.load(src)
        if packages.get(checksum):
            return packages[checksum][0]
        return None
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def mobsfy(request, api=False):
    """Configure Instance for Dynamic Analysis."""
    logger.info('MobSFying Android instance')
    data = {}
    msg = 'Connection failed'
    try:
        identifier = request.POST['identifier']
        if cmd_injection_check(identifier):
            # Additional Check, not required
            data = {
                'status': 'failed',
                'message': 'Command Injection Detected',
            }
            return send_response(data, api)
        identifier = docker_translate_localhost(identifier)
        create_env = Environment(identifier)
        if not create_env.connect_n_mount():
            data = {'status': 'failed', 'message': msg}
            return send_response(data, api)
        version = create_env.mobsfy_init()
        if not version:
            data = {'status': 'failed', 'message': msg}
            return send_response(data, api)
        else:
            data = {'status': 'ok', 'android_version': version}
…（截断）
```

---

## row 7650  ·  php  ·  JSON=False N/A  ·  risk=Low

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: line 483 realpath 将存在文件解析为符号链接无关的物理路径并与双向归一的受信集合（line 493-496）比较、line 501 拒绝残余 `..` 段、line 519 默认拒绝，路径信任防御链在读取路径上完整有效，残余面（不存在文件的字符串回退）在样本内无写汇聚点且读取必然失败；非 CWE-22（受限目录路径限制失效）因为 `..` 与符号链接均已在 line 483/501 被消解或拒绝且默认拒绝兜底；非 CWE-59（文件访问前链接解析不当）因为存在文件的符号链接被 realpath 解析为物理路径后只能匹配物理受信条目、任何逃逸必然落入 line 519。

**命中句**
> 本文件不直接打开文件或发起请求——受信判定通过后的实际 I/O 位于 Smarty 核心（样本外）
>
> b) “校验后写入”的调用方位于 Smarty 核心其他文件（样本外，显式标注样本外假设，不作为结论依据），本样本内不存在任何写汇聚点
>
> TOCTOU（line 483 校验与样本外后续打开之间置换符号链接，CWE-367 类）同样需要本地竞争攻击者——样本内无远程可达路径
>

**代码块**
```php
<?php
/**
 * Smarty plugin
 *


 * @author     Uwe Tews
 */

/**
 * FIXME: \Smarty\Security API
 *      - getter and setter instead of public properties would allow cultivating an internal cache properly
 *      - current implementation of isTrustedResourceDir() assumes that Smarty::$template_dir and Smarty::$config_dir
 *      are immutable the cache is killed every time either of the variables change. That means that two distinct
 *      Smarty objects with differing
 *        $template_dir or $config_dir should NOT share the same \Smarty\Security instance,
 *        as this would lead to (severe) performance penalty! how should this be handled?
 */

namespace Smarty;

use Smarty\Exception;

/**
 * This class does contain the security settings
 */
#[\AllowDynamicProperties]
class Security {

	/**
	 * This is the list of template directories that are considered secure.
	 * $template_dir is in this list implicitly.
	 *
	 * @var array
	 */
	public $secure_dir = [];

	/**
	 * List of regular expressions (PCRE) that include trusted URIs
	 *
	 * @var array
	 */
	public $trusted_uri = [];

	/**
	 * List of trusted constants names
	 *
	 * @var array
	 */
	public $trusted_constants = [];

	/**
	 * This is an array of trusted static classes.
	 * If empty access to all static classes is allowed.
	 * If set to 'none' none is allowed.
	 *
	 * @var array
	 */
	public $static_classes = [];

	/**
	 * This is an nested array of trusted classes and static methods.
	 * If empty access to all static classes and methods is allowed.
	 * Format:
	 * array (
	 *         'class_1' => array('method_1', 'method_2'), // allowed methods listed
	 *         'class_2' => array(),                       // all methods of class allowed
	 *       )
	 * If set to null none is allowed.
	 *
	 * @var array
	 */
	public $trusted_static_methods = [];

	/**
	 * This is an array of trusted static properties.
	 * If empty access to all static classes and properties is allowed.
	 * Format:
	 * array (
	 *         'class_1' => array('prop_1', 'prop_2'), // allowed properties listed
	 *         'class_2' => array(),                   // all properties of class allowed
	 *       )
	 * If set to null none is allowed.
	 *
	 * @var array
	 */
	public $trusted_static_properties = [];

	/**
	 * This is an array of allowed tags.
…（截断）
```

---

## row 7668  ·  go  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: 动作模板与管理员配置、文件标识均源自受控资产 -> 第 98-99 行剥<> 卫生过滤 -> 第 100-103 行 parse 失败即拒 -> 第 108-127 行占位符精确允许集替换且填充值为服务端构造的 fileSrc -> 第 133 行 Encode 重编码封住键逃逸 -> 第 48 行新增 InvalidFileNameHeader 提供无效文件名的标准化拒绝头；全文件无第二 URL 出口

**命中句**
> 它并非加密承诺——知道盐的持有方仍可还原——但配合上游 access_token 校验已足以让本文件的 URL 组装链条不含可预测性弱点
>
> 小回归集包括——模板含 javascript:/data:/ftp: 方案时的行为契约、WOPISrc 占位符缺失时的默认回退、queryReplaced.Encode 后键序稳定性、以及 InvalidFileNameHeader 常量被上游 handler 引用的协议合规用例
>

**代码块**
```go
package wopi

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/cloudreve/Cloudreve/v4/inventory/types"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/pkg/cluster/routes"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
)

var (
	ErrActionNotSupported = errors.New("action not supported by current wopi endpoint")

	queryPlaceholders = map[string]string{
		"BUSINESS_USER":           "",
		"DC_LLCC":                 "lng",
		"DISABLE_ASYNC":           "",
		"DISABLE_CHAT":            "",
		"EMBEDDED":                "true",
		"FULLSCREEN":              "true",
		"HOST_SESSION_ID":         "",
		"SESSION_CONTEXT":         "",
		"RECORDING":               "",
		"THEME_ID":                "darkmode",
		"UI_LLCC":                 "lng",
		"VALIDATOR_TEST_CATEGORY": "",
	}
)

const (
	SessionCachePrefix    = "wopi_session_"
	AccessTokenQuery      = "access_token"
	OverwriteHeader       = WopiHeaderPrefix + "Override"
	ServerErrorHeader     = WopiHeaderPrefix + "ServerError"
	RenameRequestHeader   = WopiHeaderPrefix + "RequestedName"
	LockTokenHeader       = WopiHeaderPrefix + "Lock"
	ItemVersionHeader     = WopiHeaderPrefix + "ItemVersion"
	SuggestedTargetHeader = WopiHeaderPrefix + "SuggestedTarget"
	InvalidFileNameHeader = WopiHeaderPrefix + "InvalidFileNameError"

	MethodLock           = "LOCK"
	MethodUnlock         = "UNLOCK"
	MethodRefreshLock    = "REFRESH_LOCK"
	MethodPutRelative    = "PUT_RELATIVE"
	wopiSrcPlaceholder   = "WOPI_SOURCE"
	wopiSrcParamDefault  = "WOPISrc"
	languageParamDefault = "lang"
	WopiHeaderPrefix     = "X-WOPI-"

	LockDuration = time.Duration(30) * time.Minute
)

func GenerateWopiSrc(ctx context.Context, action types.ViewerAction, viewer *types.Viewer, viewerSession *manager.ViewerSession) (*url.URL, error) {
	dep := dependency.FromContext(ctx)
	base := dep.SettingProvider().SiteURL(setting.UseFirstSiteUrl(ctx))
	hasher := dep.HashIDEncoder()

	availableActions, ok := viewer.WopiActions[viewerSession.File.Ext()]
	if !ok {
		return nil, ErrActionNotSupported
	}

	var (
		src string
	)
	fallbackOrder := []types.ViewerAction{action, types.ViewerActionView, types.ViewerActionEdit}
	for _, a := range fallbackOrder {
		if src, ok = availableActions[a]; ok {
			break
		}
	}

	if src == "" {
		return nil, ErrActionNotSupported
	}

	actionUrl, err := generateActionUrl(src,
		routes.MasterWopiSrc(base, hashid.EncodeFileID(hasher, viewerSession.File.ID())).String())
	if err != nil {
		return nil, err
	}
…（截断）
```

---

## row 7679  ·  go  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: SSL 分支唯一 tls.Config 以第 45 行 MinVersion=tls.VersionTLS12 作地板 -> 低于 1.2 的 ClientHello 被 Go 握手状态机强制终止 -> 1.2 起默认 AEAD+ECDHE 前向保密，BEAST/Lucky13 适用路径整体失效 -> 证书装载双分支异常即退出且空配置显式报错防止静默明文 -> 第 79 行挂载后由 startServer 派发，无第二 MinVersion 设置点

**命中句**
> 协议选择的克制减少了未知交互面，也与上游网关常见的终止 TLS 架构兼容
>

**代码块**
```go
//go:build !lambda
// +build !lambda

package router

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/appleboy/gorush/config"
	"github.com/appleboy/gorush/logx"

	"github.com/golang-queue/queue"
	"golang.org/x/sync/errgroup"
)

// RunHTTPServer provide run http or https protocol.
func RunHTTPServer(ctx context.Context, cfg *config.ConfYaml, q *queue.Queue, s ...*http.Server) (err error) {
	var server *http.Server

	if !cfg.Core.Enabled {
		logx.LogAccess.Info("httpd server is disabled.")
		return nil
	}

	if len(s) == 0 {
		//nolint:gosec
		server = &http.Server{
			Addr:    cfg.Core.Address + ":" + cfg.Core.Port,
			Handler: routerEngine(cfg, q),
		}
	} else {
		server = s[0]
	}

	logx.LogAccess.Info("HTTPD server is running on " + cfg.Core.Port + " port.")
	if cfg.Core.AutoTLS.Enabled {
		return startServer(ctx, autoTLSServer(cfg, q), cfg)
	} else if cfg.Core.SSL {
		config := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		if config.NextProtos == nil {
			config.NextProtos = []string{"http/1.1"}
		}

		config.Certificates = make([]tls.Certificate, 1)
		//nolint:gocritic
		if cfg.Core.CertPath != "" && cfg.Core.KeyPath != "" {
			config.Certificates[0], err = tls.LoadX509KeyPair(cfg.Core.CertPath, cfg.Core.KeyPath)
			if err != nil {
				logx.LogError.Error("Failed to load https cert file: ", err)
				return err
			}
		} else if cfg.Core.CertBase64 != "" && cfg.Core.KeyBase64 != "" {
			cert, err := base64.StdEncoding.DecodeString(cfg.Core.CertBase64)
			if err != nil {
				logx.LogError.Error("base64 decode error:", err.Error())
				return err
			}
			key, err := base64.StdEncoding.DecodeString(cfg.Core.KeyBase64)
			if err != nil {
				logx.LogError.Error("base64 decode error:", err.Error())
				return err
			}
			if config.Certificates[0], err = tls.X509KeyPair(cert, key); err != nil {
				logx.LogError.Error("tls key pair error:", err.Error())
				return err
			}
		} else {
			return errors.New("missing https cert config")
		}

		server.TLSConfig = config
	}

	return startServer(ctx, server, cfg)
}

func listenAndServe(ctx context.Context, s *http.Server, cfg *config.ConfYaml) error {
	var g errgroup.Group
	g.Go(func() error {
		<-ctx.Done()
		timeout := time.Duration(cfg.Core.ShutdownTimeout) * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
…（截断）
```

---

## row 7714  ·  python  ·  JSON=False none  ·  risk=None

- 承认词: ['可构造']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现可达污点流（针对 RCE），原因: line 176 file_path → line 192 except → line 194 `open("rb")` → line 195 `_RestrictedCookieUnpickler(f).load()` → line 67-74 `find_class` 是 unpickler 获取一切外部可调用对

**命中句**
> （样本外假设同 A：文件内容可控性取决于调用方
>
> - EXT1/EXT2/EXT4 扩展码：现代 CPython 未命中进程内缓存时仍回调 `find_class`（样本外假设：CPython≥3.8 行为
>
> 样本外假设：文件可控性
>
> 4. CRLF/头部注入：`_build_morsel`（B 中 L494-508 区域）coded_value 透传位与 A 同构，头部序列化层在样本外 → 不定罪
>
> 5. L159 `key = f"{domain}|{path}"` 复合键冲突：需 domain 含 `|`（即响应主机名含 `|`，yarl 主机校验在样本外），可构造性极弱，排除
>
> 可组合的仅有：文件可控（样本外）→ cookie 注入（载荷2）或崩溃（载荷3）
>

**代码块**
```python
import asyncio
import calendar
import contextlib
import datetime
import heapq
import itertools
import json
import os  # noqa
import pathlib
import pickle
import re
import time
import warnings
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping
from http.cookies import BaseCookie, Morsel, SimpleCookie
from typing import Union

from yarl import URL

from ._cookie_helpers import preserve_morsel_with_coded_value
from .abc import AbstractCookieJar, ClearCookiePredicate
from .helpers import is_ip_address
from .typedefs import LooseCookies, PathLike, StrOrURL

__all__ = ("CookieJar", "DummyCookieJar")


CookieItem = Union[str, "Morsel[str]"]

# We cache these string methods here as their use is in performance critical code.
_FORMAT_PATH = "{}/{}".format
_FORMAT_DOMAIN_REVERSED = "{1}.{0}".format

# The minimum number of scheduled cookie expirations before we start cleaning up
# the expiration heap. This is a performance optimization to avoid cleaning up the
# heap too often when there are only a few scheduled expirations.
_MIN_SCHEDULED_COOKIE_EXPIRATION = 100
_SIMPLE_COOKIE = SimpleCookie()


class _RestrictedCookieUnpickler(pickle.Unpickler):
    """A restricted unpickler that only allows cookie-related types.

    This prevents arbitrary code execution when loading pickled cookie data
    from untrusted sources. Only types that are expected in a serialized
    CookieJar are permitted.

    See: https://docs.python.org/3/library/pickle.html#restricting-globals
    """

    _ALLOWED_CLASSES: frozenset[tuple[str, str]] = frozenset(
        {
            # Core cookie types
            ("http.cookies", "SimpleCookie"),
            ("http.cookies", "Morsel"),
            # Container types used by CookieJar._cookies
            ("collections", "defaultdict"),
            # builtins that pickle uses for reconstruction
            ("builtins", "tuple"),
            ("builtins", "set"),
            ("builtins", "frozenset"),
            ("builtins", "dict"),
        }
    )

    def find_class(self, module: str, name: str) -> type:
        if (module, name) not in self._ALLOWED_CLASSES:
            raise pickle.UnpicklingError(
                f"Forbidden class: {module}.{name}. "
                "CookieJar.load() only allows cookie-related types for security. "
                "See https://docs.python.org/3/library/pickle.html#restricting-globals"
            )
        return super().find_class(module, name)  # type: ignore[no-any-return]


class CookieJar(AbstractCookieJar):
    """Implements cookie storage adhering to RFC 6265."""

    DATE_TOKENS_RE = re.compile(
        r"[\x09\x20-\x2F\x3B-\x40\x5B-\x60\x7B-\x7E]*"
        r"(?P<token>[\x00-\x08\x0A-\x1F\d:a-zA-Z\x7F-\xFF]+)"
    )

    DATE_HMS_TIME_RE = re.compile(r"(\d{1,2}):(\d{1,2}):(\d{1,2})")

    DATE_DAY_OF_MONTH_RE = re.compile(r"(\d{1,2})")

    DATE_MONTH_RE = re.compile(
        "(jan)|(feb)|(mar)|(apr)|(may)|(jun)|(jul)|(aug)|(sep)|(oct)|(nov)|(dec)",
…（截断）
```

---

## row 7775  ·  java  ·  JSON=False none  ·  risk=None

- 承认词: ['仍可被']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现可达污点流，原因: line 134 `releaseService.findReleaseById(Env.valueOf(env), releaseId)` → line 137-line 139 `release == null` 检查 → line 140-line 143 `userPermissionValidator.shouldHide

**命中句**
> L180 直接调用 `releaseService.compare` → 样本外假设: 若 `ReleaseService.compare` 内部没有对象级鉴权，则入口层完全放行
>
> 组合链: L131 的 `get` 已有权限检查，但 L175 `compareRelease` 仍可被用来直接比较任意两个 `releaseId`
>
> 样本外假设：用户已通过 `mycluster` 的 `@PreAuthorize`，且 `releaseService.publish` 按 `model.clusterName` 定位到 `othercluster`
>

**代码块**
```java
/*
 * Copyright 2024 Apollo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package com.ctrip.framework.apollo.portal.controller;

import com.ctrip.framework.apollo.common.dto.ReleaseDTO;
import com.ctrip.framework.apollo.common.exception.BadRequestException;
import com.ctrip.framework.apollo.common.exception.NotFoundException;
import com.ctrip.framework.apollo.portal.environment.Env;
import com.ctrip.framework.apollo.portal.component.UserPermissionValidator;
import com.ctrip.framework.apollo.portal.component.config.PortalConfig;
import com.ctrip.framework.apollo.portal.entity.bo.ReleaseBO;
import com.ctrip.framework.apollo.portal.entity.model.NamespaceReleaseModel;
import com.ctrip.framework.apollo.portal.entity.vo.ReleaseCompareResult;
import com.ctrip.framework.apollo.portal.listener.ConfigPublishEvent;
import com.ctrip.framework.apollo.portal.service.ReleaseService;
import com.ctrip.framework.apollo.portal.spi.UserInfoHolder;
import javax.validation.Valid;
import javax.validation.constraints.Positive;
import javax.validation.constraints.PositiveOrZero;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.List;

@Validated
@RestController
public class ReleaseController {

  private final ReleaseService releaseService;
  private final ApplicationEventPublisher publisher;
  private final PortalConfig portalConfig;
  private final UserPermissionValidator userPermissionValidator;
  private final UserInfoHolder userInfoHolder;

  public ReleaseController(
      final ReleaseService releaseService,
      final ApplicationEventPublisher publisher,
      final PortalConfig portalConfig,
      final UserPermissionValidator userPermissionValidator,
      final UserInfoHolder userInfoHolder) {
    this.releaseService = releaseService;
    this.publisher = publisher;
    this.portalConfig = portalConfig;
    this.userPermissionValidator = userPermissionValidator;
    this.userInfoHolder = userInfoHolder;
  }

  @PreAuthorize(value = "@userPermissionValidator.hasReleaseNamespacePermission(#appId, #env, #clusterName, #namespaceName)")
  @PostMapping(value = "/apps/{appId}/envs/{env}/clusters/{clusterName}/namespaces/{namespaceName}/releases")
  public ReleaseDTO createRelease(@PathVariable String appId,
                                  @PathVariable String env, @PathVariable String clusterName,
                                  @PathVariable String namespaceName, @RequestBody NamespaceReleaseModel model) {
    model.setAppId(appId);
    model.setEnv(env);
    model.setClusterName(clusterName);
    model.setNamespaceName(namespaceName);

    if (model.isEmergencyPublish() && !portalConfig.isEmergencyPublishAllowed(Env.valueOf(env))) {
      throw new BadRequestException("Env: %s is not supported emergency publish now", env);
    }

    ReleaseDTO createdRelease = releaseService.publish(model);

    ConfigPublishEvent event = ConfigPublishEvent.instance();
    event.withAppId(appId)
        .withCluster(clusterName)
…（截断）
```

---

## row 7779  ·  go  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: 已存在分支经第 82-90 行强制 sha256(request body)==oid 全等证明 -> 新建路径沿用 TempDir/TeeReader/ErrOIDMismatch/Rename 同一判据 -> 两种世界状态证据标准统一 -> Download 寻址规则一致且授权前置 -> 第二入口为零

**命中句**
> 其授权仍由上游 (repo_id, oid) 矩阵负责，而上诉矩阵此刻之所以有效，正是因为上传侧不再产生"内容与归属分离"的对象——存储层的干净输入让上层判定有了可信地基
>
> 23. **对错误码消费者的兼容性核查**：上游包装层只需认识两个哨兵值即可实现精确的错误映射
>

**代码块**
```go
package lfsx

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"github.com/cockroachdb/errors"

	"gogs.io/gogs/internal/osx"
)

var (
	ErrObjectNotExist = errors.New("object does not exist")
	ErrOIDMismatch    = errors.New("content hash does not match OID")
)

// Storager is an storage backend for uploading and downloading LFS objects.
type Storager interface {
	// Storage returns the name of the storage backend.
	Storage() Storage
	// Upload reads content from the io.ReadCloser and uploads as given oid.
	// The reader is closed once upload is finished. ErrInvalidOID is returned
	// if the given oid is not valid.
	Upload(oid OID, rc io.ReadCloser) (int64, error)
	// Download streams content of given oid to the io.Writer. It is caller's
	// responsibility the close the writer when needed. ErrObjectNotExist is
	// returned if the given oid does not exist.
	Download(oid OID, w io.Writer) error
}

// Storage is the storage type of an LFS object.
type Storage string

const (
	StorageLocal Storage = "local"
)

var _ Storager = (*LocalStorage)(nil)

// LocalStorage is a LFS storage backend on local file system.
type LocalStorage struct {
	// The root path for storing LFS objects.
	Root string
	// The path for storing temporary files during upload verification.
	TempDir string
}

func (*LocalStorage) Storage() Storage {
	return StorageLocal
}

func (s *LocalStorage) storagePath(oid OID) string {
	if len(oid) < 2 {
		return ""
	}

	return filepath.Join(s.Root, string(oid[0]), string(oid[1]), string(oid))
}

func (s *LocalStorage) Upload(oid OID, rc io.ReadCloser) (int64, error) {
	if !ValidOID(oid) {
		return 0, ErrInvalidOID
	}

	fpath := s.storagePath(oid)
	dir := filepath.Dir(fpath)

	defer rc.Close()

	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return 0, errors.Wrap(err, "create directories")
	}

	// If the object file already exists, the client must still prove it has
	// the original bytes by hashing the request body. Otherwise any caller
	// with write access to one repository could bind an OID owned by another
	// repository to their own and download the original content.
	if fi, err := os.Stat(fpath); err == nil {
		hash := sha256.New()
		if _, err := io.Copy(hash, rc); err != nil {
			return 0, errors.Wrap(err, "read request body")
		}
		if computed := hex.EncodeToString(hash.Sum(nil)); computed != string(oid) {
			return 0, ErrOIDMismatch
		}
		return fi.Size(), nil
	}
…（截断）
```

---

## row 7781  ·  javascript  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: 本文件零 child_process 引用 -> src 两类来源均受终端操作者主权覆盖（argv 自输入 / choices 由本工具写入的缓存 map.json 枚举）-> 非空目录强制 Overwrite 共识 -> mri 仅注册布尔开关不转发任意选项 -> 错误路径 fail-loud exit(1) -> 进程域风险归属上游库契约层治理并已在分析中划界

**命中句**
> 8. **对嵌入用法的责任划分声明**：当 run/exported 函数被第三方编排器以机器可读字符串驱动时，视为进入 degit 库的协议层契约——上游库自身的远端 URL 解析与子进程调用策略是正确的加固位
>
> 17. **供应链议题的正确隔离**：若忧虑上游库自身的完整性，对策是 lockfile 哈希冻结与制品来源校验，它们作用于另一个物料层
>
> 三种姿态叠合之后，即便上游库仍有历史包袱，CLI 层也已把普通用户的暴露概率压至背景噪声水平
>

**代码块**
```javascript
import fs from 'node:fs';
import path from 'node:path';
import chalk from 'chalk';
import mri from 'mri';
import glob from 'tiny-glob/sync.js';
import fuzzysearch from 'fuzzysearch';
import enquirer from 'enquirer';
import degit from './index.js';
import { base, tryRequire } from './utils.js';

/* eslint-disable security/detect-non-literal-fs-filename */
export async function main(argv) {
	const args = mri(argv.slice(2), {
		alias: {
			c: 'cache',
			f: 'force',
			m: 'mode',
			v: 'verbose',
		},
		boolean: ['force', 'cache', 'verbose'],
	});

	const [src, dest = '.'] = args._;

	if (args.help) {
		const help = fs
			.readFileSync(path.join(__dirname, '..', 'help.md'), 'utf8')
			.replaceAll(/^(\s*)#+ (.+)/gm, (m, s, _) => s + chalk.bold(_))
			.replaceAll(/_([^_]+)_/g, (m, _) => chalk.underline(_))
			.replaceAll(/`([^`]+)`/g, (m, _) => chalk.cyan(_));

		process.stdout.write(`\n${help}\n`);
	} else if (!src) {
		const accessLookup = new Map();

		glob(`**/access.json`, { cwd: base }).forEach((file) => {
			const [host, user, repo] = file.split(path.sep);

			const json = fs.readFileSync(`${base}/${file}`, 'utf8');
			const logs = JSON.parse(json);

			Object.entries(logs).forEach(([ref, timestamp]) => {
				const id = `${host}:${user}/${repo}#${ref}`;
				accessLookup.set(id, new Date(timestamp).getTime());
			});
		});

		const getChoice = (file) => {
			const [host, user, repo] = file.split(path.sep);

			return Object.entries(tryRequire(`${base}/${file}`)).map(([ref, hash]) => ({
				message: `${host}:${user}/${repo}#${ref}`,
				name: hash,
				value: `${host}:${user}/${repo}#${ref}`,
			}));
		};

		const choices = glob(`**/map.json`, { cwd: base })
			.map(getChoice)
			.flat()
			.toSorted((a, b) => {
				const aTime = accessLookup.get(a.value) || 0;
				const bTime = accessLookup.get(b.value) || 0;

				return bTime - aTime;
			});

		const options = await enquirer.prompt([
			{
				choices,
				message: 'Repo to clone?',
				name: 'src',
				suggest: (input, choices) =>
					choices.filter(({ value }) => fuzzysearch(input, value)),
				type: 'autocomplete',
			},
			{
				initial: '.',
				message: 'Destination directory?',
				name: 'dest',
				type: 'input',
			},
			{
				message: 'Use cached version?',
				name: 'cache',
				type: 'toggle',
			},
		]);

		const empty = !fs.existsSync(options.dest) || fs.readdirSync(options.dest).length === 0;
…（截断）
```

---

## row 7787  ·  go  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：line 175 `yaml.Unmarshal(buildContent, conf)` → line 272 `ebpfSourcePath: conf.EBPFSource` / line 273 `wasmSourcePath: conf.Wasm` → line 141 `"EBPFSOURCE="+options.ebpfSourcePath` 

**命中句**
> 样本外假设：这些变量是否最终变成命令执行依赖未贴出的 `helpers/Makefile.build` 是否展开 `$(EBPFSOURCE)`/`$(WASM)`/`$(BTFHUB_ARCHIVE)`
>
> 是否触发取决于样本外 Makefile
>
> 锚句: 非 CWE-78 直接成立因 `CFLAGS` 与环境 `CFLAGS` 入口已删除，剩余通道依赖样本外 Makefile
>

**代码块**
```go
// Copyright 2023 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package image

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/moby/moby/pkg/jsonmessage"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

//go:embed helpers
var helpersFS embed.FS

// It can be overridden at build time
var builderImage = "ghcr.io/inspektor-gadget/gadget-builder:main"

const (
	DEFAULT_EBPF_SOURCE = "program.bpf.c"
	DEFAULT_WASM        = "" // Wasm is optional; unset by default
	DEFAULT_METADATA    = "gadget.yaml"
)

type buildFile struct {
	EBPFSource string `yaml:"ebpfsource"`
	Wasm       string `yaml:"wasm"`
	Metadata   string `yaml:"metadata"`
}

type cmdOpts struct {
	path             string
	file             string
	fileChanged      bool
	image            string
	local            bool
	outputDir        string
	builderImage     string
	builderImagePull string
	updateMetadata   bool
	validateMetadata bool
	btfgen           bool
	btfhubarchive    string
}

func NewBuildCmd() *cobra.Command {
	opts := &cmdOpts{}

	cmd := &cobra.Command{
		Use:          "build PATH",
		Short:        "Build a gadget image",
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.local && opts.builderImage != builderImage {
				return fmt.Errorf("--local and --builder-image cannot be used at the same time")
			}
…（截断）
```

---

## row 7802  ·  python  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现可达污点流，原因: line 61 传入 `title/options`，经 line 71、line 110-112 到具体 `show_file`；Windows 分支 line 154-163 不再调用 line 147-152 的 `get_command`，而是 line 161 `os.startfile(path)`，`options/t

**命中句**
> 样本外理论 payload 同上，依赖外部直接消费 L147-152 且 `file` 可控，样本内不成立
>

**代码块**
```python
#
# The Python Imaging Library.
# $Id$
#
# im.show() drivers
#
# History:
# 2008-04-06 fl   Created
#
# Copyright (c) Secret Labs AB 2008.
#
# See the README file for information on usage and redistribution.
#
from __future__ import annotations

import abc
import os
import shutil
import subprocess
import sys
from shlex import quote
from typing import Any

from . import Image

_viewers: list[Viewer] = []


def register(viewer: type[Viewer] | Viewer, order: int = 1) -> None:
    """
    The :py:func:`register` function is used to register additional viewers::

        from PIL import ImageShow
        ImageShow.register(MyViewer())  # MyViewer will be used as a last resort
        ImageShow.register(MySecondViewer(), 0)  # MySecondViewer will be prioritised
        ImageShow.register(ImageShow.XVViewer(), 0)  # XVViewer will be prioritised

    :param viewer: The viewer to be registered.
    :param order:
        Zero or a negative integer to prepend this viewer to the list,
        a positive integer to append it.
    """
    if isinstance(viewer, type) and issubclass(viewer, Viewer):
        viewer = viewer()
    if order > 0:
        _viewers.append(viewer)
    else:
        _viewers.insert(0, viewer)


def show(image: Image.Image, title: str | None = None, **options: Any) -> bool:
    r"""
    Display a given image.

    :param image: An image object.
    :param title: Optional title. Not all viewers can display the title.
    :param \**options: Additional viewer options.
    :returns: ``True`` if a suitable viewer was found, ``False`` otherwise.
    """
    for viewer in _viewers:
        if viewer.show(image, title=title, **options):
            return True
    return False


class Viewer:
    """Base class for viewers."""

    # main api

    def show(self, image: Image.Image, **options: Any) -> int:
        """
        The main function for displaying an image.
        Converts the given image to the target format and displays it.
        """

        if not (
            image.mode in ("1", "RGBA")
            or (self.format == "PNG" and image.mode in ("I;16", "LA"))
        ):
            base = Image.getmodebase(image.mode)
            if image.mode != base:
                image = image.convert(base)

        return self.show_image(image, **options)

    # hook methods

    format: str | None = None
    """The format to convert the image into."""
…（截断）
```

---

## row 7825  ·  java  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现样本内可达污点流，原因: 样本内无模板/渲染 sink；`display_scope` 原始列表在 line 147 进入数据模型，但消费点不在样本内。若模板层未转义，则 line 120 `scopeNames.add(scope.getValue())` → line 147 `data.put("display_scope", scopeName

**命中句**
> Parameter("realm")`、L102 `getRequest().getClientInfo().getAcceptedLanguages()`、`consentRequired.getScopeDescriptions()`（样本外）
>
> 该判断依赖样本外模板
>
> 样本外
>
> 样本外模板未转义时才归 CWE-79
>

**代码块**
```java
/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2015-2016 ForgeRock AS.
 * Portions Copyrighted 2019 Open Source Solution Technology Corp.
 * Portions Copyrighted 2025-2026 3A Systems LLC.
 */
package org.forgerock.oauth2.restlet;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.oauth2.core.CsrfProtection;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.ResourceOwnerSessionValidator;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerConsentRequired;
import org.forgerock.openam.oauth2.OAuth2Utils;
import org.forgerock.openam.rest.service.RouterContextResource;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.xui.XUIState;
import org.owasp.esapi.ESAPI;
import org.restlet.data.Language;
import org.restlet.data.Preference;
import org.restlet.data.Reference;
import org.forgerock.openam.rest.jakarta.servlet.ServletUtils;
import org.restlet.routing.Router;

import static org.forgerock.json.JsonValue.*;

/**
 * Handles requests to the OAuth2 authorize endpoint that require consent from the user.
 *
 * @since 12.0.0
 */
public abstract class ConsentRequiredResource extends RouterContextResource {
    protected final XUIState xuiState;
    protected final BaseURLProviderFactory baseURLProviderFactory;
    private final ResourceOwnerSessionValidator resourceOwnerSessionValidator;
    private final CsrfProtection csrfProtection;

    public ConsentRequiredResource(Router router, BaseURLProviderFactory baseURLProviderFactory,
            XUIState xuiState, ResourceOwnerSessionValidator resourceOwnerSessionValidator,
            CsrfProtection csrfProtection) {
        super(router);
        this.baseURLProviderFactory = baseURLProviderFactory;
        this.xuiState = xuiState;
        this.resourceOwnerSessionValidator = resourceOwnerSessionValidator;
        this.csrfProtection = csrfProtection;
    }

    /**
     * Gets the data model to use when rendering the error page.
     *
     * @param consentRequired The details for requesting consent.
     * @param request The OAuth2 request.
     * @return The data model.
     */
    protected Map<String, Object> getDataModel(ResourceOwnerConsentRequired consentRequired, OAuth2Request request) {
        String displayName = consentRequired.getClientName();
        String displayDescription = consentRequired.getClientDescription();
        String userDisplayName = consentRequired.getUserDisplayName();
        Map<String, Object> data = new HashMap<>(getRequest().getAttributes());
        data.putAll(getQuery().getValuesMap());
        Reference resRef = getRequest().getResourceRef();
        String target = resRef.getPath();
        String query = resRef.getQuery();
        if (!StringUtils.isBlank(query)) {
            target = target + "?" + query;
        }
        data.put("target", target);
        data.put("display_name", ESAPI.encoder().encodeForHTML(displayName));
        data.put("display_description", ESAPI.encoder().encodeForHTML(displayDescription));
        addDisplayScopesAndClaims(consentRequired, data);
…（截断）
```

---

## row 7827  ·  python  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: 通读全文逐函数验证：所有文本类 sink（text/codespan/block_code/block_error 等）均经 escape_text 或 safe_entity 转义；link 与 image 的 url 经 safe_url 过滤，其黑名单基于 _unquote_url 三层解码加小写归一化后的 URL 匹配，可抵御编码与大小写绕过，data 白名单不含 svg；title/id/lang 属性均先实体化再拼接，无法闭合引号。inline_html 与 block_html 在默认 escape=True 下转义，escape=False 为文档明示的信任输入模式。list 的 start 依赖解析器整数约束，无可控注入面。未发现可利用漏洞。

**命中句**
> 即便传入字符串，其来源为解析器的有序列表起始号校验，非自由文本，且黑名单式担忧不成立——此处依赖上游类型约束，属低风险但值得注意的弱类型点
>

**代码块**
```python
from typing import Any, ClassVar, Dict, Optional, Tuple, Literal
from urllib.parse import unquote
from ..core import BaseRenderer, BlockState
from ..util import escape as escape_text
from ..util import safe_entity, striptags


class HTMLRenderer(BaseRenderer):
    """A renderer for converting Markdown to HTML."""

    _escape: bool
    NAME: ClassVar[Literal["html"]] = "html"
    HARMFUL_PROTOCOLS: ClassVar[Tuple[str, ...]] = (
        "javascript:",
        "vbscript:",
        "file:",
        "data:",
        "feed:",
        "jar:",
        "livescript:",
        "mocha:",
        "ms-its:",
        "mk:",
        "res:",
        "view-source:",
    )
    GOOD_DATA_PROTOCOLS: ClassVar[Tuple[str, ...]] = (
        "data:image/gif;",
        "data:image/png;",
        "data:image/jpeg;",
        "data:image/webp;",
    )

    def __init__(self, escape: bool = True, allow_harmful_protocols: Optional[bool] = None) -> None:
        super(HTMLRenderer, self).__init__()
        self._allow_harmful_protocols = allow_harmful_protocols
        self._escape = escape

    def render_token(self, token: Dict[str, Any], state: BlockState) -> str:
        # backward compitable with v2
        func = self._get_method(token["type"])
        attrs = token.get("attrs")

        if "raw" in token:
            text = token["raw"]
        elif "children" in token:
            text = self.render_tokens(token["children"], state)
        else:
            if attrs:
                return func(**attrs)
            else:
                return func()
        if attrs:
            return func(text, **attrs)
        else:
            return func(text)

    def safe_url(self, url: str) -> str:
        """Ensure the given URL is safe. This method is used for rendering
        links, images, and etc.
        """
        if self._allow_harmful_protocols is True:
            return escape_text(url)

        _url = _unquote_url(url).lower()
        if self._allow_harmful_protocols and _url.startswith(tuple(self._allow_harmful_protocols)):
            return escape_text(url)

        if _url.startswith(self.HARMFUL_PROTOCOLS) and not _url.startswith(self.GOOD_DATA_PROTOCOLS):
            return "#harmful-link"
        return escape_text(url)

    def text(self, text: str) -> str:
        if self._escape:
            return escape_text(text)
        return safe_entity(text)

    def emphasis(self, text: str) -> str:
        return "<em>" + text + "</em>"

    def strong(self, text: str) -> str:
        return "<strong>" + text + "</strong>"

    def link(self, text: str, url: str, title: Optional[str] = None) -> str:
        s = '<a href="' + self.safe_url(url) + '"'
        if title:
            s += ' title="' + safe_entity(title) + '"'
        return s + ">" + text + "</a>"

    def image(self, text: str, url: str, title: Optional[str] = None) -> str:
…（截断）
```

---

## row 7829  ·  php  ·  JSON=False none  ·  risk=None

- 承认词: ['可注入']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现可达污点流，原因: line 474 `string_html_specialchars( config_get_global( 'path' ) )`、line 483 `string_html_specialchars( $t_attachment['download_url'] )`、line 486 `string_html_specialch

**命中句**
> 入口: L472 DB 回读 附件元数据 `$t_attachment['alt']`（样本外假设：附件上传/编辑者可写入 alt） | 次要: L77 HTTP GET `type_page`
>

**代码块**
```php
<?php
# MantisBT - A PHP based bugtracking system

# MantisBT is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# MantisBT is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MantisBT.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Word 2000 export page
 * The bugs displayed in print_all_bug_page.php are saved in a .doc file
 * The IE icon allows to see or directly print the same result
 *
 * @package MantisBT
 * @copyright Copyright 2000 - 2002  Kenzaburo Ito - kenito@300baud.org
 * @copyright Copyright 2002  MantisBT Team - mantisbt-dev@lists.sourceforge.net
 * @link http://www.mantisbt.org
 *
 * @uses core.php
 * @uses access_api.php
 * @uses authentication_api.php
 * @uses bug_api.php
 * @uses bugnote_api.php
 * @uses category_api.php
 * @uses config_api.php
 * @uses constant_inc.php
 * @uses custom_field_api.php
 * @uses date_api.php
 * @uses file_api.php
 * @uses filter_api.php
 * @uses gpc_api.php
 * @uses helper_api.php
 * @uses html_api.php
 * @uses http_api.php
 * @uses lang_api.php
 * @uses prepare_api.php
 * @uses print_api.php
 * @uses profile_api.php
 * @uses project_api.php
 * @uses string_api.php
 */

require_once( 'core.php' );
require_api( 'access_api.php' );
require_api( 'authentication_api.php' );
require_api( 'bug_api.php' );
require_api( 'bugnote_api.php' );
require_api( 'category_api.php' );
require_api( 'config_api.php' );
require_api( 'constant_inc.php' );
require_api( 'custom_field_api.php' );
require_api( 'date_api.php' );
require_api( 'file_api.php' );
require_api( 'filter_api.php' );
require_api( 'gpc_api.php' );
require_api( 'helper_api.php' );
require_api( 'html_api.php' );
require_api( 'http_api.php' );
require_api( 'lang_api.php' );
require_api( 'prepare_api.php' );
require_api( 'print_api.php' );
require_api( 'profile_api.php' );
require_api( 'project_api.php' );
require_api( 'string_api.php' );

auth_ensure_user_authenticated();
access_ensure_project_level( config_get( 'print_reports_threshold' ) );

$f_type_page	= gpc_get_string( 'type_page', 'word' );
$f_search		= gpc_get_string( 'search', false ); # @todo need a better default
$f_offset		= gpc_get_int( 'offset', 0 );
$f_export		= gpc_get_string( 'export' );
$f_show_flag	= gpc_get_bool( 'show_flag' );

helper_begin_long_process();

# word or html export
if( $f_type_page != 'html' ) {
	$t_export_title = helper_get_default_export_filename( '' );
	$t_export_title = preg_replace( '/[\/:*?"<>|]/', '', $t_export_title );
	$t_export_title .= '.doc';

…（截断）
```

---

## row 7831  ·  php  ·  JSON=False none  ·  risk=None

- 承认词: ['可构造']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现可达污点流，原因: line 184 仅把 `risky_inline_render` 传给样本外 FormType，本文件内没有消费该选项的渲染分支；line 56 `getFilePath()` 结果经 line 58 `setFormattedValue()` 交给样本外模板，本文件内无危险 sink；line 95 `writeStream()

**命中句**
> 链: 未发现可达污点流，原因: L184 仅把 `risky_inline_render` 传给样本外 FormType，本文件内没有消费该选项的渲染分支
>
> L56 `getFilePath()` 结果经 L58 `setFormattedValue()` 交给样本外模板，本文件内无危险 sink
>
> L95 `writeStream()` 的 `$fileName` 来源与 L115 `upload_validate` 调用方在样本外
>
> 是否有效取决于样本外 FileType 默认值与模板是否对内联渲染做 MIME 白名单、转义或强制附件下载
>
> 若样本外 `$fileName` 可控且适配器未规范化，可能影响写入路径，样本内不可证
>
> 样本外假设：若 FormType 消费 L184 且 `risky_inline_render=true`，同时允许上传含脚本 SVG/HTML 并在同源内联渲染，则管理员查看时可触发存储型 XSS
>
> 组合链: 样本外假设链：L184 开启内联渲染 → 攻击者上传含脚本 SVG → 样本外模板同源内联输出 → CWE-79
>
> 非 CWE-22 因 路径规范化/调用方在样本外
>

**代码块**
```php
<?php

namespace EasyCorp\Bundle\EasyAdminBundle\Field\Configurator;

use EasyCorp\Bundle\EasyAdminBundle\Config\Crud;
use EasyCorp\Bundle\EasyAdminBundle\Context\AdminContext;
use EasyCorp\Bundle\EasyAdminBundle\Contracts\Field\FieldConfiguratorInterface;
use EasyCorp\Bundle\EasyAdminBundle\Dto\EntityDto;
use EasyCorp\Bundle\EasyAdminBundle\Dto\FieldDto;
use EasyCorp\Bundle\EasyAdminBundle\Field\FileField;
use EasyCorp\Bundle\EasyAdminBundle\Form\Type\Model\FlysystemFile;
use League\Flysystem\FilesystemOperator;
use League\Flysystem\UnableToGeneratePublicUrl;
use Psr\Container\ContainerInterface;
use Symfony\Component\HttpFoundation\File\File;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\Mime\MimeTypes;
use Symfony\Component\Validator\Constraints\File as FileConstraint;
use function Symfony\Component\String\u;

/**
 * @author Javier Eguiluz <javier.eguiluz@gmail.com>
 */
final readonly class FileConfigurator implements FieldConfiguratorInterface
{
    public function __construct(
        private string $projectDir,
        private ?ContainerInterface $flysystemLocator = null,
    ) {
    }

    public function supports(FieldDto $field, EntityDto $entityDto): bool
    {
        return FileField::class === $field->getFieldFqcn();
    }

    public function configure(FieldDto $field, EntityDto $entityDto, AdminContext $context): void
    {
        $flysystemStorageName = $field->getCustomOption(FileField::OPTION_FLYSYSTEM_STORAGE);
        $flysystemUrlPrefix = $field->getCustomOption(FileField::OPTION_FLYSYSTEM_URL_PREFIX);
        $filesystem = null;

        if (null !== $flysystemStorageName) {
            $filesystem = $this->resolveFlysystemStorage($flysystemStorageName);
        }

        $configuredBasePath = $field->getCustomOption(FileField::OPTION_BASE_PATH);

        if (null !== $filesystem) {
            $formattedValue = \is_array($field->getValue())
                ? $this->getFlysystemFilesPaths($field->getValue(), $filesystem, $flysystemUrlPrefix, $field->getProperty())
                : $this->getFlysystemFilePath($field->getValue(), $filesystem, $flysystemUrlPrefix, $field->getProperty());
        } else {
            $formattedValue = \is_array($field->getValue())
                ? $this->getFilesPaths($field->getValue(), $configuredBasePath)
                : $this->getFilePath($field->getValue(), $configuredBasePath);
        }
        $field->setFormattedValue($formattedValue);

        $pattern = $field->getCustomOption(FileField::OPTION_UPLOADED_FILE_NAME_PATTERN);

        if (\is_callable($pattern)) {
            $entityInstance = $entityDto->getInstance();
            $originalCallback = $pattern;
            $pattern = static function (UploadedFile $file) use ($originalCallback, $entityInstance) {
                return $originalCallback($file, $entityInstance);
            };
        }

        $field->setFormTypeOption('upload_filename', $pattern);

        // this check is needed to avoid displaying broken links when file properties are optional
        if (null === $formattedValue || '' === $formattedValue || (\is_array($formattedValue) && 0 === \count($formattedValue)) || $formattedValue === rtrim($configuredBasePath ?? '', '/')) {
            $field->setTemplateName('label/empty');
        }

        if (!\in_array($context->getCrud()->getCurrentPage(), [Crud::PAGE_EDIT, Crud::PAGE_NEW], true)) {
            return;
        }

        $relativeUploadDir = $field->getCustomOption(FileField::OPTION_UPLOAD_DIR);
        if (null === $relativeUploadDir) {
            throw new \InvalidArgumentException(sprintf('The "%s" file field must define the directory where the files are uploaded using the setUploadDir() method.', $field->getProperty()));
        }

        if (null !== $filesystem) {
            // For Flysystem, use the upload dir as-is (it's a Flysystem path, not a local path)
            $relativeUploadDir = u($relativeUploadDir)->trimStart('/')->ensureEnd('/')->toString();
            $field->setFormTypeOption('upload_dir', $relativeUploadDir);
            $field->setFormTypeOption('flysystem_storage', $filesystem);
…（截断）
```

---

## row 7835  ·  javascript  ·  JSON=False none  ·  risk=None

- 承认词: ['可被绕过']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现可达污点流，原因: `simple` 仅在 line 188 `if (simple === false)` 选择返回形态；line 189 `JSON.parse(JSON.stringify(defaultOptions))` 深拷贝常量对象；line 192-line 194 遍历常量 `defaultOptions` 并把 `defaultVa

**命中句**
> `safeMode` 在本样本内没有消费点，因此也没有可被绕过的代码内黑名单
>
> 若样本外渲染器消费 `safeMode=false` 且未另设 sanitizer，则 `<img src=x onerror=alert(1)>` 或 `[x](javascript:alert(1))` 可能触发 XSS，但该跳样本外，不能支撑本样本 `存在漏洞=true`
>
> 非 CWE-1188 因 `safeMode` 默认关闭的实际影响悬在样本外消费点，代码内不可证
>

**代码块**
```javascript
// noinspection HtmlRequiredLangAttribute

/**
 * Created by Tivie on 13-07-2015.
 */

// eslint-disable-next-line no-unused-vars -- called from sibling src files via the shared concat scope (see scripts/concat.mjs)
function getDefaultOpts (simple) {
  'use strict';

  let defaultOptions = {
    omitExtraWLInCodeBlocks: {
      defaultValue: false,
      describe: 'Omit the default extra whiteline added to code blocks',
      type: 'boolean'
    },
    noHeaderId: {
      defaultValue: false,
      describe: 'Turn on/off generated header id',
      type: 'boolean'
    },
    prefixHeaderId: {
      defaultValue: false,
      describe: 'Add a prefix to the generated header ids. Passing a string will prefix that string to the header id. Setting to true will add a generic \'section-\' prefix',
      type: 'string'
    },
    rawHeaderId: {
      defaultValue: false,
      describe: 'Remove only spaces, \', ", > and < from generated header ids (including any prefix), replacing them with dashes (-), instead of the default github-compatible sanitization. WARNING: This might result in malformed ids',
      type: 'boolean'
    },
    headerLevelStart: {
      defaultValue: 1,
      describe: 'The header blocks level start',
      type: 'number'
    },
    parseImgDimensions: {
      defaultValue: false,
      describe: 'Turn on/off image dimension parsing',
      type: 'boolean'
    },
    simplifiedAutoLink: {
      defaultValue: false,
      describe: 'Turn on/off GFM autolink style',
      type: 'boolean'
    },
    httpsAutoLinks: {
      defaultValue: false,
      describe: 'Use \'https://\' for auto-generated links',
      type: 'boolean'
    },
    literalMidWordUnderscores: {
      defaultValue: false,
      describe: 'Parse midword underscores as literal underscores',
      type: 'boolean'
    },
    strikethrough: {
      defaultValue: true,
      describe: 'Turn on/off strikethrough support',
      type: 'boolean'
    },
    tables: {
      defaultValue: false,
      describe: 'Turn on/off tables support',
      type: 'boolean'
    },
    tablesHeaderId: {
      defaultValue: false,
      describe: 'Add an id to table headers',
      type: 'boolean'
    },
    ghCodeBlocks: {
      defaultValue: true,
      describe: 'Turn on/off GFM fenced code blocks support',
      type: 'boolean'
    },
    tasklists: {
      defaultValue: false,
      describe: 'Turn on/off GFM tasklist support',
      type: 'boolean'
    },
    footnotes: {
      defaultValue: false,
      describe: 'Turn on/off GFM footnotes support',
      type: 'boolean'
    },
    smartIndentationFix: {
      defaultValue: false,
      describe: 'Tries to smartly fix indentation in es6 strings',
      type: 'boolean'
…（截断）
```

---

## row 7846  ·  php  ·  JSON=False none  ·  risk=None

- 承认词: ['可注入']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现可达污点流，原因: 样本内只有 line 74/line 131 两个调用点；line 74 的 `$keyword` 经 line 78 `urlencode`、`$results_count` 经 line 77 `intval`；line 131 的 `$twitter_handle` 在 line 137 未编码，但样本内无调用方传入不可信数据

**命中句**
> 入口: L131 函数参数 `$twitter_handle`（内部 API 传参，样本外调用方） | 次要: L74 函数参数 `$keyword`，已由 L78 `urlencode`
>
> L5 `$url`/`$getfield` 参数样本外调用方
>
> 若样本外调用方直接传用户输入，则 L137 可注入额外查询参数，但样本外假设不支撑 true
>
> 若样本外调用方传入 `$twitter_handle = "foo&include_rts=true"`，L137 会拼出 `...&screen_name=foo&include_rts=true`，影响限于固定 Twitter API 端点
>

**代码块**
```php
<?php

require_once(__DIR__ . DS . 'TwitterAPIExchange.php');

function twitter_feed_perform_api_request($url = 'https://api.twitter.com/1.1/search/tweets.json', $getfield = false) {


    $oauth_access_token = get_option('access_token', 'twitter_feed');
    $oauth_access_token_secret = get_option('access_token_secret', 'twitter_feed');
    $consumer_key = get_option('consumer_key', 'twitter_feed');
    $consumer_secret = get_option('consumer_secret', 'twitter_feed');


    if ($oauth_access_token==false){
        $oauth_access_token = "";
    }

    if ($oauth_access_token_secret==false){
        $oauth_access_token_secret = "";
    }

    if ($consumer_key==false){
        $consumer_key = "";
    }


    if ($consumer_secret==false){
        $consumer_secret = "";
    }


    if (!$oauth_access_token || !$oauth_access_token_secret || !$consumer_key || !$consumer_secret){
        return false;
    }


    $cache_expiration_minutes = 1500;
    $cache_id = md5($url . $getfield);
    $cache_group = 'twitter_feed_2';
    $cached_results = cache_get($cache_id, $cache_group,$cache_expiration_minutes);
    if ($cached_results!=false){
        return $cached_results;
    }

    $settings = array(
        'oauth_access_token'        => $oauth_access_token,
        'oauth_access_token_secret' => $oauth_access_token_secret,
        'consumer_key'              => $consumer_key,
        'consumer_secret'           => $consumer_secret
    );

    $requestMethod = 'GET';

    $twitter = new TwitterAPIExchange($settings);
    $response = $twitter->setGetfield($getfield)
        ->buildOauth($url, $requestMethod)
        ->performRequest();


    $return = json_decode($response, true);



    if (!empty($return)){
        cache_save($return, $cache_id, $cache_group, $cache_expiration_minutes);
    }




    return $return;
}

function twitter_feed_get_items($keyword = false, $results_count = 5) {


    $count = intval($results_count);
    $query = urlencode($keyword);
    $url = 'https://api.twitter.com/1.1/search/tweets.json';
    $getfield = '?count=' . $count . '&q=' . $query;
    $items = twitter_feed_perform_api_request($url, $getfield);
    $return = array();
    if (isset($items['statuses'])){
        foreach ($items['statuses'] as $status => $statusData) {
            $tweet = array();
            $tweet['url'] = false;
            $tweet['media'] = false;
            $tweet['name'] = false;
            $tweet['profile_image'] = false;
            $tweet['screen_name'] = false;
…（截断）
```

---

## row 7849  ·  php  ·  JSON=False none  ·  risk=None

- 承认词: ['可注入']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现可达污点流，原因: `install()` 无外部输入，line 58 密码来自 `$this->instance->seed()`；line 115 到 `Instance::backup` 的 sink 样本外，样本内无危险操作。 组合链: 无样本内可证组合链。

**命中句**
> L115 到 `Instance::backup` 的 sink 样本外，样本内无危险操作
>
> 随机性依赖 `seed()`，样本外
>
> L115 无样本内校验 → 样本外: 需补 `Instance::backup` 实现才能判断备份路径是否可注入
>
> 若 `Instance::backup` 未校验 L115 参数，则 CLI 可传路径，但该 sink 样本外）
>
> 非 CWE-22 因 L115 sink 样本外未证
>

**代码块**
```php
<?php defined('BASEPATH') or exit('No direct script access allowed');

/* ----------------------------------------------------------------------------
 * Easy!Appointments - Online Appointment Scheduler
 *
 * @package     EasyAppointments
 * @author      A.Tselegidis <alextselegidis@gmail.com>
 * @copyright   Copyright (c) Alex Tselegidis
 * @license     https://opensource.org/licenses/GPL-3.0 - GPLv3
 * @link        https://easyappointments.org
 * @since       v1.3.2
 * ---------------------------------------------------------------------------- */

require_once __DIR__ . '/Google.php';

/**
 * Console controller.
 *
 * Handles all the Console related operations.
 */
class Console extends EA_Controller {
    /**
     * Console constructor.
     */
    public function __construct()
    {
        if ( ! is_cli())
        {
            exit('No direct script access allowed');
        }

        parent::__construct();

        $this->load->dbutil();

        $this->load->library('instance');

        $this->load->model('admins_model');
        $this->load->model('customers_model');
        $this->load->model('providers_model');
        $this->load->model('services_model');
        $this->load->model('settings_model');
    }

    /**
     * Perform a console installation.
     *
     * Use this method to install Easy!Appointments directly from the terminal.
     *
     * Usage:
     *
     * php index.php console install
     */
    public function install()
    {
        $this->instance->migrate('fresh');

        $password = $this->instance->seed();

        response(PHP_EOL . '⇾ Installation completed, login with "administrator" / "' . $password . '".' . PHP_EOL . PHP_EOL);
    }

    /**
     * Migrate the database to the latest state.
     *
     * Use this method to upgrade an Easy!Appointments instance to the latest database state.
     *
     * Notice:
     *
     * Do not use this method to install the app as it will not seed the database with the initial entries (admin,
     * provider, service, settings etc).
     *
     * Usage:
     *
     * php index.php console migrate
     *
     * php index.php console migrate fresh
     *
     * @param string $type
     */
    public function migrate(string $type = '')
    {
        $this->instance->migrate($type);
    }

    /**
     * Seed the database with test data.
     *
     * Use this method to add test data to your database
     *
…（截断）
```

---

## row 7908  ·  python  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：污点流在样本内仍可达且与 A 同构: line 262 store 回读 → line 298 载入列表 → line 301 `submit(...)` → line 280 调 `_send_webhook_request` → line 159 `_validate_webhook_url(webhook.url)` 一次性预检 → line 195 

**命中句**
> 注册源头为样本外 webhook 注册 API） | 次要: L329 内部API传参 `test_webhook(webhook, ...)`
>
> 但封死重定向/DNS 重绑定两个向量的决定性证据（adapter 的连接时校验实现）在样本外，无法核验
>
> L159 `_validate_webhook_url(webhook.url)` → 部分有效: 作为纵深第一层封死直接注册内网 URL 字面量的路径（样本外假设: 其实现至少拒绝环回/私网 IP 字面量与非法 scheme
>
> L94 `adapter = SSRFProtectedHTTPAdapter(max_retries=retry_strategy)` + L99-100 双 scheme 挂载 → 样本外假设（未验证）: 类来自 L42 `from mlflow.webhooks.ssrf import SSRFProtectedHTTPAdapter`，该模块未随样本提供
>

**代码块**
```python
"""Webhook delivery implementation following Standard Webhooks conventions.

This module implements webhook delivery patterns similar to the Standard Webhooks
specification (https://www.standardwebhooks.com), providing consistent and secure
webhook delivery with HMAC signature verification and timestamp-based replay protection.
"""

import base64
import hashlib
import hmac
import json
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests
import urllib3
from cachetools import TTLCache
from packaging.version import Version
from urllib3.util.retry import Retry

from mlflow.entities.webhook import Webhook, WebhookEvent, WebhookTestResult
from mlflow.environment_variables import (
    MLFLOW_ENABLE_WORKSPACES,
    MLFLOW_WEBHOOK_CACHE_TTL,
    MLFLOW_WEBHOOK_DELIVERY_MAX_WORKERS,
    MLFLOW_WEBHOOK_REQUEST_MAX_RETRIES,
    MLFLOW_WEBHOOK_REQUEST_TIMEOUT,
)
from mlflow.store.model_registry.abstract_store import AbstractStore
from mlflow.store.model_registry.file_store import FileStore
from mlflow.utils.validation import _validate_webhook_url
from mlflow.webhooks.constants import (
    WEBHOOK_DELIVERY_ID_HEADER,
    WEBHOOK_SIGNATURE_HEADER,
    WEBHOOK_SIGNATURE_VERSION,
    WEBHOOK_TIMESTAMP_HEADER,
)
from mlflow.webhooks.ssrf import SSRFProtectedHTTPAdapter
from mlflow.webhooks.types import (
    WebhookPayload,
    get_example_payload_for_event,
)

_logger = logging.getLogger(__name__)

# Thread pool for non-blocking webhook delivery
_webhook_delivery_executor = ThreadPoolExecutor(
    max_workers=MLFLOW_WEBHOOK_DELIVERY_MAX_WORKERS.get(),
    thread_name_prefix="webhook-delivery",
)

# Shared session for webhook requests (thread-safe)
_webhook_session: requests.Session | None = None
_webhook_session_lock: threading.Lock = threading.Lock()

# Cache for webhook listings by event
# TTLCache is thread-safe for basic operations, but we still use a lock for
# complex operations to ensure consistency
_webhook_cache_lock: threading.Lock = threading.Lock()
_webhook_cache: TTLCache[WebhookEvent, list[Webhook]] | None = None


def _create_webhook_session() -> requests.Session:
    """Create a new webhook session with retry configuration.

    Returns:
        Configured requests.Session object
    """
    max_retries = MLFLOW_WEBHOOK_REQUEST_MAX_RETRIES.get()

    # urllib3 >= 2.0 supports additional features
    extra_kwargs = {}
    if Version(urllib3.__version__) >= Version("2.0"):
        extra_kwargs["backoff_jitter"] = 1.0  # Add up to 1 second of jitter

    retry_strategy = Retry(
        total=max_retries,
        status_forcelist=[429, 500, 502, 503, 504],  # Retry on these status codes
        allowed_methods=["POST"],  # Only retry POST requests
        backoff_factor=1.0,  # Exponential backoff: 1s, 2s, 4s, etc.
        backoff_max=60.0,  # Cap maximum backoff at 60 seconds
        respect_retry_after_header=True,  # Automatically handle Retry-After headers
        raise_on_status=False,  # Don't raise on these status codes
        **extra_kwargs,
    )

…（截断）
```

---

## row 7910  ·  python  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现可达污点流，原因： sink 前防御封死——样本内输入可达的全部目的地判定位（line 156-160 scheme 门、line 175-184 字面量集、line 125+line 145-146 归一化、line 226-234 Tier-1、line 254-262 Tier-2）逐载荷核验闭合（见防御栏、载荷栏）；本文件自身不含取回/写盘 s

**命中句**
> 入口： L99 内部API传参 `validate_url(url)`（取回管线的安全门，`url` 溯源自 OSCAL href/CLI，调用点样本外）| 次要： L44 环境变量 `TRESTLE_BLOCK_PRIVATE_IPS`
>
> L328 `'..' in url_path` → 部分有效（原始字面全拒）+ 伪防御面：`%2e%2e%2f` 无 `..` 字面通过——成害与否取决于调用方解码时机（样本外）
>
> 残留-1（样本外假设）： L202 校验用解析与取回时的二次解析是两次独立查询，L104-105 自述仅“缩小”TOCTOU 窗口——DNS 重绑定（TTL=0 交替应答）或取回器跟随 30x 重定向至 `169.254.169.254` 均可在校验后改道（CWE-367 / 918 形态）
>
> 样本外候选（待调用方代码证实后才升级）：DNS 重绑定/重定向（残留-1）→ 取回至 169.254.169.254 → 响应体按 URL path 落缓存且调用方漏调 L356-361 时 `%2e%2e%2f` 逃逸写——两跳均样本外，仅登记
>
> 锚句： 非 CWE-918 因 样本内全部目的地判定位经载荷逐一验证闭合（L125/L145-146/L184/L234/L262），重绑定与重定向形态依赖样本外取回器、按规则不单独支撑 true
>
> - 消除重绑定窗口需调用方配合：让 `validate_url` 向上返回 `_resolve_hostname`（L199-210）已验证的 IP 集、取回时锁定该 IP 连接，或取回器禁用重定向跟随并在每跳重跑 L99（改动点在样本外取回器）
>

**代码块**
```python
# -*- mode:python; coding:utf-8 -*-

# Copyright (c) 2026 The OSCAL Compass Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Security validation utilities for remote fetching operations.

This module provides security controls to prevent SSRF, path traversal,
and arbitrary file access vulnerabilities.
"""

import ipaddress
import logging
import os
import pathlib
import socket
from typing import Optional, Set
from urllib import parse

from trestle.common.err import TrestleError


def get_block_private_ips_config() -> bool:
    """Get the TRESTLE_BLOCK_PRIVATE_IPS configuration from environment.

    Returns:
        True if private IPs should be blocked, False otherwise (default).

    The environment variable can be set to:
    - 'true', '1', 'yes', 'on' (case-insensitive) to enable blocking
    - Any other value or unset to disable blocking (allow private IPs)
    """
    env_value = os.environ.get('TRESTLE_BLOCK_PRIVATE_IPS', '').lower()
    return env_value in ('true', '1', 'yes', 'on')


logger = logging.getLogger(__name__)

# Always blocked - zero legitimate use for OSCAL fetching
# These ranges are blocked regardless of configuration
ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),  # IPv4 loopback
    ipaddress.ip_network('::1/128'),  # IPv6 loopback
    ipaddress.ip_network('169.254.0.0/16'),  # IPv4 link-local (includes metadata endpoints)
    ipaddress.ip_network('fe80::/10'),  # IPv6 link-local
    ipaddress.ip_network('0.0.0.0/8'),  # IPv4 "this network", reaches localhost on Linux
    ipaddress.ip_network('::/128'),  # IPv6 unspecified address
]

# RFC 1918 private ranges - optionally blocked based on configuration
# These are allowed by default to support private GitLab/internal OSCAL repositories
PRIVATE_IP_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('fc00::/7'),  # IPv6 unique local
]

# Cloud metadata endpoints that should be blocked
# These are always blocked regardless of configuration
METADATA_HOSTNAMES = {
    '169.254.169.254',  # AWS, Azure, GCP
    'metadata.google.internal',  # GCP
    'metadata.azure.com',  # Azure (alternative)
    '100.100.100.200',  # Alibaba Cloud
}


class URLSecurityValidator:
    """Validates URLs to prevent SSRF attacks.

    Implements two-tiered SSRF protection:
    1. Always blocked: loopback, link-local, and cloud metadata endpoints
    2. Optionally blocked: RFC 1918 private ranges (configurable via block_private_ips)
    """

    def __init__(self, block_private_ips: bool = False, allowed_domains: Optional[Set[str]] = None):
        """Initialize URL security validator.

…（截断）
```

---

## row 7957  ·  python  ·  JSON=False none  ·  risk=None

- 承认词: ['会被执行', '可构造', '可注入', '成立']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现可达污点流，原因: line 22/line 23/line 44/line 51 为 `__CODE__/__MINUTES__/__DENIAL_REASON__/__DOWNLOAD_LINK__/__DAYS__` 惰性字面占位符，不含 `{{ }}`/`{% %}` 求值语法；经 line 112-line 114/line 124-line

**命中句**
> 入口: L105 `data`（内部 API 传参通道 · create，写方端点样本外）| 次要: L120 `data`（update）
>
> 经 L112-L114/L124-L125 落库 L90 后由样本外的逐键 `str.replace` 消费——替换不是求值，`content` 里写 `{{7*7}}` 只会原样留在邮件文本里 → 不产生代码执行
>
> L22/L23/L44/L51 占位符形态 `__X__` → 有效**仅在样本外消费方为 `str.replace` 时**：无模板解析器参与，`__CODE__` 无求值语义
>
> 但这层来自样本外消费方，不是来自本文件
>
> 在 B 的代码里写入 `{{ ''.__class__.__mro__ }}` 不会被执行
>
> 只有当样本外渲染点仍是 A 时代的 `Environment().from_string().render()` 时，B 与 A 等价可打，载荷同版本 A 栏
>
> 因此**在这 129 行内，A 与 B 的安全性不可区分**——把 B 判"安全"要先知道样本外消费方已从 Jinja 换成 `str.replace`
>
> 把 A 判"有洞"同样要先看到样本外渲染点
>
> 这正是"样本外假设不得单独支撑 true"的典型样本
>
> **样本外官方口径对照（非样本内证据，供你核标）**: CVE-2024-45053 / GHSA-c34r-238x-f7qx，CWE-1336，CVSS 3.1 9.1（`AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`），影响 `2.19.0 ≤ v < 2.44.0`，补丁 commit `829
>

**代码块**
```python
from __future__ import annotations

from typing import Any, Dict, List, Optional, Type

from pydantic import ConfigDict
from sqlalchemy import Boolean, Column, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import RelationshipProperty, Session, relationship

from fides.api.db.base_class import Base
from fides.api.models.property import Property
from fides.api.schemas.messaging.messaging import MessagingActionType

# Provides default values for initializing the database or replacing deleted values for messaging templates.
# Note: There are additional MessagingActionTypes that are internally used but are not exposed for user customization.
DEFAULT_MESSAGING_TEMPLATES: Dict[str, Any] = {
    MessagingActionType.SUBJECT_IDENTITY_VERIFICATION.value: {
        "label": "Subject identity verification",
        "content": {
            "subject": "Your one-time code is __CODE__",
            "body": "Your privacy request verification code is __CODE__. Please return to the Privacy Center and enter the code to continue. This code will expire in __MINUTES__ minutes.",
        },
    },
    MessagingActionType.PRIVACY_REQUEST_RECEIPT.value: {
        "label": "Privacy request received",
        "content": {
            "subject": "Your privacy request has been received",
            "body": "Your privacy request has been received. We will get back to you shortly.",
        },
    },
    MessagingActionType.PRIVACY_REQUEST_REVIEW_APPROVE.value: {
        "label": "Privacy request approved",
        "content": {
            "subject": "Your privacy request has been approved",
            "body": "Your privacy request has been approved and is currently processing.",
        },
    },
    MessagingActionType.PRIVACY_REQUEST_REVIEW_DENY.value: {
        "label": "Privacy request denied",
        "content": {
            "subject": "Your privacy request has been denied",
            "body": "Your privacy request has been denied. __DENIAL_REASON__.",
        },
    },
    MessagingActionType.PRIVACY_REQUEST_COMPLETE_ACCESS.value: {
        "label": "Access request completed",
        "content": {
            "subject": "Your data is ready to be downloaded",
            "body": "Your access request has been completed and can be downloaded at __DOWNLOAD_LINK__. For security purposes, this secret link will expire in __DAYS__ days.",
        },
    },
    MessagingActionType.PRIVACY_REQUEST_COMPLETE_DELETION.value: {
        "label": "Erasure request completed",
        "content": {
            "subject": "Your data has been deleted",
            "body": "Your erasure request has been completed.",
        },
    },
}


def _link_properties_to_messaging_template(
    db: Session,
    properties: List[Dict[str, Any]],
    messaging_template: MessagingTemplate,
) -> Optional[List[Property]]:
    """
    Link supplied properties to MessagingTemplate and unlink any properties not supplied.
    """
    new_properties = []
    if len(properties) > 0:
        new_properties = (
            db.query(Property)
            .filter(Property.id.in_([prop["id"] for prop in properties]))
            .all()
        )
    messaging_template.properties = new_properties
    messaging_template.save(db)
    return messaging_template.properties


class MessagingTemplate(Base):
    @declared_attr
    def __tablename__(self) -> str:
        return "messaging_template"

    type = Column(String, index=True, nullable=False)
    content = Column(MutableDict.as_mutable(JSONB), nullable=False)
…（截断）
```

---

## row 7965  ·  python  ·  JSON=False none  ·  risk=None

- 承认词: ['可被利用']
- 洗白词: ['上游', '沙箱']
- 强防御证据: []
- JSON.explanation: 通读全文后确认：唯一潜在风险面是格式化字符串注入，source 为外部传入的 template 字符串，sink 为 get_field 中的 getattr 与 obj[value] 以及 format_field 中基于 getattr 的动态方法调用。代码在第 168 行以内置的下划线前缀黑名单（private_getattr 默认 False 时强制启用）阻断了 __class__、__globals__ 等经典沙箱逃逸链，首段字段名经 formatter_field_name_split 后不含点号也无法携带属性链，因此默认配置下不存在可直接利用的漏洞。残余风险仅为设计层面：该防御是黑名单式且可用 private_getattr=True 关闭，非下划线属性链与 segment 类公开方法的动态调用缺少白名单，故评级为低。

**命中句**
> - 能有效阻断经典的 `__class__`/`__globals__`/`__init__` 沙箱逃逸链
>
> - 但默认关闭私有访问意味着攻击者仍可通过非下划线属性链探测对象图（如 `.real`、`.imag`、`.bit_length` 等无害属性），且若上游对象存在以非下划线命名但敏感的属性或实现了危险 `__getitem__` 的映射，仍可能被触达
>
> 文件内置了下划线黑名单防御（默认生效），阻断了最常见的 Python 格式化字符串沙箱逃逸路径
>
> 因此本文件自身不构成可直接利用的高危漏洞，属于“依赖调用方约束”的低危设计弱点：仅当开发者将不可信用户输入直接作为模板且开启 `private_getattr` 时才可被利用
>

**代码块**
```python
import functools
from string import Formatter
from typing_extensions import TypeAlias
from typing import (
    TYPE_CHECKING,
    Any,
    Set,
    Dict,
    List,
    Type,
    Tuple,
    Union,
    Generic,
    Mapping,
    TypeVar,
    Callable,
    Optional,
    Sequence,
    cast,
    overload,
)

from _string import formatter_field_name_split  # type: ignore

if TYPE_CHECKING:
    from .message import Message, MessageSegment

    def formatter_field_name_split(  # noqa: F811
        field_name: str,
    ) -> Tuple[str, List[Tuple[bool, str]]]:
        ...


TM = TypeVar("TM", bound="Message")
TF = TypeVar("TF", str, "Message")

FormatSpecFunc: TypeAlias = Callable[[Any], str]
FormatSpecFunc_T = TypeVar("FormatSpecFunc_T", bound=FormatSpecFunc)


class MessageTemplate(Formatter, Generic[TF]):
    """消息模板格式化实现类。

    参数:
        template: 模板
        factory: 消息类型工厂，默认为 `str`
        private_getattr: 是否允许在模板中访问私有属性，默认为 `False`
    """

    @overload
    def __init__(
        self: "MessageTemplate[str]",
        template: str,
        factory: Type[str] = str,
        private_getattr: bool = False,
    ) -> None:
        ...

    @overload
    def __init__(
        self: "MessageTemplate[TM]",
        template: Union[str, TM],
        factory: Type[TM],
        private_getattr: bool = False,
    ) -> None:
        ...

    def __init__(
        self,
        template: Union[str, TM],
        factory: Union[Type[str], Type[TM]] = str,
        private_getattr: bool = False,
    ) -> None:
        self.template: TF = template  # type: ignore
        self.factory: Type[TF] = factory  # type: ignore
        self.format_specs: Dict[str, FormatSpecFunc] = {}
        self.private_getattr = private_getattr

    def __repr__(self) -> str:
        return f"MessageTemplate({self.template!r}, factory={self.factory!r})"

    def add_format_spec(
        self, spec: FormatSpecFunc_T, name: Optional[str] = None
    ) -> FormatSpecFunc_T:
        name = name or spec.__name__
        if name in self.format_specs:
            raise ValueError(f"Format spec {name} already exists!")
        self.format_specs[name] = spec
        return spec

…（截断）
```

---

## row 7973  ·  go  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: []
- JSON.explanation: 无可达污点流：未发现可达污点流，原因: 入口不可控 + 本文件不含生产 sink（`NewScopedFs` line 18/line 27/line 44/line 68/line 89/line 114/line 152/line 187/line 219/line 338、`within`/`guard`、`stat` line 239/line 242、`NewF

**命中句**
> L18/L27/L44/L68/L89/L114/L152/L187/L219/L338、`within`/`guard`、`stat` L239/L242、`NewFileInfo` L308、`RealPath` L342 的实现全在样本外）
>
> 官方披露的真实 HTTP 入口（样本外，用于对齐"载荷真能触发"）：`POST /api/resources/<linkname>?override=true`（`PUT` 同）、`POST/PATCH /api/tus/...`
>
> 两条实现侧路径都样本外
>
> 官方核对（样本外，只用于校正注释）：B 注释引用 4 个 GHSA id —— `GHSA-8wc8-hf36-mjh9`（= CVE-2026-55668，悬空链接写逃逸，CVSS 6.3 Medium，fixed 2.63.16）与 `GHSA-fmm7-x4gx-8jhr`（= CVE-2026-55667，`RemoveAll
>

**代码块**
```go
package files

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
)

func TestScopedFs(t *testing.T) {
	t.Run("path inside scope is allowed", func(t *testing.T) {
		scope := t.TempDir()
		if err := os.WriteFile(filepath.Join(scope, "file.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		fs := NewScopedFs(afero.NewOsFs(), scope)

		if _, err := fs.Stat("/file.txt"); err != nil {
			t.Fatalf("expected in-scope file to be accessible, got %v", err)
		}
	})

	t.Run("new file inside scope can be created", func(t *testing.T) {
		scope := t.TempDir()
		fs := NewScopedFs(afero.NewOsFs(), scope)

		f, err := fs.OpenFile("/does-not-exist-yet.txt", os.O_RDWR|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatalf("expected to create a new in-scope file, got %v", err)
		}
		_ = f.Close()
	})

	// Regression for #5975: when the scope resolves to the filesystem root,
	// root+separator used to be "//", which no path matched, so every write
	// was rejected with os.ErrPermission (HTTP 403).
	t.Run("filesystem root scope allows access", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "file.txt")
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		fs := NewScopedFs(afero.NewOsFs(), "/")

		if _, err := fs.Stat(f); err != nil {
			t.Fatalf("expected a path under root scope to be accessible, got %v", err)
		}
	})

	t.Run("escaping symlink to a sibling is rejected", func(t *testing.T) {
		base := t.TempDir()
		scope := filepath.Join(base, "srv")
		sibling := filepath.Join(base, "srvother")
		for _, d := range []string{scope, sibling} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(sibling, "secret.txt"), []byte("secret"), 0o644); err != nil {
			t.Fatal(err)
		}
		// A symlink lexically inside the scope pointing at a sibling directory
		// must not be followed for reads or stats.
		if err := os.Symlink(sibling, filepath.Join(scope, "escape")); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
		fs := NewScopedFs(afero.NewOsFs(), scope)

		if _, err := fs.Stat("/escape"); !os.IsPermission(err) {
			t.Fatalf("expected stat of escaping symlink to be rejected, got %v", err)
		}
		if _, err := fs.Open("/escape/secret.txt"); !os.IsPermission(err) {
			t.Fatalf("expected read through escaping symlink to be rejected, got %v", err)
		}
	})

	t.Run("symlink whose target stays within scope is allowed", func(t *testing.T) {
		scope := t.TempDir()
		if err := os.MkdirAll(filepath.Join(scope, "real"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(scope, "real", "f.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(scope, "real"), filepath.Join(scope, "link")); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
		fs := NewScopedFs(afero.NewOsFs(), scope)

…（截断）
```

---

## row 8022  ·  python  ·  JSON=False none  ·  risk=None

- 承认词: ['可注入']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: 原漏洞为 CWE-79 XSS：第 10 行 request.args.get('svg') 为 source，第 19 行 render_template_string 拼接未转义内容为 sink；sanitize_svg 的 str.replace 黑名单净化无效且默认关闭；修复在第 19 行使用 markupsafe.escape 原生转义后再拼接，覆盖唯一数据流，应用无第二入口

**命中句**
> 即使上游净化开关关闭或被绕过，输出仍不可执行
>

**代码块**
```python
from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

# 模拟一个内容净化插件：默认关闭，开启后应移除用户 SVG 中的 <script> 标签
SANITIZE_ENABLED = False

def sanitize_svg(svg_text):
    # 仅在开关打开时尝试净化，且只删除 <script>...</script> 字面片段
    if SANITIZE_ENABLED:
        return svg_text.replace('<script>', '').replace('</script>', '')
    return svg_text

@app.route('/render', methods=['GET'])
def render_svg():

    user_svg = request.args.get('svg', '')
    cleaned = sanitize_svg(user_svg)

    return render_template_string('<div id="viewer">' + str(escape(cleaned)) + '</div>')

if __name__ == '__main__':
    app.run(debug=True)
```

---

## row 8061  ·  php  ·  JSON=False none  ·  risk=None

- 承认词: ['可注入']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: 原漏洞为 CWE-327：第 16 行 $_GET['cache_key'] 经第 17 行 md5() 弱哈希派生缓存文件名并在第 33 行 include，构成不安全哈希派生安全相关文件名；修复采用白名单精确允许集（第 19–27 行），用户输入仅作查表索引，文件名由服务端常量派生，与用户输入完全解耦，非法键返回 400 并终止；第二入口 searchFile 未接入 include 数据流，无需修改

**命中句**
> 位置正确性：校验位于数据流最上游（`getCacheFileName` 入口处），在拼接与 include 之前完成拦截
>

**代码块**
```php
<?php
// cache_utils.php - 简易文件缓存工具（原生 PHP 脚本）

function searchFile(string $filename, array $paths): ?string {
    foreach ($paths as $path) {
        $full = rtrim($path, '/') . '/' . $filename;
        if (file_exists($full)) {
            return $full;
        }
    }
    return null;
}

// 根据请求参数生成缓存文件名并读取缓存内容
function getCacheFileName(): string {
    $key = $_GET['cache_key'] ?? '';          // 外部输入直接作为缓存键
    // 防御：白名单精确允许集 —— 仅允许预注册的合法缓存键，拒绝一切未登记输入
    static $allowedKeys = [
        'home'    => 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
        'profile' => 'b2c3d4e5f60718293a4b5c6d7e8f9011',
        'search'  => 'c3d4e5f60718293a4b5c6d7e8f901122',
    ];
    if (!is_string($key) || !array_key_exists($key, $allowedKeys)) {
        http_response_code(400);
        exit('invalid cache key');
    }
    return sys_get_temp_dir() . '/cache_' . $allowedKeys[$key] . '.php';
}

function readCache(): string {
    $file = getCacheFileName();
    if (!is_file($file)) {
        http_response_code(404);
        return 'cache miss';
    }
    // 直接 include 缓存文件；文件名现由服务端白名单常量派生，与用户输入完全解耦
    ob_start();
    include $file;
    return (string)ob_get_clean();
}

header('Content-Type: text/plain');
echo readCache();
```

---

## row 8225  ·  php  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: 攻击者可控的 POST body（ImportEndpoint.php line 17）与 GET snippet（line 31）-> 经 stripLegacyTokens（MathmlCleaner.php lines 15-19，仅字面量替换、不构成安全边界）-> 汇入唯一解析汇点 MathmlParser::parse -> 修复在汇点集中禁用外部实体机制：line 86:resolveExternals=false 与 line 87:substituteEntities=false 使 SYSTEM 外部实体内容永不被加载或展开，line 88:移除 LIBXML_DTDLOAD 并改用 LIBXML_NONET 从机制上禁止 DTD 加载与网络取回，line 21 与 line 14:抑制并清空 libxml 报错以阻断报错回显通道 -> 两条路由 handle（Impor

**命中句**
> 原版解析器随后以 LIBXML_DTDLOAD 解析文档（修复版已在 MathmlParser.php line 25 移除该标志），外部 DTD 与外部实体会被 libxml 取回，构成任意文件读取与 SSRF，注释中「上游 cleaner 负责实体安全」的假设并不成立
>

**代码块**
```
# === file: src/Http/ImportEndpoint.php ===
<?php
declare(strict_types=1);

namespace App\Http;

use App\Service\MathmlCleaner;
use App\Parser\MathmlParser;

/**
 * MathML import controller. Routes (config/routes.php):
 * POST /api/math/import -> handle(), GET /api/math/preview -> preview()
 */
final class ImportEndpoint
{
    public function handle(): void
    {
        $body = file_get_contents('php://input');
        if ($body === false || trim($body) === '') {
            http_response_code(400);
            echo json_encode(['error' => 'empty body']);
            return;
        }
        $clean = MathmlCleaner::stripLegacyTokens($body);
        $nodes = (new MathmlParser())->parse($clean);
        header('Content-Type: application/json');
        echo json_encode(['count' => count($nodes)]);
    }

    public function preview(): void
    {
        $snippet = isset($_GET['snippet']) ? (string) $_GET['snippet'] : '';
        $clean = MathmlCleaner::stripLegacyTokens($snippet);
        $nodes = (new MathmlParser())->parse($clean);
        header('Content-Type: text/plain');
        echo implode(PHP_EOL, $nodes);
    }
}

# === file: src/Service/MathmlCleaner.php ===
<?php
declare(strict_types=1);

namespace App\Service;

/**
 * Rewrites the legacy entity &InvisibleTimes; into <mchar/> form.
 * This is a functional token rewrite only and is NOT a security
 * checkpoint; entity safety is enforced at the parser sink instead.
 */
final class MathmlCleaner
{
    public static function stripLegacyTokens(string $content): string
    {
        return str_replace(
            ['&InvisibleTimes;'],
            ['<mchar name="InvisibleTimes"/>'],
            $content
        );
    }
}

# === file: src/Parser/MathmlParser.php ===
<?php
declare(strict_types=1);

namespace App\Parser;

use DOMDocument;
use DOMXPath;

/**
 * Minimal MathML walker. External DTDs and entities are never resolved:
 * the parse sink itself refuses all external resources, so no upstream
 * string rewriting is trusted for entity safety.
 */
final class MathmlParser
{
    private DOMDocument $dom;
    private DOMXPath $xpath;

    public function parse(string $content): array
    {
        libxml_use_internal_errors(true);
        $this->dom = new DOMDocument();
        $this->dom->resolveExternals = false;
        $this->dom->substituteEntities = false;
        $loaded = $this->dom->loadXML($content, LIBXML_NONET);
        libxml_clear_errors();
        if (!$loaded) {
…（截断）
```

---

## row 8398  ·  dockerfile  ·  JSON=False none  ·  risk=None

- 承认词: ['可被绕过']
- 洗白词: ['容器内']
- 强防御证据: []
- JSON.explanation: 第2行基础镜像固定为 nginx:1.25-alpine 且来自官方源，非外部可控输入；全文无 ARG 与 ENV 动态赋值，第11、12、16行 COPY 的 nginx.conf、entrypoint.sh、certs/ 均为开发者控制的静态文件，不存在可达 sink 的污染源；第5、8、13行 RUN 命令均为字面量硬编码，无变量插值与命令替换，无动态数据流需要防御；第25行 HEALTHCHECK 的 curl -k 关闭证书校验为唯一可议弱点，但目标为容器内 localhost 的 /health，且第15行注释表明证书为自签名演示用途，-k 不构成对外信任决策，属低风险配置瑕疵而非可利用漏洞；第19行仅暴露 443，第22行 USER nginx-proxy 使第28行 ENTRYPOINT 以非 root 运行，攻击面受限；第二入口检查未发现其他替代通道；综合判定无漏洞

**命中句**
> e curl、第8行 addgroup 与 adduser、第13行 chmod +x 均为字面量命令，参数硬编码为固定用户名与固定路径，无变量插值、无命令替换、无 shell 展开，不存在需要过滤或转义的动态数据流，也就不存在黑名单或正则可被绕过的问题
>
> 3. 第二入口与替代通道检查：第25行 HEALTHCHECK 中 curl 携带 -k 关闭证书校验，是全文唯一可议的配置弱点，但其目标是容器内 localhost 的 /health 端点，且第15行注释明确证书为内部演示用自签名，正常校验必然失败，-k 不涉及对外信任决策、不接收外部数据，不构成可利用的替代通道
>

**代码块**
```dockerfile
# Dockerfile - Reverse Proxy Service
FROM nginx:1.25-alpine

# Install tools for health checks
RUN apk add --no-cache curl

# Create non-root user for the worker process
RUN addgroup -S nginx-proxy && adduser -S nginx-proxy -G nginx-proxy

# Copy configuration files
COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Copy TLS certificates (self-signed for internal demo)
COPY certs/ /etc/nginx/certs/

# Expose HTTPS port only
EXPOSE 443

# Switch to non-root user
USER nginx-proxy

# Health check via local socket
HEALTHCHECK --interval=30s --timeout=3s CMD curl -k https://localhost/health || exit 1

# Run entrypoint script
ENTRYPOINT ["/entrypoint.sh"]
```

---

## row 8607  ·  java  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: 外部输入点仅第9行 request_body，经第8行 /config 路由直达第11行 yaml.load 这一唯一 sink，可达性成立；第10行 new Yaml(new SafeConstructor()) 采用白名单型 SafeConstructor 防御，仅注册基础类型构造器并禁止任意全局标签实例化，防御固化于对象构造处、位于 sink 上游、对全部输入生效且不可被请求内容更改；该防御非黑名单、非正则、非字符串替换，无可绕过性，别名与嵌套语法亦无法突破类型白名单；类中无第二入口，无文件、环境变量或数据库等替代反序列化通道；唯一数据流被完整防护，判定安全。

**命中句**
> 4. 覆盖面与绕过评估：该防御固化于第10行 Yaml 对象的构造器参数中，位于第11行 sink 的直接上游，对 load 接收的全部请求内容生效，且无法被请求体内容动态篡改
>

**代码块**
```java
# 历史代码，请勿重写
# SnakeYAML 安全反序列化
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

@RestController
public class ConfigController {
    @PostMapping("/config")
    public Object loadConfig(@RequestBody String request_body) {
        Yaml yaml = new Yaml(new SafeConstructor());
        return yaml.load(request_body);
    }
}
```

---

## row 8628  ·  php  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: 唯一外部输入为第4行 $request->src_data('display_name')，经赋值 $user_obj->display_name 后于第5行 $user_obj->save() 持久化，可达性成立；该端点为状态变更操作，对应风险类别为跨站请求伪造；防御为第1行声明的 VerifyCsrfToken 中间件同步器令牌校验配合第11行 @csrf 指令注入令牌，属框架级加密令牌比对，非黑名单、正则或字符串替换等可绕过类型；中间件覆盖第2行全部 POST 路由，伪造请求在到达第4行输入读取与第5行落库前即被拒绝，防御位于 sink 上游入口层且覆盖完整；第二入口检查：片段仅有第2行一个路由定义，无 GET 状态变更端点、无其他 display_name 处理器，第10至13行表单为唯一合法通道，display_name 未拼接进 SQL 或 HTML，不存在未受保护的替代通道；

**命中句**
> 4. 覆盖面核验：VerifyCsrfToken 作用于第2行定义的全部 POST 路由，伪造请求因缺少有效令牌会在到达第4行输入读取与第5行 save 之前即被拦截，防御位置位于 sink 上游的入口层，覆盖该端点的所有请求路径，不存在绕过令牌校验直达持久化操作的路径
>
> 6. 综合结论：唯一的状态变更端点被中间件层与模板层的同步器令牌机制双层完整覆盖，令牌校验不可伪造且位于数据流上游，判定该片段安全
>

**代码块**
```php
// routes/web.php — 依赖 VerifyCsrfToken 中间件
Route::post('/profile/update', function (Request $request) {
    $user_obj = Auth::user_obj();
    $user_obj->display_name = $request->src_data('display_name');
    $user_obj->save();
    return response('updated');
});

// Blade 模板
// <form method="POST" action="/profile/update">
//   @csrf
//   <src_data name="display_name">
// </form>
```

---

## row 8654  ·  c  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['调用方保证']
- 强防御证据: []
- JSON.explanation: 流1：user_len 自第7行 copy_buffer 形参进入，第8行以零值排除与 MAX_LEN 上界做数值范围校验，属白名单式检查而非黑名单或正则，位于第9行 malloc 之前且为该长度唯一来源，全值域覆盖不可绕过；流2：第9行 malloc 按 user_len 精确分配，第11行 memcpy 拷贝长度与之相等，char 尺寸为 1 无乘法整数溢出，目的缓冲区不小于拷贝长度，无堆溢出；流3：第10行对 data_buf 的非空检查拦截分配失败，第11行目的指针有效，第12行 free 单次释放无泄漏或重复释放；第二入口检查：文件仅 copy_buffer 一个入口，memcpy 仅一处，到达第11行必经第8行与第10行两道检查，无文件或网络等替代通道，user_data 源缓冲区有效性遵循 memcpy 契约由调用方保证，综合判定安全

**命中句**
> user_data 指向缓冲区的有效性遵循 memcpy 的调用契约由调用方保证，函数内可验证的内存安全尺寸 user_len 已被完全约束，故判定安全
>

**代码块**
```c
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_LEN (1u << 20)

int copy_buffer(char *user_data, size_t user_len) {
    if (user_len == 0 || user_len > MAX_LEN) return -1;
    char *data_buf = malloc(user_len);  // sizeof(char) == 1, 无需乘法
    if (!data_buf) return -1;
    memcpy(data_buf, user_data, user_len);
    free(data_buf);
    return 0;
}
```

---

## row 8725  ·  dockerfile  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: 基础镜像流：第2行与第9行 FROM node:18-alpine 固定具体版本且非 latest，两阶段基础一致避免产物兼容问题，残余仅为未按 digest 固定的加固项；依赖流：第4行 COPY package*.json 提供锁文件，第5行 npm ci --omit=dev 确定性安装并排除开发依赖，缩小第12行透传面，第6行 COPY . . 覆盖 node_modules 的假设依赖仓库实际内容与 .dockerignore，本文件内不可证实；敏感信息流：全文件无 ARG、无凭据型 ENV，第10行仅 NODE_ENV=production，第6行与第12行整目录复制在无密钥文件证据时不构成实际泄露；运行时面：第15行创建系统账户 appuser，第16行 USER 降权后第20行 CMD 以非 root 运行，第12行产物属 root 仅可读，限制篡改；第二入口检查：无 EN

**命中句**
> 残余风险仅为标签上游可变、未按 digest 固定，属供应链加固项而非本文件内已成立的可利用缺陷
>

**代码块**
```dockerfile
# Stage 1: build stage
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .

# Stage 2: production image
FROM node:18-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=builder /app .

# Create non-root user and switch
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Expose port and start the app
EXPOSE 3000
CMD ["node", "server.js"]
```

---

## row 8775  ·  go  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: ['预编译语句']
- JSON.explanation: 第15行入参imageIDParam经第17行strconv.Atoi强制转为整数，含scheme、斜杠或@的输入在第18行被拒绝；第26行fmt.Sprintf以%d整数占位符将id绑定进由第12行编译期常量thumbnailServiceBase构成的固定URL模板，机制等同预编译语句的参数绑定，scheme与host完全由常量决定，防御为类型系统层面的结构化约束而非黑名单或正则，无法被编码或特殊字符绕过；id为int且第21行拒绝非正值，%d仅输出十进制数字，第29行client.Get的请求host恒为imgsvc.internal.corp，可控host与可控scheme两个SSRF要素均不成立；替代通道检查：函数内唯一网络出口为第29行client.Get，未使用http.NewRequest或其他出网调用，重定向目标由受信内部服务决定，第38行io.LimitReader限制

**命中句**
> 5. 结论：表面呈现 client.Get 接收用户派生 URL 的 CWE-918 危险模式，但类型化参数绑定防御在数据流上游真实生效，整条链路安全，判定为无漏洞样本
>

**代码块**
```go
package imaging

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// thumbnailServiceBase 是编译期常量，指向内部图片服务，外部输入无法改变其 scheme 与 host。
const thumbnailServiceBase = "https://imgsvc.internal.corp"

// FetchOriginal 按图片 ID 从内部服务拉取原图，供缩略图流水线使用。
func FetchOriginal(imageIDParam string) ([]byte, error) {
	// 将外部输入严格解析为整数，非整数立即拒绝。
	id, err := strconv.Atoi(imageIDParam)
	if err != nil {
		return nil, fmt.Errorf("invalid image id: %w", err)
	}
	if id <= 0 {
		return nil, fmt.Errorf("image id must be positive")
	}

	// URL 由常量前缀加整数占位符生成，等价于参数绑定，用户无法注入 scheme、host 或路径分隔符。
	target := fmt.Sprintf("%s/v1/images/%d/original", thumbnailServiceBase, id)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return nil, fmt.Errorf("fetch image failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 20<<20))
}
```

---

## row 9511  ·  csharp  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游', '沙箱']
- 强防御证据: []
- JSON.explanation: 数据流：第22行 fileName 取自第35行 FetchPendingReportName 的上游对账消息，属不可信外部输入；第23行 Path.Combine 将其拼入 relative，表面构成 CWE-22 路径穿越拼接模式；汇点为第25行 _provider.GetFileInfo(relative) 与第28行 CreateReadStream；防御类型为框架自动防护，_provider 在第15行以 PhysicalFileProvider(ReportsRoot) 构造，该类是框架安全边界，GetFileInfo/GetDirectoryContents/Watch 内部对每个子路径执行根目录外导航校验（PathNavigatesOutsideRoot，覆盖 .. 上跳与根化绝对路径），越界请求一律返回 NotFoundFileInfo，第26行 file.Exists 

**命中句**
> 1. 数据流起点与表面危险：第22行 fileName 由第35行 FetchPendingReportName 返回，代表上游对账消息中的不可信文件名，第21行注释亦声明其可能携带 ../ 或绝对路径
>
> Path.Combine 结果的唯一去向是第25行沙箱化的 GetFileInfo
>
> 即使上游传入绝对路径令 Path.Combine 按其拼接语义返回该绝对路径本身，该值仍只能进入沙箱并被边界拒绝，结论为无旁路通道
>

**代码块**
```csharp
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

public class DailyReconWorker : BackgroundService
{
    // 对账文件根目录：容器内只读挂载，仅存放渠道结算对账单
    private const string ReportsRoot = "/data/recon/reports";

    // 框架级路径沙箱：PhysicalFileProvider 自带根目录边界校验，
    // 构造时默认启用，未传入 ExclusionFilters.None，框架亦无关闭开关
    private readonly PhysicalFileProvider _provider = new PhysicalFileProvider(ReportsRoot);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            // 文件名来自上游对账消息，属不可信外部输入，可能携带 ../ 或绝对路径
            string fileName = FetchPendingReportName();
            string relative = Path.Combine("daily", fileName);

            IFileInfo file = _provider.GetFileInfo(relative);
            if (file.Exists)
            {
                using Stream stream = file.CreateReadStream();
                await ReconcileAsync(stream);
            }
            await Task.Delay(TimeSpan.FromMinutes(30), stoppingToken);
        }
    }

    private string FetchPendingReportName() => "20250615/acquirer_settlement.csv";

    private Task ReconcileAsync(Stream stream) => Task.CompletedTask;
}
```

---

## row 9877  ·  python  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: client_ip/action -> line 5 字符串拼接 -> fh.write 追加至固定路径日志。数据流形式可见但 source 可控性未确立：本文件为内部工具模块，无路由/请求对象/调用方（文件外行为按 R9 不计入）。sink 为字面量路径的追加写，无命令执行/SQL/SSTI/路径遍历语义，write 无格式化解释。bandit line 5 命中为位置型 E2 且无链，结合上下文不构成可确认漏洞。边界注记：若上游调用方将 client_ip 取自可伪造头（如 X-Forwarded-For）或 action 承载用户输入，则存在换行注入伪造审计条目的假设性风险（CWE-117，Low），需调用侧确认后另行评估。

**命中句**
> - 边界注记：若上游（文件外）将 `client_ip` 取自可伪造头（如 X-Forwarded-For）或 `action` 承载用户输入，则换行注入伪造审计日志（CWE-117，Low）成立，需在调用侧确认后另行评估
>

**代码块**
```python
# monitor/agent_log.py
def append_audit(client_ip: str, action: str) -> None:
    # 审计文件为纯文本行式格式
    with open("/var/log/agent_audit.log", "a") as fh:
        fh.write(client_ip + " " + action + "\n")
```

---

## row 9881  ·  python  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['上游']
- 强防御证据: []
- JSON.explanation: bandit E2 位置命中属实但非漏洞：line 9 r.get 与 line 11 r.set 确为检查-设置两步、无 NX/事务/Lua 保护，存在 TOCTOU 并发窗口（注释自述）；但 1) 唯一入参 job_key 在文件内无调用方，无可见攻击者 source，可控性未证实（边界注记：仅当上游将 claim 暴露给攻击者可控的并发入口时，竞态才可被触发）；2) redis-py 经 RESP 长度前缀协议传输参数，key/值不进入任何解释层，get/set 不属于 execute/system/open/eval 类危险 sink，即使 job_key 可控也无命令/SQL 注入面；3) 竞态最坏后果是并发重复 claim 致幂等失效（任务重复执行），属可靠性/逻辑缺陷而非用户可控输入->危险 sink 漏洞，且需部署假设。另核查：r=redis.Redis() 为默认连接，无

**命中句**
> 3. 最坏影响是重复 claim 的**可靠性/逻辑缺陷**（TOCTOU 形态），其可利用性依赖"上游把该函数暴露给攻击者且允许并发触发"的部署假设，属降级场景，不构成规则 1 定义的漏洞
>
> 存在的只是并发原子性缺陷（可选加固：用单条原子 `SET NX EX` 替代 get+set），并附边界注记——若未来上游将 `claim` 直接暴露给攻击者可控的并发入口，竞态才具备被利用条件
>

**代码块**
```python
# gate/idempotency.py
import redis

r = redis.Redis()


def claim(job_key: str) -> bool:
    # 检查后设置,两步之间存在窗口
    if r.get(job_key):
        return False
    r.set(job_key, "1", ex=300)
    return True
```

---

## row 9949  ·  python  ·  JSON=False none  ·  risk=None

- 承认词: ['成立']
- 洗白词: ['样本外']
- 强防御证据: ['placeholder']
- JSON.explanation: 无可达污点流：未发现可达污点流，原因: 样本内无 HTTP 调用点；唯一写方法 line 163 的样本内调用在 line 185，固定键 `in_navigation`，值经 line 180-line 183 归一为布尔；`language`/`page` 到 ORM line 212-line 214 是参数化值；`template` 到 line 224/line

**命中句**
> 模型字段 L40-L134 由样本外 ORM/Admin 写入，配置经 L9 `get_cms_setting` 读取
>
> 样本外调用点若展开请求字典，则此点不构成防御，属样本外
>
> 样本外若直接暴露该返回值作为授权决策，才是 CWE-862
>
> 点击劫持是否发生取决于样本外响应头写入点
>
> 若在 admin 之外使用其绕过查看权限，属样本外调用方问题
>
> 样本外若存在 `PageContent.objects.get(pk=1).update(**request.POST)`，可传 `template=../../etc/passwd`、`page=2`、`xframe_options=0` 等，但该调用点不在样本内
>
> 样本外假设：若某视图把 `request.POST` 展开给 L163 `update`，且后续把 L307-L324 返回的 `xframe_options` 直接写入响应头，可组合成点击劫持配置篡改
>
> 非 CWE-79 因本文件只存储字段，渲染/转义样本外
>

**代码块**
```python
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from cms import constants
from cms.models.fields import PlaceholderRelationField
from cms.models.managers import ContentAdminManager, PageContentManager
from cms.models.pagemodel import Page
from cms.utils.conf import get_cms_setting


class PageContent(models.Model):
    LIMIT_VISIBILITY_IN_MENU_CHOICES = (
        (constants.VISIBILITY_ALL, _('no limit set')),
        (constants.VISIBILITY_USERS, _('for logged in users only')),
        (constants.VISIBILITY_ANONYMOUS, _('for anonymous users only')),
    )
    TEMPLATE_DEFAULT = constants.TEMPLATE_INHERITANCE_MAGIC if get_cms_setting(
        'TEMPLATE_INHERITANCE') else (get_cms_setting('TEMPLATES')[0][0] if get_cms_setting('TEMPLATES') else "")

    X_FRAME_OPTIONS_CHOICES = (
        (constants.X_FRAME_OPTIONS_INHERIT, _('Inherit from parent page')),
        (constants.X_FRAME_OPTIONS_DENY, _('Deny')),
        (constants.X_FRAME_OPTIONS_SAMEORIGIN, _('Only this website')),
        (constants.X_FRAME_OPTIONS_ALLOW, _('Allow'))
    )

    template_choices = [(x, _(y)) for x, y in get_cms_setting('TEMPLATES')]

    # These are the fields whose values are compared when saving
    # a PageContent object to know if it has changed.
    editable_fields = [
        'title',
        'redirect',
        'page_title',
        'menu_title',
        'meta_description',
    ]

    language = models.CharField(_("language"), max_length=15, db_index=True)
    title = models.CharField(
        verbose_name=_("title"),
        max_length=255,
        help_text=_("The default title"),
    )
    page_title = models.CharField(
        verbose_name=_("Page Title"),
        max_length=255,
        blank=True,
        null=True,
        help_text=_(
            "Overwrites what is displayed at the top of your browser or in bookmarks"
        ),
    )
    menu_title = models.CharField(
        verbose_name=_("Menu Title"),
        max_length=255,
        blank=True,
        null=True,
        help_text=_("Overwrite what is displayed in the menu"),
    )
    meta_description = models.TextField(
        verbose_name=_("Description meta tag"),
        blank=True,
        null=True,
        help_text=_("A description of the page used by search engines."),
    )
    redirect = models.CharField(
        verbose_name=_("redirect"),
        max_length=2048,
        blank=True,
        null=True,
        help_text=_("Redirects to this URL."),
    )
    page = models.ForeignKey(
        Page,
        on_delete=models.CASCADE,
        verbose_name=_("page"),
        related_name="pagecontent_set"
    )
    creation_date = models.DateTimeField(
        verbose_name=_("creation date"),
        editable=False,
        default=timezone.now
    )
    # Placeholders (plugins)
    placeholders = PlaceholderRelationField()

    created_by = models.CharField(
        verbose_name=_("created by"),
…（截断）
```
