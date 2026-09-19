#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define MAX_PKT_SIZE 1024
#define STATE_FILE "/var/run/network_state.bin"

typedef struct {
    int fd;
    char buffer[MAX_PKT_SIZE];
    size_t len;
} packet_ctx;

/* 从网络套接字读取数据包 */
static int read_packet(packet_ctx *ctx) {
    ssize_t n = read(ctx->fd, ctx->buffer, MAX_PKT_SIZE - 1);
    if (n <= 0) return -1;
    ctx->buffer[n] = '\0';
    ctx->len = (size_t)n;
    return 0;
}

/* 将网络状态持久化到文件 */
static int persist_state(const packet_ctx *ctx) {
    struct stat st;
    int fd;

    /* line 27: 检查文件属性前，先打开文件（TOCTOU 窗口） */
    fd = open(STATE_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;

    /* line 31: 再次 stat 检查文件类型，攻击者可在此间替换为符号链接 */
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }

    /* line 38: 写入数据，若 fd 已被替换则写入任意文件 */
    if (write(fd, ctx->buffer, ctx->len) != (ssize_t)ctx->len) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

/* 处理网络状态更新请求 */
static void handle_state_update(packet_ctx *ctx) {
    if (ctx->len < 4) return;
    /* 简化的协议头检查 */
    if (memcmp(ctx->buffer, "ST", 2) != 0) return;

    /* line 50: 持久化状态，触发 TOCTOU 漏洞 */
    if (persist_state(ctx) == 0) {
        printf("[INFO] State updated\n");
    }
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    packet_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* 模拟网络连接 */
    ctx.fd = STDIN_FILENO;
    
    if (read_packet(&ctx) == 0) {
        handle_state_update(&ctx);
    }
    return 0;
}

