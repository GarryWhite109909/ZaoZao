#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PKT_LEN 256
#define MAX_CMD_LEN 64

typedef struct {
    char cmd[MAX_CMD_LEN];
    int len;
} pkt_t;

static int parse_packet(const char *buf, size_t buf_len, pkt_t *out) {
    if (buf == NULL || out == NULL) {
        return -1;
    }
    if (buf_len > MAX_PKT_LEN) {
        return -1;
    }
    /* line 13: 解析命令长度，显式校验上限 */
    if (buf[0] > MAX_CMD_LEN - 1) {
        return -1;
    }
    out->len = buf[0];
    /* line 17: 边界检查通过后才拷贝，防止缓冲区溢出 */
    memcpy(out->cmd, buf + 1, out->len);
    out->cmd[out->len] = '\0';
    return 0;
}

int handle_fw_update(const char *pkt, size_t pkt_len) {
    pkt_t *msg = (pkt_t *)malloc(sizeof(pkt_t));
    if (msg == NULL) {
        return -1;
    }
    memset(msg, 0, sizeof(pkt_t));

    if (parse_packet(pkt, pkt_len, msg) != 0) {
        free(msg);
        return -1;
    }

    /* line 31: 命令内容校验，仅允许固件更新指令 */
    if (strncmp(msg->cmd, "FW_UPDATE", 9) != 0) {
        free(msg);
        return -1;
    }

    /* 模拟固件写入操作 */
    printf("Applying firmware update: %s\n", msg->cmd);

    free(msg);
    return 0;
}

int main(int argc, char *argv[]) {
    /* 模拟从网络接收的数据包 */
    char raw_pkt[MAX_PKT_LEN + 2] = {0};
    size_t rlen = 0;

    if (argc > 1) {
        rlen = strlen(argv[1]);
        if (rlen > MAX_PKT_LEN) {
            fprintf(stderr, "Packet too large\n");
            return 1;
        }
        memcpy(raw_pkt, argv[1], rlen);
    }

    if (rlen > 0) {
        handle_fw_update(raw_pkt, rlen);
    }
    return 0;
}

