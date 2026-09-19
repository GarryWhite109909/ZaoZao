#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_CMD_LEN 64

typedef struct {
    char cmd[MAX_CMD_LEN];
    uint8_t len;
} command_t;

// 解析来自 UART 的原始数据（无终止符，长度由 len 字段指定）
static int parse_command(const uint8_t *raw, uint8_t raw_len, command_t *out) {
    if (raw == NULL || out == NULL || raw_len == 0) {
        return -1;
    }
    // 防御 1：拒绝超过缓冲区大小的输入
    if (raw_len >= sizeof(out->cmd)) {
        return -1;
    }
    // 防御 2：显式清零目标缓冲区，避免残留数据
    memset(out->cmd, 0, sizeof(out->cmd));
    memcpy(out->cmd, raw, raw_len);
    out->cmd[raw_len] = '\0';  // 防御 3：手动添加终止符
    out->len = raw_len;
    return 0;
}

// 模拟 UART 接收回调
static void on_uart_data(const uint8_t *data, uint8_t size) {
    command_t cmd;
    char log_buf[128];

    if (parse_command(data, size, &cmd) != 0) {
        snprintf(log_buf, sizeof(log_buf), "ERR: invalid cmd\r\n");
    } else {
        // 防御 4：使用 snprintf 限制输出长度
        snprintf(log_buf, sizeof(log_buf), "OK: %s\r\n", cmd.cmd);
    }
    // 模拟发送日志到调试端口
    printf("%s", log_buf);
}

int main(void) {
    // 模拟固件主循环收到一帧数据（长度 10，不含终止符）
    uint8_t frame[] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A};
    on_uart_data(frame, sizeof(frame));
    return 0;
}

