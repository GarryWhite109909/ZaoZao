#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_LEN 64
#define MAX_CMD_LEN 32

typedef struct {
    uint8_t buf[MAX_PKT_LEN];
    uint16_t len;
} packet_t;

// 模拟从硬件寄存器读取数据
static uint16_t hw_read_packet(uint8_t *dst, uint16_t max_len) {
    // 实际固件中此处从DMA缓冲区拷贝，长度由硬件寄存器决定
    uint16_t actual = 48;
    memcpy(dst, "AT+STATUS=OK;VER=2.1.0;CH=7;RSSI=-65;TEMP=42", actual);
    return actual;
}

// 解析命令并执行（模拟）
static void exec_cmd(const char *cmd, uint16_t len) {
    char local_cmd[MAX_CMD_LEN];
    (void)len;
    strcpy(local_cmd, cmd);  // 第20行：固定长度拷贝，无边界检查
    printf("Exec: %s\n", local_cmd);
}

int main(void) {
    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    // 第28行：从硬件获取数据包
    pkt.len = hw_read_packet(pkt.buf, sizeof(pkt.buf));

    // 第31行：长度校验——仅校验非零，未校验上限
    if (pkt.len == 0) {
        printf("Empty packet\n");
        return -1;
    }

    // 第36行：直接传入固件缓冲区，长度未限制
    exec_cmd((char *)pkt.buf, pkt.len);
    return 0;
}

