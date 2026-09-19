#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_BUF 64

typedef struct {
    char data[MAX_BUF];
    int len;
} packet_t;

/* 嵌入式固件：处理串口接收的配置包 */
int process_packet(const unsigned char *raw, size_t raw_len) {
    if (raw == NULL || raw_len == 0) {
        return -1;
    }

    packet_t *pkt = (packet_t *)malloc(sizeof(packet_t));
    if (pkt == NULL) {
        return -1;
    }

    /* line 16: 边界检查——防止栈缓冲区溢出 */
    if (raw_len > MAX_BUF - 1) {
        free(pkt);
        pkt = NULL; /* line 20: free后置NULL，防止悬垂指针 */
        return -1;
    }

    memcpy(pkt->data, raw, raw_len);
    pkt->data[raw_len] = '\0';
    pkt->len = (int)raw_len;

    /* 模拟固件配置应用 */
    printf("Config: %s\n", pkt->data);

    free(pkt);
    pkt = NULL; /* line 32: 双重防御，释放后立即置NULL */
    return 0;
}

int main(void) {
    /* 模拟从UART接收的数据 */
    unsigned char test_data[] = "set_baud=9600";
    return process_packet(test_data, strlen((char *)test_data));
}

