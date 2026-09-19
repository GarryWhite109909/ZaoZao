#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_LEN 128
#define MAX_BUF_LEN 64

typedef struct {
    uint8_t data[MAX_BUF_LEN];
    uint16_t len;
} packet_t;

/* 解析网络数据包，返回解析后的数据长度 */
static uint16_t parse_packet(const uint8_t *raw, uint16_t raw_len,
                             uint8_t *out, uint16_t out_cap) {
    if (raw == NULL || out == NULL) {
        return 0;
    }
    /* 防御1: 输入长度上限校验 */
    if (raw_len > MAX_PKT_LEN) {
        return 0;
    }
    /* 防御2: 输出缓冲区容量边界检查 */
    if (raw_len > out_cap) {
        return 0;
    }
    memcpy(out, raw, raw_len);
    return raw_len;
}

int main(void) {
    uint8_t raw_pkt[MAX_PKT_LEN];
    packet_t pkt;
    uint16_t parsed_len = 0;

    /* 模拟从网络接口接收数据 */
    memset(raw_pkt, 0xAA, sizeof(raw_pkt));
    uint16_t rx_len = 100;

    /* 防御3: 接收长度限制在缓冲区范围内 */
    if (rx_len > sizeof(raw_pkt)) {
        rx_len = sizeof(raw_pkt);
    }

    /* 防御4: 目标缓冲区容量明确传递 */
    parsed_len = parse_packet(raw_pkt, rx_len, pkt.data, sizeof(pkt.data));

    if (parsed_len > 0) {
        printf("Parsed %u bytes\n", parsed_len);
    } else {
        printf("Parse failed\n");
    }
    return 0;
}

