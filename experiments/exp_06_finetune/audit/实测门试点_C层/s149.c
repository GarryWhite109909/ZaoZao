#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_LEN  256
#define MAX_DESC_LEN 64

typedef struct {
    uint8_t  pkt[MAX_PKT_LEN];
    uint16_t pkt_len;
    uint8_t  desc[MAX_DESC_LEN];
    uint8_t  desc_len;
} telemetry_t;

/* 从网络缓冲区解析遥测数据包 */
static uint8_t parse_telemetry(const uint8_t *buf, uint16_t buf_len,
                               telemetry_t *out)
{
    if (buf == NULL || out == NULL || buf_len < 3) {
        return 0;
    }

    /* 包头: [0]=类型, [1..2]=负载长度(小端) */
    uint16_t payload_len = (uint16_t)(buf[1] | (buf[2] << 8));
    if (payload_len > (buf_len - 3)) {
        return 0;  /* 负载长度超过实际数据 */
    }

    out->pkt_len = payload_len;
    memcpy(out->pkt, buf + 3, payload_len);

    /* 描述符从负载尾部提取，长度由负载最后一个字节决定 */
    out->desc_len = out->pkt[payload_len - 1];  /* 潜在越界读 */
    if (out->desc_len > MAX_DESC_LEN) {
        out->desc_len = MAX_DESC_LEN;
    }
    memcpy(out->desc, out->pkt + payload_len - out->desc_len, out->desc_len);

    return 1;
}

int main(void)
{
    uint8_t rx_buf[300] = {0};
    telemetry_t tm;

    /* 模拟从网络接口收到数据（仅演示） */
    rx_buf[0] = 0x01;
    rx_buf[1] = 0x05;  /* payload_len = 5 */
    rx_buf[2] = 0x00;
    rx_buf[3] = 0xAA;
    rx_buf[4] = 0xBB;
    rx_buf[5] = 0xCC;
    rx_buf[6] = 0xDD;
    rx_buf[7] = 0x04;  /* desc_len = 4 */

    if (parse_telemetry(rx_buf, sizeof(rx_buf), &tm)) {
        printf("pkt_len=%u, desc_len=%u\n", tm.pkt_len, tm.desc_len);
    }
    return 0;
}

