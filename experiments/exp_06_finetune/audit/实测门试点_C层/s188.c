#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_LEN 256
#define MAX_HDR_LEN 64

typedef struct {
    uint8_t data[MAX_PKT_LEN];
    uint16_t len;
} packet_t;

int parse_packet(const uint8_t *buf, uint16_t buf_len, packet_t *out) {
    if (buf == NULL || out == NULL || buf_len < 8) {
        return -1;
    }

    // 前2字节为协议版本，2-4字节为载荷长度，4-8字节为头部校验
    uint16_t payload_len = (buf[2] << 8) | buf[3];
    if (payload_len > MAX_PKT_LEN - MAX_HDR_LEN) {
        return -1;  // 拒绝超长载荷
    }

    // 解析头部字段
    uint8_t flags = buf[4];
    uint8_t ttl = buf[5];

    // 复制载荷到输出缓冲区
    memcpy(out->data, buf + 8, payload_len);  // line 20: 潜在缓冲区溢出
    out->len = payload_len;

    // 简单校验：TTL必须非零
    if (ttl == 0) {
        return -2;
    }

    return 0;
}

int main() {
    uint8_t network_buf[MAX_PKT_LEN];
    packet_t pkt;

    // 模拟网络数据：构造一个超长载荷字段
    memset(network_buf, 0x41, sizeof(network_buf));
    network_buf[2] = 0x01;  // 载荷长度高字节
    network_buf[3] = 0x00;  // 载荷长度低字节 = 256

    // 注意：buf_len 被错误地设置为 MAX_PKT_LEN，但实际数据只有一部分有效
    parse_packet(network_buf, MAX_PKT_LEN, &pkt);
    printf("Parsed %u bytes\n", pkt.len);
    return 0;
}

