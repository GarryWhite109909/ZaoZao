#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_LEN 256
#define MAX_HDR_LEN 64

typedef struct {
    uint8_t data[MAX_PKT_LEN];
    uint16_t len;
} packet_t;

void parse_header(const uint8_t *buf, size_t buf_len) {
    char hdr_field[32];
    size_t field_len = buf_len;

    // 模拟从网络包中提取头部字段，buf_len 可能被恶意填充为大于 32
    if (field_len > MAX_HDR_LEN) {
        field_len = MAX_HDR_LEN;
    }

    // 漏洞点：没有检查 field_len 是否超过 hdr_field 的缓冲区大小
    memcpy(hdr_field, buf, field_len);  // line 18
    hdr_field[field_len] = '\0';        // line 19

    printf("Header field: %s\n", hdr_field);
}

int main() {
    packet_t pkt;
    uint16_t pkt_len;

    printf("Enter packet length: ");
    if (scanf("%hu", &pkt_len) != 1) {
        return 1;
    }

    if (pkt_len > MAX_PKT_LEN) {
        pkt_len = MAX_PKT_LEN;
    }

    printf("Enter packet data: ");
    for (uint16_t i = 0; i < pkt_len; i++) {
        scanf("%02x", (unsigned int *)&pkt.data[i]);
    }
    pkt.len = pkt_len;

    // 直接调用解析函数，传入可控长度
    parse_header(pkt.data, pkt.len);  // line 38

    return 0;
}

