#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_LEN 1024
#define HDR_SIZE 8

typedef struct {
    uint8_t data[MAX_PKT_LEN];
    uint16_t len;
} packet_t;

int parse_packet(packet_t *pkt, const uint8_t *raw, uint16_t raw_len) {
    if (raw_len < HDR_SIZE) {
        return -1;
    }
    
    uint16_t payload_len = (raw[4] << 8) | raw[5];
    uint16_t options_len = (raw[6] << 8) | raw[7];
    
    if (payload_len + options_len > MAX_PKT_LEN - HDR_SIZE) {
        return -2;
    }
    
    uint8_t payload[512];
    uint8_t options[256];
    
    // 注意：payload_len 和 options_len 来自网络字节序，可能被构造为任意值
    // 虽然上面检查了总和，但未分别检查单个长度是否超过本地缓冲区
    memcpy(payload, raw + HDR_SIZE, payload_len);          // line 24
    memcpy(options, raw + HDR_SIZE + payload_len, options_len); // line 25
    
    pkt->len = HDR_SIZE + payload_len + options_len;
    memcpy(pkt->data, raw, pkt->len);
    return 0;
}

int main() {
    uint8_t raw[MAX_PKT_LEN];
    packet_t pkt;
    
    // 模拟从网络接收的数据
    memset(raw, 0, sizeof(raw));
    raw[4] = 0x02;  // payload_len = 512
    raw[5] = 0x00;
    raw[6] = 0x00;  // options_len = 0
    raw[7] = 0x00;
    
    if (parse_packet(&pkt, raw, 520) == 0) {
        printf("Parsed %u bytes\n", pkt.len);
    }
    return 0;
}

