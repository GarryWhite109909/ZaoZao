#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_BUF_SIZE 64

typedef struct {
    uint8_t data[MAX_BUF_SIZE];
    uint16_t len;
} Packet;

// 解析串口接收的固件升级包
int parse_firmware_packet(const uint8_t *raw, uint16_t raw_len, Packet *out) {
    if (raw == NULL || out == NULL || raw_len < 4) {
        return -1;
    }

    // 前2字节为长度字段（小端序），后2字节为校验值（此处忽略校验）
    uint16_t payload_len = (uint16_t)(raw[0] | (raw[1] << 8));
    uint16_t checksum = (uint16_t)(raw[2] | (raw[3] << 8));

    // 防御：检查payload长度是否超过缓冲区上限
    if (payload_len > MAX_BUF_SIZE) {
        return -2;
    }

    // 防御：检查实际剩余数据是否足够
    if (payload_len > (raw_len - 4)) {
        return -3;
    }

    out->len = payload_len;
    // 漏洞：memcpy目标为out->data（64字节），源为raw+4，
    // 但payload_len是16位无符号数，若raw_len-4大于65535则截断，
    // 实际场景中raw_len受串口DMA限制通常小于64K，此处为模拟边界场景
    memcpy(out->data, raw + 4, payload_len);
    return 0;
}

int main(void) {
    // 模拟从串口DMA缓冲区接收的原始数据（64字节）
    uint8_t rx_buffer[64];
    memset(rx_buffer, 0, sizeof(rx_buffer));
    
    // 构造：长度字段 = 0xFFFE（65534），但实际剩余只有60字节
    rx_buffer[0] = 0xFE;
    rx_buffer[1] = 0xFF;
    
    Packet pkt;
    int ret = parse_firmware_packet(rx_buffer, sizeof(rx_buffer), &pkt);
    if (ret == 0) {
        printf("Parsed %u bytes\n", pkt.len);
    } else {
        printf("Parse error: %d\n", ret);
    }
    return 0;
}

