#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_LEN 1024
#define MAX_HDR_LEN 64

typedef struct {
    uint8_t data[MAX_PKT_LEN];
    uint16_t len;
} Packet;

// 解析网络帧头，提取关键字段
int parse_frame_header(Packet *pkt, uint8_t *dst, uint16_t dst_cap) {
    if (pkt->len < MAX_HDR_LEN) {
        return -1;  // 包太短，无法解析
    }

    // 假设帧头固定 64 字节，前 16 字节为源 MAC，后 16 字节为目的 MAC
    // 第 32-33 字节为负载长度字段（小端序）
    uint16_t payload_len = (uint16_t)(pkt->data[32] | (pkt->data[33] << 8));

    // 检查负载长度是否合理
    if (payload_len > (pkt->len - MAX_HDR_LEN)) {
        return -1;  // 负载长度超过实际剩余数据
    }

    // 将负载数据拷贝到目标缓冲区
    // 漏洞：未检查 payload_len 是否超过 dst_cap
    memcpy(dst, pkt->data + MAX_HDR_LEN, payload_len);  // line 26: 栈缓冲区溢出

    return payload_len;
}

int main() {
    Packet pkt;
    uint8_t payload_buf[64];  // 栈上缓冲区，仅能容纳 64 字节

    // 构造一个恶意数据包：负载长度字段为 256，但实际负载 256 字节
    memset(&pkt, 0, sizeof(pkt));
    pkt.len = MAX_HDR_LEN + 256;  // 总长度 320
    pkt.data[32] = 0x00;
    pkt.data[33] = 0x01;  // payload_len = 256

    // 填充负载数据（模拟网络接收）
    for (int i = 0; i < 256; i++) {
        pkt.data[MAX_HDR_LEN + i] = (uint8_t)i;
    }

    int n = parse_frame_header(&pkt, payload_buf, sizeof(payload_buf));
    if (n > 0) {
        printf("Received %d bytes\n", n);
    }
    return 0;
}

