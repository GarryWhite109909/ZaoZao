#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_FRAME_LEN 1024
#define HEADER_LEN 8
#define PAYLOAD_OFFSET 16

typedef struct {
    uint16_t type;
    uint16_t flags;
    uint32_t payload_len;
} proto_header_t;

typedef struct {
    uint8_t data[MAX_FRAME_LEN];
    size_t used;
} rx_buffer_t;

static int parse_frame_header(const uint8_t *frame, proto_header_t *hdr) {
    if (frame == NULL || hdr == NULL) return -1;
    memcpy(&hdr->type, frame, 2);
    memcpy(&hdr->flags, frame + 2, 2);
    memcpy(&hdr->payload_len, frame + 4, 4);
    return 0;
}

int process_network_frame(rx_buffer_t *buf, const uint8_t *raw, size_t raw_len) {
    if (buf == NULL || raw == NULL || raw_len < HEADER_LEN) return -1;

    proto_header_t hdr;
    if (parse_frame_header(raw, &hdr) != 0) return -1;

    // 检查payload长度是否在合理范围内（但未检查与raw_len的匹配）
    if (hdr.payload_len > MAX_FRAME_LEN - PAYLOAD_OFFSET) {
        return -2;
    }

    // 将payload复制到缓冲区（固定偏移，但raw_len可能不足）
    memcpy(buf->data + PAYLOAD_OFFSET, raw + HEADER_LEN, hdr.payload_len);
    buf->used = PAYLOAD_OFFSET + hdr.payload_len;

    // 模拟后续解析
    uint8_t *payload = buf->data + PAYLOAD_OFFSET;
    for (size_t i = 0; i < hdr.payload_len; i++) {
        payload[i] ^= 0xAA;  // 简单解密操作
    }
    return 0;
}

int main() {
    rx_buffer_t rx = {0};
    // 模拟网络接收：仅12字节数据，但payload_len声明为100
    uint8_t malformed[12] = {0};
    malformed[4] = 100;  // payload_len = 100 (小端序低字节)
    process_network_frame(&rx, malformed, sizeof(malformed));
    printf("Processed %zu bytes\n", rx.used);
    return 0;
}

