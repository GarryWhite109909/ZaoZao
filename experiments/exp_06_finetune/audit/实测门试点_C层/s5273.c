#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_FRAME_SIZE 256
#define HEADER_SIZE 8

typedef struct {
    uint8_t data[MAX_FRAME_SIZE];
    size_t length;
} FrameBuffer;

int parse_frame(const uint8_t *raw, size_t raw_len, FrameBuffer *out) {
    if (raw == NULL || out == NULL) {
        return -1;
    }
    if (raw_len < HEADER_SIZE) {
        return -2;  // 帧头不完整
    }
    
    // 从帧头解析负载长度（小端序）
    uint16_t payload_len = raw[0] | (raw[1] << 8);
    
    // 防御1：负载长度必须大于0且不超过缓冲区剩余空间
    if (payload_len == 0 || payload_len > MAX_FRAME_SIZE - HEADER_SIZE) {
        return -3;
    }
    
    // 防御2：完整帧长度必须匹配实际接收长度
    if (payload_len + HEADER_SIZE != raw_len) {
        return -4;
    }
    
    // 防御3：逐字节拷贝，确保不越界（memcpy已由长度校验保护）
    memcpy(out->data, raw + HEADER_SIZE, payload_len);
    out->length = payload_len;
    
    return 0;
}

int main(void) {
    uint8_t packet[] = {0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    FrameBuffer buf = {0};
    
    if (parse_frame(packet, sizeof(packet), &buf) == 0) {
        printf("Parsed %zu bytes\n", buf.length);
    } else {
        printf("Parse failed\n");
    }
    return 0;
}

