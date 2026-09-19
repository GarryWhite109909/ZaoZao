#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PAYLOAD 256
#define HEADER_SIZE 8

typedef struct {
    uint16_t type;
    uint16_t length;
    uint32_t seq;
} PacketHeader;

int process_packet(const uint8_t *buffer, size_t buffer_size) {
    PacketHeader hdr;
    uint8_t payload[MAX_PAYLOAD];
    
    if (buffer_size < HEADER_SIZE) {
        return -1;
    }
    
    memcpy(&hdr, buffer, HEADER_SIZE);
    hdr.length = ntohs(hdr.length);
    
    if (hdr.length > MAX_PAYLOAD) {
        return -2;
    }
    
    // 注意：这里缺少对 buffer_size - HEADER_SIZE 的检查
    memcpy(payload, buffer + HEADER_SIZE, hdr.length);
    
    // 模拟协议处理
    for (int i = 0; i < hdr.length; i++) {
        payload[i] = payload[i] ^ 0x5A;
    }
    
    return hdr.length;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    
    uint8_t buffer[512];
    size_t n = fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);
    
    if (n > 0) {
        int result = process_packet(buffer, n);
        printf("Processed %d bytes\n", result);
    }
    
    return 0;
}

