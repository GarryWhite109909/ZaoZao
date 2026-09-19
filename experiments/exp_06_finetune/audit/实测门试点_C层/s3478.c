#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 1024
#define HEADER_SIZE 4

typedef struct {
    uint16_t type;
    uint16_t length;
    uint8_t data[];
} __attribute__((packed)) Packet;

int parse_packet(const uint8_t *buffer, size_t buffer_len) {
    if (buffer_len < HEADER_SIZE) {
        return -1;
    }

    Packet *pkt = (Packet *)buffer;
    uint16_t payload_len = ntohs(pkt->length);

    // line 21: 核心边界检查 - 验证声明长度与实际缓冲区长度
    if (payload_len > buffer_len - HEADER_SIZE) {
        return -1;
    }

    char *payload = (char *)malloc(payload_len + 1);
    if (!payload) {
        return -1;
    }

    // line 29: 使用验证后的长度进行拷贝，杜绝栈溢出
    memcpy(payload, pkt->data, payload_len);
    payload[payload_len] = '\0';

    printf("Packet type: %u, payload: %s\n", ntohs(pkt->type), payload);
    free(payload);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        return 1;
    }

    uint8_t buffer[MAX_PACKET_SIZE];
    size_t bytes_read = fread(buffer, 1, MAX_PACKET_SIZE, fp);
    fclose(fp);

    if (bytes_read == 0) {
        return 1;
    }

    return parse_packet(buffer, bytes_read);
}

