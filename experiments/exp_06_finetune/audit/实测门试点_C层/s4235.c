#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 1024
#define HEADER_SIZE 8

typedef struct {
    uint16_t type;
    uint16_t length;
    uint32_t seq;
} PacketHeader;

int parse_packet(const uint8_t *data, size_t data_len, char *output, size_t out_size) {
    if (data == NULL || output == NULL) {
        return -1;
    }

    if (data_len < HEADER_SIZE) {
        return -1;
    }

    PacketHeader header;
    memcpy(&header, data, HEADER_SIZE);

    if (header.length > data_len - HEADER_SIZE) {
        return -1;
    }

    if (header.length > out_size - 1) {
        return -1;
    }

    memcpy(output, data + HEADER_SIZE, header.length);
    output[header.length] = '\0';

    return 0;
}

int main() {
    uint8_t buffer[MAX_PACKET_SIZE];
    char result[256] = {0};
    size_t recv_len = 0;

    // Simulate network receive
    recv_len = fread(buffer, 1, sizeof(buffer), stdin);
    if (recv_len == 0) {
        return 1;
    }

    if (parse_packet(buffer, recv_len, result, sizeof(result)) != 0) {
        fprintf(stderr, "Invalid packet\n");
        return 1;
    }

    printf("Received: %s\n", result);
    return 0;
}

