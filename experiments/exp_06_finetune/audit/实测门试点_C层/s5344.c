#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 1024
#define HEADER_SIZE 8

typedef struct {
    uint16_t type;
    uint16_t length;
    uint32_t checksum;
} PacketHeader;

int parse_packet(const uint8_t *buffer, size_t buffer_size, char *output, size_t output_size) {
    if (buffer == NULL || output == NULL || buffer_size < HEADER_SIZE) {
        return -1;
    }

    PacketHeader header;
    memcpy(&header, buffer, HEADER_SIZE);

    if (header.length > MAX_PACKET_SIZE || header.length > buffer_size - HEADER_SIZE) {
        return -1;
    }

    if (header.length >= output_size) {
        return -1;
    }

    memcpy(output, buffer + HEADER_SIZE, header.length);
    output[header.length] = '\0';
    return 0;
}

int main() {
    uint8_t packet[MAX_PACKET_SIZE + HEADER_SIZE];
    char result[256];
    size_t received = 0;

    while (received < sizeof(packet)) {
        int chunk = 0;
        if (scanf("%d", &chunk) != 1 || chunk <= 0) {
            break;
        }
        if (received + chunk > sizeof(packet)) {
            break;
        }
        for (int i = 0; i < chunk; i++) {
            packet[received + i] = (uint8_t)(rand() % 256);
        }
        received += chunk;
    }

    if (parse_packet(packet, received, result, sizeof(result)) == 0) {
        printf("Parsed: %s\n", result);
    } else {
        printf("Parse failed\n");
    }
    return 0;
}

