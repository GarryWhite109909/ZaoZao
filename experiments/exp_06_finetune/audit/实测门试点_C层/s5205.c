#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint16_t length;
    uint8_t *data;
} Packet;

int process_packet(const uint8_t *buffer, size_t buffer_size) {
    if (buffer_size < sizeof(uint16_t)) {
        return -1;
    }

    uint16_t length;
    memcpy(&length, buffer, sizeof(uint16_t));
    length = ntohs(length);

    if (length > buffer_size - sizeof(uint16_t)) {
        return -2;
    }

    Packet *packet = malloc(sizeof(Packet));
    if (!packet) {
        return -3;
    }

    packet->length = length;
    packet->data = malloc(length);
    if (!packet->data) {
        free(packet);
        return -4;
    }

    memcpy(packet->data, buffer + sizeof(uint16_t), length);

    // Process packet data
    for (size_t i = 0; i < packet->length; i++) {
        if (packet->data[i] == 0x00) {
            // Simulate some protocol handling
            packet->data[i] = 0xFF;
        }
    }

    // Cleanup
    free(packet->data);
    free(packet);
    return 0;
}

int main() {
    uint8_t buffer[1024] = {0};
    size_t buffer_size = 1024;

    // Simulate network receive
    buffer[0] = 0x00;
    buffer[1] = 0x10;  // length = 16

    int result = process_packet(buffer, buffer_size);
    printf("Result: %d\n", result);
    return 0;
}

