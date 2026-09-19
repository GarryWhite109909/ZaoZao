#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 1024
#define MAX_HEADER_SIZE 64

typedef struct {
    uint8_t data[MAX_PACKET_SIZE];
    size_t len;
} packet_t;

int parse_packet_header(const uint8_t *buffer, size_t buffer_len, char *header_out, size_t header_out_size) {
    if (buffer == NULL || header_out == NULL) {
        return -1;
    }

    if (buffer_len < 2) {
        return -1;
    }

    uint16_t header_len = (uint16_t)((buffer[0] << 8) | buffer[1]);

    // Header length validation: must be within bounds
    if (header_len > MAX_HEADER_SIZE || header_len > buffer_len) {
        return -1;
    }

    // Ensure destination buffer has enough space
    if (header_out_size < header_len + 1) {
        return -1;
    }

    // Safe copy with explicit bounds
    memcpy(header_out, buffer + 2, header_len);
    header_out[header_len] = '\0';

    return 0;
}

int process_network_packet(const uint8_t *packet, size_t packet_len) {
    char header[MAX_HEADER_SIZE + 1];
    int ret;

    if (packet == NULL || packet_len == 0 || packet_len > MAX_PACKET_SIZE) {
        return -1;
    }

    ret = parse_packet_header(packet, packet_len, header, sizeof(header));
    if (ret != 0) {
        return -1;
    }

    // Header is now safely null-terminated and within bounds
    printf("Parsed header: %s\n", header);
    return 0;
}

int main(void) {
    uint8_t test_packet[] = {0x00, 0x05, 'H', 'E', 'L', 'L', 'O'};
    process_network_packet(test_packet, sizeof(test_packet));
    return 0;
}

