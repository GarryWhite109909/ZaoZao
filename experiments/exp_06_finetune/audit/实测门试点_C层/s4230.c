#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_PAYLOAD_SIZE 1024

typedef struct {
    uint8_t header[4];
    uint16_t payload_length;
    uint8_t payload[MAX_PAYLOAD_SIZE];
} Packet;

int parse_packet(const uint8_t *data, size_t data_len, Packet *out) {
    if (data == NULL || out == NULL || data_len < 4) {
        return -1;
    }

    // Copy header (4 bytes)
    memcpy(out->header, data, 4);

    // Extract payload length from bytes 2-3 (big-endian)
    out->payload_length = (uint16_t)((data[2] << 8) | data[3]);

    // Validate payload length against buffer capacity
    if (out->payload_length > MAX_PAYLOAD_SIZE) {
        return -2;
    }

    // Check that we have at least the declared payload length
    if (data_len < (size_t)(4 + out->payload_length)) {
        return -3;
    }

    // Copy payload
    memcpy(out->payload, data + 4, out->payload_length);
    return 0;
}

int main(void) {
    uint8_t raw_data[20] = {0xAA, 0xBB, 0x00, 0x10};
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    int result = parse_packet(raw_data, sizeof(raw_data), &pkt);
    if (result == 0) {
        printf("Parsed: header=%02X%02X, payload_len=%u\n",
               pkt.header[0], pkt.header[1], pkt.payload_length);
    } else {
        printf("Parse failed with code %d\n", result);
    }
    return 0;
}

