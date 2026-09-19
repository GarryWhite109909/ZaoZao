#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 1024

typedef struct {
    uint8_t *data;
    size_t len;
} packet_t;

int process_packet(packet_t *pkt) {
    if (!pkt || !pkt->data) {
        return -1;
    }

    // Line 14: Validate packet length before any access
    if (pkt->len > MAX_PACKET_SIZE) {
        return -2;
    }

    // Line 17: Copy to a fixed-size buffer with bounds check
    uint8_t buffer[MAX_PACKET_SIZE];
    memcpy(buffer, pkt->data, pkt->len);

    // Line 20: Parse header (4 bytes: type + length)
    if (pkt->len < 4) {
        return -3;
    }

    uint16_t type = (buffer[0] << 8) | buffer[1];
    uint16_t payload_len = (buffer[2] << 8) | buffer[3];

    // Line 26: Validate payload length against remaining space
    if (payload_len > pkt->len - 4) {
        return -4;
    }

    // Line 29: Process payload safely
    uint8_t *payload = buffer + 4;
    uint8_t checksum = 0;
    for (size_t i = 0; i < payload_len; i++) {
        checksum ^= payload[i];
    }

    // Line 34: Store result in caller-provided buffer
    pkt->data = malloc(payload_len);
    if (!pkt->data) {
        return -5;
    }

    // Line 38: Copy payload with exact length
    memcpy(pkt->data, payload, payload_len);
    pkt->len = payload_len;

    return (checksum == 0) ? 0 : 1;
}

void free_packet(packet_t *pkt) {
    if (pkt) {
        free(pkt->data);
        pkt->data = NULL;  // Line 46: Prevent dangling pointer
        pkt->len = 0;
    }
}

int main(void) {
    uint8_t raw[] = {0x00, 0x01, 0x00, 0x02, 0xAB, 0xCD};
    packet_t pkt = {raw, sizeof(raw)};
    int result = process_packet(&pkt);
    
    if (result == 0) {
        printf("Packet processed: %zu bytes\n", pkt.len);
    }
    
    free_packet(&pkt);
    return 0;
}

