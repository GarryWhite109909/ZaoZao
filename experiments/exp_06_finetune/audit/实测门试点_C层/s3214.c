#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_PKT_SIZE 256
#define HEADER_SIZE 4

typedef struct {
    uint8_t data[MAX_PKT_SIZE];
    uint16_t len;
} packet_t;

static int process_payload(const uint8_t *payload, uint16_t payload_len) {
    // line 13: payload_len is bounded by caller, but double-check for defense-in-depth
    if (payload_len > MAX_PKT_SIZE - HEADER_SIZE) {
        return -1;
    }
    
    uint8_t *buffer = (uint8_t *)malloc(payload_len);
    if (!buffer) {
        return -2;
    }
    
    memcpy(buffer, payload, payload_len);
    
    // Simulate processing
    uint32_t checksum = 0;
    for (uint16_t i = 0; i < payload_len; i++) {
        checksum += buffer[i];
    }
    
    free(buffer);
    buffer = NULL;  // line 31: prevent dangling pointer
    
    return (int)(checksum % 100);
}

int handle_packet(packet_t *pkt) {
    if (!pkt || pkt->len > MAX_PKT_SIZE) {
        return -3;
    }
    
    // line 39: validate header length before parsing
    if (pkt->len < HEADER_SIZE) {
        return -4;
    }
    
    uint16_t payload_len = pkt->len - HEADER_SIZE;
    
    // line 44: payload_len is always < MAX_PKT_SIZE due to pkt->len check
    return process_payload(pkt->data + HEADER_SIZE, payload_len);
}

int main(void) {
    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    
    // Simulate receiving a packet
    pkt.len = 10;  // header(4) + payload(6)
    memcpy(pkt.data, "\x01\x02\x03\x04", HEADER_SIZE);
    memcpy(pkt.data + HEADER_SIZE, "abcdef", 6);
    
    int result = handle_packet(&pkt);
    printf("Result: %d\n", result);
    return 0;
}

