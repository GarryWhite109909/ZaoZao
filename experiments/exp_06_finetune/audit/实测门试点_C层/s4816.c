#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 1024
#define HEADER_SIZE 8

typedef struct {
    uint8_t *data;
    size_t length;
} Packet;

int parse_packet(const uint8_t *raw_data, size_t raw_len, Packet *out) {
    if (raw_data == NULL || out == NULL) {
        return -1;
    }
    
    if (raw_len < HEADER_SIZE) {
        return -1;
    }
    
    // Extract payload length from header (bytes 4-7, big-endian)
    uint32_t payload_len = 0;
    for (int i = 0; i < 4; i++) {
        payload_len = (payload_len << 8) | raw_data[4 + i];
    }
    
    // Validate payload length against actual remaining data
    if (payload_len > raw_len - HEADER_SIZE) {
        return -1;
    }
    
    // Allocate exactly payload_len bytes
    uint8_t *payload = (uint8_t *)malloc(payload_len);
    if (payload == NULL) {
        return -1;
    }
    
    // Copy payload with verified length
    memcpy(payload, raw_data + HEADER_SIZE, payload_len);
    
    out->data = payload;
    out->length = payload_len;
    return 0;
}

void free_packet(Packet *pkt) {
    if (pkt != NULL) {
        free(pkt->data);
        pkt->data = NULL;
        pkt->length = 0;
    }
}

int main() {
    uint8_t buffer[MAX_PACKET_SIZE];
    size_t received = 0;
    
    // Simulate receiving a network packet
    received = fread(buffer, 1, sizeof(buffer), stdin);
    if (received == 0) {
        return 1;
    }
    
    Packet pkt = {0};
    if (parse_packet(buffer, received, &pkt) == 0) {
        printf("Parsed %zu bytes of payload\n", pkt.length);
        free_packet(&pkt);
    }
    return 0;
}

