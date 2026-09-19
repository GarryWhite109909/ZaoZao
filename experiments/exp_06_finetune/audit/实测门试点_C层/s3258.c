#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PACKET_SIZE 1024

typedef struct {
    char *payload;
    size_t payload_len;
    int parsed;
} Packet;

int parse_packet(char *buffer, size_t len, Packet *pkt) {
    if (!buffer || !pkt || len > MAX_PACKET_SIZE) {
        return -1;
    }

    pkt->payload = (char *)malloc(len + 1);
    if (!pkt->payload) {
        return -1;
    }

    memcpy(pkt->payload, buffer, len);
    pkt->payload[len] = '\0';
    pkt->payload_len = len;
    pkt->parsed = 0;

    // Simulate protocol parsing: extract first 4 bytes as header
    if (len < 4) {
        free(pkt->payload);
        pkt->payload = NULL;
        pkt->payload_len = 0;
        return -2;
    }

    uint32_t header = *(uint32_t *)pkt->payload;
    if (header == 0xDEADBEEF) {
        pkt->parsed = 1;
    }
    return 0;
}

int process_packet(char *buffer, size_t len) {
    Packet pkt = {0};  // Zero-initialize to avoid garbage pointers
    int ret = parse_packet(buffer, len, &pkt);
    if (ret != 0) {
        // pkt.payload is either NULL or already freed by parse_packet
        return ret;
    }

    if (pkt.parsed) {
        printf("Parsed packet: %s\n", pkt.payload);
    }

    free(pkt.payload);
    pkt.payload = NULL;  // Prevent double-free if process_packet is called again
    return 0;
}

int main() {
    char buffer[MAX_PACKET_SIZE] = {0};
    size_t len = fread(buffer, 1, sizeof(buffer), stdin);
    return process_packet(buffer, len);
}

