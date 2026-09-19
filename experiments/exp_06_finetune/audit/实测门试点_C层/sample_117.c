#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_LEN 1024
#define MAX_HEADER_LEN 64

typedef struct {
    uint8_t *data;
    size_t len;
    uint8_t type;
} packet_t;

packet_t *parse_packet(const uint8_t *buf, size_t buf_len) {
    if (buf_len < sizeof(uint8_t) + sizeof(uint16_t)) {
        return NULL;
    }

    packet_t *pkt = (packet_t *)malloc(sizeof(packet_t));
    if (!pkt) {
        return NULL;
    }

    pkt->type = buf[0];
    uint16_t payload_len;
    memcpy(&payload_len, buf + 1, sizeof(uint16_t));
    payload_len = ntohs(payload_len);

    if (payload_len > MAX_PKT_LEN || payload_len > buf_len - 3) {
        free(pkt);
        return NULL;
    }

    pkt->data = (uint8_t *)malloc(payload_len);
    if (!pkt->data) {
        free(pkt);
        return NULL;
    }

    memcpy(pkt->data, buf + 3, payload_len);
    pkt->len = payload_len;
    return pkt;
}

void process_packet(packet_t *pkt) {
    if (!pkt) return;

    if (pkt->type == 0x01) {
        printf("Processing control packet, len=%zu\n", pkt->len);
        free(pkt->data);
        free(pkt);
        return;
    }

    if (pkt->type == 0x02) {
        printf("Processing data packet, len=%zu\n", pkt->len);
        return;
    }

    printf("Unknown packet type: 0x%02x\n", pkt->type);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <hex_packet>\n", argv[0]);
        return 1;
    }

    size_t hex_len = strlen(argv[1]);
    if (hex_len % 2 != 0 || hex_len / 2 > MAX_PKT_LEN) {
        fprintf(stderr, "Invalid hex input\n");
        return 1;
    }

    uint8_t buf[MAX_PKT_LEN];
    size_t buf_len = 0;
    for (size_t i = 0; i < hex_len; i += 2) {
        unsigned int byte;
        if (sscanf(argv[1] + i, "%2x", &byte) != 1) {
            fprintf(stderr, "Invalid hex digit\n");
            return 1;
        }
        buf[buf_len++] = (uint8_t)byte;
    }

    packet_t *pkt = parse_packet(buf, buf_len);
    if (!pkt) {
        fprintf(stderr, "Failed to parse packet\n");
        return 1;
    }

    process_packet(pkt);

    if (pkt->type != 0x01) {
        free(pkt->data);
        free(pkt);
    }

    return 0;
}

