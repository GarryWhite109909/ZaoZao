#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    size_t len;
    int parsed;
} Packet;

static Packet *packet_create(const uint8_t *buf, size_t buflen) {
    Packet *pkt = (Packet *)malloc(sizeof(Packet));
    if (!pkt) return NULL;
    pkt->data = (uint8_t *)malloc(buflen);
    if (!pkt->data) {
        free(pkt);
        return NULL;
    }
    memcpy(pkt->data, buf, buflen);
    pkt->len = buflen;
    pkt->parsed = 0;
    return pkt;
}

static void packet_destroy(Packet *pkt) {
    if (!pkt) return;
    if (pkt->data) {
        free(pkt->data);
        pkt->data = NULL;  // line 24: NULL after free
    }
    free(pkt);
}

static int parse_header(Packet *pkt, size_t *payload_len) {
    if (!pkt || !pkt->data || pkt->len < 4) return -1;  // line 29: bounds check
    uint32_t hdr = 0;
    memcpy(&hdr, pkt->data, 4);
    *payload_len = hdr & 0xFFFF;  // max 65535
    pkt->parsed = 1;
    return 0;
}

static int process_packet(const uint8_t *buf, size_t buflen) {
    Packet *pkt = packet_create(buf, buflen);
    if (!pkt) return -1;

    size_t payload_len = 0;
    if (parse_header(pkt, &payload_len) != 0) {
        packet_destroy(pkt);
        return -1;
    }

    // Simulate protocol processing with early exit
    if (payload_len > pkt->len - 4) {
        packet_destroy(pkt);
        return -1;
    }

    // Use parsed data (safe)
    printf("Payload length: %zu\n", payload_len);

    packet_destroy(pkt);  // line 53: single cleanup point
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    size_t len = strlen(argv[1]);
    if (len > 1024) return 1;  // line 60: input size limit
    return process_packet((const uint8_t *)argv[1], len);
}

