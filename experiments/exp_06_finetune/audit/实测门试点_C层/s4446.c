#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_PKT_LEN 1024
#define MAX_HDR_LEN 64
#define MAX_PAYLOAD 512

typedef struct {
    uint8_t *data;
    size_t len;
} Packet;

static int parse_header(const uint8_t *buf, size_t buf_len, size_t *payload_len) {
    if (buf_len < 8) {
        return -1;
    }
    uint16_t type = (buf[0] << 8) | buf[1];
    uint32_t declared_len = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];

    if (type != 0x0102) {
        return -1;
    }
    if (declared_len > MAX_PAYLOAD) {
        return -1;
    }
    *payload_len = (size_t)declared_len;
    return 0;
}

static int process_packet(const uint8_t *raw, size_t raw_len) {
    Packet pkt;
    size_t payload_len = 0;

    if (raw_len > MAX_PKT_LEN) {
        return -1;
    }

    if (parse_header(raw, raw_len, &payload_len) != 0) {
        return -1;
    }

    pkt.len = payload_len;
    pkt.data = (uint8_t *)malloc(payload_len);
    if (pkt.data == NULL) {
        return -1;
    }

    /* Copy payload after 8-byte header */
    memcpy(pkt.data, raw + 8, payload_len);

    /* Simulate processing */
    for (size_t i = 0; i < pkt.len; i++) {
        pkt.data[i] = (uint8_t)(pkt.data[i] ^ 0x5A);
    }

    free(pkt.data);
    pkt.data = NULL;
    return 0;
}

int main(int argc, char **argv) {
    uint8_t packet[MAX_PKT_LEN];
    size_t len = fread(packet, 1, sizeof(packet), stdin);
    if (len == 0) {
        return -1;
    }
    return process_packet(packet, len);
}

