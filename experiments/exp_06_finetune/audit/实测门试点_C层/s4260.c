#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_SIZE 1024
#define HEADER_SIZE 8
#define MAX_PAYLOAD 512

typedef struct {
    uint8_t *data;
    size_t len;
} Packet;

static int parse_header(const uint8_t *buf, size_t buf_len, uint32_t *payload_len) {
    if (buf_len < HEADER_SIZE) {
        return -1;
    }
    /* line 15: payload length comes from network bytes */
    *payload_len = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
    return 0;
}

static int process_packet(Packet *pkt) {
    uint32_t payload_len = 0;
    uint8_t *payload = NULL;

    if (parse_header(pkt->data, pkt->len, &payload_len) != 0) {
        return -1;
    }

    /* line 25: critical bound check before allocation */
    if (payload_len > MAX_PAYLOAD || pkt->len < HEADER_SIZE + payload_len) {
        return -1;
    }

    payload = (uint8_t *)malloc(payload_len);
    if (payload == NULL) {
        return -1;
    }

    /* line 33: safe copy - length validated against both source and dest */
    memcpy(payload, pkt->data + HEADER_SIZE, payload_len);

    /* simulate protocol processing */
    for (size_t i = 0; i < payload_len; i++) {
        payload[i] = payload[i] ^ 0x5A;
    }

    free(payload);
    payload = NULL;  /* line 43: NULL after free to prevent use-after-free */
    return 0;
}

int main(void) {
    uint8_t raw[64] = {0};
    Packet pkt = {raw, sizeof(raw)};
    
    /* craft a valid header: length = 16 bytes */
    raw[4] = 0;
    raw[5] = 0;
    raw[6] = 0;
    raw[7] = 16;

    return process_packet(&pkt);
}

