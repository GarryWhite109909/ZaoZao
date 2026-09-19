#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_PKT_SIZE 1024
#define MAX_HEADER_LEN 64

typedef struct {
    uint8_t *data;
    size_t len;
} packet_t;

static int parse_header(const uint8_t *buf, size_t buf_len, char *out, size_t out_size) {
    if (buf_len < 2) {
        return -1;
    }
    uint16_t hdr_len = (uint16_t)((buf[0] << 8) | buf[1]);
    if (hdr_len > MAX_HEADER_LEN || hdr_len < 2) {
        return -1;
    }
    if (buf_len < hdr_len) {
        return -1;
    }
    if (out_size < hdr_len) {
        return -1;
    }
    memcpy(out, buf + 2, hdr_len - 2);
    out[hdr_len - 2] = '\0';
    return 0;
}

int process_packet(packet_t *pkt) {
    if (!pkt || !pkt->data || pkt->len == 0 || pkt->len > MAX_PKT_SIZE) {
        return -1;
    }
    char header[MAX_HEADER_LEN] = {0};
    if (parse_header(pkt->data, pkt->len, header, sizeof(header)) != 0) {
        return -1;
    }
    printf("Header: %s\n", header);
    return 0;
}

int main(void) {
    uint8_t raw_data[MAX_PKT_SIZE];
    size_t raw_len = fread(raw_data, 1, sizeof(raw_data), stdin);
    if (raw_len == 0) {
        return 1;
    }
    packet_t pkt = {raw_data, raw_len};
    return process_packet(&pkt);
}

