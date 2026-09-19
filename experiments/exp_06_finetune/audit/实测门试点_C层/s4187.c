#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_PKT_LEN 1024
#define HDR_SIZE 8

typedef struct {
    uint16_t type;
    uint16_t length;
    uint32_t seq;
} PktHeader;

int parse_packet(const uint8_t *buf, size_t buf_len) {
    if (buf == NULL || buf_len < HDR_SIZE) {
        return -1;
    }

    PktHeader hdr;
    memcpy(&hdr, buf, HDR_SIZE);
    hdr.length = ntohs(hdr.length);

    if (hdr.length > MAX_PKT_LEN || hdr.length > buf_len - HDR_SIZE) {
        return -2;
    }

    uint8_t *payload = (uint8_t *)malloc(hdr.length);
    if (payload == NULL) {
        return -3;
    }

    memcpy(payload, buf + HDR_SIZE, hdr.length);

    uint8_t stack_buf[64];
    if (hdr.length <= sizeof(stack_buf)) {
        memcpy(stack_buf, payload, hdr.length);
        printf("Payload: %s\n", stack_buf);
    } else {
        printf("Payload too large for stack buffer\n");
    }

    free(payload);
    return 0;
}

int main(void) {
    uint8_t pkt[MAX_PKT_LEN + HDR_SIZE];
    size_t len = fread(pkt, 1, sizeof(pkt), stdin);
    return parse_packet(pkt, len);
}

