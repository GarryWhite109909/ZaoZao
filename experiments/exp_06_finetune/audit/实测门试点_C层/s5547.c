#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_PKT_SIZE 512
#define HEADER_SIZE 4
#define MAX_PAYLOAD 128

typedef struct {
    uint8_t data[MAX_PKT_SIZE];
    size_t len;
} packet_t;

static int parse_packet(const uint8_t *buf, size_t buf_len, packet_t *out) {
    if (buf == NULL || out == NULL) {
        return -1;
    }
    if (buf_len < HEADER_SIZE) {
        return -2;
    }
    
    uint16_t payload_len = (uint16_t)((buf[0] << 8) | buf[1]);
    uint8_t flags = buf[2];
    uint8_t version = buf[3];
    
    if (version != 0x01) {
        return -3;
    }
    if (payload_len > MAX_PAYLOAD) {
        return -4;
    }
    if (buf_len < (size_t)HEADER_SIZE + payload_len) {
        return -5;
    }
    
    out->len = payload_len;
    memcpy(out->data, buf + HEADER_SIZE, payload_len);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }
    
    uint8_t buffer[MAX_PKT_SIZE];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);
    
    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    
    int ret = parse_packet(buffer, bytes_read, &pkt);
    if (ret != 0) {
        fprintf(stderr, "Parse error: %d\n", ret);
        return 1;
    }
    
    printf("Parsed packet: %zu bytes\n", pkt.len);
    for (size_t i = 0; i < pkt.len; i++) {
        printf("%02x ", pkt.data[i]);
    }
    printf("\n");
    return 0;
}

