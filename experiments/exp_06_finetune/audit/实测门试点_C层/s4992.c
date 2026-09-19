#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PKT_SIZE 1024
#define MAX_HEADER_SIZE 32

typedef struct {
    uint8_t data[MAX_PKT_SIZE];
    size_t len;
} packet_t;

int parse_packet(const uint8_t *raw, size_t raw_len, packet_t *out) {
    if (raw == NULL || out == NULL) {
        return -1;
    }
    if (raw_len > MAX_PKT_SIZE) {
        return -1;
    }
    
    size_t header_len = 0;
    if (raw_len < 4) {
        return -1;
    }
    header_len = (size_t)(raw[0] << 8 | raw[1]);
    
    if (header_len > MAX_HEADER_SIZE || header_len + 4 > raw_len) {
        return -1;
    }
    
    memset(out->data, 0, sizeof(out->data));
    memcpy(out->data, raw + header_len, raw_len - header_len);
    out->len = raw_len - header_len;
    
    return 0;
}

int main(void) {
    uint8_t raw_data[MAX_PKT_SIZE] = {0};
    size_t input_len = 0;
    
    printf("Enter packet size: ");
    if (scanf("%zu", &input_len) != 1 || input_len > MAX_PKT_SIZE) {
        return 1;
    }
    
    for (size_t i = 0; i < input_len; i++) {
        raw_data[i] = (uint8_t)(i * 3 + 1);
    }
    
    packet_t pkt;
    if (parse_packet(raw_data, input_len, &pkt) == 0) {
        printf("Parsed %zu bytes\n", pkt.len);
    } else {
        printf("Parse failed\n");
    }
    return 0;
}

