#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_LEN 1024
#define MAX_HEADER_LEN 64

typedef struct {
    uint8_t *data;
    size_t len;
} Packet;

static int parse_header(const uint8_t *buf, size_t buf_len, size_t *payload_offset) {
    if (buf_len < 2) {
        return -1;
    }
    uint16_t hdr_len = (uint16_t)((buf[0] << 8) | buf[1]);
    if (hdr_len > MAX_HEADER_LEN || hdr_len < 2) {
        return -1;
    }
    if (hdr_len > buf_len) {
        return -1;
    }
    *payload_offset = hdr_len;
    return 0;
}

static int process_packet(Packet *pkt) {
    size_t payload_offset = 0;
    if (parse_header(pkt->data, pkt->len, &payload_offset) != 0) {
        return -1;
    }
    
    size_t payload_len = pkt->len - payload_offset;
    char *payload_copy = (char *)malloc(payload_len + 1);
    if (payload_copy == NULL) {
        return -1;
    }
    
    memcpy(payload_copy, pkt->data + payload_offset, payload_len);
    payload_copy[payload_len] = '\0';
    
    printf("Payload: %s\n", payload_copy);
    free(payload_copy);
    payload_copy = NULL;
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        return 1;
    }
    
    uint8_t *buffer = (uint8_t *)malloc(MAX_PKT_LEN);
    if (buffer == NULL) {
        fclose(fp);
        return 1;
    }
    
    size_t bytes_read = fread(buffer, 1, MAX_PKT_LEN, fp);
    fclose(fp);
    
    if (bytes_read == 0 || bytes_read > MAX_PKT_LEN) {
        free(buffer);
        return 1;
    }
    
    Packet pkt = { buffer, bytes_read };
    int result = process_packet(&pkt);
    
    free(buffer);
    buffer = NULL;
    return result;
}

