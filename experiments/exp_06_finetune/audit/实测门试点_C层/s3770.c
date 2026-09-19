#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PKT_LEN 1024

typedef struct {
    char *data;
    size_t len;
} packet_t;

int parse_packet(packet_t *pkt, const char *raw, size_t raw_len) {
    if (raw_len > MAX_PKT_LEN) {
        return -1;
    }
    pkt->data = (char *)malloc(raw_len + 1);
    if (!pkt->data) {
        return -1;
    }
    memcpy(pkt->data, raw, raw_len);
    pkt->data[raw_len] = '\0';
    pkt->len = raw_len;
    return 0;
}

int process_header(const char *raw, size_t raw_len) {
    if (raw_len < 4) {
        return -1;
    }
    char header[16];
    size_t copy_len = (raw_len < sizeof(header) - 1) ? raw_len : sizeof(header) - 1;
    memcpy(header, raw, copy_len);
    header[copy_len] = '\0';
    printf("Header: %s\n", header);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        return -1;
    }
    size_t input_len = strlen(argv[1]);
    if (input_len > MAX_PKT_LEN) {
        return -1;
    }
    packet_t pkt = {0};
    if (parse_packet(&pkt, argv[1], input_len) != 0) {
        return -1;
    }
    process_header(pkt.data, pkt.len);
    free(pkt.data);
    pkt.data = NULL;
    return 0;
}

