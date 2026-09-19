#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PACKET_SIZE 1024
#define MAX_FIELD_LEN 64

typedef struct {
    char header[16];
    char payload[512];
    size_t payload_len;
} Packet;

int parse_packet(const char *data, size_t data_len, Packet *out) {
    if (!data || !out || data_len < sizeof(out->header)) {
        return -1;
    }

    memcpy(out->header, data, sizeof(out->header));
    out->header[sizeof(out->header) - 1] = '\0';

    if (data_len > sizeof(out->payload)) {
        return -1;
    }

    size_t payload_start = sizeof(out->header);
    size_t payload_len = data_len - payload_start;

    // line 20: potential buffer overflow - no check against sizeof(out->payload)
    memcpy(out->payload, data + payload_start, payload_len);
    out->payload[payload_len] = '\0';
    out->payload_len = payload_len;

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    char *buf = (char *)malloc(MAX_PACKET_SIZE);
    if (!buf) {
        fclose(fp);
        return 1;
    }

    size_t n = fread(buf, 1, MAX_PACKET_SIZE, fp);
    fclose(fp);

    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    if (parse_packet(buf, n, &pkt) == 0) {
        printf("Parsed packet: header=%s, payload_len=%zu\n", pkt.header, pkt.payload_len);
    } else {
        printf("Failed to parse packet\n");
    }

    free(buf);
    return 0;
}

