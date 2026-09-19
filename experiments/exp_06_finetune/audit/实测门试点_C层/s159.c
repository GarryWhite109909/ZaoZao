#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_SIZE 256
#define MAX_FIELDS 8

typedef struct {
    uint16_t len;
    uint8_t data[MAX_PKT_SIZE];
} packet_t;

typedef struct {
    uint8_t field_count;
    uint16_t field_offsets[MAX_FIELDS];
} pkt_meta_t;

int parse_packet(const uint8_t *raw, size_t raw_len, pkt_meta_t *meta) {
    if (raw_len < 2 || raw_len > MAX_PKT_SIZE) {
        return -1;
    }

    meta->field_count = raw[0];
    if (meta->field_count > MAX_FIELDS) {
        return -1;
    }

    size_t offset = 1;
    for (int i = 0; i < meta->field_count; i++) {
        if (offset + 2 > raw_len) {
            return -1;
        }
        uint16_t field_len = (raw[offset] << 8) | raw[offset + 1];
        offset += 2;

        if (offset + field_len > raw_len) {
            return -1;
        }

        meta->field_offsets[i] = offset;
        offset += field_len;
    }

    return 0;
}

int process_packet(packet_t *pkt, size_t pkt_len) {
    pkt_meta_t meta;
    if (parse_packet(pkt->data, pkt_len, &meta) != 0) {
        return -1;
    }

    for (int i = 0; i < meta.field_count; i++) {
        uint16_t foff = meta.field_offsets[i];
        uint8_t header = pkt->data[foff];

        if (header == 0x01) {
            uint16_t value = (pkt->data[foff + 1] << 8) | pkt->data[foff + 2];
            printf("Field %d: %u\n", i, value);
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) return 1;

    packet_t pkt;
    size_t n = fread(pkt.data, 1, MAX_PKT_SIZE, fp);
    fclose(fp);

    if (n < 2) return 1;

    process_packet(&pkt, n);
    return 0;
}

