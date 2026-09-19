#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_SIZE 1024
#define MAX_FIELDS 16

typedef struct {
    uint16_t field_count;
    uint16_t offsets[MAX_FIELDS];
} PktHeader;

int parse_packet(const uint8_t *buf, size_t len, PktHeader *hdr) {
    if (len < sizeof(uint16_t)) {
        return -1;
    }
    
    memcpy(&hdr->field_count, buf, sizeof(uint16_t));
    hdr->field_count = ntohs(hdr->field_count);
    
    if (hdr->field_count > MAX_FIELDS) {
        return -1;
    }
    
    size_t offset_pos = sizeof(uint16_t);
    for (int i = 0; i < hdr->field_count; i++) {
        if (offset_pos + sizeof(uint16_t) > len) {
            return -1;
        }
        uint16_t raw_offset;
        memcpy(&raw_offset, buf + offset_pos, sizeof(uint16_t));
        hdr->offsets[i] = ntohs(raw_offset);
        offset_pos += sizeof(uint16_t);
    }
    
    return 0;
}

int process_packet(const uint8_t *data, size_t data_len) {
    PktHeader hdr;
    uint8_t *field_buf = NULL;
    
    if (parse_packet(data, data_len, &hdr) != 0) {
        return -1;
    }
    
    size_t total_size = 0;
    for (int i = 0; i < hdr.field_count; i++) {
        if (hdr.offsets[i] > MAX_PKT_SIZE) {
            return -1;
        }
        total_size += hdr.offsets[i];
    }
    
    field_buf = (uint8_t *)malloc(total_size);
    if (!field_buf) {
        return -1;
    }
    
    size_t copy_pos = 0;
    for (int i = 0; i < hdr.field_count; i++) {
        uint16_t field_len = hdr.offsets[i];
        if (copy_pos + field_len > total_size) {
            free(field_buf);
            return -1;
        }
        memcpy(field_buf + copy_pos, data + sizeof(uint16_t) + (i * sizeof(uint16_t)), field_len);
        copy_pos += field_len;
    }
    
    printf("Processed %d fields\n", hdr.field_count);
    free(field_buf);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        return 1;
    }
    
    uint8_t pkt[MAX_PKT_SIZE];
    size_t pkt_len = fread(pkt, 1, sizeof(pkt), fp);
    fclose(fp);
    
    if (process_packet(pkt, pkt_len) != 0) {
        fprintf(stderr, "Packet processing failed\n");
        return 1;
    }
    
    return 0;
}

