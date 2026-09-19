#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 1024
#define HEADER_SIZE 8
#define MAX_PAYLOAD_SIZE (MAX_PACKET_SIZE - HEADER_SIZE)

typedef struct {
    uint16_t type;
    uint16_t length;
    uint32_t checksum;
    uint8_t payload[MAX_PAYLOAD_SIZE];
} Packet;

int parse_packet(const uint8_t *buffer, size_t buffer_len, Packet *out) {
    if (buffer == NULL || out == NULL) {
        return -1;
    }
    
    if (buffer_len < HEADER_SIZE) {
        return -1;
    }
    
    uint16_t payload_len = (uint16_t)((buffer[2] << 8) | buffer[3]);
    
    if (payload_len > MAX_PAYLOAD_SIZE) {
        return -1;
    }
    
    if (buffer_len < HEADER_SIZE + payload_len) {
        return -1;
    }
    
    out->type = (uint16_t)((buffer[0] << 8) | buffer[1]);
    out->length = payload_len;
    out->checksum = (uint32_t)((buffer[4] << 24) | (buffer[5] << 16) | 
                               (buffer[6] << 8) | buffer[7]);
    
    memcpy(out->payload, buffer + HEADER_SIZE, payload_len);
    
    if (out->checksum != 0) {
        uint32_t calc = 0;
        for (int i = 0; i < payload_len; i++) {
            calc += out->payload[i];
        }
        if (calc != out->checksum) {
            return -1;
        }
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <packet_file>\n", argv[0]);
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }
    
    uint8_t buffer[MAX_PACKET_SIZE];
    size_t read_len = fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);
    
    if (read_len == 0) {
        printf("Empty file\n");
        return 1;
    }
    
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    
    if (parse_packet(buffer, read_len, &pkt) == 0) {
        printf("Packet parsed: type=%u, len=%u\n", pkt.type, pkt.length);
    } else {
        printf("Invalid packet\n");
    }
    
    return 0;
}

