#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 1024
#define HEADER_SIZE 8

typedef struct {
    uint16_t type;
    uint16_t length;
    uint32_t seq;
} PacketHeader;

int parse_packet(const uint8_t *buffer, size_t buffer_size) {
    if (buffer_size < HEADER_SIZE) {
        return -1;
    }
    
    PacketHeader header;
    memcpy(&header, buffer, HEADER_SIZE);
    
    // Validate header fields
    if (header.type != 0x01 && header.type != 0x02) {
        return -2;
    }
    
    size_t payload_length = (size_t)header.length;
    if (payload_length > buffer_size - HEADER_SIZE) {
        return -3;
    }
    
    // Allocate exactly payload_length bytes
    uint8_t *payload = (uint8_t *)malloc(payload_length);
    if (payload == NULL) {
        return -4;
    }
    
    // Copy payload data
    memcpy(payload, buffer + HEADER_SIZE, payload_length);
    
    // Process payload based on type
    if (header.type == 0x01) {
        // Type 1: payload contains a null-terminated string
        if (payload_length > 0) {
            payload[payload_length - 1] = '\0';
            printf("String: %s\n", (char *)payload);
        }
    } else {
        // Type 2: payload contains raw data
        printf("Raw data (%zu bytes)\n", payload_length);
    }
    
    free(payload);
    payload = NULL;
    
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <packet_file>\n", argv[0]);
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }
    
    uint8_t buffer[MAX_PACKET_SIZE];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);
    
    if (bytes_read == 0) {
        fprintf(stderr, "Empty file\n");
        return 1;
    }
    
    return parse_packet(buffer, bytes_read);
}

