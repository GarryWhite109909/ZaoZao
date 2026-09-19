#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 1024
#define HEADER_SIZE 8

typedef struct {
    uint8_t version;
    uint8_t type;
    uint16_t length;
    uint32_t checksum;
} PacketHeader;

int parse_packet(const uint8_t *buffer, size_t buffer_size) {
    if (buffer == NULL || buffer_size < HEADER_SIZE) {
        return -1;
    }

    PacketHeader header;
    memcpy(&header, buffer, HEADER_SIZE);
    header.length = ntohs(header.length);

    // line 19: Validate declared length against actual buffer size
    if (header.length > buffer_size - HEADER_SIZE) {
        return -1;
    }

    char *payload = (char *)malloc(header.length + 1);
    if (payload == NULL) {
        return -1;
    }

    // line 27: Bounded copy - length already validated, +1 for null terminator
    memcpy(payload, buffer + HEADER_SIZE, header.length);
    payload[header.length] = '\0';

    // Process payload...
    printf("Payload: %s\n", payload);

    free(payload);
    // line 36: Payload pointer set to NULL after free to prevent use-after-free
    payload = NULL;

    return 0;
}

int main() {
    uint8_t packet[MAX_PACKET_SIZE];
    size_t received = 0;

    // Simulate receiving a packet from network
    received = fread(packet, 1, sizeof(packet), stdin);
    if (received == 0) {
        return -1;
    }

    return parse_packet(packet, received);
}

