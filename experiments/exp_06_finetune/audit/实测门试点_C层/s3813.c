#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PKT_SIZE 1024
#define MAX_HEADER_SIZE 64

typedef struct {
    char *data;
    int length;
} Packet;

typedef struct {
    int type;
    char *payload;
} ParsedMsg;

// Parse a network packet, returning a newly allocated ParsedMsg
ParsedMsg *parse_packet(Packet *pkt) {
    if (pkt == NULL || pkt->data == NULL || pkt->length <= 0) {
        return NULL;
    }

    // Validate packet size against protocol limits
    if (pkt->length > MAX_PKT_SIZE) {
        return NULL;
    }

    ParsedMsg *msg = (ParsedMsg *)malloc(sizeof(ParsedMsg));
    if (msg == NULL) {
        return NULL;
    }

    // Read type from the first 4 bytes (big-endian)
    if (pkt->length < 4) {
        free(msg);
        return NULL;
    }
    msg->type = (pkt->data[0] << 24) | (pkt->data[1] << 16) |
                (pkt->data[2] << 8) | pkt->data[3];

    // Extract payload as a NUL-terminated string
    int payload_len = pkt->length - 4;
    if (payload_len >= MAX_HEADER_SIZE) {
        free(msg);
        return NULL;
    }

    msg->payload = (char *)malloc(payload_len + 1);
    if (msg->payload == NULL) {
        free(msg);
        return NULL;
    }

    memcpy(msg->payload, pkt->data + 4, payload_len);
    msg->payload[payload_len] = '\0';

    return msg;
}

void process_packet(Packet *pkt) {
    ParsedMsg *msg = parse_packet(pkt);
    if (msg == NULL) {
        return;
    }

    // Simulate protocol-specific processing
    printf("Type: %d, Payload: %s\n", msg->type, msg->payload);

    // Clean up and invalidate pointer to prevent dangling use
    free(msg->payload);
    msg->payload = NULL;   // line 61: NULL after free prevents double-free/UAF
    free(msg);
    msg = NULL;            // line 63: NULL after free prevents use-after-free
}

int main() {
    // Simulate a valid incoming packet
    char raw_data[] = {0x00, 0x00, 0x00, 0x01, 'H', 'e', 'l', 'l', 'o'};
    Packet pkt;
    pkt.data = raw_data;
    pkt.length = sizeof(raw_data);

    process_packet(&pkt);
    return 0;
}

