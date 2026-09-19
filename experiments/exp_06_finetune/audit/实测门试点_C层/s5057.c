#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 1024
#define HEADER_SIZE 8

typedef struct {
    uint8_t *data;
    size_t len;
} Packet;

typedef struct {
    char *msg;
    size_t msg_len;
} ParsedMsg;

int parse_packet(const uint8_t *buf, size_t buf_len, ParsedMsg *out) {
    if (buf_len < HEADER_SIZE) {
        return -1;
    }

    uint16_t msg_len = (buf[0] << 8) | buf[1];
    if (msg_len > MAX_PACKET_SIZE - HEADER_SIZE) {
        return -1;
    }

    Packet *pkt = (Packet *)malloc(sizeof(Packet));
    if (!pkt) {
        return -1;
    }
    pkt->data = (uint8_t *)malloc(msg_len);
    if (!pkt->data) {
        free(pkt);
        return -1;
    }
    memcpy(pkt->data, buf + HEADER_SIZE, msg_len);
    pkt->len = msg_len;

    out->msg = (char *)malloc(msg_len + 1);
    if (!out->msg) {
        free(pkt->data);
        free(pkt);
        return -1;
    }
    memcpy(out->msg, pkt->data, msg_len);
    out->msg[msg_len] = '\0';
    out->msg_len = msg_len;

    free(pkt->data);
    free(pkt);
    return 0;
}

int main() {
    uint8_t packet[MAX_PACKET_SIZE] = {0};
    size_t recv_len = 0;
    ParsedMsg parsed = {0};

    if (fread(packet, 1, sizeof(packet), stdin) > 0) {
        recv_len = sizeof(packet);
    }

    if (parse_packet(packet, recv_len, &parsed) == 0) {
        printf("Parsed: %s\n", parsed.msg);
        free(parsed.msg);
    }
    return 0;
}

