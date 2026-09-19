#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    size_t len;
} Packet;

typedef struct {
    Packet *pkt;
    int parsed;
} Parser;

void parse_packet(Parser *parser, const uint8_t *raw, size_t raw_len) {
    if (raw_len < 4) {
        return;
    }
    uint32_t payload_len = (raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3];
    if (payload_len > 1024 || payload_len > raw_len - 4) {
        return;
    }
    parser->pkt = (Packet *)malloc(sizeof(Packet));
    if (!parser->pkt) {
        return;
    }
    parser->pkt->data = (uint8_t *)malloc(payload_len);
    if (!parser->pkt->data) {
        free(parser->pkt);
        parser->pkt = NULL;
        return;
    }
    memcpy(parser->pkt->data, raw + 4, payload_len);
    parser->pkt->len = payload_len;
    parser->parsed = 1;
}

void process_packet(Parser *parser) {
    if (!parser->parsed || !parser->pkt) {
        return;
    }
    printf("Processing %zu bytes\n", parser->pkt->len);
}

int main() {
    uint8_t raw_data[] = {0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'};
    Parser parser = {0};
    parse_packet(&parser, raw_data, sizeof(raw_data));
    process_packet(&parser);
    if (parser.pkt) {
        free(parser.pkt->data);
        free(parser.pkt);
        parser.pkt = NULL;
    }
    return 0;
}

