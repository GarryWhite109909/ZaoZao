#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint8_t *buffer;
    size_t len;
} packet_t;

static void process_packet(packet_t *pkt, uint8_t *payload) {
    if (pkt->len > 512) {
        pkt->buffer = (uint8_t*)realloc(pkt->buffer, pkt->len);
        if (!pkt->buffer) {
            free(pkt->buffer);
            return;
        }
    }
    memcpy(pkt->buffer, payload, pkt->len);
}

static void release_packet(packet_t *pkt) {
    if (pkt->buffer) {
        free(pkt->buffer);
        pkt->buffer = NULL;
    }
}

int main(int argc, char **argv) {
    packet_t pkt = {0};
    uint8_t data[256] = {0};
    
    pkt.buffer = (uint8_t*)malloc(128);
    if (!pkt.buffer) return -1;
    pkt.len = 256;
    
    process_packet(&pkt, data);
    release_packet(&pkt);
    
    if (pkt.len > 100) {
        process_packet(&pkt, data);  // line 34: UAF - pkt.buffer is dangling
    }
    
    free(pkt.buffer);  // line 37: double-free attempt
    return 0;
}

