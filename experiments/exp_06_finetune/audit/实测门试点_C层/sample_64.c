#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint8_t *buffer;
    size_t length;
} Packet;

static Packet *g_packet = NULL;

static void process_packet(Packet *pkt) {
    if (pkt->length < 4) {
        printf("Invalid packet\n");
        return;
    }
    uint16_t type = (pkt->buffer[0] << 8) | pkt->buffer[1];
    uint16_t payload_len = (pkt->buffer[2] << 8) | pkt->buffer[3];
    
    if (type == 0x01 && payload_len > 0) {
        /* Simulate some processing that triggers a reset path */
        if (payload_len > 500) {
            /* Firmware watchdog reset simulation */
            free(pkt->buffer);
            pkt->buffer = NULL;
            pkt->length = 0;
            printf("Watchdog reset triggered\n");
            return;
        }
        printf("Processing payload of %u bytes\n", payload_len);
    }
}

static void handle_packet(Packet *pkt) {
    process_packet(pkt);
    
    /* After processing, check for pending events */
    if (g_packet != NULL && g_packet == pkt) {
        /* Reuse the buffer for other operations */
        if (pkt->buffer != NULL) {
            printf("Reusing buffer at %p\n", (void*)pkt->buffer);
        }
    }
}

int main(void) {
    g_packet = (Packet*)malloc(sizeof(Packet));
    if (!g_packet) return 1;
    
    g_packet->buffer = (uint8_t*)malloc(600);
    if (!g_packet->buffer) {
        free(g_packet);
        return 1;
    }
    g_packet->length = 600;
    
    /* Craft a packet with type=0x01, payload_len=600 (exceeds 500) */
    g_packet->buffer[0] = 0x00;
    g_packet->buffer[1] = 0x01;
    g_packet->buffer[2] = 0x02;
    g_packet->buffer[3] = 0x58;  /* 600 */
    
    handle_packet(g_packet);
    
    /* Cleanup */
    if (g_packet->buffer != NULL) {
        free(g_packet->buffer);
    }
    free(g_packet);
    return 0;
}

