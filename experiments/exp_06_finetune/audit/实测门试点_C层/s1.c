#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *payload;
    int len;
} Packet;

Packet *parse_packet(const char *data, int size) {
    if (size < 8) return NULL;

    Packet *pkt = (Packet *)malloc(sizeof(Packet));
    if (!pkt) return NULL;

    pkt->len = *(int *)(data + 4);                  // line 13
    if (pkt->len < 0 || pkt->len > 1024) {          // line 14
        free(pkt);
        return NULL;
    }

    pkt->payload = (char *)malloc(pkt->len + 1);    // line 18
    if (!pkt->payload) {
        free(pkt);
        return NULL;
    }

    memcpy(pkt->payload, data + 8, pkt->len);       // line 24
    pkt->payload[pkt->len] = '\0';
    return pkt;
}

void process_packet(Packet *pkt) {
    if (!pkt) return;

    printf("Payload: %s\n", pkt->payload);
    free(pkt->payload);                             // line 34
    free(pkt);                                      // line 35
}

int main() {
    char buffer[128] = {0};
    // Simulate network receive
    *(int *)(buffer + 4) = 20;
    strcpy(buffer + 8, "hello-network-data");

    Packet *p = parse_packet(buffer, 128);
    if (p) {
        process_packet(p);
        // No use-after-free here because p not used after free
    }
    return 0;
}

