#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_SIZE 128
#define MAX_PAYLOAD   64

typedef struct {
    uint8_t data[MAX_PKT_SIZE];
    uint16_t len;
} packet_t;

static int process_packet(packet_t *pkt, const uint8_t *payload, uint16_t payload_len) {
    if (payload_len > MAX_PAYLOAD) {
        return -1;
    }
    if (pkt->len + payload_len > MAX_PKT_SIZE) {
        return -2;
    }
    memcpy(pkt->data + pkt->len, payload, payload_len);
    pkt->len += payload_len;
    return 0;
}

int main(void) {
    packet_t rx_pkt = {0};
    uint8_t buf[MAX_PAYLOAD] = {0};
    uint16_t n = 0;

    while (1) {
        printf("Enter payload length (0-%d): ", MAX_PAYLOAD);
        if (scanf("%hu", &n) != 1) break;
        if (n == 0) break;
        if (n > MAX_PAYLOAD) {
            printf("Invalid length\n");
            continue;
        }
        printf("Enter payload: ");
        for (uint16_t i = 0; i < n; i++) {
            scanf("%02x", (unsigned int *)&buf[i]);
        }
        if (process_packet(&rx_pkt, buf, n) != 0) {
            printf("Packet full\n");
            continue;
        }
        printf("Packet len: %u\n", rx_pkt.len);
    }
    return 0;
}

