#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_LEN 1024

typedef struct {
    uint8_t *data;
    size_t len;
    uint8_t *payload;
} packet_t;

int parse_packet(packet_t *pkt) {
    if (pkt->len < 4) {
        return -1;
    }
    
    uint16_t header_len = (pkt->data[0] << 8) | pkt->data[1];
    uint16_t payload_offset = (pkt->data[2] << 8) | pkt->data[3];
    
    if (header_len < 4 || header_len > pkt->len || payload_offset > pkt->len - header_len) {
        return -1;
    }
    
    pkt->payload = pkt->data + header_len;
    return 0;
}

int process_packet(packet_t *pkt) {
    if (pkt == NULL || pkt->data == NULL) {
        return -1;
    }
    
    if (parse_packet(pkt) != 0) {
        return -1;
    }
    
    /* Process payload */
    if (pkt->payload != NULL) {
        printf("Payload length: %zu\n", pkt->len - (pkt->payload - pkt->data));
    }
    
    return 0;
}

int main(void) {
    packet_t pkt = {0};
    uint8_t buf[MAX_PKT_LEN];
    
    /* Simulate receiving network data */
    size_t recv_len = 8;
    buf[0] = 0x00; buf[1] = 0x04;  /* header_len = 4 */
    buf[2] = 0x00; buf[3] = 0x00;  /* payload_offset = 0 */
    
    pkt.data = buf;
    pkt.len = recv_len;
    
    if (process_packet(&pkt) != 0) {
        fprintf(stderr, "Packet processing failed\n");
        return 1;
    }
    
    /* Safe: pkt.data points to stack buffer, no free needed */
    pkt.data = NULL;
    pkt.payload = NULL;
    
    return 0;
}

