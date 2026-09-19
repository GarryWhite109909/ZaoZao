#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PKT_LEN 64
#define MAX_PAYLOAD_LEN 32

typedef struct {
    uint8_t payload[MAX_PAYLOAD_LEN];
    uint16_t payload_len;
} packet_t;

static int parse_packet(const uint8_t *buf, size_t buf_len, packet_t *pkt) {
    if (buf == NULL || pkt == NULL) {
        return -1;
    }
    if (buf_len < 2) {
        return -1;
    }
    
    uint16_t pkt_len = (buf[0] << 8) | buf[1];
    if (pkt_len > MAX_PKT_LEN) {
        return -1;
    }
    if (pkt_len < 2) {
        return -1;
    }
    
    uint16_t payload_len = pkt_len - 2;
    if (payload_len > MAX_PAYLOAD_LEN) {
        return -1;
    }
    
    memcpy(pkt->payload, buf + 2, payload_len);
    pkt->payload_len = payload_len;
    return 0;
}

int main(void) {
    uint8_t rx_buffer[128];
    size_t rx_len = 0;
    
    // 模拟从硬件接收数据
    rx_len = fread(rx_buffer, 1, sizeof(rx_buffer), stdin);
    if (rx_len == 0) {
        return -1;
    }
    
    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    
    if (parse_packet(rx_buffer, rx_len, &pkt) != 0) {
        printf("Invalid packet\n");
        return -1;
    }
    
    printf("Payload: ");
    for (int i = 0; i < pkt.payload_len; i++) {
        printf("%02X ", pkt.payload[i]);
    }
    printf("\n");
    
    return 0;
}

