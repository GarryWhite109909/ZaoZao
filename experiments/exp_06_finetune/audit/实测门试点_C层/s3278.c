#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_LEN 512
#define MAX_NAME_LEN 32

typedef struct {
    uint8_t *data;
    size_t len;
    uint8_t name[MAX_NAME_LEN];
} packet_t;

static int parse_packet(packet_t *pkt, const uint8_t *buf, size_t buf_len) {
    if (buf_len > MAX_PKT_LEN) {
        return -1;
    }
    
    pkt->len = buf_len;
    pkt->data = (uint8_t *)malloc(buf_len);
    if (pkt->data == NULL) {
        return -1;
    }
    
    memcpy(pkt->data, buf, buf_len);
    
    size_t name_len = buf_len < MAX_NAME_LEN - 1 ? buf_len : MAX_NAME_LEN - 1;
    memcpy(pkt->name, buf, name_len);
    pkt->name[name_len] = '\0';
    
    return 0;
}

static void free_packet(packet_t *pkt) {
    if (pkt->data != NULL) {
        free(pkt->data);
        pkt->data = NULL;  // 防止悬垂指针
    }
    pkt->len = 0;
    memset(pkt->name, 0, sizeof(pkt->name));
}

int main(void) {
    uint8_t rx_buf[MAX_PKT_LEN];
    size_t rx_len = 0;
    
    // 模拟从UART接收数据
    rx_len = fread(rx_buf, 1, sizeof(rx_buf), stdin);
    if (rx_len == 0 || rx_len > MAX_PKT_LEN) {
        return -1;
    }
    
    packet_t pkt = {0};
    if (parse_packet(&pkt, rx_buf, rx_len) != 0) {
        return -1;
    }
    
    // 使用数据
    printf("Received %zu bytes, name: %s\n", pkt.len, pkt.name);
    
    free_packet(&pkt);
    return 0;
}

