#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_LEN 1024
#define HDR_LEN 8
#define MAX_PAYLOAD (MAX_PKT_LEN - HDR_LEN)

typedef struct {
    uint16_t type;
    uint16_t len;
    uint32_t crc;
} pkt_hdr_t;

static char *g_log_buf = NULL;

static int parse_packet(const uint8_t *buf, size_t buf_len, char *out, size_t out_cap) {
    if (buf_len < HDR_LEN) return -1;
    
    pkt_hdr_t hdr;
    memcpy(&hdr, buf, HDR_LEN);
    hdr.len = ntohs(hdr.len);
    
    if (hdr.len > MAX_PAYLOAD) return -2;
    if (hdr.len > buf_len - HDR_LEN) return -3;
    
    // 模拟协议解析：将载荷复制到输出缓冲区
    memcpy(out, buf + HDR_LEN, hdr.len);
    out[hdr.len] = '\0';
    
    return hdr.len;
}

static void log_message(const char *msg) {
    if (!g_log_buf) {
        g_log_buf = (char *)malloc(256);
        if (!g_log_buf) return;
    }
    strcpy(g_log_buf, msg);  // 潜在溢出
}

int handle_network_input(const uint8_t *data, size_t data_len) {
    char payload[128];
    int payload_len;
    
    payload_len = parse_packet(data, data_len, payload, sizeof(payload));
    if (payload_len < 0) {
        return -1;
    }
    
    // 根据载荷类型记录日志
    if (payload[0] == 'E') {
        log_message(payload);
    }
    
    return payload_len;
}

int main(void) {
    // 构造一个超长但合法的网络包（hdr.len 为 200，但 payload 缓冲区只有 128）
    uint8_t pkt[MAX_PKT_LEN] = {0};
    pkt_hdr_t hdr = {0};
    hdr.type = htons(1);
    hdr.len = htons(200);
    hdr.crc = 0;
    memcpy(pkt, &hdr, HDR_LEN);
    memset(pkt + HDR_LEN, 'E', 200);
    
    handle_network_input(pkt, HDR_LEN + 200);
    
    free(g_log_buf);
    return 0;
}

