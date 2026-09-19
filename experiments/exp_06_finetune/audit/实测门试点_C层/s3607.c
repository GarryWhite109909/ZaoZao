#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_SIZE 256
#define MAX_HANDLERS 4

typedef struct {
    uint8_t *data;
    size_t len;
    int valid;
} packet_t;

typedef void (*handler_fn)(packet_t *pkt);

static handler_fn handlers[MAX_HANDLERS];
static int handler_count = 0;

// 注册包处理回调
int register_handler(handler_fn fn) {
    if (handler_count >= MAX_HANDLERS || fn == NULL) {
        return -1;
    }
    handlers[handler_count++] = fn;
    return 0;
}

// 释放包内存并置NULL
static void packet_free(packet_t *pkt) {
    if (pkt->data != NULL) {
        free(pkt->data);
        pkt->data = NULL;  // line 25: 置NULL防止悬垂
    }
    pkt->len = 0;
    pkt->valid = 0;
}

// 处理单个包（跨函数调用链）
static void process_packet(packet_t *pkt) {
    for (int i = 0; i < handler_count; i++) {
        handlers[i](pkt);
    }
}

// 主处理入口：接收原始数据并分发
void handle_rx(uint8_t *raw, size_t raw_len) {
    if (raw == NULL || raw_len == 0 || raw_len > MAX_PKT_SIZE) {
        return;
    }

    packet_t pkt = {0};
    pkt.data = (uint8_t *)malloc(raw_len);
    if (pkt.data == NULL) {
        return;
    }
    memcpy(pkt.data, raw, raw_len);
    pkt.len = raw_len;
    pkt.valid = 1;

    process_packet(&pkt);      // line 48: 跨函数调用

    packet_free(&pkt);         // line 50: 安全释放
}

// 示例handler：统计包长度
static void count_handler(packet_t *pkt) {
    if (pkt->valid && pkt->data != NULL) {
        printf("Packet len: %zu\n", pkt->len);
    }
}

int main(void) {
    register_handler(count_handler);
    uint8_t test_data[] = {0x01, 0x02, 0x03, 0x04};
    handle_rx(test_data, sizeof(test_data));
    return 0;
}

