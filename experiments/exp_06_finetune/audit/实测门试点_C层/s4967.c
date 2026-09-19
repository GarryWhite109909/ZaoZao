#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_SIZE 1024
#define MAX_HEADER_LEN 64

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} Buffer;

int process_packet(Buffer *pkt, const uint8_t *raw, size_t raw_len) {
    if (raw_len > MAX_PKT_SIZE) {
        return -1;
    }
    
    // line 15: 分配内存
    pkt->data = (uint8_t *)malloc(raw_len);
    if (pkt->data == NULL) {
        return -2;
    }
    pkt->len = raw_len;
    pkt->cap = raw_len;
    
    // line 21: 拷贝数据
    memcpy(pkt->data, raw, raw_len);
    
    // line 24: 解析头部
    if (raw_len < MAX_HEADER_LEN) {
        // line 26: 错误处理 - 释放内存并置NULL
        free(pkt->data);
        pkt->data = NULL;
        pkt->len = 0;
        pkt->cap = 0;
        return -3;
    }
    
    // line 33: 解析头部字段
    uint16_t type = (pkt->data[0] << 8) | pkt->data[1];
    uint32_t payload_len = (pkt->data[2] << 24) | (pkt->data[3] << 16) |
                           (pkt->data[4] << 8) | pkt->data[5];
    
    // line 38: 校验payload长度
    if (payload_len > pkt->len - MAX_HEADER_LEN) {
        // line 40: 错误处理 - 同样释放并置NULL
        free(pkt->data);
        pkt->data = NULL;
        pkt->len = 0;
        pkt->cap = 0;
        return -4;
    }
    
    // line 46: 正常处理
    // 此处省略实际payload处理逻辑
    
    return 0;
}

int main() {
    Buffer pkt = {0};
    uint8_t raw_data[MAX_PKT_SIZE] = {0};
    size_t raw_len = 100;
    
    // 模拟网络数据
    raw_data[0] = 0x01;
    raw_data[1] = 0x02;
    raw_data[2] = 0x00;
    raw_data[3] = 0x00;
    raw_data[4] = 0x00;
    raw_data[5] = 0x28;  // payload_len = 40
    
    int ret = process_packet(&pkt, raw_data, raw_len);
    if (ret == 0) {
        printf("Packet processed successfully\n");
    }
    
    // line 65: 最终释放
    if (pkt.data != NULL) {
        free(pkt.data);
        pkt.data = NULL;
    }
    
    return 0;
}

