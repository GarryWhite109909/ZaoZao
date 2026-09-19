#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PKT_SIZE 1024
#define HEADER_LEN 8

typedef struct {
    char *data;
    size_t len;
} Packet;

typedef struct {
    int type;
    char *payload;
} ParsedMsg;

void free_packet(Packet *pkt) {
    if (pkt) {
        free(pkt->data);
        pkt->data = NULL;  // 防御：置NULL防止悬垂指针
        pkt->len = 0;
    }
}

int parse_header(const char *buf, size_t buf_len, ParsedMsg *msg) {
    if (buf_len < HEADER_LEN) {
        return -1;  // 边界检查：长度不足直接拒绝
    }
    msg->type = (buf[0] << 8) | buf[1];  // 大端序解析类型
    return 0;
}

int process_packet(Packet *pkt, ParsedMsg *msg) {
    if (!pkt || !pkt->data || pkt->len < HEADER_LEN) {
        return -1;  // 输入校验：空指针或长度不足
    }
    
    // 解析头部
    if (parse_header(pkt->data, pkt->len, msg) != 0) {
        return -1;
    }
    
    // 提取payload（仅演示，实际会做更多处理）
    size_t payload_len = pkt->len - HEADER_LEN;
    msg->payload = malloc(payload_len + 1);
    if (!msg->payload) {
        return -1;  // 内存分配失败处理
    }
    memcpy(msg->payload, pkt->data + HEADER_LEN, payload_len);
    msg->payload[payload_len] = '\0';
    
    return 0;
}

int handle_network_packet(Packet *pkt) {
    ParsedMsg msg = {0, NULL};
    
    if (process_packet(pkt, &msg) != 0) {
        return -1;
    }
    
    // 使用msg进行业务处理...
    printf("Type: %d, Payload: %s\n", msg.type, msg.payload);
    
    // 释放payload
    free(msg.payload);
    msg.payload = NULL;  // 防御：释放后置NULL
    
    return 0;
}

int main() {
    Packet pkt = {NULL, 0};
    char raw_data[] = "\x00\x01hello world";
    
    pkt.data = malloc(strlen(raw_data) + 1);
    if (!pkt.data) return 1;
    memcpy(pkt.data, raw_data, strlen(raw_data) + 1);
    pkt.len = strlen(raw_data);
    
    handle_network_packet(&pkt);
    
    // 释放整个packet
    free_packet(&pkt);
    
    return 0;
}

