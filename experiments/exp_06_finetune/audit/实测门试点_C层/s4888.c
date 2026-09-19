#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t len;
} Packet;

Packet *parse_packet(const char *raw, size_t raw_len) {
    if (raw == NULL || raw_len < sizeof(size_t)) {
        return NULL;
    }
    
    Packet *pkt = (Packet *)malloc(sizeof(Packet));
    if (pkt == NULL) {
        return NULL;
    }
    
    size_t payload_len;
    memcpy(&payload_len, raw, sizeof(size_t));
    if (payload_len > raw_len - sizeof(size_t)) {
        free(pkt);
        return NULL;
    }
    
    pkt->data = (char *)malloc(payload_len + 1);
    if (pkt->data == NULL) {
        free(pkt);
        return NULL;
    }
    
    memcpy(pkt->data, raw + sizeof(size_t), payload_len);
    pkt->data[payload_len] = '\0';
    pkt->len = payload_len;
    
    return pkt;
}

void free_packet(Packet *pkt) {
    if (pkt == NULL) {
        return;
    }
    free(pkt->data);
    pkt->data = NULL;  // 防御: 释放后置NULL
    free(pkt);
    pkt = NULL;        // 防御: 调用方指针仍需手动置NULL
}

int main(void) {
    char buffer[64] = {0};
    size_t hdr = sizeof(size_t);
    size_t msg_len = 20;
    memcpy(buffer, &msg_len, hdr);
    memcpy(buffer + hdr, "hello network packet", 20);
    
    Packet *p = parse_packet(buffer, hdr + msg_len);
    if (p == NULL) {
        return 1;
    }
    
    printf("Packet len=%zu, data=%s\n", p->len, p->data);
    free_packet(p);
    // p = NULL;  // 调用方正确管理，避免悬垂
    return 0;
}

