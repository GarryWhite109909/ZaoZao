#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PKT_LEN 256

typedef struct {
    uint8_t *data;
    size_t len;
    int valid;
} Packet;

Packet *packet_create(size_t len) {
    if (len == 0 || len > MAX_PKT_LEN) {
        return NULL;
    }
    Packet *pkt = (Packet *)malloc(sizeof(Packet));
    if (!pkt) {
        return NULL;
    }
    pkt->data = (uint8_t *)malloc(len);
    if (!pkt->data) {
        free(pkt);
        return NULL;
    }
    pkt->len = len;
    pkt->valid = 1;
    return pkt;
}

void packet_destroy(Packet *pkt) {
    if (!pkt) {
        return;
    }
    free(pkt->data);
    pkt->data = NULL;  // 防御：释放后置NULL
    pkt->valid = 0;
    free(pkt);
}

void process_packet(Packet *pkt) {
    if (!pkt || !pkt->valid || !pkt->data) {
        return;  // 防御：使用前完整性校验
    }
    // 模拟处理：仅读取前4字节
    uint32_t header = 0;
    memcpy(&header, pkt->data, 4);
    printf("Header: 0x%08X\n", header);
}

int main(void) {
    Packet *pkt = packet_create(32);
    if (!pkt) {
        return -1;
    }
    process_packet(pkt);
    packet_destroy(pkt);
    pkt = NULL;  // 防御：外部指针置NULL
    // 后续不再使用pkt，但即使误用也会被NULL检查拦截
    process_packet(pkt);  // 安全：pkt为NULL，被空指针检查拦截
    return 0;
}

