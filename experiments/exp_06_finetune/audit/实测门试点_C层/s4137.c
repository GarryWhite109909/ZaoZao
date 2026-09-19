#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PKT_SIZE 1024

typedef struct {
    char *data;
    size_t len;
    int valid;
} packet_t;

static void packet_free(packet_t *pkt) {
    if (pkt == NULL || pkt->data == NULL) {
        return;
    }
    free(pkt->data);
    pkt->data = NULL;  // line 14: 置NULL，防止悬垂指针
    pkt->len = 0;
    pkt->valid = 0;
}

static packet_t *packet_create(const char *payload, size_t payload_len) {
    if (payload == NULL || payload_len == 0 || payload_len > MAX_PKT_SIZE) {
        return NULL;  // line 21: 输入校验，拒绝非法长度
    }
    
    packet_t *pkt = (packet_t *)calloc(1, sizeof(packet_t));
    if (pkt == NULL) {
        return NULL;
    }
    
    pkt->data = (char *)malloc(payload_len);
    if (pkt->data == NULL) {
        free(pkt);  // line 29: 失败时清理已分配内存
        return NULL;
    }
    
    memcpy(pkt->data, payload, payload_len);
    pkt->len = payload_len;
    pkt->valid = 1;
    return pkt;
}

int process_packet(packet_t *pkt) {
    if (pkt == NULL || !pkt->valid || pkt->data == NULL) {
        return -1;  // line 39: 使用前验证状态
    }
    
    // 模拟处理：仅读取数据
    size_t bytes_to_process = (pkt->len < 64) ? pkt->len : 64;
    char buffer[64];
    memcpy(buffer, pkt->data, bytes_to_process);
    
    return (int)bytes_to_process;
}

int main(void) {
    const char *payload = "firmware_update_cmd";
    packet_t *pkt = packet_create(payload, strlen(payload));
    if (pkt == NULL) {
        return -1;
    }
    
    int result = process_packet(pkt);
    printf("Processed %d bytes\n", result);
    
    packet_free(pkt);  // line 61: 安全释放
    // pkt->data 已为 NULL，此处不再使用 pkt
    packet_free(pkt);  // line 63: 双重释放测试——安全，因为 data 为 NULL
    
    return 0;
}

