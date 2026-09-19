#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_SIZE 1024
#define HEADER_SIZE 12

typedef struct {
    uint8_t *data;
    size_t len;
} Packet;

typedef struct {
    uint8_t type;
    uint16_t payload_len;
} Header;

void free_packet(Packet *pkt) {
    if (pkt && pkt->data) {
        free(pkt->data);
        pkt->data = NULL;  // line 18: 置NULL防止悬垂指针
        pkt->len = 0;
    }
}

int parse_header(const uint8_t *buf, size_t buf_len, Header *hdr) {
    if (buf_len < HEADER_SIZE) return -1;
    hdr->type = buf[0];
    hdr->payload_len = (uint16_t)((buf[1] << 8) | buf[2]);
    if (hdr->payload_len > MAX_PKT_SIZE - HEADER_SIZE) return -2;  // line 27: 边界检查
    return 0;
}

int process_packet(Packet *pkt) {
    Header hdr;
    uint8_t *payload = NULL;
    size_t payload_cap = 0;

    if (!pkt || !pkt->data || pkt->len < HEADER_SIZE) return -1;

    if (parse_header(pkt->data, pkt->len, &hdr) != 0) return -2;

    payload_cap = hdr.payload_len + 1;
    payload = (uint8_t *)malloc(payload_cap);
    if (!payload) return -3;

    memcpy(payload, pkt->data + HEADER_SIZE, hdr.payload_len);
    payload[hdr.payload_len] = '\0';

    // 处理payload（模拟网络协议逻辑）
    if (hdr.type == 0x01) {
        // 类型1处理
    } else if (hdr.type == 0x02) {
        // 类型2处理
    }

    free(payload);  // line 53: 正常释放
    payload = NULL; // line 54: 置NULL防止后续误用

    // 模拟协议处理完成后再次访问（安全：已置NULL）
    if (payload != NULL) {
        printf("Unexpected access\n");
    }

    return 0;
}

int main() {
    uint8_t raw_data[MAX_PKT_SIZE];
    Packet pkt = {0};

    // 模拟从网络接收数据
    memset(raw_data, 0, sizeof(raw_data));
    raw_data[0] = 0x01;
    raw_data[1] = 0x00;
    raw_data[2] = 0x10;  // payload_len = 16

    pkt.data = raw_data;
    pkt.len = HEADER_SIZE + 16;

    int ret = process_packet(&pkt);
    if (ret != 0) {
        fprintf(stderr, "Packet processing failed: %d\n", ret);
        return 1;
    }

    return 0;
}

