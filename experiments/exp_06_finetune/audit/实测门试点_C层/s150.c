#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PKT_LEN 1024

typedef struct {
    char *data;
    size_t len;
    int parsed;
} pkt_t;

pkt_t *parse_packet(const char *raw, size_t size) {
    pkt_t *pkt = (pkt_t *)malloc(sizeof(pkt_t));
    if (!pkt) return NULL;
    pkt->data = (char *)malloc(size);
    if (!pkt->data) {
        free(pkt);
        return NULL;
    }
    memcpy(pkt->data, raw, size);
    pkt->len = size;
    pkt->parsed = 0;
    return pkt;
}

void release_packet(pkt_t *pkt) {
    if (!pkt) return;
    if (pkt->data) {
        free(pkt->data);
        pkt->data = NULL;
    }
    free(pkt);
}

/* 模拟协议头部解析，返回头部长度，失败返回 -1 */
int parse_header(pkt_t *pkt) {
    if (!pkt || !pkt->data || pkt->len < 4) return -1;
    /* 简化：前4字节为长度字段，此处仅验证非零 */
    int hlen = (pkt->data[0] << 24) | (pkt->data[1] << 16) |
               (pkt->data[2] << 8) | pkt->data[3];
    if (hlen <= 0 || hlen > (int)pkt->len) return -1;
    return hlen;
}

int process_packet(const char *raw, size_t size) {
    pkt_t *pkt = parse_packet(raw, size);
    if (!pkt) return -1;

    int hlen = parse_header(pkt);
    if (hlen < 0) {
        release_packet(pkt);
        return -1;
    }

    /* 业务处理：这里模拟使用 pkt->data 做进一步解析 */
    if (pkt->data[hlen] == 0x01) {  /* line 40: 使用 pkt->data */
        /* 某些分支提前释放 */
        release_packet(pkt);        /* line 42: 释放后未置 NULL */
        /* ... 中间可能还有其他逻辑 ... */
        if (pkt->data[hlen + 1] == 0x02) {  /* line 45: 再次使用已释放的 pkt->data */
            printf("protocol flag detected\n");
        }
    }

    release_packet(pkt);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    size_t len = strlen(argv[1]);
    return process_packet(argv[1], len);
}

