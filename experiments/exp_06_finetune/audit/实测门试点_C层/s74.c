#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_LEN 1024
#define HDR_LEN 8

typedef struct {
    uint8_t *payload;
    size_t len;
} packet_t;

typedef struct {
    packet_t *pkt;
    int parsed;
} context_t;

static void parse_header(uint8_t *buf, size_t buf_len, packet_t *out) {
    if (buf_len < HDR_LEN) {
        out->payload = NULL;
        out->len = 0;
        return;
    }
    /* 模拟头部解析：前4字节为长度，后4字节为标志 */
    uint32_t data_len = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    if (data_len > MAX_PKT_LEN - HDR_LEN) {
        data_len = MAX_PKT_LEN - HDR_LEN;
    }
    out->payload = malloc(data_len);
    if (!out->payload) {
        out->len = 0;
        return;
    }
    memcpy(out->payload, buf + HDR_LEN, data_len);
    out->len = data_len;
}

static void free_packet(packet_t *p) {
    if (p->payload) {
        free(p->payload);
        /* 注意：此处未将 p->payload 置 NULL */
    }
}

static void process_packet(context_t *ctx, uint8_t *raw, size_t raw_len) {
    packet_t pkt = {0};
    parse_header(raw, raw_len, &pkt);
    if (!pkt.payload) {
        return;
    }
    ctx->pkt = &pkt;  /* 保存栈上结构体指针 */
    ctx->parsed = 1;

    /* 业务处理：模拟解析后的使用 */
    if (pkt.len > 0 && pkt.payload[0] == 0xFF) {
        free_packet(&pkt);  /* 第一次释放 */
        ctx->parsed = 0;
    }

    /* 后续逻辑仍可能访问 ctx->pkt（例如日志记录） */
    if (ctx->parsed) {
        printf("Parsed %zu bytes\n", ctx->pkt->len);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        return 1;
    }
    uint8_t buf[MAX_PKT_LEN];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    context_t ctx = {0};
    process_packet(&ctx, buf, n);
    return 0;
}

