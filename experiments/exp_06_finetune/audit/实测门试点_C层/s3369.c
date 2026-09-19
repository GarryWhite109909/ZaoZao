#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_SIZE 256
#define MAX_PAYLOAD  128

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} Buffer;

static int buffer_reserve(Buffer *buf, size_t extra) {
    if (buf->len > MAX_PKT_SIZE || extra > MAX_PKT_SIZE - buf->len) {
        return -1;  /* 防溢出：加法前检查 */
    }
    size_t new_cap = buf->len + extra;
    if (new_cap > buf->cap) {
        uint8_t *tmp = realloc(buf->data, new_cap);
        if (!tmp) return -1;
        buf->data = tmp;
        buf->cap = new_cap;
    }
    return 0;
}

static int process_packet(Buffer *buf, const uint8_t *pkt, size_t pkt_len) {
    if (pkt_len > MAX_PAYLOAD) {
        return -1;  /* 输入白名单：仅接受小包 */
    }
    if (buffer_reserve(buf, pkt_len) != 0) {
        return -1;
    }
    memcpy(buf->data + buf->len, pkt, pkt_len);  /* line 33 */
    buf->len += pkt_len;
    return 0;
}

int main(void) {
    Buffer rx = {NULL, 0, 0};
    uint8_t packet[MAX_PAYLOAD];
    size_t  n = 0;

    /* 模拟从硬件读取一帧 */
    n = fread(packet, 1, sizeof(packet), stdin);
    if (n == 0) return 1;

    if (process_packet(&rx, packet, n) != 0) {
        free(rx.data);
        rx.data = NULL;  /* free后置NULL */
        return 1;
    }

    /* 输出接收长度 */
    printf("%zu\n", rx.len);

    free(rx.data);
    rx.data = NULL;
    return 0;
}

