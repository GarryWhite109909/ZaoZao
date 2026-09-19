#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_BUF_SIZE 256

typedef struct {
    uint8_t *data;
    size_t len;
    size_t capacity;
} Buffer;

int buffer_init(Buffer *buf, size_t capacity) {
    if (capacity == 0 || capacity > MAX_BUF_SIZE) {
        return -1;
    }
    buf->data = (uint8_t *)malloc(capacity);
    if (!buf->data) {
        return -1;
    }
    buf->len = 0;
    buf->capacity = capacity;
    return 0;
}

void buffer_free(Buffer *buf) {
    if (buf->data) {
        free(buf->data);
        buf->data = NULL;  // 防御：释放后置NULL，防止悬垂指针
    }
    buf->len = 0;
    buf->capacity = 0;
}

int buffer_append(Buffer *buf, const uint8_t *src, size_t src_len) {
    if (!buf || !src || !buf->data) {
        return -1;
    }
    // 防御：边界检查，确保不越过容量
    if (src_len > buf->capacity - buf->len) {
        return -1;
    }
    memcpy(buf->data + buf->len, src, src_len);
    buf->len += src_len;
    return 0;
}

int process_packet(Buffer *rx_buf, const uint8_t *packet, size_t pkt_len) {
    if (pkt_len < 2) {
        return -1;
    }
    uint16_t payload_len = (uint16_t)((packet[0] << 8) | packet[1]);
    // 防御：限制payload长度不超过剩余包长
    if (payload_len > pkt_len - 2) {
        return -1;
    }
    if (buffer_append(rx_buf, packet + 2, payload_len) != 0) {
        return -1;
    }
    return 0;
}

int main(void) {
    uint8_t packet[] = {0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF};
    Buffer rx_buf;
    if (buffer_init(&rx_buf, 64) != 0) {
        return 1;
    }
    if (process_packet(&rx_buf, packet, sizeof(packet)) != 0) {
        buffer_free(&rx_buf);
        return 1;
    }
    buffer_free(&rx_buf);
    return 0;
}

