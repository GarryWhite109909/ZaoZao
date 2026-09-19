#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

typedef struct {
    char *data;
    size_t len;
    pthread_mutex_t lock;
} Buffer;

Buffer *buffer_create(size_t size) {
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (!buf) return NULL;
    buf->data = (char *)malloc(size);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    buf->len = size;
    pthread_mutex_init(&buf->lock, NULL);
    return buf;
}

void buffer_destroy(Buffer *buf) {
    if (!buf) return;
    pthread_mutex_lock(&buf->lock);
    if (buf->data) {
        memset(buf->data, 0, buf->len);  // 清除敏感数据
        free(buf->data);
        buf->data = NULL;                // line 24: 置NULL防悬垂
    }
    buf->len = 0;
    pthread_mutex_unlock(&buf->lock);
    pthread_mutex_destroy(&buf->lock);
    free(buf);                           // line 29: 释放容器
}

void buffer_write(Buffer *buf, const char *src, size_t n) {
    if (!buf || !src) return;
    pthread_mutex_lock(&buf->lock);
    if (buf->data && n <= buf->len) {    // line 35: 边界检查
        memcpy(buf->data, src, n);
    }
    pthread_mutex_unlock(&buf->lock);
}

int main() {
    Buffer *mybuf = buffer_create(1024);
    if (!mybuf) return 1;
    buffer_write(mybuf, "hello", 5);
    buffer_destroy(mybuf);
    // 后续代码不再访问 mybuf，避免UAF
    return 0;
}

