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
    free(buf->data);
    buf->data = NULL;  // 防御：置NULL防止悬垂指针
    buf->len = 0;
    pthread_mutex_unlock(&buf->lock);
    pthread_mutex_destroy(&buf->lock);
    free(buf);         // 防御：释放后置NULL
    buf = NULL;        // 局部变量置NULL（实际无效但语义明确）
}

int buffer_write(Buffer *buf, const char *src, size_t n) {
    if (!buf || !src) return -1;
    pthread_mutex_lock(&buf->lock);
    if (buf->data == NULL) {  // 防御：检查已释放状态
        pthread_mutex_unlock(&buf->lock);
        return -1;
    }
    if (n > buf->len) {       // 防御：边界检查
        pthread_mutex_unlock(&buf->lock);
        return -1;
    }
    memcpy(buf->data, src, n);
    pthread_mutex_unlock(&buf->lock);
    return 0;
}

int main(void) {
    Buffer *b = buffer_create(64);
    if (!b) return 1;
    buffer_write(b, "hello", 5);
    buffer_destroy(b);
    // b 已释放，后续不再使用（RAII 语义由调用者保证）
    return 0;
}

