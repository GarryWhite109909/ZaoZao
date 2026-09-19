#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

typedef struct {
    char *data;
    size_t size;
    pthread_mutex_t lock;
} Buffer;

Buffer *create_buffer(size_t size) {
    Buffer *buf = malloc(sizeof(Buffer));
    if (!buf) return NULL;
    buf->data = malloc(size);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    buf->size = size;
    pthread_mutex_init(&buf->lock, NULL);
    return buf;
}

void destroy_buffer(Buffer *buf) {
    if (!buf) return;
    pthread_mutex_lock(&buf->lock);
    free(buf->data);
    buf->data = NULL;  // 防御：置NULL防止悬垂指针
    buf->size = 0;
    pthread_mutex_unlock(&buf->lock);
    pthread_mutex_destroy(&buf->lock);
    free(buf);
}

int read_buffer(Buffer *buf, char *out, size_t len) {
    if (!buf || !out) return -1;
    pthread_mutex_lock(&buf->lock);
    if (!buf->data || len > buf->size) {  // 防御：双重检查
        pthread_mutex_unlock(&buf->lock);
        return -1;
    }
    memcpy(out, buf->data, len);
    pthread_mutex_unlock(&buf->lock);
    return 0;
}

int main(void) {
    Buffer *buf = create_buffer(128);
    if (!buf) return 1;
    char local[64];
    if (read_buffer(buf, local, sizeof(local)) == 0) {
        printf("Read OK\n");
    }
    destroy_buffer(buf);
    // 防御：调用后不再访问buf
    buf = NULL;  // 防御：置NULL防止二次释放
    return 0;
}

