#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

typedef struct {
    char *data;
    size_t size;
    pthread_mutex_t lock;
} Buffer;

Buffer *buffer_create(size_t size) {
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

void buffer_destroy(Buffer *buf) {
    if (!buf) return;
    pthread_mutex_lock(&buf->lock);
    free(buf->data);
    buf->data = NULL;
    buf->size = 0;
    pthread_mutex_unlock(&buf->lock);
    pthread_mutex_destroy(&buf->lock);
    free(buf);
}

int buffer_write(Buffer *buf, const char *src, size_t len) {
    if (!buf || !src) return -1;
    pthread_mutex_lock(&buf->lock);
    if (buf->data == NULL) {
        pthread_mutex_unlock(&buf->lock);
        return -1;
    }
    if (len > buf->size) {
        pthread_mutex_unlock(&buf->lock);
        return -1;
    }
    memcpy(buf->data, src, len);
    pthread_mutex_unlock(&buf->lock);
    return 0;
}

int main(void) {
    Buffer *buf = buffer_create(1024);
    if (!buf) return 1;
    
    char *msg = "hello";
    if (buffer_write(buf, msg, strlen(msg)) != 0) {
        buffer_destroy(buf);
        return 1;
    }
    
    buffer_destroy(buf);
    return 0;
}

