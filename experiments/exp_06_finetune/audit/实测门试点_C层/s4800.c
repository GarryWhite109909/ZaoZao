#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#define MAX_BUF 1024

typedef struct {
    char *data;
    size_t len;
    pthread_mutex_t lock;
} Buffer;

static void safe_free(Buffer *buf) {
    pthread_mutex_lock(&buf->lock);
    if (buf->data != NULL) {
        free(buf->data);
        buf->data = NULL;  // 防悬垂指针
        buf->len = 0;
    }
    pthread_mutex_unlock(&buf->lock);
}

static void *reader_thread(void *arg) {
    Buffer *buf = (Buffer *)arg;
    char local[MAX_BUF];
    
    pthread_mutex_lock(&buf->lock);
    if (buf->data != NULL) {
        size_t copy_len = (buf->len < MAX_BUF - 1) ? buf->len : MAX_BUF - 1;
        memcpy(local, buf->data, copy_len);
        local[copy_len] = '\0';
        printf("Reader: %s\n", local);
    }
    pthread_mutex_unlock(&buf->lock);
    return NULL;
}

int main(void) {
    Buffer buf;
    pthread_t tid;
    
    pthread_mutex_init(&buf.lock, NULL);
    buf.data = malloc(64);
    if (buf.data == NULL) {
        pthread_mutex_destroy(&buf.lock);
        return -1;
    }
    strcpy(buf.data, "temporary data");
    buf.len = strlen(buf.data) + 1;
    
    pthread_create(&tid, NULL, reader_thread, &buf);
    
    // 主线程安全释放
    safe_free(&buf);
    
    pthread_join(tid, NULL);
    pthread_mutex_destroy(&buf.lock);
    return 0;
}

