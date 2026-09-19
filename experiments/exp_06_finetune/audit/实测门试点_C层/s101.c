#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define BUF_SIZE 1024

typedef struct {
    char *data;
    size_t len;
    pthread_mutex_t lock;
} Buffer;

Buffer *global_buf;

void *reader_thread(void *arg) {
    Buffer *buf = (Buffer *)arg;
    char local[BUF_SIZE];
    
    pthread_mutex_lock(&buf->lock);
    if (buf->data != NULL) {
        memcpy(local, buf->data, buf->len);
        printf("Read %zu bytes\n", buf->len);
    }
    pthread_mutex_unlock(&buf->lock);
    return NULL;
}

void *writer_thread(void *arg) {
    Buffer *buf = (Buffer *)arg;
    
    pthread_mutex_lock(&buf->lock);
    if (buf->data) {
        free(buf->data);
        buf->data = NULL;
        buf->len = 0;
    }
    pthread_mutex_unlock(&buf->lock);
    return NULL;
}

int main() {
    pthread_t t1, t2;
    
    global_buf = (Buffer *)malloc(sizeof(Buffer));
    if (!global_buf) return 1;
    
    global_buf->data = (char *)malloc(BUF_SIZE);
    if (!global_buf->data) { free(global_buf); return 1; }
    memset(global_buf->data, 'A', BUF_SIZE);
    global_buf->len = BUF_SIZE;
    pthread_mutex_init(&global_buf->lock, NULL);
    
    pthread_create(&t1, NULL, reader_thread, global_buf);
    pthread_create(&t2, NULL, writer_thread, global_buf);
    
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    
    pthread_mutex_destroy(&global_buf->lock);
    free(global_buf);
    return 0;
}

