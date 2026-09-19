#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

typedef struct {
    char *data;
    size_t len;
    pthread_mutex_t lock;
} Buffer;

static Buffer *g_buf = NULL;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

Buffer *buffer_create(size_t initial_len) {
    Buffer *b = (Buffer *)malloc(sizeof(Buffer));
    if (!b) return NULL;
    b->data = (char *)malloc(initial_len);
    if (!b->data) {
        free(b);
        return NULL;
    }
    b->len = initial_len;
    pthread_mutex_init(&b->lock, NULL);
    return b;
}

void buffer_destroy(Buffer *b) {
    if (!b) return;
    pthread_mutex_lock(&b->lock);
    if (b->data) {
        free(b->data);
        b->data = NULL;  // line 31: NULL after free
    }
    b->len = 0;
    pthread_mutex_unlock(&b->lock);
    pthread_mutex_destroy(&b->lock);
    free(b);
}

int buffer_write(Buffer *b, const char *src, size_t n) {
    if (!b || !src) return -1;
    pthread_mutex_lock(&b->lock);
    if (b->data == NULL) {  // line 40: guard against use-after-free
        pthread_mutex_unlock(&b->lock);
        return -1;
    }
    if (n > b->len) n = b->len;  // line 44: bounds check
    memcpy(b->data, src, n);
    pthread_mutex_unlock(&b->lock);
    return (int)n;
}

void *worker(void *arg) {
    Buffer *b = (Buffer *)arg;
    char msg[] = "hello";
    int ret = buffer_write(b, msg, strlen(msg));
    if (ret < 0) {
        fprintf(stderr, "write failed\n");
    }
    return NULL;
}

int main() {
    pthread_t t1, t2;
    g_buf = buffer_create(1024);
    if (!g_buf) return 1;

    pthread_create(&t1, NULL, worker, g_buf);
    pthread_create(&t2, NULL, worker, g_buf);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    buffer_destroy(g_buf);
    g_buf = NULL;  // line 75: global pointer NULL after destroy
    return 0;
}

