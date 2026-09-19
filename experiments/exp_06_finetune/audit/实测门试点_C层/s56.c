#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

typedef struct {
    int *data;
    int size;
} Buffer;

Buffer *buf;

void *reader_thread(void *arg) {
    // 模拟延迟，增加竞态窗口
    usleep(100000);
    if (buf != NULL) {
        printf("Data: %d\n", buf->data[0]);
    }
    return NULL;
}

void *writer_thread(void *arg) {
    usleep(50000);
    if (buf != NULL) {
        free(buf->data);
        free(buf);
        buf = NULL;  // 防御：释放后置NULL
    }
    return NULL;
}

int main() {
    buf = malloc(sizeof(Buffer));
    buf->data = malloc(sizeof(int) * 4);
    buf->size = 4;
    buf->data[0] = 42;

    pthread_t t1, t2;
    pthread_create(&t1, NULL, reader_thread, NULL);
    pthread_create(&t2, NULL, writer_thread, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    return 0;
}

