#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ITEMS 8

typedef struct {
    int *data;
    size_t len;
} Buffer;

static Buffer *create_buffer(size_t size) {
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (!buf) return NULL;
    buf->data = (int *)malloc(size * sizeof(int));
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    buf->len = size;
    return buf;
}

static void free_buffer(Buffer *buf) {
    if (buf) {
        free(buf->data);
        free(buf);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    size_t n = (size_t)atoi(argv[1]);
    if (n == 0) return 1;

    Buffer *buf = create_buffer(MAX_ITEMS);
    if (!buf) return 1;

    /* 关键：用户控制的 n 直接用于写操作，未与 buf->len 比较 */
    for (size_t i = 0; i < n; i++) {
        buf->data[i] = i * 2;   // line 31: 越界写
    }

    printf("done: %d\n", buf->data[0]);
    free_buffer(buf);
    return 0;
}

