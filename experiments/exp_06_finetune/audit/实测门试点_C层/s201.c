#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 256
#define COPY_LEN(buf, src, len) memcpy(buf, src, len)

typedef struct {
    char *data;
    size_t size;
} Buffer;

static int process_chunk(Buffer *dst, const char *src, size_t len) {
    if (len > dst->size) {
        return -1;
    }
    COPY_LEN(dst->data, src, len);
    dst->data[len] = '\0';
    return 0;
}

int merge_buffers(Buffer *out, const Buffer *a, const Buffer *b) {
    if (!out || !a || !b) return -1;
    size_t total = a->size + b->size;
    if (total > out->size) {
        return -1;
    }
    if (process_chunk(out, a->data, a->size) != 0) {
        return -1;
    }
    if (process_chunk(out + 1, b->data, b->size) != 0) {  // line 26: out+1 越界
        return -1;
    }
    return 0;
}

int main(void) {
    Buffer buf1 = {malloc(128), 128};
    Buffer buf2 = {malloc(256), 256};
    Buffer merged = {malloc(512), 512};
    if (!buf1.data || !buf2.data || !merged.data) return 1;

    strcpy(buf1.data, "hello");
    buf1.size = 5;
    strcpy(buf2.data, "world");
    buf2.size = 5;

    if (merge_buffers(&merged, &buf1, &buf2) == 0) {
        printf("merged: %s\n", merged.data);
    }

    free(buf1.data);
    free(buf2.data);
    free(merged.data);
    return 0;
}

