#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ITEMS 10

typedef struct {
    int *data;
    size_t len;
} Buffer;

Buffer *create_buffer(size_t size) {
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

void process_items(Buffer *buf, int count) {
    int i;
    if (count > MAX_ITEMS) {
        printf("Too many items, truncating\n");
        count = MAX_ITEMS;
    }
    for (i = 0; i < count; i++) {
        buf->data[i] = i * 2;
    }
}

int main() {
    Buffer *buf = create_buffer(5);
    if (!buf) return 1;

    process_items(buf, 12);
    printf("Processed %zu items\n", buf->len);
    free(buf->data);
    free(buf);
    return 0;
}

