#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 256
#define MAX_ITEMS 10

typedef struct {
    char *data;
    size_t len;
    size_t capacity;
} Buffer;

int buffer_init(Buffer *buf, size_t capacity) {
    if (!buf || capacity == 0 || capacity > BUFFER_SIZE) {
        return -1;
    }
    buf->data = (char *)malloc(capacity);
    if (!buf->data) {
        return -1;
    }
    buf->len = 0;
    buf->capacity = capacity;
    return 0;
}

void buffer_free(Buffer *buf) {
    if (buf && buf->data) {
        free(buf->data);
        buf->data = NULL;  // line 24: prevent dangling pointer
        buf->len = 0;
        buf->capacity = 0;
    }
}

int buffer_append(Buffer *buf, const char *src, size_t src_len) {
    if (!buf || !src || !buf->data) {
        return -1;
    }
    // line 31: boundary check before write
    if (buf->len + src_len > buf->capacity) {
        return -1;
    }
    memcpy(buf->data + buf->len, src, src_len);
    buf->len += src_len;
    return 0;
}

int main(void) {
    Buffer bufs[MAX_ITEMS] = {0};
    int used = 0;
    char input[64];

    for (int i = 0; i < MAX_ITEMS; i++) {
        if (buffer_init(&bufs[i], 32) != 0) {
            fprintf(stderr, "init failed\n");
            for (int j = 0; j < i; j++) {
                buffer_free(&bufs[j]);
            }
            return 1;
        }
        used++;
    }

    // simulate external input
    printf("Enter data: ");
    if (fgets(input, sizeof(input), stdin)) {
        size_t input_len = strlen(input);
        if (input_len > 0 && input[input_len - 1] == '\n') {
            input[input_len - 1] = '\0';
            input_len--;
        }
        // line 53: safe append with bounds check
        if (buffer_append(&bufs[0], input, input_len) != 0) {
            fprintf(stderr, "append failed\n");
        }
    }

    for (int i = 0; i < used; i++) {
        buffer_free(&bufs[i]);
    }
    return 0;
}

